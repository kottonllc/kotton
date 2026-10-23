// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — the daily unlock credential (RFC-0053 steps 2 and 3).
//!
//! The property under test is a product one: **a daemon restart must not cost
//! the user their root secret.** Sessions live in daemon memory, so every
//! restart destroys them, and until step 2 the only credential that could mint
//! a new one was the recovery phrase — the mnemonic whose job under RFC-0031 is
//! to be the safety-deposit-box key, handled rarely. Asking for it several times
//! a day is what drives it into shell history and environment variables.
//!
//! These tests exercise the daemon half of that path over real IPC:
//! `GetUnlockMethods` before a session exists, `UnlockWithPin` opening one, the
//! attempt budget refusing when it is spent, and the step-3 strength rule
//! refusing a credential too weak to stand up to offline guessing. The
//! interactive prompting in `connect_as` sits on top and is not testable without
//! a terminal.

use crate::common::TestEnv;
use kotton::{CustodyState, KottonClient, LockMode, PinUnlock};
use kotton_common::time::now_secs;

const USER: &str = "avery";
/// Five distinct wordlist words — the shape `kotton id set-passphrase` offers,
/// and above the RFC-0053 bar.
const PASSPHRASE: &str = "abandon-ability-able-about-above";

/// Give `USER` a daily passphrase on an authenticated connection, as
/// `kotton id set-passphrase` does. This seals the operational roots into the
/// at-rest vault *and* records the authenticator hash — the two mechanisms
/// RFC-0053 distinguishes.
async fn user_with_a_passphrase(env: &mut TestEnv) {
    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    env.client
        .set_lock_policy(USER, LockMode::Passphrase, 0, Some(PASSPHRASE))
        .await
        .expect("set_lock_policy");
}

/// A client must be able to learn *which* credential to ask for before it holds
/// a session — the chicken-and-egg that kept `connect_as` on the recovery-phrase
/// path. `GetRecoveryStatus` cannot answer it: that requires a session.
#[tokio::test]
async fn unlock_methods_are_readable_before_any_session() {
    let mut env = TestEnv::spawn().await;

    // A brand-new connection, holding nothing.
    let mut fresh = KottonClient::connect_to(env.endpoint.clone())
        .await
        .expect("connect_to");

    // An identity that does not exist reports no daily credential — the same
    // answer a real identity without one gives, so this is not a way to probe
    // who exists on the device.
    assert_eq!(
        fresh.get_unlock_methods("nobody").await.expect("pre-auth"),
        (false, true)
    );

    user_with_a_passphrase(&mut env).await;

    let mut after = KottonClient::connect_to(env.endpoint.clone())
        .await
        .expect("connect_to");
    assert_eq!(
        after.get_unlock_methods(USER).await.expect("pre-auth"),
        (true, true),
        "a user with a passphrase must advertise it to an unauthenticated caller"
    );
}

/// The headline: the daily credential opens a session on a connection holding
/// nothing, and that session actually works. This is what a daemon restart costs
/// after RFC-0053 step 2 — a passphrase, not the mnemonic.
#[tokio::test]
async fn the_daily_credential_opens_a_working_session_without_the_recovery_phrase() {
    let mut env = TestEnv::spawn().await;
    user_with_a_passphrase(&mut env).await;

    // A fresh connection stands in for the next CLI invocation after the
    // daemon's in-memory sessions are gone.
    let mut fresh = KottonClient::connect_to(env.endpoint.clone())
        .await
        .expect("connect_to");

    assert_eq!(
        fresh.unlock_with_pin(USER, PASSPHRASE).await.expect("unlock"),
        PinUnlock::Unlocked
    );

    // The session is real, not just minted: an authenticated call succeeds on
    // this connection.
    let users = fresh.list_users().await.expect("list_users after unlock");
    assert!(
        users.contains(&USER.to_string()),
        "an unlocked session should be able to act; got {users:?}"
    );
}

/// RFC-0053 step 3, enforced end to end: the daemon refuses to *accept* a
/// credential too weak to survive offline guessing, on a device where nothing
/// outside Kotton counts failed attempts — which is every device today.
#[tokio::test]
async fn a_short_pin_is_refused_as_a_daily_credential() {
    let mut env = TestEnv::spawn().await;
    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");

    let err = env
        .client
        .set_lock_policy(USER, LockMode::Passphrase, 0, Some("135790"))
        .await
        .expect_err("a six-digit PIN must be refused");
    assert!(
        err.to_string().contains("hardware"),
        "the refusal should explain that nothing here counts failures, got: {err}"
    );

    // And the credential is unchanged — a refused set must not half-apply.
    //
    // This asserted `(false, true)` — *no* credential — until 2026-08-29, when
    // `create_user` began requiring one. The property under test is the same and
    // is now the stronger form of it: a refused change must leave the working
    // credential working, rather than leave the account with none. An assertion
    // that a refusal leaves nothing behind would, after this change, be
    // indistinguishable from a refusal that wiped it.
    let mut fresh = KottonClient::connect_to(env.endpoint.clone())
        .await
        .expect("connect_to");
    assert_eq!(
        fresh.get_unlock_methods(USER).await.expect("pre-auth"),
        (true, true),
        "the passphrase set at creation must survive a refused change"
    );
}

/// The budget refuses, over real IPC. Before step 2 it counted down to zero and
/// then went on verifying, so `attempts_remaining: 0` was advice rather than a
/// bound — and `UnlockWithPin` was reachable from a gateway session, which made
/// it a short secret on the network.
#[tokio::test]
async fn the_daemon_stops_checking_the_credential_once_the_budget_is_spent() {
    let mut env = TestEnv::spawn().await;
    user_with_a_passphrase(&mut env).await;

    let mut fresh = KottonClient::connect_to(env.endpoint.clone())
        .await
        .expect("connect_to");

    // Spend the budget. Each response counts down; the last one reports a wait
    // instead of a zero the user cannot act on.
    let mut spent = false;
    for _ in 0..10 {
        match fresh.unlock_with_pin(USER, "wrong-wrong-wrong").await.expect("unlock") {
            PinUnlock::Wrong { attempts_remaining } => {
                assert!(attempts_remaining > 0, "Wrong must always leave a try");
            }
            PinUnlock::RateLimited { retry_after_secs } => {
                assert!(retry_after_secs > 0);
                spent = true;
                break;
            }
            PinUnlock::Unlocked => panic!("a wrong credential must not unlock"),
        }
    }
    assert!(spent, "the attempt budget never refused");

    // And now the *correct* credential is refused too. A brake that only
    // rejected wrong ones would not be a brake: an attacker who guessed right on
    // the attempt after the budget ran out must still be turned away.
    assert!(
        matches!(
            fresh.unlock_with_pin(USER, PASSPHRASE).await.expect("unlock"),
            PinUnlock::RateLimited { .. }
        ),
        "a correct credential must be refused while the cooldown is in force"
    );

    // No session was minted along the way.
    let mut check = KottonClient::connect_to(env.endpoint.clone())
        .await
        .expect("connect_to");
    assert!(
        check.get_active_session().await.expect("get_active_session").is_none(),
        "a refused unlock must leave no session behind"
    );
}

/// The daily credential must give the **account** back, not only a session.
///
/// `UnlockWithPin` restores the operational roots to the secrets store, but a
/// user's `UserStore` binds its CEK at **load time** — so a daemon that started
/// before its user was unlocked holds a keyless store for the whole of its life.
/// Every VFS read and write against that user then fails while `UnlockOk` says
/// the account is open, and the failures are quiet: `list_members` turns its
/// error into an empty list, so a node reports success at every step and knows
/// nobody. The enrollment and recovery paths already call `reload_user_runtime`
/// for exactly this reason; the unlock path did not.
///
/// **The cold-daemon state is established here, not assumed.** The read is
/// asserted to fail *before* the unlock, so a change that left the store keyed
/// all along would fail this test rather than pass it vacuously.
#[tokio::test]
async fn the_daily_credential_gives_back_the_key_and_not_only_a_session() {
    let mut env = TestEnv::spawn().await;
    user_with_a_passphrase(&mut env).await;

    const PATH: &str = "/notes/ferry.txt";
    const BODY: &[u8] = b"8:40 on the Saturday";

    env.client.write_file(USER, PATH, BODY).await.expect("write while unlocked");
    assert_eq!(
        env.client.read_file(USER, PATH).await.expect("read while unlocked"),
        BODY
    );

    // The state every restart begins in. See the helper for why each step is the
    // product's own mechanism rather than a stub, and for the two ways of writing
    // it by hand that pass while asserting nothing.
    env.lock_as_a_restart_would(USER).await;

    env.client.read_file(USER, PATH).await.expect_err(
        "precondition: a keyless store must not be able to read the user's own file",
    );

    // A fresh connection stands in for the next CLI invocation after a restart.
    let mut fresh = KottonClient::connect_to(env.endpoint.clone())
        .await
        .expect("connect_to");
    assert_eq!(
        fresh.unlock_with_pin(USER, PASSPHRASE).await.expect("unlock"),
        PinUnlock::Unlocked
    );

    assert_eq!(
        fresh
            .read_file(USER, PATH)
            .await
            .expect("an unlocked account must be able to read its own data"),
        BODY,
        "unlock reported success, so the account's own file must open"
    );
}

/// A node that cannot read its own membership must say so, not say the person
/// knows nobody.
///
/// This is the second half of why the defect above went unseen for as long as it
/// did. `list_members` ended `unwrap_or_default()`, so a store that could not
/// open its own objects reported an **empty membership set** — and every computed
/// view is projected from that set, so the contact list, the People screens, the
/// paired-key allowlist and the vault's doors all went empty while every step
/// reported success. A wrong answer that is indistinguishable from a right one is
/// worse than an error, and it is what sent two sessions into the storage layers
/// looking for a listing bug that did not exist
/// (`TASK-listing-a-blinded-store-answers-in-blinded-keys`).
///
/// The contact is written first on purpose: with nobody there, "empty" would be
/// merely uninformative. With somebody there it is false.
#[tokio::test]
async fn a_cold_daemon_says_it_cannot_read_the_contacts_rather_than_that_there_are_none() {
    use kotton_peer::membership::Membership as _;
    use kotton_schemas::membership::{Ceremony, Member, Role};

    let mut env = TestEnv::spawn().await;
    user_with_a_passphrase(&mut env).await;

    let contact_did = "did:key:z6MkSomeoneTheyPairedWith";
    env.users
        .get(USER)
        .expect("the user is resident")
        .write_member(&Member {
            did: contact_did.to_string(),
            public_key: [9u8; 32],
            role: Role::Contact,
            admitted_by: Ceremony::Pairing,
            added_at: "2026-09-09T00:00:00Z".to_string(),
            posture: None,
            label: Some("sarah".to_string()),
            reach: None,
        })
        .await
        .expect("write the membership record while the account is open");

    let open = env.client.contact_list(USER).await.expect("list while unlocked");
    assert_eq!(open.len(), 1, "the contact is there to be missed: {open:?}");

    env.lock_as_a_restart_would(USER).await;

    // The whole property: refused, not empty.
    let err = env
        .client
        .contact_list(USER)
        .await
        .expect_err("a store that cannot open its own objects must not report zero contacts");
    let text = err.to_string();
    assert!(
        !text.is_empty(),
        "the refusal has to carry a reason a person can act on, got: {text}"
    );

    // And once the account is open again, the contact is back — so the refusal
    // above is about the lock and not about the record having gone missing.
    let mut fresh = KottonClient::connect_to(env.endpoint.clone())
        .await
        .expect("connect_to");
    assert_eq!(
        fresh.unlock_with_pin(USER, PASSPHRASE).await.expect("unlock"),
        PinUnlock::Unlocked
    );
    let after = fresh.contact_list(USER).await.expect("list after unlock");
    assert_eq!(after.len(), 1, "the contact survived the lock: {after:?}");
}

/// **Unlock ends** (`TASK-unlock-never-ends-and-nothing-reports-it`, `Done when` 4).
///
/// Before 2026-09-12 the daily credential opened custody for the life of the
/// daemon: `lock_identity` had no production caller and `auto_lock_minutes` was
/// stored and enforced nowhere, so a person whose twelve-hour session had
/// expired was asked for a passphrase to open a vault that never closed. This
/// walks the window end to end, over real IPC, on the verb `whoami` reads:
///
/// 1. unlocked, the verb reports a session with an end and a vault with an end;
/// 2. the window elapses and the sweep runs — the read refuses, the verb says
///    *locked*, and the session is **still live**, because they are two
///    lifetimes and closing one is not closing the other;
/// 3. the credential reopens the vault and re-arms the window from the policy.
///
/// The clock is not waited on. The deadline is moved into the past with the
/// primitive's own verb, and the sweep is called as the timer would call it —
/// "later" is the only thing being modelled, and it is modelled with the
/// product's mechanism rather than a stub.
#[tokio::test]
async fn custody_closes_when_its_window_elapses_and_the_credential_reopens_it() {
    let mut env = TestEnv::spawn().await;
    user_with_a_passphrase(&mut env).await;

    const PATH: &str = "/notes/window.txt";
    const BODY: &[u8] = b"locks at twelve";
    env.client.write_file(USER, PATH, BODY).await.expect("write while unlocked");

    // 1. Open, with an end — and the end is the policy's. `0` in the policy is
    // the default bound, not "never": that reading is what made the vault
    // stay open for the life of the daemon.
    let open = env.client.get_unlock_state(USER).await.expect("state while open");
    assert!(open.session_live, "create_user left this connection a session");
    assert!(open.session_until.is_some(), "a human session has an end");
    let now = now_secs();
    match open.custody {
        CustodyState::Open { until } => assert!(
            until > now && until <= now + kotton_secret::sealed_custody::DEFAULT_WINDOW_SECS,
            "custody opened by a credential closes within the default window, got until={until} now={now}"
        ),
        other => panic!("the vault is open and must say so, got {other:?}"),
    }

    // 2. The window elapses.
    assert!(
        env.runtime.custody().set_open_until(USER, now_secs() - 1),
        "precondition: the roots were in custody to have a window at all"
    );
    let closed =
        env.daemon.close_expired_custody(now_secs()).await;
    assert_eq!(closed, vec![USER.to_string()], "the sweep names what it closed");

    env.client
        .read_file(USER, PATH)
        .await
        .expect_err("a closed vault must refuse the user's own file, not read it from a store that kept the key");
    let locked = env.client.get_unlock_state(USER).await.expect("state while locked");
    assert_eq!(locked.custody, CustodyState::Locked);
    assert!(
        locked.session_live,
        "custody closing is not the session ending: the readout must show a live session and a locked vault, which is the state the report described"
    );

    // 3. The credential reopens it and re-arms the window — for a session that
    // is fresh, so the two ends arrive together again.
    let mut fresh = KottonClient::connect_to(env.endpoint.clone()).await.expect("connect_to");
    assert_eq!(
        fresh.unlock_with_pin(USER, PASSPHRASE).await.expect("unlock"),
        PinUnlock::Unlocked
    );
    assert_eq!(
        fresh.read_file(USER, PATH).await.expect("an unlocked account reads its own file"),
        BODY
    );
    let reopened = fresh.get_unlock_state(USER).await.expect("state after unlock");
    assert!(reopened.session_live);
    assert!(
        matches!(reopened.custody, CustodyState::Open { until } if until > now_secs()),
        "the credential re-armed the window, got {:?}",
        reopened.custody
    );
}

/// The window is the person's to set (RFC-0066: "the single dial trading
/// convenience against exposure, and it is the user's to set"). Minutes in the
/// policy are minutes on the deadline, and setting the policy — a credential
/// presented — is what arms it.
#[tokio::test]
async fn the_lock_policy_sets_the_length_of_the_window() {
    let mut env = TestEnv::spawn().await;
    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");

    let before = now_secs();
    env.client
        .set_lock_policy(USER, LockMode::Passphrase, 30, Some(PASSPHRASE))
        .await
        .expect("set_lock_policy");

    let state = env.client.get_unlock_state(USER).await.expect("state");
    match state.custody {
        CustodyState::Open { until } => assert!(
            (before + 30 * 60..=now_secs() + 30 * 60).contains(&until),
            "thirty minutes in the policy is thirty minutes on the window, got until={until}"
        ),
        other => panic!("setting a passphrase seals and opens the vault, got {other:?}"),
    }
}

/// **Custody closes on request** (`TASK-nothing-closes-custody-on-request`).
///
/// The security line of the window record: a person who can see their vault
/// is open should be able to close it before stepping away. `LockCustody` is
/// the same two steps the sweep takes — drop the roots, rebuild the store
/// cold — so the read refuses afterwards rather than succeeding from a store
/// that kept the key; and it is *not* `LockSession`: the session stays live,
/// which is what lets `whoami` afterwards say exactly which lifetime ended.
#[tokio::test]
async fn locking_custody_on_request_seals_the_vault_and_leaves_the_session() {
    let mut env = TestEnv::spawn().await;
    user_with_a_passphrase(&mut env).await;

    const PATH: &str = "/notes/away.txt";
    env.client.write_file(USER, PATH, b"back in five").await.expect("write while unlocked");

    env.client.lock_custody(USER).await.expect("lock");

    env.client
        .read_file(USER, PATH)
        .await
        .expect_err("a locked vault refuses the user's own file");
    let state = env.client.get_unlock_state(USER).await.expect("state");
    assert_eq!(state.custody, CustodyState::Locked);
    assert!(state.session_live, "locking the vault is not logging out");

    // Locking again is routine, and the credential reopens it.
    env.client.lock_custody(USER).await.expect("lock twice");
    let mut fresh = KottonClient::connect_to(env.endpoint.clone()).await.expect("connect_to");
    assert_eq!(
        fresh.unlock_with_pin(USER, PASSPHRASE).await.expect("unlock"),
        PinUnlock::Unlocked
    );
    assert_eq!(fresh.read_file(USER, PATH).await.expect("reads again"), b"back in five");
}
