// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — the paths a daemon restart changes
//! (`TASK-the-suite-never-restarts-a-daemon`).
//!
//! Every real device is in one state every morning: the daemon has restarted, the
//! person has not yet presented their credential, and their store is resident with
//! no key. `TestEnv::lock_as_a_restart_would` puts a daemon there in one call. Each
//! test here writes something while the account is open, takes the daemon to that
//! state, and asks one question a person would ask of it.
//!
//! **The property is the same in every test: refused, never empty.** A node that
//! cannot read a person's data must say it cannot, because "you have no unread
//! messages" and "this node cannot look yet" are different sentences, and only one
//! of them is true. Each test writes the thing first so that *empty* would be
//! false rather than merely uninformative, and each ends by unlocking and finding
//! the thing again, so the refusal is shown to be about the lock and not about the
//! data having gone.
//!
//! Three paths the record names are covered elsewhere and not repeated here:
//! unlock and the contact list in `daily_credential`, and which app is the shell in
//! `daily_credential` and `app_lifecycle`.

use crate::common::TestEnv;
use kotton::PinUnlock;
use kotton_peer::membership::Membership as _;
use kotton_record::open::LOCKED;
use kotton_schemas::membership::{Ceremony, Member, Role};
use kotton_wire::{UserRequest, UserResponse};

const USER: &str = "morgan";
/// Five distinct wordlist words, above the RFC-0053 bar — `daily_credential`'s shape.
const PASSPHRASE: &str = "abandon-ability-able-about-above";

/// Create `USER` with a daily passphrase, so the restarted state has a credential
/// to be unlocked with, and return their identity.
async fn a_person_with_a_passphrase(env: &mut TestEnv) -> String {
    let (did, _) = env
        .client
        .create_user(USER, crate::common::TEST_PASSPHRASE)
        .await
        .expect("create_user");
    env.client
        .set_lock_policy(USER, kotton::LockMode::Passphrase, 0, Some(PASSPHRASE))
        .await
        .expect("set_lock_policy");
    did
}

/// Ask the badge's question over the wire, as the shell does.
async fn unread(env: &mut TestEnv) -> UserResponse {
    env.client
        .inner()
        .send(&UserRequest::MessageUnreadCount {
            user_id: USER.to_string(),
        })
        .await
        .expect("MessageUnreadCount is answered")
}

/// A contact card, written straight into the membership set as a pairing would.
fn a_contact() -> Member {
    Member {
        did: "did:key:z6MkSomeoneMorganPairedWith".to_string(),
        public_key: ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
            .verifying_key()
            .to_bytes(),
        role: Role::Contact,
        admitted_by: Ceremony::Pairing,
        added_at: "2026-09-25T00:00:00Z".to_string(),
        posture: None,
        label: Some("sam".to_string()),
        reach: None,
    }
}

/// **The unread count.** A badge that says *0* over a message nobody has read hides
/// the message; a badge that says *locked* tells the person what to do.
///
/// The inbox is asked too, because the count is a join over it and the two must
/// agree about why they cannot answer.
///
/// This test is also what found the third cache. Before 2026-09-25 the helper
/// dropped the resident store and the `agent.db` pool but not the `records.db`
/// store the message host had opened while the account was open, so both reads
/// below *succeeded* after it ran — the inbox listed the message, the badge
/// counted it — against a store no restarted process would still hold.
#[tokio::test]
async fn a_restarted_daemon_says_it_cannot_count_unread_rather_than_that_nothing_is() {
    let mut env = TestEnv::spawn().await;
    let me = a_person_with_a_passphrase(&mut env).await;

    env.client
        .message_send(USER, &me, "the ferry is at 8:40", None)
        .await
        .expect("a note to self, while the account is open");
    match unread(&mut env).await {
        UserResponse::MessageUnread { count } => {
            assert_eq!(count, 1, "the message is there to be missed")
        }
        other => panic!("an open account counts its unread messages, got {other:?}"),
    }

    env.lock_as_a_restart_would(USER).await;

    let err = env
        .client
        .message_poll_inbox(USER)
        .await
        .expect_err("a node that cannot open the record store must not list an inbox");
    assert!(
        err.to_string().contains(LOCKED),
        "the inbox's refusal says the account is locked, got: {err}"
    );
    match unread(&mut env).await {
        UserResponse::Error { message } => assert!(
            message.contains(LOCKED),
            "the badge's refusal says the account is locked, got: {message}"
        ),
        other => panic!("a locked node must refuse to count, not answer a number: {other:?}"),
    }

    assert_eq!(
        env.client.unlock_with_pin(USER, PASSPHRASE).await.expect("unlock"),
        PinUnlock::Unlocked
    );
    match unread(&mut env).await {
        UserResponse::MessageUnread { count } => {
            assert_eq!(count, 1, "the message survived the restart")
        }
        other => panic!("an unlocked account counts again, got {other:?}"),
    }
}

/// **The vault's door loop.** For each person renting a vault, the loop derives a
/// door per contact and hands the whole window over. From the restarted state the
/// contact set cannot be read, and the one wrong answer is an empty window: the
/// hand-off would succeed, the vault would hold nobody's door, and every message
/// sent to this person while their devices sleep would have nowhere to wait.
///
/// `doors_for` is the part of the loop that reads the lock state; the dial and the
/// hand-off need a rented node and are `vault`'s tests. It must refuse, so the loop
/// skips the pass and what the vault already holds stands.
#[tokio::test]
async fn the_door_window_is_refused_from_a_restarted_daemon_rather_than_handed_over_empty() {
    let mut env = TestEnv::spawn().await;
    a_person_with_a_passphrase(&mut env).await;
    let own_identity = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);

    env.users
        .get(USER)
        .expect("resident")
        .write_member(&a_contact())
        .await
        .expect("write the contact while the account is open");
    let open = kuserd::agent::doors_for(
        &env.users.get(USER).expect("resident"),
        &own_identity,
        &[],
    )
    .await
    .expect("an open account derives its doors");
    assert!(
        !open.is_empty(),
        "one contact is a window of doors, so an empty one below would be a loss"
    );

    env.lock_as_a_restart_would(USER).await;

    // Taken after the lock: the helper installs a new resident store, and the one
    // held above is the keyed store a restarted process would not have.
    let cold = env.users.get(USER).expect("still resident, bound to no key");
    let err = kuserd::agent::doors_for(&cold, &own_identity, &[])
        .await
        .expect_err("a node that cannot read its contacts must not hand its vault an empty window");
    // Not `LOCKED`: that constant is the database layer's word, and this refusal comes
    // from the object store, whose own sentence says *"If this is your device, it is
    // locked"*. What matters is the same — the reason in the log is the lock.
    assert!(
        format!("{err:#}").contains("it is locked"),
        "the refusal says the node is locked, got: {err:#}"
    );

    assert_eq!(
        env.client.unlock_with_pin(USER, PASSPHRASE).await.expect("unlock"),
        PinUnlock::Unlocked
    );
    let after = kuserd::agent::doors_for(
        &env.users.get(USER).expect("resident"),
        &own_identity,
        &[],
    )
    .await
    .expect("the unlocked account derives its doors again");
    assert_eq!(after.len(), open.len(), "the same contact, the same window");
}

/// **The device list.** Unlike the views above, the roster is not projected from
/// the sealed membership set: its rows are `paired_nodes`, the machine's own table
/// of whom this device may dial, which lives outside the person's key because the
/// daemon needs it to reach their other devices before anyone has unlocked. So from
/// the restarted state it answers — and must answer *the same rows*, because a
/// roster that went empty here would be the defect this record is about, arriving
/// by a different road.
///
/// What it does not carry is a name: those are in the membership set, and the
/// surface's roster reads each one best-effort, so a locked node shows its rows
/// without labels rather than hiding them.
#[tokio::test]
async fn a_restarted_daemon_still_lists_the_devices_it_has_paired() {
    let mut env = TestEnv::spawn().await;
    a_person_with_a_passphrase(&mut env).await;

    let other = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
    let other_did = "did:key:z6MkMorgansLaptop";
    env.client
        .peer_add(
            USER,
            "the-laptop",
            other_did,
            &hex::encode(other.verifying_key().to_bytes()),
            "127.0.0.1:7".parse().unwrap(),
        )
        .await
        .expect("pair a device while the account is open");
    let before = env.client.list_nodes(USER).await.expect("list while open");
    assert_eq!(before.len(), 1, "the device is there to be missed: {before:?}");

    env.lock_as_a_restart_would(USER).await;

    let cold = env
        .client
        .list_nodes(USER)
        .await
        .expect("the roster is the machine's, and answers from a restarted daemon");
    assert_eq!(
        cold.iter().map(|n| n.device_did.to_string()).collect::<Vec<_>>(),
        vec![other_did.to_string()],
        "the same device, not an empty roster"
    );

    assert_eq!(
        env.client.unlock_with_pin(USER, PASSPHRASE).await.expect("unlock"),
        PinUnlock::Unlocked
    );
    assert_eq!(
        env.client.list_nodes(USER).await.expect("list after unlock").len(),
        1,
        "and the same roster once the account is open"
    );
}

/// How a lock-path test closes custody: on request, or by the window running out.
#[derive(Clone, Copy, Debug)]
enum HowItLocks {
    /// `LockCustody`, the verb a person uses before stepping away.
    OnRequest,
    /// The sweep, after the window has elapsed — the lock nobody asks for.
    WindowElapsed,
}

/// **A lock is a restart's lock, not a smaller one.** `LockCustody` and the
/// window's sweep drop the roots and rebuild the resident store cold — and until
/// 2026-09-25 left the `records.db` store and the `agent.db` pool the account had
/// opened sitting in their caches, keyed. So the vault read as *locked* while the
/// inbox, the unread count and the app registry went on answering from handles
/// opened before the lock: the person's messages readable past it.
///
/// The restarted state is the reference. The same three reads that refuse after
/// `lock_as_a_restart_would` must refuse after either lock, and all three answer
/// again after the credential.
async fn a_lock_closes_what_the_account_had_open(how: HowItLocks) {
    let mut env = TestEnv::spawn().await;
    let me = a_person_with_a_passphrase(&mut env).await;

    env.client
        .message_send(USER, &me, "back in five", None)
        .await
        .expect("a note to self, which opens the record store");
    env.client.app_list().await.expect("app_list, which opens agent.db");

    match how {
        HowItLocks::OnRequest => env.client.lock_custody(USER).await.expect("lock"),
        HowItLocks::WindowElapsed => {
            let now = kotton_common::time::now_secs();
            assert!(
                env.runtime.custody().set_open_until(USER, now - 1),
                "precondition: the roots were in custody to have a window at all"
            );
            assert_eq!(
                env.daemon.close_expired_custody(now).await,
                vec![USER.to_string()],
                "the sweep closed this account"
            );
        }
    }

    let err = env
        .client
        .message_poll_inbox(USER)
        .await
        .expect_err("a locked account's inbox must not be read from a store opened before the lock");
    assert!(err.to_string().contains(LOCKED), "{how:?}: the inbox says locked, got: {err}");
    match unread(&mut env).await {
        UserResponse::Error { message } => assert!(
            message.contains(LOCKED),
            "{how:?}: the badge says locked, got: {message}"
        ),
        other => panic!("{how:?}: a locked account must refuse to count, got {other:?}"),
    }
    let err = env
        .client
        .app_list()
        .await
        .expect_err("a locked account's app registry must not be read from a pool opened before the lock");
    assert!(err.to_string().contains(LOCKED), "{how:?}: the registry says locked, got: {err}");

    assert_eq!(
        env.client.unlock_with_pin(USER, PASSPHRASE).await.expect("unlock"),
        PinUnlock::Unlocked
    );
    assert_eq!(
        env.client.message_poll_inbox(USER).await.expect("the inbox after unlock").len(),
        1,
        "the message survived the lock"
    );
    match unread(&mut env).await {
        UserResponse::MessageUnread { count } => assert_eq!(count, 1, "and is still unread"),
        other => panic!("an unlocked account counts again, got {other:?}"),
    }
    env.client.app_list().await.expect("the registry after unlock");
}

#[tokio::test]
async fn locking_custody_closes_what_the_account_had_open() {
    a_lock_closes_what_the_account_had_open(HowItLocks::OnRequest).await;
}

#[tokio::test]
async fn the_window_closing_closes_what_the_account_had_open() {
    a_lock_closes_what_the_account_had_open(HowItLocks::WindowElapsed).await;
}

/// **A threshold signature, asked of a locked node that is not enrolled in one.** The
/// answer is the lock, not *"no FROST share on this node"*.
///
/// `threshold_sign` reads the membership set before it reads the share, so a locked
/// node refuses before it touches any signing material, and says the same thing
/// whether or not it holds a share. The two-node case — an enrolled node, a co-signer
/// listening, the signature produced again after the unlock — is
/// `enroll_threshold_sign::a_locked_coordinator_says_it_is_locked_rather_than_that_it_has_no_co_signers`;
/// this is the half that asks about the order
/// (`TASK-a-locked-node-reports-no-co-signers-rather-than-that-it-is-locked`).
#[tokio::test]
async fn a_restarted_daemon_answers_a_signing_request_with_the_lock_first() {
    let mut env = TestEnv::spawn().await;
    a_person_with_a_passphrase(&mut env).await;

    let before = env
        .client
        .threshold_sign(USER, b"asked of a node with no share")
        .await
        .expect_err("a node enrolled in no threshold cannot sign")
        .to_string();
    assert!(
        before.contains("no FROST share"),
        "while open, the refusal is the missing share, got: {before}"
    );

    env.lock_as_a_restart_would(USER).await;

    let after = env
        .client
        .threshold_sign(USER, b"asked of a node with no share")
        .await
        .expect_err("a locked node cannot sign")
        .to_string();
    assert!(
        after.contains("it is locked") && !after.contains("FROST share"),
        "once locked, the refusal is the lock and not the share, got: {after}"
    );
}

/// Put one line of `USER`'s activity on the daemon's bus, as any verb of theirs would.
fn say(env: &TestEnv, line: &str) {
    env.runtime
        .event_bus()
        .publish(kotton_diag::service::Event::for_user(
            USER,
            kotton_diag::service::EventCategory::Auth,
            kotton_diag::service::EventLevel::Info,
            line,
        ))
        .expect("the bus has subscribers: the device log is always one");
}

/// The lines of `USER`'s own event log, read over the wire as `kotton events` does.
async fn logged(env: &mut TestEnv) -> Vec<String> {
    env.client
        .query_events(Some("auth".to_string()), None, None, Some(500))
        .await
        .expect("an open account's event log is read")
        .into_iter()
        .map(|e| e.message)
        .collect()
}

/// Say `line`, then wait until it is in the log. A bounded wait rather than a sleep:
/// the log is a task on the bus, and what is being waited for is its write.
async fn logs_again(env: &mut TestEnv, line: &str) -> bool {
    say(env, line);
    for _ in 0..300 {
        if logged(env).await.iter().any(|m| m == line) {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    false
}

/// **An account's event log follows its custody, not the process.** The log is a
/// task that owns a clone of the account's `agent.db` pool and chains every line
/// under the account's key. Until 2026-09-26 it was started once at boot, for
/// whoever was open then, and nothing else started or stopped it — so a daemon
/// that restarted locked never logged the person's activity again after they
/// unlocked, and a `LockCustody` left the task writing through a keyed pool the
/// lock was meant to have let go
/// (`TASK-an-accounts-event-log-lives-by-the-process-and-not-by-the-lock`).
///
/// One morning of a person's day, in order: the restarted state, the credential,
/// `LockCustody` before stepping away, the credential again, and a restart after
/// the log has been running. After each unlock a line of theirs reaches the log;
/// a line said while they were locked never does, because no task was there to
/// write it. The last line — said after the account had been locked by request
/// and by restart — is the proof that neither lock took anything that the next
/// credential does not give back.
#[tokio::test]
async fn an_accounts_event_log_stops_at_the_lock_and_starts_at_the_credential() {
    let mut env = TestEnv::spawn().await;
    a_person_with_a_passphrase(&mut env).await;

    // From the restarted state: the daemon holds the account with no key, so it
    // runs no log for them — and the credential has to start one.
    env.lock_as_a_restart_would(USER).await;
    say(&env, "said by a restarted, locked account");
    assert_eq!(
        env.client.unlock_with_pin(USER, PASSPHRASE).await.expect("unlock"),
        PinUnlock::Unlocked
    );
    assert!(
        logs_again(&mut env, "said after the first credential").await,
        "an account unlocked after a restart logs its activity again"
    );

    // From `LockCustody`: the running log stops with the lock, so what the account
    // does while locked is written by nobody, and the credential starts it again.
    env.client.lock_custody(USER).await.expect("lock");
    say(&env, "said while locked on request");
    assert_eq!(
        env.client.unlock_with_pin(USER, PASSPHRASE).await.expect("unlock"),
        PinUnlock::Unlocked
    );
    assert!(
        logs_again(&mut env, "said after the second credential").await,
        "an account unlocked after LockCustody logs its activity again"
    );

    // And a restart of a daemon whose log was running: the old task does not
    // survive to stand in for the new one.
    env.lock_as_a_restart_would(USER).await;
    say(&env, "said by a restarted account that had been logging");
    assert_eq!(
        env.client.unlock_with_pin(USER, PASSPHRASE).await.expect("unlock"),
        PinUnlock::Unlocked
    );
    assert!(
        logs_again(&mut env, "said after the third credential").await,
        "a restart of a logging account leaves the credential a log to start"
    );

    let log = logged(&mut env).await;
    for locked in [
        "said by a restarted, locked account",
        "said while locked on request",
        "said by a restarted account that had been logging",
    ] {
        assert!(
            !log.iter().any(|m| m == locked),
            "nothing may write an account's log while it is locked, found {locked:?} in {log:?}"
        );
    }
    assert_eq!(
        env.client.verify_event_log(USER).await.expect("verify"),
        (true, None),
        "and what the restarted logs wrote chains under the account's own key"
    );
}

/// **An identity made in a daemon that is already running has its own event log
/// from creation.** `spawn_user_event_log` ran at boot for every resident account
/// and again in `rekey_resident_store` when a credential reopens one, but
/// `create_user` — the door a freshly minted identity is made through, keyed from
/// the start — started neither, so its activity was logged only after the next
/// restart found it unlocked
/// (`TASK-an-identity-made-in-a-running-daemon-keeps-no-event-log`). `create_user`
/// now starts the log beside its bundled-app install, the same point
/// `rekey_resident_store` starts it: the first time this identity's `agent.db`
/// opens with a key.
#[tokio::test]
async fn a_new_identity_has_its_event_log() {
    let mut env = TestEnv::spawn().await;
    a_person_with_a_passphrase(&mut env).await;

    assert!(
        logs_again(&mut env, "said by a freshly created identity").await,
        "an identity created in an already-running daemon logs its activity \
         with no restart or unlock between"
    );
}

/// `USER`'s identity key, as the node holds it now.
fn identity_key(env: &TestEnv) -> ed25519_dalek::SigningKey {
    let label = kotton_common::crypto::kdf_labels::identity_signing_key(USER);
    let hex_key = env
        .runtime
        .secrets()
        .get_secret(&label)
        .unwrap()
        .expect("the identity key is held while the account is open");
    let bytes: [u8; 32] = hex::decode(hex_key).unwrap().try_into().unwrap();
    ed25519_dalek::SigningKey::from_bytes(&bytes)
}

/// **A rotation, and then the morning after it.** The vault is the durable copy of
/// the person's roots, so what it seals is what the node holds after every restart.
/// A rotation that changed the key in memory and left the vault sealing the old
/// one would be undone by the first unlock: the node would sign with the key the
/// person retired, and nothing sealed to the new one would open
/// (`TASK-a-rotation-leaves-the-pin-vault-holding-the-key-it-retired`).
///
/// The other direction is asked too. A note written before the rotation was
/// sealed to the key it retired, and still opens after the restart — on the
/// retired-key set, which is sealed to the new key and so opens only if the vault
/// restored the new one.
#[tokio::test]
async fn a_rotated_key_is_still_the_key_after_a_restart_and_an_unlock() {
    let mut env = TestEnv::spawn().await;
    let me = a_person_with_a_passphrase(&mut env).await;

    env.client
        .message_send(USER, &me, "the spare key is under the blue pot", None)
        .await
        .expect("a note to self, sealed to the key about to be retired");
    let note = env.client.message_poll_inbox(USER).await.expect("the inbox");
    assert_eq!(note.len(), 1, "one note: {note:?}");
    let field = |k: &str| note[0].get(k).and_then(|v| v.as_str()).expect(k).to_string();
    let (body, nonce, eph) = (field("body"), field("nonce"), field("ephemeral_pub"));

    let old_key = identity_key(&env);
    let phrase = env.client.add_recovery_phrase(USER).await.expect("a recovery phrase");
    let new_key_hex = env
        .client
        .rotate_identity(USER, &phrase, Some(PASSPHRASE))
        .await
        .expect("rotate_identity");
    assert_eq!(hex::encode(identity_key(&env).verifying_key().to_bytes()), new_key_hex);
    assert_ne!(identity_key(&env).to_bytes(), old_key.to_bytes(), "the rotation replaced the key");

    env.lock_as_a_restart_would(USER).await;
    assert_eq!(
        env.client.unlock_with_pin(USER, PASSPHRASE).await.expect("unlock"),
        PinUnlock::Unlocked
    );

    let after = identity_key(&env);
    assert_eq!(
        hex::encode(after.verifying_key().to_bytes()),
        new_key_hex,
        "the unlock restored the rotated key, not the one the rotation retired ({})",
        hex::encode(old_key.verifying_key().to_bytes())
    );
    assert_eq!(
        env.client
            .message_decrypt_dm(USER, &body, &nonce, &eph)
            .await
            .expect("a note sealed to the retired key opens after the restart"),
        "the spare key is under the blue pot"
    );
}
