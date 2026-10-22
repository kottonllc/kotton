// SPDX-License-Identifier: AGPL-3.0-or-later
//! A keychain that cannot be read, met at boot and at the two unlock doors: an
//! unreadable key is never taken for no key, and no new one is minted over it.
//!
//! A locked keychain is transient: the person unlocks it and their passphrase
//! is right. So an unreadable read at boot loads the person keyless — loaded is
//! not unlocked — and the next unlock makes them whole; and an
//! unreadable read at an unlock refuses that unlock, closes the session it just
//! opened, and writes nothing over the roots it could not read.

use super::*;
use kotton_app::daemon::apps::OccupantHost as _;
use kotton_common::crypto::kdf_labels;
use kotton_sys::secret::{SecretsError, SecretsResult};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex as StdMutex;

const PASSPHRASE: &str = "canyon-orbit-velvet-fish-hospital";

/// A platform keychain that can be locked: while `locked`, every read of one
/// of alice's roots fails, and every write is recorded.
#[derive(Default)]
struct Keychain {
    inner: kotton_secret::MemorySecrets,
    locked: AtomicBool,
    written_while_locked: StdMutex<Vec<String>>,
}

impl Keychain {
    fn is_alices_root(key: &str) -> bool {
        [
            kdf_labels::master_secret_keychain_key("alice"),
            kdf_labels::identity_signing_key("alice"),
            kdf_labels::operational_cek("alice"),
            kdf_labels::seed32_keychain_key("alice"),
        ]
        .iter()
        .any(|l| l == key)
    }
    fn written(&self) -> Vec<String> {
        self.written_while_locked.lock().unwrap().clone()
    }
}

impl SecretsStore for Keychain {
    fn get_secret(&self, key: &str) -> SecretsResult<Option<String>> {
        if self.locked.load(Ordering::SeqCst) && Self::is_alices_root(key) {
            return Err(SecretsError::Storage("the keychain did not answer".into()));
        }
        self.inner.get_secret(key)
    }
    fn set_secret(&self, key: &str, value: &str) -> SecretsResult<()> {
        if self.locked.load(Ordering::SeqCst) {
            self.written_while_locked.lock().unwrap().push(key.to_string());
        }
        self.inner.set_secret(key, value)
    }
    fn delete_secret(&self, key: &str) -> SecretsResult<()> {
        self.inner.delete_secret(key)
    }
}

/// Alice created at `base` over `keychain` with a passphrase vault, then the
/// process gone — her roots are in the vault, out of the platform store, as an
/// unlocked person's are after a restart.
async fn alice_created(base: &Path, keychain: &Arc<Keychain>) {
    let runtime = DeviceRuntime::new_with_secrets(
        base.to_path_buf(),
        kotton_device::config::RuntimeConfig::default(),
        keychain.clone(),
    )
    .await
    .unwrap();
    runtime.create_user("alice", PASSPHRASE).await.unwrap();
}

/// A daemon booting at `base` over `keychain`, the way a restart builds one.
async fn booted(base: &Path, keychain: &Arc<Keychain>) -> DeviceDaemon {
    #[cfg(unix)]
    let endpoint = IpcEndpoint::UnixSocket(base.join("kuserd.sock"));
    #[cfg(windows)]
    let endpoint = IpcEndpoint::NamedPipe(format!("kotton-test-{}", uuid::Uuid::new_v4().simple()));
    DeviceDaemon::new_with_base_secrets_and_relay(
        base.to_path_buf(),
        endpoint,
        keychain.clone(),
        RelayChoice::None,
    )
    .await
    .expect("the daemon boots")
}

fn sessions_for(ctx: &AgentContext, user: &str) -> usize {
    ctx.sessions.read().unwrap().values().filter(|s| s.user_id == user).count()
}

/// **A person whose keychain is locked at boot is whole after they unlock.**
/// Boot loads them keyless — the state a locked account boots into — and the
/// unlock, once the keychain answers, restores the roots and rekeys the
/// resident store, and starts the event log a locked boot could not. Skipping
/// them at boot left no resident store for any unlock to rekey, so the right
/// passphrase opened a session over nothing until the daemon restarted.
#[tokio::test]
async fn a_user_whose_keychain_is_locked_at_boot_is_whole_after_unlock() {
    let temp = tempfile::tempdir().unwrap();
    let keychain = Arc::new(Keychain::default());
    alice_created(temp.path(), &keychain).await;

    keychain.locked.store(true, Ordering::SeqCst);
    let daemon = booted(temp.path(), &keychain).await;
    let ctx = daemon.agent_context();
    let resident = ctx.users.get("alice").expect("alice is resident after a locked boot");
    assert!(resident.sealing_keys().is_none(), "keyless: the keychain could not be read");
    assert_eq!(keychain.written(), Vec::<String>::new(), "nothing was written while locked");

    keychain.locked.store(false, Ordering::SeqCst);
    let resp = dispatch::handle_request(
        &ctx,
        UserRequest::UnlockWithPin { user_id: "alice".into(), pin: kotton_wire::ipc::SecretText::new(PASSPHRASE), repair: false },
        kotton_ipc::Caller::anonymous(),
        Arc::new(std::sync::Mutex::new(None)),
    )
    .await
    .unwrap();
    assert!(matches!(resp, UserResponse::UnlockOk { .. }), "the unlock opens: {resp:?}");
    assert!(
        ctx.users.get("alice").unwrap().sealing_keys().is_some(),
        "the resident store is rebuilt with her keys"
    );
    // The account's event log, which a locked boot could not start (its
    // `agent.db` would not open), is started by the same rekey.
    assert!(
        ctx.event_log_tasks.lock().unwrap().contains_key("alice"),
        "the event log starts at the unlock, not only at the next restart"
    );
}

/// **The `UnlockWithPin` arm refuses an unlock whose roots it cannot read, and
/// closes the session it opened.** The credential was right, so
/// `try_unlock_with_pin` has already issued a token; the read that follows fails,
/// and the arm takes the token back and writes nothing.
#[tokio::test]
async fn the_unlock_arm_that_cannot_read_the_roots_refuses_and_keeps_no_session() {
    let temp = tempfile::tempdir().unwrap();
    let keychain = Arc::new(Keychain::default());
    alice_created(temp.path(), &keychain).await;
    let daemon = booted(temp.path(), &keychain).await;
    let ctx = daemon.agent_context();

    keychain.locked.store(true, Ordering::SeqCst);
    let resp = dispatch::handle_request(
        &ctx,
        UserRequest::UnlockWithPin { user_id: "alice".into(), pin: kotton_wire::ipc::SecretText::new(PASSPHRASE), repair: false },
        kotton_ipc::Caller::anonymous(),
        Arc::new(std::sync::Mutex::new(None)),
    )
    .await
    .unwrap();
    match &resp {
        UserResponse::Error { message } => {
            assert!(message.contains("the keychain did not answer"), "the read's error is named: {message}")
        }
        other => panic!("an unreadable keychain must refuse the unlock: {other:?}"),
    }
    assert_eq!(sessions_for(&ctx, "alice"), 0, "the session the credential opened was closed again");
    assert_eq!(keychain.written(), Vec::<String>::new(), "no root was restored over the unreadable ones");
}

/// **The lock screen's door refuses the same way** — `open_session`, reached
/// through `OccupantHost::unlock_with_pin`.
#[tokio::test]
async fn the_lock_screen_door_that_cannot_read_the_roots_refuses_and_keeps_no_session() {
    let temp = tempfile::tempdir().unwrap();
    let keychain = Arc::new(Keychain::default());
    alice_created(temp.path(), &keychain).await;
    let daemon = booted(temp.path(), &keychain).await;
    let ctx = daemon.agent_context();
    let host = occupant_host::occupant_host(
        &ctx.runtime,
        &ctx.users,
        &ctx.sessions,
        &ctx.base,
        &ctx.db,
        &ctx.record_stores,
        &ctx.ceremonies,
        &ctx.user_dbs,
        &ctx.event_log_tasks,
        &ctx.device_db,
        &ctx.connected_peers,
        &ctx.surface_proxy,
        ctx.browser_admissions(),
    );

    keychain.locked.store(true, Ordering::SeqCst);
    let err = host
        .unlock_with_pin("alice", PASSPHRASE)
        .await
        .expect_err("an unreadable keychain must refuse the unlock");
    assert!(format!("{err:?}").contains("the keychain did not answer"), "the read's error is named: {err:?}");
    assert_eq!(sessions_for(&ctx, "alice"), 0, "the session the credential opened was closed again");
    assert_eq!(keychain.written(), Vec::<String>::new(), "no root was restored over the unreadable ones");
}

/// What the compositor decides on when the shell starts: the user database the
/// window would open, through the call `compositor.rs` makes. `Locked` is the
/// arm that draws the unlock screen; anything else is "no shell can start".
async fn what_the_window_meets(ctx: &AgentContext) -> io::Error {
    match dispatch::user_db_for_compositor(&ctx.runtime, &ctx.users, &ctx.user_dbs, &ctx.base).await {
        Ok(_) => panic!("the user database opened; the window would draw the desk"),
        Err(e) => e,
    }
}

/// **After a boot over a keychain that cannot be read, the window offers the
/// unlock screen** — the error the compositor meets is `Locked`, not the
/// "will not open, no credential fixes it" arm. A locked keychain is transient,
/// and the screen is the only door a person at the machine has to the unlock
/// that makes them whole.
#[tokio::test]
async fn after_a_locked_keychain_boot_the_window_offers_the_unlock_screen() {
    let temp = tempfile::tempdir().unwrap();
    let keychain = Arc::new(Keychain::default());
    alice_created(temp.path(), &keychain).await;
    keychain.locked.store(true, Ordering::SeqCst);
    let daemon = booted(temp.path(), &keychain).await;
    let ctx = daemon.agent_context();

    let e = what_the_window_meets(&ctx).await;
    let locked = kotton_record::open::Locked::in_error(&e);
    assert!(locked.is_some(), "an unreadable keychain must reach the unlock screen, not \"no shell can start\": {e}");
    assert!(e.to_string().contains("the keychain did not answer"), "and say why: {e}");
}

/// **A user database that is genuinely corrupt still takes the "will not open"
/// path**: no unlock screen that could never succeed. The keychain answers and
/// holds the roots; the file is not a database.
#[tokio::test]
async fn a_corrupt_user_database_is_not_offered_the_unlock_screen() {
    let temp = tempfile::tempdir().unwrap();
    let keychain = Arc::new(Keychain::default());
    {
        let runtime = DeviceRuntime::new_with_secrets(
            temp.path().to_path_buf(),
            kotton_device::config::RuntimeConfig::default(),
            keychain.clone(),
        )
        .await
        .unwrap();
        runtime.create_user("alice", PASSPHRASE).await.unwrap();
        // The roots kept in the platform store, as an install without memory
        // custody keeps them, so the key resolves at the next boot.
        for label in [
            kdf_labels::master_secret_keychain_key("alice"),
            kdf_labels::identity_signing_key("alice"),
            kdf_labels::operational_cek("alice"),
        ] {
            let value = runtime.secrets().get_secret(&label).unwrap().expect("held");
            keychain.inner.set_secret(&label, &value).unwrap();
        }
    }
    std::fs::write(temp.path().join("users").join("alice").join("agent.db"), b"not a database at all, ever").unwrap();
    let daemon = booted(temp.path(), &keychain).await;
    let ctx = daemon.agent_context();

    let e = what_the_window_meets(&ctx).await;
    assert!(
        kotton_record::open::Locked::in_error(&e).is_none(),
        "a database that will not open must not be offered a credential prompt: {e}"
    );
}

/// **A repair with a credential that does not open the vault is refused as a
/// wrong passphrase, counted against the attempt budget, and writes nothing.**
/// The repair is an unlock — `UnlockWithPin` with `repair` set — so it answers
/// to the unlock's counted credential check before the vault is touched. A
/// repair that opened the vault first would be an uncounted oracle for the
/// passphrase, and a write reachable by anything that reaches the socket.
#[tokio::test]
async fn a_repair_without_the_owners_credential_is_refused_counted_and_writes_nothing() {
    let temp = tempfile::tempdir().unwrap();
    let keychain = Arc::new(Keychain::default());
    alice_created(temp.path(), &keychain).await;
    let daemon = booted(temp.path(), &keychain).await;
    let ctx = daemon.agent_context();

    keychain.locked.store(true, Ordering::SeqCst);
    let resp = dispatch::handle_request(
        &ctx,
        UserRequest::UnlockWithPin {
            user_id: "alice".into(),
            pin: kotton_wire::ipc::SecretText::new("not-the-passphrase-at-all"),
            repair: true,
        },
        kotton_ipc::Caller::anonymous(),
        Arc::new(std::sync::Mutex::new(None)),
    )
    .await
    .unwrap();
    assert!(
        matches!(resp, UserResponse::UnlockFailed { .. }),
        "a wrong credential is answered as one, and counted: {resp:?}"
    );
    assert_eq!(sessions_for(&ctx, "alice"), 0, "no session was opened");
    assert_eq!(keychain.written(), Vec::<String>::new(), "nothing was written without the credential");
}

/// **The repair reaches the account through the unlock arm, and opens it.**
/// After a restart the roots are in the vault and out of the store — absent, the
/// case the verb writes as it writes an unreadable one. `UnlockWithPin` with
/// `repair` and the right passphrase answers `UnlockOk` naming the labels it
/// wrote, and the resident store is rebuilt with the restored key, exactly as a
/// plain unlock leaves it.
#[tokio::test]
async fn the_unlock_arm_repairs_from_the_vault_and_reports_what_it_wrote() {
    let temp = tempfile::tempdir().unwrap();
    let keychain = Arc::new(Keychain::default());
    alice_created(temp.path(), &keychain).await;
    let daemon = booted(temp.path(), &keychain).await;
    let ctx = daemon.agent_context();

    let resp = dispatch::handle_request(
        &ctx,
        UserRequest::UnlockWithPin { user_id: "alice".into(), pin: kotton_wire::ipc::SecretText::new(PASSPHRASE), repair: true },
        kotton_ipc::Caller::anonymous(),
        Arc::new(std::sync::Mutex::new(None)),
    )
    .await
    .unwrap();
    match &resp {
        UserResponse::UnlockOk { repaired, .. } => assert_eq!(
            repaired.as_deref(),
            Some(&[
                kdf_labels::master_secret_keychain_key("alice"),
                kdf_labels::identity_signing_key("alice"),
                kdf_labels::operational_cek("alice"),
            ][..]),
            "the absent roots are written from the vault, and named"
        ),
        other => panic!("a repair with the owner's credential opens the account: {other:?}"),
    }
    assert!(
        ctx.users.get("alice").unwrap().sealing_keys().is_some(),
        "the resident store is rebuilt with her keys"
    );
}
