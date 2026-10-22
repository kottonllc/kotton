// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `SetLockPolicy` arm, met by a seal that fails.
//!
//! The passphrase on record names the one that opens the device's sealed copy
//! of the person's keys, so the arm judges the new one, seals under it, and
//! records it only once that copy is written. A seal that fails is a refusal,
//! and the record and the copy are both the ones the device had before. A
//! record that fails after the seal is a refusal too, and the disagreement it
//! leaves is refused at both unlock doors rather than opened as a session that
//! restores no key.

use super::*;
use kotton_app::daemon::apps::OccupantHost as _;
use kotton_session::lock_policy;
use kotton_wire::ipc::LockMode;

const OLD: &str = "canyon-orbit-velvet-fish-hospital";
const NEW: &str = "lantern-quarry-meadow-socket-ribbon";

type Conn = Arc<std::sync::Mutex<Option<ConnSessionData>>>;

/// Alice created at `base` with `OLD`, then the process gone; a daemon booted
/// over the same keychain, as a restart builds one.
async fn alice_booted(base: &Path) -> DeviceDaemon {
    let secrets: Arc<dyn SecretsStore> = Arc::new(kotton_secret::MemorySecrets::default());
    let runtime =
        DeviceRuntime::new_with_secrets(base.to_path_buf(), RuntimeConfig::default(), secrets.clone())
            .await
            .unwrap();
    runtime.create_user("alice", OLD).await.unwrap();
    drop(runtime);
    #[cfg(unix)]
    let endpoint = IpcEndpoint::UnixSocket(base.join("kuserd.sock"));
    #[cfg(windows)]
    let endpoint = IpcEndpoint::NamedPipe(format!("kotton-test-{}", uuid::Uuid::new_v4().simple()));
    DeviceDaemon::new_with_base_secrets_and_relay(base.to_path_buf(), endpoint, secrets, RelayChoice::None)
        .await
        .expect("the daemon boots")
}

async fn send(ctx: &AgentContext, conn: &Conn, request: UserRequest) -> UserResponse {
    dispatch::handle_request(ctx, request, kotton_ipc::Caller::anonymous(), conn.clone())
        .await
        .unwrap()
}

/// A connection holding alice's session, opened with `pass`.
async fn unlocked(ctx: &AgentContext, pass: &str) -> (Conn, UserResponse) {
    let conn: Conn = Arc::new(std::sync::Mutex::new(None));
    let resp = send(
        ctx,
        &conn,
        UserRequest::UnlockWithPin { user_id: "alice".into(), pin: kotton_wire::ipc::SecretText::new(pass), repair: false },
    )
    .await;
    (conn, resp)
}

fn set_passphrase(pass: &str) -> UserRequest {
    UserRequest::SetLockPolicy {
        user_id: "alice".into(),
        mode: LockMode::Passphrase,
        auto_lock_minutes: 0,
        pin: Some(kotton_wire::ipc::SecretText::new(pass)),
    }
}

fn vault(ctx: &AgentContext) -> PathBuf {
    ctx.runtime.base_dir().join("users").join("alice").join("vault.json")
}

fn auth(ctx: &AgentContext) -> PathBuf {
    ctx.base.join("device").join("users").join("alice").join("auth.json")
}

fn sessions_for(ctx: &AgentContext, user: &str) -> usize {
    ctx.sessions.read().unwrap().values().filter(|s| s.user_id == user).count()
}

/// Alice unlocked with `OLD`, then `NEW` set while the record cannot be
/// written: a directory stands where the record's temporary file goes, so the
/// seal succeeds and the record that follows it fails. Returns her connection.
async fn record_fails_after_the_seal(ctx: &AgentContext) -> Conn {
    let (conn, opened) = unlocked(ctx, OLD).await;
    assert!(matches!(opened, UserResponse::UnlockOk { .. }), "alice unlocks: {opened:?}");
    let (auth_before, vault_before) = (read(&auth(ctx)), read(&vault(ctx)));
    let obstacle = auth(ctx).with_extension("json.tmp");
    std::fs::create_dir(&obstacle).unwrap();

    match send(ctx, &conn, set_passphrase(NEW)).await {
        UserResponse::Error { message } => {
            assert!(message.contains("could not be recorded"), "the refusal says so: {message}");
            assert!(message.contains("the record still names"), "and what is on record: {message}");
        }
        other => panic!("a record that failed must refuse, not answer {other:?}"),
    }
    assert_eq!(read(&auth(ctx)), auth_before, "the old record is whole, not truncated");
    assert_ne!(read(&vault(ctx)), vault_before, "the copy is sealed under the new passphrase");
    std::fs::remove_dir(&obstacle).unwrap();
    conn
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"))
}

/// **A seal that fails refuses, and changes neither the record nor the copy.**
/// The vault is replaced through a temporary file beside it; a directory in
/// that file's place makes the write, and so the seal, fail. Before the arm
/// sealed first, it had already recorded the new passphrase by then, and
/// answered `LockPolicySet` over a copy still sealed under the old one.
#[tokio::test]
async fn a_passphrase_the_device_cannot_seal_under_is_refused_and_not_recorded() {
    let temp = tempfile::tempdir().unwrap();
    let daemon = alice_booted(temp.path()).await;
    let ctx = daemon.agent_context();
    let (conn, opened) = unlocked(&ctx, OLD).await;
    assert!(matches!(opened, UserResponse::UnlockOk { .. }), "alice unlocks: {opened:?}");

    let (auth_before, vault_before) = (read(&auth(&ctx)), read(&vault(&ctx)));
    let obstacle = vault(&ctx).with_extension("json.tmp");
    std::fs::create_dir(&obstacle).unwrap();

    match send(&ctx, &conn, set_passphrase(NEW)).await {
        UserResponse::Error { message } => {
            assert!(message.contains("the passphrase was not changed"), "the refusal says so: {message}");
            assert!(message.contains("the one it had before"), "and what is on record: {message}");
        }
        other => panic!("a seal that failed must refuse, not answer {other:?}"),
    }
    assert_eq!(read(&auth(&ctx)), auth_before, "the passphrase on record is unchanged");
    assert_eq!(read(&vault(&ctx)), vault_before, "the sealed copy is unchanged");
    let (_, new_unlock) = unlocked(&ctx, NEW).await;
    assert!(
        matches!(new_unlock, UserResponse::UnlockFailed { .. }),
        "the passphrase that was refused does not unlock: {new_unlock:?}"
    );

    // What the refusal tells the person to do: fix the cause and set it again.
    std::fs::remove_dir(&obstacle).unwrap();
    let (conn, opened) = unlocked(&ctx, OLD).await;
    assert!(matches!(opened, UserResponse::UnlockOk { .. }), "the old passphrase still unlocks: {opened:?}");
    let set = send(&ctx, &conn, set_passphrase(NEW)).await;
    assert!(matches!(set, UserResponse::LockPolicySet), "the retry sets it: {set:?}");
    assert_ne!(read(&vault(&ctx)), vault_before, "and seals the copy under it");
    let (_, new_unlock) = unlocked(&ctx, NEW).await;
    assert!(matches!(new_unlock, UserResponse::UnlockOk { .. }), "the new passphrase unlocks: {new_unlock:?}");
}

/// **A passphrase too weak to record seals nothing.** It is judged before the
/// seal, so the copy is not re-sealed under a passphrase the record would then
/// refuse to name.
#[tokio::test]
async fn a_passphrase_too_weak_to_record_seals_nothing() {
    let temp = tempfile::tempdir().unwrap();
    let daemon = alice_booted(temp.path()).await;
    let ctx = daemon.agent_context();
    let (conn, opened) = unlocked(&ctx, OLD).await;
    assert!(matches!(opened, UserResponse::UnlockOk { .. }), "alice unlocks: {opened:?}");

    let (auth_before, vault_before) = (read(&auth(&ctx)), read(&vault(&ctx)));
    let resp = send(&ctx, &conn, set_passphrase("123456")).await;
    assert!(matches!(resp, UserResponse::Error { .. }), "a weak passphrase is refused: {resp:?}");
    assert_eq!(read(&auth(&ctx)), auth_before, "the passphrase on record is unchanged");
    assert_eq!(read(&vault(&ctx)), vault_before, "and nothing was sealed under the weak one");
    assert!(lock_policy::load(&ctx.base, "alice").unwrap().pin_hash.is_some());
}

/// **A record that fails after the seal is refused, and setting it again on the
/// session that still holds the keys makes the copy and the record agree.**
#[tokio::test]
async fn a_passphrase_sealed_but_not_recorded_is_refused_and_set_again_on_the_same_session() {
    let temp = tempfile::tempdir().unwrap();
    let daemon = alice_booted(temp.path()).await;
    let ctx = daemon.agent_context();
    let conn = record_fails_after_the_seal(&ctx).await;

    let set = send(&ctx, &conn, set_passphrase(NEW)).await;
    assert!(matches!(set, UserResponse::LockPolicySet), "the retry records it: {set:?}");

    // The keys out of memory, so the unlock has to restore them from the copy:
    // only then does an unlock show the copy and the record agree.
    assert!(ctx.runtime.custody().lock_identity("alice"), "alice's keys were held");
    let (_, new_unlock) = unlocked(&ctx, NEW).await;
    assert!(
        matches!(new_unlock, UserResponse::UnlockOk { .. }),
        "the new passphrase is on record and opens the copy: {new_unlock:?}"
    );
    assert!(
        ctx.users.get("alice").unwrap().sealing_keys().is_some(),
        "the unlock restored her keys from the copy"
    );
    let (_, old_unlock) = unlocked(&ctx, OLD).await;
    assert!(
        matches!(old_unlock, UserResponse::UnlockFailed { .. }),
        "the old passphrase is no longer on record: {old_unlock:?}"
    );
}

/// **The copy and the record left disagreeing open no session at either door.**
/// Once the keys leave memory, the old passphrase matches the record and does
/// not open the copy: both doors refuse it, say so, and keep no session. The
/// new one is refused by the record.
#[tokio::test]
async fn a_passphrase_sealed_but_not_recorded_opens_no_session_once_the_keys_are_gone() {
    let temp = tempfile::tempdir().unwrap();
    let daemon = alice_booted(temp.path()).await;
    let ctx = daemon.agent_context();
    let _conn = record_fails_after_the_seal(&ctx).await;
    assert!(ctx.runtime.custody().lock_identity("alice"), "alice's keys were held");
    let held = sessions_for(&ctx, "alice");

    let (_, old_unlock) = unlocked(&ctx, OLD).await;
    match old_unlock {
        UserResponse::Error { message } => assert!(
            message.contains("does not open under it"),
            "the refusal says the copy does not open under the passphrase on record: {message}"
        ),
        other => panic!("an unlock that restores no key must be refused, not answered {other:?}"),
    }
    assert_eq!(sessions_for(&ctx, "alice"), held, "the arm kept no session");

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
    let err = host
        .unlock_with_pin("alice", OLD)
        .await
        .expect_err("the lock screen's door refuses the same unlock");
    assert!(format!("{err:?}").contains("does not open under it"), "and says why: {err:?}");
    assert_eq!(sessions_for(&ctx, "alice"), held, "the lock screen's door kept no session");

    let (_, new_unlock) = unlocked(&ctx, NEW).await;
    assert!(
        matches!(new_unlock, UserResponse::UnlockFailed { .. }),
        "the passphrase that was not recorded is refused by the record: {new_unlock:?}"
    );
}
