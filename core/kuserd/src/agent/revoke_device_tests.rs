// SPDX-License-Identifier: AGPL-3.0-or-later
//! The shell's revoke reads the answer: `DaemonOccupantHost::revoke_device`
//! is an error when the revoke is — a device nobody paired, and a revoke a
//! drive did not take — and never success.
//!
//! Through a booted daemon and the host built over its own context, as
//! `message_open_tests` builds it.

use super::*;
use kotton_app::daemon::apps::OccupantHost as _;

const PASSPHRASE: &str = "canyon-orbit-velvet-fish-hospital";

/// A daemon booted at `base` with alice created.
async fn alice_at(base: &Path) -> DeviceDaemon {
    let keychain: Arc<dyn SecretsStore + Send + Sync> = Arc::new(kotton_secret::MemorySecrets::new());
    let runtime = DeviceRuntime::new_with_secrets(
        base.to_path_buf(),
        kotton_device::config::RuntimeConfig::default(),
        keychain.clone(),
    )
    .await
    .unwrap();
    runtime.create_user("alice", PASSPHRASE).await.unwrap();
    drop(runtime);
    #[cfg(unix)]
    let endpoint = IpcEndpoint::UnixSocket(base.join("kuserd.sock"));
    #[cfg(windows)]
    let endpoint = IpcEndpoint::NamedPipe(format!("kotton-test-{}", uuid::Uuid::new_v4().simple()));
    let daemon = DeviceDaemon::new_with_base_secrets_and_relay(base.to_path_buf(), endpoint, keychain, RelayChoice::None)
        .await
        .expect("the daemon boots");
    let resp = dispatch::handle_request(
        &daemon.agent_context(),
        UserRequest::UnlockWithPin { user_id: "alice".into(), pin: kotton_wire::ipc::SecretText::new(PASSPHRASE), repair: false },
        kotton_ipc::Caller::anonymous(),
        Arc::new(std::sync::Mutex::new(None)),
    )
    .await
    .unwrap();
    assert!(matches!(resp, UserResponse::UnlockOk { .. }), "alice unlocks: {resp:?}");
    let aid = daemon.agent_context().users.get("alice").expect("alice resident").did().to_string();
    crate::device_users::register(base, "alice", &aid, None).unwrap();
    daemon
}

/// Pair `id` to alice at `posture`, with no address: a drive so recorded is
/// one nothing can reach.
async fn paired(db: &Arc<SqlitePool>, id: &str, seed: u8, posture: kotton_schemas::membership::Posture) {
    let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes();
    let did = kotton_crypto::DidKeyMethod::from_public_key_bytes(&key).unwrap();
    kotton_peer::daemon::db::insert_paired_node(db, id, "alice", &did.to_string(), &key, "[]", 0, Some(posture.as_str()))
        .await
        .unwrap();
}

/// **A revoke the daemon answered with an error is an error at the shell's
/// door**: a device nobody paired, and a device revoked here that a drive
/// still admits. Discarding the answer, as the door did, turns both green.
#[tokio::test]
async fn the_shells_revoke_is_an_error_for_a_device_not_paired_and_for_a_revoke_a_drive_did_not_take() {
    use kotton_schemas::membership::Posture;
    let temp = tempfile::tempdir().unwrap();
    let daemon = alice_at(temp.path()).await;
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

    let missing = host.revoke_device("nobody-paired-this").await.expect_err("a missing device was revoked");
    assert!(missing.contains("not found"), "{missing}");

    paired(&ctx.db, "laptop", 6, Posture::Full).await;
    paired(&ctx.db, "vault", 9, Posture::BlindStorage).await;
    let partial = host.revoke_device("laptop").await.expect_err("a revoke no drive took was success");
    assert!(partial.contains("still admits it: vault ("), "{partial}");
    assert!(partial.contains("will not reach it"), "{partial}");
}
