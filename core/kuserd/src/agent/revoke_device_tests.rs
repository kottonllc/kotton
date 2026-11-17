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
/// one nothing can reach. A vault (`BlindStorage`) is recorded as a drive, as
/// enrolling it does (`kotton_peer::daemon::drives`).
async fn paired(db: &Arc<SqlitePool>, id: &str, seed: u8, posture: kotton_schemas::membership::Posture) {
    let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes();
    let did = kotton_crypto::DidKeyMethod::from_public_key_bytes(&key).unwrap();
    kotton_peer::daemon::db::insert_paired_node(db, id, "alice", &did.to_string(), &key, "[]", 0, Some(posture.as_str()))
        .await
        .unwrap();
    if posture == kotton_schemas::membership::Posture::BlindStorage {
        kotton_peer::daemon::drives::record(db, "alice", &key).await.unwrap();
    }
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

/// **The occupant reaches rows only** (kottonllc/kotton#597, 33A): an own-device
/// member of alice's set with no row, under each key vector the Ed25519 rule
/// refuses, is not found by `DaemonOccupantHost::revoke_device` given its DID as
/// stored, and stays in the set; the occupant's roster lists the rows and nothing
/// for it.
#[tokio::test]
async fn the_occupants_revoke_does_not_reach_a_member_with_no_row() {
    use kotton_peer::membership::{MemberStore as _, Membership as _};
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
    paired(&ctx.db, "laptop", 6, Posture::Full).await;
    let rows: Vec<String> = kotton_peer::daemon::db::list_paired_nodes(&ctx.db, "alice")
        .await
        .unwrap()
        .iter()
        .map(|n| n.device_did.to_string())
        .collect();
    let set = daemon.users().get("alice").expect("alice is loaded");

    for (name, bytes) in kotton_crypto::ed25519::refused_keys() {
        let did = kotton_crypto::DidKeyMethod::spelled_over(&bytes).to_string();
        let member = kotton_schemas::membership::Member {
            did: did.clone(),
            public_key: bytes,
            role: kotton_schemas::membership::Role::OwnDevice,
            admitted_by: kotton_schemas::membership::Ceremony::DeviceEnroll,
            added_at: "2026-11-17T00:00:00Z".to_string(),
            posture: Some(Posture::Full),
            label: Some("old".to_string()),
            reach: None,
        };
        // As an earlier build wrote it: `write_member` refuses such bytes.
        set.member_write(&member.vfs_path(), &serde_json::to_vec(&member).unwrap()).await.unwrap();

        let refused = host.revoke_device(&did).await.expect_err("the occupant revoked a member with no row");
        assert!(refused.contains("not found"), "{name}: {refused}");
        assert_eq!(set.list_members().await.unwrap(), vec![member.clone()], "{name}: the occupant removed the member");
        let listed: Vec<String> = host.list_devices().await.unwrap().into_iter().map(|d| d.did).collect();
        assert_eq!(listed, rows, "{name}: the occupant's roster is not the rows");

        // The next vector's member is written at the same path; this one goes first.
        for f in set.list_found().await.unwrap().iter().filter(|f| f.member.did == did) {
            set.remove_found(f).await.unwrap();
        }
    }
}
