// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — M28 peer sync wiring
//!
//! These tests exercise the M28 additions:
//!
//! * `RemoteBackend::Kotton` protocol variant (serde roundtrip)
//! * Error path: adding a Kotton remote with an unknown peer DID
//! * Sync over a local remote (validates `SyncMount` end-to-end without QUIC)
//! * Full loopback QUIC sync (marked `#[ignore]` until the peer-listener accept
//!   loop routing pipeline is wired — v0.4 deliverable)

use crate::common::{connect_when_ready, unique_ipc, wait_for_daemon, TestEnv};
use kotton_wire::remote::RemoteBackend;
use kotton::SyncDirection;
use std::path::PathBuf;

// ── Protocol serde ────────────────────────────────────────────────────────────

/// `RemoteBackend::Kotton` must survive a JSON round-trip via the IPC protocol.
#[test]
fn kotton_backend_serde_roundtrip() {
    let backend = RemoteBackend::Kotton {
        peer_did: "did:test:peer".to_string(),
        label: "my-vps".to_string(),
    };

    let json = serde_json::to_string(&backend).expect("serialize");
    let back: RemoteBackend = serde_json::from_str(&json).expect("deserialize");

    match back {
        RemoteBackend::Kotton { peer_did, label } => {
            assert_eq!(peer_did, "did:test:peer");
            assert_eq!(label, "my-vps");
        }
        other => panic!("expected Kotton variant, got {other:?}"),
    }
}

/// The `"type"` tag must be `"kotton"` (snake_case) in the serialised form.
#[test]
fn kotton_backend_type_tag() {
    let backend = RemoteBackend::Kotton {
        peer_did: "did:key:z6Mk1234".to_string(),
        label: "test".to_string(),
    };
    let json = serde_json::to_value(&backend).expect("serialize");
    assert_eq!(json["type"], "kotton", "type tag must be 'kotton'");
}

// ── Error path: unknown peer DID ─────────────────────────────────────────────

/// Adding a `Kotton` remote for a peer that has not been paired must return
/// an error indicating the node was not found.
#[tokio::test]
async fn remote_add_kotton_unknown_peer_returns_error() {
    let mut env = TestEnv::spawn().await;
    env.client.create_user("alice", crate::common::TEST_PASSPHRASE).await.expect("create_user");

    let result = env
        .client
        .remote_add(
            "alice",
            "peer-remote",
            RemoteBackend::Kotton {
                peer_did: "did:key:z6MkUnknownPeer".to_string(),
                label: "ghost".to_string(),
            },
            None,
        )
        .await;

    assert!(
        result.is_err(),
        "adding Kotton remote with unknown DID should fail"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("paired") || msg.contains("node") || msg.contains("DID"),
        "error should mention pairing or node: got '{msg}'"
    );
}

// ── SyncMount over a local remote ─────────────────────────────────────────────

/// Validate `SyncMount` end-to-end using a local-directory remote so the test
/// does not require live QUIC connectivity.
///
/// Sequence:
/// 1. Create & log in user.
/// 2. Write three objects to the "local" mount.
/// 3. Add a "backup" remote that points at a second temp directory.
/// 4. Push local → backup.
/// 5. Verify the objects are readable from the "backup" mount (not yet
///    mounted, so we use the SDK write/read APIs against the raw path once
///    synced). We verify `SyncResult.pushed == 3`.
#[tokio::test]
async fn sync_mount_push_to_local_remote() {
    let backup_dir = tempfile::tempdir().expect("backup tempdir");
    let backup_path: PathBuf = backup_dir.path().to_owned();

    let mut env = TestEnv::spawn().await;
    env.client.create_user("alice", crate::common::TEST_PASSPHRASE).await.expect("create_user");

    // Write three objects to the default "local" mount.
    for i in 1..=3u8 {
        env.client
            .write_file("alice", &format!("obj{i}.bin"), &[i; 64])
            .await
            .expect("write_file");
    }

    // Add a local-directory remote called "backup".
    env.client
        .remote_add(
            "alice",
            "backup",
            RemoteBackend::Local {
                path: backup_path.clone(),
            },
            None,
        )
        .await
        .expect("remote_add backup");

    // Push local → backup.
    let result = env
        .client
        .sync_mount("alice", "local", "backup", Some(SyncDirection::Push))
        .await
        .expect("sync_mount push");

    assert_eq!(
        result.pushed, 3,
        "expected 3 objects pushed, got {}",
        result.pushed
    );
    assert_eq!(result.pulled, 0, "push-only: pulled should be 0");
}

/// A file in a **subdirectory** must sync — the case a flat, non-recursive
/// listing silently dropped. `list_sealed` on a filesystem backend returns one
/// level with `is_dir` entries, so `notes/2026/trip.md` was invisible to sync
/// until it learned to recurse.
#[tokio::test]
async fn sync_pushes_files_in_subdirectories() {
    let backup_dir = tempfile::tempdir().expect("backup tempdir");
    let backup_path: PathBuf = backup_dir.path().to_owned();

    let mut env = TestEnv::spawn().await;
    env.client.create_user("alice", crate::common::TEST_PASSPHRASE).await.expect("create_user");

    // A root file and two nested ones, at different depths.
    let files = [
        ("root.txt", &b"top"[..]),
        ("notes/a.md", &b"one"[..]),
        ("notes/2026/trip.md", &b"deep"[..]),
    ];
    for (path, body) in &files {
        env.client
            .write_file("alice", path, body)
            .await
            .expect("write_file");
    }

    env.client
        .remote_add(
            "alice",
            "backup",
            RemoteBackend::Local {
                path: backup_path.clone(),
            },
            None,
        )
        .await
        .expect("remote_add backup");

    let result = env
        .client
        .sync_mount("alice", "local", "backup", Some(SyncDirection::Push))
        .await
        .expect("sync_mount push");
    assert_eq!(
        result.pushed, 3,
        "all three files, nested included, should push; got {}",
        result.pushed
    );

    // Each reads back from the backup *store* — nested paths intact.
    //
    // Store-addressed access has no protocol verb by design (RFC-0058): the IPC
    // surface holds that anything naming a store sees only ciphertext. Tests
    // reach the runtime, which already holds every key and store.
    let user_rt = env
        .users
        .get("alice")
        .expect("alice runtime");
    for (path, body) in &files {
        let got = user_rt
            .read_file_from("backup", path)
            .await
            .unwrap_or_else(|e| panic!("read {path} from backup: {e}"));
        assert_eq!(&got, body, "{path} content mismatch on backup");
    }
}

/// Push twice: both syncs push the object because the current push implementation
/// does not compare content (it always overwrites remote with local). The
/// `skipped` count is 0 because every key is locally present.
///
/// Note: content-equality deduplication (ETags / SHA-256) is a performance
/// optimisation deferred to a later sprint. M28 uses simple LWW by key presence.
#[tokio::test]
async fn sync_mount_push_is_repeatable() {
    let backup_dir = tempfile::tempdir().expect("backup tempdir");
    let backup_path: PathBuf = backup_dir.path().to_owned();

    let mut env = TestEnv::spawn().await;
    env.client.create_user("alice", crate::common::TEST_PASSPHRASE).await.expect("create_user");

    env.client
        .write_file("alice", "file.txt", b"hello")
        .await
        .expect("write_file");

    env.client
        .remote_add(
            "alice",
            "backup",
            RemoteBackend::Local { path: backup_path },
            None,
        )
        .await
        .expect("remote_add");

    // First push.
    let r1 = env
        .client
        .sync_mount("alice", "local", "backup", Some(SyncDirection::Push))
        .await
        .expect("first sync");
    assert_eq!(r1.pushed, 1);

    // Second push — current implementation re-pushes (no content-equality check).
    let r2 = env
        .client
        .sync_mount("alice", "local", "backup", Some(SyncDirection::Push))
        .await
        .expect("second sync");
    assert_eq!(
        r2.pushed, 1,
        "second sync re-pushes (no dedup optimisation yet)"
    );
    assert_eq!(r2.pulled, 0, "push-only: no pulls");
}

// ── Last-write-wins conflict resolution ───────────────────────────────────────

/// Bidirectional sync where the same key exists on both sides.
///
/// The local side is written AFTER the backup side (ensuring `local_ts >=
/// backup_ts`).  In bidirectional LWW mode the local copy wins (pushed to
/// backup) because `lts >= rts` — ties resolve to local.
#[tokio::test]
async fn sync_lww_local_newer_wins() {
    let backup_dir = tempfile::tempdir().expect("backup tempdir");
    let backup_path: PathBuf = backup_dir.path().to_owned();

    let mut env = TestEnv::spawn().await;
    env.client.create_user("alice", crate::common::TEST_PASSPHRASE).await.expect("create_user");

    // Add backup remote first so we can write to it via the SDK.
    env.client
        .remote_add(
            "alice",
            "backup",
            RemoteBackend::Local { path: backup_path },
            None,
        )
        .await
        .expect("remote_add backup");

    // Write the "older" version to backup, then the "local" version immediately
    // after.  Both writes may land in the same filesystem second; the LWW
    // tie-break rule (`lts >= rts`) ensures the local copy still wins.
    env.users
        .get("alice")
        .expect("alice runtime")
        .write_file_to("backup", "conflict.txt", b"backup-version")
        .await
        .expect("write backup side");

    env.client
        .write_file("alice", "conflict.txt", b"local-version")
        .await
        .expect("write local side");

    // Bidirectional sync — local should win and be pushed to backup.
    let result = env
        .client
        .sync_mount("alice", "local", "backup", None)
        .await
        .expect("sync_mount bidirectional");

    assert!(
        result.pushed >= 1,
        "local should have been pushed to backup (pushed={})",
        result.pushed
    );
    assert_eq!(result.pulled, 0, "local is newer: nothing should be pulled");

    // Verify backup now holds the local version.
    let content = env
        .users
        .get("alice")
        .expect("alice runtime")
        .read_file_from("backup", "conflict.txt")
        .await
        .expect("read conflict.txt from backup");
    assert_eq!(
        content, b"local-version",
        "backup should hold the local (winning) version after LWW sync"
    );
}

/// Bidirectional sync where the remote side is demonstrably newer.
///
/// The local side is written first, then we sleep 1.1 s to ensure a different
/// filesystem second, then write to backup.  LWW picks backup (remote) because
/// `remote_ts > local_ts`, and the backing store is updated on both sides.
#[tokio::test]
async fn sync_lww_remote_newer_wins() {
    let backup_dir = tempfile::tempdir().expect("backup tempdir");
    let backup_path: PathBuf = backup_dir.path().to_owned();

    let mut env = TestEnv::spawn().await;
    env.client.create_user("alice", crate::common::TEST_PASSPHRASE).await.expect("create_user");

    env.client
        .remote_add(
            "alice",
            "backup",
            RemoteBackend::Local { path: backup_path },
            None,
        )
        .await
        .expect("remote_add backup");

    // Write local copy first (older).
    env.client
        .write_file("alice", "conflict.txt", b"local-version")
        .await
        .expect("write local side");

    // Ensure remote write lands in a later filesystem second.
    tokio::time::sleep(tokio::time::Duration::from_millis(1100)).await;

    // Write remote (backup) copy — this is now strictly newer.
    env.users
        .get("alice")
        .expect("alice runtime")
        .write_file_to("backup", "conflict.txt", b"remote-version")
        .await
        .expect("write backup side");

    // Bidirectional sync — backup should win and be pulled to local.
    let result = env
        .client
        .sync_mount("alice", "local", "backup", None)
        .await
        .expect("sync_mount bidirectional");

    assert!(
        result.pulled >= 1,
        "remote (backup) should have been pulled to local (pulled={})",
        result.pulled
    );
    assert_eq!(
        result.pushed, 0,
        "remote is newer: nothing should be pushed"
    );

    // Verify local now holds the remote version.
    let content = env
        .client
        .read_file("alice", "conflict.txt")
        .await
        .expect("read conflict.txt from local");
    assert_eq!(
        content, b"remote-version",
        "local should hold the remote (winning) version after LWW sync"
    );
}

// ── Full loopback QUIC peer sync ──────────────────────────────────────────────

/// Initialise the rustls ring crypto provider exactly once per process.
///
/// Quinn requires a CryptoProvider; without this the TLS handshake panics.
fn init_crypto() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
    });
}

/// Find a free UDP port by binding to port 0 and reading the assigned port.
fn free_port() -> u16 {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind :0 for port probe");
    s.local_addr().expect("local_addr").port()
}

/// Two nodes in **different key domains** are refused, over real loopback QUIC.
///
/// This test used to assert the opposite — that the three objects pulled and
/// read back in the clear on B — and it passed, which is precisely the defect
/// RFC-0041 exists to fix. Its setup fakes pairing by writing reciprocal
/// `paired_nodes` rows instead of running enrollment, so A and B hold
/// independently generated CEKs. The old sync path made that "work" by reading
/// through the encrypting store (`get` decrypts) and writing plaintext to the
/// peer, which B then re-sealed under its own unrelated key. Data moved between
/// two key domains by passing through plaintext, and a test asserted it.
///
/// The setup is left exactly as it was, because faking pairing is the *right*
/// setup for a negative test: these two nodes genuinely are strangers. What
/// changed is the expectation. A transfer is now refused with a
/// `SealedDomainMismatch`, and the message names both domains.
///
/// Note what the earlier CEK-**epoch** check could not have caught here: two
/// nodes that were never in the same fleet both start at epoch 0 and compare
/// equal. Only a fingerprint derived from the key itself separates them.
///
/// B is told A's node is its drive, because only a drive is a sync target: a
/// device is refused before any domain is compared. The gate this holds is the
/// drive's — a node keeping another key domain's things is refused at the
/// transfer, whatever the node is.
///
/// The positive case — one key domain, sync by way of a drive — is covered by
/// `enroll_threshold_sign::file_written_on_one_device_syncs_to_a_joined_device`.
#[tokio::test]
async fn peer_sync_across_key_domains_is_refused() {
    use kuserd::DeviceDaemon;
    use kotton_sys::secret::SecretsStore;
    use kotton_secret::MemorySecrets;
    use kotton::SyncDirection;
    use std::sync::Arc;

    init_crypto();

    // ── Device A (source) ─────────────────────────────────────────────────────
    let base_a = tempfile::tempdir().expect("base_a tempdir");
    let ipc_a = unique_ipc();
    let secrets_a: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    let daemon_a = Arc::new(
        DeviceDaemon::new_with_base_and_secrets(base_a.path().to_owned(), ipc_a.clone(), Arc::clone(&secrets_a))
            .await
            .expect("DeviceDaemon A"),
    );
    let a_pubkey = daemon_a.device_signing_pubkey_bytes();
    let a_did = daemon_a.device_did().to_owned();

    // ── Device B (sink) ──────────────────────────────────────────────────
    let base_b = tempfile::tempdir().expect("base_b tempdir");
    let ipc_b = unique_ipc();
    let secrets_b: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    let daemon_b = Arc::new(
        DeviceDaemon::new_with_base_and_secrets(base_b.path().to_owned(), ipc_b.clone(), Arc::clone(&secrets_b))
            .await
            .expect("DeviceDaemon B"),
    );
    let b_pubkey = daemon_b.device_signing_pubkey_bytes();
    let b_did = daemon_b.device_did().to_owned();

    // ── Peer listener port ────────────────────────────────────────────────────
    let port_a = free_port();
    let a_addr: std::net::SocketAddr = format!("127.0.0.1:{port_a}").parse().expect("parse addr");

    // ── A's mTLS allowlist: permit B by inserting B's key into A's paired_keys ─
    // `insert_paired_node` updates both the DB and the live allowlist set.
    // Note: user "alice" is created later; SQLite doesn't enforce FK so the
    // row is accepted before the user row exists.
    let dummy_b_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    daemon_a
        .insert_paired_node("alice", &b_did, b_pubkey, dummy_b_addr)
        .await
        .expect("insert B into A's paired_nodes");

    // ── B's DB: record A as a paired node so remote_add can resolve the DID ──
    daemon_b
        .insert_paired_node("alice", &a_did, a_pubkey, a_addr)
        .await
        .expect("insert_paired_node A into B");

    // ── Start A's peer listener (uses self.paired_keys seeded above) ──────────
    daemon_a
        .start_peer_listener_background(port_a)
        .await
        .expect("start A peer listener");

    // ── Spawn IPC loops ───────────────────────────────────────────────────────
    let daemon_a =
        Arc::try_unwrap(daemon_a).unwrap_or_else(|_| panic!("sole arc owner for daemon_a"));
    let daemon_b =
        Arc::try_unwrap(daemon_b).unwrap_or_else(|_| panic!("sole arc owner for daemon_b"));
    let _task_a = tokio::spawn(async move { std::sync::Arc::new(daemon_a).run().await });
    let _task_b = tokio::spawn(async move { std::sync::Arc::new(daemon_b).run().await });
    wait_for_daemon(&ipc_a, "daemon A").await;
    wait_for_daemon(&ipc_b, "daemon B").await;

    // ── Clients ───────────────────────────────────────────────────────────────
    let mut client_a = connect_when_ready(&ipc_a, "client_a").await;
    let mut client_b = connect_when_ready(&ipc_b, "client_b").await;

    // ── Write 3 objects to A ──────────────────────────────────────────────────
    client_a.create_user("alice", crate::common::TEST_PASSPHRASE).await.expect("create_user A");
    for i in 1u8..=3 {
        client_a
            .write_file("alice", &format!("obj{i}.bin"), &[i; 64])
            .await
            .expect("write_file A");
    }

    // ── B syncs from A ────────────────────────────────────────────────────────
    client_b.create_user("alice", crate::common::TEST_PASSPHRASE).await.expect("create_user B");
    // Only a drive is a sync target, so B is told A's node is its drive — a
    // node keeping another key domain's things under the person's name, which
    // is what the domain gate exists for whatever the node is.
    client_b
        .peer_add_drive("alice", &a_did, &a_did, &hex::encode(a_pubkey), a_addr)
        .await
        .expect("record A's node as B's drive");
    client_b
        .remote_add(
            "alice",
            "peer-a",
            RemoteBackend::Kotton {
                peer_did: a_did.clone(),
                label: "device-a".to_string(),
            },
            None,
        )
        .await
        .expect("remote_add Kotton on B");

    let err = client_b
        .sync_mount("alice", "local", "peer-a", Some(SyncDirection::Pull))
        .await
        .expect_err("sync across unrelated key domains must be refused, not silently succeed");

    let msg = err.to_string();
    assert!(
        msg.contains("key domain"),
        "refusal should name the key-domain mismatch so the cause is diagnosable, got: {msg}"
    );

    // Nothing crossed. B holds no object A wrote — not a re-sealed copy, not an
    // envelope it cannot open, nothing.
    for i in 1u8..=3 {
        assert!(
            client_b
                .read_file("alice", &format!("obj{i}.bin"))
                .await
                .is_err(),
            "obj{i}.bin must not exist on a node in a different key domain"
        );
    }
}
