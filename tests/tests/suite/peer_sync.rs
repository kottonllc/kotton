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

use crate::common::{connect_when_ready, TestEnv};
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

/// A drive serving **another key domain's** packs is refused, over real
/// loopback QUIC.
///
/// This test used to pull from another *device* in an unrelated key domain,
/// and before that it asserted the pull worked — the defect the key-domain
/// gate exists to fix: data moved between two key domains by passing through
/// plaintext. A device now syncs only with a drive, so the gate's subject is a
/// drive: two people both named `alice`, each with a real vault enrolled as
/// their own drive, and the second's vault made to serve the first's pool (a
/// landlord's mistake or malice, which a vault that cannot open what it holds
/// cannot notice). The pull is refused as a key-domain mismatch, and nothing
/// crosses. No test records a device as a drive.
///
/// The positive case — one key domain, sync by way of a drive — is covered by
/// `enroll_threshold_sign::file_written_on_one_device_syncs_to_a_joined_device`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_drive_serving_another_key_domain_is_refused() {
    init_crypto();
    let a = crate::vault::spawn_device("device A").await;
    let b = crate::vault::spawn_device("device B").await;
    let mut client_a = connect_when_ready(&a.ipc, "client_a").await;
    let mut client_b = connect_when_ready(&b.ipc, "client_b").await;
    client_a.create_user("alice", crate::common::TEST_PASSPHRASE).await.expect("create_user A");
    client_b.create_user("alice", crate::common::TEST_PASSPHRASE).await.expect("create_user B");

    let (mut client_a, mut client_b, files, _vaults) =
        crate::drive_sync::a_drive_serving_another_domains_packs(client_a, client_b, "alice").await;

    let err = client_b
        .sync_mount("alice", "local", "vault", Some(SyncDirection::Pull))
        .await
        .expect_err("a pull across unrelated key domains must be refused, not silently succeed");
    let msg = err.to_string();
    assert!(
        msg.contains("key domain"),
        "refusal should name the key-domain mismatch so the cause is diagnosable, got: {msg}"
    );

    // Nothing crossed. B holds no object A wrote — not a re-sealed copy, not an
    // envelope it cannot open, nothing — and A still reads its own.
    for (name, body) in &files {
        assert!(client_b.read_file("alice", name).await.is_err(), "{name} must not exist on B");
        assert_eq!(&client_a.read_file("alice", name).await.expect("A reads its own"), body);
    }
}
