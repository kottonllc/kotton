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
use std::collections::BTreeSet;
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

// ── What a pass pushes ────────────────────────────────────────────────────────

/// The objects a pass pushed, by what each one is.
///
/// A pass carries more than the person's files. Before it moves anything it
/// makes this device's whole-keeper claims say what the device keeps
/// (`kotton_device::users::pins::claim`, kotton #189; #155 wrote a default pin
/// record at the same point), and the first device's default is whole, so its
/// first pass writes one claim: an `sh.kotton.keeps-whole` record naming this
/// device and the first drive. `log_records` then seals that record into the
/// history log, which commits one **index pack** (`_pack/…`, not a content pack)
/// and one **superblock** generation. Both are in the person's local mount by
/// the time the transfer loop lists it, so a push to a remote that does not hold
/// them moves them beside the files. A pass whose claim is already logged writes
/// no new segment.
#[derive(Debug, Default, PartialEq, Eq)]
struct Pushed {
    /// The person's files, as the loose objects that hold them.
    files: usize,
    /// Index packs: the history log's segments, here the one carrying the claim.
    index_packs: BTreeSet<String>,
    /// Content packs: none here, since nothing ran a packing pass over the files.
    content_packs: usize,
    /// Superblock generations committed with the index packs.
    superblocks: BTreeSet<String>,
}

fn pushed(result: &kotton_wire::remote::SyncResult) -> Pushed {
    use kotton_store::packed::{is_content_pack, PACK_PREFIX};
    use kotton_store::superblock::SUPERBLOCK_PREFIX;
    let mut out = Pushed::default();
    for (dir, key, _) in &result.transfers {
        if !matches!(dir, SyncDirection::Push) {
            continue;
        }
        if key.starts_with(SUPERBLOCK_PREFIX) {
            out.superblocks.insert(key.clone());
        } else if is_content_pack(key) {
            out.content_packs += 1;
        } else if key.starts_with(PACK_PREFIX) {
            out.index_packs.insert(key.clone());
        } else {
            out.files += 1;
        }
    }
    assert_eq!(
        out.files + out.index_packs.len() + out.content_packs + out.superblocks.len(),
        result.pushed as usize,
        "`pushed` counts the transfers it lists: {result:?}"
    );
    out
}

/// The whole-keeper claims in alice's record store.
async fn claims(env: &mut TestEnv) -> Vec<serde_json::Value> {
    env.client
        .record_query("alice", kotton_common::namespace::NSID_KEEPS_WHOLE, vec![], None, None)
        .await
        .expect("query whole-keeper claims")
}

/// A first pass pushed `files` files, and beside them exactly the history log
/// segment that carries this device's claim: one index pack, one superblock, no
/// content pack; and alice's store holds that one claim.
async fn assert_first_pass(env: &mut TestEnv, result: &kotton_wire::remote::SyncResult, files: usize) {
    let p = pushed(result);
    assert_eq!(p.files, files, "the files pushed: {result:?}");
    assert_eq!(p.index_packs.len(), 1, "one index pack, the segment carrying the claim: {result:?}");
    assert_eq!(p.superblocks.len(), 1, "one superblock, the generation that committed it: {result:?}");
    assert_eq!(p.content_packs, 0, "no content pack: nothing packed the files: {result:?}");
    let claims = claims(env).await;
    assert_eq!(claims.len(), 1, "the pass wrote this device's one claim: {claims:?}");
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
///    synced). We verify the push moved the three files and, beside them, the
///    history log segment carrying this device's whole-keeper claim (one index
///    pack, one superblock) — five objects, named in [`assert_first_pass`].
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

    assert!(claims(&mut env).await.is_empty(), "no claim before the first pass");

    // Push local → backup.
    let result = env
        .client
        .sync_mount("alice", "local", "backup", Some(SyncDirection::Push))
        .await
        .expect("sync_mount push");

    assert_first_pass(&mut env, &result, 3).await;
    assert_eq!(result.pulled, 0, "push-only: pulled should be 0");
}

/// A file in a **subdirectory** must sync — the case a flat, non-recursive
/// listing silently dropped. `list_sealed` on a filesystem backend returns one
/// level with `is_dir` entries, so `notes/2026/trip.md` was invisible to sync
/// until it learned to recurse.
///
/// The pass also pushes the history log segment carrying this device's
/// whole-keeper claim ([`assert_first_pass`]), so five objects move: the three
/// files, one index pack, one superblock.
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
    // All three files, nested included, beside the claim's segment.
    assert_first_pass(&mut env, &result, files.len()).await;

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

/// Push twice: both syncs push every object because the current push
/// implementation does not compare content (it always overwrites remote with
/// local). The `skipped` count is 0 because every key is locally present.
///
/// What is pushed is the file and, from the first pass on, the history log
/// segment carrying this device's whole-keeper claim (one index pack, one
/// superblock; [`assert_first_pass`]). The claim is written once, so the second
/// pass writes no new segment and pushes exactly the set the first did.
/// Equal sets prove no new segment because pack ids and superblock suffixes are
/// random (`kotton_store::packed`), so a new segment could not reuse a key.
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
    assert_first_pass(&mut env, &r1, 1).await;

    // Second push — current implementation re-pushes (no content-equality check).
    let r2 = env
        .client
        .sync_mount("alice", "local", "backup", Some(SyncDirection::Push))
        .await
        .expect("second sync");
    assert_eq!(
        pushed(&r2),
        pushed(&r1),
        "second sync re-pushes what the first did and no new segment (no dedup optimisation yet)"
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
///
/// No file is pushed. The pass does push the history log segment carrying this
/// device's whole-keeper claim (one index pack, one superblock;
/// [`assert_first_pass`]), which the backup does not hold.
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
    // Remote is newer: no file is pushed, only the claim's segment.
    assert_first_pass(&mut env, &result, 0).await;

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
/// their own drive and a file kept on it, and the second's vault made to serve
/// the first's pool whole — its packs and the key domain recorded for them (a
/// landlord's mistake or malice, which a vault that cannot open what it holds
/// cannot notice). The pull is refused at the boundary, in words naming both
/// domains, and nothing crosses. No test records a device as a drive.
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

    let (mut client_a, mut client_b, files, (a_domain, b_domain), _vaults) =
        crate::drive_sync::a_drive_serving_another_domains_packs(client_a, client_b, "alice").await;

    let err = client_b
        .sync_mount("alice", "local", "vault", Some(SyncDirection::Pull))
        .await
        .expect_err("a pull across unrelated key domains must be refused, not silently succeed");
    // The boundary's own refusal, naming both domains: the object's (A's) and
    // the one this node holds (B's) — not any earlier failure.
    let msg = err.to_string();
    assert!(
        msg.contains(&format!("belongs to key domain {a_domain}, this node holds {b_domain}")),
        "the refusal is not the key-domain boundary naming both domains, got: {msg}"
    );

    // Nothing crossed. B holds no object A wrote — not a re-sealed copy, not an
    // envelope it cannot open, nothing — and A still reads its own.
    for (name, body) in &files {
        assert!(client_b.read_file("alice", name).await.is_err(), "{name} must not exist on B");
        assert_eq!(&client_a.read_file("alice", name).await.expect("A reads its own"), body);
    }
}

// ── The device's peer acceptor decodes a peer's bytes, and only `UserRequest` ─

/// **A retired verb is refused at kuserd's decoder.** Both peer acceptors
/// decode a peer's bytes as `UserRequest` with no fallback, so a verb that
/// left the type (`ApplyRecordChangeset`, kotton #173/#219) is an unknown
/// variant on the device as on the vault. `vault::a_vault_answers_its_verbs_and_nothing_else`
/// holds the vault's half; this holds the device's: B, paired with A, dials A's
/// peer acceptor under its own operational key and sends the bytes of the
/// retired verb with a plausible row. The type no longer has the variant, so
/// the request is written as the bytes such a peer would send. A `RemoteRequest`
/// fallback or an alias table in the acceptor would answer something other than
/// the decoder's refusal, and fail here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paired_device_sending_a_retired_verb_is_refused_at_kuserds_decoder() {
    use crate::common::{enroll_streamed_as, init_crypto, peer_port};
    use crate::vault::spawn_device;
    use kotton_net::transport::quic::tls::CertOffer;
    use kotton_peer::nat::{nat_connect, NatConfig, NatResult};
    use kotton_peer::{PeerChannel as _, QuicPeerChannel};
    use kotton_schemas::membership::Posture;
    use kotton_wire::ipc::UserResponse;

    init_crypto();
    let a = spawn_device("device A").await;
    let b = spawn_device("device B").await;
    // A's peer acceptor, on a port the OS gives it, as the other two-device
    // cases start theirs (`enroll_threshold_sign`).
    a.daemon.start_peer_listener_background(0).await.expect("start A's peer listener");
    let mut client_a = connect_when_ready(&a.ipc, "client A").await;
    let client_b = connect_when_ready(&b.ipc, "client B").await;
    client_a
        .create_user("alice", crate::common::TEST_PASSPHRASE)
        .await
        .expect("create_user on A");
    let (mut client_a, _client_b, _node_b) =
        enroll_streamed_as(client_a, client_b, "alice", "device-a", "device-b", Posture::Full).await;
    let (_, a_key_hex) = client_a.get_node_identity().await.expect("A's identity");
    let a_pub: [u8; 32] = hex::decode(a_key_hex).unwrap().try_into().unwrap();
    let a_addr: std::net::SocketAddr = format!("127.0.0.1:{}", peer_port(&a.daemon.runtime())).parse().unwrap();

    // B dials as itself: its operational key, A's direct address.
    let b_key = kotton_peer::daemon::nodes::load_device_operational_key(&*b.secrets).expect("B's device key");
    let offer = CertOffer {
        admission: vec![],
        claim: None,
    };
    let conn = match nat_connect(&b_key, &offer, a_pub, Some(a_addr), &NatConfig::default(), None).await {
        NatResult::Direct(c) | NatResult::Punched(c) => c,
        other => panic!("the paired device's key opens A's peer acceptor directly: {other:?}"),
    };
    let channel = QuicPeerChannel::new(conn);

    let retired = serde_json::json!({
        "ApplyRecordChangeset": {
            "user_id": "alice",
            "nsid": "com.test.notes",
            "rows": [{
                "id": "00000000-0000-4000-8000-000000000000",
                "schema_nsid": "com.test.notes",
                "body": { "text": "planted" },
                "updated_at": 1,
                "deleted_at": null
            }]
        }
    });
    let raw = channel
        .request(&serde_json::to_vec(&retired).unwrap())
        .await
        .expect("A's peer acceptor answers");
    match serde_json::from_slice::<UserResponse>(&raw).unwrap() {
        UserResponse::Error { message } => assert!(
            message.contains("invalid peer request") && message.contains("unknown variant `ApplyRecordChangeset`"),
            "a retired verb is no request on the device's peer wire: {message}"
        ),
        other => panic!("a peer request carrying a retired verb was taken: {other:?}"),
    }
}
