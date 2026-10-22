// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — RFC-0007: Key Distribution & Multi-Device Access
//!
//! Tests two of the three key-distribution cases:
//!
//! 1. **Blind relay**: a daemon whose user has no `seed32` in the OS keychain
//!    (equivalent to being paired as `PairingPayload::BlindRelay`) must reject
//!    all CEK-requiring requests (`ReadFile`, `RecordQuery`, `RecordSearch`,
//!    `RecordDelete`, `RecordOpen`) with a `"NoCek:"` error and still serve
//!    listing requests (`ListFiles`) normally.
//!
//! 2. **Guest token TTL**: `PairNodeEphemeral` must persist
//!    `expires_at = now + ttl_seconds` in the returned `EphemeralSession`.
//!
//! Full-device QUIC pairing and peer-path expiry enforcement tests are marked
//! `#[ignore]` because they require a live QUIC listener (v0.4 deliverable).


use aes_kw::KekAes256;
use crate::common::TestEnv;
use hkdf::Hkdf;
use kotton_sys::ObjectStorage;
use kotton_wire::{UserRequest, UserResponse};
use kotton_store::EncryptedObjectStorage;
use kotton::KottonClient;
use kotton_common::crypto::kdf_labels;
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Returns a unique user ID to avoid OS keychain collisions between parallel tests.
fn unique_user_id(prefix: &str) -> String {
    format!("{}-{}", prefix, Uuid::new_v4().simple())
}

// ── blind relay ───────────────────────────────────────────────────────────────

/// A blind-relay node (seed32 absent from the OS keychain) must reject
/// `ReadFile` with a `"NoCek:"` error.
#[tokio::test]
async fn blind_relay_rejects_read_file() {
    let user_id = unique_user_id("blind-relay");
    let mut env = TestEnv::spawn().await;

    env.client.create_user(&user_id, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let token = env.client.session_token.clone().expect("session token");

    // Simulate a blind-relay node: no operational key material anywhere
    // (RFC-0039 — the CEK is the stored operational_cek, not seed32).
    //
    // Deleted through the daemon's own secrets handle rather than the platform
    // store beneath it. Since `DEC-0049` an account is locked at creation, so its
    // roots are held in the daemon's in-memory custody and the platform copies
    // are already gone — reaching past the custody layer would remove nothing and
    // leave the node still holding the CEK, which is the opposite of what this
    // test is trying to build. `SealedCustody::delete_secret` clears both.
    for label in [
        kdf_labels::operational_cek(&user_id),
        kdf_labels::master_secret_keychain_key(&user_id),
        kdf_labels::seed32_keychain_key(&user_id),
    ] {
        env.runtime.secrets().delete_secret(&label).ok();
    }

    // Open a fresh connection — Authenticate on this connection detects the
    // missing seed32 and sets cek_available = false for the session.
    let mut blind = KottonClient::connect_to(env.endpoint.clone())
        .await
        .expect("connect_to");
    blind
        .authenticate_scoped(&token, None)
        .await
        .expect("authenticate_scoped");

    let resp = blind
        .inner()
        .send(&UserRequest::ReadFile {
            user_id: user_id.clone(),
            path: "/test.txt".to_string(),
            // A whole-file range (RFC-0048); the NoCek guard fires before it.
            offset: 0,
            length: 4096,
        })
        .await
        .expect("send ReadFile");

    assert!(
        matches!(&resp, UserResponse::Error { message } if message.starts_with("NoCek:")),
        "ReadFile on blind relay must return NoCek error, got: {resp:?}"
    );

    env.client.logout_user(&user_id).await.ok();
}

/// All record operations (`RecordQuery`, `RecordSearch`, `RecordDelete`,
/// `RecordOpen`) must return `NoCek` on a blind relay node because the records
/// database is CEK-encrypted.
#[tokio::test]
async fn blind_relay_rejects_record_ops() {
    let user_id = unique_user_id("blind-relay-rec");
    let mut env = TestEnv::spawn().await;

    env.client.create_user(&user_id, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let token = env.client.session_token.clone().expect("session token");

    // Simulate a blind-relay node: no operational key material anywhere. Deleted
    // through the daemon's secrets handle, not the platform store beneath it —
    // see `blind_relay_rejects_read_file` for why that distinction now decides
    // whether this test tests anything.
    for label in [
        kdf_labels::operational_cek(&user_id),
        kdf_labels::master_secret_keychain_key(&user_id),
        kdf_labels::seed32_keychain_key(&user_id),
    ] {
        env.runtime.secrets().delete_secret(&label).ok();
    }

    let mut blind = KottonClient::connect_to(env.endpoint.clone())
        .await
        .expect("connect_to");
    blind
        .authenticate_scoped(&token, None)
        .await
        .expect("authenticate_scoped");

    // RecordQuery
    let resp = blind
        .inner()
        .send(&UserRequest::RecordQuery {
            user_id: user_id.clone(),
            schema_nsid: "sh.kotton.notes".to_string(),
            field_eq: vec![],
            limit: None,
            offset: None,
            root: None,
            app_id: None,
        })
        .await
        .expect("send RecordQuery");
    assert!(
        matches!(&resp, UserResponse::Error { message } if message.starts_with("NoCek:")),
        "RecordQuery must return NoCek on blind relay, got: {resp:?}"
    );

    // RecordSearch
    let resp = blind
        .inner()
        .send(&UserRequest::RecordSearch {
            user_id: user_id.clone(),
            nsid: None,
            text: None,
            limit: None,
            app_id: None,
        })
        .await
        .expect("send RecordSearch");
    assert!(
        matches!(&resp, UserResponse::Error { message } if message.starts_with("NoCek:")),
        "RecordSearch must return NoCek on blind relay, got: {resp:?}"
    );

    // RecordDelete
    let resp = blind
        .inner()
        .send(&UserRequest::RecordDelete {
            user_id: user_id.clone(),
            schema_nsid: "sh.kotton.notes".to_string(),
            record_id: "nonexistent".to_string(),
            root: None,
            app_id: None,
        })
        .await
        .expect("send RecordDelete");
    assert!(
        matches!(&resp, UserResponse::Error { message } if message.starts_with("NoCek:")),
        "RecordDelete must return NoCek on blind relay, got: {resp:?}"
    );

    // RecordOpen
    let resp = blind
        .inner()
        .send(&UserRequest::RecordOpen {
            user_id: user_id.clone(),
            url: "kotton://records/sh.kotton.notes/nonexistent".to_string(),
        })
        .await
        .expect("send RecordOpen");
    assert!(
        matches!(&resp, UserResponse::Error { message } if message.starts_with("NoCek:")),
        "RecordOpen must return NoCek on blind relay, got: {resp:?}"
    );

    env.client.logout_user(&user_id).await.ok();
}

/// `ListFiles` must succeed on a blind relay node — listing raw ciphertext
/// paths does not require the CEK.
#[tokio::test]
async fn blind_relay_allows_list_files() {
    let user_id = unique_user_id("blind-relay-ls");
    let mut env = TestEnv::spawn().await;

    env.client.create_user(&user_id, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let token = env.client.session_token.clone().expect("session token");

    // Simulate a blind-relay node: no operational key material (RFC-0039 — the
    // CEK is the stored operational_cek, not seed32).
    for label in [
        kdf_labels::operational_cek(&user_id),
        kdf_labels::master_secret_keychain_key(&user_id),
        kdf_labels::seed32_keychain_key(&user_id),
    ] {
        env.secrets.delete_secret(&label).ok();
    }

    let mut blind = KottonClient::connect_to(env.endpoint.clone())
        .await
        .expect("connect_to");
    blind
        .authenticate_scoped(&token, None)
        .await
        .expect("authenticate_scoped");

    let resp = blind
        .inner()
        .send(&UserRequest::ListFiles {
            user_id: user_id.clone(),
            prefix: "/".to_string(),
        })
        .await
        .expect("send ListFiles");

    assert!(
        !matches!(&resp, UserResponse::Error { message } if message.starts_with("NoCek:")),
        "ListFiles must NOT be blocked by the NoCek guard, got: {resp:?}"
    );

    env.client.logout_user(&user_id).await.ok();
}

// ── guest token TTL ───────────────────────────────────────────────────────────

/// `PairNodeEphemeral` must set `expires_at ≈ now + ttl_seconds` in the
/// `GrantEnvelope` of the returned `EphemeralSession`.
#[tokio::test]
async fn guest_token_expires_at_matches_ttl() {
    let user_id = unique_user_id("guest-token");
    let mut env = TestEnv::spawn().await;

    env.client.create_user(&user_id, crate::common::TEST_PASSPHRASE).await.expect("create_user");

    let ttl: u64 = 300;
    // Taken here rather than before `TestEnv::spawn` and `create_user`. The
    // five-second tolerance below is meant to catch clock skew between the
    // daemon and the test; anchored earlier it also had to cover a daemon
    // starting and an identity being created, which under a loaded parallel run
    // is well over five seconds. That made this fail intermittently for a reason
    // that has nothing to do with what it measures.
    let before = unix_now();

    let resp = env
        .client
        .inner()
        .send(&UserRequest::PairNodeEphemeral {
            user_id: user_id.clone(),
            label: "test-guest".to_string(),
            paths: vec!["/docs".to_string()],
            permissions: kotton_wire::peer::SessionPermissions::Read,
            ttl_seconds: ttl,
            guest_ephemeral_pubkey: None,
        })
        .await
        .expect("send PairNodeEphemeral");

    let sessions = match resp {
        UserResponse::SessionList { sessions } => sessions,
        other => panic!("expected SessionList, got {other:?}"),
    };
    assert_eq!(sessions.len(), 1, "expected exactly one session");

    let exp = sessions[0]
        .grant
        .expires_at
        .expect("GrantEnvelope must have expires_at");

    assert!(
        exp >= before + ttl as i64,
        "expires_at ({exp}) must be >= now ({before}) + ttl ({ttl})"
    );
    assert!(
        exp <= before + ttl as i64 + 5,
        "expires_at ({exp}) is more than 5 s after expected; unexpected clock skew"
    );

    env.client.logout_user(&user_id).await.ok();
}

// ── wrapped DEKs ──────────────────────────────────────────────────────────────

/// `PairNodeEphemeral` must populate `wrapped_deks` when the caller supplies
/// a `guest_ephemeral_pubkey`.  The test verifies the full round-trip:
///
///   1. Write an encrypted blob to the user's local storage (via
///      `EncryptedObjectStorage` with the user's CEK).
///   2. Call `PairNodeEphemeral` with a fresh X25519 guest ephemeral keypair.
///   3. Assert `wrapped_deks` contains an entry for the file path.
///   4. Derive the ECDH session key on the guest side; unwrap the DEK.
///   5. Decrypt the raw object bytes with the unwrapped DEK, assert plaintext.
#[tokio::test]
async fn wrapped_deks_end_to_end() {
    let user_id = unique_user_id("wrapped-deks");
    let mut env = TestEnv::spawn().await;

    // ── Create user (stores the random operational roots; no seed32) ─────────
    env.client.create_user(&user_id, crate::common::TEST_PASSPHRASE).await.expect("create_user");

    // ── Read the random operational CEK the create stored (RFC-0039) ─────────
    //
    // Through the daemon's secrets handle, not the platform store beneath it.
    // Since `DEC-0049` an account is locked at creation and its roots live in
    // in-memory custody, so the platform store legitimately holds nothing — that
    // is the property, not a fault to route around. `SealedCustody::get_secret`
    // reads what the node actually holds, which is also what the code under test
    // reads.
    let cek_hex = env
        .runtime
        .secrets()
        .get_secret(&kdf_labels::operational_cek(&user_id))
        .expect("get operational_cek secret")
        .expect("operational_cek must exist after create_user");
    let cek_bytes = hex::decode(&cek_hex).expect("decode cek hex");
    assert_eq!(cek_bytes.len(), 32, "cek must be 32 bytes");
    let mut cek = [0u8; 32];
    cek.copy_from_slice(&cek_bytes);

    // ── Write an encrypted blob to local storage under that CEK ──────────────
    let plaintext = b"hello from the guest test";
    let file_path = "/guest-test.txt";

    // Write via EncryptedObjectStorage backed by LocalObjectStorage into the
    // user's on-disk data directory.
    let data_dir = env.base_dir.join("users").join(&user_id).join("data");
    std::fs::create_dir_all(&data_dir).expect("create data dir");
    {
        let local = kotton_store::LocalObjectStorage::new(
            data_dir.clone(),
            kotton_fs::OsFilesystem,
        );
        let enc = EncryptedObjectStorage::new(local, cek);
        enc.put(std::path::Path::new("guest-test.txt"), plaintext)
            .await
            .expect("enc.put");
    }
    // Read raw (encrypted) bytes for later decryption verification.
    let raw_blob = std::fs::read(data_dir.join("guest-test.txt")).expect("read raw blob");

    // ── Generate guest X25519 ephemeral keypair ───────────────────────────────
    let guest_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let guest_x25519_pub = X25519PublicKey::from(&guest_secret);
    let guest_x25519_pub_bytes: [u8; 32] = *guest_x25519_pub.as_bytes();

    // ── Issue guest token with guest_ephemeral_pubkey ─────────────────────────
    let resp = env
        .client
        .inner()
        .send(&UserRequest::PairNodeEphemeral {
            user_id: user_id.clone(),
            label: "wrapped-deks-test".to_string(),
            paths: vec![file_path.to_string()],
            permissions: kotton_wire::peer::SessionPermissions::Read,
            ttl_seconds: 300,
            guest_ephemeral_pubkey: Some(guest_x25519_pub_bytes),
        })
        .await
        .expect("send PairNodeEphemeral");

    let session = match resp {
        UserResponse::SessionList { sessions } => {
            assert_eq!(sessions.len(), 1);
            sessions.into_iter().next().unwrap()
        }
        other => panic!("expected SessionList, got {other:?}"),
    };

    // ── Assert wrapped_deks is populated ─────────────────────────────────────
    assert!(
        session.wrapped_deks.contains_key(file_path),
        "wrapped_deks must contain an entry for '{file_path}', got: {:?}",
        session.wrapped_deks.keys().collect::<Vec<_>>()
    );
    let rewrapped_dek_bytes = &session.wrapped_deks[file_path];
    assert_eq!(
        rewrapped_dek_bytes.len(),
        40,
        "wrapped DEK must be 40 bytes"
    );

    // ── Derive session key on the guest side ─────────────────────────────────
    // The issuer's X25519 pubkey is derived from their Ed25519 identity key, read
    // through the daemon's secrets handle — the account is locked at creation
    // (`DEC-0049`), so the root is in custody rather than the platform store.
    let identity_hex = env
        .runtime
        .secrets()
        .get_secret(&kdf_labels::identity_signing_key(&user_id))
        .expect("get identity key")
        .expect("identity key must exist after create_user");
    let identity_seed: [u8; 32] = hex::decode(&identity_hex)
        .expect("decode identity hex")
        .try_into()
        .expect("identity key must be 32 bytes");
    let issuer_signing_key = ed25519_dalek::SigningKey::from_bytes(&identity_seed);
    let issuer_x25519_pub = kotton_peer::pairing::ed25519_to_x25519_public(
        issuer_signing_key.verifying_key().to_bytes(),
    )
    .expect("ed25519_to_x25519_public");

    let shared_secret = guest_secret.diffie_hellman(&issuer_x25519_pub);
    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut session_key = [0u8; 32];
    hk.expand(b"kotton:guest-session:v1", &mut session_key)
        .expect("HKDF expand");
    let session_kek = KekAes256::from(session_key);

    // ── Unwrap the DEK with the session key ───────────────────────────────────
    let wrapped: [u8; 40] = rewrapped_dek_bytes
        .as_slice()
        .try_into()
        .expect("40-byte wrapped DEK");
    let mut dek = [0u8; 32];
    session_kek
        .unwrap(&wrapped, &mut dek)
        .expect("AES-KW unwrap DEK");

    // ── Decrypt the raw blob with the unwrapped DEK ───────────────────────────
    // Wire format: [wrapped_dek: 40B][nonce: 12B][ciphertext+tag]
    const WRAPPED_DEK_LEN: usize = 40;
    const NONCE_LEN: usize = 12;
    const HEADER_LEN: usize = WRAPPED_DEK_LEN + NONCE_LEN;
    assert!(raw_blob.len() >= HEADER_LEN, "blob too short");

    let nonce_bytes: [u8; 12] = raw_blob[WRAPPED_DEK_LEN..HEADER_LEN]
        .try_into()
        .expect("12-byte nonce");
    let ciphertext = &raw_blob[HEADER_LEN..];

    use chacha20poly1305::{
        aead::{Aead, KeyInit, Payload},
        ChaCha20Poly1305,
    };
    let cipher = ChaCha20Poly1305::new_from_slice(&dek).expect("ChaCha20Poly1305::new");
    let nonce = chacha20poly1305::Nonce::from(nonce_bytes);
    // The object is sealed with its canonical path bound as AEAD AAD (H5). The
    // guest holds the path (it keyed `wrapped_deks`), so it reconstructs the
    // same AAD — `path_aad` canonicalizes away the leading slash so `/guest-
    // test.txt` matches the storage key `guest-test.txt`.
    let aad = kotton_store::path_aad(std::path::Path::new(file_path));
    let decrypted = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .expect("decrypt ciphertext");

    assert_eq!(
        decrypted.as_slice(),
        plaintext,
        "decrypted plaintext must match original"
    );

    env.client.logout_user(&user_id).await.ok();
}

// ── deferred: QUIC-dependent tests ───────────────────────────────────────────

/// Full-device pairing requires a QUIC bootstrap listener (v0.4).
/// When wired: spawn two daemon instances, run the device add/join ceremony,
/// write a file on instance A, read it on instance B.
#[tokio::test]
#[ignore = "requires live QUIC listener (v0.4)"]
async fn full_device_pairing_round_trip() {}

/// Guest token expiry enforcement runs on the QUIC peer path.
/// When wired: issue a token with ttl_seconds=1, sleep 2 s, connect as a
/// peer over QUIC, verify the request is rejected with "ephemeral session expired".
#[tokio::test]
#[ignore = "requires live QUIC peer path (v0.4)"]
async fn guest_token_expiry_enforced_on_peer_path() {}
