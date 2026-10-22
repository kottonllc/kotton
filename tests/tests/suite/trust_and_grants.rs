// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — Trust registry and grant management (Step 8)
//!
//! These tests verify the `kotton trust` and `kotton grant` IPC paths at the
//! daemon boundary via `KottonClient`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use crate::common::cli::{said, Cli};
use crate::common::TestEnv;
use ed25519_dalek::{Signer as _, SigningKey};
use kotton_wire::did::Did;
use kotton_wire::GrantEnvelope;
use kotton_crypto::DidKeyMethod;
use kotton_schemas::{CapabilityGrant, CapabilityKind, Nsid};
use rand::rngs::OsRng;
use std::time::{SystemTime, UNIX_EPOCH};

const USER: &str = "alice";

// ── helpers ───────────────────────────────────────────────────────────────────

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Generate an Ed25519 signing key and derive its `did:key:…` string.
fn gen_org_key() -> (SigningKey, String) {
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    let did = DidKeyMethod::from_public_key(&vk);
    (sk, did.to_string())
}

/// Build and sign a `GrantEnvelope` granting `schema.read:sh.kotton.notes`
/// from `issuer_did` to `subject_did`, signed with `signing_key`.
fn signed_envelope(signing_key: &SigningKey, issuer_did: &str, subject_did: &str) -> GrantEnvelope {
    let grant = CapabilityGrant::schema(CapabilityKind::Read, Nsid::from_static("sh.kotton.notes"));

    let mut env = GrantEnvelope {
        id: uuid::Uuid::new_v4().to_string(),
        issuer_did: Did::parse(issuer_did).expect("valid issuer DID"),
        subject_did: Did::parse(subject_did).expect("valid subject DID"),
        node_did: None,
        grants: vec![grant],
        issued_at: now_secs(),
        expires_at: None,
        app_id: Some("sh.kotton.notes-app".to_string()),
        issuer_signature: String::new(), // filled in below
    };

    // Produce canonical JSON (same ordering as GrantEnvelope::canonical_json).
    let canonical = env.canonical_json().expect("canonical_json");
    let sig = signing_key.sign(canonical.as_bytes());
    env.issuer_signature = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    env
}

/// Build a *self-signed* `GrantEnvelope` (issuer == subject), signed with the
/// given signing key whose DID is `did`.
fn self_signed_envelope(signing_key: &SigningKey, did: &str) -> GrantEnvelope {
    signed_envelope(signing_key, did, did)
}

// ── trust registry tests ──────────────────────────────────────────────────────

/// On a fresh daemon the trust list is empty.
#[tokio::test]
async fn trust_list_empty_by_default() {
    let mut env = TestEnv::spawn().await;
    let (_, _) = setup_user(&mut env).await;

    let dids = env.client.trust_list(USER).await.expect("trust_list");
    assert!(dids.is_empty(), "expected empty list; got: {dids:?}");
}

/// Adding an org DID makes it appear in the list.
#[tokio::test]
async fn trust_add_appears_in_list() {
    let mut env = TestEnv::spawn().await;
    let (_, _) = setup_user(&mut env).await;

    let (_, org_did) = gen_org_key();

    env.client
        .trust_add(USER, &org_did)
        .await
        .expect("trust_add");

    let dids = env.client.trust_list(USER).await.expect("trust_list");
    assert!(
        dids.contains(&org_did),
        "added DID should appear in list; got: {dids:?}"
    );
}

/// Adding the same DID twice is idempotent (INSERT OR IGNORE).
#[tokio::test]
async fn trust_add_is_idempotent() {
    let mut env = TestEnv::spawn().await;
    let (_, _) = setup_user(&mut env).await;

    let (_, org_did) = gen_org_key();

    env.client
        .trust_add(USER, &org_did)
        .await
        .expect("first trust_add");
    env.client
        .trust_add(USER, &org_did)
        .await
        .expect("second trust_add (idempotent)");

    let dids = env.client.trust_list(USER).await.expect("trust_list");
    assert_eq!(
        dids.iter().filter(|d| *d == &org_did).count(),
        1,
        "duplicate add should not create a second entry"
    );
}

/// Removing a trusted DID makes it disappear from the list.
#[tokio::test]
async fn trust_remove_removes_from_list() {
    let mut env = TestEnv::spawn().await;
    let (_, _) = setup_user(&mut env).await;

    let (_, org_did) = gen_org_key();

    env.client
        .trust_add(USER, &org_did)
        .await
        .expect("trust_add");
    env.client
        .trust_remove(USER, &org_did)
        .await
        .expect("trust_remove");

    let dids = env.client.trust_list(USER).await.expect("trust_list");
    assert!(
        !dids.contains(&org_did),
        "removed DID should not appear in list; got: {dids:?}"
    );
}

// ── grant revocation tests ────────────────────────────────────────────────────

/// Revoking an arbitrary envelope ID succeeds (INSERT OR IGNORE).
#[tokio::test]
async fn grant_revoke_succeeds() {
    let mut env = TestEnv::spawn().await;
    let (_, _) = setup_user(&mut env).await;

    let id = uuid::Uuid::new_v4().to_string();
    env.client
        .grant_revoke(USER, &id)
        .await
        .expect("grant_revoke");
}

/// Revoking the same ID twice is idempotent.
#[tokio::test]
async fn grant_revoke_is_idempotent() {
    let mut env = TestEnv::spawn().await;
    let (_, _) = setup_user(&mut env).await;

    let id = uuid::Uuid::new_v4().to_string();
    env.client
        .grant_revoke(USER, &id)
        .await
        .expect("first revoke");
    env.client
        .grant_revoke(USER, &id)
        .await
        .expect("second revoke (idempotent)");
}

// ── grant import tests ────────────────────────────────────────────────────────

/// Importing a self-signed envelope is rejected.
#[tokio::test]
async fn grant_import_rejects_self_signed() {
    let mut env = TestEnv::spawn().await;
    let (_, _) = setup_user(&mut env).await;

    let (sk, did) = gen_org_key();
    let env_blob = self_signed_envelope(&sk, &did);
    let json = serde_json::to_string(&env_blob).expect("serialize");

    let result = env.client.grant_import(USER, &json).await;
    assert!(
        result.is_err(),
        "self-signed envelope import should fail; got: {result:?}"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("self-signed"),
        "error message should mention 'self-signed'; got: {msg}"
    );
}

/// Importing from an untrusted issuer is rejected.
#[tokio::test]
async fn grant_import_rejects_untrusted_issuer() {
    let mut env = TestEnv::spawn().await;
    let (user_did, _) = setup_user(&mut env).await;

    let (org_sk, org_did) = gen_org_key();
    // Intentionally do NOT call trust_add.
    let env_blob = signed_envelope(&org_sk, &org_did, &user_did);
    let json = serde_json::to_string(&env_blob).expect("serialize");

    let result = env.client.grant_import(USER, &json).await;
    assert!(
        result.is_err(),
        "import from untrusted issuer should fail; got: {result:?}"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("trusted-issuer") || msg.contains("trusted issuer"),
        "error should mention trusted-issuer; got: {msg}"
    );
}

/// Importing a properly signed envelope from a trusted issuer succeeds.
#[tokio::test]
async fn grant_import_valid_envelope_succeeds() {
    let mut env = TestEnv::spawn().await;
    let (user_did, _) = setup_user(&mut env).await;

    let (org_sk, org_did) = gen_org_key();

    // Trust the org first.
    env.client
        .trust_add(USER, &org_did)
        .await
        .expect("trust_add");

    // Sign and import.
    let env_blob = signed_envelope(&org_sk, &org_did, &user_did);
    let expected_id = env_blob.id.clone();
    let json = serde_json::to_string(&env_blob).expect("serialize");

    let imported_id = env
        .client
        .grant_import(USER, &json)
        .await
        .expect("grant_import should succeed for trusted, valid envelope");

    assert_eq!(
        imported_id, expected_id,
        "returned envelope id should match the imported envelope"
    );
}

/// Importing the same envelope twice is idempotent (INSERT OR REPLACE).
#[tokio::test]
async fn grant_import_is_idempotent() {
    let mut env = TestEnv::spawn().await;
    let (user_did, _) = setup_user(&mut env).await;

    let (org_sk, org_did) = gen_org_key();

    env.client
        .trust_add(USER, &org_did)
        .await
        .expect("trust_add");

    let env_blob = signed_envelope(&org_sk, &org_did, &user_did);
    let json = serde_json::to_string(&env_blob).expect("serialize");

    env.client
        .grant_import(USER, &json)
        .await
        .expect("first import");
    env.client
        .grant_import(USER, &json)
        .await
        .expect("second import (idempotent)");
}

/// Importing a tampered-signature envelope is rejected.
#[tokio::test]
async fn grant_import_rejects_bad_signature() {
    let mut env = TestEnv::spawn().await;
    let (user_did, _) = setup_user(&mut env).await;

    let (org_sk, org_did) = gen_org_key();

    env.client
        .trust_add(USER, &org_did)
        .await
        .expect("trust_add");

    let mut env_blob = signed_envelope(&org_sk, &org_did, &user_did);
    // Corrupt the signature.
    env_blob.issuer_signature = URL_SAFE_NO_PAD.encode([0u8; 64]);
    let json = serde_json::to_string(&env_blob).expect("serialize");

    let result = env.client.grant_import(USER, &json).await;
    assert!(
        result.is_err(),
        "tampered signature should be rejected; got: {result:?}"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("signature"),
        "error should mention signature; got: {msg}"
    );
}

/// **`kotton grant import` acts as the person it names, from the terminal.** The envelope an
/// org issued to Alice goes in through the CLI, as its own process with only Alice's cached
/// session, and the terminal names the envelope it imported. `grant revoke` reaches the
/// daemon by the same `connect_as(--user)`.
#[tokio::test]
async fn a_grant_is_imported_from_the_terminal_as_the_user_it_names() {
    let mut env = TestEnv::spawn_cli_reachable().await;
    let (user_did, _) = env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let (org_sk, org_did) = gen_org_key();
    env.client.trust_add(USER, &org_did).await.expect("trust_add");
    let envelope = signed_envelope(&org_sk, &org_did, &user_did);
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("envelope.json");
    std::fs::write(&path, serde_json::to_string(&envelope).expect("serialize")).expect("write envelope");
    let cli = Cli::for_env(&env);
    cli.seed_session(USER, env.client.session_token.as_deref().expect("alice logged in"));

    let imported = cli.run(&["grant", "import", path.to_str().expect("utf-8 path"), "--user", USER]);
    assert!(imported.status.success(), "`kotton grant import` failed.\n{}", said(&imported));
    assert_eq!(
        String::from_utf8_lossy(&imported.stdout).lines().next(),
        Some(format!("✓ Imported envelope: {}", envelope.id).as_str()),
        "the terminal names the envelope it imported.\n{}",
        said(&imported)
    );
}

// ── shared setup ──────────────────────────────────────────────────────────────

/// Create a user and authenticate so the session is active.
async fn setup_user(env: &mut TestEnv) -> (String, String) {
    let (did, _) = env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    // Creation mints no phrase; recovery is set up as its own act.
    let recovery_key = env
        .client
        .add_recovery_phrase(USER)
        .await
        .expect("add_recovery_phrase");
    env.client
        .login_with_recovery_key(&recovery_key, Some(USER.to_string()), None)
        .await
        .expect("login_with_recovery_key");
    (did, recovery_key)
}
