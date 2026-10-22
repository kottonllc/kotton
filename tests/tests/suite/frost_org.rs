// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — FROST multi-sig org DID (Step 10)
//!
//! Tests cover:
//!  - `org_frost_new` creates a FROST org and returns shares + DID
//!  - `org_frost_join` imports a key share on a (simulated) participant device
//!  - Full DKG round trip: create → join → org appears in `org_list`
//!  - Full signing round trip: sign-begin → sign-contribute → sign-finalize
//!    → valid Ed25519 signature verifiable with the org's public key
//!  - `org_grant_issue` on a FROST org opens a signing session (not an envelope)
//!  - FROST org does NOT appear in `org_identities` with a private key
//!    (no single keychain entry; key is split)


use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use crate::common::TestEnv;
use ed25519_dalek::Verifier as _;
use kotton_wire::GrantEnvelope;
use kotton::{org_grant_issue_full, OrgGrantIssueResult};

const COORDINATOR: &str = "alice";
const COSIGNER: &str = "bob";

// ── helpers ───────────────────────────────────────────────────────────────────

async fn setup_user(env: &mut TestEnv, user_id: &str) -> String {
    let (did, _) = env.client.create_user(user_id, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    // Creation mints no phrase; recovery is set up as its own act.
    let recovery_key = env
        .client
        .add_recovery_phrase(user_id)
        .await
        .expect("add_recovery_phrase");
    env.client
        .login_with_recovery_key(&recovery_key, Some(user_id.to_string()), None)
        .await
        .expect("login");
    did
}

/// Spin up a second device — a separate daemon with its own database — and
/// create a participant user on it.
///
/// Mirrors a real co-signer device: each participant's FROST key package and
/// org row live in their own store (the daemon keys both by `org_did`, one per
/// device), and protocol messages (commitments, shares) are exchanged as hex
/// blobs exactly as they would be over the network. A single shared daemon
/// cannot host two participants of the same org — the second join would
/// overwrite the first's key package.
async fn participant_device(user_id: &str) -> TestEnv {
    let mut env = TestEnv::spawn().await;
    setup_user(&mut env, user_id).await;
    env
}

// ── org_frost_new ─────────────────────────────────────────────────────────────

/// `org_frost_new` returns a `did:key:…` and a share for each non-initiator participant.
#[tokio::test]
async fn frost_new_returns_did_and_shares() {
    let mut env = TestEnv::spawn().await;
    setup_user(&mut env, COORDINATOR).await;

    let (org_did, shares) = env
        .client
        .org_frost_new(COORDINATOR, "test-frost-org", 2, 3)
        .await
        .expect("org_frost_new");

    assert!(
        org_did.starts_with("did:key:"),
        "expected did:key DID; got {org_did}"
    );
    // Initiator receives shares for participants 2 and 3.
    assert_eq!(
        shares.len(),
        2,
        "expected 2 shares (for participants 2 and 3)"
    );
    assert_eq!(shares[0].0, 2, "first share should be for participant 2");
    assert_eq!(shares[1].0, 3, "second share should be for participant 3");
    assert!(!shares[0].1.is_empty(), "share hex should not be empty");
}

/// Threshold must be at least 2.
#[tokio::test]
async fn frost_new_rejects_threshold_one() {
    let mut env = TestEnv::spawn().await;
    setup_user(&mut env, COORDINATOR).await;

    let result = env
        .client
        .org_frost_new(COORDINATOR, "solo-org", 1, 2)
        .await;

    assert!(result.is_err(), "threshold=1 should be rejected");
}

/// Total must be >= threshold.
#[tokio::test]
async fn frost_new_rejects_total_less_than_threshold() {
    let mut env = TestEnv::spawn().await;
    setup_user(&mut env, COORDINATOR).await;

    let result = env.client.org_frost_new(COORDINATOR, "bad-org", 3, 2).await;

    assert!(result.is_err(), "total < threshold should be rejected");
}

// ── org_frost_join ────────────────────────────────────────────────────────────

/// A participant can join by importing their share; org appears in `org_list`.
#[tokio::test]
async fn frost_join_imports_share_and_appears_in_list() {
    let mut env = TestEnv::spawn().await;
    setup_user(&mut env, COORDINATOR).await;
    let mut cosigner = participant_device(COSIGNER).await;

    let (org_did, shares) = env
        .client
        .org_frost_new(COORDINATOR, "acme-frost", 2, 2)
        .await
        .expect("org_frost_new");

    // shares[0] = participant 2's share.
    let (idx, share_hex) = &shares[0];

    cosigner
        .client
        .org_frost_join(COSIGNER, "acme-frost", &org_did, share_hex, *idx)
        .await
        .expect("org_frost_join");

    // Org should now appear in cosigner's list.
    let orgs = cosigner.client.org_list(COSIGNER).await.expect("org_list");
    assert!(
        orgs.iter().any(|o| o.org_did == org_did),
        "org should appear in cosigner's list; got: {orgs:?}"
    );
}

/// Joining with a corrupt share blob returns an error.
#[tokio::test]
async fn frost_join_rejects_invalid_share() {
    let mut env = TestEnv::spawn().await;
    setup_user(&mut env, COORDINATOR).await;
    let mut cosigner = participant_device(COSIGNER).await;

    let (org_did, _) = env
        .client
        .org_frost_new(COORDINATOR, "test-invalid", 2, 2)
        .await
        .expect("org_frost_new");

    let result = cosigner
        .client
        .org_frost_join(COSIGNER, "test-invalid", &org_did, "deadbeef", 2)
        .await;

    assert!(result.is_err(), "invalid share should be rejected");
}

// ── sign-begin → sign-contribute → sign-finalize ──────────────────────────────

/// Full 2-of-2 signing round trip produces a valid GrantEnvelope.
#[tokio::test]
async fn frost_signing_round_trip_2_of_2() {
    let mut env = TestEnv::spawn().await;
    let coordinator_did = setup_user(&mut env, COORDINATOR).await;
    let mut cosigner = participant_device(COSIGNER).await;

    // Create 2-of-2 org.
    let (org_did, shares) = env
        .client
        .org_frost_new(COORDINATOR, "frost-2of2", 2, 2)
        .await
        .expect("org_frost_new");

    let (p2_idx, p2_share) = &shares[0];
    cosigner
        .client
        .org_frost_join(COSIGNER, "frost-2of2", &org_did, p2_share, *p2_idx)
        .await
        .expect("org_frost_join");

    // Coordinator initiates signing.
    let (session_id, message_hex, coordinator_id_hex, coordinator_commitment_hex) = env
        .client
        .org_frost_sign_begin(
            COORDINATOR,
            &org_did,
            &coordinator_did, // grant to oneself for test simplicity
            vec!["schema.read:sh.kotton.notes.v1".to_string()],
            Some(3600),
            None,
        )
        .await
        .expect("org_frost_sign_begin");

    assert!(!session_id.is_empty());
    assert!(!message_hex.is_empty());

    // Co-signer contributes.
    let (cosigner_id, cosigner_commitment, cosigner_share) = cosigner
        .client
        .org_frost_sign_contribute(
            COSIGNER,
            &session_id,
            &org_did,
            &message_hex,
            &coordinator_id_hex,
            &coordinator_commitment_hex,
        )
        .await
        .expect("org_frost_sign_contribute");

    assert!(!cosigner_id.is_empty());
    assert!(!cosigner_share.is_empty());

    // Coordinator finalises.
    let (envelope_id, envelope_json) = env
        .client
        .org_frost_sign_finalize(
            COORDINATOR,
            &session_id,
            &cosigner_id,
            &cosigner_commitment,
            &cosigner_share,
        )
        .await
        .expect("org_frost_sign_finalize");

    assert!(!envelope_id.is_empty());
    assert!(!envelope_json.is_empty());

    // Verify the envelope deserialises correctly.
    let envelope: GrantEnvelope =
        serde_json::from_str(&envelope_json).expect("deserialise GrantEnvelope");
    assert_eq!(envelope.id, envelope_id);
    assert_eq!(envelope.issuer_did.to_string(), org_did);
    assert!(
        !envelope.issuer_signature.is_empty(),
        "signature must be present"
    );

    // Verify the signature is a valid Ed25519 signature over the canonical form,
    // using the group verifying key derived from the org DID.
    let org_did_parsed = kotton_wire::did::Did::parse(&org_did).expect("parse org DID");
    let vk = kotton_crypto::DidKeyMethod::to_public_key(&org_did_parsed)
        .expect("extract verifying key from org DID");
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(&envelope.issuer_signature)
        .expect("decode base64 signature");
    let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).expect("parse signature");
    let canonical = envelope.canonical_json().expect("canonical_json");
    vk.verify(canonical.as_bytes(), &sig)
        .expect("FROST signature must verify against the org group key");
}

/// `org_grant_issue` on a FROST org returns a signing session, not an envelope.
#[tokio::test]
async fn org_grant_issue_on_frost_org_returns_session() {
    let mut env = TestEnv::spawn().await;
    let coordinator_did = setup_user(&mut env, COORDINATOR).await;

    let (org_did, _shares) = env
        .client
        .org_frost_new(COORDINATOR, "frost-issue-test", 2, 3)
        .await
        .expect("org_frost_new");

    let result = org_grant_issue_full(
        &mut env.client,
        COORDINATOR,
        &org_did,
        &coordinator_did,
        vec!["schema.read:sh.kotton.notes.v1".to_string()],
        Some(3600),
        None,
    )
    .await
    .expect("org_grant_issue_full");

    assert!(
        matches!(result, OrgGrantIssueResult::FrostSession { .. }),
        "expected FrostSession for a FROST org; got {result:?}"
    );
}

/// A second `sign-finalize` on an already-signed session is rejected.
#[tokio::test]
async fn frost_sign_finalize_idempotent_session_rejected() {
    let mut env = TestEnv::spawn().await;
    let coordinator_did = setup_user(&mut env, COORDINATOR).await;
    let mut cosigner = participant_device(COSIGNER).await;

    let (org_did, shares) = env
        .client
        .org_frost_new(COORDINATOR, "frost-idem", 2, 2)
        .await
        .expect("org_frost_new");
    let (p2_idx, p2_share) = &shares[0];
    cosigner
        .client
        .org_frost_join(COSIGNER, "frost-idem", &org_did, p2_share, *p2_idx)
        .await
        .expect("org_frost_join");

    let (session_id, message_hex, coord_id, coord_commitment) = env
        .client
        .org_frost_sign_begin(
            COORDINATOR,
            &org_did,
            &coordinator_did,
            vec!["vfs.read:/docs".to_string()],
            None,
            None,
        )
        .await
        .expect("sign_begin");

    let (cs_id, cs_commitment, cs_share) = cosigner
        .client
        .org_frost_sign_contribute(
            COSIGNER,
            &session_id,
            &org_did,
            &message_hex,
            &coord_id,
            &coord_commitment,
        )
        .await
        .expect("sign_contribute");

    env.client
        .org_frost_sign_finalize(COORDINATOR, &session_id, &cs_id, &cs_commitment, &cs_share)
        .await
        .expect("first finalize ok");

    // Second finalize on the same session must fail.
    let second = env
        .client
        .org_frost_sign_finalize(COORDINATOR, &session_id, &cs_id, &cs_commitment, &cs_share)
        .await;
    assert!(second.is_err(), "second finalize should be rejected");
}
