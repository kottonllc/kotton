// SPDX-License-Identifier: AGPL-3.0-or-later
//! Trust registry and grant management IPC handlers — Step 8 (identity_model).
//!
//! Covers the five new request variants:
//!
//! - `TrustAdd`    — add an org DID to the trusted-issuer registry
//! - `TrustRemove` — remove an org DID from the trusted-issuer registry
//! - `TrustList`   — list all trusted-issuer DIDs
//! - `GrantRevoke` — add an envelope ID to the local revocation list
//! - `GrantImport` — verify and store a cross-DID `GrantEnvelope`

use super::db::grant_db;
use kotton_wire::ipc::UserResponse;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::Signature;
use kotton_wire::GrantEnvelope;
use kotton_crypto::DidKeyMethod;
use sqlx::SqlitePool;
use std::io;

// ── Trust registry ────────────────────────────────────────────────────────────

/// `TrustAdd` — add `org_did` to the trusted-issuer registry.
pub async fn trust_add(pool: &SqlitePool, org_did: String) -> io::Result<UserResponse> {
    grant_db::add_trusted_issuer(pool, &org_did).await?;
    Ok(UserResponse::TrustAdded)
}

/// `TrustRemove` — remove `org_did` from the trusted-issuer registry.
pub async fn trust_remove(pool: &SqlitePool, org_did: String) -> io::Result<UserResponse> {
    grant_db::remove_trusted_issuer(pool, &org_did).await?;
    Ok(UserResponse::TrustRemoved)
}

/// `TrustList` — list all trusted-issuer DIDs.
pub async fn trust_list(pool: &SqlitePool) -> io::Result<UserResponse> {
    let dids = grant_db::list_trusted_issuers(pool).await?;
    Ok(UserResponse::TrustedIssuers { dids })
}

// ── Grant revocation ──────────────────────────────────────────────────────────

/// `GrantRevoke` — add `envelope_id` to the local revocation list.
pub async fn grant_revoke(pool: &SqlitePool, envelope_id: String) -> io::Result<UserResponse> {
    grant_db::revoke_envelope(pool, &envelope_id).await?;
    Ok(UserResponse::GrantRevoked)
}

// ── Grant import ──────────────────────────────────────────────────────────────

/// `GrantImport` — verify and store a cross-DID `GrantEnvelope`.
///
/// Validation steps:
/// 1. Deserialise the JSON.
/// 2. Reject self-signed envelopes (`issuer_did == subject_did`).
/// 3. Verify that `issuer_did` is in the trusted-issuer registry.
/// 4. Verify the Ed25519 signature.
/// 5. Reject envelopes whose ID is in a revocation list — the caller's own
///    (`pool`, per-user since RFC-0063 stage 3b-iii) **or** the org-side one
///    (`org_revocations`, machine-wide with the rest of the org state until
///    stage 3b-iv): an org's revocation of a member's envelope is the org's
///    statement, recorded with org authority, and an import must honor it.
/// 6. Store in `imported_grant_envelopes`.
pub async fn grant_import(
    pool: &SqlitePool,
    org_revocations: &SqlitePool,
    envelope_json: String,
) -> io::Result<UserResponse> {
    // Step 1: deserialise.
    let envelope: GrantEnvelope = serde_json::from_str(&envelope_json).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid envelope JSON: {e}"),
        )
    })?;

    // Step 2: reject self-signed (those are created at app install time; they
    // are not imported by the user).
    if envelope.issuer_did == envelope.subject_did {
        return Ok(UserResponse::Error {
            message: "self-signed envelopes cannot be imported; \
                      they are created automatically at app install time"
                .to_string(),
        });
    }

    // Step 3: trusted-issuer check.
    let issuer = envelope.issuer_did.to_string();
    if !grant_db::is_trusted_issuer(pool, &issuer).await? {
        return Ok(UserResponse::Error {
            message: format!(
                "issuer '{issuer}' is not in the trusted-issuer registry; \
                 run `kotton trust add {issuer}` first"
            ),
        });
    }

    // Step 4: signature verification.
    if !verify_envelope_signature(&envelope) {
        return Ok(UserResponse::Error {
            message: format!(
                "signature verification failed for envelope '{}'",
                envelope.id
            ),
        });
    }

    // Step 5: revocation check — a revoked envelope must never be imported,
    // whether the caller revoked it themselves or its issuing org did.
    if grant_db::is_revoked(pool, &envelope.id).await?
        || grant_db::is_revoked(org_revocations, &envelope.id).await?
    {
        return Ok(UserResponse::Error {
            message: format!("envelope '{}' has been revoked", envelope.id),
        });
    }

    // Step 6: store.
    let envelope_id = envelope.id.clone();
    grant_db::store_imported_envelope(pool, &envelope).await?;

    Ok(UserResponse::GrantImported { envelope_id })
}

// ── Signature helper ──────────────────────────────────────────────────────────

/// Verify the Ed25519 signature on a `GrantEnvelope`.
///
/// Returns `true` if the signature is valid, `false` on any failure
/// (bad DID, bad base64, wrong length, or verification failure).
pub fn verify_envelope_signature(envelope: &GrantEnvelope) -> bool {
    let verifying_key = match DidKeyMethod::to_public_key(&envelope.issuer_did) {
        Ok(vk) => vk,
        Err(_) => return false,
    };

    let sig_bytes = match URL_SAFE_NO_PAD.decode(&envelope.issuer_signature) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig_arr: [u8; 64] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let signature = Signature::from_bytes(&sig_arr);

    let canonical = match envelope.canonical_json() {
        Ok(s) => s,
        Err(_) => return false,
    };

    use ed25519_dalek::Verifier as _;
    verifying_key
        .verify(canonical.as_bytes(), &signature)
        .is_ok()
}
