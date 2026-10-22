// SPDX-License-Identifier: AGPL-3.0-or-later
//! FROST multi-sig org IPC handlers — Step 10 (identity_model sprint).
//!
//! ## Design summary
//!
//! Key generation uses the **trusted-dealer** path.  The initiator runs
//! `OrgFrostNew`, which calls `frost::generate_key_shares` and gets back all
//! per-participant `KeyPackage` blobs.  The initiator's own package is stored
//! in `frost_key_packages`; the remaining blobs are returned in the response
//! and must be distributed to participants out-of-band.  Each participant
//! imports their blob with `OrgFrostJoin`.
//!
//! ## Phase A note
//!
//! The peer transport (`peer_messaging` sprint) is not finished yet, so the
//! signing ceremony exchanges blobs manually via CLI copy-paste.  Phase B will
//! wire the same daemon handlers to live peer messages; no logic changes.

use kotton_wire::ipc::UserResponse;
use super::db::{frost_db, org_db};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use kotton_sys::secret::SecretsStore;
use kotton_wire::{did::Did, GrantEnvelope};
use kotton_crypto::frost as frost_provider;
use kotton_schemas::CapabilityGrant;
use kotton_common::time::now_secs;
use sqlx::SqlitePool;
use std::io;
use std::sync::Arc;
use uuid::Uuid;

// ── OrgFrostNew ───────────────────────────────────────────────────────────────

/// Create a new FROST-keyed org using the trusted-dealer path.
///
/// 1. Calls `frost::generate_key_shares(threshold, total)`.
/// 2. Stores the initiator's key package + public key package in SQLite.
/// 3. Inserts a row in `org_identities` (so the org appears in `kotton org list`).
/// 4. Returns the share blobs for all other participants.
pub async fn org_frost_new(
    user_db: &Arc<SqlitePool>,
    user_id: &str,
    name: String,
    threshold: u16,
    total: u16,
    secrets: &dyn SecretsStore,
) -> io::Result<UserResponse> {
    let owner_did = match owner_did_for(user_id, secrets) {
        Some(d) => d,
        None => {
            return Ok(UserResponse::Error {
                message: "identity key not available — unlock your session first".to_string(),
            });
        }
    };

    // Validate params early.
    if threshold < 2 {
        return Ok(UserResponse::Error {
            message: "threshold must be at least 2".to_string(),
        });
    }
    if total < threshold {
        return Ok(UserResponse::Error {
            message: "total participants must be >= threshold".to_string(),
        });
    }

    let (mut shares, pubkey_hex, org_did) =
        frost_provider::generate_key_shares(threshold, total)
            .map_err(|e| io::Error::other(format!("frost keygen: {e}")))?;

    // shares[0] = (1, initiator_key_package_hex)
    let (_, initiator_kp_hex) = shares.remove(0); // index 1 → initiator

    // Extract the initiator's FROST Identifier hex (stable — derived from the key package).
    let (_, _, initiator_id_hex) = frost_provider::signing_commit(&initiator_kp_hex)
        .map_err(|e| io::Error::other(format!("frost id probe: {e}")))?;

    // Store initiator's key package.
    frost_db::upsert_key_package(user_db, &org_did, &initiator_kp_hex, 1, &initiator_id_hex).await?;

    // Store initiator's frost_org row (pubkey + metadata).
    frost_db::insert_frost_org(
        user_db,
        &org_did,
        &name,
        &owner_did,
        threshold,
        total,
        &pubkey_hex,
    )
    .await?;

    // Also insert into org_identities so `kotton org list` shows it.
    org_db::insert_org(user_db, &org_did, &name, &owner_did).await?;

    tracing::info!(
        %org_did,
        %name,
        threshold,
        total,
        "FROST org created"
    );

    Ok(UserResponse::OrgFrostCreated {
        org_did,
        // remaining shares: indices 2..=total
        shares: shares
            .into_iter()
            .map(|(idx, share)| (idx, kotton_wire::ipc::SecretText::new(share)))
            .collect(),
    })
}

// ── OrgFrostJoin ──────────────────────────────────────────────────────────────

/// A non-initiator participant imports their FROST key share.
///
/// Validates the `KeyPackage` blob, stores it in `frost_key_packages`, and
/// inserts a row in `org_identities` so the org appears in `kotton org list`.
pub async fn org_frost_join(
    user_db: &Arc<SqlitePool>,
    user_id: &str,
    name: String,
    org_did: String,
    share_hex: String,
    participant_idx: u16,
    secrets: &dyn SecretsStore,
) -> io::Result<UserResponse> {
    let owner_did = match owner_did_for(user_id, secrets) {
        Some(d) => d,
        None => {
            return Ok(UserResponse::Error {
                message: "identity key not available — unlock your session first".to_string(),
            });
        }
    };

    // Validate the share.
    frost_provider::validate_key_package(&share_hex)
        .map_err(|e| io::Error::other(format!("invalid key package: {e}")))?;

    // Extract the participant identifier by doing a probe commit.
    let (_, _, participant_id_hex) = frost_provider::signing_commit(&share_hex)
        .map_err(|e| io::Error::other(format!("frost id probe: {e}")))?;

    // Store key package.
    frost_db::upsert_key_package(
        user_db,
        &org_did,
        &share_hex,
        participant_idx,
        &participant_id_hex,
    )
    .await?;

    // Insert into org_identities (may already exist if this device is re-joining).
    let _ = org_db::insert_org(user_db, &org_did, &name, &owner_did).await;

    tracing::info!(%org_did, %name, participant_idx, "joined FROST org");

    Ok(UserResponse::OrgFrostJoined { org_did })
}

// ── OrgFrostSignBegin ─────────────────────────────────────────────────────────

/// Initiate a FROST signing ceremony — coordinator side, round 1.
///
/// Builds the unsigned `GrantEnvelope`, serialises it as the message, runs
/// FROST round-1 (`signing_commit`), persists the session, and returns the
/// session metadata needed by co-signers.
// Allowed: the grant's five fields plus the stores, passed through whole to the signing
// session; the struct that would hold them is the grant this call builds.
#[allow(clippy::too_many_arguments)]
pub async fn org_frost_sign_begin(
    user_db: &Arc<SqlitePool>,
    user_id: &str,
    org_did: String,
    member_did: String,
    caps: Vec<String>,
    ttl_secs: Option<i64>,
    node_did: Option<String>,
    _secrets: &dyn SecretsStore,
) -> io::Result<UserResponse> {
    // Confirm this is a FROST org (we check existence; pubkey is used during finalize).
    let (_, _, _) = match frost_db::get_frost_org(user_db, &org_did).await? {
        Some(row) => row,
        None => {
            return Ok(UserResponse::Error {
                message: format!("{org_did} is not a FROST org on this device"),
            });
        }
    };

    // Load this device's key package for the given org (coord_id comes from signing_commit).
    let (kp_hex, _, _) = match frost_db::get_key_package(user_db, &org_did).await? {
        Some(row) => row,
        None => {
            return Ok(UserResponse::Error {
                message: format!("no key package found for {org_did} — join the org first"),
            });
        }
    };

    // Parse caps and DIDs.
    let grants = match parse_caps(&caps) {
        Ok(g) => g,
        Err(e) => return Ok(UserResponse::Error { message: e }),
    };

    let subject_did = match Did::parse(&member_did) {
        Ok(d) => d,
        Err(e) => {
            return Ok(UserResponse::Error {
                message: format!("invalid member_did: {e}"),
            });
        }
    };

    let issuer_did = match Did::parse(&org_did) {
        Ok(d) => d,
        Err(e) => {
            return Ok(UserResponse::Error {
                message: format!("invalid org_did: {e}"),
            });
        }
    };

    let node_did_parsed: Option<Did> = match &node_did {
        None => None,
        Some(s) => match Did::parse(s) {
            Ok(d) => Some(d),
            Err(e) => {
                return Ok(UserResponse::Error {
                    message: format!("invalid node_did: {e}"),
                });
            }
        },
    };

    let now = now_secs();
    let expires_at = ttl_secs.map(|ttl| now + ttl);

    // Build unsigned GrantEnvelope (signature field intentionally empty —
    // canonical_json() excludes it).
    let envelope = GrantEnvelope {
        id: Uuid::new_v4().to_string(),
        issuer_did,
        subject_did,
        node_did: node_did_parsed,
        grants,
        issued_at: now,
        expires_at,
        // Not an app grant: this envelope authorises a member of an org, and the
        // app binding (`DEC-0052`) does not apply. `check_grant` refuses an
        // unbound envelope, which is why this must never be stored in
        // `app_grant_envelopes`.
        app_id: None,
        issuer_signature: String::new(),
    };

    let canonical = envelope
        .canonical_json()
        .map_err(|e| io::Error::other(format!("canonical_json: {e}")))?;
    let message_hex = hex::encode(canonical.as_bytes());

    // FROST round 1: generate nonces and commitment.
    let (nonces_hex, commitment_hex, coord_actual_id_hex) = frost_provider::signing_commit(&kp_hex)
        .map_err(|e| io::Error::other(format!("frost round1: {e}")))?;

    // Serialise the pending envelope fields for later reconstruction.
    let caps_json = serde_json::to_string(&envelope.grants)
        .map_err(|e| io::Error::other(format!("caps_json: {e}")))?;

    let session_id = Uuid::new_v4().to_string();

    frost_db::insert_signing_session(
        user_db,
        &session_id,
        &org_did,
        user_id,
        &member_did,
        &caps_json,
        ttl_secs,
        node_did.as_deref(),
        &message_hex,
        &nonces_hex,
        &commitment_hex,
        &coord_actual_id_hex,
    )
    .await?;

    tracing::info!(
        %session_id,
        %org_did,
        %member_did,
        "FROST signing session opened"
    );

    Ok(UserResponse::OrgFrostSignSession {
        session_id,
        message_hex,
        coordinator_id_hex: coord_actual_id_hex,
        coordinator_commitment_hex: commitment_hex,
    })
}

// ── OrgFrostSignContribute ────────────────────────────────────────────────────

/// Co-signer: run both round-1 and round-2 atomically and return the result.
///
/// The co-signer does not need to persist anything — they execute both FROST
/// signing rounds in one shot and return `(commitment, share)` to the
/// coordinator.
pub async fn org_frost_sign_contribute(
    user_db: &Arc<SqlitePool>,
    _user_id: &str,
    _session_id: String,
    org_did: String,
    message_hex: String,
    coordinator_id_hex: String,
    coordinator_commitment_hex: String,
) -> io::Result<UserResponse> {
    // Load this device's key package for the given org.
    let (kp_hex, _, _) = match frost_db::get_key_package(user_db, &org_did).await? {
        Some(row) => row,
        None => {
            return Ok(UserResponse::Error {
                message: format!("no key package found for {org_did}"),
            });
        }
    };

    // Round 1: generate our nonces and commitment.
    let (nonces_hex, my_commitment_hex, my_id_hex) = frost_provider::signing_commit(&kp_hex)
        .map_err(|e| io::Error::other(format!("frost round1: {e}")))?;

    // Build signing package with both commitments.
    let message_bytes =
        hex::decode(&message_hex).map_err(|e| io::Error::other(format!("hex decode: {e}")))?;

    let commitments = vec![
        (coordinator_id_hex, coordinator_commitment_hex),
        (my_id_hex.clone(), my_commitment_hex.clone()),
    ];

    let signing_package_hex = frost_provider::create_signing_package(&message_bytes, &commitments)
        .map_err(|e| io::Error::other(format!("frost signing package: {e}")))?;

    // Round 2: produce our signature share.
    let my_share_hex = frost_provider::signing_sign(&kp_hex, &nonces_hex, &signing_package_hex)
        .map_err(|e| io::Error::other(format!("frost round2: {e}")))?;

    Ok(UserResponse::OrgFrostContributed {
        cosigner_id_hex: my_id_hex,
        cosigner_commitment_hex: my_commitment_hex,
        cosigner_share_hex: kotton_wire::ipc::SecretText::new(my_share_hex),
    })
}

// ── OrgFrostSignFinalize ──────────────────────────────────────────────────────

/// Coordinator finalises the FROST signing ceremony and issues the `GrantEnvelope`.
///
/// 1. Load the signing session + coordinator key material.
/// 2. Build the same `SigningPackage` the co-signer used.
/// 3. Sign with the coordinator's own key share.
/// 4. Aggregate both shares → final Ed25519 signature.
/// 5. Embed signature into the `GrantEnvelope` and record in `org_members`.
pub async fn org_frost_sign_finalize(
    user_db: &Arc<SqlitePool>,
    _user_id: &str,
    session_id: String,
    cosigner_id_hex: String,
    cosigner_commitment_hex: String,
    cosigner_share_hex: String,
) -> io::Result<UserResponse> {
    // Load session.
    let session = match frost_db::get_signing_session(user_db, &session_id).await? {
        Some(s) => s,
        None => {
            return Ok(UserResponse::Error {
                message: format!("signing session not found or already complete: {session_id}"),
            });
        }
    };

    // Load coordinator's key package.
    let (coord_kp_hex, _, _) = match frost_db::get_key_package(user_db, &session.org_did).await? {
        Some(row) => row,
        None => {
            return Ok(UserResponse::Error {
                message: format!(
                    "no key package found for {} — was this org created on this device?",
                    session.org_did
                ),
            });
        }
    };

    // Load pubkey package for aggregation.
    let (pubkey_hex, _, _) = match frost_db::get_frost_org(user_db, &session.org_did).await? {
        Some(row) => row,
        None => {
            return Ok(UserResponse::Error {
                message: format!(
                    "{} does not have a stored pubkey package on this device",
                    session.org_did
                ),
            });
        }
    };

    let message_bytes = hex::decode(&session.message_hex)
        .map_err(|e| io::Error::other(format!("hex decode message: {e}")))?;

    // Build signing package: coordinator's commitment + co-signer's commitment.
    let commitments = vec![
        (
            session.participant_id_hex.clone(),
            session.commitment_hex.clone(),
        ),
        (cosigner_id_hex.clone(), cosigner_commitment_hex),
    ];

    let signing_package_hex = frost_provider::create_signing_package(&message_bytes, &commitments)
        .map_err(|e| io::Error::other(format!("frost signing package: {e}")))?;

    // Coordinator signs with their own key share.
    let coord_share_hex =
        frost_provider::signing_sign(&coord_kp_hex, &session.nonces_hex, &signing_package_hex)
            .map_err(|e| io::Error::other(format!("frost coordinator round2: {e}")))?;

    // Aggregate.
    let sig_shares = vec![
        (session.participant_id_hex.clone(), coord_share_hex),
        (cosigner_id_hex, cosigner_share_hex),
    ];

    let sig_bytes = frost_provider::aggregate(&signing_package_hex, &pubkey_hex, &sig_shares)
        .map_err(|e| io::Error::other(format!("frost aggregate: {e}")))?;

    // Rebuild the GrantEnvelope from the stored session fields.
    let grants: Vec<CapabilityGrant> = serde_json::from_str(&session.caps_json)
        .map_err(|e| io::Error::other(format!("deserialise caps: {e}")))?;

    let issuer_did = Did::parse(&session.org_did)
        .map_err(|e| io::Error::other(format!("parse issuer_did: {e}")))?;
    let subject_did = Did::parse(&session.member_did)
        .map_err(|e| io::Error::other(format!("parse subject_did: {e}")))?;
    let node_did_parsed: Option<Did> = match &session.node_did {
        None => None,
        Some(s) => {
            Some(Did::parse(s).map_err(|e| io::Error::other(format!("parse node_did: {e}")))?)
        }
    };

    // Parse the original envelope id from the message_hex (it's the canonical JSON).
    let canon_str = String::from_utf8(message_bytes.clone())
        .map_err(|e| io::Error::other(format!("utf8 decode: {e}")))?;
    let canon_val: serde_json::Value = serde_json::from_str(&canon_str)
        .map_err(|e| io::Error::other(format!("parse canonical json: {e}")))?;
    let envelope_id = canon_val["id"].as_str().unwrap_or_default().to_string();
    let issued_at = canon_val["issued_at"].as_i64().unwrap_or_else(now_secs);
    let expires_at = canon_val["expires_at"].as_i64();

    // Signature is base64url-encoded 64 bytes.
    let issuer_signature = URL_SAFE_NO_PAD.encode(&sig_bytes);

    let envelope = GrantEnvelope {
        id: envelope_id.clone(),
        issuer_did,
        subject_did,
        node_did: node_did_parsed,
        grants,
        issued_at,
        expires_at,
        // Not an app grant: this envelope authorises a member of an org, and the
        // app binding (`DEC-0052`) does not apply.
        app_id: None,
        issuer_signature,
    };

    let envelope_json = serde_json::to_string(&envelope)
        .map_err(|e| io::Error::other(format!("serialize envelope: {e}")))?;

    // Record in org_members and mark session done.
    org_db::record_member_grant(user_db, &session.org_did, &session.member_did, &envelope_id).await?;
    frost_db::mark_session_signed(user_db, &session_id).await?;

    tracing::info!(
        %session_id,
        org_did = %session.org_did,
        member_did = %session.member_did,
        %envelope_id,
        "FROST grant issued"
    );

    Ok(UserResponse::OrgFrostSigned {
        envelope_id,
        envelope_json,
    })
}

// ── private helpers ───────────────────────────────────────────────────────────

use kotton_identity::owner_did_for;

/// One parser for a capability's display form, the plain org's: a FROST org issues the same
/// envelopes and means the same thing by each capability, so the two cannot be allowed to
/// read one string two ways. This was a copy until 2026-09-23, when the plain org's learned
/// `org.invite` and `root.member` (RFC-0088) and the copy would not have.
use super::orgs::parse_caps;
