// SPDX-License-Identifier: AGPL-3.0-or-later
//! FROST threshold-signature DB helpers — Step 10 (identity_model sprint).
//!
//! Covers four tables added in `0014_frost_sessions.sql`:
//! - `frost_orgs`                 — FROST-keyed org metadata (initiator side)
//! - `frost_key_packages`         — per-participant key material on this device
//! - `frost_signing_sessions`     — in-progress signing ceremonies
//! - `frost_signing_contributions`— round-1 commitments + round-2 shares from co-signers

use kotton_common::time::now_secs;
use sqlx::SqlitePool;
use std::io;

// ── frost_orgs ────────────────────────────────────────────────────────────────

/// Insert the initiator's FROST org row (created by `org frost new`).
pub async fn insert_frost_org(
    pool: &SqlitePool,
    org_did: &str,
    name: &str,
    owner_did: &str,
    threshold: u16,
    total: u16,
    pubkey_package_hex: &str,
) -> io::Result<()> {
    let now = now_secs();
    sqlx::query(
        "INSERT INTO frost_orgs \
         (org_did, name, owner_did, threshold, total, pubkey_package_hex, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(org_did)
    .bind(name)
    .bind(owner_did)
    .bind(threshold as i64)
    .bind(total as i64)
    .bind(pubkey_package_hex)
    .bind(now)
    .execute(pool)
    .await
    .map_err(|e| io::Error::other(format!("insert_frost_org: {e}")))?;
    Ok(())
}

/// Return the `(pubkey_package_hex, threshold, total)` for a FROST org, or `None`.
pub async fn get_frost_org(
    pool: &SqlitePool,
    org_did: &str,
) -> io::Result<Option<(String, u16, u16)>> {
    let row: Option<(String, i64, i64)> = sqlx::query_as(
        "SELECT pubkey_package_hex, threshold, total FROM frost_orgs WHERE org_did = ?",
    )
    .bind(org_did)
    .fetch_optional(pool)
    .await
    .map_err(|e| io::Error::other(format!("get_frost_org: {e}")))?;
    Ok(row.map(|(hex, t, n)| (hex, t as u16, n as u16)))
}

/// Check whether `org_did` is a FROST org (as opposed to a single-key org).
pub async fn is_frost_org(pool: &SqlitePool, org_did: &str) -> io::Result<bool> {
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM frost_orgs WHERE org_did = ?")
        .bind(org_did)
        .fetch_one(pool)
        .await
        .map_err(|e| io::Error::other(format!("is_frost_org: {e}")))?;
    Ok(count.0 > 0)
}

/// Resolve `name` to an org DID by searching `frost_orgs` for the owner.
pub async fn frost_org_did_by_name(
    pool: &SqlitePool,
    name: &str,
    owner_did: &str,
) -> io::Result<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT org_did FROM frost_orgs WHERE name = ? AND owner_did = ?",
    )
    .bind(name)
    .bind(owner_did)
    .fetch_optional(pool)
    .await
    .map_err(|e| io::Error::other(format!("frost_org_did_by_name: {e}")))?;
    Ok(row.map(|(d,)| d))
}

// ── frost_key_packages ────────────────────────────────────────────────────────

/// Store a participant's `KeyPackage` for an org on this device.
pub async fn upsert_key_package(
    pool: &SqlitePool,
    org_did: &str,
    key_package_hex: &str,
    participant_idx: u16,
    participant_id_hex: &str,
) -> io::Result<()> {
    sqlx::query(
        "INSERT OR REPLACE INTO frost_key_packages \
         (org_did, key_package_hex, participant_idx, participant_id_hex) \
         VALUES (?, ?, ?, ?)",
    )
    .bind(org_did)
    .bind(key_package_hex)
    .bind(participant_idx as i64)
    .bind(participant_id_hex)
    .execute(pool)
    .await
    .map_err(|e| io::Error::other(format!("upsert_key_package: {e}")))?;
    Ok(())
}

/// Return `(key_package_hex, participant_idx, participant_id_hex)` for this device's
/// share of `org_did`.
pub async fn get_key_package(
    pool: &SqlitePool,
    org_did: &str,
) -> io::Result<Option<(String, u16, String)>> {
    let row: Option<(String, i64, String)> = sqlx::query_as(
        "SELECT key_package_hex, participant_idx, participant_id_hex \
         FROM frost_key_packages WHERE org_did = ?",
    )
    .bind(org_did)
    .fetch_optional(pool)
    .await
    .map_err(|e| io::Error::other(format!("get_key_package: {e}")))?;
    Ok(row.map(|(h, i, id)| (h, i as u16, id)))
}

// ── frost_signing_sessions ────────────────────────────────────────────────────

/// Insert a new signing session row (created at the start of `org grant issue`
/// on a FROST org).
#[allow(clippy::too_many_arguments)]
pub async fn insert_signing_session(
    pool: &SqlitePool,
    session_id: &str,
    org_did: &str,
    user_id: &str,
    member_did: &str,
    caps_json: &str,
    ttl_secs: Option<i64>,
    node_did: Option<&str>,
    message_hex: &str,
    nonces_hex: &str,
    commitment_hex: &str,
    participant_id_hex: &str,
) -> io::Result<()> {
    let now = now_secs();
    sqlx::query(
        "INSERT INTO frost_signing_sessions \
         (session_id, org_did, user_id, member_did, caps_json, ttl_secs, node_did, \
          message_hex, nonces_hex, commitment_hex, participant_id_hex, state, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)",
    )
    .bind(session_id)
    .bind(org_did)
    .bind(user_id)
    .bind(member_did)
    .bind(caps_json)
    .bind(ttl_secs)
    .bind(node_did)
    .bind(message_hex)
    .bind(nonces_hex)
    .bind(commitment_hex)
    .bind(participant_id_hex)
    .bind(now)
    .execute(pool)
    .await
    .map_err(|e| io::Error::other(format!("insert_signing_session: {e}")))?;
    Ok(())
}

/// All fields needed to complete the signing round on the coordinator side.
pub struct SigningSession {
    pub org_did: String,
    pub member_did: String,
    pub caps_json: String,
    pub ttl_secs: Option<i64>,
    pub node_did: Option<String>,
    pub message_hex: String,
    pub nonces_hex: String,
    pub commitment_hex: String,
    pub participant_id_hex: String,
}

/// A `frost_signing_sessions` row as [`get_signing_session`] selects it, in
/// [`SigningSession`]'s field order.
type SigningSessionRow = (String, String, String, Option<i64>, Option<String>, String, String, String, String);

/// Return the signing session row, or `None` if not found.
pub async fn get_signing_session(
    pool: &SqlitePool,
    session_id: &str,
) -> io::Result<Option<SigningSession>> {
    let row: Option<SigningSessionRow> =
        sqlx::query_as(
            "SELECT org_did, member_did, caps_json, ttl_secs, node_did, \
             message_hex, nonces_hex, commitment_hex, participant_id_hex \
             FROM frost_signing_sessions WHERE session_id = ? AND state = 'pending'",
        )
        .bind(session_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| io::Error::other(format!("get_signing_session: {e}")))?;
    Ok(row.map(|(org_did, member_did, caps_json, ttl_secs, node_did, message_hex, nonces_hex, commitment_hex, participant_id_hex)| {
        SigningSession {
            org_did,
            member_did,
            caps_json,
            ttl_secs,
            node_did,
            message_hex,
            nonces_hex,
            commitment_hex,
            participant_id_hex,
        }
    }))
}

/// Mark a signing session as complete.
pub async fn mark_session_signed(pool: &SqlitePool, session_id: &str) -> io::Result<()> {
    sqlx::query("UPDATE frost_signing_sessions SET state = 'signed' WHERE session_id = ?")
        .bind(session_id)
        .execute(pool)
        .await
        .map_err(|e| io::Error::other(format!("mark_session_signed: {e}")))?;
    Ok(())
}

// ── frost_signing_contributions ───────────────────────────────────────────────

/// Record a co-signer's commitment + share for a signing session.
pub async fn upsert_contribution(
    pool: &SqlitePool,
    session_id: &str,
    participant_id_hex: &str,
    commitment_hex: &str,
    share_hex: &str,
) -> io::Result<()> {
    sqlx::query(
        "INSERT OR REPLACE INTO frost_signing_contributions \
         (session_id, participant_id_hex, commitment_hex, share_hex) \
         VALUES (?, ?, ?, ?)",
    )
    .bind(session_id)
    .bind(participant_id_hex)
    .bind(commitment_hex)
    .bind(share_hex)
    .execute(pool)
    .await
    .map_err(|e| io::Error::other(format!("upsert_contribution: {e}")))?;
    Ok(())
}

/// Return all contributions recorded for a session as `(participant_id_hex, commitment_hex, share_hex)`.
pub async fn list_contributions(
    pool: &SqlitePool,
    session_id: &str,
) -> io::Result<Vec<(String, String, String)>> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT participant_id_hex, commitment_hex, share_hex \
         FROM frost_signing_contributions WHERE session_id = ?",
    )
    .bind(session_id)
    .fetch_all(pool)
    .await
    .map_err(|e| io::Error::other(format!("list_contributions: {e}")))?;
    Ok(rows)
}
