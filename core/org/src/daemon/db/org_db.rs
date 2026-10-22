// SPDX-License-Identifier: AGPL-3.0-or-later
//! Org identity DB helpers — Step 9 (identity_model sprint).
//!
//! Covers two tables added in `0013_org_identities.sql`:
//!
//! - `org_identities` — one row per org DID owned by this user
//! - `org_members`    — envelope IDs issued to each member, for revocation

use kotton_common::time::now_secs;
use sqlx::SqlitePool;
use std::io;

// ── org_identities ────────────────────────────────────────────────────────────

/// Insert a newly created org identity row.
pub async fn insert_org(
    pool: &SqlitePool,
    org_did: &str,
    name: &str,
    owner_did: &str,
) -> io::Result<()> {
    let now = now_secs();
    sqlx::query(
        "INSERT INTO org_identities (org_did, name, owner_did, created_at) \
         VALUES (?, ?, ?, ?)",
    )
    .bind(org_did)
    .bind(name)
    .bind(owner_did)
    .bind(now)
    .execute(pool)
    .await
    .map_err(|e| io::Error::other(format!("insert_org: {e}")))?;
    Ok(())
}

/// Return `(org_did, name, owner_did, created_at)` for `org_did`, or `None`.
pub async fn get_org(
    pool: &SqlitePool,
    org_did: &str,
) -> io::Result<Option<(String, String, String, i64)>> {
    let row: Option<(String, String, String, i64)> = sqlx::query_as(
        "SELECT org_did, name, owner_did, created_at FROM org_identities WHERE org_did = ?",
    )
    .bind(org_did)
    .fetch_optional(pool)
    .await
    .map_err(|e| io::Error::other(format!("get_org: {e}")))?;
    Ok(row)
}

/// List all orgs owned by `owner_did`, ordered by creation time.
pub async fn list_orgs(
    pool: &SqlitePool,
    owner_did: &str,
) -> io::Result<Vec<(String, String, i64)>> {
    let rows: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT org_did, name, created_at FROM org_identities \
         WHERE owner_did = ? ORDER BY created_at",
    )
    .bind(owner_did)
    .fetch_all(pool)
    .await
    .map_err(|e| io::Error::other(format!("list_orgs: {e}")))?;
    Ok(rows)
}

// ── org_members ───────────────────────────────────────────────────────────────

/// Record that `envelope_id` was issued by `org_did` to `member_did`.
pub async fn record_member_grant(
    pool: &SqlitePool,
    org_did: &str,
    member_did: &str,
    envelope_id: &str,
) -> io::Result<()> {
    let now = now_secs();
    sqlx::query(
        "INSERT OR REPLACE INTO org_members (org_did, member_did, envelope_id, issued_at) \
         VALUES (?, ?, ?, ?)",
    )
    .bind(org_did)
    .bind(member_did)
    .bind(envelope_id)
    .bind(now)
    .execute(pool)
    .await
    .map_err(|e| io::Error::other(format!("record_member_grant: {e}")))?;
    Ok(())
}

/// Return all envelope IDs issued to `member_did` by `org_did`.
pub async fn get_member_envelope_ids(
    pool: &SqlitePool,
    org_did: &str,
    member_did: &str,
) -> io::Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT envelope_id FROM org_members WHERE org_did = ? AND member_did = ?",
    )
    .bind(org_did)
    .bind(member_did)
    .fetch_all(pool)
    .await
    .map_err(|e| io::Error::other(format!("get_member_envelope_ids: {e}")))?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// Delete all member rows for `member_did` under `org_did` (after revocation).
pub async fn delete_member_grants(
    pool: &SqlitePool,
    org_did: &str,
    member_did: &str,
) -> io::Result<()> {
    sqlx::query("DELETE FROM org_members WHERE org_did = ? AND member_did = ?")
        .bind(org_did)
        .bind(member_did)
        .execute(pool)
        .await
        .map_err(|e| io::Error::other(format!("delete_member_grants: {e}")))?;
    Ok(())
}

/// List all (member_did, envelope_id, issued_at) rows for `org_did`.
pub async fn list_org_grants(
    pool: &SqlitePool,
    org_did: &str,
) -> io::Result<Vec<(String, String, i64)>> {
    let rows: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT member_did, envelope_id, issued_at FROM org_members \
         WHERE org_did = ? ORDER BY issued_at",
    )
    .bind(org_did)
    .fetch_all(pool)
    .await
    .map_err(|e| io::Error::other(format!("list_org_grants: {e}")))?;
    Ok(rows)
}
