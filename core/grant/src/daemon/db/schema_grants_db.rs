// SPDX-License-Identifier: AGPL-3.0-or-later
//! Schema grants DB helpers  (RFC-0003)
//!
//! Manages the `schema_grants` table added in migration `0018`.
//!
//! Each row represents an explicit permission grant for one app to access one
//! schema NSID.  Rows also carry running quota counters so the daemon can
//! enforce per-`(app_id, nsid)` record and byte limits without a full scan.
//!
//! ## Quota semantics
//! - `record_quota = 0`  → unlimited records
//! - `byte_quota = 0`    → unlimited bytes
//! - Default limits: 50 000 records, 100 MiB (104 857 600 bytes) per pair

use kotton_common::time::now_secs;
use sqlx::SqlitePool;
use std::io;

// ── Row type ─────────────────────────────────────────────────────────────────

/// One row from `schema_grants`, returned by [`get_grant`] and [`list_grants`].
#[derive(Debug, Clone)]
pub struct SchemaGrant {
    pub app_id: String,
    pub nsid: String,
    pub can_read: bool,
    pub can_write: bool,
    pub can_register: bool,
    pub record_quota: i64,
    pub byte_quota: i64,
    pub record_count: i64,
    pub byte_count: i64,
}

// ── Reads ─────────────────────────────────────────────────────────────────────

/// A `schema_grants` row as SQLite returns it, in `SELECT` order: `app_id, nsid,
/// can_read, can_write, can_register, record_quota, byte_quota, record_count, byte_count`.
type SchemaGrantRow = (String, String, i64, i64, i64, i64, i64, i64, i64);

/// The one place a [`SchemaGrantRow`] becomes a [`SchemaGrant`].
fn grant_from_row(
    (app_id, nsid, can_read, can_write, can_register, rq, bq, rc, bc): SchemaGrantRow,
) -> SchemaGrant {
    SchemaGrant {
        app_id,
        nsid,
        can_read: can_read != 0,
        can_write: can_write != 0,
        can_register: can_register != 0,
        record_quota: rq,
        byte_quota: bq,
        record_count: rc,
        byte_count: bc,
    }
}

/// Fetch the grant row for `(app_id, nsid)`, or `None` if absent.
pub async fn get_grant(
    pool: &SqlitePool,
    app_id: &str,
    nsid: &str,
) -> io::Result<Option<SchemaGrant>> {
    let row: Option<SchemaGrantRow> = sqlx::query_as(
        "SELECT app_id, nsid, can_read, can_write, can_register,
                record_quota, byte_quota, record_count, byte_count
         FROM schema_grants
         WHERE app_id = ? AND nsid = ?",
    )
    .bind(app_id)
    .bind(nsid)
    .fetch_optional(pool)
    .await
    .map_err(|e| io::Error::other(format!("schema_grants get: {e}")))?;

    Ok(row.map(grant_from_row))
}

/// Return all grant rows for `app_id`.
pub async fn list_grants(pool: &SqlitePool, app_id: &str) -> io::Result<Vec<SchemaGrant>> {
    let rows: Vec<SchemaGrantRow> = sqlx::query_as(
        "SELECT app_id, nsid, can_read, can_write, can_register,
                record_quota, byte_quota, record_count, byte_count
         FROM schema_grants
         WHERE app_id = ?
         ORDER BY nsid",
    )
    .bind(app_id)
    .fetch_all(pool)
    .await
    .map_err(|e| io::Error::other(format!("schema_grants list: {e}")))?;

    Ok(rows.into_iter().map(grant_from_row).collect())
}

// ── Writes ────────────────────────────────────────────────────────────────────

/// Upsert a grant row, preserving existing quota counters.
///
/// If the row does not exist it is created with default quota limits.
/// If it does exist, only the `can_*` flags and `granted_at` are updated.
pub async fn set_grant(
    pool: &SqlitePool,
    app_id: &str,
    nsid: &str,
    can_read: bool,
    can_write: bool,
    can_register: bool,
) -> io::Result<()> {
    let now = now_secs();
    sqlx::query(
        "INSERT INTO schema_grants (app_id, nsid, can_read, can_write, can_register, granted_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT (app_id, nsid) DO UPDATE SET
             can_read     = excluded.can_read,
             can_write    = excluded.can_write,
             can_register = excluded.can_register,
             granted_at   = excluded.granted_at",
    )
    .bind(app_id)
    .bind(nsid)
    .bind(can_read as i64)
    .bind(can_write as i64)
    .bind(can_register as i64)
    .bind(now)
    .execute(pool)
    .await
    .map_err(|e| io::Error::other(format!("schema_grants set: {e}")))?;
    Ok(())
}

/// Remove all grants for `(app_id, nsid)`.
pub async fn revoke_grant(pool: &SqlitePool, app_id: &str, nsid: &str) -> io::Result<()> {
    sqlx::query("DELETE FROM schema_grants WHERE app_id = ? AND nsid = ?")
        .bind(app_id)
        .bind(nsid)
        .execute(pool)
        .await
        .map_err(|e| io::Error::other(format!("schema_grants revoke: {e}")))?;
    Ok(())
}

/// Override the quota limits for `(app_id, nsid)`.
///
/// The row is created with all permissions denied if it does not yet exist.
/// `record_quota = 0` or `byte_quota = 0` removes the respective limit.
pub async fn set_quota(
    pool: &SqlitePool,
    app_id: &str,
    nsid: &str,
    record_quota: i64,
    byte_quota: i64,
) -> io::Result<()> {
    let now = now_secs();
    sqlx::query(
        "INSERT INTO schema_grants (app_id, nsid, record_quota, byte_quota, granted_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (app_id, nsid) DO UPDATE SET
             record_quota = excluded.record_quota,
             byte_quota   = excluded.byte_quota,
             granted_at   = excluded.granted_at",
    )
    .bind(app_id)
    .bind(nsid)
    .bind(record_quota)
    .bind(byte_quota)
    .bind(now)
    .execute(pool)
    .await
    .map_err(|e| io::Error::other(format!("schema_grants set_quota: {e}")))?;
    Ok(())
}

// ── Quota counters ────────────────────────────────────────────────────────────

/// Increment `record_count` and `byte_count` after a successful insert.
///
/// No-ops if the row does not exist (CLI / non-app callers have no quota row).
pub async fn increment_counters(
    pool: &SqlitePool,
    app_id: &str,
    nsid: &str,
    body_bytes: i64,
) -> io::Result<()> {
    sqlx::query(
        "UPDATE schema_grants
         SET record_count = record_count + 1,
             byte_count   = byte_count   + ?
         WHERE app_id = ? AND nsid = ?",
    )
    .bind(body_bytes)
    .bind(app_id)
    .bind(nsid)
    .execute(pool)
    .await
    .map_err(|e| io::Error::other(format!("schema_grants increment: {e}")))?;
    Ok(())
}

/// Decrement `record_count` and `byte_count` after a successful delete.
///
/// Counters are floored at zero to guard against double-decrements.
pub async fn decrement_counters(
    pool: &SqlitePool,
    app_id: &str,
    nsid: &str,
    body_bytes: i64,
) -> io::Result<()> {
    sqlx::query(
        "UPDATE schema_grants
         SET record_count = MAX(0, record_count - 1),
             byte_count   = MAX(0, byte_count   - ?)
         WHERE app_id = ? AND nsid = ?",
    )
    .bind(body_bytes)
    .bind(app_id)
    .bind(nsid)
    .execute(pool)
    .await
    .map_err(|e| io::Error::other(format!("schema_grants decrement: {e}")))?;
    Ok(())
}

// ── Access checks ─────────────────────────────────────────────────────────────

/// Return `Ok(())` if `app_id` has `can_read` on `nsid`, else `Err(permission denied)`.
pub async fn check_read(pool: &SqlitePool, app_id: &str, nsid: &str) -> io::Result<()> {
    match get_grant(pool, app_id, nsid).await? {
        Some(g) if g.can_read => Ok(()),
        _ => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("permission denied: schema.read:{nsid}"),
        )),
    }
}

/// Return `Ok(())` if `app_id` has `can_write` on `nsid` and is within quota.
///
/// `new_bytes` is the serialized size of the record being inserted; it is
/// checked against the byte quota before the insert occurs.
pub async fn check_write(
    pool: &SqlitePool,
    app_id: &str,
    nsid: &str,
    new_bytes: i64,
) -> io::Result<()> {
    match get_grant(pool, app_id, nsid).await? {
        Some(g) if g.can_write => {
            if g.record_quota > 0 && g.record_count >= g.record_quota {
                return Err(io::Error::other(
                    format!(
                        "quota exceeded: record limit ({}) reached for {}",
                        g.record_quota, nsid
                    ),
                ));
            }
            if g.byte_quota > 0 && g.byte_count + new_bytes > g.byte_quota {
                return Err(io::Error::other(
                    format!(
                        "quota exceeded: byte limit ({} MiB) reached for {}",
                        g.byte_quota / 1024 / 1024,
                        nsid
                    ),
                ));
            }
            Ok(())
        }
        _ => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("permission denied: schema.write:{nsid}"),
        )),
    }
}

/// Return `Ok(())` if `app_id` has `can_register` on `nsid`.
pub async fn check_register(pool: &SqlitePool, app_id: &str, nsid: &str) -> io::Result<()> {
    match get_grant(pool, app_id, nsid).await? {
        Some(g) if g.can_register => Ok(()),
        _ => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("permission denied: schema.register:{nsid}"),
        )),
    }
}
