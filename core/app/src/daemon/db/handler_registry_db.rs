// SPDX-License-Identifier: AGPL-3.0-or-later
//! DB access for the `handler_registry` table.
//!
//! The table is created by `migrations/0005_v0_5_handler_registry.sql`.

use super::db_err;
use kotton_common::time::now_secs;
use kotton_wire::ipc::HandlerEntry;
use sqlx::{Row, SqlitePool};
use std::io;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

/// Count how many handlers are registered for `nsid`.
pub async fn count_for_nsid(db: &Arc<SqlitePool>, nsid: &str) -> io::Result<i64> {
    sqlx::query_scalar("SELECT COUNT(*) FROM handler_registry WHERE nsid = ?")
        .bind(nsid)
        .fetch_one(db.as_ref())
        .await
        .map_err(db_err)
}

/// Insert or update a handler entry. `is_default` controls the default flag.
pub async fn upsert_handler(
    db: &Arc<SqlitePool>,
    app_id: &str,
    nsid: &str,
    is_default: i32,
) -> io::Result<()> {
    let now = now_secs();
    sqlx::query(
        "INSERT INTO handler_registry (app_id, nsid, is_default, registered_at) \
         VALUES (?, ?, ?, ?) \
         ON CONFLICT (app_id, nsid) DO UPDATE SET registered_at = excluded.registered_at",
    )
    .bind(app_id)
    .bind(nsid)
    .bind(is_default)
    .bind(now)
    .execute(db.as_ref())
    .await
    .map_err(db_err)?;
    Ok(())
}

/// Check whether a given `(app_id, nsid)` row is the default. Returns `None`
/// if the row does not exist.
pub async fn get_is_default(
    db: &Arc<SqlitePool>,
    app_id: &str,
    nsid: &str,
) -> io::Result<Option<i32>> {
    sqlx::query_scalar("SELECT is_default FROM handler_registry WHERE app_id = ? AND nsid = ?")
        .bind(app_id)
        .bind(nsid)
        .fetch_optional(db.as_ref())
        .await
        .map_err(db_err)
}

/// Delete a handler entry. Returns the number of rows removed.
pub async fn delete_handler(db: &Arc<SqlitePool>, app_id: &str, nsid: &str) -> io::Result<u64> {
    let result = sqlx::query("DELETE FROM handler_registry WHERE app_id = ? AND nsid = ?")
        .bind(app_id)
        .bind(nsid)
        .execute(db.as_ref())
        .await
        .map_err(db_err)?;
    Ok(result.rows_affected())
}

/// Promote the oldest remaining handler for `nsid` to default.
pub async fn promote_oldest_to_default(db: &Arc<SqlitePool>, nsid: &str) -> io::Result<()> {
    sqlx::query(
        "UPDATE handler_registry SET is_default = 1 \
         WHERE rowid = ( \
             SELECT rowid FROM handler_registry WHERE nsid = ? \
             ORDER BY registered_at ASC LIMIT 1 \
         )",
    )
    .bind(nsid)
    .execute(db.as_ref())
    .await
    .map_err(db_err)?;
    Ok(())
}

/// Return the default handler entry for `nsid`, or `None` if none exists.
pub async fn get_default_for_nsid(
    db: &Arc<SqlitePool>,
    nsid: &str,
) -> io::Result<Option<HandlerEntry>> {
    let row = sqlx::query(
        "SELECT app_id, nsid, is_default FROM handler_registry \
         WHERE nsid = ? AND is_default = 1 LIMIT 1",
    )
    .bind(nsid)
    .fetch_optional(db.as_ref())
    .await
    .map_err(db_err)?;

    Ok(row.map(|r| HandlerEntry {
        app_id: r.get("app_id"),
        nsid: r.get("nsid"),
        is_default: r.get::<i32, _>("is_default") != 0,
    }))
}

/// Return all handler entries ordered by `nsid`, then `app_id`.
pub async fn list_all(db: &Arc<SqlitePool>) -> io::Result<Vec<HandlerEntry>> {
    let rows =
        sqlx::query("SELECT app_id, nsid, is_default FROM handler_registry ORDER BY nsid, app_id")
            .fetch_all(db.as_ref())
            .await
            .map_err(db_err)?;

    Ok(rows
        .iter()
        .map(|r| HandlerEntry {
            app_id: r.get("app_id"),
            nsid: r.get("nsid"),
            is_default: r.get::<i32, _>("is_default") != 0,
        })
        .collect())
}

/// Clear the default flag for all handlers for `nsid`.
pub async fn clear_default_for_nsid(db: &Arc<SqlitePool>, nsid: &str) -> io::Result<()> {
    sqlx::query("UPDATE handler_registry SET is_default = 0 WHERE nsid = ?")
        .bind(nsid)
        .execute(db.as_ref())
        .await
        .map_err(db_err)?;
    Ok(())
}

/// Set `(app_id, nsid)` as default. Returns `true` if the row existed.
pub async fn set_default(db: &Arc<SqlitePool>, app_id: &str, nsid: &str) -> io::Result<bool> {
    let result =
        sqlx::query("UPDATE handler_registry SET is_default = 1 WHERE app_id = ? AND nsid = ?")
            .bind(app_id)
            .bind(nsid)
            .execute(db.as_ref())
            .await
            .map_err(db_err)?;
    Ok(result.rows_affected() > 0)
}

/// Delete all handler entries for `app_id` across all NSIDs.
///
/// Called when an app is uninstalled. Does not promote remaining handlers
/// to default — the caller is responsible for that if needed.
pub async fn delete_all_for_app(db: &Arc<SqlitePool>, app_id: &str) -> io::Result<u64> {
    let result = sqlx::query("DELETE FROM handler_registry WHERE app_id = ?")
        .bind(app_id)
        .execute(db.as_ref())
        .await
        .map_err(db_err)?;
    Ok(result.rows_affected())
}
