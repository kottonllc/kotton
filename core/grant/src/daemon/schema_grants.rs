// SPDX-License-Identifier: AGPL-3.0-or-later
//! Schema grant management IPC handlers  (RFC-0003)
//!
//! Handles the four grant management variants:
//!
//! - `SchemaGrantList`   — list all grants for an app
//! - `SchemaGrantSet`    — create / update a grant
//! - `SchemaGrantRevoke` — remove a grant
//! - `SchemaQuotaSet`    — override quota limits

use super::db::schema_grants_db;
use kotton_wire::ipc::SchemaGrantEntry;
use sqlx::SqlitePool;
use std::io;
use std::sync::Arc;

use kotton_wire::ipc::UserResponse;

/// List all schema access grants for `app_id`.
pub async fn schema_grant_list(
    pool: &Arc<SqlitePool>,
    app_id: String,
) -> io::Result<UserResponse> {
    match schema_grants_db::list_grants(pool, &app_id).await {
        Ok(rows) => {
            let grants = rows
                .into_iter()
                .map(|g| SchemaGrantEntry {
                    app_id: g.app_id,
                    nsid: g.nsid,
                    can_read: g.can_read,
                    can_write: g.can_write,
                    can_register: g.can_register,
                    record_quota: g.record_quota,
                    byte_quota: g.byte_quota,
                    record_count: g.record_count,
                    byte_count: g.byte_count,
                })
                .collect();
            Ok(UserResponse::SchemaGrantListResult { grants })
        }
        Err(e) => Ok(UserResponse::Error {
            message: e.to_string(),
        }),
    }
}

/// Create or update a schema access grant for `(app_id, nsid)`.
pub async fn schema_grant_set(
    pool: &Arc<SqlitePool>,
    app_id: String,
    nsid: String,
    can_read: bool,
    can_write: bool,
    can_register: bool,
) -> io::Result<UserResponse> {
    match schema_grants_db::set_grant(pool, &app_id, &nsid, can_read, can_write, can_register).await
    {
        Ok(()) => Ok(UserResponse::SchemaGrantUpdated),
        Err(e) => Ok(UserResponse::Error {
            message: e.to_string(),
        }),
    }
}

/// Remove all schema access grants for `(app_id, nsid)`.
pub async fn schema_grant_revoke(
    pool: &Arc<SqlitePool>,
    app_id: String,
    nsid: String,
) -> io::Result<UserResponse> {
    match schema_grants_db::revoke_grant(pool, &app_id, &nsid).await {
        Ok(()) => Ok(UserResponse::SchemaGrantRevoked),
        Err(e) => Ok(UserResponse::Error {
            message: e.to_string(),
        }),
    }
}

/// Override the quota limits for `(app_id, nsid)`.
pub async fn schema_quota_set(
    pool: &Arc<SqlitePool>,
    app_id: String,
    nsid: String,
    record_quota: i64,
    byte_quota: i64,
) -> io::Result<UserResponse> {
    match schema_grants_db::set_quota(pool, &app_id, &nsid, record_quota, byte_quota).await {
        Ok(()) => Ok(UserResponse::SchemaQuotaUpdated),
        Err(e) => Ok(UserResponse::Error {
            message: e.to_string(),
        }),
    }
}
