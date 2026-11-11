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
///
/// A schema kept from apps ([`kotton_schemas::CoreSchema::is_kept_from_apps`]: `secret` and
/// `access-log`) is refused, and nothing is stored: no app is granted it. The check every
/// app's record verb passes refuses it too, whatever a row says
/// ([`schema_grants_db::refuse_if_kept_from_apps`]), so a row stored before this refusal
/// existed never goes live.
pub async fn schema_grant_set(
    pool: &Arc<SqlitePool>,
    app_id: String,
    nsid: String,
    can_read: bool,
    can_write: bool,
    can_register: bool,
) -> io::Result<UserResponse> {
    if let Some(kept) = kotton_schemas::CoreSchema::kept_from_apps(&nsid) {
        return Ok(UserResponse::Error {
            message: format!("no grant to {app_id} was stored: {}", kept.kept_from_apps_refusal()),
        });
    }
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

/// Override the quota limits for `(app_id, nsid)`. Refused on a schema kept from apps, as a
/// grant on it is ([`schema_grant_set`]): there is no app's quota on it to set.
pub async fn schema_quota_set(
    pool: &Arc<SqlitePool>,
    app_id: String,
    nsid: String,
    record_quota: i64,
    byte_quota: i64,
) -> io::Result<UserResponse> {
    if let Some(kept) = kotton_schemas::CoreSchema::kept_from_apps(&nsid) {
        return Ok(UserResponse::Error {
            message: format!("no quota for {app_id} was stored: {}", kept.kept_from_apps_refusal()),
        });
    }
    match schema_grants_db::set_quota(pool, &app_id, &nsid, record_quota, byte_quota).await {
        Ok(()) => Ok(UserResponse::SchemaQuotaUpdated),
        Err(e) => Ok(UserResponse::Error {
            message: e.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotton_common::namespace::{NSID_ACCESS_LOG, NSID_NOTES, NSID_PETNAME, NSID_SECRET};

    const APP: &str = "com.example.keys";

    async fn grant_store() -> Arc<SqlitePool> {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            "CREATE TABLE schema_grants (
                app_id TEXT NOT NULL, nsid TEXT NOT NULL,
                can_read INTEGER NOT NULL DEFAULT 0, can_write INTEGER NOT NULL DEFAULT 0,
                can_register INTEGER NOT NULL DEFAULT 0,
                record_quota INTEGER NOT NULL DEFAULT 50000,
                byte_quota INTEGER NOT NULL DEFAULT 104857600,
                record_count INTEGER NOT NULL DEFAULT 0, byte_count INTEGER NOT NULL DEFAULT 0,
                granted_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                PRIMARY KEY (app_id, nsid))",
        )
        .execute(&pool)
        .await
        .unwrap();
        Arc::new(pool)
    }

    /// No app is granted a schema kept from apps: the grant and its quota are refused and
    /// nothing is stored. A row planted straight into the store goes live for no check, read,
    /// write or register. Notes, granted the same way, is any app's.
    #[tokio::test]
    async fn no_app_is_granted_a_schema_kept_from_apps() {
        let pool = grant_store().await;
        for kept in [NSID_SECRET, NSID_ACCESS_LOG, NSID_PETNAME] {
            match schema_grant_set(&pool, APP.into(), kept.into(), true, true, true).await.unwrap() {
                UserResponse::Error { message } => {
                    assert!(message.contains(kept) && message.contains("no app is granted it"), "{message}")
                }
                other => panic!("a grant on {kept} was stored: {other:?}"),
            }
            assert!(schema_grants_db::get_grant(&pool, APP, kept).await.unwrap().is_none());
            let quota = schema_quota_set(&pool, APP.into(), kept.into(), 0, 0).await.unwrap();
            assert!(matches!(quota, UserResponse::Error { .. }), "{quota:?}");

            schema_grants_db::set_grant(&pool, APP, kept, true, true, true).await.unwrap();
            for err in [
                schema_grants_db::check_read(&pool, APP, kept).await.unwrap_err(),
                schema_grants_db::check_write(&pool, APP, kept, 1).await.unwrap_err(),
                schema_grants_db::check_register(&pool, APP, kept).await.unwrap_err(),
            ] {
                assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
                assert!(err.to_string().contains(kept), "{err}");
            }
        }
        let granted = schema_grant_set(&pool, APP.into(), NSID_NOTES.into(), true, true, false).await.unwrap();
        assert!(matches!(granted, UserResponse::SchemaGrantUpdated), "{granted:?}");
        schema_grants_db::check_read(&pool, APP, NSID_NOTES).await.expect("notes is granted");
    }
}
