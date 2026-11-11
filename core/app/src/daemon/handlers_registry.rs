// SPDX-License-Identifier: AGPL-3.0-or-later
//! Handler registry IPC handlers — M17b.
//!
//! These handlers implement the UTI / Launch Services equivalent for Kotton.
//! State lives in the caller's per-user agent database (`handler_registry`
//! table, `migrations_user/0002_app_cluster.sql`) — which app opens which
//! schema is each user's preference, per-user by construction since RFC-0063
//! stage 3b.

use super::db::handler_registry_db as hrdb;
use kotton_wire::ipc::UserResponse;
use sqlx::SqlitePool;
use std::io;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// The refusal for a handler of a schema kept from every app
/// ([`kotton_schemas::CoreSchema::is_kept_from_apps`]: `secret` and `access-log`), or `None`.
/// No app handles either: a handler is the app a record of the schema is opened in, which
/// would hand it the row.
fn kept_from_apps(nsid: &str) -> Option<UserResponse> {
    kotton_schemas::CoreSchema::kept_from_apps(nsid)
        .map(|kept| UserResponse::Error { message: kept.kept_from_apps_refusal() })
}

/// Register `app_id` as a handler for `nsid`.
///
/// If this is the first handler for the NSID it becomes the default
/// automatically.  A second registration for the same (app_id, nsid) pair is
/// idempotent (updates `registered_at`). A schema kept from apps is refused, and nothing is
/// stored.
pub async fn handler_register(
    user_db: &Arc<SqlitePool>,
    app_id: String,
    nsid: String,
) -> io::Result<UserResponse> {
    if let Some(refused) = kept_from_apps(&nsid) {
        return Ok(refused);
    }
    let existing = hrdb::count_for_nsid(user_db, &nsid).await?;
    let is_default: i32 = if existing == 0 { 1 } else { 0 };
    hrdb::upsert_handler(user_db, &app_id, &nsid, is_default).await?;
    Ok(UserResponse::HandlerRegistered)
}

/// Unregister `app_id` as a handler for `nsid`.
///
/// If the removed entry was the default and other handlers remain, the
/// oldest-registered surviving handler is promoted to default.
pub async fn handler_unregister(
    user_db: &Arc<SqlitePool>,
    app_id: String,
    nsid: String,
) -> io::Result<UserResponse> {
    let was_default = hrdb::get_is_default(user_db, &app_id, &nsid).await?;
    hrdb::delete_handler(user_db, &app_id, &nsid).await?;

    if was_default == Some(1) {
        hrdb::promote_oldest_to_default(user_db, &nsid).await?;
    }

    Ok(UserResponse::HandlerUnregistered)
}

/// Return the default handler for `nsid`, or `HandlerNotFound` if none exists.
///
/// A schema kept from apps has no handler, whatever row the registry holds: one stored
/// before the refusal existed, or written into the table some other way, is never answered.
pub async fn handler_get_for(user_db: &Arc<SqlitePool>, nsid: String) -> io::Result<UserResponse> {
    if kotton_schemas::CoreSchema::kept_from_apps(&nsid).is_some() {
        return Ok(UserResponse::HandlerNotFound { nsid });
    }
    match hrdb::get_default_for_nsid(user_db, &nsid).await? {
        Some(entry) => Ok(UserResponse::HandlerInfo { entry }),
        None => Ok(UserResponse::HandlerNotFound { nsid }),
    }
}

/// Return all registered handlers, ordered by NSID then app_id.
pub async fn handler_list(user_db: &Arc<SqlitePool>) -> io::Result<UserResponse> {
    let entries = hrdb::list_all(user_db).await?;
    Ok(UserResponse::HandlerList { entries })
}

/// Set `app_id` as the default handler for `nsid`.
///
/// `app_id` must already be registered for `nsid`. A schema kept from apps is refused.
pub async fn handler_set_default(
    user_db: &Arc<SqlitePool>,
    app_id: String,
    nsid: String,
) -> io::Result<UserResponse> {
    if let Some(refused) = kept_from_apps(&nsid) {
        return Ok(refused);
    }
    hrdb::clear_default_for_nsid(user_db, &nsid).await?;
    let found = hrdb::set_default(user_db, &app_id, &nsid).await?;

    if !found {
        return Ok(UserResponse::Error {
            message: format!(
                "app '{}' is not registered as a handler for '{}'",
                app_id, nsid
            ),
        });
    }

    Ok(UserResponse::DefaultHandlerSet)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use kotton_wire::ipc::UserResponse;
    use sqlx::SqlitePool;
    use std::sync::Arc;

    /// Create a bare in-memory SQLite pool with the handler_registry table.
    async fn test_db() -> Arc<SqlitePool> {
        let pool = SqlitePool::connect(":memory:").await.expect("in-memory db");
        sqlx::query(
            "CREATE TABLE handler_registry (
                app_id        TEXT    NOT NULL,
                nsid          TEXT    NOT NULL,
                is_default    INTEGER NOT NULL DEFAULT 0,
                registered_at INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (app_id, nsid)
             )",
        )
        .execute(&pool)
        .await
        .expect("create handler_registry");
        Arc::new(pool)
    }

    // ── register ─────────────────────────────────────────────────────────────

    /// No app handles `secret` or `petname`: registering one is refused and stores nothing,
    /// setting one as default is refused, and a row planted straight into the table is never
    /// answered.
    #[tokio::test]
    async fn no_app_handles_a_schema_kept_from_apps() {
        let db = test_db().await;
        for secret in [kotton_common::namespace::NSID_SECRET, kotton_common::namespace::NSID_PETNAME] {
            let resp = handler_register(&db, "com.acme.keys".into(), secret.into()).await.unwrap();
            match resp {
                UserResponse::Error { message } => assert!(message.contains(secret), "{message}"),
                other => panic!("expected a refusal, got {other:?}"),
            }
            assert_eq!(hrdb::count_for_nsid(&db, secret).await.unwrap(), 0, "nothing was stored");
            let resp = handler_set_default(&db, "com.acme.keys".into(), secret.into()).await.unwrap();
            assert!(matches!(resp, UserResponse::Error { .. }), "{resp:?}");

            hrdb::upsert_handler(&db, "com.acme.keys", secret, 1).await.unwrap();
            let resp = handler_get_for(&db, secret.into()).await.unwrap();
            assert!(matches!(resp, UserResponse::HandlerNotFound { .. }), "{resp:?}");
        }
    }

    #[tokio::test]
    async fn first_registration_becomes_default() {
        let db = test_db().await;
        let resp = handler_register(&db, "com.acme.app".into(), kotton_common::namespace::NSID_NOTES.into())
            .await
            .unwrap();
        assert!(matches!(resp, UserResponse::HandlerRegistered));

        // The auto-default should be set.
        let resp = handler_get_for(&db, kotton_common::namespace::NSID_NOTES.into())
            .await
            .unwrap();
        match resp {
            UserResponse::HandlerInfo { entry } => {
                assert_eq!(entry.app_id, "com.acme.app");
                assert!(entry.is_default);
            }
            other => panic!("expected HandlerInfo, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn second_registration_does_not_steal_default() {
        let db = test_db().await;
        handler_register(&db, "com.first.app".into(), kotton_common::namespace::NSID_NOTES.into())
            .await
            .unwrap();
        handler_register(&db, "com.second.app".into(), kotton_common::namespace::NSID_NOTES.into())
            .await
            .unwrap();

        // Default must still be the first app.
        let resp = handler_get_for(&db, kotton_common::namespace::NSID_NOTES.into())
            .await
            .unwrap();
        match resp {
            UserResponse::HandlerInfo { entry } => assert_eq!(entry.app_id, "com.first.app"),
            other => panic!("expected HandlerInfo, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn register_is_idempotent() {
        let db = test_db().await;
        handler_register(&db, "com.acme.app".into(), kotton_common::namespace::NSID_NOTES.into())
            .await
            .unwrap();
        // Second call must not error.
        let resp = handler_register(&db, "com.acme.app".into(), kotton_common::namespace::NSID_NOTES.into())
            .await
            .unwrap();
        assert!(matches!(resp, UserResponse::HandlerRegistered));
    }

    // ── unregister ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn unregister_default_promotes_next() {
        let db = test_db().await;
        handler_register(&db, "com.first.app".into(), kotton_common::namespace::NSID_NOTES.into())
            .await
            .unwrap();
        handler_register(&db, "com.second.app".into(), kotton_common::namespace::NSID_NOTES.into())
            .await
            .unwrap();

        // Remove the default.
        let resp = handler_unregister(&db, "com.first.app".into(), kotton_common::namespace::NSID_NOTES.into())
            .await
            .unwrap();
        assert!(matches!(resp, UserResponse::HandlerUnregistered));

        // The surviving handler should now be default.
        let resp = handler_get_for(&db, kotton_common::namespace::NSID_NOTES.into())
            .await
            .unwrap();
        match resp {
            UserResponse::HandlerInfo { entry } => {
                assert_eq!(entry.app_id, "com.second.app");
                assert!(entry.is_default);
            }
            other => panic!("expected HandlerInfo after promotion, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unregister_last_handler_leaves_not_found() {
        let db = test_db().await;
        handler_register(&db, "com.acme.app".into(), kotton_common::namespace::NSID_NOTES.into())
            .await
            .unwrap();
        handler_unregister(&db, "com.acme.app".into(), kotton_common::namespace::NSID_NOTES.into())
            .await
            .unwrap();

        let resp = handler_get_for(&db, kotton_common::namespace::NSID_NOTES.into())
            .await
            .unwrap();
        assert!(
            matches!(resp, UserResponse::HandlerNotFound { .. }),
            "expected HandlerNotFound after removing last handler"
        );
    }

    // ── get ──────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_unknown_nsid_returns_not_found() {
        let db = test_db().await;
        let resp = handler_get_for(&db, kotton_common::namespace::NSID_NOTES.into())
            .await
            .unwrap();
        assert!(matches!(resp, UserResponse::HandlerNotFound { .. }));
    }

    // ── list ─────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_returns_all_handlers() {
        let db = test_db().await;
        handler_register(&db, "com.acme.app".into(), kotton_common::namespace::NSID_NOTES.into())
            .await
            .unwrap();
        handler_register(&db, "com.acme.app".into(), kotton_common::namespace::NSID_CONTACTS.into())
            .await
            .unwrap();
        handler_register(&db, "com.other.app".into(), kotton_common::namespace::NSID_NOTES.into())
            .await
            .unwrap();

        let resp = handler_list(&db).await.unwrap();
        match resp {
            UserResponse::HandlerList { entries } => {
                assert_eq!(entries.len(), 3);
            }
            other => panic!("expected HandlerList, got {other:?}"),
        }
    }

    // ── set_default ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn set_default_switches_handler() {
        let db = test_db().await;
        handler_register(&db, "com.first.app".into(), kotton_common::namespace::NSID_NOTES.into())
            .await
            .unwrap();
        handler_register(&db, "com.second.app".into(), kotton_common::namespace::NSID_NOTES.into())
            .await
            .unwrap();

        let resp = handler_set_default(&db, "com.second.app".into(), kotton_common::namespace::NSID_NOTES.into())
            .await
            .unwrap();
        assert!(matches!(resp, UserResponse::DefaultHandlerSet));

        let resp = handler_get_for(&db, kotton_common::namespace::NSID_NOTES.into())
            .await
            .unwrap();
        match resp {
            UserResponse::HandlerInfo { entry } => assert_eq!(entry.app_id, "com.second.app"),
            other => panic!("expected HandlerInfo, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn set_default_unregistered_app_returns_error() {
        let db = test_db().await;
        handler_register(&db, "com.first.app".into(), kotton_common::namespace::NSID_NOTES.into())
            .await
            .unwrap();

        let resp = handler_set_default(&db, "com.unknown.app".into(), kotton_common::namespace::NSID_NOTES.into())
            .await
            .unwrap();
        assert!(
            matches!(resp, UserResponse::Error { .. }),
            "expected Error for unregistered app"
        );
    }
}
