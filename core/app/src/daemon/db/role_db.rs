// SPDX-License-Identifier: AGPL-3.0-or-later
//! Role registry database access — migration `0017_app_roles.sql`.
//!
//! Maps named system roles (e.g. `"shell"`, `"dock"`) to installed app IDs.
//! The daemon queries this table at boot to determine which app to open for
//! each role instead of hardcoding app IDs.

use super::db_err;
use sqlx::SqlitePool;
use std::io;
use std::sync::Arc;

/// Return the `app_id` registered for `role`, or `None` if not set.
pub async fn get_role(db: &Arc<SqlitePool>, role: &str) -> io::Result<Option<String>> {
    sqlx::query_scalar::<_, String>("SELECT app_id FROM app_roles WHERE role = ?")
        .bind(role)
        .fetch_optional(db.as_ref())
        .await
        .map_err(db_err)
}

/// Insert or replace the `app_id` for `role`.
pub async fn set_role(db: &Arc<SqlitePool>, role: &str, app_id: &str) -> io::Result<()> {
    sqlx::query("INSERT OR REPLACE INTO app_roles (role, app_id) VALUES (?, ?)")
        .bind(role)
        .bind(app_id)
        .execute(db.as_ref())
        .await
        .map_err(db_err)?;
    Ok(())
}
