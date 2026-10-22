// SPDX-License-Identifier: AGPL-3.0-or-later
//! DB access for the `app_registry` table.
//!
//! The table is created by `migrations/0006_v0_6_app_registry.sql`.

use super::db_err;
use kotton_wire::ipc::InstalledApp;
use sqlx::{Row, SqlitePool};
use std::io;
use std::sync::Arc;
// ── Queries ───────────────────────────────────────────────────────────────────

/// Insert a new app row.
///
/// `capabilities` should be a JSON-encoded `Vec<String>` like
/// `["schema.read:sh.kotton.notes", "schema.write:sh.kotton.notes"]`.
/// `wasm_hash` is a BLAKE3 hex digest of the WASM bytes, used by
/// `auto_install_bundled_apps` to detect when a bundled app has changed
/// and needs reinstalling without a manual data-directory wipe, and by
/// `app verify` to confirm the on-disk binary matches the stored hash.
// Allowed: one argument per `app_registry` column it writes, as `insert_paired_node` does for its table.
#[allow(clippy::too_many_arguments)]
pub async fn insert_app(
    db: &Arc<SqlitePool>,
    app_id: &str,
    name: &str,
    version: &str,
    capabilities_json: &str,
    wasm_path: &str,
    installed_at: &str,
    wasm_hash: &str,
    approved_json: &str,
) -> io::Result<()> {
    sqlx::query(
        "INSERT OR REPLACE INTO app_registry \
         (app_id, name, version, capabilities, wasm_path, installed_at, wasm_hash, approved_json) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(app_id)
    .bind(name)
    .bind(version)
    .bind(capabilities_json)
    .bind(wasm_path)
    .bind(installed_at)
    .bind(wasm_hash)
    .bind(approved_json)
    .execute(db.as_ref())
    .await
    .map_err(db_err)?;
    Ok(())
}

/// Return the stored `wasm_hash` for an app. Returns `None` if not found.
pub async fn get_wasm_hash(db: &Arc<SqlitePool>, app_id: &str) -> io::Result<Option<String>> {
    sqlx::query_scalar("SELECT wasm_hash FROM app_registry WHERE app_id = ?")
        .bind(app_id)
        .fetch_optional(db.as_ref())
        .await
        .map_err(db_err)
}

/// Delete an app row. Returns `true` if a row was deleted.
pub async fn delete_app(db: &Arc<SqlitePool>, app_id: &str) -> io::Result<bool> {
    let result = sqlx::query("DELETE FROM app_registry WHERE app_id = ?")
        .bind(app_id)
        .execute(db.as_ref())
        .await
        .map_err(db_err)?;
    Ok(result.rows_affected() > 0)
}

/// Retrieve a single app. Returns `None` if not found.
#[allow(dead_code)]
pub async fn get_app(db: &Arc<SqlitePool>, app_id: &str) -> io::Result<Option<InstalledApp>> {
    let row = sqlx::query(
        "SELECT app_id, name, version, capabilities, installed_at, bundle_path, dev \
         FROM app_registry WHERE app_id = ?",
    )
    .bind(app_id)
    .fetch_optional(db.as_ref())
    .await
    .map_err(db_err)?;

    Ok(row.map(|r| {
        let caps_json: String = r.get("capabilities");
        let caps: Vec<String> = serde_json::from_str(&caps_json).unwrap_or_default();
        let dev_flag: i64 = r.try_get("dev").unwrap_or(0);
        InstalledApp {
            app_id: r.get("app_id"),
            name: r.get("name"),
            version: r.get("version"),
            capabilities: caps,
            installed_at: r.get("installed_at"),
            bundle_path: r.get("bundle_path"),
            dev: dev_flag != 0,
            running: false,
        }
    }))
}

/// Return the `wasm_path` for an app. Returns `None` if not found.
pub async fn get_wasm_path(db: &Arc<SqlitePool>, app_id: &str) -> io::Result<Option<String>> {
    sqlx::query_scalar("SELECT wasm_path FROM app_registry WHERE app_id = ?")
        .bind(app_id)
        .fetch_optional(db.as_ref())
        .await
        .map_err(db_err)
}

/// Count all installed apps.
pub async fn count_apps(db: &SqlitePool) -> io::Result<u32> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM app_registry")
        .fetch_one(db)
        .await
        .map_err(db_err)?;
    Ok(count as u32)
}

/// List all installed apps, ordered by `installed_at` descending.
pub async fn list_apps(db: &Arc<SqlitePool>) -> io::Result<Vec<InstalledApp>> {
    let rows = sqlx::query(
        "SELECT app_id, name, version, capabilities, installed_at, bundle_path, dev \
         FROM app_registry ORDER BY installed_at DESC",
    )
    .fetch_all(db.as_ref())
    .await
    .map_err(db_err)?;

    Ok(rows
        .into_iter()
        .map(|r| {
            let caps_json: String = r.get("capabilities");
            let caps: Vec<String> = serde_json::from_str(&caps_json).unwrap_or_default();
            let dev_flag: i64 = r.try_get("dev").unwrap_or(0);
            InstalledApp {
                app_id: r.get("app_id"),
                name: r.get("name"),
                version: r.get("version"),
                capabilities: caps,
                installed_at: r.get("installed_at"),
                bundle_path: r.get("bundle_path"),
                dev: dev_flag != 0,
                running: false,
            }
        })
        .collect())
}

/// Insert or replace a web-bundle app (no WASM bytes).
///
/// Used by `AppRegisterBundle` — bundle-only apps that have no `.wasm` file.
/// `wasm_path` is stored as an empty string (schema NOT NULL constraint).
// Allowed: one argument per `app_registry` column it writes, as `insert_paired_node` does for its table.
#[allow(clippy::too_many_arguments)]
pub async fn insert_bundle_app(
    db: &Arc<SqlitePool>,
    app_id: &str,
    name: &str,
    version: &str,
    capabilities_json: &str,
    bundle_path: &str,
    installed_at: &str,
    dev: bool,
) -> io::Result<()> {
    sqlx::query(
        "INSERT OR REPLACE INTO app_registry \
         (app_id, name, version, capabilities, wasm_path, wasm_hash, installed_at, bundle_path, dev) \
         VALUES (?, ?, ?, ?, '', '', ?, ?, ?)",
    )
    .bind(app_id)
    .bind(name)
    .bind(version)
    .bind(capabilities_json)
    .bind(installed_at)
    .bind(bundle_path)
    .bind(if dev { 1i32 } else { 0i32 })
    .execute(db.as_ref())
    .await
    .map_err(db_err)?;
    Ok(())
}

/// Return the `bundle_path` for an app. Returns `None` if not found or no bundle.
pub async fn get_bundle_path(db: &Arc<SqlitePool>, app_id: &str) -> io::Result<Option<String>> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT bundle_path FROM app_registry WHERE app_id = ?")
            .bind(app_id)
            .fetch_optional(db.as_ref())
            .await
            .map_err(db_err)?;
    Ok(row.and_then(|(path,)| path))
}

/// What the user approved for `app_id`, as a `CapabilitySet`.
///
/// `Ok(None)` means **never approved** — a row written before the consent gate
/// existed, or one whose approval was not recorded. That is deliberately not the
/// same as `Ok(Some(empty))`, which means the user was asked and said no to
/// everything. The sandbox treats both as "grants nothing", but only the first
/// is a reason to re-run the ceremony, and a bundled app in that state is
/// reinstalled at boot rather than left inert.
///
/// The manifest is **not** consulted here, and that is the entire point of this
/// function: `manifest.capabilities` is what the app asked for, and reading it
/// as what it may have is the defect
/// `TASK-the-approval-is-signed-but-not-enforced` was filed for.
pub async fn get_approved(
    db: &Arc<SqlitePool>,
    app_id: &str,
) -> io::Result<Option<kotton_schemas::CapabilitySet>> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT approved_json FROM app_registry WHERE app_id = ?")
            .bind(app_id)
            .fetch_optional(db.as_ref())
            .await
            .map_err(db_err)?;

    let Some((json,)) = row else {
        return Ok(None);
    };
    if json.is_empty() {
        return Ok(None);
    }
    let grants: Vec<kotton_schemas::CapabilityGrant> = serde_json::from_str(&json)
        .map_err(|e| io::Error::other(format!("approved_json for {app_id}: {e}")))?;
    Ok(Some(kotton_schemas::CapabilitySet::new(grants)))
}
