// SPDX-License-Identifier: AGPL-3.0-or-later
//! DB access for the `extension_registry` table.
//!
//! The table is created by `core/device/migrations/0020_extension_registry.sql`
//! (the machine db's migrations live with the crate that opens it).
//!
//! What this table is *not*: the source of an extension's authority. Capability
//! grants live in the signed `GrantEnvelope` (`grant_db`), so what an extension
//! may do is verified cryptographically on every call rather than read from a
//! row. An attacker with write access to this database can make an extension
//! *appear* installed; they cannot give it a capability, because the envelope
//! would not verify.

use sqlx::{Row, SqlitePool};
use std::io;
use std::sync::Arc;

use super::db_err;

/// A registry row, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExtensionRow {
    pub extension_id: String,
    pub name: String,
    pub version: String,
    pub class: String,
    pub description: String,
    pub wasm_path: String,
    pub content_hash: String,
    /// `None` when the package was unsigned — a fact to surface, not an error.
    pub publisher_did: Option<String>,
    /// The network posture **as consented**, JSON. Enforced from here rather
    /// than from a re-read of the on-disk manifest, so a later edit to that
    /// file cannot widen what the user approved.
    pub network_json: Option<String>,
    pub credential_slots: Vec<String>,
    pub installed_at: i64,
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn insert_extension(db: &Arc<SqlitePool>, row: &ExtensionRow) -> io::Result<()> {
    let slots = serde_json::to_string(&row.credential_slots)
        .map_err(|e| io::Error::other(format!("credential slots: {e}")))?;
    sqlx::query(
        "INSERT OR REPLACE INTO extension_registry \
         (extension_id, name, version, class, description, wasm_path, content_hash, \
          publisher_did, network_json, credential_slots, installed_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&row.extension_id)
    .bind(&row.name)
    .bind(&row.version)
    .bind(&row.class)
    .bind(&row.description)
    .bind(&row.wasm_path)
    .bind(&row.content_hash)
    .bind(&row.publisher_did)
    .bind(&row.network_json)
    .bind(&slots)
    .bind(row.installed_at)
    .execute(db.as_ref())
    .await
    .map_err(db_err)?;
    Ok(())
}

fn row_from(r: &sqlx::sqlite::SqliteRow) -> io::Result<ExtensionRow> {
    let slots_json: String = r.try_get("credential_slots").map_err(db_err)?;
    Ok(ExtensionRow {
        extension_id: r.try_get("extension_id").map_err(db_err)?,
        name: r.try_get("name").map_err(db_err)?,
        version: r.try_get("version").map_err(db_err)?,
        class: r.try_get("class").map_err(db_err)?,
        description: r.try_get("description").map_err(db_err)?,
        wasm_path: r.try_get("wasm_path").map_err(db_err)?,
        content_hash: r.try_get("content_hash").map_err(db_err)?,
        publisher_did: r.try_get("publisher_did").map_err(db_err)?,
        network_json: r.try_get("network_json").map_err(db_err)?,
        credential_slots: serde_json::from_str(&slots_json).unwrap_or_default(),
        installed_at: r.try_get("installed_at").map_err(db_err)?,
    })
}

pub(crate) async fn get_extension(
    db: &Arc<SqlitePool>,
    extension_id: &str,
) -> io::Result<Option<ExtensionRow>> {
    let found = sqlx::query("SELECT * FROM extension_registry WHERE extension_id = ?")
        .bind(extension_id)
        .fetch_optional(db.as_ref())
        .await
        .map_err(db_err)?;
    match found {
        Some(r) => Ok(Some(row_from(&r)?)),
        None => Ok(None),
    }
}

pub(crate) async fn list_extensions(db: &Arc<SqlitePool>) -> io::Result<Vec<ExtensionRow>> {
    let rows = sqlx::query("SELECT * FROM extension_registry ORDER BY extension_id")
        .fetch_all(db.as_ref())
        .await
        .map_err(db_err)?;
    rows.iter().map(row_from).collect()
}

/// Remove the registry row. The caller is responsible for also deleting the
/// package and **revoking its grants** — uninstall is not complete until the
/// envelope is revoked, because the envelope, not this row, is the authority.
pub(crate) async fn delete_extension(db: &Arc<SqlitePool>, extension_id: &str) -> io::Result<()> {
    sqlx::query("DELETE FROM extension_registry WHERE extension_id = ?")
        .bind(extension_id)
        .execute(db.as_ref())
        .await
        .map_err(db_err)?;
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    async fn pool() -> Arc<SqlitePool> {
        let db = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(include_str!(
            "../../../device/migrations/0020_extension_registry.sql"
        ))
        .execute(&db)
        .await
        .unwrap();
        Arc::new(db)
    }

    fn a_row() -> ExtensionRow {
        ExtensionRow {
            extension_id: "sh.kotton.feed-reader".into(),
            name: "Feed Reader".into(),
            version: "0.1.0".into(),
            class: "fetcher".into(),
            description: "Mirrors a feed.".into(),
            wasm_path: "/data/extensions/sh.kotton.feed-reader/extension.wasm".into(),
            content_hash: "a".repeat(64),
            publisher_did: None,
            network_json: Some(r#"{"endpoints":["*.substack.com"]}"#.into()),
            credential_slots: vec!["api-token".into()],
            installed_at: 1_754_000_000,
        }
    }

    #[tokio::test]
    async fn an_extension_round_trips() {
        let db = pool().await;
        let row = a_row();
        insert_extension(&db, &row).await.unwrap();

        let found = get_extension(&db, &row.extension_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found, row, "what was stored is what comes back");
        assert_eq!(found.credential_slots, vec!["api-token".to_string()]);

        assert!(get_extension(&db, "sh.kotton.absent")
            .await
            .unwrap()
            .is_none());
    }

    /// Reinstalling the same id replaces rather than duplicating — an upgrade
    /// is the same extension at a new hash, not a second one.
    #[tokio::test]
    async fn reinstalling_replaces_in_place() {
        let db = pool().await;
        insert_extension(&db, &a_row()).await.unwrap();

        let mut upgraded = a_row();
        upgraded.version = "0.2.0".into();
        upgraded.content_hash = "b".repeat(64);
        insert_extension(&db, &upgraded).await.unwrap();

        let all = list_extensions(&db).await.unwrap();
        assert_eq!(all.len(), 1, "one id, one row");
        assert_eq!(all[0].version, "0.2.0");
        assert_eq!(all[0].content_hash, "b".repeat(64));
    }

    #[tokio::test]
    async fn unsigned_packages_record_a_null_publisher_rather_than_failing() {
        let db = pool().await;
        let row = a_row();
        assert!(row.publisher_did.is_none());
        insert_extension(&db, &row).await.unwrap();
        let found = get_extension(&db, &row.extension_id)
            .await
            .unwrap()
            .unwrap();
        assert!(
            found.publisher_did.is_none(),
            "unsigned is a fact to surface, not an error"
        );
    }

    #[tokio::test]
    async fn listing_is_ordered_and_delete_removes_only_its_own_row() {
        let db = pool().await;
        for id in ["sh.kotton.zebra", "sh.kotton.alpha"] {
            let mut row = a_row();
            row.extension_id = id.into();
            insert_extension(&db, &row).await.unwrap();
        }
        let all = list_extensions(&db).await.unwrap();
        assert_eq!(
            all.iter()
                .map(|r| r.extension_id.as_str())
                .collect::<Vec<_>>(),
            vec!["sh.kotton.alpha", "sh.kotton.zebra"]
        );

        delete_extension(&db, "sh.kotton.alpha").await.unwrap();
        let all = list_extensions(&db).await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].extension_id, "sh.kotton.zebra");
    }
}
