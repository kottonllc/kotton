// SPDX-License-Identifier: AGPL-3.0-or-later
//! Durable app schema definitions for one principal.
//!
//! The [`SchemaRegistry`](crate::registry::SchemaRegistry) is built in
//! memory at startup from the sealed core schemas; everything an app registers
//! is written here so it comes back after a restart. Without that, a user's
//! records outlive the knowledge needed to read them —
//! `record_cmds::query` refuses an NSID the registry does not know, and
//! `apply_record_segments` skips replicated rows whose schema this device has
//! never seen.
//!
//! One row per NSID, keyed within this user's database, which is why no owner
//! column appears: the database *is* the principal.
//!
//! The **migration** that creates `app_schemas` stays in `kuserd`
//! (`migrations_user/0007_app_schemas.sql`), for the reason `core/grant` records
//! when its tables moved: the per-user migrations are one numbered sequence
//! against one database, and splitting a sequence across crates would make its
//! ordering a function of the dependency graph.

use sqlx::SqlitePool;
use std::io;

use kotton_schemas::definition::SchemaDefinition;

/// Map a `sqlx` error, naming the table so a failure says where it came from.
fn db_err(e: sqlx::Error) -> io::Error {
    io::Error::other(format!("app_schemas: {e}"))
}

/// Persist one schema definition, replacing any earlier version of it.
///
/// Called after the in-memory registry has accepted the definition, so the
/// version and `extends` rules have already been applied — this records the
/// outcome rather than deciding it. `registered_at` is preserved across an
/// upgrade: it records when this user first registered the NSID, not when they
/// last bumped it.
pub async fn upsert(pool: &SqlitePool, def: &SchemaDefinition) -> io::Result<()> {
    let json = serde_json::to_string(def)
        .map_err(|e| io::Error::other(format!("serialize schema: {e}")))?;

    sqlx::query(
        "INSERT INTO app_schemas (nsid, version, definition_json)
         VALUES (?, ?, ?)
         ON CONFLICT(nsid) DO UPDATE SET
             version         = excluded.version,
             definition_json = excluded.definition_json",
    )
    .bind(def.nsid.as_str())
    .bind(def.version)
    .bind(json)
    .execute(pool)
    .await
    .map_err(db_err)?;

    Ok(())
}

/// Every schema definition this user has registered.
///
/// A row that will not deserialize is skipped with a warning rather than
/// failing the load: one unreadable definition must not cost the user every
/// other schema they own, and the alternative — refusing to open — locks them
/// out of records that are otherwise fine.
pub async fn load_all(pool: &SqlitePool) -> io::Result<Vec<SchemaDefinition>> {
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT nsid, definition_json FROM app_schemas ORDER BY registered_at, nsid")
            .fetch_all(pool)
            .await
            .map_err(db_err)?;

    let mut defs = Vec::with_capacity(rows.len());
    for (nsid, json) in rows {
        match serde_json::from_str::<SchemaDefinition>(&json) {
            Ok(def) => defs.push(def),
            Err(e) => tracing::warn!(
                nsid = %nsid,
                error = %e,
                "app_schemas: stored definition will not deserialize, skipping it"
            ),
        }
    }
    Ok(defs)
}
