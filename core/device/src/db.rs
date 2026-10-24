// SPDX-License-Identifier: AGPL-3.0-or-later
//! The machine's two databases: `system/agent.db` (the machine db — paired
//! nodes, sync rules, sessions) and `system/device.db` (device configuration).
//!
//! Both opens live here, in the crate that acts on the machine's authority, so
//! that any binary serving this machine's paired set — the full daemon, or a
//! vault that keeps and does nothing else — opens the same files under the same
//! migrations. The migrator is one static: two crates each embedding a copy of
//! `migrations/` would be two schemas that drift.
//!
//! On `device.db` in particular:
//! The file is `kdeviced`'s: its schema is versioned by kdeviced's migrations
//! (`0002_device_config.sql` carries the `device_config` DDL), and the
//! `device_config` table lives here, not in the machine-wide `agent.db` —
//! device configuration is device authority. `kuserd` opens the file too
//! because the config verbs (`RendezvousSet`, `QuicGatewaySet`, …) still arrive
//! on the user socket: routing them through the supervisor needs a
//! kuserd↔kdeviced credential, per-child tokens, that does not exist. The
//! *storage* is device-scoped; the verb authority is not yet.

use sqlx::SqlitePool;
use std::io;
use std::path::Path;

/// The machine db's schema, embedded once.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

fn db_err(e: sqlx::Error) -> io::Error {
    io::Error::other(e.to_string())
}

/// Open (or create) the machine db at `path` and bring it to the current schema.
pub async fn open_machine_db<P: AsRef<Path>>(path: P) -> Result<SqlitePool, sqlx::Error> {
    let pool = kotton_record::open_sqlite(path.as_ref()).await?;
    MIGRATOR.run(&pool).await.map_err(|e| {
        sqlx::Error::Io(std::io::Error::other(format!("migration failed: {e}")))
    })?;
    Ok(pool)
}

/// Open (or create) `system/device.db` and make sure the `device_config`
/// table exists, importing legacy rows from `agent.db` on first contact.
///
/// Deliberately **not** `sqlx::migrate!` — kdeviced is this file's migration
/// owner, and two runners on one file would fight over `_sqlx_migrations`.
/// The `CREATE TABLE IF NOT EXISTS` matches kdeviced's DDL exactly and covers
/// the unsupervised boot (dev/test) where kdeviced has never run.
pub async fn open_device_db(base: &Path, agent_db: &SqlitePool) -> io::Result<SqlitePool> {
    let path = base.join("system").join("device.db");
    // The base dir and `system/`, owner-only when made here; one that exists
    // is left as it is (`kotton_common::fs::create_dir_all_owner_only`).
    if let Some(parent) = path.parent() {
        kotton_common::fs::create_dir_all_owner_only(parent)
            .map_err(|e| io::Error::other(format!("cannot create device db dir: {e}")))?;
    }

    let url = format!("sqlite://{}?mode=rwc", path.display());
    let pool = SqlitePool::connect(&url)
        .await
        .map_err(|e| io::Error::other(format!("cannot open device.db: {e}")))?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS device_config (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    )
    .execute(&pool)
    .await
    .map_err(db_err)?;

    import_legacy_rows(&pool, agent_db).await?;
    keep_a_cleared_relay_cleared(&pool).await?;
    Ok(pool)
}

/// Give a relay the person cleared before clearing wrote an empty row the empty
/// row it would be written as now.
///
/// Clearing used to delete `relay_url`, and a missing row is a device nobody has
/// told, which `KOTTON_RELAY_URL` filled at construction.
/// Those clears are still recognisable: `set_coord_url` wrote the forwarding
/// address `relay_url_previous` in the same call that deleted `relay_url`, and
/// nothing deletes `relay_url_previous`. Since clearing writes an empty row, no
/// path produces *previous without current* again, so the pair names exactly a
/// clear made under the old meaning. Runs on every open and changes nothing
/// once the row exists.
///
/// A clear made while the device held no relay wrote no forwarding address, and
/// so did any clear before the forwarding address existed; those left no trace
/// and are not recovered here.
async fn keep_a_cleared_relay_cleared(device_db: &SqlitePool) -> io::Result<()> {
    sqlx::query(
        "INSERT OR IGNORE INTO device_config (key, value) \
         SELECT 'relay_url', '' \
         WHERE EXISTS (SELECT 1 FROM device_config WHERE key = 'relay_url_previous') \
           AND NOT EXISTS (SELECT 1 FROM device_config WHERE key = 'relay_url')",
    )
    .execute(device_db)
    .await
    .map_err(db_err)?;
    Ok(())
}

/// One-time move of `device_config` rows out of the machine-wide `agent.db`.
///
/// Runs only while the device-scope table is empty, so it happens exactly once
/// per install; a crash between copy and delete leaves rows in both places,
/// which the next boot resolves as "already imported" — nothing reads the
/// legacy table any more, and the machine-wide `agent.db` is to be deleted.
async fn import_legacy_rows(device_db: &SqlitePool, agent_db: &SqlitePool) -> io::Result<()> {
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM device_config")
        .fetch_one(device_db)
        .await
        .map_err(db_err)?;
    if count > 0 {
        return Ok(());
    }

    let rows: Vec<(String, String)> = sqlx::query_as("SELECT key, value FROM device_config")
        .fetch_all(agent_db)
        .await
        .map_err(db_err)?;
    if rows.is_empty() {
        return Ok(());
    }

    for (key, value) in &rows {
        sqlx::query("INSERT OR REPLACE INTO device_config (key, value) VALUES (?, ?)")
            .bind(key)
            .bind(value)
            .execute(device_db)
            .await
            .map_err(db_err)?;
    }
    sqlx::query("DELETE FROM device_config")
        .execute(agent_db)
        .await
        .map_err(db_err)?;
    tracing::info!(
        rows = rows.len(),
        "device_config imported from agent.db into device.db (RFC-0063 stage 3a)"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn mem_pool_with_device_config() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS device_config (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool
    }

    async fn get(pool: &SqlitePool, key: &str) -> Option<String> {
        sqlx::query_scalar("SELECT value FROM device_config WHERE key = ?")
            .bind(key)
            .fetch_optional(pool)
            .await
            .unwrap()
    }

    /// Legacy rows move: present in device.db afterward, gone from agent.db.
    #[tokio::test]
    async fn legacy_rows_move_once() {
        let agent = mem_pool_with_device_config().await;
        let device = mem_pool_with_device_config().await;
        sqlx::query("INSERT INTO device_config (key, value) VALUES ('relay_url', 'https://r')")
            .execute(&agent)
            .await
            .unwrap();

        import_legacy_rows(&device, &agent).await.unwrap();

        assert_eq!(get(&device, "relay_url").await.as_deref(), Some("https://r"));
        assert_eq!(get(&agent, "relay_url").await, None);
    }

    /// A populated device.db is never overwritten by whatever lingers in
    /// agent.db — the import is first-contact only.
    #[tokio::test]
    async fn import_never_overwrites_a_populated_device_db() {
        let agent = mem_pool_with_device_config().await;
        let device = mem_pool_with_device_config().await;
        sqlx::query("INSERT INTO device_config (key, value) VALUES ('relay_url', 'https://old')")
            .execute(&agent)
            .await
            .unwrap();
        sqlx::query("INSERT INTO device_config (key, value) VALUES ('relay_url', 'https://new')")
            .execute(&device)
            .await
            .unwrap();

        import_legacy_rows(&device, &agent).await.unwrap();

        assert_eq!(get(&device, "relay_url").await.as_deref(), Some("https://new"));
        // The stale legacy row stays put (nothing reads it); it is not pulled in.
        assert_eq!(get(&agent, "relay_url").await.as_deref(), Some("https://old"));
    }

    /// Empty everywhere is a clean no-op.
    #[tokio::test]
    async fn empty_source_is_a_no_op() {
        let agent = mem_pool_with_device_config().await;
        let device = mem_pool_with_device_config().await;
        import_legacy_rows(&device, &agent).await.unwrap();
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM device_config")
            .fetch_one(&device)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    /// A device whose person cleared their relay before clearing wrote an empty
    /// row opens with the empty row, so construction does not refill it from
    /// the environment; a device nobody told, and one with a relay set, open as
    /// they were.
    #[tokio::test]
    async fn a_relay_cleared_under_the_old_meaning_opens_cleared() {
        let agent = mem_pool_with_device_config().await;
        async fn open_with(
            rows: &[(&str, &str)],
            agent: &SqlitePool,
        ) -> (tempfile::TempDir, SqlitePool) {
            let dir = tempfile::tempdir().unwrap();
            let first = open_device_db(dir.path(), agent).await.unwrap();
            for (k, v) in rows {
                sqlx::query("INSERT INTO device_config (key, value) VALUES (?, ?)")
                    .bind(k)
                    .bind(v)
                    .execute(&first)
                    .await
                    .unwrap();
            }
            first.close().await;
            let reopened = open_device_db(dir.path(), agent).await.unwrap();
            (dir, reopened)
        }

        // Cleared before this: the forwarding address, and no relay row.
        let (_c, cleared) = open_with(
            &[("relay_url_previous", "https://her-old.relay"), ("relay_url_previous_until", "1")],
            &agent,
        )
        .await;
        assert_eq!(get(&cleared, "relay_url").await.as_deref(), Some(""));

        // Nobody told it: no row, and none written.
        let (_u, untold) = open_with(&[("device-name", "attic")], &agent).await;
        assert_eq!(get(&untold, "relay_url").await, None);

        // Moved to a new relay: the row stands.
        let (_m, moved) = open_with(
            &[("relay_url", "https://new"), ("relay_url_previous", "https://old")],
            &agent,
        )
        .await;
        assert_eq!(get(&moved, "relay_url").await.as_deref(), Some("https://new"));
    }

    /// **A machine database from before #99 keeps every row when its
    /// `paired_nodes` is re-keyed by person and DID**
    /// (`migrations/0027_paired_nodes_per_person.sql`): every column of the
    /// `paired_nodes`, `drives`, legacy `sync_rules` and legacy `mount_configs`
    /// row reads back as written before the migration, and the
    /// reference those two held to `paired_nodes(id)` is gone with the key it
    /// named: with foreign keys enforced, as every pool here opens, a row can
    /// still be written and removed in each, and two people's rows under one
    /// label are both kept.
    #[tokio::test]
    async fn the_rekeyed_paired_nodes_keep_every_row_and_two_peoples_labels() {
        let dir = tempfile::tempdir().unwrap();
        let pool = kotton_record::open_sqlite(&dir.path().join("agent.db")).await.unwrap();
        let (before, rekey): (Vec<_>, Vec<_>) = MIGRATOR.iter().partition(|m| m.version < 27);
        for m in before {
            sqlx::raw_sql(&m.sql[..]).execute(&pool).await.unwrap();
        }
        sqlx::raw_sql(
            "INSERT INTO paired_nodes (id, user_id, device_did, public_key, addresses, paired_at, posture, relay_url) \
             VALUES ('vault', 'bob', 'did:key:zBob', x'07', '[]', 5, 'blind-storage', 'https://relay'); \
             INSERT INTO drives (user_id, vault_key, tenancy, node_id, recorded_at) VALUES ('bob', x'07', 'bob', 'vault', 5); \
             INSERT INTO sync_rules (user_id, node_id, path, watch, configured_at) VALUES ('bob', 'vault', '/notes', 1, 5); \
             INSERT INTO mount_configs (user_id, node_id, remote_path, local_path, mounted_at) VALUES ('bob', 'vault', '/', '/v', 5);",
        )
        .execute(&pool)
        .await
        .unwrap();
        for m in rekey {
            sqlx::raw_sql(&m.sql[..]).execute(&pool).await.unwrap();
        }

        let row: (String, String, String, Vec<u8>, i64, Option<String>, Option<String>) = sqlx::query_as(
            "SELECT user_id, device_did, id, public_key, paired_at, posture, relay_url FROM paired_nodes",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            row,
            ("bob".into(), "did:key:zBob".into(), "vault".into(), vec![7], 5, Some("blind-storage".into()), Some("https://relay".into()))
        );
        let drives: Vec<(String, Vec<u8>, String, String, i64)> =
            sqlx::query_as("SELECT user_id, vault_key, tenancy, node_id, recorded_at FROM drives")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(drives, [("bob".into(), vec![7], "bob".into(), "vault".into(), 5)]);
        let rules: Vec<(i64, String, String, String, i64, i64)> =
            sqlx::query_as("SELECT id, user_id, node_id, path, watch, configured_at FROM sync_rules")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(rules, [(1, "bob".into(), "vault".into(), "/notes".into(), 1, 5)]);
        // id, user_id, node_id, remote_path, local_path, cache_budget_bytes, pins, mounted_at
        type Mount = (i64, String, String, String, String, Option<i64>, String, i64);
        let mounts: Vec<Mount> = sqlx::query_as(
            "SELECT id, user_id, node_id, remote_path, local_path, cache_budget_bytes, pins, mounted_at FROM mount_configs",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(mounts, [(1, "bob".into(), "vault".into(), "/".into(), "/v".into(), None, "[]".into(), 5)]);

        // Another person's row under the same label sits beside bob's.
        sqlx::query(
            "INSERT INTO paired_nodes (id, user_id, device_did, public_key, addresses, paired_at) \
             VALUES ('vault', 'alice', 'did:key:zAlice', x'09', '[]', 6)",
        )
        .execute(&pool)
        .await
        .unwrap();
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM paired_nodes WHERE id = 'vault'").fetch_one(&pool).await.unwrap();
        assert_eq!(n, 2);
        // And the legacy tables, which referenced a key that is gone, are
        // still written and emptied under enforced foreign keys.
        sqlx::raw_sql(
            "INSERT INTO mount_configs (user_id, node_id, remote_path, local_path, mounted_at) VALUES ('alice', 'vault', '/', '/a', 6); \
             INSERT INTO sync_rules (user_id, node_id, path, configured_at) VALUES ('alice', 'vault', '/a', 6); \
             DELETE FROM paired_nodes WHERE user_id = 'bob'; \
             DELETE FROM mount_configs; DELETE FROM sync_rules;",
        )
        .execute(&pool)
        .await
        .unwrap();
    }
}
