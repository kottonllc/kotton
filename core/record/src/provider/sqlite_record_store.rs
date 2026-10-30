// SPDX-License-Identifier: AGPL-3.0-or-later
//! `SqliteRecordStore` — rusqlite-backed implementation of [`RecordStore`].
//!
//! ## Table layout
//!
//! One table per schema NSID, named by replacing `.` with `_`:
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS com_kotton_notes (
//!     id          TEXT    NOT NULL PRIMARY KEY,
//!     schema_nsid TEXT    NOT NULL,
//!     body        TEXT    NOT NULL,   -- JSON-encoded record fields
//!     created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
//!     updated_at  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
//!     deleted_at  INTEGER,            -- NULL = alive; non-NULL = tombstone
//!     revision    INTEGER NOT NULL DEFAULT 0, -- writes of this row; 0 = before the count
//!     root        TEXT,               -- NULL = Personal; else the root's id
//!     filed_at    INTEGER             -- ms, the filing device's clock; NULL = filed before the stamp
//! );
//! ```
//!
//! ## Every record has a place in the order it was filed
//!
//! `filed_at` is when the person's device that first filed the record filed
//! it, in milliseconds. A record *this* store files is stamped strictly above
//! every stamp already in the table — so two records it files inside one
//! millisecond, or across a clock step backwards, still come out in the order
//! it filed them. A merged row keeps the stamp it arrived with (below), so
//! that guarantee is per filing device, not over the table. It is the one clock a
//! conversation has: a message's own `sent_at` is its *sender's* claim, and the
//! two halves of a conversation are claimed by two machines
//! (`TASK-a-conversation-is-ordered-by-a-clock-it-does-not-hold`).
//!
//! Stamped once. A rewrite of the same id keeps it, and a merge keeps the stamp
//! the row arrived with, because a read mark written against it on one of the
//! person's devices has to name the same place on the next.
//!
//! ## Every record has a root (RFC-0071 R17)
//!
//! `root` is the root the record belongs to, and **an unmarked row is
//! Personal's**. A table written before the column existed is given it in
//! place, on open, by `ALTER TABLE … ADD COLUMN` — every existing row is then
//! unmarked, which is Personal, so nothing existing moves and no row is
//! rewritten. That is how `data/` was adopted as Personal's tree: a marker,
//! not a copy. Why Personal is unmarked rather than stamped with its id is
//! [`ChangesetRow::root`]'s note.
//!
//! ## Every write is a new version
//!
//! A row's version is `(updated_at, revision)`. `updated_at` is whole seconds;
//! `revision` counts the row's writes. Every write here — an insert, a rewrite,
//! a delete — sets `revision` to the one it replaces plus one, read inside the
//! statement that writes it. An insert does read the row first (`SELECT root,
//! filed_at, updated_at`, for its root, its place in the filing order and the
//! version it replaces), but that read and the write both run under the
//! store's held `conn` mutex, which serialises the pair: no other write of the
//! row lands between them, so two writes of a row can never share a version. A merge keeps the revision the row arrived with, so the
//! next write here counts on from it.
//!
//! The seconds alone could not do this: a record written and deleted inside one
//! second had one version, so the delete was never logged and a peer holding the
//! write would not have taken it (kotton #158). A finer clock would only have
//! shrunk that second; a count cannot tie. A table written before the column is
//! given it on open, every row at `0`, the version an earlier device logged it
//! at, so nothing already logged is logged again.
//!
//! **A local write is never older than the row it replaces.** An insert, a
//! rewrite or a delete takes `updated_at` = the later of this store's clock and
//! the `updated_at` the row already holds (kotton #172), and its revision still
//! counts on, so its version is strictly newer. Without the floor, two things
//! stamp a write below what it replaces: this device's clock stepped back
//! between a write and the next, or a row merged from a device whose clock runs
//! ahead. Either way a peer that already took the earlier version would keep it
//! and never take the later one — a delete that does not reach the person's
//! other devices. A row's `updated_at` can therefore run ahead of this store's
//! clock, and stays there across further writes until the clock catches up: it
//! is a version, and the clock is only its usual source. A merge does not take
//! the floor; an arriving row keeps the times it was written with.
//!
//! ## One clock
//!
//! Every time this store writes — `created_at`, `updated_at` and `deleted_at` in
//! seconds, `filed_at` in milliseconds — is read from one [`StoreClock`] and
//! bound into the statement, never taken from SQL's `now`. The clock is the
//! system clock unless a caller gives the store another with
//! [`SqliteRecordStore::with_clock`], which is how a test holds a second instead
//! of racing the wall clock for one (kotton #177). It is read under the held
//! `conn` mutex, so the writes of one store take their times in the order they
//! are written. A write's `updated_at` is the clock's second or the row's own,
//! whichever is later ("Every write is a new version"), so it can lead the clock. The column defaults in the DDL above are for rows written
//! without the store; the store itself always binds its stamps.
//!
//! ## Sync
//!
//! `export_changeset(since)` queries all schema tables for rows with
//! `updated_at > since` (including tombstones) and returns them as a
//! [`RecordChangeset`].  `merge_changeset` applies incoming rows with
//! last-write-wins semantics via a SQLite upsert: a row is taken when its
//! version is strictly newer than the one held.
//!
//! Neither is a wire verb. The rows another device's store exported reach this
//! one only through the sealed record log (`crate::replication`:
//! `log_records` on the sender, `apply_record_segments` here), which is the one
//! replication path; the peer verb that once carried plaintext rows straight
//! to `merge_changeset` is retired (kotton #173).
//!
//! ## Threading
//!
//! `rusqlite::Connection` is `Send` but not `Sync`.  All operations are
//! dispatched via `tokio::task::spawn_blocking` so the blocking connection is
//! never held across an `.await` point.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use kotton_schemas::{definition::SchemaDefinition, nsid::Nsid};
use rusqlite::{params, Connection};
use serde_json::Value;
use uuid::Uuid;

use crate::record_store::{
    ChangesetRow, Record, RecordChangeset, RecordFilter, RecordId, RecordStore, RecordStoreError,
    Result, SyncWatermark,
};

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Convert an NSID string to a safe SQLite table name.
///
/// `sh.kotton.notes` → `sh_kotton_notes`
///
/// Every character outside `[A-Za-z0-9_]` becomes `_`, not just the dots. The
/// narrower version silently produced **invalid SQL** for any NSID containing a
/// hyphen: `sh.kotton.channel.key-grant` became `sh_kotton_channel_key-grant`,
/// which SQLite rejects at the `-`. That took out channel messaging entirely —
/// creating a channel failed at the key-grant insert — and went unnoticed
/// because nothing exercised it (found 2026-08-10 by the first messaging test).
///
/// Widening this is safe precisely *because* such NSIDs could never have worked:
/// no table with an invalid identifier exists to migrate.
///
/// Note the pre-existing property this inherits rather than introduces: the
/// mapping is not injective, so `a.b-c` and `a.b_c` would share a table. Records
/// carry their `schema_nsid` in a column, so they stay distinguishable, but a
/// future NSID grammar should forbid the ambiguity at the source.
fn nsid_to_table(nsid: &str) -> String {
    nsid.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// DDL to create a schema table.
fn create_table_sql(table: &str) -> String {
    format!(
        r#"
        CREATE TABLE IF NOT EXISTS {t} (
            id          TEXT    NOT NULL,
            schema_nsid TEXT    NOT NULL,
            body        TEXT    NOT NULL,
            created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
            updated_at  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
            deleted_at  INTEGER,
            root        TEXT,
            filed_at    INTEGER,
            revision    INTEGER NOT NULL DEFAULT 0
        ) STRICT;

        CREATE UNIQUE INDEX IF NOT EXISTS idx_{t}_id ON {t} (id);
        CREATE INDEX        IF NOT EXISTS idx_{t}_deleted ON {t} (deleted_at);
        "#,
        t = table
    )
}

/// The columns `table` has, by name.
fn columns_of(conn: &Connection, table: &str) -> rusqlite::Result<Vec<String>> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let names = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .filter_map(|r| r.ok())
        .collect();
    Ok(names)
}

/// Every table in the file that holds records — those with an `updated_at`.
fn record_tables(conn: &Connection) -> rusqlite::Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
    )?;
    let names: Vec<String> = stmt
        .query_map([], |row| row.get(0))?
        .filter_map(|r| r.ok())
        .collect();
    let mut out = Vec::new();
    for name in names {
        if columns_of(conn, &name)?.iter().any(|c| c == "updated_at") {
            out.push(name);
        }
    }
    Ok(out)
}

/// Give `table` its `root` column if it predates it, and the index reads use.
///
/// **In place, and a marker rather than a copy** (RFC-0071 R17). The column is
/// added with no default, so every row already there is unmarked — which is
/// Personal — and no row is read or rewritten. Idempotent: a table that has the
/// column is only indexed, which `IF NOT EXISTS` makes a no-op.
fn adopt_into_roots(conn: &Connection, table: &str) -> rusqlite::Result<()> {
    if !columns_of(conn, table)?.iter().any(|c| c == "root") {
        conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN root TEXT;"))?;
    }
    conn.execute_batch(&format!(
        "CREATE INDEX IF NOT EXISTS idx_{table}_root ON {table} (root);"
    ))
}

/// Give `table` its `filed_at` column if it predates it, and the index the
/// stamp reads its predecessor from.
///
/// In place, like [`adopt_into_roots`]: the column is added with no default, so
/// every row already there reads as filed before the stamp existed and none is
/// rewritten. A query reads such a row as its `created_at`, which is the same
/// holder's clock in whole seconds.
fn adopt_filing_order(conn: &Connection, table: &str) -> rusqlite::Result<()> {
    if !columns_of(conn, table)?.iter().any(|c| c == "filed_at") {
        conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN filed_at INTEGER;"))?;
    }
    conn.execute_batch(&format!(
        "CREATE INDEX IF NOT EXISTS idx_{table}_filed ON {table} (filed_at);"
    ))
}

/// Give `table` its `revision` column if it predates it.
///
/// In place, like [`adopt_into_roots`]: every row already there takes `0`, the
/// revision a row written before the count carries on the wire too, so its
/// version is the one an earlier version of this device logged it at and
/// nothing is logged twice. The next write of the row takes `1`.
fn adopt_write_revision(conn: &Connection, table: &str) -> rusqlite::Result<()> {
    if !columns_of(conn, table)?.iter().any(|c| c == "revision") {
        conn.execute_batch(&format!(
            "ALTER TABLE {table} ADD COLUMN revision INTEGER NOT NULL DEFAULT 0;"
        ))?;
    }
    Ok(())
}

/// Everything a table written by an earlier version is given on open.
fn adopt(conn: &Connection, table: &str) -> rusqlite::Result<()> {
    adopt_into_roots(conn, table)?;
    adopt_filing_order(conn, table)?;
    adopt_write_revision(conn, table)
}

/// Run [`adopt`] over every record table in the file.
fn adopt_every_table(conn: &Connection) -> rusqlite::Result<()> {
    for table in record_tables(conn)? {
        adopt(conn, &table)?;
    }
    Ok(())
}

/// The clock a [`SqliteRecordStore`] stamps its writes with, in milliseconds
/// since the Unix epoch (module doc, "One clock").
///
/// The system clock by default. A value from it is a time, not an identifier:
/// it names no person and no device, and it already rides on every row.
#[derive(Clone)]
pub struct StoreClock(Arc<dyn Fn() -> i64 + Send + Sync>);

impl StoreClock {
    /// This device's clock.
    pub fn system() -> Self {
        Self::new(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0)
        })
    }

    /// A clock that reads `now`, in milliseconds since the epoch.
    pub fn new(now: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        Self(Arc::new(now))
    }

    /// A clock held at `millis`: every read returns it.
    pub fn fixed(millis: i64) -> Self {
        Self::new(move || millis)
    }

    /// The time now, in milliseconds since the epoch.
    pub fn millis(&self) -> i64 {
        (self.0)()
    }
}

impl Default for StoreClock {
    fn default() -> Self {
        Self::system()
    }
}

/// Whole seconds of a millisecond time — the unit `created_at`, `updated_at`
/// and `deleted_at` are kept in.
fn seconds(millis: i64) -> i64 {
    millis.div_euclid(1000)
}

/// The stamp a record filed now takes in `table`: this device's clock, or one
/// past the newest stamp already there, whichever is later.
///
/// **The `+ 1` is the whole of the ordering guarantee.** A clock alone ties
/// inside one tick and runs backwards when it is corrected; the table's own
/// newest stamp does neither, so a record filed after another always sorts
/// after it. It is read under the same connection lock the insert holds, so no
/// second writer can take the same stamp between the read and the write.
fn next_filing_stamp(conn: &Connection, table: &str, now: i64) -> rusqlite::Result<i64> {
    let newest: Option<i64> =
        conn.query_row(&format!("SELECT MAX(filed_at) FROM {table}"), [], |row| row.get(0))?;
    Ok(newest.map_or(now, |n| now.max(n + 1)))
}

// ── SqliteRecordStore ────────────────────────────────────────────────────────

/// SQLite-backed record store with last-write-wins sync semantics.
#[derive(Clone)]
pub struct SqliteRecordStore {
    conn: Arc<Mutex<Connection>>,
    clock: StoreClock,
}

impl SqliteRecordStore {
    /// Open (or create) a SQLite database at `path`.
    ///
    /// If `key` is `Some`, the database is opened (or created) with SQLCipher
    /// encryption using the supplied 32-byte key.  The key **must** be the same
    /// value that was used when the database was first created; passing the wrong
    /// key will cause all queries to fail with a "file is not a database" error.
    ///
    /// Pass `None` during development or when encryption is not yet wired
    /// through from the caller's key-derivation context.
    ///
    /// Enables WAL mode for better concurrent read performance.
    pub fn open(path: &std::path::Path, key: Option<&[u8; 32]>) -> Result<Self> {
        if let Some(parent) = path.parent() {
            kotton_common::fs::create_dir_all_owner_only(parent)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        }

        let conn = Connection::open(path)?;

        // SQLCipher key — MUST be the very first statement on the connection.
        if let Some(key) = key {
            conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";\n", hex::encode(key)))?;
        }

        // WAL mode for better concurrent read/write throughput
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;

        // Enable foreign key checks
        conn.execute_batch("PRAGMA foreign_keys=ON;")?;

        // Every table written before records had a root gets the column now,
        // before anything reads it (RFC-0071 R17).
        adopt_every_table(&conn)?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            clock: StoreClock::system(),
        })
    }

    /// Stamp this store's writes from `clock` instead of the system clock.
    ///
    /// Set it where the store is opened, before the store is cloned: a clone
    /// shares the connection but carries its own clock.
    pub fn with_clock(mut self, clock: StoreClock) -> Self {
        self.clock = clock;
        self
    }

    /// Open an in-memory database (useful for testing).
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            clock: StoreClock::system(),
        })
    }
}

#[async_trait]
impl RecordStore for SqliteRecordStore {
    async fn create_table(&self, schema: &SchemaDefinition) -> Result<()> {
        let table = nsid_to_table(schema.nsid.as_str());
        let conn = Arc::clone(&self.conn);

        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute_batch(&create_table_sql(&table))?;
            // `CREATE … IF NOT EXISTS` leaves an older table as it was, so a
            // table this process meets for the first time here is adopted here.
            adopt(&conn, &table)?;
            Ok::<(), RecordStoreError>(())
        })
        .await?
    }

    async fn insert_in(
        &self,
        schema_nsid: &Nsid,
        root: Option<String>,
        record: Value,
    ) -> Result<RecordId> {
        let table = nsid_to_table(schema_nsid.as_str());
        let nsid_str = schema_nsid.as_str().to_owned();

        // Use provided id or generate a new UUID v4.
        let id = record
            .get("id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned())
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        // Always store the id inside the body so that `json_extract(body, '$.id')`
        // can be used for direct lookups (e.g. `record_open`).
        let mut record_with_id = record;
        if let Some(obj) = record_with_id.as_object_mut() {
            obj.entry("id".to_owned())
                .or_insert_with(|| serde_json::json!(&id));
        }
        let body = serde_json::to_string(&record_with_id)?;
        let conn = Arc::clone(&self.conn);
        let id_clone = id.clone();
        let clock = self.clock.clone();

        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            // Read under the lock, so this store's writes take their times in
            // the order they are written (module doc, "One clock").
            let now = clock.millis();
            // A record does not change root by being rewritten: the replace
            // below would delete a row that may be in a root this writer cannot
            // read. Tombstones included — a deleted row is still that root's.
            let existing: Option<(Option<String>, Option<i64>, i64)> = conn
                .query_row(
                    &format!("SELECT root, filed_at, updated_at FROM {table} WHERE id = ?1"),
                    params![id_clone],
                    |row| {
                        Ok((
                            row.get::<_, Option<String>>(0)?,
                            row.get::<_, Option<i64>>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(other),
                })?;
            if let Some((held, _, _)) = &existing {
                if *held != root {
                    return Err(RecordStoreError::InAnotherRoot(id_clone));
                }
            }
            // Never older than the row it replaces: a clock stepped back, or a
            // row merged from a clock running ahead, would otherwise stamp this
            // write below the version a peer already holds, and the peer would
            // keep that one (module doc, "Every write is a new version").
            let updated_at = existing
                .as_ref()
                .map_or(seconds(now), |(_, _, held)| seconds(now).max(*held));
            // Filed once: a rewrite keeps the place the record already had.
            let filed_at = match existing.and_then(|(_, filed, _)| filed) {
                Some(filed) => filed,
                None => next_filing_stamp(&conn, &table, now)?,
            };
            // A new version: the revision this write replaces, tombstone
            // included, plus one, read inside the statement that writes it.
            // The `SELECT root, filed_at, updated_at` above ran first, and the
            // held `conn` mutex serialises it with this INSERT, so no other
            // write of the row comes between them (module doc, "Every write is
            // a new version").
            conn.execute(
                &format!(
                    "INSERT OR REPLACE INTO {table} \
                    (id, schema_nsid, body, created_at, updated_at, root, filed_at, revision) \
                    VALUES (?1, ?2, ?3, ?6, ?7, ?4, ?5, \
                    COALESCE((SELECT revision FROM {table} WHERE id = ?1), 0) + 1)"
                ),
                params![id_clone, nsid_str, body, root, filed_at, seconds(now), updated_at],
            )?;
            Ok::<(), RecordStoreError>(())
        })
        .await??;

        Ok(id)
    }

    async fn query(&self, schema_nsid: &Nsid, filter: RecordFilter) -> Result<Vec<Record>> {
        let table = nsid_to_table(schema_nsid.as_str());
        let conn = Arc::clone(&self.conn);

        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();

            // A namespace nothing has ever written has no table, and asking a
            // store for records it holds none of is not an error — it is an
            // empty answer. Reporting it as a failure made two ordinary things
            // fail: a fresh user polling an inbox before ever sending, and a
            // delivery checking whether it already held a copy (`DEC-0055`),
            // where an error had to be treated as "cannot tell" and so refused.
            let exists: bool = conn
                .prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?")
                .and_then(|mut stmt| stmt.exists([&table]))
                .unwrap_or(false);
            if !exists {
                return Ok(Vec::new());
            }

            // Build WHERE clause. The root predicate is first and always there:
            // a read names the roots it may see, Personal alone by default.
            let (in_roots, root_ids) = filter.roots.predicate();
            let mut where_parts: Vec<String> = vec!["deleted_at IS NULL".to_owned(), in_roots];
            let mut bound: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
            for id in root_ids {
                bound.push(Box::new(id));
            }

            for (field, val) in &filter.field_eq {
                where_parts.push(format!("json_extract(body, '$.{field}') = ?"));
                let s = match val {
                    Value::String(s) => s.clone(),
                    other => serde_json::to_string(other).unwrap_or_default(),
                };
                bound.push(Box::new(s));
            }
            if let Some(ref text) = filter.text {
                where_parts.push("body LIKE ? ESCAPE '\\'".to_owned());
                // Escape LIKE special characters in the user input.
                let escaped = text
                    .replace('\\', "\\\\")
                    .replace('%', "\\%")
                    .replace('_', "\\_");
                bound.push(Box::new(format!("%{escaped}%")));
            }

            // Pagination cursor: only rows inserted before `before_id` (by rowid).
            if let Some(ref bid) = filter.before_id {
                where_parts.push(format!("rowid < (SELECT rowid FROM {table} WHERE id = ?)"));
                bound.push(Box::new(bid.clone()));
            }

            let where_clause = where_parts.join(" AND ");
            let mut sql = format!(
                "SELECT id, schema_nsid, body, updated_at, root, \
                 COALESCE(filed_at, created_at * 1000) \
                 FROM {table} WHERE {where_clause} \
                 ORDER BY rowid DESC"
            );

            if let Some(limit) = filter.limit {
                sql.push_str(&format!(" LIMIT {limit}"));
            }
            if let Some(offset) = filter.offset {
                sql.push_str(&format!(" OFFSET {offset}"));
            }

            let mut stmt = conn.prepare(&sql)?;
            let params: Vec<&dyn rusqlite::types::ToSql> =
                bound.iter().map(|b| b.as_ref()).collect();

            let rows = stmt.query_map(params.as_slice(), |row| {
                let id: String = row.get(0)?;
                let schema_nsid: String = row.get(1)?;
                let body_str: String = row.get(2)?;
                let updated_at: i64 = row.get(3)?;
                let root: Option<String> = row.get(4)?;
                let filed_at: i64 = row.get(5)?;
                Ok((id, schema_nsid, body_str, updated_at, root, filed_at))
            })?;

            let mut records = Vec::new();
            for row in rows {
                let (id, schema_nsid, body_str, updated_at, root, filed_at) = row?;
                let body: Value = serde_json::from_str(&body_str).unwrap_or(Value::Null);
                records.push(Record {
                    id,
                    schema_nsid,
                    body,
                    updated_at,
                    root,
                    filed_at,
                });
            }
            Ok::<Vec<Record>, RecordStoreError>(records)
        })
        .await?
    }

    async fn delete_in(
        &self,
        schema_nsid: &Nsid,
        record_id: &RecordId,
        roots: &crate::record_store::RootSelection,
    ) -> Result<()> {
        let table = nsid_to_table(schema_nsid.as_str());
        let id = record_id.clone();
        let conn = Arc::clone(&self.conn);
        let (in_roots, root_ids) = roots.predicate();
        let clock = self.clock.clone();

        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let now = seconds(clock.millis());
            // Never older than the row it replaces (module doc, "Every write is
            // a new version"): `MAX(?, updated_at)` reads the row's version
            // before this statement writes it, so both stamps take it.
            let mut bound: Vec<Box<dyn rusqlite::types::ToSql>> =
                vec![Box::new(now), Box::new(now), Box::new(id.clone())];
            for r in root_ids {
                bound.push(Box::new(r));
            }
            let params: Vec<&dyn rusqlite::types::ToSql> =
                bound.iter().map(|b| b.as_ref()).collect();
            let affected = conn.execute(
                &format!(
                    "UPDATE {table} SET deleted_at = MAX(?, updated_at), \
                     updated_at = MAX(?, updated_at), \
                     revision = revision + 1 \
                     WHERE id = ? AND deleted_at IS NULL AND {in_roots}"
                ),
                params.as_slice(),
            )?;
            if affected == 0 {
                return Err(RecordStoreError::RecordNotFound(id));
            }
            Ok::<(), RecordStoreError>(())
        })
        .await?
    }

    async fn gc_tombstones(&self, before_ts: SyncWatermark) -> Result<u64> {
        // Remove all rows tombstoned before `before_ts` (Unix seconds).
        //
        // The invariant this relies on: a tombstone is collected only when it
        // is strictly older than `before_ts`, and `before_ts` is no later than
        // this store's clock reads now (no caller in the tree passes one yet;
        // its one test passes `i64::MAX` and re-inserts nothing after). A record
        // re-inserted under a collected id restarts at revision 1, but its
        // `updated_at` is now, a strictly later second than the tombstone's
        // `deleted_at`, so on a peer still holding the tombstone it wins on
        // the second, whatever the count. A `before_ts` in the future, or the
        // clock stepped back past a collected tombstone, breaks that: the
        // re-insert can then lose to the tombstone it replaced.
        let conn = Arc::clone(&self.conn);

        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();

            // Find all schema tables (skip sqlite internals).
            let tables: Vec<String> = {
                let mut stmt = conn.prepare(
                    "SELECT name FROM sqlite_master \
                     WHERE type='table' AND name NOT LIKE 'sqlite_%'",
                )?;
                let names: Vec<String> = stmt
                    .query_map([], |row| row.get(0))?
                    .filter_map(|r| r.ok())
                    .collect();
                names
            };

            let mut total: u64 = 0;
            for table in &tables {
                // Check if the table has a deleted_at column before issuing GC.
                let has_deleted_col: bool = conn
                    .prepare(&format!("PRAGMA table_info({table})"))?
                    .query_map([], |row| {
                        let col_name: String = row.get(1)?;
                        Ok(col_name)
                    })?
                    .filter_map(|r| r.ok())
                    .any(|col| col == "deleted_at");

                if !has_deleted_col {
                    continue;
                }

                let affected = conn.execute(
                    &format!(
                        "DELETE FROM {table} WHERE deleted_at IS NOT NULL \
                         AND deleted_at < ?1"
                    ),
                    params![before_ts],
                )?;
                total += affected as u64;
            }
            Ok::<u64, RecordStoreError>(total)
        })
        .await?
    }

    async fn merge_changeset(&self, changeset: RecordChangeset) -> Result<()> {
        let conn = Arc::clone(&self.conn);
        let clock = self.clock.clone();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            for row in &changeset {
                let table = nsid_to_table(&row.schema_nsid);

                // Require the table to exist; the sync layer registers schemas
                // before sending records.
                let exists: bool = conn
                    .query_row(
                        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
                        params![table],
                        |_| Ok(true),
                    )
                    .unwrap_or(false);
                if !exists {
                    return Err(RecordStoreError::TableNotFound(row.schema_nsid.clone()));
                }

                let body = serde_json::to_string(&row.body)?;
                // LWW upsert: apply only when the incoming row is strictly newer
                // — a later second, or the same second and a higher revision,
                // which is how a delete made in the second its record was
                // written replaces it (kotton #158). The revision it arrives with
                // is kept, so a write here after it counts on from it.
                //
                // The root is written on insert and **never changed by a
                // merge**: a record belongs to exactly one root (RFC-0071 R17),
                // and a newer version is a newer version of that root's record.
                // An incoming row naming a different root for an id already
                // held is not applied — it is either a peer that has a record
                // this device does not, under a colliding id, or a peer trying
                // to move a row, and neither is a merge.
                //
                // The filing stamp arrives with the row and is kept: it is
                // where the device that first held the record placed it, and a
                // read mark written there must name the same place here. A row
                // filed before the stamp existed is stamped on arrival, which
                // is the best this device can say about it. An update never
                // moves a stamp the row already has.
                let filed_at = match row.filed_at {
                    Some(filed) => filed,
                    None => next_filing_stamp(&conn, &table, clock.millis())?,
                };
                conn.execute(
                    &format!(
                        "INSERT INTO {table} \
                         (id, schema_nsid, body, created_at, updated_at, deleted_at, root, filed_at, revision) \
                         VALUES (?1, ?2, ?3, ?4, ?4, ?5, ?6, ?7, ?8) \
                         ON CONFLICT(id) DO UPDATE SET \
                           body       = excluded.body, \
                           updated_at = excluded.updated_at, \
                           deleted_at = excluded.deleted_at, \
                           revision   = excluded.revision, \
                           filed_at   = COALESCE({table}.filed_at, excluded.filed_at) \
                         WHERE (excluded.updated_at > {table}.updated_at \
                                OR (excluded.updated_at = {table}.updated_at \
                                    AND excluded.revision > {table}.revision)) \
                           AND excluded.root IS {table}.root"
                    ),
                    params![
                        row.id,
                        row.schema_nsid,
                        body,
                        row.updated_at,
                        row.deleted_at,
                        row.root,
                        filed_at,
                        row.revision
                    ],
                )?;
            }
            Ok::<(), RecordStoreError>(())
        })
        .await?
    }

    async fn export_changeset(&self, since: SyncWatermark) -> Result<RecordChangeset> {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();

            // Enumerate all schema tables (skip sqlite internals).
            let tables: Vec<String> = {
                let mut stmt = conn.prepare(
                    "SELECT name FROM sqlite_master \
                     WHERE type='table' AND name NOT LIKE 'sqlite_%'",
                )?;
                let names: Vec<String> = stmt
                    .query_map([], |row| row.get(0))?
                    .filter_map(|r| r.ok())
                    .collect();
                names
            };

            let mut changeset = RecordChangeset::new();
            for table in &tables {
                // Skip tables that aren't schema tables (no updated_at column).
                let col_names: Vec<String> = {
                    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
                    let names: Vec<String> = stmt
                        .query_map([], |row| row.get::<_, String>(1))?
                        .filter_map(|r| r.ok())
                        .collect();
                    names
                };
                if !col_names.iter().any(|c| c == "updated_at") {
                    continue;
                }

                let mut stmt = conn.prepare(&format!(
                    "SELECT id, schema_nsid, body, updated_at, deleted_at, root, filed_at, revision \
                     FROM {table} WHERE updated_at > ?1"
                ))?;
                let rows_data: Vec<_> = stmt
                    .query_map(params![since], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, Option<i64>>(4)?,
                            row.get::<_, Option<String>>(5)?,
                            row.get::<_, Option<i64>>(6)?,
                            row.get::<_, i64>(7)?,
                        ))
                    })?
                    .filter_map(|r| r.ok())
                    .collect();
                // Each row leaves with its root, its place in the filing order
                // and its revision: records travel with all three.
                for (id, schema_nsid, body_str, updated_at, deleted_at, root, filed_at, revision) in
                    rows_data
                {
                    let body = serde_json::from_str(&body_str).unwrap_or(Value::Null);
                    changeset.push(ChangesetRow {
                        id,
                        schema_nsid,
                        body,
                        updated_at,
                        revision,
                        deleted_at,
                        root,
                        filed_at,
                    });
                }
            }
            Ok::<RecordChangeset, RecordStoreError>(changeset)
        })
        .await?
    }

    async fn migrate_table(
        &self,
        old: &SchemaDefinition,
        new: &SchemaDefinition,
    ) -> crate::record_store::MigrationResult {
        use crate::record_store::MigrationError;
        use std::collections::HashSet;

        // Reject version downgrades or identical re-registrations via this path.
        if new.version <= old.version {
            return Err(MigrationError::Downgrade {
                nsid: old.nsid.as_str().to_owned(),
                current: old.version,
                proposed: new.version,
            });
        }

        let old_names: HashSet<&str> = old.fields.iter().map(|f| f.name.as_str()).collect();
        let new_names: HashSet<&str> = new.fields.iter().map(|f| f.name.as_str()).collect();

        // Reject removal of any field present in the old schema.
        if let Some(removed) = old_names.difference(&new_names).next() {
            return Err(MigrationError::Destructive {
                field: (*removed).to_owned(),
            });
        }

        // Reject new required fields that carry no default — existing records
        // would be missing them.
        for added in new_names.difference(&old_names) {
            let field = new
                .fields
                .iter()
                .find(|f| f.name.as_str() == *added)
                .expect("field must be in new.fields");
            if !field.nullable && field.default.is_none() {
                return Err(MigrationError::NonAdditive {
                    field: (*added).to_owned(),
                });
            }
        }

        // For the JSON-body storage model no DDL is required — all fields live
        // inside the `body` TEXT blob.  A future column-per-field backend would
        // emit `ALTER TABLE ADD COLUMN ... DEFAULT ...` here.
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record_store::RootSelection;
    use kotton_schemas::core::CoreSchema;
    use serde_json::json;

    fn notes_store() -> SqliteRecordStore {
        SqliteRecordStore::in_memory().expect("in-memory store")
    }

    async fn store_with_notes_table() -> SqliteRecordStore {
        let store = notes_store();
        let schema = CoreSchema::Notes.definition();
        store.create_table(&schema).await.expect("create_table");
        store
    }

    fn notes_nsid() -> Nsid {
        Nsid::new("sh.kotton.notes").unwrap()
    }

    // ── at rest ────────────────────────────────────────────────────────────

    /// The 16-byte magic every plaintext SQLite file begins with.
    const SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";

    /// A string that appears in the record and nowhere else, so finding it in a
    /// file is unambiguous.
    const MARKER: &str = "kotton-at-rest-canary-8f3a1d";

    /// Write one record through a store at `path`, keyed or not, and close it.
    async fn write_a_record(path: &std::path::Path, key: Option<&[u8; 32]>) {
        let store = SqliteRecordStore::open(path, key).expect("open");
        store.create_table(&CoreSchema::Notes.definition()).await.expect("create_table");
        store
            .insert(&notes_nsid(), json!({ "title": MARKER, "body": MARKER, "tags": [] }))
            .await
            .expect("insert");
        // Dropped here: the connection closes and WAL is checkpointed, so what is
        // on disk is what a person with the disk would find.
        drop(store);
    }

    /// Every byte written under `dir`, file by file — the main database and any
    /// `-wal` / `-journal` beside it.
    fn bytes_on_disk(dir: &std::path::Path) -> Vec<(String, Vec<u8>)> {
        std::fs::read_dir(dir)
            .expect("read dir")
            .flatten()
            .filter(|e| e.path().is_file())
            .map(|e| {
                (
                    e.file_name().to_string_lossy().into_owned(),
                    std::fs::read(e.path()).expect("read file"),
                )
            })
            .collect()
    }

    /// **The README's strongest sentence, as a test.**
    ///
    /// *"Encryption at rest — sealed on the device; a keyless node cannot write
    /// plaintext at all."* That claim had nothing behind it: `DEC-0049` removed
    /// the fallback that opened a keyless store, and `open.rs` refuses with
    /// `LOCKED` now — but refusing to *open* without a key and *writing
    /// ciphertext* with one are two different claims, and only the first was
    /// checked. Nothing in the workspace ever opened the file and looked.
    ///
    /// Checks every file in the directory, not just `records.db`. SQLCipher
    /// encrypts the WAL too, and a `-wal` holding plaintext beside a sealed main
    /// file would satisfy a narrower test while leaving the record readable to
    /// anyone with the disk — which is the whole of what this claim is about.
    #[tokio::test]
    async fn a_keyed_store_writes_no_plaintext_to_disk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = [7u8; 32];
        write_a_record(&dir.path().join("records.db"), Some(&key)).await;

        let files = bytes_on_disk(dir.path());
        assert!(!files.is_empty(), "nothing was written; the test would pass vacuously");

        for (name, bytes) in &files {
            assert!(
                !bytes.starts_with(SQLITE_MAGIC),
                "{name} begins with the plaintext SQLite header"
            );
            assert!(
                !bytes.windows(MARKER.len()).any(|w| w == MARKER.as_bytes()),
                "{name} contains the record's text in the clear"
            );
        }
    }

    /// **The control, and the test is worth nothing without it.**
    ///
    /// An unkeyed store must fail both assertions above. Without this, a typo in
    /// the marker or a store that silently wrote nothing would make the test
    /// above pass against a database sitting in plaintext — which is exactly the
    /// failure it exists to catch.
    #[tokio::test]
    async fn the_check_can_tell_the_difference() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_a_record(&dir.path().join("records.db"), None).await;

        let files = bytes_on_disk(dir.path());
        let main = files
            .iter()
            .find(|(n, _)| n == "records.db")
            .map(|(_, b)| b.clone())
            .expect("records.db");
        assert!(
            main.starts_with(SQLITE_MAGIC),
            "an unkeyed store should be plain SQLite; if it is not, the assertion above proves nothing"
        );
        assert!(
            files
                .iter()
                .any(|(_, b)| b.windows(MARKER.len()).any(|w| w == MARKER.as_bytes())),
            "an unkeyed store should leave the record's text findable on disk"
        );
    }

    // ── create_table ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn create_table_is_idempotent() {
        let store = notes_store();
        let schema = CoreSchema::Notes.definition();
        store.create_table(&schema).await.unwrap();
        // Second call must not error
        store.create_table(&schema).await.unwrap();
    }

    // ── insert / query round-trip ─────────────────────────────────────────

    #[tokio::test]
    async fn insert_and_query_round_trip() {
        let store = store_with_notes_table().await;
        let nsid = notes_nsid();

        let record = json!({
            "title": "Hello World",
            "body": "First note",
            "tags": []
        });

        let id = store.insert(&nsid, record.clone()).await.unwrap();
        assert!(!id.is_empty(), "id should be a non-empty UUID");

        let results = store.query(&nsid, RecordFilter::new()).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, id);
        assert_eq!(results[0].body["title"], "Hello World");
    }

    #[tokio::test]
    async fn insert_with_explicit_id() {
        let store = store_with_notes_table().await;
        let nsid = notes_nsid();

        let id = store
            .insert(&nsid, json!({ "id": "my-custom-id", "title": "Custom" }))
            .await
            .unwrap();

        assert_eq!(id, "my-custom-id");
        let results = store.query(&nsid, RecordFilter::new()).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "my-custom-id");
    }

    #[tokio::test]
    async fn query_filter_by_field() {
        let store = store_with_notes_table().await;
        let nsid = notes_nsid();

        store
            .insert(&nsid, json!({ "title": "Alpha" }))
            .await
            .unwrap();
        store
            .insert(&nsid, json!({ "title": "Beta" }))
            .await
            .unwrap();

        let results = store
            .query(&nsid, RecordFilter::new().eq("title", "Alpha"))
            .await
            .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].body["title"], "Alpha");
    }

    #[tokio::test]
    async fn query_limit_and_offset() {
        let store = store_with_notes_table().await;
        let nsid = notes_nsid();

        for i in 0..5 {
            store
                .insert(&nsid, json!({ "title": format!("Note {i}") }))
                .await
                .unwrap();
        }

        let page1 = store
            .query(&nsid, RecordFilter::new().limit(2))
            .await
            .unwrap();
        assert_eq!(page1.len(), 2);

        let page2 = store
            .query(&nsid, RecordFilter::new().limit(2).offset(2))
            .await
            .unwrap();
        assert_eq!(page2.len(), 2);

        // Pages must not overlap
        assert_ne!(page1[0].id, page2[0].id);
        assert_ne!(page1[1].id, page2[1].id);
    }

    // ── delete / tombstone ────────────────────────────────────────────────

    #[tokio::test]
    async fn delete_hides_record_from_query() {
        let store = store_with_notes_table().await;
        let nsid = notes_nsid();

        let id = store
            .insert(&nsid, json!({ "title": "To delete" }))
            .await
            .unwrap();

        store.delete(&nsid, &id).await.unwrap();

        let results = store.query(&nsid, RecordFilter::new()).await.unwrap();
        assert!(
            results.is_empty(),
            "deleted record should not appear in query results"
        );
    }

    #[tokio::test]
    async fn delete_nonexistent_returns_error() {
        let store = store_with_notes_table().await;
        let nsid = notes_nsid();

        let err = store
            .delete(&nsid, &"no-such-id".to_owned())
            .await
            .unwrap_err();

        assert!(
            matches!(err, RecordStoreError::RecordNotFound(_)),
            "expected RecordNotFound, got {err:?}"
        );
    }

    // ── tombstone GC ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn gc_tombstones_removes_deleted_rows() {
        let store = store_with_notes_table().await;
        let nsid = notes_nsid();

        let id = store
            .insert(&nsid, json!({ "title": "Ephemeral" }))
            .await
            .unwrap();
        store.delete(&nsid, &id).await.unwrap();

        // GC with a far-future version removes all tombstones.
        let removed = store.gc_tombstones(i64::MAX).await.unwrap();
        assert_eq!(removed, 1, "one tombstoned row should have been removed");

        // A second GC pass finds nothing left to remove.
        let removed2 = store.gc_tombstones(i64::MAX).await.unwrap();
        assert_eq!(removed2, 0);
    }

    // ── changeset (LWW sync) ───────────────────────────────────────────────

    #[tokio::test]
    async fn merge_newer_wins() {
        let store = store_with_notes_table().await;
        let nsid = notes_nsid();

        let id = store
            .insert(&nsid, json!({ "title": "Original" }))
            .await
            .unwrap();

        // Peer has a newer version of the same record.
        let newer_ts: i64 = 9_000_000_000;
        let changeset = vec![ChangesetRow {
            id: id.clone(),
            schema_nsid: "sh.kotton.notes".to_owned(),
            body: json!({ "title": "Updated by peer" }),
            updated_at: newer_ts,
            revision: 0,
            deleted_at: None,
            root: None,
            filed_at: None,
        }];
        store.merge_changeset(changeset).await.unwrap();

        let results = store.query(&nsid, RecordFilter::new()).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].body["title"], "Updated by peer");
    }

    #[tokio::test]
    async fn merge_older_does_not_overwrite() {
        let store = store_with_notes_table().await;
        let nsid = notes_nsid();

        let id = store
            .insert(&nsid, json!({ "title": "Local" }))
            .await
            .unwrap();

        // Peer's version is stale (epoch ~1970) — must be rejected.
        let changeset = vec![ChangesetRow {
            id: id.clone(),
            schema_nsid: "sh.kotton.notes".to_owned(),
            body: json!({ "title": "Stale peer version" }),
            updated_at: 1,
            revision: 0,
            deleted_at: None,
            root: None,
            filed_at: None,
        }];
        store.merge_changeset(changeset).await.unwrap();

        let results = store.query(&nsid, RecordFilter::new()).await.unwrap();
        assert_eq!(
            results[0].body["title"], "Local",
            "stale peer version must not overwrite local"
        );
    }

    #[tokio::test]
    async fn merge_new_record_inserted() {
        let store = store_with_notes_table().await;
        let nsid = notes_nsid();

        // Record that only exists on the peer.
        let changeset = vec![ChangesetRow {
            id: "peer-only-id".to_owned(),
            schema_nsid: "sh.kotton.notes".to_owned(),
            body: json!({ "title": "Peer note" }),
            updated_at: 1_000_000,
            revision: 0,
            deleted_at: None,
            root: None,
            filed_at: None,
        }];
        store.merge_changeset(changeset).await.unwrap();

        let results = store.query(&nsid, RecordFilter::new()).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "peer-only-id");
    }

    #[tokio::test]
    async fn export_returns_records_after_watermark() {
        let store = store_with_notes_table().await;
        let nsid = notes_nsid();

        store.insert(&nsid, json!({ "title": "A" })).await.unwrap();
        store.insert(&nsid, json!({ "title": "B" })).await.unwrap();

        let all = store.export_changeset(0).await.unwrap();
        assert_eq!(all.len(), 2);

        // Nothing newer than far future.
        let none = store.export_changeset(i64::MAX).await.unwrap();
        assert!(none.is_empty());
    }

    #[tokio::test]
    async fn export_includes_tombstones() {
        let store = store_with_notes_table().await;
        let nsid = notes_nsid();

        let id = store
            .insert(&nsid, json!({ "title": "To delete" }))
            .await
            .unwrap();
        store.delete(&nsid, &id).await.unwrap();

        let cs = store.export_changeset(0).await.unwrap();
        let row = cs.iter().find(|r| r.id == id).unwrap();
        assert!(
            row.deleted_at.is_some(),
            "tombstoned row must appear in changeset with deleted_at set"
        );
    }

    // ── migrate_table (M17a) ───────────────────────────────────────────────

    fn notes_v1() -> SchemaDefinition {
        use kotton_schemas::field::{FieldType, SchemaField};
        SchemaDefinition::new(
            Nsid::new("sh.kotton.notes").unwrap(),
            1,
            vec![
                SchemaField::required("title", FieldType::String),
                SchemaField::required("body", FieldType::String),
            ],
        )
    }

    #[tokio::test]
    async fn migrate_additive_nullable_field_ok() {
        use kotton_schemas::field::{FieldType, SchemaField};
        let store = notes_store();
        let v1 = notes_v1();
        let v2 = SchemaDefinition::new(
            Nsid::new("sh.kotton.notes").unwrap(),
            2,
            vec![
                SchemaField::required("title", FieldType::String),
                SchemaField::required("body", FieldType::String),
                SchemaField::nullable("pinned_at", FieldType::Datetime), // new, nullable
            ],
        );
        store.migrate_table(&v1, &v2).await.unwrap();
    }

    #[tokio::test]
    async fn migrate_additive_field_with_default_ok() {
        use kotton_schemas::field::{FieldType, SchemaField};
        let store = notes_store();
        let v1 = notes_v1();
        let v2 = SchemaDefinition::new(
            Nsid::new("sh.kotton.notes").unwrap(),
            2,
            vec![
                SchemaField::required("title", FieldType::String),
                SchemaField::required("body", FieldType::String),
                SchemaField::with_default("archived", FieldType::Bool, serde_json::json!(false)),
            ],
        );
        store.migrate_table(&v1, &v2).await.unwrap();
    }

    #[tokio::test]
    async fn migrate_destructive_removal_rejected() {
        use crate::record_store::MigrationError;
        use kotton_schemas::field::{FieldType, SchemaField};
        let store = notes_store();
        let v1 = notes_v1();
        // v2 removes the `body` field — destructive.
        let v2 = SchemaDefinition::new(
            Nsid::new("sh.kotton.notes").unwrap(),
            2,
            vec![SchemaField::required("title", FieldType::String)],
        );
        let err = store.migrate_table(&v1, &v2).await.unwrap_err();
        assert!(
            matches!(err, MigrationError::Destructive { .. }),
            "expected Destructive, got: {err}"
        );
    }

    #[tokio::test]
    async fn migrate_downgrade_rejected() {
        use crate::record_store::MigrationError;
        use kotton_schemas::field::{FieldType, SchemaField};
        let store = notes_store();
        let v2 = SchemaDefinition::new(
            Nsid::new("sh.kotton.notes").unwrap(),
            2,
            vec![SchemaField::required("title", FieldType::String)],
        );
        let v1 = notes_v1(); // version 1 < version 2
                             // Attempting to "migrate" from v2 → v1 is a downgrade.
        let err = store.migrate_table(&v2, &v1).await.unwrap_err();
        assert!(
            matches!(err, MigrationError::Downgrade { .. }),
            "expected Downgrade, got: {err}"
        );
    }

    #[tokio::test]
    async fn migrate_non_additive_required_field_rejected() {
        use crate::record_store::MigrationError;
        use kotton_schemas::field::{FieldType, SchemaField};
        let store = notes_store();
        let v1 = notes_v1();
        // v2 adds a required field with no default — existing records can't
        // satisfy the constraint.
        let v2 = SchemaDefinition::new(
            Nsid::new("sh.kotton.notes").unwrap(),
            2,
            vec![
                SchemaField::required("title", FieldType::String),
                SchemaField::required("body", FieldType::String),
                SchemaField::required("author", FieldType::String), // required, no default
            ],
        );
        let err = store.migrate_table(&v1, &v2).await.unwrap_err();
        assert!(
            matches!(err, MigrationError::NonAdditive { .. }),
            "expected NonAdditive, got: {err}"
        );
    }

    // ── roots (RFC-0071 R17) ───────────────────────────────────────────────

    const FAMILY: &str = "5f1a0c2e9b7d4a3c8e6f1b2d3c4a5e6f";
    const ATTIC: &str = "0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d";

    fn titles(records: &[Record]) -> Vec<String> {
        let mut t: Vec<String> = records
            .iter()
            .map(|r| r.body["title"].as_str().unwrap_or_default().to_owned())
            .collect();
        t.sort();
        t
    }

    /// **The migration is a marker, not a copy** — the way `data/` became
    /// Personal's tree. A `records.db` written before records had a root is
    /// opened, and its table gains the column in place; the row already there
    /// is unmarked, which is Personal, and reads back through the default read
    /// exactly as it did before. Nothing was rewritten to make that true.
    #[tokio::test]
    async fn a_table_written_before_roots_is_adopted_in_place_and_every_row_is_personal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("records.db");
        {
            // The DDL as it stood before the column: no `root`.
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE sh_kotton_notes (
                    id TEXT NOT NULL, schema_nsid TEXT NOT NULL, body TEXT NOT NULL,
                    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                    updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                    deleted_at INTEGER
                ) STRICT;
                CREATE UNIQUE INDEX idx_sh_kotton_notes_id ON sh_kotton_notes (id);
                INSERT INTO sh_kotton_notes (id, schema_nsid, body)
                  VALUES ('old', 'sh.kotton.notes', '{\"title\":\"written last year\"}');",
            )
            .unwrap();
        }

        let store = SqliteRecordStore::open(&path, None).unwrap();
        let cols = columns_of(&store.conn.lock().unwrap(), "sh_kotton_notes").unwrap();
        assert!(cols.iter().any(|c| c == "root"), "the table was not adopted: {cols:?}");

        let read = store.query(&notes_nsid(), RecordFilter::new()).await.unwrap();
        assert_eq!(titles(&read), vec!["written last year"]);
        assert_eq!(read[0].root, None, "an adopted row is Personal, which is unmarked");

        // And it is Personal's only: a read of another root does not see it.
        let family = store
            .query(&notes_nsid(), RecordFilter::new().roots(RootSelection::only(FAMILY)))
            .await
            .unwrap();
        assert!(family.is_empty(), "a Personal row read back from Family: {family:?}");
    }

    /// **A record written into one root reads back from that root and no
    /// other** — the store half of the test the record asks for, with a
    /// Personal row, a Family row and an Attic row side by side in one table.
    #[tokio::test]
    async fn a_record_in_one_root_is_read_back_only_from_that_root() {
        let store = store_with_notes_table().await;
        store.insert_in(&notes_nsid(), None, json!({ "title": "dentist" })).await.unwrap();
        store
            .insert_in(&notes_nsid(), Some(FAMILY.into()), json!({ "title": "school play" }))
            .await
            .unwrap();
        store
            .insert_in(&notes_nsid(), Some(ATTIC.into()), json!({ "title": "boxes" }))
            .await
            .unwrap();

        let read = |sel: RootSelection| {
            let store = store.clone();
            async move {
                titles(&store.query(&notes_nsid(), RecordFilter::new().roots(sel)).await.unwrap())
            }
        };
        assert_eq!(read(RootSelection::personal()).await, vec!["dentist"]);
        assert_eq!(read(RootSelection::only(FAMILY)).await, vec!["school play"]);
        assert_eq!(
            read(RootSelection { personal: true, others: vec![FAMILY.into()] }).await,
            vec!["dentist", "school play"],
        );
        assert!(
            read(RootSelection { personal: false, others: vec![] }).await.is_empty(),
            "a selection naming no root matched rows"
        );
        // The default read — every caller that predates roots — is Personal's.
        assert_eq!(
            titles(&store.query(&notes_nsid(), RecordFilter::new()).await.unwrap()),
            vec!["dentist"]
        );
    }

    /// **A record does not change root by being rewritten.** An insert naming
    /// the id of a row in another root is refused rather than serviced as a
    /// replace — which would delete that row, in a root the writer may not be
    /// able to read, and recreate it in the writer's.
    #[tokio::test]
    async fn a_record_does_not_change_root_by_being_rewritten() {
        let store = store_with_notes_table().await;
        store
            .insert_in(&notes_nsid(), Some(FAMILY.into()), json!({ "id": "x", "title": "theirs" }))
            .await
            .unwrap();

        let err = store
            .insert_in(&notes_nsid(), None, json!({ "id": "x", "title": "mine now" }))
            .await
            .unwrap_err();
        assert!(matches!(err, RecordStoreError::InAnotherRoot(ref id) if id == "x"), "{err}");

        let family = store
            .query(&notes_nsid(), RecordFilter::new().roots(RootSelection::only(FAMILY)))
            .await
            .unwrap();
        assert_eq!(titles(&family), vec!["theirs"], "the refused write still moved the row");

        // Rewriting it in its own root is an ordinary update.
        store
            .insert_in(&notes_nsid(), Some(FAMILY.into()), json!({ "id": "x", "title": "edited" }))
            .await
            .unwrap();
        let family = store
            .query(&notes_nsid(), RecordFilter::new().roots(RootSelection::only(FAMILY)))
            .await
            .unwrap();
        assert_eq!(titles(&family), vec!["edited"]);
    }

    /// A delete reaches only the roots it names, and a row outside them is
    /// *not found* — the same answer as a row that does not exist.
    #[tokio::test]
    async fn a_delete_reaches_only_the_roots_it_names() {
        let store = store_with_notes_table().await;
        let id = store
            .insert_in(&notes_nsid(), Some(FAMILY.into()), json!({ "title": "school play" }))
            .await
            .unwrap();

        let err = store.delete(&notes_nsid(), &id).await.unwrap_err();
        assert!(matches!(err, RecordStoreError::RecordNotFound(_)), "{err}");
        let err = store
            .delete_in(&notes_nsid(), &id, &RootSelection::only(ATTIC))
            .await
            .unwrap_err();
        assert!(matches!(err, RecordStoreError::RecordNotFound(_)), "{err}");

        store.delete_in(&notes_nsid(), &id, &RootSelection::only(FAMILY)).await.unwrap();
        let family = store
            .query(&notes_nsid(), RecordFilter::new().roots(RootSelection::only(FAMILY)))
            .await
            .unwrap();
        assert!(family.is_empty());
    }

    /// **Records travel with their root.** A Family row exported from one
    /// store and merged into another is Family's there, not Personal's; a
    /// Personal row travels unmarked and is Personal's on arrival; and an
    /// incoming version naming a different root for an id already held is not
    /// applied, because a merge is a newer version and not a move.
    #[tokio::test]
    async fn a_record_travels_with_its_root_through_export_and_merge() {
        let here = store_with_notes_table().await;
        here.insert_in(&notes_nsid(), None, json!({ "title": "dentist" })).await.unwrap();
        here.insert_in(&notes_nsid(), Some(FAMILY.into()), json!({ "id": "sp", "title": "school play" }))
            .await
            .unwrap();
        let changeset = here.export_changeset(0).await.unwrap();
        let family_row = changeset.iter().find(|r| r.id == "sp").unwrap();
        assert_eq!(family_row.root.as_deref(), Some(FAMILY));
        let wire = serde_json::to_value(changeset.iter().find(|r| r.id != "sp").unwrap()).unwrap();
        assert!(wire.get("root").is_none(), "a Personal row was stamped on the way out: {wire}");

        let there = store_with_notes_table().await;
        there.merge_changeset(changeset.clone()).await.unwrap();
        assert_eq!(
            titles(&there.query(&notes_nsid(), RecordFilter::new()).await.unwrap()),
            vec!["dentist"]
        );
        assert_eq!(
            titles(
                &there
                    .query(&notes_nsid(), RecordFilter::new().roots(RootSelection::only(FAMILY)))
                    .await
                    .unwrap()
            ),
            vec!["school play"]
        );

        // A newer version of `sp` claiming to be Personal's is not a merge.
        let mut moved = family_row.clone();
        moved.root = None;
        moved.updated_at += 100;
        moved.body = json!({ "id": "sp", "title": "moved" });
        there.merge_changeset(vec![moved]).await.unwrap();
        assert_eq!(
            titles(
                &there
                    .query(&notes_nsid(), RecordFilter::new().roots(RootSelection::only(FAMILY)))
                    .await
                    .unwrap()
            ),
            vec!["school play"],
            "a merge moved a record between roots"
        );
    }

    // ── the filing order (TASK-a-conversation-is-ordered-by-a-clock-it-does-not-hold)

    fn filed(records: &[Record]) -> Vec<(String, i64)> {
        records
            .iter()
            .map(|r| (r.body["title"].as_str().unwrap_or_default().to_owned(), r.filed_at))
            .collect()
    }

    /// **Many records inside one millisecond still come out in the order they
    /// were filed.** This is the case the record was opened for, one level
    /// down: a clock ties inside one tick, and a conversation's two halves filed
    /// in the same tick had nothing to order them. The stamp is strictly
    /// greater than every stamp before it, so they cannot tie.
    #[tokio::test]
    async fn records_filed_inside_one_tick_are_still_strictly_ordered() {
        let store = store_with_notes_table().await;
        for i in 0..200 {
            store.insert(&notes_nsid(), json!({ "title": format!("{i:03}") })).await.unwrap();
        }
        let mut rows = filed(&store.query(&notes_nsid(), RecordFilter::new()).await.unwrap());
        rows.reverse(); // the query answers newest-first
        let titles: Vec<&str> = rows.iter().map(|(t, _)| t.as_str()).collect();
        let expected: Vec<String> = (0..200).map(|i| format!("{i:03}")).collect();
        assert_eq!(titles, expected.iter().map(String::as_str).collect::<Vec<_>>());
        for pair in rows.windows(2) {
            assert!(pair[0].1 < pair[1].1, "a stamp did not increase: {pair:?}");
        }
    }

    /// A clock stepped backwards does not send a new record back in time: the
    /// newest stamp already in the table is the floor.
    #[tokio::test]
    async fn a_clock_stepped_backwards_still_files_after_what_is_there() {
        let store = store_with_notes_table().await;
        store.insert(&notes_nsid(), json!({ "title": "first" })).await.unwrap();
        let conn = store.conn.lock().unwrap();
        let newest: i64 = conn
            .query_row("SELECT MAX(filed_at) FROM sh_kotton_notes", [], |r| r.get(0))
            .unwrap();
        assert_eq!(next_filing_stamp(&conn, "sh_kotton_notes", newest - 60_000).unwrap(), newest + 1);
        assert_eq!(next_filing_stamp(&conn, "sh_kotton_notes", newest + 5).unwrap(), newest + 5);
    }

    /// Filed once. A rewrite of the same id is the same record in the same
    /// place; moving it to the end would move a message someone already read
    /// below their mark.
    #[tokio::test]
    async fn a_rewrite_keeps_the_place_the_record_was_filed_in() {
        let store = store_with_notes_table().await;
        store.insert(&notes_nsid(), json!({ "id": "a", "title": "a" })).await.unwrap();
        store.insert(&notes_nsid(), json!({ "id": "b", "title": "b" })).await.unwrap();
        let before = filed(&store.query(&notes_nsid(), RecordFilter::new()).await.unwrap());
        store.insert(&notes_nsid(), json!({ "id": "a", "title": "a" })).await.unwrap();
        let after = filed(&store.query(&notes_nsid(), RecordFilter::new()).await.unwrap());
        let stamp = |rows: &[(String, i64)], t: &str| rows.iter().find(|(x, _)| x == t).unwrap().1;
        assert_eq!(stamp(&before, "a"), stamp(&after, "a"));
        assert!(stamp(&after, "a") < stamp(&after, "b"));
    }

    /// **The stamp travels, and a merge keeps it.** A read mark written against
    /// it on one of the person's devices must name the same place on the next,
    /// so the device that merges a row must not re-stamp it with its sync time.
    /// A row from before the stamp existed is stamped on arrival instead.
    #[tokio::test]
    async fn a_filing_stamp_travels_through_export_and_merge() {
        let here = store_with_notes_table().await;
        here.insert(&notes_nsid(), json!({ "id": "x", "title": "x" })).await.unwrap();
        let changeset = here.export_changeset(0).await.unwrap();
        let stamp = changeset[0].filed_at.expect("an exported row carries its stamp");

        let there = store_with_notes_table().await;
        // Something filed on the other device first, later on its own clock.
        there.insert(&notes_nsid(), json!({ "id": "y", "title": "y" })).await.unwrap();
        there.merge_changeset(changeset.clone()).await.unwrap();
        let rows = filed(&there.query(&notes_nsid(), RecordFilter::new()).await.unwrap());
        assert_eq!(rows.iter().find(|(t, _)| t == "x").unwrap().1, stamp, "re-stamped on merge");

        // A newer version of the row does not move it either.
        let mut newer = changeset[0].clone();
        newer.updated_at += 100;
        newer.filed_at = Some(stamp + 1_000_000);
        there.merge_changeset(vec![newer]).await.unwrap();
        let rows = filed(&there.query(&notes_nsid(), RecordFilter::new()).await.unwrap());
        assert_eq!(rows.iter().find(|(t, _)| t == "x").unwrap().1, stamp, "an update moved the stamp");

        // A row with no stamp is placed after everything this device holds.
        let mut unstamped = changeset[0].clone();
        unstamped.id = "z".into();
        unstamped.body = json!({ "id": "z", "title": "z" });
        unstamped.filed_at = None;
        there.merge_changeset(vec![unstamped]).await.unwrap();
        let rows = filed(&there.query(&notes_nsid(), RecordFilter::new()).await.unwrap());
        let newest_other = rows.iter().filter(|(t, _)| t != "z").map(|(_, f)| *f).max().unwrap();
        assert!(rows.iter().find(|(t, _)| t == "z").unwrap().1 > newest_other);
    }

    /// A table written before the stamp is adopted in place, like `root`, and a
    /// row in it reads as its `created_at` in milliseconds — the holder's clock
    /// at a coarser grain — so it sorts before anything filed since.
    #[tokio::test]
    async fn a_table_written_before_the_stamp_is_adopted_and_its_rows_read_as_created_at() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("records.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE sh_kotton_notes (
                    id TEXT NOT NULL, schema_nsid TEXT NOT NULL, body TEXT NOT NULL,
                    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                    updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                    deleted_at INTEGER,
                    root TEXT
                ) STRICT;
                CREATE UNIQUE INDEX idx_sh_kotton_notes_id ON sh_kotton_notes (id);
                INSERT INTO sh_kotton_notes (id, schema_nsid, body, created_at)
                  VALUES ('old', 'sh.kotton.notes', '{\"title\":\"old\"}', 1700000000);",
            )
            .unwrap();
        }
        let store = SqliteRecordStore::open(&path, None).unwrap();
        let cols = columns_of(&store.conn.lock().unwrap(), "sh_kotton_notes").unwrap();
        assert!(cols.iter().any(|c| c == "filed_at"), "the table was not adopted: {cols:?}");

        store.insert(&notes_nsid(), json!({ "title": "new" })).await.unwrap();
        let rows = filed(&store.query(&notes_nsid(), RecordFilter::new()).await.unwrap());
        assert_eq!(rows.iter().find(|(t, _)| t == "old").unwrap().1, 1_700_000_000_000);
        assert!(rows.iter().find(|(t, _)| t == "new").unwrap().1 > 1_700_000_000_000);
    }

    /// A table written before the revision is adopted in place on open, with
    /// foreign keys on as every open sets them: every row already there takes
    /// revision `0` and leaves on the wire with no `revision`, the bytes an
    /// earlier version logged it as, so it is not logged again; its next write
    /// is revision `1`, and a delete after that `2`.
    #[tokio::test]
    async fn a_table_written_before_the_revision_is_adopted_and_counts_on_from_zero() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("records.db");
        {
            // The DDL as it stood before the column.
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE sh_kotton_notes (
                    id TEXT NOT NULL, schema_nsid TEXT NOT NULL, body TEXT NOT NULL,
                    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                    updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                    deleted_at INTEGER,
                    root TEXT,
                    filed_at INTEGER
                ) STRICT;
                CREATE UNIQUE INDEX idx_sh_kotton_notes_id ON sh_kotton_notes (id);
                INSERT INTO sh_kotton_notes (id, schema_nsid, body, updated_at)
                  VALUES ('old', 'sh.kotton.notes', '{\"title\":\"old\"}', 1700000000);",
            )
            .unwrap();
        }
        let store = SqliteRecordStore::open(&path, None).unwrap();
        {
            let conn = store.conn.lock().unwrap();
            let fk: i64 = conn.query_row("PRAGMA foreign_keys", [], |r| r.get(0)).unwrap();
            assert_eq!(fk, 1, "the store is opened with foreign keys on");
            let cols = columns_of(&conn, "sh_kotton_notes").unwrap();
            assert!(cols.iter().any(|c| c == "revision"), "the table was not adopted: {cols:?}");
        }

        let exported = store.export_changeset(0).await.unwrap();
        assert_eq!(exported.len(), 1, "no row was lost or added");
        assert_eq!(exported[0].revision, 0);
        let wire = serde_json::to_value(&exported[0]).unwrap();
        assert!(wire.get("revision").is_none(), "an adopted row is not re-encoded: {wire}");

        store
            .insert(&notes_nsid(), json!({ "id": "old", "title": "rewritten" }))
            .await
            .unwrap();
        store.delete(&notes_nsid(), &"old".to_owned()).await.unwrap();
        let revision = |rows: &RecordChangeset| rows[0].revision;
        assert_eq!(revision(&store.export_changeset(0).await.unwrap()), 2);

        // Opening again leaves an adopted table as it is.
        drop(store);
        let again = SqliteRecordStore::open(&path, None).unwrap();
        assert_eq!(revision(&again.export_changeset(0).await.unwrap()), 2);
    }

    // ── the clock (kotton #177)

    /// **Two stores given one held clock stamp their rows alike.** Every time
    /// a store writes comes from its clock, in Rust, not from SQL's `now`: the
    /// seconds of a write and a delete are the held second, and the filing
    /// stamp is the held millisecond, on both stores.
    #[tokio::test]
    async fn two_stores_given_one_held_clock_stamp_their_rows_alike() {
        const HELD: i64 = 1_700_000_000_999;
        let clock = StoreClock::fixed(HELD);
        let mut exported = Vec::new();
        for _ in 0..2 {
            let store = notes_store().with_clock(clock.clone());
            store.create_table(&CoreSchema::Notes.definition()).await.unwrap();
            let id = store.insert(&notes_nsid(), json!({ "title": "t" })).await.unwrap();
            store.delete(&notes_nsid(), &id).await.unwrap();
            let created_at: i64 = store
                .conn
                .lock()
                .unwrap()
                .query_row("SELECT created_at FROM sh_kotton_notes", [], |r| r.get(0))
                .unwrap();
            assert_eq!(created_at, HELD / 1000);
            exported.push(store.export_changeset(0).await.unwrap().remove(0));
        }
        for row in &exported {
            assert_eq!(row.updated_at, HELD / 1000, "updated_at is not the held second");
            assert_eq!(row.deleted_at, Some(HELD / 1000), "deleted_at is not the held second");
            assert_eq!(row.filed_at, Some(HELD), "filed_at is not the held millisecond");
        }
        assert_eq!(exported[0].updated_at, exported[1].updated_at);
    }

    /// **A store opened without a clock stamps from the system clock**, and
    /// that clock advances. The write's second lies between two readings of the
    /// system clock taken around it.
    #[tokio::test]
    async fn the_default_clock_is_the_system_clock_and_advances() {
        let system = || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64
        };
        let first = StoreClock::default().millis();
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        assert!(StoreClock::default().millis() > first, "the default clock did not advance");

        let store = store_with_notes_table().await;
        let before = system();
        store.insert(&notes_nsid(), json!({ "title": "t" })).await.unwrap();
        let after = system();
        let row = store.export_changeset(0).await.unwrap().remove(0);
        assert!(
            (before / 1000..=after / 1000).contains(&row.updated_at),
            "updated_at {} is not the system clock's second ({before}..={after} ms)",
            row.updated_at
        );
        let filed = row.filed_at.unwrap();
        assert!((before..=after).contains(&filed), "filed_at {filed} is not the system clock");
    }

    /// The merge orders by `(updated_at, revision)`: in the same second a higher
    /// revision wins and a lower one does not, and a later second wins whatever
    /// its revision, so last save still wins across devices.
    #[tokio::test]
    async fn merge_orders_the_same_second_by_revision() {
        let store = store_with_notes_table().await;
        let nsid = notes_nsid();
        let row = |title: &str, updated_at: i64, revision: i64| ChangesetRow {
            id: "r".to_owned(),
            schema_nsid: "sh.kotton.notes".to_owned(),
            body: json!({ "title": title }),
            updated_at,
            revision,
            deleted_at: None,
            root: None,
            filed_at: None,
        };
        let title = |s: &SqliteRecordStore| {
            let nsid = nsid.clone();
            let s = s.clone();
            async move { s.query(&nsid, RecordFilter::new()).await.unwrap()[0].body["title"].clone() }
        };

        store.merge_changeset(vec![row("a", 100, 3)]).await.unwrap();
        store.merge_changeset(vec![row("same", 100, 3)]).await.unwrap();
        assert_eq!(title(&store).await, "a", "an equal version is not newer");
        store.merge_changeset(vec![row("lower", 100, 2)]).await.unwrap();
        assert_eq!(title(&store).await, "a");
        store.merge_changeset(vec![row("higher", 100, 4)]).await.unwrap();
        assert_eq!(title(&store).await, "higher");
        store.merge_changeset(vec![row("later", 101, 1)]).await.unwrap();
        assert_eq!(title(&store).await, "later", "a later second wins whatever its revision");

        // A write here counts on from the revision the merge kept.
        store
            .insert(&nsid, json!({ "id": "r", "title": "local" }))
            .await
            .unwrap();
        assert_eq!(store.export_changeset(0).await.unwrap()[0].revision, 2);
    }
}
