// SPDX-License-Identifier: AGPL-3.0-or-later
//! Relational database provider (SQLite)
//!
//! ## Modules
//!
//! ### Connection pool
//!
//! - [`open_sqlite`] — open/create a connection pool
//! - [`migrate`] — run an embedded `sqlx::migrate!()` migrator
//! - [`SqlitePool`] — re-exported for callers that need the pool type
//!
//! ### Schema-aware record store (M16+)
//!
//! - [`record_store`] — [`RecordStore`] trait, [`Record`], [`RecordFilter`], error types
//! - [`sqlite_record_store`] — [`SqliteRecordStore`] implementation backed by rusqlite
//!
//! ```rust,no_run
//! use kotton_record::{
//!     record_store::{RecordFilter, RecordStore},
//!     sqlite_record_store::SqliteRecordStore,
//! };
//! use kotton_schemas::{core::CoreSchema, nsid::Nsid};
//! use std::path::Path;
//!
//! # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let store = SqliteRecordStore::open(Path::new("records.db"), None)?;
//! let notes = CoreSchema::Notes.definition();
//! store.create_table(&notes).await?;
//!
//! let nsid = Nsid::new("sh.kotton.notes")?;
//! let id = store.insert(&nsid, serde_json::json!({"title": "Hello"})).await?;
//! let records = store.query(&nsid, RecordFilter::new()).await?;
//! # Ok(()) }
//! ```

pub mod record_store;
pub mod sqlite_record_store;

// Re-exports — record store
pub use record_store::{
    ChangesetRow, Record, RecordChangeset, RecordFilter, RecordId, RecordStore, RecordStoreError,
    RootSelection, SyncWatermark,
};
pub use sqlite_record_store::{SqliteRecordStore, StoreClock};

// Re-exports — connection pool
pub use sqlx::SqlitePool;

use std::path::Path;

/// Open (or create) a SQLite database at `path`.
///
/// Creates missing parent directories owner-only (`0700`), and leaves an
/// existing one as it is (`kotton_common::fs::create_dir_all_owner_only`):
/// the record store is often the first to make a node's base dir and
/// `system/`. Returns a connection pool ready
/// for queries. Callers are responsible for running migrations via
/// [`migrate`] or `sqlx::migrate!()`.
pub async fn open_sqlite(path: &Path) -> Result<SqlitePool, sqlx::Error> {
    if let Some(parent) = path.parent() {
        kotton_common::fs::create_dir_all_owner_only(parent).map_err(|e| {
            sqlx::Error::Io(std::io::Error::other(
                format!("failed to create database directory: {e}"),
            ))
        })?;
    }

    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        // A pooled writer must WAIT for the write lock, not fail fast with
        // SQLITE_BUSY ("database is locked"). SQLite permits a single writer, so
        // without a busy timeout two concurrent writes on the pool race and one
        // errors immediately under load. Ten seconds is generous; a real
        // contended write completes in milliseconds.
        .busy_timeout(std::time::Duration::from_secs(10))
        // WAL lets readers proceed alongside the single writer (throughput) and
        // matches the record store's journal mode.
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
        .foreign_keys(true);

    sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await
}

/// Run a pre-built [`sqlx::migrate::Migrator`] against `pool`.
///
/// Use this with `sqlx::migrate!("./migrations")` in the consuming crate:
/// ```ignore
/// let pool = kotton_record::open_sqlite(&path).await?;
/// kotton_record::migrate(&pool, &sqlx::migrate!("./migrations")).await?;
/// ```
pub async fn migrate(
    pool: &SqlitePool,
    migrator: &sqlx::migrate::Migrator,
) -> Result<(), sqlx::migrate::MigrateError> {
    migrator.run(pool).await
}
