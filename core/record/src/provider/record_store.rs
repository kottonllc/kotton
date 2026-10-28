// SPDX-License-Identifier: AGPL-3.0-or-later
//! `RecordStore` trait — last-write-wins record storage abstraction.
//!
//! Each record carries an `updated_at` Unix-second timestamp and a `revision`,
//! a per-row count of writes. During sync, `export_changeset` returns all rows
//! (including tombstones) modified after a given watermark; `merge_changeset`
//! applies them with LWW semantics — an incoming row is written only when its
//! version, `(updated_at, revision)` compared in that order, is strictly newer
//! than the local row's.
//!
//! **Why the revision.** `updated_at` is whole seconds, so on its own it cannot
//! tell a write from the next write of the same row in the same second: a record
//! written and deleted inside one second had one version, the delete was never
//! logged, and a peer holding the write would not have applied it (kotton #158).
//! Every write on this device raises the row's revision by one, so a write is
//! strictly newer than the version it replaces whatever the clock says, and the
//! seconds still order writes made on different devices, which is what
//! "last save wins" means to the person.
//!
//! # Future: field-level CRDTs
//! For v0.4 personal-data workloads (notes, contacts, calendar) row-level LWW
//! is correct — concurrent edits to the same record on two devices are rare
//! and "last save wins" matches user expectations.  When collaborative schemas
//! are needed (v0.6+) the `merge_changeset` / `export_changeset` surface is
//! compatible with an Automerge or similar CRDT backend; only the
//! implementation changes.

use async_trait::async_trait;
use kotton_schemas::{definition::SchemaDefinition, nsid::Nsid};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

// ── Type aliases ────────────────────────────────────────────────────────────

/// Opaque, stable identifier for a stored record (UUID v4 string).
pub type RecordId = String;

/// Unix timestamp (seconds) used as a sync watermark.
///
/// `export_changeset(since)` returns all rows with `updated_at > since`.
/// `gc_tombstones(before)` removes tombstones with `deleted_at < before`.
pub type SyncWatermark = i64;

// ── Changeset types ───────────────────────────────────────────────────────────

/// A single record snapshot contained in a sync changeset.
///
/// Transmitted by [`RecordStore::export_changeset`]; applied by
/// [`RecordStore::merge_changeset`] with last-write-wins semantics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangesetRow {
    /// Stable record identifier.
    pub id: RecordId,
    /// NSID of the schema this record belongs to.
    pub schema_nsid: String,
    /// JSON body of the record fields at the time of export.
    pub body: Value,
    /// Unix timestamp (seconds) of the last write.
    pub updated_at: SyncWatermark,
    /// How many times this row has been written, counting every device's writes
    /// that reached the writer: each write takes the revision it replaces plus
    /// one, and a merge keeps the revision the row arrived with.
    ///
    /// **With `updated_at`, it is the row's version**, and the version is what
    /// both halves of sync key on: [`RecordStore::merge_changeset`] applies a row
    /// whose `(updated_at, revision)` is strictly newer, and
    /// `replication::log_records` logs every `(id, updated_at, revision)` the log
    /// does not yet carry. A write and the delete after it in the same second
    /// are two versions, not one (kotton #158).
    ///
    /// `0` on a row written before the count existed, and skipped then, so a
    /// segment written by this version for such a row is the segment an earlier
    /// version wrote, and an earlier version's segment reads as revision `0`.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub revision: i64,
    /// Unix timestamp when the record was deleted, or `None` if alive.
    pub deleted_at: Option<SyncWatermark>,
    /// The root this record belongs to (RFC-0071 R17), or `None` for the
    /// person's *Personal* root.
    ///
    /// **`None` is Personal, and it travels as `None`.** Personal's id is minted
    /// per device on first run and stays so until the core root travels (R16), so
    /// a row stamped with this device's Personal id would name a root the
    /// person's other device does not have — and a row in a root the reader is
    /// not a member of is not readable, so the record would vanish there. An
    /// unmarked row is Personal on every device that reads it. A row in any other
    /// root carries that root's id, and merging it never lands it in Personal.
    ///
    /// Skipped when `None` so a segment written by this version and read by an
    /// earlier one is the segment that earlier version wrote.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    /// When the device that first held this record filed it — [`Record::filed_at`].
    ///
    /// **It travels, and a merge keeps it.** A position stamped again on every
    /// device that merges the row would be that device's *sync* time, and a read
    /// mark written on one device would then name a different place on the next
    /// (`DEC-0061` marks sync across a person's devices). `None` on a row filed
    /// before the stamp existed, and skipped then, so a segment written by this
    /// version for such a row is the segment an earlier version wrote.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filed_at: Option<i64>,
}

/// Whether a revision is the one a row written before the count carries.
fn is_zero(revision: &i64) -> bool {
    *revision == 0
}

/// Batch of record changes for sync; produced by
/// [`RecordStore::export_changeset`] and consumed by
/// [`RecordStore::merge_changeset`].
pub type RecordChangeset = Vec<ChangesetRow>;

// ── Supporting types ─────────────────────────────────────────────────────────

/// Which roots a read may return rows from, in the store's own terms
/// (RFC-0071 R17).
///
/// **The default is Personal and nothing else.** Every read that does not say
/// otherwise — every caller written before records had a root — sees exactly
/// what it saw before, because every row it could see was Personal's. A row in
/// any other root is reached only by a selection that names it, and the one
/// thing that builds such a selection from a request is
/// [`crate::roots::RootAccess`], which asks the person's membership first
/// (R12). So a row in a root the person is not a member of has no path to a
/// caller that does not go through that check.
///
/// `personal` stands for the rows with no root marked, which are Personal's —
/// see [`ChangesetRow::root`] for why Personal is unmarked rather than stamped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootSelection {
    /// Include Personal's rows — the ones with no root marked.
    pub personal: bool,
    /// Include the rows of these roots, by id.
    pub others: Vec<String>,
}

impl Default for RootSelection {
    fn default() -> Self {
        Self::personal()
    }
}

impl RootSelection {
    /// Personal's rows and nobody else's.
    pub fn personal() -> Self {
        Self { personal: true, others: Vec::new() }
    }

    /// One root other than Personal.
    pub fn only(root: impl Into<String>) -> Self {
        Self { personal: false, others: vec![root.into()] }
    }

    /// Whether a row stored under `root` (`None` is Personal) is in this
    /// selection.
    pub fn admits(&self, root: Option<&str>) -> bool {
        match root {
            None => self.personal,
            Some(r) => self.others.iter().any(|o| o == r),
        }
    }

    /// The SQL predicate this selection is, over a `root` column, with its
    /// bound values. A selection naming nothing matches nothing.
    pub(crate) fn predicate(&self) -> (String, Vec<String>) {
        let mut parts: Vec<String> = Vec::new();
        if self.personal {
            parts.push("root IS NULL".to_owned());
        }
        if !self.others.is_empty() {
            let marks = vec!["?"; self.others.len()].join(", ");
            parts.push(format!("root IN ({marks})"));
        }
        if parts.is_empty() {
            return ("0".to_owned(), Vec::new());
        }
        (format!("({})", parts.join(" OR ")), self.others.clone())
    }
}

/// Filter for [`RecordStore::query`].
#[derive(Debug, Default, Clone)]
pub struct RecordFilter {
    /// Exact field-equality predicates (field_name, expected_value).
    pub field_eq: Vec<(String, Value)>,
    /// Case-insensitive substring match over the full JSON body.
    pub text: Option<String>,
    /// Maximum number of results to return.
    pub limit: Option<usize>,
    /// Number of results to skip (for pagination).
    pub offset: Option<usize>,
    /// Stable pagination cursor — only records whose `rowid` is less than the
    /// row matching this record ID are returned.  Used with `ORDER BY rowid DESC`
    /// so callers can walk backwards through an ordered set page by page.
    ///
    /// Pass the `_id` field from the last record on the previous page.
    pub before_id: Option<String>,
    /// Which roots' rows to return. Personal's alone by default — see
    /// [`RootSelection`].
    pub roots: RootSelection,
}

impl RecordFilter {
    /// Create an empty filter: every live record in Personal.
    pub fn new() -> Self {
        Default::default()
    }

    /// Add an exact-equality predicate.
    pub fn eq(mut self, field: impl Into<String>, value: impl Into<Value>) -> Self {
        self.field_eq.push((field.into(), value.into()));
        self
    }

    /// Add a case-insensitive substring filter over the JSON body.
    pub fn text(mut self, s: impl Into<String>) -> Self {
        self.text = Some(s.into());
        self
    }

    /// Limit the result set.
    pub fn limit(mut self, n: usize) -> Self {
        self.limit = Some(n);
        self
    }

    /// Offset the result set.
    pub fn offset(mut self, n: usize) -> Self {
        self.offset = Some(n);
        self
    }

    /// Set the pagination cursor.  Only records inserted before the record
    /// with this ID are returned.
    pub fn before_id(mut self, id: impl Into<String>) -> Self {
        self.before_id = Some(id.into());
        self
    }

    /// Read from these roots rather than Personal's alone.
    pub fn roots(mut self, roots: RootSelection) -> Self {
        self.roots = roots;
        self
    }
}

/// A record returned from [`RecordStore::query`].
#[derive(Debug, Clone)]
pub struct Record {
    /// Stable record identifier.
    pub id: RecordId,
    /// The NSID of the schema this record belongs to.
    pub schema_nsid: String,
    /// JSON body of the record.
    pub body: Value,
    /// Unix timestamp (seconds) of the last write.
    pub updated_at: i64,
    /// The root it belongs to, `None` for Personal (RFC-0071 R17).
    pub root: Option<String>,
    /// Where this record was filed: milliseconds on the clock of the person's
    /// device that first filed it, stamped once, then. A record a device files
    /// is stamped strictly above every stamp already in that device's table, so
    /// what one device files is in the order it filed it. A record that arrives
    /// by sync from another of the person's devices keeps the stamp it was filed
    /// with there, which can sit anywhere among this device's own — so across
    /// devices this is an order by the person's own clocks, not the order this
    /// store received anything
    /// (`TASK-a-message-synced-in-below-a-read-mark-counts-as-read`).
    ///
    /// **This is the holder's fact, never a writer's claim.** A record's body may
    /// carry a time its author asserted — `sent_at` on a message is the *sending*
    /// machine's clock, in whole seconds — and two people's claims share no clock
    /// at all. The store that holds both halves of a conversation has one, so
    /// both directions are ordered by it, and nothing another person writes can
    /// move where their record falls
    /// (`TASK-a-conversation-is-ordered-by-a-clock-it-does-not-hold`).
    ///
    /// A row filed before the stamp existed reads as its `created_at` in
    /// milliseconds — the same holder's clock at a coarser grain, and earlier
    /// than anything stamped since.
    pub filed_at: i64,
}

// ── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum RecordStoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("schema not found: {0}")]
    SchemaNotFound(String),

    #[error("record not found: {0}")]
    RecordNotFound(String),

    #[error("no table for schema: {0} — call create_table first")]
    TableNotFound(String),

    #[error("task join error")]
    Join(#[from] tokio::task::JoinError),

    /// A write that would move a record from one root to another.
    ///
    /// A record belongs to exactly one root (RFC-0071 R17), and rewriting it is
    /// not how it changes root: an `INSERT OR REPLACE` naming the id of a row in
    /// another root would delete that row — possibly in a root the writer cannot
    /// read — and recreate it in the writer's. Moving a record between roots is
    /// its own act, and nothing here performs it.
    #[error("record {0} belongs to another root")]
    InAnotherRoot(String),
}

pub type Result<T> = std::result::Result<T, RecordStoreError>;

// ── Migration error ───────────────────────────────────────────────────────────

/// Error returned when a schema migration is rejected.
///
/// Additive migrations (new nullable fields, or fields with a declared default)
/// are always accepted.  Any other structural change requires a new NSID version
/// segment instead.
#[derive(Debug, Error)]
pub enum MigrationError {
    /// A field present in the old schema was removed — this would silently
    /// discard data in existing records.  Use a new NSID instead.
    #[error(
        "destructive migration: field '{field}' was removed; \
         use a new NSID version segment instead of mutating the existing schema"
    )]
    Destructive { field: String },

    /// The incoming version is lower than the currently registered version.
    #[error(
        "downgrade rejected: '{nsid}' is at version {current}, \
         proposed version {proposed} is not an upgrade"
    )]
    Downgrade {
        nsid: String,
        current: u32,
        proposed: u32,
    },

    /// A newly added field is not nullable and carries no default value.
    /// Existing records would be missing this field, violating the contract.
    #[error(
        "non-additive field '{field}': newly added required fields must be \
         nullable (`nullable = true`) or carry a default value"
    )]
    NonAdditive { field: String },
}

pub type MigrationResult = std::result::Result<(), MigrationError>;

// ── Trait ────────────────────────────────────────────────────────────────────

/// Async record storage with last-write-wins sync semantics.
///
/// Implementations open a per-user SQLite file, one table per schema NSID.
/// Tables must be created before records can be inserted or synced.
#[async_trait]
pub trait RecordStore: Send + Sync {
    /// Ensure a table exists for `schema`.
    ///
    /// Idempotent — calling this on an already-created table is a no-op.
    async fn create_table(&self, schema: &SchemaDefinition) -> Result<()>;

    /// Insert a JSON record into `schema_nsid`'s table.
    ///
    /// Returns the stable [`RecordId`] (UUID v4).  The caller may supply an
    /// `id` field in `record`; if absent one is generated.
    async fn insert(&self, schema_nsid: &Nsid, record: Value) -> Result<RecordId> {
        self.insert_in(schema_nsid, None, record).await
    }

    /// Insert a JSON record into `schema_nsid`'s table, in `root` — `None` is
    /// Personal (RFC-0071 R17).
    ///
    /// Refuses with [`RecordStoreError::InAnotherRoot`] when `record` names the
    /// id of a row already in a different root: a record does not change root by
    /// being rewritten.
    async fn insert_in(
        &self,
        schema_nsid: &Nsid,
        root: Option<String>,
        record: Value,
    ) -> Result<RecordId>;

    /// Query non-deleted records matching `filter`.
    async fn query(&self, schema_nsid: &Nsid, filter: RecordFilter) -> Result<Vec<Record>>;

    /// Soft-delete a record by writing a tombstone.
    ///
    /// The row is retained with `deleted_at` set so the tombstone can be
    /// propagated to paired devices before garbage collection.
    async fn delete(&self, schema_nsid: &Nsid, record_id: &RecordId) -> Result<()> {
        self.delete_in(schema_nsid, record_id, &RootSelection::personal()).await
    }

    /// Soft-delete a record, if it is in one of `roots`.
    ///
    /// A record outside the selection is [`RecordStoreError::RecordNotFound`],
    /// the same answer as one that does not exist: a caller that may not read a
    /// root learns nothing about what is in it by trying to delete from it.
    async fn delete_in(
        &self,
        schema_nsid: &Nsid,
        record_id: &RecordId,
        roots: &RootSelection,
    ) -> Result<()>;

    /// Remove tombstoned rows with `deleted_at < before_ts`.
    ///
    /// Safe to call periodically after tombstones have had enough time to
    /// propagate to all paired devices (e.g. 30-day window).
    async fn gc_tombstones(&self, before_ts: SyncWatermark) -> Result<u64>;

    /// Apply an incoming [`RecordChangeset`] from a peer.
    ///
    /// Each row is applied with last-write-wins semantics: the row is written
    /// only when its version is strictly newer — `incoming.updated_at >
    /// local.updated_at`, or the same second and `incoming.revision >
    /// local.revision` — or the record doesn't exist locally. Tombstones
    /// (`deleted_at` set) are applied the same way, so a delete made in the
    /// second its record was written still replaces it.
    ///
    /// The sync layer must ensure schema tables exist (via [`Self::create_table`])
    /// before calling this; rows for unknown tables return
    /// [`RecordStoreError::TableNotFound`].
    async fn merge_changeset(&self, changeset: RecordChangeset) -> Result<()>;

    /// Export a [`RecordChangeset`] containing all rows (including tombstones)
    /// with `updated_at > since`.
    ///
    /// Pass `since = 0` to export everything.  The receiver uses the highest
    /// `updated_at` in the returned set as `since` on the next call.
    async fn export_changeset(&self, since: SyncWatermark) -> Result<RecordChangeset>;

    /// Validate and apply an additive schema migration from `old` to `new`.
    ///
    /// Rules enforced:
    /// - `new.version <= old.version` → [`MigrationError::Downgrade`]
    /// - A field present in `old` but absent in `new` → [`MigrationError::Destructive`]
    /// - A field added in `new` that is not nullable and has no default →
    ///   [`MigrationError::NonAdditive`]
    ///
    /// For the JSON-body `SqliteRecordStore` this is a validation-only operation
    /// — all field values live in the `body` TEXT blob and existing rows remain
    /// valid after any additive extension.  A DDL-based backend would emit
    /// `ALTER TABLE ADD COLUMN` statements here.
    async fn migrate_table(
        &self,
        old: &SchemaDefinition,
        new: &SchemaDefinition,
    ) -> MigrationResult;
}
