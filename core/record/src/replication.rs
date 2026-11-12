// SPDX-License-Identifier: AGPL-3.0-or-later
//! Record replication over the sealed history log (RFC-0046).
//!
//! Moved out of `05_runtime` (RFC-0060). The mount arrives as
//! `&dyn SyncableStore` — the trait lives in `core/sys`, which this crate
//! already depends on, so `record` never depends on `core/store`. The trait is
//! the seam: `store` provides the implementation, `record` names only the
//! capability, and neither crate knows the other.
//!
//! Nothing here opens a sealed object. These functions export record versions,
//! hand them to the mount as opaque payloads, and read back what the log
//! carries — which is what lets replication reach a blind node that can never
//! read a byte of it.
//!
//! **This is the one path a record takes between devices.** `kotton_sync`'s
//! engine calls [`log_records`] before a push and [`apply_record_segments`]
//! after a pull; nothing else hands one device's rows to another's
//! `merge_changeset`. There was a second path, a peer verb that carried
//! plaintext rows to a paired device for it to merge (`ApplyRecordChangeset`),
//! and it was retired (kotton #173): nothing in the tree sent it, its rows had
//! no `revision`, so a same-second delete through it lost to the write, and a
//! verb that lets a peer write into the person's records in the clear is reach
//! nobody used. Carrying `revision` on it would have extended that reach
//! rather than removed it. A new way for records to move is a change to this
//! module, sealed like the rest of the log, not a verb beside it.
//!
//! **The access log stays on the device that wrote it** (kotton #450). The protocol's *The
//! first release is a platform a stranger can use from the command line* keeps the log on the
//! device and puts it in a drive only if the person pins it there. A row of `access-log`
//! ([`kotton_common::namespace::NSID_ACCESS_LOG`]) is held here by that identity, by name, not
//! by a schema flag, which would be a new protocol shape. Two paths carry a row from this
//! device's store to the person's drive, and both hold it: [`log_records`] logs no row of it,
//! and [`snapshot_records`] puts none of this device's rows of it in the base state, carrying
//! instead, verbatim, only the rows of it the log already carries. Both do otherwise only when
//! this device's own setting pins the log to `personal` ([`AccessLogPin::Personal`]), which the
//! device keeps in its own database (`kotton_device::users::log_pin`) and the sync engine reads
//! for each pass. A row of it that arrives in a segment from another of the person's devices,
//! one that pinned its log, is merged by [`apply_record_segments`] as any row is.
//!
//! **A removal follows the record** (kotton #484). Unpinned, one thing of the log still
//! leaves: the removal of a record the drive's log already carries, which arrived from it or
//! was sent while this device pinned. Which records those are is read off the log itself, the
//! rows it carries, as the dedup reads what it has logged; nothing is remembered beside it.
//! The removal is the record's newest logged version made a tombstone, one revision on
//! ([`removal_of`]): it carries the record's id, schema, root and stamps as the drive already
//! holds them, no body, and no time the arrival did not carry, so it tells a host nothing the
//! record's arrival did not, beyond that a removal happened. Nothing else of an unpinned log
//! leaves, a removal of a record the drive never carried included.
//!
//! The log is a linked history of what the person did, which principle VII warns about, so
//! nothing here names a row of it, its id, or what it says in a process log or an error.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::RwLock;

use anyhow::{anyhow, Result};
use kotton_sys::store::{SnapshotSummary, SyncableStore};

use crate::record_store::{ChangesetRow, RecordStore as _, SyncWatermark};
use crate::provider::sqlite_record_store::SqliteRecordStore;
use crate::registry::SchemaRegistry;
use kotton_schemas::SchemaId;

/// Where this device's access log goes: the device's own setting, read for each pass
/// (module doc).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessLogPin {
    /// Kept on this device: no row of `access-log` from this device's store is logged, and a
    /// snapshot carries only the rows of it the log already carries. The default.
    #[default]
    Unpinned,
    /// Pinned to `personal`: this device's rows of `access-log` ride the record log to the
    /// person's first drive like any record. Given for that drive's mount alone.
    Personal,
}

/// Return `true` for a row of the access log, by the schema the row names: the one identity
/// replication keeps on the device that wrote it (module doc).
pub fn is_access_log(schema_nsid: &str) -> bool {
    schema_nsid == kotton_common::namespace::NSID_ACCESS_LOG
}

/// Return `true` when a committed write of a row of `schema` should wake a sync pass. Every
/// schema's should but `access-log`'s: a log record rides the next pass that runs anyway, so
/// a pinned log adds no rhythm a host can read (kotton #450). The record store asks this
/// before it signals a write (`SqliteRecordStore::with_write_signal`).
pub fn a_write_wakes_a_pass(schema: &SchemaId) -> bool {
    *schema != SchemaId::from_static(kotton_common::namespace::NSID_ACCESS_LOG)
}

/// The removal of the log record `carried`, the newest version of it the drive's log carries,
/// when `held`, this device's version of the same record, is a tombstone that version loses
/// to; else `None` (kotton #484, module doc).
///
/// The removal is `carried` made a tombstone one revision on, at the second `carried` was
/// written: `deleted_at` and `updated_at` are `carried`'s `updated_at`, and the id, schema,
/// root and filing stamp are `carried`'s. So it is strictly newer than `carried`, and taken
/// wherever `carried` is held, and it adds no field and no time the arrival did not carry.
/// Its body is empty: what the person removed is not sent again, and a device that takes the
/// removal keeps none of it. It is no newer than `held`, which beat `carried` and was written
/// at least one revision on, so this device's own tombstone stays as it is.
///
/// `None` when `carried` is a tombstone already (the removal is logged, or another device
/// removed it), when `held` is alive, or when `held` does not beat `carried`: then this
/// device's store, once it merges the log, holds `carried` again, and there is nothing it
/// removed.
fn removal_of(carried: &ChangesetRow, held: &ChangesetRow) -> Option<ChangesetRow> {
    let removed = carried.deleted_at.is_none()
        && held.deleted_at.is_some()
        && held.id == carried.id
        && held.schema_nsid == carried.schema_nsid
        && held.root == carried.root
        && (held.updated_at, held.revision) > (carried.updated_at, carried.revision);
    removed.then(|| ChangesetRow {
        id: carried.id.clone(),
        schema_nsid: carried.schema_nsid.clone(),
        body: serde_json::Value::Object(Default::default()),
        updated_at: carried.updated_at,
        revision: carried.revision + 1,
        deleted_at: Some(carried.updated_at),
        root: carried.root.clone(),
        filed_at: carried.filed_at,
    })
}

/// The newest version of each row of the access log the drive's log carries, by id: what the
/// drive already holds of the log, which is what a removal on an unpinned device may follow
/// (kotton #484). Ordered by `(updated_at, revision)`, as a merge orders versions.
fn carried_log_rows(logged: &[kotton_sys::store::RecordSegmentView]) -> BTreeMap<String, (ChangesetRow, &Vec<u8>)> {
    let mut newest: BTreeMap<String, (ChangesetRow, &Vec<u8>)> = BTreeMap::new();
    for seg in logged {
        for payload in &seg.rows {
            let Ok(row) = serde_json::from_slice::<ChangesetRow>(payload) else {
                continue;
            };
            if !is_access_log(&row.schema_nsid) {
                continue;
            }
            let at = (row.updated_at, row.revision);
            let is_newest = newest
                .get(&row.id)
                .is_none_or(|(held, _)| at > (held.updated_at, held.revision));
            if is_newest {
                newest.insert(row.id.clone(), (row, payload));
            }
        }
    }
    newest
}

/// The identity of one version of one row, as the log's dedup compares it: the schema
/// that holds the row, its id within that schema, and its version, `(updated_at,
/// revision)`.
///
/// The schema is part of it because the store holds a row by `(schema, id)` (kotton #467):
/// without it, two schemas' rows under one id at one version are one key, and the second is
/// never logged. It is read off the field every logged row has always carried,
/// `schema_nsid`, as the row spells it, so nothing stored or sent changes shape, and a row
/// the log carries under the spelling the store exports is not logged again.
///
/// A row an earlier log carries under a core schema's old name (`sh.kotton.notes`, written
/// before a schema was named by the key that publishes it) is logged once more: the store
/// holds it under the identity that name became, so its key is not the logged one. It is
/// logged once, since the next pass finds it under its identity, and that is right twice
/// over. It cannot set a peer back, being the same `(updated_at, revision)` a merge takes
/// only when strictly newer; and the applier skips a segment in the old spelling, so this
/// copy is what carries the row to a device that joins after the rename.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct VersionKey {
    schema: String,
    id: String,
    updated_at: SyncWatermark,
    revision: i64,
}

impl VersionKey {
    fn of(row: &ChangesetRow) -> Self {
        Self {
            schema: row.schema_nsid.clone(),
            id: row.id.clone(),
            updated_at: row.updated_at,
            revision: row.revision,
        }
    }
}

/// Append the user's record changes to the sealed history log on `mount`.
///
/// The producer half of record sync on the log (RFC-0046). Records live in a
/// SQLite store and the log lives in the packed object mount; `DeviceRuntime`
/// owns both, so it is the coordinator. This exports the record store's current
/// state, drops every version the log already carries, and seals what remains as
/// one `Entry::Record` segment — which replication then moves like any other
/// pack, reaching even a blind node that can never read it.
///
/// **What has already been logged is derived from the log itself**, as a set of
/// [`VersionKey`] identities, `(schema, id, updated_at, revision)`, rather than from a
/// persisted high-water mark. The log is the source of truth for what it carries, so a
/// derived view cannot drift out of step with it the way a remembered watermark
/// can — the failure mode this project keeps rediscovering. That one dedup also
/// does double duty: it is why a row written in the same wall-clock second as
/// the last is not missed (version identity, not a `> timestamp` cursor), and why
/// a row this device merged *in* from a peer is not re-logged (the peer's segment
/// already carries that exact version).
///
/// **Same-second writes of one row are distinct versions too.** The seconds
/// alone could not tell a record's write from its delete in the same second, so
/// that delete was taken as already logged and never left the device (kotton
/// #158). Every write raises the row's [`ChangesetRow::revision`], so a write
/// never has the identity of the version it replaces, whatever the clock read.
///
/// **A version is named by its schema too** (kotton #467). The store holds a row by
/// `(schema, id)`, so two schemas may each hold a row under one caller-chosen id, and two
/// such first writes in one second carry the same `updated_at` and revision `1`. Keyed by
/// id alone, the second was read as the first, already logged, and never left the device.
///
/// Exporting the full state each pass is O(store); the dedup keeps the *log*
/// bounded regardless, since only unlogged versions are appended. A watermark
/// floor to bound the export read too is a later, measured optimization.
///
/// **No row of `access-log` is logged unless `pin` is [`AccessLogPin::Personal`]** (module
/// doc): unpinned, this device's rows of it, its own and any it merged in, stay in its store.
/// A row merged in from a device that pinned its log is already logged at that version, so it
/// is not logged again either way. **But a removal follows the record** (kotton #484):
/// unpinned, a record of it the log carries and this device has removed is logged once as its
/// removal ([`removal_of`]), and nothing more of it; a removal of a record the log never
/// carried stays here with the rest.
///
/// Returns the seq the segment committed at, `None` if nothing was unlogged (or
/// the mount has no history log — a blind storage node).
pub async fn log_records(
    store: &SqliteRecordStore,
    mount: &dyn SyncableStore,
    pin: AccessLogPin,
) -> Result<Option<u64>> {

    // The version identities the log already carries — this device's own and any
    // a peer's replication delivered.
    let logged = mount.scan_record_segments().await?;
    let mut logged_versions: HashSet<VersionKey> = HashSet::new();
    for seg in &logged {
        for payload in &seg.rows {
            if let Ok(row) = serde_json::from_slice::<ChangesetRow>(payload) {
                logged_versions.insert(VersionKey::of(&row));
            }
        }
    }

    // Everything currently in the store, minus what is already logged at that
    // exact version. Unpinned, a row of the access log is not among it, and only its
    // removal of a record the log carries is logged, in the removal's own form.
    let pinned = pin == AccessLogPin::Personal;
    let carried = if pinned { BTreeMap::new() } else { carried_log_rows(&logged) };
    let mut fresh: Vec<ChangesetRow> = Vec::new();
    for row in store.export_changeset(0).await? {
        if !pinned && is_access_log(&row.schema_nsid) {
            if let Some(removal) = carried.get(&row.id).and_then(|(c, _)| removal_of(c, &row)) {
                fresh.push(removal);
            }
            continue;
        }
        if !logged_versions.contains(&VersionKey::of(&row)) {
            fresh.push(row);
        }
    }
    if fresh.is_empty() {
        return Ok(None);
    }

    let payloads: Vec<Vec<u8>> = fresh
        .iter()
        .map(|row| serde_json::to_vec(row).map_err(|e| anyhow!("serialize changeset row: {e}")))
        .collect::<Result<_>>()?;

    Ok(mount.append_record_segment(&payloads).await?)
}

/// Merge the record changes the history log carries into the user's store.
///
/// The consumer half of record sync on the log (RFC-0046), the mirror of
/// [`log_records`]: take the rows [`scan_record_segments`] surfaces — this
/// device's own and any a peer's replication delivered — and feed them to
/// `merge_changeset`. No high-water state is needed on this side either:
/// `merge_changeset` is idempotent last-write-wins, so re-applying a segment is
/// a harmless no-op, and the producer's version dedup already stops a merged row
/// from being re-logged. A blind storage node (no `K_log`) surfaces nothing and
/// applies nothing.
///
/// `merge_changeset` requires the table to exist, so each schema present is
/// created from the registry first (idempotent). A row whose schema this device
/// does not know is skipped with a warning rather than failing the pass —
/// interpreting it would need a schema this device has never seen, which is a
/// separate concern (RFC-0046 §schema evolution) and must not block the schemas
/// it does know.
///
/// Returns the number of rows fed to `merge_changeset` (last-write-wins may
/// no-op some of them).
///
/// [`log_records`]: log_records
/// [`scan_record_segments`]: kotton_sys::store::ObjectStorage::scan_record_segments
pub async fn apply_record_segments(
    registry: &RwLock<SchemaRegistry>,
    store: &SqliteRecordStore,
    mount: &dyn SyncableStore,
) -> Result<usize> {

    let mut by_nsid: HashMap<String, Vec<ChangesetRow>> = HashMap::new();
    for seg in mount.scan_record_segments().await? {
        for payload in &seg.rows {
            if let Ok(row) = serde_json::from_slice::<ChangesetRow>(payload) {
                by_nsid.entry(row.schema_nsid.clone()).or_default().push(row);
            }
        }
    }
    if by_nsid.is_empty() {
        return Ok(0);
    }

    let mut applied = 0usize;
    for (nsid_str, rows) in by_nsid {
        let Ok(nsid) = SchemaId::parse(&nsid_str) else {
            tracing::warn!(schema = %nsid_str, "apply_record_segments: a segment names a schema by no identity, skipping");
            continue;
        };
        let schema = {
            let reg = registry.read().unwrap();
            reg.get(&nsid).cloned()
        };
        let Some(schema) = schema else {
            tracing::warn!(
                nsid = %nsid_str,
                "apply_record_segments: schema not registered on this device, skipping its records"
            );
            continue;
        };
        store.create_table(&schema).await?;
        let n = rows.len();
        store.merge_changeset(rows).await?;
        applied += n;
    }
    Ok(applied)
}

/// Snapshot the mount's history log, bounding the **record** log alongside the
/// objects (RFC-0046 L4 / RFC-0047 snapshot).
///
/// The record half of the snapshot pass, and the coordinator that keeps the
/// object layer schema-ignorant. The object snapshot subsumes every segment
/// older than `keep_full_secs` and re-expresses live objects as a fresh base
/// state; on its own it would drop the `Entry::Record` payloads riding in those
/// subsumed segments, so record history would silently shrink to whatever landed
/// inside the window. This supplies the record base state — this device's current
/// merged records — so the subsumed record versions are replaced by their current
/// value rather than lost, which is exactly what bounds an append-only log a blind
/// node cannot prune.
///
/// The base is `export_changeset(0)` (every schema this device knows) **plus, held
/// verbatim, any logged row whose schema this device does not know**: the applier
/// skipped those, so they are absent from the export, and a snapshot that dropped
/// them would discard another writer's records this device merely cannot interpret
/// (RFC-0046 §schema evolution). Applying every known segment first ensures a
/// segment that has arrived but not yet been merged is captured before it can be
/// subsumed.
///
/// **The access log, unpinned, adds nothing to the base** (module doc): with `pin`
/// [`AccessLogPin::Unpinned`] the export's rows of `access-log` are left out, and the rows of
/// it the log already carries, another device's pinned log's or this device's own from before
/// it was unpinned, are carried verbatim, the newest logged version of each. So a snapshot
/// neither sends this device's log to the drive nor drops what another device sent there. A
/// carried row this device has removed is carried as its removal instead (kotton #484), the
/// one row of it [`log_records`] would log unpinned. Pinned, the export's rows of it are the
/// base as any schema's are.
///
/// Returns the snapshot summary, or `None` for a mount with no history log —
/// a blind storage node cannot snapshot, because snapshotting is merging and merging
/// is reading.
pub async fn snapshot_records(
    registry: &RwLock<SchemaRegistry>,
    store: &SqliteRecordStore,
    mount: &dyn SyncableStore,
    keep_full_secs: u64,
    pin: AccessLogPin,
) -> Result<Option<SnapshotSummary>> {
    // Merge everything the log carries into the store first, so a logged-but-
    // unapplied segment is reflected in the export below before it can be
    // subsumed. Idempotent LWW, so this is safe to run every pass.
    apply_record_segments(registry, store, mount).await?;


    // Current merged state of every schema this device knows — the same opaque
    // encoding `log_records` seals, so scan/apply round-trip it unchanged.
    let pinned = pin == AccessLogPin::Personal;
    let exported = store.export_changeset(0).await?;
    let mut rows: Vec<Vec<u8>> = exported
        .iter()
        .filter(|row| pinned || !is_access_log(&row.schema_nsid))
        .map(|row| serde_json::to_vec(row).map_err(|e| anyhow!("serialize changeset row: {e}")))
        .collect::<Result<_>>()?;

    // Carry verbatim any logged row this device cannot merge, and, unpinned, every logged
    // row of the access log. `scan` is awaited first so the registry lock is held only over
    // in-memory work, never across an await.
    let logged = mount.scan_record_segments().await?;
    {
        let reg = registry.read().unwrap();
        for seg in &logged {
            for payload in &seg.rows {
                let Ok(row) = serde_json::from_slice::<ChangesetRow>(payload) else {
                    continue;
                };
                if !pinned && is_access_log(&row.schema_nsid) {
                    continue;
                }
                let unknown = SchemaId::parse(&row.schema_nsid)
                    .ok()
                    .map(|nsid| reg.get(&nsid).is_none())
                    .unwrap_or(true);
                if unknown {
                    rows.push(payload.clone());
                }
            }
        }
    }
    // Unpinned, the newest logged version of each access-log row, by `(updated_at,
    // revision)`: the base replaces a row's history with its current value, as the export
    // does for the rest. A record of it this device has removed and the log does not yet
    // carry removed is carried as its removal (kotton #484), as the next `log_records` would
    // log it, so the base keeps nothing of what the person removed.
    if !pinned {
        let held: HashMap<&str, &ChangesetRow> = exported
            .iter()
            .filter(|row| is_access_log(&row.schema_nsid))
            .map(|row| (row.id.as_str(), row))
            .collect();
        for (id, (carried, payload)) in carried_log_rows(&logged) {
            match held.get(id.as_str()).and_then(|h| removal_of(&carried, h)) {
                Some(removal) => rows.push(
                    serde_json::to_vec(&removal).map_err(|e| anyhow!("serialize changeset row: {e}"))?,
                ),
                None => rows.push(payload.clone()),
            }
        }
    }

    Ok(mount.snapshot(keep_full_secs, &rows).await?)
}

#[cfg(test)]
mod tests {
    //! The producer's dedup, against a mount that keeps its record log in
    //! memory: the record crate cannot reach `kotton-store`'s mounts, and the
    //! dedup is the record crate's own.

    use super::*;
    use bytes::Bytes;
    use kotton_schemas::core::CoreSchema;
    use kotton_sys::store::{
        ObjectMetadata, ObjectStorage, ObjectStorageError, ObjectStorageResult,
        RecordSegmentView, SealedObjectAccess,
    };
    use crate::provider::sqlite_record_store::StoreClock;
    use serde_json::json;
    use std::path::Path;
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::sync::{Arc, Mutex};

    /// A mount that carries a record log and nothing else.
    #[derive(Default)]
    struct LogOnly {
        segments: Mutex<Vec<Vec<Vec<u8>>>>,
    }

    fn none<T>(key: &Path) -> ObjectStorageResult<T> {
        Err(ObjectStorageError::NotFound(key.display().to_string()))
    }

    #[async_trait::async_trait]
    impl ObjectStorage for LogOnly {
        async fn get(&self, key: &Path) -> ObjectStorageResult<Bytes> {
            none(key)
        }
        async fn put(&self, key: &Path, _data: &[u8]) -> ObjectStorageResult<()> {
            none(key)
        }
        async fn delete(&self, key: &Path) -> ObjectStorageResult<()> {
            none(key)
        }
        async fn list(&self, _prefix: &Path) -> ObjectStorageResult<Vec<ObjectMetadata>> {
            Ok(Vec::new())
        }
        async fn metadata(&self, key: &Path) -> ObjectStorageResult<ObjectMetadata> {
            none(key)
        }
        fn backend_name(&self) -> &str {
            "log-only"
        }
    }

    #[async_trait::async_trait]
    impl SealedObjectAccess for LogOnly {
        async fn get_sealed(&self, key: &Path) -> ObjectStorageResult<Bytes> {
            none(key)
        }
        async fn put_sealed(&self, key: &Path, _blob: &[u8]) -> ObjectStorageResult<()> {
            none(key)
        }
        async fn append_record_segment(&self, rows: &[Vec<u8>]) -> ObjectStorageResult<Option<u64>> {
            if rows.is_empty() {
                return Ok(None);
            }
            let mut segments = self.segments.lock().unwrap();
            segments.push(rows.to_vec());
            Ok(Some(segments.len() as u64))
        }
        /// A snapshot that subsumes every segment: the log becomes the one base segment.
        async fn snapshot(
            &self,
            _keep_full_secs: u64,
            record_rows: &[Vec<u8>],
        ) -> ObjectStorageResult<Option<SnapshotSummary>> {
            let mut segments = self.segments.lock().unwrap();
            let subsumed = segments.len();
            *segments = vec![record_rows.to_vec()];
            Ok(Some(SnapshotSummary {
                segments_subsumed: subsumed,
                records_captured: record_rows.len(),
                ..Default::default()
            }))
        }
        async fn scan_record_segments(&self) -> ObjectStorageResult<Vec<RecordSegmentView>> {
            let segments = self.segments.lock().unwrap();
            Ok(segments
                .iter()
                .enumerate()
                .map(|(i, rows)| RecordSegmentView {
                    writer: "did:key:test".to_owned(),
                    seq: i as u64 + 1,
                    rows: rows.clone(),
                })
                .collect())
        }
    }

    impl LogOnly {
        /// Every row the log carries, in the order it was logged.
        fn rows(&self) -> Vec<ChangesetRow> {
            self.segments
                .lock()
                .unwrap()
                .iter()
                .flatten()
                .map(|p| serde_json::from_slice(p).unwrap())
                .collect()
        }
    }

    fn notes() -> SchemaId {
        SchemaId::from_static(kotton_common::namespace::NSID_NOTES)
    }

    async fn store() -> SqliteRecordStore {
        let store = SqliteRecordStore::in_memory().unwrap();
        store.create_table(&CoreSchema::Notes.definition()).await.unwrap();
        store
    }

    /// A store whose clock is held on one second, so every write it makes lands
    /// in that second however the scheduler runs the steps (kotton #177).
    async fn store_in_one_second() -> SqliteRecordStore {
        let store = SqliteRecordStore::in_memory()
            .unwrap()
            .with_clock(StoreClock::fixed(1_700_000_000_500));
        store.create_table(&CoreSchema::Notes.definition()).await.unwrap();
        store
    }

    /// **A record written, logged and deleted inside one second has its delete
    /// logged** (kotton #158), and a second store that merges the log holds it
    /// deleted. The store's clock is held on one second, and the seconds are
    /// asserted equal, so this holds the case and cannot pass by straddling a
    /// second.
    #[tokio::test]
    async fn a_delete_in_the_second_its_record_was_written_is_logged() {
        let store = store_in_one_second().await;
        let mount = LogOnly::default();

        let id = store.insert(&notes(), json!({ "title": "brief" })).await.unwrap();
        assert!(log_records(&store, &mount, AccessLogPin::Unpinned).await.unwrap().is_some());
        store.delete(&notes(), &id).await.unwrap();
        assert!(
            log_records(&store, &mount, AccessLogPin::Unpinned).await.unwrap().is_some(),
            "the delete was taken as already logged"
        );

        let logged = mount.rows();
        assert_eq!(logged.len(), 2, "the write and its delete: {logged:?}");
        let (write, delete) = (&logged[0], &logged[1]);
        assert_eq!(write.updated_at, delete.updated_at, "the held clock was not used");
        assert_eq!((write.deleted_at, delete.deleted_at.is_some()), (None, true));
        assert!(delete.revision > write.revision);

        // Nothing is left unlogged, so the next pass appends nothing.
        assert_eq!(log_records(&store, &mount, AccessLogPin::Unpinned).await.unwrap(), None);

        // A store that took the write and then merges the delete holds it
        // deleted, so the delete reaches the person's other devices.
        let peer = store_with(std::slice::from_ref(write)).await;
        assert_eq!(peer.query(&notes(), Default::default()).await.unwrap().len(), 1);
        peer.merge_changeset(vec![delete.clone()]).await.unwrap();
        assert!(peer.query(&notes(), Default::default()).await.unwrap().is_empty());
    }

    /// A rewrite in the second the record was written is a new version too, so
    /// it is logged and a peer holding the first version takes it.
    #[tokio::test]
    async fn a_rewrite_in_the_second_its_record_was_written_is_logged() {
        let store = store_in_one_second().await;
        let mount = LogOnly::default();

        let id = store.insert(&notes(), json!({ "title": "first" })).await.unwrap();
        assert!(log_records(&store, &mount, AccessLogPin::Unpinned).await.unwrap().is_some());
        store
            .insert(&notes(), json!({ "id": id, "title": "second" }))
            .await
            .unwrap();
        assert!(log_records(&store, &mount, AccessLogPin::Unpinned).await.unwrap().is_some());

        let logged = mount.rows();
        assert_eq!(logged.len(), 2);
        assert_eq!(logged[0].updated_at, logged[1].updated_at, "the held clock was not used");

        let peer = store_with(&logged[..1]).await;
        peer.merge_changeset(logged[1..].to_vec()).await.unwrap();
        let held = peer.query(&notes(), Default::default()).await.unwrap();
        assert_eq!(held[0].body["title"], "second");
    }

    fn tasks() -> SchemaId {
        SchemaId::from_static(kotton_common::namespace::NSID_TASKS)
    }

    /// **Two schemas' first writes of one id in one second are two versions** (kotton
    /// #467). The store holds a row by `(schema, id)`, so `notes` and `tasks` may each hold
    /// a row under one id the caller chose. The clock is held on one second and both rows
    /// are asserted to carry the same `(updated_at, revision)`, so the only thing telling
    /// them apart is the schema: the case a dedup by id alone took as already logged.
    #[tokio::test]
    async fn two_schemas_first_writes_of_one_id_in_one_second_are_both_logged() {
        let store = store_in_one_second().await;
        store.create_table(&CoreSchema::Tasks.definition()).await.unwrap();
        let mount = LogOnly::default();

        let id = store.insert(&notes(), json!({ "id": "shared", "title": "a note" })).await.unwrap();
        assert_eq!(id, "shared");
        assert!(log_records(&store, &mount, AccessLogPin::Unpinned).await.unwrap().is_some());
        store.insert(&tasks(), json!({ "id": "shared", "title": "a task" })).await.unwrap();
        assert!(
            log_records(&store, &mount, AccessLogPin::Unpinned).await.unwrap().is_some(),
            "the task was taken as the note's version, already logged"
        );

        let logged = mount.rows();
        assert_eq!(logged.len(), 2, "the note and the task: {logged:?}");
        let (note, task) = (&logged[0], &logged[1]);
        assert_eq!((note.id.as_str(), task.id.as_str()), ("shared", "shared"));
        assert_eq!(
            (note.updated_at, note.revision),
            (task.updated_at, task.revision),
            "the two rows were not at one version, so the case was not held"
        );
        assert_eq!(note.revision, 1, "each is its row's first write");
        assert_ne!(note.schema_nsid, task.schema_nsid);

        // Nothing is left unlogged, so the next pass appends nothing.
        assert_eq!(log_records(&store, &mount, AccessLogPin::Unpinned).await.unwrap(), None);
    }

    /// **A row an earlier log carries under a core schema's old name is logged once more,
    /// under its identity, and once.** A log written before a schema was named by the key that
    /// publishes it spells a notes row `sh.kotton.notes`, in the form without `revision`; the
    /// store holds that row under the identity the name became, at the same version. The
    /// exported key is not the logged one, so the row is logged again, and the next pass finds
    /// it under its identity and logs nothing.
    #[tokio::test]
    async fn a_row_logged_under_an_old_core_name_is_logged_once_under_its_identity() {
        let store = store_in_one_second().await;
        let mount = LogOnly::default();
        let earlier = json!({
            "id": "kept",
            "schema_nsid": "sh.kotton.notes",
            "body": { "title": "from before" },
            "updated_at": 1_600_000_000,
            "deleted_at": null,
        });
        mount.segments.lock().unwrap().push(vec![serde_json::to_vec(&earlier).unwrap()]);

        // The row as the store holds it once it has respelled the old name.
        let mut held = mount.rows();
        held[0].schema_nsid = kotton_common::namespace::NSID_NOTES.to_owned();
        store.merge_changeset(held).await.unwrap();
        let exported = store.export_changeset(0).await.unwrap();
        assert_eq!(exported.len(), 1);
        assert_eq!(exported[0].schema_nsid, kotton_common::namespace::NSID_NOTES);

        assert!(
            log_records(&store, &mount, AccessLogPin::Unpinned).await.unwrap().is_some(),
            "the row was taken as logged under its old name"
        );
        let segments = mount.segments.lock().unwrap().clone();
        assert_eq!(segments.len(), 2, "one segment was appended");
        assert_eq!(segments[1].len(), 1, "the one row: {:?}", mount.rows());
        let relogged: ChangesetRow = serde_json::from_slice(&segments[1][0]).unwrap();
        assert_eq!(relogged.schema_nsid, kotton_common::namespace::NSID_NOTES);
        assert_eq!(relogged.id, "kept");
        assert_eq!((relogged.updated_at, relogged.revision), (1_600_000_000, 0));

        // Once: the next pass finds the row under its identity.
        assert_eq!(log_records(&store, &mount, AccessLogPin::Unpinned).await.unwrap(), None);
    }

    /// A store whose clock a test sets, in milliseconds, between its writes.
    async fn store_on(clock: Arc<AtomicI64>) -> SqliteRecordStore {
        let store = SqliteRecordStore::in_memory()
            .unwrap()
            .with_clock(StoreClock::new(move || clock.load(Ordering::SeqCst)));
        store.create_table(&CoreSchema::Notes.definition()).await.unwrap();
        store
    }

    const T: i64 = 1_700_000_000_500;

    /// **A delete is never older than the write it replaces** (kotton #172).
    /// The clock steps back three seconds between a record's write and its
    /// delete; the delete still lands at the write's second, one revision on,
    /// so a peer that merged the write takes the delete.
    #[tokio::test]
    async fn a_delete_after_the_clock_steps_back_still_replaces_the_write() {
        let clock = Arc::new(AtomicI64::new(T));
        let store = store_on(Arc::clone(&clock)).await;
        let mount = LogOnly::default();

        let id = store.insert(&notes(), json!({ "title": "brief" })).await.unwrap();
        assert!(log_records(&store, &mount, AccessLogPin::Unpinned).await.unwrap().is_some());
        clock.store(T - 3_000, Ordering::SeqCst);
        store.delete(&notes(), &id).await.unwrap();
        assert!(log_records(&store, &mount, AccessLogPin::Unpinned).await.unwrap().is_some());

        let logged = mount.rows();
        assert_eq!(logged.len(), 2, "the write and its delete: {logged:?}");
        let (write, delete) = (&logged[0], &logged[1]);
        assert_eq!(write.updated_at, T / 1000);
        assert_eq!(delete.updated_at, write.updated_at, "the delete was stamped older");
        assert_eq!(delete.deleted_at, Some(write.updated_at));
        assert!(delete.revision > write.revision);

        let peer = store_with(std::slice::from_ref(write)).await;
        peer.merge_changeset(vec![delete.clone()]).await.unwrap();
        assert!(
            peer.query(&notes(), Default::default()).await.unwrap().is_empty(),
            "the peer kept the write"
        );
    }

    /// The same for a rewrite: written at `t`, rewritten after the clock steps
    /// back, and a peer holding the first version takes the second.
    #[tokio::test]
    async fn a_rewrite_after_the_clock_steps_back_still_replaces_the_write() {
        let clock = Arc::new(AtomicI64::new(T));
        let store = store_on(Arc::clone(&clock)).await;
        let mount = LogOnly::default();

        let id = store.insert(&notes(), json!({ "title": "first" })).await.unwrap();
        assert!(log_records(&store, &mount, AccessLogPin::Unpinned).await.unwrap().is_some());
        clock.store(T - 3_000, Ordering::SeqCst);
        store
            .insert(&notes(), json!({ "id": id, "title": "second" }))
            .await
            .unwrap();
        assert!(log_records(&store, &mount, AccessLogPin::Unpinned).await.unwrap().is_some());

        let logged = mount.rows();
        assert_eq!(logged.len(), 2);
        assert_eq!(logged[1].updated_at, logged[0].updated_at, "the rewrite was stamped older");
        assert!(logged[1].revision > logged[0].revision);

        let peer = store_with(&logged[..1]).await;
        peer.merge_changeset(logged[1..].to_vec()).await.unwrap();
        let held = peer.query(&notes(), Default::default()).await.unwrap();
        assert_eq!(held[0].body["title"], "second");
    }

    /// A row merged from a device whose clock runs ahead, then rewritten here:
    /// the rewrite lands at the merged row's future second, one revision on,
    /// and a peer that holds the future-stamped row takes it. The merge itself
    /// keeps the time the row arrived with.
    #[tokio::test]
    async fn a_rewrite_of_a_future_stamped_merged_row_lands_at_its_stamp() {
        let ahead = store_on(Arc::new(AtomicI64::new(T + 60_000))).await;
        let id = ahead.insert(&notes(), json!({ "title": "ahead" })).await.unwrap();
        let future = ahead.export_changeset(0).await.unwrap();
        assert_eq!(future[0].updated_at, T / 1000 + 60);

        let store = store_on(Arc::new(AtomicI64::new(T))).await;
        store.merge_changeset(future.clone()).await.unwrap();
        let merged = store.export_changeset(0).await.unwrap();
        assert_eq!(merged[0].updated_at, future[0].updated_at, "the merge re-stamped the row");

        store
            .insert(&notes(), json!({ "id": id, "title": "here" }))
            .await
            .unwrap();
        let rewrite = store.export_changeset(0).await.unwrap();
        assert_eq!(rewrite[0].updated_at, future[0].updated_at, "the rewrite was stamped older");
        assert_eq!(rewrite[0].revision, future[0].revision + 1);

        ahead.merge_changeset(rewrite).await.unwrap();
        let held = ahead.query(&notes(), Default::default()).await.unwrap();
        assert_eq!(held[0].body["title"], "here", "the peer kept the future-stamped row");
    }

    fn access_log() -> SchemaId {
        SchemaId::from_static(kotton_common::namespace::NSID_ACCESS_LOG)
    }

    /// A store that knows notes and the access log, and a registry that knows both.
    async fn a_device() -> (RwLock<SchemaRegistry>, SqliteRecordStore) {
        let store = store().await;
        store.create_table(&CoreSchema::AccessLog.definition()).await.unwrap();
        (RwLock::new(SchemaRegistry::new()), store)
    }

    /// One thing the daemon was asked, with `what` naming `what`.
    fn entry(what: &str) -> serde_json::Value {
        json!({ "device": "did:key:a", "at": "2026-11-10T00:00:00Z", "asker": "terminal",
                "door": "local", "act": "read", "what": what })
    }

    fn schemas_of(rows: &[ChangesetRow]) -> Vec<&str> {
        rows.iter().map(|r| r.schema_nsid.as_str()).collect()
    }

    /// **Unpinned, the log carries no row of the access log** (kotton #450): a note written
    /// beside it is logged, the log record is not, on this pass or the next, and a delete of it
    /// is not either. Pinned to `personal`, the next pass logs the record, the one written
    /// before the pin among them, and then nothing more.
    #[tokio::test]
    async fn an_access_log_row_is_logged_only_when_the_log_is_pinned() {
        let (_registry, store) = a_device().await;
        let mount = LogOnly::default();
        store.insert(&access_log(), entry("before-the-pin")).await.unwrap();
        store.insert(&notes(), json!({ "title": "a note" })).await.unwrap();

        assert!(log_records(&store, &mount, AccessLogPin::Unpinned).await.unwrap().is_some());
        assert_eq!(schemas_of(&mount.rows()), [kotton_common::namespace::NSID_NOTES], "the log record left");
        assert_eq!(log_records(&store, &mount, AccessLogPin::Unpinned).await.unwrap(), None);
        let gone = store.insert(&access_log(), entry("deleted-unpinned")).await.unwrap();
        store.delete(&access_log(), &gone).await.unwrap();
        assert_eq!(log_records(&store, &mount, AccessLogPin::Unpinned).await.unwrap(), None);

        assert!(log_records(&store, &mount, AccessLogPin::Personal).await.unwrap().is_some());
        let logged = mount.rows();
        let log: Vec<&ChangesetRow> = logged.iter().filter(|r| is_access_log(&r.schema_nsid)).collect();
        assert_eq!(log.len(), 2, "both log records, the deleted one as its tombstone: {logged:?}");
        assert_eq!(log_records(&store, &mount, AccessLogPin::Personal).await.unwrap(), None);
    }

    /// **Unpinned, a snapshot puts none of this device's log in the base, and keeps what the
    /// log already carried** (kotton #450). A row of the access log another device logged,
    /// pinned, is merged here and carried into the base at its newest logged version; a row
    /// this device wrote, unpinned, is not in it; the note is. Pinned, this device's row is in
    /// the next base too.
    #[tokio::test]
    async fn an_unpinned_snapshot_carries_only_the_log_rows_already_logged() {
        let (registry, store) = a_device().await;
        let mount = LogOnly::default();

        // Another device's pinned log, written and then rewritten, in the drive's log.
        let theirs = {
            let (_r, there) = a_device().await;
            let id = there.insert(&access_log(), entry("theirs-first")).await.unwrap();
            log_records(&there, &mount, AccessLogPin::Personal).await.unwrap();
            there.insert(&access_log(), json!({ "id": id, "what": "theirs-second",
                "device": "did:key:b", "at": "2026-11-10T00:00:01Z", "asker": "terminal",
                "door": "local", "act": "read" })).await.unwrap();
            log_records(&there, &mount, AccessLogPin::Personal).await.unwrap();
            id
        };
        let mine = store.insert(&access_log(), entry("mine-unpinned")).await.unwrap();
        store.insert(&notes(), json!({ "title": "a note" })).await.unwrap();
        log_records(&store, &mount, AccessLogPin::Unpinned).await.unwrap();

        let summary = snapshot_records(&registry, &store, &mount, 0, AccessLogPin::Unpinned)
            .await
            .unwrap()
            .expect("the mount snapshots");
        assert_eq!(summary.segments_subsumed, 3);
        let base = mount.rows();
        let log: Vec<&ChangesetRow> = base.iter().filter(|r| is_access_log(&r.schema_nsid)).collect();
        assert_eq!(log.len(), 1, "one row of the log, theirs, at one version: {base:?}");
        assert_eq!((log[0].id.as_str(), log[0].body["what"].as_str()), (theirs.as_str(), Some("theirs-second")));
        assert!(!base.iter().any(|r| r.id == mine), "this device's unpinned log record is in the base");
        assert!(schemas_of(&base).contains(&kotton_common::namespace::NSID_NOTES), "the note was dropped");
        // It was merged here, as any row is.
        assert_eq!(store.query(&access_log(), Default::default()).await.unwrap().len(), 2);

        snapshot_records(&registry, &store, &mount, 0, AccessLogPin::Personal).await.unwrap();
        assert!(mount.rows().iter().any(|r| r.id == mine), "pinned, this device's log record is in the base");
    }

    /// The one row of the access log under `id` the drive's log carries the newest of.
    fn newest_logged(mount: &LogOnly, id: &str) -> ChangesetRow {
        let mut rows: Vec<ChangesetRow> =
            mount.rows().into_iter().filter(|r| is_access_log(&r.schema_nsid) && r.id == id).collect();
        rows.sort_by_key(|r| (r.updated_at, r.revision));
        rows.pop().expect("the log carries the record")
    }

    /// **A removal follows the record** (kotton #484). Device Y pins and logs R; device X,
    /// unpinned, merges R from the log and removes it. X's next pass logs one row, R's removal,
    /// and nothing else of its log; Y merges it and holds R no more. The removal carries what
    /// R's arrival carried and no more: R's id, schema, root, filing stamp and second, one
    /// revision on, with no body and no time R did not carry. Logged once.
    #[tokio::test]
    async fn an_unpinned_removal_of_a_record_the_drive_carries_is_logged() {
        let mount = LogOnly::default();
        let (_ry, y) = a_device().await;
        let r = y.insert(&access_log(), entry("pinned-on-y")).await.unwrap();
        assert!(log_records(&y, &mount, AccessLogPin::Personal).await.unwrap().is_some());
        let arrival = newest_logged(&mount, &r);

        let (rx, x) = a_device().await;
        apply_record_segments(&rx, &x, &mount).await.unwrap();
        assert_eq!(x.query(&access_log(), Default::default()).await.unwrap().len(), 1, "X did not receive R");
        let own = x.insert(&access_log(), entry("x-own-unpinned")).await.unwrap();
        x.delete(&access_log(), &r).await.unwrap();

        let before = mount.rows().len();
        assert!(log_records(&x, &mount, AccessLogPin::Unpinned).await.unwrap().is_some(), "the removal stayed on X");
        let sent: Vec<ChangesetRow> = mount.rows().split_off(before);
        assert_eq!(sent.len(), 1, "more than the removal left X: {sent:?}");
        let removal = &sent[0];
        assert!(!sent.iter().any(|row| row.id == own), "X's own log record left");
        assert_eq!(
            (&removal.id, &removal.schema_nsid, &removal.root, removal.filed_at, removal.updated_at),
            (&arrival.id, &arrival.schema_nsid, &arrival.root, arrival.filed_at, arrival.updated_at),
            "the removal is not R's"
        );
        assert_eq!((removal.revision, removal.deleted_at), (arrival.revision + 1, Some(arrival.updated_at)));
        assert_eq!(removal.body, json!({}), "the removal sent R's body again");
        let fields = |row: &ChangesetRow| -> Vec<String> {
            let serde_json::Value::Object(map) = serde_json::to_value(row).unwrap() else { unreachable!() };
            map.keys().cloned().collect()
        };
        let mut arrived = fields(&arrival);
        arrived.push("deleted_at".to_owned());
        arrived.sort();
        arrived.dedup();
        assert_eq!(fields(removal), arrived, "the removal carries a field R's arrival did not");
        assert_eq!(log_records(&x, &mount, AccessLogPin::Unpinned).await.unwrap(), None, "logged twice");

        let (ry, _) = a_device().await;
        apply_record_segments(&ry, &y, &mount).await.unwrap();
        assert!(y.query(&access_log(), Default::default()).await.unwrap().is_empty(), "Y still holds R");
        let on_y = y.export_changeset(0).await.unwrap();
        let r_on_y = on_y.iter().find(|row| row.id == r).expect("Y's tombstone of R");
        assert_eq!(r_on_y.body, json!({}), "Y keeps what the person removed");

        // X's own tombstone is newer than the removal and stays.
        apply_record_segments(&rx, &x, &mount).await.unwrap();
        assert!(x.query(&access_log(), Default::default()).await.unwrap().iter().all(|row| row.id != r));
    }

    /// **The same, on one device that pinned, logged R, then unpinned and removed it**
    /// (kotton #484): the log carries R because it was sent while pinned, so the removal is
    /// logged and the drive's newest version of R is its tombstone. A snapshot after keeps
    /// that tombstone, and none of R's body.
    #[tokio::test]
    async fn a_record_sent_while_pinned_and_removed_after_the_unpin_is_removed_from_the_drive() {
        let mount = LogOnly::default();
        let (registry, store) = a_device().await;
        let r = store.insert(&access_log(), entry("sent-while-pinned")).await.unwrap();
        assert!(log_records(&store, &mount, AccessLogPin::Personal).await.unwrap().is_some());
        store.delete(&access_log(), &r).await.unwrap();

        assert!(log_records(&store, &mount, AccessLogPin::Unpinned).await.unwrap().is_some(), "the drive keeps R");
        let newest = newest_logged(&mount, &r);
        assert!(newest.deleted_at.is_some(), "the drive's newest R is alive: {newest:?}");

        snapshot_records(&registry, &store, &mount, 0, AccessLogPin::Unpinned).await.unwrap();
        let base: Vec<ChangesetRow> = mount.rows().into_iter().filter(|row| row.id == r).collect();
        assert_eq!(base.len(), 1, "{base:?}");
        assert!(base[0].deleted_at.is_some() && base[0].body == json!({}), "the base keeps R: {base:?}");
        let (_ro, other) = a_device().await;
        apply_record_segments(&registry, &other, &mount).await.unwrap();
        assert!(other.query(&access_log(), Default::default()).await.unwrap().is_empty());
    }

    /// **A snapshot taken before the removal is logged carries the removal** (kotton #484),
    /// not the record: the base is the log's current value, and the record's current value
    /// here is removed. The next pass then logs nothing.
    #[tokio::test]
    async fn an_unpinned_snapshot_carries_a_removal_not_yet_logged() {
        let mount = LogOnly::default();
        let (_ry, y) = a_device().await;
        let r = y.insert(&access_log(), entry("removed-before-the-snapshot")).await.unwrap();
        log_records(&y, &mount, AccessLogPin::Personal).await.unwrap();

        let (rx, x) = a_device().await;
        apply_record_segments(&rx, &x, &mount).await.unwrap();
        x.delete(&access_log(), &r).await.unwrap();
        snapshot_records(&rx, &x, &mount, 0, AccessLogPin::Unpinned).await.unwrap();
        let base: Vec<ChangesetRow> = mount.rows().into_iter().filter(|row| row.id == r).collect();
        assert_eq!(base.len(), 1, "{base:?}");
        assert!(base[0].deleted_at.is_some() && base[0].body == json!({}), "the base keeps R: {base:?}");
        assert_eq!(log_records(&x, &mount, AccessLogPin::Unpinned).await.unwrap(), None);
    }

    /// **Only that leaves** (kotton #484): unpinned, a device's own log records, kept or
    /// removed, and its removals of records the drive never carried, leave nothing, by a pass
    /// or by a snapshot, though the log carries another record of the log beside them. A
    /// record carried and not removed is not sent again either.
    #[tokio::test]
    async fn an_unpinned_device_sends_nothing_of_its_own_log_and_no_removal_the_drive_never_carried() {
        let mount = LogOnly::default();
        let (_ry, y) = a_device().await;
        let carried = y.insert(&access_log(), entry("carried-and-kept")).await.unwrap();
        log_records(&y, &mount, AccessLogPin::Personal).await.unwrap();

        let (rx, x) = a_device().await;
        apply_record_segments(&rx, &x, &mount).await.unwrap();
        let kept = x.insert(&access_log(), entry("x-own-kept")).await.unwrap();
        let removed = x.insert(&access_log(), entry("x-own-removed")).await.unwrap();
        x.delete(&access_log(), &removed).await.unwrap();
        let logged = mount.rows();

        assert_eq!(log_records(&x, &mount, AccessLogPin::Unpinned).await.unwrap(), None, "something of X's log left");
        assert_eq!(mount.rows().len(), logged.len());

        snapshot_records(&rx, &x, &mount, 0, AccessLogPin::Unpinned).await.unwrap();
        let base = mount.rows();
        let log: Vec<&ChangesetRow> = base.iter().filter(|row| is_access_log(&row.schema_nsid)).collect();
        assert_eq!(log.len(), 1, "{base:?}");
        assert_eq!(log[0].id, carried);
        assert!(log[0].deleted_at.is_none());
        assert!(!base.iter().any(|row| row.id == kept || row.id == removed), "X's own log is in the base");
    }

    /// **A removal the drive's log carries already is not logged again** (kotton #484): when
    /// another device removed R first, X's own later removal of it sends nothing; and a record
    /// X removed that the log then carries newer, alive, is not removed by X.
    #[tokio::test]
    async fn a_removal_is_logged_only_over_a_live_record_it_beats() {
        let r = ChangesetRow {
            id: "r".to_owned(),
            schema_nsid: kotton_common::namespace::NSID_ACCESS_LOG.to_owned(),
            body: json!({ "what": "r" }),
            updated_at: 100,
            revision: 1,
            deleted_at: None,
            root: None,
            filed_at: Some(100_000),
        };
        let gone = ChangesetRow { updated_at: 120, revision: 2, deleted_at: Some(120), ..r.clone() };
        assert!(removal_of(&r, &gone).is_some());
        assert!(removal_of(&r, &r).is_none(), "a live record was removed");
        let removed_there = removal_of(&r, &gone).unwrap();
        assert!(removal_of(&removed_there, &gone).is_none(), "a carried removal was sent again");
        let newer_there = ChangesetRow { updated_at: 130, revision: 2, ..r.clone() };
        assert!(removal_of(&newer_there, &gone).is_none(), "a removal beaten by a newer write was sent");
        let elsewhere = ChangesetRow { root: Some("another-root".to_owned()), ..gone.clone() };
        assert!(removal_of(&r, &elsewhere).is_none(), "a removal in another root was sent");
    }

    /// **Writing a log record wakes no pass** (kotton #450): a store given a write signal
    /// calls it after an insert and a delete of a note, and never for a row of the access log.
    /// Counted, not timed: the signal is called inside the write, or not at all.
    #[tokio::test]
    async fn a_log_record_written_or_deleted_signals_no_pass() {
        let woken = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = Arc::clone(&woken);
        let store = store()
            .await
            .with_write_signal(Arc::new(move || {
                count.fetch_add(1, Ordering::SeqCst);
            }));
        store.create_table(&CoreSchema::AccessLog.definition()).await.unwrap();

        let entry_id = store.insert(&access_log(), entry("quiet")).await.unwrap();
        store.delete(&access_log(), &entry_id).await.unwrap();
        assert_eq!(woken.load(Ordering::SeqCst), 0, "a log record's write signalled a pass");

        let note = store.insert(&notes(), json!({ "title": "a note" })).await.unwrap();
        assert_eq!(woken.load(Ordering::SeqCst), 1, "a note's write signalled no pass");
        store.delete(&notes(), &note).await.unwrap();
        assert_eq!(woken.load(Ordering::SeqCst), 2);

        let merged = store.export_changeset(0).await.unwrap();
        store.merge_changeset(merged).await.unwrap();
        assert_eq!(woken.load(Ordering::SeqCst), 2, "a merge, which a pass makes, signalled one");

        // The handle a pass writes through: the same rows, and no signal.
        let pass = store.without_write_signal();
        let quiet = pass.insert(&notes(), json!({ "title": "the pass's own" })).await.unwrap();
        let seen = store.query(&notes(), Default::default()).await.unwrap();
        assert!(seen.iter().any(|r| r.id == quiet), "the pass's handle is not the same database");
        pass.delete(&notes(), &quiet).await.unwrap();
        assert_eq!(woken.load(Ordering::SeqCst), 2, "a write through the pass's handle signalled");
        store.insert(&notes(), json!({ "title": "after" })).await.unwrap();
        assert_eq!(woken.load(Ordering::SeqCst), 3, "the store lost its signal to its clone");
    }

    async fn store_with(rows: &[ChangesetRow]) -> SqliteRecordStore {
        let peer = store().await;
        peer.merge_changeset(rows.to_vec()).await.unwrap();
        peer
    }
}
