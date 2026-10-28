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

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use anyhow::{anyhow, Result};
use kotton_sys::store::{SnapshotSummary, SyncableStore};

use crate::record_store::{ChangesetRow, RecordStore as _, SyncWatermark};
use crate::provider::sqlite_record_store::SqliteRecordStore;
use crate::registry::SchemaRegistry;
use kotton_schemas::nsid::Nsid;

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
/// `(id, updated_at, revision)` version identities, rather than from a persisted
/// high-water mark. The log is the source of truth for what it carries, so a
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
/// Exporting the full state each pass is O(store); the dedup keeps the *log*
/// bounded regardless, since only unlogged versions are appended. A watermark
/// floor to bound the export read too is a later, measured optimization.
///
/// Returns the seq the segment committed at, `None` if nothing was unlogged (or
/// the mount has no history log — a blind storage node).
pub async fn log_records(
    store: &SqliteRecordStore,
    mount: &dyn SyncableStore,
) -> Result<Option<u64>> {

    // The version identities the log already carries — this device's own and any
    // a peer's replication delivered.
    let logged = mount.scan_record_segments().await?;
    let mut logged_versions: HashSet<(String, SyncWatermark, i64)> = HashSet::new();
    for seg in &logged {
        for payload in &seg.rows {
            if let Ok(row) = serde_json::from_slice::<ChangesetRow>(payload) {
                logged_versions.insert((row.id, row.updated_at, row.revision));
            }
        }
    }

    // Everything currently in the store, minus what is already logged at that
    // exact version.
    let fresh: Vec<ChangesetRow> = store
        .export_changeset(0)
        .await?
        .into_iter()
        .filter(|row| !logged_versions.contains(&(row.id.clone(), row.updated_at, row.revision)))
        .collect();
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
        let Ok(nsid) = Nsid::new(&nsid_str) else {
            tracing::warn!(nsid = %nsid_str, "apply_record_segments: invalid NSID in a segment, skipping");
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
/// Returns the snapshot summary, or `None` for a mount with no history log —
/// a blind storage node cannot snapshot, because snapshotting is merging and merging
/// is reading.
pub async fn snapshot_records(
    registry: &RwLock<SchemaRegistry>,
    store: &SqliteRecordStore,
    mount: &dyn SyncableStore,
    keep_full_secs: u64,
) -> Result<Option<SnapshotSummary>> {
    // Merge everything the log carries into the store first, so a logged-but-
    // unapplied segment is reflected in the export below before it can be
    // subsumed. Idempotent LWW, so this is safe to run every pass.
    apply_record_segments(registry, store, mount).await?;


    // Current merged state of every schema this device knows — the same opaque
    // encoding `log_records` seals, so scan/apply round-trip it unchanged.
    let mut rows: Vec<Vec<u8>> = store
        .export_changeset(0)
        .await?
        .iter()
        .map(|row| serde_json::to_vec(row).map_err(|e| anyhow!("serialize changeset row: {e}")))
        .collect::<Result<_>>()?;

    // Carry verbatim any logged row this device cannot merge. `scan` is awaited
    // first so the registry lock is held only over in-memory work, never across
    // an await.
    let logged = mount.scan_record_segments().await?;
    {
        let reg = registry.read().unwrap();
        for seg in &logged {
            for payload in &seg.rows {
                let Ok(row) = serde_json::from_slice::<ChangesetRow>(payload) else {
                    continue;
                };
                let unknown = Nsid::new(&row.schema_nsid)
                    .ok()
                    .map(|nsid| reg.get(&nsid).is_none())
                    .unwrap_or(true);
                if unknown {
                    rows.push(payload.clone());
                }
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
    use serde_json::json;
    use std::path::Path;
    use std::sync::Mutex;

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

    fn notes() -> Nsid {
        Nsid::new("sh.kotton.notes").unwrap()
    }

    async fn store() -> SqliteRecordStore {
        let store = SqliteRecordStore::in_memory().unwrap();
        store.create_table(&CoreSchema::Notes.definition()).await.unwrap();
        store
    }

    /// Wait for the start of the next wall-clock second, so the few in-memory
    /// writes after it land inside one second rather than straddling two.
    async fn at_the_start_of_a_second() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        let into = now.subsec_millis() as u64;
        tokio::time::sleep(std::time::Duration::from_millis(1000 - into + 5)).await;
    }

    /// **A record written, logged and deleted inside one second has its delete
    /// logged** (kotton #158), and a second store that merges the log holds it
    /// deleted. The seconds are asserted equal, so this holds the case and does
    /// not pass by straddling a second.
    #[tokio::test]
    async fn a_delete_in_the_second_its_record_was_written_is_logged() {
        let store = store().await;
        let mount = LogOnly::default();

        at_the_start_of_a_second().await;
        let id = store.insert(&notes(), json!({ "title": "brief" })).await.unwrap();
        assert!(log_records(&store, &mount).await.unwrap().is_some());
        store.delete(&notes(), &id).await.unwrap();
        assert!(
            log_records(&store, &mount).await.unwrap().is_some(),
            "the delete was taken as already logged"
        );

        let logged = mount.rows();
        assert_eq!(logged.len(), 2, "the write and its delete: {logged:?}");
        let (write, delete) = (&logged[0], &logged[1]);
        assert_eq!(write.updated_at, delete.updated_at, "the steps straddled a second");
        assert_eq!((write.deleted_at, delete.deleted_at.is_some()), (None, true));
        assert!(delete.revision > write.revision);

        // Nothing is left unlogged, so the next pass appends nothing.
        assert_eq!(log_records(&store, &mount).await.unwrap(), None);

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
        let store = store().await;
        let mount = LogOnly::default();

        at_the_start_of_a_second().await;
        let id = store.insert(&notes(), json!({ "title": "first" })).await.unwrap();
        assert!(log_records(&store, &mount).await.unwrap().is_some());
        store
            .insert(&notes(), json!({ "id": id, "title": "second" }))
            .await
            .unwrap();
        assert!(log_records(&store, &mount).await.unwrap().is_some());

        let logged = mount.rows();
        assert_eq!(logged.len(), 2);
        assert_eq!(logged[0].updated_at, logged[1].updated_at, "the steps straddled a second");

        let peer = store_with(&logged[..1]).await;
        peer.merge_changeset(logged[1..].to_vec()).await.unwrap();
        let held = peer.query(&notes(), Default::default()).await.unwrap();
        assert_eq!(held[0].body["title"], "second");
    }

    async fn store_with(rows: &[ChangesetRow]) -> SqliteRecordStore {
        let peer = store().await;
        peer.merge_changeset(rows.to_vec()).await.unwrap();
        peer
    }
}
