// SPDX-License-Identifier: AGPL-3.0-or-later
//! Object storage abstraction
//!
//! Provides async operations for key-value object storage with:
//! - Object operations (get, put, delete)
//! - Listing and metadata queries
//! - Backend-agnostic interface
//!
//! This is the abstraction layer for blob/object storage systems like S3, Azure Blob,
//! IPFS, or local filesystem-based object storage. Unlike platform::Filesystem which
//! provides POSIX-like semantics, ObjectStorage provides simple key-value operations
//! suitable for cloud storage backends.

pub mod key;

pub use key::{NotCanonical, StorageKey};

use std::collections::BTreeMap;
use async_trait::async_trait;
use bytes::Bytes;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;

/// Errors that can occur during object storage operations
#[derive(Debug, Error)]
pub enum ObjectStorageError {
    /// Object not found
    #[error("Object not found: {0}")]
    NotFound(String),

    /// Permission denied
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Object already exists
    #[error("Already exists: {0}")]
    AlreadyExists(String),

    /// I/O operation failed
    #[error("I/O error: {0}")]
    IoError(String),

    /// Invalid object key
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// Backend-specific error
    #[error("Backend error: {0}")]
    BackendError(String),
}

/// Result type for object storage operations
pub type ObjectStorageResult<T> = Result<T, ObjectStorageError>;

/// What one packing pass did (RFC-0045).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackSummary {
    /// Loose files moved into packs this pass.
    pub files_packed: usize,
    /// Packs sealed and written this pass.
    pub packs_written: usize,
    /// Loose originals deleted after verification (P4).
    pub loose_deleted: usize,
    /// The superblock generation committed, if the pass changed anything.
    pub generation: Option<u64>,
}

/// What one compaction pass did (RFC-0045 §Compaction).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompactSummary {
    /// Packs rewritten because their live fraction fell below the threshold.
    pub packs_rewritten: usize,
    /// Fresh packs written to hold the live chunks salvaged from them.
    pub packs_written: usize,
    /// Packs deleted after the replacement was verified and committed (P4) —
    /// both the rewritten originals and any pack the current manifest does not
    /// reference at all (crash-orphaned, or wholly dead).
    pub packs_retired: usize,
    /// Live chunks carried into the fresh packs.
    pub chunks_kept: usize,
    /// Names under the pack prefix outside the reserved pack-id grammar,
    /// listed and left in place: the store never wrote them, so it neither
    /// reads nor deletes them (kotton #273). A peer's object sync can deliver
    /// one; this count is where it shows.
    pub packs_unadmitted: usize,
    /// The superblock generation committed, if the pass changed anything.
    pub generation: Option<u64>,
}

/// What one P3 scan recovery did (RFC-0045 — "the store is self-describing").
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanRecovery {
    /// Packs opened and walked.
    pub packs_scanned: usize,
    /// Manifest chunks found across them — one per pass ever committed and not
    /// yet compacted away.
    pub manifests_found: usize,
    /// Generation of the manifest adopted and committed as a fresh superblock.
    pub generation: u64,
    /// Files the adopted manifest describes.
    pub files_recovered: usize,
}

/// What one history-log snapshot pass did (RFC-0047).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SnapshotSummary {
    /// Segments subsumed by the snapshot and dropped from the live set.
    pub segments_subsumed: usize,
    /// Segments retained because they fall inside the full-detail window.
    pub segments_retained: usize,
    /// Live paths the snapshot records.
    pub files_captured: usize,
    /// Record changeset rows the snapshot carries as its base state (RFC-0046
    /// L4). Zero on an object-only store; on a store with records it is the
    /// current merged state that lets the subsumed record segments be dropped.
    pub records_captured: usize,
    /// The superblock generation committed.
    pub generation: u64,
}

/// What one log-driven reconciliation did (RFC-0047).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconcileSummary {
    /// Segments found in the pack set that the local log did not know about —
    /// what a peer's replication delivered.
    pub segments_adopted: usize,
    /// Paths whose current version changed as a result.
    pub paths_changed: usize,
    /// Paths the log says are current but whose bytes have not arrived yet.
    ///
    /// Not an error: packs replicate independently of the segments describing
    /// them, so a reconcile can legitimately run ahead of the content. The next
    /// one picks them up.
    pub paths_pending_content: usize,
    /// Paths where two writers wrote concurrently and the losing version was
    /// retained rather than overwritten.
    pub conflicts: usize,
    /// The superblock generation committed, if anything changed.
    pub generation: Option<u64>,
}

/// One record-carrying history segment, surfaced from the pack set for the
/// record layer to apply (RFC-0046).
///
/// The log carries record changeset rows as opaque `payload` bytes — this crate
/// never interprets them, which is what keeps the storage layer free of the
/// record schema. `(writer, seq)` identifies the segment so the record layer can
/// track a per-writer high-water mark and apply each segment at most once; the
/// underlying merge is idempotent regardless, so re-application is only wasteful.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordSegmentView {
    /// The DID of the writer that produced this segment.
    pub writer: String,
    /// The writer's monotonic sequence number for this segment.
    pub seq: u64,
    /// The serialized changeset rows this segment carries, in write order.
    pub rows: Vec<Vec<u8>>,
}

/// One prior version of a file that keeps its versions
/// (`TASK-a-file-keeps-its-versions-when-the-person-asks`).
///
/// **Everything a version is, and nothing a person could have named.** A
/// version is a point in the file's own history: the content it held and the
/// moment that content was written, both read off the `ObjectWrite` entry the
/// history log already holds for it. There is no label, no message and no
/// parent here — the moment a version can be named it is a commit, and the
/// store has not built a worse git.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileVersion {
    /// The content id — the handle a read or a restore addresses it by. A
    /// digest rather than an index, so it stays valid as newer writes arrive.
    pub content_id: String,
    /// True (unpadded) size of this version, in bytes.
    pub size: u64,
    /// Wall-clock seconds this content was written, as the log recorded it.
    pub at: u64,
    /// The content id of the version this one was **written from** — the
    /// version its writer had open — or `None` for a file's first write
    /// (ruled 2026-09-24). Causality, like the moment: where the bytes came
    /// from, which is what a reconcile of two versions written apart needs as
    /// their common ancestor. Never a name.
    pub written_from: Option<String>,
}

/// Metadata about a stored object
#[derive(Debug, Clone)]
pub struct ObjectMetadata {
    /// Object key/path
    pub key: String,
    /// Whether this represents a directory/prefix
    pub is_dir: bool,
    /// Size in bytes (0 for directories)
    pub size: u64,
    /// Last modified time (Unix timestamp, None if not available)
    pub modified: Option<u64>,
}

/// Abstraction for object storage operations
///
/// Implementations provide different storage backends:
/// - Local filesystem-based object storage
/// - AWS S3
/// - Azure Blob Storage
/// - IPFS
/// - In-memory storage (for testing)
///
/// All backends must be thread-safe (Send + Sync) and support async operations.
/// Keys are treated as opaque strings - backends decide how to map them to storage.
#[async_trait]
pub trait ObjectStorage: Send + Sync {
    /// Get an object by key
    ///
    /// # Arguments
    /// * `key` - Object key/path
    ///
    /// # Returns
    /// The object data as bytes
    ///
    /// # Errors
    /// - `NotFound` if object doesn't exist
    /// - `PermissionDenied` if access is denied
    /// - `IoError` for I/O failures
    async fn get(&self, key: &Path) -> ObjectStorageResult<Bytes>;

    /// Put an object
    ///
    /// # Arguments
    /// * `key` - Object key/path
    /// * `data` - Object data
    ///
    /// # Errors
    /// - `PermissionDenied` if access is denied
    /// - `IoError` for I/O failures
    async fn put(&self, key: &Path, data: &[u8]) -> ObjectStorageResult<()>;

    /// Delete an object
    ///
    /// # Arguments
    /// * `key` - Object key/path
    ///
    /// # Errors
    /// - `NotFound` if object doesn't exist
    /// - `PermissionDenied` if access is denied
    /// - `IoError` for I/O failures
    async fn delete(&self, key: &Path) -> ObjectStorageResult<()>;

    /// List objects with a given prefix
    ///
    /// # Arguments
    /// * `prefix` - Key prefix to list (can be empty for all objects)
    ///
    /// # Returns
    /// Vector of object metadata
    ///
    /// # Errors
    /// - `PermissionDenied` if access is denied
    /// - `IoError` for I/O failures
    async fn list(&self, prefix: &Path) -> ObjectStorageResult<Vec<ObjectMetadata>>;

    /// Get metadata for an object
    ///
    /// # Arguments
    /// * `key` - Object key/path
    ///
    /// # Returns
    /// Object metadata
    ///
    /// # Errors
    /// - `NotFound` if object doesn't exist
    /// - `PermissionDenied` if access is denied
    /// - `IoError` for I/O failures
    async fn metadata(&self, key: &Path) -> ObjectStorageResult<ObjectMetadata>;

    /// Check if an object exists
    ///
    /// # Arguments
    /// * `key` - Object key/path
    ///
    /// # Returns
    /// true if object exists, false otherwise
    async fn exists(&self, key: &Path) -> ObjectStorageResult<bool> {
        match self.metadata(key).await {
            Ok(_) => Ok(true),
            Err(ObjectStorageError::NotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Read `[offset, offset + length)` of an object, and the object's total
    /// size — the size so a caller fetching a large object in ranges knows when
    /// it has the whole thing without a second round trip.
    ///
    /// A short return is not an error: a range clipped by the end of the object
    /// returns what exists, and `offset` past the end returns nothing with the
    /// true total. Only the object being absent is `NotFound`.
    ///
    /// # Why a default, and what the default costs
    ///
    /// The default reads the whole object and slices it. That is **correct on
    /// every backend** and honest about what a store with no ranged path can
    /// do: an object sealed as one AEAD envelope has no readable interior
    /// before its tag is checked, so there is nothing to read a range *of*.
    ///
    /// It is also quadratic when a caller walks a large object range by range,
    /// which is why a store that keeps objects as independently-sealed pieces
    /// (the RFC-0045 pack layer) overrides it. The distinction is a property of
    /// the format, not of the backend, so it belongs on the layer that knows
    /// the format rather than in every caller.
    async fn get_range(
        &self,
        key: &Path,
        offset: u64,
        length: u64,
    ) -> ObjectStorageResult<(Bytes, u64)> {
        let whole = self.get(key).await?;
        let total = whole.len() as u64;
        let start = offset.min(total) as usize;
        let end = offset.saturating_add(length).min(total) as usize;
        Ok((whole.slice(start..end), total))
    }

    /// Begin writing an object as a **stream**, or report that this store has
    /// no streaming ingest.
    ///
    /// `Ok(None)` means "this store can only take an object whole" — an honest
    /// answer rather than a silent success, exactly as [`pack_loose`] returns
    /// `None` from a store with no pack layer. The caller then buffers, and a
    /// caller that cannot afford to buffer must refuse rather than try: an
    /// object too large to hold in memory is a clean refusal, and an
    /// out-of-memory is not.
    ///
    /// # Why this exists
    ///
    /// [`put`] takes a `&[u8]`, so the largest object this store can accept is
    /// bounded by what the writer can hold in memory at once — the ceiling that
    /// stood between a person and a model of their own
    /// (`TASK-a-model-is-larger-than-the-store-will-seal`). A sink takes the
    /// bytes as they arrive and seals them as they land, so peak memory is a
    /// function of the piece rather than of the object.
    ///
    /// [`pack_loose`]: SealedObjectAccess::pack_loose
    /// [`put`]: ObjectStorage::put
    async fn begin_stream(&self, key: &Path) -> ObjectStorageResult<Option<Box<dyn ObjectSink>>> {
        let _ = key;
        Ok(None)
    }

    /// Get backend name for debugging/logging
    fn backend_name(&self) -> &str;
}

/// One object being written as a stream — the write half of
/// [`ObjectStorage::begin_stream`].
///
/// # The visibility contract
///
/// **Nothing at the object's key changes until [`commit`] returns `Ok`.** A
/// sink that is dropped without committing leaves the key exactly as it was,
/// which is what lets a caller verify the content hash of what it fed in and
/// then decide: commit on a match, drop on a mismatch. The integrity gate
/// therefore stays with the caller that declared the hash, and no path ever
/// resolves to bytes nobody checked.
///
/// # What a dropped sink does leave behind
///
/// Sealed bytes already written to the backing store, unreferenced by anything.
/// They are not readable — no name resolves to them — and they are reclaimed by
/// the store's compaction pass like any other dead chunk. This is the real cost
/// of streaming and it is a **disk** cost, not a memory one: a stream that is
/// going to be refused is refused only after its last byte, so a caller must
/// still bound how much one unverified stream may write.
///
/// [`commit`]: ObjectSink::commit
#[async_trait]
pub trait ObjectSink: Send {
    /// Append the next bytes of the object. Calls are in order and contiguous;
    /// the sink does not reorder and does not seek.
    async fn push(&mut self, bytes: &[u8]) -> ObjectStorageResult<()>;

    /// Finish the object and make it visible at its key.
    ///
    /// After this returns `Ok`, a `get` of the key serves exactly the
    /// concatenation of every `push`. After an `Err`, the key is unchanged.
    async fn commit(&mut self) -> ObjectStorageResult<()>;
}

/// Access to objects as **sealed, self-contained blobs** — the bytes as they
/// rest in the backing store, without decryption on read or encryption on write.
///
/// For an encrypting store this is the inner ciphertext; for a store that only
/// ever holds sealed bytes (a blind storage node, a peer link) the sealed view and
/// the ordinary view are the same thing.
///
/// # Why this exists
///
/// Replication must move sealed material and never observe plaintext
/// (RFC-0041 B1/B2). Reading through [`ObjectStorage::get`] on an encrypting
/// store decrypts, so a sync pass built on it hands plaintext to the peer —
/// which is exactly the defect RFC-0041 corrects. A node whose posture withholds
/// the data keys (RFC-0036 `BlindStorage`) must receive bytes it cannot open.
///
/// # Deliberately no default implementation
///
/// A default that delegated to `get`/`put` would make every backend compile for
/// free — and would silently leak plaintext from any future encrypting wrapper
/// whose author forgot to override it. Requiring an explicit implementation
/// means a store that has not stated how it exposes sealed bytes simply cannot
/// be replicated: a compile error rather than a disclosure.
///
/// Implementors that hold plaintext at rest (an unencrypted local store, an
/// in-memory test store) implement this as the identity — correct, because their
/// objects already *are* the bytes at rest. It is the wrapper's job to decide
/// what "sealed" means for the data it protects.
#[async_trait]
pub trait SealedObjectAccess: ObjectStorage {
    /// Read the object exactly as it rests in the backing store.
    ///
    /// # Errors
    /// Same conditions as [`ObjectStorage::get`].
    async fn get_sealed(&self, key: &Path) -> ObjectStorageResult<Bytes>;

    /// Write `blob` verbatim to the backing store.
    ///
    /// `blob` is expected to be a sealed object produced by [`get_sealed`] on a
    /// store in the same key domain. No sealing is applied.
    ///
    /// [`get_sealed`]: SealedObjectAccess::get_sealed
    ///
    /// # Errors
    /// Same conditions as [`ObjectStorage::put`].
    async fn put_sealed(&self, key: &Path, blob: &[u8]) -> ObjectStorageResult<()>;

    /// Delete an object by its **storage** key — the key space `get_sealed`
    /// and `put_sealed` address.
    ///
    /// Matters exactly where `list_sealed` does: a key-blinding store maps
    /// logical keys before deleting, so removing an object the caller knows by
    /// its stored key (a retired superblock generation, a cleared tombstone
    /// set) must bypass that mapping or it silently deletes nothing. Identical
    /// to [`ObjectStorage::delete`] for every store that does not blind, which
    /// is why the default forwards.
    async fn delete_sealed(&self, key: &Path) -> ObjectStorageResult<()> {
        self.delete(key).await
    }

    /// List objects in the **storage** key space — the keys `get_sealed` and
    /// `put_sealed` address, not the caller's logical keys.
    ///
    /// The distinction matters exactly once, but load-bearingly: a store that
    /// blinds keys (RFC-0044) has [`ObjectStorage::list`] recover the caller's
    /// plaintext paths for a human, while replication must see the opaque stored
    /// keys — both so `get_sealed`/`put_sealed` address the same thing `list`
    /// reported, and so that only opaque keys ever cross the wire to a blind
    /// replica. For every store that does not blind, the two are identical, which
    /// is why the default simply forwards.
    async fn list_sealed(&self, prefix: &Path) -> ObjectStorageResult<Vec<ObjectMetadata>> {
        self.list(prefix).await
    }

    /// Rewrite any objects still stored under a pre-blinding key scheme to the
    /// current one, returning how many moved (RFC-0044).
    ///
    /// Default: nothing to migrate — a store that does not blind keys has no
    /// legacy scheme to leave behind. Only a blinding wrapper overrides this,
    /// and it is safe to call on a fully-migrated store (returns 0). The caller
    /// is responsible for not calling it on a store with no path key.
    async fn migrate_blinding(&self) -> ObjectStorageResult<usize> {
        Ok(0)
    }

    /// Run one packing pass: move loose objects into sealed fixed-size packs
    /// (RFC-0045), returning what was done — or `None` from a store that does
    /// not pack.
    ///
    /// Default: `None`, meaning "this store has no pack layer," which is an
    /// honest answer, not a silent success. The distinction matters at the
    /// replication boundary: pack-level sync must refuse to push a store whose
    /// pre-sync pass reports `None` while the peer is a blind storage node, because
    /// loose objects on the wire reopen the size channel packing exists to
    /// close. That posture check lives with sync, where the peer's posture is
    /// known — this default only makes "cannot pack" distinguishable from
    /// "packed nothing".
    async fn pack_loose(&self) -> ObjectStorageResult<Option<PackSummary>> {
        Ok(None)
    }

    /// Run one compaction pass: rewrite packs whose live fraction has fallen
    /// below the threshold, sweep packs the manifest no longer references, and
    /// reclaim the space (RFC-0045 §Compaction) — or `None` from a store that
    /// does not pack.
    ///
    /// This is the **only** operation in the pack layer that deletes user data,
    /// so it is the one governed by P4: a pack is retired only after the pack
    /// carrying its live chunks has been read back and confirmed to open and to
    /// contain them, and only after the superblock naming the replacement is
    /// committed. Reclamation is never in the same step as the write that
    /// supersedes it.
    ///
    /// Compaction must read chunks to know which are live, so a blind storage node
    /// can never run it. `None` here carries the same meaning as it does for
    /// [`pack_loose`]: "this store has no pack layer," distinguishable from
    /// "compacted nothing".
    ///
    /// [`pack_loose`]: ObjectStorage::pack_loose
    async fn compact(&self) -> ObjectStorageResult<Option<CompactSummary>> {
        Ok(None)
    }

    /// Rebuild the store's root pointer by scanning its packs, for a store whose
    /// superblock is missing or unreadable (RFC-0045 P3).
    ///
    /// This is what "the store is self-describing" has to mean in practice: a
    /// device holding only the key material and the packs can recover, with no
    /// external index (RFC-0034 continuity). Every manifest ever committed is
    /// still sitting in a pack, kind-tagged; the scan takes the newest whose
    /// chunk references all resolve and commits a superblock naming it.
    ///
    /// Returns `Ok(None)` when a superblock already loads — recovery never
    /// competes with a working root pointer — and from any store with no pack
    /// layer.
    async fn recover_by_scan(&self) -> ObjectStorageResult<Option<ScanRecovery>> {
        Ok(None)
    }

    /// Collapse the history log: replay it, write one segment carrying the
    /// merged state, and drop the segments it subsumes from the live set
    /// (RFC-0046 L4, widened by RFC-0047).
    ///
    /// Without this the log grows forever, which RFC-0046 calls a bug rather
    /// than a tradeoff. Segments inside `keep_full_secs` are retained at full
    /// detail so recent history stays granular; everything older is represented
    /// by the snapshot alone.
    ///
    /// A snapshot records **live state only** — it carries no deletions for
    /// paths already gone. That is safe because a device whose high-water mark
    /// predates the retained window does not *merge*: it adopts the snapshot as
    /// its base state, exactly as a hosted service tells a client with too old
    /// a cursor to resync. Merging an ancient segment against a snapshot is the
    /// case that would resurrect a deleted file, and it is precisely the case
    /// that never happens.
    ///
    /// Requires the data keys — snapshotting is merging, and merging is reading
    /// — so a blind storage node returns `None`, as does any store with no log.
    ///
    /// `record_rows` is this device's **current merged record state** (RFC-0046
    /// L4), each row the same opaque changeset payload
    /// [`append_record_segment`](Self::append_record_segment) takes. The snapshot
    /// carries these as its record base and drops the record entries in the
    /// segments it subsumes, so record history is bounded alongside objects. The
    /// caller — which owns the record store and its schema — assembles them; this
    /// layer never interprets a row. Pass `&[]` for an object-only store. A row
    /// whose only copy is in a subsumed segment and is *not* in `record_rows` is
    /// dropped, so the caller must include every row it means to keep.
    async fn snapshot(
        &self,
        _keep_full_secs: u64,
        _record_rows: &[Vec<u8>],
    ) -> ObjectStorageResult<Option<SnapshotSummary>> {
        Ok(None)
    }

    /// Erase a path and **its entire history** (RFC-0047 `purge`).
    ///
    /// Ordinary deletion is non-destructive on a store that keeps history: the
    /// file leaves the current state and stays recoverable, which is what makes
    /// a generous retention default safe to offer. `purge` is the way back out
    /// of that bargain, and it is what lets retention be generous in the first
    /// place — a user who deletes something sensitive can insist it is gone.
    ///
    /// It is a snapshot with the path excluded rather than merged forward:
    /// segments are immutable and sealed, so the only way to unsay something is
    /// to write a new base state that never mentions it and retire every
    /// segment that did. It therefore subsumes the whole log, not merely the
    /// part outside the retention window.
    ///
    /// This removes the **record** as well as the content. Dropping only the
    /// bytes would leave entries saying that a path of some size existed at
    /// some time, which is most of what a user purging a file wants gone.
    ///
    /// Because it subsumes the whole log, it also passes over the record-
    /// changeset entries (`Entry::Record`, RFC-0046) that share it. Those belong
    /// to a different domain — the user's records, not this object path — so
    /// purge **carries them forward verbatim** rather than dropping them; erasing
    /// one file must not silently discard the record history stored beside it.
    ///
    /// # What it cannot do
    ///
    /// It is authoritative for this store and, once the new base state
    /// replicates, for the fleet that adopts it. It cannot reach copies already
    /// held by someone else — the same limit
    /// principle IV in `docs/design/principles.md` states for revocation, and for
    /// the same reason: you can stop future access, you cannot un-give what was
    /// given.
    async fn purge(&self, _path: &Path) -> ObjectStorageResult<Option<SnapshotSummary>> {
        Ok(None)
    }

    /// Rebuild current state from the history log, adopting any segments that
    /// have arrived from a peer (RFC-0047).
    ///
    /// This is what replaces comparing two listings and picking by timestamp.
    /// Replication moves packs; packs carry segments; and merging two devices'
    /// histories is a **set union of segments followed by a replay**. A set
    /// union is trivially convergent — order-independent, idempotent, and with
    /// no losing side — where per-file last-write-wins never was, which is the
    /// whole reason the log exists.
    ///
    /// The division of labour matters: the **log** decides what the state is,
    /// and the **manifests** say where the bytes for a given content id live.
    /// Segments deliberately carry no chunk references, so they stay small and
    /// stay a record of facts rather than a second copy of the manifest.
    ///
    /// Requires the data keys, since replaying means reading. A blind storage node
    /// returns `None` — it carries the segments that make this possible and
    /// performs none of it.
    async fn reconcile(&self) -> ObjectStorageResult<Option<ReconcileSummary>> {
        Ok(None)
    }

    /// Paths holding a retained losing version, with each version's content id.
    ///
    /// R3 (RFC-0071) says replication never destroys the only copy. A store that
    /// keeps a concurrent loser's bytes but offers no way to name them has met
    /// the letter and not the point: the write survives and the user cannot have
    /// it back. These two calls are what make the retention reachable.
    ///
    /// The default is empty — a backend with no history has no conflicts to
    /// retain, which is a true answer rather than a stub.
    async fn retained_conflicts(&self) -> ObjectStorageResult<BTreeMap<String, Vec<String>>> {
        Ok(BTreeMap::new())
    }

    /// The bytes of one retained losing version of `key`, by content id.
    async fn read_retained(&self, key: &Path, content_id: &str) -> ObjectStorageResult<Bytes> {
        let _ = content_id;
        Err(ObjectStorageError::NotFound(
            key.to_string_lossy().into_owned(),
        ))
    }

    /// Settle a conflict on `key`, releasing the versions it was retaining.
    ///
    /// `keep` names a retained version to **promote**: its bytes are written at
    /// `key` as an ordinary new version, so the resolution enters the log as a
    /// write naming what it superseded. Another device replaying sees a decision
    /// rather than a reversal it cannot account for. `None` keeps the current
    /// version and simply releases the rest.
    ///
    /// This is what bounds R3's cost. Retention holds a losing write until
    /// somebody chooses, and without a way to choose it holds forever — the same
    /// shape as a non-destructive delete waiting on `purge`.
    async fn resolve_conflict(&self, key: &Path, keep: Option<&str>) -> ObjectStorageResult<()> {
        let _ = (key, keep);
        Ok(())
    }

    /// Turn `key`'s **keep versions** switch on or off
    /// (`TASK-a-file-keeps-its-versions-when-the-person-asks`).
    ///
    /// On or off and nothing else: no duration, no count, no policy — storage
    /// is the person's or their provider's, and the platform shows its cost as
    /// a number rather than deciding it. On, every write that supersedes this
    /// file's content keeps the superseded version. Off, nothing is kept and
    /// what was kept is released; compaction reclaims its bytes on its own
    /// pass, since compaction is the one operation that deletes (P4).
    ///
    /// The default refuses: a store that keeps no history has no log to name a
    /// version by, and a switch that silently did nothing would be worse than
    /// one that is not there.
    async fn set_keep_versions(&self, key: &Path, on: bool) -> ObjectStorageResult<()> {
        let _ = on;
        Err(ObjectStorageError::BackendError(format!(
            "{} keeps no history, so it cannot keep versions",
            key.to_string_lossy()
        )))
    }

    /// Whether `key` keeps its versions. `false` from a store with no history.
    async fn keeps_versions(&self, key: &Path) -> ObjectStorageResult<bool> {
        let _ = key;
        Ok(false)
    }

    /// The prior versions of `key` that can be read back, newest first.
    ///
    /// Each is an entry the history log already holds, reached by its moment;
    /// see [`FileVersion`]. Empty for a file that never kept its versions, and
    /// from a store with no history.
    async fn versions(&self, key: &Path) -> ObjectStorageResult<Vec<FileVersion>> {
        let _ = key;
        Ok(Vec::new())
    }

    /// The generation at which `key`'s **current** version entered the history
    /// log (RFC-0047) — the `seq` of the newest segment that records this
    /// content at this path — or `None` while it has not.
    ///
    /// `None` is three true answers and never a guess: a write still loose,
    /// which is durable here and in no segment until the next packing pass
    /// commits it; a path the log never named; and every path of a store that
    /// keeps no history. It is a readout of this store's own log and says
    /// nothing about what any other device has adopted — that is an
    /// acknowledgement, and the replication model carries none yet
    /// (`TASK-arrived-needs-a-device-to-say-which-generation-of-a-root-it-has-adopted`).
    async fn logged(&self, key: &Path) -> ObjectStorageResult<Option<u64>> {
        let _ = key;
        Ok(None)
    }

    /// The bytes of one prior version of `key`, by content id.
    async fn read_version(&self, key: &Path, content_id: &str) -> ObjectStorageResult<Bytes> {
        let _ = content_id;
        Err(ObjectStorageError::NotFound(
            key.to_string_lossy().into_owned(),
        ))
    }

    /// Restore a prior version of `key`: **a new write of its old bytes**.
    ///
    /// Never a rewrite of the log. The restore enters history as one more
    /// write naming what it superseded, and recording the version it restores
    /// as the one it was written from, so the version it replaced is itself
    /// kept, and nothing that was written is unsaid. The default is an ordinary
    /// write, for a store with no log to record either in.
    async fn restore_version(&self, key: &Path, content_id: &str) -> ObjectStorageResult<()> {
        let bytes = self.read_version(key, content_id).await?;
        self.put(key, &bytes).await
    }

    /// What `key`'s kept versions cost, in bytes: the content of every chunk
    /// they hold that no current file does — **exactly the chunks that differ**.
    ///
    /// A number and nothing more. Zero for a file that keeps nothing.
    async fn versions_cost(&self, key: &Path) -> ObjectStorageResult<u64> {
        let _ = key;
        Ok(0)
    }

    /// What every kept version in this store costs together, in bytes, counted
    /// the way [`versions_cost`](Self::versions_cost) counts — each chunk once.
    async fn versions_cost_total(&self) -> ObjectStorageResult<u64> {
        Ok(0)
    }

    /// Append a batch of record changeset rows to the history log as a single
    /// sealed segment, returning the writer sequence it was committed at
    /// (RFC-0046).
    ///
    /// This is the record layer's producer seam. The rows are opaque here —
    /// serialized changeset rows the record layer alone interprets — and are
    /// sealed under `K_log` like any other segment, so they replicate to a blind
    /// node as bytes it cannot read. An empty batch, or a store with no log
    /// (a blind storage node has no `K_log`), appends nothing and returns `None`.
    async fn append_record_segment(&self, _rows: &[Vec<u8>]) -> ObjectStorageResult<Option<u64>> {
        Ok(None)
    }

    /// Every record-carrying segment currently in the pack set, for the record
    /// layer to open and merge (RFC-0046).
    ///
    /// The mirror of [`append_record_segment`](Self::append_record_segment):
    /// surfaces the opaque rows the log has accumulated — this device's own and
    /// any a peer's replication delivered — keyed by `(writer, seq)` so the
    /// caller can apply each at most once. Requires the data keys; a blind
    /// replica carries these segments and reads none of them, returning empty.
    async fn scan_record_segments(&self) -> ObjectStorageResult<Vec<RecordSegmentView>> {
        Ok(Vec::new())
    }

    /// The packs that hold the content of every path `kept` keeps, each with
    /// the paths it holds content for: what a device must have in hand to keep
    /// those paths whole (kotton #55, pins).
    ///
    /// `kept` is asked of each path the current state names — its current
    /// version, and the losing versions a conflict retained — in the store's
    /// logical key space (`files/<person path>` for the person's tree). Kept
    /// versions are not asked about: they are history, fetched when opened.
    ///
    /// Each pack is named by its storage key, already admitted ([`StorageKey`],
    /// kotton #301): a store builds it from an id it admitted where the
    /// manifest naming it was decoded, so a caller reads or writes under it
    /// without parsing it again.
    ///
    /// Default: `None` — a store with no pack layer has no packs to name, and
    /// "this store cannot say" is distinguishable from "no pack is needed".
    async fn packs_holding(
        &self,
        _kept: &(dyn for<'p> Fn(&'p str) -> bool + Send + Sync),
    ) -> ObjectStorageResult<Option<BTreeMap<StorageKey, Vec<String>>>> {
        Ok(None)
    }
}

/// A store that can be replicated: it supports ordinary access *and* can expose
/// its objects as sealed blobs.
///
/// Blanket-implemented, so declaring both traits is sufficient. Sync holds
/// `dyn SyncableStore` because it needs `list`/`metadata` to decide *what* to
/// transfer and sealed access to perform the transfer without decrypting.
pub trait SyncableStore: ObjectStorage + SealedObjectAccess {}

impl<T: ObjectStorage + SealedObjectAccess> SyncableStore for T {}

/// Where a node's own mounts rest — the shelves beneath its pools (RFC-0084 V5).
///
/// A user's "local" mount is a sealed stack over some backend. On a device the
/// backend is a directory; on a rented vault it may be a bucket the landlord
/// pays for. Which one is the *node's* configuration, decided once for the
/// process and never named on any wire: a device that pushes to a vault cannot
/// tell whether its packs landed on a disk or in a bucket, and must not be
/// able to. This trait is that seam. `open` is asked once per mount, when a
/// store is created or reloaded, and hands back the raw backend the sealed
/// stack is then built over.
///
/// `path` is where the mount's configuration says its objects live. A
/// directory-backed set of shelves uses it; a bucket-backed one derives a key
/// prefix from `user_id` and `mount` instead and ignores it.
pub trait Shelves: Send + Sync {
    fn open(&self, user_id: &str, mount: &str, path: &Path) -> Arc<dyn SyncableStore>;
}

impl<S: Shelves + ?Sized> Shelves for Arc<S> {
    fn open(&self, user_id: &str, mount: &str, path: &Path) -> Arc<dyn SyncableStore> {
        (**self).open(user_id, mount, path)
    }
}
