// SPDX-License-Identifier: AGPL-3.0-or-later
//! Packed object store — loose-then-pack, with pack-aware reads
//! (`docs/design/store.md`).
//!
//! Wraps the blinded store and adds the pack layer on top of it:
//!
//! ```text
//! PackedObjectStorage           put → loose;  get → loose, then packs
//!   └── BlindedObjectStorage        blinded keys, path in the sealed body
//!         └── EncryptedObjectStorage    per-object DEK envelope
//!               └── LocalObjectStorage
//! ```
//!
//! **Writes land loose** — an ordinary blinded object, durable when `put`
//! returns, exactly the store that already ships. **`pack_loose` is the batch
//! pass** that moves loose objects into sealed fixed-size packs: chunk
//! (content-defined), fill packs, seal, write, commit a new manifest +
//! superblock, verify every chunk it now depends on, and only then delete the
//! loose originals (verify before delete). **Reads check loose first** — a rewrite shadows its
//! packed version until the next pass — then fall back to manifest → packs,
//! verifying each chunk's BLAKE3 digest against the sealed manifest before
//! returning a byte, so a relocated or corrupted chunk fails the read rather
//! than serving wrong bytes.
//!
//! # Reserved storage namespace
//!
//! Packs, superblocks, and the tombstone set live under `_`-prefixed storage
//! keys (`_pack/…`, `_superblock/…`, `_tombstones`). Blinded components are
//! base32, an alphabet with no `_`, so collision with a blinded object key is
//! structurally impossible.
//!
//! The reserved names have one grammar (kotton #276, written down here
//! because this is where a reserved name is first held as a value,
//! [`PackId`]):
//!
//! ```text
//! reserved     := pack | superblock | tombstones
//! pack         := "_pack/" index-id | "_pack/" content-id
//! index-id     := hex32
//! content-id   := "c-" hex32
//! superblock   := "_superblock/" gen "-" hex16
//! tombstones   := "_tombstones"
//! gen          := 20 decimal digits, zero-padded
//! hexN         := N characters of 0-9a-f
//! ```
//!
//! A pack id is 128 random bits in lowercase hex (`PackWriter::fresh_id`), a
//! content pack's prefixed `c-`, which no hex id begins with. A superblock's
//! name is its generation, zero-padded so text order is generation order, and
//! 64 random bits (`crate::superblock`).
//!
//! Of these, only a pack id is *named by something the store reads*: a
//! manifest and a superblock name packs, and another device may have written
//! them. So a pack id is the reserved name admitted as a value, [`PackId`],
//! where it is decoded, and where a pass that reads, rewrites or deletes packs
//! lists them. A superblock's name is read from a listing by
//! `crate::superblock`'s loader, and the tombstone set's is a constant.
//! [`crate::StorageKey`] does not yet hold this grammar for every key
//! (kotton #276).
//!
//! # A refused generation is held
//!
//! The rule, for a manifest naming a pack outside the grammar (kotton #273):
//!
//! - **Its generation is passed over** as a superblock that does not open is.
//!   Reads, listings and commits use the newest generation whose manifest
//!   decodes, and the refusal is a `warn` from `crate::superblock` naming the
//!   superblock's key and the id (`load_committed`). Only that refusal is
//!   passed over: a malformed manifest, or one of a version this code does not
//!   read, fails the load, since it may be a newer device's correct write.
//! - **A commit past it is numbered above it** (kotton #308), so it sorts
//!   below every later commit by generation alone.
//! - **It is held.** While any present generation's manifest is refused,
//!   wherever it sorts, compaction does not run and retirement keeps its
//!   superblock (`held_generation`). The data only that manifest names is
//!   unreadable, and kept on the shelf, never deleted.
//!
//! That is the concession: one bad ref costs the person the data only its
//! generation names, readable again once the generation is repaired, and
//! compaction until then. The rest of the mount reads and writes. The seam is
//! a repair that re-adopts the held generation's other refs, which is not
//! built (see PR 298). Only when no generation decodes is the mount
//! unreadable.
//!
//! A name under `_pack/` outside the grammar is left in place and counted
//! (`CompactSummary::packs_unadmitted`).
//!
//! # Deletes and tombstones
//!
//! Deleting a packed file cannot rewrite bytes (packs are immutable) and must
//! not require a 16 MiB pack write per delete. Instead the path is recorded in
//! a small sealed **tombstone set**; reads treat a tombstoned path as absent,
//! and the next packing pass folds the deletions into the manifest and clears
//! the set. A loose write to a tombstoned path supersedes the tombstone —
//! loose-first reads make the resurrection visible immediately.
//!
//! # What this does *not* do
//!
//! Pack-level sync is not built. Until it is, running `pack_loose` on a
//! mount that also syncs object-by-object is **not safe against manifest
//! divergence** — two devices packing independently produce two manifests that
//! object-level LWW cannot merge. Nothing is destroyed (superblock keys never
//! collide across devices, packs are immutable), but one device's packed files
//! can become unreachable-by-name on the other until the manifests are merged.
//! The runtime therefore only triggers packing explicitly, never as part of
//! sync.

use crate::chunker::chunk_boundaries;
use crate::history::{Entry as HistoryEntry, Segment};
use crate::manifest::{
    chunk_digest, frame_chunk, unframe_chunk, ChunkKind, FileEntry, Manifest, ManifestDecodeError,
    PackChunkRef,
};
use crate::pack::{open_pack, read_chunk_from_plaintext, scan_chunks, ChunkRef};
use crate::superblock::{
    commit_superblock, load_adopted_superblock, load_current_superblock, read_superblock,
    retirable_superblocks, superblock_keys, PassedOver, Superblock, SUPERBLOCK_PREFIX,
};
use async_trait::async_trait;
use bytes::Bytes;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use kotton_sys::store::{
    CompactSummary, FileVersion, ObjectMetadata, ObjectSink, ObjectStorage, ObjectStorageError,
    ObjectStorageResult, PackSummary, ReconcileSummary, RecordSegmentView, ScanRecovery,
    SealedObjectAccess, SnapshotSummary,
};
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Storage-key prefix for sealed packs. Reserved: base32 blinded components
/// can never start with `_`.
pub const PACK_PREFIX: &str = "_pack";

/// Storage-key prefix of a **content pack**: a pack that holds file content
/// and nothing else — no history segment, no manifest (kotton #55, pins).
///
/// Every other pack under [`PACK_PREFIX`] is an **index pack**: it may hold a
/// segment of the history log or a manifest, and a device that reads the store
/// must have it to know what the store holds. A content pack it needs only for
/// the files it keeps whole, or a file it opens. The split is what lets a
/// device keep the index of a drive without its content ("a device keeps
/// what its person chose"; on demand, the index is fetched and content when
/// opened).
///
/// What the split shows a holder who cannot open a pack: which of the packs it
/// holds are index packs. A packing pass writes one index pack beside the
/// content packs it fills, so the holder learns how many content packs each
/// pass wrote — which the count of packs and the superblock's commit already
/// told it — and nothing about what is in them. What it costs: a pass that
/// writes content now seals two packs where it sealed one, the index one at
/// the smaller fixed size, [`crate::pack::INDEX_PACK_SIZE`], when it fits.
/// Packs written before the split carry no mark and are read as index packs,
/// so a store written before keeps every byte on every device, as it did.
pub const CONTENT_PACK_PREFIX: &str = "_pack/c-";

/// Whether a pack stored under `key` is `len` bytes long as its class says it
/// must be: a content pack exactly [`crate::pack::PACK_SIZE`], an index pack
/// exactly [`crate::pack::INDEX_PACK_SIZE`] or, when its index did not fit
/// that, [`crate::pack::PACK_SIZE`]. Two sizes a holder can see, each saying
/// nothing of what is inside.
pub fn has_its_fixed_size(key: &str, len: u64) -> bool {
    let (full, index) = (crate::pack::PACK_SIZE as u64, crate::pack::INDEX_PACK_SIZE as u64);
    len == full || (!is_content_pack(key) && len == index)
}

/// Whether the storage key `key` names a content pack ([`CONTENT_PACK_PREFIX`]).
pub fn is_content_pack(key: &str) -> bool {
    kind(key) == ObjectKind::ContentPack
}

/// What a storage key names, by the namespace rule of the store: the one
/// reading of a key, which every site that sorts keys calls ([`kind`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    /// A superblock: a key under [`SUPERBLOCK_PREFIX`]`/`.
    Superblock,
    /// A content pack: a key under [`CONTENT_PACK_PREFIX`].
    ContentPack,
    /// An index pack: any other key under [`PACK_PREFIX`]`/`, packs written
    /// before the split among them.
    IndexPack,
    /// Any other key in the reserved `_` namespace: the tombstone set
    /// ([`TOMBSTONES_KEY`]), a directory entry such as `_pack` itself, or a
    /// name this rule does not know. Never a person's file.
    Reserved,
    /// A blinded object: one file of the person's, loose.
    File,
}

/// The kind of object the storage key `key` names.
///
/// - **The `/` boundary.** A prefix names its directory, not a stem: a key is
///   a pack only under `_pack/`, a superblock only under `_superblock/`. So
///   `_packets` is not a pack, and neither is `_pack` itself (a directory
///   entry a listing returns); both are [`ObjectKind::Reserved`], as is `_`.
/// - **A key is read as it is.** A key from outside the store is admitted
///   before anything reads it, so none carries a leading `/`, a `.` or a
///   `..` for this rule to read past, and no key the store writes carries one
///   either. `/_pack/i-1` is therefore not a pack: it starts with no `_`, and
///   is [`ObjectKind::File`] like any other key outside the reserved
///   namespace. The admissions: a sync pass's listings, on both sides
///   ([`crate::StorageKey`], kotton #265); a pack id a manifest or superblock
///   names, where it is decoded, and the pack listing compaction and scan
///   recovery act on ([`PackId`], kotton #273); and every key and prefix the
///   sealed view (`kotton_sealed::Sealed`) is handed, which it takes typed
///   (kotton #275, #320). Keys that still reach a store unadmitted come
///   through other doors, each tracked where it is: a guest re-wrap's raw
///   read (`LocalObjectStorage::resolve_key`'s doc) and drive move's copy
///   (kotton #274).
/// - **The rest of the `_` namespace** is [`ObjectKind::Reserved`].
///   Blinded components are base32, an alphabet with no `_`, so only a key
///   in the reserved namespace starts with one, and every other key is
///   [`ObjectKind::File`].
pub fn kind(key: &str) -> ObjectKind {
    let under = |prefix: &str| key.strip_prefix(prefix).is_some_and(|rest| rest.starts_with('/'));
    if under(SUPERBLOCK_PREFIX) {
        ObjectKind::Superblock
    } else if key.starts_with(CONTENT_PACK_PREFIX) {
        ObjectKind::ContentPack
    } else if under(PACK_PREFIX) {
        ObjectKind::IndexPack
    } else if key.starts_with('_') {
        ObjectKind::Reserved
    } else {
        ObjectKind::File
    }
}

/// Storage key of the sealed tombstone set (pending deletes of packed files).
pub const TOMBSTONES_KEY: &str = "_tombstones";

/// How many lowercase hex digits name a pack, after `_pack/` and a content
/// pack's `c-` (the reserved grammar, module doc).
pub const PACK_ID_HEX_LEN: usize = 32;

/// A pack's storage key, admitted: `_pack/<hex32>` for an index pack,
/// `_pack/c-<hex32>` for a content pack (the reserved grammar, module doc),
/// and nothing else (kotton #273).
///
/// A manifest names a pack for every chunk it maps, and a superblock names
/// the pack its manifest is in. Both were written by a device that may not
/// be this one, and every read, every fetch on open ([`crate::fetch`]) and
/// every compaction builds a storage key from the id they name. So the id is
/// admitted where it is decoded: a [`crate::manifest::PackChunkRef`] holds a
/// `PackId`, and deserializing one parses it, so a manifest or superblock
/// that names `_pack/../x`, an id that is not hex, or an empty one does not
/// decode at all. Nothing reads such an id afterwards, because there is none
/// to read.
///
/// Every `PackId` is a [`crate::StorageKey`] and reads as a pack by the
/// namespace rule ([`kind`]); serialized, it is the key as text, as it
/// always was.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PackId(crate::StorageKey);

impl PackId {
    /// Admit `id`, or say why it is not a pack id in the reserved grammar.
    pub fn parse(id: &str) -> Result<Self, crate::NotCanonical> {
        let refuse = |why| Err(crate::NotCanonical { key: id.to_string(), why });
        let key = crate::StorageKey::parse(id)?;
        let Some(name) = id.strip_prefix(PACK_PREFIX).and_then(|rest| rest.strip_prefix('/')) else {
            return refuse("it is not under `_pack/`");
        };
        let hex = name.strip_prefix("c-").unwrap_or(name);
        if hex.len() != PACK_ID_HEX_LEN || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return refuse("a pack's name is not 32 lowercase hex digits, or `c-` and 32");
        }
        Ok(Self(key))
    }

    /// The id as text: the pack's storage key.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// The id as the path a store is addressed by.
    pub fn as_path(&self) -> &Path {
        self.0.as_path()
    }

    /// The id as an admitted storage key.
    pub fn as_key(&self) -> &crate::StorageKey {
        &self.0
    }

    /// Whether this is a content pack ([`CONTENT_PACK_PREFIX`]).
    pub fn is_content(&self) -> bool {
        self.as_str().starts_with(CONTENT_PACK_PREFIX)
    }
}

impl TryFrom<String> for PackId {
    type Error = crate::NotCanonical;
    fn try_from(id: String) -> Result<Self, Self::Error> {
        Self::parse(&id)
    }
}

impl From<PackId> for String {
    fn from(id: PackId) -> Self {
        id.0.as_str().to_string()
    }
}

impl std::fmt::Display for PackId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AsRef<Path> for PackId {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

/// Lets a set or map of ids be asked by `&str`; the order is the string's.
impl std::borrow::Borrow<str> for PackId {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

/// One loose object as the packer sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LooseEntry {
    /// Logical (unblinded) path, canonical: forward slashes, no leading slash.
    pub path: String,
    /// True content size in bytes.
    pub size: u64,
    /// Last-modified Unix seconds, if the backing store tracks it.
    pub modified: Option<u64>,
}

/// A store whose loose objects can be enumerated with their logical names —
/// what the packer consumes.
///
/// Only a store that can recover logical paths implements this (for a blinding
/// store, the name lives inside each object's seal, so enumeration reads the
/// objects). The reserved `_` storage namespace is excluded by contract.
#[async_trait]
pub trait LooseObjectSource: ObjectStorage + SealedObjectAccess {
    /// Every loose object: logical path, true size, modified time.
    async fn list_loose(&self) -> ObjectStorageResult<Vec<LooseEntry>>;
}

/// Pending deletes of packed files, applied at the next packing pass.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Tombstones {
    /// path → deletion time (Unix seconds), for a future LWW merge.
    deleted: BTreeMap<String, u64>,
}

/// ChaCha20-Poly1305 nonce length for the tombstone seal.
const NONCE_LEN: usize = 12;

/// Manifest cache: distinguishes "never loaded" from "loaded, store has no
/// superblock yet".
enum CacheState {
    Unloaded,
    Loaded(Option<(u64, Arc<Manifest>)>),
}

/// What a store needs in order to append history: who it writes as, and the
/// db-domain key the segment body is sealed under.
struct LogWriter {
    writer_did: String,
    k_log: [u8; 32],
}

/// The packed store. See the module docs for the layering and semantics.
pub struct PackedObjectStorage<S: LooseObjectSource + 'static> {
    /// Shared rather than owned, because a streaming write outlives the call
    /// that began it: [`begin_stream`] hands back a sink the caller holds
    /// across many `push`es, and that sink writes packs through this same
    /// store. An `Arc` is what lets the sink be `'static` without the store
    /// being copied or the layering being rearranged.
    ///
    /// [`begin_stream`]: ObjectStorage::begin_stream
    inner: Arc<S>,
    k_pack: [u8; 32],
    /// `None` on a store that appends no history — see
    /// [`PackedObjectStorage::with_log`].
    log: Option<Arc<LogWriter>>,
    /// Shared with any live sink, for the same reason `inner` is: the sink
    /// commits a generation, and the store's next read must see it.
    manifest_cache: Arc<Mutex<CacheState>>,
    tombstone_cache: Arc<Mutex<Option<Arc<Tombstones>>>>,
}

impl<S: LooseObjectSource + 'static> PackedObjectStorage<S> {
    /// Wrap `inner`, sealing packs under `k_pack`
    /// (`kotton_crypto::derive_pack_key`).
    ///
    /// The store appends no history in this form. See [`with_log`].
    ///
    /// [`with_log`]: Self::with_log
    pub fn new(inner: S, k_pack: [u8; 32]) -> Self {
        Self {
            inner: Arc::new(inner),
            k_pack,
            log: None,
            manifest_cache: Arc::new(Mutex::new(CacheState::Unloaded)),
            tombstone_cache: Arc::new(Mutex::new(None)),
        }
    }

    /// Append history segments for every packing pass, attributed to
    /// `writer_did` and sealed under `k_log`
    /// (`kotton_crypto::derive_history_log_key`).
    ///
    /// Logging is opt-in at the **store** rather than implied by the format,
    /// because not every store can log. `K_log` derives from `master_secret`,
    /// and a blind storage node holds none — it carries segments without being able
    /// to write or read them, which is the whole point of the inner seal. A
    /// store that cannot log must still be constructible, so this is a separate
    /// step rather than an argument to [`new`].
    ///
    /// [`new`]: Self::new
    pub fn with_log(mut self, writer_did: impl Into<String>, k_log: [u8; 32]) -> Self {
        self.log = Some(Arc::new(LogWriter {
            writer_did: writer_did.into(),
            k_log,
        }));
        self
    }

    /// Canonical manifest key for a caller path: forward slashes, no leading
    /// slash — the same form the blinded layer embeds.
    fn canon(key: &Path) -> String {
        let unix = key.to_string_lossy().replace('\\', "/");
        unix.trim_start_matches('/').to_string()
    }

    /// The packs this store's shelf lists, each name admitted as a [`PackId`]
    /// (kotton #273), for a pass that reads, rewrites or deletes what it
    /// lists: compaction and scan recovery.
    ///
    /// A shelf lists what is on it, and a bucket or a directory may hold a
    /// name the store never wrote. One outside the reserved grammar is named
    /// in the log and left where it is: never read, rewritten or deleted,
    /// since nothing the store wrote is under that name. How many were left
    /// is the second value, which compaction reports
    /// (`CompactSummary::packs_unadmitted`): a name a peer's sync can plant
    /// (`StorageKey` admits `_pack/zz`) is never swept, so it is counted
    /// where the pass that would have swept it reports.
    async fn listed_packs(&self, pass: &str) -> ObjectStorageResult<(BTreeSet<PackId>, usize)> {
        let mut packs = BTreeSet::new();
        let mut unadmitted = 0usize;
        for m in self.inner.list_sealed(Path::new(PACK_PREFIX)).await? {
            if m.is_dir {
                continue;
            }
            match PackId::parse(&m.key) {
                Ok(id) => {
                    packs.insert(id);
                }
                Err(refused) => {
                    tracing::warn!(pass, "{refused}; left as it is");
                    unadmitted += 1;
                }
            }
        }
        Ok((packs, unadmitted))
    }

    // ── manifest state ──────────────────────────────────────────────────────

    /// Read the committed manifest ([`load_committed`]), straight from disk.
    async fn load_state_from_disk(&self) -> ObjectStorageResult<Option<(u64, Manifest)>> {
        Ok(load_committed(&*self.inner, &self.k_pack)
            .await?
            .map(|c| (c.base_generation(), c.manifest)))
    }

    /// The current manifest, cached after first load.
    async fn manifest(&self) -> ObjectStorageResult<Option<(u64, Arc<Manifest>)>> {
        if let CacheState::Loaded(state) = &*self.manifest_cache.lock().unwrap() {
            return Ok(state.clone());
        }
        let state = self
            .load_state_from_disk()
            .await?
            .map(|(gen, m)| (gen, Arc::new(m)));
        *self.manifest_cache.lock().unwrap() = CacheState::Loaded(state.clone());
        Ok(state)
    }

    fn invalidate_manifest_cache(&self) {
        *self.manifest_cache.lock().unwrap() = CacheState::Unloaded;
    }

    /// Read one chunk by its manifest ref, verifying its digest.
    ///
    /// The digest check is what binds a chunk to its logical position: refs
    /// live in the sealed manifest, so a replica that relocates or swaps pack
    /// bytes cannot make this return the wrong chunk — the read fails instead.
    async fn read_framed_chunk(&self, r: &PackChunkRef) -> ObjectStorageResult<Vec<u8>> {
        let blob = self.inner.get_sealed(r.pack_id.as_path()).await?;
        let plaintext = open_pack(&self.k_pack, &blob)?;
        Self::framed_from_plaintext(&plaintext, r)
    }

    fn framed_from_plaintext(
        plaintext: &[u8],
        r: &PackChunkRef,
    ) -> ObjectStorageResult<Vec<u8>> {
        framed_from_plaintext(plaintext, r)
    }

    /// Reassemble **part** of a packed file: `[offset, offset + length)`.
    ///
    /// This is the read half of the same defect the streaming sink answers on
    /// the write half. A caller fetching a large object in ranges — the IPC
    /// client does, because a whole object exceeds the frame cap — used to make
    /// the daemon read and decrypt the *whole* object once per range, so
    /// serving one object cost time quadratic in its size. At note sizes that
    /// is invisible; at model sizes it never finishes.
    ///
    /// A chunk is only read when the range touches it, so the work is
    /// proportional to what was asked for. The chunk lengths come from the
    /// sealed manifest, so skipping is not a guess about the plaintext: the
    /// running offset is exact, and every chunk that *is* read still has its
    /// digest checked before a byte of it is returned. Skipping a chunk is
    /// therefore not skipping a verification — it is declining to read bytes
    /// nobody asked for.
    ///
    /// Packs are opened lazily and the most recent kept, as in
    /// [`read_packed_file`](Self::read_packed_file).
    async fn read_packed_range(
        &self,
        entry: &FileEntry,
        offset: u64,
        length: u64,
    ) -> ObjectStorageResult<Bytes> {
        let end = offset.saturating_add(length).min(entry.size);
        if offset >= end {
            return Ok(Bytes::new());
        }
        let mut out: Vec<u8> = Vec::with_capacity((end - offset) as usize);
        let mut open: Option<(PackId, Vec<u8>)> = None;
        let mut pos: u64 = 0;
        for r in &entry.chunks {
            // A chunk's framed length carries the one-byte kind tag, so the
            // plaintext it contributes is one byte shorter. A zero-length
            // framed chunk cannot exist — the tag is always there — and is
            // refused rather than quietly treated as empty.
            let framed_len = r.length as u64;
            if framed_len == 0 {
                return Err(ObjectStorageError::BackendError(format!(
                    "manifest records a zero-length chunk in {} — corrupt entry",
                    r.pack_id
                )));
            }
            let plain_len = framed_len - 1;
            let chunk_end = pos + plain_len;
            if chunk_end <= offset {
                pos = chunk_end;
                continue;
            }
            if pos >= end {
                break;
            }

            if open.as_ref().map(|(id, _)| id.as_str()) != Some(r.pack_id.as_str()) {
                let blob = self.inner.get_sealed(r.pack_id.as_path()).await?;
                open = Some((r.pack_id.clone(), open_pack(&self.k_pack, &blob)?));
            }
            let (_, plaintext) = open.as_ref().unwrap();
            let framed = framed_from_plaintext(plaintext, r)?;
            let (kind, payload) = unframe_chunk(&framed)?;
            if kind != ChunkKind::Data {
                return Err(ObjectStorageError::BackendError(format!(
                    "expected a data chunk in {}, found {kind:?}",
                    r.pack_id
                )));
            }
            if payload.len() as u64 != plain_len {
                return Err(ObjectStorageError::BackendError(format!(
                    "chunk in {} holds {} bytes where the manifest says {plain_len} — refusing \
                     to serve a range positioned by a length that is not true",
                    r.pack_id,
                    payload.len()
                )));
            }
            let from = offset.saturating_sub(pos).min(plain_len) as usize;
            let to = (end - pos).min(plain_len) as usize;
            out.extend_from_slice(&payload[from..to]);
            pos = chunk_end;
        }
        if out.len() as u64 != end - offset {
            return Err(ObjectStorageError::BackendError(format!(
                "range [{offset}, {end}) assembled {} bytes — the chunk lengths in the manifest \
                 do not add up to the size it records",
                out.len()
            )));
        }
        Ok(Bytes::from(out))
    }

    /// Reassemble a packed file from its manifest entry.
    ///
    /// Packs are opened lazily and the most recent kept, so a file whose
    /// chunks were written sequentially costs one 16 MiB open per pack it
    /// spans, not per chunk.
    async fn read_packed_file(&self, entry: &FileEntry) -> ObjectStorageResult<Bytes> {
        let mut out: Vec<u8> = Vec::with_capacity(entry.size as usize);
        let mut open: Option<(PackId, Vec<u8>)> = None;
        for r in &entry.chunks {
            if open.as_ref().map(|(id, _)| id.as_str()) != Some(r.pack_id.as_str()) {
                let blob = self.inner.get_sealed(r.pack_id.as_path()).await?;
                open = Some((r.pack_id.clone(), open_pack(&self.k_pack, &blob)?));
            }
            let (_, plaintext) = open.as_ref().unwrap();
            let framed = Self::framed_from_plaintext(plaintext, r)?;
            let (kind, payload) = unframe_chunk(&framed)?;
            if kind != ChunkKind::Data {
                return Err(ObjectStorageError::BackendError(format!(
                    "expected a data chunk in {}, found {kind:?}",
                    r.pack_id
                )));
            }
            out.extend_from_slice(payload);
        }
        if out.len() as u64 != entry.size {
            return Err(ObjectStorageError::BackendError(format!(
                "reassembled {} bytes, manifest says {} — refusing to serve a corrupt file",
                out.len(),
                entry.size
            )));
        }
        Ok(Bytes::from(out))
    }

    // ── tombstones ──────────────────────────────────────────────────────────

    async fn load_tombstones(&self) -> ObjectStorageResult<Arc<Tombstones>> {
        load_tombstones_from(&*self.inner, &self.k_pack, &self.tombstone_cache).await
    }

    /// Persist the tombstone set; an empty set is deleted, not written.
    async fn save_tombstones(&self, tombs: &Tombstones) -> ObjectStorageResult<()> {
        save_tombstones_to(&*self.inner, &self.k_pack, &self.tombstone_cache, tombs).await
    }


    // ── the packing pass ────────────────────────────────────────────────────

    /// Run one packing pass. See the module docs; the ordering here **is** the
    /// safety argument:
    ///
    /// 1. chunk + write packs (loose untouched)
    /// 2. verify every chunk the new manifest depends on for this pass's files
    /// 3. commit the superblock
    /// 4. only then delete loose originals and clear applied tombstones
    ///
    /// A crash anywhere leaves a store that opens and loses nothing: before
    /// step 3 the previous superblock (or none) is current and loose objects
    /// still serve; between 3 and 4 both copies exist and loose-first reads
    /// serve identical content; a re-run deduplicates against the committed
    /// manifest and converges.
    async fn run_pack_pass(&self) -> ObjectStorageResult<PackSummary> {
        let mut loose = self.inner.list_loose().await?;
        loose.sort_by(|a, b| a.path.cmp(&b.path));
        let tombs = self.load_tombstones().await?;
        // One superblock load, since the pass needs both halves of the root
        // pointer: the manifest to build on, and the log head to chain to.
        let (base_gen, base_manifest) = match load_committed(&*self.inner, &self.k_pack).await? {
            Some(c) => (c.base_generation(), c.manifest),
            None => (0, Manifest::new()),
        };

        if loose.is_empty() && tombs.deleted.is_empty() {
            return Ok(PackSummary {
                generation: (base_gen > 0).then_some(base_gen),
                ..Default::default()
            });
        }

        // Dedup index: every chunk the fleet already stores, by content
        // digest. Packs are immutable and never retired by this pass, so a
        // reused ref stays valid.
        let mut chunk_index: HashMap<String, PackChunkRef> = HashMap::new();
        for entry in base_manifest.files.values() {
            for r in &entry.chunks {
                chunk_index
                    .entry(r.digest.clone())
                    .or_insert_with(|| r.clone());
            }
        }

        let mut new_manifest = base_manifest.clone();

        // Apply pending deletes — except where a loose write has superseded
        // the tombstone (delete-then-recreate).
        let loose_paths: BTreeSet<&str> = loose.iter().map(|e| e.path.as_str()).collect();
        let mut deleted_paths: Vec<(String, u64)> = Vec::new();
        for (path, at) in &tombs.deleted {
            if !loose_paths.contains(path.as_str()) && new_manifest.files.remove(path).is_some() {
                deleted_paths.push((path.clone(), *at));
            }
        }

        // Chunk every loose file, filling packs as chunks accumulate so
        // memory stays bounded by one pack plus one file. Content packs: the
        // index goes in a pack of its own at the commit. (Compaction holds
        // more: a content writer and an index writer, each up to a pack open,
        // beside the pack it is salvaging — about three packs, where one
        // writer made it about two.)
        let mut writer = PackWriter::content(Arc::clone(&self.inner), self.k_pack);
        let mut planned: Vec<String> = Vec::with_capacity(loose.len());
        for entry in &loose {
            let data = self.inner.get(Path::new(&entry.path)).await?;
            let mut chunks = Vec::new();
            for (off, len) in chunk_boundaries(&data) {
                let framed = frame_chunk(ChunkKind::Data, &data[off..off + len]);
                let digest = chunk_digest(&framed);
                let r = match chunk_index.get(&digest) {
                    Some(existing) => existing.clone(),
                    None => {
                        let r = writer.push(framed, &digest).await?;
                        chunk_index.insert(digest, r.clone());
                        r
                    }
                };
                chunks.push(r);
            }
            new_manifest.files.insert(
                entry.path.clone(),
                FileEntry {
                    size: data.len() as u64,
                    modified: entry.modified.or_else(now_secs),
                    chunks,
                    keep_versions: false,
                },
            );
            planned.push(entry.path.clone());
        }
        // What this pass superseded, kept where the file keeps its versions and
        // released where it does not — including a file this pass deleted.
        keep_what_was_superseded(&base_manifest, &mut new_manifest);

        // The tail — segment, manifest, packs, verification, superblock —
        // is `commit_new_state`, shared with the streaming ingest so the two
        // cannot drift on the ordering that keeps a crash lossless.
        let (generation, packs_written) = commit_new_state(
            &*self.inner,
            &self.k_pack,
            self.log.as_deref(),
            &mut writer,
            &base_manifest,
            &mut new_manifest,
            base_gen,
            &planned,
            &deleted_paths,
            &BTreeMap::new(),
            "loose originals left in place",
        )
        .await?;

        // The commit is durable; now — and only now — retire the loose side.
        let mut loose_deleted = 0usize;
        for path in &planned {
            self.inner.delete(Path::new(path)).await?;
            loose_deleted += 1;
        }
        self.save_tombstones(&Tombstones::default()).await?;
        if let Err(e) = retire_superseded(&*self.inner, &self.k_pack).await {
            tracing::warn!(error = %e, "old superblock retirement failed; harmless, retried next pass");
        }

        *self.manifest_cache.lock().unwrap() =
            CacheState::Loaded(Some((generation, Arc::new(new_manifest))));

        Ok(PackSummary {
            files_packed: planned.len(),
            packs_written,
            loose_deleted,
            generation: Some(generation),
        })
    }

    // ── the compaction pass ─────────────────────────────────────────────────

    /// Run one compaction pass. As with the packing pass, the ordering **is**
    /// the safety argument — and here it is four steps, not three:
    ///
    /// 1. rewrite live chunks out of the packs being reclaimed, into fresh ones
    /// 2. read the fresh packs back; confirm each opens and holds what is claimed
    /// 3. commit a superblock naming them
    /// 4. only then retire the old packs
    ///
    /// A crash anywhere loses nothing. Before step 3 the previous superblock is
    /// still current and still points at the originals, which are untouched —
    /// the freshly written packs are merely unreferenced, and the next pass
    /// sweeps them. Between 3 and 4 both copies exist and every read resolves
    /// through the committed manifest. Re-running converges either way.
    ///
    /// This is the **only** operation in the pack layer that deletes user data.
    /// A liveness miscalculation loses it permanently, and git, restic and borg
    /// have each shipped a GC bug of exactly this shape — which is why the
    /// read-back is unconditional and why the manifest is re-checked against the
    /// retirement set before anything is unlinked.
    ///
    /// **Requires exclusive access to the mount.** A pack that no committed
    /// manifest references is treated as reclaimable, so a packing pass running
    /// concurrently — whose packs are written but not yet committed — would look
    /// exactly like crash debris. Both passes are explicit triggers and neither
    /// is wired into an automatic path, so this holds today by construction
    /// rather than by locking; it stops holding the moment either becomes
    /// automatic.
    async fn run_compaction_pass(&self) -> ObjectStorageResult<CompactSummary> {
        let Some(committed) = load_committed(&*self.inner, &self.k_pack).await? else {
            // Nothing committed means no manifest, so no pack can be *proven*
            // dead. A store that has only ever written loose objects compacts
            // to a no-op rather than sweeping packs it cannot account for.
            return Ok(CompactSummary::default());
        };
        // Compaction deletes what the manifest it reads does not name. A
        // present generation whose manifest was refused names packs no
        // readable manifest may name, so while one is present, wherever it
        // sorts, this pass deletes nothing (the rule in the module doc).
        for (generation, key) in superblock_keys(&*self.inner).await? {
            if let Some(why) = held_generation(&*self.inner, &self.k_pack, &key).await? {
                return Err(ObjectStorageError::BackendError(format!(
                    "compaction not run: generation {generation} ({key}) is held, its manifest \
                     refused ({why}); the packs only it names are kept, and compaction stays off \
                     until it is repaired"
                )));
            }
        }
        let Committed {
            superblock: sb,
            manifest: base_manifest,
            ..
        } = committed;

        // Live = every chunk the current files depend on, deduplicated by
        // digest. The manifest's own chunk is deliberately absent: this pass
        // writes a fresh manifest, so the old chunk is dead by construction.
        let mut live: BTreeMap<String, PackChunkRef> = BTreeMap::new();
        for entry in base_manifest.files.values() {
            for r in &entry.chunks {
                live.entry(r.digest.clone()).or_insert_with(|| r.clone());
            }
        }

        // Retained losing versions are live too. Without this the chunks a
        // conflict preserved are unreferenced, and this pass is what would
        // destroy the write the merge deliberately kept.
        for entries in base_manifest.conflicts.values() {
            for entry in entries {
                for r in &entry.chunks {
                    live.entry(r.digest.clone()).or_insert_with(|| r.clone());
                }
            }
        }

        // Kept versions are live too, for the same reason and in the same way:
        // a file that keeps its versions has asked for exactly these chunks to
        // outlive the write that superseded them. This is the line that makes
        // the switch mean something, and turning the switch off is what removes
        // them from this set — after which the pass reclaims them like any
        // other dead chunk.
        for entries in base_manifest.versions.values() {
            for entry in entries {
                for r in &entry.chunks {
                    live.entry(r.digest.clone()).or_insert_with(|| r.clone());
                }
            }
        }

        // Packs are fixed-size, so capacity is the denominator for every live
        // fraction and no pack has to be opened to be measured.
        let capacity = crate::pack::max_payload();
        let (on_disk, packs_unadmitted) = self.listed_packs("compaction").await?;

        // History segments are live too, and the manifest names them: `log` is
        // the liveness set. A segment chunk *not* listed there is collectable —
        // which is exactly how a snapshot retires the segments it subsumes,
        // by writing a shorter list.
        for r in &base_manifest.log {
            live.entry(r.digest.clone()).or_insert_with(|| r.clone());
        }

        let mut live_bytes: HashMap<PackId, usize> = HashMap::new();
        for r in live.values() {
            *live_bytes.entry(r.pack_id.clone()).or_default() +=
                CHUNK_LEN_BYTES + r.length as usize;
        }

        // Two populations, handled differently.
        //
        // *Dead* — no live chunk points into it at all: wholly superseded, or
        // debris from a pass that wrote packs and crashed before committing.
        // Nothing references these, so they need no manifest rewrite and no
        // commit; they are simply unlinked.
        //
        // The pack holding the *current* manifest chunk has no live **data**
        // bytes and must never be swept on that basis — it is the store's root
        // pointer. It becomes collectable only once a newer manifest is
        // committed, which the rewrite path below handles explicitly.
        let dead: BTreeSet<PackId> = on_disk
            .iter()
            .filter(|id| live_bytes.get(*id).copied().unwrap_or(0) == 0)
            .filter(|id| *id != &sb.manifest.pack_id)
            .cloned()
            .collect();

        // *Sparse* — partly live, below the threshold. These need the full
        // four-step dance because their live chunks must survive.
        let sparse: BTreeSet<PackId> = on_disk
            .iter()
            .filter(|id| {
                let b = live_bytes.get(*id).copied().unwrap_or(0);
                b > 0 && (b as f64) / (capacity as f64) < COMPACT_LIVE_FRACTION
            })
            .cloned()
            .collect();

        // Convergence guard, and the real economics of this operation: **a pack
        // occupies `PACK_SIZE` on disk however little of it is live**, because
        // the padding is inside the AEAD. So rewriting one sparse pack
        // into one fresh pack reclaims exactly nothing — compaction pays only
        // when it ends with *fewer packs than it started with*. Without this
        // guard a store of small, fully-live files would also rewrite itself
        // into an identical shape on every pass, forever, since a sparsely
        // filled pack reads as "mostly dead" by capacity even when every byte
        // in it is live.
        //
        // The replacement count is the packs needed to hold the salvage; the
        // manifest rides along in the last of them when it fits, which is the
        // normal case (a manifest is small against 16 MiB).
        let salvage_bytes: usize = sparse.iter().filter_map(|id| live_bytes.get(id)).sum();
        let replacement_packs = salvage_bytes.div_ceil(capacity).max(1);
        let rewrite = replacement_packs < sparse.len();

        // Sweeping needs no commit — this is the crash-debris path. With no
        // rewrite it happens now; with one it waits until the rewrite has
        // committed, so a pass that fails retires nothing at all.
        let mut packs_retired = 0usize;
        if !rewrite {
            for pack_id in &dead {
                self.inner.delete_sealed(pack_id.as_path()).await?;
                packs_retired += 1;
            }
        }

        if !rewrite {
            return Ok(CompactSummary {
                packs_retired,
                packs_unadmitted,
                generation: Some(sb.generation),
                ..Default::default()
            });
        }
        let to_retire = sparse;

        // 1. Salvage. Chunks are read in offset order so each doomed pack is
        //    opened once. File content goes to content packs and everything
        //    else — segments — to index packs, so a compacted store keeps the
        //    split a device keeps the index by ([`CONTENT_PACK_PREFIX`]).
        let mut writer = PackWriter::new(Arc::clone(&self.inner), self.k_pack);
        let mut content = PackWriter::content(Arc::clone(&self.inner), self.k_pack);
        let mut moved: HashMap<String, PackChunkRef> = HashMap::new();
        let mut packs_rewritten = 0usize;
        for pack_id in &to_retire {
            let mut refs: Vec<&PackChunkRef> =
                live.values().filter(|r| &r.pack_id == pack_id).collect();
            if refs.is_empty() {
                continue;
            }
            refs.sort_by_key(|r| r.offset);
            let blob = self.inner.get_sealed(pack_id.as_path()).await?;
            let plaintext = open_pack(&self.k_pack, &blob)?;
            for r in refs {
                let framed = Self::framed_from_plaintext(&plaintext, r)?;
                let is_data = matches!(unframe_chunk(&framed), Ok((ChunkKind::Data, _)));
                let new_ref = if is_data {
                    content.push(framed, &r.digest).await?
                } else {
                    writer.push(framed, &r.digest).await?
                };
                moved.insert(r.digest.clone(), new_ref);
            }
            packs_rewritten += 1;
        }

        // Repoint: a chunk that moved takes its new ref, anything else keeps
        // the ref it had, because its pack survives this pass.
        let mut new_manifest = base_manifest.clone();
        for entry in new_manifest.files.values_mut() {
            for r in &mut entry.chunks {
                if let Some(new_ref) = moved.get(&r.digest) {
                    *r = new_ref.clone();
                }
            }
        }
        // Segments follow their chunks when salvage moves them. Losing a ref
        // here would orphan history as surely as deleting it.
        for r in &mut new_manifest.log {
            if let Some(new_ref) = moved.get(&r.digest) {
                *r = new_ref.clone();
            }
        }

        // Retained losing versions follow their chunks too. Keeping them
        // live above and then failing to repoint them here would leave the
        // manifest naming packs this pass is about to retire — the write would
        // survive collection and die of a stale reference instead.
        for entries in new_manifest.conflicts.values_mut() {
            for entry in entries.iter_mut() {
                for r in &mut entry.chunks {
                    if let Some(new_ref) = moved.get(&r.digest) {
                        *r = new_ref.clone();
                    }
                }
            }
        }
        // Kept versions follow their chunks, for the reason retained losers do.
        for entries in new_manifest.versions.values_mut() {
            for entry in entries.iter_mut() {
                for r in &mut entry.chunks {
                    if let Some(new_ref) = moved.get(&r.digest) {
                        *r = new_ref.clone();
                    }
                }
            }
        }

        // Same reason as the packing pass: the generation is stamped inside the
        // manifest before it is sealed, so a recovery scan can order it.
        let generation = sb.generation + 1;
        new_manifest.generation = generation;

        let manifest_framed = new_manifest.to_chunk()?;
        let manifest_digest = chunk_digest(&manifest_framed);
        let manifest_ref = writer.push(manifest_framed, &manifest_digest).await?;
        content.flush().await?;
        writer.flush().await?;
        let packs_written = writer.written.len() + content.written.len();


        // The liveness check against the failure mode that matters here.
        // If any surviving reference still points into a doomed pack, the
        // salvage was incomplete and the pass must not proceed.
        for (path, entry) in &new_manifest.files {
            for r in &entry.chunks {
                if to_retire.contains(&r.pack_id) {
                    return Err(ObjectStorageError::BackendError(format!(
                        "compaction refused: {path} still references pack {} slated for \
                         retirement; no pack retired",
                        r.pack_id
                    )));
                }
            }
        }
        for r in &new_manifest.log {
            if to_retire.contains(&r.pack_id) {
                return Err(ObjectStorageError::BackendError(format!(
                    "compaction refused: a history segment still points into pack {} slated \
                     for retirement; no pack retired",
                    r.pack_id
                )));
            }
        }
        for (path, entries) in &new_manifest.versions {
            for r in entries.iter().flat_map(|e| &e.chunks) {
                if to_retire.contains(&r.pack_id) {
                    return Err(ObjectStorageError::BackendError(format!(
                        "compaction refused: a kept version of {path} still references pack \
                         {} slated for retirement; no pack retired",
                        r.pack_id
                    )));
                }
            }
        }

        // 2. Verify — read the fresh packs back before anything is unlinked.
        let mut by_pack: BTreeMap<PackId, Vec<PackChunkRef>> = BTreeMap::new();
        for r in moved.values() {
            by_pack.entry(r.pack_id.clone()).or_default().push(r.clone());
        }
        by_pack
            .entry(manifest_ref.pack_id.clone())
            .or_default()
            .push(manifest_ref.clone());
        for (pack_id, refs) in &by_pack {
            let blob = self.inner.get_sealed(pack_id.as_path()).await?;
            let plaintext = open_pack(&self.k_pack, &blob)?;
            for r in refs {
                Self::framed_from_plaintext(&plaintext, r).map_err(|e| {
                    ObjectStorageError::BackendError(format!(
                        "compaction read-back failed, no pack retired: {e}"
                    ))
                })?;
            }
        }
        let readback = Manifest::from_chunk(&self.read_framed_chunk(&manifest_ref).await?)?;
        if readback != new_manifest {
            return Err(ObjectStorageError::BackendError(
                "compaction manifest read-back mismatch, no pack retired".into(),
            ));
        }

        // 3. Commit.
        commit_superblock(
            &*self.inner,
            &self.k_pack,
            &Superblock {
                version: 1,
                generation,
                manifest: manifest_ref,
            },
        )
        .await?;

        // 4. Durable; now — and only now — reclaim. The pack that held the
        //    superseded manifest goes too, if nothing live remains in it: it
        //    was spared the sweep above only because it was the root pointer,
        //    and the commit just replaced it.
        for pack_id in to_retire.iter().chain(&dead) {
            self.inner.delete_sealed(pack_id.as_path()).await?;
            packs_retired += 1;
        }
        let old_manifest_pack = &sb.manifest.pack_id;
        if live_bytes.get(old_manifest_pack).copied().unwrap_or(0) == 0
            && !to_retire.contains(old_manifest_pack)
        {
            self.inner.delete_sealed(old_manifest_pack.as_path()).await?;
            packs_retired += 1;
        }
        if let Err(e) = retire_superseded(&*self.inner, &self.k_pack).await {
            tracing::warn!(error = %e, "old superblock retirement failed; harmless, retried next pass");
        }

        *self.manifest_cache.lock().unwrap() =
            CacheState::Loaded(Some((generation, Arc::new(new_manifest))));

        Ok(CompactSummary {
            packs_rewritten,
            packs_written,
            packs_retired,
            chunks_kept: moved.len(),
            packs_unadmitted,
            generation: Some(generation),
        })
    }
}

/// Live fraction below which a pack is worth rewriting. A starting value:
/// append-mostly corpora (photos) rarely trip it, churny ones do so
/// regularly.
const COMPACT_LIVE_FRACTION: f64 = 0.5;

/// Default full-detail window: recent history stays segment-by-segment.
/// Apple's Time Machine keeps hourly backups for 24 hours before thinning, and
/// the same shape applies here — the last day is where a user actually reaches
/// for "undo".
pub const DEFAULT_KEEP_FULL_SECS: u64 = 24 * 60 * 60;

impl<S: LooseObjectSource + 'static> PackedObjectStorage<S> {
    // ── snapshotting ────────────────────────────────────────────────────────

    /// Collapse the log. See [`ObjectStorage::snapshot`] for the contract.
    ///
    /// The snapshot is written as an ordinary segment and appended like any
    /// other, then the live set is rewritten to `[snapshot] + retained tail`.
    /// Nothing is unlinked here: the subsumed segments simply stop being named
    /// by the manifest, which is what makes them collectable, and compaction
    /// reclaims their bytes on its own schedule. Separating "no longer live"
    /// from "bytes reclaimed" is the same discipline as verify-before-delete — the pass that
    /// decides something is dead is never the pass that deletes it.
    /// `record_rows` decides what happens to the record-changeset entries
    /// (`Entry::Record`) in the segments this pass subsumes:
    /// - `Some(rows)` — a **bounding** snapshot: drop the subsumed record entries
    ///   and emit `rows` (the caller's current merged record state) as the new
    ///   base, so record history stays bounded alongside objects.
    /// - `None` — **preserve**: carry every subsumed record entry forward
    ///   verbatim. This is the `purge` path — it erases one object path, and must
    ///   not discard the unrelated record history stored in the same log.
    async fn run_snapshot_pass(
        &self,
        keep_full_secs: u64,
        exclude: Option<&str>,
        record_rows: Option<&[Vec<u8>]>,
    ) -> ObjectStorageResult<Option<SnapshotSummary>> {
        let Some(log) = &self.log else {
            return Ok(None);
        };
        let Some(committed) = load_committed(&*self.inner, &self.k_pack).await? else {
            return Ok(None);
        };
        let base_gen = committed.base_generation();
        let mut manifest = committed.manifest;
        if manifest.log.is_empty() {
            return Ok(None);
        }

        // Read the log, keeping each segment beside the ref that names it so
        // the retained tail can be rebuilt without re-deriving digests.
        let mut segments: Vec<(PackChunkRef, Segment)> = Vec::with_capacity(manifest.log.len());
        for r in &manifest.log {
            let framed = self.read_framed_chunk(r).await?;
            segments.push((r.clone(), Segment::from_chunk(&log.k_log, &framed)?));
        }

        // A segment's time is the newest thing in it. Derived rather than
        // stamped on the segment, so the format needs no extra field to
        // support a retention policy that may yet change.
        let seg_at = |s: &Segment| s.entries.iter().map(|e| e.at()).max().unwrap_or(0);
        // Zero means "retain nothing", stated rather than derived: a horizon of
        // `now` would otherwise keep or drop a segment depending on whether its
        // timestamp landed in this second.
        let retained: Vec<(PackChunkRef, Segment)> = if keep_full_secs == 0 {
            Vec::new()
        } else {
            let horizon = now_secs().unwrap_or(0).saturating_sub(keep_full_secs);
            segments
                .iter()
                .filter(|(_, s)| seg_at(s) >= horizon)
                .cloned()
                .collect()
        };
        if retained.len() == segments.len() && exclude.is_none() {
            // Everything is inside the window; collapsing would discard
            // granularity and gain nothing.
            return Ok(Some(SnapshotSummary {
                segments_retained: retained.len(),
                generation: base_gen,
                ..Default::default()
            }));
        }

        // Replay everything, then express the result as a segment. Only live
        // paths are recorded; see the trait docs for why omitting old deletions
        // is safe.
        let state = crate::replay::replay(
            &segments
                .iter()
                .map(|(r, s)| (r.digest.clone(), s.clone()))
                .collect::<Vec<_>>(),
        );
        let generation = base_gen + 1;
        let mut snapshot = Segment::new(log.writer_did.clone(), generation);
        snapshot.snapshot = true;
        snapshot.parents = segments.iter().map(|(r, _)| r.digest.clone()).collect();
        // A file that keeps its versions is **carried, not collapsed**. Its
        // versions are named by the log's own entries — no second model — so a
        // snapshot that re-expressed its history as one live-state entry would
        // unname every version it keeps while its bytes stayed kept. Its
        // entries are carried forward verbatim below instead, and the union of
        // entries for that path is then exactly what it was before this pass:
        // replay is a function of that set, so it reaches the same answer.
        let kept: BTreeSet<String> = manifest
            .files
            .iter()
            .filter(|(p, e)| e.keep_versions && exclude != Some(p.as_str()))
            .map(|(p, _)| p.clone())
            .collect();
        for (path, v) in state.live() {
            if exclude == Some(path) || kept.contains(path) {
                continue;
            }
            snapshot.entries.push(HistoryEntry::ObjectWrite {
                path: path.to_string(),
                digest: v.digest.clone().unwrap_or_default(),
                size: v.size,
                // The snapshot *is* the base state, so its entries claim no
                // predecessor: nothing before it survives to be a parent.
                parent: None,
                at: v.at,
                // Nor where it came from, for the same reason. A file whose
                // written-from matters to a person keeps its versions, and its
                // entries are carried below rather than collapsed here.
                written_from: None,
            });
        }
        let files_captured = snapshot.entries.len()
            + kept
                .iter()
                .filter(|p| state.current.get(*p).is_some_and(|v| !v.is_delete()))
                .count();

        // Fold the record log into the same snapshot segment. The
        // subsumed segments' `Entry::Record` payloads would otherwise vanish when
        // they drop out of `manifest.log`, so either re-express them as the
        // caller's current merged state (bounding) or carry them verbatim
        // (preserving) — see this fn's docs and the trait's `snapshot`/`purge`.
        let subsumed = |segments: &[(PackChunkRef, Segment)]| -> Vec<Segment> {
            let retained_digests: std::collections::HashSet<&str> =
                retained.iter().map(|(r, _)| r.digest.as_str()).collect();
            segments
                .iter()
                .filter(|(r, _)| !retained_digests.contains(r.digest.as_str()))
                .map(|(_, s)| s.clone())
                .collect()
        };
        for seg in subsumed(&segments) {
            for entry in seg.entries {
                if entry.path().is_some_and(|p| kept.contains(p)) {
                    snapshot.entries.push(entry);
                }
            }
        }
        let records_captured = match record_rows {
            Some(rows) => {
                // Bounding: the caller's current merged state replaces the
                // subsumed record entries. Stamped `now`, as a fresh append is.
                let at = now_secs().unwrap_or(0);
                for payload in rows {
                    snapshot.entries.push(HistoryEntry::Record {
                        payload: payload.clone(),
                        at,
                    });
                }
                rows.len()
            }
            None => {
                // Preserve: re-emit each subsumed segment's record entries as they
                // stood, timestamp included — nothing about the records changes.
                let mut carried = 0;
                for seg in subsumed(&segments) {
                    for entry in seg.entries {
                        if matches!(entry, HistoryEntry::Record { .. }) {
                            snapshot.entries.push(entry);
                            carried += 1;
                        }
                    }
                }
                carried
            }
        };

        let mut writer = PackWriter::new(Arc::clone(&self.inner), self.k_pack);
        let framed = snapshot.to_chunk(&log.k_log)?;
        let digest = chunk_digest(&framed);
        let snapshot_ref = writer.push(framed, &digest).await?;

        if let Some(path) = exclude {
            manifest.files.remove(path);
            // A purge erases a path's entire history, and a kept version is
            // history with its bytes still attached.
            manifest.versions.remove(path);
        }
        manifest.generation = generation;
        manifest.log = std::iter::once(snapshot_ref.clone())
            .chain(retained.iter().map(|(r, _)| r.clone()))
            .collect();

        let manifest_framed = manifest.to_chunk()?;
        let manifest_digest = chunk_digest(&manifest_framed);
        let manifest_ref = writer.push(manifest_framed, &manifest_digest).await?;
        writer.flush().await?;

        // Verify before committing, on the same principle as every other pass:
        // a snapshot that does not read back would strand the history it claims
        // to have subsumed.
        let readback = Segment::from_chunk(&log.k_log, &self.read_framed_chunk(&snapshot_ref).await?)?;
        if readback != snapshot {
            return Err(ObjectStorageError::BackendError(
                "snapshot read-back mismatch, log left unchanged".into(),
            ));
        }
        let manifest_readback =
            Manifest::from_chunk(&self.read_framed_chunk(&manifest_ref).await?)?;
        if manifest_readback != manifest {
            return Err(ObjectStorageError::BackendError(
                "snapshot manifest read-back mismatch, log left unchanged".into(),
            ));
        }

        commit_superblock(
            &*self.inner,
            &self.k_pack,
            &Superblock {
                version: 1,
                generation,
                manifest: manifest_ref,
            },
        )
        .await?;
        if let Err(e) = retire_superseded(&*self.inner, &self.k_pack).await {
            tracing::warn!(error = %e, "old superblock retirement failed; harmless, retried next pass");
        }
        *self.manifest_cache.lock().unwrap() =
            CacheState::Loaded(Some((generation, Arc::new(manifest))));

        Ok(Some(SnapshotSummary {
            segments_subsumed: segments.len() - retained.len(),
            segments_retained: retained.len(),
            files_captured,
            records_captured,
            generation,
        }))
    }

    // ── log-driven reconciliation ───────────────────────────────────────────

    /// Everything the pack set holds that this store can read: segments and
    /// manifests, each with the digest naming it.
    ///
    /// Both are found the same way — by kind tag inside the pack seal — because
    /// a peer's replication delivers packs, not an index. Nothing tells us which
    /// chunks arrived; we look.
    #[allow(clippy::type_complexity)]
    async fn scan_log_and_manifests(
        &self,
        k_log: &[u8; 32],
    ) -> ObjectStorageResult<(Vec<(PackChunkRef, Segment)>, Vec<Manifest>)> {
        let mut segments = Vec::new();
        let mut manifests = Vec::new();
        for pack_id in self.listed_packs("scan").await?.0 {
            // A content pack holds neither a segment nor a manifest
            // (`CONTENT_PACK_PREFIX`), so it is not opened to look.
            if pack_id.is_content() {
                continue;
            }
            let Ok(blob) = self.inner.get_sealed(pack_id.as_path()).await else {
                continue;
            };
            let Ok(plaintext) = open_pack(&self.k_pack, &blob) else {
                continue;
            };
            for (cref, framed) in scan_chunks(&plaintext) {
                match unframe_chunk(framed) {
                    Ok((ChunkKind::HistorySegment, _)) => {
                        if let Ok(seg) = Segment::from_chunk(k_log, framed) {
                            segments.push((
                                PackChunkRef {
                                    pack_id: pack_id.clone(),
                                    offset: cref.offset,
                                    length: cref.length,
                                    digest: chunk_digest(framed),
                                },
                                seg,
                            ));
                        }
                    }
                    Ok((ChunkKind::Manifest, _)) => {
                        if let Ok(man) = Manifest::from_chunk(framed) {
                            manifests.push(man);
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok((segments, manifests))
    }

    /// Reconcile from the log. See [`ObjectStorage::reconcile`].
    async fn run_reconcile(&self) -> ObjectStorageResult<Option<ReconcileSummary>> {
        let Some(log) = &self.log else {
            return Ok(None);
        };
        // No superblock is not a reason to refuse: a device that has just
        // joined the fleet has no history of its own and everything to adopt
        // from the packs a peer shipped it. Starting from an empty base is what
        // makes bootstrap and steady-state the same code path.
        let (base_gen, mut manifest) =
            match load_committed(&*self.inner, &self.k_pack).await? {
                Some(c) => (c.base_generation(), c.manifest),
                None => (0, Manifest::new()),
            };

        let (segments, manifests) = self.scan_log_and_manifests(&log.k_log).await?;
        let known: BTreeSet<&str> = manifest.log.iter().map(|r| r.digest.as_str()).collect();
        let adopted = segments
            .iter()
            .filter(|(r, _)| !known.contains(r.digest.as_str()))
            .count();
        if adopted == 0 {
            return Ok(Some(ReconcileSummary {
                generation: (base_gen > 0).then_some(base_gen),
                ..Default::default()
            }));
        }

        // The union is the merge. Nothing is discarded and nothing loses, which
        // is why this converges where per-file LWW did not.
        let state = crate::replay::replay(
            &segments
                .iter()
                .map(|(r, seg)| (r.digest.clone(), seg.clone()))
                .collect::<Vec<_>>(),
        );

        // Where the bytes are: any manifest in the pack set that describes this
        // content will do, because a content id is content-addressed and a peer
        // materialising the same bytes produces the same entry.
        let mut by_content: HashMap<String, FileEntry> = HashMap::new();
        for m in &manifests {
            for entry in m.files.values() {
                by_content
                    .entry(entry.content_id())
                    .or_insert_with(|| entry.clone());
            }
        }

        let mut files: BTreeMap<String, FileEntry> = BTreeMap::new();
        let mut pending = 0usize;
        for (path, v) in state.live() {
            let Some(digest) = v.digest.as_deref() else {
                continue;
            };
            match by_content.get(digest) {
                Some(entry) => {
                    files.insert(path.to_string(), entry.clone());
                }
                // The log knows this path is current, but the pack carrying its
                // chunks has not arrived. Leaving it out is honest; inventing an
                // entry would produce a name that fails on read.
                None => pending += 1,
            }
        }

        // Keep the losing versions' chunks referenced, or compaction will
        // reclaim them and the retained `Version` will name bytes that are gone.
        // A loser whose pack has not arrived is skipped rather than invented —
        // the same honesty `pending` applies to current versions above.
        let mut retained: BTreeMap<String, Vec<FileEntry>> = BTreeMap::new();
        for (path, losers) in &state.conflicts {
            let mut entries = Vec::new();
            for v in losers {
                let Some(digest) = v.digest.as_deref() else {
                    continue;
                };
                if let Some(entry) = by_content.get(digest) {
                    entries.push(entry.clone());
                }
            }
            if !entries.is_empty() {
                retained.insert(path.clone(), entries);
            }
        }

        let paths_changed = files
            .iter()
            .filter(|(p, e)| {
                manifest.files.get(*p).map(|old| old.content_id()) != Some(e.content_id())
            })
            .count()
            + manifest.files.keys().filter(|p| !files.contains_key(*p)).count();

        let generation = base_gen + 1;
        // The switch is this device's fact about its file, and the log does not
        // carry it — so a replay rebuilds `files` without it, and it is carried
        // from the manifest this device already had. What a peer's write
        // superseded is kept the same way any write's is.
        let base = manifest.clone();
        manifest.files = files;
        keep_what_was_superseded(&base, &mut manifest);
        manifest.conflicts = retained;
        manifest.log = segments.iter().map(|(r, _)| r.clone()).collect();
        manifest.generation = generation;

        let mut writer = PackWriter::new(Arc::clone(&self.inner), self.k_pack);
        let manifest_framed = manifest.to_chunk()?;
        let manifest_digest = chunk_digest(&manifest_framed);
        let manifest_ref = writer.push(manifest_framed, &manifest_digest).await?;
        writer.flush().await?;

        let readback = Manifest::from_chunk(&self.read_framed_chunk(&manifest_ref).await?)?;
        if readback != manifest {
            return Err(ObjectStorageError::BackendError(
                "reconcile manifest read-back mismatch, state left unchanged".into(),
            ));
        }

        commit_superblock(
            &*self.inner,
            &self.k_pack,
            &Superblock {
                version: 1,
                generation,
                manifest: manifest_ref,
            },
        )
        .await?;
        if let Err(e) = retire_superseded(&*self.inner, &self.k_pack).await {
            tracing::warn!(error = %e, "old superblock retirement failed; harmless, retried next pass");
        }
        *self.manifest_cache.lock().unwrap() =
            CacheState::Loaded(Some((generation, Arc::new(manifest))));

        Ok(Some(ReconcileSummary {
            segments_adopted: adopted,
            paths_changed,
            paths_pending_content: pending,
            conflicts: state.conflicts.len(),
            generation: Some(generation),
        }))
    }

    // ── the record log seam ─────────────────────────────────────────────────

    /// Append record rows as one sealed segment. See
    /// [`ObjectStorage::append_record_segment`].
    ///
    /// A record-only commit: the manifest's file set is untouched and only its
    /// log grows. It mirrors the object producer inside the packing pass —
    /// same segment shape, same `seq = generation`, same seal — but is driven
    /// from above, because the object store cannot see a record write.
    async fn run_append_record_segment(
        &self,
        rows: &[Vec<u8>],
    ) -> ObjectStorageResult<Option<u64>> {
        let Some(log) = &self.log else {
            return Ok(None);
        };
        if rows.is_empty() {
            return Ok(None);
        }

        // An empty store is a valid base: a device can log records before it
        // has ever packed an object (bootstrap and steady state share a path).
        let (base_gen, mut manifest) =
            match load_committed(&*self.inner, &self.k_pack).await? {
                Some(c) => (c.base_generation(), c.manifest),
                None => (0, Manifest::new()),
            };
        let generation = base_gen + 1;

        let mut segment = Segment::new(log.writer_did.clone(), generation);
        segment.parents = manifest
            .log
            .last()
            .map(|r| r.digest.clone())
            .into_iter()
            .collect();
        let at = now_secs().unwrap_or(0);
        for payload in rows {
            segment.entries.push(HistoryEntry::Record {
                payload: payload.clone(),
                at,
            });
        }

        let mut writer = PackWriter::new(Arc::clone(&self.inner), self.k_pack);
        let framed = segment.to_chunk(&log.k_log)?;
        let digest = chunk_digest(&framed);
        let segment_ref = writer.push(framed, &digest).await?;
        manifest.log.push(segment_ref.clone());
        manifest.generation = generation;

        let manifest_framed = manifest.to_chunk()?;
        let manifest_digest = chunk_digest(&manifest_framed);
        let manifest_ref = writer.push(manifest_framed, &manifest_digest).await?;
        writer.flush().await?;

        // Verify both the segment and the manifest reopen before committing:
        // this is user history, and a superblock must never name a segment that
        // will not read back.
        Segment::from_chunk(&log.k_log, &self.read_framed_chunk(&segment_ref).await?)?;
        let readback = Manifest::from_chunk(&self.read_framed_chunk(&manifest_ref).await?)?;
        if readback != manifest {
            return Err(ObjectStorageError::BackendError(
                "record segment manifest read-back mismatch, state left unchanged".into(),
            ));
        }

        commit_superblock(
            &*self.inner,
            &self.k_pack,
            &Superblock {
                version: 1,
                generation,
                manifest: manifest_ref,
            },
        )
        .await?;
        if let Err(e) = retire_superseded(&*self.inner, &self.k_pack).await {
            tracing::warn!(error = %e, "old superblock retirement failed; harmless, retried next pass");
        }
        *self.manifest_cache.lock().unwrap() =
            CacheState::Loaded(Some((generation, Arc::new(manifest))));

        Ok(Some(generation))
    }

    /// Every record-carrying segment in the pack set, in `(writer, seq)` order.
    /// See [`ObjectStorage::scan_record_segments`].
    async fn run_scan_record_segments(&self) -> ObjectStorageResult<Vec<RecordSegmentView>> {
        let Some(log) = &self.log else {
            return Ok(Vec::new());
        };
        let (segments, _manifests) = self.scan_log_and_manifests(&log.k_log).await?;
        let mut out = Vec::new();
        for (_r, seg) in segments {
            let rows: Vec<Vec<u8>> = seg
                .entries
                .iter()
                .filter_map(|e| match e {
                    HistoryEntry::Record { payload, .. } => Some(payload.clone()),
                    _ => None,
                })
                .collect();
            if !rows.is_empty() {
                out.push(RecordSegmentView {
                    writer: seg.writer,
                    seq: seg.seq,
                    rows,
                });
            }
        }
        // Deterministic order so the record layer's per-writer high-water logic
        // sees each writer's segments in the sequence they were written.
        out.sort_by(|a, b| a.writer.cmp(&b.writer).then(a.seq.cmp(&b.seq)));
        Ok(out)
    }

    // ── scan recovery ───────────────────────────────────────────────────────

    /// Rebuild the superblock by scanning packs. See
    /// [`ObjectStorage::recover_by_scan`] for what this is for.
    ///
    /// The scan is deliberately forgiving about damage and strict about what it
    /// adopts. A pack that will not open is skipped rather than fatal — losing
    /// one pack must not cost the whole store — and candidates are tried newest
    /// generation first, so a corrupt newest manifest falls back to the last
    /// intact one rather than failing recovery outright. What it will not do is
    /// commit a manifest whose chunks are not all present and intact: adopting
    /// one would produce a store that opens and then fails on read, which is
    /// worse than reporting that nothing could be recovered.
    async fn run_scan_recovery(&self) -> ObjectStorageResult<Option<ScanRecovery>> {
        if load_current_superblock(&*self.inner, &self.k_pack)
            .await?
            .is_some()
        {
            // A working root pointer is authoritative; scanning could only
            // disagree with it.
            return Ok(None);
        }

        let (pack_ids, _) = self.listed_packs("scan recovery").await?;

        let mut packs_scanned = 0usize;
        let mut candidates: Vec<(Manifest, PackChunkRef)> = Vec::new();
        for pack_id in &pack_ids {
            let Ok(blob) = self.inner.get_sealed(pack_id.as_path()).await else {
                continue;
            };
            let Ok(plaintext) = open_pack(&self.k_pack, &blob) else {
                tracing::warn!(pack = %pack_id, "scan recovery: pack will not open, skipping");
                continue;
            };
            packs_scanned += 1;
            for (cref, framed) in scan_chunks(&plaintext) {
                if !matches!(unframe_chunk(framed), Ok((ChunkKind::Manifest, _))) {
                    continue;
                }
                let Ok(manifest) = Manifest::from_chunk(framed) else {
                    continue;
                };
                candidates.push((
                    manifest,
                    PackChunkRef {
                        pack_id: pack_id.clone(),
                        offset: cref.offset,
                        length: cref.length,
                        digest: chunk_digest(framed),
                    },
                ));
            }
        }

        let manifests_found = candidates.len();
        if candidates.is_empty() {
            return Ok(Some(ScanRecovery {
                packs_scanned,
                ..Default::default()
            }));
        }
        // Newest first. Ties break on the manifest chunk's digest so the choice
        // is deterministic across devices scanning the same pack set.
        candidates.sort_by(|a, b| {
            b.0.generation
                .cmp(&a.0.generation)
                .then_with(|| a.1.digest.cmp(&b.1.digest))
        });

        for (manifest, manifest_ref) in candidates {
            if !self.manifest_fully_resolves(&manifest).await {
                tracing::warn!(
                    generation = manifest.generation,
                    "scan recovery: manifest references missing or damaged chunks, trying older"
                );
                continue;
            }
            // Commit above whatever generation the adopted manifest claims, so
            // a later pass never reuses a generation this store has already
            // seen. Superblock keys carry a random suffix, so this cannot
            // collide with a peer's commit at the same number.
            let generation = manifest.generation.max(1);
            commit_superblock(
                &*self.inner,
                &self.k_pack,
                &Superblock {
                    version: 1,
                    generation,
                    manifest: manifest_ref,
                },
            )
            .await?;
            let files_recovered = manifest.files.len();
            *self.manifest_cache.lock().unwrap() =
                CacheState::Loaded(Some((generation, Arc::new(manifest))));
            return Ok(Some(ScanRecovery {
                packs_scanned,
                manifests_found,
                generation,
                files_recovered,
            }));
        }

        // Manifests were found and none was whole.
        Ok(Some(ScanRecovery {
            packs_scanned,
            manifests_found,
            ..Default::default()
        }))
    }

    /// Whether every chunk this manifest depends on opens and matches its
    /// recorded digest — the gate on adopting it.
    async fn manifest_fully_resolves(&self, manifest: &Manifest) -> bool {
        let mut by_pack: BTreeMap<PackId, Vec<PackChunkRef>> = BTreeMap::new();
        for entry in manifest.files.values() {
            for r in &entry.chunks {
                by_pack.entry(r.pack_id.clone()).or_default().push(r.clone());
            }
        }
        for (pack_id, refs) in &by_pack {
            let Ok(blob) = self.inner.get_sealed(pack_id.as_path()).await else {
                return false;
            };
            let Ok(plaintext) = open_pack(&self.k_pack, &blob) else {
                return false;
            };
            for r in refs {
                if Self::framed_from_plaintext(&plaintext, r).is_err() {
                    return false;
                }
            }
        }
        true
    }
}

// ── the tombstone set, reachable without a store handle ─────────────────────
//
// Free functions rather than methods because a live streaming sink has to clear
// a tombstone when it commits, and a sink is not a method of the store. The
// cache is passed in so both routes keep the same one warm — a sink that wrote
// the set and left the store's copy stale would make a deleted-then-rewritten
// path read as absent until something else invalidated it.

/// Sealed under `K_pack` with the storage key as AAD, like the superblock.
/// Not padded: this object is device-local working state that pack-level
/// sync will keep off the wire; until then its size discloses at most a
/// pending-delete count to a peer that already holds the ciphertext.
fn seal_tombstones(k_pack: &[u8; 32], tombs: &Tombstones) -> ObjectStorageResult<Vec<u8>> {
    let body = serde_json::to_vec(tombs).map_err(|e| {
        ObjectStorageError::BackendError(format!("tombstones serialize: {e}"))
    })?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let cipher = ChaCha20Poly1305::new(k_pack.into());
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &body,
                aad: TOMBSTONES_KEY.as_bytes(),
            },
        )
        .map_err(|_| ObjectStorageError::BackendError("tombstones seal failed".into()))?;
    let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

fn open_tombstones(k_pack: &[u8; 32], blob: &[u8]) -> ObjectStorageResult<Tombstones> {
    if blob.len() < NONCE_LEN {
        return Err(ObjectStorageError::BackendError(
            "tombstones blob too short".into(),
        ));
    }
    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
    let cipher = ChaCha20Poly1305::new(k_pack.into());
    let body = cipher
        .decrypt(
            Nonce::from_slice(nonce_bytes),
            Payload {
                msg: ciphertext,
                aad: TOMBSTONES_KEY.as_bytes(),
            },
        )
        .map_err(|_| {
            ObjectStorageError::BackendError("tombstones open failed (corrupt?)".into())
        })?;
    serde_json::from_slice(&body)
        .map_err(|e| ObjectStorageError::BackendError(format!("tombstones parse: {e}")))
}

/// The tombstone set, from the cache when it is warm.
async fn load_tombstones_from<S: SealedObjectAccess + ?Sized>(
    store: &S,
    k_pack: &[u8; 32],
    cache: &Mutex<Option<Arc<Tombstones>>>,
) -> ObjectStorageResult<Arc<Tombstones>> {
    if let Some(t) = &*cache.lock().unwrap() {
        return Ok(t.clone());
    }
    let loaded = match store.get_sealed(Path::new(TOMBSTONES_KEY)).await {
        Ok(blob) => Arc::new(open_tombstones(k_pack, &blob)?),
        Err(ObjectStorageError::NotFound(_)) => Arc::new(Tombstones::default()),
        Err(e) => return Err(e),
    };
    *cache.lock().unwrap() = Some(loaded.clone());
    Ok(loaded)
}

/// Persist the tombstone set; an empty set is deleted, not written.
async fn save_tombstones_to<S: SealedObjectAccess + ?Sized>(
    store: &S,
    k_pack: &[u8; 32],
    cache: &Mutex<Option<Arc<Tombstones>>>,
    tombs: &Tombstones,
) -> ObjectStorageResult<()> {
    if tombs.deleted.is_empty() {
        match store.delete_sealed(Path::new(TOMBSTONES_KEY)).await {
            Ok(()) | Err(ObjectStorageError::NotFound(_)) => {}
            Err(e) => return Err(e),
        }
    } else {
        let blob = seal_tombstones(k_pack, tombs)?;
        store.put_sealed(Path::new(TOMBSTONES_KEY), &blob).await?;
    }
    *cache.lock().unwrap() = Some(Arc::new(tombs.clone()));
    Ok(())
}

/// One framed chunk out of an opened pack's plaintext, checked against the
/// digest the sealed manifest records for it.
///
/// The digest check is what binds a chunk to its logical position: refs live in
/// the sealed manifest, so a replica that relocates or swaps pack bytes cannot
/// make this return the wrong chunk — the read fails instead.
///
/// A free function because both the store's methods and a live streaming sink
/// need it, and the sink is not a method of the store.
fn framed_from_plaintext(plaintext: &[u8], r: &PackChunkRef) -> ObjectStorageResult<Vec<u8>> {
    let framed = read_chunk_from_plaintext(
        plaintext,
        ChunkRef {
            offset: r.offset,
            length: r.length,
        },
    )?;
    if chunk_digest(&framed) != r.digest {
        return Err(ObjectStorageError::BackendError(format!(
            "chunk digest mismatch in {} at offset {} — corrupt or mis-addressed pack",
            r.pack_id, r.offset
        )));
    }
    Ok(framed)
}

/// Read one chunk by its manifest ref, opening the pack that holds it.
/// The committed state a store reads and builds on: the newest generation
/// whose superblock opens **and whose manifest decodes**.
///
/// A manifest that does not decode — one naming a pack outside the reserved
/// grammar ([`PackId`], kotton #273) — is sealed under the person's own key,
/// so a device of theirs wrote it, wrongly. Its generation is passed over as a
/// superblock that does not open is, and reported on the same channel, a
/// `warn` from `crate::superblock` naming the superblock's key and the
/// refusal: one bad ref costs the generation it is in, not the mount.
///
/// Only that refusal is passed over ([`ManifestDecodeError::PackIdRefused`]).
/// A manifest that is malformed, or of a version this code does not read,
/// fails the load as it always did: it may be a newer device's correct write,
/// and building past it would roll that device back. A manifest whose pack
/// cannot be *read* fails the load too; that says nothing about the
/// generation.
struct Committed {
    superblock: Superblock,
    manifest: Manifest,
    /// The newer generations passed over, newest first (`Adopted::passed_over`).
    passed_over: Vec<PassedOver>,
}

impl Committed {
    /// The generation a commit built on this state follows: the highest of the
    /// one adopted and those passed over above it (kotton #308). Numbered past
    /// a passed-over generation, a commit sorts above it by generation, not by
    /// the key tie-break.
    fn base_generation(&self) -> u64 {
        self.passed_over
            .iter()
            .map(|p| p.generation)
            .fold(self.superblock.generation, u64::max)
    }
}

async fn load_committed<S: SealedObjectAccess + ?Sized>(
    store: &S,
    k_pack: &[u8; 32],
) -> ObjectStorageResult<Option<Committed>> {
    let adopted = load_adopted_superblock(store, k_pack, |sb| async move {
        let framed = read_framed_chunk_from(store, k_pack, &sb.manifest).await?;
        match Manifest::decode(&framed) {
            Ok(manifest) => Ok(Ok(manifest)),
            Err(refused @ ManifestDecodeError::PackIdRefused(_)) => Ok(Err(refused.into())),
            Err(ManifestDecodeError::Malformed(e)) => Err(e),
        }
    })
    .await?;
    Ok(adopted.map(|a| Committed {
        superblock: a.superblock,
        manifest: a.state,
        passed_over: a.passed_over,
    }))
}

/// Whether the generation whose superblock is `key` is **held**: its
/// superblock opens and its manifest is refused for a pack id
/// ([`ManifestDecodeError::PackIdRefused`]). Returns the refusal if so.
///
/// A held generation's manifest may be the only one naming some packs, and
/// none of them can be read through it. So while it is present nothing that
/// deletes may run on the strength of the manifests that *do* decode:
/// compaction refuses, and retirement ([`retire_superseded`]) keeps its
/// superblock. A superblock that does not open, or whose manifest pack is
/// gone (a superseded generation whose manifest compaction already retired),
/// holds nothing. A read that fails otherwise is an error, not a "no".
async fn held_generation<S: SealedObjectAccess + ?Sized>(
    store: &S,
    k_pack: &[u8; 32],
    key: &str,
) -> ObjectStorageResult<Option<String>> {
    let Some(sb) = read_superblock(store, k_pack, key).await? else {
        return Ok(None);
    };
    let framed = match read_framed_chunk_from(store, k_pack, &sb.manifest).await {
        Ok(framed) => framed,
        Err(ObjectStorageError::NotFound(_)) => return Ok(None),
        Err(e) => return Err(e),
    };
    match Manifest::decode(&framed) {
        Err(refused @ ManifestDecodeError::PackIdRefused(_)) => Ok(Some(refused.to_string())),
        _ => Ok(None),
    }
}

/// Retire the superblocks a commit superseded (`retirable_superblocks`),
/// keeping any held generation ([`held_generation`]): its superblock is what
/// holds the packs only it names. Returns how many were deleted.
async fn retire_superseded<S: SealedObjectAccess + ?Sized>(
    store: &S,
    k_pack: &[u8; 32],
) -> ObjectStorageResult<usize> {
    let mut retired = 0usize;
    for key in retirable_superblocks(store).await? {
        if let Some(why) = held_generation(store, k_pack, &key).await? {
            tracing::warn!(%key, error = %why, "keeping a superblock generation whose manifest was refused");
            continue;
        }
        store.delete_sealed(Path::new(&key)).await?;
        retired += 1;
    }
    Ok(retired)
}

async fn read_framed_chunk_from<S: SealedObjectAccess + ?Sized>(
    store: &S,
    k_pack: &[u8; 32],
    r: &PackChunkRef,
) -> ObjectStorageResult<Vec<u8>> {
    let blob = store.get_sealed(r.pack_id.as_path()).await?;
    let plaintext = open_pack(k_pack, &blob)?;
    framed_from_plaintext(&plaintext, r)
}

/// Seal the history segment and the manifest, write out the packs, verify
/// everything the new state depends on, and commit the superblock.
///
/// This is the tail of every write that moves the store's root pointer, held in
/// one place because the ordering **is** the safety argument and
/// two copies of a safety argument are one copy and one liability. The batch
/// packing pass and the streaming ingest reach it by different routes and leave
/// through the same door: no name resolves to the new state until every chunk
/// it depends on has been read back out of a sealed pack and matched against
/// its digest, and the manifest has been parsed back into exactly what was
/// committed.
///
/// `written` names the paths this change writes and `deleted` the paths it
/// removes — together they are the history segment's contents and the set
/// verified before anything is deleted. `intact` says what a failure leaves untouched, because the caller
/// knows what it has not yet retired and this does not.
///
/// Returns the committed generation and how many packs were written.
#[allow(clippy::too_many_arguments)]
async fn commit_new_state<S: SealedObjectAccess + ?Sized>(
    store: &S,
    k_pack: &[u8; 32],
    log: Option<&LogWriter>,
    writer: &mut PackWriter<S>,
    base_manifest: &Manifest,
    new_manifest: &mut Manifest,
    base_gen: u64,
    written: &[String],
    deleted: &[(String, u64)],
    written_from: &BTreeMap<String, String>,
    intact: &str,
) -> ObjectStorageResult<(u64, usize)> {
    // Stamped before serialization so the sealed manifest carries the
    // generation it is about to be committed at — the only thing a recovery scan
    // can order manifests by once the superblock is gone.
    let generation = base_gen + 1;
    new_manifest.generation = generation;

    // The content this change wrote is sealed in its own packs, and the index
    // — the segment and the manifest — in packs of its own
    // ([`CONTENT_PACK_PREFIX`]), so a device can keep the index without the
    // content. `writer` may hold content chunks; the index writer holds none.
    writer.flush().await?;
    let mut index = PackWriter::new(Arc::clone(&writer.store), *k_pack);

    // The history segment for this change, appended before the
    // manifest so both land in the same pack when they fit.
    //
    // Deriving the segment from the change rather than from intercepting each
    // `put` is deliberate: the caller already knows exactly what changed and
    // what the previous state was, so the log costs no change to the ordinary
    // write path, which stays a plain durable object write.
    let segment_ref = match log {
        None => None,
        Some(log) => {
            // `seq` is the generation this segment is committed at.
            // Monotonic per writer, since a writer's own generations only
            // increase, and unique across writers because `(writer, seq)`
            // differs on the writer. Gaps are fine — the log asks for
            // monotonic, not gapless.
            let mut segment = Segment::new(log.writer_did.clone(), generation);
            segment.parents = base_manifest
                .log
                .last()
                .map(|r| r.digest.clone())
                .into_iter()
                .collect();

            for path in written {
                let entry = &new_manifest.files[path];
                let parent = base_manifest.files.get(path).map(|e| e.content_id());
                segment.entries.push(HistoryEntry::ObjectWrite {
                    path: path.clone(),
                    digest: entry.content_id(),
                    size: entry.size,
                    // A write that says where it came from is recorded as
                    // saying so — a restore does. Any other write was made from
                    // the version this store held when it landed, which is the
                    // one any writer reading the file would have opened.
                    written_from: written_from.get(path).cloned().or_else(|| parent.clone()),
                    parent,
                    at: entry.modified.or_else(now_secs).unwrap_or(0),
                });
            }
            for (path, at) in deleted {
                segment.entries.push(HistoryEntry::ObjectDelete {
                    path: path.clone(),
                    parent: base_manifest.files.get(path).map(|e| e.content_id()),
                    at: *at,
                });
            }

            let framed = segment.to_chunk(&log.k_log)?;
            let digest = chunk_digest(&framed);
            let r = index.push(framed, &digest).await?;
            new_manifest.log.push(r.clone());
            Some(r)
        }
    };

    // The manifest itself is the final chunk. Its refs to chunks in the
    // still-open pack are already fixed — offsets are assigned at push —
    // so there is no circularity in it landing in that same pack.
    let manifest_framed = new_manifest.to_chunk()?;
    let manifest_digest = chunk_digest(&manifest_framed);
    let manifest_ref = index.push(manifest_framed, &manifest_digest).await?;
    index.flush().await?;
    let packs_written = writer.written.len() + index.written.len();

    // Verify every chunk this change's files now depend on — including
    // reused ones, because retiring what they replace stakes those files on
    // them — plus the manifest chunk, before anything is deleted.
    let mut to_verify: BTreeMap<PackId, Vec<PackChunkRef>> = BTreeMap::new();
    for path in written {
        for r in &new_manifest.files[path].chunks {
            to_verify.entry(r.pack_id.clone()).or_default().push(r.clone());
        }
    }
    to_verify
        .entry(manifest_ref.pack_id.clone())
        .or_default()
        .push(manifest_ref.clone());
    // The segment is user history; it is verified before anything is retired,
    // exactly like the chunks the manifest depends on.
    if let Some(r) = &segment_ref {
        to_verify.entry(r.pack_id.clone()).or_default().push(r.clone());
    }
    for (pack_id, refs) in &to_verify {
        let blob = store.get_sealed(pack_id.as_path()).await?;
        let plaintext = open_pack(k_pack, &blob)?;
        for r in refs {
            framed_from_plaintext(&plaintext, r).map_err(|e| {
                ObjectStorageError::BackendError(format!(
                    "pack verification failed, {intact}: {e}"
                ))
            })?;
        }
    }
    // The manifest chunk must parse back to exactly what was committed.
    let readback =
        Manifest::from_chunk(&read_framed_chunk_from(store, k_pack, &manifest_ref).await?)?;
    if &readback != new_manifest {
        return Err(ObjectStorageError::BackendError(format!(
            "manifest read-back mismatch, {intact}"
        )));
    }

    commit_superblock(
        store,
        k_pack,
        &Superblock {
            version: 1,
            generation,
            manifest: manifest_ref,
        },
    )
    .await?;

    Ok((generation, packs_written))
}

/// One object being written as a stream, sealed into packs as it arrives.
///
/// # Why this is the pack layer's job and not a new format
///
/// A loose object is a single AEAD envelope: one nonce, one tag over the whole
/// plaintext. Nothing can be sealed until the last byte has arrived, and
/// nothing can be opened until the whole thing is read — which is the same
/// fact seen from the write side and the read side, and it is why
/// `MAX_SEALED_OBJECT_BYTES` was a bound on memory rather than on anything a
/// user would recognise.
///
/// The pack layer already stores an object as **independently-sealed pieces
/// with a sealed index**, because content-defined chunking needed that for
/// dedup and edit locality. A streaming ingest is that same machinery fed a
/// piece at a time instead of a file at a time: the bytes at rest are
/// byte-for-byte what a packing pass over the same object would have produced,
/// so nothing about the format on disk changes and nothing needs migrating.
/// What changes is *when* the packing happens for an object too large to hold.
///
/// # What bounds memory
///
/// One chunk being framed (at most `MAX_CHUNK`, 1 MiB), the chunker's buffer
/// (under `MAX_CHUNK`), and the open pack (at most `PACK_SIZE`, 16 MiB). None
/// of these is a function of the object's size.
struct PackStreamSink<S: LooseObjectSource + 'static> {
    store: Arc<S>,
    k_pack: [u8; 32],
    log: Option<Arc<LogWriter>>,
    manifest_cache: Arc<Mutex<CacheState>>,
    tombstone_cache: Arc<Mutex<Option<Arc<Tombstones>>>>,
    /// Canonical path this object commits to.
    path: String,
    chunker: crate::chunker::StreamChunker,
    /// `None` once committed, so a second commit is refused rather than
    /// silently committing an empty second generation.
    writer: Option<PackWriter<S>>,
    /// The object's chunks in order, as they are placed.
    chunks: Vec<PackChunkRef>,
    /// Chunks already placed **by this stream**, for self-dedup.
    ///
    /// Deliberately not seeded from the current manifest. Reusing a ref from an
    /// existing manifest is what the batch pass does and it is safe there
    /// because the pass is short; a stream carrying gigabytes is open long
    /// enough for a concurrent compaction to retire the pack the reused ref
    /// names, and the reader would then find a digest that resolves to nothing.
    /// Re-sealing bytes this stream has already seen costs disk and cannot
    /// dangle.
    seen: HashMap<String, PackChunkRef>,
    /// True size of everything pushed so far.
    size: u64,
}

impl<S: LooseObjectSource + 'static> PackStreamSink<S> {
    /// Place one content-defined chunk into the open pack.
    async fn place(&mut self, chunk: &[u8]) -> ObjectStorageResult<()> {
        let framed = frame_chunk(ChunkKind::Data, chunk);
        let digest = chunk_digest(&framed);
        let r = match self.seen.get(&digest) {
            Some(existing) => existing.clone(),
            None => {
                let writer = self.writer.as_mut().ok_or_else(|| {
                    ObjectStorageError::BackendError(
                        "streaming write used after it was committed".into(),
                    )
                })?;
                let r = writer.push(framed, &digest).await?;
                self.seen.insert(digest, r.clone());
                r
            }
        };
        self.chunks.push(r);
        Ok(())
    }
}

#[async_trait]
impl<S: LooseObjectSource + 'static> ObjectSink for PackStreamSink<S> {
    async fn push(&mut self, bytes: &[u8]) -> ObjectStorageResult<()> {
        self.size += bytes.len() as u64;
        for chunk in self.chunker.push(bytes) {
            self.place(&chunk).await?;
        }
        Ok(())
    }

    async fn commit(&mut self) -> ObjectStorageResult<()> {
        let mut chunker = std::mem::take(&mut self.chunker);
        for chunk in chunker.finish() {
            self.place(&chunk).await?;
        }
        let mut writer = self.writer.take().ok_or_else(|| {
            ObjectStorageError::BackendError("streaming write committed twice".into())
        })?;

        // The base is re-read here rather than remembered from `begin_stream`,
        // because a stream carrying gigabytes is open long enough for the store
        // to have moved underneath it. Building on the generation that is
        // current *now* is what makes a concurrent small write survive this
        // one, instead of being erased by a manifest assembled minutes ago.
        let (base_gen, base_manifest) =
            match load_committed(&*self.store, &self.k_pack).await? {
                Some(c) => (c.base_generation(), c.manifest),
                None => (0, Manifest::new()),
            };

        let mut new_manifest = base_manifest.clone();
        new_manifest.files.insert(
            self.path.clone(),
            FileEntry {
                size: self.size,
                modified: now_secs(),
                chunks: std::mem::take(&mut self.chunks),
                keep_versions: false,
            },
        );
        // A streamed write supersedes like any other: the file's switch decides
        // whether what it replaced is kept.
        keep_what_was_superseded(&base_manifest, &mut new_manifest);

        let written = [self.path.clone()];
        let (generation, _) = commit_new_state(
            &*self.store,
            &self.k_pack,
            self.log.as_deref(),
            &mut writer,
            &base_manifest,
            &mut new_manifest,
            base_gen,
            &written,
            &[],
            &BTreeMap::new(),
            "the object's previous version is untouched",
        )
        .await?;

        *self.manifest_cache.lock().unwrap() =
            CacheState::Loaded(Some((generation, Arc::new(new_manifest))));

        // Only now is the new content the answer at this path, so only now are
        // the two things that would still shadow it removed. Both run after the
        // commit, so the window between them serves the *old* version rather
        // than a mixture: a reader sees the previous bytes and then the new
        // ones, never neither.
        //
        // A tombstone would make the freshly packed file read as absent — reads
        // consult the tombstone set before the manifest — and a loose copy at
        // the same path would win over it outright, because a loose object is
        // normally the newer one. Here it is the older one.
        let tombs =
            load_tombstones_from(&*self.store, &self.k_pack, &self.tombstone_cache).await?;
        if tombs.deleted.contains_key(&self.path) {
            let mut updated = (*tombs).clone();
            updated.deleted.remove(&self.path);
            save_tombstones_to(&*self.store, &self.k_pack, &self.tombstone_cache, &updated)
                .await?;
        }
        match self.store.delete(Path::new(&self.path)).await {
            Ok(()) | Err(ObjectStorageError::NotFound(_)) => {}
            Err(e) => return Err(e),
        }

        if let Err(e) = retire_superseded(&*self.store, &self.k_pack).await {
            tracing::warn!(error = %e, "old superblock retirement failed; harmless, retried next pass");
        }
        Ok(())
    }
}

/// Fills packs and writes them out as they fill.
///
/// Owns its store handle rather than borrowing one, so a writer can outlive the
/// call that made it — which is what a streaming ingest needs and what a
/// batch pass does not care about either way.
struct PackWriter<S: SealedObjectAccess + ?Sized> {
    store: Arc<S>,
    k_pack: [u8; 32],
    /// Whether every pack this writer seals holds file content and nothing
    /// else — named under [`CONTENT_PACK_PREFIX`] — or may hold the index
    /// (a history segment, a manifest), named as every pack was before.
    content: bool,
    pack_id: PackId,
    group: Vec<Vec<u8>>,
    /// Σ (4-byte length prefix + framed chunk) for the open pack.
    payload: usize,
    written: Vec<PackId>,
}

/// Per-chunk length prefix width inside a pack (mirrors `pack.rs`).
const CHUNK_LEN_BYTES: usize = 4;

impl<S: SealedObjectAccess + ?Sized> PackWriter<S> {
    /// A writer of index packs: what it seals may hold a history segment or a
    /// manifest, and every device that reads the store fetches it.
    fn new(store: Arc<S>, k_pack: [u8; 32]) -> Self {
        Self {
            store,
            k_pack,
            content: false,
            pack_id: Self::fresh_id(false),
            group: Vec::new(),
            payload: 0,
            written: Vec::new(),
        }
    }

    /// A writer of content packs: file content and nothing else, which a
    /// device fetches only for what it keeps whole, or when a file is opened
    /// ([`is_content_pack`]).
    fn content(store: Arc<S>, k_pack: [u8; 32]) -> Self {
        Self { content: true, pack_id: Self::fresh_id(true), ..Self::new(store, k_pack) }
    }

    /// Random 128-bit pack id. Random rather than sequential so two devices
    /// packing independently can never write the same pack key (packs are
    /// immutable; a key collision would pit two contents against each other).
    /// A content pack's id carries [`CONTENT_PACK_PREFIX`]'s `c-`, which no
    /// index pack's hex id can begin with.
    fn fresh_id(content: bool) -> PackId {
        let mut id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut id);
        use std::fmt::Write as _;
        let mut s = String::with_capacity(PACK_PREFIX.len() + 2 + 2 * id.len());
        s.push_str(PACK_PREFIX);
        s.push('/');
        if content {
            s.push_str("c-");
        }
        for b in id {
            let _ = write!(s, "{b:02x}");
        }
        PackId::parse(&s).expect("a fresh pack id is in the reserved grammar by construction")
    }

    /// Append a framed chunk, sealing the open pack first if it would not
    /// fit. Returns the chunk's final ref — offsets are assigned at push and
    /// never change, which is what lets the manifest reference chunks in the
    /// pack it will itself land in.
    async fn push(&mut self, framed: Vec<u8>, digest: &str) -> ObjectStorageResult<PackChunkRef> {
        let need = CHUNK_LEN_BYTES + framed.len();
        if need > crate::pack::max_payload() {
            return Err(ObjectStorageError::BackendError(format!(
                "a single chunk of {} bytes exceeds pack capacity — for a manifest \
                 chunk this means the store has outgrown the single-chunk manifest \
                 (a known RFC-0045 limit; the manifest needs splitting before this \
                 store can pack)",
                framed.len()
            )));
        }
        if self.payload + need > crate::pack::max_payload() {
            self.flush().await?;
        }
        let r = PackChunkRef {
            pack_id: self.pack_id.clone(),
            offset: self.payload as u32,
            length: framed.len() as u32,
            digest: digest.to_string(),
        };
        self.payload += need;
        self.group.push(framed);
        Ok(r)
    }

    /// Seal and write the open pack, if it holds anything.
    async fn flush(&mut self) -> ObjectStorageResult<()> {
        if self.group.is_empty() {
            return Ok(());
        }
        let chunks: Vec<&[u8]> = self.group.iter().map(|c| c.as_slice()).collect();
        // An index pack whose index fits the smaller size is sealed at it
        // (`crate::pack::INDEX_PACK_SIZE`); content, and an index that does
        // not fit, at the full size.
        let size = if !self.content && self.payload <= crate::pack::max_payload_of(crate::pack::INDEX_PACK_SIZE) {
            crate::pack::INDEX_PACK_SIZE
        } else {
            crate::pack::PACK_SIZE
        };
        let (blob, refs) = crate::pack::seal_pack_sized(&self.k_pack, &chunks, size)?;

        // The refs handed out by `push` must be exactly what the sealer
        // produced — a divergence would mean every ref in the manifest is a
        // lie, so it is checked for real, not debug-asserted.
        let mut expect = 0u32;
        for (r, chunk) in refs.iter().zip(&self.group) {
            if r.offset != expect || r.length as usize != chunk.len() {
                return Err(ObjectStorageError::BackendError(
                    "pack layout diverged from planned chunk refs".into(),
                ));
            }
            expect += (CHUNK_LEN_BYTES + chunk.len()) as u32;
        }

        self.store.put_sealed(self.pack_id.as_path(), &blob).await?;
        self.written
            .push(std::mem::replace(&mut self.pack_id, Self::fresh_id(self.content)));
        self.group.clear();
        self.payload = 0;
        Ok(())
    }
}

/// Current Unix time in seconds, for tombstones and manifest entries whose
/// backing store tracks no timestamp.
fn now_secs() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// Recovering the only copy: the versions a concurrent write retained, and their bytes.
///
/// `replay()` keeps a losing `Version` and `reconcile` keeps its chunks, but a
/// retained version nobody can read is retained in name only. These are the two
/// calls that make the retention mean something to a user.
impl<S: LooseObjectSource + 'static> PackedObjectStorage<S> {
    /// Paths that have retained losing versions, with each version's content id.
    ///
    /// The content id is the handle for [`Self::read_retained`]; it is a digest
    /// rather than an index so it stays valid as other conflicts resolve.
    pub async fn retained_conflicts(&self) -> ObjectStorageResult<BTreeMap<String, Vec<String>>> {
        let Some((_, manifest)) = self.manifest().await? else {
            return Ok(BTreeMap::new());
        };
        Ok(manifest
            .conflicts
            .iter()
            .map(|(path, entries)| {
                (
                    path.clone(),
                    entries.iter().map(|e| e.content_id().to_string()).collect(),
                )
            })
            .collect())
    }

    /// Settle a conflict on `key`: promote a retained version if asked, then
    /// release what was being retained.
    ///
    /// Promotion is an ordinary `put`, deliberately. The resolution then enters
    /// the history as a write whose parent is the version it replaced, so it
    /// replays on another device as a decision rather than a reversal — and it
    /// needs no merge-state format of its own.
    pub async fn resolve_conflict(&self, key: &Path, keep: Option<&str>) -> ObjectStorageResult<()> {
        let canon = Self::canon(key);
        if let Some(content_id) = keep {
            let bytes = self.read_retained(key, content_id).await?;
            self.put(key, &bytes).await?;
        }

        // Release after the promotion, so a failure above leaves the retained
        // version exactly where it was rather than dropping it half-resolved.
        let Some((generation, manifest)) = self.manifest().await? else {
            return Ok(());
        };
        let mut manifest = (*manifest).clone();
        if manifest.conflicts.remove(&canon).is_none() {
            return Ok(());
        }
        self.commit_manifest(manifest, generation, "conflict resolution").await
    }

    /// Commit a manifest that changes no file's bytes — a released conflict, a
    /// switch turned on or off — as the next generation after `base_gen`.
    ///
    /// Same commit sequence every other pass uses: seal, read back, then point
    /// the superblock at it. A change that did not read back could release a
    /// retained version into a manifest nobody can load.
    async fn commit_manifest(
        &self,
        mut manifest: Manifest,
        base_gen: u64,
        what: &str,
    ) -> ObjectStorageResult<()> {
        let generation = base_gen + 1;
        manifest.generation = generation;
        let mut writer = PackWriter::new(Arc::clone(&self.inner), self.k_pack);
        let framed = manifest.to_chunk()?;
        let digest = chunk_digest(&framed);
        let manifest_ref = writer.push(framed, &digest).await?;
        writer.flush().await?;

        let readback = Manifest::from_chunk(&self.read_framed_chunk(&manifest_ref).await?)?;
        if readback != manifest {
            return Err(ObjectStorageError::BackendError(format!(
                "{what} manifest read-back mismatch, state left unchanged"
            )));
        }

        commit_superblock(
            &*self.inner,
            &self.k_pack,
            &Superblock {
                version: 1,
                generation,
                manifest: manifest_ref,
            },
        )
        .await?;
        if let Err(e) = retire_superseded(&*self.inner, &self.k_pack).await {
            tracing::warn!(error = %e, "old superblock retirement failed; harmless, retried next pass");
        }
        *self.manifest_cache.lock().unwrap() =
            CacheState::Loaded(Some((generation, Arc::new(manifest))));
        Ok(())
    }

    /// The bytes of one retained losing version of `key`.
    pub async fn read_retained(&self, key: &Path, content_id: &str) -> ObjectStorageResult<Bytes> {
        let canon = Self::canon(key);
        let Some((_, manifest)) = self.manifest().await? else {
            return Err(ObjectStorageError::NotFound(canon));
        };
        let entry = manifest
            .conflicts
            .get(&canon)
            .and_then(|entries| entries.iter().find(|e| e.content_id() == content_id))
            .ok_or_else(|| ObjectStorageError::NotFound(canon.clone()))?;
        self.read_packed_file(entry).await
    }
}

/// What a write superseded, kept where the file keeps its versions and released
/// where it does not: a file keeps its versions when the person asks.
///
/// `next` is the state a pass is about to commit and `base` the state it built
/// on; `next.files` is already what the pass decided. This settles the two
/// things that follow from it and nothing else: each file's switch, carried from
/// `base` because the switch is the file's and a write does not change it, and
/// `next.versions`, rebuilt from `base.versions` plus whatever a kept file's
/// write superseded.
///
/// One function for every pass that moves `files` — the packing pass, the
/// streaming ingest and reconciliation — because *what a superseding write
/// keeps* is one rule, and three copies of it are how a kept version would
/// quietly go dead on only one of the three paths.
///
/// A path that is no longer in `next.files` is released: the switch is a fact
/// about the file, and a deleted file has none. Its bytes stay until compaction,
/// like any other dead chunk.
fn keep_what_was_superseded(base: &Manifest, next: &mut Manifest) {
    let mut versions: BTreeMap<String, Vec<FileEntry>> = BTreeMap::new();
    for (path, entry) in next.files.iter_mut() {
        // Entries rebuilt from elsewhere — reconciliation takes them from any
        // manifest holding the same content — carry whatever switch that
        // manifest's path had. The switch is this path's, so it is set here and
        // only here.
        entry.keep_versions = false;
        let Some(before) = base.files.get(path) else {
            continue;
        };
        if !before.keep_versions {
            continue;
        }
        entry.keep_versions = true;
        let now = entry.content_id();
        let was = before.content_id();
        let mut kept = base.versions.get(path).cloned().unwrap_or_default();
        // The current content is not a version of itself — a restore makes an
        // old version current again, and it leaves this set until something
        // supersedes it once more.
        kept.retain(|e| e.content_id() != now);
        if was != now && !kept.iter().any(|e| e.content_id() == was) {
            let mut superseded = before.clone();
            superseded.keep_versions = false;
            kept.push(superseded);
        }
        if !kept.is_empty() {
            versions.insert(path.clone(), kept);
        }
    }
    next.versions = versions;
}

/// The content id `bytes` would have once packed — the same value
/// [`FileEntry::content_id`] reports for them, computed without packing.
///
/// For a loose write, whose content has no manifest entry yet: the versions a
/// file lists leave out the one it currently holds, and while a write is loose
/// the only way to know which that is, is to ask the bytes.
fn content_id_of(bytes: &[u8]) -> String {
    let digests: Vec<String> = chunk_boundaries(bytes)
        .into_iter()
        .map(|(off, len)| chunk_digest(&frame_chunk(ChunkKind::Data, &bytes[off..off + len])))
        .collect();
    crate::manifest::content_id_of_digests(digests.iter().map(String::as_str))
}

/// A file's versions.
///
/// **The log names them; the manifest keeps them.** A version is an
/// `ObjectWrite` entry the history log already holds — its content id, its size
/// and its moment — and it is listed only while `Manifest::versions` (or the
/// file's own entry, see [`versions`](Self::versions)) still holds the chunks to
/// read it back. There is no second model: nothing here stores a version,
/// names one, or orders one by anything but time.
impl<S: LooseObjectSource + 'static> PackedObjectStorage<S> {
    /// Turn `key`'s switch on or off. See [`SealedObjectAccess::set_keep_versions`].
    ///
    /// A file written but not yet packed has no entry in the tree, so there is
    /// nothing for the switch to sit beside; it is packed first, which is the
    /// pass maintenance would have run on it anyway. Off releases what was kept
    /// in the same commit that turns the switch off, and compaction reclaims it.
    pub async fn set_keep_versions(&self, key: &Path, on: bool) -> ObjectStorageResult<()> {
        let canon = Self::canon(key);
        if self.log.is_none() {
            return Err(ObjectStorageError::BackendError(format!(
                "{canon}: this store keeps no history, so it has nothing to name a version by"
            )));
        }
        if self.load_tombstones().await?.deleted.contains_key(&canon) {
            return Err(ObjectStorageError::NotFound(canon));
        }
        let in_tree = |m: &Option<(u64, Arc<Manifest>)>| {
            m.as_ref().is_some_and(|(_, m)| m.files.contains_key(&canon))
        };
        let mut state = self.manifest().await?;
        if !in_tree(&state) {
            match self.inner.metadata(key).await {
                Ok(_) => {
                    self.run_pack_pass().await?;
                    state = self.manifest().await?;
                }
                Err(ObjectStorageError::NotFound(_)) => {
                    return Err(ObjectStorageError::NotFound(canon))
                }
                Err(e) => return Err(e),
            }
        }
        let Some((generation, manifest)) = state else {
            return Err(ObjectStorageError::NotFound(canon));
        };
        let mut manifest = (*manifest).clone();
        let entry = manifest
            .files
            .get_mut(&canon)
            .ok_or_else(|| ObjectStorageError::NotFound(canon.clone()))?;
        if entry.keep_versions == on {
            return Ok(());
        }
        entry.keep_versions = on;
        if !on {
            manifest.versions.remove(&canon);
        }
        self.commit_manifest(manifest, generation, "keep-versions switch").await
    }

    /// Whether `key` keeps its versions.
    pub async fn keeps_versions(&self, key: &Path) -> ObjectStorageResult<bool> {
        let canon = Self::canon(key);
        if self.load_tombstones().await?.deleted.contains_key(&canon) {
            return Ok(false);
        }
        Ok(self
            .manifest()
            .await?
            .and_then(|(_, m)| m.files.get(&canon).map(|e| e.keep_versions))
            .unwrap_or(false))
    }

    /// Every entry that can be read back as a prior version of `canon`, by
    /// content id, and the content id of what the file holds now.
    ///
    /// Two sources. The kept set is the obvious one. The other is the file's
    /// own packed entry **while a newer write is still loose**: that entry is
    /// already *before this write*, the log already names it, and the pass that
    /// will move it into the kept set has simply not run yet. Leaving it out
    /// would make the version a person most wants — the one before the edit
    /// they just regretted — the one they cannot reach until maintenance runs.
    async fn readable_versions(
        &self,
        key: &Path,
    ) -> ObjectStorageResult<(BTreeMap<String, FileEntry>, Option<String>)> {
        let canon = Self::canon(key);
        let mut readable = BTreeMap::new();
        if self.load_tombstones().await?.deleted.contains_key(&canon) {
            return Ok((readable, None));
        }
        let Some((_, manifest)) = self.manifest().await? else {
            return Ok((readable, None));
        };
        let Some(entry) = manifest.files.get(&canon) else {
            return Ok((readable, None));
        };
        if !entry.keep_versions {
            return Ok((readable, Some(entry.content_id())));
        }
        for kept in manifest.versions.get(&canon).into_iter().flatten() {
            readable.insert(kept.content_id(), kept.clone());
        }
        let current = match self.inner.get(key).await {
            Ok(loose) => {
                readable.insert(entry.content_id(), entry.clone());
                content_id_of(&loose)
            }
            Err(ObjectStorageError::NotFound(_)) => entry.content_id(),
            Err(e) => return Err(e),
        };
        readable.remove(&current);
        Ok((readable, Some(current)))
    }

    /// `key`'s prior versions, newest first. See [`SealedObjectAccess::versions`].
    pub async fn versions(&self, key: &Path) -> ObjectStorageResult<Vec<FileVersion>> {
        let Some(log) = &self.log else {
            return Ok(Vec::new());
        };
        let canon = Self::canon(key);
        let (readable, _) = self.readable_versions(key).await?;
        if readable.is_empty() {
            return Ok(Vec::new());
        }
        let Some((_, manifest)) = self.manifest().await? else {
            return Ok(Vec::new());
        };
        // The log is read, not a list kept beside it: each version is the entry
        // that wrote it. One content written twice — a restore, or a write
        // that happened to reproduce an old version — is one version, reached
        // by the latest moment it was written.
        //
        // Grouped by pack so each is opened once: segments from a run of passes
        // share packs once compaction has merged them, and opening a 16 MiB pack
        // per segment would make listing a file's versions cost the log's length
        // in whole-pack decryptions.
        let mut by_pack: BTreeMap<&PackId, Vec<&PackChunkRef>> = BTreeMap::new();
        for r in &manifest.log {
            by_pack.entry(&r.pack_id).or_default().push(r);
        }
        let mut segments: Vec<Segment> = Vec::with_capacity(manifest.log.len());
        for (pack_id, refs) in by_pack {
            let blob = self.inner.get_sealed(pack_id.as_path()).await?;
            let plaintext = open_pack(&self.k_pack, &blob)?;
            for r in refs {
                segments.push(Segment::from_chunk(
                    &log.k_log,
                    &framed_from_plaintext(&plaintext, r)?,
                )?);
            }
        }
        let mut by_content: BTreeMap<String, FileVersion> = BTreeMap::new();
        for segment in segments {
            for entry in segment.entries {
                let HistoryEntry::ObjectWrite {
                    path,
                    digest,
                    size,
                    at,
                    written_from,
                    ..
                } = entry
                else {
                    continue;
                };
                if path != canon || !readable.contains_key(&digest) {
                    continue;
                }
                let v = by_content.entry(digest.clone()).or_insert(FileVersion {
                    content_id: digest,
                    size,
                    at,
                    written_from: written_from.clone(),
                });
                if at > v.at {
                    v.at = at;
                    v.written_from = written_from;
                }
            }
        }
        let mut out: Vec<FileVersion> = by_content.into_values().collect();
        out.sort_by(|a, b| b.at.cmp(&a.at).then_with(|| a.content_id.cmp(&b.content_id)));
        Ok(out)
    }

    /// The generation at which `key`'s current version entered the log. See
    /// [`SealedObjectAccess::logged`].
    ///
    /// **Loose first, and loose is `None`.** A write lands loose and a loose
    /// object shadows its packed version, so while one is present the current
    /// version is that write — durable, and in no segment. Only once a packing
    /// pass has committed it is the manifest's entry current, and only then is
    /// the log read: newest segment first, stopping at the first that records
    /// this content at this path, so the common case — a write the last pass
    /// committed — opens one chunk rather than the log's length of them.
    pub async fn logged(&self, key: &Path) -> ObjectStorageResult<Option<u64>> {
        let Some(log) = &self.log else {
            return Ok(None);
        };
        let canon = Self::canon(key);
        if self.load_tombstones().await?.deleted.contains_key(&canon) {
            return Ok(None);
        }
        match self.inner.metadata(key).await {
            Ok(_) => return Ok(None),
            Err(ObjectStorageError::NotFound(_)) => {}
            Err(e) => return Err(e),
        }
        let Some((_, manifest)) = self.manifest().await? else {
            return Ok(None);
        };
        let Some(entry) = manifest.files.get(&canon) else {
            return Ok(None);
        };
        let current = entry.content_id();
        for r in manifest.log.iter().rev() {
            let segment = Segment::from_chunk(&log.k_log, &self.read_framed_chunk(r).await?)?;
            let records_it = segment.entries.iter().any(|e| {
                matches!(e, HistoryEntry::ObjectWrite { path, digest, .. }
                    if *path == canon && *digest == current)
            });
            if records_it {
                return Ok(Some(segment.seq));
            }
        }
        Ok(None)
    }

    /// The bytes of one prior version of `key`. See [`SealedObjectAccess::read_version`].
    pub async fn read_version(&self, key: &Path, content_id: &str) -> ObjectStorageResult<Bytes> {
        let (readable, _) = self.readable_versions(key).await?;
        let entry = readable
            .get(content_id)
            .ok_or_else(|| ObjectStorageError::NotFound(Self::canon(key)))?;
        self.read_packed_file(entry).await
    }

    /// Restore a prior version of `key`. See [`SealedObjectAccess::restore_version`].
    ///
    /// **A new write, committed now, that reuses the version's chunks.** It
    /// appends one `ObjectWrite` naming the version it supersedes as its parent
    /// and the version it restores as where it was written from, and the
    /// superseded version is kept like any other. No chunk is re-sealed: the
    /// restored content is the kept entry's chunks, so a restore costs a
    /// segment and a manifest, never a second copy of the bytes.
    ///
    /// An edit still loose is packed first. Otherwise the restore would
    /// overwrite it before any pass had made it a version — the one write a
    /// person restoring after a bad edit might yet want to look at again.
    pub async fn restore_version(&self, key: &Path, content_id: &str) -> ObjectStorageResult<()> {
        let canon = Self::canon(key);
        match self.inner.metadata(key).await {
            Ok(_) => {
                self.run_pack_pass().await?;
            }
            Err(ObjectStorageError::NotFound(_)) => {}
            Err(e) => return Err(e),
        }
        let not_found = || ObjectStorageError::NotFound(canon.clone());
        let (base_gen, base) = self.manifest().await?.ok_or_else(not_found)?;
        let current = base.files.get(&canon).ok_or_else(not_found)?;
        if !current.keep_versions {
            return Err(not_found());
        }
        let kept = base
            .versions
            .get(&canon)
            .and_then(|kept| kept.iter().find(|e| e.content_id() == content_id))
            .ok_or_else(not_found)?;

        let mut next = (*base).clone();
        next.files.insert(
            canon.clone(),
            FileEntry {
                size: kept.size,
                modified: now_secs(),
                chunks: kept.chunks.clone(),
                keep_versions: true,
            },
        );
        keep_what_was_superseded(&base, &mut next);
        let mut writer = PackWriter::new(Arc::clone(&self.inner), self.k_pack);
        let (generation, _) = commit_new_state(
            &*self.inner,
            &self.k_pack,
            self.log.as_deref(),
            &mut writer,
            &base,
            &mut next,
            base_gen,
            std::slice::from_ref(&canon),
            &[],
            &BTreeMap::from([(canon.clone(), content_id.to_owned())]),
            "the current version is untouched",
        )
        .await?;
        *self.manifest_cache.lock().unwrap() =
            CacheState::Loaded(Some((generation, Arc::new(next))));
        if let Err(e) = retire_superseded(&*self.inner, &self.k_pack).await {
            tracing::warn!(error = %e, "old superblock retirement failed; harmless, retried next pass");
        }
        Ok(())
    }

    /// Distinct chunks the kept versions hold that nothing else live does, by
    /// digest, with their content length — the bytes the switch is costing.
    fn cost_of<'a>(
        manifest: &Manifest,
        kept: impl Iterator<Item = &'a FileEntry>,
    ) -> u64 {
        let mut elsewhere: BTreeSet<&str> = BTreeSet::new();
        for r in manifest
            .files
            .values()
            .chain(manifest.conflicts.values().flatten())
            .flat_map(|e| &e.chunks)
        {
            elsewhere.insert(r.digest.as_str());
        }
        let mut counted: BTreeMap<String, u64> = BTreeMap::new();
        for r in kept.flat_map(|e| &e.chunks) {
            if !elsewhere.contains(r.digest.as_str()) {
                // The framed length carries the one-byte kind tag; what the
                // person stored is the rest.
                counted.insert(r.digest.clone(), u64::from(r.length.saturating_sub(1)));
            }
        }
        counted.values().sum()
    }

    /// What `key`'s kept versions cost. See [`SealedObjectAccess::versions_cost`].
    pub async fn versions_cost(&self, key: &Path) -> ObjectStorageResult<u64> {
        let canon = Self::canon(key);
        let Some((_, manifest)) = self.manifest().await? else {
            return Ok(0);
        };
        Ok(Self::cost_of(
            &manifest,
            manifest.versions.get(&canon).into_iter().flatten(),
        ))
    }

    /// What every kept version in the store costs together.
    pub async fn versions_cost_total(&self) -> ObjectStorageResult<u64> {
        let Some((_, manifest)) = self.manifest().await? else {
            return Ok(0);
        };
        Ok(Self::cost_of(&manifest, manifest.versions.values().flatten()))
    }
}

#[async_trait]
impl<S: LooseObjectSource + 'static> ObjectStorage for PackedObjectStorage<S> {
    /// Loose first — a rewrite shadows its packed version — then the manifest.
    async fn get(&self, key: &Path) -> ObjectStorageResult<Bytes> {
        match self.inner.get(key).await {
            Ok(data) => return Ok(data),
            Err(ObjectStorageError::NotFound(_)) => {}
            Err(e) => return Err(e),
        }
        let canon = Self::canon(key);
        let not_found = || ObjectStorageError::NotFound(canon.clone());

        if self.load_tombstones().await?.deleted.contains_key(&canon) {
            return Err(not_found());
        }
        let Some((_, manifest)) = self.manifest().await? else {
            return Err(not_found());
        };
        let entry = manifest.files.get(&canon).ok_or_else(not_found)?;
        self.read_packed_file(entry).await
    }

    /// Loose first, then the manifest — and only the chunks the range touches.
    ///
    /// The loose side has no interior to read into: a loose object is one AEAD
    /// envelope, so serving a range of it means opening all of it. That is the
    /// inherited default and it is right for what is loose, because what is
    /// loose is what arrived small enough to hold. Anything large enough for
    /// the difference to matter came in through [`begin_stream`] and is packed.
    ///
    /// [`begin_stream`]: ObjectStorage::begin_stream
    async fn get_range(
        &self,
        key: &Path,
        offset: u64,
        length: u64,
    ) -> ObjectStorageResult<(Bytes, u64)> {
        match self.inner.get_range(key, offset, length).await {
            Ok(found) => return Ok(found),
            Err(ObjectStorageError::NotFound(_)) => {}
            Err(e) => return Err(e),
        }
        let canon = Self::canon(key);
        let not_found = || ObjectStorageError::NotFound(canon.clone());

        if self.load_tombstones().await?.deleted.contains_key(&canon) {
            return Err(not_found());
        }
        let Some((_, manifest)) = self.manifest().await? else {
            return Err(not_found());
        };
        let entry = manifest.files.get(&canon).ok_or_else(not_found)?;
        let bytes = self.read_packed_range(entry, offset, length).await?;
        Ok((bytes, entry.size))
    }

    /// Writes always land loose (the loose-then-pack model).
    async fn put(&self, key: &Path, data: &[u8]) -> ObjectStorageResult<()> {
        self.inner.put(key, data).await
    }

    /// A streaming write goes **straight into packs**, skipping the loose stage.
    ///
    /// Loose-then-pack exists so that an ordinary write is one durable object
    /// write and nothing more, with the chunking paid later in a batch. It is
    /// the right trade for a note. It is not available for an object that
    /// cannot be held in memory, because the loose stage *is* holding it in
    /// memory — so for those the packing is not deferred, it is the write.
    ///
    /// Nothing about the result differs from what a packing pass would have
    /// produced: the same content-defined chunks, in the same pack format,
    /// named by the same manifest.
    async fn begin_stream(&self, key: &Path) -> ObjectStorageResult<Option<Box<dyn ObjectSink>>> {
        Ok(Some(Box::new(PackStreamSink {
            store: Arc::clone(&self.inner),
            k_pack: self.k_pack,
            log: self.log.clone(),
            manifest_cache: Arc::clone(&self.manifest_cache),
            tombstone_cache: Arc::clone(&self.tombstone_cache),
            path: Self::canon(key),
            chunker: crate::chunker::StreamChunker::new(),
            writer: Some(PackWriter::content(Arc::clone(&self.inner), self.k_pack)),
            chunks: Vec::new(),
            seen: HashMap::new(),
            size: 0,
        })))
    }

    /// Removes the loose copy and/or tombstones the packed entry.
    async fn delete(&self, key: &Path) -> ObjectStorageResult<()> {
        let loose_existed = match self.inner.delete(key).await {
            Ok(()) => true,
            Err(ObjectStorageError::NotFound(_)) => false,
            Err(e) => return Err(e),
        };

        let canon = Self::canon(key);
        let tombs = self.load_tombstones().await?;
        let already_tombstoned = tombs.deleted.contains_key(&canon);
        let packed = !already_tombstoned
            && match self.manifest().await? {
                Some((_, m)) => m.files.contains_key(&canon),
                None => false,
            };

        if packed {
            let mut updated = (*tombs).clone();
            updated.deleted.insert(canon.clone(), now_secs().unwrap_or(0));
            self.save_tombstones(&updated).await?;
        }

        if !loose_existed && !packed && !already_tombstoned {
            return Err(ObjectStorageError::NotFound(canon));
        }
        Ok(())
    }

    /// Merges the loose listing with the manifest's files under `prefix`.
    ///
    /// The manifest side is flat (every packed file under the prefix), which
    /// matches what the flat backends already return; a loose entry wins over
    /// a packed one at the same path, because the loose copy is newer.
    async fn list(&self, prefix: &Path) -> ObjectStorageResult<Vec<ObjectMetadata>> {
        let mut out = self.inner.list(prefix).await?;
        let seen: BTreeSet<String> = out.iter().map(|m| m.key.clone()).collect();

        let Some((_, manifest)) = self.manifest().await? else {
            return Ok(out);
        };
        let tombs = self.load_tombstones().await?;

        let canon = Self::canon(prefix);
        let base = if canon.is_empty() {
            String::new()
        } else {
            format!("{canon}/")
        };
        for (path, entry) in manifest.files.iter() {
            let in_scope = path == &canon || path.starts_with(&base);
            if !in_scope || seen.contains(path) || tombs.deleted.contains_key(path) {
                continue;
            }
            out.push(ObjectMetadata {
                key: path.clone(),
                is_dir: false,
                size: entry.size,
                modified: entry.modified,
            });
        }
        Ok(out)
    }

    async fn metadata(&self, key: &Path) -> ObjectStorageResult<ObjectMetadata> {
        match self.inner.metadata(key).await {
            Ok(meta) => return Ok(meta),
            Err(ObjectStorageError::NotFound(_)) => {}
            Err(e) => return Err(e),
        }
        let canon = Self::canon(key);
        if self.load_tombstones().await?.deleted.contains_key(&canon) {
            return Err(ObjectStorageError::NotFound(canon));
        }
        let Some((_, manifest)) = self.manifest().await? else {
            return Err(ObjectStorageError::NotFound(canon));
        };
        let entry = manifest
            .files
            .get(&canon)
            .ok_or(ObjectStorageError::NotFound(canon.clone()))?;
        Ok(ObjectMetadata {
            key: canon,
            is_dir: false,
            size: entry.size,
            modified: entry.modified,
        })
    }

    fn backend_name(&self) -> &str {
        self.inner.backend_name()
    }
}

#[async_trait]
impl<S: LooseObjectSource + 'static> SealedObjectAccess for PackedObjectStorage<S> {
    async fn get_sealed(&self, key: &Path) -> ObjectStorageResult<Bytes> {
        self.inner.get_sealed(key).await
    }

    /// Pass-through, invalidating the local caches when replication rewrites
    /// the state they mirror (a peer pushing a newer superblock or tombstone
    /// set must be visible to the next read).
    async fn put_sealed(&self, key: &Path, blob: &[u8]) -> ObjectStorageResult<()> {
        self.inner.put_sealed(key, blob).await?;
        let key_str = key.to_string_lossy();
        if kind(&key_str) == ObjectKind::Superblock {
            self.invalidate_manifest_cache();
        } else if key_str == TOMBSTONES_KEY {
            *self.tombstone_cache.lock().unwrap() = None;
        }
        Ok(())
    }

    /// Storage-key-space delete, bypassing this layer's tombstone logic — the
    /// default would route through logical `delete` and tombstone a stored key
    /// as if it were a path.
    async fn delete_sealed(&self, key: &Path) -> ObjectStorageResult<()> {
        self.inner.delete_sealed(key).await
    }

    async fn list_sealed(&self, prefix: &Path) -> ObjectStorageResult<Vec<ObjectMetadata>> {
        self.inner.list_sealed(prefix).await
    }

    async fn migrate_blinding(&self) -> ObjectStorageResult<usize> {
        self.inner.migrate_blinding().await
    }

    async fn pack_loose(&self) -> ObjectStorageResult<Option<PackSummary>> {
        self.run_pack_pass().await.map(Some)
    }

    async fn compact(&self) -> ObjectStorageResult<Option<CompactSummary>> {
        self.run_compaction_pass().await.map(Some)
    }

    async fn recover_by_scan(&self) -> ObjectStorageResult<Option<ScanRecovery>> {
        self.run_scan_recovery().await
    }

    async fn snapshot(
        &self,
        keep_full_secs: u64,
        record_rows: &[Vec<u8>],
    ) -> ObjectStorageResult<Option<SnapshotSummary>> {
        self.run_snapshot_pass(keep_full_secs, None, Some(record_rows))
            .await
    }

    async fn reconcile(&self) -> ObjectStorageResult<Option<ReconcileSummary>> {
        self.run_reconcile().await
    }

    /// Every pack the current files (and the losers a conflict retained) that
    /// `kept` keeps have their content in, read from the manifest alone — no
    /// pack is opened, so a pack this store does not hold is named as surely
    /// as one it does.
    async fn packs_holding(
        &self,
        kept: &(dyn for<'p> Fn(&'p str) -> bool + Send + Sync),
    ) -> ObjectStorageResult<Option<BTreeMap<crate::StorageKey, Vec<String>>>> {
        let mut packs: BTreeMap<crate::StorageKey, Vec<String>> = BTreeMap::new();
        let Some((_, manifest)) = self.manifest().await? else {
            return Ok(Some(packs));
        };
        let current = manifest.files.iter();
        let retained = manifest.conflicts.iter().flat_map(|(path, entries)| entries.iter().map(move |e| (path, e)));
        let named: Vec<(&String, &FileEntry)> = current.chain(retained).collect();
        for (path, entry) in named {
            if !kept(path) {
                continue;
            }
            for r in &entry.chunks {
                let paths = packs.entry(r.pack_id.as_key().clone()).or_default();
                if paths.last() != Some(path) {
                    paths.push(path.clone());
                }
            }
        }
        Ok(Some(packs))
    }

    async fn retained_conflicts(&self) -> ObjectStorageResult<BTreeMap<String, Vec<String>>> {
        PackedObjectStorage::retained_conflicts(self).await
    }

    async fn read_retained(&self, key: &Path, content_id: &str) -> ObjectStorageResult<Bytes> {
        PackedObjectStorage::read_retained(self, key, content_id).await
    }

    async fn resolve_conflict(&self, key: &Path, keep: Option<&str>) -> ObjectStorageResult<()> {
        PackedObjectStorage::resolve_conflict(self, key, keep).await
    }

    async fn set_keep_versions(&self, key: &Path, on: bool) -> ObjectStorageResult<()> {
        PackedObjectStorage::set_keep_versions(self, key, on).await
    }

    async fn keeps_versions(&self, key: &Path) -> ObjectStorageResult<bool> {
        PackedObjectStorage::keeps_versions(self, key).await
    }

    async fn versions(&self, key: &Path) -> ObjectStorageResult<Vec<FileVersion>> {
        PackedObjectStorage::versions(self, key).await
    }

    async fn logged(&self, key: &Path) -> ObjectStorageResult<Option<u64>> {
        PackedObjectStorage::logged(self, key).await
    }

    async fn read_version(&self, key: &Path, content_id: &str) -> ObjectStorageResult<Bytes> {
        PackedObjectStorage::read_version(self, key, content_id).await
    }

    async fn restore_version(&self, key: &Path, content_id: &str) -> ObjectStorageResult<()> {
        PackedObjectStorage::restore_version(self, key, content_id).await
    }

    async fn versions_cost(&self, key: &Path) -> ObjectStorageResult<u64> {
        PackedObjectStorage::versions_cost(self, key).await
    }

    async fn versions_cost_total(&self) -> ObjectStorageResult<u64> {
        PackedObjectStorage::versions_cost_total(self).await
    }

    async fn append_record_segment(&self, rows: &[Vec<u8>]) -> ObjectStorageResult<Option<u64>> {
        self.run_append_record_segment(rows).await
    }

    async fn scan_record_segments(&self) -> ObjectStorageResult<Vec<RecordSegmentView>> {
        self.run_scan_record_segments().await
    }

    async fn purge(&self, path: &Path) -> ObjectStorageResult<Option<SnapshotSummary>> {
        let canon = Self::canon(path);
        // The loose copy first. A path written but not yet packed has no history
        // to erase, so a purge that only rewrote the log left the bytes sitting
        // in the loose store — erasing the record of a file that was still
        // readable, which is the opposite of what this verb promises. Absent is
        // fine: it means the only copy was already packed.
        match self.inner.delete(path).await {
            Ok(()) => {}
            Err(ObjectStorageError::NotFound(_)) => {}
            Err(e) => return Err(e),
        }
        // `None`: purge erases one object path; the record entries in the log it
        // subsumes belong to a different domain and are carried forward verbatim.
        self.run_snapshot_pass(0, Some(&canon), None).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::PACK_SIZE;
    use crate::{BlindedObjectStorage, EncryptedObjectStorage, MemoryObjectStorage};
    use kotton_crypto::path_blind::derive_path_blind_key;
    use kotton_crypto::derive_pack_key;

    const CEK: [u8; 32] = [0x42; 32];

    /// The namespace rule's boundary cases, read once (`kind`).
    #[test]
    fn kind_reads_each_key_by_the_one_namespace_rule() {
        let blinded = kotton_crypto::path_blind::blind_object_key(
            &derive_path_blind_key(&CEK),
            "files/notes/a.txt",
        );
        assert!(!blinded.starts_with('_') && blinded.contains('/'), "a blinded key: {blinded}");
        for (key, want) in [
            ("_superblock/7", ObjectKind::Superblock),
            ("_pack/c-1", ObjectKind::ContentPack),
            ("_pack/i-1", ObjectKind::IndexPack),
            // A pack written before the split carries no mark.
            ("_pack/0123", ObjectKind::IndexPack),
            // Nothing is read past: a leading `/` is refused where a key
            // enters (`crate::StorageKey`), so here it is just not a `_`.
            ("/_pack/i-1", ObjectKind::File),
            ("/_pack/c-1", ObjectKind::File),
            ("/_superblock/7", ObjectKind::File),
            // The `/` boundary: a prefix names its directory, not a stem.
            ("_packets", ObjectKind::Reserved),
            ("_superblocks/7", ObjectKind::Reserved),
            ("_pack", ObjectKind::Reserved),
            ("_superblock", ObjectKind::Reserved),
            ("_", ObjectKind::Reserved),
            (TOMBSTONES_KEY, ObjectKind::Reserved),
            (blinded.as_str(), ObjectKind::File),
        ] {
            assert_eq!(kind(key), want, "{key}");
        }
        assert!(is_content_pack("_pack/c-1") && !is_content_pack("_pack/i-1"));
    }

    /// The reserved grammar for a pack id, held by [`PackId::parse`]: the two
    /// forms the store writes are admitted, and every other spelling is
    /// refused with its reason. Every admitted id reads as a pack by the
    /// namespace rule.
    #[test]
    fn a_pack_id_is_admitted_only_in_the_reserved_grammar() {
        let hex = "0123456789abcdef".repeat(2);
        for (id, content) in [(format!("_pack/{hex}"), false), (format!("_pack/c-{hex}"), true)] {
            let admitted = PackId::parse(&id).unwrap();
            assert_eq!((admitted.as_str(), admitted.is_content()), (id.as_str(), content));
            assert_eq!(kind(admitted.as_str()), if content { ObjectKind::ContentPack } else { ObjectKind::IndexPack });
        }
        let fresh = [PackWriter::<MemoryObjectStorage>::fresh_id(false), PackWriter::<MemoryObjectStorage>::fresh_id(true)];
        assert_eq!(fresh.map(|id| id.is_content()), [false, true]);
        let name = "a pack's name is not 32 lowercase hex digits, or `c-` and 32";
        for (id, why) in [
            (String::new(), "it is empty"),
            ("_pack/../x".to_string(), "a component is `.` or `..`"),
            (format!("/_pack/{hex}"), "it starts with `/`"),
            (format!("_pack//{hex}"), "a component is empty"),
            (format!("_superblock/{hex}"), "it is not under `_pack/`"),
            (format!("_packs/{hex}"), "it is not under `_pack/`"),
            ("_pack/i-1".to_string(), name),
            ("_pack/c-1".to_string(), name),
            (format!("_pack/{}", &hex[1..]), name),
            (format!("_pack/{hex}0"), name),
            (format!("_pack/{}", hex.to_uppercase()), name),
            (format!("_pack/C-{hex}"), name),
            (format!("_pack/c-c-{}", &hex[2..]), name),
            (format!("_pack/{hex}/x"), name),
            (format!("_pack/c-{}", "zz".repeat(16)), name),
        ] {
            assert_eq!(PackId::parse(&id), Err(crate::NotCanonical { key: id.clone(), why }), "{id:?}");
        }
    }

    type TestStore =
        PackedObjectStorage<BlindedObjectStorage<EncryptedObjectStorage<MemoryObjectStorage>>>;

    /// The real composition over a shared memory backing, so tests can inspect
    /// exactly what a replica would store.
    fn store_with_backing() -> (TestStore, MemoryObjectStorage) {
        let backing = MemoryObjectStorage::new();
        let enc = EncryptedObjectStorage::new(backing.clone(), CEK);
        let blinded = BlindedObjectStorage::new(enc, derive_path_blind_key(&CEK));
        (
            PackedObjectStorage::new(blinded, derive_pack_key(&CEK)),
            backing,
        )
    }

    fn store() -> TestStore {
        store_with_backing().0
    }

    /// Deterministic pseudo-random content — enough entropy for the chunker to
    /// find natural boundaries.
    fn noise(len: usize, seed: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        let mut state = seed;
        while out.len() < len {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            out.extend_from_slice(&state.to_le_bytes());
        }
        out.truncate(len);
        out
    }

    // ── wrapper transparency (before any pack pass) ─────────────────────────

    #[tokio::test]
    async fn loose_operations_pass_through_unchanged() {
        let s = store();
        let key = Path::new("notes/a.md");
        s.put(key, b"hello").await.unwrap();
        assert_eq!(s.get(key).await.unwrap().as_ref(), b"hello");
        assert_eq!(s.metadata(key).await.unwrap().size, 5);
        assert_eq!(s.list(Path::new("notes")).await.unwrap().len(), 1);
        s.delete(key).await.unwrap();
        assert!(matches!(
            s.get(key).await,
            Err(ObjectStorageError::NotFound(_))
        ));
    }

    // ── the pack pass ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn a_pack_pass_round_trips_files_of_all_shapes() {
        let s = store();
        let big = noise(3 * 1024 * 1024, 7); // multi-chunk
        s.put(Path::new("photos/big.jpg"), &big).await.unwrap();
        s.put(Path::new("notes/tiny.md"), b"a note").await.unwrap();
        s.put(Path::new("notes/empty.md"), b"").await.unwrap();

        let summary = s.pack_loose().await.unwrap().unwrap();
        assert_eq!(summary.files_packed, 3);
        assert_eq!(summary.loose_deleted, 3);
        assert_eq!(summary.generation, Some(1));
        assert!(summary.packs_written >= 1);

        // Loose side is empty; everything still reads.
        assert!(s.inner.list_loose().await.unwrap().is_empty());
        assert_eq!(s.get(Path::new("photos/big.jpg")).await.unwrap(), big);
        assert_eq!(
            s.get(Path::new("notes/tiny.md")).await.unwrap().as_ref(),
            b"a note"
        );
        assert_eq!(
            s.get(Path::new("notes/empty.md")).await.unwrap().as_ref(),
            b""
        );
    }

    /// After packing, a replica sees only fixed-size packs and
    /// constant-size superblocks — nothing tracks file count, size, or shape.
    #[tokio::test]
    async fn the_replica_view_is_uniform() {
        let (s, backing) = store_with_backing();
        s.put(Path::new("a/huge.bin"), &noise(2 * 1024 * 1024, 1))
            .await
            .unwrap();
        s.put(Path::new("b/one-byte.txt"), b"x").await.unwrap();
        s.pack_loose().await.unwrap();

        let mut superblock_sizes = Vec::new();
        for m in backing.list(Path::new("")).await.unwrap() {
            if matches!(kind(&m.key), ObjectKind::ContentPack | ObjectKind::IndexPack) {
                assert!(has_its_fixed_size(&m.key, m.size), "pack {} is {} bytes, not its class's fixed size", m.key, m.size);
            } else if kind(&m.key) == ObjectKind::Superblock {
                superblock_sizes.push(m.size);
            } else {
                panic!("unexpected replica-visible object after packing: {}", m.key);
            }
        }
        superblock_sizes.dedup();
        assert_eq!(superblock_sizes.len(), 1, "superblock sizes must be constant");
    }

    #[tokio::test]
    async fn a_packed_store_reopens_cold() {
        let (s, backing) = store_with_backing();
        let content = noise(300 * 1024, 3);
        s.put(Path::new("docs/report.pdf"), &content).await.unwrap();
        s.pack_loose().await.unwrap();

        // A fresh instance over the same backing — cold caches, superblock load.
        let enc = EncryptedObjectStorage::new(backing, CEK);
        let blinded = BlindedObjectStorage::new(enc, derive_path_blind_key(&CEK));
        let reopened = PackedObjectStorage::new(blinded, derive_pack_key(&CEK));
        assert_eq!(
            reopened.get(Path::new("docs/report.pdf")).await.unwrap(),
            content
        );
        assert_eq!(
            reopened
                .metadata(Path::new("docs/report.pdf"))
                .await
                .unwrap()
                .size,
            content.len() as u64
        );
    }

    #[tokio::test]
    async fn a_rewrite_shadows_its_packed_version_and_repacks() {
        let s = store();
        let key = Path::new("notes/plan.md");
        s.put(key, b"v1").await.unwrap();
        s.pack_loose().await.unwrap();

        s.put(key, b"v2 - rewritten").await.unwrap();
        assert_eq!(s.get(key).await.unwrap().as_ref(), b"v2 - rewritten");

        let summary = s.pack_loose().await.unwrap().unwrap();
        assert_eq!(summary.generation, Some(2));
        assert_eq!(s.get(key).await.unwrap().as_ref(), b"v2 - rewritten");
    }

    /// Dedup: identical content already in packs is referenced, not re-stored.
    /// The second pass writes only the pack carrying the new manifest.
    #[tokio::test]
    async fn unchanged_chunks_are_reused_across_passes() {
        let s = store();
        let content = noise(2 * 1024 * 1024, 9);
        s.put(Path::new("a/original.bin"), &content).await.unwrap();
        s.pack_loose().await.unwrap();

        s.put(Path::new("b/copy.bin"), &content).await.unwrap();
        let summary = s.pack_loose().await.unwrap().unwrap();
        assert_eq!(
            summary.packs_written, 1,
            "identical content must dedup to just the manifest-bearing pack"
        );

        let (_, manifest) = s.manifest().await.unwrap().unwrap();
        assert_eq!(
            manifest.files["a/original.bin"].chunks, manifest.files["b/copy.bin"].chunks,
            "both files must reference the same chunks"
        );
        assert_eq!(s.get(Path::new("b/copy.bin")).await.unwrap(), content);
    }

    // ── deletes ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn deleting_a_packed_file_tombstones_then_applies() {
        let s = store();
        s.put(Path::new("old/gone.txt"), b"bye").await.unwrap();
        s.put(Path::new("keep/stay.txt"), b"hi").await.unwrap();
        s.pack_loose().await.unwrap();

        s.delete(Path::new("old/gone.txt")).await.unwrap();
        assert!(matches!(
            s.get(Path::new("old/gone.txt")).await,
            Err(ObjectStorageError::NotFound(_))
        ));
        assert!(matches!(
            s.metadata(Path::new("old/gone.txt")).await,
            Err(ObjectStorageError::NotFound(_))
        ));
        let listed: Vec<String> = s
            .list(Path::new(""))
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.key)
            .collect();
        assert!(!listed.contains(&"old/gone.txt".to_string()));

        // The next pass folds the delete into the manifest and clears the set.
        s.pack_loose().await.unwrap();
        assert!(matches!(
            s.get(Path::new("old/gone.txt")).await,
            Err(ObjectStorageError::NotFound(_))
        ));
        assert_eq!(s.get(Path::new("keep/stay.txt")).await.unwrap().as_ref(), b"hi");
        let (_, manifest) = s.manifest().await.unwrap().unwrap();
        assert!(!manifest.files.contains_key("old/gone.txt"));
        assert!(s.load_tombstones().await.unwrap().deleted.is_empty());
    }

    #[tokio::test]
    async fn delete_then_rewrite_resurrects() {
        let s = store();
        let key = Path::new("notes/phoenix.md");
        s.put(key, b"first life").await.unwrap();
        s.pack_loose().await.unwrap();

        s.delete(key).await.unwrap();
        s.put(key, b"second life").await.unwrap();
        assert_eq!(s.get(key).await.unwrap().as_ref(), b"second life");

        // The pass must keep the resurrected file, not apply the stale tombstone.
        s.pack_loose().await.unwrap();
        assert_eq!(s.get(key).await.unwrap().as_ref(), b"second life");
    }

    #[tokio::test]
    async fn deleting_a_missing_file_is_not_found() {
        let s = store();
        assert!(matches!(
            s.delete(Path::new("never/existed")).await,
            Err(ObjectStorageError::NotFound(_))
        ));
    }

    // ── compaction ──────────────────────────────────────────────────────────

    /// Every pack currently on disk.
    async fn pack_ids(s: &TestStore) -> BTreeSet<String> {
        s.inner
            .list_sealed(Path::new(PACK_PREFIX))
            .await
            .unwrap()
            .into_iter()
            .filter(|m| !m.is_dir)
            .map(|m| m.key)
            .collect()
    }

    #[tokio::test]
    async fn compaction_reclaims_the_pack_a_deleted_file_left_behind() {
        let s = store();
        // Two passes so the files land in different packs, and the first pack
        // also ends up holding a manifest that the second pass supersedes.
        s.put(Path::new("a/gone.txt"), b"delete me").await.unwrap();
        s.pack_loose().await.unwrap();
        // Whatever this pass wrote holds the doomed file's only chunk.
        let doomed = pack_ids(&s).await;

        s.put(Path::new("b/stay.txt"), b"keep me").await.unwrap();
        s.pack_loose().await.unwrap();

        // Delete and fold it into the manifest. `doomed` is now wholly dead —
        // its data chunk is unreferenced and the manifest in it superseded.
        // Note this pass writes a pack of its own for the new manifest, which
        // is why the baseline for "did the set shrink" is taken after it.
        s.delete(Path::new("a/gone.txt")).await.unwrap();
        s.pack_loose().await.unwrap();
        let staged = pack_ids(&s).await;
        assert!(doomed.iter().all(|p| staged.contains(p)));

        let summary = s.compact().await.unwrap().unwrap();
        assert!(summary.packs_retired >= 1, "nothing reclaimed: {summary:?}");

        let after = pack_ids(&s).await;
        assert!(
            after.len() < staged.len(),
            "compaction did not shrink the pack set: {staged:?} → {after:?}"
        );
        for p in &doomed {
            assert!(!after.contains(p), "dead pack {p} survived compaction");
        }
        // The survivor is untouched and the deleted file stays gone.
        assert_eq!(s.get(Path::new("b/stay.txt")).await.unwrap().as_ref(), b"keep me");
        assert!(matches!(
            s.get(Path::new("a/gone.txt")).await,
            Err(ObjectStorageError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn compaction_sweeps_crash_orphaned_packs() {
        let s = store();
        s.put(Path::new("notes/kept.md"), b"still here").await.unwrap();
        s.pack_loose().await.unwrap();

        // A pass that wrote a pack and died before committing leaves exactly
        // this: a pack no superblock references.
        let orphan = format!("{PACK_PREFIX}/{}", "ab".repeat(16));
        s.inner
            .put_sealed(Path::new(&orphan), &vec![0u8; PACK_SIZE])
            .await
            .unwrap();
        assert!(pack_ids(&s).await.contains(&orphan));

        let summary = s.compact().await.unwrap().unwrap();
        assert!(summary.packs_retired >= 1);
        assert!(
            !pack_ids(&s).await.contains(&orphan),
            "crash debris survived compaction"
        );
        assert_eq!(
            s.get(Path::new("notes/kept.md")).await.unwrap().as_ref(),
            b"still here"
        );
    }

    #[tokio::test]
    async fn compaction_converges_and_does_not_churn() {
        let s = store();
        s.put(Path::new("notes/a.md"), b"one").await.unwrap();
        s.put(Path::new("notes/b.md"), b"two").await.unwrap();
        s.pack_loose().await.unwrap();

        s.compact().await.unwrap();
        let settled = pack_ids(&s).await;

        // A second pass must be a no-op. A pack is `PACK_SIZE` on disk however
        // little of it is live, so rewriting a sparse-but-fully-live pack into
        // another sparse pack reclaims nothing — and would repeat forever.
        let again = s.compact().await.unwrap().unwrap();
        assert_eq!(again.packs_retired, 0, "compaction churned: {again:?}");
        assert_eq!(again.packs_rewritten, 0);
        assert_eq!(pack_ids(&s).await, settled);
        assert_eq!(s.get(Path::new("notes/a.md")).await.unwrap().as_ref(), b"one");
        assert_eq!(s.get(Path::new("notes/b.md")).await.unwrap().as_ref(), b"two");
    }

    #[tokio::test]
    async fn compaction_merges_sparse_packs_into_fewer() {
        let s = store();
        // Two large files that will be mostly deleted, each paired with a small
        // survivor, sized so the pass fills more than one pack.
        s.put(Path::new("a_big.bin"), &noise(10 * 1024 * 1024, 1)).await.unwrap();
        s.put(Path::new("b_small.bin"), &noise(2 * 1024 * 1024, 2)).await.unwrap();
        s.put(Path::new("c_big.bin"), &noise(10 * 1024 * 1024, 3)).await.unwrap();
        s.put(Path::new("d_small.bin"), &noise(2 * 1024 * 1024, 4)).await.unwrap();
        s.pack_loose().await.unwrap();

        let before = pack_ids(&s).await;
        assert!(before.len() >= 2, "test needs multiple packs, got {before:?}");

        let keep_b = s.get(Path::new("b_small.bin")).await.unwrap();
        let keep_d = s.get(Path::new("d_small.bin")).await.unwrap();

        s.delete(Path::new("a_big.bin")).await.unwrap();
        s.delete(Path::new("c_big.bin")).await.unwrap();
        s.pack_loose().await.unwrap();

        let summary = s.compact().await.unwrap().unwrap();
        let after = pack_ids(&s).await;
        assert!(
            after.len() < before.len(),
            "sparse packs were not merged: {before:?} → {after:?} ({summary:?})"
        );

        // Verify-before-delete's whole point: the survivors are byte-identical afterwards.
        assert_eq!(s.get(Path::new("b_small.bin")).await.unwrap(), keep_b);
        assert_eq!(s.get(Path::new("d_small.bin")).await.unwrap(), keep_d);
        assert!(matches!(
            s.get(Path::new("a_big.bin")).await,
            Err(ObjectStorageError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn compaction_retires_nothing_when_a_salvage_read_fails() {
        let s = store();
        s.put(Path::new("a_big.bin"), &noise(10 * 1024 * 1024, 1)).await.unwrap();
        s.put(Path::new("b_small.bin"), &noise(2 * 1024 * 1024, 2)).await.unwrap();
        s.put(Path::new("c_big.bin"), &noise(10 * 1024 * 1024, 3)).await.unwrap();
        s.put(Path::new("d_small.bin"), &noise(2 * 1024 * 1024, 4)).await.unwrap();
        s.pack_loose().await.unwrap();
        s.delete(Path::new("a_big.bin")).await.unwrap();
        s.delete(Path::new("c_big.bin")).await.unwrap();
        s.pack_loose().await.unwrap();

        let before = pack_ids(&s).await;

        // Corrupt one pack the salvage must read — one holding a survivor's
        // content. A failure anywhere before the commit leaves every original
        // in place.
        let survivor = |p: &str| p == "b_small.bin";
        let holding = s.packs_holding(&survivor).await.unwrap().unwrap();
        let victim = holding.keys().next().unwrap().clone();
        s.inner
            .put_sealed(victim.as_path(), &vec![0u8; PACK_SIZE])
            .await
            .unwrap();

        assert!(s.compact().await.is_err(), "corruption was not refused");
        // Nothing is retired: not the packs being salvaged, and not a pack
        // nothing references either — here the first pass's index pack, whose
        // manifest the second superseded — whose sweep waits for the rewrite
        // to commit.
        assert_eq!(pack_ids(&s).await, before, "a pack was retired despite a failed pass");
    }

    // ── the history log ─────────────────────────────────────────────────────

    const K_LOG: [u8; 32] = [0x9e; 32];
    const WRITER: &str = "did:kel:zAlice";

    fn logging_store() -> TestStore {
        store().with_log(WRITER, K_LOG)
    }

    /// The segment the last pass appended, if any.
    async fn head_segment(s: &TestStore) -> Option<Segment> {
        let (_, manifest) = s.manifest().await.unwrap()?;
        let r = manifest.log.last()?;
        let framed = s.read_framed_chunk(r).await.unwrap();
        Some(Segment::from_chunk(&K_LOG, &framed).unwrap())
    }

    #[tokio::test]
    async fn a_pack_pass_appends_a_readable_segment() {
        let s = logging_store();
        s.put(Path::new("notes/a.md"), b"hello").await.unwrap();
        s.put(Path::new("notes/b.md"), b"world").await.unwrap();
        s.pack_loose().await.unwrap();

        let seg = head_segment(&s).await.expect("a segment was appended");
        assert_eq!(seg.writer, WRITER);
        assert_eq!(seg.seq, 1, "seq is the generation it committed at");
        assert!(seg.parents.is_empty(), "the first segment chains to nothing");

        let mut paths: Vec<&str> = seg.entries.iter().filter_map(|e| e.path()).collect();
        paths.sort_unstable();
        assert_eq!(paths, ["notes/a.md", "notes/b.md"]);
        assert!(seg
            .entries
            .iter()
            .all(|e| matches!(e, HistoryEntry::ObjectWrite { parent: None, .. })));
    }

    #[tokio::test]
    async fn a_store_without_a_log_appends_nothing() {
        let s = store();
        s.put(Path::new("notes/a.md"), b"hello").await.unwrap();
        s.pack_loose().await.unwrap();
        assert!(head_segment(&s).await.is_none());
    }

    #[tokio::test]
    async fn each_segment_chains_to_the_one_before_it() {
        let s = logging_store();
        s.put(Path::new("a.md"), b"one").await.unwrap();
        s.pack_loose().await.unwrap();
        let first = head_segment(&s).await.unwrap();

        s.put(Path::new("b.md"), b"two").await.unwrap();
        s.pack_loose().await.unwrap();
        let second = head_segment(&s).await.unwrap();

        assert_eq!(second.seq, 2);
        assert_eq!(second.parents.len(), 1, "must name its predecessor");
        assert!(!second.parents[0].is_empty());
        assert_ne!(first.seq, second.seq);
    }

    /// A rewrite records the version it superseded — the parent link that makes
    /// a later concurrent edit detectable as a fact rather than a guess.
    #[tokio::test]
    async fn a_rewrite_records_its_parent_version() {
        let s = logging_store();
        s.put(Path::new("f.md"), b"first").await.unwrap();
        s.pack_loose().await.unwrap();
        let v1 = match &head_segment(&s).await.unwrap().entries[0] {
            HistoryEntry::ObjectWrite { digest, .. } => digest.clone(),
            other => panic!("expected a write, got {other:?}"),
        };

        s.put(Path::new("f.md"), b"second").await.unwrap();
        s.pack_loose().await.unwrap();
        match &head_segment(&s).await.unwrap().entries[0] {
            HistoryEntry::ObjectWrite { parent, digest, .. } => {
                assert_eq!(parent.as_deref(), Some(v1.as_str()));
                assert_ne!(digest, &v1, "new content, new version");
            }
            other => panic!("expected a write, got {other:?}"),
        }
    }

    /// The defect the log exists to fix: a delete becomes a recorded fact
    /// naming what it removed, not an absence to be re-inferred.
    #[tokio::test]
    async fn a_delete_is_recorded_as_an_entry_naming_its_parent() {
        let s = logging_store();
        s.put(Path::new("gone.txt"), b"bye").await.unwrap();
        s.pack_loose().await.unwrap();
        let v1 = match &head_segment(&s).await.unwrap().entries[0] {
            HistoryEntry::ObjectWrite { digest, .. } => digest.clone(),
            other => panic!("expected a write, got {other:?}"),
        };

        s.delete(Path::new("gone.txt")).await.unwrap();
        s.pack_loose().await.unwrap();
        match &head_segment(&s).await.unwrap().entries[0] {
            HistoryEntry::ObjectDelete { path, parent, .. } => {
                assert_eq!(path, "gone.txt");
                assert_eq!(parent.as_deref(), Some(v1.as_str()));
            }
            other => panic!("expected a delete, got {other:?}"),
        }
    }

    // ── the record log seam ─────────────────────────────────────────────────

    /// A record segment lands beside object segments, leaves file state
    /// untouched, surfaces its rows intact, and does not disturb object
    /// reconcile — the four things the producer/consumer seam must guarantee.
    #[tokio::test]
    async fn a_record_segment_is_appended_and_surfaced_beside_objects() {
        let s = logging_store();

        // An object pass first, so record and object segments coexist.
        s.put(Path::new("notes/a.md"), b"hello").await.unwrap();
        s.pack_loose().await.unwrap();

        let seq = s
            .append_record_segment(&[b"row-1".to_vec(), b"row-2".to_vec()])
            .await
            .unwrap()
            .expect("a logging store appends a record segment");
        assert_eq!(seq, 2, "seq is the generation it committed at, after the gen-1 pack pass");

        // A record commit does not disturb file state.
        assert_eq!(s.get(Path::new("notes/a.md")).await.unwrap().as_ref(), b"hello");

        // The rows are surfaced intact and attributed.
        let surfaced = s.scan_record_segments().await.unwrap();
        assert_eq!(surfaced.len(), 1);
        assert_eq!(surfaced[0].writer, WRITER);
        assert_eq!(surfaced[0].seq, 2);
        assert_eq!(surfaced[0].rows, vec![b"row-1".to_vec(), b"row-2".to_vec()]);

        // Object reconcile still rebuilds the file, ignoring the record segment
        // it now carries in the log.
        s.reconcile().await.unwrap();
        assert_eq!(s.get(Path::new("notes/a.md")).await.unwrap().as_ref(), b"hello");
    }

    /// Records can be logged before any object is ever packed, and successive
    /// segments surface in `(writer, seq)` order.
    #[tokio::test]
    async fn record_segments_surface_in_seq_order() {
        let s = logging_store();
        assert_eq!(s.append_record_segment(&[b"first".to_vec()]).await.unwrap(), Some(1));
        assert_eq!(s.append_record_segment(&[b"second".to_vec()]).await.unwrap(), Some(2));

        let surfaced = s.scan_record_segments().await.unwrap();
        assert_eq!(surfaced.len(), 2);
        assert_eq!((surfaced[0].seq, &surfaced[0].rows), (1, &vec![b"first".to_vec()]));
        assert_eq!((surfaced[1].seq, &surfaced[1].rows), (2, &vec![b"second".to_vec()]));
    }

    /// The two no-op paths: an empty batch writes nothing, and a store with no
    /// log (a blind storage node) cannot append or read record history at all.
    #[tokio::test]
    async fn appending_no_rows_or_without_a_log_is_a_no_op() {
        let s = logging_store();
        assert_eq!(s.append_record_segment(&[]).await.unwrap(), None);
        assert!(s.scan_record_segments().await.unwrap().is_empty());

        let no_log = store();
        assert_eq!(no_log.append_record_segment(&[b"x".to_vec()]).await.unwrap(), None);
        assert!(no_log.scan_record_segments().await.unwrap().is_empty());
    }

    /// Every readable segment anywhere in the pack set — what a reader
    /// reconstructing the log actually has to do.
    async fn all_segments(s: &TestStore) -> Vec<(String, Segment)> {
        let mut out = Vec::new();
        for m in s.inner.list_sealed(Path::new(PACK_PREFIX)).await.unwrap() {
            if m.is_dir {
                continue;
            }
            let blob = s.inner.get_sealed(Path::new(&m.key)).await.unwrap();
            let Ok(plaintext) = open_pack(&s.k_pack, &blob) else {
                continue;
            };
            for (_, framed) in scan_chunks(&plaintext) {
                if let Ok(seg) = Segment::from_chunk(&K_LOG, framed) {
                    out.push((chunk_digest(framed), seg));
                }
            }
        }
        out
    }

    /// Compaction must not destroy history. Segments are not in the manifest,
    /// so a liveness calculation built only from file chunks sweeps the packs
    /// holding them — silently, and non-deterministically, since a segment
    /// usually shares a pack with the manifest that *is* protected.
    #[tokio::test]
    async fn compaction_preserves_history_it_cannot_collect() {
        let s = logging_store();
        s.put(Path::new("gone.txt"), b"bye").await.unwrap();
        s.pack_loose().await.unwrap();

        s.delete(Path::new("gone.txt")).await.unwrap();
        s.put(Path::new("keep.txt"), b"hi").await.unwrap();
        s.pack_loose().await.unwrap();
        let head_before = head_segment(&s).await.unwrap();
        let segments_before = all_segments(&s).await.len();
        assert_eq!(segments_before, 2, "two passes, two segments");

        s.compact().await.unwrap();

        // The head still resolves, and points at the same segment.
        assert_eq!(
            head_segment(&s).await.expect("log head survived compaction"),
            head_before
        );
        // And the whole chain is still there, not just the head.
        let after = all_segments(&s).await;
        assert_eq!(after.len(), segments_before, "compaction collected history");

        // The surviving log still reproduces the store's state.
        let state = crate::replay::replay(&after);
        let live: Vec<&str> = state.live().map(|(p, _)| p).collect();
        assert_eq!(live, ["keep.txt"]);
    }

    /// End to end: what the log says the tree is must be what the store says it
    /// is. This is the property the whole mechanism rests on.
    #[tokio::test]
    async fn replaying_the_log_reproduces_the_stores_own_state() {
        let s = logging_store();
        s.put(Path::new("keep/a.md"), b"alpha").await.unwrap();
        s.put(Path::new("drop/b.md"), b"beta").await.unwrap();
        s.pack_loose().await.unwrap();
        let seg1 = head_segment(&s).await.unwrap();

        s.delete(Path::new("drop/b.md")).await.unwrap();
        s.put(Path::new("keep/c.md"), b"gamma").await.unwrap();
        s.pack_loose().await.unwrap();
        let seg2 = head_segment(&s).await.unwrap();

        let state = crate::replay::replay(&[
            (seg2.parents[0].clone(), seg1),
            ("head".to_string(), seg2),
        ]);
        let mut live: Vec<&str> = state.live().map(|(p, _)| p).collect();
        live.sort_unstable();
        assert_eq!(live, ["keep/a.md", "keep/c.md"]);
        assert!(!state.has_conflicts(), "one writer cannot conflict with itself");

        // And it agrees with the manifest the same pass committed.
        let (_, manifest) = s.manifest().await.unwrap().unwrap();
        let mut packed: Vec<&str> = manifest.files.keys().map(|k| k.as_str()).collect();
        packed.sort_unstable();
        assert_eq!(live, packed);
    }

    // ── snapshotting ────────────────────────────────────────────────────────

    /// Everything is inside the window, so collapsing would spend granularity
    /// for nothing.
    #[tokio::test]
    async fn a_snapshot_of_only_recent_history_is_a_no_op() {
        let s = logging_store();
        s.put(Path::new("a.md"), b"one").await.unwrap();
        s.pack_loose().await.unwrap();

        let out = s.snapshot(DEFAULT_KEEP_FULL_SECS, &[]).await.unwrap().unwrap();
        assert_eq!(out.segments_subsumed, 0);
        assert_eq!(out.segments_retained, 1);
        let (_, m) = s.manifest().await.unwrap().unwrap();
        assert_eq!(m.log.len(), 1, "the log was not rewritten");
    }

    /// The mechanism: history older than the window collapses into one segment,
    /// and the log stops growing.
    #[tokio::test]
    async fn a_snapshot_subsumes_history_older_than_the_window() {
        let s = logging_store();
        for (path, body) in [("a.md", "one"), ("b.md", "two"), ("c.md", "three")] {
            s.put(Path::new(path), body.as_bytes()).await.unwrap();
            s.pack_loose().await.unwrap();
        }
        s.delete(Path::new("b.md")).await.unwrap();
        s.pack_loose().await.unwrap();
        let (_, before) = s.manifest().await.unwrap().unwrap();
        assert_eq!(before.log.len(), 4);

        // keep_full = 0 puts every existing segment outside the window.
        let out = s.snapshot(0, &[]).await.unwrap().unwrap();
        assert_eq!(out.segments_subsumed, 4);
        assert_eq!(out.segments_retained, 0);
        assert_eq!(out.files_captured, 2, "b.md was deleted");

        let (_, after) = s.manifest().await.unwrap().unwrap();
        assert_eq!(after.log.len(), 1, "the log collapsed to the snapshot");

        // The snapshot alone reproduces the state, and the delete does not
        // come back — it is absent from the base rather than asserted against.
        let seg = head_segment(&s).await.unwrap();
        let state = crate::replay::replay(&[("snap".to_string(), seg)]);
        let mut live: Vec<&str> = state.live().map(|(p, _)| p).collect();
        live.sort_unstable();
        assert_eq!(live, ["a.md", "c.md"]);

        // And the files themselves still read.
        assert_eq!(s.get(Path::new("a.md")).await.unwrap().as_ref(), b"one");
        assert!(matches!(
            s.get(Path::new("b.md")).await,
            Err(ObjectStorageError::NotFound(_))
        ));
    }

    /// Subsumed segments are no longer live, so compaction may reclaim them —
    /// which is the whole point of the log list being the liveness set.
    #[tokio::test]
    async fn subsumed_segments_become_collectable() {
        let s = logging_store();
        for (path, body) in [("a.md", "one"), ("b.md", "two")] {
            s.put(Path::new(path), body.as_bytes()).await.unwrap();
            s.pack_loose().await.unwrap();
        }
        let all_before = all_segments(&s).await.len();
        s.snapshot(0, &[]).await.unwrap();

        // Still on disk — snapshotting decides deadness, compaction reclaims.
        assert!(all_segments(&s).await.len() > 1);
        let (_, m) = s.manifest().await.unwrap().unwrap();
        assert_eq!(m.log.len(), 1);
        assert!(all_before >= 2);

        // Compaction is now free to drop them, and the snapshot survives.
        s.compact().await.unwrap();
        let head = head_segment(&s).await.expect("the snapshot is still live");
        assert!(!head.entries.is_empty());
        assert_eq!(s.get(Path::new("a.md")).await.unwrap().as_ref(), b"one");
    }

    /// A snapshot's parents are what it subsumed, so their absence must not
    /// read as "you are missing history". Without the flag every replay after
    /// the first snapshot would report the whole collected log as missing.
    #[tokio::test]
    async fn a_snapshots_subsumed_parents_are_not_reported_missing() {
        let s = logging_store();
        s.put(Path::new("a.md"), b"one").await.unwrap();
        s.pack_loose().await.unwrap();
        s.put(Path::new("b.md"), b"two").await.unwrap();
        s.pack_loose().await.unwrap();
        s.snapshot(0, &[]).await.unwrap();

        let head = head_segment(&s).await.unwrap();
        assert!(head.snapshot, "a snapshot must say so");
        assert!(!head.parents.is_empty(), "it did subsume segments");

        let state = crate::replay::replay(&[("snap".to_string(), head)]);
        assert!(
            state.missing_segments.is_empty(),
            "collected history reported as missing: {:?}",
            state.missing_segments
        );
    }

    /// `purge` erases the record, not just the bytes — a file's whole history
    /// stops existing, which is what makes generous retention safe to default
    /// to.
    #[tokio::test]
    async fn purge_erases_a_paths_entire_history() {
        let s = logging_store();
        s.put(Path::new("secret.txt"), b"sensitive").await.unwrap();
        s.pack_loose().await.unwrap();
        s.put(Path::new("secret.txt"), b"revised").await.unwrap();
        s.put(Path::new("keep.txt"), b"unrelated").await.unwrap();
        s.pack_loose().await.unwrap();

        // Ordinary deletion is non-destructive: the history still names it.
        s.delete(Path::new("secret.txt")).await.unwrap();
        s.pack_loose().await.unwrap();
        assert!(all_segments(&s)
            .await
            .iter()
            .any(|(_, seg)| seg.entries.iter().any(|e| e.path() == Some("secret.txt"))));

        s.purge(Path::new("secret.txt")).await.unwrap().unwrap();

        // The live log mentions it nowhere — not as a write, not as a delete.
        let (_, manifest) = s.manifest().await.unwrap().unwrap();
        assert!(!manifest.files.contains_key("secret.txt"));
        for r in &manifest.log {
            let framed = s.read_framed_chunk(r).await.unwrap();
            let seg = Segment::from_chunk(&K_LOG, &framed).unwrap();
            assert!(
                seg.entries.iter().all(|e| e.path() != Some("secret.txt")),
                "a live segment still names the purged path"
            );
        }

        // The unrelated file is untouched.
        assert_eq!(
            s.get(Path::new("keep.txt")).await.unwrap().as_ref(),
            b"unrelated"
        );
        assert!(matches!(
            s.get(Path::new("secret.txt")).await,
            Err(ObjectStorageError::NotFound(_))
        ));
    }

    /// Purging a live file removes it, not merely its past.
    #[tokio::test]
    async fn purge_removes_a_file_that_still_exists() {
        let s = logging_store();
        s.put(Path::new("live.txt"), b"here").await.unwrap();
        s.put(Path::new("other.txt"), b"stays").await.unwrap();
        s.pack_loose().await.unwrap();

        s.purge(Path::new("live.txt")).await.unwrap().unwrap();
        assert!(matches!(
            s.get(Path::new("live.txt")).await,
            Err(ObjectStorageError::NotFound(_))
        ));
        assert_eq!(s.get(Path::new("other.txt")).await.unwrap().as_ref(), b"stays");

        let state = crate::replay::replay(&[("snap".into(), head_segment(&s).await.unwrap())]);
        let live: Vec<&str> = state.live().map(|(p, _)| p).collect();
        assert_eq!(live, ["other.txt"]);
    }

    /// A store with no log cannot snapshot, and neither can one with no keys.
    #[tokio::test]
    async fn a_store_without_a_log_cannot_snapshot() {
        let s = store();
        s.put(Path::new("a.md"), b"one").await.unwrap();
        s.pack_loose().await.unwrap();
        assert!(s.snapshot(0, &[]).await.unwrap().is_none());
    }

    /// The record payloads a segment carries, in order.
    fn record_rows_of(seg: &Segment) -> Vec<Vec<u8>> {
        seg.entries
            .iter()
            .filter_map(|e| match e {
                HistoryEntry::Record { payload, .. } => Some(payload.clone()),
                _ => None,
            })
            .collect()
    }

    /// The record half of a snapshot: it replaces the record versions
    /// in the segments it subsumes with the caller's current merged state, so the
    /// log stops growing while the current row survives — the object and record
    /// domains collapse in one segment.
    #[tokio::test]
    async fn a_record_snapshot_replaces_subsumed_record_versions() {
        let s = logging_store();
        // Two logged versions of one record, across two segments, plus an object,
        // so the snapshot spans both domains.
        s.append_record_segment(&[b"note@v1".to_vec()]).await.unwrap();
        s.append_record_segment(&[b"note@v2".to_vec()]).await.unwrap();
        s.put(Path::new("a.md"), b"one").await.unwrap();
        s.pack_loose().await.unwrap();

        // keep_full = 0 subsumes every segment; the caller supplies only the
        // current record version as the base.
        let out = s.snapshot(0, &[b"note@v2".to_vec()]).await.unwrap().unwrap();
        assert_eq!(out.segments_subsumed, 3);
        assert_eq!(out.files_captured, 1);
        assert_eq!(out.records_captured, 1);

        // The live log is one segment — the snapshot — and it carries only the
        // current record version; v1 was subsumed with its segment.
        let (_, m) = s.manifest().await.unwrap().unwrap();
        assert_eq!(m.log.len(), 1, "the log collapsed to the snapshot");
        let snap = head_segment(&s).await.unwrap();
        assert!(snap.snapshot);
        assert_eq!(record_rows_of(&snap), vec![b"note@v2".to_vec()]);
        assert_eq!(s.get(Path::new("a.md")).await.unwrap().as_ref(), b"one");

        // Compaction reclaims the subsumed segments; the snapshot's record base
        // survives it. That the bound is realized, not the history, is the point.
        s.compact().await.unwrap();
        let snap = head_segment(&s).await.expect("the snapshot survives compaction");
        assert_eq!(record_rows_of(&snap), vec![b"note@v2".to_vec()]);
    }

    /// `purge` erases one object path, but the record entries sharing its log
    /// belong to a different domain and are carried forward verbatim —
    /// erasing a file must not silently discard the records stored beside it.
    #[tokio::test]
    async fn purge_carries_record_history_forward() {
        let s = logging_store();
        s.append_record_segment(&[b"keep-1".to_vec(), b"keep-2".to_vec()])
            .await
            .unwrap();
        s.put(Path::new("secret.txt"), b"sensitive").await.unwrap();
        s.put(Path::new("keep.txt"), b"unrelated").await.unwrap();
        s.pack_loose().await.unwrap();

        let out = s.purge(Path::new("secret.txt")).await.unwrap().unwrap();
        assert_eq!(out.records_captured, 2, "the record entries are carried, not dropped");

        // The object path is gone from the live log…
        let (_, m) = s.manifest().await.unwrap().unwrap();
        assert!(!m.files.contains_key("secret.txt"));
        assert!(matches!(
            s.get(Path::new("secret.txt")).await,
            Err(ObjectStorageError::NotFound(_))
        ));

        // …but the records that shared the log survive verbatim in the snapshot,
        // through compaction.
        let mut rows = record_rows_of(&head_segment(&s).await.unwrap());
        rows.sort();
        assert_eq!(rows, vec![b"keep-1".to_vec(), b"keep-2".to_vec()]);
        assert_eq!(s.get(Path::new("keep.txt")).await.unwrap().as_ref(), b"unrelated");

        s.compact().await.unwrap();
        let mut rows = record_rows_of(&head_segment(&s).await.expect("snapshot survives compaction"));
        rows.sort();
        assert_eq!(rows, vec![b"keep-1".to_vec(), b"keep-2".to_vec()]);
    }

    // ── log-driven reconciliation: two devices ──────────────────────────────

    /// A device in the same fleet: same keys, its own disk, its own writer DID.
    fn device(writer: &str) -> TestStore {
        store().with_log(writer, K_LOG)
    }

    /// What replication does — move packs. Superblocks stay device-local, which
    /// is the point: each device keeps its own root and merges by replaying.
    async fn ship_packs(from: &TestStore, to: &TestStore) {
        for m in from
            .inner
            .list_sealed(Path::new(PACK_PREFIX))
            .await
            .unwrap()
        {
            if m.is_dir {
                continue;
            }
            let blob = from.inner.get_sealed(Path::new(&m.key)).await.unwrap();
            to.inner.put_sealed(Path::new(&m.key), &blob).await.unwrap();
        }
    }

    /// Two devices writing independently converge on the union — no listing
    /// comparison, no timestamp arbitration.
    #[tokio::test]
    async fn two_devices_converge_by_replaying_each_others_segments() {
        let a = device("did:kel:zA");
        let b = device("did:kel:zB");
        a.put(Path::new("from_a.md"), b"alpha").await.unwrap();
        a.pack_loose().await.unwrap();
        b.put(Path::new("from_b.md"), b"bravo").await.unwrap();
        b.pack_loose().await.unwrap();

        ship_packs(&a, &b).await;
        ship_packs(&b, &a).await;
        let ra = a.reconcile().await.unwrap().unwrap();
        let rb = b.reconcile().await.unwrap().unwrap();
        assert_eq!(ra.segments_adopted, 1);
        assert_eq!(rb.segments_adopted, 1);
        assert_eq!(ra.paths_pending_content, 0);
        assert_eq!(rb.paths_pending_content, 0);

        for s in [&a, &b] {
            assert_eq!(s.get(Path::new("from_a.md")).await.unwrap().as_ref(), b"alpha");
            assert_eq!(s.get(Path::new("from_b.md")).await.unwrap().as_ref(), b"bravo");
        }
    }

    /// The headline defect, fixed end to end: a delete on one device removes the
    /// file on the other instead of the other copying it back.
    #[tokio::test]
    async fn a_delete_propagates_between_devices_and_does_not_resurrect() {
        let a = device("did:kel:zA");
        let b = device("did:kel:zB");
        a.put(Path::new("shared.md"), b"content").await.unwrap();
        a.pack_loose().await.unwrap();
        ship_packs(&a, &b).await;
        b.reconcile().await.unwrap();
        assert_eq!(b.get(Path::new("shared.md")).await.unwrap().as_ref(), b"content");

        a.delete(Path::new("shared.md")).await.unwrap();
        a.pack_loose().await.unwrap();
        ship_packs(&a, &b).await;
        b.reconcile().await.unwrap();

        assert!(
            matches!(
                b.get(Path::new("shared.md")).await,
                Err(ObjectStorageError::NotFound(_))
            ),
            "the delete did not propagate"
        );

        // And it stays deleted: shipping again and reconciling again must not
        // resurrect it, which is exactly what a listing diff would do.
        ship_packs(&b, &a).await;
        b.reconcile().await.unwrap();
        assert!(matches!(
            b.get(Path::new("shared.md")).await,
            Err(ObjectStorageError::NotFound(_))
        ));
    }

    /// Two writers editing the same path without seeing each other: detected as
    /// a conflict rather than silently arbitrated, and the loser is retained.
    #[tokio::test]
    async fn concurrent_edits_across_devices_are_detected_not_arbitrated() {
        let a = device("did:kel:zA");
        let b = device("did:kel:zB");
        a.put(Path::new("doc.md"), b"base").await.unwrap();
        a.pack_loose().await.unwrap();
        ship_packs(&a, &b).await;
        b.reconcile().await.unwrap();

        // Both edit from the same base, neither having seen the other.
        a.put(Path::new("doc.md"), b"a's edit").await.unwrap();
        a.pack_loose().await.unwrap();
        b.put(Path::new("doc.md"), b"b's edit").await.unwrap();
        b.pack_loose().await.unwrap();

        ship_packs(&a, &b).await;
        let rb = b.reconcile().await.unwrap().unwrap();
        assert_eq!(rb.conflicts, 1, "a concurrent edit must be reported");

        // Both devices pick the same winner without coordinating.
        ship_packs(&b, &a).await;
        a.reconcile().await.unwrap();
        assert_eq!(
            a.get(Path::new("doc.md")).await.unwrap(),
            b.get(Path::new("doc.md")).await.unwrap(),
            "devices disagreed on the winner"
        );
    }

    /// The retained loser's **bytes** survive, including across compaction.
    ///
    /// `concurrent_edits_across_devices_are_detected_not_arbitrated` proves the
    /// conflict is detected and a winner agreed. This proves the other half, and
    /// it is the half that was missing: `replay()` retained the losing `Version`
    /// (digest, size, writer) but `reconcile` rebuilt the manifest from current
    /// versions only, so the loser's chunks were referenced by nothing and the
    /// next compaction reclaimed them. Retaining the record while dropping the
    /// bytes is still destroying the write.
    #[tokio::test]
    async fn a_retained_losing_version_keeps_its_bytes_through_compaction() {
        let a = device("did:kel:zA");
        let b = device("did:kel:zB");
        a.put(Path::new("doc.md"), b"base").await.unwrap();
        a.pack_loose().await.unwrap();
        ship_packs(&a, &b).await;
        b.reconcile().await.unwrap();

        a.put(Path::new("doc.md"), b"a's edit").await.unwrap();
        a.pack_loose().await.unwrap();
        b.put(Path::new("doc.md"), b"b's edit").await.unwrap();
        b.pack_loose().await.unwrap();

        ship_packs(&a, &b).await;
        assert_eq!(b.reconcile().await.unwrap().unwrap().conflicts, 1);

        // The loser is nameable, and its bytes are the ones that lost.
        let retained = b.retained_conflicts().await.unwrap();
        let ids = retained.get("doc.md").expect("doc.md must have a retained version");
        assert_eq!(ids.len(), 1, "one loser retained");

        let winner = b.get(Path::new("doc.md")).await.unwrap();
        let loser = b.read_retained(Path::new("doc.md"), &ids[0]).await.unwrap();
        assert_ne!(loser, winner, "the retained version must be the losing one");
        let both: [&[u8]; 2] = [winner.as_ref(), loser.as_ref()];
        assert!(
            both.contains(&b"a's edit".as_slice()) && both.contains(&b"b's edit".as_slice()),
            "both writes must be reachable, got {:?} and {:?}",
            String::from_utf8_lossy(&winner),
            String::from_utf8_lossy(&loser),
        );

        // The pass that used to destroy it. Compaction reclaims unreferenced
        // chunks, so this is where a retained-but-unreferenced loser died.
        b.compact().await.unwrap();
        let after = b.read_retained(Path::new("doc.md"), &ids[0]).await.unwrap();
        assert_eq!(after, loser, "compaction reclaimed the retained version's bytes");
    }

    /// Resolving a conflict releases the retained version — and promoting one
    /// makes it the current value through an ordinary write.
    ///
    /// This is what bounds the cost of keeping the only copy. Retention holds a losing write until
    /// somebody chooses; without this it holds forever.
    #[tokio::test]
    async fn resolving_a_conflict_promotes_and_releases() {
        let a = device("did:kel:zA");
        let b = device("did:kel:zB");
        a.put(Path::new("doc.md"), b"base").await.unwrap();
        a.pack_loose().await.unwrap();
        ship_packs(&a, &b).await;
        b.reconcile().await.unwrap();

        a.put(Path::new("doc.md"), b"a's edit").await.unwrap();
        a.pack_loose().await.unwrap();
        b.put(Path::new("doc.md"), b"b's edit").await.unwrap();
        b.pack_loose().await.unwrap();
        ship_packs(&a, &b).await;
        assert_eq!(b.reconcile().await.unwrap().unwrap().conflicts, 1);

        let ids = b.retained_conflicts().await.unwrap();
        let id = ids.get("doc.md").unwrap()[0].clone();
        let loser = b.read_retained(Path::new("doc.md"), &id).await.unwrap();

        // Promote the loser: it becomes current, and the conflict is released.
        b.resolve_conflict(Path::new("doc.md"), Some(&id)).await.unwrap();
        assert_eq!(
            b.get(Path::new("doc.md")).await.unwrap(),
            loser,
            "the promoted version must be the current one"
        );
        assert!(
            b.retained_conflicts().await.unwrap().is_empty(),
            "resolving must release the retention, or the cost never comes back"
        );
    }

    /// Resolving without promoting keeps the winner and still releases.
    #[tokio::test]
    async fn resolving_without_promoting_keeps_the_winner() {
        let a = device("did:kel:zA");
        let b = device("did:kel:zB");
        a.put(Path::new("doc.md"), b"base").await.unwrap();
        a.pack_loose().await.unwrap();
        ship_packs(&a, &b).await;
        b.reconcile().await.unwrap();

        a.put(Path::new("doc.md"), b"a's edit").await.unwrap();
        a.pack_loose().await.unwrap();
        b.put(Path::new("doc.md"), b"b's edit").await.unwrap();
        b.pack_loose().await.unwrap();
        ship_packs(&a, &b).await;
        b.reconcile().await.unwrap();

        let winner = b.get(Path::new("doc.md")).await.unwrap();
        b.resolve_conflict(Path::new("doc.md"), None).await.unwrap();

        assert_eq!(b.get(Path::new("doc.md")).await.unwrap(), winner);
        assert!(b.retained_conflicts().await.unwrap().is_empty());
    }

    /// Reconciling twice changes nothing — the union is idempotent, which is
    /// what lets it run on every sync without drift.
    #[tokio::test]
    async fn reconciliation_is_idempotent() {
        let a = device("did:kel:zA");
        let b = device("did:kel:zB");
        a.put(Path::new("x.md"), b"one").await.unwrap();
        a.pack_loose().await.unwrap();
        ship_packs(&a, &b).await;

        let first = b.reconcile().await.unwrap().unwrap();
        assert_eq!(first.segments_adopted, 1);
        let second = b.reconcile().await.unwrap().unwrap();
        assert_eq!(second.segments_adopted, 0, "nothing new the second time");
        assert_eq!(second.paths_changed, 0);
        assert_eq!(b.get(Path::new("x.md")).await.unwrap().as_ref(), b"one");
    }

    /// Segments can arrive before the packs holding their content. That is
    /// reported, not treated as loss or invented into a broken entry.
    #[tokio::test]
    async fn content_that_has_not_arrived_yet_is_reported_pending() {
        let a = device("did:kel:zA");
        let b = device("did:kel:zB");
        a.put(Path::new("big.bin"), &noise(64 * 1024, 5)).await.unwrap();
        a.pack_loose().await.unwrap();

        // Ship only the pack holding the segment and manifest — the last one
        // written — leaving the data pack behind.
        let packs: Vec<String> = a.inner
            .list_sealed(Path::new(PACK_PREFIX))
            .await
            .unwrap()
            .into_iter()
            .filter(|m| !m.is_dir)
            .map(|m| m.key)
            .collect();
        let mut shipped_any = false;
        for key in &packs {
            let blob = a.inner.get_sealed(Path::new(key)).await.unwrap();
            let pt = open_pack(&a.k_pack, &blob).unwrap();
            let has_segment = scan_chunks(&pt)
                .iter()
                .any(|(_, f)| Segment::from_chunk(&K_LOG, f).is_ok());
            if has_segment {
                b.inner.put_sealed(Path::new(key), &blob).await.unwrap();
                shipped_any = true;
            }
        }
        assert!(shipped_any);

        let r = b.reconcile().await.unwrap().unwrap();
        assert_eq!(r.segments_adopted, 1);
        // The index rides in a pack of its own (`CONTENT_PACK_PREFIX`), so the
        // pack with the segment carries the manifest that names the file and
        // where its content is: the name is known, not pending, and its
        // content is a pack this store does not hold — not found until it
        // arrives (a device fetches it on open, `crate::fetch`), and read
        // whole once it does. What must never happen is a name whose content,
        // once here, reads wrong.
        assert_eq!(r.paths_pending_content, 0, "the index named the file");
        assert!(matches!(
            b.get(Path::new("big.bin")).await,
            Err(ObjectStorageError::NotFound(_))
        ));
        for key in packs.iter().filter(|k| is_content_pack(k)) {
            let blob = a.inner.get_sealed(Path::new(key)).await.unwrap();
            b.inner.put_sealed(Path::new(key), &blob).await.unwrap();
        }
        assert_eq!(b.get(Path::new("big.bin")).await.unwrap(), noise(64 * 1024, 5));
    }

    /// **A packing pass seals content and index apart**: the file's chunks in
    /// content packs, which hold nothing else, and the segment and manifest in
    /// an index pack, which holds no content — so a device can keep the index
    /// and leave the content (kotton #55). `packs_holding` names a file's
    /// content packs from the manifest alone.
    #[tokio::test]
    async fn a_pass_seals_content_and_index_in_packs_of_their_own() {
        let a = device("did:kel:zA");
        a.put(Path::new("photo.jpg"), &noise(64 * 1024, 7)).await.unwrap();
        a.put(Path::new("note.md"), b"a note").await.unwrap();
        a.pack_loose().await.unwrap();
        let mut kinds: Vec<(bool, Vec<ChunkKind>)> = Vec::new();
        for m in a.inner.list_sealed(Path::new(PACK_PREFIX)).await.unwrap() {
            let blob = a.inner.get_sealed(Path::new(&m.key)).await.unwrap();
            let pt = open_pack(&a.k_pack, &blob).unwrap();
            let in_it = scan_chunks(&pt).iter().map(|(_, f)| unframe_chunk(f).unwrap().0).collect();
            kinds.push((is_content_pack(&m.key), in_it));
        }
        assert_eq!(kinds.len(), 2, "{kinds:?}");
        for (content, in_it) in &kinds {
            if *content {
                assert!(in_it.iter().all(|k| *k == ChunkKind::Data), "a content pack holds {in_it:?}");
            } else {
                assert!(!in_it.contains(&ChunkKind::Data), "an index pack holds content: {in_it:?}");
                assert!(in_it.contains(&ChunkKind::Manifest));
            }
        }
        let photo = |p: &str| p == "photo.jpg";
        let holding = a.packs_holding(&photo).await.unwrap().unwrap();
        assert_eq!(holding.len(), 1);
        let (id, paths) = holding.iter().next().unwrap();
        assert!(is_content_pack(id.as_str()), "{id}");
        assert_eq!(paths, &["photo.jpg".to_string()]);
        assert!(!is_content_pack("_pack/c0ffee00c0ffee00c0ffee00c0ffee00"), "an index pack whose hex begins with c");
    }

    // ── scan recovery ───────────────────────────────────────────────────────

    /// A second store over the same bytes — a cold device with the key material
    /// and the packs and nothing else.
    fn store_over(backing: MemoryObjectStorage) -> TestStore {
        let enc = EncryptedObjectStorage::new(backing, CEK);
        let blinded = BlindedObjectStorage::new(enc, derive_path_blind_key(&CEK));
        PackedObjectStorage::new(blinded, derive_pack_key(&CEK))
    }

    /// Lose the root pointer, keeping every pack.
    async fn wipe_superblocks(s: &TestStore) {
        for m in s
            .inner
            .list_sealed(Path::new(SUPERBLOCK_PREFIX))
            .await
            .unwrap()
        {
            if !m.is_dir {
                s.inner.delete_sealed(Path::new(&m.key)).await.unwrap();
            }
        }
    }

    #[tokio::test]
    async fn scan_recovery_rebuilds_a_lost_superblock() {
        let (s, backing) = store_with_backing();
        let big = noise(2 * 1024 * 1024, 11);
        s.put(Path::new("photos/big.jpg"), &big).await.unwrap();
        s.put(Path::new("notes/a.md"), b"hello").await.unwrap();
        s.pack_loose().await.unwrap();
        wipe_superblocks(&s).await;

        // A cold store over the same packs: no cache, no superblock, just the
        // key material — the premise of continuity.
        let cold = store_over(backing);
        assert!(
            cold.get(Path::new("notes/a.md")).await.is_err(),
            "a store with no root pointer must not resolve names"
        );

        let rec = cold.recover_by_scan().await.unwrap().unwrap();
        assert_eq!(rec.files_recovered, 2, "{rec:?}");
        assert!(rec.generation >= 1);
        assert!(rec.manifests_found >= 1);

        assert_eq!(cold.get(Path::new("notes/a.md")).await.unwrap().as_ref(), b"hello");
        assert_eq!(cold.get(Path::new("photos/big.jpg")).await.unwrap(), big);
    }

    /// The log lives in the manifest, so recovering the manifest recovers the
    /// log with it. When the log head sat in the superblock this was not
    /// possible at all — a scan could rebuild the files and still lose every
    /// segment.
    #[tokio::test]
    async fn scan_recovery_restores_the_log_with_the_manifest() {
        let (s, backing) = store_with_backing();
        let s = s.with_log(WRITER, K_LOG);
        s.put(Path::new("a.md"), b"one").await.unwrap();
        s.pack_loose().await.unwrap();
        s.put(Path::new("b.md"), b"two").await.unwrap();
        s.pack_loose().await.unwrap();
        let head_before = head_segment(&s).await.unwrap();
        wipe_superblocks(&s).await;

        let cold = store_over(backing);
        cold.recover_by_scan().await.unwrap().unwrap();

        assert_eq!(
            head_segment(&cold).await.expect("the log came back too"),
            head_before
        );
        let (_, manifest) = cold.manifest().await.unwrap().unwrap();
        assert_eq!(manifest.log.len(), 2, "both segments recovered");
    }

    #[tokio::test]
    async fn scan_recovery_declines_when_a_superblock_still_loads() {
        let s = store();
        s.put(Path::new("notes/a.md"), b"hi").await.unwrap();
        s.pack_loose().await.unwrap();
        assert!(
            s.recover_by_scan().await.unwrap().is_none(),
            "recovery must not compete with a working root pointer"
        );
    }

    #[tokio::test]
    async fn scan_recovery_adopts_the_newest_manifest() {
        let (s, backing) = store_with_backing();
        s.put(Path::new("a.md"), b"first").await.unwrap();
        s.pack_loose().await.unwrap();
        s.put(Path::new("b.md"), b"second").await.unwrap();
        s.pack_loose().await.unwrap();
        wipe_superblocks(&s).await;

        // Both passes left a manifest in a pack; only the newer knows about b.
        let cold = store_over(backing);
        let rec = cold.recover_by_scan().await.unwrap().unwrap();
        assert!(rec.manifests_found >= 2, "{rec:?}");
        assert_eq!(rec.generation, 2, "{rec:?}");
        assert_eq!(rec.files_recovered, 2);
        assert_eq!(cold.get(Path::new("b.md")).await.unwrap().as_ref(), b"second");
    }

    #[tokio::test]
    async fn scan_recovery_falls_back_past_a_damaged_manifest() {
        let (s, backing) = store_with_backing();
        s.put(Path::new("a.md"), b"survives").await.unwrap();
        s.pack_loose().await.unwrap();
        let first_pass = pack_ids(&s).await;
        s.put(Path::new("b.md"), b"lost with its pack").await.unwrap();
        s.pack_loose().await.unwrap();

        // Destroy the second pass's pack: its manifest *and* b's chunk go with
        // it. The first pass's manifest is intact and self-contained.
        let doomed: Vec<String> = pack_ids(&s)
            .await
            .into_iter()
            .filter(|p| !first_pass.contains(p))
            .collect();
        assert!(!doomed.is_empty());
        for p in &doomed {
            s.inner
                .put_sealed(Path::new(p), &vec![0u8; PACK_SIZE])
                .await
                .unwrap();
        }
        wipe_superblocks(&s).await;

        let cold = store_over(backing);
        let rec = cold.recover_by_scan().await.unwrap().unwrap();
        assert_eq!(rec.generation, 1, "should have fallen back: {rec:?}");
        assert_eq!(rec.files_recovered, 1);
        assert_eq!(cold.get(Path::new("a.md")).await.unwrap().as_ref(), b"survives");
    }

    // ── failure modes ───────────────────────────────────────────────────────

    /// A corrupted pack fails the reads that depend on it and no others —
    /// detection, never wrong bytes.
    #[tokio::test]
    async fn a_corrupted_pack_fails_closed_and_is_scoped() {
        let (s, backing) = store_with_backing();
        s.put(Path::new("first.bin"), &noise(100 * 1024, 1))
            .await
            .unwrap();
        s.pack_loose().await.unwrap();
        let survivor = noise(100 * 1024, 2);
        s.put(Path::new("second.bin"), &survivor).await.unwrap();
        s.pack_loose().await.unwrap();

        // Corrupt the pack holding the *first* file's chunks.
        let (_, manifest) = s.manifest().await.unwrap().unwrap();
        let victim_pack = manifest.files["first.bin"].chunks[0].pack_id.clone();
        let mut blob = backing
            .get_sealed(victim_pack.as_path())
            .await
            .unwrap()
            .to_vec();
        blob[1000] ^= 0xff;
        backing
            .put_sealed(victim_pack.as_path(), &blob)
            .await
            .unwrap();

        assert!(
            s.get(Path::new("first.bin")).await.is_err(),
            "a corrupt pack must fail the read, not return wrong bytes"
        );
        assert_eq!(
            s.get(Path::new("second.bin")).await.unwrap(),
            survivor,
            "corruption in one pack must not affect files in another"
        );
    }

    /// The crash window between superblock commit and loose deletion: both
    /// copies exist. Reads serve identical content and a re-run converges.
    #[tokio::test]
    async fn the_commit_to_delete_crash_window_converges() {
        let s = store();
        let content = noise(500 * 1024, 5);
        s.put(Path::new("docs/crash.bin"), &content).await.unwrap();
        s.pack_loose().await.unwrap();

        // Simulate the crash window: the loose copy reappears (as if deletion
        // never ran) while the packed copy is committed.
        s.put(Path::new("docs/crash.bin"), &content).await.unwrap();
        assert_eq!(s.get(Path::new("docs/crash.bin")).await.unwrap(), content);

        let summary = s.pack_loose().await.unwrap().unwrap();
        assert_eq!(summary.packs_written, 1, "all data chunks must dedup");
        assert_eq!(s.get(Path::new("docs/crash.bin")).await.unwrap(), content);
        assert!(s.inner.list_loose().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_empty_pass_is_a_noop() {
        let (s, backing) = store_with_backing();
        let summary = s.pack_loose().await.unwrap().unwrap();
        assert_eq!(summary, PackSummary::default());
        assert!(
            backing.list(Path::new("")).await.unwrap().is_empty(),
            "a no-op pass must write nothing"
        );
    }

    // ── listing and merge semantics ─────────────────────────────────────────

    #[tokio::test]
    async fn list_merges_loose_and_packed_with_loose_winning() {
        let s = store();
        s.put(Path::new("notes/packed.md"), b"packed").await.unwrap();
        s.put(Path::new("notes/both.md"), b"old").await.unwrap();
        s.pack_loose().await.unwrap();

        s.put(Path::new("notes/loose.md"), b"loose!").await.unwrap();
        s.put(Path::new("notes/both.md"), b"new and longer").await.unwrap();

        let listed = s.list(Path::new("notes")).await.unwrap();
        let mut keys: Vec<&str> = listed.iter().map(|m| m.key.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["notes/both.md", "notes/loose.md", "notes/packed.md"]);

        // The duplicate path reports the loose (newer) size.
        let both = listed.iter().find(|m| m.key == "notes/both.md").unwrap();
        assert_eq!(both.size, b"new and longer".len() as u64);
    }

    // ---- streaming ingest and ranged reads (large objects) ----------------
    //
    // These exist because a model is gigabytes and everything above was written
    // for files. The sizes below cross a pack boundary (PACK_SIZE is 16 MiB) on
    // purpose: a single-pack object would exercise none of the seams that
    // actually break.

    /// Stream an object larger than one pack and read it back byte for byte.
    #[tokio::test]
    async fn a_streamed_object_reads_back_byte_for_byte() {
        let s = store();
        let want = noise(20 * 1024 * 1024, 0xA11CE);

        let mut sink = s
            .begin_stream(Path::new("models/w.gguf"))
            .await
            .unwrap()
            .expect("the packed store offers streaming ingest");
        for piece in want.chunks(4 * 1024 * 1024) {
            sink.push(piece).await.unwrap();
        }
        sink.commit().await.unwrap();

        let got = s.get(Path::new("models/w.gguf")).await.unwrap();
        assert_eq!(got.len(), want.len(), "size round-trips");
        assert_eq!(got.as_ref(), want.as_slice(), "bytes round-trip");
    }

    /// A ranged read serves exactly what a whole read would, including across
    /// pack boundaries and at the ends — the property `read_file` now depends
    /// on to stop decrypting the whole object per range.
    #[tokio::test]
    async fn a_ranged_read_serves_the_same_bytes_as_a_whole_read() {
        let s = store();
        let want = noise(20 * 1024 * 1024, 0xBEEF);
        let mut sink = s.begin_stream(Path::new("m.bin")).await.unwrap().unwrap();
        for piece in want.chunks(4 * 1024 * 1024) {
            sink.push(piece).await.unwrap();
        }
        sink.commit().await.unwrap();

        // Walk it the way the client does, and rebuild.
        let mut rebuilt = Vec::with_capacity(want.len());
        let mut offset = 0u64;
        loop {
            let (part, total) = s
                .get_range(Path::new("m.bin"), offset, 4 * 1024 * 1024)
                .await
                .unwrap();
            assert_eq!(total, want.len() as u64, "every range reports the true size");
            if part.is_empty() {
                break;
            }
            rebuilt.extend_from_slice(&part);
            offset += part.len() as u64;
        }
        assert_eq!(rebuilt, want, "a walk of ranges equals the whole object");

        // Awkward ranges: unaligned, straddling a boundary, and past the end.
        let (mid, _) = s.get_range(Path::new("m.bin"), 1_234_567, 999_999).await.unwrap();
        assert_eq!(mid.as_ref(), &want[1_234_567..1_234_567 + 999_999]);
        let (tail, _) = s
            .get_range(Path::new("m.bin"), want.len() as u64 - 10, 4096)
            .await
            .unwrap();
        assert_eq!(tail.as_ref(), &want[want.len() - 10..], "a short tail is not padded");
        let (past, _) = s
            .get_range(Path::new("m.bin"), want.len() as u64 + 1, 16)
            .await
            .unwrap();
        assert!(past.is_empty(), "reading past the end yields nothing, not an error");
    }

    /// A stream that is never committed is invisible — the property the hash
    /// gate in `write_file` rests on. Bytes are on disk; no name resolves to
    /// them.
    #[tokio::test]
    async fn an_uncommitted_stream_is_invisible() {
        let s = store();
        let mut sink = s.begin_stream(Path::new("half.bin")).await.unwrap().unwrap();
        sink.push(&noise(20 * 1024 * 1024, 7)).await.unwrap();
        drop(sink);

        assert!(
            matches!(
                s.get(Path::new("half.bin")).await,
                Err(ObjectStorageError::NotFound(_))
            ),
            "an uncommitted stream must not resolve"
        );
        let listed = s.list(Path::new("")).await.unwrap();
        assert!(
            !listed.iter().any(|m| m.key == "half.bin"),
            "nor appear in a listing"
        );
    }

    /// While a replacement streams, the old bytes keep serving. The swap is the
    /// commit, not the first push — so a reader during a long ingest sees one
    /// version or the other and never a mixture.
    #[tokio::test]
    async fn a_streamed_overwrite_serves_the_old_bytes_until_it_commits() {
        let s = store();
        s.put(Path::new("m.bin"), b"the old bytes").await.unwrap();

        let replacement = noise(20 * 1024 * 1024, 0xF00D);
        let mut sink = s.begin_stream(Path::new("m.bin")).await.unwrap().unwrap();
        for piece in replacement.chunks(4 * 1024 * 1024) {
            sink.push(piece).await.unwrap();
            assert_eq!(
                s.get(Path::new("m.bin")).await.unwrap().as_ref(),
                b"the old bytes",
                "the old version serves for the whole ingest"
            );
        }
        sink.commit().await.unwrap();
        assert_eq!(
            s.get(Path::new("m.bin")).await.unwrap().as_ref(),
            replacement.as_slice(),
            "and the new one only after the commit"
        );
    }

    /// Peak resident memory, in bytes, from the kernel rather than from a guess.
    ///
    /// `VmHWM` is a high-water mark and never falls, which is exactly what makes
    /// it the right instrument here: measure it after a small ingest and again
    /// after a much larger one, and if the second reading has barely moved then
    /// nothing held the object.
    fn peak_rss_bytes() -> u64 {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmHWM:") {
                let kb: u64 = rest
                    .trim()
                    .trim_end_matches(" kB")
                    .trim()
                    .parse()
                    .unwrap_or(0);
                return kb * 1024;
            }
        }
        0
    }

    /// One deterministic 4 MiB piece, generated on demand.
    ///
    /// The source is produced piece by piece rather than as one buffer: a test
    /// that holds the whole object cannot measure whether the code under it
    /// holds the whole object. The first version of this measurement did
    /// exactly that and reported the test's own allocation as the system's.
    fn piece(seed: u64, index: usize, len: usize) -> Vec<u8> {
        noise(len, seed.wrapping_mul(0x9E37_79B9).wrapping_add(index as u64))
    }

    /// **The property this whole unit exists for**: peak memory is bounded by
    /// the chunk, not by the object.
    ///
    /// Before this change a file was reassembled whole and sealed as one AEAD
    /// envelope, so peak memory was a multiple of the file and a model-sized
    /// object could not be installed at all — `MAX_SEALED_OBJECT_BYTES` refused
    /// it at 256 MiB.
    ///
    /// **This measurement is run against a store backed by real files.** The
    /// `store()` helper above is backed by `MemoryObjectStorage`, which holds
    /// every byte in RAM by design, so resident memory there scales with the
    /// object however well the ingest streams — the instrument cannot perceive
    /// the property. Measured against the memory-backed store: peak RSS rose
    /// 481 MiB for 192 MiB of additional object, which says nothing
    /// about the ingest.
    ///
    /// The instrument is `VmHWM`, which only ever rises, so a second larger
    /// ingest that barely moves it is the assertion.
    ///
    /// **It is measured in a process of its own.** `VmHWM` is the process's,
    /// and the test binary runs every test in this crate on threads of one
    /// process, so a test sealing packs beside this one raised the peak this
    /// one reads — it went red at 71 MiB against 64 once tests that seal
    /// several 16 MiB packs across three stores ran beside it. So the test
    /// runs itself again, alone, in a child of this binary, and asserts that
    /// the child passed.
    #[tokio::test]
    async fn peak_memory_does_not_scale_with_the_object() {
        const ALONE: &str = "KOTTON_STORE_PEAK_MEMORY_ALONE";
        if std::env::var_os(ALONE).is_none() {
            let name = "provider::packed::tests::peak_memory_does_not_scale_with_the_object";
            let out = std::process::Command::new(std::env::current_exe().expect("this test binary"))
                .args([name, "--exact", "--test-threads=1", "--nocapture"])
                .env(ALONE, "1")
                .output()
                .expect("the measurement runs in a process of its own");
            let said = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
            assert!(out.status.success() && said.contains("1 passed"), "the measurement alone failed:\n{said}");
            eprintln!("{}", said.lines().filter(|l| l.contains("peak RSS")).collect::<Vec<_>>().join("\n"));
            return;
        }
        let dir = tempfile::tempdir().expect("a temporary directory");
        let backing = crate::LocalObjectStorage::new(
            dir.path().to_path_buf(),
            kotton_fs::provider::os::OsFilesystem,
        );
        let enc = EncryptedObjectStorage::new(backing, CEK);
        let blinded = BlindedObjectStorage::new(enc, derive_path_blind_key(&CEK));
        let s = PackedObjectStorage::new(blinded, derive_pack_key(&CEK));

        const PIECE: usize = 4 * 1024 * 1024;
        async fn ingest(
            s: &PackedObjectStorage<
                BlindedObjectStorage<EncryptedObjectStorage<crate::LocalObjectStorage>>,
            >,
            key: &str,
            pieces: usize,
            seed: u64,
        ) -> std::time::Duration {
            let t0 = std::time::Instant::now();
            let mut sink = s.begin_stream(Path::new(key)).await.unwrap().unwrap();
            for i in 0..pieces {
                sink.push(&piece(seed, i, PIECE)).await.unwrap();
            }
            sink.commit().await.unwrap();
            t0.elapsed()
        }

        // Warm every allocation path, so the first real reading is not measuring
        // lazy initialisation.
        let _ = ingest(&s, "warm.bin", 2, 1).await;

        let small_pieces = 16; // 64 MiB
        let t_small = ingest(&s, "small.bin", small_pieces, 2).await;
        let after_small = peak_rss_bytes();

        let large_pieces = 64; // 256 MiB — four times the object
        let t_large = ingest(&s, "large.bin", large_pieces, 3).await;
        let after_large = peak_rss_bytes();

        let grew = after_large.saturating_sub(after_small);
        let extra = ((large_pieces - small_pieces) * PIECE) as u64;
        eprintln!(
            "peak RSS {} MiB -> {} MiB (+{} MiB) for {} MiB more object; {:?} -> {:?}",
            after_small >> 20,
            after_large >> 20,
            grew >> 20,
            extra >> 20,
            t_small,
            t_large,
        );

        // Loose on purpose: this asserts the *shape* — flat rather than
        // proportional — and a tight bound would flake on a different allocator.
        assert!(
            grew < 64 * 1024 * 1024,
            "peak RSS grew by {} MiB for {} MiB more object — memory is still \
             scaling with the object",
            grew >> 20,
            extra >> 20,
        );

        // A bound that held because the write truncated would be worse than no
        // bound, so check the far end arrived.
        let total_len = (large_pieces * PIECE) as u64;
        let (tail, total) = s
            .get_range(Path::new("large.bin"), total_len - 8, 8)
            .await
            .unwrap();
        assert_eq!(total, total_len, "the whole object is there");
        assert_eq!(tail.len(), 8);
    }

    // ── a file keeps its versions ───────────────────────────────────────────
    //
    // A file keeps its versions when the person asks: a switch on the file,
    // on or off; the log's own entries name each version; the kept set is
    // what keeps its bytes; restore is a new write; off, and a delete, release.

    const NOTE: &str = "notes/plan.md";

    /// Write `bytes` at `path` and run the pass maintenance would.
    async fn write_packed(s: &TestStore, path: &str, bytes: &[u8]) {
        s.put(Path::new(path), bytes).await.unwrap();
        s.pack_loose().await.unwrap();
    }

    /// The chunk digests `path`'s packed entry holds right now.
    async fn chunks_of(s: &TestStore, path: &str) -> Vec<String> {
        let (_, m) = s.manifest().await.unwrap().unwrap();
        m.files[path].chunks.iter().map(|r| r.digest.clone()).collect()
    }

    /// Whether any chunk with one of these digests is still anywhere in the
    /// pack set — what "reclaimed" means once compaction has run.
    async fn held_anywhere(s: &TestStore, digests: &[String]) -> bool {
        for id in pack_ids(s).await {
            let blob = s.inner.get_sealed(Path::new(&id)).await.unwrap();
            let plaintext = open_pack(&s.k_pack, &blob).unwrap();
            for (_, framed) in scan_chunks(&plaintext) {
                if digests.contains(&chunk_digest(framed)) {
                    return true;
                }
            }
        }
        false
    }

    /// Off is the default and is **absent** from the manifest, so a store where
    /// nobody touched the switch writes the bytes it wrote before it existed.
    #[tokio::test]
    async fn a_file_keeps_no_versions_until_the_person_turns_it_on() {
        let s = logging_store();
        write_packed(&s, NOTE, b"first").await;
        write_packed(&s, NOTE, b"second").await;
        assert!(!s.keeps_versions(Path::new(NOTE)).await.unwrap());
        assert!(s.versions(Path::new(NOTE)).await.unwrap().is_empty());
        assert_eq!(s.versions_cost(Path::new(NOTE)).await.unwrap(), 0);

        let (_, m) = s.manifest().await.unwrap().unwrap();
        assert!(m.versions.is_empty());
        let json = String::from_utf8(m.to_chunk().unwrap()[1..].to_vec()).unwrap();
        assert!(
            !json.contains("keep_versions") && !json.contains("\"versions\""),
            "an off switch changed the manifest's bytes: {json}"
        );
    }

    /// Off is today's behaviour: what a write superseded is dead, and
    /// compaction reclaims it.
    #[tokio::test]
    async fn off_a_superseded_version_is_reclaimed() {
        let s = logging_store();
        write_packed(&s, NOTE, b"version one").await;
        let one = chunks_of(&s, NOTE).await;
        write_packed(&s, NOTE, b"version two").await;
        let two = chunks_of(&s, NOTE).await;
        write_packed(&s, NOTE, b"version three").await;

        assert!(held_anywhere(&s, &one).await, "the bytes are there until compaction runs");
        s.compact().await.unwrap();
        assert!(!held_anywhere(&s, &one).await, "an off file's superseded version survived");
        assert!(!held_anywhere(&s, &two).await, "an off file's superseded version survived");
        assert_eq!(s.get(Path::new(NOTE)).await.unwrap().as_ref(), b"version three");
    }

    /// On: every write that supersedes the file keeps what it superseded, the
    /// log names each one, and compaction — which reclaims everything else a
    /// write left behind — keeps them.
    #[tokio::test]
    async fn on_a_superseded_version_is_retained_through_compaction() {
        let s = logging_store();
        write_packed(&s, NOTE, b"version one").await;
        s.set_keep_versions(Path::new(NOTE), true).await.unwrap();
        assert!(s.keeps_versions(Path::new(NOTE)).await.unwrap());
        let one = chunks_of(&s, NOTE).await;
        write_packed(&s, NOTE, b"version two").await;
        let two = chunks_of(&s, NOTE).await;
        write_packed(&s, NOTE, b"version three!").await;

        let versions = s.versions(Path::new(NOTE)).await.unwrap();
        assert_eq!(versions.len(), 2, "two writes superseded two versions: {versions:?}");
        assert!(versions[0].at >= versions[1].at, "newest first");
        assert_eq!(
            versions.iter().map(|v| v.size).collect::<Vec<_>>(),
            vec![11, 11],
            "each version is the size the log recorded for it"
        );
        // Each one is exactly the chunks that differ: two one-chunk notes.
        assert_eq!(s.versions_cost(Path::new(NOTE)).await.unwrap(), 22);
        assert_eq!(s.versions_cost_total().await.unwrap(), 22);

        s.compact().await.unwrap();
        assert!(held_anywhere(&s, &one).await && held_anywhere(&s, &two).await);
        let mut back: Vec<Vec<u8>> = Vec::new();
        for v in &versions {
            back.push(s.read_version(Path::new(NOTE), &v.content_id).await.unwrap().to_vec());
        }
        assert_eq!(back, vec![b"version two".to_vec(), b"version one".to_vec()]);
        assert_eq!(s.get(Path::new(NOTE)).await.unwrap().as_ref(), b"version three!");
    }

    /// Off again releases what was kept, in the commit that turns it off, and
    /// the next compaction reclaims it.
    #[tokio::test]
    async fn turning_it_off_again_reclaims_what_it_kept() {
        let s = logging_store();
        write_packed(&s, NOTE, b"version one").await;
        s.set_keep_versions(Path::new(NOTE), true).await.unwrap();
        let one = chunks_of(&s, NOTE).await;
        write_packed(&s, NOTE, b"version two").await;
        let two = chunks_of(&s, NOTE).await;
        write_packed(&s, NOTE, b"version three").await;
        let kept = s.versions(Path::new(NOTE)).await.unwrap();
        assert_eq!(kept.len(), 2);

        s.set_keep_versions(Path::new(NOTE), false).await.unwrap();
        assert!(!s.keeps_versions(Path::new(NOTE)).await.unwrap());
        assert!(s.versions(Path::new(NOTE)).await.unwrap().is_empty());
        assert_eq!(s.versions_cost_total().await.unwrap(), 0);
        assert!(matches!(
            s.read_version(Path::new(NOTE), &kept[0].content_id).await,
            Err(ObjectStorageError::NotFound(_))
        ));

        s.compact().await.unwrap();
        assert!(!held_anywhere(&s, &one).await, "turning it off did not reclaim version one");
        assert!(!held_anywhere(&s, &two).await, "turning it off did not reclaim version two");
        assert_eq!(s.get(Path::new(NOTE)).await.unwrap().as_ref(), b"version three");
    }

    /// A restore is **a new write of old bytes**: the log only grows, the entry
    /// it appends names what it superseded, and the version it replaced is
    /// itself kept.
    #[tokio::test]
    async fn a_restore_is_a_new_write_and_the_log_only_grows() {
        let s = logging_store();
        write_packed(&s, NOTE, b"the good draft").await;
        s.set_keep_versions(Path::new(NOTE), true).await.unwrap();
        let good = s.manifest().await.unwrap().unwrap().1.files[NOTE].content_id();
        write_packed(&s, NOTE, b"the bad edit").await;
        let bad = s.manifest().await.unwrap().unwrap().1.files[NOTE].content_id();
        let log_before = s.manifest().await.unwrap().unwrap().1.log.clone();

        s.restore_version(Path::new(NOTE), &good).await.unwrap();
        assert_eq!(s.get(Path::new(NOTE)).await.unwrap().as_ref(), b"the good draft");
        s.pack_loose().await.unwrap();

        let log_after = s.manifest().await.unwrap().unwrap().1.log.clone();
        assert_eq!(
            &log_after[..log_before.len()],
            &log_before[..],
            "a restore rewrote history instead of adding to it"
        );
        let head = head_segment(&s).await.unwrap();
        assert!(
            head.entries.iter().any(|e| matches!(
                e,
                HistoryEntry::ObjectWrite { path, digest, parent, .. }
                    if path == NOTE && digest == &good && parent.as_deref() == Some(bad.as_str())
            )),
            "the restore is not a write naming what it superseded: {head:?}"
        );
        let now: Vec<String> =
            s.versions(Path::new(NOTE)).await.unwrap().into_iter().map(|v| v.content_id).collect();
        assert_eq!(now, vec![bad.clone()], "the bad edit is now the version, and the good one is current");
        assert_eq!(
            s.read_version(Path::new(NOTE), &bad).await.unwrap().as_ref(),
            b"the bad edit"
        );
    }

    /// The owner's step, in the store: turn it on, edit badly, get the old one
    /// back — before maintenance has packed the bad edit.
    #[tokio::test]
    async fn the_version_before_an_edit_not_yet_packed_is_already_reachable() {
        let s = logging_store();
        write_packed(&s, NOTE, b"what I meant").await;
        s.set_keep_versions(Path::new(NOTE), true).await.unwrap();
        s.put(Path::new(NOTE), b"what I typed at 2am").await.unwrap();

        let versions = s.versions(Path::new(NOTE)).await.unwrap();
        assert_eq!(versions.len(), 1, "the packed version is already before this write");
        s.restore_version(Path::new(NOTE), &versions[0].content_id).await.unwrap();
        assert_eq!(s.get(Path::new(NOTE)).await.unwrap().as_ref(), b"what I meant");

        // The bad edit was packed before the restore superseded it, so it is a
        // version now rather than bytes the restore overwrote unseen.
        let now = s.versions(Path::new(NOTE)).await.unwrap();
        assert_eq!(now.len(), 1);
        assert_eq!(
            s.read_version(Path::new(NOTE), &now[0].content_id).await.unwrap().as_ref(),
            b"what I typed at 2am"
        );
    }

    /// The version a write was made from: two writes made
    /// apart from one version record that same version and neither records the
    /// other; a restore records the version it restored; a fresh file's first
    /// write records none. And a restore's written-from is not its parent: it
    /// is written from what it restores and supersedes what was current, and
    /// the test pins both. What replay makes of that sequence is not asserted
    /// here — it reads the cycle as a conflict, which is filed, not pinned;
    /// see the note at the end of the test.
    #[tokio::test]
    async fn a_write_records_the_version_it_was_written_from() {
        fn write_of(seg: &Segment, path: &str) -> (String, Option<String>, Option<String>) {
            seg.entries
                .iter()
                .find_map(|e| match e {
                    HistoryEntry::ObjectWrite { path: p, digest, parent, written_from, .. }
                        if p == path =>
                    {
                        Some((digest.clone(), parent.clone(), written_from.clone()))
                    }
                    _ => None,
                })
                .expect("the segment holds a write of the path")
        }

        let a = device("did:kel:zA");
        let b = device("did:kel:zB");
        write_packed(&a, NOTE, b"base").await;
        let (base, _, first) = write_of(&head_segment(&a).await.unwrap(), NOTE);
        assert_eq!(first, None, "a fresh file's first write was written from nothing");
        ship_packs(&a, &b).await;
        b.reconcile().await.unwrap();

        write_packed(&a, NOTE, b"a's edit").await;
        write_packed(&b, NOTE, b"b's edit").await;
        let (a_edit, _, a_from) = write_of(&head_segment(&a).await.unwrap(), NOTE);
        let (b_edit, _, b_from) = write_of(&head_segment(&b).await.unwrap(), NOTE);
        assert_eq!(a_from.as_deref(), Some(base.as_str()));
        assert_eq!(b_from, a_from, "two writes from one version share it");
        assert_ne!(a_from.as_deref(), Some(b_edit.as_str()));
        assert_ne!(b_from.as_deref(), Some(a_edit.as_str()));

        // A restore on one device: written from what it restores, superseding
        // what was current.
        b.set_keep_versions(Path::new(NOTE), true).await.unwrap();
        write_packed(&b, NOTE, b"b's second edit").await;
        let (second, _, _) = write_of(&head_segment(&b).await.unwrap(), NOTE);
        b.restore_version(Path::new(NOTE), &b_edit).await.unwrap();
        let (restored, parent, from) = write_of(&head_segment(&b).await.unwrap(), NOTE);
        assert_eq!(restored, b_edit);
        assert_eq!(from.as_deref(), Some(b_edit.as_str()), "a restore is written from what it restores");
        assert_eq!(parent.as_deref(), Some(second.as_str()), "and supersedes what was current");
        let listed = b.versions(Path::new(NOTE)).await.unwrap();
        assert_eq!(listed[0].content_id, second);
        assert_eq!(listed[0].written_from.as_deref(), Some(b_edit.as_str()));

        assert_eq!(b.get(Path::new(NOTE)).await.unwrap().as_ref(), b"b's edit");
        // Replay of this log is not asserted here, on purpose: a write that
        // returns a file to content it held before (A → B → A) is a cycle in
        // content-id parents and replay reads it as a conflict, restore or
        // not. That is a known gap.
    }

    /// A file written but never packed has no entry for the switch to sit
    /// beside, so turning it on puts the file in the tree first.
    #[tokio::test]
    async fn turning_it_on_for_a_file_not_yet_packed_puts_it_in_the_tree() {
        let s = logging_store();
        s.put(Path::new(NOTE), b"fresh").await.unwrap();
        s.set_keep_versions(Path::new(NOTE), true).await.unwrap();
        let (_, m) = s.manifest().await.unwrap().unwrap();
        assert!(m.files[NOTE].keep_versions);
        write_packed(&s, NOTE, b"fresher").await;
        assert_eq!(s.versions(Path::new(NOTE)).await.unwrap().len(), 1);
    }

    /// A store that keeps no log has nothing to name a version by, so it says
    /// so rather than keeping bytes nobody can reach; a missing file is missing.
    #[tokio::test]
    async fn the_switch_is_refused_where_nothing_could_name_a_version() {
        let plain = store();
        write_packed(&plain, NOTE, b"x").await;
        assert!(plain.set_keep_versions(Path::new(NOTE), true).await.is_err());
        assert!(!plain.keeps_versions(Path::new(NOTE)).await.unwrap());

        let s = logging_store();
        assert!(matches!(
            s.set_keep_versions(Path::new("nowhere.md"), true).await,
            Err(ObjectStorageError::NotFound(_))
        ));
    }

    /// Rule 2: two devices that edit one file apart produce two versions; the
    /// store keeps both, byte for byte, and names neither. The destructuring of
    /// `FileVersion` is the other half of the rule: a field a person could name
    /// a version by would stop this from compiling.
    #[tokio::test]
    async fn two_writes_apart_are_two_versions_neither_merged_nor_named() {
        let a = device("did:kel:zA");
        let b = device("did:kel:zB");
        write_packed(&a, NOTE, b"base").await;
        ship_packs(&a, &b).await;
        b.reconcile().await.unwrap();
        b.set_keep_versions(Path::new(NOTE), true).await.unwrap();

        write_packed(&a, NOTE, b"a's edit").await;
        write_packed(&b, NOTE, b"b's edit").await;
        ship_packs(&a, &b).await;
        assert_eq!(b.reconcile().await.unwrap().unwrap().conflicts, 1);

        // A sync did not take the switch away: it is this device's fact.
        assert!(b.keeps_versions(Path::new(NOTE)).await.unwrap());

        let mut reachable: Vec<Vec<u8>> = vec![b.get(Path::new(NOTE)).await.unwrap().to_vec()];
        for v in b.versions(Path::new(NOTE)).await.unwrap() {
            let FileVersion { content_id, size, at: _, written_from: _ } = v;
            let bytes = b.read_version(Path::new(NOTE), &content_id).await.unwrap();
            assert_eq!(bytes.len() as u64, size);
            reachable.push(bytes.to_vec());
        }
        for id in b.retained_conflicts().await.unwrap().remove(NOTE).unwrap_or_default() {
            reachable.push(b.read_retained(Path::new(NOTE), &id).await.unwrap().to_vec());
        }
        reachable.sort();
        reachable.dedup();
        assert_eq!(
            reachable,
            vec![b"a's edit".to_vec(), b"b's edit".to_vec(), b"base".to_vec()],
            "each write is reachable exactly as written, and nothing else is"
        );
    }

    /// A snapshot collapses history, and would unname a kept file's versions
    /// while their bytes stayed kept. It carries a kept file's entries instead,
    /// and collapses everything else as before.
    #[tokio::test]
    async fn a_snapshot_keeps_the_entries_that_name_a_kept_version() {
        let s = logging_store();
        write_packed(&s, NOTE, b"version one").await;
        s.set_keep_versions(Path::new(NOTE), true).await.unwrap();
        write_packed(&s, NOTE, b"version two").await;
        write_packed(&s, NOTE, b"version three").await;
        write_packed(&s, "other.md", b"a").await;
        write_packed(&s, "other.md", b"b").await;
        let before = s.versions(Path::new(NOTE)).await.unwrap();
        assert_eq!(before.len(), 2);

        let summary = s.snapshot(0, &[]).await.unwrap().unwrap();
        assert!(summary.segments_subsumed > 1, "{summary:?}");
        assert_eq!(s.manifest().await.unwrap().unwrap().1.log.len(), 1);

        assert_eq!(s.versions(Path::new(NOTE)).await.unwrap(), before, "a snapshot unnamed a kept version");
        let head = head_segment(&s).await.unwrap();
        let other = head.entries.iter().filter(|e| e.path() == Some("other.md")).count();
        assert_eq!(other, 1, "a file that keeps nothing still collapses to one entry");
        assert_eq!(s.get(Path::new(NOTE)).await.unwrap().as_ref(), b"version three");
    }

    /// The switch is the file's, so a deleted file has none: its versions are
    /// released with it and compaction reclaims them.
    #[tokio::test]
    async fn deleting_a_kept_file_releases_its_versions() {
        let s = logging_store();
        write_packed(&s, NOTE, b"version one").await;
        s.set_keep_versions(Path::new(NOTE), true).await.unwrap();
        let one = chunks_of(&s, NOTE).await;
        write_packed(&s, NOTE, b"version two").await;
        write_packed(&s, "other.md", b"bystander").await;
        assert_eq!(s.versions(Path::new(NOTE)).await.unwrap().len(), 1);

        s.delete(Path::new(NOTE)).await.unwrap();
        assert!(s.versions(Path::new(NOTE)).await.unwrap().is_empty());
        s.pack_loose().await.unwrap();
        assert!(s.manifest().await.unwrap().unwrap().1.versions.is_empty());
        s.compact().await.unwrap();
        assert!(!held_anywhere(&s, &one).await);
    }

    /// A purge erases a path's history, and a kept version is history.
    #[tokio::test]
    async fn purge_erases_a_kept_files_versions() {
        let s = logging_store();
        write_packed(&s, NOTE, b"version one").await;
        s.set_keep_versions(Path::new(NOTE), true).await.unwrap();
        write_packed(&s, NOTE, b"version two").await;
        s.purge(Path::new(NOTE)).await.unwrap();
        let (_, m) = s.manifest().await.unwrap().unwrap();
        assert!(!m.versions.contains_key(NOTE) && !m.files.contains_key(NOTE));
    }

    /// **The wire half.** A kept version is chunks in ordinary sealed packs, so
    /// whatever moves packs moves it, and nothing a target holds says which
    /// chunk is a version and which a photo: every pack it ships is the same
    /// size. And the scope is **one device**: the bytes arrive, but
    /// the switch and the kept set are the writer's manifest, which does not
    /// travel, so the peer lists no version of the file. What a root's history
    /// means on its targets is undecided.
    #[tokio::test]
    async fn a_kept_version_travels_as_a_pack_and_the_promise_is_one_device() {
        let a = device("did:kel:zA");
        let b = device("did:kel:zB");
        write_packed(&a, NOTE, b"version one").await;
        a.set_keep_versions(Path::new(NOTE), true).await.unwrap();
        let one = chunks_of(&a, NOTE).await;
        write_packed(&a, NOTE, b"version two").await;
        a.compact().await.unwrap();
        assert!(held_anywhere(&a, &one).await);

        // Every pack is its class's fixed size (`has_its_fixed_size`), and the
        // pack the version is in is a content pack like any other.
        let packs = a.inner.list_sealed(Path::new(PACK_PREFIX)).await.unwrap();
        for m in packs.iter().filter(|m| !m.is_dir) {
            assert!(has_its_fixed_size(&m.key, m.size), "pack {} is shaped differently: {}", m.key, m.size);
        }
        let held_in = |r: &PackChunkRef| packs.iter().find(|m| m.key == r.pack_id.as_str()).map(|m| (is_content_pack(&m.key), m.size));
        let (_, manifest) = a.manifest().await.unwrap().unwrap();
        let kept = manifest.versions.get(NOTE).expect("the version is kept");
        for r in kept.iter().flat_map(|e| &e.chunks) {
            assert_eq!(held_in(r), Some((true, PACK_SIZE as u64)), "a version is not in a content pack like any other");
        }
        ship_packs(&a, &b).await;
        assert!(held_anywhere(&b, &one).await, "a kept version did not travel with the packs");

        b.reconcile().await.unwrap();
        assert_eq!(b.get(Path::new(NOTE)).await.unwrap().as_ref(), b"version two");
        assert!(!b.keeps_versions(Path::new(NOTE)).await.unwrap(), "the switch travelled");
        assert!(b.versions(Path::new(NOTE)).await.unwrap().is_empty(), "a peer listed a version");
        assert_eq!(a.versions(Path::new(NOTE)).await.unwrap().len(), 1);
    }

    /// **The cost, measured.** Small edits to a large file: a version costs the
    /// chunks that differ, so each edit costs about the chunk it landed in —
    /// not a copy of the file.
    ///
    /// The full measurement is a hundred edits:
    /// `KOTTON_VERSIONS_EDITS=100 cargo test -p kotton-store --lib -- \
    /// small_edits_to_a_large_file --nocapture`, whose printed line is the
    /// number. The
    /// suite runs ten, because every edit here is a packing pass that seals a
    /// fixed-size 16 MiB pack and reads it back, and a hundred of them would add
    /// most of an hour to `just test` to prove the same per-edit bound.
    #[tokio::test]
    async fn small_edits_to_a_large_file_cost_the_chunks_they_touched() {
        const SIZE: usize = 4 * 1024 * 1024;
        let edits: usize = std::env::var("KOTTON_VERSIONS_EDITS")
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or(10);
        let s = logging_store();
        let original = noise(SIZE, 7);
        write_packed(&s, "big.bin", &original).await;
        s.set_keep_versions(Path::new("big.bin"), true).await.unwrap();
        let file_chunks = chunks_of(&s, "big.bin").await.len();

        let mut current = original.clone();
        for i in 0..edits {
            // A few bytes overwritten in place, somewhere different each time.
            let at = (i * 40_503 + 1_234) % (SIZE - 16);
            current[at..at + 8].copy_from_slice(&(i as u64).to_le_bytes());
            write_packed(&s, "big.bin", &current).await;
            // What maintenance does between passes; without it the test holds
            // a hundred mostly-empty 16 MiB packs in memory.
            if i % 10 == 9 {
                s.compact().await.unwrap();
            }
        }

        let versions = s.versions(Path::new("big.bin")).await.unwrap();
        assert_eq!(versions.len(), edits, "one version per superseding write");
        let cost = s.versions_cost(Path::new("big.bin")).await.unwrap();
        let copies = (edits * SIZE) as u64;
        eprintln!(
            "versions cost: {edits} edits of 8 bytes to a {} MiB file ({file_chunks} chunks) \
             cost {cost} bytes ({:.1} MiB, {:.2} chunks of 256 KiB per edit); \
             {edits} full copies would be {} MiB — {:.1}% of that",
            SIZE >> 20,
            cost as f64 / (1 << 20) as f64,
            cost as f64 / edits as f64 / crate::chunker::TARGET_CHUNK as f64,
            copies >> 20,
            100.0 * cost as f64 / copies as f64,
        );
        assert!(
            cost <= (edits * 2 * crate::chunker::MAX_CHUNK) as u64,
            "a small edit cost more than the chunks around it: {cost} bytes"
        );
        assert!(cost < copies / 4, "versions cost like copies: {cost} of {copies}");

        // And the oldest is the original, byte for byte, after every compaction.
        let oldest = versions.last().unwrap();
        assert_eq!(
            s.read_version(Path::new("big.bin"), &oldest.content_id).await.unwrap().as_ref(),
            original.as_slice()
        );
    }

    /// **A pack id is admitted where the manifest is decoded** (kotton #273).
    ///
    /// The manifest names the packs every read and every compaction builds a
    /// key from, and the device that wrote it may not be this one. So a
    /// manifest naming a pack id outside the reserved grammar ([`PackId`]) is
    /// refused when it is decoded, before a key is built from it. Here it is
    /// the only generation, so there is none to fall back to
    /// ([`load_committed`]; the fallback is the next test): the read fails
    /// naming the id, compaction fails, nothing is asked of a drive and
    /// nothing is written. The shelf here is a memory store, which takes a
    /// key's characters as they are, as a bucket does: refused at decode, `..`
    /// never reaches a shelf of either kind.
    #[tokio::test]
    async fn a_manifest_naming_a_pack_outside_the_grammar_is_refused_and_nothing_is_fetched_or_written() {
        use crate::fetch::PackSlot;
        use std::sync::atomic::Ordering;

        for bad in ["_pack/../x", &format!("{CONTENT_PACK_PREFIX}{}", "zz".repeat(16)), ""] {
            let backing = MemoryObjectStorage::new();
            let slot = PackSlot::default();
            let s = fetching(&backing, &slot);
            s.put(Path::new("notes/a.md"), b"hello").await.unwrap();
            s.pack_loose().await.unwrap();

            // A manifest that names `bad` where the file's pack was, committed
            // as the current generation the way any device's commit is.
            let (generation, _) = s.manifest().await.unwrap().unwrap();
            let earlier = s.inner.list_sealed(Path::new(SUPERBLOCK_PREFIX)).await.unwrap();
            commit_forged_manifest(&s, "notes/a.md", bad, generation + 1).await;
            for m in earlier {
                s.inner.delete_sealed(Path::new(&m.key)).await.unwrap();
            }

            let drive = Arc::new(AnsweringDrive { asked: Default::default() });
            slot.lend(drive.clone());
            let before = shelf_keys(&backing).await;
            let fresh = fetching(&backing, &slot);
            match fresh.get(Path::new("notes/a.md")).await {
                Err(e) => assert!(e.to_string().contains(&format!("storage key {bad:?} refused")), "{bad:?}: {e}"),
                Ok(b) => panic!("{bad:?}: a manifest naming it was read: {b:?}"),
            }
            assert!(fresh.compact().await.is_err(), "{bad:?}: compaction ran on a manifest naming it");
            assert_eq!(drive.asked.load(Ordering::SeqCst), 0, "{bad:?}: a drive was asked for it");
            assert_eq!(shelf_keys(&backing).await, before, "{bad:?}: something was written");
        }
    }

    /// A drive that answers every fetch, as a hostile one would.
    struct AnsweringDrive {
        asked: std::sync::atomic::AtomicUsize,
    }
    #[async_trait]
    impl crate::fetch::PackSource for AnsweringDrive {
        async fn fetch(&self, _user_id: &str, _key: &str) -> anyhow::Result<Option<Bytes>> {
            self.asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Some(Bytes::from_static(b"whatever the drive serves")))
        }
    }

    /// A packed store over a shelf that fetches what it misses from the drive
    /// lent to `slot`, the shelf a memory store: it takes a key's characters
    /// as they are, as a bucket does.
    fn fetching(
        backing: &MemoryObjectStorage,
        slot: &crate::fetch::PackSlot,
    ) -> PackedObjectStorage<BlindedObjectStorage<EncryptedObjectStorage<crate::fetch::FetchOnMiss>>> {
        let shelf = crate::fetch::FetchOnMiss::new(Arc::new(backing.clone()), "alice", slot.clone());
        let enc = EncryptedObjectStorage::new(shelf, CEK);
        PackedObjectStorage::new(BlindedObjectStorage::new(enc, derive_path_blind_key(&CEK)), derive_pack_key(&CEK))
    }

    async fn shelf_keys(backing: &MemoryObjectStorage) -> BTreeSet<String> {
        backing.list(Path::new("")).await.unwrap().into_iter().map(|m| m.key).collect()
    }

    /// Commit, as generation `generation`, the current manifest with the
    /// first chunk of `path` naming pack `bad`: what a device of the person's
    /// that writes a bad ref commits. Only that ref changes; another file's
    /// ref into the same pack keeps naming it.
    async fn commit_forged_manifest<S: LooseObjectSource + 'static>(
        s: &PackedObjectStorage<S>,
        path: &str,
        bad: &str,
        generation: u64,
    ) {
        commit_edited_manifest(s, generation, |m| {
            m["files"][path]["chunks"][0]["pack_id"] = serde_json::Value::from(bad);
        })
        .await;
    }

    /// Commit, as generation `generation`, the current manifest as `edit`
    /// leaves its JSON. Sealed under the store's own key, so everything but
    /// the edit is authentic.
    async fn commit_edited_manifest<S: LooseObjectSource + 'static>(
        s: &PackedObjectStorage<S>,
        generation: u64,
        edit: impl FnOnce(&mut serde_json::Value),
    ) {
        let (_, manifest) = s.manifest().await.unwrap().unwrap();
        let mut value = serde_json::to_value(&*manifest).unwrap();
        edit(&mut value);
        let json = serde_json::to_string(&value).unwrap();
        let framed = frame_chunk(ChunkKind::Manifest, json.as_bytes());
        let (blob, refs) = crate::pack::seal_pack(&derive_pack_key(&CEK), &[framed.as_slice()]).unwrap();
        let holder = format!("{PACK_PREFIX}/{:032x}", generation | 0xab00);
        s.inner.put_sealed(Path::new(&holder), &blob).await.unwrap();
        let manifest_ref: PackChunkRef = serde_json::from_value(serde_json::json!({
            "pack_id": holder,
            "offset": refs[0].offset,
            "length": refs[0].length,
            "digest": crate::manifest::chunk_digest(&framed),
        }))
        .unwrap();
        let sb = Superblock { version: 1, generation, manifest: manifest_ref };
        commit_superblock(&*s.inner, &derive_pack_key(&CEK), &sb).await.unwrap();
    }

    /// The superblock keys of generation `generation` on `s`'s shelf.
    async fn superblocks_of<S: LooseObjectSource + 'static>(s: &PackedObjectStorage<S>, generation: u64) -> Vec<String> {
        let tag = format!("{generation:020}-");
        s.inner.list_sealed(Path::new(SUPERBLOCK_PREFIX)).await.unwrap()
            .into_iter().map(|m| m.key).filter(|k| k.contains(&tag)).collect()
    }

    /// The `warn` lines emitted on this thread while it is alive: the channel
    /// the generation fallback reports on (`crate::superblock`). A
    /// current-thread test runtime keeps every poll on this thread.
    struct WarnLines(Arc<Mutex<Vec<String>>>);
    impl tracing::Subscriber for WarnLines {
        fn enabled(&self, m: &tracing::Metadata<'_>) -> bool {
            *m.level() <= tracing::Level::WARN
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            struct Line<'a>(&'a mut String);
            impl tracing::field::Visit for Line<'_> {
                fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
                    use std::fmt::Write as _;
                    let _ = write!(self.0, "{}={v:?} ", f.name());
                }
            }
            let mut line = String::new();
            event.record(&mut Line(&mut line));
            self.0.lock().unwrap().push(line);
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// **A newer manifest that does not decode is passed over, like a
    /// superblock that does not open** (kotton #273, PR 298's assessment).
    ///
    /// Two files across two generations; the newer generation's manifest names
    /// `_pack/../x`. The store reads the generation before it: the older file
    /// reads, the listing works, nothing is asked of a drive or written for the
    /// bad id, and the refusal is reported on the channel the existing
    /// fallback reports on. Compaction, the one pass that deletes, does not run
    /// on the strength of a fallback.
    #[tokio::test]
    async fn a_newer_manifest_that_does_not_decode_falls_back_to_the_last_good_generation() {
        use crate::fetch::PackSlot;
        use std::sync::atomic::Ordering;

        let backing = MemoryObjectStorage::new();
        let slot = PackSlot::default();
        let s = fetching(&backing, &slot);
        s.put(Path::new("notes/a.md"), b"older").await.unwrap();
        s.pack_loose().await.unwrap();
        s.put(Path::new("notes/b.md"), b"newer").await.unwrap();
        s.pack_loose().await.unwrap();

        // Generation 2 is replaced by a generation 2 whose manifest names the
        // bad id for `b.md`, as the device that wrote it would have committed.
        let (generation, _) = s.manifest().await.unwrap().unwrap();
        assert_eq!(generation, 2);
        let sbs = superblocks_of(&s, 2).await;
        commit_forged_manifest(&s, "notes/b.md", "_pack/../x", 2).await;
        for k in sbs {
            s.inner.delete_sealed(Path::new(&k)).await.unwrap();
        }

        let drive = Arc::new(AnsweringDrive { asked: Default::default() });
        slot.lend(drive.clone());
        let before = shelf_keys(&backing).await;
        let lines = Arc::new(Mutex::new(Vec::new()));
        let _capture = tracing::subscriber::set_default(WarnLines(lines.clone()));
        // Another test may already have registered the warn's callsite with
        // no subscriber, and `Dispatch::new` rebuilds interest before
        // `set_default` counts this one: rebuild now that it does.
        tracing::callsite::rebuild_interest_cache();

        let fresh = fetching(&backing, &slot);
        assert_eq!(fresh.get(Path::new("notes/a.md")).await.unwrap().as_ref(), b"older");
        let listed: Vec<String> = fresh.list(Path::new("")).await.unwrap().into_iter().map(|m| m.key).collect();
        assert_eq!(listed, ["notes/a.md"], "the listing is not generation 1's");
        assert!(
            matches!(fresh.get(Path::new("notes/b.md")).await, Err(ObjectStorageError::NotFound(_))),
            "a file only the refused generation names was served"
        );
        let refused = lines.lock().unwrap().clone();
        assert!(
            refused.iter().any(|l| l.contains("_pack/../x") && l.contains("00000000000000000002-")),
            "the refusal was not reported: {refused:?}"
        );

        let err = fresh.compact().await.expect_err("compaction ran over a generation it passed over");
        assert!(err.to_string().contains("_pack/../x"), "{err}");
        assert_eq!(drive.asked.load(Ordering::SeqCst), 0, "a drive was asked for the bad id");
        assert_eq!(shelf_keys(&backing).await, before, "something was written or deleted");
    }

    /// **A name under `_pack/` outside the grammar is left, and counted**
    /// (kotton #273). A peer's object sync admits a structurally canonical
    /// key such as `_pack/zz`, which is no pack id. Compaction never reads or
    /// deletes it, as the store never wrote it, so its summary is where it
    /// shows.
    #[tokio::test]
    async fn compaction_counts_the_names_it_leaves_unadmitted() {
        let s = store();
        s.put(Path::new("notes/a.md"), b"hello").await.unwrap();
        s.pack_loose().await.unwrap();
        for planted in ["_pack/zz", "_pack/c-zz"] {
            s.inner.put_sealed(Path::new(planted), b"planted").await.unwrap();
        }
        let summary = s.compact().await.unwrap().unwrap();
        assert_eq!(summary.packs_unadmitted, 2, "{summary:?}");
        for planted in ["_pack/zz", "_pack/c-zz"] {
            assert_eq!(s.inner.get_sealed(Path::new(planted)).await.unwrap().as_ref(), b"planted");
        }
        assert_eq!(s.get(Path::new("notes/a.md")).await.unwrap().as_ref(), b"hello");
    }

    /// **Data only a skipped generation names is held, not deleted**
    /// (kotton #273, PR 298's second assessment).
    ///
    /// Generation 1 holds `a`; generation 2 holds `a`, `b` and `c`, and only
    /// `c`'s ref names `_pack/../x`, so `b`'s pack is named by the refused
    /// manifest alone. Two later writes commit above the skipped generation
    /// (numbered past it, #308), and compaction stays off while it is present:
    /// it refuses naming the generation and the id, and `b`'s pack and the
    /// skipped superblock are still on the shelf. `b` is unreadable meanwhile;
    /// everything else reads and writes.
    #[tokio::test]
    async fn a_pack_only_a_skipped_generation_names_is_held_and_compaction_stays_off() {
        use crate::fetch::PackSlot;
        use std::sync::atomic::Ordering;

        let backing = MemoryObjectStorage::new();
        let slot = PackSlot::default();
        let s = fetching(&backing, &slot);
        s.put(Path::new("notes/a.md"), b"one").await.unwrap();
        s.pack_loose().await.unwrap();
        s.put(Path::new("notes/b.md"), b"two").await.unwrap();
        s.put(Path::new("notes/c.md"), b"three").await.unwrap();
        s.pack_loose().await.unwrap();
        let (generation, manifest) = s.manifest().await.unwrap().unwrap();
        assert_eq!(generation, 2);
        let b_pack = manifest.files["notes/b.md"].chunks[0].pack_id.to_string();
        let real = superblocks_of(&s, 2).await;
        commit_forged_manifest(&s, "notes/c.md", "_pack/../x", 2).await;
        for k in real {
            s.inner.delete_sealed(Path::new(&k)).await.unwrap();
        }
        let skipped = superblocks_of(&s, 2).await;
        assert_eq!(skipped.len(), 1);

        let drive = Arc::new(AnsweringDrive { asked: Default::default() });
        slot.lend(drive.clone());
        let fresh = fetching(&backing, &slot);
        fresh.put(Path::new("notes/d.md"), b"four").await.unwrap();
        let first = fresh.pack_loose().await.unwrap().unwrap();
        assert_eq!(first.generation, Some(3), "a commit past the skipped generation is not numbered above it");
        fresh.put(Path::new("notes/e.md"), b"five").await.unwrap();
        fresh.pack_loose().await.unwrap();

        let err = fresh.compact().await.expect_err("compaction ran while a skipped generation names data");
        assert!(err.to_string().contains("_pack/../x") && err.to_string().contains(&skipped[0]), "{err}");
        let shelf = shelf_keys(&backing).await;
        assert!(shelf.contains(&b_pack), "the pack only the skipped generation names was deleted");
        assert!(shelf.contains(&skipped[0]), "the skipped generation's superblock was retired");
        for (path, bytes) in [("notes/a.md", &b"one"[..]), ("notes/d.md", b"four"), ("notes/e.md", b"five")] {
            assert_eq!(fresh.get(Path::new(path)).await.unwrap().as_ref(), bytes, "{path}");
        }
        assert!(matches!(fresh.get(Path::new("notes/b.md")).await, Err(ObjectStorageError::NotFound(_))));
        assert_eq!(drive.asked.load(Ordering::SeqCst), 0, "a drive was asked for the bad id");
    }

    /// **Only a pack-id refusal is skipped.** A manifest of a version this
    /// code does not read is not a bad ref: it is a newer format, and building
    /// past it would roll back the device that wrote it. Its generation fails
    /// the load as before, and nothing is written or deleted.
    #[tokio::test]
    async fn a_manifest_of_an_unsupported_version_fails_the_load_and_is_not_skipped() {
        let backing = MemoryObjectStorage::new();
        let slot = crate::fetch::PackSlot::default();
        let s = fetching(&backing, &slot);
        s.put(Path::new("notes/a.md"), b"one").await.unwrap();
        s.pack_loose().await.unwrap();
        commit_edited_manifest(&s, 2, |m| m["version"] = serde_json::Value::from(2)).await;

        let before = shelf_keys(&backing).await;
        let fresh = fetching(&backing, &slot);
        let err = fresh.get(Path::new("notes/a.md")).await.expect_err("a newer format was skipped");
        assert!(err.to_string().contains("unsupported manifest version 2"), "{err}");
        assert!(fresh.list(Path::new("")).await.is_err(), "a newer format was listed past");
        assert!(fresh.compact().await.is_err(), "compaction ran past a newer format");
        assert_eq!(shelf_keys(&backing).await, before, "something was written or deleted");
    }
}
