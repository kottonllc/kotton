// SPDX-License-Identifier: AGPL-3.0-or-later
//! Manifest layer — the sealed map from files to pack chunks.
//!
//! Packs are opaque containers ([`crate::pack`]); this layer is what turns them
//! back into files. A [`Manifest`] maps each logical path to the chunks that
//! constitute it, and each chunk to `(pack_id, offset, length)`. Manifests are
//! themselves stored as chunks in packs, indistinguishable from data to a
//! replica.
//!
//! # Chunk framing and scan recovery
//!
//! Every chunk carries a one-byte **kind tag** inside the seal:
//!
//! ```text
//! chunk payload := [ kind: u8 ][ bytes ]
//! ```
//!
//! The tag is what makes the store self-describing: a device that has lost the
//! superblock (or never had one) can open every pack, walk its chunks, and find
//! the manifests by tag — recovering every file with no external index. That is
//! the continuity invariant reaching this layer: the mnemonic and the
//! pack set are sufficient, and nothing else is load-bearing.
//!
//! The tag costs one byte per chunk and is inside the AEAD, so a replica cannot
//! use it to tell a manifest chunk from a photo chunk (the history log depends
//! on exactly this indistinguishability).

use crate::packed::PackId;
use kotton_sys::store::{ObjectStorageError, ObjectStorageResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// What a chunk's payload is, recorded inside the seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkKind {
    /// File content bytes.
    Data,
    /// A serialized [`Manifest`].
    Manifest,
    /// A sealed history-log segment, carrying object changes as well as record
    /// ones. The tag byte is the one reserved as `RecordSegment`; only the name
    /// is wider, with the log's scope.
    HistorySegment,
}

impl ChunkKind {
    fn to_byte(self) -> u8 {
        match self {
            Self::Data => 0,
            Self::Manifest => 1,
            Self::HistorySegment => 2,
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Data),
            1 => Some(Self::Manifest),
            2 => Some(Self::HistorySegment),
            _ => None,
        }
    }
}

/// Frame a chunk payload with its kind tag.
pub fn frame_chunk(kind: ChunkKind, bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + bytes.len());
    out.push(kind.to_byte());
    out.extend_from_slice(bytes);
    out
}

/// Split a framed chunk back into its kind and payload.
///
/// An unknown tag is refused rather than guessed at — a future format that adds
/// tags must bump a version, not rely on old readers misinterpreting new kinds.
pub fn unframe_chunk(framed: &[u8]) -> ObjectStorageResult<(ChunkKind, &[u8])> {
    let (&tag, rest) = framed.split_first().ok_or_else(|| {
        ObjectStorageError::BackendError("chunk too short to carry a kind tag".into())
    })?;
    let kind = ChunkKind::from_byte(tag).ok_or_else(|| {
        ObjectStorageError::BackendError(format!("unknown chunk kind tag {tag}"))
    })?;
    Ok((kind, rest))
}

/// Where a chunk lives across the pack set — what a manifest records per chunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackChunkRef {
    /// The pack object's storage key, admitted where it is decoded
    /// ([`PackId`], kotton #273): a manifest or superblock naming anything
    /// outside the reserved grammar does not decode.
    pub pack_id: PackId,
    /// Byte offset of the chunk's length prefix within the pack plaintext.
    pub offset: u32,
    /// Chunk payload length, including the kind tag.
    pub length: u32,
    /// Hex BLAKE3 digest of the framed chunk payload.
    ///
    /// The positional fields say *where* a chunk is; this says *what* it is —
    /// the identity that deduplication, cheap versioning (two versions of a file
    /// share every unchanged chunk), and skip-unchanged sync all key on. Inside
    /// the sealed manifest, so a replica learns nothing from it. Recorded from
    /// day one because retrofitting it is a format migration and recording it is
    /// one field.
    pub digest: String,
}

/// The hex BLAKE3 digest a [`PackChunkRef`] carries for a framed chunk payload.
pub fn chunk_digest(framed: &[u8]) -> String {
    hex_encode(blake3_bytes(framed))
}

fn blake3_bytes(data: &[u8]) -> [u8; 32] {
    use kotton_sys::crypto::Hasher as _;
    let out = kotton_crypto::Blake3Hasher::new()
        .hash(data)
        .expect("blake3 is infallible");
    out.try_into().expect("blake3 output is 32 bytes")
}

fn hex_encode(bytes: [u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// One file's entry: its true size and the chunks that reconstruct it, in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    /// True (unpadded) file size in bytes.
    pub size: u64,
    /// Last-modified Unix seconds, carried for sync's LWW comparison.
    pub modified: Option<u64>,
    /// The file's chunks, concatenated in order to reconstruct it.
    pub chunks: Vec<PackChunkRef>,
    /// Whether this file **keeps its versions** — the person's switch, on or
    /// off and nothing else.
    ///
    /// A fact about the file, so it lives here beside `size` and `modified` and
    /// never in the file's bytes: the content id is the chunks alone, so turning
    /// it on or off changes no version of the file. Off is the default and is
    /// **not serialized**, so every manifest written before the switch existed —
    /// and every one written since for a file that never had it turned on —
    /// is byte-identical to what it was, which is what keeps manifests
    /// deterministic across devices that never touched the switch.
    ///
    /// On, a write that supersedes this file's content moves the superseded
    /// entry into [`Manifest::versions`] instead of letting its chunks go dead.
    /// Off, nothing is retained and whatever was is released.
    #[serde(default, skip_serializing_if = "is_false")]
    pub keep_versions: bool,
}

/// For `skip_serializing_if`: an off switch is the absence of the field.
fn is_false(b: &bool) -> bool {
    !*b
}

impl FileEntry {
    /// A stable identity for this file's *content*, derived from its chunk
    /// digests.
    ///
    /// The history log needs to name "the version of this path I had" without
    /// re-reading the file — a parent version has to be computable from the
    /// manifest alone, for entries whose bytes may be in a pack this device has
    /// never opened. Chunk digests are content-addressed, so hashing the
    /// ordered list is equivalent to hashing the content and costs nothing.
    ///
    /// Identical content therefore yields an identical id on every device,
    /// which is what makes `parent` comparable across writers.
    pub fn content_id(&self) -> String {
        content_id_of_digests(self.chunks.iter().map(|r| r.digest.as_str()))
    }
}

/// The content id ([`FileEntry::content_id`]) of the chunks whose digests are
/// `digests`, in order: what a file's content id is, computed before or
/// without a pack to place its chunks in.
pub fn content_id_of_digests<'a>(digests: impl IntoIterator<Item = &'a str>) -> String {
    let mut joined = String::new();
    for digest in digests {
        joined.push_str(digest);
        joined.push('\n');
    }
    hex_encode(blake3_bytes(joined.as_bytes()))
}

/// The sealed map from logical paths to pack chunks.
///
/// Serialized as JSON and stored as a `ChunkKind::Manifest` chunk. `BTreeMap`
/// rather than `HashMap` so serialization is deterministic — two devices
/// materialising the same state produce byte-identical manifests, which keeps
/// manifest chunks dedupable and comparisons meaningful.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Format version, for forward migration. Currently 1.
    pub version: u32,
    /// The superblock generation this manifest was written for.
    ///
    /// Redundant while a superblock exists — it names the manifest directly.
    /// It exists for **scan recovery**: with the superblock lost, a scan finds
    /// every manifest ever committed still sitting in a pack, and nothing else
    /// in the format says which of them is current. Manifests written before
    /// this field read as generation 0, which sorts oldest — the correct
    /// degradation, since any manifest written since carries a real one.
    #[serde(default)]
    pub generation: u64,
    /// path → file entry. Paths are canonical object keys (forward slashes, no
    /// leading slash) — the *logical* names, sealed here and nowhere visible.
    pub files: BTreeMap<String, FileEntry>,
    /// The history segments currently in the log, oldest first.
    ///
    /// This is the log's **liveness set**, and it lives here rather than in the
    /// superblock for three reasons. The superblock's sealed plaintext is a
    /// fixed 1024 bytes, which holds only a handful of chunk refs. Compaction
    /// already reads the manifest, so it learns which segments to preserve for
    /// free instead of having to open every pack and classify chunks
    /// structurally. And a recovery scan recovers the manifest, so recovering the
    /// manifest now recovers the log with it.
    ///
    /// A segment chunk not named here is collectable: that is precisely what a
    /// snapshot does — write one segment subsuming a run of others, then shorten
    /// this list. Retention policy is therefore expressed entirely as *what
    /// stays in this vector*.
    #[serde(default)]
    pub log: Vec<PackChunkRef>,
    /// path → the versions that lost a concurrent write and are **retained**.
    ///
    /// Replication never destroys the only copy. `replay()`
    /// already keeps a losing `Version`, but that is metadata — digest, size,
    /// writer. Without the entry here its chunks are referenced by nothing, and
    /// compaction reclaims unreferenced chunks. Retaining the record while
    /// dropping the bytes is still destroying the write; this is what makes the
    /// retention real.
    ///
    /// These entries are live for compaction exactly as `files` is. They leave
    /// when the conflict is resolved, which is the same shape as a delete on a
    /// store: retained by default, released by an explicit act.
    #[serde(default)]
    pub conflicts: BTreeMap<String, Vec<FileEntry>>,
    /// path → superseded entries of a file whose switch is on, **retained**.
    ///
    /// This is a liveness set and not a version list, and the difference is the
    /// whole design. *Which* versions a file has and *when* each was written is
    /// the history log's to say: every one of these was committed as an
    /// `ObjectWrite` entry naming its content id, its size and its moment, and
    /// that entry is what a person reaches a version by. The log carries no
    /// chunk references on purpose, so on its own it names bytes that
    /// compaction would reclaim; an entry here is what keeps them. Nothing here
    /// carries a name, a message or a parent — the log already says the
    /// only things a version is.
    ///
    /// Live for compaction exactly as `files` and `conflicts` are. An entry
    /// leaves when the file's switch is turned off, when the file is deleted, or
    /// when the path is purged — each an explicit act of the person's, never a
    /// duration the platform picked.
    ///
    /// Empty is not serialized, for the reason `FileEntry::keep_versions` is not.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub versions: BTreeMap<String, Vec<FileEntry>>,
}

impl Manifest {
    /// An empty v1 manifest.
    pub fn new() -> Self {
        Self {
            version: 1,
            generation: 0,
            files: BTreeMap::new(),
            log: Vec::new(),
            conflicts: BTreeMap::new(),
            versions: BTreeMap::new(),
        }
    }

    /// Serialize to the framed chunk payload (`ChunkKind::Manifest`).
    pub fn to_chunk(&self) -> ObjectStorageResult<Vec<u8>> {
        let json = serde_json::to_vec(self).map_err(|e| {
            ObjectStorageError::BackendError(format!("manifest serialize: {e}"))
        })?;
        Ok(frame_chunk(ChunkKind::Manifest, &json))
    }

    /// Parse from a framed chunk payload, refusing a non-manifest kind.
    pub fn from_chunk(framed: &[u8]) -> ObjectStorageResult<Self> {
        let (kind, bytes) = unframe_chunk(framed)?;
        if kind != ChunkKind::Manifest {
            return Err(ObjectStorageError::BackendError(format!(
                "expected a manifest chunk, found {kind:?}"
            )));
        }
        let manifest: Self = serde_json::from_slice(bytes).map_err(|e| {
            ObjectStorageError::BackendError(format!("manifest parse: {e}"))
        })?;
        if manifest.version != 1 {
            return Err(ObjectStorageError::BackendError(format!(
                "unsupported manifest version {}",
                manifest.version
            )));
        }
        Ok(manifest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::{read_chunk, seal_pack};

    const KEY: [u8; 32] = [0x5a; 32];

    fn sample() -> Manifest {
        let mut m = Manifest::new();
        m.files.insert(
            "notes/2026/trip.md".into(),
            FileEntry {
                size: 5,
                modified: Some(1_700_000_000),
                chunks: vec![PackChunkRef {
                    pack_id: PackId::parse(&format!("_pack/c-{}", "7a".repeat(16))).unwrap(),
                    offset: 0,
                    length: 6,
                    digest: chunk_digest(b"\x00hello"),
                }],
                keep_versions: false,
            },
        );
        m
    }

    #[test]
    fn a_manifest_round_trips_through_chunk_framing() {
        let m = sample();
        assert_eq!(Manifest::from_chunk(&m.to_chunk().unwrap()).unwrap(), m);
    }

    /// Deterministic serialization: the same logical state always produces the
    /// same bytes, whichever device writes it.
    #[test]
    fn serialization_is_deterministic() {
        let mut a = Manifest::new();
        let mut b = Manifest::new();
        for key in ["z", "a", "m"] {
            let entry = FileEntry {
                size: 1,
                modified: None,
                chunks: vec![],
                keep_versions: false,
            };
            a.files.insert(key.into(), entry.clone());
        }
        for key in ["m", "z", "a"] {
            let entry = FileEntry {
                size: 1,
                modified: None,
                chunks: vec![],
                keep_versions: false,
            };
            b.files.insert(key.into(), entry.clone());
        }
        assert_eq!(a.to_chunk().unwrap(), b.to_chunk().unwrap());
    }

    /// Scan recovery's mechanism: manifests are recoverable from the pack set alone by
    /// scanning chunk kind tags — no superblock, no index.
    #[test]
    fn a_manifest_is_recoverable_by_scanning_a_pack() {
        let m = sample();
        let manifest_chunk = m.to_chunk().unwrap();
        let data_chunk = frame_chunk(ChunkKind::Data, b"just a photo");
        let chunks: Vec<&[u8]> = vec![&data_chunk, &manifest_chunk];
        let (blob, refs) = seal_pack(&KEY, &chunks).unwrap();

        // A recovering device opens the pack and walks every chunk by tag.
        let mut recovered: Vec<Manifest> = Vec::new();
        for r in &refs {
            let framed = read_chunk(&KEY, &blob, *r).unwrap();
            if let Ok((ChunkKind::Manifest, _)) = unframe_chunk(&framed) {
                recovered.push(Manifest::from_chunk(&framed).unwrap());
            }
        }
        assert_eq!(recovered, vec![m]);
    }

    #[test]
    fn a_data_chunk_is_not_mistaken_for_a_manifest() {
        let framed = frame_chunk(ChunkKind::Data, b"{\"version\":1,\"files\":{}}");
        assert!(
            Manifest::from_chunk(&framed).is_err(),
            "kind tag, not content sniffing, decides what a chunk is"
        );
    }

    #[test]
    fn an_unknown_kind_tag_is_refused() {
        assert!(unframe_chunk(&[9, 1, 2, 3]).is_err());
        assert!(unframe_chunk(&[]).is_err());
    }

    /// **A pack id is admitted where the manifest is decoded** (kotton #273).
    /// A manifest naming a pack outside the reserved grammar
    /// (`crate::packed::PackId`) does not decode, wherever in it the ref sits:
    /// so no key is ever built from that id, on any shelf.
    #[test]
    fn a_manifest_naming_a_pack_outside_the_grammar_does_not_decode() {
        let good = sample();
        let real = good.files["notes/2026/trip.md"].chunks[0].pack_id.to_string();
        let hex = "7a".repeat(16);
        for bad in [
            "_pack/../x".to_string(),
            format!("_pack/c-{}", "zz".repeat(16)),
            String::new(),
            format!("_pack/{}", &hex[..31]),
            format!("_pack/{}", hex.to_uppercase()),
            format!("/_pack/{hex}"),
            format!("_pack/{hex}/x"),
            format!("_pack/i-{}", &hex[..30]),
            format!("_superblock/{hex}"),
        ] {
            let mut in_log = good.clone();
            in_log.log.push(good.files["notes/2026/trip.md"].chunks[0].clone());
            for m in [&good, &in_log] {
                let json = serde_json::to_string(m)
                    .unwrap()
                    .replace(&format!("\"{real}\""), &format!("\"{bad}\""));
                assert!(json.contains(&format!("\"pack_id\":\"{bad}\"")), "{json}");
                let err = Manifest::from_chunk(&frame_chunk(ChunkKind::Manifest, json.as_bytes()))
                    .expect_err(&format!("a manifest naming {bad:?} decoded"));
                assert!(err.to_string().contains(&format!("storage key {bad:?} refused")), "{bad:?}: {err}");
            }
        }
        // The ids the store writes decode as they are.
        for id in [format!("_pack/{hex}"), format!("_pack/c-{hex}")] {
            let json = serde_json::to_string(&good).unwrap().replace(&format!("\"{real}\""), &format!("\"{id}\""));
            let m = Manifest::from_chunk(&frame_chunk(ChunkKind::Manifest, json.as_bytes())).unwrap();
            assert_eq!(m.files["notes/2026/trip.md"].chunks[0].pack_id.as_str(), id);
        }
    }

    #[test]
    fn an_unsupported_version_is_refused() {
        let mut m = sample();
        m.version = 2;
        let framed = m.to_chunk().unwrap();
        assert!(Manifest::from_chunk(&framed).is_err());
    }

    /// The digest is content identity: same payload, same digest; one byte off,
    /// different digest — what dedup, versioning, and skip-unchanged sync key on.
    #[test]
    fn chunk_digests_are_content_identity() {
        let a = frame_chunk(ChunkKind::Data, b"same bytes");
        let b = frame_chunk(ChunkKind::Data, b"same bytes");
        let c = frame_chunk(ChunkKind::Data, b"same bytez");
        assert_eq!(chunk_digest(&a), chunk_digest(&b));
        assert_ne!(chunk_digest(&a), chunk_digest(&c));
        assert_eq!(chunk_digest(&a).len(), 64, "hex blake3 is 64 chars");
    }

    /// The tag rides inside the pack seal, so what a replica stores reveals no
    /// kind byte in the clear — the property the history log leans on.
    #[test]
    fn kind_tags_are_sealed_not_visible() {
        let manifest_chunk = sample().to_chunk().unwrap();
        let chunks: Vec<&[u8]> = vec![&manifest_chunk];
        let (blob, _) = seal_pack(&KEY, &chunks).unwrap();
        // The serialized manifest JSON must not appear in the sealed pack.
        assert!(
            !blob
                .windows(b"\"files\"".len())
                .any(|w| w == b"\"files\""),
            "manifest content leaked into the sealed pack"
        );
    }
}
