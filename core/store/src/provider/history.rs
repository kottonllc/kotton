// SPDX-License-Identifier: AGPL-3.0-or-later
//! The sealed history log, of records and of objects.
//!
//! Each device appends **segments**: immutable, sealed batches of changes. A
//! segment is stored as a chunk in a pack like any other data, so a replica
//! cannot tell a history segment from a photo — that property comes from
//! blinded keys and fixed-size packs rather than from anything here, which is
//! why this rests on them.
//!
//! # Why a log at all
//!
//! Object replication currently compares two listings and moves whatever
//! differs, which cannot express a delete (an absence is indistinguishable from
//! "not yet copied") and cannot tell a concurrent edit from a sequential one.
//! Both need changes to be **facts** rather than states. Once they are, one
//! mechanism yields delete propagation, causal conflict detection, offline
//! catch-up, version history, and point-in-time restore.
//!
//! # Double sealing
//!
//! A segment is sealed **twice**, and the inner seal is the point. The outer
//! seal is the pack's (`K_pack`, CEK-derived, object domain) and is free — it
//! is what packs already do. The inner seal is `K_log`, derived from
//! `master_secret`, so history stays in the db key domain, which is separate
//! from object contents. A device holding only the CEK can therefore
//! *carry* segments without reading them, and a CEK compromise does not yield
//! the user's history.
//!
//! # Encoding
//!
//! Canonical CBOR is the natural format. This uses JSON with `BTreeMap`-ordered
//! structures instead, matching [`Manifest`](crate::manifest::Manifest), which
//! made the same call for the same reason — determinism, so two devices
//! materialising identical state produce identical bytes and the chunk dedupes.
//! No CBOR crate is in the workspace, and adding a serialization dependency
//! under a seal is a supply-chain decision that should not be made in passing.
//! Said here rather than left as drift.

use crate::manifest::{frame_chunk, unframe_chunk, ChunkKind};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use kotton_sys::store::{ObjectStorageError, ObjectStorageResult};
use rand::RngCore as _;
use serde::{Deserialize, Serialize};

/// ChaCha20-Poly1305 nonce length.
const NONCE_LEN: usize = 12;

/// One recorded change.
///
/// Record payloads are **opaque here on purpose**. The log's contract is to
/// carry facts, not to interpret them; only the record layer above knows what a
/// changeset row means. Keeping it opaque is also what keeps this crate from
/// depending on the record schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Entry {
    /// A file was written with this content.
    ObjectWrite {
        /// Canonical logical path (forward slashes, no leading slash).
        path: String,
        /// BLAKE3 digest of the full content, as content identity.
        digest: String,
        /// True (unpadded) size in bytes.
        size: u64,
        /// The version of this path the writer held when it wrote — the causal
        /// predecessor **for this path specifically**. `None` means the writer
        /// believed the path did not exist. Two entries for one path sharing a
        /// parent are concurrent *by construction*, which is what makes
        /// conflict detection a fact rather than a guess about clocks.
        parent: Option<String>,
        /// Wall-clock seconds. May order two concurrent writes; may never
        /// decide *whether* they conflict.
        at: u64,
        /// The version this content was **written from** — the content id of
        /// the version the writer had open when it wrote — or `None` for a
        /// fresh file's first write.
        ///
        /// Not [`parent`](Self::ObjectWrite::parent), though for an ordinary
        /// write the two are the same content. `parent` is what this write
        /// *supersedes*, and replay decides conflicts by it; `written_from` is
        /// where the bytes *came from*. They part at a restore: it supersedes
        /// the version that was current and was written from the one it
        /// restores, and folding the second into `parent` would make replay
        /// read the superseded version as a concurrent head. Two writes made
        /// apart from one version share a `written_from`, which is the common
        /// ancestor a later reconcile — a person's, in an app, never the
        /// store's — needs and could not recover if it were not recorded now.
        ///
        /// Causality, not a name: a content id, like `parent`. Absent from the
        /// serialized entry when `None`, so a segment written before this field
        /// existed reads as it always did.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        written_from: Option<String>,
    },
    /// A file was deleted. A delete is an entry, not an absence — which is the
    /// whole reason deletes can propagate and stop resurrecting.
    ObjectDelete {
        /// Canonical logical path.
        path: String,
        /// As [`Entry::ObjectWrite::parent`].
        parent: Option<String>,
        /// Wall-clock seconds.
        at: u64,
    },
    /// An opaque record-layer changeset row.
    Record {
        /// Serialized row, interpreted only by the record layer.
        payload: Vec<u8>,
        /// Wall-clock seconds.
        at: u64,
    },
}

impl Entry {
    /// The path this entry concerns, for object entries.
    pub fn path(&self) -> Option<&str> {
        match self {
            Self::ObjectWrite { path, .. } | Self::ObjectDelete { path, .. } => Some(path),
            Self::Record { .. } => None,
        }
    }

    /// Wall-clock seconds recorded on this entry.
    pub fn at(&self) -> u64 {
        match self {
            Self::ObjectWrite { at, .. } | Self::ObjectDelete { at, .. } | Self::Record { at, .. } => *at,
        }
    }
}

/// One device's immutable batch of changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Segment {
    /// Format version, for forward migration. Currently 1.
    pub version: u32,
    /// The **DID** of the writer.
    ///
    /// A DID rather than a fleet-local device id, and nothing in the current
    /// design needs that generality — every writer today is one of your own
    /// devices. It is here because a shared space requires writers outside your
    /// fleet, and widening the identity field later would re-cut the format of
    /// the mechanism everything else is built on.
    pub writer: String,
    /// Per-writer, monotonic.
    pub seq: u64,
    /// Digests of the segments this writer had seen when it wrote.
    ///
    /// Not required for convergence — the underlying reconciliation is
    /// last-write-wins and converges regardless — but it lets a reader detect
    /// that it is *missing* segments rather than silently merging a partial
    /// view.
    pub parents: Vec<String>,
    /// Whether this segment carries merged base state rather than a batch of
    /// changes.
    ///
    /// It changes what `parents` means, which is why it has to be recorded
    /// rather than inferred. On an ordinary segment a parent that is absent is
    /// **missing** — go and fetch it. On a snapshot the parents are the
    /// segments it *subsumed*, so their absence is the expected outcome of
    /// collection, not a gap. Without this flag every replay after the first
    /// snapshot would report the whole collected history as missing, and the
    /// signal would be worthless exactly when it started mattering.
    #[serde(default)]
    pub snapshot: bool,
    /// The changes, in the order they occurred.
    pub entries: Vec<Entry>,
}

impl Segment {
    /// A new v1 segment.
    pub fn new(writer: impl Into<String>, seq: u64) -> Self {
        Self {
            version: 1,
            writer: writer.into(),
            seq,
            parents: Vec::new(),
            snapshot: false,
            entries: Vec::new(),
        }
    }

    /// Seal under `k_log` and frame as a [`ChunkKind::HistorySegment`] chunk —
    /// the form that goes into a pack.
    pub fn to_chunk(&self, k_log: &[u8; 32]) -> ObjectStorageResult<Vec<u8>> {
        let json = serde_json::to_vec(self)
            .map_err(|e| ObjectStorageError::BackendError(format!("segment serialize: {e}")))?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let cipher = ChaCha20Poly1305::new(k_log.into());
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &json,
                    aad: &[],
                },
            )
            .map_err(|_| ObjectStorageError::BackendError("segment seal failed".into()))?;

        let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        sealed.extend_from_slice(&nonce_bytes);
        sealed.extend_from_slice(&ciphertext);
        Ok(frame_chunk(ChunkKind::HistorySegment, &sealed))
    }

    /// Unframe and open a segment chunk, refusing a chunk of another kind.
    ///
    /// Refusing on kind matters more than it looks: without it, a caller
    /// holding `K_log` could be handed a data chunk and would fail with a
    /// decrypt error rather than a type error, which reads as corruption when
    /// it is a routing bug.
    pub fn from_chunk(k_log: &[u8; 32], framed: &[u8]) -> ObjectStorageResult<Self> {
        let (kind, sealed) = unframe_chunk(framed)?;
        if kind != ChunkKind::HistorySegment {
            return Err(ObjectStorageError::BackendError(format!(
                "expected a history segment chunk, found {kind:?}"
            )));
        }
        if sealed.len() < NONCE_LEN {
            return Err(ObjectStorageError::BackendError(
                "segment chunk too short to be sealed".into(),
            ));
        }
        let (nonce_bytes, ciphertext) = sealed.split_at(NONCE_LEN);
        let cipher = ChaCha20Poly1305::new(k_log.into());
        let json = cipher
            .decrypt(
                Nonce::from_slice(nonce_bytes),
                Payload {
                    msg: ciphertext,
                    aad: &[],
                },
            )
            .map_err(|_| {
                ObjectStorageError::BackendError(
                    "segment open failed (wrong key or corrupt)".into(),
                )
            })?;

        let segment: Self = serde_json::from_slice(&json)
            .map_err(|e| ObjectStorageError::BackendError(format!("segment parse: {e}")))?;
        if segment.version != 1 {
            return Err(ObjectStorageError::BackendError(format!(
                "unsupported segment version {}",
                segment.version
            )));
        }
        Ok(segment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::chunk_digest;

    const K_LOG: [u8; 32] = [0x7c; 32];
    const OTHER: [u8; 32] = [0x3d; 32];

    fn sample() -> Segment {
        let mut s = Segment::new("did:kel:zAlice", 7);
        s.parents = vec!["abc123".into()];
        s.entries = vec![
            Entry::ObjectWrite {
                path: "notes/trip.md".into(),
                digest: "deadbeef".into(),
                size: 42,
                parent: None,
                at: 1_700_000_000,
                written_from: None,
            },
            Entry::ObjectDelete {
                path: "old/gone.txt".into(),
                parent: Some("cafe".into()),
                at: 1_700_000_001,
            },
            Entry::Record {
                payload: b"opaque row".to_vec(),
                at: 1_700_000_002,
            },
        ];
        s
    }

    #[test]
    fn a_segment_round_trips_through_its_seal() {
        let framed = sample().to_chunk(&K_LOG).unwrap();
        assert_eq!(Segment::from_chunk(&K_LOG, &framed).unwrap(), sample());
    }

    #[test]
    fn the_wrong_key_cannot_open_a_segment() {
        let framed = sample().to_chunk(&K_LOG).unwrap();
        assert!(Segment::from_chunk(&OTHER, &framed).is_err());
    }

    /// The inner seal is the reason segments are db-domain: a peer holding the
    /// pack key sees a chunk it cannot read.
    #[test]
    fn a_segment_body_is_not_legible_in_the_framed_chunk() {
        let framed = sample().to_chunk(&K_LOG).unwrap();
        for needle in [
            b"notes/trip.md".as_slice(),
            b"did:kel:zAlice".as_slice(),
            b"opaque row".as_slice(),
        ] {
            assert!(
                !framed.windows(needle.len()).any(|w| w == needle),
                "plaintext {:?} survived the seal",
                std::str::from_utf8(needle).unwrap()
            );
        }
    }

    #[test]
    fn a_data_chunk_is_not_mistaken_for_a_segment() {
        let data = frame_chunk(ChunkKind::Data, b"file bytes");
        let err = Segment::from_chunk(&K_LOG, &data).unwrap_err().to_string();
        assert!(err.contains("expected a history segment"), "{err}");
    }

    #[test]
    fn a_truncated_segment_is_refused_not_panicked_on() {
        let framed = sample().to_chunk(&K_LOG).unwrap();
        for cut in [framed.len() - 1, framed.len() / 2, 3] {
            assert!(Segment::from_chunk(&K_LOG, &framed[..cut]).is_err());
        }
    }

    /// Two devices materialising the same segment must produce the same
    /// *plaintext*; the sealed bytes differ because the nonce is random, which
    /// is why segments are addressed by their chunk digest rather than expected
    /// to dedupe against one another.
    #[test]
    fn sealing_is_randomised_but_the_body_is_deterministic() {
        let a = sample().to_chunk(&K_LOG).unwrap();
        let b = sample().to_chunk(&K_LOG).unwrap();
        assert_ne!(chunk_digest(&a), chunk_digest(&b));
        assert_eq!(
            Segment::from_chunk(&K_LOG, &a).unwrap(),
            Segment::from_chunk(&K_LOG, &b).unwrap()
        );
    }
}
