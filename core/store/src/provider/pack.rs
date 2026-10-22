// SPDX-License-Identifier: AGPL-3.0-or-later
//! Pack format — the fixed-size sealed container.
//!
//! A pack holds many chunks, sealed as one AEAD blob of exactly `PACK_SIZE`
//! bytes. A replica sees a set of identical-looking blobs and cannot tell how
//! many chunks any pack holds, how large they are, or which chunks belong to the
//! same file — chunk boundaries and lengths live *inside* the seal. The mapping from files to chunks is a separate manifest layer built on
//! top of this.
//!
//! # What this module is, and is not
//!
//! This is the container primitive only: pack a set of chunks into a sealed
//! blob, and read one chunk back by its position. It has no notion of files,
//! manifests, compaction, or a superblock — those compose above it. Keeping the
//! seal/unseal and the byte layout in one small, exhaustively-tested unit is the
//! point: it is the layer a bug corrupts *all* of the user's data, so it earns
//! more tests than code.
//!
//! # Layout
//!
//! ```text
//! plaintext := [ chunk₁ ‖ chunk₂ ‖ … ‖ zero-padding ]
//! chunk     := [ len: u32 BE ][ bytes ]
//! pack blob := AEAD( K_pack, nonce, plaintext )        exactly PACK_SIZE on disk
//! ```
//!
//! The AEAD tag and nonce are stored alongside the ciphertext, so the on-disk
//! object is `nonce ‖ ciphertext ‖ tag`, padded with the sealed zeros so every
//! pack is byte-identical in size. Padding is *inside* the seal, so the padding
//! bytes are indistinguishable from content and the true fill level does not
//! leak.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use kotton_sys::store::{ObjectStorageError, ObjectStorageResult};
use rand::RngCore as _;

/// Default pack size — 16 MiB. A per-mount constant in practice;
/// exposed here as the default the container is built and validated against.
pub const PACK_SIZE: usize = 16 * 1024 * 1024;

/// ChaCha20-Poly1305 nonce length.
const NONCE_LEN: usize = 12;
/// ChaCha20-Poly1305 tag length.
const TAG_LEN: usize = 16;
/// Per-chunk length prefix width.
const CHUNK_LEN_BYTES: usize = 4;

/// Where a chunk sits inside a pack's *plaintext* — everything needed to read it
/// back, and exactly what a manifest stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkRef {
    /// Byte offset of the chunk's length prefix within the pack plaintext.
    pub offset: u32,
    /// Chunk payload length (not counting the prefix).
    pub length: u32,
}

/// The largest total chunk payload one pack can hold, after the seal overhead
/// and per-chunk prefixes are accounted for.
///
/// Exposed so the packer above this layer knows when to seal and open a fresh
/// pack rather than discovering it by overflow.
pub const fn max_payload() -> usize {
    PACK_SIZE - NONCE_LEN - TAG_LEN
}

/// Seal `chunks` into one `PACK_SIZE` blob, returning the blob and a `ChunkRef`
/// for each chunk in the order given.
///
/// Fails if the chunks do not fit — the caller (a packer that fills packs to
/// capacity) is expected to size batches against [`max_payload`], so an overflow
/// here is a logic error, not a runtime condition.
pub fn seal_pack(key: &[u8; 32], chunks: &[&[u8]]) -> ObjectStorageResult<(Vec<u8>, Vec<ChunkRef>)> {
    let mut plaintext = Vec::with_capacity(max_payload());
    let mut refs = Vec::with_capacity(chunks.len());

    for chunk in chunks {
        let len = u32::try_from(chunk.len()).map_err(|_| {
            ObjectStorageError::BackendError("chunk exceeds u32 length".into())
        })?;
        let offset = u32::try_from(plaintext.len()).map_err(|_| {
            ObjectStorageError::BackendError("pack plaintext exceeds u32 offset".into())
        })?;
        plaintext.extend_from_slice(&len.to_be_bytes());
        plaintext.extend_from_slice(chunk);
        refs.push(ChunkRef {
            offset,
            length: len,
        });
    }

    if plaintext.len() > max_payload() {
        return Err(ObjectStorageError::BackendError(format!(
            "chunks total {} bytes, exceeds pack payload capacity {}",
            plaintext.len(),
            max_payload()
        )));
    }

    // Pad the plaintext to the fixed fill target so the ciphertext is constant
    // size. The zeros are sealed, so they are indistinguishable from content.
    plaintext.resize(max_payload(), 0);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = ChaCha20Poly1305::new(key.into());
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &plaintext,
                aad: &[],
            },
        )
        .map_err(|_| ObjectStorageError::BackendError("pack seal failed".into()))?;

    let mut blob = Vec::with_capacity(PACK_SIZE);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    debug_assert_eq!(blob.len(), PACK_SIZE, "sealed pack is not PACK_SIZE");

    Ok((blob, refs))
}

/// Open a pack blob and return its whole plaintext (still including padding).
///
/// Callers reading a single chunk should prefer [`read_chunk`], which slices
/// without exposing the padding; this exists for a full re-pack pass.
pub fn open_pack(key: &[u8; 32], blob: &[u8]) -> ObjectStorageResult<Vec<u8>> {
    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err(ObjectStorageError::BackendError(
            "pack blob too short to be sealed".into(),
        ));
    }
    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: &[],
            },
        )
        .map_err(|_| ObjectStorageError::BackendError("pack open failed (wrong key or corrupt)".into()))
}

/// Walk every chunk in an opened pack plaintext, in stored order.
///
/// The primitive behind scan recovery: with no superblock there is no index, so
/// the only way back is to read the packs themselves and let the kind tags say
/// what each chunk is.
///
/// Stops at the first zero-length prefix, which begins the padding. A framed
/// chunk always carries a kind tag and a version, so it is never empty and zero
/// is unambiguous. A truncated tail ends the walk rather than failing it —
/// everything before the damage is still recoverable, which is the entire point
/// of scanning.
pub fn scan_chunks(plaintext: &[u8]) -> Vec<(ChunkRef, &[u8])> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + CHUNK_LEN_BYTES <= plaintext.len() {
        let len = u32::from_be_bytes(plaintext[at..at + CHUNK_LEN_BYTES].try_into().unwrap());
        if len == 0 {
            break;
        }
        let start = at + CHUNK_LEN_BYTES;
        let Some(end) = start.checked_add(len as usize).filter(|e| *e <= plaintext.len()) else {
            break;
        };
        out.push((
            ChunkRef {
                offset: at as u32,
                length: len,
            },
            &plaintext[start..end],
        ));
        at = end;
    }
    out
}

/// Read a single chunk from a pack blob by its `ChunkRef`, without materialising
/// the padding.
///
/// This is the hot path — reading one file's chunk out of a 16 MiB pack — so it
/// opens the pack and slices exactly the referenced range, validating that the
/// stored length prefix matches the ref (a mismatch means a corrupt or
/// mis-addressed pack, and is refused rather than returning wrong bytes).
pub fn read_chunk(key: &[u8; 32], blob: &[u8], chunk: ChunkRef) -> ObjectStorageResult<Vec<u8>> {
    let plaintext = open_pack(key, blob)?;
    read_chunk_from_plaintext(&plaintext, chunk)
}

/// Slice one chunk out of an already-opened pack plaintext, with the same
/// validation as [`read_chunk`].
///
/// For callers reading several chunks from one pack — a multi-chunk file, a
/// verification pass — so the 16 MiB AEAD open happens once per pack rather
/// than once per chunk.
pub fn read_chunk_from_plaintext(
    plaintext: &[u8],
    chunk: ChunkRef,
) -> ObjectStorageResult<Vec<u8>> {
    let start = chunk.offset as usize;
    let len_end = start + CHUNK_LEN_BYTES;
    if len_end > plaintext.len() {
        return Err(ObjectStorageError::BackendError(
            "chunk offset past end of pack".into(),
        ));
    }
    let stored_len = u32::from_be_bytes(plaintext[start..len_end].try_into().unwrap());
    if stored_len != chunk.length {
        return Err(ObjectStorageError::BackendError(format!(
            "chunk length mismatch at offset {}: ref says {}, pack says {stored_len}",
            chunk.offset, chunk.length
        )));
    }
    let data_end = len_end + chunk.length as usize;
    if data_end > plaintext.len() {
        return Err(ObjectStorageError::BackendError(
            "chunk length past end of pack".into(),
        ));
    }
    Ok(plaintext[len_end..data_end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x5a; 32];

    #[test]
    fn a_chunk_round_trips_by_ref() {
        let chunks: Vec<&[u8]> = vec![b"first", b"second chunk", b"third"];
        let (blob, refs) = seal_pack(&KEY, &chunks).unwrap();
        assert_eq!(blob.len(), PACK_SIZE, "every pack is exactly PACK_SIZE");
        for (chunk, r) in chunks.iter().zip(&refs) {
            assert_eq!(&read_chunk(&KEY, &blob, *r).unwrap(), chunk);
        }
    }

    /// The property the whole design rests on: a pack blob reveals nothing about
    /// its contents. Two packs holding wildly different chunk sets are identical
    /// in size, and neither leaks a chunk boundary or length in the clear.
    #[test]
    fn a_pack_is_opaque_and_constant_size() {
        let (few, _) = seal_pack(&KEY, &[b"x"]).unwrap();
        let big = vec![7u8; 1_000_000];
        let (many, _) = seal_pack(&KEY, &[&big, &big, &big]).unwrap();
        assert_eq!(few.len(), many.len(), "size must not track fill");
        assert_eq!(few.len(), PACK_SIZE);

        // The distinctive payload does not appear in the clear.
        assert!(
            !many.windows(16).any(|w| w == [7u8; 16]),
            "chunk content leaked into the sealed pack"
        );
    }

    #[test]
    fn a_wrong_key_cannot_open_a_pack() {
        let (blob, refs) = seal_pack(&KEY, &[b"secret"]).unwrap();
        let wrong = [0x99; 32];
        assert!(open_pack(&wrong, &blob).is_err());
        assert!(read_chunk(&wrong, &blob, refs[0]).is_err());
    }

    /// A pack corrupted on disk must be *detected*, never returned as garbage.
    #[test]
    fn a_corrupted_pack_is_detected() {
        let (mut blob, refs) = seal_pack(&KEY, &[b"important"]).unwrap();
        // Flip a byte in the ciphertext body.
        blob[NONCE_LEN + 4] ^= 0xff;
        assert!(
            read_chunk(&KEY, &blob, refs[0]).is_err(),
            "AEAD must reject a tampered pack, not return wrong bytes"
        );
    }

    /// A `ChunkRef` that does not match what the pack actually stores is refused,
    /// so a mis-addressed or swapped ref cannot serve the wrong chunk.
    #[test]
    fn a_mismatched_ref_is_refused() {
        let (blob, refs) = seal_pack(&KEY, &[b"aaaa", b"bbbbbbbb"]).unwrap();
        // Claim the first chunk has the second's length.
        let bad = ChunkRef {
            offset: refs[0].offset,
            length: refs[1].length,
        };
        assert!(read_chunk(&KEY, &blob, bad).is_err());
    }

    #[test]
    fn an_empty_chunk_round_trips() {
        let (blob, refs) = seal_pack(&KEY, &[b""]).unwrap();
        assert_eq!(read_chunk(&KEY, &blob, refs[0]).unwrap(), b"");
    }

    #[test]
    fn overflowing_the_pack_is_an_error_not_a_panic() {
        let too_big = vec![0u8; max_payload()]; // no room for the length prefix
        assert!(seal_pack(&KEY, &[&too_big]).is_err());
    }

    #[test]
    fn a_full_reopen_returns_the_padded_plaintext() {
        let (blob, refs) = seal_pack(&KEY, &[b"hi"]).unwrap();
        let plain = open_pack(&KEY, &blob).unwrap();
        assert_eq!(plain.len(), max_payload(), "plaintext is padded to capacity");
        // The chunk is still readable from the reopened plaintext at its ref.
        let start = refs[0].offset as usize + CHUNK_LEN_BYTES;
        assert_eq!(&plain[start..start + 2], b"hi");
    }
}
