// SPDX-License-Identifier: AGPL-3.0-or-later
//! Content-defined chunking — gear-hash boundaries in the FastCDC
//! family.
//!
//! A file is split where a rolling hash of its own bytes crosses a threshold, so
//! boundaries are a function of *content*, not position. Insert a byte near the
//! start of a fixed-offset scheme and every later chunk shifts — the whole file
//! re-uploads after a one-byte edit. Content-defined boundaries re-synchronise
//! within a chunk or two, so an edit changes a bounded neighbourhood and sync
//! moves only that.
//!
//! # Determinism is format-critical
//!
//! Two devices must chunk the same bytes identically, or the same file dedups
//! against nothing and every device re-uploads its own copy. Everything that
//! decides a boundary — the gear table, the masks, the size bounds — is
//! therefore **fixed forever**, like a KDF label. A change is a new chunker
//! *version* recorded in mount metadata, never a silent retune.
//!
//! The gear table is generated at compile time from a fixed splitmix64 seed
//! rather than embedded as 256 literals: same stability, and the derivation is
//! auditable instead of being a wall of magic numbers.
//!
//! # Parameters
//!
//! Min 64 KiB / target 256 KiB / max 1 MiB. Sized against `PACK_SIZE` = 16 MiB
//! (a pack holds ~64 target-size chunks) and against the known-file
//! fingerprinting analysis: chunks are sealed inside packs, so chunk size never
//! reaches a replica — these bounds are purely about edit locality and manifest
//! size, not privacy.

/// Minimum chunk size — no boundary is considered before this many bytes.
pub const MIN_CHUNK: usize = 64 * 1024;
/// Target (average) chunk size.
pub const TARGET_CHUNK: usize = 256 * 1024;
/// Maximum chunk size — a boundary is forced at this many bytes.
pub const MAX_CHUNK: usize = 1024 * 1024;

/// Mask giving ~`TARGET_CHUNK` average: 18 one-bits ⇒ a boundary roughly every
/// 2¹⁸ = 256 KiB of content.
const BOUNDARY_MASK: u64 = (1 << 18) - 1;

/// The 256-entry gear table, derived from a fixed seed. **Never regenerate with
/// a different seed** — boundaries are wire/format stability.
const GEAR: [u64; 256] = build_gear_table();

/// splitmix64 — tiny, well-known, and `const`-evaluable, which is the whole
/// reason it is used here: the table is derived at compile time from one seed
/// instead of pasted as literals.
const fn splitmix64(state: u64) -> (u64, u64) {
    let state = state.wrapping_add(0x9E3779B97F4A7C15);
    let mut z = state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    (state, z ^ (z >> 31))
}

const fn build_gear_table() -> [u64; 256] {
    // The seed spells "kotton-cdc-v1" packed into a u64 — arbitrary, but fixed.
    let mut state: u64 = 0x6B6F74746F6E5F31;
    let mut table = [0u64; 256];
    let mut i = 0;
    while i < 256 {
        let (next, value) = splitmix64(state);
        state = next;
        table[i] = value;
        i += 1;
    }
    table
}

/// Split `data` into content-defined chunks, returned as `(offset, length)`
/// pairs covering the input exactly, in order.
///
/// Deterministic: the same bytes always produce the same boundaries, on every
/// device, forever (see module docs). An empty input produces no chunks.
pub fn chunk_boundaries(data: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut start = 0;

    while start < data.len() {
        let remaining = &data[start..];
        let len = find_boundary(remaining);
        out.push((start, len));
        start += len;
    }
    out
}

/// The same boundaries, found without ever holding the whole input.
///
/// [`chunk_boundaries`] needs the file in memory to split it, so every caller
/// of the packer did too — a ceiling a model larger than the store would seal
/// meets. This is the same
/// function fed a piece at a time.
///
/// **It produces byte-identical chunks**, and that is a format property rather
/// than a nicety: two devices that chunked the same bytes differently would
/// dedup against nothing and each re-upload its own copy. The reason it can
/// promise that is in [`find_boundary`] — the scan never looks past
/// [`MAX_CHUNK`] bytes, so once that many are buffered the next boundary is
/// already decided and no later byte can move it. The streaming form therefore
/// waits for `MAX_CHUNK` before cutting, and at end of stream finishes the tail
/// exactly as the whole-buffer form finishes the last chunk.
///
/// Peak memory is under `MAX_CHUNK` plus the largest piece pushed.
#[derive(Default)]
pub struct StreamChunker {
    buf: Vec<u8>,
}

impl StreamChunker {
    /// A chunker with nothing buffered.
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Feed the next bytes of the object; returns every chunk now decided.
    ///
    /// Decided means final: a chunk returned here is the same chunk
    /// [`chunk_boundaries`] would have produced at that offset over the whole
    /// object.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<Vec<u8>> {
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        // `>=`, not `>`: with MAX_CHUNK bytes in hand the scan cannot see
        // further even if more arrive, so the boundary is already final.
        while self.buf.len() >= MAX_CHUNK {
            let len = find_boundary(&self.buf);
            out.push(self.buf[..len].to_vec());
            self.buf.drain(..len);
        }
        out
    }

    /// End of stream: the chunks the buffered tail splits into.
    ///
    /// The tail is under `MAX_CHUNK`, so it is one chunk except where
    /// [`find_boundary`] cuts it earlier — the same last-chunk rule the
    /// whole-buffer form uses, which is why the two agree to the byte.
    pub fn finish(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while !self.buf.is_empty() {
            let len = find_boundary(&self.buf);
            out.push(self.buf[..len].to_vec());
            self.buf.drain(..len);
        }
        out
    }
}

/// Length of the next chunk at the head of `data`.
fn find_boundary(data: &[u8]) -> usize {
    if data.len() <= MIN_CHUNK {
        return data.len();
    }
    let limit = data.len().min(MAX_CHUNK);
    let mut hash: u64 = 0;

    // The hash warms up over the bytes before MIN_CHUNK but no boundary is
    // taken there, so a boundary decision always has a full window behind it.
    for (i, &byte) in data[..limit].iter().enumerate() {
        hash = (hash << 1).wrapping_add(GEAR[byte as usize]);
        if i >= MIN_CHUNK && (hash & BOUNDARY_MASK) == 0 {
            return i + 1;
        }
    }
    limit
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic pseudo-random buffer — content with enough entropy for
    /// the gear hash to find natural boundaries.
    fn noise(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed;
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            let (next, v) = splitmix64(state);
            state = next;
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.truncate(len);
        out
    }

    #[test]
    fn boundaries_cover_the_input_exactly() {
        let data = noise(3 * 1024 * 1024, 7);
        let chunks = chunk_boundaries(&data);
        let mut expected_start = 0;
        for (start, len) in &chunks {
            assert_eq!(*start, expected_start, "chunks must be contiguous");
            expected_start = start + len;
        }
        assert_eq!(expected_start, data.len(), "chunks must cover the input");
    }

    #[test]
    fn bounds_are_respected() {
        let data = noise(8 * 1024 * 1024, 42);
        let chunks = chunk_boundaries(&data);
        for (i, (_, len)) in chunks.iter().enumerate() {
            assert!(*len <= MAX_CHUNK, "chunk {i} exceeds MAX_CHUNK: {len}");
            // Every chunk except the final one respects the minimum.
            if i + 1 < chunks.len() {
                assert!(*len > MIN_CHUNK, "chunk {i} under MIN_CHUNK: {len}");
            }
        }
        // Sanity: the target actually produces multiple chunks on real-size input.
        assert!(chunks.len() > 8, "expected many chunks, got {}", chunks.len());
    }

    #[test]
    fn chunking_is_deterministic() {
        let data = noise(2 * 1024 * 1024, 99);
        assert_eq!(chunk_boundaries(&data), chunk_boundaries(&data));
    }

    /// The property content-defined chunking exists for: an insert near the start changes a bounded neighbourhood, not
    /// every following chunk.
    #[test]
    fn an_early_insert_changes_only_a_bounded_neighbourhood() {
        let original = noise(6 * 1024 * 1024, 123);
        let mut edited = original.clone();
        edited.insert(10_000, 0xAB);

        let chunks_of = |data: &[u8]| -> std::collections::HashSet<Vec<u8>> {
            chunk_boundaries(data)
                .into_iter()
                .map(|(s, l)| data[s..s + l].to_vec())
                .collect()
        };
        let before = chunks_of(&original);
        let after = chunks_of(&edited);

        let changed = after.difference(&before).count();
        assert!(
            changed <= 3,
            "a one-byte insert should change at most a few chunks, changed {changed} of {}",
            after.len()
        );
        // And the vast majority survive byte-identical (what sync would skip).
        let kept = after.intersection(&before).count();
        assert!(
            kept >= after.len() - 3,
            "most chunks must survive an early edit: kept {kept} of {}",
            after.len()
        );
    }

    /// The streaming chunker is the same chunker. Not "close enough": a
    /// boundary that moved by one byte would re-chunk every object written
    /// through the streaming path, so it would dedup against nothing that the
    /// packing pass ever wrote, and the two halves of the store would disagree
    /// about what a file is made of.
    ///
    /// Fed in every shape that matters — one byte at a time, in IPC-sized
    /// pieces, and all at once — because the boundary rule is the only thing
    /// that may decide where a cut falls, and the arrival pattern is not it.
    #[test]
    fn streaming_chunks_are_byte_identical_to_whole_buffer_chunks() {
        let data = noise(5 * 1024 * 1024 + 7919, 31);
        let expected: Vec<Vec<u8>> = chunk_boundaries(&data)
            .into_iter()
            .map(|(s, l)| data[s..s + l].to_vec())
            .collect();

        for piece in [1usize, 4096, 64 * 1024, 4 * 1024 * 1024, data.len()] {
            let mut chunker = StreamChunker::new();
            let mut got: Vec<Vec<u8>> = Vec::new();
            for window in data.chunks(piece) {
                got.extend(chunker.push(window));
            }
            got.extend(chunker.finish());
            assert_eq!(
                got, expected,
                "fed in {piece}-byte pieces, the cuts must land where they land"
            );
        }
    }

    /// The degenerate inputs, on the streaming side: nothing at all, and less
    /// than one chunk's worth. `push` alone must emit nothing — a chunker that
    /// cut early would be cutting on arrival size, which is the bug the test
    /// above exists to prevent.
    #[test]
    fn a_short_stream_is_decided_only_at_its_end() {
        let mut chunker = StreamChunker::new();
        assert!(chunker.finish().is_empty(), "an empty stream has no chunks");

        let small = noise(1000, 5);
        let mut chunker = StreamChunker::new();
        assert!(
            chunker.push(&small).is_empty(),
            "under MAX_CHUNK nothing is decided yet"
        );
        assert_eq!(chunker.finish(), vec![small]);
    }

    #[test]
    fn small_and_empty_inputs() {
        assert!(chunk_boundaries(&[]).is_empty());
        let small = noise(1000, 5);
        assert_eq!(chunk_boundaries(&small), vec![(0, 1000)]);
        // Exactly MIN_CHUNK is one chunk.
        let min = noise(MIN_CHUNK, 5);
        assert_eq!(chunk_boundaries(&min), vec![(0, MIN_CHUNK)]);
    }

    /// Pin the gear table's first entries. If this test fails, the table
    /// changed — which silently re-chunks every corpus and breaks cross-device
    /// dedup. That is a format break and must be a versioned migration.
    #[test]
    fn the_gear_table_is_pinned() {
        assert_eq!(GEAR[0], 0x3886dad4a67cb19d);
        assert_eq!(GEAR[1], 0xeaf114536defeee0);
        assert_eq!(GEAR[255], 0x1ef775b3ed0c04c2);
    }

    /// Low-entropy input (all zeros) never finds a natural boundary, so MAX_CHUNK
    /// forces cuts — the degenerate case must not produce one giant chunk.
    #[test]
    fn zero_entropy_input_is_cut_at_max_chunk() {
        let data = vec![0u8; 3 * MAX_CHUNK + 100];
        let chunks = chunk_boundaries(&data);
        assert_eq!(
            chunks,
            vec![
                (0, MAX_CHUNK),
                (MAX_CHUNK, MAX_CHUNK),
                (2 * MAX_CHUNK, MAX_CHUNK),
                (3 * MAX_CHUNK, 100),
            ]
        );
    }
}
