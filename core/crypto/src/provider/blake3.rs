// SPDX-License-Identifier: AGPL-3.0-or-later
//! BLAKE3 hash implementation

use kotton_sys::crypto::{HashResult, Hasher};

/// BLAKE3 cryptographic hasher
#[derive(Debug, Clone, Copy, Default)]
pub struct Blake3Hasher;

impl Blake3Hasher {
    /// Create a new BLAKE3 hasher
    pub fn new() -> Self {
        Self
    }
}

impl Hasher for Blake3Hasher {
    fn hash(&self, data: &[u8]) -> HashResult<Vec<u8>> {
        let hash = blake3::hash(data);
        Ok(hash.as_bytes().to_vec())
    }

    fn output_size(&self) -> usize {
        32 // BLAKE3 produces 256-bit (32-byte) hashes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_hash() {
        let hasher = Blake3Hasher::new();
        let hash = hasher.hash(b"hello world").unwrap();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_blake3_deterministic() {
        let hasher = Blake3Hasher::new();
        let hash1 = hasher.hash(b"test data").unwrap();
        let hash2 = hasher.hash(b"test data").unwrap();
        assert_eq!(hash1, hash2);
    }
}
