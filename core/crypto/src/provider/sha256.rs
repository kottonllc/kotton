// SPDX-License-Identifier: AGPL-3.0-or-later
//! SHA-256 hash implementation

use kotton_sys::crypto::{HashResult, Hasher};
use ring::digest;

/// SHA-256 cryptographic hasher
#[derive(Debug, Clone, Copy, Default)]
pub struct Sha256Hasher;

impl Sha256Hasher {
    /// Create a new SHA-256 hasher
    pub fn new() -> Self {
        Self
    }
}

impl Hasher for Sha256Hasher {
    fn hash(&self, data: &[u8]) -> HashResult<Vec<u8>> {
        let digest = digest::digest(&digest::SHA256, data);
        Ok(digest.as_ref().to_vec())
    }

    fn output_size(&self) -> usize {
        32 // SHA-256 produces 256-bit (32-byte) hashes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hash() {
        let hasher = Sha256Hasher::new();
        let hash = hasher.hash(b"hello world").unwrap();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_sha256_deterministic() {
        let hasher = Sha256Hasher::new();
        let hash1 = hasher.hash(b"test data").unwrap();
        let hash2 = hasher.hash(b"test data").unwrap();
        assert_eq!(hash1, hash2);
    }
}
