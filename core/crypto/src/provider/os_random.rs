// SPDX-License-Identifier: AGPL-3.0-or-later
//! OS-provided cryptographically secure random number generation

use getrandom::getrandom;
use kotton_sys::crypto::{RandomError, RandomResult, RandomSource};

/// OS random number generator
///
/// Uses the OS-provided CSPRNG via the `getrandom` crate:
/// - Windows: `BCryptGenRandom`
/// - macOS/iOS: `SecRandomCopyBytes`
/// - Linux: `getrandom()` syscall
#[derive(Debug, Clone, Copy, Default)]
pub struct OsRandom;

impl OsRandom {
    /// Create a new OS random source
    pub fn new() -> Self {
        Self
    }
}

impl RandomSource for OsRandom {
    fn random_bytes(&self, len: usize) -> RandomResult<Vec<u8>> {
        let mut bytes = vec![0u8; len];
        getrandom(&mut bytes)
            .map_err(|e| RandomError::OperationFailed(format!("OS RNG failed: {}", e)))?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_os_random() {
        let rng = OsRandom::new();
        let bytes = rng.random_bytes(32).unwrap();
        assert_eq!(bytes.len(), 32);

        // Should generate different bytes each time
        let bytes2 = rng.random_bytes(32).unwrap();
        assert_ne!(bytes, bytes2);
    }

    #[test]
    fn test_various_sizes() {
        let rng = OsRandom::new();
        for size in [16, 32, 64, 128] {
            let bytes = rng.random_bytes(size).unwrap();
            assert_eq!(bytes.len(), size);
        }
    }
}
