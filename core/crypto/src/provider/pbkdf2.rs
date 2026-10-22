// SPDX-License-Identifier: AGPL-3.0-or-later
//! PBKDF2-HMAC-SHA256 key derivation implementation

use kotton_sys::crypto::{KdfError, KdfResult, KeyDeriver};
use ring::pbkdf2;
use std::num::NonZeroU32;

/// PBKDF2-HMAC-SHA256 key deriver
#[derive(Debug, Clone, Copy, Default)]
pub struct Pbkdf2Deriver;

impl Pbkdf2Deriver {
    /// Create a new PBKDF2 deriver
    pub fn new() -> Self {
        Self
    }
}

impl KeyDeriver for Pbkdf2Deriver {
    fn derive_key(&self, password: &[u8], salt: &[u8], iterations: u32) -> KdfResult<Vec<u8>> {
        if iterations == 0 {
            return Err(KdfError::InvalidParameter(
                "Iterations must be greater than 0".into(),
            ));
        }

        if salt.len() < 16 {
            return Err(KdfError::InvalidParameter(format!(
                "Salt too short: {} bytes (minimum 16)",
                salt.len()
            )));
        }

        let iterations = NonZeroU32::new(iterations)
            .ok_or_else(|| KdfError::InvalidParameter("Invalid iteration count".into()))?;

        let mut key = vec![0u8; 32]; // 256-bit derived key
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            iterations,
            salt,
            password,
            &mut key,
        );

        Ok(key)
    }

    fn output_size(&self) -> usize {
        32 // 256-bit keys
    }

    fn min_salt_size(&self) -> usize {
        16 // Minimum recommended salt size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pbkdf2_derive() {
        let deriver = Pbkdf2Deriver::new();
        let password = b"password123";
        let salt = [0u8; 16];

        let key = deriver.derive_key(password, &salt, 10000).unwrap();
        assert_eq!(key.len(), 32);

        // Same inputs should produce same output
        let key2 = deriver.derive_key(password, &salt, 10000).unwrap();
        assert_eq!(key, key2);

        // Different password should produce different output
        let key3 = deriver.derive_key(b"different", &salt, 10000).unwrap();
        assert_ne!(key, key3);
    }

    #[test]
    fn test_invalid_iterations() {
        let deriver = Pbkdf2Deriver::new();
        let result = deriver.derive_key(b"password", &[0u8; 16], 0);
        assert!(matches!(result, Err(KdfError::InvalidParameter(_))));
    }

    #[test]
    fn test_salt_too_short() {
        let deriver = Pbkdf2Deriver::new();
        let result = deriver.derive_key(b"password", &[0u8; 8], 10000);
        assert!(matches!(result, Err(KdfError::InvalidParameter(_))));
    }
}
