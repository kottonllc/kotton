// SPDX-License-Identifier: AGPL-3.0-or-later
//! ChaCha20-Poly1305 encryption implementation

use kotton_sys::crypto::{
    DecryptError, DecryptResult, Decryptor, EncryptError, EncryptResult, Encryptor,
};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use ring::rand::{SecureRandom, SystemRandom};

/// ChaCha20-Poly1305 encryptor
#[derive(Debug)]
pub struct ChaCha20Encryptor {
    rng: SystemRandom,
}

impl ChaCha20Encryptor {
    /// Create a new ChaCha20-Poly1305 encryptor
    pub fn new() -> Self {
        Self {
            rng: SystemRandom::new(),
        }
    }
}

impl Default for ChaCha20Encryptor {
    fn default() -> Self {
        Self::new()
    }
}

impl Encryptor for ChaCha20Encryptor {
    fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> EncryptResult<(Vec<u8>, Vec<u8>)> {
        if key.len() != 32 {
            return Err(EncryptError::InvalidKeyLength {
                expected: 32,
                actual: key.len(),
            });
        }

        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key)
            .map_err(|_| EncryptError::OperationFailed("Failed to create key".into()))?;
        let sealing_key = LessSafeKey::new(unbound_key);

        // Generate random nonce (12 bytes for ChaCha20-Poly1305)
        let mut nonce_bytes = vec![0u8; 12];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| EncryptError::OperationFailed("Failed to generate nonce".into()))?;

        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| EncryptError::OperationFailed("Failed to create nonce".into()))?;

        // Prepare data for in-place encryption
        let mut in_out = plaintext.to_vec();
        in_out.reserve(CHACHA20_POLY1305.tag_len());

        sealing_key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| EncryptError::OperationFailed("Encryption failed".into()))?;

        Ok((in_out, nonce_bytes))
    }

    fn key_size(&self) -> usize {
        32 // ChaCha20 uses 256-bit keys
    }

    fn nonce_size(&self) -> usize {
        12 // ChaCha20-Poly1305 standard nonce size
    }
}

/// ChaCha20-Poly1305 decryptor
#[derive(Debug, Clone, Copy, Default)]
pub struct ChaCha20Decryptor;

impl ChaCha20Decryptor {
    /// Create a new ChaCha20-Poly1305 decryptor
    pub fn new() -> Self {
        Self
    }
}

impl Decryptor for ChaCha20Decryptor {
    fn decrypt(&self, key: &[u8], ciphertext: &[u8], nonce: &[u8]) -> DecryptResult<Vec<u8>> {
        if key.len() != 32 {
            return Err(DecryptError::InvalidKeyLength {
                expected: 32,
                actual: key.len(),
            });
        }

        if nonce.len() != 12 {
            return Err(DecryptError::InvalidNonceLength {
                expected: 12,
                actual: nonce.len(),
            });
        }

        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key)
            .map_err(|_| DecryptError::OperationFailed("Failed to create key".into()))?;
        let opening_key = LessSafeKey::new(unbound_key);

        let nonce_obj = Nonce::try_assume_unique_for_key(nonce)
            .map_err(|_| DecryptError::OperationFailed("Invalid nonce".into()))?;

        let mut in_out = ciphertext.to_vec();

        let plaintext = opening_key
            .open_in_place(nonce_obj, Aad::empty(), &mut in_out)
            .map_err(|_| DecryptError::OperationFailed("Decryption failed".into()))?;

        Ok(plaintext.to_vec())
    }

    fn key_size(&self) -> usize {
        32 // ChaCha20 uses 256-bit keys
    }

    fn nonce_size(&self) -> usize {
        12 // ChaCha20-Poly1305 standard nonce size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20_encrypt_decrypt() {
        let encryptor = ChaCha20Encryptor::new();
        let decryptor = ChaCha20Decryptor::new();

        let key = [0u8; 32];
        let plaintext = b"secret message";

        let (ciphertext, nonce) = encryptor.encrypt(&key, plaintext).unwrap();
        assert_ne!(ciphertext.as_slice(), plaintext);

        let decrypted = decryptor.decrypt(&key, &ciphertext, &nonce).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_invalid_key_length() {
        let encryptor = ChaCha20Encryptor::new();
        let result = encryptor.encrypt(&[0u8; 16], b"data");
        assert!(matches!(result, Err(EncryptError::InvalidKeyLength { .. })));
    }
}
