// SPDX-License-Identifier: AGPL-3.0-or-later
//! AES-256-GCM encryption implementation

use kotton_sys::crypto::{
    DecryptError, DecryptResult, Decryptor, EncryptError, EncryptResult, Encryptor,
};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};

/// AES-256-GCM encryptor
#[derive(Debug)]
pub struct AesGcmEncryptor {
    rng: SystemRandom,
}

impl AesGcmEncryptor {
    /// Create a new AES-256-GCM encryptor
    pub fn new() -> Self {
        Self {
            rng: SystemRandom::new(),
        }
    }
}

impl Default for AesGcmEncryptor {
    fn default() -> Self {
        Self::new()
    }
}

impl Encryptor for AesGcmEncryptor {
    fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> EncryptResult<(Vec<u8>, Vec<u8>)> {
        if key.len() != 32 {
            return Err(EncryptError::InvalidKeyLength {
                expected: 32,
                actual: key.len(),
            });
        }

        let unbound_key = UnboundKey::new(&AES_256_GCM, key)
            .map_err(|_| EncryptError::OperationFailed("Failed to create key".into()))?;
        let sealing_key = LessSafeKey::new(unbound_key);

        // Generate random nonce (12 bytes for GCM)
        let mut nonce_bytes = vec![0u8; 12];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| EncryptError::OperationFailed("Failed to generate nonce".into()))?;

        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| EncryptError::OperationFailed("Failed to create nonce".into()))?;

        // Prepare data for in-place encryption
        let mut in_out = plaintext.to_vec();
        in_out.reserve(AES_256_GCM.tag_len());

        sealing_key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| EncryptError::OperationFailed("Encryption failed".into()))?;

        Ok((in_out, nonce_bytes))
    }

    fn key_size(&self) -> usize {
        32 // AES-256
    }

    fn nonce_size(&self) -> usize {
        12 // GCM standard nonce size
    }
}

/// AES-256-GCM decryptor
#[derive(Debug, Clone, Copy, Default)]
pub struct AesGcmDecryptor;

impl AesGcmDecryptor {
    /// Create a new AES-256-GCM decryptor
    pub fn new() -> Self {
        Self
    }
}

impl Decryptor for AesGcmDecryptor {
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

        let unbound_key = UnboundKey::new(&AES_256_GCM, key)
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
        32 // AES-256
    }

    fn nonce_size(&self) -> usize {
        12 // GCM standard nonce size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_gcm_encrypt_decrypt() {
        let encryptor = AesGcmEncryptor::new();
        let decryptor = AesGcmDecryptor::new();

        let key = [0u8; 32];
        let plaintext = b"secret message";

        let (ciphertext, nonce) = encryptor.encrypt(&key, plaintext).unwrap();
        assert_ne!(ciphertext.as_slice(), plaintext);

        let decrypted = decryptor.decrypt(&key, &ciphertext, &nonce).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_invalid_key_length() {
        let encryptor = AesGcmEncryptor::new();
        let result = encryptor.encrypt(&[0u8; 16], b"data");
        assert!(matches!(result, Err(EncryptError::InvalidKeyLength { .. })));
    }
}
