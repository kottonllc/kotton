// SPDX-License-Identifier: AGPL-3.0-or-later
//! Symmetric encryption traits

use thiserror::Error;

/// Errors that can occur during encryption operations
#[derive(Debug, Error)]
pub enum EncryptError {
    /// Invalid key length
    #[error("Invalid key length: expected {expected} bytes, got {actual} bytes")]
    InvalidKeyLength { expected: usize, actual: usize },

    /// Encryption operation failed
    #[error("Encryption failed: {0}")]
    OperationFailed(String),
}

/// Result type for encryption operations
pub type EncryptResult<T> = Result<T, EncryptError>;

/// Errors that can occur during decryption operations
#[derive(Debug, Error)]
pub enum DecryptError {
    /// Invalid key length
    #[error("Invalid key length: expected {expected} bytes, got {actual} bytes")]
    InvalidKeyLength { expected: usize, actual: usize },

    /// Invalid nonce length
    #[error("Invalid nonce length: expected {expected} bytes, got {actual} bytes")]
    InvalidNonceLength { expected: usize, actual: usize },

    /// Decryption operation failed (wrong key, corrupted data, or authentication failure)
    #[error("Decryption failed: {0}")]
    OperationFailed(String),
}

/// Result type for decryption operations
pub type DecryptResult<T> = Result<T, DecryptError>;

/// Trait for symmetric encryption with authenticated encryption (AEAD)
///
/// Implementations provide specific algorithms (AES-GCM, ChaCha20-Poly1305, etc.)
pub trait Encryptor: Send + Sync {
    /// Encrypt plaintext with the provided key
    ///
    /// # Arguments
    /// * `key` - Encryption key (length must match algorithm requirements)
    /// * `plaintext` - Data to encrypt
    ///
    /// # Returns
    /// Tuple of (ciphertext, nonce) where the nonce is randomly generated
    ///
    /// # Errors
    /// - `InvalidKeyLength` if key size is incorrect
    /// - `OperationFailed` if encryption operation fails
    fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> EncryptResult<(Vec<u8>, Vec<u8>)>;

    /// Get the required key size in bytes
    fn key_size(&self) -> usize;

    /// Get the nonce size in bytes
    fn nonce_size(&self) -> usize;
}

/// Trait for symmetric decryption with authenticated encryption (AEAD)
///
/// Implementations provide specific algorithms (AES-GCM, ChaCha20-Poly1305, etc.)
pub trait Decryptor: Send + Sync {
    /// Decrypt ciphertext with the provided key and nonce
    ///
    /// # Arguments
    /// * `key` - Decryption key (length must match algorithm requirements)
    /// * `ciphertext` - Encrypted data (includes authentication tag)
    /// * `nonce` - Nonce used during encryption
    ///
    /// # Returns
    /// The decrypted plaintext
    ///
    /// # Errors
    /// - `InvalidKeyLength` if key size is incorrect
    /// - `InvalidNonceLength` if nonce size is incorrect
    /// - `OperationFailed` if decryption or authentication fails
    fn decrypt(&self, key: &[u8], ciphertext: &[u8], nonce: &[u8]) -> DecryptResult<Vec<u8>>;

    /// Get the required key size in bytes
    fn key_size(&self) -> usize;

    /// Get the nonce size in bytes
    fn nonce_size(&self) -> usize;
}
