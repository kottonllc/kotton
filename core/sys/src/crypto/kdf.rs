// SPDX-License-Identifier: AGPL-3.0-or-later
//! Key derivation function traits

use thiserror::Error;

/// Errors that can occur during key derivation
#[derive(Debug, Error)]
pub enum KdfError {
    /// Invalid parameter (e.g., zero iterations, insufficient salt)
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    /// Key derivation operation failed
    #[error("Key derivation failed: {0}")]
    OperationFailed(String),
}

/// Result type for key derivation operations
pub type KdfResult<T> = Result<T, KdfError>;

/// Trait for password-based key derivation
///
/// Implementations provide specific KDF algorithms (PBKDF2, Argon2, etc.)
pub trait KeyDeriver: Send + Sync {
    /// Derive a key from a password
    ///
    /// # Arguments
    /// * `password` - Password to derive from
    /// * `salt` - Cryptographic salt (should be randomly generated)
    /// * `iterations` - Number of iterations (work factor)
    ///
    /// # Returns
    /// Derived key bytes
    ///
    /// # Errors
    /// - `InvalidParameter` if iterations is 0 or salt is too short
    /// - `OperationFailed` if derivation fails
    fn derive_key(&self, password: &[u8], salt: &[u8], iterations: u32) -> KdfResult<Vec<u8>>;

    /// Get the output key size in bytes
    fn output_size(&self) -> usize;

    /// Get the recommended minimum salt size in bytes
    fn min_salt_size(&self) -> usize;
}
