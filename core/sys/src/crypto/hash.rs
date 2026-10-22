// SPDX-License-Identifier: AGPL-3.0-or-later
//! Cryptographic hashing trait

use thiserror::Error;

/// Errors that can occur during hashing operations
#[derive(Debug, Error)]
pub enum HashError {
    /// Hashing operation failed
    #[error("Hash operation failed: {0}")]
    OperationFailed(String),
}

/// Result type for hashing operations
pub type HashResult<T> = Result<T, HashError>;

/// Trait for cryptographic hash functions
///
/// Implementations provide specific hash algorithms (Blake3, SHA-256, etc.)
/// The algorithm choice is made by the provider, not the caller.
pub trait Hasher: Send + Sync {
    /// Hash the provided data
    ///
    /// # Arguments
    /// * `data` - Data to hash
    ///
    /// # Returns
    /// The hash digest as bytes
    fn hash(&self, data: &[u8]) -> HashResult<Vec<u8>>;

    /// Get the output size in bytes for this hasher
    fn output_size(&self) -> usize;
}
