// SPDX-License-Identifier: AGPL-3.0-or-later
//! Cryptographically secure random number generation

use thiserror::Error;

/// Errors that can occur during random generation
#[derive(Debug, Error)]
pub enum RandomError {
    /// Random generation failed
    #[error("Random generation failed: {0}")]
    OperationFailed(String),
}

/// Result type for random generation operations
pub type RandomResult<T> = Result<T, RandomError>;

/// Trait for cryptographically secure random number generation
///
/// Implementations use OS-provided CSPRNGs or hardware RNGs
pub trait RandomSource: Send + Sync {
    /// Generate cryptographically secure random bytes
    ///
    /// # Arguments
    /// * `len` - Number of random bytes to generate
    ///
    /// # Returns
    /// Random bytes
    ///
    /// # Errors
    /// - `OperationFailed` if RNG fails
    fn random_bytes(&self, len: usize) -> RandomResult<Vec<u8>>;
}
