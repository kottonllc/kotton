// SPDX-License-Identifier: AGPL-3.0-or-later
//! Hierarchical Deterministic Key Derivation
//!
//! Provides trait abstraction for deriving cryptographic keys from a seed
//! using hierarchical deterministic paths (BIP-32, SLIP-10, etc.).

use thiserror::Error;

/// Errors that can occur during HD key derivation
#[derive(Debug, Error)]
pub enum HdKdfError {
    /// Invalid derivation path
    #[error("Invalid derivation path: {0}")]
    InvalidPath(String),

    /// Derivation failed
    #[error("Derivation failed: {0}")]
    DerivationFailed(String),
}

/// Result type for HD key derivation operations
pub type HdKdfResult<T> = Result<T, HdKdfError>;

/// Hierarchical Deterministic Key Derivation Function
///
/// Implementations provide specific HD derivation schemes (SLIP-10, BIP-32, etc.)
pub trait HdKeyDeriver: Send + Sync {
    /// Derive a key from a seed using a hierarchical path
    ///
    /// # Arguments
    /// * `seed` - Master seed bytes (typically from BIP-39 mnemonic)
    /// * `path` - Derivation path (e.g., "m/44'/1234'/0'/0'/0'")
    ///
    /// # Returns
    /// 32-byte derived private key
    fn derive_key(&self, seed: &[u8], path: &str) -> HdKdfResult<[u8; 32]>;
}
