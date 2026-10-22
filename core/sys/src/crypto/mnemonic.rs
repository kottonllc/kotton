// SPDX-License-Identifier: AGPL-3.0-or-later
//! Mnemonic phrase generation and validation abstraction
//!
//! Provides trait abstraction for generating and validating recovery phrases.
//! Implementations might use BIP39, SLIP-0039, or other mnemonic standards.

use thiserror::Error;

/// Errors that can occur during mnemonic operations
#[derive(Debug, Error)]
pub enum MnemonicError {
    /// Failed to generate mnemonic
    #[error("Generation failed: {0}")]
    GenerationFailed(String),

    /// Invalid mnemonic phrase
    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(String),
}

/// Result type for mnemonic operations
pub type MnemonicResult<T> = Result<T, MnemonicError>;

/// Mnemonic phrase generator and validator
///
/// Implementations provide mnemonic generation (e.g., BIP39, SLIP-0039) for
/// account recovery and secure backups.
pub trait MnemonicProvider: Send + Sync {
    /// Generate a new mnemonic phrase
    ///
    /// Returns a human-readable recovery phrase (typically 12 or 24 words).
    fn generate(&self) -> MnemonicResult<String>;

    /// Validate a mnemonic phrase
    ///
    /// Checks if the phrase is well-formed and has a valid checksum.
    /// Does not verify if it corresponds to any existing account.
    fn validate(&self, mnemonic_phrase: &str) -> MnemonicResult<()>;

    /// Get the entropy bytes from a mnemonic phrase
    ///
    /// Converts the mnemonic words back to the original entropy.
    /// This can be used as a seed for key derivation.
    fn to_entropy(&self, mnemonic_phrase: &str) -> MnemonicResult<Vec<u8>>;

    /// Derive a seed from a mnemonic phrase with optional passphrase
    ///
    /// Returns a 64-byte seed suitable for hierarchical deterministic key derivation.
    /// For BIP39, this applies PBKDF2 to the mnemonic + passphrase.
    fn to_seed(&self, mnemonic_phrase: &str, passphrase: &str) -> MnemonicResult<Vec<u8>>;
}
