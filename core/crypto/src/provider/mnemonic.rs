// SPDX-License-Identifier: AGPL-3.0-or-later
//! BIP39 mnemonic generation and validation
//!
//! Provides BIP39-compliant mnemonic phrase generation and validation
//! for secure account recovery.

use bip39::{Language, Mnemonic};
use kotton_sys::crypto::{MnemonicError, MnemonicProvider, MnemonicResult};

/// BIP39 mnemonic provider
///
/// Generates 24-word BIP39 mnemonics and validates mnemonic phrases.
pub struct Bip39MnemonicProvider;

impl MnemonicProvider for Bip39MnemonicProvider {
    /// Generate a 24-word BIP39 mnemonic (256 bits of entropy)
    fn generate(&self) -> MnemonicResult<String> {
        use rand::rngs::OsRng;
        use rand::RngCore;

        // Generate 32 bytes (256 bits) of entropy for 24 words
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);

        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
            .map_err(|e| MnemonicError::GenerationFailed(e.to_string()))?;

        Ok(mnemonic.to_string())
    }

    /// Validate a BIP39 mnemonic phrase
    fn validate(&self, mnemonic_phrase: &str) -> MnemonicResult<()> {
        Mnemonic::parse_in_normalized(Language::English, mnemonic_phrase)
            .map(|_| ())
            .map_err(|e| MnemonicError::InvalidMnemonic(e.to_string()))
    }

    /// Get entropy bytes from a BIP39 mnemonic
    fn to_entropy(&self, mnemonic_phrase: &str) -> MnemonicResult<Vec<u8>> {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic_phrase)
            .map_err(|e| MnemonicError::InvalidMnemonic(e.to_string()))?;

        // For BIP39, we use the seed (not raw entropy) for key derivation
        // Using empty passphrase
        let seed = mnemonic.to_seed("");
        Ok(seed[..32].to_vec())
    }

    /// Derive a 64-byte seed from BIP39 mnemonic with optional passphrase
    fn to_seed(&self, mnemonic_phrase: &str, passphrase: &str) -> MnemonicResult<Vec<u8>> {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic_phrase)
            .map_err(|e| MnemonicError::InvalidMnemonic(e.to_string()))?;

        // BIP39 seed derivation with passphrase (PBKDF2)
        let seed = mnemonic.to_seed(passphrase);
        Ok(seed.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mnemonic() {
        let provider = Bip39MnemonicProvider;
        let mnemonic = provider.generate().unwrap();

        // Should be 24 words
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 24);
    }

    #[test]
    fn test_validate_mnemonic() {
        let provider = Bip39MnemonicProvider;

        // Valid 24-word test mnemonic
        let valid = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        assert!(provider.validate(valid).is_ok());

        // Invalid mnemonic
        assert!(provider.validate("not a valid mnemonic").is_err());
    }

    #[test]
    fn test_to_entropy() {
        let provider = Bip39MnemonicProvider;
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

        let entropy = provider.to_entropy(mnemonic).unwrap();

        // Should return 32 bytes
        assert_eq!(entropy.len(), 32);
    }

    #[test]
    fn test_deterministic_entropy() {
        let provider = Bip39MnemonicProvider;
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

        let entropy1 = provider.to_entropy(mnemonic).unwrap();
        let entropy2 = provider.to_entropy(mnemonic).unwrap();

        // Same mnemonic should produce same entropy
        assert_eq!(entropy1, entropy2);
    }
}
