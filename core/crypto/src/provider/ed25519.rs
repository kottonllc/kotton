// SPDX-License-Identifier: AGPL-3.0-or-later
//! Ed25519 signature implementation

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use kotton_sys::crypto::{
    KeygenResult, KeypairGenerator, SignError, SignResult, Signer, Verifier, VerifyError,
    VerifyResult,
};

/// Ed25519 keypair generator
#[derive(Debug, Clone, Copy, Default)]
pub struct Ed25519Keypair;

impl Ed25519Keypair {
    /// Create a new Ed25519 keypair generator
    pub fn new() -> Self {
        Self
    }

    /// Derive Ed25519 keypair from seed bytes
    ///
    /// # Arguments
    /// * `seed` - 32-byte seed for deterministic key derivation
    ///
    /// # Returns
    /// Tuple of (private_key_bytes, public_key_bytes)
    ///
    /// # Errors
    /// Returns `KeygenError` if seed is not exactly 32 bytes
    pub fn from_seed(&self, seed: &[u8]) -> KeygenResult<(Vec<u8>, Vec<u8>)> {
        if seed.len() != 32 {
            return Err(kotton_sys::crypto::KeygenError::OperationFailed(
                format!("Seed must be exactly 32 bytes, got {}", seed.len()),
            ));
        }

        let seed_array: [u8; 32] = seed.try_into().map_err(|_| {
            kotton_sys::crypto::KeygenError::OperationFailed(
                "Failed to convert seed to array".to_string(),
            )
        })?;

        let signing_key = SigningKey::from_bytes(&seed_array);
        let verifying_key = signing_key.verifying_key();

        Ok((
            signing_key.to_bytes().to_vec(),
            verifying_key.to_bytes().to_vec(),
        ))
    }
}

impl KeypairGenerator for Ed25519Keypair {
    fn generate(&self) -> KeygenResult<(Vec<u8>, Vec<u8>)> {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key();

        let private_key = signing_key.to_bytes().to_vec();
        let public_key = verifying_key.to_bytes().to_vec();

        Ok((private_key, public_key))
    }

    fn private_key_size(&self) -> usize {
        32 // Ed25519 private keys are 32 bytes
    }

    fn public_key_size(&self) -> usize {
        32 // Ed25519 public keys are 32 bytes
    }
}

/// Ed25519 signer
#[derive(Debug, Clone, Copy, Default)]
pub struct Ed25519Signer;

impl Ed25519Signer {
    /// Create a new Ed25519 signer
    pub fn new() -> Self {
        Self
    }
}

impl Signer for Ed25519Signer {
    fn sign(&self, private_key: &[u8], message: &[u8]) -> SignResult<Vec<u8>> {
        if private_key.len() != 32 {
            return Err(SignError::InvalidPrivateKey(format!(
                "Expected 32 bytes, got {}",
                private_key.len()
            )));
        }

        let key_bytes: [u8; 32] = private_key
            .try_into()
            .map_err(|_| SignError::InvalidPrivateKey("Invalid key format".into()))?;

        let signing_key = SigningKey::from_bytes(&key_bytes);
        let signature = signing_key.sign(message);

        Ok(signature.to_bytes().to_vec())
    }

    fn private_key_size(&self) -> usize {
        32
    }

    fn signature_size(&self) -> usize {
        64 // Ed25519 signatures are 64 bytes
    }
}

/// Ed25519 verifier
#[derive(Debug, Clone, Copy, Default)]
pub struct Ed25519Verifier;

impl Ed25519Verifier {
    /// Create a new Ed25519 verifier
    pub fn new() -> Self {
        Self
    }
}

impl Verifier for Ed25519Verifier {
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> VerifyResult<bool> {
        if public_key.len() != 32 {
            return Err(VerifyError::InvalidPublicKey(format!(
                "Expected 32 bytes, got {}",
                public_key.len()
            )));
        }

        if signature.len() != 64 {
            return Err(VerifyError::InvalidSignature(format!(
                "Expected 64 bytes, got {}",
                signature.len()
            )));
        }

        let key_bytes: [u8; 32] = public_key
            .try_into()
            .map_err(|_| VerifyError::InvalidPublicKey("Invalid key format".into()))?;

        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| VerifyError::InvalidPublicKey(e.to_string()))?;

        let sig_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| VerifyError::InvalidSignature("Invalid signature format".into()))?;

        let signature = Signature::from_bytes(&sig_bytes);

        match verifying_key.verify(message, &signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn public_key_size(&self) -> usize {
        32
    }

    fn signature_size(&self) -> usize {
        64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_sign_verify() {
        let keygen = Ed25519Keypair::new();
        let signer = Ed25519Signer::new();
        let verifier = Ed25519Verifier::new();

        let (private_key, public_key) = keygen.generate().unwrap();
        let message = b"test message";

        let signature = signer.sign(&private_key, message).unwrap();
        assert_eq!(signature.len(), 64);

        let valid = verifier.verify(&public_key, message, &signature).unwrap();
        assert!(valid);

        // Wrong message should fail
        let invalid = verifier
            .verify(&public_key, b"wrong message", &signature)
            .unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_ed25519_from_seed_deterministic() {
        let keygen = Ed25519Keypair::new();
        let seed = [42u8; 32];

        let (private1, public1) = keygen.from_seed(&seed).unwrap();
        let (private2, public2) = keygen.from_seed(&seed).unwrap();

        // Same seed should produce same keypair
        assert_eq!(private1, private2);
        assert_eq!(public1, public2);
        assert_eq!(private1.len(), 32);
        assert_eq!(public1.len(), 32);
    }

    #[test]
    fn test_ed25519_from_seed_wrong_size() {
        let keygen = Ed25519Keypair::new();
        let short_seed = [42u8; 16];

        let result = keygen.from_seed(&short_seed);
        assert!(result.is_err());
    }
}
