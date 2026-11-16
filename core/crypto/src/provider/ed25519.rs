// SPDX-License-Identifier: AGPL-3.0-or-later
//! Ed25519 signing and key generation, and the path every crate above this one checks a
//! signature by.
//!
//! The rule is `kotton-ed25519`'s: [`VerifyingKey`] is a key that passed it and
//! [`VerifyingKey::verify`] the one check, which this module re-exports so the paths above it
//! hold. [`verify`] takes the library's key, puts its bytes to that rule and checks through the
//! type, for the callers that still hold the library's key.

use ed25519_dalek::{SignatureError, Signer as _, SigningKey};
use kotton_sys::crypto::{
    KeygenResult, KeypairGenerator, SignError, SignResult, Signer, Verifier, VerifyError,
    VerifyResult,
};

pub use kotton_ed25519::{Refused, Signature, VerifyingKey};

/// The keys and signatures the rule refuses, for the tests that hold a check to it.
#[cfg(any(test, feature = "test-utils"))]
pub use kotton_ed25519::refused;

/// Every vector [`refused`] names as a key, each with its name: the eight encodings of small
/// order, the identity's other encodings, the mixed-order key, the non-canonical encoding and
/// the bytes that are no point. A test that holds a site to the rule runs it over all of them.
#[cfg(any(test, feature = "test-utils"))]
pub fn refused_keys() -> Vec<(String, [u8; 32])> {
    let mut keys: Vec<(String, [u8; 32])> =
        refused::SMALL_ORDER_KEYS.iter().enumerate().map(|(i, k)| (format!("small order {i}"), *k)).collect();
    keys.extend(
        refused::IDENTITY_OTHER_ENCODINGS.iter().enumerate().map(|(i, k)| (format!("the identity, encoding {}", i + 2), *k)),
    );
    keys.push(("mixed order".to_string(), refused::mixed_order_key()));
    keys.push(("not canonical".to_string(), refused::NON_CANONICAL_KEY));
    keys.push(("not a point".to_string(), refused::NOT_A_POINT));
    keys
}

/// Verify `signature` over `message` under `key` by the rule: the key's bytes must pass
/// [`VerifyingKey::from_bytes`], and the signature [`VerifyingKey::verify`].
pub fn verify(key: &ed25519_dalek::VerifyingKey, message: &[u8], signature: &Signature) -> Result<(), SignatureError> {
    VerifyingKey::from_bytes(key.as_bytes())
        .and_then(|key| key.verify(message, signature))
        .map_err(|_| SignatureError::new())
}

/// The rule's key of `key`. A key made from a seed is a multiple of the base point by a scalar
/// that is not zero modulo the group's order, so it passes the rule (nothing an honest side
/// makes is refused); a refusal here is a defect in the library, and panics rather than name a
/// key that is no key.
///
/// It stands where the library's signing key is still held; kottonllc/kotton#565 gives the
/// signing key a type whose own `verifying_key` returns the rule's key.
pub fn verifying_key(key: &SigningKey) -> VerifyingKey {
    VerifyingKey::from_bytes(key.verifying_key().as_bytes()).expect("a key made from a seed passes the Ed25519 rule")
}

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

        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| VerifyError::InvalidPublicKey(e.to_string()))?;

        let sig_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| VerifyError::InvalidSignature("Invalid signature format".into()))?;

        let signature = Signature::from_bytes(&sig_bytes);

        match verify(&verifying_key, message, &signature) {
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

    /// The rule's key of a signing key is the library's key's bytes, put to the rule.
    /// The list is every key vector the rule's crate names, and the rule refuses each.
    #[test]
    fn refused_keys_are_refused() {
        let keys = refused_keys();
        assert_eq!(keys.len(), refused::SMALL_ORDER_KEYS.len() + refused::IDENTITY_OTHER_ENCODINGS.len() + 3);
        for (name, bytes) in keys {
            assert!(VerifyingKey::from_bytes(&bytes).is_err(), "{name}");
        }
    }

    #[test]
    fn verifying_key_is_the_signing_keys_key() {
        for seed in [[0u8; 32], [1; 32], [42; 32], [255; 32]] {
            let key = SigningKey::from_bytes(&seed);
            assert_eq!(verifying_key(&key).as_bytes(), key.verifying_key().as_bytes());
        }
    }

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

    /// The `kotton_sys` verifier refuses a signature under a key of small order.
    #[test]
    fn the_verifier_refuses_a_small_order_key() {
        let valid = Ed25519Verifier::new()
            .verify(&refused::SMALL_ORDER_KEY, b"any message", &refused::under_small_order_key_bytes())
            .unwrap();
        assert!(!valid);
    }

    /// The `kotton_sys` verifier refuses a non-canonical signature by a key it would otherwise
    /// believe.
    #[test]
    fn the_verifier_refuses_a_non_canonical_signature() {
        let key = SigningKey::from_bytes(&[42; 32]);
        let public = key.verifying_key().to_bytes();
        let message = b"test message";
        let verifier = Ed25519Verifier::new();
        assert!(verifier.verify(&public, message, &key.sign(message).to_bytes()).unwrap());
        for sig in refused::non_canonical(&key, message) {
            assert!(!verifier.verify(&public, message, &sig.to_bytes()).unwrap());
        }
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
