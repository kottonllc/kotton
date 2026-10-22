// SPDX-License-Identifier: AGPL-3.0-or-later
//! Digital signature traits

use thiserror::Error;

/// Errors that can occur during signing operations
#[derive(Debug, Error)]
pub enum SignError {
    /// Invalid private key length or format
    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),

    /// Signing operation failed
    #[error("Signing failed: {0}")]
    OperationFailed(String),
}

/// Result type for signing operations
pub type SignResult<T> = Result<T, SignError>;

/// Errors that can occur during signature verification
#[derive(Debug, Error)]
pub enum VerifyError {
    /// Invalid public key length or format
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Invalid signature length or format
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Verification operation failed
    #[error("Verification failed: {0}")]
    OperationFailed(String),
}

/// Result type for verification operations
pub type VerifyResult<T> = Result<T, VerifyError>;

/// Errors that can occur during keypair generation
#[derive(Debug, Error)]
pub enum KeygenError {
    /// Keypair generation failed
    #[error("Keypair generation failed: {0}")]
    OperationFailed(String),
}

/// Result type for keypair generation
pub type KeygenResult<T> = Result<T, KeygenError>;

/// Trait for digital signature creation
///
/// Implementations provide specific signature algorithms (Ed25519, etc.)
pub trait Signer: Send + Sync {
    /// Sign a message with the provided private key
    ///
    /// # Arguments
    /// * `private_key` - Private signing key
    /// * `message` - Message to sign
    ///
    /// # Returns
    /// The signature bytes
    ///
    /// # Errors
    /// - `InvalidPrivateKey` if private key size is incorrect
    /// - `OperationFailed` if signature generation fails
    fn sign(&self, private_key: &[u8], message: &[u8]) -> SignResult<Vec<u8>>;

    /// Get the required private key size in bytes
    fn private_key_size(&self) -> usize;

    /// Get the signature size in bytes
    fn signature_size(&self) -> usize;
}

/// Trait for digital signature verification
///
/// Implementations provide specific signature algorithms (Ed25519, etc.)
pub trait Verifier: Send + Sync {
    /// Verify a signature on a message
    ///
    /// # Arguments
    /// * `public_key` - Public verification key
    /// * `message` - Message that was signed
    /// * `signature` - Signature to verify
    ///
    /// # Returns
    /// `true` if signature is valid, `false` otherwise
    ///
    /// # Errors
    /// - `InvalidPublicKey` if public key format/size is incorrect
    /// - `InvalidSignature` if signature format/size is incorrect
    /// - `OperationFailed` if verification operation fails
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> VerifyResult<bool>;

    /// Get the required public key size in bytes
    fn public_key_size(&self) -> usize;

    /// Get the signature size in bytes
    fn signature_size(&self) -> usize;
}

/// Trait for keypair generation
///
/// Implementations provide specific key types (Ed25519, X25519, etc.)
pub trait KeypairGenerator: Send + Sync {
    /// Generate a new keypair
    ///
    /// # Returns
    /// Tuple of (private_key, public_key)
    fn generate(&self) -> KeygenResult<(Vec<u8>, Vec<u8>)>;

    /// Get the private key size in bytes
    fn private_key_size(&self) -> usize;

    /// Get the public key size in bytes
    fn public_key_size(&self) -> usize;
}
