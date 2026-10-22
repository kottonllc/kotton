// SPDX-License-Identifier: AGPL-3.0-or-later
//! Cryptographic primitives abstraction
//!
//! This module provides focused trait abstractions for cryptographic operations:
//! - **Hashing**: Cryptographic hash functions (Blake3, SHA-256, etc.)
//! - **Encryption/Decryption**: Symmetric AEAD ciphers (AES-GCM, ChaCha20-Poly1305, etc.)
//! - **Signing/Verification**: Digital signatures (Ed25519, etc.)
//! - **Key Derivation**: Password-based KDFs (PBKDF2, Argon2, etc.)
//! - **Random Generation**: Cryptographically secure random bytes
//!
//! Algorithm choices are made by provider implementations, not by the platform.
//! Services compose these primitives as needed for their security requirements.

pub mod suite;
pub mod encrypt;
pub mod hash;
pub mod hdkdf;
pub mod kdf;
pub mod mnemonic;
pub mod random;
pub mod sign;

pub use encrypt::{DecryptError, DecryptResult, Decryptor, EncryptError, EncryptResult, Encryptor};
pub use hash::{HashError, HashResult, Hasher};
pub use hdkdf::{HdKdfError, HdKdfResult, HdKeyDeriver};
pub use kdf::{KdfError, KdfResult, KeyDeriver};
pub use mnemonic::{MnemonicError, MnemonicProvider, MnemonicResult};
pub use random::{RandomError, RandomResult, RandomSource};
pub use sign::{
    KeygenError, KeygenResult, KeypairGenerator, SignError, SignResult, Signer, Verifier,
    VerifyError, VerifyResult,
};
