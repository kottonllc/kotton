// SPDX-License-Identifier: AGPL-3.0-or-later
//! Cryptographic provider implementations
//!
//! This crate provides concrete implementations of the crypto traits defined in
//! `Kotton-platform-crypto`. Each module implements specific algorithms:
//!
//! - **blake3**: BLAKE3 hasher
//! - **sha256**: SHA-256 hasher
//! - **aes_gcm**: AES-256-GCM encryption/decryption
//! - **chacha20**: ChaCha20-Poly1305 encryption/decryption
//! - **ed25519**: Ed25519 signing/verification and keypair generation
//! - **pbkdf2**: PBKDF2-HMAC-SHA256 key derivation
//! - **os_random**: OS-provided cryptographically secure random number generation
//! - **did**: DID method implementations (did:key)

pub mod aes_gcm;
pub mod blake3;
pub mod cek_recovery;
pub mod chacha20;
pub mod daily_credential;
pub mod did;
pub mod ed25519;
pub mod frost;
pub mod kdf;
pub mod kel_verify;
pub mod mnemonic;
pub mod os_random;
pub mod pair_handle;
/// RFC-0040's handshake lives in `kotton-pair` now, so a browser can share it
/// (see that crate's docs); this is the name every caller here has always used.
pub use kotton_pair::handshake as pair_handshake;
pub mod path_blind;
pub mod pbkdf2;
pub mod pin_wrap;
pub mod recovery;
pub mod sha256;
pub mod suite;
pub mod vault;
pub mod warm_key;
pub mod x25519;

pub use self::blake3::Blake3Hasher;
pub use self::sha256::Sha256Hasher;
pub use aes_gcm::{AesGcmDecryptor, AesGcmEncryptor};
pub use cek_recovery::{generate_cek, unwrap_cek_recovery, wrap_cek_recovery, CekRecovery};
pub use chacha20::{ChaCha20Decryptor, ChaCha20Encryptor};
pub use did::resolver::{CompositeDidResolver, DidKeyResolver, DidResolver, DidWebResolver};
pub use did::DidKeyMethod;
pub use ed25519::{Ed25519Keypair, Ed25519Signer, Ed25519Verifier};
pub use kdf::{
    derive_cek, derive_cek_recovery_kek, derive_db_key, derive_identity_key,
    derive_identity_recovery_kek, derive_master_secret, derive_master_secret_recovery_kek,
    derive_history_log_key, derive_migration_seed, derive_pack_key, derive_session_key,
    master_from_mnemonic,
    mnemonic_to_seed32,
    try_mnemonic_to_seed32,
};
pub use recovery::{
    unwrap_master_secret_recovery, unwrap_recovery,
    wrap_master_secret_recovery, wrap_recovery, RecoveryCopy,
};
pub use mnemonic::Bip39MnemonicProvider;
pub use os_random::OsRandom;
pub use pair_handle::{
    contact_knock_to_dial, contact_knock_to_open, dm_inbox_handle, dm_inbox_target, door_announce_name, door_day, door_expect_name, epoch_at,
    lookup_epochs, lookup_handle, publish_handle, PairHandle, CONTACT_KNOCK_INFO, CONTACT_KNOCK_LEN, DM_INBOX_INFO, DOOR_DAY_SECS,
    DOOR_NAME_INFO, EPOCH_SECS, PAIR_HANDLE_INFO,
};
pub use pair_handshake::{
    commit as pair_commit, derive_pair_keys, derive_session, hmac_sha256, hmac_sha256_var,
    verify_commitment,
    PairEphemeral, PairSession, EnrollmentSide, Transcript as PairTranscript,
};
pub use pbkdf2::Pbkdf2Deriver;
pub use pin_wrap::{unwrap_seed, wrap_seed, WrappedSeed};
pub use suite::Ed25519Suite;
pub use suite::ED25519_LIBRARY_TAG;
pub use vault::{open_vault, seal_vault, AtRestVault, OperationalRoots, SealedRoot};
pub use warm_key::{verify_warm_key_delegation, WarmKeyDenied};
