// SPDX-License-Identifier: AGPL-3.0-or-later
//! PIN-based wrapping of `seed32`.
//!
//! Derives a 256-bit wrap key from the user's PIN via Argon2id, then uses
//! ChaCha20-Poly1305 to encrypt / decrypt the 32-byte `seed32`.
//!
//! The result is a [`WrappedSeed`] — a small JSON-serialisable blob stored at
//! `users/{user_id}/wrapped_seed.json`.  This complements the OS keychain:
//! when the keychain entry is absent (cold boot on a new device, keychain
//! reset, etc.) the user can re-enter their PIN to recover `seed32` without
//! presenting their BIP-39 recovery mnemonic.
//!
//! ## Security
//!
//! * Argon2id parameters are taken from [`kotton_common::crypto::pin`] —
//!   64 MiB, 3 iterations, 1 lane.  At these parameters the full 10⁶ PIN
//!   space costs ~83 GPU-hours to exhaust.
//! * Each call to [`wrap_seed`] generates a fresh 16-byte salt and 12-byte
//!   nonce, so two wraps of the same seed + PIN produce different output.
//! * An incorrect PIN produces a ChaCha20-Poly1305 authentication failure
//!   that is indistinguishable from a corrupted file at the API level.

use anyhow::{bail, Context};
use argon2::{Algorithm, Argon2, Params, Version};
use kotton_common::crypto::pin as pin_params;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

/// On-disk representation of a PIN-wrapped `seed32`.
///
/// All binary fields are lowercase hex strings.  The `version` field allows
/// future KDF or cipher changes without silent breakage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedSeed {
    /// Format version — always `1` for this implementation.
    pub version: u32,
    /// 16-byte random Argon2id salt, hex-encoded.
    pub salt: String,
    /// 12-byte ChaCha20-Poly1305 nonce, hex-encoded.
    pub nonce: String,
    /// 48-byte ciphertext (32 plaintext bytes + 16 auth tag), hex-encoded.
    pub ciphertext: String,
}

/// Wrap `seed32` under a key derived from `pin`.
///
/// Generates a fresh random salt and nonce on every call, so calling this
/// twice with the same inputs produces two different blobs (both correct).
pub fn wrap_seed(pin: &str, seed32: &[u8; 32]) -> anyhow::Result<WrappedSeed> {
    let rng = SystemRandom::new();

    let mut salt = [0u8; 16];
    rng.fill(&mut salt)
        .map_err(|_| anyhow::anyhow!("failed to generate random salt"))?;

    let mut nonce_bytes = vec![0u8; 12];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| anyhow::anyhow!("failed to generate random nonce"))?;

    let wrap_key = derive_wrap_key(pin, &salt)?;

    let unbound = UnboundKey::new(&CHACHA20_POLY1305, &wrap_key)
        .map_err(|_| anyhow::anyhow!("failed to create ChaCha20 key"))?;
    let sealing_key = LessSafeKey::new(unbound);
    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
        .map_err(|_| anyhow::anyhow!("failed to construct nonce"))?;

    let mut in_out = seed32.to_vec();
    in_out.reserve(CHACHA20_POLY1305.tag_len());
    sealing_key
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| anyhow::anyhow!("ChaCha20-Poly1305 encryption failed"))?;

    Ok(WrappedSeed {
        version: 1,
        salt: hex::encode(salt),
        nonce: hex::encode(&nonce_bytes),
        ciphertext: hex::encode(&in_out),
    })
}

/// Recover `seed32` from a [`WrappedSeed`] using `pin`.
///
/// Returns an error if the PIN is incorrect, the blob is corrupt, or the
/// version is unrecognised.
pub fn unwrap_seed(wrapped: &WrappedSeed, pin: &str) -> anyhow::Result<[u8; 32]> {
    if wrapped.version != 1 {
        bail!("unsupported wrapped_seed version: {}", wrapped.version);
    }

    let salt = hex::decode(&wrapped.salt).context("invalid salt hex in wrapped_seed")?;
    let nonce_bytes = hex::decode(&wrapped.nonce).context("invalid nonce hex in wrapped_seed")?;
    let mut ciphertext =
        hex::decode(&wrapped.ciphertext).context("invalid ciphertext hex in wrapped_seed")?;

    let wrap_key = derive_wrap_key(pin, &salt)?;

    let unbound = UnboundKey::new(&CHACHA20_POLY1305, &wrap_key)
        .map_err(|_| anyhow::anyhow!("failed to create ChaCha20 key"))?;
    let opening_key = LessSafeKey::new(unbound);
    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
        .map_err(|_| anyhow::anyhow!("failed to construct nonce"))?;

    let plaintext = opening_key
        .open_in_place(nonce, Aad::empty(), &mut ciphertext)
        .map_err(|_| anyhow::anyhow!("decryption failed — wrong PIN or corrupted file"))?;

    let seed32: [u8; 32] = plaintext
        .try_into()
        .map_err(|_| anyhow::anyhow!("decrypted payload is not 32 bytes"))?;

    Ok(seed32)
}

// ─── shared unlock-key derivation ───────────────────────────────────────────────

/// Derive the 32-byte unlock key `U` from a PIN and salt via Argon2id.
///
/// This is the device-local unlock credential (RFC-0039): the same derivation
/// backs both [`wrap_seed`] and the at-rest [`crate::vault`] that wraps the
/// operational roots. Parameters are the OWASP-interactive minimums from
/// [`kotton_common::crypto::pin`].
pub fn derive_wrap_key(pin: &str, salt: &[u8]) -> anyhow::Result<[u8; 32]> {
    let params = Params::new(
        pin_params::ARGON2_M_COST,
        pin_params::ARGON2_T_COST,
        pin_params::ARGON2_P_COST,
        Some(pin_params::ARGON2_OUTPUT_LEN),
    )
    .map_err(|e| anyhow::anyhow!("argon2 params error: {e}"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut wrap_key = [0u8; 32];
    argon2
        .hash_password_into(pin.as_bytes(), salt, &mut wrap_key)
        .map_err(|e| anyhow::anyhow!("argon2 hashing failed: {e}"))?;

    Ok(wrap_key)
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let seed = [42u8; 32];
        let wrapped = wrap_seed("123456", &seed).unwrap();
        let recovered = unwrap_seed(&wrapped, "123456").unwrap();
        assert_eq!(seed, recovered);
    }

    #[test]
    fn wrong_pin_fails() {
        let seed = [7u8; 32];
        let wrapped = wrap_seed("111111", &seed).unwrap();
        assert!(
            unwrap_seed(&wrapped, "222222").is_err(),
            "wrong PIN must not decrypt"
        );
    }

    #[test]
    fn fresh_randomness_each_wrap() {
        let seed = [1u8; 32];
        let w1 = wrap_seed("000000", &seed).unwrap();
        let w2 = wrap_seed("000000", &seed).unwrap();
        // Each wrap must use a distinct salt and nonce.
        assert_ne!(w1.salt, w2.salt);
        assert_ne!(w1.nonce, w2.nonce);
    }

    #[test]
    fn bad_ciphertext_fails() {
        let seed = [5u8; 32];
        let mut wrapped = wrap_seed("999999", &seed).unwrap();
        // Flip one byte in the ciphertext.
        let mut bytes = hex::decode(&wrapped.ciphertext).unwrap();
        bytes[0] ^= 0xff;
        wrapped.ciphertext = hex::encode(&bytes);
        assert!(
            unwrap_seed(&wrapped, "999999").is_err(),
            "tampered ciphertext must not verify"
        );
    }

    #[test]
    fn unknown_version_rejected() {
        let seed = [3u8; 32];
        let mut wrapped = wrap_seed("123456", &seed).unwrap();
        wrapped.version = 99;
        assert!(unwrap_seed(&wrapped, "123456").is_err());
    }
}
