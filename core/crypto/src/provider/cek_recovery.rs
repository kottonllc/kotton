// SPDX-License-Identifier: AGPL-3.0-or-later
//! Hybrid CEK recovery wrapping (RFC-0033).
//!
//! In the Hybrid model the Content Encryption Key (CEK) is a random 32-byte key
//! (not derived from `seed32`), so it can be **rotated** and the VFS re-encrypted
//! without changing the user's identity. To keep the mnemonic as the single
//! recovery root, a **recovery copy** of the CEK is wrapped under a KEK derived
//! from `seed32` ([`derive_cek_recovery_kek`]). The mnemonic alone can therefore
//! always recover the CEK — and thus the user's data — even after total device
//! loss. That is the continuity invariant in code.
//!
//! Operational CEK copies (one per Full device) are sealed to each device's warm
//! key by the enrollment ceremony; this module handles only the mnemonic-rooted
//! recovery copy, stored in the VFS at `/identity/cek/recovery`.

use anyhow::{bail, Context};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use crate::kdf::derive_cek_recovery_kek;

/// In-VFS representation of the mnemonic-recoverable CEK copy.
///
/// Binary fields are lowercase hex. The KEK is re-derived from `seed32` at
/// recovery time, so — unlike a PIN-wrapped seed — no salt is stored; the random
/// nonce alone provides per-wrap uniqueness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CekRecovery {
    /// Format version — always `1` for this implementation.
    pub version: u32,
    /// CEK rotation epoch this copy is for (RFC-0033). Bumped on rotation.
    pub epoch: u32,
    /// 12-byte ChaCha20-Poly1305 nonce, hex-encoded.
    pub nonce: String,
    /// 48-byte ciphertext (32 plaintext bytes + 16 auth tag), hex-encoded.
    pub ciphertext: String,
}

/// Associated data binding the wrap's `version` and `epoch` into the AEAD tag.
///
/// Without this the tag covers only the 32-byte CEK, so the `version`/`epoch`
/// fields sit outside the authenticated envelope — an edit to the stored
/// `epoch` would go undetected and mislabel which rotation generation the
/// recovered CEK belongs to. Binding them here makes any such tamper a
/// decryption failure. Layout is fixed: `version` then `epoch`, little-endian.
fn recovery_aad(version: u32, epoch: u32) -> [u8; 8] {
    let mut aad = [0u8; 8];
    aad[..4].copy_from_slice(&version.to_le_bytes());
    aad[4..].copy_from_slice(&epoch.to_le_bytes());
    aad
}

/// Generate a fresh random 32-byte CEK.
pub fn generate_cek() -> anyhow::Result<[u8; 32]> {
    let mut cek = [0u8; 32];
    SystemRandom::new()
        .fill(&mut cek)
        .map_err(|_| anyhow::anyhow!("failed to generate random CEK"))?;
    Ok(cek)
}

/// Wrap `cek` into a mnemonic-recoverable [`CekRecovery`] under the KEK derived
/// from `seed32`. `epoch` records the CEK rotation generation.
pub fn wrap_cek_recovery(
    seed32: &[u8; 32],
    cek: &[u8; 32],
    epoch: u32,
) -> anyhow::Result<CekRecovery> {
    let kek = derive_cek_recovery_kek(seed32);

    let mut nonce_bytes = vec![0u8; 12];
    SystemRandom::new()
        .fill(&mut nonce_bytes)
        .map_err(|_| anyhow::anyhow!("failed to generate random nonce"))?;

    let unbound = UnboundKey::new(&CHACHA20_POLY1305, &kek)
        .map_err(|_| anyhow::anyhow!("failed to create ChaCha20 key"))?;
    let sealing_key = LessSafeKey::new(unbound);
    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
        .map_err(|_| anyhow::anyhow!("failed to construct nonce"))?;

    let mut in_out = cek.to_vec();
    in_out.reserve(CHACHA20_POLY1305.tag_len());
    sealing_key
        .seal_in_place_append_tag(nonce, Aad::from(recovery_aad(1, epoch)), &mut in_out)
        .map_err(|_| anyhow::anyhow!("ChaCha20-Poly1305 encryption failed"))?;

    Ok(CekRecovery {
        version: 1,
        epoch,
        nonce: hex::encode(&nonce_bytes),
        ciphertext: hex::encode(&in_out),
    })
}

/// Recover the CEK from a [`CekRecovery`] using `seed32` (re-derived from the
/// mnemonic). Errors if the seed is wrong, the blob is corrupt, or the version
/// is unrecognised.
pub fn unwrap_cek_recovery(blob: &CekRecovery, seed32: &[u8; 32]) -> anyhow::Result<[u8; 32]> {
    if blob.version != 1 {
        bail!("unsupported cek_recovery version: {}", blob.version);
    }

    let kek = derive_cek_recovery_kek(seed32);
    let nonce_bytes = hex::decode(&blob.nonce).context("invalid nonce hex in cek_recovery")?;
    let mut ciphertext =
        hex::decode(&blob.ciphertext).context("invalid ciphertext hex in cek_recovery")?;

    let unbound = UnboundKey::new(&CHACHA20_POLY1305, &kek)
        .map_err(|_| anyhow::anyhow!("failed to create ChaCha20 key"))?;
    let opening_key = LessSafeKey::new(unbound);
    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
        .map_err(|_| anyhow::anyhow!("failed to construct nonce"))?;

    let plaintext = opening_key
        .open_in_place(
            nonce,
            Aad::from(recovery_aad(blob.version, blob.epoch)),
            &mut ciphertext,
        )
        .map_err(|_| anyhow::anyhow!("decryption failed — wrong seed or corrupted recovery copy"))?;

    let cek: [u8; 32] = plaintext
        .try_into()
        .map_err(|_| anyhow::anyhow!("decrypted payload is not 32 bytes"))?;
    Ok(cek)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_recovers_cek() {
        let seed = [9u8; 32];
        let cek = [42u8; 32];
        let blob = wrap_cek_recovery(&seed, &cek, 0).unwrap();
        // The mnemonic (via seed32) alone recovers the exact CEK.
        assert_eq!(unwrap_cek_recovery(&blob, &seed).unwrap(), cek);
    }

    #[test]
    fn wrong_seed_fails() {
        let cek = [7u8; 32];
        let blob = wrap_cek_recovery(&[1u8; 32], &cek, 0).unwrap();
        assert!(
            unwrap_cek_recovery(&blob, &[2u8; 32]).is_err(),
            "a different seed must not recover the CEK"
        );
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let seed = [3u8; 32];
        let mut blob = wrap_cek_recovery(&seed, &[5u8; 32], 0).unwrap();
        let mut bytes = hex::decode(&blob.ciphertext).unwrap();
        bytes[0] ^= 0xff;
        blob.ciphertext = hex::encode(&bytes);
        assert!(unwrap_cek_recovery(&blob, &seed).is_err());
    }

    #[test]
    fn unknown_version_rejected() {
        let seed = [4u8; 32];
        let mut blob = wrap_cek_recovery(&seed, &[1u8; 32], 0).unwrap();
        blob.version = 99;
        assert!(unwrap_cek_recovery(&blob, &seed).is_err());
    }

    #[test]
    fn epoch_is_preserved() {
        let blob = wrap_cek_recovery(&[1u8; 32], &[2u8; 32], 7).unwrap();
        assert_eq!(blob.epoch, 7);
    }

    #[test]
    fn tampered_epoch_fails() {
        // epoch is bound into the AEAD AAD, so editing it must break decryption.
        let seed = [8u8; 32];
        let mut blob = wrap_cek_recovery(&seed, &[5u8; 32], 3).unwrap();
        blob.epoch = 4;
        assert!(
            unwrap_cek_recovery(&blob, &seed).is_err(),
            "a flipped epoch must be detected by the authenticated AAD"
        );
    }

    #[test]
    fn fresh_nonce_each_wrap() {
        let seed = [1u8; 32];
        let cek = [2u8; 32];
        let a = wrap_cek_recovery(&seed, &cek, 0).unwrap();
        let b = wrap_cek_recovery(&seed, &cek, 0).unwrap();
        assert_ne!(a.nonce, b.nonce, "each wrap uses a fresh nonce");
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn generated_ceks_are_random_and_32_bytes() {
        let a = generate_cek().unwrap();
        let b = generate_cek().unwrap();
        assert_eq!(a.len(), 32);
        assert_ne!(a, b, "two generated CEKs must differ");
    }
}
