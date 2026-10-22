// SPDX-License-Identifier: AGPL-3.0-or-later
//! Mnemonic-rooted recovery wrapping for the operational roots (RFC-0039).
//!
//! In the generate-and-seal model the operational roots — `master_secret` (the
//! DB-encryption root), the identity key, and the CEK — are random 32-byte secrets
//! (**not** derived from `seed32`), so each can be rotated without changing the
//! mnemonic. To keep the mnemonic as the single recovery root, a **recovery copy**
//! of each is wrapped under a **domain-separated, mnemonic-derived KEK**
//! ([`derive_master_secret_recovery_kek`], [`derive_identity_recovery_kek`],
//! [`crate::kdf::derive_cek_recovery_kek`]). The mnemonic alone can therefore
//! always re-establish a working identity *and* recover all data after total
//! device loss — the continuity invariant in code.
//!
//! This module is the shared AEAD envelope ([`RecoveryCopy`] + [`wrap_recovery`] /
//! [`unwrap_recovery`]) plus thin per-root helpers. (`cek_recovery.rs` predates it
//! and additionally binds a rotation `epoch`; it can fold onto this envelope later.)

use anyhow::{bail, Context};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use crate::kdf::derive_master_secret_recovery_kek;

/// A mnemonic-recoverable copy of one 32-byte operational root.
///
/// Binary fields are lowercase hex. The KEK is re-derived from `seed32` at recovery
/// time, so no salt is stored; the random nonce alone provides per-wrap uniqueness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCopy {
    /// Format version — always `1` for this implementation.
    pub version: u32,
    /// 12-byte ChaCha20-Poly1305 nonce, hex-encoded.
    pub nonce: String,
    /// 48-byte ciphertext (32 plaintext bytes + 16 auth tag), hex-encoded.
    pub ciphertext: String,
}

/// Associated data binding the wrap's `version` into the AEAD tag, so an edit to the
/// stored `version` becomes a decryption failure rather than a silent mislabel.
fn recovery_aad(version: u32) -> [u8; 4] {
    version.to_le_bytes()
}

/// Wrap a 32-byte `secret` under `kek` into a [`RecoveryCopy`]. The caller derives
/// the domain-separated KEK for the specific root (see the per-root helpers below).
pub fn wrap_recovery(kek: &[u8; 32], secret: &[u8; 32]) -> anyhow::Result<RecoveryCopy> {
    let mut nonce_bytes = vec![0u8; 12];
    SystemRandom::new()
        .fill(&mut nonce_bytes)
        .map_err(|_| anyhow::anyhow!("failed to generate random nonce"))?;

    let unbound = UnboundKey::new(&CHACHA20_POLY1305, kek)
        .map_err(|_| anyhow::anyhow!("failed to create ChaCha20 key"))?;
    let sealing_key = LessSafeKey::new(unbound);
    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
        .map_err(|_| anyhow::anyhow!("failed to construct nonce"))?;

    let mut in_out = secret.to_vec();
    in_out.reserve(CHACHA20_POLY1305.tag_len());
    sealing_key
        .seal_in_place_append_tag(nonce, Aad::from(recovery_aad(1)), &mut in_out)
        .map_err(|_| anyhow::anyhow!("ChaCha20-Poly1305 encryption failed"))?;

    Ok(RecoveryCopy {
        version: 1,
        nonce: hex::encode(&nonce_bytes),
        ciphertext: hex::encode(&in_out),
    })
}

/// Recover the 32-byte secret from a [`RecoveryCopy`] using `kek`. Errors if the KEK
/// is wrong, the blob is corrupt, or the version is unrecognised.
pub fn unwrap_recovery(copy: &RecoveryCopy, kek: &[u8; 32]) -> anyhow::Result<[u8; 32]> {
    if copy.version != 1 {
        bail!("unsupported recovery copy version: {}", copy.version);
    }

    let nonce_bytes = hex::decode(&copy.nonce).context("invalid nonce hex in recovery copy")?;
    let mut ciphertext =
        hex::decode(&copy.ciphertext).context("invalid ciphertext hex in recovery copy")?;

    let unbound = UnboundKey::new(&CHACHA20_POLY1305, kek)
        .map_err(|_| anyhow::anyhow!("failed to create ChaCha20 key"))?;
    let opening_key = LessSafeKey::new(unbound);
    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
        .map_err(|_| anyhow::anyhow!("failed to construct nonce"))?;

    let plaintext = opening_key
        .open_in_place(nonce, Aad::from(recovery_aad(copy.version)), &mut ciphertext)
        .map_err(|_| anyhow::anyhow!("decryption failed — wrong seed or corrupted recovery copy"))?;

    plaintext
        .try_into()
        .map_err(|_| anyhow::anyhow!("decrypted payload is not 32 bytes"))
}

// ── Per-root helpers (derive the domain-separated KEK, then wrap/unwrap) ─────────

// `wrap_identity_recovery` / `unwrap_identity_recovery` were deleted 2026-09-04
// (`DEC-0051`): a phrase-sealed copy of the identity key is in-place forgery with
// extra steps, and nothing may open one. The KEK label stays reserved.

/// Seal a recovery copy of the operational **`master_secret`** under the mnemonic.
pub fn wrap_master_secret_recovery(seed32: &[u8; 32], master_secret: &[u8; 32]) -> anyhow::Result<RecoveryCopy> {
    wrap_recovery(&derive_master_secret_recovery_kek(seed32), master_secret)
}
/// Recover the operational `master_secret` from its [`RecoveryCopy`] using the mnemonic seed.
pub fn unwrap_master_secret_recovery(copy: &RecoveryCopy, seed32: &[u8; 32]) -> anyhow::Result<[u8; 32]> {
    unwrap_recovery(copy, &derive_master_secret_recovery_kek(seed32))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::{derive_cek_recovery_kek, derive_identity_recovery_kek, derive_master_secret_recovery_kek};

    #[test]
    fn round_trip_generic() {
        let kek = [11u8; 32];
        let secret = [42u8; 32];
        let copy = wrap_recovery(&kek, &secret).unwrap();
        assert_eq!(unwrap_recovery(&copy, &kek).unwrap(), secret);
    }

    #[test]
    fn wrong_kek_fails() {
        let copy = wrap_recovery(&[1u8; 32], &[7u8; 32]).unwrap();
        assert!(unwrap_recovery(&copy, &[2u8; 32]).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let kek = [3u8; 32];
        let mut copy = wrap_recovery(&kek, &[5u8; 32]).unwrap();
        let mut bytes = hex::decode(&copy.ciphertext).unwrap();
        bytes[0] ^= 0xff;
        copy.ciphertext = hex::encode(&bytes);
        assert!(unwrap_recovery(&copy, &kek).is_err());
    }

    #[test]
    fn unknown_version_rejected() {
        let kek = [4u8; 32];
        let mut copy = wrap_recovery(&kek, &[1u8; 32]).unwrap();
        copy.version = 99;
        assert!(unwrap_recovery(&copy, &kek).is_err());
    }

    #[test]
    fn fresh_nonce_each_wrap() {
        let kek = [1u8; 32];
        let secret = [2u8; 32];
        let a = wrap_recovery(&kek, &secret).unwrap();
        let b = wrap_recovery(&kek, &secret).unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn master_secret_helper_round_trip() {
        let seed = [3u8; 32];
        let ms = [7u8; 32];
        let copy = wrap_master_secret_recovery(&seed, &ms).unwrap();
        assert_eq!(unwrap_master_secret_recovery(&copy, &seed).unwrap(), ms);
    }

    #[test]
    fn recovery_keks_are_domain_separated() {
        // The three roots' recovery KEKs must never collide — distinct labels.
        let seed = [5u8; 32];
        let m = derive_master_secret_recovery_kek(&seed);
        let i = derive_identity_recovery_kek(&seed);
        let c = derive_cek_recovery_kek(&seed);
        assert_ne!(m, i, "master vs identity recovery KEK collide");
        assert_ne!(m, c, "master vs cek recovery KEK collide");
        assert_ne!(i, c, "identity vs cek recovery KEK collide");
    }

}
