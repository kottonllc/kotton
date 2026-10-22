// SPDX-License-Identifier: AGPL-3.0-or-later
//! At-rest vault for the operational roots (RFC-0039).
//!
//! In the generate-and-seal model the three operational roots — `master_secret`
//! (DB-encryption root), the identity key, and the CEK — are random and stored
//! only wrapped. This module wraps all three at rest under the **device-local
//! unlock credential** `U = Argon2id(PIN, salt)` (the same derivation as
//! [`crate::pin_wrap`]; a biometric-enclave `U` is a later variant).
//!
//! One Argon2 pass derives `U`; each root is sealed with a distinct nonce and a
//! **domain-separating AAD** (`version || root-label`), so a ciphertext sealed for
//! one root cannot be substituted for another and an edited `version` is a
//! decryption failure. The vault is a small JSON blob at
//! `users/{user_id}/vault.json`; on unlock the roots are unwrapped for the
//! session. `seed32` is **never** part of this — the mnemonic seals only the
//! separate recovery copies ([`crate::recovery`]).

use anyhow::{bail, Context};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use crate::pin_wrap::derive_wrap_key;

/// Version written for a vault sealed under the credential alone.
const VERSION: u32 = 1;
/// Version written for a vault additionally bound to this device's hardware
/// (RFC-0053 step 8 / RFC-0056 `HardwareCustody`).
///
/// A separate version rather than an optional field, so the failure mode is
/// legible: a reader that cannot supply the binding secret refuses a v2 vault by
/// name instead of attempting a decryption that would fail for reasons nobody
/// could diagnose. It is also what makes downgrade explicit — see
/// [`binding_aad`].
const VERSION_BOUND: u32 = 2;
const LABEL_MASTER: &[u8] = b"master_secret";
const LABEL_IDENTITY: &[u8] = b"identity_key";
const LABEL_CEK: &[u8] = b"cek";
/// HKDF domain separator mixing the device binding into the unlock key.
const BINDING_INFO: &[u8] = b"kotton:vault:device-binding:v1";

/// The three operational roots, in the clear (in memory only, for a session).
#[derive(Clone)]
pub struct OperationalRoots {
    pub master_secret: [u8; 32],
    pub identity_key: [u8; 32],
    pub cek: [u8; 32],
}

/// One root sealed under `U`. Binary fields are lowercase hex.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedRoot {
    /// 12-byte ChaCha20-Poly1305 nonce, hex-encoded.
    pub nonce: String,
    /// 48-byte ciphertext (32 plaintext bytes + 16 auth tag), hex-encoded.
    pub ciphertext: String,
}

/// On-disk at-rest vault: the three operational roots wrapped under `U`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtRestVault {
    /// Format version — always `1` for this implementation.
    pub version: u32,
    /// 16-byte random Argon2id salt, hex-encoded. `U = Argon2id(PIN, salt)`.
    pub salt: String,
    pub master_secret: SealedRoot,
    pub identity_key: SealedRoot,
    pub cek: SealedRoot,
}

/// AAD binding the format `version` and the per-root `label` into the AEAD tag.
fn root_aad(version: u32, label: &[u8]) -> Vec<u8> {
    let mut aad = version.to_le_bytes().to_vec();
    aad.extend_from_slice(label);
    aad
}

fn seal_root(
    u: &[u8; 32],
    label: &[u8],
    version: u32,
    secret: &[u8; 32],
) -> anyhow::Result<SealedRoot> {
    let mut nonce_bytes = vec![0u8; 12];
    SystemRandom::new()
        .fill(&mut nonce_bytes)
        .map_err(|_| anyhow::anyhow!("failed to generate random nonce"))?;

    let unbound = UnboundKey::new(&CHACHA20_POLY1305, u)
        .map_err(|_| anyhow::anyhow!("failed to create ChaCha20 key"))?;
    let sealing_key = LessSafeKey::new(unbound);
    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
        .map_err(|_| anyhow::anyhow!("failed to construct nonce"))?;

    let mut in_out = secret.to_vec();
    in_out.reserve(CHACHA20_POLY1305.tag_len());
    // The version is inside the AAD, so a v2 vault edited to claim v1 fails to
    // open rather than silently falling back to an unbound derivation. Downgrade
    // is refused by the cryptography, not only by the version check above.
    sealing_key
        .seal_in_place_append_tag(nonce, Aad::from(root_aad(version, label)), &mut in_out)
        .map_err(|_| anyhow::anyhow!("ChaCha20-Poly1305 encryption failed"))?;

    Ok(SealedRoot {
        nonce: hex::encode(&nonce_bytes),
        ciphertext: hex::encode(&in_out),
    })
}

fn open_root(u: &[u8; 32], label: &[u8], version: u32, sealed: &SealedRoot) -> anyhow::Result<[u8; 32]> {
    let nonce_bytes = hex::decode(&sealed.nonce).context("invalid nonce hex in vault")?;
    let mut ciphertext = hex::decode(&sealed.ciphertext).context("invalid ciphertext hex in vault")?;

    let unbound = UnboundKey::new(&CHACHA20_POLY1305, u)
        .map_err(|_| anyhow::anyhow!("failed to create ChaCha20 key"))?;
    let opening_key = LessSafeKey::new(unbound);
    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
        .map_err(|_| anyhow::anyhow!("failed to construct nonce"))?;

    let plaintext = opening_key
        .open_in_place(nonce, Aad::from(root_aad(version, label)), &mut ciphertext)
        .map_err(|_| anyhow::anyhow!("vault decryption failed — wrong PIN or corrupted vault"))?;

    plaintext
        .try_into()
        .map_err(|_| anyhow::anyhow!("decrypted root is not 32 bytes"))
}

/// Mix a device-binding secret into the credential-derived unlock key.
///
/// `U' = HKDF-SHA256(ikm = U, salt = binding, info = BINDING_INFO)`.
///
/// The binding is the **salt** and the credential the **IKM**, which is the
/// right way round: HKDF-Extract is a PRF keyed by the salt, so a binding secret
/// the attacker does not hold makes the output unpredictable even when they know
/// the credential. Reversing them would let someone who copied the vault
/// precompute candidate `U'` values from guessed credentials alone.
fn bind_to_device(u: &[u8; 32], binding: &[u8; 32]) -> [u8; 32] {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(binding), u);
    let mut bound = [0u8; 32];
    hk.expand(BINDING_INFO, &mut bound)
        .expect("32 bytes is a valid HKDF output length");
    bound
}

/// The unlock key for a vault: `U`, optionally bound to this device.
fn unlock_key(pin: &str, salt: &[u8], binding: Option<&[u8; 32]>) -> anyhow::Result<[u8; 32]> {
    let u = derive_wrap_key(pin, salt)?;
    Ok(match binding {
        Some(b) => bind_to_device(&u, b),
        None => u,
    })
}

/// Seal the three operational roots under `U` derived from `pin`. A fresh salt is
/// generated, so re-sealing the same roots + PIN yields a different vault.
///
/// `binding`, when present, is a secret this device can reproduce and another
/// cannot (RFC-0053 step 8). It makes the vault **useless off this machine**,
/// which is what removes the offline attack — the attacker must guess on the
/// device, at the device's rate, rather than on rented hardware.
///
/// It does **not** by itself justify a short credential. That requires the
/// binding to be held by something that *counts failed attempts*, which is a
/// property of the backend rather than of binding as such — see
/// `kotton_sys::secret::attempt_limiting`.
pub fn seal_vault(
    pin: &str,
    roots: &OperationalRoots,
    binding: Option<&[u8; 32]>,
) -> anyhow::Result<AtRestVault> {
    let mut salt = [0u8; 16];
    SystemRandom::new()
        .fill(&mut salt)
        .map_err(|_| anyhow::anyhow!("failed to generate random salt"))?;

    let version = if binding.is_some() {
        VERSION_BOUND
    } else {
        VERSION
    };
    let u = unlock_key(pin, &salt, binding)?;

    Ok(AtRestVault {
        version,
        salt: hex::encode(salt),
        master_secret: seal_root(&u, LABEL_MASTER, version, &roots.master_secret)?,
        identity_key: seal_root(&u, LABEL_IDENTITY, version, &roots.identity_key)?,
        cek: seal_root(&u, LABEL_CEK, version, &roots.cek)?,
    })
}

/// Open the vault with `pin`, recovering the three operational roots. Errors if
/// the PIN is wrong, the vault is corrupt, or the version is unrecognised.
///
/// A `VERSION_BOUND` vault requires `binding`; a `VERSION` vault must not be
/// given one. Both mismatches are refused **before** any decryption is
/// attempted, so the error says what is actually wrong rather than reporting a
/// wrong credential.
pub fn open_vault(
    vault: &AtRestVault,
    pin: &str,
    binding: Option<&[u8; 32]>,
) -> anyhow::Result<OperationalRoots> {
    match (vault.version, binding) {
        (VERSION, None) | (VERSION_BOUND, Some(_)) => {}
        (VERSION_BOUND, None) => bail!(
            "this vault is bound to a device's hardware and cannot be opened without it \
             — recover with your recovery phrase on this device, or on another one"
        ),
        (VERSION, Some(_)) => bail!(
            "this vault predates device binding; opening it must not mix in a binding secret"
        ),
        (other, _) => bail!("unsupported vault version: {other}"),
    }

    let salt = hex::decode(&vault.salt).context("invalid salt hex in vault")?;
    let u = unlock_key(pin, &salt, binding)?;

    Ok(OperationalRoots {
        master_secret: open_root(&u, LABEL_MASTER, vault.version, &vault.master_secret)?,
        identity_key: open_root(&u, LABEL_IDENTITY, vault.version, &vault.identity_key)?,
        cek: open_root(&u, LABEL_CEK, vault.version, &vault.cek)?,
    })
}


#[cfg(test)]
mod tests {
    use super::*;

    const BINDING: [u8; 32] = [7u8; 32];
    const OTHER_DEVICE: [u8; 32] = [9u8; 32];

    fn roots() -> OperationalRoots {
        OperationalRoots {
            master_secret: [1u8; 32],
            identity_key: [2u8; 32],
            cek: [3u8; 32],
        }
    }

    #[test]
    fn round_trip() {
        let v = seal_vault("123456", &roots(), None).unwrap();
        let out = open_vault(&v, "123456", None).unwrap();
        assert_eq!(out.master_secret, [1u8; 32]);
        assert_eq!(out.identity_key, [2u8; 32]);
        assert_eq!(out.cek, [3u8; 32]);
    }

    #[test]
    fn wrong_pin_fails() {
        let v = seal_vault("111111", &roots(), None).unwrap();
        assert!(open_vault(&v, "222222", None).is_err(), "wrong PIN must not open the vault");
    }

    #[test]
    fn fresh_salt_each_seal() {
        let a = seal_vault("000000", &roots(), None).unwrap();
        let b = seal_vault("000000", &roots(), None).unwrap();
        assert_ne!(a.salt, b.salt);
        assert_ne!(a.master_secret.ciphertext, b.master_secret.ciphertext);
    }

    #[test]
    fn tampered_root_fails() {
        let mut v = seal_vault("999999", &roots(), None).unwrap();
        let mut bytes = hex::decode(&v.identity_key.ciphertext).unwrap();
        bytes[0] ^= 0xff;
        v.identity_key.ciphertext = hex::encode(&bytes);
        assert!(open_vault(&v, "999999", None).is_err());
    }

    #[test]
    fn roots_cannot_be_substituted() {
        // The per-root AAD label must prevent swapping one root's ciphertext for
        // another's — even though all three are sealed under the same U.
        let mut v = seal_vault("424242", &roots(), None).unwrap();
        v.identity_key = v.master_secret.clone(); // put master's ciphertext in the identity slot
        assert!(
            open_vault(&v, "424242", None).is_err(),
            "a root sealed under one label must not open under another"
        );
    }

    #[test]
    fn unknown_version_rejected() {
        let mut v = seal_vault("123456", &roots(), None).unwrap();
        v.version = 99;
        assert!(open_vault(&v, "123456", None).is_err());
    }

    // ── Device binding (RFC-0053 step 8) ────────────────────────────────────

    #[test]
    fn a_bound_vault_round_trips_on_its_own_device() {
        let v = seal_vault("123456", &roots(), Some(&BINDING)).unwrap();
        assert_eq!(v.version, VERSION_BOUND);
        let out = open_vault(&v, "123456", Some(&BINDING)).unwrap();
        assert_eq!(out.master_secret, [1u8; 32]);
    }

    /// The property the whole feature exists for: copying the file to another
    /// machine buys nothing, **even with the correct credential**. This is what
    /// removes the offline attack — guessing has to happen on the device.
    #[test]
    fn a_bound_vault_is_useless_on_another_device() {
        let v = seal_vault("123456", &roots(), Some(&BINDING)).unwrap();
        assert!(
            open_vault(&v, "123456", Some(&OTHER_DEVICE)).is_err(),
            "the right credential on the wrong device must not open a bound vault"
        );
    }

    /// Stripping the binding must not degrade to an unbound open. An attacker
    /// who edits `version` back to 1 is refused by the version check, and would
    /// be refused by the AAD even if that check were removed.
    #[test]
    fn a_bound_vault_cannot_be_downgraded_to_unbound() {
        let mut v = seal_vault("123456", &roots(), Some(&BINDING)).unwrap();
        assert!(
            open_vault(&v, "123456", None).is_err(),
            "a v2 vault must not open without its binding"
        );

        v.version = VERSION;
        assert!(
            open_vault(&v, "123456", None).is_err(),
            "editing the version must not produce an openable unbound vault"
        );
    }

    /// The reverse mistake: handing a binding to a vault that was never bound.
    /// Refused explicitly rather than reported as a wrong credential, because
    /// the two have completely different remedies.
    #[test]
    fn an_unbound_vault_refuses_a_binding() {
        let v = seal_vault("123456", &roots(), None).unwrap();
        // `.err()` rather than `unwrap_err()`: `OperationalRoots` has no `Debug`
        // on purpose — key material should not be printable — and `unwrap_err`
        // would require it.
        let err = open_vault(&v, "123456", Some(&BINDING))
            .err()
            .expect("a binding must be refused")
            .to_string();
        assert!(err.contains("predates device binding"), "got: {err}");
    }

    /// A v1 vault written before this change still opens untouched — the
    /// migration must never strand an existing user's data.
    #[test]
    fn vaults_written_before_binding_still_open() {
        let v = seal_vault("123456", &roots(), None).unwrap();
        assert_eq!(v.version, VERSION, "unbound seals must still write v1");
        assert!(open_vault(&v, "123456", None).is_ok());
    }

    /// The binding must actually change the key, not merely the version field.
    #[test]
    fn binding_changes_the_derived_key() {
        let u = [4u8; 32];
        assert_ne!(bind_to_device(&u, &BINDING), u);
        assert_ne!(bind_to_device(&u, &BINDING), bind_to_device(&u, &OTHER_DEVICE));
    }
}
