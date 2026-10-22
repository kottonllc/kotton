// SPDX-License-Identifier: AGPL-3.0-or-later
//! X25519 ECDH + ChaCha20-Poly1305 encryption for peer-to-peer and channel
//! messages (`sh.kotton.message.v1`).
//!
//! ## DM encryption (ephemeral ECDH)
//!
//! Each DM is encrypted with a fresh ephemeral X25519 keypair so that the
//! sender's identity key is never used as a static DH key:
//!
//! 1. Generate ephemeral `(eph_priv, eph_pub)`.
//! 2. Derive `shared_secret = X25519(eph_priv, recipient_x25519_pub)`.
//! 3. `sym_key = HKDF-SHA-256(ikm=shared_secret, salt=none, info="kotton:dm:v1")`.
//! 4. `(ciphertext, nonce) = ChaCha20-Poly1305(sym_key, plaintext)`.
//! 5. Store `(ciphertext, nonce, eph_pub)` in the record.
//!
//! Recipients derive `sym_key` by converting their own Ed25519 private key to
//! X25519, then running the same HKDF over `X25519(own_priv, eph_pub)`.
//!
//! ## Channel encryption (symmetric key)
//!
//! Channel messages use a 32-byte symmetric key pre-distributed to all members
//! via `sh.kotton.channel.key-grant` records (each grant is a DM-encrypted
//! copy of the channel key).
//!
//! The channel key is never sent to the hosting node in plaintext.
//!
//! ## DID ↔ X25519 key conversion
//!
//! Kotton DIDs are `did:key:` over Ed25519 public keys.  X25519 keys are
//! derived from Ed25519 keys via the Birkhoff point conversion (Elligator2):
//! Ed25519 verifying key (Edwards point) → Montgomery (X25519) point.
//! Ed25519 signing key seed → clamped X25519 scalar via SLIP-10-consistent
//! hashing (same approach as used in `core/05_runtime/src/user/pairing.rs`).

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use rand::RngCore;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

// ── Key conversion (Ed25519 ↔ X25519) ─────────────────────────────────────────

/// Convert an Ed25519 verifying-key byte array (32 bytes, compressed Edwards
/// point) to an X25519 public key (Montgomery form).
///
/// Used to derive the recipient's X25519 public key from their `did:key:`
/// (which encodes an Ed25519 verifying key).
pub fn ed25519_pub_to_x25519(ed_pub: &[u8; 32]) -> Result<X25519PublicKey> {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    let compressed = CompressedEdwardsY(*ed_pub);
    let edwards = compressed
        .decompress()
        .context("invalid Ed25519 public key: cannot decompress Edwards point")?;
    let montgomery = edwards.to_montgomery();
    Ok(X25519PublicKey::from(montgomery.to_bytes()))
}

/// Convert an Ed25519 signing key to an X25519 static secret.
///
/// Follows RFC 7748 §6.4 / Libsodium `crypto_sign_ed25519_sk_to_curve25519`.
/// The seed is SHA-512-hashed, the first 32 bytes are clamped per RFC 7748 §5,
/// and the result is used directly as the X25519 scalar.
pub fn ed25519_priv_to_x25519(signing_key: &SigningKey) -> StaticSecret {
    use sha2::Digest;
    let seed = signing_key.as_bytes();
    let hash = sha2::Sha512::digest(seed);
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&hash[..32]);
    // RFC 7748 §5 clamping
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    StaticSecret::from(scalar)
}

// ── HKDF key derivation ───────────────────────────────────────────────────────

fn derive_sym_key(dh_output: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, dh_output);
    let mut key = [0u8; 32];
    hk.expand(info, &mut key)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
    Ok(key)
}

// ── ChaCha20-Poly1305 seal / open ─────────────────────────────────────────────

fn chacha_seal(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 12])> {
    let unbound = UnboundKey::new(&CHACHA20_POLY1305, key)
        .map_err(|_| anyhow::anyhow!("chacha20: invalid key"))?;
    let sealing = LessSafeKey::new(unbound);

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut buf = plaintext.to_vec();
    buf.reserve(CHACHA20_POLY1305.tag_len());
    sealing
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut buf)
        .map_err(|_| anyhow::anyhow!("chacha20: encryption failed"))?;

    Ok((buf, nonce_bytes))
}

fn chacha_open(key: &[u8; 32], ciphertext: &[u8], nonce_bytes: &[u8; 12]) -> Result<Vec<u8>> {
    let unbound = UnboundKey::new(&CHACHA20_POLY1305, key)
        .map_err(|_| anyhow::anyhow!("chacha20: invalid key"))?;
    let opening = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(*nonce_bytes);
    let mut buf = ciphertext.to_vec();
    let plaintext = opening
        .open_in_place(nonce, Aad::empty(), &mut buf)
        .map_err(|_| anyhow::anyhow!("chacha20: decryption failed — bad key or tampered data"))?;
    Ok(plaintext.to_vec())
}

// ── DM encryption / decryption ────────────────────────────────────────────────

pub const DM_HKDF_INFO: &[u8] = b"kotton:dm:v1";

/// Encrypt `plaintext` as a DM to the recipient whose Ed25519 public key is
/// `recipient_ed_pub`.
///
/// Returns `(ciphertext, nonce_12, ephemeral_pub_32)`.  Store all three in
/// the `sh.kotton.message.v1` record (base64-encoded).
pub fn dm_encrypt(
    plaintext: &[u8],
    recipient_ed_pub: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 12], [u8; 32])> {
    let recipient_x25519 = ed25519_pub_to_x25519(recipient_ed_pub)?;

    // Generate ephemeral keypair
    let eph_priv = StaticSecret::random_from_rng(rand::thread_rng());
    let eph_pub = X25519PublicKey::from(&eph_priv);

    // DH + HKDF
    let dh = eph_priv.diffie_hellman(&recipient_x25519);
    let sym_key = derive_sym_key(dh.as_bytes(), DM_HKDF_INFO)?;

    let (ciphertext, nonce) = chacha_seal(&sym_key, plaintext)?;

    Ok((ciphertext, nonce, eph_pub.to_bytes()))
}

/// Decrypt a DM ciphertext using the recipient's Ed25519 signing key.
///
/// `eph_pub` is the 32-byte ephemeral X25519 public key stored in the record.
pub fn dm_decrypt(
    ciphertext: &[u8],
    nonce: &[u8; 12],
    eph_pub: &[u8; 32],
    recipient_signing_key: &SigningKey,
) -> Result<Vec<u8>> {
    let own_x25519 = ed25519_priv_to_x25519(recipient_signing_key);
    let eph_x25519 = X25519PublicKey::from(*eph_pub);
    let dh = own_x25519.diffie_hellman(&eph_x25519);
    let sym_key = derive_sym_key(dh.as_bytes(), DM_HKDF_INFO)?;
    chacha_open(&sym_key, ciphertext, nonce)
}

// ── Retired identity keys ─────────────────────────────────────────────────────

/// HKDF info for sealing a person's **retired** identity keys to their current
/// one. Distinct from [`DM_HKDF_INFO`] so a sealed key set can never be opened
/// as a message, nor a message as a key set.
pub const RETIRED_KEYS_HKDF_INFO: &[u8] = b"kotton:identity:retired-keys:v1";

/// Seal `keys` — identity keys a rotation retired — to `holder_ed_pub`, the
/// key that replaced them. The same ephemeral-ECDH construction as a DM, under
/// its own label.
///
/// What this is for: a message sealed to a key before a rotation opens only on
/// that key, so a node that discards it loses the person's own history
/// (`TASK-a-rotated-identity-key-leaves-every-older-message-sealed-to-a-key-the-node-no-longer-holds`).
/// Sealing the retired keys to the current one keeps them under the same lock
/// as the current one and nowhere else in the clear.
///
/// Returns `(ciphertext, nonce_12, ephemeral_pub_32)`.
pub fn retired_keys_seal(
    keys: &[SigningKey],
    holder_ed_pub: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 12], [u8; 32])> {
    let holder_x25519 = ed25519_pub_to_x25519(holder_ed_pub)?;
    let eph_priv = StaticSecret::random_from_rng(rand::thread_rng());
    let eph_pub = X25519PublicKey::from(&eph_priv);
    let dh = eph_priv.diffie_hellman(&holder_x25519);
    let sym_key = derive_sym_key(dh.as_bytes(), RETIRED_KEYS_HKDF_INFO)?;
    let mut plaintext = Vec::with_capacity(keys.len() * 32);
    for k in keys {
        plaintext.extend_from_slice(&k.to_bytes());
    }
    let sealed = chacha_seal(&sym_key, &plaintext);
    plaintext.fill(0);
    let (ciphertext, nonce) = sealed?;
    Ok((ciphertext, nonce, eph_pub.to_bytes()))
}

/// Open a key set sealed by [`retired_keys_seal`] with `holder`. Errors when
/// `holder` is not the key it was sealed to.
pub fn retired_keys_open(
    ciphertext: &[u8],
    nonce: &[u8; 12],
    eph_pub: &[u8; 32],
    holder: &SigningKey,
) -> Result<Vec<SigningKey>> {
    let own_x25519 = ed25519_priv_to_x25519(holder);
    let dh = own_x25519.diffie_hellman(&X25519PublicKey::from(*eph_pub));
    let sym_key = derive_sym_key(dh.as_bytes(), RETIRED_KEYS_HKDF_INFO)?;
    let mut plaintext = chacha_open(&sym_key, ciphertext, nonce)?;
    let keys = if plaintext.len() % 32 == 0 {
        Ok(plaintext
            .chunks_exact(32)
            .map(|c| SigningKey::from_bytes(c.try_into().expect("chunks_exact(32)")))
            .collect())
    } else {
        Err(anyhow::anyhow!("retired key set is not a whole number of keys"))
    };
    plaintext.fill(0);
    keys
}

// ── Channel symmetric key management ──────────────────────────────────────────

/// Generate a fresh 32-byte channel symmetric key.
pub fn channel_key_generate() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

/// Encrypt `plaintext` with a 32-byte channel symmetric key.
///
/// Returns `(ciphertext, nonce_12)`.
pub fn channel_encrypt(plaintext: &[u8], channel_key: &[u8; 32]) -> Result<(Vec<u8>, [u8; 12])> {
    chacha_seal(channel_key, plaintext)
}

/// Decrypt a channel message ciphertext.
pub fn channel_decrypt(
    ciphertext: &[u8],
    nonce: &[u8; 12],
    channel_key: &[u8; 32],
) -> Result<Vec<u8>> {
    chacha_open(channel_key, ciphertext, nonce)
}

pub const CHANNEL_KEY_WRAP_INFO: &[u8] = b"kotton:channel-key-wrap:v1";

/// Wrap (encrypt) a 32-byte channel key for delivery to `recipient_ed_pub`
/// using ephemeral X25519 ECDH (same scheme as `dm_encrypt`).
///
/// Returns `(encrypted_key, nonce_12, ephemeral_pub_32)`.  Store in a
/// `sh.kotton.channel.key-grant` record (base64-encoded).
pub fn channel_key_wrap(
    channel_key: &[u8; 32],
    recipient_ed_pub: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 12], [u8; 32])> {
    let recipient_x25519 = ed25519_pub_to_x25519(recipient_ed_pub)?;
    let eph_priv = StaticSecret::random_from_rng(rand::thread_rng());
    let eph_pub = X25519PublicKey::from(&eph_priv);
    let dh = eph_priv.diffie_hellman(&recipient_x25519);
    let wrap_key = derive_sym_key(dh.as_bytes(), CHANNEL_KEY_WRAP_INFO)?;
    let (enc_key, nonce) = chacha_seal(&wrap_key, channel_key)?;
    Ok((enc_key, nonce, eph_pub.to_bytes()))
}

/// Unwrap a channel key received in a `sh.kotton.channel.key-grant` record.
pub fn channel_key_unwrap(
    enc_key: &[u8],
    nonce: &[u8; 12],
    eph_pub: &[u8; 32],
    recipient_signing_key: &SigningKey,
) -> Result<[u8; 32]> {
    let own_x25519 = ed25519_priv_to_x25519(recipient_signing_key);
    let eph_x25519 = X25519PublicKey::from(*eph_pub);
    let dh = own_x25519.diffie_hellman(&eph_x25519);
    let wrap_key = derive_sym_key(dh.as_bytes(), CHANNEL_KEY_WRAP_INFO)?;
    let plain = chacha_open(&wrap_key, enc_key, nonce)?;
    plain
        .try_into()
        .map_err(|_| anyhow::anyhow!("channel key unwrap: expected 32 bytes"))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn random_signing_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    #[test]
    fn dm_roundtrip() {
        let recipient_key = random_signing_key();
        let recipient_pub: [u8; 32] = recipient_key.verifying_key().to_bytes();

        let plaintext = b"hello, encrypted world!";
        let (ct, nonce, eph_pub) = dm_encrypt(plaintext, &recipient_pub).unwrap();

        let decrypted = dm_decrypt(&ct, &nonce, &eph_pub, &recipient_key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn dm_wrong_key_fails() {
        let recipient_key = random_signing_key();
        let recipient_pub: [u8; 32] = recipient_key.verifying_key().to_bytes();
        let wrong_key = random_signing_key();

        let (ct, nonce, eph_pub) = dm_encrypt(b"secret", &recipient_pub).unwrap();
        assert!(dm_decrypt(&ct, &nonce, &eph_pub, &wrong_key).is_err());
    }

    #[test]
    fn channel_roundtrip() {
        let key = channel_key_generate();
        let plaintext = b"channel message";
        let (ct, nonce) = channel_encrypt(plaintext, &key).unwrap();
        let decrypted = channel_decrypt(&ct, &nonce, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn channel_key_wrap_roundtrip() {
        let recipient_key = random_signing_key();
        let recipient_pub: [u8; 32] = recipient_key.verifying_key().to_bytes();

        let channel_key = channel_key_generate();
        let (enc_key, nonce, eph_pub) = channel_key_wrap(&channel_key, &recipient_pub).unwrap();
        let unwrapped = channel_key_unwrap(&enc_key, &nonce, &eph_pub, &recipient_key).unwrap();
        assert_eq!(unwrapped, channel_key);
    }

    #[test]
    fn retired_keys_open_only_on_the_key_they_were_sealed_to() {
        let holder = random_signing_key();
        let retired = [random_signing_key(), random_signing_key()];
        let (ct, nonce, eph) =
            retired_keys_seal(&retired, &holder.verifying_key().to_bytes()).unwrap();
        let opened = retired_keys_open(&ct, &nonce, &eph, &holder).unwrap();
        assert_eq!(
            opened.iter().map(SigningKey::to_bytes).collect::<Vec<_>>(),
            retired.iter().map(SigningKey::to_bytes).collect::<Vec<_>>(),
        );
        // Not by a retired key itself, and not as a message: the label differs.
        assert!(retired_keys_open(&ct, &nonce, &eph, &retired[0]).is_err());
        assert!(dm_decrypt(&ct, &nonce, &eph, &holder).is_err());
    }
}
