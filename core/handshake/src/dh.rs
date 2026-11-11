// SPDX-License-Identifier: AGPL-3.0-or-later
//! The exchange, as this crate's own: X25519 that refuses a result of all zeros.
//!
//! The handshake's page: "Either side closes if an exchange yields all zeros, which is what refuses a key
//! of low order." Noise does not require the check and `snow` does not make it, so the one
//! exchange every message runs is this one, handed to `snow` through its resolver. Hashing,
//! the cipher and the random source are `snow`'s ring-backed ones.

use snow::params::DHChoice;
use snow::resolvers::{BoxedCryptoResolver, CryptoResolver, FallbackResolver, RingResolver};
use snow::types::{Cipher, Dh, Hash, Random};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// The resolver every handshake here is built with.
pub(crate) fn resolver() -> BoxedCryptoResolver {
    Box::new(FallbackResolver::new(
        Box::new(Exchange),
        Box::new(RingResolver),
    ))
}

struct Exchange;

impl CryptoResolver for Exchange {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        None
    }

    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        match choice {
            DHChoice::Curve25519 => Some(Box::new(Contributory::default())),
            _ => None,
        }
    }

    fn resolve_hash(&self, _: &snow::params::HashChoice) -> Option<Box<dyn Hash>> {
        None
    }

    fn resolve_cipher(&self, _: &snow::params::CipherChoice) -> Option<Box<dyn Cipher>> {
        None
    }
}

/// An X25519 key that refuses a non-contributory exchange. The private half is zeroed when
/// it is dropped.
#[derive(Default)]
struct Contributory {
    private: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl Dh for Contributory {
    fn name(&self) -> &'static str {
        "25519"
    }

    fn pub_len(&self) -> usize {
        32
    }

    fn priv_len(&self) -> usize {
        32
    }

    fn set(&mut self, private: &[u8]) {
        self.private.copy_from_slice(private);
        self.public = PublicKey::from(&StaticSecret::from(*self.private)).to_bytes();
    }

    fn generate(&mut self, rng: &mut dyn Random) {
        let mut fresh = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut fresh[..]);
        self.set(&fresh[..]);
    }

    fn pubkey(&self) -> &[u8] {
        &self.public
    }

    fn privkey(&self) -> &[u8] {
        &self.private[..]
    }

    fn dh(&self, public: &[u8], out: &mut [u8]) -> Result<(), snow::Error> {
        // snow hands its whole key buffer in; the value is its first 32 bytes.
        let public: [u8; 32] = public
            .get(..32)
            .and_then(|p| p.try_into().ok())
            .ok_or(snow::Error::Dh)?;
        let shared = StaticSecret::from(*self.private).diffie_hellman(&PublicKey::from(public));
        if !shared.was_contributory() {
            return Err(snow::Error::Dh);
        }
        out[..32].copy_from_slice(shared.as_bytes());
        Ok(())
    }
}
