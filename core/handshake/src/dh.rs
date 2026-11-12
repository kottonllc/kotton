// SPDX-License-Identifier: AGPL-3.0-or-later
//! The exchange, as this crate's own: X25519 that refuses a result of all zeros.
//!
//! The handshake's page: "Either side closes if an exchange yields all zeros, which is what refuses a key
//! of low order." Noise does not require the check and `snow` does not make it, so the one
//! exchange every message runs is this one, handed to `snow` through its resolver. Hashing,
//! the cipher and the random source are `snow`'s ring-backed ones.
//!
//! **The responder's ephemeral value, kept for one read.** A recovery claim's tag is an
//! exchange between the claimed authority's key and the responder's ephemeral value of the
//! handshake (the handshake page's *Recovery keeps its door*), and `snow` never hands an
//! ephemeral value's private half back. So a responder's handshake is built with
//! [`responder_resolver`], whose second exchange, the one `snow` makes the ephemeral value
//! from (its builder resolves the static's first), writes the private half it is given or
//! makes into a slot the caller holds. The caller checks that slot against the value the
//! second message carried before it trusts it, keeps it until it has read the frame that
//! answers its first, and no longer (the page's *Consequences*); it is zeroed when dropped.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use snow::params::DHChoice;
use snow::resolvers::{BoxedCryptoResolver, CryptoResolver, FallbackResolver, RingResolver};
use snow::types::{Cipher, Dh, Hash, Random};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Where a responder's ephemeral private half is written, for the one read it is kept for.
pub(crate) type EphemeralSlot = Arc<Mutex<Option<Zeroizing<[u8; 32]>>>>;

/// The resolver every initiator's handshake here is built with.
pub(crate) fn resolver() -> BoxedCryptoResolver {
    Box::new(FallbackResolver::new(
        Box::new(Exchange::default()),
        Box::new(RingResolver),
    ))
}

/// The resolver a responder's handshake is built with: as [`resolver`], and the ephemeral
/// value's private half is written to `slot`.
pub(crate) fn responder_resolver(slot: EphemeralSlot) -> BoxedCryptoResolver {
    Box::new(FallbackResolver::new(
        Box::new(Exchange {
            resolved: AtomicUsize::new(0),
            keep: Some(slot),
        }),
        Box::new(RingResolver),
    ))
}

#[derive(Default)]
struct Exchange {
    /// How many exchanges this resolver has handed out: `snow` resolves the static's first
    /// and the ephemeral value's second.
    resolved: AtomicUsize,
    keep: Option<EphemeralSlot>,
}

impl CryptoResolver for Exchange {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        None
    }

    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        match choice {
            DHChoice::Curve25519 => {
                let nth = self.resolved.fetch_add(1, Ordering::Relaxed);
                Some(Box::new(Contributory {
                    keep: self.keep.clone().filter(|_| nth == 1),
                    ..Contributory::default()
                }))
            }
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
    /// Where the private half is written as well, for a responder's ephemeral value.
    keep: Option<EphemeralSlot>,
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
        if let Some(slot) = &self.keep {
            if let Ok(mut kept) = slot.lock() {
                *kept = Some(Zeroizing::new(*self.private));
            }
        }
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
