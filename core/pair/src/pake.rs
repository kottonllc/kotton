// SPDX-License-Identifier: AGPL-3.0-or-later
//! The spoken code as a key: SPAKE2 over Ed25519 (RFC-0022, "Key agreement").
//!
//! Two strangers share a short code out of band. A balanced PAKE turns it into a
//! key that an eavesdropper — the relay, which routes every byte — cannot
//! derive without the code, and cannot brute-force offline: each wrong guess is
//! one failed run, and the offer burns on the first. The committed handshake
//! then folds this key into its schedule ([`crate::derive_session_with`]), so the
//! six digits the humans compare are also the code's.
//!
//! This is the `spake2` crate's protocol with the crate's own defaults, wrapped so
//! that the RNG is passed in (this crate compiles for the browser, where the
//! process RNG is not a given) and so that the role identities are pinned here,
//! once, and cannot drift between the two ends.

use anyhow::{anyhow, Result};
use rand::{CryptoRng, RngCore};
use spake2::{Ed25519Group, Identity, Password, Spake2};

/// Role identities bound into the PAKE, so a message from one side cannot be
/// reflected as the other's.
const ID_ISSUER: &[u8] = b"kotton:contact-pair:issuer:v1";
const ID_JOINER: &[u8] = b"kotton:contact-pair:joiner:v1";

/// Which side of the PAKE this party runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PakeRole {
    /// The side that spoke the code (SPAKE2's A).
    Issuer,
    /// The side that typed it (SPAKE2's B).
    Joiner,
}

/// A started PAKE: holds this side's secret scalar until the peer's message
/// arrives. Consumed by [`Pake::finish`].
pub struct Pake {
    inner: Spake2<Ed25519Group>,
}

impl Pake {
    /// Start the exchange for `role` with the shared `code`, returning the message
    /// to send. The code is used as the password verbatim, after the caller has
    /// normalised it (lowercase, trimmed) — normalisation is the caller's, since
    /// it is part of what a human is asked to type.
    pub fn start(role: PakeRole, code: &[u8], rng: impl CryptoRng + RngCore) -> (Self, Vec<u8>) {
        let pw = Password::new(code);
        let (a, b) = (Identity::new(ID_ISSUER), Identity::new(ID_JOINER));
        let (inner, msg) = match role {
            PakeRole::Issuer => Spake2::<Ed25519Group>::start_a_with_rng(&pw, &a, &b, rng),
            PakeRole::Joiner => Spake2::<Ed25519Group>::start_b_with_rng(&pw, &a, &b, rng),
        };
        (Self { inner }, msg)
    }

    /// Finish with the peer's message: the 32-byte shared key. Equal on both
    /// sides if and only if both used the same code and the messages were not
    /// substituted.
    pub fn finish(self, peer_msg: &[u8]) -> Result<[u8; 32]> {
        let key = self
            .inner
            .finish(peer_msg)
            .map_err(|e| anyhow!("pake: {e:?}"))?;
        key.as_slice()
            .try_into()
            .map_err(|_| anyhow!("pake produced a key of {} bytes, expected 32", key.len()))
    }
}

/// The key-confirmation tag one side sends after the PAKE: `HMAC(k, role ‖ sid)`.
/// Checked before the commit round, so a wrong code aborts before any digits
/// exist to be compared.
pub fn confirm_tag(k_pake: &[u8; 32], role: PakeRole, sid: &[u8; 16]) -> [u8; 32] {
    let label: &[u8] = match role {
        PakeRole::Issuer => b"issuer-pake",
        PakeRole::Joiner => b"joiner-pake",
    };
    let mut msg = Vec::with_capacity(label.len() + 16);
    msg.extend_from_slice(label);
    msg.extend_from_slice(sid);
    crate::hmac_sha256(k_pake, &msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn the_same_code_agrees_and_a_different_one_does_not() {
        let (a, ma) = Pake::start(PakeRole::Issuer, b"ripple-canyon-ember", OsRng);
        let (b, mb) = Pake::start(PakeRole::Joiner, b"ripple-canyon-ember", OsRng);
        let ka = a.finish(&mb).unwrap();
        let kb = b.finish(&ma).unwrap();
        assert_eq!(ka, kb);

        let (a, ma) = Pake::start(PakeRole::Issuer, b"ripple-canyon-ember", OsRng);
        let (b, mb) = Pake::start(PakeRole::Joiner, b"ripple-canyon-amber", OsRng);
        let ka = a.finish(&mb).unwrap();
        let kb = b.finish(&ma).unwrap();
        assert_ne!(ka, kb, "a one-letter typo must not agree");
        let sid = [7u8; 16];
        assert_ne!(
            confirm_tag(&ka, PakeRole::Joiner, &sid),
            confirm_tag(&kb, PakeRole::Joiner, &sid)
        );
    }

    /// A reflected message — one side's own frame handed back to it — is refused
    /// by the group encoding itself, not merely mismatched.
    #[test]
    fn a_reflected_message_is_refused() {
        let (a, ma) = Pake::start(PakeRole::Issuer, b"x", OsRng);
        assert!(a.finish(&ma).is_err());
        let (b, mb) = Pake::start(PakeRole::Joiner, b"x", OsRng);
        assert!(b.finish(&mb).is_err());
    }
}
