// SPDX-License-Identifier: AGPL-3.0-or-later
//! The post-handshake symmetric channel (RFC-0040 reference notes).
//!
//! ChaCha20-Poly1305 under `k_enc` with **counter nonces from zero, issuer even /
//! joiner odd**. `k_enc` is fresh per ceremony, so nonce reuse is structurally
//! impossible; the parity split keeps the two directions from ever colliding on
//! a nonce despite sharing the key.
//!
//! Sans-I/O: [`AeadChannel::seal`] and [`AeadChannel::open`] turn bytes into
//! bytes, and whatever carries them — a QUIC stream, a WebSocket relayed by a
//! gateway, a test's `Vec` — is the caller's business. Frames must be delivered
//! **in order and without loss**, which every carrier this is used over
//! guarantees; a reordered frame fails to open, as it should.

use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};

use crate::handshake::EnrollmentSide;

/// One side of an established pairing channel.
pub struct AeadChannel {
    cipher: ChaCha20Poly1305,
    /// Number of frames this side has sealed.
    send_count: u64,
    /// Number of frames this side has opened.
    recv_count: u64,
    /// This side's nonce parity: `true` = even (issuer), `false` = odd (joiner).
    send_even: bool,
}

impl AeadChannel {
    /// Key a channel with the ceremony's `k_enc`, as `role`.
    pub fn new(k_enc: &[u8; 32], role: EnrollmentSide) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(k_enc.into()),
            send_count: 0,
            recv_count: 0,
            send_even: matches!(role, EnrollmentSide::Issuer),
        }
    }

    /// Nonce for the `count`-th frame of a given parity: `2*count + parity`, packed
    /// big-endian into the low 8 bytes of the 12-byte nonce.
    fn nonce(count: u64, even: bool) -> Nonce {
        let n = count
            .checked_mul(2)
            .and_then(|v| v.checked_add(if even { 0 } else { 1 }))
            .expect("pairing AEAD nonce counter overflow (impossible in one ceremony)");
        let mut bytes = [0u8; 12];
        bytes[4..].copy_from_slice(&n.to_be_bytes());
        Nonce::from(bytes)
    }

    /// Seal one frame under this side's next nonce.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = Self::nonce(self.send_count, self.send_even);
        self.send_count += 1;
        self.cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| anyhow!("pairing channel AEAD seal failed: {e}"))
    }

    /// Open the peer's next frame.
    pub fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // The peer's parity is the opposite of ours.
        let nonce = Self::nonce(self.recv_count, !self.send_even);
        self.recv_count += 1;
        self.cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|e| anyhow!("pairing channel AEAD open failed (tamper or desync): {e}"))
    }

    /// Frames sealed so far by this side.
    pub fn sent(&self) -> u64 {
        self.send_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_directions_round_trip_and_never_share_a_nonce() {
        let k = [9u8; 32];
        let mut i = AeadChannel::new(&k, EnrollmentSide::Issuer);
        let mut j = AeadChannel::new(&k, EnrollmentSide::Joiner);
        for n in 0..4u8 {
            let ct = i.seal(&[n]).unwrap();
            assert_eq!(j.open(&ct).unwrap(), vec![n]);
            let ct = j.seal(&[n, n]).unwrap();
            assert_eq!(i.open(&ct).unwrap(), vec![n, n]);
        }
        // The same count on the two parities is two different nonces.
        assert_ne!(AeadChannel::nonce(3, true), AeadChannel::nonce(3, false));
    }

    #[test]
    fn a_reordered_or_tampered_frame_does_not_open() {
        let k = [1u8; 32];
        let mut i = AeadChannel::new(&k, EnrollmentSide::Issuer);
        let mut j = AeadChannel::new(&k, EnrollmentSide::Joiner);
        let first = i.seal(b"first").unwrap();
        let second = i.seal(b"second").unwrap();
        assert!(j.open(&second).is_err(), "out of order must fail");
        let mut bad = first.clone();
        bad[0] ^= 1;
        assert!(j.open(&bad).is_err(), "tampered must fail");
    }
}
