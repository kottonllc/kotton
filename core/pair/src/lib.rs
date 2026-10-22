// SPDX-License-Identifier: AGPL-3.0-or-later
//! kotton-pair — the pairing handshake and its channel, as pure mechanism.
//!
//! RFC-0040's committed ephemeral-X25519 handshake ([`handshake`]) and the
//! ChaCha20-Poly1305 counter-nonce channel it keys ([`channel`]) used to live in
//! two places: the math in `kotton-crypto`, the channel inside `kotton-peer`'s
//! QUIC state machine. Both are sans-I/O by construction — no socket, no clock,
//! no database — and both are needed by a party that is neither a node nor a
//! peer: a **browser** joining the ceremony through a gateway that must not be
//! able to read what follows (RFC-0078 GW3).
//!
//! A browser cannot depend on `kotton-crypto` — that crate reaches `kotton-wire`
//! and `kotton-sys`, which reach `uuid` and `tokio`'s network stack, none of
//! which compile for `wasm32-unknown-unknown`. So the handshake moved here, where
//! nothing above it is pulled in, and `kotton-crypto` re-exports it under the
//! name every existing caller uses. One definition of the key schedule, on both
//! ends of the wire, is the whole point: a second copy in JavaScript is a second
//! chance to get the transcript order wrong.
//!
//! **This crate has no authority.** It names no principal and holds no key
//! longer than one ceremony. It sits with `core/common` and `core/sys` in the
//! workspace's *mechanism* group for that reason.

pub mod browser;
pub mod channel;
pub mod handshake;
pub mod pake;
pub mod wire;

pub use channel::AeadChannel;
pub use pake::{Pake, PakeRole};
pub use handshake::{
    commit, derive_pair_keys, derive_session, derive_session_with, hmac_sha256, hmac_sha256_var, verify_commitment,
    EnrollmentSide, PairEphemeral, PairSession, Transcript,
};
