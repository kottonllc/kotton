// SPDX-License-Identifier: AGPL-3.0-or-later
//! The RFC-0040 handshake messages, as pure data.
//!
//! Moved here from `kotton_wire::peer` (which re-exports them) so both ends of a
//! browser ceremony — the node and a `wasm32` client — share one definition.
//! Field order and names are the wire; see the ceremony diagram in
//! `kotton_wire::peer`.

use serde::{Deserialize, Serialize};

/// `PairHello` — J's opening frame: protocol version + the offer's session id.
/// Sent in the clear (pre-key-agreement).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairHello {
    /// Handshake protocol version; transcript-bound so a v2 cannot be confused
    /// into v1 semantics.
    pub v: u16,
    /// 16-byte random session id — the mDNS offer instance name, single-use.
    pub sid: [u8; 16],
}

/// `PairCommit` — I's commitment `SHA-256(eph_pub_I ‖ nonce_I)`, sent **before**
/// I sees J's ephemeral key. This is the round that makes six digits worth exactly
/// one-in-a-million to an attacker (RFC-0040 §4).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairCommit {
    /// The 32-byte SHA-256 commitment to the issuer's ephemeral key + nonce.
    pub commit: [u8; 32],
}

/// `PairReveal` — an ephemeral public key and its nonce. J sends first (opening in
/// the clear); I sends second, revealing what its `PairCommit` bound. The receiver
/// of I's reveal MUST check it opens the commitment before proceeding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairReveal {
    /// The sender's ephemeral X25519 public key.
    pub eph_pub: [u8; 32],
    /// The sender's 32-byte nonce.
    pub nonce: [u8; 32],
}

/// `PairInfo` — the issuer's human label ("austin's PC"), sent as the **first
/// frame encrypted under `k_enc`**, before either confirmation. The §7 consent
/// dialogs need the name; broadcasting it over mDNS would leak presence, so it
/// travels inside the encrypted channel instead (RFC-0040 §1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairInfo {
    /// The issuer's device/identity label, shown to the joiner's human.
    pub label: String,
}

/// `PairConfirm` — a confirmation MAC `HMAC(k_conf_role, "<role>-confirmed" ‖
/// transcript)`, released by each side **only after** its local human confirms the
/// SAS. Either direction; each side verifies the peer's before proceeding. A peer
/// that could not compute the shared secret fails here even if a human
/// mis-confirms (RFC-0040 §2, key confirmation).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairConfirm {
    /// The 32-byte HMAC-SHA256 confirmation tag.
    pub mac: [u8; 32],
}

/// `PairAttestation` — the issuer's identity signature over the handshake
/// transcript, sent (AEAD under `k_enc`) right after the RFC-0033 payload. It
/// proves the SAS-confirmed party holds the identity key the payload claims,
/// binding the whole bundle to *this* transcript (anti-replay) and answering
/// "**whose** identity did this device just join" (RFC-0040 §2 step 9–10).
///
/// Signed with the **identity key** (the key the delivered KEL resolves to), not
/// the operational transport key — that is the only reading under which the
/// joiner's "verify against the KEL" step composes. On the QR/manual rungs, where
/// the issuer's key is pinned out-of-band, this same signature upgrades the
/// ceremony to full cryptographic authentication with no human comparison.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairAttestation {
    /// The issuer's identity public key (Ed25519). For a `Full`/`Cosigner`
    /// enrollment the joiner additionally checks this equals `resolve_current_key`
    /// of the delivered KEL; for a blind enrollment it *is* the learned root key.
    pub identity_pubkey: [u8; 32],
    /// Ed25519 signature (64 bytes) over `"kotton:pair-attest:v1" ‖ transcript`.
    /// A `Vec<u8>` because serde derives arrays only up to `[u8; 32]` (matches the
    /// `GuestAccessToken` convention).
    pub signature: Vec<u8>,
}

/// One SPAKE2 message (RFC-0022's key agreement over the relay). Sent in the
/// clear before the commit round, by each side; a party without the spoken code
/// derives a different key from it and fails [`PakeConfirm`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PakeMsg {
    pub msg: Vec<u8>,
}

/// Proof of the PAKE key: `HMAC(k_pake, "<role>-pake" ‖ sid)`. Exchanged before
/// any digits are shown, so a wrong code fails as a wrong code rather than as
/// two humans staring at different numbers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PakeConfirm {
    pub mac: [u8; 32],
}
