// SPDX-License-Identifier: AGPL-3.0-or-later
//! Key Event Log (KEL) event schema — RFC-0038.
//!
//! The identity-continuity layer replaces `did:key` (identifier == a single key)
//! with a stable **AID** whose authoritative key is established by an append-only,
//! hash-chained, **pre-rotated** key event log. This module is the tier-02 wire
//! schema for a KEL event plus its **canonical encoding** — the deterministic
//! byte form that the event digest and signatures are taken over.
//!
//! Tier boundary: this crate defines the *types* and the *canonical form* only.
//! Hashing (the SHA-256 digest / AID derivation) and signature verification —
//! including `validate(prev, event)` and the pre-rotation reveal checks — live in
//! tier-03 (`kotton-providers-crypto`), which owns the crypto primitives. Keeping
//! the canonical form here means every tier produces byte-identical pre-images.
//!
//! The canonical form follows the codebase's existing signed-message convention
//! (`WarmKeyDelegation::signing_message`): a **domain-tagged, newline-joined**
//! string of **hex-encoded** fields in a **fixed order**, so there is no
//! map/key-order ambiguity and no dependency on a canonical serializer.

use serde::{Deserialize, Serialize};

/// Domain-separation tag prefixing the canonical event pre-image (so an event
/// digest can never collide with an AID digest or any other hash in the system).
pub const CANONICAL_DOMAIN: &str = "kotton:kel:event:v1";

/// A self-certifying **autonomic identifier**: `"did:kel:" || multibase(digest of
/// the inception event)`. Stable across every rotation (the digest never changes).
/// The value is computed in tier-03 at inception; this is the wire wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Aid(pub String);

impl std::fmt::Display for Aid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The authoritative operational key-state a KEL event installs: a FROST group key
/// (RFC-0034 resolved FROST-aggregate-under-the-AID) with its threshold `M` of `N`.
/// A degenerate 1-of-1 (`threshold == participants == 1`) is a single-device state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyState {
    /// The Ed25519 group verifying key (a FROST aggregate verifies as plain Ed25519).
    pub group_key: [u8; 32],
    /// M — signatures required.
    pub threshold: u16,
    /// N — total signers.
    pub participants: u16,
}

/// The kind of a KEL event. Establishment events (`Inception`, the three
/// `Rotation*` kinds) change the key-state; `Interaction` anchors data without
/// rotating; `Contest` vetoes a pending recovery (RFC-0038 §"Contestable recovery").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventKind {
    /// seq 0 — establishes the AID, first key-state, first recovery commitment.
    Inception,
    /// Quorum-authorized rotation (add/remove device); carries the recovery
    /// commitment forward unchanged.
    RotationCooperative,
    /// Tier-1 guardian-authorized recovery rotation (evicts a full-device compromise).
    RotationGuardian,
    /// Tier-2 mnemonic-authorized recovery rotation (disaster / override).
    RotationMnemonic,
    /// Quorum-authorized **addition** of recovery authorities. Grows the committed
    /// set; may never shrink or replace it.
    ///
    /// This is how "add a device, add a guardian, add a storage node" works after
    /// first run, which is the whole point of an identity that starts with none.
    /// Growth-only is what keeps it safe to authorize with the key already on the
    /// device: whoever holds it can add a way in but cannot take yours away, so a
    /// stolen device still cannot lock its owner out — they recover with the
    /// authority that is still there, then rotate the intruder's out.
    RotationAddRecovery,
    /// A veto of a pending recovery event.
    Contest,
    /// Acts under the current key-state without changing it (anchors a data epoch).
    Interaction,
}

impl EventKind {
    /// Stable canonical tag (never change these strings — they are hashed).
    pub fn tag(self) -> &'static str {
        match self {
            EventKind::Inception => "inception",
            EventKind::RotationCooperative => "rot-coop",
            EventKind::RotationGuardian => "rot-guardian",
            EventKind::RotationMnemonic => "rot-mnemonic",
            EventKind::RotationAddRecovery => "rot-add-recovery",
            EventKind::Contest => "contest",
            EventKind::Interaction => "interaction",
        }
    }
}

/// Who authorized a KEL event, and the proof. The signature is **excluded from the
/// canonical pre-image it signs**; the revealed keys are checked against the prior
/// event's `recovery_commitment` in tier-03 validation (pre-rotation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Authorization {
    /// Signed by the prior event's `key_state.group_key` (FROST aggregate ≡ Ed25519).
    Quorum { sig: Vec<u8> },
    /// Reveals the guardian group key (must be a member of the prior
    /// `recovery_commitment` set) and signs with it.
    Guardian {
        revealed_group_key: [u8; 32],
        /// Sibling path proving the revealed key is in the committed set. Empty
        /// for a one-member set, where the root *is* the leaf.
        #[serde(default)]
        proof: Vec<[u8; 32]>,
        sig: Vec<u8>,
    },
    /// Reveals the mnemonic-derived recovery key (must be a member of the prior
    /// `recovery_commitment` set) and signs with it.
    Mnemonic {
        revealed_rec_pubkey: [u8; 32],
        /// Sibling path proving the revealed key is in the committed set. Empty
        /// for a one-member set, where the root *is* the leaf.
        #[serde(default)]
        proof: Vec<[u8; 32]>,
        sig: Vec<u8>,
    },
    /// A veto of the event whose digest is `contested_digest`, authorized by `by`.
    Contest {
        contested_digest: [u8; 32],
        by: Box<Authorization>,
        sig: Vec<u8>,
    },
}

impl Authorization {
    /// Stable canonical tag for the authorization kind.
    pub fn tag(&self) -> &'static str {
        match self {
            Authorization::Quorum { .. } => "quorum",
            Authorization::Guardian { .. } => "guardian",
            Authorization::Mnemonic { .. } => "mnemonic",
            Authorization::Contest { .. } => "contest",
        }
    }
}

/// The contest/dispute window for a recovery event (RFC-0038).
///
/// Named `Window` until 2026-08-24, which is how the field below came to be
/// `contest_window: Option<Window>` — the field name was carrying the meaning
/// the type name had dropped. When a field has to re-state what its type is,
/// the type is under-named. It also collided with the shell's UI `Window`,
/// which is a different thing entirely.
///
/// Finalization — how the window is witnessed and closed — is the deferred
/// `RecoveryArbiter` substrate
/// (`IDEA-recovery-arbiter`); this only carries the parameters that
/// must be committed (signed) so they cannot be tampered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContestWindow {
    /// Minimum wall-clock seconds the announcement must stand before it can finalize.
    pub min_seconds: u64,
}

/// A single key event. The log is per-identity, append-only, and hash-chained via
/// `prev_event_digest`; each establishment event pre-commits `recovery_commitment`
/// = the digest of the next recovery authority (pre-rotation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KelEvent {
    /// The identity this event belongs to.
    pub aid: Aid,
    /// Monotonic sequence number; 0 at inception.
    pub seq: u64,
    /// SHA-256 digest of the canonical form of the previous event; `None` at seq 0.
    pub prev_event_digest: Option<[u8; 32]>,
    pub kind: EventKind,
    /// The operational key-state this event installs.
    pub key_state: KeyState,
    /// Merkle root over the set of recovery authorities. Carried forward unchanged
    /// by a cooperative rotation; set fresh by a recovery rotation; grown by a
    /// `RotationAddRecovery`.
    pub recovery_commitment: [u8; 32],
    /// The recovery authorities `recovery_commitment` commits to, present only on a
    /// `RotationAddRecovery`.
    ///
    /// Carried in the clear because a verifier cannot check "this set grew" from two
    /// roots — a Merkle root proves membership, never containment. These are public
    /// keys of authorities the user chose, so the leak is the *shape* of someone's
    /// recovery (how many, and which are guardian groups), not anything that opens
    /// it.
    ///
    /// It is also what a recovering device needs to build its own inclusion proof:
    /// a phrase knows its own member and not the others
    /// (`TASK-a-recovering-device-cannot-build-its-own-inclusion-proof`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recovery_set: Vec<[u8; 32]>,
    pub authorization: Authorization,
    /// Present on recovery events (`RotationGuardian`/`RotationMnemonic`); `None`
    /// on cooperative rotations, interactions, and inception.
    pub contest_window: Option<ContestWindow>,
}

impl KelEvent {
    /// The canonical, deterministic pre-image the event digest and the
    /// authorization signature are taken over.
    ///
    /// Domain-tagged, newline-joined, hex-encoded fields in a fixed order. Excludes
    /// the `authorization` (a signature cannot cover itself) — the revealed keys in
    /// the authorization are bound instead by the pre-rotation commitment check in
    /// validation. Every committed field is included so a tampered `seq`,
    /// `key_state`, `recovery_commitment`, or window is a signature/digest failure.
    pub fn canonical(&self) -> String {
        let prev = self
            .prev_event_digest
            .map(hex::encode)
            .unwrap_or_default();
        let window = self
            .contest_window
            .as_ref()
            .map(|w| w.min_seconds.to_string())
            .unwrap_or_default();
        [
            CANONICAL_DOMAIN,
            &self.aid.0,
            &self.seq.to_string(),
            &prev,
            self.kind.tag(),
            &hex::encode(self.key_state.group_key),
            &self.key_state.threshold.to_string(),
            &self.key_state.participants.to_string(),
            &hex::encode(self.recovery_commitment),
            &window,
        ]
        .join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> KelEvent {
        KelEvent {
            aid: Aid("did:kel:zTEST".into()),
            seq: 3,
            prev_event_digest: Some([7u8; 32]),
            kind: EventKind::RotationCooperative,
            key_state: KeyState {
                group_key: [9u8; 32],
                threshold: 2,
                participants: 3,
            },
            recovery_commitment: [1u8; 32],
            recovery_set: Vec::new(),
            authorization: Authorization::Quorum { sig: vec![0u8; 64] },
            contest_window: None,
        }
    }

    #[test]
    fn canonical_is_deterministic() {
        let e = event();
        assert_eq!(e.canonical(), e.canonical(), "canonical form must be stable");
    }

    #[test]
    fn canonical_excludes_the_authorization_signature() {
        // Two events identical except for the authorization signature must share a
        // canonical pre-image (a signature cannot cover itself).
        let a = event();
        let mut b = event();
        b.authorization = Authorization::Quorum { sig: vec![255u8; 64] };
        assert_eq!(a.canonical(), b.canonical());
    }

    #[test]
    fn canonical_changes_when_a_committed_field_changes() {
        let base = event();
        let canon = base.canonical();

        let mut seq = event();
        seq.seq = 4;
        assert_ne!(canon, seq.canonical(), "seq must be committed");

        let mut key = event();
        key.key_state.group_key = [10u8; 32];
        assert_ne!(canon, key.canonical(), "group_key must be committed");

        let mut thr = event();
        thr.key_state.threshold = 3;
        assert_ne!(canon, thr.canonical(), "threshold must be committed");

        let mut rec = event();
        rec.recovery_commitment = [2u8; 32];
        assert_ne!(canon, rec.canonical(), "recovery_commitment must be committed");

        let mut kind = event();
        kind.kind = EventKind::Interaction;
        assert_ne!(canon, kind.canonical(), "kind must be committed");

        let mut win = event();
        win.contest_window = Some(ContestWindow { min_seconds: 3600 });
        assert_ne!(canon, win.canonical(), "contest window must be committed");
    }

    #[test]
    fn inception_has_no_prev_digest_in_canonical() {
        let mut e = event();
        e.kind = EventKind::Inception;
        e.seq = 0;
        e.prev_event_digest = None;
        // The prev-digest slot is empty (not the string "None"); still deterministic.
        assert_eq!(e.canonical(), e.canonical());
        assert!(!e.canonical().contains("None"));
    }

    #[test]
    fn serde_round_trips() {
        let e = event();
        let json = serde_json::to_string(&e).unwrap();
        let back: KelEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }
}
