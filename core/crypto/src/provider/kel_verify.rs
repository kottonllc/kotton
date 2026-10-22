// SPDX-License-Identifier: AGPL-3.0-or-later
//! KEL verification — RFC-0038 (tier-03 crypto for the tier-02 [`kotton_wire::kel`] schema).
//!
//! Replays a key event log: the SHA-256 event digest, the self-addressing AID,
//! and `validate(prev, event)` — the chain + signature + **pre-rotation** checks.
//! Pre-rotation is the security core: each event pre-commits `recovery_commitment
//! = hash(pub(next recovery authority))`, so an attacker holding the *current*
//! quorum cannot roll the identity forward — a recovery must **reveal** a key that
//! hashes to the prior commitment, which only the guardians / the mnemonic hold.
//!
//! Signatures are Ed25519 over the event's [`KelEvent::canonical`] bytes; the chain
//! digest and the AID are SHA-256 over the same canonical form. The timed
//! finalization of a recovery's contest window is the deferred `RecoveryArbiter`
//! substrate (`IDEA-recovery-arbiter`); `validate` reports a recovery
//! as *validly authorized* ([`Verdict::PendingRecovery`]) and hands finalization to
//! the arbiter.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use kotton_wire::did::Did;
use kotton_wire::kel::{Aid, Authorization, EventKind, KelEvent, KeyState, ContestWindow};
use sha2::{Digest, Sha256};

/// Resolves a `did:kel` AID to its current authoritative key by replaying its KEL
/// (RFC-0038 Phase 3). The verification surfaces (grant checks, mTLS, peer auth)
/// dispatch a `did:kel` issuer through this instead of decoding a `did:key`. For
/// **own** identity the KEL is local (see `kotton_identity::kel_store`); other
/// issuers' KELs arrive via the identity-core packet (RFC-0034). Returns `None`
/// when the AID's KEL is unavailable — callers must then **fail closed**.
pub trait KelResolver: Send + Sync {
    fn current_key(&self, aid: &Did) -> Option<[u8; 32]>;
}

/// The result of validating a candidate event against its predecessor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Fully valid and final (inception, cooperative rotation, interaction).
    Valid,
    /// A recovery event whose authorization is valid (the revealed key matches the
    /// prior pre-rotation commitment and signs) — but finalization awaits the
    /// contest window via the [`RecoveryArbiter`].
    PendingRecovery,
    /// Rejected, with a reason.
    Invalid(String),
}

fn invalid(msg: impl Into<String>) -> Verdict {
    Verdict::Invalid(msg.into())
}

/// SHA-256 of the event's canonical pre-image (the chain digest).
pub fn digest(event: &KelEvent) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(event.canonical().as_bytes());
    h.finalize().into()
}

/// The pre-rotation commitment to a recovery authority's public key.
pub fn recovery_commitment_for(pubkey: &[u8; 32]) -> [u8; 32] {
    recovery_root(std::slice::from_ref(pubkey))
}

// ── The recovery commitment is a set, not a key ────────────────────────────────
//
// `recovery_commitment` was `hash(pub(next recovery authority))` — one hash, so an
// identity committed to exactly **one** way back in. `Authorization` has had both
// `Mnemonic` and `Guardian` variants since it was written and they could never
// both be live, which put a data-format limit across the product goal of several
// independent recovery options.
//
// It is now a Merkle root over a *set* of recovery public keys. The field is still
// 32 bytes and a one-member set is the old behaviour, so nothing about the wire
// shape grew; what changed is that a recovery event now also carries an inclusion
// proof for the key it reveals.
//
// Two details worth explaining, one of which is less load-bearing than it looks:
//
// **Domain separation.** A leaf is `H(0x00 || pubkey)` and an internal node is
// `H(0x01 || …)`. In the general Merkle case this is what stops an attacker
// presenting an internal node as a leaf and "revealing" a key that was never in
// the set.
//
// **Here it does nothing yet, and that is measured rather than assumed.** A leaf
// preimage is a fixed 32-byte public key and a node preimage is 64 bytes, so the
// two hash inputs can never coincide whether or not they are tagged. Both
// attempts to write a test that goes red when the tags are removed failed — the
// tags were deleted and the whole suite stayed green, twice.
//
// They are kept anyway, because the property they hold is the one that breaks
// first if leaves ever stop being fixed-width — a set that admitted, say, a
// guardian *group descriptor* rather than a bare key would lose the length
// argument silently. Two bytes of hashing to make that a non-event is worth
// paying. What is not worth doing is claiming they are carrying weight now: a
// guard described as load-bearing when it is not is how the next person decides
// the real guard is redundant.
//
// **Sorted pairs.** Children are hashed as `H(0x01 || min || max)`, so a proof is
// a bare list of siblings with no direction bits to get wrong. Set membership is
// all this needs to prove; position in the tree is not meaningful here, and not
// encoding it removes a way to encode it incorrectly.

const LEAF_TAG: u8 = 0x00;
const NODE_TAG: u8 = 0x01;

fn leaf_hash(pubkey: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([LEAF_TAG]);
    h.update(pubkey);
    h.finalize().into()
}

fn node_hash(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut h = Sha256::new();
    h.update([NODE_TAG]);
    h.update(lo);
    h.update(hi);
    h.finalize().into()
}

/// The root committed by an identity with **no** recovery authority configured.
///
/// A distinct constant rather than zeroes or random bytes, so "no way back in" is
/// representable *and* distinguishable — the shell can tell a person their account
/// has no recovery yet, which committing random entropy would have made impossible
/// to detect. Nothing hashes to it, so it can never be opened by a proof.
pub fn empty_recovery_root() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"kotton:kel:recovery-set:empty:v1");
    h.finalize().into()
}

/// The Merkle root over a set of recovery public keys.
///
/// Leaves are sorted and de-duplicated first, so the root is a function of the set
/// rather than of the order it was written in — two clients building the same set
/// must reach the same commitment.
pub fn recovery_root(pubkeys: &[[u8; 32]]) -> [u8; 32] {
    let mut leaves: Vec<[u8; 32]> = pubkeys.iter().map(leaf_hash).collect();
    leaves.sort_unstable();
    leaves.dedup();
    if leaves.is_empty() {
        return empty_recovery_root();
    }
    let mut level = leaves;
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            next.push(match pair {
                [a, b] => node_hash(a, b),
                // An odd node is carried up rather than doubled. Hashing it with
                // itself would make a two-member set with a duplicate collide with
                // a one-member set, which is the classic Merkle malleability bug.
                [a] => *a,
                _ => unreachable!("chunks(2) yields 1 or 2"),
            });
        }
        level = next;
    }
    level[0]
}

/// The sibling path proving `pubkey` is in the set, or `None` if it is not.
pub fn recovery_proof(pubkeys: &[[u8; 32]], pubkey: &[u8; 32]) -> Option<Vec<[u8; 32]>> {
    let mut leaves: Vec<[u8; 32]> = pubkeys.iter().map(leaf_hash).collect();
    leaves.sort_unstable();
    leaves.dedup();
    let mut idx = leaves.binary_search(&leaf_hash(pubkey)).ok()?;
    let mut level = leaves;
    let mut path = Vec::new();
    while level.len() > 1 {
        let sibling = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        if sibling < level.len() {
            path.push(level[sibling]);
        }
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            next.push(match pair {
                [a, b] => node_hash(a, b),
                [a] => *a,
                _ => unreachable!("chunks(2) yields 1 or 2"),
            });
        }
        idx /= 2;
        level = next;
    }
    Some(path)
}

/// Whether `pubkey`, with `proof`, is a member of the set committed by `root`.
pub fn verify_recovery_inclusion(root: &[u8; 32], pubkey: &[u8; 32], proof: &[[u8; 32]]) -> bool {
    // An empty set admits nothing, and says so before doing any work — a zero-length
    // proof against the empty root would otherwise reduce to comparing a leaf hash
    // against a constant, which is a comparison that should never be reachable.
    if *root == empty_recovery_root() {
        return false;
    }
    let mut acc = leaf_hash(pubkey);
    for sib in proof {
        acc = node_hash(&acc, sib);
    }
    acc == *root
}

/// The Ed25519 public key of the KEL recovery key derived at `K_rec[index]`
/// (`kdf::derive_kel_recovery_key`). Its `recovery_commitment_for` is what an
/// inception/recovery event pre-commits.
pub fn kel_recovery_pubkey(kel_recovery_seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(kel_recovery_seed)
        .verifying_key()
        .to_bytes()
}

/// Derive the self-addressing AID from an inception event: `"did:kel:" ||
/// hex(SHA-256(canonical with the aid field blanked))`. (Multibase encoding is a
/// later refinement; hex is self-certifying regardless.)
pub fn derive_aid(inception: &KelEvent) -> Aid {
    let mut e = inception.clone();
    e.aid = Aid(String::new());
    Aid(format!("did:kel:{}", hex::encode(digest(&e))))
}

/// Build a self-signed **inception** event for a fresh identity (RFC-0038).
///
/// `group_sk` is the operational key-state this identity is born with (a 1-of-1 at
/// creation); `recovery_set` is the set of recovery authorities it pre-commits to.
/// Returns the inception with its self-addressing `aid` and self-signature set;
/// `validate_inception` accepts it, and its `aid` is the identity's `did:kel` AID.
///
/// **An empty `recovery_set` is legal and is the intended default for a fresh
/// identity.** It commits `empty_recovery_root()`, which nothing can open — an
/// account with no way back in, stated rather than implied. That is what lets first
/// run ask for nothing: no phrase, no card, no ceremony at the moment a person has
/// least to lose, and a detectable "you have no recovery yet" the product can act
/// on later. Authorities are added afterwards by an ordinary rotation.
pub fn build_inception(group_sk: &SigningKey, recovery_set: &[[u8; 32]]) -> KelEvent {
    let mut e = KelEvent {
        aid: Aid(String::new()),
        seq: 0,
        prev_event_digest: None,
        kind: EventKind::Inception,
        key_state: KeyState {
            group_key: group_sk.verifying_key().to_bytes(),
            threshold: 1,
            participants: 1,
        },
        recovery_commitment: recovery_root(recovery_set),
        recovery_set: recovery_set.to_vec(),
        authorization: Authorization::Quorum { sig: vec![0u8; 64] },
        contest_window: None,
    };
    e.aid = derive_aid(&e);
    let sig = group_sk.sign(e.canonical().as_bytes()).to_bytes().to_vec();
    e.authorization = Authorization::Quorum { sig };
    e
}

/// Build the deterministic **inception** for a user's root identity from their
/// mnemonic-derived `seed32` (RFC-0038 / RFC-0039). The seq-0 key-state is the
/// mnemonic-derived identity key (`kdf::derive_identity_key`); the pre-rotation
/// commitment is `pub(K_rec[0])` (`kdf::derive_kel_recovery_key(seed32, 0)`).
///
/// Because every input is a pure function of `seed32`, the inception — and thus
/// the AID (`derive_aid`) — is **reconstructible from the mnemonic alone, with no
/// network**. That is what lets a fresh device recover its `did:kel` identity and
/// what `login_with_recovery_key` matches the user record on, honoring the
/// identity-continuity invariant (the mnemonic always recovers a working identity).
pub fn build_user_inception(seed32: &[u8; 32]) -> KelEvent {
    let group_sk = SigningKey::from_bytes(&crate::kdf::derive_identity_key(seed32));
    let krec0 = kel_recovery_pubkey(&crate::kdf::derive_kel_recovery_key(seed32, 0));
    build_inception(&group_sk, &[krec0])
}

/// Mint a fresh identity: a random operational key and **no recovery authority**.
///
/// This is what a first run should call. The key is random rather than derived
/// from a mnemonic, which is RFC-0039 invariant 4 as written — *"all three
/// operational roots are random and independent of the mnemonic"* — and closes the
/// deviation recorded against it on 2026-08-16. The rotation path
/// (`rotate_identity_via_mnemonic`) has always installed a random key with that
/// invariant quoted at the call site; inception was the only place still deriving
/// one, so this brings one function into line with what the rest of the system
/// already assumes.
///
/// It matters beyond tidiness. While the identity key derives from a phrase, the
/// phrase **is** the identity — a new phrase is a new AID, so it can never be
/// rotated, and a person who loses it but still has their device can neither be
/// shown it again (the seed is never stored) nor issued another. Their machine
/// works until it dies. With a random key the phrase becomes one authority among
/// several, and losing it is survivable.
///
/// Returns the inception and the signing key it installs; the caller stores the
/// key and the event, and the event's `aid` is the identity's DID.
pub fn build_fresh_inception(group_sk: &SigningKey) -> KelEvent {
    build_inception(group_sk, &[])
}

/// Build a **recovery-set growth** event: install `new_set`, signed by the current
/// operational key.
///
/// `new_set` must contain every member of `prev`'s set — validation rejects anything
/// else, which is what makes this safe to authorize with a key that might be on a
/// stolen device. The set travels on the event because containment cannot be proved
/// from two Merkle roots.
pub fn build_add_recovery(prev: &KelEvent, new_set: &[[u8; 32]], group_sk: &SigningKey) -> KelEvent {
    let mut e = KelEvent {
        aid: prev.aid.clone(),
        seq: prev.seq + 1,
        prev_event_digest: Some(digest(prev)),
        kind: EventKind::RotationAddRecovery,
        key_state: prev.key_state.clone(),
        recovery_commitment: recovery_root(new_set),
        recovery_set: new_set.to_vec(),
        authorization: Authorization::Quorum { sig: vec![0u8; 64] },
        contest_window: None,
    };
    let sig = group_sk.sign(e.canonical().as_bytes()).to_bytes().to_vec();
    e.authorization = Authorization::Quorum { sig };
    e
}

/// Build a **mnemonic recovery rotation** (RFC-0038): the headline pre-rotation
/// move. Reveal `K_rec[recovery_index]` (which must hash to `prev`'s
/// `recovery_commitment`), install a fresh operational key-state (`new_group_sk`),
/// pre-commit the next reserve `pub(K_rec[recovery_index + 1])`, sign with the
/// revealed key, and chain off `prev`.
///
/// An attacker holding the *current* quorum cannot forge this — the reveal must
/// match a commitment only the mnemonic can open. For a lone factor (single device)
/// `resolve_current_key` finalizes it immediately via `LocalArbiter`; a multi-factor
/// identity holds it pending the (deferred) witnessed contest window.
///
/// `recovery_index` is how many recovery rotations have already occurred (0 for the
/// first — the inception committed `pub(K_rec[0])`). `contest_min_seconds` is the
/// minimum window carried on the event (committed, so it cannot be tampered).
/// `prior_set` is the set of recovery public keys `prev.recovery_commitment`
/// commits to, and it is required because a Merkle proof cannot be built from a
/// root alone. For the ordinary one-member case pass `&[revealed]` — the proof is
/// then empty and the root *is* the leaf.
///
/// **Where a recovering party gets the set is an open question**, and this
/// signature is where it surfaces rather than hides. A device holding only the
/// phrase knows *its own* member and not the others, so it cannot compute the
/// sibling path unaided. The leaf hashes reveal nothing but the set's size, so
/// publishing them alongside the chain is one answer; requiring the recovering
/// party to present every leaf hash (making the "proof" the whole set) is another,
/// and for the two-to-five members a real recovery set will have, the size
/// difference is a few dozen bytes. Filed as
/// `TASK-a-recovering-device-cannot-build-its-own-inclusion-proof`.
///
/// If `prior_set` does not contain the revealed key the proof comes back empty and
/// validation rejects the event — a caller error that fails closed and loudly
/// rather than producing an event that looks valid.
pub fn build_mnemonic_rotation(
    prev: &KelEvent,
    seed32: &[u8; 32],
    recovery_index: u64,
    new_group_sk: &SigningKey,
    contest_min_seconds: u64,
    prior_set: &[[u8; 32]],
) -> KelEvent {
    let revealed = SigningKey::from_bytes(&crate::kdf::derive_kel_recovery_key(seed32, recovery_index));
    let next_reserve =
        kel_recovery_pubkey(&crate::kdf::derive_kel_recovery_key(seed32, recovery_index + 1));
    let mut e = KelEvent {
        aid: prev.aid.clone(),
        seq: prev.seq + 1,
        prev_event_digest: Some(digest(prev)),
        kind: EventKind::RotationMnemonic,
        key_state: KeyState {
            group_key: new_group_sk.verifying_key().to_bytes(),
            threshold: 1,
            participants: 1,
        },
        recovery_commitment: recovery_commitment_for(&next_reserve),
        recovery_set: vec![next_reserve],
        authorization: Authorization::Mnemonic {
            revealed_rec_pubkey: revealed.verifying_key().to_bytes(),
            proof: recovery_proof(prior_set, &revealed.verifying_key().to_bytes())
                .unwrap_or_default(),
            sig: vec![0u8; 64],
        },
        contest_window: Some(ContestWindow {
            min_seconds: contest_min_seconds,
        }),
    };
    let sig = revealed.sign(e.canonical().as_bytes()).to_bytes().to_vec();
    e.authorization = Authorization::Mnemonic {
        revealed_rec_pubkey: revealed.verifying_key().to_bytes(),
        proof: recovery_proof(prior_set, &revealed.verifying_key().to_bytes())
            .unwrap_or_default(),
        sig,
    };
    e
}

fn verify_sig(pubkey: &[u8; 32], event: &KelEvent, sig: &[u8]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(sig) else {
        return false;
    };
    // verify_strict: reject malleable signatures on identity KEL events.
    vk.verify_strict(event.canonical().as_bytes(), &sig).is_ok()
}

/// Validate an inception event (seq 0): no prev digest, self-signed by its own
/// key-state, and its `aid` matches the self-addressing derivation.
pub fn validate_inception(event: &KelEvent) -> Verdict {
    if event.seq != 0 {
        return invalid("inception must have seq 0");
    }
    if event.prev_event_digest.is_some() {
        return invalid("inception must have no prev_event_digest");
    }
    if !matches!(event.kind, EventKind::Inception) {
        return invalid("seq 0 event must be an Inception");
    }
    if event.aid != derive_aid(event) {
        return invalid("aid is not the self-addressing digest of the inception");
    }
    // Inception is self-signed by the key-state it establishes.
    match &event.authorization {
        Authorization::Quorum { sig } if verify_sig(&event.key_state.group_key, event, sig) => {
            Verdict::Valid
        }
        Authorization::Quorum { .. } => invalid("inception self-signature is invalid"),
        _ => invalid("inception must be Quorum-authorized (self-signed)"),
    }
}

/// Validate a candidate event `event` against its predecessor `prev`.
pub fn validate(prev: &KelEvent, event: &KelEvent) -> Verdict {
    if event.aid != prev.aid {
        return invalid("aid mismatch");
    }
    if event.seq != prev.seq + 1 {
        return invalid("seq must increment by 1");
    }
    if event.prev_event_digest != Some(digest(prev)) {
        return invalid("prev_event_digest does not chain to the predecessor");
    }

    match (event.kind, &event.authorization) {
        // Cooperative rotation: quorum-signed; recovery lineage carried forward.
        (EventKind::RotationCooperative, Authorization::Quorum { sig }) => {
            if !verify_sig(&prev.key_state.group_key, event, sig) {
                return invalid("cooperative rotation: bad quorum signature");
            }
            if event.recovery_commitment != prev.recovery_commitment {
                return invalid(
                    "cooperative rotation may not change recovery_commitment \
                     (only a recovery event advances the recovery lineage)",
                );
            }
            if event.contest_window.is_some() {
                return invalid("cooperative rotation carries no contest window");
            }
            Verdict::Valid
        }

        // Adding recovery authorities: quorum-signed, and may only **grow** the set.
        //
        // This is how an identity that started with none gains one, and how a second
        // is added later — both after first run, which is where they belong. It is
        // safe to authorize with the key already on the device precisely because it
        // cannot subtract: whoever holds that key can add a way in, never remove
        // yours, so a stolen device still cannot lock its owner out. They recover
        // with the authority that is still committed, then rotate the intruder's out.
        //
        // The new set travels in the clear because containment is not a property a
        // Merkle root can prove — a root proves membership. Checking growth needs
        // both sets, so the event carries the one it is installing and the verifier
        // recomputes the root from it.
        (EventKind::RotationAddRecovery, Authorization::Quorum { sig }) => {
            if !verify_sig(&prev.key_state.group_key, event, sig) {
                return invalid("add-recovery: bad quorum signature");
            }
            if event.key_state != prev.key_state {
                return invalid("add-recovery must not change key_state");
            }
            if event.contest_window.is_some() {
                return invalid("add-recovery carries no contest window");
            }
            if event.recovery_set.is_empty() {
                return invalid("add-recovery must carry the set it installs");
            }
            if recovery_root(&event.recovery_set) != event.recovery_commitment {
                return invalid("add-recovery: commitment does not match the carried set");
            }
            // Growth, checked directly against the predecessor's own set.
            //
            // The first attempt tried to recover the prior set by searching subsets
            // of the new one for a matching root. That was wrong twice: `windows`
            // yields contiguous slices, and a prior set of {A, C} inside {A, B, C}
            // is not contiguous — and searching all subsets is exponential for a
            // check that should be a comparison. Every event that *sets* a
            // commitment now carries the set it committed, so the predecessor's set
            // is simply available.
            if prev.recovery_commitment != empty_recovery_root() {
                if prev.recovery_set.is_empty() {
                    return invalid(
                        "add-recovery: predecessor commits a non-empty set but did not \
                         carry it, so growth cannot be checked",
                    );
                }
                let new_members: std::collections::BTreeSet<_> = event.recovery_set.iter().collect();
                if !prev.recovery_set.iter().all(|m| new_members.contains(m)) {
                    return invalid(
                        "add-recovery may only grow the set — every prior authority must \
                         still be present",
                    );
                }
            }
            Verdict::Valid
        }

        // Interaction: quorum-signed; changes nothing.
        (EventKind::Interaction, Authorization::Quorum { sig }) => {
            if !verify_sig(&prev.key_state.group_key, event, sig) {
                return invalid("interaction: bad quorum signature");
            }
            if event.key_state != prev.key_state
                || event.recovery_commitment != prev.recovery_commitment
            {
                return invalid("interaction must not change key_state or recovery_commitment");
            }
            Verdict::Valid
        }

        // Guardian recovery: reveal the pre-committed guardian key; sign with it.
        (EventKind::RotationGuardian, Authorization::Guardian { revealed_group_key, proof, sig }) => {
            validate_recovery(event, prev, revealed_group_key, proof, sig)
        }

        // Mnemonic recovery: reveal the pre-committed mnemonic reserve key; sign.
        (EventKind::RotationMnemonic, Authorization::Mnemonic { revealed_rec_pubkey, proof, sig }) => {
            validate_recovery(event, prev, revealed_rec_pubkey, proof, sig)
        }

        (EventKind::Inception, _) => invalid("inception cannot follow a predecessor"),
        (EventKind::Contest, _) => {
            invalid("contest events are resolved by the RecoveryArbiter, not the chain")
        }
        _ => invalid("event kind and authorization do not match"),
    }
}

/// Shared recovery-event check: the revealed key must hash to the prior
/// `recovery_commitment` (pre-rotation), sign this event, and carry a contest
/// window. Returns `PendingRecovery` (finalization is the arbiter's job).
fn validate_recovery(
    event: &KelEvent,
    prev: &KelEvent,
    revealed_pubkey: &[u8; 32],
    proof: &[[u8; 32]],
    sig: &[u8],
) -> Verdict {
    if !verify_recovery_inclusion(&prev.recovery_commitment, revealed_pubkey, proof) {
        return invalid("revealed recovery key is not a member of the prior commitment set");
    }
    if !verify_sig(revealed_pubkey, event, sig) {
        return invalid("recovery signature is invalid for the revealed key");
    }
    if event.contest_window.is_none() {
        return invalid("a recovery event must carry a contest window");
    }
    Verdict::PendingRecovery
}

// ── The RecoveryArbiter seam (RECOVERY-ARBITER.md) ──────────────────────────────
//
// The KEL core routes every recovery through this boundary so finalization is
// never assumed synchronous; the eclipse-resistant `WitnessedArbiter` is a later
// impl swap. `LocalArbiter` is correct-today with an honest posture: a lone factor
// finalizes immediately; a multi-factor recovery enters a window (real timed
// finalization + contest handling is deferred — this is the seam, not the substrate).

/// Finalization state of a pending recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finalization {
    /// Awaiting the contest window / witness quorum.
    Pending,
    /// Finalized — authoritative.
    Finalized,
}

/// The seam every recovery resolves through. See `RECOVERY-ARBITER.md`.
pub trait RecoveryArbiter {
    /// Whether a validly-authorized recovery has finalized. `has_other_factors`
    /// reflects whether the identity has any independent contesting factor
    /// (guardians / another live device); a lone factor has nothing to contest.
    fn finalization(&self, event: &KelEvent, has_other_factors: bool) -> Finalization;
}

/// Correct-today degenerate arbiter. Honest posture: a lone factor finalizes
/// immediately (nothing can contest — the machine-count floor); a multi-factor
/// recovery is `Pending` until the (deferred) witnessed substrate closes it.
pub struct LocalArbiter;

impl RecoveryArbiter for LocalArbiter {
    fn finalization(&self, _event: &KelEvent, has_other_factors: bool) -> Finalization {
        if has_other_factors {
            Finalization::Pending
        } else {
            Finalization::Finalized
        }
    }
}

/// Replay a full KEL from inception and return the **current authoritative group
/// key** — what "speaks for" the AID right now. This is the primitive the
/// verification surfaces (grant checks, mTLS, peer/IPC auth) call instead of the
/// one-line `did:key` decode (RFC-0038 Phase 3).
///
/// Validates the inception and every transition. A recovery event advances the
/// state only once the `arbiter` finalizes it; an unfinalized recovery (and
/// anything chained off it) is not yet authoritative, so resolution stops at the
/// last finalized event and returns the pre-recovery key. `has_other_factors` is
/// passed to the arbiter (a lone factor finalizes immediately; a multi-factor
/// recovery waits for the contest window).
pub fn resolve_current_key<A: RecoveryArbiter>(
    events: &[KelEvent],
    arbiter: &A,
    has_other_factors: bool,
) -> Result<[u8; 32], String> {
    let first = events.first().ok_or_else(|| "empty KEL".to_string())?;
    match validate_inception(first) {
        Verdict::Valid => {}
        v => return Err(format!("invalid inception: {v:?}")),
    }
    let mut current = first;
    for e in &events[1..] {
        match validate(current, e) {
            Verdict::Valid => current = e,
            Verdict::PendingRecovery => match arbiter.finalization(e, has_other_factors) {
                Finalization::Finalized => current = e,
                // An unfinalized recovery is not yet authoritative — the current
                // key remains the pre-recovery state; stop replaying past it.
                Finalization::Pending => break,
            },
            Verdict::Invalid(why) => {
                return Err(format!("invalid event at seq {}: {why}", e.seq))
            }
        }
    }
    Ok(current.key_state.group_key)
}

/// How many mnemonic recoveries a chain has already performed — the `recovery_index` the
/// *next* one must use.
///
/// The reserve keys are a ladder: the inception commits to `pub(K_rec[0])`, and each recovery
/// reveals `K_rec[n]` while pre-committing `pub(K_rec[n+1])`. So the index is not a choice, it
/// is a count, and getting it wrong produces a rotation whose revealed key does not hash to
/// the stored commitment — rejected by [`validate`], but only after the event is built.
///
/// Counting rather than storing it keeps the chain the single source of truth: a counter kept
/// beside the chain is one more thing that can disagree with it.
pub fn next_recovery_index(chain: &[KelEvent]) -> u64 {
    // **Both** recovery kinds consume a rung, and this counted only one of them until
    // 2026-08-24. `validate_recovery` serves `RotationGuardian` and `RotationMnemonic` alike
    // and checks each against the *same* `prev.recovery_commitment` — there is one reserve
    // ladder, not one per kind. Counting only mnemonic recoveries returns an index one too low
    // for any identity that has ever used a guardian, which builds an event whose revealed key
    // does not match the stored commitment and stops the chain replaying from then on.
    //
    // The bug survived its own test because that test performed two *mnemonic* recoveries, so
    // both counts agreed. `a_guardian_recovery_also_consumes_a_rung` is the one that fails.
    chain
        .iter()
        .filter(|e| matches!(e.kind, EventKind::RotationMnemonic | EventKind::RotationGuardian))
        .count() as u64
}

/// Whether `chain`'s tip commits `reserve_pubkey` as a recovery authority.
///
/// **The one check two sides run, which is the point.** A device recovering from a
/// phrase asks it of a chain it was handed, to decide whether the phrase has
/// authority over that identity. A node serving a chain asks the *same* question of
/// the chains it hosts, to decide whether the asker may have one
/// (`TASK-recovery-on-a-device-with-no-chain-has-nothing-to-verify-against`).
///
/// That symmetry is what lets the node answer a stranger safely. It is not trusted
/// to decide who may ask, because the query — an unrevealed rung of the asker's
/// ladder — is itself the proof; and it cannot lie in its answer, because the asker
/// re-runs this against what comes back.
///
/// Lifted out of `login_with_recovery_key`, where it was inline and had one caller.
/// Two implementations of a membership test that gate the same authority is the
/// shape that produced the `next_recovery_index` bug (see above): they agreed until
/// they did not.
///
/// Says nothing about *which* rung: the caller derives candidate keys and this
/// answers for the one it is given. A recovering device does not know how many
/// recoveries an identity has had — that count lives in the chain it is trying to
/// obtain — so it offers a window and this is asked once per candidate.
pub fn tip_commits_recovery_key(chain: &[KelEvent], reserve_pubkey: &[u8; 32]) -> bool {
    let Some(tip) = chain.last() else {
        return false;
    };
    // `recovery_set` is carried in the clear only on the events that *set* it —
    // inception, `RotationAddRecovery`, and the recovery rotations, which install a
    // fresh one-member set. `RotationCooperative` is the exception: it carries the
    // commitment forward unchanged and puts no set in the clear. So an absent set is
    // not an empty one, and the last event carrying one is always the set that
    // matches the tip's commitment — every kind that changes the commitment also
    // publishes what it changed it to.
    //
    // Reading only `tip.recovery_set`, as this did while it was inline in
    // `login_with_recovery_key`, meant an identity that set up recovery and then
    // rotated its key normally could not be recovered by its own phrase — the
    // commitment still named it and nothing could see that.
    // `a_cooperative_rotation_does_not_hide_the_recovery_set` fails against that
    // version; measured, not assumed.
    //
    // `verify_recovery_inclusion` refuses the empty root on its own, so a chain that
    // never committed any authority still answers `false` rather than matching.
    let Some(set) = chain
        .iter()
        .rev()
        .map(|e| &e.recovery_set)
        .find(|s| !s.is_empty())
    else {
        return false;
    };
    recovery_proof(set, reserve_pubkey).is_some_and(|proof| {
        verify_recovery_inclusion(&tip.recovery_commitment, reserve_pubkey, &proof)
    })
}

/// The first of `candidates` this chain commits, if any.
///
/// The window a recovering device offers, resolved against one chain. Returns the
/// key rather than a bool so a caller can tell *which* rung matched without
/// re-deriving, and `None` rather than an error because "not this identity" is the
/// ordinary answer when a node hosts several.
pub fn tip_commits_any_recovery_key(
    chain: &[KelEvent],
    candidates: &[[u8; 32]],
) -> Option<[u8; 32]> {
    candidates
        .iter()
        .copied()
        .find(|k| tip_commits_recovery_key(chain, k))
}

/// Whether what a device presents proves that `device_key` speaks for the AID a verifier is
/// already current on.
///
/// **The verifier holds a tip, not a log.** [`validate`] reads only the immediately preceding
/// event — `prev.aid`, `prev.seq`, `digest(prev)`, `prev.key_state.group_key`,
/// `prev.recovery_commitment` — so verification is a state machine, and a chain is merely one
/// way to *reconstruct* the state rather than the state itself. A verifier kept current needs
/// the events it has not seen and nothing before them, which for a recovery is one event of
/// about a kilobyte.
///
/// That is why this takes `since_tip` rather than a whole KEL. Identity is the thing every
/// other guarantee rests on, and making every verifier carry, store and replay an append-only
/// log to answer *may this device connect?* taxes the core primitive for history that only its
/// owner needs. The log keeps its place — audit, and bootstrapping a verifier that holds
/// nothing — but it does not belong at the admission surface.
///
/// The chain-for-a-different-AID attack is refused **structurally** here rather than by an
/// added guard, and by two independent checks inside [`validate`] — `event.aid == prev.aid`
/// and `prev_event_digest == digest(prev)`. Either alone refuses a stranger's well-formed
/// KEL; disabling one and re-running the test still refuses it, which is what confirmed
/// they are independent rather than one carrying the other. The reported message is
/// `aid mismatch` only because that check runs first; the digest is what would still hold if
/// an attacker contrived a matching AID.
///
/// An earlier form of this function took a stored *inception* plus a whole chain and needed
/// an explicit digest comparison of its own to catch the same attack. That guard was a
/// symptom of replaying from the wrong end, and replaying from the tip removes the need for
/// it.
///
/// `since_tip` empty means "I claim to be current": admitted only if the tip already names
/// this device, which is the ordinary paired case.
pub fn admits_device<A: RecoveryArbiter>(
    tip: &KelEvent,
    since_tip: &[KelEvent],
    device_key: &[u8; 32],
    arbiter: &A,
    has_other_factors: bool,
) -> Result<(), String> {
    let mut current = tip;
    for e in since_tip {
        match validate(current, e) {
            Verdict::Valid => current = e,
            Verdict::PendingRecovery => match arbiter.finalization(e, has_other_factors) {
                Finalization::Finalized => current = e,
                // An unfinalized recovery is not authoritative yet. Stop here rather than
                // continue: everything chained off it inherits that.
                Finalization::Pending => break,
            },
            Verdict::Invalid(why) => {
                return Err(format!("event at seq {} does not continue the tip: {why}", e.seq))
            }
        }
    }
    if current.key_state.group_key != *device_key {
        return Err("presented events verify but do not authorize this device key".to_string());
    }
    Ok(())
}

/// The key a contact now speaks with, learned from the key log they carried — or why
/// the log teaches nothing (`TASK-a-rotated-persons-contacts-keep-the-key-it-retired`).
///
/// `held` is the log this card kept for `aid` (at pairing, or the last time this
/// answered), and `held_key` the key the card holds for them. `offered` is the log
/// that arrived. Returns the key the offered log resolves to.
///
/// **The proof is the identity's own and nobody else's.** A log replays only from an
/// inception whose digest *is* `aid`, and every event after it is signed by the key
/// state before it or reveals a key that state pre-committed. So a relay, a vault or
/// a third contact carrying one cannot write one; the worst they can do is carry an
/// old one, and that is refused below.
///
/// **It only moves forward.** With a log held, the offered one must *continue* it —
/// hold it as a prefix — and is then replayed from the held tip, the shape
/// [`admits_device`] argues for: a verifier current on an identity needs the events it
/// has not seen. An older log, a fork, or a log for someone else is refused, so a key a
/// rotation retired cannot be put back by replaying the log from before it. With no
/// log held (a contact admitted before logs were kept, or on this machine), the offered
/// log is replayed from `aid` and must pass through `held_key` — the card never moves
/// to a key that does not descend from the one it already believes.
///
/// A recovery rotation is finalized as a lone factor, the posture pairing already
/// takes (`verify_identity`): the contest window is unenforced everywhere (RFC-0067,
/// *the contest window is enforced*), and when it is, this is where a contact's
/// replay takes the arbiter too.
pub fn contact_key_from_log(
    held: &[KelEvent],
    held_key: &[u8; 32],
    aid: &str,
    offered: &[KelEvent],
) -> Result<[u8; 32], String> {
    let first = offered.first().ok_or_else(|| "the key log is empty".to_string())?;
    if first.aid.0 != aid {
        return Err(format!("that key log is {}'s, and it arrived from {aid}", first.aid));
    }
    if held.is_empty() {
        // Replayed here rather than by `resolve_current_key`, because the answer
        // must be a key installed at or after the one the card holds — a replay
        // that stops before reaching it would otherwise move the card backwards.
        match validate_inception(first) {
            Verdict::Valid => {}
            v => return Err(format!("invalid inception: {v:?}")),
        }
        let mut current = first;
        let mut reached = current.key_state.group_key == *held_key;
        for e in &offered[1..] {
            match validate(current, e) {
                Verdict::Valid => current = e,
                Verdict::PendingRecovery => match LocalArbiter.finalization(e, false) {
                    Finalization::Finalized => current = e,
                    Finalization::Pending => break,
                },
                Verdict::Invalid(why) => return Err(format!("invalid event at seq {}: {why}", e.seq)),
            }
            reached |= current.key_state.group_key == *held_key;
        }
        if !reached {
            return Err("that key log never installs the key this card holds".to_string());
        }
        return Ok(current.key_state.group_key);
    }
    if offered.len() < held.len() || offered[..held.len()] != *held {
        return Err("that key log does not continue the one this card holds".to_string());
    }
    let mut current = held.last().expect("held is not empty");
    for e in &offered[held.len()..] {
        match validate(current, e) {
            Verdict::Valid => current = e,
            Verdict::PendingRecovery => match LocalArbiter.finalization(e, false) {
                Finalization::Finalized => current = e,
                Finalization::Pending => break,
            },
            Verdict::Invalid(why) => {
                return Err(format!("event at seq {} does not continue the held log: {why}", e.seq))
            }
        }
    }
    Ok(current.key_state.group_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::derive_kel_recovery_key;
    use kotton_wire::kel::{ContestWindow, KeyState};

    fn keystate(sk: &SigningKey, threshold: u16, participants: u16) -> KeyState {
        KeyState {
            group_key: sk.verifying_key().to_bytes(),
            threshold,
            participants,
        }
    }

    /// Build + sign an event with the given key over its canonical form.
    fn sign_quorum(mut e: KelEvent, sk: &SigningKey) -> KelEvent {
        // canonical() excludes the authorization, so the placeholder sig below does
        // not affect what we sign.
        e.authorization = Authorization::Quorum { sig: vec![0u8; 64] };
        let sig = sk.sign(e.canonical().as_bytes()).to_bytes().to_vec();
        e.authorization = Authorization::Quorum { sig };
        e
    }

    fn seed32() -> [u8; 32] {
        [42u8; 32]
    }

    /// An inception at K_rec[0]'s commitment, signed by `group_sk`.
    fn inception(group_sk: &SigningKey) -> KelEvent {
        let krec0 = kel_recovery_pubkey(&derive_kel_recovery_key(&seed32(), 0));
        let mut e = KelEvent {
            aid: Aid(String::new()),
            seq: 0,
            prev_event_digest: None,
            kind: EventKind::Inception,
            key_state: keystate(group_sk, 1, 1),
            recovery_commitment: recovery_commitment_for(&krec0),
            recovery_set: Vec::new(),
            authorization: Authorization::Quorum { sig: vec![0u8; 64] },
            contest_window: None,
        };
        e.aid = derive_aid(&e);
        sign_quorum(e, group_sk)
    }

    #[test]
    fn inception_validates() {
        let group = SigningKey::from_bytes(&[1u8; 32]);
        assert_eq!(validate_inception(&inception(&group)), Verdict::Valid);
    }

    #[test]
    fn tampered_inception_aid_is_rejected() {
        let group = SigningKey::from_bytes(&[1u8; 32]);
        let mut e = inception(&group);
        e.aid = Aid("did:kel:deadbeef".into());
        assert!(matches!(validate_inception(&e), Verdict::Invalid(_)));
    }

    // ── The recovery set ──────────────────────────────────────────────────────

    fn pk(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn a_one_member_set_admits_its_member_and_nothing_else() {
        let set = [pk(1)];
        let root = recovery_root(&set);
        let proof = recovery_proof(&set, &pk(1)).expect("member");
        assert!(verify_recovery_inclusion(&root, &pk(1), &proof));
        assert!(!verify_recovery_inclusion(&root, &pk(2), &proof));
        assert!(recovery_proof(&set, &pk(2)).is_none());
    }

    #[test]
    fn every_member_of_a_larger_set_proves_and_non_members_do_not() {
        // Deliberately not a power of two: the odd node is carried up rather than
        // paired with itself, and that path needs exercising.
        let set = [pk(1), pk(2), pk(3), pk(4), pk(5)];
        let root = recovery_root(&set);
        for m in set {
            let proof = recovery_proof(&set, &m).expect("member");
            assert!(
                verify_recovery_inclusion(&root, &m, &proof),
                "member {m:?} failed its own proof"
            );
        }
        assert!(recovery_proof(&set, &pk(9)).is_none());
        let stolen = recovery_proof(&set, &pk(1)).expect("member");
        assert!(!verify_recovery_inclusion(&root, &pk(9), &stolen));
    }

    #[test]
    fn the_root_is_a_function_of_the_set_not_its_order() {
        let a = recovery_root(&[pk(1), pk(2), pk(3)]);
        let b = recovery_root(&[pk(3), pk(1), pk(2)]);
        assert_eq!(a, b, "two clients building the same set must commit the same root");
        // And a duplicate is not a second member.
        assert_eq!(a, recovery_root(&[pk(1), pk(2), pk(3), pk(2)]));
    }

    #[test]
    fn the_empty_set_admits_nothing() {
        let root = recovery_root(&[]);
        assert_eq!(root, empty_recovery_root());
        assert!(!verify_recovery_inclusion(&root, &pk(1), &[]));
        assert!(!verify_recovery_inclusion(&root, &pk(1), &[pk(2)]));
        // And it is distinguishable from a real set, which is the whole point of
        // choosing it over random entropy: the shell can tell a person their
        // account has no way back in yet.
        assert_ne!(root, recovery_root(&[pk(1)]));
    }

    /// An internal node cannot be presented as a set member.
    ///
    /// **Neither assertion here depends on the domain tags**, and that is written
    /// down because it took two attempts to establish. The test was added
    /// believing it proved the tags necessary; deleting the tags left it green.
    /// The doc was then corrected to claim the *second* assertion was the
    /// tag-dependent one; deleting the tags left that green too.
    ///
    /// The actual reason: leaf inputs are a fixed 32 bytes and node inputs are 64,
    /// so the two hash domains cannot collide with or without tags. No test can
    /// show the tags necessary today, because they are not.
    ///
    /// The property is still worth pinning — an internal node must never verify as
    /// a member, however that is currently achieved — and this is the test that
    /// goes red if the leaves ever stop being fixed-width and nothing else picks
    /// up the slack.
    #[test]
    fn an_internal_node_cannot_be_passed_off_as_a_member() {
        let set = [pk(1), pk(2)];
        let root = recovery_root(&set);
        let forged_member: [u8; 32] = node_hash(&leaf_hash(&pk(1)), &leaf_hash(&pk(2)));
        assert!(
            !verify_recovery_inclusion(&root, &forged_member, &[]),
            "an internal node was accepted as a set member"
        );
        // Distinct because the inputs are 32 and 64 bytes, not because of the
        // tags — see the doc comment.
        assert_ne!(leaf_hash(&pk(1)), node_hash(&pk(1), &pk(1)));
    }

    /// A two-member set whose members are identical must not collide with the
    /// one-member set — the classic Merkle malleability bug, avoided by carrying
    /// an odd node up rather than hashing it with itself.
    #[test]
    fn a_duplicated_member_does_not_forge_a_different_set() {
        assert_eq!(recovery_root(&[pk(1), pk(1)]), recovery_root(&[pk(1)]));
        assert_ne!(recovery_root(&[pk(1), pk(2)]), recovery_root(&[pk(1)]));
    }

    /// A fresh identity is valid, has a random key, and admits no recovery.
    ///
    /// The last clause is the one worth pinning: the account exists and works, and
    /// there is provably no way back into it. That is the honest state for a first
    /// run that asked for nothing, and it is detectable — which is exactly what
    /// committing random entropy instead would have destroyed.
    #[test]
    fn a_fresh_inception_is_valid_and_has_no_recovery_authority() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let inc = build_fresh_inception(&sk);

        assert_eq!(validate_inception(&inc), Verdict::Valid);
        assert_eq!(inc.recovery_commitment, empty_recovery_root());
        assert!(!inc.aid.0.is_empty(), "the AID is the self-addressing digest");

        // Nothing opens it. Not the key that would have been committed by the old
        // seed-derived path, and not an empty proof.
        let would_have_been = kel_recovery_pubkey(&crate::kdf::derive_kel_recovery_key(&[9u8; 32], 0));
        assert!(!verify_recovery_inclusion(&inc.recovery_commitment, &would_have_been, &[]));
    }

    /// Two fresh identities differ, which is the whole point of a random key.
    ///
    /// Under the seed-derived path the AID was a pure function of the mnemonic, so
    /// this test could not have been written: the same phrase always produced the
    /// same identity, which is what made the phrase unrotatable.
    #[test]
    fn two_fresh_inceptions_are_different_identities() {
        let a = build_fresh_inception(&SigningKey::from_bytes(&[1u8; 32]));
        let b = build_fresh_inception(&SigningKey::from_bytes(&[2u8; 32]));
        assert_ne!(a.aid, b.aid);
        assert_eq!(a.recovery_commitment, b.recovery_commitment, "both have none");
    }

    /// A cooperative rotation cannot grant itself a recovery authority — and that
    /// rule, plus an empty inception, is a **dead end this test found**.
    ///
    /// The carry-forward rule is right and load-bearing: it is why a stolen device
    /// can rotate the operational key but never replace your way back in. But an
    /// identity born with `empty_recovery_root()` cannot *gain* an authority under
    /// the rules as they stand:
    ///
    /// - a cooperative rotation may not change `recovery_commitment` (this test);
    /// - a recovery rotation must reveal a member of the current set, and the empty
    ///   set has none.
    ///
    /// So "first run commits nothing, add recovery later" is not yet expressible,
    /// and shipping the empty inception without an answer would make every fresh
    /// account permanently unrecoverable. Filed as
    /// `TASK-an-identity-with-no-recovery-cannot-gain-one`.
    #[test]
    fn a_cooperative_rotation_still_cannot_grant_itself_recovery() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let inc = build_fresh_inception(&sk);
        let new_sk = SigningKey::from_bytes(&[8u8; 32]);

        let mut rot = KelEvent {
            aid: inc.aid.clone(),
            seq: 1,
            prev_event_digest: Some(digest(&inc)),
            kind: EventKind::RotationCooperative,
            key_state: KeyState {
                group_key: new_sk.verifying_key().to_bytes(),
                threshold: 1,
                participants: 1,
            },
            // Trying to install a recovery authority on the way past.
            recovery_commitment: recovery_root(&[[3u8; 32]]),
            recovery_set: Vec::new(),
            authorization: Authorization::Quorum { sig: vec![0u8; 64] },
            contest_window: None,
        };
        let sig = sk.sign(rot.canonical().as_bytes()).to_bytes().to_vec();
        rot.authorization = Authorization::Quorum { sig };

        assert!(
            matches!(validate(&inc, &rot), Verdict::Invalid(_)),
            "a cooperative rotation must not be able to grant itself a recovery authority"
        );
    }

    fn add_recovery(prev: &KelEvent, set: &[[u8; 32]], signer: &SigningKey) -> KelEvent {
        let mut e = KelEvent {
            aid: prev.aid.clone(),
            seq: prev.seq + 1,
            prev_event_digest: Some(digest(prev)),
            kind: EventKind::RotationAddRecovery,
            key_state: prev.key_state.clone(),
            recovery_commitment: recovery_root(set),
            recovery_set: set.to_vec(),
            authorization: Authorization::Quorum { sig: vec![0u8; 64] },
            contest_window: None,
        };
        let sig = signer.sign(e.canonical().as_bytes()).to_bytes().to_vec();
        e.authorization = Authorization::Quorum { sig };
        e
    }

    /// The whole point of an identity that starts with no recovery: it can gain one
    /// afterwards, with the key already on the device, without a ceremony at first
    /// run. This is the case `TASK-an-identity-with-no-recovery-cannot-gain-one`
    /// was filed for.
    #[test]
    fn an_identity_with_no_recovery_can_gain_its_first_authority() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let inc = build_fresh_inception(&sk);
        assert_eq!(inc.recovery_commitment, empty_recovery_root());

        let add = add_recovery(&inc, &[[1u8; 32]], &sk);
        assert_eq!(validate(&inc, &add), Verdict::Valid);
        assert_eq!(add.recovery_commitment, recovery_root(&[[1u8; 32]]));
    }

    /// And a second, later, just as easily — "add a device, add a guardian, add a
    /// storage node" are all things a person does repeatedly after first run, so
    /// none of them may cost more than the first.
    #[test]
    fn a_second_authority_is_no_harder_than_the_first() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let inc = build_fresh_inception(&sk);
        let first = add_recovery(&inc, &[[1u8; 32]], &sk);
        let second = add_recovery(&first, &[[1u8; 32], [2u8; 32]], &sk);
        assert_eq!(validate(&first, &second), Verdict::Valid);
    }

    /// The rule that makes the above safe to sign with a key that might be stolen.
    ///
    /// Whoever holds the current key can add a way in and never remove yours, so a
    /// thief cannot lock the owner out: the owner recovers with the authority still
    /// committed, then rotates the intruder's out.
    #[test]
    fn add_recovery_may_not_drop_an_existing_authority() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let inc = build_fresh_inception(&sk);
        let first = add_recovery(&inc, &[[1u8; 32], [2u8; 32]], &sk);

        // Replacing the set with one of the intruder's choosing.
        let evict = add_recovery(&first, &[[9u8; 32]], &sk);
        assert!(matches!(validate(&first, &evict), Verdict::Invalid(_)));

        // Even dropping one while keeping another, and even while adding.
        let partial = add_recovery(&first, &[[1u8; 32], [9u8; 32]], &sk);
        assert!(matches!(validate(&first, &partial), Verdict::Invalid(_)));
    }

    /// The commitment must match the set the event carries, or the set is decoration
    /// and the growth check is checking nothing.
    #[test]
    fn add_recovery_rejects_a_commitment_that_does_not_match_its_set() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let inc = build_fresh_inception(&sk);
        let mut lying = add_recovery(&inc, &[[1u8; 32]], &sk);
        lying.recovery_commitment = recovery_root(&[[5u8; 32]]);
        let sig = sk.sign(lying.canonical().as_bytes()).to_bytes().to_vec();
        lying.authorization = Authorization::Quorum { sig };
        assert!(matches!(validate(&inc, &lying), Verdict::Invalid(_)));
    }

    #[test]
    fn cooperative_rotation_accepts_and_requires_carry_forward() {
        let group = SigningKey::from_bytes(&[1u8; 32]);
        let inc = inception(&group);
        let newgroup = SigningKey::from_bytes(&[2u8; 32]);

        // Valid: signed by the PRIOR group key, recovery_commitment carried forward.
        let mut rot = KelEvent {
            aid: inc.aid.clone(),
            seq: 1,
            prev_event_digest: Some(digest(&inc)),
            kind: EventKind::RotationCooperative,
            key_state: keystate(&newgroup, 2, 2),
            recovery_commitment: inc.recovery_commitment, // carried forward
            recovery_set: Vec::new(),
            authorization: Authorization::Quorum { sig: vec![] },
            contest_window: None,
        };
        rot = sign_quorum(rot, &group);
        assert_eq!(validate(&inc, &rot), Verdict::Valid);

        // Rejected: alters the recovery lineage without revealing a reserve key.
        let mut bad = rot.clone();
        bad.recovery_commitment = [9u8; 32];
        let bad = sign_quorum(bad, &group);
        assert!(matches!(validate(&inc, &bad), Verdict::Invalid(_)));
    }

    #[test]
    fn mnemonic_recovery_requires_the_committed_reserve_key() {
        let group = SigningKey::from_bytes(&[1u8; 32]);
        let inc = inception(&group);

        // The true holder reveals K_rec[0] (matches inception's commitment) and signs.
        let krec0_seed = derive_kel_recovery_key(&seed32(), 0);
        let krec0 = SigningKey::from_bytes(&krec0_seed);
        let survivor = SigningKey::from_bytes(&[7u8; 32]);
        let krec1 = kel_recovery_pubkey(&derive_kel_recovery_key(&seed32(), 1));

        let mut rec = KelEvent {
            aid: inc.aid.clone(),
            seq: 1,
            prev_event_digest: Some(digest(&inc)),
            kind: EventKind::RotationMnemonic,
            key_state: keystate(&survivor, 1, 1),
            recovery_commitment: recovery_commitment_for(&krec1),
            recovery_set: Vec::new(),
            authorization: Authorization::Mnemonic {
                revealed_rec_pubkey: krec0.verifying_key().to_bytes(),
                proof: Vec::new(),
                sig: vec![0u8; 64],
            },
            contest_window: Some(ContestWindow { min_seconds: 3600 }),
        };
        let sig = krec0.sign(rec.canonical().as_bytes()).to_bytes().to_vec();
        rec.authorization = Authorization::Mnemonic {
            revealed_rec_pubkey: krec0.verifying_key().to_bytes(),
            proof: Vec::new(),
            sig,
        };
        assert_eq!(validate(&inc, &rec), Verdict::PendingRecovery);
    }

    /// Headline (RFC-0038): an attacker holding the entire current quorum can act
    /// with it, but CANNOT forge a mnemonic recovery — they lack `K_rec` (only the
    /// mnemonic derives it), so a revealed key won't match the prior commitment.
    #[test]
    fn full_quorum_compromise_cannot_forge_a_recovery() {
        let group = SigningKey::from_bytes(&[1u8; 32]);
        let inc = inception(&group);

        // Attacker HAS the group signing key (the whole quorum). They pick an
        // arbitrary "recovery" key they control and try to roll the identity forward.
        let attacker_rec = SigningKey::from_bytes(&[0xAB; 32]);
        let attacker_new = SigningKey::from_bytes(&[0xCD; 32]);
        let mut forged = KelEvent {
            aid: inc.aid.clone(),
            seq: 1,
            prev_event_digest: Some(digest(&inc)),
            kind: EventKind::RotationMnemonic,
            key_state: keystate(&attacker_new, 1, 1),
            recovery_commitment: [0u8; 32],
            recovery_set: Vec::new(),
            authorization: Authorization::Mnemonic {
                revealed_rec_pubkey: attacker_rec.verifying_key().to_bytes(),
                proof: Vec::new(),
                sig: vec![0u8; 64],
            },
            contest_window: Some(ContestWindow { min_seconds: 3600 }),
        };
        let sig = attacker_rec.sign(forged.canonical().as_bytes()).to_bytes().to_vec();
        forged.authorization = Authorization::Mnemonic {
            revealed_rec_pubkey: attacker_rec.verifying_key().to_bytes(),
            proof: Vec::new(),
            sig,
        };
        // Rejected: the revealed key does not hash to the pre-committed reserve.
        assert!(
            matches!(validate(&inc, &forged), Verdict::Invalid(_)),
            "a full-quorum thief must not be able to forge a recovery without K_rec"
        );

        // And a cooperative rotation they DO sign cannot alter the recovery lineage
        // (so the true mnemonic-holder can still supersede them).
        let mut coop = KelEvent {
            aid: inc.aid.clone(),
            seq: 1,
            prev_event_digest: Some(digest(&inc)),
            kind: EventKind::RotationCooperative,
            key_state: keystate(&attacker_new, 1, 1),
            recovery_commitment: [0u8; 32], // attacker tries to re-root recovery
            recovery_set: Vec::new(),
            authorization: Authorization::Quorum { sig: vec![] },
            contest_window: None,
        };
        coop = sign_quorum(coop, &group);
        assert!(matches!(validate(&inc, &coop), Verdict::Invalid(_)));
    }

    #[test]
    fn local_arbiter_finalizes_lone_factor_immediately() {
        let group = SigningKey::from_bytes(&[1u8; 32]);
        let inc = inception(&group);
        let a = LocalArbiter;
        assert_eq!(a.finalization(&inc, false), Finalization::Finalized);
        assert_eq!(a.finalization(&inc, true), Finalization::Pending);
    }

    /// A cooperative rotation, signed by the prior key and carrying the recovery
    /// commitment forward.
    fn coop_rotation(prev: &KelEvent, new_group: &SigningKey, prior_sk: &SigningKey) -> KelEvent {
        let mut r = KelEvent {
            aid: prev.aid.clone(),
            seq: prev.seq + 1,
            prev_event_digest: Some(digest(prev)),
            kind: EventKind::RotationCooperative,
            key_state: keystate(new_group, 2, 2),
            recovery_commitment: prev.recovery_commitment,
            recovery_set: Vec::new(),
            authorization: Authorization::Quorum { sig: vec![] },
            contest_window: None,
        };
        r = sign_quorum(r, prior_sk);
        r
    }

    #[test]
    fn resolve_current_key_replays_cooperative_rotations() {
        let g0 = SigningKey::from_bytes(&[1u8; 32]);
        let g1 = SigningKey::from_bytes(&[2u8; 32]);
        let g2 = SigningKey::from_bytes(&[3u8; 32]);
        let inc = inception(&g0);
        let r1 = coop_rotation(&inc, &g1, &g0);
        let r2 = coop_rotation(&r1, &g2, &g1);

        let key = resolve_current_key(&[inc, r1, r2], &LocalArbiter, false).unwrap();
        assert_eq!(
            key,
            g2.verifying_key().to_bytes(),
            "current key is the latest rotation's group key"
        );
    }

    #[test]
    fn resolve_rejects_a_broken_chain() {
        let g0 = SigningKey::from_bytes(&[1u8; 32]);
        let g1 = SigningKey::from_bytes(&[2u8; 32]);
        let inc = inception(&g0);
        let mut bad = coop_rotation(&inc, &g1, &g0);
        bad.prev_event_digest = Some([0u8; 32]); // wrong link
        assert!(resolve_current_key(&[inc, bad], &LocalArbiter, false).is_err());
    }

    #[test]
    fn resolve_finalizes_a_lone_factor_recovery_but_holds_a_multi_factor_one() {
        let g0 = SigningKey::from_bytes(&[1u8; 32]);
        let inc = inception(&g0);
        let krec0 = SigningKey::from_bytes(&derive_kel_recovery_key(&seed32(), 0));
        let survivor = SigningKey::from_bytes(&[7u8; 32]);
        let krec1 = kel_recovery_pubkey(&derive_kel_recovery_key(&seed32(), 1));

        let mut rec = KelEvent {
            aid: inc.aid.clone(),
            seq: 1,
            prev_event_digest: Some(digest(&inc)),
            kind: EventKind::RotationMnemonic,
            key_state: keystate(&survivor, 1, 1),
            recovery_commitment: recovery_commitment_for(&krec1),
            recovery_set: Vec::new(),
            authorization: Authorization::Mnemonic {
                revealed_rec_pubkey: krec0.verifying_key().to_bytes(),
                proof: Vec::new(),
                sig: vec![0u8; 64],
            },
            contest_window: Some(ContestWindow { min_seconds: 3600 }),
        };
        let sig = krec0.sign(rec.canonical().as_bytes()).to_bytes().to_vec();
        rec.authorization = Authorization::Mnemonic {
            revealed_rec_pubkey: krec0.verifying_key().to_bytes(),
            proof: Vec::new(),
            sig,
        };
        let chain = vec![inc, rec];

        // Lone factor → finalizes → current key is the survivor's.
        assert_eq!(
            resolve_current_key(&chain, &LocalArbiter, false).unwrap(),
            survivor.verifying_key().to_bytes()
        );
        // Multi-factor → pending → current key stays the pre-recovery (inception) key.
        assert_eq!(
            resolve_current_key(&chain, &LocalArbiter, true).unwrap(),
            g0.verifying_key().to_bytes()
        );
    }

    #[test]
    fn build_mnemonic_rotation_rotates_the_authoritative_key_for_a_lone_factor() {
        // A user's inception + a mnemonic recovery rotation built from the same seed:
        // the revealed K_rec[0] matches the inception's commitment, so it validates.
        let seed = seed32();
        let inc = build_user_inception(&seed);
        let new_key = SigningKey::from_bytes(&[42u8; 32]);
        let rot = build_mnemonic_rotation(&inc, &seed, 0, &new_key, 3600, &[kel_recovery_pubkey(&crate::kdf::derive_kel_recovery_key(&seed, 0))]);
        let chain = vec![inc.clone(), rot];

        // Lone factor (single device) → finalizes → the NEW key now speaks.
        assert_eq!(
            resolve_current_key(&chain, &LocalArbiter, false).unwrap(),
            new_key.verifying_key().to_bytes()
        );
        // Multi-factor → the recovery holds pending → the pre-recovery key still speaks.
        assert_eq!(
            resolve_current_key(&chain, &LocalArbiter, true).unwrap(),
            inc.key_state.group_key
        );
        // A rotation revealing the WRONG reserve index cannot forge the key change.
        let forged = build_mnemonic_rotation(&inc, &seed, 5, &new_key, 3600, &[kel_recovery_pubkey(&crate::kdf::derive_kel_recovery_key(&seed, 5))]);
        assert!(resolve_current_key(&[inc, forged], &LocalArbiter, false).is_err());
    }

    // ── Recovered-device admission (RFC-0081 gap 3) ──────────────────────────────
    //
    // The verifier holds a **tip** and is offered the events it has not seen. For a recovery
    // that is one event; for a device already current it is none.

    // ── The recovery-membership check both sides of a fetch run ──────────────────

    /// A phrase's own rung is committed by the identity it belongs to, and nothing else is.
    #[test]
    fn a_chain_commits_the_phrase_that_incepted_it_and_no_other() {
        let seed = seed32();
        let chain = vec![build_user_inception(&seed)];
        let mine = kel_recovery_pubkey(&crate::kdf::derive_kel_recovery_key(&seed, 0));
        assert!(tip_commits_recovery_key(&chain, &mine));

        // A different phrase. This is the case that makes the fetch safe to answer for a
        // stranger: the query is an unrevealed rung, so one that is not a member matches
        // nothing and the node discloses nothing by looking.
        let other = kel_recovery_pubkey(&crate::kdf::derive_kel_recovery_key(&[3u8; 32], 0));
        assert!(!tip_commits_recovery_key(&chain, &other));

        // The wrong rung of the *right* phrase is also not a member — the ladder's other
        // rungs are committed by later events, not this one.
        let wrong_rung = kel_recovery_pubkey(&crate::kdf::derive_kel_recovery_key(&seed, 4));
        assert!(!tip_commits_recovery_key(&chain, &wrong_rung));
    }

    /// An identity minted with no recovery authority matches nothing, rather than everything.
    ///
    /// `build_fresh_inception` commits the empty set, whose root is a constant. Reducing a
    /// membership test against a constant is the shape that silently admits anyone, so
    /// `verify_recovery_inclusion` refuses the empty root before doing any work and this
    /// pins that it stays refused through this path too.
    #[test]
    fn an_identity_with_no_recovery_authority_admits_no_phrase() {
        let chain = vec![build_fresh_inception(&SigningKey::from_bytes(&[11u8; 32]))];
        let anything = kel_recovery_pubkey(&crate::kdf::derive_kel_recovery_key(&seed32(), 0));
        assert!(!tip_commits_recovery_key(&chain, &anything));
        assert!(tip_commits_any_recovery_key(&chain, &[anything]).is_none());
    }

    /// **The set is not on the tip after an ordinary rotation, and the check must still find
    /// it.**
    ///
    /// `recovery_commitment` is carried forward unchanged by a cooperative rotation;
    /// `recovery_set` is not — it is in the clear only on the events that set it. So the tip
    /// of a chain that rotated normally after recovery was set up commits the same
    /// authorities and carries none of them.
    ///
    /// Measured, not assumed: this test fails against the version of the check that read
    /// `tip.recovery_set` — which is what `login_with_recovery_key` did inline before this
    /// was lifted out of it. The effect was that setting up recovery and then rotating your
    /// key normally left the phrase unable to recover the identity it was an authority for,
    /// which is the case recovery exists for.
    #[test]
    fn a_cooperative_rotation_does_not_hide_the_recovery_set() {
        let seed = seed32();
        let inc = build_user_inception(&seed);
        let mine = kel_recovery_pubkey(&crate::kdf::derive_kel_recovery_key(&seed, 0));
        assert!(tip_commits_recovery_key(std::slice::from_ref(&inc), &mine));

        // An ordinary rotation: new key, same commitment carried forward, no set in the clear.
        let rotated = KelEvent {
            aid: inc.aid.clone(),
            seq: 1,
            prev_event_digest: Some(digest(&inc)),
            kind: EventKind::RotationCooperative,
            key_state: keystate(&SigningKey::from_bytes(&[12u8; 32]), 1, 1),
            recovery_commitment: inc.recovery_commitment,
            recovery_set: Vec::new(),
            authorization: Authorization::Quorum { sig: vec![0u8; 64] },
            contest_window: None,
        };
        let chain = vec![inc, rotated];
        assert!(
            tip_commits_recovery_key(&chain, &mine),
            "the phrase is still an authority — the commitment says so — and a check that \
             reads only the tip's cleartext set cannot see it"
        );
    }

    /// The window a recovering device offers resolves to the rung that matched.
    ///
    /// It offers several because it cannot know how many recoveries an identity has had:
    /// that count is in the chain it does not have yet, which is the whole problem.
    #[test]
    fn the_offered_window_reports_which_rung_matched() {
        let seed = seed32();
        let chain = vec![build_user_inception(&seed)];
        let rung = |i| kel_recovery_pubkey(&crate::kdf::derive_kel_recovery_key(&seed, i));
        let window: Vec<[u8; 32]> = (0u64..4).map(rung).collect();
        assert_eq!(tip_commits_any_recovery_key(&chain, &window), Some(rung(0)));

        // A window from someone else's phrase resolves to nothing, however wide.
        let theirs: Vec<[u8; 32]> = (0u64..4)
            .map(|i| kel_recovery_pubkey(&crate::kdf::derive_kel_recovery_key(&[5u8; 32], i)))
            .collect();
        assert_eq!(tip_commits_any_recovery_key(&chain, &theirs), None);
    }

    /// Both recovery kinds draw on the same reserve ladder, so both advance the index.
    ///
    /// The bug this pins shipped on 2026-08-23 and survived its own test, which performed two
    /// *mnemonic* recoveries — a case where counting one kind and counting both agree. An
    /// identity that has ever used a guardian recovery would then build its next mnemonic
    /// rotation against the wrong rung, reveal a key that does not match the stored
    /// commitment, and stop replaying from that point on.
    #[test]
    fn a_guardian_recovery_also_consumes_a_rung() {
        let group = SigningKey::from_bytes(&[7u8; 32]);
        let inc = inception(&group);
        assert_eq!(next_recovery_index(std::slice::from_ref(&inc)), 0);

        // A guardian recovery reveals the same pre-committed reserve `validate_recovery`
        // checks for a mnemonic one — the ladder is shared.
        let guardian = KelEvent {
            aid: inc.aid.clone(),
            seq: 1,
            prev_event_digest: Some(digest(&inc)),
            kind: EventKind::RotationGuardian,
            key_state: keystate(&SigningKey::from_bytes(&[8u8; 32]), 1, 1),
            recovery_commitment: [0u8; 32],
            recovery_set: Vec::new(),
            authorization: Authorization::Guardian {
                revealed_group_key: [0u8; 32],
                proof: Vec::new(),
                sig: vec![0u8; 64],
            },
            contest_window: Some(ContestWindow { min_seconds: 3600 }),
        };
        assert_eq!(
            next_recovery_index(&[inc, guardian]),
            1,
            "a guardian recovery consumes a reserve rung; counting only mnemonic ones \
             returns an index that builds an unverifiable chain"
        );
    }

    /// The whole point. A node current only on the inception is offered one rotation event,
    /// and admits the device that rotation names — having never been told that key in advance.
    #[test]
    fn one_rotation_event_admits_the_device_it_names() {
        let group = SigningKey::from_bytes(&[7u8; 32]);
        let tip = inception(&group);
        let recovered = SigningKey::from_bytes(&[9u8; 32]);
        let rot = build_mnemonic_rotation(&tip, &seed32(), 0, &recovered, 0, &[kel_recovery_pubkey(&crate::kdf::derive_kel_recovery_key(&seed32(), 0))]);
        assert_eq!(
            admits_device(&tip, &[rot], &recovered.verifying_key().to_bytes(), &LocalArbiter, false),
            Ok(())
        );
    }

    /// A stranger's KEL is refused **structurally**: it is well-formed and valid on its own
    /// terms, and it simply does not chain from this verifier's tip. No explicit AID
    /// comparison is involved — `validate` requires `prev_event_digest == digest(tip)`.
    #[test]
    fn a_valid_chain_that_does_not_continue_my_tip_is_refused() {
        let my_tip = inception(&SigningKey::from_bytes(&[7u8; 32]));
        let theirs = inception(&SigningKey::from_bytes(&[11u8; 32]));
        let attacker = SigningKey::from_bytes(&[12u8; 32]);
        let their_rot = build_mnemonic_rotation(&theirs, &seed32(), 0, &attacker, 0, &[kel_recovery_pubkey(&crate::kdf::derive_kel_recovery_key(&seed32(), 0))]);

        // Valid where it belongs...
        assert_eq!(
            admits_device(&theirs, std::slice::from_ref(&their_rot), &attacker.verifying_key().to_bytes(), &LocalArbiter, false),
            Ok(())
        );
        // ...and refused here.
        let err = admits_device(&my_tip, &[their_rot], &attacker.verifying_key().to_bytes(), &LocalArbiter, false)
            .unwrap_err();
        assert!(err.contains("does not continue the tip"), "got: {err}");
    }

    #[test]
    fn a_tampered_signature_is_refused() {
        let group = SigningKey::from_bytes(&[7u8; 32]);
        let tip = inception(&group);
        let recovered = SigningKey::from_bytes(&[9u8; 32]);
        let mut rot = build_mnemonic_rotation(&tip, &seed32(), 0, &recovered, 0, &[kel_recovery_pubkey(&crate::kdf::derive_kel_recovery_key(&seed32(), 0))]);
        if let Authorization::Mnemonic { sig, .. } = &mut rot.authorization {
            sig[0] ^= 0xff;
        }
        assert!(admits_device(&tip, &[rot], &recovered.verifying_key().to_bytes(), &LocalArbiter, false).is_err());
    }

    /// Verifying is not the same as authorizing the caller. Kept distinct because it is the
    /// subtlest failure and collapsing it into the others would make it read as an attack.
    #[test]
    fn events_that_verify_do_not_admit_a_key_they_do_not_name() {
        let tip = inception(&SigningKey::from_bytes(&[7u8; 32]));
        let recovered = SigningKey::from_bytes(&[9u8; 32]);
        let bystander = SigningKey::from_bytes(&[13u8; 32]);
        let rot = build_mnemonic_rotation(&tip, &seed32(), 0, &recovered, 0, &[kel_recovery_pubkey(&crate::kdf::derive_kel_recovery_key(&seed32(), 0))]);
        let err = admits_device(&tip, &[rot], &bystander.verifying_key().to_bytes(), &LocalArbiter, false)
            .unwrap_err();
        assert!(err.contains("do not authorize"), "got: {err}");
    }

    /// Offering nothing is the ordinary paired case: admitted only if the tip already names
    /// this device. A verifier must not be talked into admitting a stranger by silence.
    #[test]
    fn offering_nothing_admits_only_the_key_the_tip_already_names() {
        let group = SigningKey::from_bytes(&[7u8; 32]);
        let tip = inception(&group);
        assert_eq!(
            admits_device(&tip, &[], &group.verifying_key().to_bytes(), &LocalArbiter, false),
            Ok(())
        );
        let stranger = SigningKey::from_bytes(&[14u8; 32]);
        assert!(admits_device(&tip, &[], &stranger.verifying_key().to_bytes(), &LocalArbiter, false).is_err());
    }

    /// A verifier several rotations behind catches up on the run it is offered — bounded by
    /// how stale it is, never by how much history exists.
    #[test]
    fn a_verifier_behind_by_several_events_catches_up_on_the_run() {
        let group = SigningKey::from_bytes(&[7u8; 32]);
        let tip = inception(&group);
        let a = SigningKey::from_bytes(&[9u8; 32]);
        let b = SigningKey::from_bytes(&[10u8; 32]);
        let r1 = build_mnemonic_rotation(&tip, &seed32(), 0, &a, 0, &[kel_recovery_pubkey(&crate::kdf::derive_kel_recovery_key(&seed32(), 0))]);
        let r2 = build_mnemonic_rotation(&r1, &seed32(), 1, &b, 0, &[kel_recovery_pubkey(&crate::kdf::derive_kel_recovery_key(&seed32(), 1))]);
        assert_eq!(
            admits_device(&tip, &[r1, r2], &b.verifying_key().to_bytes(), &LocalArbiter, false),
            Ok(())
        );
    }

    // ── contact_key_from_log ─────────────────────────────────────────────────
    // `TASK-a-rotated-persons-contacts-keep-the-key-it-retired`: what a contact's card
    // learns from a key log it is handed, and what it refuses to.

    fn rung(i: u64) -> [u8; 32] {
        kel_recovery_pubkey(&crate::kdf::derive_kel_recovery_key(&seed32(), i))
    }

    /// An identity's log: its inception, then one mnemonic rotation per key in `keys`.
    fn a_log_rotating_to(first: &SigningKey, keys: &[&SigningKey]) -> Vec<KelEvent> {
        let mut chain = vec![inception(first)];
        for (i, k) in keys.iter().enumerate() {
            let prev = chain.last().unwrap().clone();
            chain.push(build_mnemonic_rotation(&prev, &seed32(), i as u64, k, 0, &[rung(i as u64)]));
        }
        chain
    }

    #[test]
    fn a_log_that_continues_the_held_one_teaches_the_rotated_key() {
        let (old, new) = (SigningKey::from_bytes(&[7u8; 32]), SigningKey::from_bytes(&[9u8; 32]));
        let held = a_log_rotating_to(&old, &[]);
        let offered = a_log_rotating_to(&old, &[&new]);
        let aid = held[0].aid.0.clone();
        assert_eq!(
            contact_key_from_log(&held, &old.verifying_key().to_bytes(), &aid, &offered),
            Ok(new.verifying_key().to_bytes())
        );
        // The same log again teaches what the card already holds, and nothing else.
        assert_eq!(
            contact_key_from_log(&offered, &new.verifying_key().to_bytes(), &aid, &offered),
            Ok(new.verifying_key().to_bytes())
        );
    }

    /// Replaying the log from before a rotation must not put the retired key back —
    /// the case a rotation for a stolen key exists for.
    #[test]
    fn an_older_log_does_not_put_a_retired_key_back() {
        let (k0, k1, k2) = (
            SigningKey::from_bytes(&[7u8; 32]),
            SigningKey::from_bytes(&[9u8; 32]),
            SigningKey::from_bytes(&[10u8; 32]),
        );
        let held = a_log_rotating_to(&k0, &[&k1, &k2]);
        let aid = held[0].aid.0.clone();
        for older in [held[..1].to_vec(), held[..2].to_vec()] {
            assert!(
                contact_key_from_log(&held, &k2.verifying_key().to_bytes(), &aid, &older).is_err(),
                "a log {} events long must not roll a card holding {} back",
                older.len(),
                held.len()
            );
        }
    }

    /// A rotation nobody pre-committed — signed with a key that is not the reserve —
    /// is refused, whoever carries it: the log is the identity's word, not the carrier's.
    #[test]
    fn a_rotation_the_identity_did_not_authorize_is_refused() {
        let (old, thief) = (SigningKey::from_bytes(&[7u8; 32]), SigningKey::from_bytes(&[13u8; 32]));
        let held = a_log_rotating_to(&old, &[]);
        let aid = held[0].aid.0.clone();
        // Signed with the current key rather than revealing the pre-committed reserve.
        let mut forged = build_mnemonic_rotation(&held[0], &[99u8; 32], 0, &thief, 0, &[]);
        forged.prev_event_digest = Some(digest(&held[0]));
        let offered = vec![held[0].clone(), forged];
        assert!(contact_key_from_log(&held, &old.verifying_key().to_bytes(), &aid, &offered).is_err());
    }

    /// A well-formed log that is somebody else's teaches nothing about this contact.
    #[test]
    fn someone_elses_log_is_refused() {
        let old = SigningKey::from_bytes(&[7u8; 32]);
        let held = a_log_rotating_to(&old, &[]);
        let theirs = a_log_rotating_to(&SigningKey::from_bytes(&[11u8; 32]), &[&SigningKey::from_bytes(&[12u8; 32])]);
        let aid = held[0].aid.0.clone();
        assert!(contact_key_from_log(&held, &old.verifying_key().to_bytes(), &aid, &theirs).is_err());
        // Nor with no log held: the name on the log is not this contact's.
        assert!(contact_key_from_log(&[], &old.verifying_key().to_bytes(), &aid, &theirs).is_err());
    }

    /// Whoever stole the key a card holds can mint an identity of their own on it and
    /// rotate that to a key they choose. That log installs the held key and replays —
    /// it is simply not this contact's, and the name it replays from is what says so.
    #[test]
    fn a_thief_cannot_mint_a_log_on_the_stolen_key_for_a_card_with_none() {
        let stolen = SigningKey::from_bytes(&[7u8; 32]);
        let theirs = SigningKey::from_bytes(&[15u8; 32]);
        let victim_aid = "did:kel:the-person-whose-key-was-stolen";
        let minted = a_log_rotating_to(&stolen, &[&theirs]);
        assert!(minted.iter().any(|e| e.key_state.group_key == stolen.verifying_key().to_bytes()));
        assert!(contact_key_from_log(&[], &stolen.verifying_key().to_bytes(), victim_aid, &minted).is_err());
    }

    /// With no log held, the offered one must pass through the key the card holds —
    /// a card never moves to a key that does not descend from the one it believes.
    #[test]
    fn with_no_log_held_the_offered_one_must_descend_from_the_held_key() {
        let (old, new) = (SigningKey::from_bytes(&[7u8; 32]), SigningKey::from_bytes(&[9u8; 32]));
        let offered = a_log_rotating_to(&old, &[&new]);
        let aid = offered[0].aid.0.clone();
        assert_eq!(
            contact_key_from_log(&[], &old.verifying_key().to_bytes(), &aid, &offered),
            Ok(new.verifying_key().to_bytes())
        );
        let stranger = SigningKey::from_bytes(&[14u8; 32]).verifying_key().to_bytes();
        assert!(contact_key_from_log(&[], &stranger, &aid, &offered).is_err());
    }
}
