// SPDX-License-Identifier: AGPL-3.0-or-later
//! Which identifiers this device announces under, and looks a peer up by.
//!
//! One file, so the policy of rotating rendezvous handles has one place to
//! live. The derivation is [`kotton_crypto::pair_handle`]; what is here is the policy
//! question it leaves open — *which* handles a device publishes, in what order a
//! lookup tries them.
//!
//! # The property this is for
//!
//! A coordination server told "device `did:key:z6Mk…` is at `203.0.113.9`" holds
//! an identifier joined to a location. Repeated, that composes into a
//! presence-and-association history — an asset built out of somebody else's life.
//! Per-pair, per-epoch handles remove the join key: each observation still exists,
//! and no two of them link.
//!
//! # Nothing durable
//!
//! A device does not announce under its durable DID beside its rotating handles:
//! there is no durable identity, durable reservation, durable dial fallback or
//! durable presence push here, and nothing here can name a device durably to a
//! relay. A relay can learn only that *a handle* was at *an address* at *a
//! time*, which composes into nothing.

use anyhow::Result;
use ed25519_dalek::SigningKey;
use kotton_crypto::PairHandle;
use kotton_crypto::{
    dm_inbox_handle, dm_inbox_target, epoch_at, lookup_epochs, lookup_handle, publish_handle,
};
use kotton_net::rendezvous::client::RendezvousError;
use std::time::{SystemTime, UNIX_EPOCH};


/// Seconds since the Unix epoch, or `0` if the clock is before it.
///
/// A clock that far wrong produces handles nobody else derives, which surfaces as
/// an unreachable peer. That is the honest failure: the alternative is refusing to
/// publish at all, which is the same outcome with less information in the log.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The handle to publish this device's address under so `peer_pub` can find it.
///
/// One per paired peer, by construction: a handle a second peer could recognise
/// would be a join key of its own, so being reachable by three devices means three
/// announcements rather than one shared one.
pub fn publish_to(signing_key: &SigningKey, peer_pub: &[u8; 32], now: u64) -> Result<PairHandle> {
    publish_handle(signing_key, peer_pub, epoch_at(now))
}

/// The fingerprints to look `peer_pub` up under, in the order to try them.
///
/// The peer's handles for the current epoch and one either side — a lookup at
/// 10:59 must still find a device that published at 10:01 — followed, while
/// [`ANNOUNCE_DURABLE_DID`] holds, by the peer's durable DID so an un-upgraded
/// peer is still reachable.
pub fn lookup_candidates(
    signing_key: &SigningKey,
    peer_pub: &[u8; 32],
    now: u64,
) -> Result<Vec<String>> {
    let candidates: Vec<String> = lookup_epochs(now)
        .into_iter()
        .filter_map(|epoch| lookup_handle(signing_key, peer_pub, epoch).ok())
        .map(|did| did.to_string())
        .collect();

    if candidates.is_empty() {
        anyhow::bail!("no rendezvous identifier could be derived for this peer");
    }
    Ok(candidates)
}

/// The handles this device holds relay **reservations** under so `peer_pub` can
/// open a circuit to it (ROTATING-RENDEZVOUS-HANDLES step 6).
///
/// A reservation is a live connection, not a momentary push: it must exist at
/// the instant of the dial, and there is no store-and-forward to absorb clock
/// skew after the fact. So the target holds the **current and previous**
/// epoch's reservations, and a dialer tries current then previous
/// ([`circuit_targets`]) — a dialer whose clock is behind finds the previous
/// one still held, and one whose clock is ahead names what it thinks is
/// "previous", which is the target's "current".
///
/// One per paired peer, like the presence announcements and for the same
/// reason: a label a second peer could recognise would be a join key. The cost
/// is `2N` held connections per device (`+1` while [`ANNOUNCE_DURABLE_DID`]
/// keeps the durable reservation beside them), and the relay's
/// `MAX_RESERVATIONS` divides by that.
pub fn reservation_handles(
    signing_key: &SigningKey,
    peer_pub: &[u8; 32],
    now: u64,
) -> Vec<PairHandle> {
    let epoch = epoch_at(now);
    let mut epochs = vec![epoch];
    if let Some(prev) = epoch.checked_sub(1) {
        epochs.push(prev);
    }
    epochs
        .into_iter()
        .filter_map(|e| match publish_handle(signing_key, peer_pub, e) {
            Ok(h) => Some(h),
            Err(err) => {
                tracing::warn!(error = %err, "reservation: no handle for a paired peer");
                None
            }
        })
        .collect()
}

/// The mailbox labels a user answers for one contact right now — current epoch
/// and the previous one, the same slack a device reservation keeps for a sender
/// whose clock runs behind.
pub fn dm_inbox_reservations(
    own_identity: &SigningKey,
    contact_ed_pub: &[u8; 32],
    now: u64,
) -> Vec<PairHandle> {
    let epoch = epoch_at(now);
    let mut epochs = vec![epoch];
    if let Some(prev) = epoch.checked_sub(1) {
        epochs.push(prev);
    }
    epochs
        .into_iter()
        .filter_map(|e| match dm_inbox_handle(own_identity, contact_ed_pub, e) {
            Ok(h) => Some(h),
            Err(err) => {
                tracing::warn!(error = %err, "mailbox: no handle for a contact");
                None
            }
        })
        .collect()
}

/// The keys one pair's door needs for one epoch: the handle that
/// reserves it and answers inside the circuit, and the one key it admits — the
/// contact's handle for the same pair and epoch. Both come from the same
/// Diffie–Hellman, so either party derives both; a node handed them can hold
/// the door and can open nothing.
pub struct DmDoorKeys {
    pub handle: PairHandle,
    pub admit: [u8; 32],
}

pub fn dm_door(
    own_identity: &SigningKey,
    contact_ed_pub: &[u8; 32],
    epoch: u64,
) -> Result<DmDoorKeys> {
    let handle = dm_inbox_handle(own_identity, contact_ed_pub, epoch)?;
    let their = dm_inbox_target(own_identity, contact_ed_pub, epoch)?;
    let admit = kotton_crypto::did::DidKeyMethod::to_public_key(&their)?.to_bytes();
    Ok(DmDoorKeys { handle, admit })
}

/// Where to hand a message to `contact_ed_pub`, in order: their mailbox for the
/// current epoch, then the previous one.
///
/// The label the sender authenticates as is their own mailbox for the same pair
/// and epoch — as with a device circuit, both ends of the edge rotate together,
/// so the relay sees two labels that name nobody and do not compose.
pub fn dm_delivery_attempts(
    own_identity: &SigningKey,
    contact_ed_pub: &[u8; 32],
    now: u64,
) -> Result<Vec<DeliveryAttempt>> {
    let epoch = epoch_at(now);
    let mut epochs = vec![epoch];
    if let Some(prev) = epoch.checked_sub(1) {
        epochs.push(prev);
    }
    let mut attempts = Vec::with_capacity(epochs.len());
    for e in epochs {
        let own = dm_inbox_handle(own_identity, contact_ed_pub, e)?;
        let target = dm_inbox_target(own_identity, contact_ed_pub, e)?;
        let target_pub = kotton_crypto::did::DidKeyMethod::to_public_key(&target)?.to_bytes();
        attempts.push(DeliveryAttempt {
            epoch: e,
            auth_did: own.did.to_string(),
            auth_key: own.signing_key,
            target: target.to_string(),
            target_pub,
        });
    }
    if attempts.is_empty() {
        anyhow::bail!("no mailbox attempt could be derived for this contact");
    }
    Ok(attempts)
}

/// One try at handing a message over: the sender's own handle for the pair and
/// epoch, which labels the dial *and* is the certificate inside the circuit,
/// and the recipient's handle, which the dial names and the circuit's far end
/// must prove. Nothing durable travels on either side.
pub struct DeliveryAttempt {
    /// The hour both handles are for — which a knock on the local network is
    /// bound to as well.
    pub epoch: u64,
    pub auth_did: String,
    pub auth_key: SigningKey,
    pub target: String,
    /// The Ed25519 key the far end has to present: the recipient's handle for
    /// this epoch — held by their device, or by the vault they handed it to.
    pub target_pub: [u8; 32],
}

/// One try of a relayed dial: who to authenticate as, and who to name.
///
/// Both ends of the edge travel together deliberately — an attempt that
/// authenticated durably while naming a handle would relink what the handle
/// unlinked.
pub struct CircuitAttempt {
    /// The `fingerprint` this dial authenticates the `/relay/open` as.
    pub auth_did: String,
    /// Signs the attempt's `Authorization` header.
    pub auth_key: SigningKey,
    /// The reservation label the dial names (`?to=…`).
    pub target: String,
}

/// The attempts a relayed dial makes to reach `peer_pub`, in order.
///
/// Per-pair first: authenticate as this device's own current-epoch handle for
/// the pair, name the handle the peer reserves under — current epoch, then
/// previous, which covers a dialer whose clock runs ahead of the target's. The
/// served circuit is then labelled `(handle, handle)`, and no two circuits link
/// across pairs or hours. While [`ANNOUNCE_DURABLE_DID`] holds, a final attempt
/// is durable at **both** ends: an un-upgraded target reserves only under its
/// durable DID.
pub fn circuit_attempts(
    signing_key: &SigningKey,
    peer_pub: &[u8; 32],
    now: u64,
) -> Result<Vec<CircuitAttempt>> {
    let mut attempts = Vec::with_capacity(3);

    if let Ok(own) = publish_handle(signing_key, peer_pub, epoch_at(now)) {
        let epoch = epoch_at(now);
        let mut epochs = vec![epoch];
        if let Some(prev) = epoch.checked_sub(1) {
            epochs.push(prev);
        }
        for e in epochs {
            if let Ok(target) = lookup_handle(signing_key, peer_pub, e) {
                attempts.push(CircuitAttempt {
                    auth_did: own.did.to_string(),
                    auth_key: own.signing_key.clone(),
                    target: target.to_string(),
                });
            }
        }
    }

    if attempts.is_empty() {
        anyhow::bail!("no circuit attempt could be derived for this peer");
    }
    Ok(attempts)
}

/// Whether a relay rejected an announcement because of *who* made it: the
/// signature verified and the relay's rule refused the request.
///
/// Its cause is the relay's admission rule, which its operator sets over the
/// wire: an operator narrowed who may use it to *only my devices* or *the people I
/// invite*, and this request carried no admission tag under a key the relay
/// accepts. The rule admits by proof — a MAC under a key the admitted set holds —
/// and never by identity, so a handle is refused or admitted exactly as a durable
/// DID would be. A device presents a tag under the admission key it holds for its
/// relay ([`crate::relay_keys`]); one that holds none is refused by a relay whose
/// rule has been narrowed.
pub fn is_identity_refusal(error: &RendezvousError) -> bool {
    matches!(error, RendezvousError::HttpError { status: 403, .. })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotton_crypto::DidKeyMethod;
    use kotton_crypto::EPOCH_SECS;
    use rand::rngs::OsRng;

    fn pair() -> (SigningKey, SigningKey) {
        (
            SigningKey::generate(&mut OsRng),
            SigningKey::generate(&mut OsRng),
        )
    }

    /// The whole point: what A publishes under is the first thing B tries, with
    /// neither having exchanged anything.
    #[test]
    fn what_one_publishes_is_what_the_other_tries_first() {
        let (a, b) = pair();
        let now = 1_760_000_000;

        let published = publish_to(&a, &b.verifying_key().to_bytes(), now).unwrap();
        let tried = lookup_candidates(&b, &a.verifying_key().to_bytes(), now).unwrap();

        assert_eq!(tried[0], published.did.to_string());
    }

    /// A lookup late in an epoch still finds an address published early in it, and
    /// one early in an epoch still finds the previous one's — the tolerance exists
    /// so that a few minutes of clock skew reads as skew, not as an outage.
    #[test]
    fn a_lookup_spans_the_epoch_boundary() {
        let (a, b) = pair();
        let published_at = 4 * EPOCH_SECS + 10;
        let looked_up_at = 5 * EPOCH_SECS + 10; // the next epoch

        let published = publish_to(&a, &b.verifying_key().to_bytes(), published_at).unwrap();
        let tried = lookup_candidates(&b, &a.verifying_key().to_bytes(), looked_up_at).unwrap();

        assert!(
            tried.contains(&published.did.to_string()),
            "an epoch-old announcement is still findable"
        );
    }

    /// A device's handle for one peer is meaningless to another: a third device
    /// that knows both cannot tell that two announcements are the same machine.
    #[test]
    fn a_handle_names_a_pair_not_a_device() {
        let (a, b) = pair();
        let (_, c) = pair();
        let now = 1_760_000_000;

        let to_b = publish_to(&a, &b.verifying_key().to_bytes(), now).unwrap();
        let to_c = publish_to(&a, &c.verifying_key().to_bytes(), now).unwrap();

        assert_ne!(to_b.did.to_string(), to_c.did.to_string());
    }

    /// And it is meaningless across time: next epoch's announcement does not link
    /// to this one's, which is what stops observations composing into a history.
    #[test]
    fn a_handle_does_not_survive_its_epoch() {
        let (a, b) = pair();
        let b_pub = b.verifying_key().to_bytes();

        let now = publish_to(&a, &b_pub, 6 * EPOCH_SECS).unwrap();
        let later = publish_to(&a, &b_pub, 7 * EPOCH_SECS).unwrap();

        assert_ne!(now.did.to_string(), later.did.to_string());
    }

    // ── circuits (step 6) ─────────────────────────────────────────────────

    /// The reservation a device holds is the first thing a peer's dial names —
    /// the publish/lookup symmetry, on the circuit path.
    #[test]
    fn what_one_reserves_under_is_what_the_other_dials_first() {
        let (a, b) = pair();
        let now = 1_760_000_000;

        let reserved = reservation_handles(&a, &b.verifying_key().to_bytes(), now);
        let attempts = circuit_attempts(&b, &a.verifying_key().to_bytes(), now).unwrap();

        assert_eq!(attempts[0].target, reserved[0].did.to_string());
    }

    /// The target holds current and previous; the dialer tries current then
    /// previous. A dialer a whole epoch ahead or behind still names a held
    /// reservation — a reservation is live, so the tolerance must come from
    /// what is *held*, not from a lookup window after the fact.
    #[test]
    fn a_skewed_dialer_still_names_a_held_reservation() {
        let (a, b) = pair();
        let target_now = 5 * EPOCH_SECS + 10;
        let held: Vec<String> = reservation_handles(&a, &b.verifying_key().to_bytes(), target_now)
            .into_iter()
            .map(|h| h.did.to_string())
            .collect();
        assert_eq!(held.len(), 2, "current and previous epoch are both held");

        for dialer_now in [target_now - EPOCH_SECS, target_now, target_now + EPOCH_SECS] {
            let attempts =
                circuit_attempts(&b, &a.verifying_key().to_bytes(), dialer_now).unwrap();
            assert!(
                attempts.iter().any(|at| held.contains(&at.target)),
                "a dialer at {dialer_now} (target at {target_now}) must name a held reservation"
            );
        }
    }

    /// Every attempt is handle-to-handle: a device's own durable `did:key` is never
    /// an identity it authenticates a dial under, and a peer's never a target.
    #[test]
    fn no_circuit_attempt_names_a_durable_identity() {
        let (a, b) = pair();
        let attempts = circuit_attempts(&b, &a.verifying_key().to_bytes(), 1_760_000_000).unwrap();
        let a_durable = DidKeyMethod::from_public_key_bytes(&a.verifying_key().to_bytes())
            .unwrap()
            .to_string();
        let b_durable = DidKeyMethod::from_public_key_bytes(&b.verifying_key().to_bytes())
            .unwrap()
            .to_string();
        assert!(!attempts.is_empty());
        for at in &attempts {
            assert_ne!(at.target, a_durable, "a relayed dial never names a durable target");
            assert_ne!(at.auth_did, b_durable, "a relayed dial never authenticates durably");
        }
    }

    /// A message's dial is handle-to-handle too: neither person's identity key
    /// is the label it authenticates under or the door it names. It takes no
    /// relay, so it is the same two labels at every relay a sender dials at
    /// once — a relay learns nothing durable by being one more path.
    #[test]
    fn no_message_delivery_attempt_names_a_durable_identity() {
        let (alice, bob) = pair();
        let durable = |k: &SigningKey| {
            DidKeyMethod::from_public_key_bytes(&k.verifying_key().to_bytes()).unwrap().to_string()
        };
        let attempts =
            dm_delivery_attempts(&alice, &bob.verifying_key().to_bytes(), 1_760_000_000).unwrap();
        assert!(!attempts.is_empty());
        for at in &attempts {
            for who in [&alice, &bob] {
                assert_ne!(at.target, durable(who), "a message's dial never names an identity");
                assert_ne!(at.auth_did, durable(who), "a message's dial never authenticates as one");
            }
            assert_ne!(at.target_pub, bob.verifying_key().to_bytes());
        }
    }

    /// Step 5's assertion, kept after the window closed so it cannot quietly reopen:
    /// nothing looks a peer up by a durable identifier.
    #[test]
    fn nothing_looks_a_peer_up_by_a_durable_identifier() {
        let (a, b) = pair();
        let tried = lookup_candidates(&b, &a.verifying_key().to_bytes(), 1_760_000_000).unwrap();
        let a_durable = DidKeyMethod::from_public_key_bytes(&a.verifying_key().to_bytes())
            .unwrap()
            .to_string();
        assert!(!tried.is_empty());
        assert!(!tried.contains(&a_durable));
    }
}
