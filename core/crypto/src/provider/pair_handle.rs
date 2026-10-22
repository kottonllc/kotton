// SPDX-License-Identifier: AGPL-3.0-or-later
//! Per-pair, per-epoch rendezvous handles an intermediary cannot link.
//!
//! Two devices that already know each other's Ed25519 identity keys can each
//! compute the same handle, without either sending anything, and without the
//! party in the middle learning who is who.
//!
//! ## Why this exists
//!
//! A coordination server told "device `did:key:z6Mk…` is at `203.0.113.9`" holds a
//! durable identifier joined to a location. Repeat that hourly and it becomes a
//! presence-and-association history keyed to a person. The durable identifier is
//! the **join key**; strip it and the remaining observations stop composing,
//! because an address seen once is shared, NAT'd and attached to nobody.
//!
//! ## The constraint that shapes the construction
//!
//! The relay needs no account database because **the identifier *is* the
//! verification key** — it calls `ed25519_key_from_did(fingerprint)` and checks the
//! push signature against the key it extracts. That is why a device can announce
//! itself to a server that has never heard of it.
//!
//! Replacing the DID with an opaque hash destroys that. The relay could no longer
//! verify a push, so anyone could publish a bogus address under anyone's handle —
//! a new vulnerability rather than a weaker property. So the shape is kept and only
//! *which key* changes:
//!
//! ```text
//! shared     = X25519(own_priv, peer_pub)     // static-static, equal on both sides
//! seed       = HKDF-SHA256(shared, INFO ‖ epoch_be ‖ publisher_pub)
//! handle     = did:key(Ed25519::from_seed(seed))
//! ```
//!
//! The relay verifies exactly as it does today and **needs no change at all**, so a
//! deployed relay keeps working and old and new clients coexist during rollout.
//!
//! `publisher_pub` is in the derivation because without it the handle is symmetric:
//! both devices would derive the same one, publish to the same slot, and the second
//! would overwrite the first. Each side publishes under its own key and looks the
//! peer up under theirs.
//!
//! ## What this does not do
//!
//! It does not hide IP addresses. A coordination server must return a routable
//! address and sees a source address on every request; one that retains stable
//! source addresses can still re-link across epochs. The honest claim is *the
//! coordination server no longer learns durable identities or the association
//! graph — it still sees network location.*
//!
//! Either device in a pair can derive the other's handle **and its signing key**,
//! since the shared secret is symmetric. That is not a gap: they are each other's
//! paired peers, and mTLS device certificates — not this label — decide who may
//! actually connect. [`lookup_handle`] returns only the [`Did`] regardless, because
//! a caller looking someone up has no use for a signing capability.

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use kotton_wire::did::Did;
use sha2::Sha256;
use x25519_dalek::PublicKey as X25519PublicKey;

use super::did::DidKeyMethod;
use super::x25519::{ed25519_priv_to_x25519, ed25519_pub_to_x25519};

/// Domain separator. Changing it rotates every handle in the system at once,
/// which is the intended way to retire a broken scheme.
pub const PAIR_HANDLE_INFO: &[u8] = b"kotton:pair-handle:v1";

/// Domain separator for DM inbox addresses (ROTATING-RENDEZVOUS-HANDLES step 7).
///
/// A distinct separator, not a reuse: an inbox address must never collide with a
/// rendezvous handle, and the two must be revocable independently. The pair here
/// is **user identity keys** (the same X25519 conversion `dm_encrypt` already
/// performs between contacts), not device operational keys — a DM is user
/// authority, so its address derives from user key material.
pub const DM_INBOX_INFO: &[u8] = b"kotton:dm-inbox:v1";

/// How long a handle lasts.
///
/// This lives here rather than with either caller because **both sides must agree**
/// — it is protocol, not local policy, and a length that drifted between crates
/// would fail silently and look like a network fault.
pub const EPOCH_SECS: u64 = 3600;

/// A handle this device can publish under: the label, and the key that proves it.
pub struct PairHandle {
    /// Published as the `fingerprint`, and what the peer looks up.
    pub did: Did,
    /// Signs the push. The relay recovers the matching public key from `did`.
    pub signing_key: SigningKey,
}

/// The epoch containing `unix_secs`.
pub fn epoch_at(unix_secs: u64) -> u64 {
    unix_secs / EPOCH_SECS
}

/// The epochs a lookup should try, in order of likelihood: current, previous, next.
///
/// One epoch of slack in each direction. Without it, two devices either side of a
/// boundary — or with a few minutes of clock skew — miss each other entirely, and
/// the symptom looks like an unreachable peer rather than a clock problem.
pub fn lookup_epochs(unix_secs: u64) -> [u64; 3] {
    let now = epoch_at(unix_secs);
    [now, now.saturating_sub(1), now + 1]
}

/// The handle **this device** publishes under to be found by `peer_ed_pub`.
///
/// The peer computes the same [`Did`] with [`lookup_handle`].
pub fn publish_handle(
    own_signing_key: &SigningKey,
    peer_ed_pub: &[u8; 32],
    epoch: u64,
) -> Result<PairHandle> {
    let own_pub = own_signing_key.verifying_key().to_bytes();
    let (did, signing_key) =
        derive(own_signing_key, peer_ed_pub, &own_pub, epoch, PAIR_HANDLE_INFO)?;
    Ok(PairHandle { did, signing_key })
}

/// The handle **`peer_ed_pub` publishes under** — what this device looks up.
///
/// Returns only the [`Did`]: the caller is reading, not announcing.
pub fn lookup_handle(
    own_signing_key: &SigningKey,
    peer_ed_pub: &[u8; 32],
    epoch: u64,
) -> Result<Did> {
    let (did, _) = derive(
        own_signing_key,
        peer_ed_pub,
        peer_ed_pub,
        epoch,
        PAIR_HANDLE_INFO,
    )?;
    Ok(did)
}

/// The address **this user's** DM inbox answers under for `contact_ed_pub`,
/// this epoch (ROTATING-RENDEZVOUS-HANDLES step 7).
///
/// The keys are the two users' **identity keys** — the same pair `dm_encrypt`
/// runs its ECDH over — so any contact who can encrypt a DM to this user can
/// also derive where to queue it, with nothing exchanged. The owner tag is the
/// recipient's key: each direction of a contact pair has its own mailbox, so
/// the blobs under one address are exactly one sender's messages to one
/// recipient, and no two addresses link across pairs or epochs.
///
/// Returns the signing key too: the relay requires a poll (`GET`) or an
/// acknowledge (`DELETE`) to be signed by the address's own key.
pub fn dm_inbox_handle(
    own_signing_key: &SigningKey,
    contact_ed_pub: &[u8; 32],
    epoch: u64,
) -> Result<PairHandle> {
    let own_pub = own_signing_key.verifying_key().to_bytes();
    let (did, signing_key) =
        derive(own_signing_key, contact_ed_pub, &own_pub, epoch, DM_INBOX_INFO)?;
    Ok(PairHandle { did, signing_key })
}

/// The address to **queue a DM to `contact_ed_pub`** under, this epoch — the
/// contact's [`dm_inbox_handle`] as seen from the sender's side.
///
/// Returns only the [`Did`]: submitting to an inbox is unauthenticated, so the
/// sender has no use for the signing capability — though, the shared secret
/// being symmetric, it *could* derive it and read back or withdraw what it
/// itself queued, and nothing else.
pub fn dm_inbox_target(
    own_signing_key: &SigningKey,
    contact_ed_pub: &[u8; 32],
    epoch: u64,
) -> Result<Did> {
    let (did, _) = derive(
        own_signing_key,
        contact_ed_pub,
        contact_ed_pub,
        epoch,
        DM_INBOX_INFO,
    )?;
    Ok(did)
}

/// Domain separator for the local-network door's announcement
/// (`TASK-the-local-network-is-a-door-opened-on-purpose-for-ten-minutes-and-a-relay-introduces-your-devices`).
///
/// Its own separator, for the reason [`DM_INBOX_INFO`] has one: a name shouted on a
/// café's network must never collide with a handle a relay holds, and the two are
/// retired independently.
pub const DOOR_NAME_INFO: &[u8] = b"kotton:door-name:v1";

/// How long a door name lasts: one day. A name is also bound to the router, so a
/// recording made on another network, or on another day, shares nothing with it.
pub const DOOR_DAY_SECS: u64 = 86_400;

/// The day containing `unix_secs`, as a door name counts days.
pub fn door_day(unix_secs: u64) -> u64 {
    unix_secs / DOOR_DAY_SECS
}

/// The mDNS instance name **this device** announces under while its door is open,
/// so that `peer_ed_pub` — one of the person's own devices — recognises it.
///
/// ```text
/// shared = X25519(own_priv, peer_pub)
/// name   = hex(HKDF-SHA256(shared, DOOR_NAME_INFO ‖ day_be ‖ router ‖ publisher_pub)[..16])
/// ```
///
/// No hostname, DID, device name or stable address goes in, so nothing that comes
/// out can be joined to a device: a stranger sees 32 hex characters that change
/// with the network and the day. `router` is the opaque key the caller derives for
/// the network it is on; this function never learns what it names.
pub fn door_announce_name(
    own_signing_key: &SigningKey,
    peer_ed_pub: &[u8; 32],
    router: &[u8; 32],
    day: u64,
) -> Result<String> {
    let own_pub = own_signing_key.verifying_key().to_bytes();
    door_name(own_signing_key, peer_ed_pub, &own_pub, router, day)
}

/// The name `peer_ed_pub` announces under on `router` on `day` — what this device
/// looks for when it browses. The peer computes the same string with
/// [`door_announce_name`].
pub fn door_expect_name(
    own_signing_key: &SigningKey,
    peer_ed_pub: &[u8; 32],
    router: &[u8; 32],
    day: u64,
) -> Result<String> {
    door_name(own_signing_key, peer_ed_pub, peer_ed_pub, router, day)
}

/// Domain separator for the knock a contact puts on every datagram to a person's
/// door on the local network
/// (`TASK-a-contacts-message-can-reach-their-device-over-the-local-network-while-its-door-is-open`).
///
/// Its own separator, for the reason [`DOOR_NAME_INFO`] has one: a knock must never
/// equal a door name or a relay handle, and the three are retired independently.
pub const CONTACT_KNOCK_INFO: &[u8] = b"kotton:contact-knock:v1";

/// How long a knock is: 128 bits, which nobody on the network guesses.
pub const CONTACT_KNOCK_LEN: usize = 16;

/// The knock **this person's** door, opened under `nonce`, answers for the contact
/// `contact_ed_pub` in `epoch`, on the network keyed `router`.
///
/// ```text
/// shared = X25519(own_identity, contact_pub)
/// knock  = HKDF-SHA256(shared, CONTACT_KNOCK_INFO ‖ nonce ‖ epoch_be ‖ router ‖ door_owner_pub)[..16]
/// ```
///
/// The nonce is the door's: fresh each time the door opens and announced as its
/// only name, so a knock heard in one session is noise in the next. Only the two
/// people derive it, so a stranger's datagram carries no knock the door knows, and
/// a contact's knock names nobody to anyone listening.
pub fn contact_knock_to_open(
    own_identity: &SigningKey,
    contact_ed_pub: &[u8; 32],
    nonce: &[u8; 16],
    epoch: u64,
    router: &[u8; 32],
) -> Result<[u8; CONTACT_KNOCK_LEN]> {
    let own_pub = own_identity.verifying_key().to_bytes();
    contact_knock(own_identity, contact_ed_pub, &own_pub, nonce, epoch, router)
}

/// The knock this person puts on a dial to `their_ed_pub`'s door, announced under
/// `nonce` — what [`contact_knock_to_open`] computes on their side.
pub fn contact_knock_to_dial(
    own_identity: &SigningKey,
    their_ed_pub: &[u8; 32],
    nonce: &[u8; 16],
    epoch: u64,
    router: &[u8; 32],
) -> Result<[u8; CONTACT_KNOCK_LEN]> {
    contact_knock(own_identity, their_ed_pub, their_ed_pub, nonce, epoch, router)
}

fn contact_knock(
    own_identity: &SigningKey,
    peer_ed_pub: &[u8; 32],
    door_owner_pub: &[u8; 32],
    nonce: &[u8; 16],
    epoch: u64,
    router: &[u8; 32],
) -> Result<[u8; CONTACT_KNOCK_LEN]> {
    let own_x = ed25519_priv_to_x25519(own_identity);
    let peer_x: X25519PublicKey = ed25519_pub_to_x25519(peer_ed_pub)
        .context("contact knock: contact key is not a curve point")?;
    let shared = own_x.diffie_hellman(&peer_x);

    let mut info = Vec::with_capacity(CONTACT_KNOCK_INFO.len() + 16 + 8 + 32 + 32);
    info.extend_from_slice(CONTACT_KNOCK_INFO);
    info.extend_from_slice(nonce);
    info.extend_from_slice(&epoch.to_be_bytes());
    info.extend_from_slice(router);
    info.extend_from_slice(door_owner_pub);

    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut knock = [0u8; CONTACT_KNOCK_LEN];
    hk.expand(&info, &mut knock)
        .map_err(|_| anyhow::anyhow!("contact knock: HKDF expand failed"))?;
    Ok(knock)
}

fn door_name(
    own_signing_key: &SigningKey,
    peer_ed_pub: &[u8; 32],
    owner_ed_pub: &[u8; 32],
    router: &[u8; 32],
    day: u64,
) -> Result<String> {
    let own_x = ed25519_priv_to_x25519(own_signing_key);
    let peer_x: X25519PublicKey =
        ed25519_pub_to_x25519(peer_ed_pub).context("door name: peer key is not a curve point")?;
    let shared = own_x.diffie_hellman(&peer_x);

    let mut info = Vec::with_capacity(DOOR_NAME_INFO.len() + 8 + 32 + 32);
    info.extend_from_slice(DOOR_NAME_INFO);
    info.extend_from_slice(&day.to_be_bytes());
    info.extend_from_slice(router);
    info.extend_from_slice(owner_ed_pub);

    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut name = [0u8; 16];
    hk.expand(&info, &mut name)
        .map_err(|_| anyhow::anyhow!("door name: HKDF expand failed"))?;
    Ok(hex::encode(name))
}

/// Both directions in one place. The shared secret is symmetric; only the
/// owner's key in the `info` string tells the directions apart, and only the
/// domain separator tells the schemes apart.
fn derive(
    own_signing_key: &SigningKey,
    peer_ed_pub: &[u8; 32],
    owner_ed_pub: &[u8; 32],
    epoch: u64,
    domain_info: &[u8],
) -> Result<(Did, SigningKey)> {
    let own_x = ed25519_priv_to_x25519(own_signing_key);
    let peer_x: X25519PublicKey =
        ed25519_pub_to_x25519(peer_ed_pub).context("pair handle: peer key is not a curve point")?;
    let shared = own_x.diffie_hellman(&peer_x);

    let mut info = Vec::with_capacity(domain_info.len() + 8 + 32);
    info.extend_from_slice(domain_info);
    info.extend_from_slice(&epoch.to_be_bytes());
    info.extend_from_slice(owner_ed_pub);

    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut seed = [0u8; 32];
    hk.expand(&info, &mut seed)
        .map_err(|_| anyhow::anyhow!("pair handle: HKDF expand failed"))?;

    let signing_key = SigningKey::from_bytes(&seed);
    let did = DidKeyMethod::from_public_key(&signing_key.verifying_key());
    Ok((did, signing_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, Verifier};
    use rand::rngs::OsRng;

    fn pair() -> (SigningKey, SigningKey) {
        (
            SigningKey::generate(&mut OsRng),
            SigningKey::generate(&mut OsRng),
        )
    }

    /// **The constraint the whole design exists to preserve.** The relay verifies a
    /// push by extracting a key from the fingerprint, so a handle must be a DID
    /// whose key verifies the signature sent with it. An opaque handle would leave
    /// the relay unable to verify anything, and anyone free to publish a bogus
    /// address under anyone's handle.
    #[test]
    fn the_handle_verifies_its_own_signature() {
        let (a, b) = pair();
        let h = publish_handle(&a, &b.verifying_key().to_bytes(), 42).unwrap();

        let signature = h.signing_key.sign(b"addr=203.0.113.9:7700");

        // Exactly what the relay does: recover the key from the DID it was handed.
        let recovered = DidKeyMethod::to_public_key(&h.did).expect("handle is a did:key");
        assert!(recovered
            .verify(b"addr=203.0.113.9:7700", &signature)
            .is_ok());
    }

    /// The door's name: what A announces on a router today is what B expects, and
    /// a different router, a different day, or a different peer gives a name that
    /// shares nothing with it.
    #[test]
    fn a_door_name_is_recognised_by_the_pair_and_changes_with_router_and_day() {
        let (a, b) = pair();
        let (a_pub, b_pub) = (a.verifying_key().to_bytes(), b.verifying_key().to_bytes());
        let home = [7u8; 32];
        let cafe = [9u8; 32];

        let today = door_announce_name(&a, &b_pub, &home, 20_000).unwrap();
        assert_eq!(today, door_expect_name(&b, &a_pub, &home, 20_000).unwrap());
        assert_eq!(today.len(), 32, "16 bytes, hex: {today}");

        let elsewhere = door_announce_name(&a, &b_pub, &cafe, 20_000).unwrap();
        let tomorrow = door_announce_name(&a, &b_pub, &home, 20_001).unwrap();
        let (c, _) = pair();
        let other_peer =
            door_announce_name(&a, &c.verifying_key().to_bytes(), &home, 20_000).unwrap();
        for other in [&elsewhere, &tomorrow, &other_peer] {
            assert_ne!(&today, other);
        }
        // Directional, as a rendezvous handle is: B's own announcement is not A's.
        assert_ne!(today, door_announce_name(&b, &a_pub, &home, 20_000).unwrap());
    }

    /// The knock a contact dials with is the one the door opens for, and only in the
    /// session, epoch and network it was derived for: a new nonce, a new hour, another
    /// router, a third person, or the other direction each gives a knock that shares
    /// nothing with it.
    #[test]
    fn a_knock_is_the_pairs_alone_and_new_each_time_the_door_opens() {
        let (a, b) = pair();
        let (a_pub, b_pub) = (a.verifying_key().to_bytes(), b.verifying_key().to_bytes());
        let (home, cafe) = ([7u8; 32], [9u8; 32]);
        let (n1, n2) = ([1u8; 16], [2u8; 16]);

        let open = contact_knock_to_open(&a, &b_pub, &n1, 500, &home).unwrap();
        assert_eq!(open, contact_knock_to_dial(&b, &a_pub, &n1, 500, &home).unwrap());

        let (c, _) = pair();
        let others = [
            contact_knock_to_open(&a, &b_pub, &n2, 500, &home).unwrap(),
            contact_knock_to_open(&a, &b_pub, &n1, 501, &home).unwrap(),
            contact_knock_to_open(&a, &b_pub, &n1, 500, &cafe).unwrap(),
            contact_knock_to_open(&a, &c.verifying_key().to_bytes(), &n1, 500, &home).unwrap(),
            // B's own door, opened under the same nonce, is not A's.
            contact_knock_to_open(&b, &a_pub, &n1, 500, &home).unwrap(),
            // A third person dialling A's door cannot make B's knock.
            contact_knock_to_dial(&c, &a_pub, &n1, 500, &home).unwrap(),
        ];
        for other in others {
            assert_ne!(open, other);
        }
        // And it is not the door name for the same pair: separate separators.
        let name = door_announce_name(&a, &b_pub, &home, 500).unwrap();
        assert_ne!(hex::encode(open), name);
    }

    /// What A publishes under is what B looks up, with neither having sent anything.
    #[test]
    fn a_publishes_where_b_looks() {
        let (a, b) = pair();
        let (a_pub, b_pub) = (a.verifying_key().to_bytes(), b.verifying_key().to_bytes());

        assert_eq!(
            publish_handle(&a, &b_pub, 42).unwrap().did.to_string(),
            lookup_handle(&b, &a_pub, 42).unwrap().to_string()
        );
    }

    /// And symmetrically, so both directions of a pair work.
    #[test]
    fn b_publishes_where_a_looks() {
        let (a, b) = pair();
        let (a_pub, b_pub) = (a.verifying_key().to_bytes(), b.verifying_key().to_bytes());

        assert_eq!(
            publish_handle(&b, &a_pub, 42).unwrap().did.to_string(),
            lookup_handle(&a, &b_pub, 42).unwrap().to_string()
        );
    }

    /// Without the publisher's key in the derivation the handle is symmetric, both
    /// devices publish to one slot, and the second silently overwrites the first.
    #[test]
    fn the_two_directions_do_not_collide() {
        let (a, b) = pair();
        let (a_pub, b_pub) = (a.verifying_key().to_bytes(), b.verifying_key().to_bytes());

        assert_ne!(
            publish_handle(&a, &b_pub, 42).unwrap().did.to_string(),
            publish_handle(&b, &a_pub, 42).unwrap().did.to_string()
        );
    }

    /// The point of rotation: one epoch's handle says nothing about the next.
    #[test]
    fn a_new_epoch_is_a_new_handle() {
        let (a, b) = pair();
        let b_pub = b.verifying_key().to_bytes();

        assert_ne!(
            publish_handle(&a, &b_pub, 42).unwrap().did.to_string(),
            publish_handle(&a, &b_pub, 43).unwrap().did.to_string()
        );
    }

    /// One device's handles for two peers must differ, or the relay could group a
    /// device's peers together — which is the association graph again.
    #[test]
    fn a_different_peer_is_a_different_handle() {
        let (a, b) = pair();
        let c = SigningKey::generate(&mut OsRng);

        assert_ne!(
            publish_handle(&a, &b.verifying_key().to_bytes(), 42)
                .unwrap()
                .did
                .to_string(),
            publish_handle(&a, &c.verifying_key().to_bytes(), 42)
                .unwrap()
                .did
                .to_string()
        );
    }

    /// A handle must carry neither party's identity.
    #[test]
    fn a_handle_reveals_neither_identity() {
        let (a, b) = pair();
        let (a_pub, b_pub) = (a.verifying_key().to_bytes(), b.verifying_key().to_bytes());

        let h = publish_handle(&a, &b_pub, 42).unwrap().did.to_string();
        assert_ne!(h, DidKeyMethod::from_public_key(&a.verifying_key()).to_string());
        assert_ne!(h, DidKeyMethod::from_public_key(&b.verifying_key()).to_string());
        assert!(!h.contains(&hex::encode(a_pub)));
        assert!(!h.contains(&hex::encode(b_pub)));
    }

    /// Devices restart. A handle that changed within an epoch would be unfindable.
    #[test]
    fn a_handle_is_deterministic() {
        let (a, b) = pair();
        let b_pub = b.verifying_key().to_bytes();

        assert_eq!(
            publish_handle(&a, &b_pub, 42).unwrap().did.to_string(),
            publish_handle(&a, &b_pub, 42).unwrap().did.to_string()
        );
    }

    /// It must be a `did:key`, because that is what the relay parses.
    #[test]
    fn a_handle_is_a_did_key() {
        let (a, b) = pair();
        let h = publish_handle(&a, &b.verifying_key().to_bytes(), 42)
            .unwrap()
            .did
            .to_string();

        assert!(h.starts_with("did:key:z"), "not a did:key: {h}");
    }

    /// The shared secret is what authorises, and it never travels. A stranger
    /// holding both public keys and the epoch still cannot land on the handle.
    #[test]
    fn a_third_party_cannot_compute_the_pair_handle() {
        let (a, b) = pair();
        let eve = SigningKey::generate(&mut OsRng);
        let (a_pub, b_pub) = (a.verifying_key().to_bytes(), b.verifying_key().to_bytes());

        let real = publish_handle(&a, &b_pub, 42).unwrap().did.to_string();
        assert_ne!(lookup_handle(&eve, &a_pub, 42).unwrap().to_string(), real);
        assert_ne!(lookup_handle(&eve, &b_pub, 42).unwrap().to_string(), real);
    }

    // ── DM inbox addresses (step 7) ───────────────────────────────────────

    /// Where A queues a DM for B is exactly where B polls, nothing exchanged.
    #[test]
    fn a_queues_where_b_polls() {
        let (a, b) = pair();
        let (a_pub, b_pub) = (a.verifying_key().to_bytes(), b.verifying_key().to_bytes());

        assert_eq!(
            dm_inbox_target(&a, &b_pub, 42).unwrap().to_string(),
            dm_inbox_handle(&b, &a_pub, 42).unwrap().did.to_string()
        );
    }

    /// Each direction of a contact pair is its own mailbox: A's messages to B
    /// and B's messages to A never share an address.
    #[test]
    fn the_two_dm_directions_do_not_collide() {
        let (a, b) = pair();
        let (a_pub, b_pub) = (a.verifying_key().to_bytes(), b.verifying_key().to_bytes());

        assert_ne!(
            dm_inbox_handle(&a, &b_pub, 42).unwrap().did.to_string(),
            dm_inbox_handle(&b, &a_pub, 42).unwrap().did.to_string()
        );
    }

    /// An inbox address rotates like everything else here.
    #[test]
    fn a_new_epoch_is_a_new_inbox_address() {
        let (a, b) = pair();
        let b_pub = b.verifying_key().to_bytes();

        assert_ne!(
            dm_inbox_handle(&a, &b_pub, 42).unwrap().did.to_string(),
            dm_inbox_handle(&a, &b_pub, 43).unwrap().did.to_string()
        );
    }

    /// The schemes are domain-separated: the same pair, the same epoch, and the
    /// same owner still produce different identifiers for rendezvous and for the
    /// inbox — an operator cannot join the two surfaces on a shared label, and
    /// retiring one scheme cannot retire the other by accident.
    #[test]
    fn an_inbox_address_never_collides_with_a_rendezvous_handle() {
        let (a, b) = pair();
        let b_pub = b.verifying_key().to_bytes();

        assert_ne!(
            dm_inbox_handle(&a, &b_pub, 42).unwrap().did.to_string(),
            publish_handle(&a, &b_pub, 42).unwrap().did.to_string()
        );
    }

    /// The poll must be signable by the address's own key — the relay's `GET`
    /// auth requires the polling DID to equal the inbox DID.
    #[test]
    fn the_inbox_handle_verifies_its_own_signature() {
        let (a, b) = pair();
        let h = dm_inbox_handle(&a, &b.verifying_key().to_bytes(), 42).unwrap();

        let signature = h.signing_key.sign(b"poll");
        let recovered = DidKeyMethod::to_public_key(&h.did).expect("address is a did:key");
        assert!(recovered.verify(b"poll", &signature).is_ok());
    }

    /// A lookup spans the boundary, so a device a few minutes out still connects.
    #[test]
    fn a_lookup_spans_the_epoch_boundary() {
        let one_second_before_a_boundary = EPOCH_SECS * 100 - 1;
        let epochs = lookup_epochs(one_second_before_a_boundary);

        assert_eq!(epochs[0], 99, "current");
        assert_eq!(epochs[1], 98, "previous");
        assert_eq!(epochs[2], 100, "next — the one a fast clock already publishes in");
    }

    /// Epoch zero must not underflow into u64::MAX.
    #[test]
    fn the_first_epoch_has_no_previous() {
        assert_eq!(lookup_epochs(0), [0, 0, 1]);
    }
}
