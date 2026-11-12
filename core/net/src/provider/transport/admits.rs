// SPDX-License-Identifier: AGPL-3.0-or-later
//! Who a door admits: the one question a responder asks once the handshake has shown it the
//! initiator's static key (kotton-protocol's *One handshake admits a device, by the identity's
//! log*).
//!
//! The handshake delivers the initiator's key in its Montgomery form, and proves the initiator
//! holds it. What a responder does with that is [`Admits`]: it takes the initiator's Ed25519
//! key to be the one, among the keys it admits there, whose Montgomery form that is. Where it
//! holds none, it asks for the initiator's events, and the frame that answers carries events or
//! a recovery claim; each is put to the same trait. Whatever the answer is, the circuit closes
//! the same way on a refusal, and nothing here writes a line about who was refused.
//!
//! [`HeldKeys`] answers it from what a door admits today: a live set of Ed25519 keys, and,
//! for a node that keeps identities' logs, the [`Admission`] that admits a recovered device by
//! the events it offers or a device that holds only a recovery authority by its claim.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use super::quic::tls::{Admission, Admitted};

/// Who a door admits. Every key here is 32 bytes; `initiator` is always the Montgomery form
/// the handshake delivered, and each answer is the Ed25519 key the initiator is known by.
pub trait Admits: Send + Sync {
    /// The admitted key whose Montgomery form is `initiator`, by what the door holds. `None`
    /// where it holds none, or holds two with that one form: then neither is admitted.
    fn by_key(&self, initiator: &[u8; 32]) -> Option<[u8; 32]>;

    /// Asked for its events, the initiator answered with `events`, oldest first, each as the
    /// bytes it carries one in: the key they admit, if they admit the initiator.
    fn by_events(&self, initiator: &[u8; 32], events: &[Vec<u8>]) -> Option<[u8; 32]>;

    /// Asked for its events, the initiator answered with a recovery claim by `authority`
    /// whose tag the caller has already checked for this connection: the key the initiator
    /// is known by, if the door holds an identity that committed that authority.
    fn by_claim(&self, initiator: &[u8; 32], authority: &[u8; 32]) -> Option<[u8; 32]>;
}

/// The Montgomery form of an Ed25519 key, or `None` where it is no point.
fn montgomery(ed: &[u8; 32]) -> Option<[u8; 32]> {
    kotton_crypto::x25519::ed25519_pub_to_x25519(ed)
        .ok()
        .map(|m| m.to_bytes())
}

/// The one key of `keys` whose Montgomery form is `initiator`; none where two are.
fn one_of<'a>(keys: impl IntoIterator<Item = &'a [u8; 32]>, initiator: &[u8; 32]) -> Option<[u8; 32]> {
    let mut found = None;
    for key in keys {
        if montgomery(key).as_ref() == Some(initiator) {
            if found.is_some_and(|f| f != *key) {
                return None;
            }
            found = Some(*key);
        }
    }
    found
}

/// What a door admits today: a live set of Ed25519 keys, consulted at every connection, and
/// the admission a node that keeps identities' logs holds.
///
/// A device's door holds its paired devices' keys and its node's admission; a contact's door
/// holds the one key the pair derives for the initiator this hour, and an empty admission.
#[derive(Clone, Debug)]
pub struct HeldKeys {
    keys: Arc<RwLock<HashSet<[u8; 32]>>>,
    admission: Admission,
}

impl HeldKeys {
    pub fn new(keys: Arc<RwLock<HashSet<[u8; 32]>>>, admission: Admission) -> Self {
        Self { keys, admission }
    }

    /// The set alone, and no admission by events or claim.
    pub fn only(keys: Arc<RwLock<HashSet<[u8; 32]>>>) -> Self {
        Self::new(keys, Admission::default())
    }
}

impl Admits for HeldKeys {
    fn by_key(&self, initiator: &[u8; 32]) -> Option<[u8; 32]> {
        one_of(self.keys.read().unwrap().iter(), initiator)
    }

    fn by_events(&self, initiator: &[u8; 32], events: &[Vec<u8>]) -> Option<[u8; 32]> {
        let offered: Vec<kotton_wire::kel::KelEvent> = events
            .iter()
            .map(|e| serde_json::from_slice(e).ok())
            .collect::<Option<_>>()?;
        let aid = offered.first()?.aid.to_string();
        let tip = self.admission.tips.read().unwrap().get(&aid).cloned()?;
        let key = one_of(offered.iter().map(|e| &e.key_state.group_key), initiator)?;
        kotton_crypto::kel_verify::admits_device(
            &tip,
            &offered,
            &key,
            &kotton_crypto::kel_verify::LocalArbiter,
            false,
        )
        .ok()?;
        // Decided here; written down by the handler, which holds the database.
        self.admission
            .admitted
            .write()
            .unwrap()
            .insert(key, Admitted::ByProof { aid, events: offered });
        Some(key)
    }

    fn by_claim(&self, initiator: &[u8; 32], authority: &[u8; 32]) -> Option<[u8; 32]> {
        let aid = self.admission.authorities.read().unwrap().get(authority).cloned()?;
        let key = kotton_crypto::x25519::x25519_pub_to_ed25519(initiator)?;
        self.admission
            .admitted
            .write()
            .unwrap()
            .insert(key, Admitted::ByClaim { aid });
        Some(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn key(n: u8) -> [u8; 32] {
        SigningKey::from_bytes(&[n; 32]).verifying_key().to_bytes()
    }

    /// The responder names the initiator by the key it holds whose Montgomery form the
    /// handshake delivered, and by no other.
    #[test]
    fn a_held_key_is_found_by_its_montgomery_form() {
        let held = HeldKeys::only(Arc::new(RwLock::new(HashSet::from([key(1), key(2)]))));
        assert_eq!(held.by_key(&montgomery(&key(2)).unwrap()), Some(key(2)));
        assert_eq!(held.by_key(&montgomery(&key(3)).unwrap()), None);
    }

    /// A key and its negation have one Montgomery form; a door that holds both admits
    /// neither, since it could not say which the initiator is.
    #[test]
    fn two_held_keys_with_one_montgomery_form_admit_neither() {
        use curve25519_dalek::edwards::CompressedEdwardsY;
        let k = key(1);
        let negated = (-CompressedEdwardsY(k).decompress().unwrap()).compress().to_bytes();
        assert_eq!(montgomery(&k), montgomery(&negated));
        let held = HeldKeys::only(Arc::new(RwLock::new(HashSet::from([k, negated]))));
        assert_eq!(held.by_key(&montgomery(&k).unwrap()), None);
    }

    /// Events that are not events, and a claim by an authority no held identity committed,
    /// admit nobody.
    #[test]
    fn nothing_offered_by_a_stranger_admits_it() {
        let held = HeldKeys::only(Arc::new(RwLock::new(HashSet::new())));
        let initiator = montgomery(&key(4)).unwrap();
        assert_eq!(held.by_events(&initiator, &[b"not an event".to_vec()]), None);
        assert_eq!(held.by_events(&initiator, &[]), None);
        assert_eq!(held.by_claim(&initiator, &key(5)), None);
    }
}
