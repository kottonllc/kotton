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
//! **A claimant has no name** (#511). A device admitted on a recovery claim holds no key a
//! door knows, so it is named by no key: [`Admits::by_claim`] answers with the identity whose
//! authority it proved, and that standing travels with the connection ([`Peer::Claim`]).
//! Nothing is written for it to a table shared across connections.
//!
//! [`HeldKeys`] answers it from what a door admits today: a live set of Ed25519 keys, and,
//! for a node that keeps identities' logs, the [`Admission`] that admits a recovered device by
//! the events it offers or a device that holds only a recovery authority by its claim.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};

use super::quic::tls::{Admission, Admitted};

/// Who a door's connection is from: a key it admitted, or a recovery claim's standing. Never
/// both, and a claimant is named by no key.
///
/// It is what a peer transport hands the handler for every request on the connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Peer {
    /// A key the connection admitted, as the transport names it: its `did:key`. (A QUIC
    /// connection that proved no key names its socket address here, and stands as a stranger.)
    Key(String),
    /// A device admitted on a recovery claim for the identity `aid`: it has proved that it holds
    /// a recovery authority `aid` committed, and nothing else about it is known.
    Claim { aid: String },
}

impl Peer {
    /// The key's `did:key`, where this is a key; a claimant has none.
    pub fn did(&self) -> Option<&str> {
        match self {
            Self::Key(did) => Some(did),
            Self::Claim { .. } => None,
        }
    }
}

/// Who a door admits. Every key here is 32 bytes; `initiator` is always the Montgomery form
/// the handshake delivered.
pub trait Admits: Send + Sync {
    /// The admitted key whose Montgomery form is `initiator`, by what the door holds. `None`
    /// where it holds none, or holds two with that one form: then neither is admitted.
    fn by_key(&self, initiator: &[u8; 32]) -> Option<[u8; 32]>;

    /// Asked for its events, the initiator answered with `events`, oldest first, each as the
    /// bytes it carries one in: the key they admit, if they admit the initiator.
    fn by_events(&self, initiator: &[u8; 32], events: &[Vec<u8>]) -> Option<[u8; 32]>;

    /// Asked for its events, the initiator answered with a recovery claim by `authority`
    /// whose tag the caller has already checked for this connection: the identity that
    /// committed that authority, if the door holds one. The claimant is named by no key, so
    /// none is returned (#511).
    fn by_claim(&self, authority: &[u8; 32]) -> Option<String>;
}

/// The Montgomery form of an Ed25519 key, or `None` where it is no point.
fn montgomery(ed: &[u8; 32]) -> Option<[u8; 32]> {
    kotton_crypto::x25519::ed25519_pub_to_x25519(ed)
        .ok()
        .map(|m| m.to_bytes())
}

/// The one key of `keys`, each beside its Montgomery form, whose form is `initiator`; none
/// where two are.
fn one_of<'a>(
    keys: impl IntoIterator<Item = (&'a [u8; 32], Option<[u8; 32]>)>,
    initiator: &[u8; 32],
) -> Option<[u8; 32]> {
    let mut found = None;
    for (key, form) in keys {
        if form.as_ref() == Some(initiator) {
            if found.is_some_and(|f| f != *key) {
                return None;
            }
            found = Some(*key);
        }
    }
    found
}

/// Each held key beside its Montgomery form, `None` where it is no point.
type Forms = HashMap<[u8; 32], Option<[u8; 32]>>;

/// What a door admits today: a live set of Ed25519 keys, consulted at every connection, and
/// the admission a node that keeps identities' logs holds.
///
/// A device's door holds its paired devices' keys and its node's admission; a contact's door
/// holds the one key the pair derives for the initiator this hour, and an empty admission.
#[derive(Clone, Debug)]
pub struct HeldKeys {
    keys: Arc<RwLock<HashSet<[u8; 32]>>>,
    /// Each held key's Montgomery form, made once per key rather than at every connection.
    /// Entries for keys no longer held are let go the next time a key is added.
    forms: Arc<Mutex<Forms>>,
    admission: Admission,
}

impl HeldKeys {
    pub fn new(keys: Arc<RwLock<HashSet<[u8; 32]>>>, admission: Admission) -> Self {
        Self {
            keys,
            forms: Arc::default(),
            admission,
        }
    }

    /// The set alone, and no admission by events or claim.
    pub fn only(keys: Arc<RwLock<HashSet<[u8; 32]>>>) -> Self {
        Self::new(keys, Admission::default())
    }
}

impl Admits for HeldKeys {
    fn by_key(&self, initiator: &[u8; 32]) -> Option<[u8; 32]> {
        let keys = self.keys.read().unwrap();
        let mut forms = self.forms.lock().unwrap();
        for key in keys.iter() {
            forms.entry(*key).or_insert_with(|| montgomery(key));
        }
        if forms.len() > keys.len() {
            forms.retain(|k, _| keys.contains(k));
        }
        one_of(keys.iter().map(|k| (k, forms.get(k).copied().flatten())), initiator)
    }

    fn by_events(&self, initiator: &[u8; 32], events: &[Vec<u8>]) -> Option<[u8; 32]> {
        // Each event's JSON until step 1 of #496 gives events their binary form (#512); step 1
        // replaces this decoding.
        let offered: Vec<kotton_wire::kel::KelEvent> = events
            .iter()
            .map(|e| serde_json::from_slice(e).ok())
            .collect::<Option<_>>()?;
        let aid = offered.first()?.aid.to_string();
        let tip = self.admission.tips.read().unwrap().get(&aid).cloned()?;
        // The candidate is taken from the offered events' keys, not from a set the door holds.
        // That is equivalent to asking for the key the events admit: `admits_device` below
        // replays the events from the door's own tip and accepts only where the key state they
        // end on is exactly `key`, so a key some event names but the replay does not end on is
        // refused there. And `key` is the one whose Montgomery form the handshake proved the
        // initiator holds; none where two offered keys share that form.
        let key = one_of(
            offered
                .iter()
                .map(|e| (&e.key_state.group_key, montgomery(&e.key_state.group_key))),
            initiator,
        )?;
        kotton_crypto::kel_verify::admits_device(
            &tip,
            &offered,
            &key,
            &kotton_crypto::kel_verify::LocalArbiter,
            false,
        )
        .ok()?;
        // Decided here; written down by the handler, which holds the database. The key is the
        // device's own, which the events name and the handshake proved.
        self.admission
            .admitted
            .write()
            .unwrap()
            .insert(key, Admitted::ByProof { aid, events: offered });
        Some(key)
    }

    fn by_claim(&self, authority: &[u8; 32]) -> Option<String> {
        self.admission.authorities.read().unwrap().get(authority).cloned()
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

    /// The forms are kept beside the live set: a key added is found at the next connection,
    /// and one removed is found no longer.
    #[test]
    fn the_kept_forms_follow_the_live_set() {
        let set = Arc::new(RwLock::new(HashSet::from([key(1)])));
        let held = HeldKeys::only(Arc::clone(&set));
        assert_eq!(held.by_key(&montgomery(&key(1)).unwrap()), Some(key(1)));
        set.write().unwrap().insert(key(2));
        assert_eq!(held.by_key(&montgomery(&key(2)).unwrap()), Some(key(2)));
        set.write().unwrap().remove(&key(1));
        assert_eq!(held.by_key(&montgomery(&key(1)).unwrap()), None);
        set.write().unwrap().insert(key(3));
        assert_eq!(held.by_key(&montgomery(&key(3)).unwrap()), Some(key(3)));
        assert_eq!(held.forms.lock().unwrap().len(), 2, "the removed key's form is let go");
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
        assert_eq!(held.by_claim(&key(5)), None);
    }
}
