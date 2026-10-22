// SPDX-License-Identifier: AGPL-3.0-or-later
//! The relay admission keys a device holds, by relay: a device presents its
//! relay's admission tag, and the reach row sets the rule.
//!
//! A relay whose operator narrowed its rule admits a request only with a tag
//! under a key it reads (`kotton_net::rendezvous::AdmissionKey`). Every place
//! this device makes a reservation, opens a circuit, looks up an address or
//! pushes one asks this keyring for the key it holds for **that** relay, and
//! presents a tag under it. A device holding no key for a relay presents none,
//! which a relay admitting anyone does not ask for.
//!
//! **Where the keys come from, and nothing else puts them here:**
//!
//! - the operator's own desktop, which minted them and keeps them sealed
//!   beside the operator credential (`kuserd`'s `agent::operator`);
//! - another of the operator's own devices, in its answer to `NodeRelay`
//!   ([`RelayAdmission`] with an `offer`) — and only one whose paired row this
//!   device recorded as *full* ([`offers_from`]);
//! - a vault, to its tenant, in its answer to `NodeRelay` (the *invited* key,
//!   no `offer`);
//! - a relay's invite, which the person stood this device there with — kept
//!   sealed in their store by `kuserd` and held again from it after a restart
//!   ([`RelayKeyring::hold_invited`]).
//!
//! A contact's key for their operator's relay rides on the card, in the reach
//! note, and is read from there at delivery; it is not copied here, so it is
//! never handed on to this person's own devices as if it were theirs.
//!
//! **Held in memory only.** Nothing here is written to disk: the desktop's
//! sealed record is the durable copy, and every other holder learns its key
//! again at its next connect. Two tiers, and *mine* is never replaced by
//! *invited*: an operator's device that is also a tenant of its own vault keeps
//! presenting the key its own rule reads under *only my devices* — at its own
//! relay, *mine* is chosen before anything its vault handed it
//! ([`RelayKeyring::at_supplied_address`], and for a relayed dial
//! [`RelayKeyring::dialing_supplied_address`]).
//!
//! **Its own relay is read from its own records, and there are two**: the
//! relay this device stands at (`config relay set`), and every relay its
//! person operates, at the address their sealed operator credential names
//! ([`RelayKeyring::hold_as_operator`]). An operator's desktop need not stand
//! at the relay it operates to be that relay's operator's device: taking its
//! own vault's offer meets the vault at that relay, and the relay's *only my
//! devices* reads *mine* there.

use kotton_net::rendezvous::AdmissionKey;
use kotton_schemas::membership::Posture;
use kotton_wire::ipc::SecretText;
use kotton_wire::peer::PairedNode;
use kotton_wire::rendezvous::RelayAdmission;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Which key a device presents at a relay, and where it came from. Ordered:
/// a key of a higher rank is never replaced by one of a lower.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// The key the people an operator invites hold, learned from a paired
    /// node's answer.
    Invited,
    /// The operator's own devices' key, learned from another of that person's
    /// devices.
    LearnedMine,
    /// The operator's own devices' key, from the sealed record this device
    /// keeps itself. Nothing a peer answers replaces it.
    KeptMine,
}

/// What this device holds for one person at one relay.
#[derive(Clone, Debug, Default)]
pub struct RelayKeys {
    /// The key presented there, and which one it is.
    pub present: Option<(AdmissionKey, Tier)>,
    /// The *invited* key, held only as one of the relay's operator's own
    /// devices — what their reach note hands their contacts, and what they hand
    /// another of their own devices. Never set from an invitee's answer.
    pub offer: Option<AdmissionKey>,
    /// The address the person's own operator record names for this relay,
    /// when the keys are held as its operator from that record
    /// ([`RelayKeyring::hold_as_operator`]). An address there is this person's
    /// own relay by their own record, as the relay this device stands at is.
    /// Never set from anything a peer, a contact or an invite said.
    pub operated_at: Option<String>,
}

/// What a device presented at a relay, by kind and never by key: what it can
/// say of a refusal there from its own knowledge, since the relay answers every
/// refusal with one `403` and says nothing more ([`RefusedAtTheRelay`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Presented {
    /// No key: none of this device's own was chosen for the address dialled,
    /// and none was handed. Says nothing of what the device holds for the
    /// relay elsewhere: at an address another party supplied, its own keys are
    /// never presented.
    Nothing,
    /// The key another party's code handed for this one dial — a vault's
    /// invite carries the relay's *invited* key.
    Handed,
    /// A key this device holds for the relay, of this tier.
    Held(Tier),
}

/// The key a dial or a reservation presents at a relay, with what it is
/// ([`Presented`]): one value, so what is presented and what is said of it
/// cannot disagree.
#[derive(Clone, Debug)]
pub struct Presenting {
    key: Option<AdmissionKey>,
    what: Presented,
}

impl Presenting {
    /// The key another party handed for this dial, or nothing when it handed
    /// none.
    pub fn handed(key: Option<AdmissionKey>) -> Self {
        let what = if key.is_some() { Presented::Handed } else { Presented::Nothing };
        Self { key, what }
    }

    /// A key this device holds, of its tier, or nothing when it holds none.
    pub fn held(held: Option<(AdmissionKey, Tier)>) -> Self {
        match held {
            Some((key, tier)) => Self { key: Some(key), what: Presented::Held(tier) },
            None => Self::handed(None),
        }
    }

    /// The key presented, if any.
    pub fn key(&self) -> Option<&AdmissionKey> {
        self.key.as_ref()
    }

    /// The key presented, if any, taken.
    pub fn into_key(self) -> Option<AdmissionKey> {
        self.key
    }

    /// What was presented.
    pub fn what(&self) -> Presented {
        self.what
    }
}

/// Which first contact a relay refused: what was being met there, so the
/// person can be told which invite admits them at that relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirstContact {
    /// An admit by a vault's invite, at the relay the invite names.
    VaultInvite,
    /// A contact's spoken code, at the relay this device stands at.
    SpokenCode,
}

/// A relay refused, at its door, what this device presented on a first-contact
/// dial or reservation: the `403` it answers every refusal with. Typed, so the
/// dial that met it stops at once instead of waiting for the other side, and
/// the person is told from this device's own knowledge what it presented there
/// and which invite admits it.
///
/// It says the relay *refused*, never what the relay's rule is: the answer is
/// an unsigned HTTP status that a proxy in front of the relay, or anything on
/// the path, could give as well, as decision 0006 reads a relay's `403` for
/// forget.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefusedAtTheRelay {
    /// The relay's address, as it was dialled.
    pub url: String,
    /// What this device presented there.
    pub presented: Presented,
    /// What was being met there.
    pub meeting: FirstContact,
}

impl RefusedAtTheRelay {
    /// `e` as a refusal at the door of the relay at `url`, if it is one: the
    /// variant a `403` at the WebSocket upgrade comes back as
    /// (`kotton_net::transport::rendezvous_dial` and `rendezvous_reserve`), and
    /// no other. Every other failure is not a refusal, and is `None`.
    pub fn of(
        e: &kotton_sys::net::TransportError,
        url: &str,
        presenting: &Presenting,
        meeting: FirstContact,
    ) -> Option<Self> {
        matches!(e, kotton_sys::net::TransportError::AuthenticationFailed(_)).then(|| Self {
            url: url.to_string(),
            presented: presenting.what(),
            meeting,
        })
    }
}

impl std::fmt::Display for RefusedAtTheRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let what = match self.presented {
            Presented::Nothing => "no key",
            Presented::Handed => "the key the invite handed",
            Presented::Held(Tier::Invited) => "invited",
            Presented::Held(Tier::LearnedMine) => "mine, learned",
            Presented::Held(Tier::KeptMine) => "mine, kept",
        };
        write!(f, "the relay at {} refused what this device presented there ({what}) — nothing was shared", self.url)
    }
}

impl std::error::Error for RefusedAtTheRelay {}

/// A relay as this keyring names it: the key it proved, 32 bytes.
/// Never its address — two spellings of one address are one relay, one relay at
/// a new address is the same relay, and nothing here compares URLs.
pub type RelayId = [u8; 32];

/// A relay's key as the wire and the device's configuration spell it — 64 hex —
/// read as a [`RelayId`]; `None` for no key, or text that is not one. A relay
/// recorded with no key has no slot here, so nothing is held or presented for it.
pub fn relay_id(hex_key: Option<&str>) -> Option<RelayId> {
    hex::decode(hex_key?.trim()).ok()?.try_into().ok()
}

/// Every relay key this device holds, **by person and by relay**. Cloning
/// shares.
///
/// By person because a device can serve more than one, and a key is one
/// person's: what one person's note offers, what one person's own devices are
/// handed and what one person's deliveries present are read for that person
/// alone ([`Self::present_for`], [`Self::offer_for`], [`Self::for_own_device`]).
/// The device's own reservations, presence and relayed dials are the
/// machine's reach and present any key it holds for the relay
/// ([`Self::present_at`]) — a relay learns only which tier, never whose.
///
/// By relay means by the relay's key ([`RelayId`]). Whoever holds keys for a
/// relay and whoever presents them there meet at the key the relay proved, so a
/// relay's URL typed one way at `enrol` and another at `config relay set`
/// is still one relay; and a relay nobody recorded a key for has no slot.
#[derive(Clone, Default)]
pub struct RelayKeyring {
    held: Arc<RwLock<HashMap<(String, RelayId), RelayKeys>>>,
    /// What each paired node told a person about the relay it reserves at,
    /// kept per (person, node): the relay's key, the address it named, and the
    /// admission key **that node handed over**, if any. A relayed dial to that
    /// node, at that address, presents that key and no other
    /// ([`Self::present_for_peer`]) — the reach rule: *mine*, and any key this person holds as their
    /// own, is never selected by anything a peer said.
    reached_by: Arc<RwLock<HashMap<Reach, PeerRelay>>>,
}

/// One node's answer about where it reserves, as [`RelayKeyring::learn_proven`] kept it.
#[derive(Clone)]
struct PeerRelay {
    relay: RelayId,
    url: String,
    /// The key that node handed this person to present at its relay.
    handed: Option<AdmissionKey>,
}

/// Whose answer, from which node: a person, and the node's public key.
type Reach = (String, [u8; 32]);

impl std::fmt::Debug for RelayKeyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RelayKeyring(<redacted>)")
    }
}

/// The choice behind [`RelayKeyring::at_supplied_address`] and
/// [`RelayKeyring::dialing_supplied_address`]: at this device's own relay by
/// its own record — the relay it stands at, `own_url` and `own_relay`, or a
/// relay its person operates at the address their credential names,
/// `operated` — `own` of its key before what was `handed`; anywhere else, what
/// was `handed` and nothing of this device's.
fn supplied(
    dialing: &str,
    handed: Option<AdmissionKey>,
    own_url: &str,
    own_relay: Option<&RelayId>,
    operated: Option<RelayId>,
    own: impl Fn(&RelayId) -> Option<(AdmissionKey, Tier)>,
) -> Presenting {
    let stood = own_relay.filter(|_| kotton_schemas::membership::same_relay_address(dialing, own_url)).copied();
    match stood.into_iter().chain(operated).find_map(|r| own(&r)) {
        Some(held) => Presenting::held(Some(held)),
        None => Presenting::handed(handed),
    }
}

/// Whether a paired node whose row records `posture` (its text,
/// [`PairedNode::posture`]) is one an `offer` is learned from: one of the
/// person's own devices that holds their keys — *full*, or a row recorded
/// before postures were, which is one (the issuer of the device it enrolled is
/// written so). Any other text is not, a posture this build does not recognise
/// included. The same rule `kuserd`'s `NodeRelay` arm answers by, read from the
/// other end: it hands an `offer` only to an asker whose row says `full` or
/// nothing, and a vault hands none to anyone, so an `offer` from a cosigner or a
/// blind storage is a false answer — and either may be a host's machine.
pub fn offers_from(posture: Option<impl AsRef<str>>) -> bool {
    match posture {
        None => true,
        Some(p) => p.as_ref() == Posture::Full.as_str(),
    }
}

fn slot(user: &str, relay: &RelayId) -> (String, RelayId) {
    (user.to_string(), *relay)
}

impl RelayKeyring {
    /// The key this machine presents at `relay` for its own reach: the
    /// highest-ranked any person here holds for it.
    pub fn present_at(&self, relay: &RelayId) -> Option<AdmissionKey> {
        self.presented_at(relay).map(|(key, _)| key)
    }

    /// [`Self::present_at`], with the tier of the key it chose.
    pub fn presented_at(&self, relay: &RelayId) -> Option<(AdmissionKey, Tier)> {
        self.held
            .read()
            .unwrap()
            .iter()
            .filter(|((_, r), _)| r == relay)
            .filter_map(|(_, k)| k.present.clone())
            .max_by_key(|(_, tier)| *tier)
    }

    /// The key `user` presents at `relay`, if they hold one.
    pub fn present_for(&self, user: &str, relay: &RelayId) -> Option<AdmissionKey> {
        self.at(user, relay).present.map(|(key, _)| key)
    }

    /// Everything held for `user` at `relay`.
    pub fn at(&self, user: &str, relay: &RelayId) -> RelayKeys {
        self.held.read().unwrap().get(&slot(user, relay)).cloned().unwrap_or_default()
    }

    /// Hold both keys as `user`'s, the relay's operator, from the sealed
    /// record this device keeps (or, on a vault, from what its operator told
    /// it): present *mine*, offer *invited*. Replaces what was held, which is
    /// how a rotation reaches this device.
    ///
    /// `at` is the address the operator credential for the relay names, when
    /// the record is the person's own credential: there, a dial or a delivery
    /// to an address another party supplied is at this person's own relay by
    /// their own record ([`Self::at_supplied_address`],
    /// [`Self::dialing_supplied_address`]), whether or not this device stands
    /// at it. `None` holds the keys without making any address own.
    pub fn hold_as_operator(&self, user: &str, relay: &RelayId, at: Option<&str>, mine: AdmissionKey, invited: AdmissionKey) {
        self.held.write().unwrap().insert(
            slot(user, relay),
            RelayKeys {
                present: Some((mine, Tier::KeptMine)),
                offer: Some(invited),
                operated_at: at.map(str::to_string),
            },
        );
    }

    /// The relay whose operator record names `dialing` as its address — held
    /// by `user` alone, or by anyone on this machine for `None` — if any.
    fn operated_at(&self, user: Option<&str>, dialing: &str) -> Option<RelayId> {
        self.held
            .read()
            .unwrap()
            .iter()
            .filter(|((u, _), _)| user.is_none_or(|user| u == user))
            .find(|(_, k)| {
                k.operated_at.as_deref().is_some_and(|at| kotton_schemas::membership::same_relay_address(dialing, at))
            })
            .map(|((_, r), _)| *r)
    }

    /// Hold `invited` for `user` to present at `relay`: the key a relay's
    /// invite carried, which `user` stood this device there with (kept sealed
    /// in their store and held again from it after a restart).
    /// Never replaces a key of a higher tier, so an operator's *mine* stays.
    pub fn hold_invited(&self, user: &str, relay: &RelayId, invited: AdmissionKey) {
        self.hold(user, relay, invited, Tier::Invited, None);
    }

    /// Forget everything `user` holds at `relay` — the operator credential that
    /// was their record of it is forgotten (`relay forget`): its address is no
    /// longer their own, *mine* is no longer presented there, and *invited* is
    /// no longer offered. Nothing of anyone else's, and nothing at another relay,
    /// changes. A key this device keeps for the relay on another record — an
    /// invite the person stood here with — is the caller's to hold again.
    pub fn release(&self, user: &str, relay: &RelayId) {
        self.held.write().unwrap().remove(&slot(user, relay));
    }

    /// Forget everything `user` holds at every relay — a vault told a new reach
    /// set drops the keys of the relays it no longer stands at.
    pub fn forget(&self, user: &str) {
        self.held.write().unwrap().retain(|(u, _), _| u != user);
    }

    /// Hold `key` for `user` to present at `relay` as `tier`, and `offer`
    /// with it. Refused — nothing changes — when a key of a higher tier is
    /// held; the same tier replaces it (a rotation).
    fn hold(&self, user: &str, relay: &RelayId, key: AdmissionKey, tier: Tier, offer: Option<AdmissionKey>) {
        let mut held = self.held.write().unwrap();
        let entry = held.entry(slot(user, relay)).or_default();
        if matches!(&entry.present, Some((_, have)) if *have > tier) {
            return;
        }
        entry.present = Some((key, tier));
        if tier >= Tier::LearnedMine {
            entry.offer = offer;
        }
    }

    /// Learn what the paired node `node` answered `user`'s connect to
    /// `NodeRelay` — the relay it reserves at, by that relay's key `relay` and
    /// the address `url` — **once the relay at `url` has proved `relay`**
    /// ([`crate::relay_key::prove_relay`], with `relay` expected). Answers
    /// whether it was learned. What the node *is* is read from the node the
    /// connect dialled, its key and its recorded posture together, so nothing
    /// between the dial and the fold can weigh one node's answer as another's.
    ///
    /// The proof is what makes the answer safe to act on. A paired node — a
    /// vault someone else runs, say — could otherwise name *this device's own*
    /// relay's key beside an address of its choosing, and the next relayed dial
    /// to it would present this device's *mine* there. At `url` it cannot sign
    /// for a key it does not hold, so it teaches nothing: no key is held under
    /// its word, and no address is recorded to dial with one. A relay that does
    /// not answer who it is teaches nothing either — the next connect asks again.
    pub async fn learn_proven(
        &self,
        user: &str,
        node: &PairedNode,
        url: &str,
        relay: &RelayId,
        admission: Option<&RelayAdmission>,
    ) -> bool {
        match crate::relay_key::prove_relay(url, Some(relay)).await {
            Ok(Some(proved)) if proved == *relay => {
                self.learn(user, &node.public_key, node.posture.as_deref(), url, relay, admission);
                true
            }
            other => {
                tracing::info!(url, answer = ?other.err(), "a paired node named a relay its address did not prove; nothing learned");
                false
            }
        }
    }

    /// [`Self::learn_proven`]'s second half, once the proof holds. An answer
    /// with an `offer` came from one of the operator's own devices, and its
    /// `present` is *mine*; one without is an invitee's. Neither replaces a key
    /// this device keeps itself, so a peer that answers falsely cannot take its
    /// place. A key that does not parse teaches nothing.
    ///
    /// **An `offer` is learned only from a node of `posture` that holds the
    /// person's keys** ([`offers_from`]). From a cosigner or a blind storage an
    /// answer carrying one is a false answer, and its admission teaches nothing
    /// at all — not *mine*, not the offer, not even *invited* in their place,
    /// and no key for a relayed dial to it — so it changes nothing this device
    /// presents or offers, whatever it held before. Its relay is still learned,
    /// as from an answer with no key. An answer with no `offer` is an invitee's
    /// from any posture: a vault hands its tenant *invited* that way.
    fn learn(
        &self,
        user: &str,
        node: &[u8; 32],
        posture: Option<&str>,
        url: &str,
        relay: &RelayId,
        admission: Option<&RelayAdmission>,
    ) {
        let admission = admission.filter(|a| {
            let honest = a.offer.is_none() || offers_from(posture);
            if !honest {
                tracing::warn!(?posture, "a paired node that is no full device of this person's offered a relay key; nothing learned");
            }
            honest
        });
        let present = admission.and_then(|a| {
            let k = AdmissionKey::parse(a.present.expose());
            if k.is_none() {
                tracing::warn!("a paired node handed an admission key that is not one; ignored");
            }
            k
        });
        self.reached_by.write().unwrap().insert(
            (user.to_string(), *node),
            PeerRelay { relay: *relay, url: url.to_string(), handed: present.clone() },
        );
        let (Some(admission), Some(present)) = (admission, present) else { return };
        match admission.offer.as_ref().and_then(|o| AdmissionKey::parse(o.expose())) {
            Some(offer) => self.hold(user, relay, present, Tier::LearnedMine, Some(offer)),
            None => self.hold(user, relay, present, Tier::Invited, None),
        }
    }

    /// The relay `node` last told `user` it reserves at, by its key, when
    /// `dialing` is the address it named with it. A readout: nothing presents a
    /// key through this.
    pub fn relay_of(&self, user: &str, node: &[u8; 32], dialing: &str) -> Option<RelayId> {
        self.peer(user, node, dialing).map(|p| p.relay)
    }

    /// The address `node` last told `user` it reserves at, once the relay there
    /// proved the key `node` named beside it. A readout, by node and not by
    /// address: the person's reach note keeps the relay another of their own
    /// devices put there through a renewal on this one
    /// (`kotton_device::users::reach::relays_to_list`). Nothing presents a key
    /// through this, and it is held in memory only, so it is empty for a node
    /// this device has not reached since it started.
    pub fn told_relay(&self, user: &str, node: &[u8; 32]) -> Option<String> {
        self.reached_by.read().unwrap().get(&(user.to_string(), *node)).map(|p| p.url.clone())
    }

    /// The key to present on a relayed dial to `node` at `dialing` — the
    /// address `node` named as its relay: exactly the key **`node` handed
    /// `user`** with that answer, and nothing else. Never the keyring-wide
    /// ranking ([`Self::present_at`]): an address a peer supplied is not a
    /// place this person's own keys go, whatever relay key the peer named
    /// beside it and whatever that address proves (a forwarder in front of this
    /// person's own relay proves that relay's key). A node that handed no key,
    /// or an address it did not name, gets none.
    pub fn present_for_peer(&self, user: &str, node: &[u8; 32], dialing: &str) -> Option<AdmissionKey> {
        self.peer(user, node, dialing).and_then(|p| p.handed)
    }

    /// **The one choice of what to present at an address a peer or a contact
    /// supplied** — a paired node's relay, a contact's note — for `user`'s
    /// contact delivery; a relayed dial is the machine's reach and reads
    /// [`Self::dialing_supplied_address`]. Every path driven by what another
    /// party said goes through one of the two.
    ///
    /// The rule: **nothing a peer or a contact says selects this person's own
    /// keys.** Whether `dialing` is this device's own relay is read from this
    /// device's own records — `own_url` and `own_relay`, the address and key the
    /// person named at `config relay set`, and the address each of `user`'s
    /// operator credentials names for the relay it operates
    /// ([`Self::hold_as_operator`]) — never from a relay key the other
    /// party wrote beside the address. There, the key `user` holds for it is
    /// presented, and what the other party handed only when `user` holds none:
    /// an operator's device that is also a tenant of its own vault is handed
    /// *invited*, and its own rule reads *mine*: the supplied-address check
    /// never refuses the person at their own relay.
    /// Anywhere else, what that party `handed` over for its own relay is
    /// presented, and only at the address it came with; an address that is not
    /// this device's own relay is handed nothing of this person's, whatever key
    /// it was labelled with and whatever it proves.
    pub fn at_supplied_address(
        &self,
        user: &str,
        dialing: &str,
        handed: Option<AdmissionKey>,
        own_url: &str,
        own_relay: Option<&RelayId>,
    ) -> Option<AdmissionKey> {
        supplied(dialing, handed, own_url, own_relay, self.operated_at(Some(user), dialing), |r| self.at(user, r).present)
            .into_key()
    }

    /// [`Self::at_supplied_address`] for a **relayed dial**, which is this
    /// machine's reach: at this device's own relay by its own record, the key
    /// this machine presents there for its own reservations
    /// ([`Self::present_at`]) — the relay learns nothing from the dial it did
    /// not from the reservation. So a dial made for no person's pool, the
    /// operator's to their own vault, presents the key its own relay reads.
    /// A relay operated from this machine, at the address its credential
    /// names, is its own relay by that record too: the operator's admit of
    /// their own vault's invite, met at the relay they operate, presents
    /// *mine* there though this device stands nowhere.
    /// Anywhere else, exactly what was handed.
    pub fn dialing_supplied_address(
        &self,
        dialing: &str,
        handed: Option<AdmissionKey>,
        own_url: &str,
        own_relay: Option<&RelayId>,
    ) -> Option<AdmissionKey> {
        self.presenting_on_a_dial(dialing, handed, own_url, own_relay).into_key()
    }

    /// [`Self::dialing_supplied_address`], with what the key it chose is — for
    /// a first-contact dial, which says it when the relay refuses it
    /// ([`RefusedAtTheRelay`]).
    pub fn presenting_on_a_dial(
        &self,
        dialing: &str,
        handed: Option<AdmissionKey>,
        own_url: &str,
        own_relay: Option<&RelayId>,
    ) -> Presenting {
        supplied(dialing, handed, own_url, own_relay, self.operated_at(None, dialing), |r| self.presented_at(r))
    }

    fn peer(&self, user: &str, node: &[u8; 32], dialing: &str) -> Option<PeerRelay> {
        self.reached_by
            .read()
            .unwrap()
            .get(&(user.to_string(), *node))
            .filter(|p| p.url == dialing)
            .cloned()
    }

    /// What to hand one of `user`'s **own** devices that asked where this node
    /// reserves: the key `user` presents there and, when held as the operator,
    /// the one offered on. `None` when `user` holds nothing for `relay` —
    /// another person's keys on this machine are never handed.
    pub fn for_own_device(&self, user: &str, relay: &RelayId) -> Option<RelayAdmission> {
        let keys = self.at(user, relay);
        let (present, _) = keys.present?;
        Some(RelayAdmission {
            present: SecretText::new(present.to_text()),
            offer: keys.offer.map(|k| SecretText::new(k.to_text())),
        })
    }

    /// The *invited* key `user` holds as `relay`'s operator, for their reach
    /// note.
    pub fn offer_for(&self, user: &str, relay: &RelayId) -> Option<AdmissionKey> {
        self.at(user, relay).offer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(b: u8) -> AdmissionKey {
        AdmissionKey::from_bytes([b; 32])
    }

    const R: RelayId = [1u8; 32];
    const NODE: [u8; 32] = [9u8; 32];
    const URL: &str = "http://r:7700";

    const FULL: Option<&str> = Some("full");
    const VAULT: Option<&str> = Some("blind-storage");

    /// The paired node `NODE`, recorded as `posture`.
    fn node(posture: Option<&str>) -> PairedNode {
        PairedNode {
            id: "node".into(),
            device_did: kotton_wire::did::Did::new("peer", "node"),
            public_key: NODE,
            paired_at: 0,
            addresses: vec![],
            relay_url: None,
            posture: posture.map(str::to_string),
        }
    }

    fn answer(present: u8, offer: Option<u8>) -> RelayAdmission {
        RelayAdmission { present: SecretText::new(k(present).to_text()), offer: offer.map(|o| SecretText::new(k(o).to_text())) }
    }

    /// *Mine* kept here is never replaced by anything learned; a learned
    /// *mine* is never replaced by *invited*; the same tier replaces itself; an
    /// invitee's answer carries no offer on; and one person's keys are never
    /// read as another's.
    #[test]
    fn mine_outranks_invited_and_an_invitee_offers_nothing() {
        let ring = RelayKeyring::default();
        ring.hold_as_operator("lee", &R, None, k(1), k(2));
        // A peer answering with an offer of its own does not replace what is kept.
        ring.learn("lee", &NODE, FULL, URL, &R, Some(&answer(9, Some(8))));
        ring.learn("lee", &NODE, FULL, URL, &R, Some(&answer(3, None)));
        assert_eq!(ring.present_for("lee", &R), Some(k(1)));
        assert_eq!(ring.offer_for("lee", &R), Some(k(2)));
        assert_eq!(ring.present_at(&R), Some(k(1)));

        let tenant = RelayKeyring::default();
        tenant.learn("sam", &NODE, VAULT, URL, &R, Some(&answer(2, None)));
        assert_eq!(tenant.present_for("sam", &R), Some(k(2)));
        assert_eq!(tenant.offer_for("sam", &R), None);
        assert_eq!(tenant.relay_of("sam", &NODE, URL), Some(R));
        assert_eq!(tenant.relay_of("sam", &NODE, "http://elsewhere:7700"), None, "a key goes only where it was proved");
        assert!(tenant.for_own_device("sam", &R).unwrap().offer.is_none());
        // Where the node said it reserves is read back by person and node.
        assert_eq!(tenant.told_relay("sam", &NODE).as_deref(), Some(URL));
        assert_eq!(tenant.told_relay("lee", &NODE), None, "another person was told nothing");
        assert_eq!(tenant.told_relay("sam", &[0u8; 32]), None, "nor by another node");

        let own = RelayKeyring::default();
        own.learn("lee", &NODE, FULL, URL, &R, ring.for_own_device("lee", &R).as_ref());
        assert_eq!(own.present_for("lee", &R), Some(k(1)));
        assert_eq!(own.offer_for("lee", &R), Some(k(2)));
        // Invited never replaces a learned mine.
        own.learn("lee", &NODE, FULL, URL, &R, Some(&answer(5, None)));
        assert_eq!(own.present_for("lee", &R), Some(k(1)));
        assert!(!format!("{own:?}").contains(&k(2).to_text()));
    }

    /// **A relay released is no longer its operator's own** (`relay forget`):
    /// after [`RelayKeyring::release`], nothing is presented or offered there
    /// for that person, whether kept here or learned from another of their
    /// devices, and its address is no longer read as theirs, which is
    /// what a restart with the credential gone holds. Another person's keys at
    /// that relay, and the person's keys at another relay, are untouched.
    #[test]
    fn a_relay_released_is_presented_offered_and_owned_no_more() {
        const OTHER: RelayId = [2u8; 32];
        let ring = RelayKeyring::default();
        ring.hold_as_operator("lee", &R, Some(URL), k(1), k(2));
        ring.hold_as_operator("lee", &OTHER, Some("http://other:7700"), k(3), k(4));
        ring.hold_as_operator("jo", &R, None, k(5), k(6));
        assert_eq!(ring.operated_at(Some("lee"), URL), Some(R));
        // *Mine* learned from another of the person's own devices, at a relay
        // this device keeps no record for: the tier between kept and invited.
        const LEARNED: RelayId = [3u8; 32];
        ring.learn("lee", &NODE, FULL, "http://learned:7700", &LEARNED, Some(&answer(7, Some(8))));
        assert_eq!(ring.at("lee", &LEARNED).present.map(|(_, t)| t), Some(Tier::LearnedMine));

        ring.release("lee", &LEARNED);
        assert_eq!(ring.present_for("lee", &LEARNED), None, "a learned mine is still presented");
        assert_eq!(ring.offer_for("lee", &LEARNED), None, "a learned offer is still offered");
        ring.release("lee", &R);
        assert_eq!(ring.present_for("lee", &R), None);
        assert_eq!(ring.offer_for("lee", &R), None);
        assert!(ring.at("lee", &R).operated_at.is_none());
        assert_eq!(ring.operated_at(Some("lee"), URL), None, "the address is still read as the person's own");
        assert_eq!(ring.present_for("lee", &OTHER), Some(k(3)), "another relay's keys went with it");
        assert_eq!(ring.present_for("jo", &R), Some(k(5)), "another person's keys at the relay went with it");
        assert_eq!(ring.present_at(&R), Some(k(5)));
    }

    /// **One person's keys are theirs on a machine two people use.** The
    /// operator's keys offer nothing on another person's note and are handed
    /// to none of their devices; the machine's own reach still presents the key
    /// held for the relay.
    #[test]
    fn one_persons_relay_keys_are_never_read_as_anothers() {
        let ring = RelayKeyring::default();
        ring.hold_as_operator("lee", &R, None, k(1), k(2));
        assert_eq!(ring.offer_for("jo", &R), None);
        assert!(ring.for_own_device("jo", &R).is_none());
        assert_eq!(ring.present_for("jo", &R), None);
        assert_eq!(ring.present_at(&R), Some(k(1)));
    }

    /// **A relay is its key here**: keys held for one relay's key are presented at that key and
    /// at no other, and a relay with no key recorded names no slot — nothing is
    /// read by address.
    #[test]
    fn keys_are_held_and_presented_by_the_relays_key_and_never_by_its_address() {
        let ring = RelayKeyring::default();
        ring.hold_as_operator("lee", &R, None, k(1), k(2));
        assert_eq!(ring.present_at(&[2u8; 32]), None, "another relay's key finds nothing");
        assert_eq!(relay_id(Some(&hex::encode(R))), Some(R));
        assert_eq!(relay_id(Some(&format!(" {} ", hex::encode(R)))), Some(R));
        assert_eq!(relay_id(Some("http://r:7700")), None, "an address is not a relay's name");
        assert_eq!(relay_id(None), None);
        ring.forget("lee");
        assert_eq!(ring.present_at(&R), None);
    }

    /// A relay at a loopback address that proves `key` to whoever asks.
    async fn proving(key: ed25519_dalek::SigningKey) -> String {
        use ed25519_dalek::Signer as _;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else { return };
                let key = key.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let nonce = req
                        .split_once("nonce=")
                        .and_then(|(_, r)| r.split([' ', '&']).next())
                        .and_then(|h| hex::decode(h).ok())
                        .unwrap_or_default();
                    let body = serde_json::to_string(&kotton_wire::rendezvous::RelayIdentity {
                        key: hex::encode(key.verifying_key().as_bytes()),
                        addr: String::new(),
                        sig: hex::encode(key.sign(&kotton_wire::rendezvous::identity_signing_input(&nonce, "")).to_bytes()),
                    })
                    .unwrap();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                });
            }
        });
        url
    }

    /// **A paired node that names this device's own relay beside an address
    /// of its choosing learns it nothing.** This device holds *mine* for its own relay. A node answers
    /// `NodeRelay` with that relay's key and the address of a relay it runs,
    /// which proves its own key there, not the one named: nothing is learned,
    /// and a relayed dial to that address is handed no key — so *mine* never
    /// leaves for it. The honest answer, the named key proved at the named
    /// address, is learned, and its key goes only to that address.
    #[tokio::test]
    async fn a_relay_key_a_node_names_is_learned_only_where_its_address_proves_it() {
        let own = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let own_id: RelayId = own.verifying_key().to_bytes();
        let ring = RelayKeyring::default();
        ring.hold_as_operator("lee", &own_id, None, k(1), k(2));

        // The lie: this device's relay's key, at a relay the node runs.
        let theirs = proving(ed25519_dalek::SigningKey::from_bytes(&[12u8; 32])).await;
        assert!(!ring.learn_proven("lee", &node(VAULT), &theirs, &own_id, None).await, "a key the address did not prove was learned");
        assert_eq!(ring.present_for_peer("lee", &NODE, &theirs), None, "a relayed dial to the node's address would present a key");

        // The truth: the named key, proved at the named address.
        let at_own = proving(own.clone()).await;
        assert!(ring.learn_proven("lee", &node(VAULT), &at_own, &own_id, None).await);
        assert_eq!(ring.relay_of("lee", &NODE, &at_own), Some(own_id));
        assert_eq!(ring.relay_of("lee", &NODE, &theirs), None, "proved at one address, handed to no other");
    }

    /// **A relay key offered on is learned only from a paired node recorded as
    /// *full*.**
    /// A cosigner and a blind storage are paired to this person and may be a
    /// host's machine; a row whose posture this build does not recognise is
    /// read as neither *full* nor as none recorded. Each answers `NodeRelay` at this device's own relay,
    /// proved there, with a *mine* and an `offer` of its own choosing — after
    /// this device learned its keys from its desktop, when it holds only the
    /// *invited* key an invite gave it, and when it holds nothing. Each time
    /// what it presents, what it offers (which an invite minted here carries)
    /// and what a relayed dial to that node is handed are what they were. The
    /// same answer from the desktop, *full*, or from a row recorded before
    /// postures, is learned.
    #[tokio::test]
    async fn an_offer_is_learned_only_from_a_full_paired_node() {
        let own = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let own_id: RelayId = own.verifying_key().to_bytes();
        let url = proving(own).await;
        let desktop = PairedNode { public_key: [3u8; 32], ..node(FULL) };
        let hosts = [
            PairedNode { public_key: [4u8; 32], ..node(Some("cosigner")) },
            PairedNode { public_key: [5u8; 32], ..node(VAULT) },
            // A posture this build does not recognise: not full.
            PairedNode { public_key: [6u8; 32], ..node(Some("steward")) },
        ];
        let lie = answer(9, Some(8));

        // Mine learned from the desktop: a host's offer replaces nothing.
        let ring = RelayKeyring::default();
        assert!(ring.learn_proven("lee", &desktop, &url, &own_id, Some(&answer(1, Some(2)))).await);
        assert_eq!((ring.present_for("lee", &own_id), ring.offer_for("lee", &own_id)), (Some(k(1)), Some(k(2))), "the desktop's offer");
        for host in &hosts {
            assert!(ring.learn_proven("lee", host, &url, &own_id, Some(&lie)).await, "the relay is still learned");
            assert_eq!(ring.present_for("lee", &own_id), Some(k(1)), "{:?} replaced mine", host.posture);
            assert_eq!(ring.offer_for("lee", &own_id), Some(k(2)), "{:?} replaced the offer", host.posture);
            assert_eq!(ring.present_at(&own_id), Some(k(1)));
            assert_eq!(ring.present_for_peer("lee", &host.public_key, &url), None, "{:?} was presented its own key", host.posture);
            assert_eq!(ring.relay_of("lee", &host.public_key, &url), Some(own_id));
        }

        // Only invited, from an invite: still only invited, and nothing offered.
        let invitee = RelayKeyring::default();
        invitee.hold_invited("lee", &own_id, k(5));
        for host in &hosts {
            invitee.learn_proven("lee", host, &url, &own_id, Some(&lie)).await;
            assert_eq!(invitee.present_for("lee", &own_id), Some(k(5)), "{:?} replaced invited", host.posture);
            assert_eq!(invitee.offer_for("lee", &own_id), None, "{:?} set an offer", host.posture);
        }

        // Nothing held: nothing held after, not even invited in its place.
        let bare = RelayKeyring::default();
        for host in &hosts {
            bare.learn_proven("lee", host, &url, &own_id, Some(&lie)).await;
            assert_eq!(bare.at("lee", &own_id).present.map(|(k, _)| k), None, "{:?} set a key to present", host.posture);
            assert_eq!(bare.offer_for("lee", &own_id), None, "{:?} set an offer", host.posture);
            assert_eq!(bare.present_at(&own_id), None);
        }

        // The full desktop's answer, and a row from before postures, are learned.
        for (from, ring) in [(desktop.clone(), RelayKeyring::default()), (node(None), RelayKeyring::default())] {
            assert!(ring.learn_proven("lee", &from, &url, &own_id, Some(&lie)).await);
            assert_eq!(ring.at("lee", &own_id).present, Some((k(9), Tier::LearnedMine)), "{:?}", from.posture);
            assert_eq!(ring.offer_for("lee", &own_id), Some(k(8)), "{:?}", from.posture);
        }
        assert!(offers_from(None::<&str>) && offers_from(FULL));
        assert!(![Posture::Cosigner, Posture::BlindStorage, Posture::Gateway].into_iter().any(|p| offers_from(Some(p.as_str()))));
        assert!(!offers_from(Some("steward")) && !offers_from(Some("")) && !offers_from(Some("Full")), "text that is not `full` is not full");
    }

    /// A TCP forwarder at a loopback address of its own, in front of `to`.
    async fn forwarder(to: &str) -> String {
        let to = to.trim_start_matches("http://").to_string();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            loop {
                let Ok((mut inbound, _)) = listener.accept().await else { return };
                let to = to.clone();
                tokio::spawn(async move {
                    if let Ok(mut outbound) = tokio::net::TcpStream::connect(&to).await {
                        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                    }
                });
            }
        });
        url
    }

    /// **A forwarder in front of this device's own relay is handed nothing of
    /// this person's** — the forwarding form of the same reach. The forwarder proves the relay's key, since it only passes the
    /// relay's answer back, so a node naming this device's own relay beside the
    /// forwarder's address passes the proof. It is still not a place *mine*
    /// goes: a relayed dial there presents what the node handed over and
    /// nothing else — nothing, when it handed nothing, and its own key when it
    /// handed one — never the keyring's own *mine*.
    #[tokio::test]
    async fn a_forwarder_in_front_of_this_devices_relay_is_never_presented_mine() {
        let own = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let own_id: RelayId = own.verifying_key().to_bytes();
        let ring = RelayKeyring::default();
        ring.hold_as_operator("lee", &own_id, None, k(1), k(2));
        let relay = proving(own).await;
        let front = forwarder(&relay).await;

        assert!(ring.learn_proven("lee", &node(VAULT), &front, &own_id, None).await, "the forwarder proves the relay's key");
        assert_eq!(ring.present_for_peer("lee", &NODE, &front), None, "mine was presented at the forwarder");

        // A node that hands a key of its own is presented that key, not mine.
        let handed = RelayAdmission { present: SecretText::new(k(7).to_text()), offer: None };
        assert!(ring.learn_proven("lee", &node(VAULT), &front, &own_id, Some(&handed)).await);
        assert_eq!(ring.present_for_peer("lee", &NODE, &front), Some(k(7)));
        assert_ne!(ring.present_for_peer("lee", &NODE, &front), Some(k(1)));
        // And the keyring's own key for its own relay is untouched.
        assert_eq!(ring.present_for("lee", &own_id), Some(k(1)));
    }

    /// **A contact's note that labels its own server with this device's relay
    /// key is handed nothing of this person's** — the contact-delivery
    /// channel. The note says `{addr: their
    /// server, key: this device's relay's key, admit: none}`; a delivery to
    /// that address presents nothing, because the address is not this device's
    /// own relay by this device's own record. At this device's own relay, by
    /// that record, the person's own key is presented; and a key the contact
    /// handed over is presented where they handed it.
    #[test]
    fn a_contacts_note_naming_this_devices_relay_key_beside_its_own_server_is_handed_nothing() {
        let ring = RelayKeyring::default();
        let own_id: RelayId = [11u8; 32];
        let own_url = "http://own.relay:7700";
        ring.hold_as_operator("lee", &own_id, None, k(1), k(2));

        // The lying note: their server, labelled with this device's relay key.
        let theirs = "http://their.server:7700";
        assert_eq!(ring.at_supplied_address("lee", theirs, None, own_url, Some(&own_id)), None, "mine went to their server");
        // This device's own relay, by its own record: the person's own key.
        assert_eq!(ring.at_supplied_address("lee", own_url, None, own_url, Some(&own_id)), Some(k(1)));
        // A key the contact handed for their relay is theirs to be presented.
        assert_eq!(ring.at_supplied_address("lee", theirs, Some(k(7)), own_url, Some(&own_id)), Some(k(7)));
        // Another person on this machine is handed nothing of lee's.
        assert_eq!(ring.at_supplied_address("jo", own_url, None, own_url, Some(&own_id)), None);
    }

    /// **At this device's own relay, the person's own key comes before what a
    /// vault handed them.** An operator's device that is also a tenant of its own vault is
    /// handed *invited* by the vault's `NodeRelay`, at the vault's relay — which
    /// is this device's own. A contact delivery there and a relayed dial there
    /// both present *mine*, which the relay's *only my devices* reads; the
    /// handed key is still what goes anywhere else it came with, and what a
    /// tenant who holds nothing of their own presents at the same relay.
    #[test]
    fn at_its_own_relay_the_person_presents_mine_before_what_their_vault_handed() {
        let ring = RelayKeyring::default();
        let own_url = "http://own.relay:7700";
        ring.hold_as_operator("lee", &R, None, k(1), k(2));
        // The vault answers lee the tenant with *invited*, at lee's own relay.
        ring.learn("lee", &NODE, VAULT, own_url, &R, Some(&answer(2, None)));
        let handed = ring.present_for_peer("lee", &NODE, own_url);
        assert_eq!(handed, Some(k(2)), "the vault handed invited");

        assert_eq!(ring.at_supplied_address("lee", own_url, handed.clone(), own_url, Some(&R)), Some(k(1)), "invited was presented at the operator's own relay");
        assert_eq!(ring.dialing_supplied_address(own_url, handed.clone(), own_url, Some(&R)), Some(k(1)), "a dial presented invited at the operator's own relay");

        // Elsewhere, what was handed and nothing of lee's.
        let theirs = "http://their.relay:7700";
        assert_eq!(ring.at_supplied_address("lee", theirs, handed.clone(), own_url, Some(&R)), Some(k(2)));
        assert_eq!(ring.dialing_supplied_address(theirs, None, own_url, Some(&R)), None, "mine went to an address that is not this device's relay");

        // A tenant holding nothing of their own presents what they were handed.
        let tenant = RelayKeyring::default();
        assert_eq!(tenant.at_supplied_address("sam", own_url, Some(k(2)), own_url, Some(&R)), Some(k(2)));
        assert_eq!(tenant.dialing_supplied_address(own_url, Some(k(2)), own_url, Some(&R)), Some(k(2)));
    }

    /// **A relay this person operates is their own relay by their own record,
    /// though this device stands nowhere.** The operator's desktop holds the
    /// relay's keys from its sealed record, with the address its operator
    /// credential names, and has no relay set (`own_url` empty). Its own vault's
    /// invite, met at that relay, hands *invited*: the admit's dial and a
    /// delivery there present *mine*, which the relay's *only my devices*
    /// reads, however the address is spelled. Anywhere else — another address,
    /// whatever relay key it was labelled with — what was handed and nothing of
    /// the operator's; another person on this machine is handed nothing of
    /// theirs at a delivery; and keys held with no address make none their own.
    #[test]
    fn a_relay_this_person_operates_is_their_own_by_the_address_their_credential_names() {
        let ring = RelayKeyring::default();
        let operated = "http://own.relay:7700";
        ring.hold_as_operator("lee", &R, Some(operated), k(1), k(2));
        let invited = Some(k(2));

        for dialing in [operated, "http://own.relay:7700/"] {
            assert_eq!(ring.dialing_supplied_address(dialing, invited.clone(), "", None), Some(k(1)), "the admit presented invited at {dialing:?}");
            assert_eq!(ring.at_supplied_address("lee", dialing, invited.clone(), "", None), Some(k(1)), "a delivery presented invited at {dialing:?}");
        }
        // Standing at another relay changes nothing at the operated one.
        let stood = "http://stood.relay:7700";
        assert_eq!(ring.dialing_supplied_address(operated, invited.clone(), stood, Some(&[3u8; 32])), Some(k(1)));

        let theirs = "http://their.relay:7700";
        assert_eq!(ring.dialing_supplied_address(theirs, None, "", None), None, "mine went to an address the operator's record does not name");
        assert_eq!(ring.dialing_supplied_address(theirs, Some(k(7)), "", None), Some(k(7)));
        assert_eq!(ring.at_supplied_address("lee", theirs, None, "", None), None);
        assert_eq!(ring.at_supplied_address("jo", operated, None, "", None), None, "another person was handed lee's key");

        let unaddressed = RelayKeyring::default();
        unaddressed.hold_as_operator("lee", &R, None, k(1), k(2));
        assert_eq!(unaddressed.dialing_supplied_address(operated, invited.clone(), "", None), invited, "keys held with no address made one own");
    }

    /// **A relayed dial at this device's own relay presents the machine's key
    /// there, whoever it is for** (case 2). The operator's dial to their vault
    /// names no pool, so it is for no person; it presents what this machine
    /// presents at its own relay for its own reservations. A contact delivery
    /// stays the person's: another person on this machine is handed nothing of
    /// the operator's.
    #[test]
    fn a_dial_for_no_pool_at_its_own_relay_presents_the_machines_key() {
        let ring = RelayKeyring::default();
        let own_url = "http://own.relay:7700";
        ring.hold_as_operator("lee", &R, None, k(1), k(2));
        assert_eq!(ring.dialing_supplied_address(own_url, None, own_url, Some(&R)), ring.present_at(&R));
        assert_eq!(ring.dialing_supplied_address(own_url, None, own_url, Some(&R)), Some(k(1)));
        assert_eq!(ring.at_supplied_address("", own_url, None, own_url, Some(&R)), None, "a delivery for no person read someone's key");
        assert_eq!(ring.dialing_supplied_address(own_url, None, own_url, None), None, "a relay recorded with no key names no slot");
    }

    /// **The two spellings of this device's own relay are one address**
    /// (with and without the trailing `/`). A contact or a peer that writes this device's relay
    /// with a trailing `/`, or this device having recorded it with one, is
    /// still this device's relay — by `same_relay_address`, the comparison a
    /// contact's note is read with too. A different address with a slash is
    /// still a different address.
    #[test]
    fn the_own_relay_spelled_with_or_without_a_trailing_slash_is_one_address() {
        let ring = RelayKeyring::default();
        ring.hold_as_operator("lee", &R, None, k(1), k(2));
        let bare = "http://own.relay:7700";
        let slashed = "http://own.relay:7700/";
        for (dialing, own_url) in [(slashed, bare), (bare, slashed), (slashed, slashed), (" http://own.relay:7700/ ", bare)] {
            assert_eq!(ring.at_supplied_address("lee", dialing, None, own_url, Some(&R)), Some(k(1)), "{dialing:?} at {own_url:?}");
            assert_eq!(ring.dialing_supplied_address(dialing, None, own_url, Some(&R)), Some(k(1)), "{dialing:?} at {own_url:?}");
        }
        assert_eq!(ring.at_supplied_address("lee", "http://own.relay:7700//x/", None, bare, Some(&R)), None);
        assert_eq!(ring.at_supplied_address("lee", "http://their.relay:7700/", None, bare, Some(&R)), None);
        assert_eq!(ring.at_supplied_address("lee", "/", None, "", Some(&R)), None, "an empty address is no relay's");
    }

    /// **A first-contact dial knows what it presents, so a refusal can say it**:
    /// the key the one choice made ([`RelayKeyring::presenting_on_a_dial`]) and
    /// its kind travel together — *mine* kept or learned, or *invited*, at this
    /// device's own relay by its own record; what the invite handed, or nothing,
    /// anywhere else.
    #[test]
    fn a_dial_says_which_key_it_presented() {
        let ring = RelayKeyring::default();
        let own_url = "http://own.relay:7700";
        let theirs = "http://their.relay:7700";
        ring.hold_as_operator("lee", &R, Some(own_url), k(1), k(2));
        let at_own = ring.presenting_on_a_dial(own_url, Some(k(7)), "", None);
        assert_eq!((at_own.key(), at_own.what()), (Some(&k(1)), Presented::Held(Tier::KeptMine)));
        let handed = ring.presenting_on_a_dial(theirs, Some(k(7)), "", None);
        assert_eq!((handed.key(), handed.what()), (Some(&k(7)), Presented::Handed));
        let nothing = ring.presenting_on_a_dial(theirs, None, "", None);
        assert_eq!((nothing.key(), nothing.what()), (None, Presented::Nothing));

        let invitee = RelayKeyring::default();
        invitee.hold_invited("sam", &R, k(2));
        let stood = invitee.presenting_on_a_dial(own_url, None, own_url, Some(&R));
        assert_eq!((stood.key(), stood.what()), (Some(&k(2)), Presented::Held(Tier::Invited)));
        assert_eq!(Presenting::held(invitee.presented_at(&[9u8; 32])).what(), Presented::Nothing, "a relay held nothing for");
    }

    /// **Only the relay's refusal at its door is a refusal**
    /// ([`RefusedAtTheRelay::of`]): the variant a `403` at the upgrade comes
    /// back as. A relay not reached, or one that closed the socket, is not —
    /// those are the other side not there yet, and a dial waits for it.
    #[test]
    fn only_a_refusal_at_the_relays_door_is_read_as_one() {
        use kotton_sys::net::TransportError;
        let presenting = Presenting::handed(None);
        let refused = TransportError::AuthenticationFailed("the relay refused: HTTP error: 403 Forbidden".into());
        assert_eq!(
            RefusedAtTheRelay::of(&refused, "http://r", &presenting, FirstContact::SpokenCode),
            Some(RefusedAtTheRelay { url: "http://r".into(), presented: Presented::Nothing, meeting: FirstContact::SpokenCode })
        );
        for other in [
            TransportError::ConnectionFailed("HTTP error: 404 Not Found".into()),
            TransportError::ConnectionFailed("Connection refused (os error 111)".into()),
            TransportError::ListenerClosed,
        ] {
            assert_eq!(RefusedAtTheRelay::of(&other, "http://r", &presenting, FirstContact::VaultInvite), None, "{other}");
        }
    }
}
