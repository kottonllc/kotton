// SPDX-License-Identifier: AGPL-3.0-or-later
//! Device-network membership set (RFC-0024 §"Device-network membership").
//!
//! A user's **membership set** records every node, device, and contact admitted to
//! their network. The enrollment (RFC-0025), pairing (RFC-0022), and relay-invite
//! (RFC-0024) ceremonies *write* to it; the paired-key allowlist (RFC-0004), the
//! relay allowlist, and the device list are **computed views** over it — never
//! independently edited. Revoke once (remove a member) and every derived gate
//! closes on the next handshake.
//!
//! Records live in the user's VFS at [`member_path`] (`/network/members/<did>`), so
//! they sync across the user's own nodes (RFC-0008) like any other record.

use serde::{Deserialize, Serialize};

// ── Role / provenance / posture ───────────────────────────────────────────────

/// What kind of principal a member is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    /// Another node/device the user owns (admitted by RFC-0025 enrollment).
    OwnDevice,
    /// Another person's node, paired for messaging (RFC-0022). Grants no data access.
    Contact,
    /// A relay admitted to carry the user's traffic.
    Relay,
}

/// The ceremony that admitted a member — its provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Ceremony {
    /// Device/node enrollment (RFC-0025 / RFC-0007).
    DeviceEnroll,
    /// Contact pairing (RFC-0022).
    Pairing,
    /// Relay invite redemption (RFC-0024).
    RelayInvite,
}

/// For an [`Role::OwnDevice`] member, whether it holds identity or is a blind
/// replica (RFC-0025).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Posture {
    /// Holds the user's identity (a FROST share, or `seed32` for the first device);
    /// can decrypt and sync all data.
    #[default]
    Full,
    /// Holds a FROST **share** (can co-sign with the quorum) but **no** data keys —
    /// no CEK, so it cannot decrypt (RFC-0036). Strengthens identity
    /// availability/recovery using untrusted hardware (e.g. a hosted node) without
    /// expanding the data-trust boundary: identity authority and data access are
    /// separable material.
    Cosigner,
    /// Ciphertext-only sync target — holds no key material and can decrypt nothing.
    ///
    /// Named `BlindStorage` and not `BlindReplica`, which it was until 2026-08-28.
    /// "Replica" claims a mirror of the device, and that is wrong twice over: it is
    /// not the product model — a person chooses what to keep off-device, the way
    /// every consumer cloud works — and a drive is where a person's things live,
    /// which each device syncs with, not a copy of any one device. It holds files
    /// and records alike as sealed packs it cannot open.
    ///
    /// *Replica* is worth keeping for what it should mean: a second copy of a blind
    /// storage in another geography, for the operator's own continuity. That is
    /// infrastructure behind one of these, not a posture a user enrols.
    BlindStorage,
    /// The browser-facing gateway (RFC-0078 GW3): a device that relays sealed
    /// browser frames to this node and holds nothing — no share, no key, no
    /// data. For the person who pairs it as one, it may speak exactly one verb,
    /// `BrowserFrame`, naming that person, and the peer path refuses it every
    /// other one; a posture is a person's row, so what the same key is to
    /// another person is read from theirs. Paired so the relay carries it and
    /// the node admits it; postured so pairing gives it no reach.
    Gateway,
}

/// The words `device add` has for a posture, each with the posture it asks for. The grammar
/// the shell parses (`parse_add`, `client/shell/src/commands/device.rs`) reads it, and so do
/// the daemon's hints that name a `device add` posture flag (`device_add_flag` in
/// `kotton-device`, which looks a flag up by posture). A gateway is not here: it is
/// `--gateway <code>`, a word with a value. What holds the rest: `cargo xtask
/// device-add-check` finds no other `device add --` in code under `core/` outside tests and
/// comments (its module doc says what a text check cannot see), and a shell test holds its
/// usage line's bracket to these keys. Prose outside `core/` is not held.
///
/// `drive enrol` has a table of its own in the shell, since its default (blind) and its set
/// (it has `--full`) differ. Neither table is a judgement: the daemon remains the only guard
/// on posture, and these are grammar.
pub const DEVICE_ADD_POSTURE_FLAGS: [(&str, Posture); 2] =
    [("--blind", Posture::BlindStorage), ("--cosigner", Posture::Cosigner)];

/// The posture `device add` asks for when the line names none.
pub const DEVICE_ADD_DEFAULT_POSTURE: Posture = Posture::Full;

impl Posture {
    /// The kebab-case name this serialises as, for the one column that stores it as text.
    pub fn as_str(&self) -> &'static str {
        match self {
            Posture::Full => "full",
            Posture::Cosigner => "cosigner",
            Posture::BlindStorage => "blind-storage",
            Posture::Gateway => "gateway",
        }
    }

    /// The inverse of [`Posture::as_str`].
    pub fn parse(s: &str) -> Option<Posture> {
        match s {
            "full" => Some(Posture::Full),
            "cosigner" => Some(Posture::Cosigner),
            "blind-storage" => Some(Posture::BlindStorage),
            "gateway" => Some(Posture::Gateway),
            _ => None,
        }
    }
}

// ── Member ────────────────────────────────────────────────────────────────────

/// One member of a user's device-network membership set (RFC-0024).
///
/// The canonical fields (`did`, `public_key`, `role`, `admitted_by`, `added_at`)
/// are from RFC-0024; `posture` and `label` carry the RFC-0025 own-device details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    /// The member's DID (`did:key:z6Mk…`).
    pub did: String,
    /// The member's raw Ed25519 public key — redundant with `did`, but avoids
    /// re-deriving it at every mTLS handshake / allowlist check.
    pub public_key: [u8; 32],
    /// What kind of principal this is.
    pub role: Role,
    /// Which ceremony admitted this member.
    pub admitted_by: Ceremony,
    /// When the member was admitted (ISO-8601 / RFC-3339).
    pub added_at: String,
    /// Identity posture — `Some` only for [`Role::OwnDevice`] members.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posture: Option<Posture>,
    /// Optional human label (e.g. `"home-vps"`, `"alice's phone"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// For a [`Role::Contact`]: the latest [`ReachNote`] they signed — every
    /// relay they are admitted to and their device keys. Handed over at pairing
    /// and replaced whenever a newer one arrives sealed from them; where a
    /// delivery to them is dialled (DEC-0055). Absent on own devices, and on a
    /// contact whose note has not arrived yet.
    ///
    /// It replaced a single `relay_url` the card was handed once and never
    /// refreshed. A card stored before that still carries the old key on disk,
    /// and it is ignored: the note is the only thing a card is dialled from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reach: Option<ReachNote>,
}

// ── ReachNote ────────────────────────────────────────────────────────────────

/// Where a person can be reached, in their own words and under their own
/// signature (`IDEA-reachability-service-endpoints`, ruled 2026-09-24).
///
/// The identity key is the anchor a contact keeps forever; this is a mutable,
/// expiring hint that hangs off it. A person's daemon re-signs it whenever the
/// relays it holds at change, and sends it **sealed to each contact** over the
/// relationship that already exists — never to a relay in the clear and never
/// through a directory, so the join key *this identity is found at this relay*
/// exists only on the cards of people who already know them (RFC-0083 R4).
///
/// The shape only. Signing and the rules for believing one — the contact's
/// key, newer wins, an expired note fails closed — are
/// `kotton_crypto::reach_note`, because this crate holds no cryptography.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReachNote {
    /// Whose note this is: the identity's AID. Signed, so a note cannot be
    /// replayed onto somebody else's card.
    pub did: String,
    /// Every relay the person is admitted to, most-preferred first.
    pub relays: Vec<RelayRef>,
    /// The person's device keys, hex Ed25519 public keys, so a direct
    /// connection from one of them can be recognised.
    pub devices: Vec<String>,
    /// Monotonic: a card replaces its note only with a higher version.
    pub version: u64,
    /// Unix seconds after which the note is not believed. Inside the
    /// signature, so a stale note cannot be made to look fresh.
    pub expires_at: u64,
    /// Hex Ed25519 signature by the identity key over every field above.
    pub sig: String,
}

/// One relay in a [`ReachNote`]: the relay's key where it has one, and where
/// it was last found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayRef {
    /// The relay's own key, hex — the key it proved at `GET /identity` when the
    /// person's device learned it (`TASK-a-relay-has-a-key-of-its-own-and-proves-it`).
    /// `None` when it showed none: a relay that keeps no key, or did not answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Where the relay was last found — a locator, not a trust anchor.
    pub addr: String,
    /// The relay's *invited* admission key, when the person is its operator
    /// and hands it to their contacts
    /// (`TASK-a-device-presents-its-relays-admission-tag-and-the-reach-row-sets-the-rule`):
    /// a contact presents a tag under it at this relay and is admitted under
    /// *the people I invite*. Every contact of the operator is handed the same
    /// key, so the tag says *one of them* and never *which*. A secret: the note
    /// is sealed to each contact and this prints as `<redacted>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admit: Option<AdmitKey>,
}

/// An admission key as a reach note carries it: base64url, 32 bytes. On the
/// wire it is the plain string; in a `{:?}` it is `<redacted>`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AdmitKey(pub String);

impl std::fmt::Debug for AdmitKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl ReachNote {
    /// Every relay a delivery to this person is dialled at, in the order they
    /// prefer, while the note is unexpired at `now`. An expired note names
    /// nowhere — it fails closed rather than routing to a relay the person may
    /// have left, and the caller falls back to its own.
    pub fn relays_at(&self, now: u64) -> Vec<&str> {
        if now >= self.expires_at {
            return Vec::new();
        }
        self.relays
            .iter()
            .map(|r| r.addr.as_str())
            .filter(|a| !a.trim().is_empty())
            .collect()
    }

    /// The admission key this note hands for the relay at `addr`, when it is
    /// unexpired at `now` and names that relay with one: the key this person,
    /// as that relay's operator, invited whoever holds the note with.
    pub fn admit_at(&self, addr: &str, now: u64) -> Option<&str> {
        if now >= self.expires_at {
            return None;
        }
        self.relays
            .iter()
            .find(|r| same_relay_address(&r.addr, addr))
            .and_then(|r| r.admit.as_ref())
            .map(|k| k.0.as_str())
    }
}

impl Member {
    /// The VFS path where this member record is stored: `/network/members/<did>`.
    pub fn vfs_path(&self) -> String {
        member_path(&self.did)
    }

    /// Whether this member belongs in the **paired-key allowlist** that gates
    /// RFC-0004 peer mTLS: this device's fleet, and nobody else.
    ///
    /// A contact was here once, so that a message from them could reach a door.
    /// They have their own door now — a per-pair mailbox whose verifier admits
    /// one key and whose vocabulary is one verb (`DEC-0055`) — so putting their
    /// key in the *device* allowlist would admit them to the peer listener and
    /// to every device reservation as well, and leave a standing check as the
    /// only thing between them and a storage verb. The narrower predicate is
    /// what makes that check unnecessary rather than merely correct.
    pub fn in_paired_key_allowlist(&self) -> bool {
        matches!(self.role, Role::OwnDevice)
    }

    /// Whether this member is one of the user's own devices (the device-list view).
    pub fn is_own_device(&self) -> bool {
        matches!(self.role, Role::OwnDevice)
    }

    /// Where a delivery to this contact is dialled at `now`: every relay their
    /// held note names, and nothing else on the card. Empty when no note has
    /// arrived or the one held has expired.
    pub fn reach_relays(&self, now: u64) -> Vec<&str> {
        self.reach.as_ref().map(|n| n.relays_at(now)).unwrap_or_default()
    }

    /// The admission key the held note hands for the relay at `addr`, when
    /// the note is unexpired at `now` and names that relay with one: the key
    /// this contact, as that relay's operator, invited this person with.
    pub fn reach_admit(&self, addr: &str, now: u64) -> Option<&str> {
        self.reach.as_ref().and_then(|n| n.admit_at(addr, now))
    }
}

/// Whether two spellings of a relay's address are one address: the one
/// comparison of an address a device makes, here for a contact's note
/// ([`Member::reach_admit`]) and in `kotton_peer::relay_keys` for whether an
/// address is this device's own relay. Space around either and a trailing `/`
/// are not part of it; anything else is — a relay's address is a locator,
/// compared exactly, so a spelling this does not match is refused rather than
/// guessed at. An empty address is no relay's.
///
/// Not a relay's name: a relay is named by its key (RFC-0084 V9). An address
/// is compared only where the question is *where*, not *who* — a forwarder in
/// front of a relay proves that relay's key at an address that is not its own.
pub fn same_relay_address(a: &str, b: &str) -> bool {
    let bare = |s: &str| s.trim().trim_end_matches('/').to_string();
    let a = bare(a);
    !a.is_empty() && a == bare(b)
}

/// The VFS path for a member record by DID: `/network/members/<did>`.
pub fn member_path(did: &str) -> String {
    format!("/network/members/{did}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(role: Role, posture: Option<Posture>) -> Member {
        Member {
            did: "did:key:z6MkExample".to_string(),
            public_key: [7u8; 32],
            role,
            admitted_by: Ceremony::DeviceEnroll,
            added_at: "2026-06-24T00:00:00Z".to_string(),
            posture,
            label: Some("home-vps".to_string()),
            reach: None,
        }
    }

    #[test]
    fn member_json_round_trips() {
        let m = sample(Role::OwnDevice, Some(Posture::Full));
        let json = serde_json::to_string(&m).unwrap();
        let back: Member = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
        // Enums serialise as kebab-case strings.
        assert!(json.contains("\"own-device\""));
        assert!(json.contains("\"device-enroll\""));
        assert!(json.contains("\"full\""));
    }

    #[test]
    fn optional_fields_are_omitted_when_absent() {
        let m = Member {
            label: None,
            reach: None,
            posture: None,
            ..sample(Role::Contact, None)
        };
        let json = serde_json::to_string(&m).unwrap();
        assert!(!json.contains("posture"));
        assert!(!json.contains("label"));
    }

    /// The **paired-key allowlist is this device's fleet and nobody else**.
    ///
    /// It read *own-device + contact* until the narrowing this test was not
    /// updated for. A contact was in it so that a message from them could reach
    /// a door; they have their own door now — a per-pair mailbox whose verifier
    /// admits one key and whose vocabulary is one verb (`DEC-0055`) — and the
    /// device allowlist gates RFC-0004 peer mTLS, which serves `ReadFile`,
    /// `ReadSealed`, `ListSealed` and `RecoveryFetch`.
    /// Admitting a contact there to deliver a message hands them all of that and
    /// leaves a runtime check as the only thing in the way.
    ///
    /// That contacts reach doors without it is not an argument, it is measured:
    /// `contact_pairing::a_message_reaches_the_other_person_and_they_read_it` and
    /// `three_people_on_three_daemons_read_one_channel_message` both run over a
    /// real relay between separate daemons, with every peer a `Role::Contact`.
    #[test]
    fn computed_views_follow_role() {
        // paired-key allowlist = own-device, and nothing else.
        assert!(sample(Role::OwnDevice, Some(Posture::Full)).in_paired_key_allowlist());
        assert!(
            !sample(Role::Contact, None).in_paired_key_allowlist(),
            "a contact has their own door; the device allowlist is peer mTLS"
        );
        assert!(!sample(Role::Relay, None).in_paired_key_allowlist());
        // device list = own-device only.
        assert!(sample(Role::OwnDevice, None).is_own_device());
        assert!(!sample(Role::Contact, None).is_own_device());
    }

    #[test]
    fn vfs_path_is_under_network_members() {
        let m = sample(Role::OwnDevice, None);
        assert_eq!(m.vfs_path(), "/network/members/did:key:z6MkExample");
        assert_eq!(member_path("did:key:zABC"), "/network/members/did:key:zABC");
    }

    fn note(addr: &str, expires_at: u64) -> ReachNote {
        ReachNote {
            did: "did:key:z6MkExample".to_string(),
            relays: vec![RelayRef { key: None, addr: addr.to_string(), admit: None }],
            devices: vec![],
            version: 1,
            expires_at,
            sig: String::new(),
        }
    }

    /// A contact's card is dialled from their note and from nothing else on
    /// it. A card stored before the note replaced `relay_url` still carries
    /// that key on disk; it must not route anything, or a relay the person
    /// has since left would keep receiving their messages.
    #[test]
    fn a_card_reads_its_relay_from_the_note_and_not_from_relay_url() {
        let stored = serde_json::json!({
            "did": "did:key:z6MkExample",
            "public_key": vec![7u8; 32],
            "role": "contact",
            "admitted_by": "pairing",
            "added_at": "2026-06-24T00:00:00Z",
            "relay_url": "http://relay.they.left",
        });
        let old: Member = serde_json::from_value(stored.clone()).unwrap();
        assert!(old.reach_relays(100).is_empty(), "a bare relay_url routes nothing");
        assert!(!serde_json::to_string(&old).unwrap().contains("relay_url"));

        let mut with_note = stored;
        with_note["reach"] = serde_json::to_value(note("http://relay.they.use", 200)).unwrap();
        let card: Member = serde_json::from_value(with_note).unwrap();
        assert_eq!(card.reach_relays(100), vec!["http://relay.they.use"]);
    }

    /// An expired note names nowhere: the signed expiry is what bounds how long
    /// a stale note can route anyone, so a card past it fails closed.
    #[test]
    fn an_expired_note_names_no_relay() {
        let card = Member { reach: Some(note("http://relay.they.use", 200)), ..sample(Role::Contact, None) };
        assert_eq!(card.reach_relays(199), vec!["http://relay.they.use"]);
        assert!(card.reach_relays(200).is_empty());
        assert!(card.reach_relays(10_000).is_empty());
    }

    /// Every relay the note names is a way to reach them, in the order they
    /// prefer; a blank address names nowhere and is not one.
    #[test]
    fn a_card_names_every_relay_in_the_note_in_order() {
        let mut n = note("http://relay.first", 200);
        n.relays.push(RelayRef { key: None, addr: "  ".to_string(), admit: None });
        n.relays.push(RelayRef { key: None, addr: "http://relay.second".to_string(), admit: None });
        let card = Member { reach: Some(n), ..sample(Role::Contact, None) };
        assert_eq!(card.reach_relays(100), vec!["http://relay.first", "http://relay.second"]);
    }
}
