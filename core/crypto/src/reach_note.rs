// SPDX-License-Identifier: AGPL-3.0-or-later
//! Signing a reach note, and the rules for believing one
//! (`IDEA-reachability-service-endpoints`, ruled 2026-09-24).
//!
//! A [`ReachNote`] is a person's own statement of where they can be reached.
//! The identity key is the anchor a contact keeps; the note is a mutable hint
//! that hangs off it. Three rules make a hint safe to dial:
//!
//! - **Only the person signs it.** A note is believed under the key the card
//!   already holds for that person and no other, so a relay, a vault or a third
//!   contact that carries one cannot write one.
//! - **Newer wins, and only newer.** A card replaces its note only with a higher
//!   version; an older one is refused, so a note withheld and replayed later
//!   cannot pin a person to a relay they left.
//! - **An expired note fails closed.** The expiry is inside the signature and a
//!   note past it is refused on arrival and not dialled once held — the bound on
//!   how long a stale note can route anyone, which newer-wins alone does not give
//!   against a carrier that simply withholds the newer one.
//!
//! The signature covers a length-framed encoding of every field rather than a
//! serialisation, because a note is stored on the card and re-serialised, and a
//! signature over bytes that are rebuilt must not depend on how they were
//! rebuilt.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
pub use kotton_schemas::membership::{AdmitKey, ReachNote, RelayRef};

/// Domain tag under a note's signature, so a signature over a note can never
/// be mistaken for one over anything else the identity key signs. Versioned so
/// a second kind of signer can be added without a format change.
pub const REACH_NOTE_DOMAIN: &[u8] = b"kotton:reach-note:v1";

/// How long a freshly signed note is believed: thirty days, the relay
/// forwarding window (RFC-0083 R5). A note is re-signed once less than half of
/// this remains.
pub const REACH_NOTE_TTL_SECS: u64 = 30 * 24 * 60 * 60;

/// The longest life a note may claim. A note claiming more is refused: the
/// expiry exists to bound staleness, and a note that claims a year does not.
pub const MAX_NOTE_LIFETIME_SECS: u64 = 90 * 24 * 60 * 60;

/// How far past [`MAX_NOTE_LIFETIME_SECS`] a note's claimed life may run and
/// still be read as this reader's clock being behind rather than as the note
/// being wrong: seven days. A device that was off for a week and woke with a
/// drifted clock is the shape this clears, and it clears on its own as that
/// clock runs; a note claiming a year more is nobody's clock, and the
/// signer's next note will be as wrong as this one, so it is a verdict
/// ([`clock_may_explain`],
/// `TASK-a-door-refusal-that-can-clear-settles-a-reach-note-version-until-the-next`).
pub const CLOCK_BEHIND_SLACK_SECS: u64 = 7 * 24 * 60 * 60;

/// A note is written by a stranger's device as far as the reader is concerned
/// until its signature checks, so its shape is bounded before anything else.
pub const MAX_RELAYS: usize = 16;
/// See [`MAX_RELAYS`].
pub const MAX_DEVICES: usize = 64;
/// See [`MAX_RELAYS`].
pub const MAX_ADDR_LEN: usize = 512;

/// What became of a note that was believed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kept {
    /// It was newer than the card's, and replaces it.
    Replaced,
    /// The card already holds this very note — a retried delivery.
    AlreadyHeld,
}

/// Sign a note for `did` with `key`, the identity's current key.
pub fn sign(
    did: &str,
    relays: Vec<RelayRef>,
    devices: Vec<String>,
    version: u64,
    expires_at: u64,
    key: &SigningKey,
) -> ReachNote {
    let mut note = ReachNote {
        did: did.to_string(),
        relays,
        devices,
        version,
        expires_at,
        sig: String::new(),
    };
    note.sig = hex::encode(key.sign(&signed_bytes(&note)).to_bytes());
    note
}

/// The note `did` should hold now, or `None` when `held` still says it.
///
/// A new one is signed when nothing is held, when the relays or devices differ
/// from what the held note lists, or when it is due for renewal
/// ([`renewal_due`]). Its version is the signing time, pushed past `held`'s so
/// a clock that stepped backwards cannot produce a note every card would
/// refuse.
///
/// The relays are compared **as a set** ([`same_relays`]): the same relays in
/// another order say the same thing, and are not signed again. The order is
/// the signing device's preference and routes nothing — a sender dials every
/// relay a note lists at once — and two of a person's devices each prefer
/// their own relay, so comparing the order would have each re-sign the other's
/// note at every pass
/// (`TASK-a-persons-devices-on-different-relays-re-sign-one-reach-note-against-each-other`).
pub fn next(
    held: Option<&ReachNote>,
    did: &str,
    relays: &[RelayRef],
    devices: &[String],
    key: &SigningKey,
    now: u64,
) -> Option<ReachNote> {
    if let Some(h) = held {
        let says_it = h.did == did && same_relays(&h.relays, relays) && h.devices == devices;
        let fresh = !renewal_due(h, now);
        let still_signed_by_this_key =
            verify(h, &key.verifying_key().to_bytes(), did, now).is_ok();
        if says_it && fresh && still_signed_by_this_key {
            return None;
        }
    }
    let version = held.map_or(now, |h| now.max(h.version.saturating_add(1)));
    Some(sign(
        did,
        relays.to_vec(),
        devices.to_vec(),
        version,
        now.saturating_add(REACH_NOTE_TTL_SECS),
        key,
    ))
}

/// Whether `held` is due to be signed again however little has changed: less
/// than half its life remains at `now`.
pub fn renewal_due(held: &ReachNote, now: u64) -> bool {
    held.expires_at <= now.saturating_add(REACH_NOTE_TTL_SECS / 2)
}

/// Whether `a` and `b` list the same relays — each with the same key and the
/// same admission key — in any order. See [`next`] for why order is not part of
/// what a note says.
pub fn same_relays(a: &[RelayRef], b: &[RelayRef]) -> bool {
    let count = |list: &[RelayRef], r: &RelayRef| list.iter().filter(|x| *x == r).count();
    a.len() == b.len() && a.iter().all(|r| count(a, r) == count(b, r))
}

/// Whether `note` claims, at `now`, a longer life than any note is given
/// ([`MAX_NOTE_LIFETIME_SECS`]) — which [`verify`] refuses.
pub fn outlives_any_note(note: &ReachNote, now: u64) -> bool {
    note.expires_at > now.saturating_add(MAX_NOTE_LIFETIME_SECS)
}

/// Whether the reader's clock being behind may explain why `note` claims too
/// long a life at `now`: it claims more than [`MAX_NOTE_LIFETIME_SECS`] by at
/// most [`CLOCK_BEHIND_SLACK_SECS`].
///
/// Unlike every other refusal [`verify`] makes, that one is then as much about
/// the reader's clock as about the note: a fresh note read on a device whose
/// clock trails the signer's claims too long a life, and stops claiming it as
/// that clock runs on — within the slack, so within a week. A card that
/// refuses a note for it has said something about itself, and is asked
/// again. Past the slack no clock explains it, and the refusal is a verdict
/// (`TASK-a-door-refusal-that-can-clear-settles-a-reach-note-version-until-the-next`).
pub fn clock_may_explain(note: &ReachNote, now: u64) -> bool {
    outlives_any_note(note, now)
        && note.expires_at <= now.saturating_add(MAX_NOTE_LIFETIME_SECS).saturating_add(CLOCK_BEHIND_SLACK_SECS)
}

/// Check `note` is `did`'s, signed by `signer`, well-formed and unexpired at
/// `now`. The whole of what arriving at a card requires, before versions.
pub fn verify(note: &ReachNote, signer: &[u8; 32], did: &str, now: u64) -> Result<(), String> {
    if note.did != did {
        return Err(format!("that reach note is {}'s, and it arrived from {did}", note.did));
    }
    if note.relays.len() > MAX_RELAYS {
        return Err(format!("a reach note lists at most {MAX_RELAYS} relays"));
    }
    if note.devices.len() > MAX_DEVICES {
        return Err(format!("a reach note lists at most {MAX_DEVICES} devices"));
    }
    for r in &note.relays {
        if !is_relay_addr(&r.addr) {
            return Err("a reach note names a relay that is not an http(s) address".to_string());
        }
        if let Some(k) = &r.key {
            if !is_hex_key(k) {
                return Err("a reach note names a relay key that is not a key".to_string());
            }
        }
        if let Some(k) = &r.admit {
            if !is_admit_key(&k.0) {
                return Err("a reach note names an admission key that is not a key".to_string());
            }
        }
    }
    if !note.devices.iter().all(|d| is_hex_key(d)) {
        return Err("a reach note names a device key that is not a key".to_string());
    }
    if now >= note.expires_at {
        return Err("that reach note has expired".to_string());
    }
    if outlives_any_note(note, now) {
        return Err("that reach note claims a longer life than any note is given".to_string());
    }
    let key = VerifyingKey::from_bytes(signer)
        .map_err(|_| "the contact's key is not a valid Ed25519 key".to_string())?;
    let sig = hex::decode(&note.sig)
        .ok()
        .and_then(|b| Signature::from_slice(&b).ok())
        .ok_or_else(|| "that reach note carries no readable signature".to_string())?;
    key.verify(&signed_bytes(note), &sig)
        .map_err(|_| "that reach note was not signed by the person it names".to_string())
}

/// Whether a card holding `held` should take `incoming`, which arrived from
/// `did` whose identity key the card holds as `signer`.
///
/// `Ok(Replaced)` when it is theirs, unexpired and newer; `Ok(AlreadyHeld)` when
/// it is the very note held; an error for anything else — including a different
/// note at the version already held, which has no order to be believed by.
pub fn accept(
    held: Option<&ReachNote>,
    incoming: &ReachNote,
    signer: &[u8; 32],
    did: &str,
    now: u64,
) -> Result<Kept, String> {
    verify(incoming, signer, did, now)?;
    match held {
        Some(h) if h == incoming => Ok(Kept::AlreadyHeld),
        Some(h) if h.version >= incoming.version => Err(format!(
            "a newer reach note (version {}) is already held than the one that arrived (version {})",
            h.version, incoming.version
        )),
        _ => Ok(Kept::Replaced),
    }
}

fn is_relay_addr(addr: &str) -> bool {
    addr.len() <= MAX_ADDR_LEN
        && (addr.starts_with("http://") || addr.starts_with("https://"))
        && !addr.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// 32 bytes, base64url without padding: 43 characters of its alphabet.
fn is_admit_key(k: &str) -> bool {
    k.len() == 43 && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn is_hex_key(k: &str) -> bool {
    k.len() == 64 && k.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Every field but the signature, length-framed, under the domain tag.
fn signed_bytes(note: &ReachNote) -> Vec<u8> {
    fn frame(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
    }
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(REACH_NOTE_DOMAIN);
    frame(&mut out, note.did.as_bytes());
    out.extend_from_slice(&(note.relays.len() as u32).to_be_bytes());
    for r in &note.relays {
        match &r.key {
            Some(k) => {
                out.push(1);
                frame(&mut out, k.as_bytes());
            }
            None => out.push(0),
        }
        frame(&mut out, r.addr.as_bytes());
        // Written only when present, after a byte no relay's first byte can
        // be (a relay starts with 0 or 1, and the device count's first byte is
        // 0 under `MAX_DEVICES`), so a note that carries no key signs the bytes
        // it signed before the key existed and every note already held still
        // verifies.
        if let Some(k) = &r.admit {
            out.push(2);
            frame(&mut out, k.0.as_bytes());
        }
    }
    out.extend_from_slice(&(note.devices.len() as u32).to_be_bytes());
    for d in &note.devices {
        frame(&mut out, d.as_bytes());
    }
    out.extend_from_slice(&note.version.to_be_bytes());
    out.extend_from_slice(&note.expires_at.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID: &str = "did:kel:Ealice";
    const NOW: u64 = 1_800_000_000;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn relay(addr: &str) -> RelayRef {
        RelayRef { key: None, addr: addr.to_string(), admit: None }
    }

    fn device(seed: u8) -> String {
        hex::encode(key(seed).verifying_key().to_bytes())
    }

    fn pubkey(seed: u8) -> [u8; 32] {
        key(seed).verifying_key().to_bytes()
    }

    #[test]
    fn a_note_the_person_signed_is_believed() {
        let note = sign(DID, vec![relay("https://relay.one")], vec![device(9)], 7, NOW + 60, &key(1));
        assert_eq!(verify(&note, &pubkey(1), DID, NOW), Ok(()));
        assert_eq!(accept(None, &note, &pubkey(1), DID, NOW), Ok(Kept::Replaced));
    }

    /// Anybody who carries a note — a relay, a vault, a third contact — can
    /// hold a signing key. Only the one the card holds for the person counts.
    #[test]
    fn a_note_signed_by_any_other_key_is_refused() {
        let note = sign(DID, vec![relay("https://relay.evil")], vec![], 7, NOW + 60, &key(2));
        assert!(verify(&note, &pubkey(1), DID, NOW).is_err());
        assert!(accept(None, &note, &pubkey(1), DID, NOW).is_err());
    }

    /// Every field is under the signature: a carrier that swaps the relay, the
    /// version or the expiry has a note nobody signed.
    #[test]
    fn a_note_changed_after_signing_is_refused() {
        let note = sign(DID, vec![relay("https://relay.one")], vec![device(9)], 7, NOW + 60, &key(1));
        let tampered = [
            ReachNote { relays: vec![relay("https://relay.evil")], ..note.clone() },
            ReachNote { version: 8, ..note.clone() },
            ReachNote { expires_at: NOW + 120, ..note.clone() },
            ReachNote { devices: vec![device(8)], ..note.clone() },
            ReachNote { relays: vec![RelayRef { key: Some(device(3)), ..relay("https://relay.one") }], ..note.clone() },
        ];
        for t in tampered {
            assert!(verify(&t, &pubkey(1), DID, NOW).is_err(), "{t:?}");
        }
    }

    /// **The invited key rides in the note, under its signature, and a note
    /// without one signs what it signed before the key existed**
    /// (`TASK-a-device-presents-its-relays-admission-tag-and-the-reach-row-sets-the-rule`).
    /// A carrier that adds, swaps or strips the key has a note nobody signed;
    /// a key that is not 32 bytes of base64url is refused; and the key never
    /// prints.
    #[test]
    fn a_notes_admission_key_is_signed_and_never_printed() {
        let admit = AdmitKey("A".repeat(43));
        let with = RelayRef { admit: Some(admit.clone()), ..relay("https://relay.one") };
        let note = sign(DID, vec![with.clone()], vec![], 7, NOW + 60, &key(1));
        assert_eq!(verify(&note, &pubkey(1), DID, NOW), Ok(()));
        assert!(!format!("{note:?}").contains(&admit.0), "the key printed");

        let stripped = ReachNote { relays: vec![relay("https://relay.one")], ..note.clone() };
        let swapped = ReachNote {
            relays: vec![RelayRef { admit: Some(AdmitKey("B".repeat(43))), ..relay("https://relay.one") }],
            ..note.clone()
        };
        assert!(verify(&stripped, &pubkey(1), DID, NOW).is_err());
        assert!(verify(&swapped, &pubkey(1), DID, NOW).is_err());

        let without = sign(DID, vec![relay("https://relay.one")], vec![], 7, NOW + 60, &key(1));
        let added = ReachNote { relays: vec![with], ..without.clone() };
        assert!(verify(&added, &pubkey(1), DID, NOW).is_err());

        // The bytes a keyless note signs are the bytes it signed before: the
        // key's frame is the only addition, and it is absent here.
        let mut before = REACH_NOTE_DOMAIN.to_vec();
        before.extend_from_slice(&(DID.len() as u32).to_be_bytes());
        before.extend_from_slice(DID.as_bytes());
        before.extend_from_slice(&1u32.to_be_bytes());
        before.push(0);
        before.extend_from_slice(&("https://relay.one".len() as u32).to_be_bytes());
        before.extend_from_slice(b"https://relay.one");
        before.extend_from_slice(&0u32.to_be_bytes());
        before.extend_from_slice(&7u64.to_be_bytes());
        before.extend_from_slice(&(NOW + 60).to_be_bytes());
        assert_eq!(signed_bytes(&without), before);

        let bad = sign(
            DID,
            vec![RelayRef { admit: Some(AdmitKey("not a key".into())), ..relay("https://relay.one") }],
            vec![],
            7,
            NOW + 60,
            &key(1),
        );
        assert!(verify(&bad, &pubkey(1), DID, NOW).is_err());
    }

    /// A note is someone's, and signed as theirs: one person's note cannot be
    /// replayed onto another's card, even by that other person.
    #[test]
    fn a_note_naming_someone_else_is_refused() {
        let note = sign("did:kel:Ebob", vec![relay("https://relay.one")], vec![], 7, NOW + 60, &key(1));
        assert!(verify(&note, &pubkey(1), DID, NOW).is_err());
    }

    #[test]
    fn an_expired_note_is_refused() {
        let note = sign(DID, vec![relay("https://relay.one")], vec![], 7, NOW, &key(1));
        assert_eq!(
            accept(None, &note, &pubkey(1), DID, NOW),
            Err("that reach note has expired".to_string())
        );
        let later = sign(DID, vec![relay("https://relay.one")], vec![], 7, NOW + 10, &key(1));
        assert!(accept(None, &later, &pubkey(1), DID, NOW + 10).is_err());
        assert!(accept(None, &later, &pubkey(1), DID, NOW + 9).is_ok());
    }

    #[test]
    fn a_note_claiming_too_long_a_life_is_refused() {
        let note = sign(DID, vec![], vec![], 7, NOW + MAX_NOTE_LIFETIME_SECS + 1, &key(1));
        assert!(verify(&note, &pubkey(1), DID, NOW).is_err());
        assert!(outlives_any_note(&note, NOW));
        assert!(!outlives_any_note(&note, NOW + 1), "a clock one second on reads it as a note's life");
        assert!(verify(&note, &pubkey(1), DID, NOW + 1).is_ok());
    }

    /// A clock behind by up to a week past the longest life explains a note
    /// claiming too long a life; one second further, nothing does — and
    /// neither does a note claiming for ever.
    #[test]
    fn a_reader_s_clock_explains_too_long_a_life_only_within_the_slack() {
        let edge = NOW + MAX_NOTE_LIFETIME_SECS + CLOCK_BEHIND_SLACK_SECS;
        let within = sign(DID, vec![], vec![], 7, edge, &key(1));
        assert!(clock_may_explain(&within, NOW), "a week past the longest life");
        let short = sign(DID, vec![], vec![], 7, NOW + MAX_NOTE_LIFETIME_SECS + 1, &key(1));
        assert!(clock_may_explain(&short, NOW));
        let past = sign(DID, vec![], vec![], 7, edge + 1, &key(1));
        assert!(!clock_may_explain(&past, NOW), "one second past the slack");
        let forever = sign(DID, vec![], vec![], 7, u64::MAX, &key(1));
        assert!(!clock_may_explain(&forever, NOW) && !clock_may_explain(&forever, u64::MAX - 1));
        let fits = sign(DID, vec![], vec![], 7, NOW + MAX_NOTE_LIFETIME_SECS, &key(1));
        assert!(!clock_may_explain(&fits, NOW), "a life that fits needs no explaining");
    }

    /// Newer wins, and only newer: a note replayed after a newer one arrived
    /// would pin the person to a relay they left.
    #[test]
    fn an_older_version_never_overwrites_a_newer() {
        let newer = sign(DID, vec![relay("https://relay.two")], vec![], 8, NOW + 60, &key(1));
        let older = sign(DID, vec![relay("https://relay.one")], vec![], 7, NOW + 60, &key(1));
        assert!(accept(Some(&newer), &older, &pubkey(1), DID, NOW).is_err());
        assert_eq!(accept(Some(&older), &newer, &pubkey(1), DID, NOW), Ok(Kept::Replaced));
        // The very note held is a retried delivery, not a conflict.
        assert_eq!(accept(Some(&newer), &newer, &pubkey(1), DID, NOW), Ok(Kept::AlreadyHeld));
        // A different note at the held version has no order to win by.
        let rival = sign(DID, vec![relay("https://relay.three")], vec![], 8, NOW + 60, &key(1));
        assert!(accept(Some(&newer), &rival, &pubkey(1), DID, NOW).is_err());
    }

    #[test]
    fn a_malformed_note_is_refused_before_its_signature() {
        let bad_addr = sign(DID, vec![relay("relay.one")], vec![], 7, NOW + 60, &key(1));
        assert!(verify(&bad_addr, &pubkey(1), DID, NOW).is_err());
        let bad_device = sign(DID, vec![], vec!["zz".to_string()], 7, NOW + 60, &key(1));
        assert!(verify(&bad_device, &pubkey(1), DID, NOW).is_err());
        let many = (0..=MAX_RELAYS).map(|i| relay(&format!("https://r{i}"))).collect();
        let too_many = sign(DID, many, vec![], 7, NOW + 60, &key(1));
        assert!(verify(&too_many, &pubkey(1), DID, NOW).is_err());
    }

    /// The daemon re-signs when a relay is added, and not otherwise.
    #[test]
    fn a_note_is_re_signed_when_a_relay_is_added_and_only_then() {
        let one = vec![relay("https://relay.one")];
        let first = next(None, DID, &one, &[], &key(1), NOW).expect("nothing held: sign one");
        assert_eq!(first.version, NOW);
        assert_eq!(next(Some(&first), DID, &one, &[], &key(1), NOW + 5), None, "unchanged: keep it");

        let two = vec![relay("https://relay.two"), relay("https://relay.one")];
        let second = next(Some(&first), DID, &two, &[], &key(1), NOW + 5).expect("a relay was added");
        assert_eq!(second.relays, two);
        assert!(second.version > first.version);
        assert_eq!(accept(Some(&first), &second, &pubkey(1), DID, NOW + 5), Ok(Kept::Replaced));
    }

    /// **The same relays in another order are the same note**
    /// (`TASK-a-persons-devices-on-different-relays-re-sign-one-reach-note-against-each-other`).
    /// Each of a person's devices lists its own relay first; the note one of
    /// them signed is kept by the other, and a relay that differs in its key or
    /// its admission key is a different relay.
    #[test]
    fn the_same_relays_in_another_order_are_not_signed_again() {
        let mine_first = vec![relay("https://relay.one"), relay("https://relay.two")];
        let theirs_first = vec![relay("https://relay.two"), relay("https://relay.one")];
        let held = next(None, DID, &theirs_first, &[], &key(1), NOW).unwrap();
        assert_eq!(next(Some(&held), DID, &mine_first, &[], &key(1), NOW + 5), None, "reordered: keep it");

        let rekeyed = vec![RelayRef { key: Some(device(3)), ..relay("https://relay.one") }, relay("https://relay.two")];
        assert!(next(Some(&held), DID, &rekeyed, &[], &key(1), NOW + 5).is_some(), "a relay's key is part of it");
        let fewer = vec![relay("https://relay.one")];
        assert!(next(Some(&held), DID, &fewer, &[], &key(1), NOW + 5).is_some(), "so is every relay");
        let doubled = [relay("https://relay.one"), relay("https://relay.one"), relay("https://relay.two")];
        let other = [relay("https://relay.one"), relay("https://relay.two"), relay("https://relay.two")];
        assert!(!same_relays(&doubled, &other), "a relay counts as often as it is listed");
    }

    #[test]
    fn a_note_is_re_signed_before_it_expires() {
        let one = vec![relay("https://relay.one")];
        let first = next(None, DID, &one, &[], &key(1), NOW).unwrap();
        let before_half = NOW + REACH_NOTE_TTL_SECS / 2 - 10;
        assert_eq!(next(Some(&first), DID, &one, &[], &key(1), before_half), None);
        let past_half = NOW + REACH_NOTE_TTL_SECS / 2 + 10;
        let renewed = next(Some(&first), DID, &one, &[], &key(1), past_half).expect("renew");
        assert!(renewed.expires_at > first.expires_at);
    }

    /// A clock that stepped backwards must not produce a version every card
    /// already holding the last note would refuse.
    #[test]
    fn the_version_climbs_past_the_last_even_when_the_clock_went_back() {
        let one = vec![relay("https://relay.one")];
        let first = next(None, DID, &one, &[], &key(1), NOW).unwrap();
        let two = vec![relay("https://relay.two")];
        let second = next(Some(&first), DID, &two, &[], &key(1), NOW - 1000).unwrap();
        assert_eq!(second.version, first.version + 1);
    }

    /// After a rotation the held note is under a key this identity no longer
    /// signs with; it is re-signed rather than kept, or the new key would never
    /// sign one.
    #[test]
    fn a_note_under_a_retired_key_is_re_signed() {
        let one = vec![relay("https://relay.one")];
        let first = next(None, DID, &one, &[], &key(1), NOW).unwrap();
        let again = next(Some(&first), DID, &one, &[], &key(2), NOW + 5).expect("rotated");
        assert_eq!(verify(&again, &pubkey(2), DID, NOW + 5), Ok(()));
    }
}
