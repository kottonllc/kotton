// SPDX-License-Identifier: AGPL-3.0-or-later
//! The direct-message envelope: what is sealed, what is signed, and what shows
//! (RFC-0064 MS1 and MS7; `DEC-0056`).
//!
//! **Outside the seal, nothing names a person.** A [`SealedDm`] is an ephemeral
//! key, a nonce and ciphertext. That is the whole of what crosses a door, and
//! the whole of what a vault holds for a person who is asleep — so a node that
//! cannot open it learns what the relay learns and no more.
//!
//! **Inside the seal, the sender signs.** The plaintext is the [`DmInner`]
//! fields followed by the sender's Ed25519 signature over them, under a domain
//! tag. The recipient checks that signature against the key of the contact
//! whose door the message arrived through. This is what stops a node that
//! holds the pair's *handle* keys — the vault, under `DEC-0056` — from speaking
//! as the person: those keys reserve a door and answer it, and cannot produce
//! this signature, because the identity key never leaves the person's devices.
//!
//! The signature covers the serialised inner bytes exactly as sealed, so there
//! is no canonical form to agree on: what was signed is what was sent.
//!
//! **A channel copy's ciphertext rides after the JSON, as bytes.** The sealed
//! plaintext is the [`DmInner`] JSON object, then — for a channel copy only —
//! the channel ciphertext as the bytes it is ([`ChannelCopy::body`]), then the
//! signature over both. The JSON object ends where its closing brace does, so
//! nothing has to say where the ciphertext starts; the signature's 64 bytes say
//! where it ends. It was base64 inside the JSON until 2026-10-09, and the JSON
//! is sealed and rides base64 again, so a group's every message carried its
//! ciphertext encoded twice
//! (`TASK-a-channel-copy-carries-its-sealed-bytes-base64-twice`).

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use kotton_crypto::x25519::{dm_decrypt, dm_encrypt};
use kotton_wire::ipc::SealedDm;
use serde::{Deserialize, Serialize};

/// Domain tag under the sender's signature, so a signature over a message can
/// never be mistaken for a signature over anything else the identity key signs.
pub const DM_SIG_DOMAIN: &[u8] = b"kotton:dm:v1:sender";

/// A channel message's body, carried inside a direct-message envelope
/// (`DEC-0055`: *a group message is the same verb to each current member*).
///
/// **Two layers, and each does one job.** The channel key seals the body, and it
/// is the group's secret: the door this travels through, and any vault holding
/// it on the way, can no more derive it than they can derive a DM's plaintext.
/// The DM envelope around it is transport to *one* member's door — it names who
/// this copy is for, and carries the sender's signature.
///
/// So a member's copy of a channel message is the same ciphertext every other
/// member gets, and `message_decrypt_channel` opens it with their own key-grant
/// exactly as it opens one filed locally. What differs between members is only
/// the envelope, which is thrown away once the copy is filed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelCopy {
    pub channel_did: String,
    /// The key-grant epoch this was sealed under (RFC-0064). Stamped so history
    /// can say which stretch of the conversation a message belongs to; opening
    /// it does not depend on the epoch and trusts the AEAD instead.
    pub epoch: u64,
    /// The channel ciphertext — sealed under the channel key — as its bytes.
    ///
    /// **Two forms, and one place decides between them: [`envelope_form`] and
    /// [`parse`].** Inside the envelope a member is handed, the bytes ride raw
    /// after the inner JSON object, inside the seal and under the signature,
    /// and the JSON carries no `body` at all. Inside the JSON they would be
    /// base64 that the seal then base64s again, which cost every channel
    /// message a third on the wire and a share to a group a fifth of its cap.
    /// **Everywhere else** a `DmInner` is serialised — a streamed share's
    /// manifest kept waiting on the shelf (`stream::Waiting`), a test — the
    /// field is base64 like any other bytes in JSON, so nothing that keeps a
    /// copy loses its ciphertext.
    ///
    /// **Not outside the seal**, though the bytes are already ciphertext:
    /// every member is handed the same ones, so outside each member's own seal
    /// they would be a key joining every door they were handed at into one
    /// channel — the record a relay or a vault holding several members' mail
    /// could compose. Inside it, each member's copy is bytes nobody but they
    /// can relate to anyone else's.
    #[serde(default, with = "kotton_wire::base64_bytes", skip_serializing_if = "Vec::is_empty")]
    pub body: Vec<u8>,
    /// The channel nonce, base64.
    pub nonce: String,
}

/// A channel **key-grant** carried inside a direct-message envelope.
///
/// Admission travels the same door a message does, for the same reason: a channel
/// has no node of its own, so the only route to a member is the one the granter
/// already has to them. Without this a member on another daemon was granted a key
/// that never left the granter's store — the grant record said *"theirs travels by
/// sync"*, and between two people who have only paired there is no sync to travel
/// by. A cross-daemon channel could be created and could never be opened.
///
/// What is inside is the grant as the recipient will file it: the channel key
/// wrapped to *their* identity key, which the granter did with the key they hold.
/// A grant that arrives wrapped to somebody else is inert — it will not unwrap —
/// so the door's own check (this came from the contact it says it did) is the
/// whole of what has to be true.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelGrant {
    pub channel_did: String,
    pub epoch: u64,
    /// The channel key, wrapped to the recipient's identity key, base64.
    pub enc_key: String,
    pub nonce: String,
    pub ephemeral_pub: String,
    pub granted_at: u64,
    /// Who holds this epoch's key, sealed under it — the epoch's **roster**,
    /// written by whoever minted the epoch (RFC-0064, *Encryption model for
    /// channels*, the note of 2026-10-08). Opened with the same unwrap as the
    /// key: unwrap the key, then open this.
    ///
    /// Absent on a grant minted before rosters existed. Omitted rather than
    /// null for the same reason as [`DmInner::channel`]: the signature covers
    /// the serialised bytes as sealed, so a grant without one must serialise as
    /// it did before this field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roster: Option<SealedRoster>,
}

/// A channel epoch's roster — every member that epoch's key was granted to,
/// `{did, key, reach, kel}`: each with the identity key, the reach note and
/// the key log its minting member held for them, the key believed only when
/// the log yields it (`messages::RosterMember`, since 2026-10-09; DIDs alone
/// before) — sealed under that epoch's channel key.
///
/// **Inside the seal, and nowhere else.** A relay or a vault carrying a grant
/// sees base64 it cannot open, as it does today; the members of a channel are
/// learned by exactly the people who hold the key, at the moment they learn
/// the key and never before. No record kind is added for it: it rides in each
/// key-grant of the epoch, the granter's own copy included.
///
/// Where a channel's *name* would go too, if the owner rules for the naming
/// idea's Shape 1
/// (`IDEA-a-channel-has-no-name-and-nothing-lists-the-channels-a-person-is-in`).
/// The plaintext is an object for that reason; the name is not in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedRoster {
    /// The roster ciphertext, base64 — sealed under the epoch's channel key.
    pub body: String,
    /// Its nonce, base64.
    pub nonce: String,
}

/// What a direct message says, once opened. Every field here is the sender's
/// claim, and the signature is what makes it theirs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DmInner {
    pub from_did: String,
    pub to_did: String,
    pub thread_id: String,
    pub sent_at: u64,
    /// `"text"` today; RFC-0064 MS5's `app:<nsid>` later.
    #[serde(rename = "type")]
    pub kind: String,
    pub text: String,
    /// Present when this envelope carries a **channel** message rather than a
    /// direct one. `text` is then empty and the readable body is
    /// [`ChannelCopy::body`], which only a member holding the channel key can
    /// open.
    ///
    /// `skip_serializing_if` is load-bearing rather than tidy: the signature
    /// covers the serialised inner bytes exactly as sealed, so a direct message
    /// must serialise to the same bytes it did before this field existed, or
    /// every node that has not upgraded would read a forgery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<ChannelCopy>,
    /// Present when this envelope carries a channel **key-grant** — admission
    /// rather than a message. `text` is then empty and nothing is filed as a
    /// message.
    ///
    /// Omitted rather than null for the same reason as `channel`: the signature
    /// covers the bytes as sealed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<ChannelGrant>,
    /// Present when this envelope carries the sender's **reach note** — where
    /// they can be reached, signed by them — rather than a message. `text` is
    /// then empty, nothing is filed as a message, and the recipient's card for
    /// the sender takes the note if it is newer
    /// (`TASK-a-persons-reach-note-is-signed-by-them-and-replaces-relay-url`).
    ///
    /// Sealed like everything else here, so the only parties who ever learn a
    /// person's relays are the people they have paired with. Omitted rather
    /// than null for the same reason as `channel`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reach: Option<kotton_crypto::reach_note::ReachNote>,
    /// Present when this envelope carries one of the sender's **devices**
    /// signing for a message the recipient sent them — the way an
    /// acknowledgement travels back when the message was picked up from a
    /// vault rather than handed to a device at its door
    /// (`TASK-a-message-stays-in-the-outbox-until-one-of-their-devices-signs-for-it`).
    /// `text` is then empty and nothing is filed as a message. Omitted rather
    /// than null for the same reason as `channel`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack: Option<kotton_wire::ipc::DeliveryAck>,
    /// The sender's **key log**, carried beside their reach note, so a contact
    /// whose card holds a key the sender has since rotated away can learn the
    /// new one from the identity's own proof
    /// (`TASK-a-rotated-persons-contacts-keep-the-key-it-retired`). The card
    /// takes a key from nothing else: the log replays from the AID the card
    /// already holds and must continue the log it kept
    /// (`kotton_crypto::kel_verify::contact_key_from_log`), and this envelope's
    /// signature must then hold under the key it resolves to.
    ///
    /// Sent with every note rather than after a rotation, so its presence says
    /// nothing about whether one happened. Omitted when empty for the same
    /// reason as `channel`: the signature covers the bytes as sealed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kel: Vec<kotton_wire::kel::KelEvent>,
    /// Present when this envelope carries a **share** — a file handed to this
    /// person, `kind` [`crate::share::MESSAGE_TYPE`] (RFC-0090, *The record*).
    /// `text` is then the file's name, which is what the conversation shows; the
    /// manifest is what the recipient's node verifies and files under *Shared
    /// with you*. Sealed to a recipient it never carries `origin`
    /// ([`crate::share::Manifest::for_recipient`]).
    ///
    /// Omitted rather than null for the same reason as `channel`: the signature
    /// covers the bytes as sealed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub share: Option<crate::share::Manifest>,
    /// Present when this envelope carries one **range** of a streamed share's
    /// bytes — the share's manifest is a message of its own, and its bytes
    /// follow it this way (RFC-0090, *Above the frame cap*; RFC-0048). `text`
    /// is then empty and nothing is filed as a message: the recipient's node
    /// keeps the range toward its stream, and files the share once the stream
    /// is whole and hashes to the manifest's digest. For a share to a **group**
    /// the envelope carries [`Self::channel`] as well, and the range's bytes are
    /// that channel ciphertext, not in the range
    /// (`TASK-a-share-to-a-group-above-the-inline-cap-is-a-stream-to-each-member`).
    ///
    /// Omitted rather than null for the same reason as `channel`: the signature
    /// covers the bytes as sealed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range: Option<crate::share::Range>,
}

/// Seal `inner` to `recipient_pub`, signed by `sender`.
pub fn seal(
    inner: &DmInner,
    sender: &SigningKey,
    recipient_pub: &[u8; 32],
) -> Result<SealedDm, String> {
    let bytes = envelope_form(inner)?;
    let sig = sender.sign(&signed_bytes(&bytes));
    let mut plaintext = bytes;
    plaintext.extend_from_slice(&sig.to_bytes());
    let (ciphertext, nonce, eph_pub) =
        dm_encrypt(&plaintext, recipient_pub).map_err(|e| format!("encryption failed: {e}"))?;
    Ok(SealedDm {
        ephemeral_pub: B64.encode(eph_pub),
        nonce: B64.encode(nonce),
        body: B64.encode(ciphertext),
    })
}

/// Open `sealed` as `recipient` and verify that `sender_pub` signed what is
/// inside. The one entry point a door uses: a message that opens but was not
/// signed by the contact whose door it came through is refused as a forgery,
/// not filed as a curiosity.
pub fn open(
    sealed: &SealedDm,
    recipient: &SigningKey,
    sender_pub: &[u8; 32],
) -> Result<DmInner, String> {
    let (bytes, sig) = unseal(sealed, recipient)?;
    let key = VerifyingKey::from_bytes(sender_pub).map_err(|_| "sender key is not a valid Ed25519 key".to_string())?;
    key.verify(&signed_bytes(&bytes), &sig)
        .map_err(|_| "the message was not signed by the contact it arrived from".to_string())?;
    parse(&bytes)
}

/// A message opened but not yet held to anyone: what it claims, and the
/// bytes and signature that claim is checked against once the claimed
/// sender's key is known. For a message taken from a vault, whose door
/// proved a pair key and not a person: the device opens, reads `from_did`,
/// looks that contact's key up, and verifies.
pub struct Claimed {
    pub inner: DmInner,
    bytes: Vec<u8>,
    sig: Signature,
}

impl Claimed {
    /// Hold the claim to `sender_pub`. A claim that fails is a forgery.
    pub fn verify(&self, sender_pub: &[u8; 32]) -> Result<(), String> {
        let key = VerifyingKey::from_bytes(sender_pub)
            .map_err(|_| "sender key is not a valid Ed25519 key".to_string())?;
        key.verify(&signed_bytes(&self.bytes), &self.sig)
            .map_err(|_| "the message was not signed by the contact it claims".to_string())
    }
}

/// Open `sealed` as `recipient` and return the claim, unverified. The caller
/// must [`Claimed::verify`] before believing any of it.
pub fn open_claimed(sealed: &SealedDm, recipient: &SigningKey) -> Result<Claimed, String> {
    let (bytes, sig) = unseal(sealed, recipient)?;
    let inner = parse(&bytes)?;
    Ok(Claimed { inner, bytes, sig })
}

/// Open `sealed` as `recipient` without checking who signed it.
///
/// For reading a record already in the recipient's own store: the door
/// verified the signature when it filed the record, and the stored `from_did`
/// is that verified claim. Never the entry point for anything that *arrives*.
pub fn open_filed(sealed: &SealedDm, recipient: &SigningKey) -> Result<DmInner, String> {
    let (bytes, _sig) = unseal(sealed, recipient)?;
    parse(&bytes)
}

fn unseal(sealed: &SealedDm, recipient: &SigningKey) -> Result<(Vec<u8>, Signature), String> {
    let ciphertext = B64.decode(&sealed.body).map_err(|_| "DM: body is not base64".to_string())?;
    let nonce: [u8; 12] = B64
        .decode(&sealed.nonce)
        .map_err(|_| "DM: nonce is not base64".to_string())?
        .try_into()
        .map_err(|_| "DM: nonce must be 12 bytes".to_string())?;
    let eph_pub: [u8; 32] = B64
        .decode(&sealed.ephemeral_pub)
        .map_err(|_| "DM: ephemeral_pub is not base64".to_string())?
        .try_into()
        .map_err(|_| "DM: ephemeral_pub must be 32 bytes".to_string())?;
    let plaintext = dm_decrypt(&ciphertext, &nonce, &eph_pub, recipient)
        .map_err(|e| format!("DM decryption failed: {e}"))?;
    if plaintext.len() < Signature::BYTE_SIZE {
        return Err("DM: opened, but carries no sender signature".to_string());
    }
    let (bytes, sig) = plaintext.split_at(plaintext.len() - Signature::BYTE_SIZE);
    let sig = Signature::from_slice(sig).map_err(|_| "DM: malformed sender signature".to_string())?;
    Ok((bytes.to_vec(), sig))
}

fn signed_bytes(inner: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(DM_SIG_DOMAIN.len() + inner.len());
    m.extend_from_slice(DM_SIG_DOMAIN);
    m.extend_from_slice(inner);
    m
}

/// What the sender signs and seals for `inner`: its JSON object, and — for a
/// channel copy, and only for one — the channel ciphertext after it as raw
/// bytes, with no `body` in the JSON. The one writer of that form; [`parse`] is
/// its one reader. Any other serialisation of a `DmInner` carries the body
/// base64 in its field ([`ChannelCopy::body`]).
fn envelope_form(inner: &DmInner) -> Result<Vec<u8>, String> {
    let json = |i: &DmInner| serde_json::to_vec(i).map_err(|e| format!("envelope: {e}"));
    let Some(copy) = &inner.channel else {
        return json(inner);
    };
    if copy.body.is_empty() {
        return Err("envelope: a channel copy with no channel ciphertext".to_string());
    }
    // The JSON without the body. A clone, so the caller's copy is untouched;
    // the body is cloned and dropped with it, a cost beside the seal itself.
    let mut head = inner.clone();
    if let Some(c) = &mut head.channel {
        c.body = Vec::new();
    }
    let mut bytes = json(&head)?;
    bytes.extend_from_slice(&copy.body);
    Ok(bytes)
}

/// The signed bytes as a message — [`envelope_form`] read back: the
/// [`DmInner`] JSON object, and after it the channel ciphertext when, and only
/// when, the object carries a channel copy. A channel copy whose JSON carries
/// a `body` is refused, whatever follows it: in the envelope the ciphertext has
/// one form, and a copy in the older one (base64 inside the JSON) is not read.
///
/// Leading whitespace before the JSON is accepted, as the JSON reader accepts
/// it. That is harmless: the bytes are the signer's own, under their own
/// signature, and the boundary that matters — where the ciphertext starts — is
/// the end of the JSON value, which whitespace before it does not move.
fn parse(bytes: &[u8]) -> Result<DmInner, String> {
    let not_a_message = |e: String| format!("DM: opened, but is not a message: {e}");
    let mut stream = serde_json::Deserializer::from_slice(bytes).into_iter::<DmInner>();
    let mut inner = match stream.next() {
        Some(Ok(inner)) => inner,
        Some(Err(e)) => return Err(not_a_message(e.to_string())),
        None => return Err(not_a_message("it is empty".to_string())),
    };
    let after = &bytes[stream.byte_offset()..];
    match (&mut inner.channel, after.is_empty()) {
        (Some(copy), _) if !copy.body.is_empty() => {
            return Err(not_a_message(
                "a channel copy that carries its ciphertext inside the JSON, where the envelope does not carry it".to_string(),
            ))
        }
        (Some(copy), false) => copy.body = after.to_vec(),
        (Some(_), true) => return Err(not_a_message("a channel copy that carries no channel ciphertext".to_string())),
        (None, true) => {}
        (None, false) => return Err(not_a_message("it carries bytes after it that nothing reads".to_string())),
    }
    Ok(inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn inner() -> DmInner {
        DmInner {
            from_did: "did:kel:alice".into(),
            to_did: "did:kel:bob".into(),
            thread_id: "t1".into(),
            sent_at: 1_700_000_000,
            kind: "text".into(),
            text: "the milk is in the fridge".into(),
            channel: None,
            grant: None,
            reach: None,
            ack: None,
            kel: Vec::new(),
            share: None,
            range: None,
        }
    }

    /// The compatibility the signature depends on.
    ///
    /// A signature is over the serialised inner bytes exactly as sealed, so a
    /// direct message must serialise to the same bytes it did before `channel`
    /// existed. If the field were ever written as `null` instead of omitted, a
    /// node on the older shape would verify a signature over bytes it never
    /// received and read every direct message as a forgery.
    #[test]
    fn a_direct_message_serialises_as_though_the_channel_field_were_not_there() {
        let bytes = serde_json::to_vec(&inner()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(
            !text.contains("channel"),
            "a direct message must not carry the field at all, got {text}"
        );
        assert!(
            !text.contains("reach"),
            "nor the reach note's, which is newer still, got {text}"
        );
    }

    /// A reach note travels in the same envelope as a message, sealed and
    /// signed the same way, and comes out of the seal exactly as it went in.
    #[test]
    fn a_reach_note_is_sealed_and_opened_like_any_other_message() {
        let alice = key(1);
        let bob = key(2);
        let mut i = inner();
        i.text = String::new();
        i.kind = "reach".into();
        i.reach = kotton_crypto::reach_note::next(
            None,
            "did:kel:alice",
            &[kotton_crypto::reach_note::RelayRef { key: None, addr: "https://relay.alice".into(), admit: None }],
            &[],
            &alice,
            1_700_000_000,
        );
        let sealed = seal(&i, &alice, &bob.verifying_key().to_bytes()).unwrap();
        assert!(
            !serde_json::to_string(&sealed).unwrap().contains("relay.alice"),
            "the relay a person is found at is legible to nobody but the contact"
        );
        let opened = open(&sealed, &bob, &alice.verifying_key().to_bytes()).unwrap();
        assert_eq!(opened.reach, i.reach);
    }

    /// And a channel copy travels in the same envelope, signed the same way.
    #[test]
    fn a_channel_copy_is_sealed_and_opened_like_any_other_message() {
        let alice = key(1);
        let bob = key(2);
        let mut i = inner();
        i.text = String::new();
        i.channel = Some(ChannelCopy {
            channel_did: "did:kel:the-ferry-thread".into(),
            epoch: 3,
            body: b"channel-ciphertext \x00\x7f}{ \xff".to_vec(),
            nonce: "bm9uY2U".into(),
        });

        let sealed = seal(&i, &alice, &bob.verifying_key().to_bytes()).unwrap();
        let opened = open(&sealed, &bob, &alice.verifying_key().to_bytes()).unwrap();
        assert_eq!(opened, i);
        let claimed = open_claimed(&sealed, &bob).unwrap();
        claimed.verify(&alice.verifying_key().to_bytes()).unwrap();
        assert_eq!(claimed.inner, i);

        // The whole point of the two layers: what crosses the door names no
        // channel, so a vault holding this learns nothing it could not learn
        // from a direct message.
        let outside = serde_json::to_string(&sealed).unwrap();
        assert!(
            !outside.contains("ferry") && !outside.contains("channel_did"),
            "the channel must not show outside the seal, got {outside}"
        );
    }

    /// **A channel copy carries its ciphertext once**
    /// (`TASK-a-channel-copy-carries-its-sealed-bytes-base64-twice`): inside
    /// the seal, the ciphertext is its own bytes after the JSON — not base64
    /// in it — so the only base64 it ever rides in is the envelope's. The
    /// ciphertext's base64 appears nowhere in what was sealed, and the sealed
    /// plaintext is the JSON, the bytes, and the signature, to the byte.
    #[test]
    fn a_channel_copy_carries_its_ciphertext_as_bytes_after_the_json_and_nowhere_else() {
        let (alice, bob) = (key(1), key(2));
        let ciphertext: Vec<u8> = (0..=255u8).cycle().take(3_000).collect();
        let mut i = inner();
        i.text = String::new();
        i.channel = Some(ChannelCopy {
            channel_did: "did:kel:the-ferry-thread".into(),
            epoch: 3,
            body: ciphertext.clone(),
            nonce: "bm9uY2U".into(),
        });
        let sealed = seal(&i, &alice, &bob.verifying_key().to_bytes()).unwrap();
        let (signed, _) = unseal(&sealed, &bob).unwrap();
        let mut head = i.clone();
        head.channel.as_mut().unwrap().body = Vec::new();
        let json = serde_json::to_vec(&head).unwrap();
        assert!(!String::from_utf8_lossy(&json).contains("\"body\""), "the JSON names no body");
        assert_eq!(signed.len(), json.len() + ciphertext.len(), "the JSON and the ciphertext, nothing else");
        assert_eq!((&signed[..json.len()], &signed[json.len()..]), (&json[..], &ciphertext[..]));
        let encoded = B64.encode(&ciphertext);
        assert!(
            !String::from_utf8_lossy(&json).contains(&encoded[..64]),
            "the ciphertext is not base64 inside the JSON as well"
        );
    }

    /// The bytes after the JSON are a channel copy's and nothing else's: a
    /// direct message carrying any is not a message, and neither is a
    /// channel copy carrying none — each refused once opened and verified,
    /// rather than read with a part of what was signed ignored.
    #[test]
    fn bytes_after_the_json_are_read_only_as_a_channel_copys_ciphertext() {
        let (alice, bob) = (key(1), key(2));
        let sealed_with = |json: Vec<u8>, after: &[u8]| {
            let mut bytes = json;
            bytes.extend_from_slice(after);
            let sig = alice.sign(&signed_bytes(&bytes));
            bytes.extend_from_slice(&sig.to_bytes());
            let (ct, nonce, eph) = dm_encrypt(&bytes, &bob.verifying_key().to_bytes()).unwrap();
            SealedDm { ephemeral_pub: B64.encode(eph), nonce: B64.encode(nonce), body: B64.encode(ct) }
        };
        let direct = serde_json::to_vec(&inner()).unwrap();
        let err = open(&sealed_with(direct, b"stowaway"), &bob, &alice.verifying_key().to_bytes()).unwrap_err();
        assert!(err.contains("bytes after it that nothing reads"), "{err}");

        let mut i = inner();
        i.channel = Some(ChannelCopy { channel_did: "did:kel:c".into(), epoch: 1, body: Vec::new(), nonce: "bm9uY2U".into() });
        let channel = serde_json::to_vec(&i).unwrap();
        let err = open(&sealed_with(channel, b""), &bob, &alice.verifying_key().to_bytes()).unwrap_err();
        assert!(err.contains("carries no channel ciphertext"), "{err}");

        // The older form — the ciphertext base64 inside the JSON — is not read,
        // with bytes after it or without.
        i.channel.as_mut().unwrap().body = b"channel-ciphertext".to_vec();
        let older = serde_json::to_vec(&i).unwrap();
        assert!(String::from_utf8_lossy(&older).contains("\"body\""));
        for after in [&b""[..], b"more"] {
            let err = open(&sealed_with(older.clone(), after), &bob, &alice.verifying_key().to_bytes()).unwrap_err();
            assert!(err.contains("inside the JSON"), "{err}");
        }
    }

    /// **Outside the envelope a copy keeps its ciphertext.** A `DmInner` is
    /// serialised elsewhere too — a streamed share's manifest waits on the
    /// shelf as one (`stream::Waiting`) — and there the body is base64 in its
    /// field and comes back as the same bytes. Skipped there, a group share
    /// that streamed would be opened with no ciphertext and declined.
    #[test]
    fn a_channel_copy_serialised_outside_the_envelope_keeps_its_ciphertext() {
        let mut i = inner();
        i.channel = Some(ChannelCopy {
            channel_did: "did:kel:the-ferry-thread".into(),
            epoch: 3,
            body: (0..=255u8).collect(),
            nonce: "bm9uY2U".into(),
        });
        let json = serde_json::to_vec(&i).unwrap();
        let back: DmInner = serde_json::from_slice(&json).unwrap();
        assert_eq!(back, i);
    }

    #[test]
    fn what_is_sealed_is_what_is_opened() {
        let alice = key(1);
        let bob = key(2);
        let sealed = seal(&inner(), &alice, &bob.verifying_key().to_bytes()).unwrap();
        let opened = open(&sealed, &bob, &alice.verifying_key().to_bytes()).unwrap();
        assert_eq!(opened, inner());
    }

    /// The whole reason the signature exists: a party holding the recipient's
    /// pair keys — a vault, under `DEC-0056` — can reserve the door and answer
    /// it, but cannot write a message that opens as the person's.
    #[test]
    fn a_message_signed_by_someone_else_is_refused_at_the_door() {
        let alice = key(1);
        let bob = key(2);
        let landlord = key(3);
        let sealed = seal(&inner(), &landlord, &bob.verifying_key().to_bytes()).unwrap();
        let err = open(&sealed, &bob, &alice.verifying_key().to_bytes()).unwrap_err();
        assert!(err.contains("not signed by the contact"), "{err}");
    }

    /// Nothing outside the seal names anyone: the wire form has three fields,
    /// and the sender, recipient, thread and time are all inside.
    ///
    /// **The needles are long on purpose.** This test searched for `"t1"` — the
    /// fixture's whole thread id — until 2026-09-12, and the wire form is
    /// base64, so two given characters turn up in a few hundred random ones
    /// about a tenth of the time. Measured: ten runs, one red, with
    /// `t1 is legible on the outside` and nothing legible about it. A test that
    /// fails on the ciphertext's luck rather than on the property is not a
    /// flaky test to re-run, it is a test asserting something other than what
    /// it says (`TASK-a-plaintext-search-over-ciphertext-needs-a-long-needle`).
    ///
    /// A needle this long collides by chance at a rate below any number of runs
    /// this repository will ever do, so a red here is the real thing: plaintext
    /// on the outside.
    #[test]
    fn the_outside_names_nobody() {
        let sealed = seal(&inner(), &key(1), &key(2).verifying_key().to_bytes()).unwrap();
        let v = serde_json::to_value(&sealed).unwrap();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys, ["body", "ephemeral_pub", "nonce"]);
        let wire = serde_json::to_string(&sealed).unwrap();
        for word in [
            "did:kel:alice",
            "did:kel:bob",
            "the milk is in the fridge",
            // Every field of the fixture that is long enough to search for. The
            // thread id (`t1`) and the timestamp are not, and are covered by
            // `a_sealed_dm_opens_for_its_recipient_and_nobody_else` reading
            // them back out of the seal rather than by a substring search that
            // cannot tell a leak from a coincidence.
            "text",
        ] {
            assert!(
                word.len() >= 4,
                "a needle shorter than four characters finds itself in base64 by chance"
            );
            assert!(!word.is_empty() && !wire.contains(word), "{word} is legible on the outside");
        }
    }

    /// A signature is over the bytes as sealed, so changing one inner byte
    /// after signing — which only someone who can open it could do — fails.
    #[test]
    fn a_tampered_inner_fails() {
        let alice = key(1);
        let bob = key(2);
        let mut i = inner();
        let sealed = seal(&i, &alice, &bob.verifying_key().to_bytes()).unwrap();
        i.text.push('!');
        let bytes = serde_json::to_vec(&i).unwrap();
        let (_, sig) = unseal(&sealed, &bob).unwrap();
        let key = alice.verifying_key();
        assert!(key.verify(&signed_bytes(&bytes), &sig).is_err());
    }

    #[test]
    fn a_plaintext_without_a_signature_is_not_a_message() {
        let bob = key(2);
        let (ct, nonce, eph) = dm_encrypt(b"hi", &bob.verifying_key().to_bytes()).unwrap();
        let sealed = SealedDm {
            ephemeral_pub: B64.encode(eph),
            nonce: B64.encode(nonce),
            body: B64.encode(ct),
        };
        let err = open_filed(&sealed, &bob).unwrap_err();
        assert!(err.contains("no sender signature"), "{err}");
    }
}
