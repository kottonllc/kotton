// SPDX-License-Identifier: AGPL-3.0-or-later
//! `ContactRequest` — what another person's node may say to yours
//! (RFC-0064, `DEC-0055`, RFC-0082 rule 1).
//!
//! A contact is admitted at a door of its own: a per-pair mailbox reservation
//! whose address is derived from the two identity keys, whose TLS verifier
//! admits exactly one key — that contact's — and which decodes **this** type.
//! Nothing else is reachable through it, so `ReadSealed` from a contact is not
//! refused by an arm; it cannot be named.
//!
//! That is the whole reason this type exists rather than a check on
//! `UserRequest`. RFC-0022 CP5 grants a contact *"authenticated public keys and
//! nothing else"*, and a vocabulary of one verb is what that sentence looks like
//! on the wire.
use serde::{Deserialize, Serialize};

/// A direct message as it crosses between two nodes — what a door hands over,
/// and what a vault may be asked to hold (`DEC-0056`).
///
/// Three fields, and none of them names a person. The sender, the recipient,
/// the thread and the time are *inside* the seal, signed by the sender's
/// identity key (RFC-0064 MS7), so a node that cannot open this learns exactly
/// what the relay learns: some bytes, at some time, under a fresh key. The
/// ephemeral key is per message (MS1) and is what a retried delivery is
/// recognised by.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedDm {
    /// The sender's ephemeral X25519 public key, base64. Fresh per message.
    pub ephemeral_pub: String,
    /// The ChaCha20-Poly1305 nonce, base64, 12 bytes.
    pub nonce: String,
    /// The ciphertext, base64: the signed inner message, sealed to the
    /// recipient's identity key.
    pub body: String,
}

/// One door a device hands its vault to hold (`DEC-0056`): the pair's inbox
/// handle for one epoch, as the key that reserves it and answers inside the
/// circuit, and the one key the door admits — the sender's handle for the same
/// pair and epoch. Both derive from the two identity keys on the device; the
/// vault can derive neither and is told nothing about which contact this is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldDoor {
    pub epoch: u64,
    /// The handle's Ed25519 seed, base64. Reserves the label at the relay and
    /// is the certificate inside a served circuit. Opens nothing.
    pub seed: String,
    /// The Ed25519 public key the door admits, base64.
    pub admit: String,
}

/// One outbox entry a device hands its own vault to carry while no device of
/// the sender's is awake (`TASK-a-message-stays-in-the-outbox-until-one-of-their-devices-signs-for-it`,
/// clause 3; RFC-0083 R1 and R2: the relay never keeps, the vault is the
/// person's node).
///
/// Exactly the bytes the outbox sends, and the pair's doors for the epochs the
/// vault may try them in — the same keys `HeldDoor` carries for this pair, so a
/// vault handed them learns no key it did not hold, and can open nothing: the
/// seed is the sender's handle for the pair and epoch, which labels the dial
/// and answers inside its circuit, and `admit` is the recipient's handle, which
/// the dial names. Nothing here names either person.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CarriedMessage {
    pub sealed: SealedDm,
    pub doors: Vec<HeldDoor>,
}

/// One message a vault carries for a person, as `FrameCarried` lists it: the
/// id the sender's device sealed it under, and the last epoch of the doors it
/// was handed — after which the vault cannot try it, and drops it. A device
/// reads this to hand a message again before its window closes, rather than
/// on every pass
/// (`TASK-a-device-hands-its-vault-a-week-of-doors-for-every-message-on-every-pickup`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Carrying {
    pub ephemeral_pub: String,
    pub through_epoch: u64,
}

/// A message a vault took for a person while none of their devices was awake,
/// returned to a device of theirs by `TakeDeliveries`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingDelivery {
    /// The door it arrived at — its `did:key`, which the device that made the
    /// door can map back to a contact and an epoch. Empty for a signature the
    /// vault kept for its sender after carrying their message (`CarryMessage`):
    /// that arrived at no door of theirs, and is filed under none, so the row
    /// records no hour but the hand-over's.
    pub handle_did: String,
    pub sealed: SealedDm,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContactRequest {
    /// Hand over one sealed message, addressed to the user whose mailbox this
    /// is.
    ///
    /// The recipient's node opens it, checks that it is addressed here and that
    /// the sender it names inside is the contact whose door it came through,
    /// and files it as its own `sh.kotton.message.v1` record. Article V's two
    /// copies, and neither contingent on the other.
    DeliverMessage {
        /// The message, sealed. Nothing outside the seal names anyone.
        sealed: SealedDm,
    },
    /// A sealed message handed over by whichever of the sender's nodes is
    /// carrying it — a device of theirs, or their vault while no device is
    /// awake — and the way every node hands a contact anything over the
    /// network: a direct message, a channel copy, a key-grant, a reach note, an
    /// acknowledgement sent back
    /// (`TASK-a-message-stays-in-the-outbox-until-one-of-their-devices-signs-for-it`,
    /// clause 3).
    ///
    /// **One act, a different answer.** The recipient files it exactly as
    /// `DeliverMessage`; what differs is who may read the answer. A vault
    /// carrying it is not the sender and must not learn which of the
    /// recipient's devices signed, nor who the recipient is — a
    /// [`DeliveryAck`] in the clear names both. So a device that signs for it
    /// answers [`ContactResponse::SignedSealed`]: the acknowledgement sealed to
    /// the sender, which a carrier keeps as it came and cannot open. A vault
    /// answering this door holds it and answers as a vault, `Delivered` with no
    /// acknowledgement — *sent*, never *delivered*.
    ///
    /// **Said the same way from a device and from a vault, and for every
    /// kind**, so the door cannot tell a message the sender's device handed over
    /// from one their vault carried — which, message by message, would be a
    /// record of when the sender's devices were off, kept by a contact — nor a
    /// direct message from a grant or a note, which the recipient's vault would
    /// otherwise read off every delivery it holds. `DeliverMessage` is what a
    /// node says to another account on the same machine.
    CarryMessage {
        /// The message, sealed — the outbox's own bytes, every try.
        sealed: SealedDm,
    },
}

impl ContactRequest {
    /// The sealed message this request hands over, whoever hands it.
    pub fn sealed(&self) -> &SealedDm {
        match self {
            ContactRequest::DeliverMessage { sealed } | ContactRequest::CarryMessage { sealed } => sealed,
        }
    }
}

/// One of the recipient's devices signing for a message
/// (`TASK-a-message-stays-in-the-outbox-until-one-of-their-devices-signs-for-it`).
///
/// **The only thing that can say a message arrived.** A vault or a relay can
/// hold a message and say so; neither holds a device key, so neither can make
/// this. The sender believes it only when `device` is a key listed in the
/// reach note its card holds for `from_did` — a note that person signed with
/// their identity key — and the signature below checks under that device key
/// (`kotton_crypto::delivery_ack`).
///
/// Not to be confused with the vault pickup's `ack`, which is a device telling
/// its *own* vault it may let a held message go.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryAck {
    /// The message signed for: its sealed ephemeral key, base64 — the id every
    /// copy of it carries and the one a second copy is dropped by.
    pub message_id: String,
    /// Who signs for it: the recipient's identity AID.
    pub from_did: String,
    /// Who it is signed to: the sender's identity AID.
    pub to_did: String,
    /// The device key that signed, hex Ed25519.
    pub device: String,
    /// Hex Ed25519 signature by `device` over every field above.
    pub sig: String,
}

/// What one sent direct message reads as, for the person who sent it
/// (`MessageDeliveries`): the record it was filed as, the one word
/// ([`Delivery::word`]), and when it is next tried while it waits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryReading {
    /// The sender's own record id for the message.
    pub message_id: String,
    /// `sent`, `delivered` or `waiting at home`.
    pub word: String,
    /// Unix seconds the next try is due, while the message is not yet signed
    /// for. `None` once it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContactResponse {
    /// Stored, or already held — the sender may retry an interrupted delivery
    /// without producing a second copy (`DEC-0055`: at-least-once, with the
    /// message's own ciphertext as the identity).
    Delivered {
        /// True when this delivery is what filed the record; false when the
        /// recipient already had it.
        stored: bool,
        /// Present when one of the recipient's **devices** filed the message
        /// and signs for it. A vault answering the door holds the message and
        /// sends none — it has no device key — so a message it took reads as
        /// *sent* until a device picks it up and signs for it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ack: Option<DeliveryAck>,
    },
    /// A device of the recipient's filed a message handed over as
    /// [`ContactRequest::CarryMessage`], or already held it, and signs for
    /// it: `ack` is an envelope whose inner message carries the
    /// [`DeliveryAck`], sealed to the sender like any message, so a carrier
    /// that reads this answer learns that a device signed and not which, nor
    /// for whom. The sender's device opens it in the answer; a sender whose
    /// vault carried it opens it at their next pickup from that vault.
    SignedSealed {
        /// As `Delivered`'s: whether this hand-over is what filed the record.
        stored: bool,
        ack: SealedDm,
    },
    /// Not stored, and why — a record addressed elsewhere, an unreadable
    /// record, or a store that refused it. Anything that may clear with time is
    /// said this way — a vault holding as much as it will, a card that could
    /// not be written, a key not unlocked — so the sender tries again. So is a
    /// card's refusal that says something about the recipient's node rather
    /// than what it was handed: no contact's card for the sender, or a clock
    /// behind the sender's by no more than a week past a note's longest life
    /// (`TASK-a-door-refusal-that-can-clear-settles-a-reach-note-version-until-the-next`).
    Refused { reason: String },
    /// Refused by the recipient's own card, as its verdict on what it was
    /// handed: a reach note that is not theirs, expired, or older than the one
    /// the card holds. Handed the same thing again, the card says the same, so
    /// the sender does not hand it again
    /// (`TASK-a-reach-note-a-contact-refused-is-sent-to-them-again-every-hour`).
    ///
    /// Only a device that opened the envelope can say it, and only of a note:
    /// a vault opens nothing, and a message is never a verdict a retry cannot
    /// change. A node that predates it reads this as an answer it cannot parse,
    /// which is a door that did not answer — tried again, as before.
    Declined { reason: String },
}

/// What became of a message once its sender's node had sealed and kept its own
/// copy (`DEC-0055`).
///
/// A send is two facts, and collapsing them into one loses the one that matters:
/// the sender's copy always exists, and whether the other copy does depends on
/// the world. Article X's honest floor is `Unreachable` — with nothing of theirs
/// awake and no vault, a message waits at home, and the person is told rather
/// than left to assume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Delivery {
    /// One of the recipient's devices filed it and signed for it
    /// ([`DeliveryAck`]), under a device key their reach note lists.
    Delivered,
    /// Handed to something of the recipient's that holds it — their vault —
    /// or to a node that did not sign for it. Kept in the sender's outbox and
    /// tried again until a device signs for it.
    Sent,
    /// The recipient already had it — a retried delivery, not a second copy.
    AlreadyHeld,
    /// Filed directly: the recipient is another account on this machine, so no
    /// carrier was involved at all.
    Local,
    /// Nowhere to hand it to, or the hand-off was refused. The sender's copy is
    /// kept; nothing was lost, and nothing arrived.
    Unreachable { reason: String },
}

/// Where one member's copy of a **channel** message went (`DEC-0055`: *a group
/// message is the same verb to each current member*).
///
/// One entry per current member other than the sender. A member is never a
/// failed send: the sender's own copy exists regardless (Article V), and a
/// member with nothing awake and no vault is `Unreachable` for their copy alone
/// while every other copy is handed over.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberDelivery {
    pub member_did: String,
    pub delivery: Delivery,
}

impl Delivery {
    /// The one word the sender is owed, in their language rather than the
    /// enum's (`DEC-0056`).
    ///
    /// **Four words, and the mapping lives here** because it is the point where
    /// a wire fact becomes a sentence a person reads, and there is exactly one
    /// of those. It was written twice before this — once in the daemon's
    /// occupant host and once in the browser's page — and a fifth word or a
    /// leaked `reason` reaching one surface and not the other is the failure
    /// nobody sees, because each surface looks right on its own.
    ///
    /// **`Unreachable`'s `reason` is deliberately dropped.** It names the
    /// machinery — which of the recipient's nodes was tried, whether a vault
    /// answered — and a sender who can read that is timing someone's day. The
    /// sender is told the message is waiting at their *own* home and nothing
    /// about the recipient's.
    ///
    /// **`AlreadyHeld` is `delivered`**, not a fifth word: a retried hand-off
    /// that finds the record already there arrived, and the difference between
    /// the first attempt and the second is the sender's business only insofar
    /// as it is not.
    pub fn word(&self) -> &'static str {
        match self {
            Delivery::Delivered | Delivery::AlreadyHeld => "delivered",
            Delivery::Sent => "sent",
            Delivery::Local => "local",
            Delivery::Unreachable { .. } => "waiting at home",
        }
    }
}

#[cfg(test)]
mod delivery_word_tests {
    use super::Delivery;

    /// `DEC-0056` allows the sender four words. This pins them, because this
    /// mapping is the only place the enum becomes the vocabulary — and a fifth
    /// word, or a leaked `Unreachable` reason, would reach a person's screen
    /// with nothing else noticing.
    #[test]
    fn the_sender_is_owed_four_words_and_no_others() {
        assert_eq!(Delivery::Delivered.word(), "delivered");
        assert_eq!(
            Delivery::AlreadyHeld.word(),
            "delivered",
            "a retried delivery that finds the record already held is delivered; \
             the sender is not owed the difference"
        );
        assert_eq!(Delivery::Local.word(), "local");
        assert_eq!(
            Delivery::Sent.word(),
            "sent",
            "held for them, and no device of theirs has signed for it yet"
        );

        let waiting = Delivery::Unreachable {
            reason: "no device awake and no vault".to_string(),
        };
        assert_eq!(waiting.word(), "waiting at home");
        assert!(
            !waiting.word().contains("vault") && !waiting.word().contains("device"),
            "the reason names the machinery and must not reach the word: {}",
            waiting.word()
        );
    }
}
