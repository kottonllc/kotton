// SPDX-License-Identifier: AGPL-3.0-or-later
//! A device signing for a message, and the rule for believing it
//! (`TASK-a-message-stays-in-the-outbox-until-one-of-their-devices-signs-for-it`).
//!
//! A message stays in its sender's outbox until one of the recipient's devices
//! signs for it. That signature is a [`DeliveryAck`], and it is what turns
//! *sent* into *delivered*, so the rule for believing one is the whole of what
//! *delivered* means:
//!
//! - **Only a device of the recipient's signs it.** The signing key must be one
//!   the reach note the sender's card holds for the recipient lists — a note the
//!   recipient signed with their identity key and the card believed under the
//!   key pairing authenticated. A vault, a relay, or a third contact carrying
//!   the acknowledgement holds no such key and cannot make one.
//! - **It names the message, the recipient and the sender.** All three are
//!   inside the signature, so an acknowledgement for one message cannot be
//!   spent on another, nor one person's on another's card.
//! - **An expired note lists nobody.** The same fail-closed rule the note's
//!   relays follow: a message whose recipient's note has lapsed stays *sent*
//!   until a fresh note arrives, rather than being believed under device keys
//!   the person may since have dropped.
//!
//! Signed over a length-framed encoding under its own domain tag, so a device
//! signature over an acknowledgement can never be mistaken for one over
//! anything else a device key signs.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
pub use kotton_schemas::membership::ReachNote;
pub use kotton_wire::ipc::DeliveryAck;

/// Domain tag under an acknowledgement's signature. Versioned so its shape can
/// change without an old signature reading as a new one.
pub const DELIVERY_ACK_DOMAIN: &[u8] = b"kotton:delivery-ack:v1";

/// `device` signs for `message_id`, which `from_did` received from `to_did`.
pub fn sign(message_id: &str, from_did: &str, to_did: &str, device: &SigningKey) -> DeliveryAck {
    let mut ack = DeliveryAck {
        message_id: message_id.to_string(),
        from_did: from_did.to_string(),
        to_did: to_did.to_string(),
        device: hex::encode(device.verifying_key().to_bytes()),
        sig: String::new(),
    };
    ack.sig = hex::encode(device.sign(&signed_bytes(&ack)).to_bytes());
    ack
}

/// Believe `ack` as `recipient_did` signing for `message_id`, sent by
/// `sender_did`, only if a device `note` lists signed it and `note` is the
/// recipient's and unexpired at `now`.
///
/// `note` must be the one the sender's card holds — already believed under the
/// recipient's identity key — and never one that arrived with the ack.
pub fn verify(
    ack: &DeliveryAck,
    note: Option<&ReachNote>,
    recipient_did: &str,
    sender_did: &str,
    message_id: &str,
    now: u64,
) -> Result<(), String> {
    if ack.message_id != message_id {
        return Err("that acknowledgement is for a different message".to_string());
    }
    if ack.from_did != recipient_did {
        return Err(format!(
            "that acknowledgement says {} signed for it, and it came from {recipient_did}",
            ack.from_did
        ));
    }
    if ack.to_did != sender_did {
        return Err("that acknowledgement is signed to someone else".to_string());
    }
    let Some(note) = note else {
        return Err(format!(
            "no reach note is held for {recipient_did}, so no device of theirs is known to sign for anything"
        ));
    };
    if note.did != recipient_did {
        return Err("the reach note held is not the recipient's".to_string());
    }
    if now >= note.expires_at {
        return Err(format!(
            "the reach note held for {recipient_did} has expired, so it lists no device to believe"
        ));
    }
    if !note.devices.iter().any(|d| d.eq_ignore_ascii_case(&ack.device)) {
        return Err(format!(
            "that acknowledgement was signed by a key {recipient_did}'s reach note does not list"
        ));
    }
    let device: [u8; 32] = hex::decode(&ack.device)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| "that acknowledgement names a device key that is not a key".to_string())?;
    let key = VerifyingKey::from_bytes(&device)
        .map_err(|_| "that acknowledgement names a device key that is not a key".to_string())?;
    let sig = hex::decode(&ack.sig)
        .ok()
        .and_then(|b| Signature::from_slice(&b).ok())
        .ok_or_else(|| "that acknowledgement carries no readable signature".to_string())?;
    key.verify(&signed_bytes(ack), &sig)
        .map_err(|_| "that acknowledgement was not signed by the device it names".to_string())
}

/// Every field but the signature, length-framed, under the domain tag.
fn signed_bytes(ack: &DeliveryAck) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(DELIVERY_ACK_DOMAIN);
    for field in [&ack.message_id, &ack.from_did, &ack.to_did, &ack.device] {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field.as_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reach_note;

    const NOW: u64 = 1_800_000_000;
    const BOB: &str = "did:kel:bob";
    const ALICE: &str = "did:kel:alice";
    const MSG: &str = "ZXBoZW1lcmFsLWtleQ==";

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// Bob's note, signed by his identity key (seed 2), listing `devices`.
    fn bobs_note(devices: &[u8]) -> ReachNote {
        let devices: Vec<String> = devices
            .iter()
            .map(|s| hex::encode(key(*s).verifying_key().to_bytes()))
            .collect();
        reach_note::next(None, BOB, &[], &devices, &key(2), NOW).unwrap()
    }

    #[test]
    fn an_acknowledgement_signed_by_a_device_in_the_note_is_believed() {
        let note = bobs_note(&[20, 21]);
        let ack = sign(MSG, BOB, ALICE, &key(21));
        assert_eq!(verify(&ack, Some(&note), BOB, ALICE, MSG, NOW), Ok(()));
    }

    /// The case the record names: nothing but a device the recipient listed
    /// can say a message arrived — not their identity key used as a device,
    /// not a vault's key, not anyone's.
    #[test]
    fn an_acknowledgement_not_signed_by_a_device_in_the_note_is_refused() {
        let note = bobs_note(&[20]);
        for stranger in [30u8, 2] {
            let ack = sign(MSG, BOB, ALICE, &key(stranger));
            let refused = verify(&ack, Some(&note), BOB, ALICE, MSG, NOW);
            assert!(
                refused.as_ref().is_err_and(|e| e.contains("does not list")),
                "key {stranger}: {refused:?}"
            );
        }
    }

    #[test]
    fn an_acknowledgement_with_no_note_held_is_refused() {
        let ack = sign(MSG, BOB, ALICE, &key(20));
        assert!(verify(&ack, None, BOB, ALICE, MSG, NOW).is_err());
    }

    #[test]
    fn an_acknowledgement_under_an_expired_note_is_refused() {
        let note = bobs_note(&[20]);
        let ack = sign(MSG, BOB, ALICE, &key(20));
        assert!(verify(&ack, Some(&note), BOB, ALICE, MSG, note.expires_at).is_err());
    }

    #[test]
    fn an_acknowledgement_is_spent_on_its_own_message_and_people_only() {
        let note = bobs_note(&[20]);
        let ack = sign(MSG, BOB, ALICE, &key(20));
        assert!(verify(&ack, Some(&note), BOB, ALICE, "b3RoZXI=", NOW).is_err(), "another message");
        assert!(verify(&ack, Some(&note), BOB, "did:kel:carol", MSG, NOW).is_err(), "another sender");
        let mut carols = note.clone();
        carols.did = "did:kel:carol".into();
        assert!(
            verify(&ack, Some(&carols), "did:kel:carol", ALICE, MSG, NOW).is_err(),
            "another recipient's card"
        );
    }

    /// A field changed after signing — the message id swapped to spend one
    /// acknowledgement on another message — breaks the signature.
    #[test]
    fn an_acknowledgement_changed_after_signing_is_refused() {
        let note = bobs_note(&[20]);
        let mut ack = sign(MSG, BOB, ALICE, &key(20));
        ack.message_id = "b3RoZXI=".into();
        let refused = verify(&ack, Some(&note), BOB, ALICE, "b3RoZXI=", NOW);
        assert!(
            refused.as_ref().is_err_and(|e| e.contains("not signed by the device")),
            "{refused:?}"
        );
    }
}
