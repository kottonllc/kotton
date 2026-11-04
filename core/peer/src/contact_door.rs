// SPDX-License-Identifier: AGPL-3.0-or-later
//! The one door a contact's message arrives at: one request type, one
//! acceptor.
//!
//! A device answers it by filing the message into the person's store; a vault
//! answers it by keeping the sealed bytes until a device takes them. From the
//! sender's side those are one door — the same request type, the same one-key
//! verifier, the same answer — and the sender must not be able to tell them
//! apart. So the acceptor is built here, once, and each node hands
//! it only the thing that differs: what to do with a sealed message that
//! arrived. Everything that would otherwise be enforced at runtime, or not at
//! all, between two acceptors wearing one name is one implementation.

use crate::door::{PeerDoor, PeerHandler};
use kotton_wire::ipc::{ContactRequest, ContactResponse};
use std::future::Future;

/// Build the contact door over `take`: what this node does with one sealed
/// message that arrived through it — handed over by the sender, or carried by
/// their vault ([`ContactRequest::CarryMessage`]), which is the same message
/// with an answer the carrier cannot read.
pub fn contact_door<F, Fut>(take: F) -> PeerHandler
where
    F: Fn(ContactRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ContactResponse> + Send + 'static,
{
    PeerDoor::<ContactRequest, ContactResponse>::serving(
        move |_peer_did, request| {
            // Handed the peer's DID by the transport, and ignoring it: the
            // door's verifier admits exactly one key, so *who* arrived is
            // settled before this runs.
            take(request)
        },
        // The only thing nameable here is a delivery, so anything else is not a
        // refused verb — it is not a `ContactRequest` at all.
        |e| ContactResponse::Refused {
            reason: format!("that is not something a contact can say: {e}"),
        },
    )
}
