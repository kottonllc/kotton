// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `peer` domain.
//!
//! Laid out by tier within the domain: `provider` holds the implementations,
//! and `daemon` the fleet's IPC verbs and tables.

/// NAT traversal: the connection ladder from direct, through STUN and a
/// simultaneous hole-punch, to a TURN relay.
///
/// "How do I reach my own device behind a NAT" is a mesh *assembly* over the
/// primitives `net` provides, which is peer authority rather than mechanism:
/// authority is the axis code is placed by.
pub mod daemon;
pub mod devices;

// Tests that live with the code they exercise: `pairing` is this crate's, so
// `frost_signing_tests` is too.
#[cfg(test)]
mod frost_signing_tests;
#[cfg(test)]
mod pair_channel_tests;
pub mod dialer;
pub mod membership;
pub mod nat;
pub mod operator;
/// The pairing channel: SAS-confirmed key agreement over a bootstrap
/// connection.
///
/// Pure — no `crate::` paths, no runtime type, two free functions over a
/// send/recv pair.
pub mod pair_channel;
/// The pairing ceremony: codes, listeners, and the committed enrollment runs.
///
/// This is the mesh *assembly* — it
/// composes transports into a way for two of a user's devices to find and
/// authenticate each other — which is peer authority rather than mechanism.
pub mod pairing;
pub mod contact_delivery;
pub mod contact_door;
pub mod door;
pub mod introduction;
/// The local-network door: closed by default, opened on purpose for ten minutes or
/// kept open on one network, and shut by itself. Not [`door`], which is a vocabulary.
pub mod local_door;
/// The local network as the door sees it: one beacon out while the door is open, and
/// the beacons of other open doors heard.
pub mod local_network;
pub mod contact_pairing;
pub mod provider;
/// Being reachable: the bound QUIC socket, the presence registration that says
/// where to dial this device, and the relay reservation that carries a circuit
/// when nothing direct works.
///
/// Not four fields on `DeviceRuntime` used by nothing but these tasks. Which of
/// a user's devices can
/// find this one is peer authority, not the machine's.
pub mod reachability;
pub mod relay_keys;
/// What makes a relay *this relay*: the key it proves when dialled.
pub mod relay_key;
/// Which identifiers this device announces under, and looks a peer up by — the
/// policy the per-pair handle derivation in `core/crypto` leaves open, and the
/// one place the rotating-handle migration happens.
pub mod rendezvous;
/// How wide this run opens its sockets — the one switch every inbound listener
/// consults, so a same-machine run stays off the LAN and raises no firewall dialog.
pub mod scope;

pub use provider::*;
pub use door::PeerHandler;
pub use reachability::Reachability;
pub use scope::local_only;
