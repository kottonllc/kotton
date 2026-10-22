// SPDX-License-Identifier: AGPL-3.0-or-later
//! Network layer scaffolding for DeviceRuntime
//!
//! These modules implement the network-facing capabilities of DeviceRuntime:
//! transport instantiation, discovery, connection accept loops, and permission
//! checks.
//!
//! `routing.rs` and `lifecycle.rs` are in `device/`, not here. Neither is
//! network code: routing maps a device fingerprint to the user who owns it, and
//! lifecycle is `start`/`shutdown` for the whole runtime. Both are `device`'s,
//! and here they would make this directory look like it spanned two authorities.
//!
//! # Wiring status
//!
//! - `peer_listener.rs` — binds the inbound QUIC socket; accept loop is a stub.
//! - `local_door.rs` — the local-network door: a listener and an announcement that
//!   exist only while the person has opened it.
//! - `introduction.rs` — the listener a relay's introduction opens for one of the
//!   person's devices, for one session.
//! - `transport.rs`, `accept.rs` — scaffolded, not yet wired.

mod accept;
// `discovery` and `transport` are reachable from `device::lifecycle`, which starts
// them — the device owns the network, not the reverse.
pub(crate) mod peer_listener;
/// The local-network door's socket and announcement, which exist only while it is open.
pub mod local_door;
/// The listener an introduction opens: one device, one address, one token, one session.
pub mod introduction;
mod permissions;
