// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton-device` — the machine's own authority.
//!
//! On whose authority does this crate act? **The machine's.** Its contents are
//! facts about *this node*: the operational identity it signs as, and the
//! configuration that decides what services it runs and how it is reachable.
//! None of it belongs to a user, and none of it can reach a user's data.
//!
//! ## What this crate is not
//!
//! It is **not** the daemon. The daemon decides *who is asking* — it holds
//! session tokens, their lifetimes, and the act of believing a credential.
//! This crate answers *what is running*. The tell is what a piece of state is
//! keyed by: a key the daemon issued is authentication; a key it received, or a
//! fact about the machine, is this crate's.
//!
//! ## The invariant
//!
//! `DeviceRuntime` lives here; the user-runtime registry does not — it is the
//! daemon's. **Nothing in this crate may reach a user's data.** A crate that
//! names the machine's authority and offers a data path would be exactly the
//! shape this invariant exists to prevent, and the machine is the layer an
//! operator principal sits nearest to.

pub mod users;
pub mod config;
pub mod db;
pub mod identity;
pub mod network;
pub mod registry;
pub mod runtime;

pub use runtime::DeviceRuntime;
pub use runtime::network::introduction::Introducer;
pub use runtime::network::local_door::{DoorReading, LocalWay};

pub use config::{
    DiscoveryMethod, NatNetworkConfig, PermissionConfig, PermissionMode, RelayConfig,
    RuntimeConfig, StorageConfig, TlsConfig, TransportConfig, TurnServer,
};
pub use identity::{ensure_device_identity, DeviceIdentity};
