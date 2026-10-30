// SPDX-License-Identifier: AGPL-3.0-or-later
//! IPC contract between `kuserd` (the user daemon) and its clients.
//!
//! `UserRequest` and `UserResponse` are the canonical wire types for all
//! communication over the Kotton named-pipe / Unix-socket IPC channel used
//! by the user daemon (`kuserd`).
//!
//! Both `06_daemon` (server) and the `kotton-client` SDK (client) re-export
//! these types from here so there is exactly one definition in the codebase.
//!
//! # Layer note
//!
//! This module may only import from within `wire` (e.g. `crate::remote`).
//! It must never import from `05_runtime` or higher — that would create a
//! downward dependency that defeats the purpose of the schemas layer.

pub mod browser_inner;
pub mod contact_request;
pub mod peer_request;
pub mod types;
pub mod remote_request;
pub mod request;
pub mod response;
pub mod vault_request;

pub use types::*;
pub use request::*;
pub use response::*;
pub use contact_request::{
    CarriedMessage, Carrying, ContactRequest, ContactResponse, Delivery, DeliveryAck, DeliveryReading, HeldDoor,
    MemberDelivery, PendingDelivery, SealedDm,
};
pub use browser_inner::{ChannelCall, ChannelFrame};
pub use peer_request::PeerRequest;
pub use vault_request::{LineCame, LineEnrolled, LineToEnrol, MintWaiting, OperatedService, OperatorVerb, SecretBytes, SecretText, SecretValue, Unstood, UnstoodRelay, UnstoodRelayState, UnstoodWhy, VaultRequest, VaultTenant};
