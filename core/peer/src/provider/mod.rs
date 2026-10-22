// SPDX-License-Identifier: AGPL-3.0-or-later
//! Peer-backed ObjectStorage for the Kotton VFS.
//!
//! `KottonPeerObjectStorage` implements the `ObjectStorage` trait by forwarding
//! each operation to a paired peer daemon over a QUIC connection, using the same
//! length-prefixed JSON `DeviceRequest` / `DeviceResponse` wire protocol that the
//! local IPC channel uses.
//!
//! # Crate layout
//!
//! - [`channel`]  — [`PeerChannel`] trait + [`QuicPeerChannel`] implementation
//! - [`storage`]  — [`KottonPeerObjectStorage`] top-level export

pub mod channel;
pub mod storage;

pub use channel::{refused_at_handshake, PeerChannel, QuicPeerChannel, RefusedAtHandshake};
pub use storage::KottonPeerObjectStorage;
