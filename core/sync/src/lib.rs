// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `sync` domain — replicating a user's data between their nodes.
//!
//! Above `store`, `record`, `peer` and `device`. The sealed replication primitive
//! that used to hold this crate's name lives in [`kotton_sealed`] and sits *below*
//! `store`; see that crate's doc for why one name could not cover both.
//!
//! Today this holds [`host::SyncHost`], the seam that lets the sync engine stop
//! naming daemon-internal types. The engine itself follows.

pub mod engine;
pub mod host;

pub use host::{PeerLinks, SyncHost, UserResources};
