// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton-rendezvous` HTTP client.

pub mod admission;
pub mod client;
pub mod identity;

pub use admission::{say_as_operator, AdmissionKey};
pub use client::{RendezvousClient, RendezvousError};
pub use identity::fetch_relay_identity;
