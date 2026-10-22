// SPDX-License-Identifier: AGPL-3.0-or-later
//! Building the machine's network services from its configuration.
//!
//! These turn a [`crate::config::TransportConfig`] or
//! [`crate::config::DiscoveryMethod`] into a live implementation from
//! `kotton-net`. The choosing is the machine's — which is why this is here and
//! not in `net`, whose job is to *provide* transports rather than to decide
//! which ones this node runs.
//!
//! It also settles a placement between `net` and `device`. `net` is a primitive tier and `device` a domain, so a
//! `net` that named `TransportConfig` would be an inversion; the config is
//! already here, and these two follow it.
//!
//! Both arrived from `05_runtime` naming no runtime type — the same test that
//! let `config` and `identity` land first.

pub mod discovery;
pub mod transport;

pub use discovery::instantiate_discovery;
pub use transport::{instantiate_transport, TransportInstance};
