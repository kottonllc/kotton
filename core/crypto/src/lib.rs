// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `crypto` domain.
//!
//! Laid out by tier within the domain (RFC-0059); `provider` holds the
//! implementations. Higher tiers arrive as `05_runtime` and `06_daemon`
//! dissolve.

pub mod key_health;
pub mod provider;
pub mod delivery_ack;
pub mod reach_note;

pub use provider::*;
