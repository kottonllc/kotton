// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `secret` domain.
//!
//! Laid out by tier within the domain (RFC-0059); `provider` holds the
//! implementations. Higher tiers arrive as `05_runtime` and `06_daemon`
//! dissolve.

pub mod provider;

pub use provider::*;
