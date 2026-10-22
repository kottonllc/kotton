// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `session` domain.
//!
//! Laid out by tier within the domain (RFC-0059): `provider` holds the
//! implementations, `service` the stateful coordination — session management,
//! token refresh, rate limiting. Higher tiers arrive as `05_runtime` and
//! `06_daemon` dissolve.

pub mod lock_policy;
pub mod provider;
pub mod service;

pub use provider::*;
