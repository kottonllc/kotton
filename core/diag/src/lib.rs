// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `diag` domain — events, health, and inspection.
//!
//! Laid out by tier within the domain (RFC-0059): `service` holds the event
//! bus and its subscriber management. Higher tiers arrive as `05_runtime` and
//! `06_daemon` dissolve.

pub mod service;

pub use service::*;
