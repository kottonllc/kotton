// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `proc` domain.
//!
//! Laid out by tier within the domain (RFC-0059); `provider` holds the
//! implementations. Higher tiers arrive as `05_runtime` and `06_daemon`
//! dissolve.

pub mod provider;

/// What a confined child is granted, and the one call that applies it.
///
/// `DEC-0074` — *an inference engine is a guest, and is confined like one* —
/// names this crate as where process confinement lives. Two callers use it:
/// `kuserd` spawning `kinferd`, which parses a stranger's weights file, and
/// `kuserd` spawning `kotton-runner`, which executes a stranger's WASM on every
/// launch of every app.
pub mod sandbox;

pub use provider::*;
pub use sandbox::{confine, Grant, Profile, Reach, SandboxError};
