// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `fs` domain — the virtual filesystem.
//!
//! Laid out by tier within the domain (RFC-0059): `provider` holds the
//! implementations of [`kotton_sys::fs::Filesystem`]. `runtime` and `daemon`
//! arrive as `05_runtime` and `06_daemon` dissolve.

pub mod provider;
pub mod runtime;

pub use provider::{MemoryFilesystem, OsFilesystem};
