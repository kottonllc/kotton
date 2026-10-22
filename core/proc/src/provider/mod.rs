// SPDX-License-Identifier: AGPL-3.0-or-later
//! OS process runtime provider
//!
//! Implements Process trait using tokio::process for standard OS process execution.

mod os;
pub use os::OsProcess;

/// The operating-system sandbox, one implementation per platform.
///
/// Not re-exported: the vocabulary in [`crate::sandbox`] is the surface, and a
/// caller that reached a provider directly would be picking a platform.
pub(crate) mod sandbox;
