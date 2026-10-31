// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `store` domain.
//!
//! Laid out by tier within the domain: `provider` holds the implementations,
//! and `runtime` the tier above them.

pub mod fetch;
pub mod fs_view;
pub mod provider;
pub mod runtime;
pub mod shelf;
pub mod stack;
pub mod storage_key;

pub use provider::*;
pub use fs_view::Fs;
pub use shelf::LocalShelves;
pub use storage_key::{NotCanonical, StorageKey};
