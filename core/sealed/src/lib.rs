// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `sealed` domain — the sealed face of a store.
//!
//! Holds [`Sealed`], the primitive that lets a caller address a store's objects
//! without holding the means to open them. `store` depends on this; it is below
//! `store`, not above it.
//!
//! So the key it takes, [`kotton_sys::store::StorageKey`], is not `store`'s to
//! own: it lives in `kotton-sys`, under both, and `store` re-exports it. This
//! crate names `kotton-sys` and nothing of the store's (kotton #275).
//!
//! ## Why this is not called `sync`
//!
//! It was, until 2026-08-24, and the name cost a day. The crate's own doc promised
//! that "higher tiers arrive as `06_daemon` dissolves" — meaning the 1,621-line sync
//! engine in `kuserd` would land here. It cannot: that engine names `store`,
//! `record`, `peer` and `device`, so it sits *above* `store`, while this crate sits
//! *below* it. Cargo rejects the cycle, which is how the promise was found to be
//! false rather than merely aspirational.
//!
//! One name was being asked to span two tiers with `store` between them. Splitting
//! the name is what makes the tiers legible: sealing is a primitive under `store`,
//! syncing is an engine over it, and `core/sync` now holds the latter.

pub mod runtime;

pub use runtime::Sealed;
