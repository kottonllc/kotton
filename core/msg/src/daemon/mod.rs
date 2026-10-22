// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `msg` domain's **daemon tier** — the IPC verbs.
//!
//! Moved here from `kuserd` 2026-08-21, following `core/org` and `core/grant`.
//!
//! ## Why this one needed a trait first
//!
//! `org` and `grant` moved as they were: their handlers named nothing from the
//! runtime crate. This file did — it took `&DeviceRuntime` *and* the daemon's
//! residency map through fifteen signatures — so the move had to be preceded by
//! naming what it actually used. Counted rather than assumed, that was six
//! things: a keychain, the user directory both ways, the user's own current key,
//! a contact's stored key, and per-user record access. No event bus, no mount
//! locks, no peer client, no transport.
//!
//! [`messages::MessageHost`] is that list. The daemon implements it; this
//! domain never learns what a `DeviceRuntime` is.
//!
//! ## No tables
//!
//! Unlike `org` and `grant`, nothing here owns a table. Messages *are* records,
//! so storage is the `record` domain's and reaches this crate through the host.
//! A domain with no tables of its own is not an incomplete one — it means this
//! domain's authority is over the *shape* of a message, not over a store.
pub mod delivery;
mod filing;
pub mod messages;
pub mod outbox;
pub mod stream;
