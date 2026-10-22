// SPDX-License-Identifier: AGPL-3.0-or-later
//! Making a user resident, from the machine's side of the line.
//!
//! ## Why a trait and not a map
//!
//! A pairing ceremony provisions a user part-way through: the join delivers a KEL,
//! the AID is adopted, a `UserStore` comes into existence — and the *rest* of the
//! ceremony needs that user resident to continue. So the registration is not a step
//! that can be deferred to the end and handed back to the caller.
//!
//! `kuserd`'s `residency.rs` is explicit that the map is the daemon's: "the daemon's
//! bookkeeping of lifetimes it creates and destroys — not a fact about the machine."
//! A ceremony here that held the map would drag it out of the daemon.
//!
//! So the ceremony names what it needs instead. `device` may ask its host to make a
//! user resident and to hand one back; it still cannot enumerate them, and it does
//! not own the map. Same shape as `kotton_sync::UserResources`, and the same reason:
//! the lifetime belongs to whoever is hosting, and the operation belongs here.
//!
//! `load_users` set this precedent before either of them — "Returns the loaded users;
//! registering them is the caller's." This is that rule where the registering cannot
//! wait until the end.

use std::sync::Arc;

use kotton_store::runtime::user::UserStore;

/// The host's live user map, as much of it as a ceremony needs.
///
/// Deliberately two methods. A ceremony makes a user resident and reads one back;
/// it never asks *which* users exist, and nothing here would let it — that is
/// residency's own question, and residency is the daemon's.
pub trait Residency: Send + Sync {
    /// Make `store` the live handle for `user_id`, replacing any current one.
    ///
    /// Replacement is the point during enrollment: a re-join swaps in a
    /// CEK-refreshed handle, and in-flight requests holding the old `Arc` finish
    /// against it.
    fn insert(&self, user_id: String, store: Arc<UserStore>);

    /// `user_id`'s live handle, or `None` when that user is not resident.
    fn get(&self, user_id: &str) -> Option<Arc<UserStore>>;
}
