// SPDX-License-Identifier: AGPL-3.0-or-later
//! IPC request handlers, split by concern.
//!
//! `agent/mod.rs` owns the dispatch (the `match` table) and the central
//! session-auth guard.  Each submodule owns the business logic for its slice.

pub mod extensions;
// The handlers are `kotton_device::users::files`; their tests are here,
// because they need this crate's `DaemonFileHost`.
pub(crate) mod device_config;
#[cfg(test)]
mod files_tests;
// The ceremony is `kotton_device::users::pairing`. Its tests are here:
// they assert on the daemon's real residency map.
#[cfg(test)]
mod pairing_tests;
// The engine itself is `kotton_sync::engine`. Its tests are here:
// they integrate against this crate's `DaemonUserResources`.
#[cfg(test)]
mod sync_engine_tests;
pub mod user;

// Re-export so that handler submodules can `use super::{DeviceRequest, DeviceResponse}`.
pub(crate) use super::protocol::UserResponse;

// Resolving a user id to a live runtime is *residency*, which is the daemon's
// bookkeeping and not the machine's. The sync engine asks it over
// `kotton_sync::UserResources`, never by naming `residency::UserRegistry`, and
// `residency::DaemonUserResources` is where that reasoning lives.

/// Who is making this request and what privileges do they carry.
///
/// **Built and not yet consumed.** No handler reads it to make an
/// access-control decision; the construction site binds it as `_caller`, which
/// says the same thing. Said because a doc that describes an architecture the
/// code does not have is worse than no doc: the next reader takes the check as
/// done.
///
/// **The distinction it names *is* enforced, by two other mechanisms**, so this
/// is unfinished convenience rather than a gap. Sealed replication refuses an
/// ephemeral guest inline at the construction site, and the dispatch floor
/// independently enforces `origin >= required_trust(op)`. What is
/// missing is only the typed form that would let a handler ask without
/// re-deriving it.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Consumed by no handler yet; see the note above.
pub(crate) enum CallerContext {
    /// Permanently-paired remote device — trusted for all sync paths.
    PairedDevice { peer_did: String },
    /// Ephemeral guest holding a scoped `GrantEnvelope`.
    /// Access is limited to the paths and operations in the grant.
    EphemeralGuest { peer_did: String },
}

impl CallerContext {
    /// Returns `true` if this caller is an ephemeral (non-paired) guest.
    #[allow(dead_code)] // See the note on CallerContext.
    pub fn is_ephemeral(&self) -> bool {
        matches!(self, CallerContext::EphemeralGuest { .. })
    }
}
