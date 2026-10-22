// SPDX-License-Identifier: AGPL-3.0-or-later
//! What a sync engine needs from whoever is hosting it.
//!
//! ## Why this exists
//!
//! A sync engine schedules replication passes. To do that it reaches three things
//! keyed by user: the user's live store, their record store, and the per-user
//! database holding their sync rules. It owns none of them — they are created and
//! destroyed by the hosting process, on lifetimes the engine has no say in.
//!
//! While the engine lived inside `kuserd` it held that daemon's three locators as
//! fields: `residency::UserRegistry`, `residency::RecordStores`, and
//! `db::user_db::UserDbMap`. Those three field types, not the replication logic, are
//! what pinned 1,621 lines of domain work inside a binary crate.
//!
//! `residency`'s own module doc puts the locators on the right side of the line —
//! "the daemon's bookkeeping of lifetimes it creates and destroys, not a fact about
//! the machine". So they stay in the daemon, and the engine names what it needs of them.
//!
//! ## What this buys beyond relocation
//!
//! Every call site in the daemon first reaches `DeviceRuntime` for `base_dir()`,
//! `secrets()` and `schema_registry` before it can open anything. None of those
//! appear in any signature here. Opening a record store is not the engine's
//! business and neither are the ingredients; an implementor closes over whatever it
//! needs. The engine asks for a user's record store and gets one, or does not.

use std::sync::Arc;

use anyhow::Result;
use kotton_record::SqliteRecordStore;
use kotton_store::runtime::user::UserStore;

/// The live per-user resources of the process hosting a sync engine.
///
/// Implemented by the host — today `kuserd`, over its residency registry and
/// per-user database map. Every method is keyed by `user_id`; none takes the
/// ingredients for opening a thing, only the name of the user whose thing is wanted.
#[async_trait::async_trait]
pub trait UserResources: Send + Sync + 'static {
    /// The users resident in the host right now.
    ///
    /// A snapshot, not a live view: a pass iterates it, and a user arriving
    /// mid-pass is picked up by the next pass rather than mutating the list
    /// underneath the caller.
    fn user_ids(&self) -> Vec<String>;

    /// `user_id`'s live store, or `None` when that user is not resident.
    ///
    /// `None` is an ordinary answer — a user who has logged out is not an error
    /// condition for a scheduler that runs on a timer.
    fn user_store(&self, user_id: &str) -> Option<Arc<UserStore>>;

    /// `user_id`'s record store, opening it if the host has not already.
    ///
    /// `Err` means it could not be opened at all; the caller's contract is to skip
    /// that user's pass, not to abort the sweep.
    fn record_store(&self, user_id: &str) -> Result<Arc<SqliteRecordStore>>;

    /// The pool holding `user_id`'s sync rules, or `None` when it cannot be opened.
    ///
    /// `None` rather than `Err` because the engine's existing behaviour is that a
    /// rule which cannot be read is a pass that does not run — not a crash, and not
    /// a failure worth propagating past the user it concerns.
    async fn agent_db(&self, user_id: &str) -> Option<Arc<sqlx::SqlitePool>>;

    /// A sync pass for `user_id` has landed: refresh whatever the host keeps
    /// *outside* the store as a copy of something inside it.
    ///
    /// Called once per successful pass, after the pulled objects and record
    /// segments are in place, from the one function both sync entry points
    /// share. The engine does not know what the copies are; the host does. The
    /// one there is today is the display name every device caches beside its
    /// user id so a lock screen can greet the person before their store opens
    /// (`TASK-a-persons-name-travels-with-their-identity`): the name is a sealed
    /// record in the store, and a pass is how a record another device wrote
    /// arrives here.
    ///
    /// Infallible to the engine: a copy that could not be refreshed is the
    /// host's to report, and never a reason to call the pass a failure.
    async fn pass_landed(&self, _user_id: &str) {}
}

/// Opening a replication link to one of the user's other nodes.
///
/// Separate from [`UserResources`] because it is a different kind of thing: that
/// trait hands back *stores*, this one dials a *peer*. Both are lent by the same
/// host, and [`SyncHost`] is how the engine holds one object that does both.
///
/// The engine cannot do this itself. Building the link needs the machine's dialer
/// and the user's CEK domain, and `core/device` — which owns both — may not name a
/// `UserStore`, so the assembled operation lives on neither side and is lent
/// across. `kuserd` implements it in one line over `DeviceRuntime`.
#[async_trait::async_trait]
pub trait PeerLinks: Send + Sync + 'static {
    /// A replication client for `node`, on `user_id`'s behalf.
    ///
    /// `loaded` is the user's store when the caller already holds one — the
    /// implementor needs it to state the link's key domain, and passing the
    /// handle avoids resolving the same user twice in one pass.
    async fn open_peer_client(
        &self,
        node: kotton_wire::peer::PairedNode,
        user_id: &str,
        loaded: Option<&UserStore>,
    ) -> Result<kotton_peer::KottonPeerObjectStorage>;
}

/// Everything a sync engine is lent by its host.
///
/// A supertrait rather than a third set of methods, so the two halves stay
/// separately meaningful and the engine still holds exactly one handle. The
/// blanket impl means a host satisfies this by implementing both halves — there
/// is nothing to remember to also implement.
pub trait SyncHost: UserResources + PeerLinks {}

impl<T: UserResources + PeerLinks> SyncHost for T {}
