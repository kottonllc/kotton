// SPDX-License-Identifier: AGPL-3.0-or-later
//! Keeping each person's reach note current, and in their contacts' hands. The
//! note is signed by its person, and it is what a contact reaches them by.
//!
//! A person never sees their reach note and never edits it. This is what does
//! instead: when the relays this device holds at change, and on a timer so a
//! note is renewed before it expires, it asks for each resident person's
//! current note ([`kotton_device::users::reach::current_note`]) and, when that
//! is a newly signed one, seals it to every contact over the same door a
//! message takes. A contact's card then holds the latest note and is dialled
//! from it, so a person who moves relay is followed without pairing again.
//!
//! What it sends is decided per contact, not per signing: the keeper remembers
//! which version each contact has settled, and a pass sends the current note to
//! every contact that has not settled it
//! ([`kotton_msg::daemon::messages::hand_reach_note_to`]). A contact settles a
//! version when their node takes it, or when their card refuses that very
//! version — which a retry cannot change, so it is not sent again every hour. So
//! a note signed by the pairing ceremony rather than here still reaches everyone
//! else, and a contact who was unreachable is tried again on the next pass — an
//! hour, or the next relay change — while one whose card refused it is not. The
//! memory is the daemon's and starts empty, so a restart sends each contact the
//! current note once more, which a card that already holds it answers as already
//! held and one that refused it refuses again. Holding a note until one of the
//! contact's *devices* signs for it, rather than their door, is the outbox's
//! work — the parent record's second unit.

use crate::agent::message_host::DaemonMessageHost;
use crate::residency::{RecordStores, UserRegistry};
use kotton_device::DeviceRuntime;
use kotton_msg::daemon::messages::{hand_reach_note_to, NotesSettled};
use kotton_peer::membership::Membership as _;
use kotton_schemas::membership::Role;
use std::sync::Arc;
use std::time::Duration;

/// How often a pass runs with nothing poking it. It is what renews a note
/// before it expires and what catches a person unlocked since the last pass;
/// an hour is well inside the half-life a note is renewed at.
const RECHECK: Duration = Duration::from_secs(60 * 60);

/// Run a pass now, then again whenever this device's relays change and on
/// [`RECHECK`].
pub fn spawn(runtime: Arc<DeviceRuntime>, users: UserRegistry, record_stores: RecordStores) {
    tokio::spawn(async move {
        let changed = runtime.reach_changed();
        let mut settled = NotesSettled::new();
        loop {
            pass(&runtime, &users, &record_stores, &mut settled).await;
            tokio::select! {
                _ = changed.notified() => {}
                _ = tokio::time::sleep(RECHECK) => {}
            }
        }
    });
}

/// One pass over every resident person.
pub async fn pass(
    runtime: &Arc<DeviceRuntime>,
    users: &UserRegistry,
    record_stores: &RecordStores,
    settled: &mut NotesSettled,
) {
    let now = kotton_peer::rendezvous::unix_now();
    let host = DaemonMessageHost {
        runtime: runtime.as_ref(),
        users,
        record_stores,
    };
    for (user_id, store) in users.all() {
        hand_note(runtime, &host, &user_id, store.as_ref(), now, settled).await;
    }
}

/// Hand `user_id`'s current note to every contact **now**, and return once each
/// has answered or been found unreachable.
///
/// For a desktop about to narrow its own relay: a set drops
/// every reservation the new rule refuses, so a contact who holds no key yet and
/// whose own reach is that relay could be handed the note carrying the key only
/// before the set. The pass above would get there on its own, but after the set,
/// and then over a relay that no longer admits them. Each contact is sent the
/// note whatever the keeper last recorded; a card already holding it answers as
/// already held.
pub async fn hand_to_contacts(
    runtime: &DeviceRuntime,
    users: &UserRegistry,
    record_stores: &RecordStores,
    user_id: &str,
) {
    let Some(store) = users.get(user_id) else {
        return;
    };
    let host = DaemonMessageHost {
        runtime,
        users,
        record_stores,
    };
    let now = kotton_peer::rendezvous::unix_now();
    hand_note(runtime, &host, user_id, store.as_ref(), now, &mut NotesSettled::new()).await;
}

/// One person's pass: their note signed if it is due, and handed to every
/// contact that has not settled its version.
async fn hand_note(
    runtime: &DeviceRuntime,
    host: &DaemonMessageHost<'_>,
    user_id: &str,
    store: &kotton_store::runtime::user::UserStore,
    now: u64,
    settled: &mut NotesSettled,
) {
    let user_id = user_id.to_string();
    // The relay keys this person keeps as an operator, held before their
    // note is signed: the note offers *invited* to their contacts, and this
    // device's reservations present *mine*. In memory only, so this is also
    // how they come back after a restart.
    super::operator::present_kept_keys(runtime, store);
    let note = match kotton_device::users::reach::current_note(runtime, store, &user_id, now).await {
        Ok((note, _)) => note,
        // Locked, holding a retired key, or a held note that cannot be
        // read: nothing is signed over it. The first two clear with an
        // unlock or a recovery; the last does not, so this is said above
        // `debug`, where a note that has stopped being renewed shows.
        Err(e) => {
            tracing::info!(user_id, error = %e, "no reach note signed this pass");
            return;
        }
    };
    let contacts: Vec<String> = match store.list_members().await {
        Ok(m) => m.into_iter().filter(|m| m.role == Role::Contact).map(|m| m.did).collect(),
        Err(e) => {
            tracing::warn!(user_id, error = %e, "the contacts to send a reach note to are unreadable");
            return;
        }
    };
    hand_reach_note_to(host, &user_id, &contacts, &note, settled).await;
}
