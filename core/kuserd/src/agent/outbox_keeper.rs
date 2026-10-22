// SPDX-License-Identifier: AGPL-3.0-or-later
//! Trying again what no device has signed for yet.
//!
//! A direct message stays in its sender's outbox until one of the recipient's
//! devices signs for it (`kotton_msg::daemon::outbox`). This is what tries it
//! again: on a short tick, every resident person's outbox is read and each
//! message whose next try is due is handed over once more — the same sealed
//! bytes, so a retry is the same message and the recipient keeps one copy.
//!
//! **While this device is off**, the sender's own vault carries it — a relay
//! keeps nothing, and the vault is the person's node. The
//! pickup pass hands the vault the outbox (`vault_doors`), and the vault tries
//! each message at the recipient's door until a device of theirs signs for it
//! (`kvaultd::carry`); the signature waits at the vault, sealed to this person,
//! for the next pickup.

use crate::agent::message_host::{outbox_retry, DaemonMessageHost};
use crate::residency::{RecordStores, UserRegistry};
use kotton_device::DeviceRuntime;
use kotton_msg::daemon::outbox;
use std::sync::Arc;
use std::time::Duration;

/// Run a pass on every tick: as often as the shortest retry, and never less
/// often than every thirty seconds, so a message due is tried within a tick of
/// falling due.
pub fn spawn(runtime: Arc<DeviceRuntime>, users: UserRegistry, record_stores: RecordStores) {
    tokio::spawn(async move {
        let retry = outbox_retry();
        let tick = Duration::from_secs(retry.base_secs.clamp(1, 30));
        loop {
            tokio::time::sleep(tick).await;
            pass(&runtime, &users, &record_stores).await;
        }
    });
}

/// One pass over every resident person's outbox.
pub async fn pass(runtime: &Arc<DeviceRuntime>, users: &UserRegistry, record_stores: &RecordStores) {
    let host = DaemonMessageHost {
        runtime: runtime.as_ref(),
        users,
        record_stores,
    };
    let now = kotton_peer::rendezvous::unix_now();
    for (user_id, _) in users.all() {
        let tried = outbox::retry_due(&host, &user_id, now, outbox_retry()).await;
        if tried > 0 {
            tracing::debug!(user_id, tried, "outbox pass");
        }
    }
}
