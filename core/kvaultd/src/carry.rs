// SPDX-License-Identifier: AGPL-3.0-or-later
//! What a vault carries for the person it keeps for while no device of theirs
//! is awake
//! (`TASK-a-message-stays-in-the-outbox-until-one-of-their-devices-signs-for-it`,
//! clause 3; RFC-0024's sender half, which RFC-0083 R1 moved off the relay).
//!
//! A direct message stays in its sender's outbox until one of the recipient's
//! devices signs for it, and the outbox is tried again by whichever device of
//! the sender's is awake. When none is, this is what tries it: a device hands
//! its vault the outbox with `CarryFrame`, a frame at a time — each message's
//! own sealed bytes and the pair's doors for the hours it may be tried in — and
//! the vault dials the recipient's door at the relay it reserves at, as the
//! sender's device would, until a device of theirs signs for it. The verb was
//! `CarryMessages`, a whole-set replacement, until 2026-10-08, and was renamed
//! rather than changed in place so that a vault from before refuses it as a
//! verb it does not know, instead of reading a readout as *carry nothing*.
//!
//! **What this holds, and what it can do with it.** The sealed bytes, which it
//! cannot open; and the pair's per-epoch handles — the same keys `HoldDoors`
//! already hands it for this person's inbox, the sender's handle labelling the
//! dial and the recipient's naming its target. They prove the pair inside the
//! circuit and nothing else, so a carrier can hand over only what the sender
//! sealed. It is told neither person: the recipient opens the message and
//! proves who wrote it by the signature inside (RFC-0064 MS7).
//!
//! **What comes back, and what is not kept.** A device of the recipient's that
//! files a carried message answers with its acknowledgement *sealed to the
//! sender* (`ContactResponse::SignedSealed`), so this vault learns that a device
//! signed and not which one, nor for whom. The sender's own devices say every
//! outbox try the same way (`CarryMessage`), so the recipient's door cannot tell
//! this vault from them. That envelope is kept as a held
//! delivery under no door — an empty `handle_did` — stamped with when the
//! message was handed here rather than when it was signed for, and the sender's
//! next pickup takes it — `file_from_vault` opens it and believes the signature
//! only under a device key the recipient's reach note lists. The carried row is
//! then dropped. Nothing here records which device signed, nor any hour but the
//! hand-over's: every door is one hour's, so the envelope is filed under none
//! (ruled by the owner 2026-09-26).
//!
//! A door that holds without signing — the recipient's own vault — is *sent*,
//! not *delivered*, here as everywhere, and the message is tried again.
//!
//! **Where it dials.** At the relay this vault reserves at, and nowhere else.
//! The recipient's reach note names the relays they are reached at; handing
//! those to the vault is a question the record leaves open, and this does not
//! answer it by guessing (the record's 2026-09-26 heading).

use crate::doors::decode32;
use ed25519_dalek::{SigningKey, VerifyingKey};
use kotton_crypto::did::DidKeyMethod;
use kotton_device::DeviceRuntime;
use kotton_peer::rendezvous::{self, DeliveryAttempt};
use kotton_wire::ipc::{CarriedMessage, Carrying, ContactRequest, ContactResponse, HeldDoor, SealedDm, UserResponse};
use sqlx::{Row, SqlitePool};
use std::io;
use std::sync::Arc;
use std::time::Duration;

/// How many messages a vault carries for one person at once. A bound, as the
/// held deliveries' is (RFC-0083 R3): what does not fit stays in the outbox
/// and is tried by the sender's device when one is awake.
pub const CARRY_CAP: usize = 1024;

/// How many doors one carried message may bring: a little over a week of
/// hours, the window a device hands its vault for its own inbox. A message is
/// carried for as long as its doors last and no longer, which is the time half
/// of R3's bound.
pub const DOORS_PER_MESSAGE: usize = 24 * 7 + 2;

/// How long one dial is given before the message waits for its next try.
const DIAL_WITHIN: Duration = Duration::from_secs(15);

pub async fn init(db: &SqlitePool) -> io::Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS carried_messages (
            user_id TEXT NOT NULL,
            ephemeral_pub TEXT NOT NULL,
            sealed TEXT NOT NULL,
            doors TEXT NOT NULL,
            handed_at INTEGER NOT NULL,
            attempts INTEGER NOT NULL,
            next_at INTEGER NOT NULL,
            through_epoch INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (user_id, ephemeral_pub)
        )",
    )
    .execute(db)
    .await
    .map_err(io::Error::other)?;
    // A table from before `through_epoch` gains it in place. Its rows read 0 —
    // a window already closed — so the device's next pass hands each again,
    // and the upsert writes the real epoch: nothing is rewritten here.
    let has: bool = sqlx::query(
        "SELECT COUNT(*) AS n FROM pragma_table_info('carried_messages') WHERE name = 'through_epoch'",
    )
    .fetch_one(db)
    .await
    .map(|r| r.get::<i64, _>("n") > 0)
    .map_err(io::Error::other)?;
    if !has {
        sqlx::query("ALTER TABLE carried_messages ADD COLUMN through_epoch INTEGER NOT NULL DEFAULT 0")
            .execute(db)
            .await
            .map_err(io::Error::other)?;
    }
    Ok(())
}

/// `CarryFrame`: stop carrying what `drop` names, then carry `messages` for
/// `user_id`, and answer with every message carried for them now.
///
/// **A set is built across passes, one frame at a time.** Until 2026-10-08 this
/// was `CarryMessages` and replaced the set with the one handed, so a device had to hand its whole
/// outbox in one request — and the peer frame (10 MiB, RFC-0048 ST1) cannot hold
/// two shares near the inline cap, so an outbox holding them was carried by no
/// vault, its text messages included
/// (`TASK-an-outbox-holding-two-shares-is-handed-to-its-vault-in-one-frame-that-cannot-hold-them`).
/// Now the device hands what is new and names what may go, and the answer's
/// list — each id with the last epoch its doors reach — is what it diffs
/// against next. A message already carried keeps its schedule and its first
/// hand-over time; its doors, and the epoch they reach, are the ones handed now.
///
/// Every bound holds against the set that results, not the request: what is
/// carried never passes [`CARRY_CAP`] however many requests built it, and a
/// request that would take it past is refused whole, changing nothing.
pub async fn carry(
    db: &Arc<SqlitePool>,
    user_id: &str,
    messages: Vec<CarriedMessage>,
    drop: Vec<String>,
) -> UserResponse {
    let refused = |message: String| UserResponse::Error { message };
    if messages.len() > CARRY_CAP || drop.len() > CARRY_CAP {
        return refused(format!("a vault carries at most {CARRY_CAP} messages for one person"));
    }
    let mut rows = Vec::with_capacity(messages.len());
    for m in messages {
        if m.doors.is_empty() || m.doors.len() > DOORS_PER_MESSAGE {
            return refused(format!("a carried message brings between 1 and {DOORS_PER_MESSAGE} doors"));
        }
        if m.doors.iter().any(|d| decode32(&d.seed).is_none() || decode32(&d.admit).is_none()) {
            return refused("a carried message's door is not two 32-byte keys".to_string());
        }
        let (Ok(sealed), Ok(doors)) = (serde_json::to_string(&m.sealed), serde_json::to_string(&m.doors)) else {
            return refused("a carried message could not be kept as it came".to_string());
        };
        // The last hour it may be tried in; `doors` is not empty, checked above.
        let through = m.doors.iter().map(|d| d.epoch).max().unwrap_or(0);
        rows.push((m.sealed.ephemeral_pub, sealed, doors, through));
    }
    let err = |e: sqlx::Error| UserResponse::Error {
        message: format!("could not keep what is carried: {e}"),
    };
    let now = rendezvous::unix_now() as i64;
    // One transaction, as the doors' window is: a pass never sees half a
    // request, and a refused one leaves what was carried as it was.
    let mut tx = match db.begin().await {
        Ok(t) => t,
        Err(e) => return err(e),
    };
    for gone in &drop {
        if let Err(e) = sqlx::query("DELETE FROM carried_messages WHERE user_id = ? AND ephemeral_pub = ?")
            .bind(user_id)
            .bind(gone)
            .execute(&mut *tx)
            .await
        {
            return err(e);
        }
    }
    for (id, sealed, doors, through) in &rows {
        // A message already carried keeps its schedule and its first hand-over
        // time; its doors, and so its window, are the ones the device handed
        // now — which is how a device extends a window about to close.
        if let Err(e) = sqlx::query(
            "INSERT INTO carried_messages (user_id, ephemeral_pub, sealed, doors, handed_at, attempts, next_at, through_epoch)
             VALUES (?, ?, ?, ?, ?, 0, ?, ?)
             ON CONFLICT (user_id, ephemeral_pub) DO UPDATE SET doors = excluded.doors, through_epoch = excluded.through_epoch",
        )
        .bind(user_id)
        .bind(id)
        .bind(sealed)
        .bind(doors)
        .bind(now)
        .bind(now)
        .bind(*through as i64)
        .execute(&mut *tx)
        .await
        {
            return err(e);
        }
    }
    let carrying: Vec<Carrying> = match sqlx::query(
        "SELECT ephemeral_pub, through_epoch FROM carried_messages WHERE user_id = ? ORDER BY handed_at, ephemeral_pub",
    )
    .bind(user_id)
    .fetch_all(&mut *tx)
    .await
    {
        Ok(r) => r
            .into_iter()
            .map(|r| Carrying {
                ephemeral_pub: r.get::<String, _>("ephemeral_pub"),
                through_epoch: r.get::<i64, _>("through_epoch").max(0) as u64,
            })
            .collect(),
        Err(e) => return err(e),
    };
    if carrying.len() > CARRY_CAP {
        // Dropped with the transaction: nothing this request did is kept.
        return refused(format!("a vault carries at most {CARRY_CAP} messages for one person"));
    }
    if let Err(e) = tx.commit().await {
        return err(e);
    }
    let room = CARRY_CAP.saturating_sub(carrying.len()) as u32;
    UserResponse::FrameCarried { carried: carrying.len() as u32, carrying, room }
}

/// How many messages this vault carries for `user_id` — a readout.
pub async fn count(db: &SqlitePool, user_id: &str) -> u32 {
    sqlx::query("SELECT COUNT(*) AS n FROM carried_messages WHERE user_id = ?")
        .bind(user_id)
        .fetch_one(db)
        .await
        .map(|r| r.get::<i64, _>("n") as u32)
        .unwrap_or(0)
}

/// How long a carried message waits after `attempts` tries: `base` after the
/// first, doubling to an hour — the outbox's own schedule (`Retry::DEFAULT`).
/// `KOTTON_VAULT_CARRY_SECS` sets a flat interval, the seam a test uses.
fn wait_after(attempts: u32) -> u64 {
    let (base, cap) = schedule();
    let doublings = attempts.saturating_sub(1).min(16);
    base.saturating_mul(1u64 << doublings).min(cap.max(base))
}

fn schedule() -> (u64, u64) {
    match std::env::var("KOTTON_VAULT_CARRY_SECS").ok().and_then(|v| v.parse::<u64>().ok()) {
        Some(s) if s > 0 => (s, s),
        _ => (30, 60 * 60),
    }
}

/// Try every carried message that is due, on a tick as short as the shortest
/// wait and never longer than thirty seconds.
pub fn spawn(runtime: Arc<DeviceRuntime>, db: Arc<SqlitePool>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let tick = Duration::from_secs(schedule().0.clamp(1, 30));
        // Until the vault closes its database at shutdown.
        while !db.is_closed() {
            tokio::time::sleep(tick).await;
            pass(&runtime, &db).await;
        }
    })
}

/// One pass: each carried message that is due is dialled once, in the order it
/// was handed here.
pub async fn pass(runtime: &Arc<DeviceRuntime>, db: &Arc<SqlitePool>) {
    if db.is_closed() {
        return;
    }
    let relay = runtime.reachability().nat().relay_url;
    if relay.trim().is_empty() {
        return;
    }
    let now = rendezvous::unix_now();
    let due = match due(db, now).await {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error = %e, "what this vault carries could not be read this pass");
            return;
        }
    };
    // Presented as a tenant would present it: the invited key, when the
    // operator has handed the vault its relay's keys.
    let admission = crate::reach::invited(runtime);
    for (user_id, id) in due {
        // Read when its turn comes, not with the rest: a share's range is
        // seven MiB sealed, and a pass that read every due row first would
        // hold a whole share's ranges at once. One the device named for
        // dropping since the pass began is gone, and not dialled.
        let r = match sqlx::query(
            "SELECT sealed, doors, handed_at, attempts FROM carried_messages WHERE user_id = ? AND ephemeral_pub = ?",
        )
        .bind(&user_id)
        .bind(&id)
        .fetch_optional(db.as_ref())
        .await
        {
            Ok(Some(r)) => r,
            Ok(None) => continue,
            Err(e) => {
                tracing::warn!(error = %e, "a carried message could not be read this pass");
                continue;
            }
        };
        let attempts = r.get::<i64, _>("attempts") as u32;
        let handed_at = r.get::<i64, _>("handed_at") as u64;
        let (Ok(sealed), Ok(doors)) = (
            serde_json::from_str::<SealedDm>(&r.get::<String, _>("sealed")),
            serde_json::from_str::<Vec<HeldDoor>>(&r.get::<String, _>("doors")),
        ) else {
            drop_carried(db, &user_id, &id).await;
            continue;
        };
        let tries = attempts_at(&doors, now);
        if tries.is_empty() {
            // Every door has passed: carried for as long as it was handed doors
            // for, and no longer. The outbox still holds it.
            if doors.iter().all(|d| d.epoch + 1 < kotton_crypto::epoch_at(now)) {
                drop_carried(db, &user_id, &id).await;
            } else {
                reschedule(db, &user_id, &id, attempts).await;
            }
            continue;
        }
        let request = ContactRequest::CarryMessage { sealed };
        let answer = tokio::time::timeout(
            DIAL_WITHIN,
            kotton_peer::contact_delivery::deliver_by(&relay, tries, &request, admission.clone()),
        )
        .await;
        match answer {
            Ok(Ok(ContactResponse::SignedSealed { ack, .. })) => {
                match keep_signature(db, &user_id, handed_at, ack).await {
                    ContactResponse::Delivered { .. } => drop_carried(db, &user_id, &id).await,
                    // Not kept — the held deliveries are full, or the person
                    // holds no door here any more. Tried again: the device that
                    // holds it signs for it again.
                    _ => reschedule(db, &user_id, &id, attempts).await,
                }
            }
            // Held without a signature — their vault — or answered in the
            // clear, which a carrier never keeps: tried again until a device
            // signs for it sealed. A card declines only a reach note, and a
            // vault carries messages, so `Declined` is a door saying something
            // a carried message never earns, and is tried again like a refusal.
            Ok(Ok(ContactResponse::Delivered { .. }))
            | Ok(Ok(ContactResponse::Refused { .. }))
            | Ok(Ok(ContactResponse::Declined { .. }))
            | Ok(Err(_))
            | Err(_) => reschedule(db, &user_id, &id, attempts).await,
        }
    }
}

/// What is due at `now`, by person and id, **in the order it was handed
/// here**: by hand-over time, and within one second by the order the rows were
/// written — a device hands its outbox a frame at a time, several in a second.
///
/// The order is the device's (`vault_doors::carried_for` hands every message
/// before any range of a share), so a share's manifest is dialled before its
/// ranges: the recipient's node keeps a range only for a share whose manifest
/// is waiting there, and refuses one that comes first as something that may
/// clear — tried again here, never lost, but seven MiB sent for nothing
/// (`TASK-a-senders-vault-carries-a-shares-ranges-while-no-device-of-theirs-is-awake`).
/// A message upserted again keeps its row, and so its place.
async fn due(db: &SqlitePool, now: u64) -> Result<Vec<(String, String)>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT user_id, ephemeral_pub FROM carried_messages WHERE next_at <= ? ORDER BY handed_at, rowid",
    )
    .bind(now as i64)
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|r| (r.get("user_id"), r.get("ephemeral_pub"))).collect())
}

/// Keep a sealed signature for `user_id`, to be taken at their next pickup.
///
/// Filed under no door — an empty `handle_did` — and stamped with when the
/// message was handed to this vault, never when it was signed. Every door is
/// one hour's, and `held_doors` maps it back, so any door would record an hour
/// the row has no need to say: the sender's pickup opens the envelope and reads
/// no door (`file_from_vault`). Ruled by the owner 2026-09-26
/// (`TASK-a-message-stays-in-the-outbox-until-one-of-their-devices-signs-for-it`).
async fn keep_signature(db: &SqlitePool, user_id: &str, handed_at: u64, ack: SealedDm) -> ContactResponse {
    crate::doors::keep_at(db, user_id, "", ack, handed_at).await
}

/// The dials for `now`: this hour's door, then the last hour's — a recipient
/// whose clock sits either side of the boundary still answers — from the doors
/// the device handed over.
fn attempts_at(doors: &[HeldDoor], now: u64) -> Vec<DeliveryAttempt> {
    let epoch = kotton_crypto::epoch_at(now);
    let mut out = Vec::with_capacity(2);
    for e in [Some(epoch), epoch.checked_sub(1)].into_iter().flatten() {
        let Some(door) = doors.iter().find(|d| d.epoch == e) else {
            continue;
        };
        let (Some(seed), Some(admit)) = (decode32(&door.seed), decode32(&door.admit)) else {
            continue;
        };
        let Ok(target) = VerifyingKey::from_bytes(&admit) else {
            continue;
        };
        let auth_key = SigningKey::from_bytes(&seed);
        out.push(DeliveryAttempt {
            epoch: e,
            auth_did: DidKeyMethod::from_public_key(&auth_key.verifying_key()).to_string(),
            auth_key,
            target: DidKeyMethod::from_public_key(&target).to_string(),
            target_pub: admit,
        });
    }
    out
}

async fn reschedule(db: &SqlitePool, user_id: &str, id: &str, attempts: u32) {
    let attempts = attempts.saturating_add(1);
    let next = rendezvous::unix_now().saturating_add(wait_after(attempts));
    if let Err(e) = sqlx::query(
        "UPDATE carried_messages SET attempts = ?, next_at = ? WHERE user_id = ? AND ephemeral_pub = ?",
    )
    .bind(attempts as i64)
    .bind(next as i64)
    .bind(user_id)
    .bind(id)
    .execute(db)
    .await
    {
        tracing::warn!(error = %e, "a carried message's next try could not be kept");
    }
}

async fn drop_carried(db: &SqlitePool, user_id: &str, id: &str) {
    if let Err(e) = sqlx::query("DELETE FROM carried_messages WHERE user_id = ? AND ephemeral_pub = ?")
        .bind(user_id)
        .bind(id)
        .execute(db)
        .await
    {
        tracing::warn!(error = %e, "a carried message could not be dropped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

    fn door(epoch: u64, seed: u8) -> HeldDoor {
        let admit = SigningKey::from_bytes(&[seed.wrapping_add(1); 32]).verifying_key().to_bytes();
        HeldDoor { epoch, seed: B64.encode([seed; 32]), admit: B64.encode(admit) }
    }

    fn message(id: &str, doors: Vec<HeldDoor>) -> CarriedMessage {
        CarriedMessage {
            sealed: SealedDm { ephemeral_pub: id.into(), nonce: "n".into(), body: "b".into() },
            doors,
        }
    }

    async fn db() -> (tempfile::TempDir, Arc<SqlitePool>) {
        let dir = tempfile::tempdir().unwrap();
        let db = kotton_device::db::open_machine_db(dir.path().join("agent.db")).await.unwrap();
        init(&db).await.unwrap();
        (dir, Arc::new(db))
    }

    /// What a device hands is added and what it names is dropped: a message
    /// its outbox no longer holds stops being carried, one it still holds keeps
    /// its schedule whether or not it is handed again, another person's is
    /// untouched — and every answer lists what is carried now, which is what
    /// the device diffs against on its next pass.
    #[tokio::test]
    async fn what_is_handed_is_added_and_what_is_named_is_dropped() {
        let (_dir, db) = db().await;
        let now = kotton_crypto::epoch_at(rendezvous::unix_now());
        let doors = || vec![door(now, 1)];
        let carried = carry(&db, "alice", vec![message("m1", doors()), message("m2", doors())], vec![]).await;
        let UserResponse::FrameCarried { carried: 2, carrying, .. } = carried else { panic!("{carried:?}") };
        assert_eq!(sorted(carrying), ["m1", "m2"]);
        carry(&db, "bob", vec![message("m9", doors())], vec![]).await;
        sqlx::query("UPDATE carried_messages SET attempts = 3 WHERE ephemeral_pub = 'm2'")
            .execute(db.as_ref())
            .await
            .unwrap();

        // A second frame adds without replacing: m1 and m2 are still carried.
        let carried = carry(&db, "alice", vec![message("m3", doors())], vec![]).await;
        let UserResponse::FrameCarried { carried: 3, carrying, .. } = carried else { panic!("{carried:?}") };
        assert_eq!(sorted(carrying), ["m1", "m2", "m3"], "a frame is added to the set, never the set");

        // m1 was signed for and left alice's outbox; m2 is handed again.
        let carried = carry(&db, "alice", vec![message("m2", doors())], vec!["m1".into(), "m9".into()]).await;
        let UserResponse::FrameCarried { carried: 2, carrying, .. } = carried else { panic!("{carried:?}") };
        assert_eq!(sorted(carrying), ["m2", "m3"]);
        assert_eq!(count(&db, "bob").await, 1, "another person's carry is theirs, whatever is named");
        let attempts: i64 = sqlx::query("SELECT attempts FROM carried_messages WHERE ephemeral_pub = 'm2'")
            .fetch_one(db.as_ref())
            .await
            .unwrap()
            .get("attempts");
        assert_eq!(attempts, 3, "a message still carried keeps its schedule");

        // Empty both ways is the readout, and changes nothing.
        let carried = carry(&db, "alice", vec![], vec![]).await;
        let UserResponse::FrameCarried { carried: 2, carrying, .. } = carried else { panic!("{carried:?}") };
        assert_eq!(sorted(carrying), ["m2", "m3"]);
    }

    /// The cap holds against the set a request leaves, not the request: a
    /// frame that would take what is carried past it is refused whole and
    /// changes nothing, and one that drops as many as it adds is not.
    #[tokio::test]
    async fn the_cap_holds_against_what_is_carried_not_what_one_frame_hands() {
        let (_dir, db) = db().await;
        let now = kotton_crypto::epoch_at(rendezvous::unix_now());
        let full: Vec<CarriedMessage> = (0..CARRY_CAP).map(|i| message(&format!("m{i}"), vec![door(now, 1)])).collect();
        let carried = carry(&db, "alice", full, vec![]).await;
        assert!(matches!(carried, UserResponse::FrameCarried { carried, .. } if carried as usize == CARRY_CAP), "{carried:?}");

        let one_more = carry(&db, "alice", vec![message("over", vec![door(now, 1)])], vec![]).await;
        assert!(matches!(one_more, UserResponse::Error { .. }), "{one_more:?}");
        assert_eq!(count(&db, "alice").await as usize, CARRY_CAP, "a refused frame changes nothing");

        let swapped = carry(&db, "alice", vec![message("over", vec![door(now, 1)])], vec!["m0".into()]).await;
        let UserResponse::FrameCarried { carrying, .. } = swapped else { panic!("{swapped:?}") };
        assert_eq!(carrying.len(), CARRY_CAP);
        let ids = sorted(carrying);
        assert!(ids.contains(&"over".to_string()) && !ids.contains(&"m0".to_string()));
    }

    /// Every answer says the room left: the cap less what is carried for
    /// the person once the request is applied — a frame's additions take it,
    /// its drops give it back, a message handed again takes none, and another
    /// person's carry is not counted.
    #[tokio::test]
    async fn each_answer_says_the_room_left_under_the_cap() {
        let (_dir, db) = db().await;
        let now = kotton_crypto::epoch_at(rendezvous::unix_now());
        let room = |answer: UserResponse| match answer {
            UserResponse::FrameCarried { room, .. } => room as usize,
            other => panic!("{other:?}"),
        };
        carry(&db, "bob", vec![message("theirs", vec![door(now, 1)])], vec![]).await;
        assert_eq!(room(carry(&db, "alice", vec![], vec![]).await), CARRY_CAP, "nothing carried for her");
        let three: Vec<CarriedMessage> = ["m1", "m2", "m3"].iter().map(|id| message(id, vec![door(now, 1)])).collect();
        assert_eq!(room(carry(&db, "alice", three, vec![]).await), CARRY_CAP - 3);
        assert_eq!(room(carry(&db, "alice", vec![message("m1", vec![door(now, 1)])], vec!["m2".into()]).await), CARRY_CAP - 2);
        let rest: Vec<CarriedMessage> =
            (0..CARRY_CAP - 2).map(|i| message(&format!("n{i}"), vec![door(now, 1)])).collect();
        assert_eq!(room(carry(&db, "alice", rest, vec![]).await), 0, "full");
    }

    fn sorted(carrying: Vec<Carrying>) -> Vec<String> {
        let mut ids: Vec<String> = carrying.into_iter().map(|c| c.ephemeral_pub).collect();
        ids.sort();
        ids
    }

    /// The answer says, for each message, the last epoch its doors reach — the
    /// largest of the doors it was handed — and a message handed again with a
    /// later window reads the later one, its schedule kept.
    #[tokio::test]
    async fn each_carried_message_is_answered_with_the_last_epoch_its_doors_reach() {
        let (_dir, db) = db().await;
        let now = kotton_crypto::epoch_at(rendezvous::unix_now());
        let carried = carry(&db, "alice", vec![message("m1", vec![door(now + 5, 1), door(now + 90, 1), door(now, 1)])], vec![]).await;
        let UserResponse::FrameCarried { carrying, .. } = carried else { panic!("{carried:?}") };
        assert_eq!(carrying, vec![Carrying { ephemeral_pub: "m1".into(), through_epoch: now + 90 }]);

        sqlx::query("UPDATE carried_messages SET attempts = 2 WHERE ephemeral_pub = 'm1'")
            .execute(db.as_ref())
            .await
            .unwrap();
        let carried = carry(&db, "alice", vec![message("m1", vec![door(now + 168, 1)])], vec![]).await;
        let UserResponse::FrameCarried { carrying, .. } = carried else { panic!("{carried:?}") };
        assert_eq!(carrying[0].through_epoch, now + 168, "handed again, the window is the new one");
        let attempts: i64 = sqlx::query("SELECT attempts FROM carried_messages WHERE ephemeral_pub = 'm1'")
            .fetch_one(db.as_ref())
            .await
            .unwrap()
            .get("attempts");
        assert_eq!(attempts, 2, "and the schedule is kept");
    }

    /// A table from before `through_epoch` gains the column on open, and its
    /// rows read 0 — a window already closed — so the device hands them again.
    #[tokio::test]
    async fn a_table_from_before_the_window_column_gains_it_and_its_rows_read_closed() {
        let dir = tempfile::tempdir().unwrap();
        let db = kotton_device::db::open_machine_db(dir.path().join("agent.db")).await.unwrap();
        sqlx::query(
            "CREATE TABLE carried_messages (user_id TEXT NOT NULL, ephemeral_pub TEXT NOT NULL, sealed TEXT NOT NULL,
             doors TEXT NOT NULL, handed_at INTEGER NOT NULL, attempts INTEGER NOT NULL, next_at INTEGER NOT NULL,
             PRIMARY KEY (user_id, ephemeral_pub))",
        )
        .execute(&db)
        .await
        .unwrap();
        sqlx::query("INSERT INTO carried_messages VALUES ('alice', 'old', 's', '[]', 1, 0, 1)")
            .execute(&db)
            .await
            .unwrap();
        init(&db).await.unwrap();
        init(&db).await.unwrap();
        let carried = carry(&Arc::new(db), "alice", vec![], vec![]).await;
        let UserResponse::FrameCarried { carrying, .. } = carried else { panic!("{carried:?}") };
        assert_eq!(carrying, vec![Carrying { ephemeral_pub: "old".into(), through_epoch: 0 }]);
    }

    /// What is due is dialled in the order it was handed: a share's manifest,
    /// handed in the frame before its ranges, goes before them however its id
    /// sorts — the recipient keeps a range only for a share whose manifest is
    /// waiting there — and a frame handed in the same second as another keeps
    /// its place behind it. A message handed again keeps its place; one not
    /// due is not taken.
    #[tokio::test]
    async fn what_is_due_is_dialled_in_the_order_it_was_handed() {
        let (_dir, db) = db().await;
        let now = kotton_crypto::epoch_at(rendezvous::unix_now());
        let doors = || vec![door(now, 1)];
        // Earlier than any frame below, by its hand-over time.
        carry(&db, "bob", vec![message("0-earlier", doors())], vec![]).await;
        sqlx::query("UPDATE carried_messages SET handed_at = handed_at - 60 WHERE ephemeral_pub = '0-earlier'")
            .execute(db.as_ref())
            .await
            .unwrap();
        // The manifest's frame, then each range in a frame of its own: ids
        // that sort the other way round.
        carry(&db, "alice", vec![message("z-manifest", doors())], vec![]).await;
        carry(&db, "alice", vec![message("b-range", doors())], vec![]).await;
        carry(&db, "alice", vec![message("a-range", doors())], vec![]).await;
        carry(&db, "alice", vec![message("not-due", doors())], vec![]).await;
        sqlx::query("UPDATE carried_messages SET next_at = next_at + 3600 WHERE ephemeral_pub = 'not-due'")
            .execute(db.as_ref())
            .await
            .unwrap();
        // The manifest handed again, as a window extended re-hands it.
        carry(&db, "alice", vec![message("z-manifest", doors())], vec![]).await;
        // Within one second, as a pass hands its frames.
        sqlx::query("UPDATE carried_messages SET handed_at = ? WHERE user_id = 'alice'")
            .bind(rendezvous::unix_now() as i64)
            .execute(db.as_ref())
            .await
            .unwrap();

        let order: Vec<String> = due(&db, rendezvous::unix_now()).await.unwrap().into_iter().map(|(_, id)| id).collect();
        assert_eq!(order, ["0-earlier", "z-manifest", "b-range", "a-range"]);
    }

    /// A carry is bounded in size and in time (RFC-0083 R3): no more doors
    /// than a week's window, no door that is not two keys.
    #[tokio::test]
    async fn a_carry_past_its_bounds_is_refused_whole() {
        let (_dir, db) = db().await;
        let too_many: Vec<HeldDoor> = (0..DOORS_PER_MESSAGE as u64 + 1).map(|e| door(e, 1)).collect();
        assert!(matches!(carry(&db, "alice", vec![message("m1", too_many)], vec![]).await, UserResponse::Error { .. }));
        let mut bad = door(1, 1);
        bad.admit = "short".into();
        assert!(matches!(carry(&db, "alice", vec![message("m1", vec![bad])], vec![]).await, UserResponse::Error { .. }));
        assert!(matches!(carry(&db, "alice", vec![message("m1", vec![])], vec![]).await, UserResponse::Error { .. }));
        assert_eq!(count(&db, "alice").await, 0);
    }

    /// A signature is kept under no door and stamped with the hand-over, never
    /// the signing: signed hours later, while the hand-over hour's door is in
    /// the set or after every door in it has passed, the row names no door and
    /// reads the same hour.
    #[tokio::test]
    async fn a_kept_signature_says_nothing_about_when_it_was_signed() {
        let (_dir, db) = db().await;
        crate::doors::init(&db).await.unwrap();
        // The person holds a door here, as `keep_at` asks.
        sqlx::query("INSERT INTO held_doors (user_id, epoch, handle_did, seed, admit) VALUES ('alice', 1, 'h', 's', 'a')")
            .execute(db.as_ref())
            .await
            .unwrap();
        for (ack, hours_ago) in [("in-the-set", 3), ("every-door-passed", 24 * 8)] {
            let handed_at = rendezvous::unix_now() - hours_ago * 3600;
            let sealed = SealedDm { ephemeral_pub: ack.into(), nonce: "n".into(), body: "b".into() };
            let kept = keep_signature(&db, "alice", handed_at, sealed).await;
            assert!(matches!(kept, ContactResponse::Delivered { stored: true, .. }), "{kept:?}");
            let row = sqlx::query("SELECT handle_did, received_at FROM held_deliveries WHERE ephemeral_pub = ?")
                .bind(ack)
                .fetch_one(db.as_ref())
                .await
                .unwrap();
            assert_eq!(row.get::<String, _>("handle_did"), "", "{ack}: filed under no door");
            assert_eq!(row.get::<i64, _>("received_at") as u64, handed_at, "{ack}: stamped with the hand-over, not the signing");
        }
        let UserResponse::Deliveries { items } = crate::doors::take(&db, "alice", vec![]).await else {
            panic!("the pickup reads what is held")
        };
        assert_eq!(items.len(), 2);
        assert!(items.iter().all(|d| d.handle_did.is_empty()), "the pickup is handed no door: {items:?}");
    }

    /// The dial for an hour is that hour's door and then the last hour's, each
    /// authenticating as the sender's handle and naming the recipient's —
    /// exactly what the sender's own device derives from the identity key.
    #[test]
    fn the_dial_is_this_hours_door_then_the_last_hours() {
        use ed25519_dalek::SigningKey;
        let (alice, bob) = (SigningKey::from_bytes(&[1; 32]), SigningKey::from_bytes(&[2; 32]));
        let now = rendezvous::unix_now();
        let epoch = kotton_crypto::epoch_at(now);
        let doors: Vec<HeldDoor> = [epoch - 1, epoch, epoch + 1]
            .into_iter()
            .map(|e| {
                let k = rendezvous::dm_door(&alice, &bob.verifying_key().to_bytes(), e).unwrap();
                HeldDoor { epoch: e, seed: B64.encode(k.handle.signing_key.to_bytes()), admit: B64.encode(k.admit) }
            })
            .collect();
        let tries = attempts_at(&doors, now);
        let own = rendezvous::dm_delivery_attempts(&alice, &bob.verifying_key().to_bytes(), now).unwrap();
        assert_eq!(tries.len(), 2);
        for (carried, derived) in tries.iter().zip(own.iter()) {
            assert_eq!(
                (carried.epoch, &carried.auth_did, &carried.target, carried.target_pub),
                (derived.epoch, &derived.auth_did, &derived.target, derived.target_pub),
                "the vault dials as the sender's device would"
            );
        }
        assert!(attempts_at(&doors[2..], now).is_empty(), "no door for this hour is no dial");
    }
}
