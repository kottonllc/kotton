// SPDX-License-Identifier: AGPL-3.0-or-later
//! The doors a vault holds for the people it keeps for (`DEC-0056`).
//!
//! A person's device derives, for each contact and each epoch of a window
//! ahead, the pair's inbox handle and the one key that door admits, and hands
//! them here with `HoldDoors`. The vault reserves each at its relay exactly as
//! a device reserves its own mailbox — the reconcile loop in `Reachability`
//! does not know the difference — and what arrives is kept as it came: an
//! ephemeral key, a nonce and ciphertext, filed under the door it came
//! through. A device of the person's takes it with `TakeDeliveries`, opens it,
//! proves who wrote it, files it, and acknowledges; only then is it dropped.
//!
//! **What this file never holds.** A key that opens. The seeds here are pair
//! handles: they label a reservation and answer inside its circuit, and they
//! cannot produce the signature inside the seal (RFC-0064 MS7), so a vault can
//! take a message for a person and cannot write one as them. It is also not
//! told which contact a door is for; it learns what the relay learns — a handle
//! got some bytes at some time.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::SigningKey;
use kotton_crypto::did::DidKeyMethod;
use kotton_device::DeviceRuntime;
use kotton_peer::contact_door::contact_door;
use kotton_peer::reachability::DmDoor;
use kotton_peer::PeerHandler;
use kotton_wire::ipc::{ContactResponse, HeldDoor, PendingDelivery, SealedDm, UserResponse};
use sqlx::{Row, SqlitePool};
use std::io;
use std::sync::Arc;

/// How many messages a vault will hold for one person before refusing. A
/// bound, so the relay-side rule (RFC-0083 R3: a copy is bounded in size and
/// time) is a number and not a hope. A refused delivery stays at the sender,
/// who is told. The time half is [`HELD_FOR_SECS`].
pub const DELIVERY_CAP: i64 = 4096;

/// How long a vault holds a delivery once a device of the person's has been
/// handed it and has not acknowledged it: a week from when it arrived here,
/// after which the next pickup drops it
/// (`TASK-a-copy-a-vault-holds-that-never-clears-is-held-for-ever-and-can-stop-the-pickup`).
///
/// **Why a week.** It is RFC-0083 R3's "bounded in … time" given a number, and
/// the same week everything else here is measured in: the doors a device hands
/// its vault reach a week ahead, a carried message is carried for a week of
/// doors, and a reach note may claim up to a week past the longest life before
/// a receiver's clock stops explaining it
/// ([`kotton_crypto::reach_note::CLOCK_BEHIND_SLACK_SECS`], held at or below
/// this by the assertion beside it). A device that was handed a copy and could
/// not file it answers *not yet*: the copy may clear — a grant it has not been
/// given, a clock behind the sender's — and is handed again at every pickup.
/// What has not cleared in a week will not: a channel the person left, an epoch
/// they will never hold, a note past its slack, an epoch a sender stamped
/// `u64::MAX`. Without the bound each is held for ever, counts toward
/// [`DELIVERY_CAP`] for ever, and 256 of them at the head of the queue are a
/// whole answer that stops every pickup behind them.
///
/// **Handed out before it is dropped.** Only a row a pickup's answer has
/// already carried is ever dropped (`handed_out`: put into an answer, which is
/// not the same as read by every device of the person's — see `init`), and a
/// pickup hands out the oldest first. So a copy waiting for a device that sleeps is handed out on
/// the first pickup that reaches it, however old it is, and a device off for a
/// month is handed everything a device off for a day would have been. What
/// differs is the retrying: a copy past the week that does not file on the
/// pickup that first hands it out is dropped at the next, where a device off
/// for a day would have been handed it again until its week was out. A direct
/// message or a channel copy that is dropped stays in its sender's outbox until
/// a device of the person's signs for it, and arrives here again with a fresh
/// week; a key-grant does not, since it is handed over once and nothing signs
/// for it (`hand_grant_over` in `core/msg`).
///
/// The bound counts from arrival, not from the first hand-out, because the row
/// records no hour of a device's: `received_at` is the door's arrival or, for a
/// signature kept after a carry, the hand-over to the carrier (`carry`), and a
/// bit says the copy was handed out. A clock that started at the first hand-out
/// would write down when a device of the person's was awake, which nothing here
/// keeps (ruled by the owner 2026-09-26, for the carried signature).
pub const HELD_FOR_SECS: u64 = 7 * 24 * 60 * 60;

// A note the receiver's clock is behind on clears within the slack as that
// clock runs on; a hold shorter than the slack would drop it first.
const _: () = assert!(HELD_FOR_SECS >= kotton_crypto::reach_note::CLOCK_BEHIND_SLACK_SECS);

/// How many pending deliveries one `TakeDeliveries` returns, at most.
const TAKE_BATCH: i64 = 256;

/// How many bytes of sealed deliveries one `TakeDeliveries` returns, past the
/// first: the answer travels as one frame, under the peer frame cap (10 MiB,
/// RFC-0048 ST1), and since a delivery may be a share whose body is a file of
/// up to five MiB (RFC-0090; nearly nine sealed), a batch bounded by count
/// alone would let two of them make an answer no device can read — and every
/// pickup after it would fail the same way, messages and all. The first is
/// returned whatever its size, so nothing held is ever stuck behind this; the
/// device asks again for the rest, as it already does.
const TAKE_BYTES: usize = 6 * 1024 * 1024;

pub async fn init(db: &SqlitePool) -> io::Result<()> {
    for ddl in [
        "CREATE TABLE IF NOT EXISTS held_doors (
            user_id TEXT NOT NULL,
            epoch INTEGER NOT NULL,
            handle_did TEXT NOT NULL,
            seed TEXT NOT NULL,
            admit TEXT NOT NULL,
            PRIMARY KEY (user_id, handle_did)
        )",
        "CREATE TABLE IF NOT EXISTS held_deliveries (
            user_id TEXT NOT NULL,
            handle_did TEXT NOT NULL,
            ephemeral_pub TEXT NOT NULL,
            sealed TEXT NOT NULL,
            received_at INTEGER NOT NULL,
            handed_out INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (user_id, ephemeral_pub)
        )",
    ] {
        sqlx::query(ddl).execute(db).await.map_err(io::Error::other)?;
    }
    // A table from before `handed_out` gains it in place. Its rows read 0 —
    // never handed out — so each goes into a pickup's answer before the bound
    // can drop it: an upgrade drops nothing a pickup answer has not carried.
    //
    // `handed_out` means *put into an answer*, not *seen by a device*. An
    // answer lost on the way, or taken by one of the person's devices, marks a
    // row another device never saw; the week then runs for every device of
    // theirs at once. The vault cannot tell which device read an answer, and
    // keeps no record that would let it.
    let has: bool = sqlx::query(
        "SELECT COUNT(*) AS n FROM pragma_table_info('held_deliveries') WHERE name = 'handed_out'",
    )
    .fetch_one(db)
    .await
    .map(|r| r.get::<i64, _>("n") > 0)
    .map_err(io::Error::other)?;
    if !has {
        sqlx::query("ALTER TABLE held_deliveries ADD COLUMN handed_out INTEGER NOT NULL DEFAULT 0")
            .execute(db)
            .await
            .map_err(io::Error::other)?;
    }
    Ok(())
}

/// `HoldDoors`: replace the window this vault holds for `user_id`.
pub async fn hold(
    runtime: &Arc<DeviceRuntime>,
    db: &Arc<SqlitePool>,
    user_id: &str,
    doors: Vec<HeldDoor>,
) -> UserResponse {
    let now_epoch = kotton_crypto::epoch_at(kotton_peer::rendezvous::unix_now());
    let mut rows = Vec::with_capacity(doors.len());
    for d in doors {
        if d.epoch + 1 < now_epoch {
            continue;
        }
        let Some(seed) = decode32(&d.seed) else {
            return UserResponse::Error {
                message: "a door's seed is not 32 bytes".to_string(),
            };
        };
        if decode32(&d.admit).is_none() {
            return UserResponse::Error {
                message: "a door's admitted key is not 32 bytes".to_string(),
            };
        }
        let did = DidKeyMethod::from_public_key(&SigningKey::from_bytes(&seed).verifying_key());
        rows.push((d.epoch, did.to_string(), d.seed, d.admit));
    }
    let err = |e: sqlx::Error| UserResponse::Error {
        message: format!("could not keep the doors: {e}"),
    };
    // One transaction: the window is replaced whole, so a reader — the
    // reconcile loop, a readout — never sees half of it.
    let mut tx = match db.begin().await {
        Ok(t) => t,
        Err(e) => return err(e),
    };
    if let Err(e) = sqlx::query("DELETE FROM held_doors WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut *tx)
        .await
    {
        return err(e);
    }
    let mut through = 0u64;
    for (epoch, did, seed, admit) in &rows {
        through = through.max(*epoch);
        if let Err(e) = sqlx::query(
            "INSERT OR REPLACE INTO held_doors (user_id, epoch, handle_did, seed, admit) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(user_id)
        .bind(*epoch as i64)
        .bind(did)
        .bind(seed)
        .bind(admit)
        .execute(&mut *tx)
        .await
        {
            return err(e);
        }
    }
    if let Err(e) = tx.commit().await {
        return err(e);
    }
    refresh(runtime, db).await;
    UserResponse::DoorsHeld {
        held: rows.len() as u32,
        through_epoch: through,
    }
}

/// `TakeDeliveries`: drop what the device acknowledges, and what it was handed
/// and has not acknowledged within [`HELD_FOR_SECS`] of its arrival; return
/// what remains, oldest first.
pub async fn take(db: &Arc<SqlitePool>, user_id: &str, ack: Vec<String>) -> UserResponse {
    take_at(db, user_id, ack, kotton_peer::rendezvous::unix_now()).await
}

/// [`take`], at `now`.
pub(crate) async fn take_at(db: &Arc<SqlitePool>, user_id: &str, ack: Vec<String>, now: u64) -> UserResponse {
    for eph in &ack {
        if let Err(e) = sqlx::query("DELETE FROM held_deliveries WHERE user_id = ? AND ephemeral_pub = ?")
            .bind(user_id)
            .bind(eph)
            .execute(db.as_ref())
            .await
        {
            return UserResponse::Error {
                message: format!("could not drop an acknowledged delivery: {e}"),
            };
        }
    }
    // Past the bound: handed out at an earlier pickup, never acknowledged, and
    // here longer than a week. A row no pickup has reached yet is kept whatever
    // its age, so it is handed out before it can be dropped.
    let held_since = now.saturating_sub(HELD_FOR_SECS).min(i64::MAX as u64) as i64;
    if let Err(e) =
        sqlx::query("DELETE FROM held_deliveries WHERE user_id = ? AND handed_out = 1 AND received_at < ?")
            .bind(user_id)
            .bind(held_since)
            .execute(db.as_ref())
            .await
    {
        return UserResponse::Error {
            message: format!("could not drop what was held past its week: {e}"),
        };
    }
    let rows = match sqlx::query(
        "SELECT ephemeral_pub, handle_did, sealed, handed_out FROM held_deliveries WHERE user_id = ? \
         ORDER BY received_at LIMIT ?",
    )
    .bind(user_id)
    .bind(TAKE_BATCH)
    .fetch_all(db.as_ref())
    .await
    {
        Ok(r) => r,
        Err(e) => {
            return UserResponse::Error {
                message: format!("could not read what is held: {e}"),
            }
        }
    };
    let mut items = Vec::new();
    let mut bytes = 0usize;
    // The rows this answer reached for the first time. A row past the size
    // bound was not reached, and is not marked: it is handed out by a later ask.
    let mut first_handed = Vec::new();
    for r in rows {
        let text = r.get::<String, _>("sealed");
        if !items.is_empty() && bytes + text.len() > TAKE_BYTES {
            break;
        }
        if r.get::<i64, _>("handed_out") == 0 {
            first_handed.push(r.get::<String, _>("ephemeral_pub"));
        }
        // Only what is returned counts toward the answer's size: a row that
        // will not parse is not in the answer, and must not shorten it. It is
        // reached all the same, so it leaves within the bound rather than
        // standing at the head of every pickup for ever.
        if let Ok(sealed) = serde_json::from_str::<SealedDm>(&text) {
            bytes += text.len();
            items.push(PendingDelivery { handle_did: r.get::<String, _>("handle_did"), sealed });
        }
    }
    for eph in &first_handed {
        // A row left unmarked is only kept longer — until a pickup that can
        // mark it — so a failure here costs the bound, never a delivery.
        if let Err(e) =
            sqlx::query("UPDATE held_deliveries SET handed_out = 1 WHERE user_id = ? AND ephemeral_pub = ?")
                .bind(user_id)
                .bind(eph)
                .execute(db.as_ref())
                .await
        {
            tracing::warn!(error = %e, "a delivery handed out could not be marked; its week waits for the next pickup");
        }
    }
    UserResponse::Deliveries { items }
}

/// Rebuild the door registry from the table, dropping doors whose epoch has
/// passed. Whole-set replacement, as the mailbox registry is: the table is the
/// truth, and `Reachability` reconciles the reservations on its next pass.
pub async fn refresh(runtime: &Arc<DeviceRuntime>, db: &Arc<SqlitePool>) {
    let now_epoch = kotton_crypto::epoch_at(kotton_peer::rendezvous::unix_now()) as i64;
    let _ = sqlx::query("DELETE FROM held_doors WHERE epoch < ?")
        .bind(now_epoch - 1)
        .execute(db.as_ref())
        .await;
    let rows = match sqlx::query("SELECT user_id, epoch, handle_did, seed, admit FROM held_doors")
        .fetch_all(db.as_ref())
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "held doors unreadable; holding none");
            Vec::new()
        }
    };
    let mut doors = Vec::with_capacity(rows.len());
    for r in rows {
        let (Some(seed), Some(admit)) = (
            decode32(&r.get::<String, _>("seed")),
            decode32(&r.get::<String, _>("admit")),
        ) else {
            continue;
        };
        let signing_key = SigningKey::from_bytes(&seed);
        let did = DidKeyMethod::from_public_key(&signing_key.verifying_key());
        let user_id: String = r.get("user_id");
        let handle_did = did.to_string();
        doors.push(DmDoor {
            epoch: r.get::<i64, _>("epoch") as u64,
            handle: kotton_crypto::PairHandle { did, signing_key },
            admit,
            handler: door_handler(Arc::clone(db), user_id, handle_did),
        });
    }
    let count = doors.len();
    *runtime.reachability().dm_doors().write().unwrap() = doors;
    tracing::debug!(doors = count, "held doors reconciled");
}

/// The door itself: takes one sealed message and keeps it as it came —
/// handed over or carried alike, since a vault answers both as a vault: it
/// holds, and signs for nothing.
fn door_handler(db: Arc<SqlitePool>, user_id: String, handle_did: String) -> PeerHandler {
    contact_door(move |request| {
        let sealed = request.sealed().clone();
        let db = Arc::clone(&db);
        let user_id = user_id.clone();
        let handle_did = handle_did.clone();
        async move { keep(&db, &user_id, &handle_did, sealed).await }
    })
}

async fn keep(db: &SqlitePool, user_id: &str, handle_did: &str, sealed: SealedDm) -> ContactResponse {
    keep_at(db, user_id, handle_did, sealed, kotton_peer::rendezvous::unix_now()).await
}

/// Keep `sealed` for `user_id` under the door `handle_did` — empty for a
/// signature kept after a carry, which arrived at no door of theirs — as
/// arriving at `received_at`, what a pickup is ordered by. The door stamps its arrivals
/// now; a carried message's acknowledgement is stamped with when the message
/// was handed to the vault (`carry`), so the row records nothing about when a
/// device signed.
pub(crate) async fn keep_at(
    db: &SqlitePool,
    user_id: &str,
    handle_did: &str,
    sealed: SealedDm,
    received_at: u64,
) -> ContactResponse {
    let refused = |reason: String| ContactResponse::Refused { reason };
    let held: i64 = match sqlx::query("SELECT COUNT(*) AS n FROM held_deliveries WHERE user_id = ?")
        .bind(user_id)
        .fetch_one(db)
        .await
    {
        Ok(r) => r.get("n"),
        Err(e) => return refused(format!("could not count what is held: {e}")),
    };
    let already: bool = match sqlx::query(
        "SELECT 1 FROM held_deliveries WHERE user_id = ? AND ephemeral_pub = ? LIMIT 1",
    )
    .bind(user_id)
    .bind(&sealed.ephemeral_pub)
    .fetch_optional(db)
    .await
    {
        Ok(r) => r.is_some(),
        Err(e) => return refused(format!("could not check for an existing copy: {e}")),
    };
    if already {
        // A vault holds; it never signs for anything — it has no device key,
        // and only a device's signature says a message arrived.
        return ContactResponse::Delivered { stored: false, ack: None };
    }
    if held >= DELIVERY_CAP {
        return refused("this vault is holding as much as it will for them".to_string());
    }
    let Ok(text) = serde_json::to_string(&sealed) else {
        return refused("that message could not be kept as it came".to_string());
    };
    // Kept only for a person this vault still holds a door for, in the same
    // statement as the insert: a delivery racing the landlord's drop of this
    // tenant either lands before the drop's sweep and goes with it, or finds
    // no door and is refused back to the sender — never a row for a tenant
    // who is gone (`tenancy::drop_tenant`).
    match sqlx::query(
        "INSERT INTO held_deliveries (user_id, handle_did, ephemeral_pub, sealed, received_at)
         SELECT ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM held_doors WHERE user_id = ?)",
    )
    .bind(user_id)
    .bind(handle_did)
    .bind(&sealed.ephemeral_pub)
    .bind(text)
    .bind(received_at as i64)
    .bind(user_id)
    .execute(db)
    .await
    {
        Ok(r) if r.rows_affected() == 1 => ContactResponse::Delivered { stored: true, ack: None },
        Ok(_) => refused("this vault no longer holds a door for them".to_string()),
        Err(e) => refused(format!("could not keep the message: {e}")),
    }
}

pub(crate) fn decode32(s: &str) -> Option<[u8; 32]> {
    B64.decode(s).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sealed delivery whose body is `len` bytes of base64 — the size a share
    /// of about three-quarters of that many plaintext bytes seals to.
    fn sealed_of(seed: u8, len: usize) -> SealedDm {
        SealedDm {
            ephemeral_pub: format!("eph-{seed}"),
            nonce: "bm9uY2U=".into(),
            body: std::iter::repeat_n(char::from(b'A' + seed), len).collect(),
        }
    }

    async fn holding(sealed: &[SealedDm]) -> Arc<SqlitePool> {
        let db = Arc::new(SqlitePool::connect("sqlite::memory:").await.expect("db"));
        init(&db).await.expect("tables");
        for (i, s) in sealed.iter().enumerate() {
            sqlx::query(
                "INSERT INTO held_deliveries (user_id, handle_did, ephemeral_pub, sealed, received_at) \
                 VALUES ('bob', 'did:key:door', ?, ?, ?)",
            )
            .bind(&s.ephemeral_pub)
            .bind(serde_json::to_string(s).unwrap())
            .bind(i as i64)
            .execute(db.as_ref())
            .await
            .expect("held");
        }
        db
    }

    /// **A pickup's answer fits the frame it travels in**, however large what
    /// is held: two shares near the inline cap come back over two asks, each
    /// answer under the peer frame cap, and the second is not stuck behind the
    /// first (`TASK-a-file-shared-with-a-contact-is-a-copy-of-theirs-under-shared-with-you`).
    /// Small messages still come back many to an answer.
    #[tokio::test]
    async fn a_pickup_answer_fits_one_frame_and_nothing_held_is_stuck_behind_it() {
        const FRAME_CAP: usize = 10 * 1024 * 1024;
        let big = 8_900_000;
        let db = holding(&[sealed_of(0, big), sealed_of(1, big), sealed_of(2, 100)]).await;

        let UserResponse::Deliveries { items } = take(&db, "bob", vec![]).await else { panic!() };
        let frame = serde_json::to_vec(&UserResponse::Deliveries { items: items.clone() }).unwrap();
        assert_eq!(items.len(), 1, "two near-cap shares in one answer");
        assert!(frame.len() < FRAME_CAP, "{} bytes in a {FRAME_CAP} byte frame", frame.len());

        let UserResponse::Deliveries { items } = take(&db, "bob", vec!["eph-0".into()]).await else { panic!() };
        assert_eq!(items.iter().map(|i| i.sealed.ephemeral_pub.as_str()).collect::<Vec<_>>(), ["eph-1"]);
        let UserResponse::Deliveries { items } = take(&db, "bob", vec!["eph-1".into()]).await else { panic!() };
        assert_eq!(items.iter().map(|i| i.sealed.ephemeral_pub.as_str()).collect::<Vec<_>>(), ["eph-2"]);

        let small: Vec<SealedDm> = (0..40).map(|i| sealed_of(i, 200)).collect();
        let db = holding(&small).await;
        let UserResponse::Deliveries { items } = take(&db, "bob", vec![]).await else { panic!() };
        assert_eq!(items.len(), 40, "small messages are still taken many at a time");
    }

    /// What is held for "bob" now, by id, oldest first.
    async fn held_ids(db: &SqlitePool) -> Vec<String> {
        sqlx::query("SELECT ephemeral_pub FROM held_deliveries WHERE user_id = 'bob' ORDER BY received_at")
            .fetch_all(db)
            .await
            .expect("held")
            .into_iter()
            .map(|r| r.get::<String, _>("ephemeral_pub"))
            .collect()
    }

    /// Hold `sealed` for "bob" as arriving at `received_at`, never handed out.
    async fn hold_at(db: &SqlitePool, sealed: &SealedDm, received_at: u64) {
        sqlx::query(
            "INSERT INTO held_deliveries (user_id, handle_did, ephemeral_pub, sealed, received_at) \
             VALUES ('bob', 'did:key:door', ?, ?, ?)",
        )
        .bind(&sealed.ephemeral_pub)
        .bind(serde_json::to_string(sealed).unwrap())
        .bind(received_at as i64)
        .execute(db)
        .await
        .expect("held");
    }

    fn ids(r: UserResponse) -> Vec<String> {
        let UserResponse::Deliveries { items } = r else { panic!("{r:?}") };
        items.into_iter().map(|i| i.sealed.ephemeral_pub).collect()
    }

    /// **A copy handed out and not acknowledged within a week of arriving is
    /// dropped, and a younger one is kept**
    /// (`TASK-a-copy-a-vault-holds-that-never-clears-is-held-for-ever-and-can-stop-the-pickup`).
    /// Both are handed out at the first pickup — the old one too — and the
    /// device acknowledges neither, as it does a copy it answers *not yet*. At
    /// the next pickup the one past the week is gone and the one inside it is
    /// handed out again, until its own week is out.
    #[tokio::test]
    async fn a_copy_handed_out_and_not_taken_within_a_week_is_dropped_and_a_younger_one_is_kept() {
        let now = 1_000 * HELD_FOR_SECS;
        let db = holding(&[]).await;
        hold_at(&db, &sealed_of(0, 100), now - HELD_FOR_SECS - 60).await;
        hold_at(&db, &sealed_of(1, 100), now - HELD_FOR_SECS + 3_600).await;

        assert_eq!(ids(take_at(&db, "bob", vec![], now).await), ["eph-0", "eph-1"], "the first pickup hands out both");
        assert_eq!(
            ids(take_at(&db, "bob", vec![], now + 60).await),
            ["eph-1"],
            "a copy handed out and held past its week is handed out again"
        );
        assert_eq!(held_ids(&db).await, ["eph-1"]);

        assert_eq!(ids(take_at(&db, "bob", vec![], now + 3_600).await), ["eph-1"], "inside its week, still held");
        assert!(ids(take_at(&db, "bob", vec![], now + 3_660).await).is_empty());
        assert!(held_ids(&db).await.is_empty(), "past its week, dropped");
    }

    /// **Nothing is dropped before a pickup has handed it out.** A copy that
    /// waited a month for a sleeping device is handed out on the first pickup
    /// that reaches it; one behind an answer that is full is not reached, so it
    /// is kept, however old, until an ask hands it out — here the ask after
    /// the stuck one at the head has gone.
    #[tokio::test]
    async fn a_copy_past_its_week_is_handed_out_before_it_is_dropped() {
        let now = 1_000 * HELD_FOR_SECS;
        let month = 30 * 24 * 60 * 60;
        let db = holding(&[]).await;
        // A share near the inline cap at the head: an answer of its own.
        hold_at(&db, &sealed_of(0, 8_900_000), now - month - 2).await;
        hold_at(&db, &sealed_of(1, 100), now - month - 1).await;

        assert_eq!(ids(take_at(&db, "bob", vec![], now).await), ["eph-0"], "a month old, and handed out");
        assert_eq!(
            ids(take_at(&db, "bob", vec![], now + 1).await),
            ["eph-1"],
            "the one the first answer did not reach is handed out, not dropped"
        );
        assert!(ids(take_at(&db, "bob", vec![], now + 2).await).is_empty());
    }

    /// A table from before the bound gains `handed_out` in place, and its rows
    /// read as never handed out: an upgraded vault hands each out before it
    /// can drop it.
    #[tokio::test]
    async fn a_table_from_before_the_bound_hands_every_row_out_before_dropping_it() {
        let now = 1_000 * HELD_FOR_SECS;
        let db = Arc::new(SqlitePool::connect("sqlite::memory:").await.expect("db"));
        sqlx::query(
            "CREATE TABLE held_deliveries (user_id TEXT NOT NULL, handle_did TEXT NOT NULL, \
             ephemeral_pub TEXT NOT NULL, sealed TEXT NOT NULL, received_at INTEGER NOT NULL, \
             PRIMARY KEY (user_id, ephemeral_pub))",
        )
        .execute(db.as_ref())
        .await
        .expect("an old table");
        hold_at(&db, &sealed_of(0, 100), now - 2 * HELD_FOR_SECS).await;
        init(&db).await.expect("tables");
        init(&db).await.expect("and again, changing nothing");

        assert_eq!(ids(take_at(&db, "bob", vec![], now).await), ["eph-0"]);
        assert!(ids(take_at(&db, "bob", vec![], now + 1).await).is_empty());
    }

    /// A held row that will not parse is not in the answer, so it does not
    /// count toward the answer's size: the deliveries behind it come back as
    /// many to an answer as they would without it.
    #[tokio::test]
    async fn a_row_that_will_not_parse_does_not_shorten_a_pickup() {
        let two_mib = 2 * 1024 * 1024;
        let db = holding(&[sealed_of(1, two_mib), sealed_of(2, two_mib)]).await;
        sqlx::query(
            "INSERT INTO held_deliveries (user_id, handle_did, ephemeral_pub, sealed, received_at) \
             VALUES ('bob', 'did:key:door', 'eph-junk', ?, -1)",
        )
        .bind("x".repeat(5 * 1024 * 1024))
        .execute(db.as_ref())
        .await
        .expect("a row the vault cannot read back");
        let UserResponse::Deliveries { items } = take(&db, "bob", vec![]).await else { panic!() };
        assert_eq!(
            items.iter().map(|i| i.sealed.ephemeral_pub.as_str()).collect::<Vec<_>>(),
            ["eph-1", "eph-2"],
            "an unreadable row took up room in the answer"
        );
    }
}
