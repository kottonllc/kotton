// SPDX-License-Identifier: AGPL-3.0-or-later
//! Handing a person's doors to their vault, and taking what it held.
//!
//! For each resident user with a drive recorded on this device
//! (`kotton_peer::daemon::drives`), at the vault it is reached through: derive the
//! pair handle for every contact and every epoch of the window ahead, hand
//! them over with `HoldDoors`, then `TakeDeliveries` — open each, prove who
//! wrote it against the contact's identity key, file it, and acknowledge. Runs
//! at start, whenever a pairing changes the contact set, and on a timer, so the
//! window stays topped up and a message that waited is read soon after a
//! device wakes.
//!
//! Then `CarryFrame`: what the person's outbox holds, each message's own
//! sealed bytes with the pair's doors for the window, so the vault tries them
//! at the recipient's door while no device of this person's is awake, and
//! keeps the signature that comes back — sealed to this person — for the next
//! pickup here: a message stays in the outbox until one of the recipient's
//! devices signs for it. Handed after the pickup, so a message signed for while this
//! device slept leaves the outbox before the set is handed again. A pass asks
//! the vault what it carries, names what the outbox no longer holds, and hands
//! what is new in frames of at most [`CARRY_FRAME_BYTES`] past the first entry
//! — so an outbox of shares near the inline cap is carried a frame at a time,
//! where handed whole it would be carried by no vault at all.
//!
//! The vault is told nothing about which contact a door belongs to, and holds
//! nothing that opens: the seeds are handles, and the signature inside the seal
//! is the person's own key, which never leaves here.

use crate::agent::message_host::DaemonMessageHost;
use crate::residency::{RecordStores, UserRegistry};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use kotton_device::DeviceRuntime;
use kotton_msg::daemon::delivery;
use kotton_peer::daemon::nodes::load_signing_key;
use kotton_peer::membership::Membership as _;
use kotton_peer::rendezvous;
use kotton_schemas::membership::Role;
use kotton_wire::ipc::{CarriedMessage, Carrying, HeldDoor, UserRequest, UserResponse};
use sqlx::SqlitePool;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

/// How far ahead a device hands its vault doors: a week, at the current epoch
/// length. A person whose every device sleeps longer is unreachable by each
/// contact until one wakes — a floor named rather than hidden.
pub const WINDOW_EPOCHS: u64 = 24 * 7;

/// How many bytes of carried messages one `CarryFrame` request hands, past
/// its first: the request travels as one frame, and the peer frame is 10 MiB in
/// both directions (`QuicPeerChannel::MAX_RESPONSE_BYTES` for an answer, the
/// transport's `MAX_MESSAGE_SIZE` for a request the vault reads).
///
/// The first entry of a frame goes whatever its size, as
/// `kvaultd::doors::take`'s first delivery does, so nothing in the outbox is
/// stuck behind this bound. The largest first entry is a share at
/// `kotton_msg::share::INLINE_MAX` — five MiB of plaintext, which seals to a
/// little under nine — with a week of doors (about 20 kB); the rest of the
/// frame is the drop list (at most `CARRY_CAP` ids of 44 characters, under 50
/// kB) and the request's own few dozen bytes. So a frame past its first entry
/// holds at most this many bytes, and two near-cap shares never share one: six
/// MiB, the bound the pickup's answer already uses, leaves every frame of small
/// messages under ten with room for the drop list, and sends a lone share by
/// itself, as it does each full range of a share above the inline cap (about
/// seven MiB sealed, so never two to a frame). A message larger than the frame (none
/// is built today: a share above the inline cap streams) goes alone and fails
/// alone, never taking another message with it.
pub const CARRY_FRAME_BYTES: usize = 6 * 1024 * 1024;

/// How many `CarryFrame` requests one pass hands a vault. At most a little
/// over half a gigabyte a pass with every frame full of shares; what is left is
/// handed on the next pass, which asks the vault again what it carries.
pub const CARRY_FRAMES_PER_PASS: usize = 64;

/// How near the end of its window a carried message is handed again: six days.
///
/// A message's doors reach [`WINDOW_EPOCHS`] (a week) past the pass that
/// handed them, and the vault answers each carried message with the last epoch
/// they reach. A pass hands again every message whose window ends within this
/// many epochs, with a fresh week of doors — so an awake device re-hands each
/// carried message **once a day** (a week less these six days), about 1,440
/// times fewer than re-handing every message on every pass, once a minute. A
/// re-hand is the message as it was first handed, its sealed
/// bytes and a week of doors: about 20 kB of doors a day for every message,
/// and for a share near the inline cap its nine MiB as well — for each range
/// of a streamed share, its seven (handing the doors alone is not built).
///
/// **The floor.** Whenever a device passes, every message the vault carries
/// is covered **at least six days** past that pass, and a full week past it
/// when that pass is the one that re-handed it; the every-pass shape gave a
/// week always. The day given up is the price of not sending a week of doors
/// every minute. The floor and the rate move together: a larger value raises
/// the floor and re-hands more often, and [`WINDOW_EPOCHS`] (168) is the
/// every-pass shape again.
pub const EXTEND_WITHIN_EPOCHS: u64 = 144;

/// How often the window is topped up and the vault asked what it holds.
/// `KOTTON_VAULT_PICKUP_SECS` overrides it, so a test need not wait a minute
/// to see a message that waited.
fn pickup_interval() -> Duration {
    std::env::var("KOTTON_VAULT_PICKUP_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(60))
}

pub fn spawn(
    runtime: Arc<DeviceRuntime>,
    db: Arc<SqlitePool>,
    users: UserRegistry,
    record_stores: RecordStores,
) {
    tokio::spawn(async move {
        loop {
            sync_once(&runtime, &db, &users, &record_stores).await;
            tokio::time::sleep(pickup_interval()).await;
        }
    });
}

/// One pass: every user, every vault of theirs.
pub async fn sync_once(
    runtime: &Arc<DeviceRuntime>,
    db: &Arc<SqlitePool>,
    users: &UserRegistry,
    record_stores: &RecordStores,
) {
    for (user_id, store) in users.all() {
        // The nodes the person's drives are reached through, as the drive
        // record names them (`kotton_peer::daemon::drives`).
        let vaults = match kotton_peer::daemon::drives::nodes(db, &user_id).await {
            Ok(v) if !v.is_empty() => v,
            // Nothing rented. The ordinary case, and the only one of the four
            // exits below that is not a fault.
            Ok(_) => continue,
            Err(e) => {
                tracing::warn!(user_id, error = %e, "cannot read which nodes this person rents; no doors are held for them this pass");
                continue;
            }
        };
        let own_identity = match load_signing_key(&user_id, runtime.secrets()) {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!(user_id, error = %e, "this identity's key is unavailable, so its doors cannot be derived");
                continue;
            }
        };
        let host = DaemonMessageHost {
            runtime: runtime.as_ref(),
            users,
            record_stores,
        };
        // The people this person shares a channel with and never paired with:
        // the vault holds their pair's doors too, so a co-member's copy waits
        // there while every device sleeps, and carries this person's copies to
        // them. Unreadable rosters hand only the contacts' doors.
        let co = match kotton_msg::daemon::messages::co_members(&host, &user_id).await {
            Ok(co) => co.into_iter().map(|c| (c.did, c.key)).collect::<Vec<_>>(),
            Err(e) => {
                tracing::warn!(user_id, error = %e, "the channels this person is in are unreadable; the vault is handed no co-member's door");
                Vec::new()
            }
        };
        let co_keys: Vec<[u8; 32]> = co.iter().map(|(_, k)| *k).collect();
        let doors = match doors_for(&store, &own_identity, &co_keys).await {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(user_id, error = %e, "membership is unreadable, so no door can be derived for any contact");
                continue;
            }
        };
        // A door is per contact. No contacts means nothing to hold, and a vault
        // holding nothing is indistinguishable from no vault at all — which is
        // the confusion this whole function is easy to have about itself.
        if doors.is_empty() {
            tracing::warn!(
                user_id,
                vaults = vaults.len(),
                "this person rents a node and knows nobody, so it is handed no doors"
            );
        }
        for vault in vaults {
            let label = vault.id.clone();
            // The address the dial will use, kept because the node is moved into
            // it. A vault that cannot be reached is almost always a vault at the
            // wrong address, and the log line that does not say which address was
            // tried sends the reader to the code instead of to `peer list`.
            let tried = vault
                .addresses
                .first()
                .map(|a| a.to_string())
                .unwrap_or_else(|| "— no address recorded —".to_string());
            let conn = match runtime.dialer().connect(vault, &user_id).await {
                Ok(c) => c,
                Err(e) => {
                    // **`warn!`, not `debug!`.** A rented node that cannot be
                    // dialled holds no doors, so every message sent to this
                    // person while their devices sleep waits at the sender's
                    // home — and the sender is told *waiting at home*, which is
                    // the same thing they would be told if nothing were rented
                    // at all. Those are opposite facts about whether this
                    // person's messages arrive, so they differ here, in a
                    // warning, and not only in a `debug!` line and a sqlite
                    // table nobody reads.
                    tracing::warn!(user_id, vault = %label, addr = %tried, error = %e, "the node this person rents cannot be reached; it is holding no doors, so nothing will reach them while they sleep");
                    continue;
                }
            };
            match conn
                .send(&UserRequest::HoldDoors {
                    user_id: user_id.clone(),
                    doors: doors.clone(),
                })
                .await
            {
                // `held == 0` is a successful hand-off of nothing, which is
                // the shape that reads as working and is not. Said out loud,
                // because it is what an empty `held_doors` table looks like
                // from this side.
                Ok(UserResponse::DoorsHeld { held: 0, .. }) => {
                    tracing::warn!(user_id, vault = %label, "the vault accepted the hand-off and holds zero doors");
                }
                Ok(UserResponse::DoorsHeld {
                    held,
                    through_epoch,
                }) => {
                    tracing::debug!(user_id, vault = %label, held, through_epoch, "vault holds the doors");
                }
                Ok(other) => {
                    tracing::warn!(user_id, vault = %label, ?other, "vault refused the doors")
                }
                Err(e) => {
                    tracing::warn!(user_id, vault = %label, error = %e, "handing doors over failed")
                }
            }
            // Take what waited. Acknowledge only what was filed or was already
            // here; a message this node could not open or prove stays held, and
            // is logged, rather than being dropped on the vault's word.
            let mut ack: Vec<String> = Vec::new();
            for _round in 0..8 {
                let items = match conn
                    .send(&UserRequest::TakeDeliveries {
                        user_id: user_id.clone(),
                        ack: std::mem::take(&mut ack),
                    })
                    .await
                {
                    Ok(UserResponse::Deliveries { items }) => items,
                    Ok(other) => {
                        tracing::warn!(user_id, vault = %label, ?other, "vault answered the pickup oddly");
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(user_id, vault = %label, error = %e, "pickup failed");
                        break;
                    }
                };
                if items.is_empty() {
                    break;
                }
                let mut stuck = 0usize;
                for item in &items {
                    match delivery::file_from_vault(&host, &user_id, item).await {
                        Ok(stored) => {
                            if stored {
                                tracing::info!(
                                    user_id,
                                    "a message that waited at the vault is filed"
                                );
                            }
                            ack.push(item.sealed.ephemeral_pub.clone());
                        }
                        Err(e) => {
                            stuck += 1;
                            tracing::warn!(user_id, error = %e, "a held message could not be filed; it stays held");
                        }
                    }
                }
                if ack.is_empty() || stuck == items.len() {
                    break;
                }
            }
            if !ack.is_empty() {
                let _ = conn
                    .send(&UserRequest::TakeDeliveries {
                        user_id: user_id.clone(),
                        ack,
                    })
                    .await;
            }
            // What the outbox holds now, for the vault to carry. An outbox that
            // cannot be read hands nothing — never an empty outbox, which would
            // tell the vault to drop what is still waiting.
            let messages = match carried_for(&store, &own_identity, &co).await {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!(user_id, error = %e, "the outbox is unreadable, so the vault is not handed it this pass");
                    continue;
                }
            };
            // What the vault carries now, read fresh each pass rather than
            // remembered from the last: the vault drops a message itself once
            // it is signed for or its doors have passed, and only it knows.
            // Handing nothing and naming nothing is the readout.
            let (carrying, mut room) = match conn
                .send(&UserRequest::CarryFrame {
                    user_id: user_id.clone(),
                    messages: vec![],
                    drop: vec![],
                })
                .await
            {
                Ok(UserResponse::FrameCarried { carrying, room, .. }) => (carrying, room as usize),
                Ok(other) => {
                    tracing::warn!(user_id, vault = %label, ?other, "vault would not say what it carries; the outbox is not handed this pass");
                    continue;
                }
                Err(e) => {
                    tracing::warn!(user_id, vault = %label, error = %e, "asking the vault what it carries failed");
                    continue;
                }
            };
            let already: HashSet<String> = carrying.iter().map(|c| c.ephemeral_pub.clone()).collect();
            let now_epoch = kotton_crypto::epoch_at(rendezvous::unix_now());
            let (mut drop, add) = difference(carrying, messages, now_epoch);
            // Only what the vault has room for, counted after what this pass
            // names for dropping: what does not fit waits in the outbox and is
            // not handed, where handed it would be refused whole every pass.
            let add = within_room(add, &already, room.saturating_add(drop.len()));
            let mut frames = frames(add).into_iter();
            for _frame in 0..CARRY_FRAMES_PER_PASS {
                let messages = frames.next().unwrap_or_default();
                if messages.is_empty() && drop.is_empty() {
                    break;
                }
                // Room is read again after every frame, so another device of
                // this person's handing the same vault at once is seen here,
                // and the rest of the pass waits rather than being refused.
                let new = messages.iter().filter(|m| !already.contains(&m.sealed.ephemeral_pub)).count();
                if new > room.saturating_add(drop.len()) {
                    tracing::info!(user_id, vault = %label, room, "the vault has no room for the rest of the outbox; it waits for signatures to free some");
                    break;
                }
                let handed = messages.len();
                match conn
                    .send(&UserRequest::CarryFrame {
                        user_id: user_id.clone(),
                        messages,
                        drop: std::mem::take(&mut drop),
                    })
                    .await
                {
                    Ok(UserResponse::FrameCarried { carried, room: left, .. }) => {
                        room = left as usize;
                        tracing::debug!(user_id, vault = %label, handed, carried, room, "vault carries a frame of the outbox");
                    }
                    // A frame refused is that frame's, and the vault is asked
                    // its room again: refused for room — another device took
                    // it — the check above ends the pass at the next frame; for
                    // anything else, the next frame is still handed, so a
                    // message the vault will not take never keeps the rest
                    // from it. Either way the next pass tries it again.
                    Ok(other) => {
                        tracing::warn!(user_id, vault = %label, handed, ?other, "vault refused to carry a frame of the outbox");
                        match conn
                            .send(&UserRequest::CarryFrame { user_id: user_id.clone(), messages: vec![], drop: vec![] })
                            .await
                        {
                            Ok(UserResponse::FrameCarried { room: left, .. }) => room = left as usize,
                            _ => break,
                        }
                    }
                    Err(e) => {
                        tracing::warn!(user_id, vault = %label, handed, error = %e, "handing a frame of the outbox over failed")
                    }
                }
            }
            let left = frames.len();
            if left > 0 {
                tracing::info!(user_id, vault = %label, frames = left, "more of the outbox than one pass hands; the rest goes on the next");
            }
        }
    }
}

/// Every message in this person's outbox, as the vault carries it: the sealed
/// bytes the outbox sends every try, and the pair's doors for the window — the
/// same keys [`doors_for`] hands for this person's inbox, since the sender's
/// handle for a pair is the door their contact's messages arrive at.
///
/// A message to someone who is no longer a contact is not carried; the outbox
/// keeps it, and says so to whoever reads it. A copy to a **co-member** —
/// somebody this person shares a channel with and never paired with, `co` —
/// is carried with the doors the roster's key derives, one window per key the
/// rosters carry for them.
///
/// **A share's ranges are carried as any message is**, so a sender's vault
/// carries them while no device of the sender's is awake.
/// Each is a direct message of its own, sealed to the recipient and signed by
/// this person, so the vault holds it as it holds the rest — bytes it cannot
/// open, under the pair's handles — and tries it at the recipient's door until
/// a device of theirs signs for it; the signature comes back sealed to this
/// person and is taken at the next pickup here, where the outbox takes the
/// range out as it does one signed for at the door. So a share sent from a
/// device that then sleeps is filed whole on the recipient's node all the
/// same. A range is about seven MiB sealed and goes in a frame of its own
/// ([`frames`]): as one request, two ranges would make a request no vault
/// could read.
///
/// **Every message before any range**, as the outbox's own retry orders them,
/// and the vault dials in the order it was handed: a range is kept only for a
/// share whose manifest the recipient's node holds, and one that arrives first
/// is refused as something that may clear — tried again, never lost, but
/// seven MiB sent for nothing. It also means a text message takes the vault's
/// room before a share's bytes do, within what one pass hands
/// ([`within_room`]); once the vault is full from earlier passes, a message
/// waits with the ranges until signatures free room.
pub async fn carried_for(
    store: &kotton_store::runtime::user::UserStore,
    own_identity: &ed25519_dalek::SigningKey,
    co: &[(String, [u8; 32])],
) -> anyhow::Result<Vec<CarriedMessage>> {
    use crate::agent::outbox_shelf::Outbox as _;
    let mut out = Vec::new();
    let mut entries = store.outbox_entries().await?;
    entries.sort_by_key(|e| e.part_of.is_some());
    // A window is the pair's, not the message's: derived once per contact, so
    // a share of sixty-four ranges costs one week of doors here, not 65.
    let mut windows: std::collections::HashMap<String, Vec<HeldDoor>> = std::collections::HashMap::new();
    for entry in entries {
        if !windows.contains_key(&entry.to_did) {
            let contact = store
                .read_member(&entry.to_did)
                .await?
                .filter(|m| matches!(m.role, Role::Contact));
            let keys: Vec<[u8; 32]> = match contact {
                Some(contact) => vec![contact.public_key],
                None => co.iter().filter(|(did, _)| *did == entry.to_did).map(|(_, k)| *k).collect(),
            };
            if keys.is_empty() {
                continue;
            }
            windows.insert(entry.to_did.clone(), window(own_identity, &keys));
        }
        out.push(CarriedMessage {
            sealed: entry.sealed,
            doors: windows[&entry.to_did].clone(),
        });
    }
    Ok(out)
}

/// What a pass names for the vault to drop — what it carries that the outbox
/// no longer holds — and what it hands: what the outbox holds that the vault
/// does not carry yet, and what it carries whose window ends within
/// [`EXTEND_WITHIN_EPOCHS`] of `now_epoch`, handed again with a fresh week. A
/// message carried with time to spare is not handed again: its bytes and its
/// doors went with it the first time.
pub fn difference(
    carrying: Vec<Carrying>,
    outbox: Vec<CarriedMessage>,
    now_epoch: u64,
) -> (Vec<String>, Vec<CarriedMessage>) {
    let held: HashSet<&str> = outbox.iter().map(|m| m.sealed.ephemeral_pub.as_str()).collect();
    let drop: Vec<String> = carrying
        .iter()
        .filter(|c| !held.contains(c.ephemeral_pub.as_str()))
        .map(|c| c.ephemeral_pub.clone())
        .collect();
    let extend_by = now_epoch.saturating_add(EXTEND_WITHIN_EPOCHS);
    let covered: HashSet<String> = carrying
        .into_iter()
        .filter(|c| c.through_epoch > extend_by)
        .map(|c| c.ephemeral_pub)
        .collect();
    let add = outbox.into_iter().filter(|m| !covered.contains(&m.sealed.ephemeral_pub)).collect();
    (drop, add)
}

/// What of `add` is handed when the vault has `room` for this many more
/// messages: every message it already carries — a window extended takes no
/// room — and, of the rest, the first `room` in `add`'s order, which is
/// [`carried_for`]'s: every message before any range, so a text message takes
/// room before a share's bytes do. The rest waits in the outbox for the next
/// pass, after signatures have freed room.
///
/// The vault refuses a frame that would take what
/// it carries past its cap, whole, and a pass that handed everything new would
/// hand the same refused frames — up to 63 ranges, about 450 MiB — every
/// minute.
pub fn within_room(add: Vec<CarriedMessage>, carried: &HashSet<String>, room: usize) -> Vec<CarriedMessage> {
    let mut left = room;
    add.into_iter()
        .filter(|m| {
            if carried.contains(&m.sealed.ephemeral_pub) {
                return true;
            }
            if left == 0 {
                return false;
            }
            left -= 1;
            true
        })
        .collect()
}

/// `add` cut into the frames it is handed in, in its own order: entries
/// accumulate until the next would take a frame past [`CARRY_FRAME_BYTES`],
/// and a frame's first entry goes whatever its size — as
/// `kvaultd::doors::take` answers a pickup.
pub fn frames(add: Vec<CarriedMessage>) -> Vec<Vec<CarriedMessage>> {
    let mut out: Vec<Vec<CarriedMessage>> = Vec::new();
    let mut frame: Vec<CarriedMessage> = Vec::new();
    let mut bytes = 0usize;
    for m in add {
        // As it travels: an entry that cannot be measured goes alone.
        let size = serde_json::to_vec(&m).map_or(usize::MAX, |v| v.len());
        if !frame.is_empty() && bytes.saturating_add(size) > CARRY_FRAME_BYTES {
            out.push(std::mem::take(&mut frame));
            bytes = 0;
        }
        bytes = bytes.saturating_add(size);
        frame.push(m);
    }
    if !frame.is_empty() {
        out.push(frame);
    }
    out
}

/// The window this person's vault is handed: a door per contact per epoch, or
/// an error when the contact set cannot be read.
///
/// **An error, never an empty window.** A node restarted and not yet unlocked
/// holds a store with no key, and its membership set cannot be listed. Answering
/// that with zero contacts would hand the vault an empty window — which is a
/// successful hand-off of *nobody* — and every door the vault held for this
/// person would lapse while their devices sleep. The caller skips the pass
/// instead, so what the vault holds stands until a pass that can read.
///
/// Its own function so the suite can ask it from the state a restart leaves a
/// daemon in (the suite never restarts one); `sync_once` needs a
/// rented node to reach it, and this is the part that reads the lock state.
///
/// `co_members` are the identity keys of the people this person shares a
/// channel with and never paired with, as the rosters carry them
/// (`kotton_msg::daemon::messages::co_members`): their pair's doors are handed
/// too, keyed by the pair exactly as a contact's, so a co-member's copy waits
/// at the vault while this person's devices sleep. A key that is also a
/// contact's is handed once.
pub async fn doors_for(
    store: &kotton_store::runtime::user::UserStore,
    own_identity: &ed25519_dalek::SigningKey,
    co_members: &[[u8; 32]],
) -> anyhow::Result<Vec<HeldDoor>> {
    let mut keys: Vec<[u8; 32]> = store
        .list_members()
        .await?
        .into_iter()
        .filter(|m| matches!(m.role, Role::Contact))
        .map(|m| m.public_key)
        .collect();
    for key in co_members {
        if !keys.contains(key) {
            keys.push(*key);
        }
    }
    Ok(window(own_identity, &keys))
}

/// The doors for every contact, from the previous epoch to the end of the
/// window, in the form the vault keeps.
fn window(own_identity: &ed25519_dalek::SigningKey, contacts: &[[u8; 32]]) -> Vec<HeldDoor> {
    let now = kotton_crypto::epoch_at(rendezvous::unix_now());
    let first = now.saturating_sub(1);
    let mut doors = Vec::with_capacity(contacts.len() * (WINDOW_EPOCHS as usize + 2));
    for contact in contacts {
        for epoch in first..=now + WINDOW_EPOCHS {
            match rendezvous::dm_door(own_identity, contact, epoch) {
                Ok(k) => doors.push(HeldDoor {
                    epoch,
                    seed: B64.encode(k.handle.signing_key.to_bytes()),
                    admit: B64.encode(k.admit),
                }),
                Err(e) => tracing::warn!(error = %e, "no door could be derived for a contact"),
            }
        }
    }
    doors
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use kotton_msg::envelope::{self, DmInner};
    use kotton_msg::share::{Manifest, FRAME_CAP, INLINE_MAX, MESSAGE_TYPE};

    /// A message from Alice to Bob as her outbox holds it, carried with a week
    /// of the pair's real doors: a share of `file` bytes when given, else text.
    fn outbox_entry(alice: &SigningKey, bob: &SigningKey, file: Option<usize>) -> CarriedMessage {
        let share = file.map(|n| Manifest::of_file("film.mov", &vec![7u8; n], None).unwrap());
        let inner = DmInner {
            from_did: "did:kel:alice".into(),
            to_did: "did:kel:bob".into(),
            thread_id: "t".into(),
            sent_at: 1,
            kind: if share.is_some() { MESSAGE_TYPE.into() } else { "text".into() },
            text: "the milk is in the fridge".into(),
            channel: None,
            grant: None,
            reach: None,
            ack: None,
            kel: Vec::new(),
            share,
            range: None,
        };
        let bob_pub = bob.verifying_key().to_bytes();
        CarriedMessage {
            sealed: envelope::seal(&inner, alice, &bob_pub).unwrap(),
            doors: window(alice, &[bob_pub]),
        }
    }

    /// **An outbox of two shares at the inline cap and a text message is
    /// handed to its vault in frames that each fit the peer frame**, all three
    /// handed and each once, with the largest drop list a vault can be told
    /// riding in the first, measured as the request travels. Handed whole, the
    /// request is near eighteen MiB and no vault can read it.
    #[test]
    fn two_shares_at_the_inline_cap_and_a_message_are_handed_in_frames_that_fit() {
        let (alice, bob) = (SigningKey::from_bytes(&[1; 32]), SigningKey::from_bytes(&[2; 32]));
        let outbox = vec![
            outbox_entry(&alice, &bob, Some(INLINE_MAX)),
            outbox_entry(&alice, &bob, Some(INLINE_MAX)),
            outbox_entry(&alice, &bob, None),
        ];
        let ids: Vec<String> = outbox.iter().map(|m| m.sealed.ephemeral_pub.clone()).collect();
        // What a vault holding the most it may can be told to drop: ids of the
        // same shape as the outbox's own.
        let gone: Vec<String> = (0..kvault_cap()).map(|_| ids[2].clone()).collect();

        let (drop, add) = difference(vec![], outbox, 0);
        assert!(drop.is_empty());
        let frames = frames(add);
        let mut handed: Vec<String> = Vec::new();
        for (i, frame) in frames.iter().enumerate() {
            handed.extend(frame.iter().map(|m| m.sealed.ephemeral_pub.clone()));
            let request = UserRequest::CarryFrame {
                user_id: "alice".into(),
                messages: frame.clone(),
                drop: if i == 0 { gone.clone() } else { vec![] },
            };
            let bytes = serde_json::to_vec(&request).unwrap().len();
            assert!(bytes < FRAME_CAP, "frame {i} is {bytes} bytes in a {FRAME_CAP} byte frame");
        }
        assert_eq!(handed, ids, "every message handed, once, in the outbox's order");
        assert_eq!(frames.len(), 3, "a share past the bound goes by itself, and nothing joins it");
    }

    /// A pass hands what the vault does not carry and names what the outbox no
    /// longer holds; a message carried with its window well open is not handed
    /// again.
    #[test]
    fn a_pass_hands_what_is_new_and_names_what_is_gone() {
        let (alice, bob) = (SigningKey::from_bytes(&[1; 32]), SigningKey::from_bytes(&[2; 32]));
        let (kept, new) = (outbox_entry(&alice, &bob, None), outbox_entry(&alice, &bob, None));
        let (kept_id, new_id) = (kept.sealed.ephemeral_pub.clone(), new.sealed.ephemeral_pub.clone());
        let now = 1_000;
        let carrying = vec![carried(&kept_id, now + 160), carried("signed-for", now + 160)];
        let (drop, add) = difference(carrying, vec![kept, new], now);
        assert_eq!(drop, vec!["signed-for".to_string()]);
        assert_eq!(add.iter().map(|m| m.sealed.ephemeral_pub.clone()).collect::<Vec<_>>(), vec![new_id]);
        assert!(frames(vec![]).is_empty(), "nothing new is no frame");
    }

    /// **A carried message is handed again as its window closes, and not
    /// before**: ten epochs from the end of its doors it goes again, with a
    /// fresh week; one handed this pass, its doors a week ahead, does not, so a
    /// device does not hand a week of doors for every message on every pickup.
    #[test]
    fn a_carried_message_is_handed_again_as_its_window_closes_and_not_before() {
        let (alice, bob) = (SigningKey::from_bytes(&[1; 32]), SigningKey::from_bytes(&[2; 32]));
        let (closing, open) = (outbox_entry(&alice, &bob, None), outbox_entry(&alice, &bob, None));
        let (closing_id, open_id) = (closing.sealed.ephemeral_pub.clone(), open.sealed.ephemeral_pub.clone());
        let now = kotton_crypto::epoch_at(rendezvous::unix_now());
        let carrying = vec![carried(&closing_id, now + 10), carried(&open_id, now + WINDOW_EPOCHS)];
        let (drop, add) = difference(carrying, vec![closing, open], now);
        assert!(drop.is_empty());
        assert_eq!(add.iter().map(|m| m.sealed.ephemeral_pub.clone()).collect::<Vec<_>>(), vec![closing_id]);
        let through = add[0].doors.iter().map(|d| d.epoch).max().unwrap();
        assert!(through >= now + WINDOW_EPOCHS, "handed again with a fresh week, not the old one: {through}");
    }

    /// **A share's ranges are handed to the vault as the rest of the outbox
    /// is**, every message before any range, and each full range in a frame
    /// of its own that fits the peer frame. Whatever order the outbox lists its entries in, what the
    /// vault is handed is the text message and the manifest, then the ranges,
    /// each with the pair's real week of doors: all five, not the two that are
    /// not ranges.
    #[tokio::test]
    async fn a_shares_ranges_are_handed_after_every_message_each_in_a_frame_that_fits() {
        use crate::agent::outbox_shelf::Outbox as _;
        use kotton_msg::daemon::outbox::OutboxEntry;
        use kotton_peer::membership::Membership as _;
        use kotton_schemas::membership::{Ceremony, Member};
        use kotton_store::runtime::{user::UserStore, UserKeys};

        let (alice, bob) = (SigningKey::from_bytes(&[1; 32]), SigningKey::from_bytes(&[2; 32]));
        let bob_pub = bob.verifying_key().to_bytes();
        let temp = tempfile::TempDir::new().unwrap();
        let store = UserStore::create(
            "alice",
            "did:kel:alice",
            temp.path().to_path_buf(),
            UserKeys::new(Some(kotton_crypto::derive_cek(&[7u8; 32]))),
            &kotton_store::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();
        store
            .write_member(&Member {
                did: "did:kel:bob".into(),
                public_key: bob_pub,
                role: Role::Contact,
                admitted_by: Ceremony::Pairing,
                added_at: "2026-10-08T00:00:00Z".into(),
                posture: None,
                label: None,
                reach: None,
            })
            .await
            .unwrap();

        // A share of two full ranges and a short one, as `send_share` keeps it.
        let film: Vec<u8> = (0..2 * kotton_msg::share::RANGE_LEN + 12_345).map(|i| (i % 251) as u8).collect();
        let manifest = outbox_entry(&alice, &bob, Some(INLINE_MAX)).sealed;
        let digest = kotton_msg::share::digest_of(&film);
        let ranges: Vec<_> = kotton_msg::share::ranges(&digest, &manifest.ephemeral_pub, &film)
            .into_iter()
            .map(|range| {
                let inner = DmInner {
                    from_did: "did:kel:alice".into(),
                    to_did: "did:kel:bob".into(),
                    thread_id: "t".into(),
                    sent_at: 1,
                    kind: MESSAGE_TYPE.into(),
                    text: String::new(),
                    channel: None,
                    grant: None,
                    reach: None,
                    ack: None,
                    kel: Vec::new(),
                    share: None,
                    range: Some(range),
                };
                envelope::seal(&inner, &alice, &bob_pub).unwrap()
            })
            .collect();
        let text = outbox_entry(&alice, &bob, None).sealed;
        let kept = |key: &str, sealed: &kotton_wire::ipc::SealedDm, part_of: Option<String>| OutboxEntry {
            id: key.into(),
            to_did: "did:kel:bob".into(),
            record_id: "1".into(),
            sealed: sealed.clone(),
            queued_at: 1,
            attempts: 0,
            next_at: 1,
            carried: false,
            part_of,
            channel_did: None,
        };
        // The ranges kept first; the outbox lists its entries in no order of
        // its own, so what is handed is ordered here or not at all.
        for (i, range) in ranges.iter().enumerate() {
            store.keep_outbox_entry(&kept(&format!("a{i}"), range, Some(manifest.ephemeral_pub.clone()))).await.unwrap();
        }
        store.keep_outbox_entry(&kept("y", &text, None)).await.unwrap();
        store.keep_outbox_entry(&kept("z", &manifest, None)).await.unwrap();

        let handed = carried_for(&store, &alice, &[]).await.unwrap();
        let ids: Vec<String> = handed.iter().map(|m| m.sealed.ephemeral_pub.clone()).collect();
        let ranges: Vec<String> = ranges.iter().map(|r| r.ephemeral_pub.clone()).collect();
        assert_eq!(ids.len(), 5, "the vault is handed every range, the share and the message: {ids:?}");
        assert_eq!(ids[..2], [text.ephemeral_pub.clone(), manifest.ephemeral_pub.clone()], "every message first");
        // In any order among themselves: once the manifest waits, a range is
        // kept wherever it falls in its stream.
        let mut after: Vec<String> = ids[2..].to_vec();
        let mut expected = ranges.clone();
        after.sort();
        expected.sort();
        assert_eq!(after, expected, "then the ranges");
        let week = window(&alice, &[bob_pub]);
        assert!(handed.iter().all(|m| m.doors == week), "each with the pair's week of doors");

        let frames = frames(difference(vec![], handed, 0).1);
        let mut in_frames = Vec::new();
        for (i, frame) in frames.iter().enumerate() {
            in_frames.extend(frame.iter().map(|m| m.sealed.ephemeral_pub.clone()));
            let request = UserRequest::CarryFrame { user_id: "alice".into(), messages: frame.clone(), drop: vec![] };
            let bytes = serde_json::to_vec(&request).unwrap().len();
            assert!(bytes < FRAME_CAP, "frame {i} is {bytes} bytes in a {FRAME_CAP} byte frame");
        }
        assert_eq!(in_frames, ids, "every one handed, once, in that order");
        for full in &ranges[..2] {
            let alone = frames.iter().find(|f| f.iter().any(|m| m.sealed.ephemeral_pub == *full)).unwrap();
            assert_eq!(alone.len(), 1, "a full range goes in a frame of its own");
        }
    }

    /// **A vault with room for two more is handed two new messages and no
    /// more** — the text message and one range, in [`carried_for`]'s order —
    /// while a message it already carries is handed again to extend its window
    /// however full it is: an extension takes no room. Handed everything new,
    /// as until this was found on review, the vault refuses the frames past
    /// its cap whole, and every pass hands them again.
    #[test]
    fn a_vault_with_room_for_two_is_handed_the_message_and_one_range_and_nothing_more() {
        let (alice, bob) = (SigningKey::from_bytes(&[1; 32]), SigningKey::from_bytes(&[2; 32]));
        // Every message before any range, as `carried_for` orders them; the
        // last is one the vault carries already, its window closing.
        let add: Vec<CarriedMessage> = (0..5).map(|_| outbox_entry(&alice, &bob, None)).collect();
        let id = |i: usize| add[i].sealed.ephemeral_pub.clone();
        let (message, first_range, extended) = (id(0), id(1), id(4));
        let already: HashSet<String> = [extended.clone()].into_iter().collect();

        let handed: Vec<String> =
            within_room(add.clone(), &already, 2).into_iter().map(|m| m.sealed.ephemeral_pub).collect();
        assert_eq!(handed, [message, first_range, extended.clone()], "two new, and the extension");

        let full: Vec<String> =
            within_room(add, &already, 0).into_iter().map(|m| m.sealed.ephemeral_pub).collect();
        assert_eq!(full, [extended], "a full vault is handed only what extends a window");
    }

    fn carried(id: &str, through_epoch: u64) -> Carrying {
        Carrying { ephemeral_pub: id.into(), through_epoch }
    }

    /// The most ids a vault can be told to drop in one request: what it carries
    /// for one person at most (`kvaultd::carry::CARRY_CAP`, which this crate
    /// does not link).
    fn kvault_cap() -> usize {
        1024
    }
}
