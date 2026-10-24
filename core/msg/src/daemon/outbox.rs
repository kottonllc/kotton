// SPDX-License-Identifier: AGPL-3.0-or-later
//! The outbox: a direct message stays in it until one of the recipient's
//! devices signs for it
//! (`TASK-a-message-stays-in-the-outbox-until-one-of-their-devices-signs-for-it`,
//! the sender half of RFC-0064's store-and-forward).
//!
//! **What *delivered* means, mechanically.** A door answering is not enough:
//! the far end of a door may be the recipient's vault, which holds the pair's
//! handle keys and nothing that opens (`DEC-0056`), and a vault holding a
//! message is not the person having it. So a message reads *delivered* only
//! when a [`DeliveryAck`] comes back that a device key in the recipient's reach
//! note signed (`kotton_crypto::delivery_ack`). Until then it stays here and is
//! tried again — *sent* while something of theirs holds it, *waiting at home*
//! while nothing does.
//!
//! **Two ways an acknowledgement comes back.** A device answering its door
//! signs for the message in the answer itself. A device that picks a message
//! up from its vault sends the acknowledgement back as a sealed envelope over
//! the sender's own door ([`ack_envelope`]); if nothing of the sender's is
//! there to take it, the sender's next try reaches the device, which finds the
//! copy it already holds, files nothing, and signs for it again. Either way a
//! message converges on *delivered* and the recipient keeps one copy.
//!
//! **One id.** A message's id is its sealed ephemeral key, fresh per message
//! (RFC-0064 MS1). A retry sends the same sealed bytes, so it carries the same
//! id and is dropped by it; the acknowledgement names it.
//!
//! **Every path at once.** A hand-over dials every way to the person the host
//! knows — each relay in their note, and this node's own — with the same
//! sealed bytes on each, so every copy is the one message and the recipient
//! drops all but the first by its id ([`dial`],
//! `TASK-a-message-reaches-them-by-every-path-at-once-and-they-keep-one-copy`).
//! The first acknowledgement that holds is the answer; nobody chooses a path,
//! and nothing a person reads names the one that worked.

use super::filing;
use super::messages::{load_user_signing_key, MessageHost};
use crate::envelope::{self, DmInner};
use kotton_wire::ipc::{ContactRequest, ContactResponse, Delivery, DeliveryAck, DeliveryReading, SealedDm};
use futures_util::stream::{FuturesUnordered, StreamExt};
use serde::{Deserialize, Serialize};

/// One way to a person's door — a relay, or the local network while this
/// device's door is open there; a connection a relay introduces joins the same
/// list when it can carry a contact's message.
///
/// Opaque to this domain, and not a string: it holds whatever the host minted
/// ([`MessageHost::contact_paths`]) and only the host reads it back
/// ([`MessageHost::deliver_on`]). A path is the host's value rather than a name
/// the host looks up, so what it carries — a relay's address, or the open door's
/// way — cannot be spelled by anything else, and the domain can neither read one
/// nor log one: its `Debug` prints nothing
/// (`TASK-a-delivery-path-is-a-string-so-the-local-network-is-checked-twice`).
/// The domain only dials them all at once, and never hands one back to a surface.
pub struct Path(Box<dyn std::any::Any + Send + Sync>);

impl Path {
    /// A path holding `way`, which only a host that can name its type reads back.
    pub fn new<W: std::any::Any + Send + Sync>(way: W) -> Self {
        Path(Box::new(way))
    }

    /// The way this path holds, if it is a `W`.
    pub fn way<W: std::any::Any>(&self) -> Option<&W> {
        self.0.downcast_ref()
    }
}

impl std::fmt::Debug for Path {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Path(..)")
    }
}

/// One direct message in the outbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxEntry {
    /// The message's id: its sealed ephemeral key, which every copy carries and
    /// the recipient drops a second copy by.
    pub id: String,
    /// Who it is for — the identity the acknowledgement must come from.
    pub to_did: String,
    /// The sender's own record for it, which the readings are keyed by.
    pub record_id: String,
    /// Exactly the bytes sent the first time. Every retry sends these again,
    /// so a retry is the same message and never a second one.
    pub sealed: SealedDm,
    pub queued_at: u64,
    /// Tries so far.
    pub attempts: u32,
    /// Unix seconds the next try is due.
    pub next_at: u64,
    /// Something of the recipient's — their vault — holds it, and no device
    /// has signed for it yet. Reads *sent*; otherwise *waiting at home*.
    pub carried: bool,
    /// Set on a **range** of a streamed share (RFC-0090's unit 4): the id of
    /// the share's manifest, the message this is part of. A range is handed
    /// over and signed for as any message is, one by one, so a stream that is
    /// cut off resumes from the first range nobody signed for and never from
    /// byte zero; but it is not a message the person sent, so it reads as
    /// nothing ([`readings`]), its signature is not kept as one ([`take_ack`]),
    /// and its manifest's signature takes every range of it out with it.
    ///
    /// Omitted when absent, so every entry kept before it reads as it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub part_of: Option<String>,
    /// Set on a **channel copy** — a member's copy of a post, of a share (its
    /// manifest and every range), or of a leave notice: the channel it is a
    /// copy for. A copy is for a member, and a member is somebody the
    /// channel's current roster names; once the roster this node holds no
    /// longer names its recipient, nobody is left to sign for it, and it is
    /// taken out ([`drop_channel_copies`],
    /// `TASK-a-channel-copy-to-a-member-who-left-is-retried-from-the-outbox-for-ever`).
    ///
    /// Omitted when absent, so every entry kept before it reads as it did —
    /// and an entry kept before it carries none, and is never taken out by a
    /// roster: it leaves as it always did, by a signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_did: Option<String>,
}

/// That a message was signed for by one of its recipient's devices — kept
/// without which device, or when. The signature was checked when it arrived;
/// which of someone's devices woke at what time is not the sender's to keep.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedFor {
    pub id: String,
    pub to_did: String,
    pub record_id: String,
}

/// How long a waiting message waits before the next try: `base` after the
/// first, doubling, never more than `cap`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retry {
    pub base_secs: u64,
    pub cap_secs: u64,
}

impl Retry {
    /// Thirty seconds, doubling to an hour. An hour is the longest a person
    /// who comes back online waits for a message someone left for them, when
    /// the sender rents no vault to carry the retrying while their devices are
    /// off (`kvaultd::carry` keeps the same schedule).
    pub const DEFAULT: Retry = Retry { base_secs: 30, cap_secs: 60 * 60 };

    /// Seconds from a try to the next, after `attempts` tries.
    pub fn after(&self, attempts: u32) -> u64 {
        let doublings = attempts.saturating_sub(1).min(16);
        self.base_secs.saturating_mul(1u64 << doublings).min(self.cap_secs.max(self.base_secs))
    }
}

/// Hand `sealed` to `contact_did` and say what became of it: *delivered* only
/// when a device of theirs signed for it and the signature holds, *sent* when
/// something of theirs took it and nothing signed, *waiting at home* when
/// nothing answered on any path or every door refused.
///
/// Every hand-over that waits on a device's signature goes through here — a
/// direct message from the outbox, a channel copy, a key-grant, a reach note —
/// so an acknowledgement is read in exactly one place, and every one of them is
/// dialled on every path ([`dial`]). The acknowledgement sent back after a
/// vault pickup calls [`dial`] directly instead: it carries no acknowledgement
/// of its own, so the first door that takes it settles it, rather than waiting
/// on every path.
///
/// **All of it is said as [`ContactRequest::CarryMessage`]**, from a device of
/// the sender's and from their vault alike (clause 3), and a device that signs
/// answers sealed to this person ([`open_ack`] reads it). Said any other way by
/// either, something at the recipient's door could tell them apart: a
/// device's hand-over from a vault's carry — which, message by message, is a
/// record of when the sender's devices were off, kept by a contact — or a
/// direct message from a channel copy, a grant or a note, which is a label the
/// recipient's vault, which opens nothing, would otherwise read on every one.
pub async fn hand_over(
    host: &dyn MessageHost,
    user_id: &str,
    contact_did: &str,
    sealed: &SealedDm,
) -> Delivery {
    hand_over_answered(host, user_id, contact_did, sealed).await.delivery()
}

/// What a hand-over came to, read whole: the [`Delivery`] a sender is told, or
/// that the contact's own card refused what it was handed as a verdict on it
/// ([`ContactResponse::Declined`]) — which handing it over again cannot change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Handed {
    /// Taken, held, or not reached by anything of theirs.
    Delivery(Delivery),
    /// Their card refused it, and nothing of theirs took it on another path.
    Declined { reason: String },
}

impl Handed {
    /// As the one [`Delivery`] a sender reads: nothing of theirs took a
    /// declined hand-over, so it is *waiting at home* like any other.
    pub fn delivery(self) -> Delivery {
        match self {
            Handed::Delivery(delivery) => delivery,
            Handed::Declined { reason } => Delivery::Unreachable { reason },
        }
    }
}

/// As [`hand_over`], keeping a card's verdict apart from not being reached —
/// for a reach note, the one thing a card refuses as a verdict
/// (`TASK-a-reach-note-a-contact-refused-is-sent-to-them-again-every-hour`).
/// What is said at the door is the same; only the reading differs.
pub async fn hand_over_answered(
    host: &dyn MessageHost,
    user_id: &str,
    contact_did: &str,
    sealed: &SealedDm,
) -> Handed {
    let request = ContactRequest::CarryMessage { sealed: sealed.clone() };
    hand_over_as(host, user_id, contact_did, &request).await
}

async fn hand_over_as(
    host: &dyn MessageHost,
    user_id: &str,
    contact_did: &str,
    request: &ContactRequest,
) -> Handed {
    let sealed = request.sealed();
    // Only a device signing settles it: a door that holds without signing —
    // a vault — is not the person having it, so the other paths are waited on.
    let settles = |ack: Option<DeliveryAck>| async move {
        let Some(ack) = ack else { return false };
        match take_ack(host, user_id, contact_did, &sealed.ephemeral_pub, &ack).await {
            Ok(_) => true,
            Err(reason) => {
                tracing::warn!(
                    user_id,
                    contact = %contact_did,
                    %reason,
                    "a door answered with an acknowledgement that does not hold; the message \
                     is held there and stays unsigned-for"
                );
                false
            }
        }
    };
    race(host, user_id, contact_did, request, settles).await
}

/// Dial every path to `contact_did` at once with the same `request` — the same
/// sealed bytes on each — and
/// return as soon as a door's answer `settles` it — handed the acknowledgement
/// the answer carries, if any — as *delivered* when it carried one and *sent*
/// when not. The paths still out are dropped, and a copy of theirs that lands
/// anyway is dropped by its id and signed for again. With nothing settled,
/// wait for every path: *sent* if any door took it, *waiting at home* if none
/// did.
///
/// A path that hangs holds up nothing but itself: answers are read in the
/// order they arrive, not the order the paths were listed.
///
/// The reason a *waiting at home* carries names no path. It travels in the
/// answer to whoever sent, and which relays a person is reached at is theirs;
/// the host says per path what failed, in its own log.
pub async fn dial<F, Fut>(
    host: &dyn MessageHost,
    user_id: &str,
    contact_did: &str,
    request: &ContactRequest,
    settles: F,
) -> Delivery
where
    F: Fn(Option<DeliveryAck>) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    race(host, user_id, contact_did, request, settles).await.delivery()
}

/// [`dial`], read whole: with nothing settled and nothing held, a card that
/// declined it ([`ContactResponse::Declined`]) is [`Handed::Declined`], ahead
/// of a door that refused it or did not answer: a card that declined it has
/// opened this very note and judged it, and a door that refused or did not
/// answer has judged nothing, so neither outweighs the verdict.
async fn race<F, Fut>(
    host: &dyn MessageHost,
    user_id: &str,
    contact_did: &str,
    request: &ContactRequest,
    settles: F,
) -> Handed
where
    F: Fn(Option<DeliveryAck>) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let unreachable = |reason: String| Handed::Delivery(Delivery::Unreachable { reason });
    let paths = match host.contact_paths(user_id, contact_did).await {
        Ok(paths) if !paths.is_empty() => paths,
        Ok(_) => return unreachable("no way to reach them is known yet".to_string()),
        Err(reason) => return unreachable(reason),
    };
    let count = paths.len();
    let mut racing: FuturesUnordered<_> = paths
        .iter()
        .map(|path| host.deliver_on(user_id, contact_did, path, request))
        .collect();
    let mut held = false;
    // What their door said when it refused, which is theirs to say and names
    // no path; a transport's error may name one, and stays in the host's log.
    let mut refusals: Vec<String> = Vec::new();
    // What their card said when it declined: theirs too, and kept apart,
    // because it is the one refusal a second try cannot change.
    let mut declined: Vec<String> = Vec::new();
    let keep_once = |said: &mut Vec<String>, reason: String| {
        if !said.contains(&reason) {
            said.push(reason);
        }
    };
    while let Some(answer) = racing.next().await {
        // A signature sealed to this person answers a carried message: opened
        // here, and read exactly as one in the clear would be. One that does
        // not open, or is not an acknowledgement from them to this person, is a
        // door that took it and said nothing this node can check.
        let ack = match answer {
            Ok(ContactResponse::SignedSealed { ack, .. }) => open_ack(host, user_id, contact_did, &ack).await,
            Ok(ContactResponse::Delivered { ack, .. }) => ack,
            Ok(ContactResponse::Refused { reason }) => {
                keep_once(&mut refusals, reason);
                continue;
            }
            Ok(ContactResponse::Declined { reason }) => {
                keep_once(&mut declined, reason);
                continue;
            }
            Err(_) => continue,
        };
        let signed = ack.is_some();
        if settles(ack).await {
            return Handed::Delivery(if signed { Delivery::Delivered } else { Delivery::Sent });
        }
        held = true;
    }
    if held {
        return Handed::Delivery(Delivery::Sent);
    }
    if !declined.is_empty() {
        let reason = declined.join("; ");
        tracing::info!(
            user_id,
            contact = %contact_did,
            %reason,
            "this contact's card refused what it was handed, and would refuse it again"
        );
        return Handed::Declined { reason };
    }
    let reason = if refusals.is_empty() {
        format!("nothing of theirs answered on any of {count} ways to reach them")
    } else {
        refusals.join("; ")
    };
    tracing::warn!(
        user_id,
        contact = %contact_did,
        %reason,
        "nothing of this contact's took the message on any path, so the sender's copy waits at home"
    );
    unreachable(reason)
}

/// The acknowledgement inside `sealed`, an envelope `contact_did` sealed to
/// `user_id` in answer to a carried message — or `None` when it does not open
/// under this person's key, was not written by that contact, or carries no
/// acknowledgement. Believing what it carries is still [`take_ack`]'s.
async fn open_ack(
    host: &dyn MessageHost,
    user_id: &str,
    contact_did: &str,
    sealed: &SealedDm,
) -> Option<DeliveryAck> {
    let own_key = load_user_signing_key(user_id, host.secrets())?;
    // A card's key, or for a co-member the one a roster carries: a copy to a
    // member who never paired with this person is signed for too.
    let contact_pub = super::messages::far_key(host, user_id, contact_did).await?;
    let own = host.user_aid(user_id)?;
    let inner = envelope::open(sealed, &own_key, &contact_pub).ok()?;
    (inner.from_did == contact_did && inner.to_did == own).then_some(inner.ack).flatten()
}

/// Believe `ack` as `contact_did` signing for `message_id`, and if that message
/// is in `user_id`'s outbox, take it out and keep that it was signed for.
///
/// Believed under a device key the reach note this node holds for them lists:
/// their card's, or for a co-member a roster's (`messages::far_note`).
///
/// `Ok(true)` when this is what signed the message for; `Ok(false)` when the
/// acknowledgement holds and there was nothing in the outbox for it — already
/// signed for, or not a message the outbox holds (a channel copy, unless it is
/// the manifest of a share to a group whose bytes stream). An error
/// when it does not hold: not signed by a device the card's note for
/// `contact_did` lists, or for another message or person.
pub async fn take_ack(
    host: &dyn MessageHost,
    user_id: &str,
    contact_did: &str,
    message_id: &str,
    ack: &DeliveryAck,
) -> Result<bool, String> {
    let own = host
        .user_aid(user_id)
        .ok_or_else(|| "this identity is not available on this node".to_string())?;
    // The card's note, or — for a co-member, whom this person never paired
    // with — the one a channel's roster carries for them, signed by them.
    let note = super::messages::far_note(host, user_id, contact_did).await;
    kotton_crypto::delivery_ack::verify(ack, note.as_ref(), contact_did, &own, message_id, now_secs())?;
    let entries = host
        .outbox_entries(user_id)
        .await
        .map_err(|e| format!("could not read the outbox: {e}"))?;
    let Some(entry) = entries.iter().find(|e| e.id == message_id && e.to_did == contact_did).cloned()
    else {
        return Ok(false);
    };
    // A range of a share is not a message the person sent: its signature takes
    // it out of the outbox, so the stream is not sent again from it, and is
    // not kept as a message signed for.
    let held = filing::outbox_entry(user_id, &entry.id).await;
    if entry.part_of.is_some() {
        host.drop_outbox_entry(user_id, &entry.id)
            .await
            .map_err(|e| format!("could not take a signed-for range out of the outbox: {e}"))?;
        tracing::debug!(user_id, contact = %contact_did, "a range of a share was signed for");
        return Ok(true);
    }
    // The fact first, then the entry: a failure between the two leaves both,
    // and a reading takes signed-for over waiting.
    host.keep_signed_for(
        user_id,
        &SignedFor { id: entry.id.clone(), to_did: entry.to_did.clone(), record_id: entry.record_id.clone() },
    )
    .await
    .map_err(|e| format!("could not keep that the message was signed for: {e}"))?;
    host.drop_outbox_entry(user_id, &entry.id)
        .await
        .map_err(|e| format!("could not take a signed-for message out of the outbox: {e}"))?;
    drop(held);
    // A share signed for was filed whole, so nothing of its stream is owed:
    // a range still waiting is taken out with it, each under its own lock.
    for part in entries.iter().filter(|e| e.part_of.as_deref() == Some(entry.id.as_str())) {
        let _part = filing::outbox_entry(user_id, &part.id).await;
        if let Err(e) = host.drop_outbox_entry(user_id, &part.id).await {
            tracing::info!(user_id, error = %e, "a range of a share signed for stays in the outbox");
        }
    }
    tracing::debug!(user_id, contact = %contact_did, "a message was signed for");
    Ok(true)
}

/// A fresh outbox entry for `sealed`, a message to `to_did` whose sender's own
/// record is `record_id` — a copy for `channel_did`, when it is one: untried,
/// and due now.
pub fn new_entry(to_did: &str, record_id: &str, sealed: &SealedDm, channel_did: Option<&str>) -> OutboxEntry {
    let now = now_secs();
    OutboxEntry {
        id: sealed.ephemeral_pub.clone(),
        to_did: to_did.to_string(),
        record_id: record_id.to_string(),
        sealed: sealed.clone(),
        queued_at: now,
        attempts: 0,
        next_at: now,
        carried: false,
        part_of: None,
        channel_did: channel_did.map(str::to_owned),
    }
}

/// Put a sealed direct message in `user_id`'s outbox and make the first try —
/// a member's copy of a message to `channel_did`, when it is one.
///
/// Kept **before** the first try, so a node that stops mid-send still holds
/// it. A message that cannot be kept is still tried once, and the failure is
/// said: it is then a message nothing will try again.
pub async fn send(
    host: &dyn MessageHost,
    user_id: &str,
    to_did: &str,
    record_id: &str,
    sealed: &SealedDm,
    channel_did: Option<&str>,
    retry: Retry,
) -> Delivery {
    let entry = new_entry(to_did, record_id, sealed, channel_did);
    if let Err(e) = host.keep_outbox_entry(user_id, &entry).await {
        tracing::warn!(user_id, error = %e, "a message could not be kept in the outbox; it is tried once and not again");
    }
    attempt(host, user_id, entry, retry).await
}

/// The shares whose first send is still handing their pieces, by person and
/// manifest id. Process-wide, as what it guards is: this node's keeper and a
/// send on it both read one person's outbox.
static SENDING: std::sync::Mutex<Vec<(String, String)>> = std::sync::Mutex::new(Vec::new());

/// That a share's first send is handing it ([`send_share`]), until dropped —
/// so the outbox keeper ([`retry_due`]) leaves it alone, and only what that
/// send did not settle is the keeper's afterwards. Dropped with the send,
/// however it ends, a cancelled one included.
struct Sending {
    key: (String, String),
}

impl Sending {
    fn mark(user_id: &str, manifest: &str) -> Self {
        let key = (user_id.to_string(), manifest.to_string());
        SENDING.lock().unwrap_or_else(|p| p.into_inner()).push(key.clone());
        Self { key }
    }

    /// Whether the share whose manifest is `manifest` is being sent now.
    fn is(user_id: &str, manifest: &str) -> bool {
        SENDING.lock().unwrap_or_else(|p| p.into_inner()).iter().any(|(u, m)| u == user_id && m == manifest)
    }
}

impl Drop for Sending {
    fn drop(&mut self) {
        let mut sending = SENDING.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(i) = sending.iter().position(|k| *k == self.key) {
            sending.swap_remove(i);
        }
    }
}

/// Put a share whose bytes stream in `user_id`'s outbox — its sealed
/// `manifest` and every one of its sealed `ranges` — and make the first try
/// (RFC-0090, *Delivery › Above the frame cap*).
///
/// **Kept whole before anything is tried**, as [`send`] keeps a message, so a
/// node that stops mid-stream still holds every range nobody has signed for,
/// and its next pass resumes from those. Then the manifest goes first: the
/// recipient's node keeps it waiting for its bytes, and files nothing. The
/// ranges follow in order, each signed for and taken out of the outbox as it
/// lands, so what is cut off resumes where it stopped. A range nothing of
/// theirs took ends the try — the rest wait in the outbox for the next pass,
/// rather than travelling to nobody. Last, the manifest again: with its bytes
/// whole on the recipient's node it is filed and signed for, and that is the
/// share's one word.
///
/// Every piece is said as every message is ([`hand_over`]): a
/// [`ContactRequest::CarryMessage`] of sealed bytes, so nothing at their door
/// can tell a range from a message.
///
/// A member's copy of a share to `channel_did` carries the channel on every
/// piece, the manifest and each range, so a roster that no longer names them
/// takes the whole of it out ([`drop_channel_copies`]).
#[allow(clippy::too_many_arguments)]
pub async fn send_share(
    host: &dyn MessageHost,
    user_id: &str,
    to_did: &str,
    record_id: &str,
    manifest: &SealedDm,
    ranges: &[SealedDm],
    channel_did: Option<&str>,
    retry: Retry,
) -> Delivery {
    let now = now_secs();
    let entry = |sealed: &SealedDm, part_of: Option<String>| OutboxEntry {
        id: sealed.ephemeral_pub.clone(),
        to_did: to_did.to_string(),
        record_id: record_id.to_string(),
        sealed: sealed.clone(),
        queued_at: now,
        attempts: 0,
        next_at: now,
        carried: false,
        part_of,
        channel_did: channel_did.map(str::to_owned),
    };
    let first = entry(manifest, None);
    let parts: Vec<OutboxEntry> =
        ranges.iter().map(|r| entry(r, Some(manifest.ephemeral_pub.clone()))).collect();
    // The keeper passes over this share until this send has handed what it
    // will: kept with `next_at` now, its pieces are due, and a pass would hand
    // the same ranges beside this one.
    let _sending = Sending::mark(user_id, &manifest.ephemeral_pub);
    if let Err(e) = host.keep_outbox_entry(user_id, &first).await {
        tracing::warn!(user_id, error = %e, "a share could not be kept in the outbox; it is tried once and not again");
    }
    for part in &parts {
        // A range not kept could not be told signed for from never kept, so
        // nothing of the stream is handed until the outbox holds all of it.
        if let Err(e) = host.keep_outbox_entry(user_id, part).await {
            tracing::warn!(user_id, error = %e, "a share's bytes could not be kept in the outbox, so none of them is handed");
            return attempt(host, user_id, first, retry).await;
        }
    }
    let said = attempt(host, user_id, first, retry).await;
    if said == Delivery::Delivered {
        return said;
    }
    for part in parts {
        if let Delivery::Unreachable { .. } = attempt(host, user_id, part, retry).await {
            return said;
        }
    }
    // The manifest as the outbox now holds it — the first try changed its
    // count and its next time — or, when something took it out meanwhile,
    // signed for already.
    match host.outbox_entries(user_id).await {
        Ok(entries) => match entries.into_iter().find(|e| e.id == manifest.ephemeral_pub) {
            Some(now_held) => attempt(host, user_id, now_held, retry).await,
            None => Delivery::Delivered,
        },
        Err(e) => {
            tracing::info!(user_id, error = %e, "the outbox could not be read after a share's ranges; its manifest is tried on the next pass");
            said
        }
    }
}

/// Try one outbox entry once, and keep what the try learned.
pub async fn attempt(
    host: &dyn MessageHost,
    user_id: &str,
    mut entry: OutboxEntry,
    retry: Retry,
) -> Delivery {
    let delivery = hand_over(host, user_id, &entry.to_did, &entry.sealed).await;
    if delivery == Delivery::Delivered {
        // `take_ack` took it out of the outbox.
        return delivery;
    }
    // An acknowledgement that came back another way while this try was out
    // has already taken the entry out; writing it back would retry a message
    // that is signed for. The question and the write-back are one step for
    // the entry, so a signature taking it out cannot land between them.
    let _entry = filing::outbox_entry(user_id, &entry.id).await;
    match host.all_signed_for(user_id).await {
        Ok(signed) if signed.iter().any(|s| s.id == entry.id) => return Delivery::Delivered,
        _ => {}
    }
    // A range is not kept as signed for — it is not a message the person
    // sent — so it is signed for when it is gone: taken out by its own
    // signature on another path, or with its share's. Every range a send
    // tries was kept first (`send_share`), so gone is never never-kept.
    //
    // A channel copy can be taken out by something other than a signature:
    // a roster that no longer names its recipient ([`drop_channel_copies`]),
    // which may land while this try is out. Written back, it would be tried
    // for ever again, so it is written back only while the outbox still holds
    // it, and otherwise answers what its door said.
    if entry.part_of.is_some() || entry.channel_did.is_some() {
        match host.outbox_entries(user_id).await {
            Ok(held) if !held.iter().any(|e| e.id == entry.id) => {
                return if entry.part_of.is_some() { Delivery::Delivered } else { delivery };
            }
            Ok(_) => {}
            Err(e) => {
                tracing::info!(user_id, error = %e, "the outbox could not be read after a try; it is not written back");
                return delivery;
            }
        }
    }
    entry.attempts = entry.attempts.saturating_add(1);
    entry.carried |= delivery == Delivery::Sent;
    entry.next_at = now_secs().saturating_add(retry.after(entry.attempts));
    if let Err(e) = host.keep_outbox_entry(user_id, &entry).await {
        tracing::warn!(user_id, error = %e, "the outbox could not keep what a try learned");
    }
    delivery
}

/// Try every entry in `user_id`'s outbox that is due at `now`. Returns how many
/// were tried.
///
/// Every message before any range; within each group the order is the outbox
/// listing's, which is undefined and differs between platforms. That is enough
/// here, because each entry is tried on its own and none depends on another's
/// having gone first but a range on its manifest, which the grouping already
/// orders. `carried_for` (kuserd's `vault_doors`) orders within each group too, by
/// `handed_order`, because the vault it hands to takes the first that fits its room.
pub async fn retry_due(host: &dyn MessageHost, user_id: &str, now: u64, retry: Retry) -> usize {
    let entries = match host.outbox_entries(user_id).await {
        Ok(e) => e,
        Err(e) => {
            tracing::info!(user_id, error = %e, "the outbox could not be read this pass");
            return 0;
        }
    };
    // Every message — a share's manifest among them — before any range, as a
    // share is first sent: a range is kept only for a share whose manifest the
    // recipient's node holds.
    // A share whose first send is still handing it is that send's.
    let mut due: Vec<OutboxEntry> = entries
        .into_iter()
        .filter(|e| e.next_at <= now && !Sending::is(user_id, e.part_of.as_deref().unwrap_or(&e.id)))
        .collect();
    due.sort_by_key(|e| e.part_of.is_some());
    let streamed: Vec<String> = due.iter().filter_map(|e| e.part_of.clone()).collect();
    let mut tried = 0;
    for entry in due {
        tried += 1;
        let delivery = attempt(host, user_id, entry, retry).await;
        tracing::debug!(user_id, word = delivery.word(), "an outbox message was tried again");
    }
    // A share whose last waiting range this pass handed is whole on their node
    // now, and filed there; its manifest, tried before its ranges, is tried
    // once more, so it is signed for this pass and not at its next turn.
    if streamed.is_empty() {
        return tried;
    }
    let Ok(left) = host.outbox_entries(user_id).await else { return tried };
    let owed = |id: &str| left.iter().any(|e| e.part_of.as_deref() == Some(id));
    for manifest in left.iter().filter(|e| streamed.contains(&e.id) && !owed(&e.id)) {
        tried += 1;
        attempt(host, user_id, manifest.clone(), retry).await;
    }
    tried
}

/// Take out of `user_id`'s outbox every copy of `channel_did` whose recipient
/// `still_in` does not name — a share's manifest and every range of it — and
/// say so in the log. Returns how many entries were taken out.
///
/// **A copy is for a member, and the roster says who one is.** A copy waits
/// until a device of its recipient's signs for it; somebody who has left the
/// channel, or been removed from it, is somebody the sender's node will not
/// hand another copy to ([`super::messages`]'s fan-out reads the same
/// roster), and a copy already waiting for them is the same copy, handed late.
/// So it goes when the roster that no longer names them reaches this node —
/// which the caller decides; this only takes out what it is told is not
/// somebody's any more (`TASK-a-channel-copy-to-a-member-who-left-is-retried-from-the-outbox-for-ever`).
///
/// An entry that carries no channel — a direct message, or a copy kept before
/// entries carried one — is never taken out here. Each is taken out under its
/// own lock, as a signature takes one out ([`take_ack`]), so a try that was
/// out meanwhile does not write it back ([`attempt`]). An outbox that cannot
/// be listed takes nothing out, and is said.
pub async fn drop_channel_copies(
    host: &dyn MessageHost,
    user_id: &str,
    channel_did: &str,
    still_in: &(dyn Fn(&str) -> bool + Sync),
) -> usize {
    let entries = match host.outbox_entries(user_id).await {
        Ok(e) => e,
        Err(e) => {
            tracing::info!(user_id, error = %e, "the outbox could not be read after a roster changed; nothing is taken out this time");
            return 0;
        }
    };
    // Every piece of a share carries its channel and its recipient
    // ([`send_share`]), so its ranges go with its manifest.
    let gone = entries
        .iter()
        .filter(|e| e.channel_did.as_deref() == Some(channel_did) && !still_in(&e.to_did))
        .map(|e| e.id.as_str());
    let mut dropped = 0;
    for id in gone {
        let _entry = filing::outbox_entry(user_id, id).await;
        match host.drop_outbox_entry(user_id, id).await {
            Ok(()) => dropped += 1,
            Err(e) => {
                tracing::info!(user_id, error = %e, "a copy for somebody no longer in the channel stays in the outbox")
            }
        }
    }
    if dropped > 0 {
        tracing::info!(
            user_id,
            channel = %channel_did,
            dropped,
            "copies waiting for people the channel's roster no longer names were taken out of the outbox"
        );
    }
    dropped
}

/// What each direct message `user_id` sent `peer_did` reads as, from the
/// outbox and what was signed for. Keyed by the sender's own record id.
pub async fn readings(
    host: &dyn MessageHost,
    user_id: &str,
    peer_did: &str,
) -> Result<Vec<DeliveryReading>, String> {
    let signed = host
        .all_signed_for(user_id)
        .await
        .map_err(|e| format!("could not read what was signed for: {e}"))?;
    let waiting = host
        .outbox_entries(user_id)
        .await
        .map_err(|e| format!("could not read the outbox: {e}"))?;
    let mut out: Vec<DeliveryReading> = signed
        .iter()
        .filter(|s| s.to_did == peer_did)
        .map(|s| DeliveryReading {
            message_id: s.record_id.clone(),
            word: Delivery::Delivered.word().to_string(),
            retry_at: None,
        })
        .collect();
    // A range of a share is not a message the person sent: the share reads as
    // its manifest does.
    for e in waiting.iter().filter(|e| e.to_did == peer_did && e.part_of.is_none()) {
        if signed.iter().any(|s| s.id == e.id) {
            continue;
        }
        let word = if e.carried {
            Delivery::Sent.word()
        } else {
            Delivery::Unreachable { reason: String::new() }.word()
        };
        out.push(DeliveryReading {
            message_id: e.record_id.clone(),
            word: word.to_string(),
            retry_at: Some(e.next_at),
        });
    }
    // The fourth word. A message to another account on this machine is filed
    // straight into their store: no carrier took it, so the outbox never held
    // it and nothing of theirs signs for it, and without this it read as
    // nothing at all once the page that sent it closed. It is *local* for as
    // long as it exists, which is what the send answered with
    // (`TASK-messages-is-the-drawn-one`).
    if host.local_user_for_did(peer_did).is_some() {
        let me = host
            .user_aid(user_id)
            .ok_or_else(|| "identity unavailable — unlock your session first".to_string())?;
        let sent = host
            .record_query(
                user_id,
                kotton_common::namespace::NSID_MESSAGE_V1,
                vec![
                    ("from_did".to_string(), serde_json::json!(me)),
                    ("to_did".to_string(), serde_json::json!(peer_did)),
                ],
                Some(super::messages::CONVERSATION_LIMIT),
                None,
                None,
            )
            .await
            .map_err(|e| format!("could not read what you sent: {e}"))?;
        for r in sent.into_iter().map(super::messages::expose_row_id) {
            let Some(id) = r.get("id").and_then(|v| v.as_str()) else {
                continue;
            };
            if !out.iter().any(|x| x.message_id == id) {
                out.push(DeliveryReading {
                    message_id: id.to_string(),
                    word: Delivery::Local.word().to_string(),
                    retry_at: None,
                });
            }
        }
    }
    Ok(out)
}

/// The envelope a device sends back to `sender_did` to sign for a message it
/// picked up somewhere other than its own door — sealed to the sender like any
/// message, so a vault holding it on the way learns nothing.
pub fn ack_envelope(
    host: &dyn MessageHost,
    user_id: &str,
    own_did: &str,
    sender_did: &str,
    sender_pub: &[u8; 32],
    message_id: &str,
) -> Result<SealedDm, String> {
    let key = load_user_signing_key(user_id, host.secrets())
        .ok_or_else(|| "this identity's key is not available on this node".to_string())?;
    let inner = DmInner {
        from_did: own_did.to_string(),
        to_did: sender_did.to_string(),
        thread_id: String::new(),
        sent_at: now_secs(),
        kind: "ack".to_string(),
        text: String::new(),
        channel: None,
        grant: None,
        reach: None,
        ack: Some(host.sign_delivery_ack(message_id, own_did, sender_did)),
        kel: Vec::new(),
        share: None,
        range: None,
    };
    envelope::seal(&inner, &key, sender_pub)
}

fn now_secs() -> u64 {
    kotton_common::time::now_secs().max(0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::delivery;
    use crate::daemon::messages::NotKept;
    use ed25519_dalek::SigningKey;
    use kotton_crypto::reach_note::{self, Kept, ReachNote};
    use kotton_sys::secret::{SecretsResult, SecretsStore};
    use kotton_wire::ipc::{ContactRequest, PendingDelivery, UserResponse};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};

    #[test]
    fn a_waiting_message_is_tried_again_sooner_first_and_never_less_than_hourly() {
        let r = Retry::DEFAULT;
        assert_eq!(r.after(1), 30);
        assert_eq!(r.after(2), 60);
        assert_eq!(r.after(3), 120);
        assert_eq!(r.after(40), 3600, "capped");
        let flat = Retry { base_secs: 2, cap_secs: 2 };
        assert_eq!((flat.after(1), flat.after(9)), (2, 2));
    }

    /// Retries due at once, so a test can drive them by hand.
    const NOW_AGAIN: Retry = Retry { base_secs: 0, cap_secs: 0 };

    struct Keychain([u8; 32]);
    impl SecretsStore for Keychain {
        fn get_secret(&self, _key: &str) -> SecretsResult<Option<String>> {
            Ok(Some(hex::encode(self.0)))
        }
        fn set_secret(&self, _key: &str, _value: &str) -> SecretsResult<()> {
            Ok(())
        }
        fn delete_secret(&self, _key: &str) -> SecretsResult<()> {
            Ok(())
        }
    }

    /// One person's node, paired with one other. `awake` is whether a device
    /// of theirs answers their door; `vault` is whether a vault of theirs
    /// answers it when none does, holding what arrives.
    struct Node {
        did: &'static str,
        identity: SigningKey,
        device: SigningKey,
        keychain: Keychain,
        /// The device key this node signs for messages with — its own, unless
        /// a test makes it sign with a key its note does not list.
        signs_with: SigningKey,
        awake: AtomicBool,
        vault: AtomicBool,
        held: Mutex<Vec<SealedDm>>,
        /// The ways the other person's door is reached from here. `door` is
        /// the one the earlier tests use; `hang` is a path that never
        /// answers; `silent` is one that fails at once, as a relay with
        /// nothing of theirs behind it does; `vault` is always their vault,
        /// which holds and never signs.
        paths: Mutex<Vec<&'static str>>,
        /// Which path carried which message id, as each dial set out.
        dialled: Mutex<Vec<(&'static str, String)>>,
        /// What each dial said at the door: handed over, or carried.
        said: Mutex<Vec<&'static str>>,
        records: Mutex<Vec<serde_json::Value>>,
        outbox: Mutex<Vec<OutboxEntry>>,
        signed: Mutex<Vec<SignedFor>>,
        peer: OnceLock<Arc<Node>>,
        /// The other person is another account on this machine.
        local_peer: AtomicBool,
        /// What this person's card says to a reach note handed to them: kept,
        /// unless a test sets why not.
        card: Mutex<Option<NotKept>>,
        /// This person's card for the other, judged by the card's own rule
        /// ([`judge_reach_note`](crate::daemon::messages::judge_reach_note)),
        /// when a test keeps one and sets no answer in `card`.
        kept: Mutex<Option<KeptCard>>,
        /// The names this person's cards show, by DID.
        card_names: Mutex<Vec<(String, String)>>,
        /// This person's Personal tree: every file, by its path from the root.
        tree: Mutex<Vec<(String, Vec<u8>)>>,
        /// This person's stream shelf, by key.
        shelf: Mutex<std::collections::BTreeMap<String, Vec<u8>>>,
        /// Every request this node said at the other person's door, as it
        /// crosses: what a relay carries inside the circuit, and a vault holds.
        frames: Mutex<Vec<String>>,
        /// How many more dials the other person's door answers before the
        /// connection drops, when a test cuts it; `None` for no cut.
        answers: Mutex<Option<usize>>,
        /// The dial, counted from one, during which this node's outbox keeper
        /// runs a pass — as a keeper on its timer does while a long send is
        /// still handing pieces.
        keeper_at: Mutex<Option<usize>>,
        /// The dial, counted from one, whose message another path hands over
        /// and has signed for first, while this path then fails.
        taken_elsewhere_at: Mutex<Option<usize>>,
        /// Cards this person holds besides the one for the other person:
        /// somebody who can reach their door and is not the one they message.
        other_cards: Mutex<Vec<(String, [u8; 32])>>,
    }

    fn node(did: &'static str, seed: u8) -> Arc<Node> {
        let device = SigningKey::from_bytes(&[seed + 100; 32]);
        Arc::new(Node {
            did,
            identity: SigningKey::from_bytes(&[seed; 32]),
            signs_with: device.clone(),
            device,
            keychain: Keychain([seed; 32]),
            awake: AtomicBool::new(true),
            vault: AtomicBool::new(false),
            held: Mutex::new(vec![]),
            paths: Mutex::new(vec!["door"]),
            dialled: Mutex::new(vec![]),
            said: Mutex::new(vec![]),
            records: Mutex::new(vec![]),
            outbox: Mutex::new(vec![]),
            signed: Mutex::new(vec![]),
            peer: OnceLock::new(),
            local_peer: AtomicBool::new(false),
            card: Mutex::new(None),
            kept: Mutex::new(None),
            card_names: Mutex::new(vec![]),
            tree: Mutex::new(vec![]),
            shelf: Mutex::new(Default::default()),
            frames: Mutex::new(vec![]),
            answers: Mutex::new(None),
            keeper_at: Mutex::new(None),
            taken_elsewhere_at: Mutex::new(None),
            other_cards: Mutex::new(vec![]),
        })
    }

    /// A card one person keeps for the other, as far as a reach note is
    /// concerned: whether it is written yet, the note it holds, and what this
    /// person's clock reads.
    struct KeptCard {
        written: bool,
        held: Option<ReachNote>,
        clock: u64,
    }

    impl KeptCard {
        fn written_at(clock: u64) -> Option<KeptCard> {
            Some(KeptCard { written: true, held: None, clock })
        }
    }

    fn pair(a: &Arc<Node>, b: &Arc<Node>) {
        a.peer.set(Arc::clone(b)).ok().unwrap();
        b.peer.set(Arc::clone(a)).ok().unwrap();
    }

    impl Node {
        fn peer(&self) -> &Arc<Node> {
            self.peer.get().unwrap()
        }
        fn public(&self) -> [u8; 32] {
            self.identity.verifying_key().to_bytes()
        }
        /// The reach note this person signed, listing their one device.
        fn note(&self) -> ReachNote {
            let device = hex::encode(self.device.verifying_key().to_bytes());
            reach_note::next(None, self.did, &[], &[device], &self.identity, now_secs()).unwrap()
        }
        fn filed(&self) -> usize {
            self.records.lock().unwrap().len()
        }
        /// This person's note at `version`, listing their one device.
        fn note_at(&self, version: u64) -> ReachNote {
            let device = hex::encode(self.device.verifying_key().to_bytes());
            let expires_at = now_secs() + reach_note::REACH_NOTE_TTL_SECS;
            reach_note::sign(self.did, vec![], vec![device], version, expires_at, &self.identity)
        }
        /// How many times this node has dialled the other person's door.
        fn handed(&self) -> usize {
            self.dialled.lock().unwrap().len()
        }
    }

    #[async_trait::async_trait]
    impl MessageHost for Node {
        fn secrets(&self) -> &(dyn SecretsStore + Send + Sync) {
            &self.keychain
        }
        fn user_aid(&self, _: &str) -> Option<String> {
            Some(self.did.to_string())
        }
        fn local_user_for_did(&self, _: &str) -> Option<String> {
            self.local_peer.load(Ordering::SeqCst).then(|| "v".to_string())
        }
        fn user_current_key(&self, _: &str) -> Option<[u8; 32]> {
            Some(self.public())
        }
        async fn member_public_key(&self, _: &str, did: &str) -> Option<[u8; 32]> {
            if did == self.peer().did {
                return Some(self.peer().public());
            }
            self.other_cards.lock().unwrap().iter().find(|(d, _)| d == did).map(|(_, k)| *k)
        }
        async fn contact_paths(&self, _: &str, contact_did: &str) -> Result<Vec<Path>, String> {
            assert_eq!(contact_did, self.peer().did);
            Ok(self.paths.lock().unwrap().iter().map(|p| Path::new(p.to_string())).collect())
        }
        /// The other person's door: a device of theirs if one is awake, their
        /// vault if not and they have one, nothing otherwise — on every path
        /// but `hang`, which never answers, and `vault`, which is theirs.
        async fn deliver_on(
            &self,
            _: &str,
            contact_did: &str,
            path: &Path,
            request: &ContactRequest,
        ) -> Result<ContactResponse, String> {
            let sealed = request.sealed();
            let peer = self.peer();
            assert_eq!(contact_did, peer.did);
            let path = *self.paths.lock().unwrap().iter().find(|p| Some(**p) == path.way::<String>().map(String::as_str)).expect("a path this node named");
            self.dialled.lock().unwrap().push((path, sealed.ephemeral_pub.clone()));
            self.said.lock().unwrap().push(match request {
                ContactRequest::DeliverMessage { .. } => "handed over",
                ContactRequest::CarryMessage { .. } => "carried",
            });
            self.frames.lock().unwrap().push(serde_json::to_string(request).unwrap());
            let dial = self.dialled.lock().unwrap().len();
            if *self.keeper_at.lock().unwrap() == Some(dial) {
                *self.keeper_at.lock().unwrap() = None;
                retry_due(self, "u", u64::MAX, NOW_AGAIN).await;
            }
            if *self.taken_elsewhere_at.lock().unwrap() == Some(dial) {
                *self.taken_elsewhere_at.lock().unwrap() = None;
                let answer = delivery::accept(
                    peer.as_ref(),
                    "u",
                    self.did,
                    &self.public(),
                    ContactRequest::DeliverMessage { sealed: sealed.clone() },
                )
                .await;
                let ContactResponse::Delivered { ack: Some(ack), .. } = answer else {
                    panic!("the other path was not signed for: {answer:?}")
                };
                take_ack(self, "u", peer.did, &sealed.ephemeral_pub, &ack).await.unwrap();
                return Err("this path dropped after another took it".to_string());
            }
            if let Some(left) = self.answers.lock().unwrap().as_mut() {
                if *left == 0 {
                    return Err("the connection dropped".to_string());
                }
                *left -= 1;
            }
            if path == "hang" {
                return std::future::pending().await;
            }
            if path == "silent" {
                return Err(format!("nothing of {}'s answered at {path}", peer.did));
            }
            if path == "vault" {
                peer.held.lock().unwrap().push(sealed.clone());
                return Ok(ContactResponse::Delivered { stored: true, ack: None });
            }
            if peer.awake.load(Ordering::SeqCst) {
                return Ok(delivery::accept(peer.as_ref(), "u", self.did, &self.public(), request.clone()).await);
            }
            if peer.vault.load(Ordering::SeqCst) {
                peer.held.lock().unwrap().push(sealed.clone());
                return Ok(ContactResponse::Delivered { stored: true, ack: None });
            }
            Err(format!("nothing of {}'s is awake at {path}", peer.did))
        }
        fn sign_delivery_ack(&self, message_id: &str, from_did: &str, to_did: &str) -> DeliveryAck {
            kotton_crypto::delivery_ack::sign(message_id, from_did, to_did, &self.signs_with)
        }
        async fn contact_reach_note(&self, _: &str, contact_did: &str) -> Option<ReachNote> {
            (contact_did == self.peer().did).then(|| self.peer().note())
        }
        async fn outbox_entries(&self, _: &str) -> anyhow::Result<Vec<OutboxEntry>> {
            Ok(self.outbox.lock().unwrap().clone())
        }
        async fn keep_outbox_entry(&self, _: &str, entry: &OutboxEntry) -> anyhow::Result<()> {
            let mut outbox = self.outbox.lock().unwrap();
            outbox.retain(|e| e.id != entry.id);
            outbox.push(entry.clone());
            Ok(())
        }
        async fn drop_outbox_entry(&self, _: &str, id: &str) -> anyhow::Result<()> {
            self.outbox.lock().unwrap().retain(|e| e.id != id);
            Ok(())
        }
        async fn keep_signed_for(&self, _: &str, signed: &SignedFor) -> anyhow::Result<()> {
            let mut all = self.signed.lock().unwrap();
            all.retain(|s| s.id != signed.id);
            all.push(signed.clone());
            Ok(())
        }
        async fn all_signed_for(&self, _: &str) -> anyhow::Result<Vec<SignedFor>> {
            Ok(self.signed.lock().unwrap().clone())
        }
        async fn keep_reach_note(&self, _: &str, contact_did: &str, note: ReachNote) -> Result<Kept, NotKept> {
            use crate::daemon::messages::{judge_reach_note, NoteCard};
            if let Some(not_kept) = self.card.lock().unwrap().clone() {
                return Err(not_kept);
            }
            let mut kept = self.kept.lock().unwrap();
            let Some(card) = kept.as_mut() else { return Ok(Kept::AlreadyHeld) };
            let key = self.peer().public();
            let on = card.written.then_some(NoteCard { held: card.held.as_ref(), key: &key });
            let judged = judge_reach_note(on, &note, contact_did, card.clock);
            if judged == Ok(Kept::Replaced) {
                card.held = Some(note);
            }
            judged
        }
        fn own_key_log(&self, _: &str) -> Vec<kotton_wire::kel::KelEvent> {
            Vec::new()
        }
        fn contact_key_log(&self, _: &str, _: &str) -> Vec<kotton_wire::kel::KelEvent> {
            Vec::new()
        }
        async fn adopt_contact_key(&self, _: &str, _: &str, _: &[kotton_wire::kel::KelEvent], _: [u8; 32]) -> Result<(), NotKept> {
            unreachable!("nobody in these tests carries a key log")
        }
        fn retired_identity_keys(&self, _: &str, _: &ed25519_dalek::SigningKey) -> Vec<ed25519_dalek::SigningKey> {
            Vec::new()
        }
        async fn contact_name(&self, _: &str, contact_did: &str) -> Option<String> {
            self.card_names.lock().unwrap().iter().find(|(d, _)| d == contact_did).map(|(_, n)| n.clone())
        }
        /// The Personal tree's folder `dir`, by the names directly in it.
        async fn personal_names(&self, _: &str, dir: &str) -> Result<Vec<String>, String> {
            let prefix = format!("{dir}/");
            let mut names: Vec<String> = self
                .tree
                .lock()
                .unwrap()
                .iter()
                .filter_map(|(path, _)| path.strip_prefix(&prefix))
                .map(|rest| rest.split('/').next().unwrap_or(rest).to_string())
                .collect();
            names.dedup();
            Ok(names)
        }
        async fn personal_write(&self, _: &str, path: &str, bytes: &[u8]) -> Result<(), String> {
            let mut tree = self.tree.lock().unwrap();
            tree.retain(|(p, _)| p != path);
            tree.push((path.to_string(), bytes.to_vec()));
            Ok(())
        }
        async fn stream_keep(&self, _: &str, key: &str, bytes: &[u8]) -> Result<(), String> {
            self.shelf.lock().unwrap().insert(key.to_string(), bytes.to_vec());
            Ok(())
        }
        async fn stream_keys(&self, _: &str) -> Result<Vec<String>, String> {
            Ok(self.shelf.lock().unwrap().keys().cloned().collect())
        }
        async fn stream_read(&self, _: &str, key: &str) -> Result<Vec<u8>, String> {
            self.shelf.lock().unwrap().get(key).cloned().ok_or_else(|| format!("nothing kept under {key}"))
        }
        async fn stream_drop(&self, _: &str, key: &str) -> Result<(), String> {
            self.shelf.lock().unwrap().remove(key);
            Ok(())
        }
        async fn record_insert(&self, _: &str, _: &str, record: serde_json::Value) -> anyhow::Result<String> {
            let mut records = self.records.lock().unwrap();
            records.push(record);
            Ok(records.len().to_string())
        }
        async fn record_delete(&self, _: &str, _: &str, _: &str) -> anyhow::Result<()> {
            anyhow::bail!("nothing in these tests deletes a record")
        }
        async fn record_query(
            &self,
            _: &str,
            _: &str,
            field_eq: Vec<(String, serde_json::Value)>,
            _: Option<usize>,
            _: Option<usize>,
            _: Option<String>,
        ) -> anyhow::Result<Vec<serde_json::Value>> {
            // A store read answers from what it saw when asked, and the answer
            // arrives after an await: two copies filing at once can both be
            // told *none yet* here, which is the race `filing` closes.
            let seen: Vec<serde_json::Value> = self
                .records
                .lock()
                .unwrap()
                .iter()
                .filter(|r| field_eq.iter().all(|(k, v)| r.get(k) == Some(v)))
                .cloned()
                .collect();
            tokio::task::yield_now().await;
            Ok(seen)
        }
    }

    /// Alice seals `text` to Bob and sends it through the outbox, as
    /// `message_send` does once her own copy is filed as record `record_id`.
    async fn alice_sends(alice: &Node, record_id: &str, text: &str) -> (SealedDm, Delivery) {
        let bob = alice.peer();
        let inner = DmInner {
            from_did: alice.did.into(),
            to_did: bob.did.into(),
            thread_id: "t".into(),
            sent_at: now_secs(),
            kind: "text".into(),
            text: text.into(),
            channel: None,
            grant: None,
            reach: None,
            ack: None,
            kel: Vec::new(),
            share: None,
            range: None,
        };
        let sealed = envelope::seal(&inner, &alice.identity, &bob.public()).unwrap();
        let delivery = send(alice, "u", bob.did, record_id, &sealed, None, NOW_AGAIN).await;
        (sealed, delivery)
    }

    fn words(readings: &[DeliveryReading]) -> Vec<(&str, &str)> {
        readings.iter().map(|r| (r.message_id.as_str(), r.word.as_str())).collect()
    }

    /// Bob's every device is off and he has no vault: Alice's message waits in
    /// her outbox and reads *waiting at home*, with its next try. A device of
    /// his comes back, the next try reaches it, and it signs for the message:
    /// Bob holds one copy, Alice's reading is *delivered*, and nothing is ever
    /// tried again.
    #[tokio::test]
    async fn a_message_to_someone_whose_every_device_is_off_is_signed_for_once_when_one_returns() {
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        bob.awake.store(false, Ordering::SeqCst);

        let (_, first) = alice_sends(&alice, "r1", "the milk is in the fridge").await;
        assert!(matches!(first, Delivery::Unreachable { .. }), "{first:?}");
        let waiting = readings(alice.as_ref(), "u", bob.did).await.unwrap();
        assert_eq!(words(&waiting), vec![("r1", "waiting at home")]);
        assert!(waiting[0].retry_at.is_some(), "the wait is a number: when it is tried next");

        // Still off: tried, and still waiting.
        assert_eq!(retry_due(alice.as_ref(), "u", now_secs(), NOW_AGAIN).await, 1);
        assert_eq!(bob.filed(), 0);

        bob.awake.store(true, Ordering::SeqCst);
        assert_eq!(retry_due(alice.as_ref(), "u", now_secs(), NOW_AGAIN).await, 1);
        assert_eq!(bob.filed(), 1, "bob holds it");
        assert_eq!(
            words(&readings(alice.as_ref(), "u", bob.did).await.unwrap()),
            vec![("r1", "delivered")]
        );
        assert!(alice.outbox.lock().unwrap().is_empty(), "out of the outbox once signed for");
        assert_eq!(alice.signed.lock().unwrap().len(), 1, "signed for once");

        // Nothing left to try, however often the keeper passes.
        for _ in 0..3 {
            assert_eq!(retry_due(alice.as_ref(), "u", now_secs(), NOW_AGAIN).await, 0);
        }
        assert_eq!(bob.filed(), 1, "one copy, once");
    }

    /// A message to another account on this machine never enters the outbox
    /// and nothing signs for it, and it still reads as one of the four words:
    /// *local*, for every message Alice filed to Bob and for nothing else —
    /// not what Bob sent her, and not a message to someone who is not local.
    #[tokio::test]
    async fn a_message_to_another_account_on_this_machine_reads_local_after_the_send_is_gone() {
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        {
            let mut records = alice.records.lock().unwrap();
            records.push(serde_json::json!({"_id": "r1", "from_did": alice.did, "to_did": bob.did}));
            records.push(serde_json::json!({"_id": "r2", "from_did": bob.did, "to_did": alice.did}));
            records.push(serde_json::json!({"_id": "r3", "from_did": alice.did, "to_did": bob.did}));
        }

        assert!(
            readings(alice.as_ref(), "u", bob.did).await.unwrap().is_empty(),
            "someone not on this machine: what the outbox never held has no word"
        );

        alice.local_peer.store(true, Ordering::SeqCst);
        assert_eq!(
            words(&readings(alice.as_ref(), "u", bob.did).await.unwrap()),
            vec![("r1", "local"), ("r3", "local")],
            "every message she sent him, and not the one he sent her"
        );
    }

    /// **One conversation is both directions between two people, and nothing
    /// else in the store** (`TASK-messages-is-the-drawn-one`): what Bob sent
    /// Alice and what Alice sent Bob, newest-filed first by Alice's own store,
    /// with the store's `_id` and `_filed_at` renamed to the wire's — and not
    /// a line between Alice and anyone else.
    #[tokio::test]
    async fn a_conversation_is_both_directions_between_two_people_newest_filed_first() {
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        {
            let mut records = alice.records.lock().unwrap();
            let r = |id: &str, from: &str, to: &str, filed: u64| {
                serde_json::json!({"_id": id, "_filed_at": filed, "from_did": from, "to_did": to})
            };
            records.push(r("r1", alice.did, bob.did, 100));
            records.push(r("r2", "did:kel:carol", alice.did, 150));
            records.push(r("r3", bob.did, alice.did, 300));
            records.push(r("r4", alice.did, "did:kel:carol", 200));
            // A reply filed later whose sender's clock ran behind: the store's
            // filing order is what places it, not `sent_at`.
            let mut late = r("r5", alice.did, bob.did, 400);
            late["sent_at"] = serde_json::json!(1);
            records.push(late);
        }
        let answer = super::super::messages::message_conversation(
            alice.as_ref(),
            "u".to_string(),
            bob.did.to_string(),
        )
        .await
        .unwrap();
        let kotton_wire::ipc::UserResponse::MessageHistory { messages } = answer else {
            panic!("a conversation answers as a history: {answer:?}");
        };
        let ids: Vec<&str> = messages.iter().map(|m| m["id"].as_str().unwrap()).collect();
        assert_eq!(ids, vec!["r5", "r3", "r1"], "both directions, this pair only, newest-filed first");
        assert_eq!(messages[1]["filed_at"], serde_json::json!(300));
        assert!(messages.iter().all(|m| m.get("_id").is_none() && m.get("_filed_at").is_none()));
    }

    /// A node that files the message and signs with a key Bob's note does not
    /// list has not said the message arrived: Alice's reading stays *sent*,
    /// the message stays in her outbox, and it is tried again.
    #[tokio::test]
    async fn an_acknowledgement_not_signed_by_a_device_in_the_note_is_refused() {
        let alice = node("did:kel:alice", 1);
        let bob = Arc::new(Node { signs_with: SigningKey::from_bytes(&[66; 32]), ..Arc::into_inner(node("did:kel:bob", 2)).unwrap() });
        pair(&alice, &bob);

        let (_, delivery) = alice_sends(&alice, "r1", "hello").await;
        assert_eq!(delivery, Delivery::Sent, "held there, and nobody bob's note lists signed");
        assert_eq!(
            words(&readings(alice.as_ref(), "u", bob.did).await.unwrap()),
            vec![("r1", "sent")]
        );
        assert_eq!(alice.outbox.lock().unwrap().len(), 1, "still in the outbox");
        assert!(alice.signed.lock().unwrap().is_empty());

        // And an acknowledgement envelope carrying the same forgery is refused
        // at Alice's door rather than taken.
        let id = alice.outbox.lock().unwrap()[0].id.clone();
        let sealed = ack_envelope(bob.as_ref(), "u", bob.did, alice.did, &alice.public(), &id).unwrap();
        let answer = delivery::accept(
            alice.as_ref(),
            "u",
            bob.did,
            &bob.public(),
            ContactRequest::DeliverMessage { sealed },
        )
        .await;
        assert!(matches!(answer, ContactResponse::Refused { .. }), "{answer:?}");
        assert_eq!(alice.outbox.lock().unwrap().len(), 1, "still waiting to be signed for");
    }

    /// The same message handed to Bob's door twice — two paths, or a retry
    /// whose answer was lost — is kept once, and signed for both times, so the
    /// sender whose first answer went missing is answered on the second.
    #[tokio::test]
    async fn a_copy_delivered_twice_is_kept_once() {
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        let (sealed, _) = alice_sends(&alice, "r1", "twice").await;
        assert_eq!(bob.filed(), 1);
        let again = delivery::accept(
            bob.as_ref(),
            "u",
            alice.did,
            &alice.public(),
            ContactRequest::DeliverMessage { sealed },
        )
        .await;
        match again {
            ContactResponse::Delivered { stored: false, ack: Some(_) } => {}
            other => panic!("a second copy files nothing and is signed for again: {other:?}"),
        }
        assert_eq!(bob.filed(), 1, "kept once");
    }

    /// Bob's devices are off and his vault takes the message: it is *sent*,
    /// not *delivered* — a vault holds and cannot sign. When a device of his
    /// picks it up, it signs for it back over Alice's door, and Alice's
    /// reading turns *delivered* without her trying again.
    #[tokio::test]
    async fn a_message_a_vault_held_is_signed_for_when_a_device_picks_it_up() {
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        bob.awake.store(false, Ordering::SeqCst);
        bob.vault.store(true, Ordering::SeqCst);

        let (_, delivery) = alice_sends(&alice, "r1", "held for you").await;
        assert_eq!(delivery, Delivery::Sent);
        assert_eq!(
            words(&readings(alice.as_ref(), "u", bob.did).await.unwrap()),
            vec![("r1", "sent")]
        );

        bob.awake.store(true, Ordering::SeqCst);
        let held = std::mem::take(&mut *bob.held.lock().unwrap());
        for sealed in held {
            let item = PendingDelivery { handle_did: "did:key:door".into(), sealed };
            assert_eq!(delivery::file_from_vault(bob.as_ref(), "u", &item).await, Ok(true));
        }
        assert_eq!(bob.filed(), 1);
        assert_eq!(
            words(&readings(alice.as_ref(), "u", bob.did).await.unwrap()),
            vec![("r1", "delivered")]
        );
        assert!(alice.outbox.lock().unwrap().is_empty());
        assert_eq!(alice.filed(), 0, "an acknowledgement is not a message in alice's conversation");
        assert_eq!(
            *bob.said.lock().unwrap(),
            vec!["carried"],
            "the signature sent back is said as everything handed to a contact is, so the door cannot tell it by its verb"
        );
    }

    /// Alice's devices are off and her vault carries her message to Bob's door
    /// (`CarryMessage`). Bob files it once and signs for it — sealed to Alice,
    /// so the answer the vault reads names neither Bob nor the device that
    /// signed. Alice's next pickup opens it, believes it under Bob's note, and
    /// her message reads *delivered*; a second carry is kept once and signed
    /// for again, and taking that second signature changes nothing.
    #[tokio::test]
    async fn a_message_her_vault_carries_is_signed_for_sealed_to_her_and_read_delivered_at_her_pickup() {
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        bob.awake.store(false, Ordering::SeqCst);
        let (sealed, first) = alice_sends(&alice, "r1", "carried for me").await;
        assert!(matches!(first, Delivery::Unreachable { .. }), "{first:?}");

        let carry = || ContactRequest::CarryMessage { sealed: sealed.clone() };
        let answer = delivery::accept(bob.as_ref(), "u", alice.did, &alice.public(), carry()).await;
        let ContactResponse::SignedSealed { stored: true, ack } = answer.clone() else {
            panic!("a device signs for a carried message sealed to its sender: {answer:?}");
        };
        let said = serde_json::to_string(&answer).unwrap();
        let device = hex::encode(bob.device.verifying_key().to_bytes());
        assert!(
            !said.contains(bob.did) && !said.contains(&device) && !said.contains(alice.did),
            "the carrier reads no one's name and no device: {said}"
        );
        assert_eq!(bob.filed(), 1);
        assert_eq!(
            words(&readings(alice.as_ref(), "u", bob.did).await.unwrap()),
            vec![("r1", "waiting at home")],
            "nothing is delivered until alice takes the signature"
        );

        // The vault keeps it as it came, under no door; alice's pickup takes it.
        let held = PendingDelivery { handle_did: String::new(), sealed: ack };
        assert_eq!(delivery::file_from_vault(alice.as_ref(), "u", &held).await, Ok(true));
        assert_eq!(
            words(&readings(alice.as_ref(), "u", bob.did).await.unwrap()),
            vec![("r1", "delivered")]
        );
        assert!(alice.outbox.lock().unwrap().is_empty());
        assert_eq!(alice.filed(), 0, "a signature is not a message in her conversation");

        // Carried again — the vault had not yet been told — kept once, and
        // signed for again; the second signature finds nothing left to take.
        let again = delivery::accept(bob.as_ref(), "u", alice.did, &alice.public(), carry()).await;
        let ContactResponse::SignedSealed { stored: false, ack } = again else {
            panic!("a second carry is kept once and signed for again: {again:?}");
        };
        assert_eq!(bob.filed(), 1, "kept once");
        let held = PendingDelivery { handle_did: String::new(), sealed: ack };
        assert_eq!(delivery::file_from_vault(alice.as_ref(), "u", &held).await, Ok(false));
        assert_eq!(alice.signed.lock().unwrap().len(), 1, "signed for once");
    }

    /// Every try from Alice's outbox — the first, and each retry — is said at
    /// Bob's door exactly as her vault says it, so nothing at his door tells a
    /// message her device handed over from one her vault carried while her
    /// devices were off. And it still reads *delivered* from her device: the
    /// signature comes back sealed to her, and she opens it.
    #[tokio::test]
    async fn her_devices_outbox_tries_are_said_as_her_vault_says_them() {
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        bob.awake.store(false, Ordering::SeqCst);
        let (_, first) = alice_sends(&alice, "r1", "the same either way").await;
        assert!(matches!(first, Delivery::Unreachable { .. }), "{first:?}");
        bob.awake.store(true, Ordering::SeqCst);
        assert_eq!(retry_due(alice.as_ref(), "u", now_secs(), NOW_AGAIN).await, 1);
        assert_eq!(*alice.said.lock().unwrap(), vec!["carried", "carried"]);
        assert_eq!(
            words(&readings(alice.as_ref(), "u", bob.did).await.unwrap()),
            vec![("r1", "delivered")]
        );
        assert_eq!(bob.filed(), 1);
    }

    /// A node that files a carried message and signs, sealed, with a key Bob's
    /// note does not list has not said it arrived: Alice's pickup takes the
    /// envelope off her vault, believes nothing, and the message stays in her
    /// outbox. Sealing the signature changes who can read it, not what it
    /// takes to believe it.
    #[tokio::test]
    async fn a_carried_message_signed_by_a_key_the_note_does_not_list_is_refused_at_her_pickup() {
        let alice = node("did:kel:alice", 1);
        let bob = Arc::new(Node { signs_with: SigningKey::from_bytes(&[66; 32]), ..Arc::into_inner(node("did:kel:bob", 2)).unwrap() });
        pair(&alice, &bob);
        bob.awake.store(false, Ordering::SeqCst);
        let (sealed, _) = alice_sends(&alice, "r1", "carried, forged").await;
        let answer = delivery::accept(
            bob.as_ref(),
            "u",
            alice.did,
            &alice.public(),
            ContactRequest::CarryMessage { sealed },
        )
        .await;
        let ContactResponse::SignedSealed { ack, .. } = answer else { panic!("{answer:?}") };
        let held = PendingDelivery { handle_did: String::new(), sealed: ack };
        assert_eq!(delivery::file_from_vault(alice.as_ref(), "u", &held).await, Ok(false), "taken off the vault, not believed");
        assert_eq!(alice.outbox.lock().unwrap().len(), 1, "still waiting to be signed for");
        assert!(alice.signed.lock().unwrap().is_empty());
    }

    /// Two ways to Bob's door, both of them working: the message is dialled on
    /// both at once with the same sealed bytes — one message id — and Bob
    /// keeps one copy; Alice's reading is *delivered* once and nothing is left
    /// to try.
    #[tokio::test]
    async fn a_message_dialled_on_two_paths_at_once_is_kept_once_and_delivered_once() {
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        *alice.paths.lock().unwrap() = vec!["door", "their other relay"];

        let (sealed, delivery) = alice_sends(&alice, "r1", "by every way at once").await;
        assert_eq!(delivery, Delivery::Delivered);
        let dialled = alice.dialled.lock().unwrap().clone();
        assert_eq!(
            dialled,
            vec![("door", sealed.ephemeral_pub.clone()), ("their other relay", sealed.ephemeral_pub.clone())],
            "every path set out with the one message"
        );
        assert_eq!(bob.filed(), 1, "kept once");
        assert_eq!(
            words(&readings(alice.as_ref(), "u", bob.did).await.unwrap()),
            vec![("r1", "delivered")]
        );
        assert_eq!(alice.signed.lock().unwrap().len(), 1, "signed for once");
        assert_eq!(retry_due(alice.as_ref(), "u", now_secs(), NOW_AGAIN).await, 0);
    }

    /// A message waiting for Bob is tried again on every path, with the same
    /// bytes each time — a retry is the whole dial again, not the path that
    /// happened to answer last.
    #[tokio::test]
    async fn a_retry_dials_every_path_again_with_the_same_message() {
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        bob.awake.store(false, Ordering::SeqCst);
        *alice.paths.lock().unwrap() = vec!["door", "their other relay"];
        let (sealed, _) = alice_sends(&alice, "r1", "again and again").await;
        assert_eq!(retry_due(alice.as_ref(), "u", now_secs(), NOW_AGAIN).await, 1);
        let dialled = alice.dialled.lock().unwrap().clone();
        assert_eq!(dialled.len(), 4, "two paths, twice: {dialled:?}");
        assert!(dialled.iter().all(|(_, id)| *id == sealed.ephemeral_pub), "one message id throughout");
        for path in ["door", "their other relay"] {
            assert_eq!(dialled.iter().filter(|(p, _)| *p == path).count(), 2, "{path} on every try");
        }
    }

    /// A way to Bob that never answers — a relay gone quiet — holds up
    /// nothing: the path listed after it answers and settles the message.
    #[tokio::test]
    async fn a_path_that_never_answers_does_not_hold_up_the_one_that_does() {
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        *alice.paths.lock().unwrap() = vec!["hang", "door"];
        let sent = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            alice_sends(&alice, "r1", "whichever answers"),
        )
        .await
        .expect("the answering path settles it while the other still hangs");
        assert_eq!(sent.1, Delivery::Delivered);
        assert_eq!(bob.filed(), 1);
    }

    /// Bob's vault answers on one path before his device answers on another.
    /// A vault holding it is not Bob having it, so the dial waits on: the
    /// device signs, and the message is *delivered*, not *sent*.
    #[tokio::test]
    async fn a_vault_answering_first_does_not_end_the_dial_before_a_device_signs() {
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        *alice.paths.lock().unwrap() = vec!["vault", "door"];
        let (_, delivery) = alice_sends(&alice, "r1", "for bob, not his vault").await;
        assert_eq!(bob.held.lock().unwrap().len(), 1, "the vault took it first");
        assert_eq!(delivery, Delivery::Delivered);
        assert_eq!(bob.filed(), 1);
        assert!(alice.outbox.lock().unwrap().is_empty());
    }

    /// Nothing of Bob's answers on any path: the reason Alice's answer
    /// carries says so and names none of the ways it tried.
    #[tokio::test]
    async fn waiting_at_home_names_no_path() {
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        bob.awake.store(false, Ordering::SeqCst);
        *alice.paths.lock().unwrap() = vec!["door", "their other relay"];
        let (_, delivery) = alice_sends(&alice, "r1", "nobody home").await;
        let Delivery::Unreachable { reason } = delivery else { panic!("{delivery:?}") };
        assert!(!reason.contains("door") && !reason.contains("relay"), "{reason}");
        assert_eq!(alice.dialled.lock().unwrap().len(), 2, "both were tried");
    }

    /// Two copies of one message at Bob's door in the same moment — the two
    /// paths above, landing together. Both ask whether a copy is filed while
    /// neither has filed yet; one files, the other finds it, and both are
    /// signed for.
    #[tokio::test]
    async fn two_copies_arriving_at_once_are_filed_once() {
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        bob.awake.store(false, Ordering::SeqCst);
        let (sealed, _) = alice_sends(&alice, "r1", "at once").await;
        assert_eq!(bob.filed(), 0);

        let copy = || ContactRequest::DeliverMessage { sealed: sealed.clone() };
        let alice_pub = alice.public();
        let (a, b) = tokio::join!(
            delivery::accept(bob.as_ref(), "u", alice.did, &alice_pub, copy()),
            delivery::accept(bob.as_ref(), "u", alice.did, &alice_pub, copy()),
        );
        assert_eq!(bob.filed(), 1, "kept once");
        let stored: Vec<bool> = [a, b]
            .into_iter()
            .map(|answer| match answer {
                ContactResponse::Delivered { stored, ack: Some(_) } => stored,
                other => panic!("each copy is signed for: {other:?}"),
            })
            .collect();
        assert_eq!(stored.iter().filter(|s| **s).count(), 1, "{stored:?}");
    }

    /// The same message at Bob's door and picked up from his vault in the
    /// same moment — it was dialled on a path his vault answers as well as
    /// one his device does. One copy is filed.
    #[tokio::test]
    async fn a_copy_at_the_door_and_one_from_the_vault_at_once_are_filed_once() {
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        bob.awake.store(false, Ordering::SeqCst);
        let (sealed, _) = alice_sends(&alice, "r1", "both ways").await;
        bob.awake.store(true, Ordering::SeqCst);

        let alice_pub = alice.public();
        let held = PendingDelivery { handle_did: "did:key:door".into(), sealed: sealed.clone() };
        let (at_door, from_vault) = tokio::join!(
            delivery::accept(bob.as_ref(), "u", alice.did, &alice_pub, ContactRequest::DeliverMessage { sealed }),
            delivery::file_from_vault(bob.as_ref(), "u", &held),
        );
        assert!(matches!(at_door, ContactResponse::Delivered { ack: Some(_), .. }), "{at_door:?}");
        assert!(from_vault.is_ok(), "{from_vault:?}");
        assert_eq!(bob.filed(), 1, "kept once");
    }

    /// A key-grant handed over on two paths lands twice at once. It is filed
    /// once — two rows would be two claims on one epoch.
    #[tokio::test]
    async fn a_key_grant_arriving_twice_at_once_is_filed_once() {
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        let inner = DmInner {
            from_did: alice.did.into(),
            to_did: bob.did.into(),
            thread_id: String::new(),
            sent_at: now_secs(),
            kind: "grant".into(),
            text: String::new(),
            channel: None,
            grant: Some(crate::envelope::ChannelGrant {
                channel_did: "did:key:channel".into(),
                epoch: 1,
                enc_key: "k".into(),
                nonce: "n".into(),
                ephemeral_pub: "the grant's own key".into(),
                granted_at: 1,
                roster: None,
            }),
            reach: None,
            ack: None,
            kel: Vec::new(),
            share: None,
            range: None,
        };
        let sealed = envelope::seal(&inner, &alice.identity, &bob.public()).unwrap();
        let alice_pub = alice.public();
        let copy = || ContactRequest::DeliverMessage { sealed: sealed.clone() };
        let (a, b) = tokio::join!(
            delivery::accept(bob.as_ref(), "u", alice.did, &alice_pub, copy()),
            delivery::accept(bob.as_ref(), "u", alice.did, &alice_pub, copy()),
        );
        assert!(matches!(a, ContactResponse::Delivered { .. }) && matches!(b, ContactResponse::Delivered { .. }), "{a:?} {b:?}");
        assert_eq!(bob.filed(), 1, "one grant row");
    }
    /// **`TASK-a-reach-note-a-contact-refused-is-sent-to-them-again-every-hour`.**
    /// While nothing of Bob's answers, Alice's note settles nothing and is
    /// handed to him at every pass. Once a device of his answers and his card
    /// refuses that version — it holds a newer one — the refusal is a verdict:
    /// handed once, and never again however often the keeper passes. A newer
    /// version is his card's to judge afresh, and is handed to him.
    #[tokio::test]
    async fn a_note_their_card_refused_is_not_handed_to_them_again_and_one_not_delivered_is() {
        use crate::daemon::messages::{hand_reach_note_to, NotesSettled};
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        let contacts = vec![bob.did.to_string()];
        let mut settled = NotesSettled::new();
        let first = alice.note_at(10);

        bob.awake.store(false, Ordering::SeqCst);
        for pass in 1..=3 {
            hand_reach_note_to(alice.as_ref(), "u", &contacts, &first, &mut settled).await;
            assert_eq!(alice.handed(), pass, "not reached at pass {pass}, so handed to him again");
        }
        assert!(settled.is_empty(), "a note nothing of his answered is settled for nobody");

        bob.awake.store(true, Ordering::SeqCst);
        *bob.card.lock().unwrap() = Some(NotKept::Refused("a newer reach note is already held".into()));
        hand_reach_note_to(alice.as_ref(), "u", &contacts, &first, &mut settled).await;
        assert_eq!(alice.handed(), 4, "reached, and his card refused it");
        for _ in 0..3 {
            hand_reach_note_to(alice.as_ref(), "u", &contacts, &first, &mut settled).await;
        }
        assert_eq!(alice.handed(), 4, "a version his card refused is not handed to him again");
        assert_eq!(settled.get(&("u".to_string(), bob.did.to_string())), Some(&10));

        let second = alice.note_at(11);
        hand_reach_note_to(alice.as_ref(), "u", &contacts, &second, &mut settled).await;
        assert_eq!(alice.handed(), 5, "a newer version is handed to him");
    }

    /// A card this node only *failed* to keep a note on has given no verdict —
    /// the note may be good — so the door says it as a refusal that may clear,
    /// and the note is handed again at every pass until it is kept.
    #[tokio::test]
    async fn a_note_their_card_could_not_keep_is_handed_to_them_again() {
        use crate::daemon::messages::{hand_reach_note_over, hand_reach_note_to, NotesSettled};
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        let contacts = vec![bob.did.to_string()];
        let mut settled = NotesSettled::new();
        let note = alice.note_at(10);
        *bob.card.lock().unwrap() = Some(NotKept::Failed("could not read the card".into()));

        let handed = hand_reach_note_over(alice.as_ref(), "u", bob.did, &note).await;
        assert!(
            matches!(handed, Handed::Delivery(Delivery::Unreachable { .. })),
            "a failure to keep is not a verdict: {handed:?}"
        );
        for pass in 2..=4 {
            hand_reach_note_to(alice.as_ref(), "u", &contacts, &note, &mut settled).await;
            assert_eq!(alice.handed(), pass, "handed again at pass {pass}");
        }

        *bob.card.lock().unwrap() = None;
        hand_reach_note_to(alice.as_ref(), "u", &contacts, &note, &mut settled).await;
        hand_reach_note_to(alice.as_ref(), "u", &contacts, &note, &mut settled).await;
        assert_eq!(alice.handed(), 5, "kept once his card could keep it, and not handed again");
    }

    /// A card's verdict on one path and a vault holding the note on another:
    /// something of theirs took it, and that is what it reads as. A card that
    /// declines and a door that does not answer: the verdict stands, because
    /// the silent path judged nothing.
    #[tokio::test]
    async fn a_note_held_on_one_path_is_taken_and_one_declined_beside_silence_is_declined() {
        use crate::daemon::messages::hand_reach_note_over;
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        *bob.card.lock().unwrap() = Some(NotKept::Refused("that note has expired".into()));
        let note = alice.note_at(10);

        *alice.paths.lock().unwrap() = vec!["door", "vault"];
        let handed = hand_reach_note_over(alice.as_ref(), "u", bob.did, &note).await;
        assert_eq!(handed, Handed::Delivery(Delivery::Sent), "his vault holds it");

        *alice.paths.lock().unwrap() = vec!["door", "silent"];
        let handed = hand_reach_note_over(alice.as_ref(), "u", bob.did, &note).await;
        assert_eq!(handed, Handed::Declined { reason: "that note has expired".into() });
    }

    /// **`TASK-a-door-refusal-that-can-clear-settles-a-reach-note-version-until-the-next`.**
    /// Alice's note reaches a door of Bob's while his node has no contact's
    /// card for her. That is a fact about his cards, not a verdict on her
    /// note, so the door says a refusal that may clear and the note is handed
    /// to him at every pass; the first pass after his card is there, it is
    /// kept on it and settles.
    #[tokio::test]
    async fn a_note_handed_before_their_card_for_her_is_written_is_handed_again_and_kept_once_it_is() {
        use crate::daemon::messages::{hand_reach_note_over, hand_reach_note_to, NotesSettled};
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        let contacts = vec![bob.did.to_string()];
        let mut settled = NotesSettled::new();
        let note = alice.note_at(10);
        *bob.kept.lock().unwrap() = Some(KeptCard { written: false, held: None, clock: now_secs() });

        let handed = hand_reach_note_over(alice.as_ref(), "u", bob.did, &note).await;
        let Handed::Delivery(Delivery::Unreachable { reason }) = handed else {
            panic!("no card yet is not a verdict on the note: {handed:?}")
        };
        assert!(reason.contains("is not a contact"), "{reason}");
        for pass in 2..=4 {
            hand_reach_note_to(alice.as_ref(), "u", &contacts, &note, &mut settled).await;
            assert_eq!(alice.handed(), pass, "his card is not written yet, so handed to him again at pass {pass}");
        }
        assert!(settled.is_empty(), "a note no card has judged is settled for nobody");

        bob.kept.lock().unwrap().as_mut().unwrap().written = true;
        hand_reach_note_to(alice.as_ref(), "u", &contacts, &note, &mut settled).await;
        assert_eq!(alice.handed(), 5, "handed once his card is written");
        assert_eq!(bob.kept.lock().unwrap().as_ref().unwrap().held.as_ref(), Some(&note), "and kept on it");
        for _ in 0..3 {
            hand_reach_note_to(alice.as_ref(), "u", &contacts, &note, &mut settled).await;
        }
        assert_eq!(alice.handed(), 5, "kept, and so settled: not handed to him again");
        assert_eq!(settled.get(&("u".to_string(), bob.did.to_string())), Some(&10));
    }

    /// Bob's clock trails Alice's far enough that her fresh note claims, by
    /// his clock, a day more than the longest life a note may — which a clock
    /// behind explains. That is his clock's to clear: the note is handed to him
    /// again, and kept once his clock has run on two days. A note claiming more
    /// than a clock explains — a week past the longest life, and a day more —
    /// is a verdict however his clock reads, and settles on the first answer.
    #[tokio::test]
    async fn a_note_their_clock_reads_as_outliving_any_note_is_handed_again_until_it_does_not() {
        use crate::daemon::messages::{hand_reach_note_over, hand_reach_note_to, NotesSettled};
        const DAY: u64 = 24 * 60 * 60;
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        let contacts = vec![bob.did.to_string()];
        let mut settled = NotesSettled::new();
        let note = alice.note_at(10);
        let behind = note.expires_at - reach_note::MAX_NOTE_LIFETIME_SECS - DAY;
        *bob.kept.lock().unwrap() = KeptCard::written_at(behind);

        let handed = hand_reach_note_over(alice.as_ref(), "u", bob.did, &note).await;
        let Handed::Delivery(Delivery::Unreachable { reason }) = handed else {
            panic!("a clock behind hers is not a verdict on the note: {handed:?}")
        };
        assert!(reason.contains("longer life"), "{reason}");
        for pass in 2..=3 {
            hand_reach_note_to(alice.as_ref(), "u", &contacts, &note, &mut settled).await;
            assert_eq!(alice.handed(), pass, "handed to him again at pass {pass}");
        }
        assert!(settled.is_empty());

        bob.kept.lock().unwrap().as_mut().unwrap().clock = behind + 2 * DAY;
        for _ in 0..3 {
            hand_reach_note_to(alice.as_ref(), "u", &contacts, &note, &mut settled).await;
        }
        assert_eq!(alice.handed(), 4, "kept once his clock has run on, and not handed again");
        assert_eq!(bob.kept.lock().unwrap().as_ref().unwrap().held.as_ref(), Some(&note));

        let next = alice.note_at(11);
        bob.kept.lock().unwrap().as_mut().unwrap().clock =
            next.expires_at - reach_note::MAX_NOTE_LIFETIME_SECS - reach_note::CLOCK_BEHIND_SLACK_SECS - DAY;
        for _ in 0..3 {
            hand_reach_note_to(alice.as_ref(), "u", &contacts, &next, &mut settled).await;
        }
        assert_eq!(alice.handed(), 5, "past what a clock explains: declined once, and settled");
        assert_eq!(settled.get(&("u".to_string(), bob.did.to_string())), Some(&11));
        assert_eq!(bob.kept.lock().unwrap().as_ref().unwrap().held.as_ref(), Some(&note), "and not kept");
    }

    /// One device of Bob's answers — one that has no card for Alice yet —
    /// while the device that has one sleeps. A refusal that may clear outranks
    /// no silence: nothing of his has judged the note, and it settles nothing.
    #[tokio::test]
    async fn one_device_refusing_a_note_for_want_of_a_card_beside_a_silent_one_settles_nothing() {
        use crate::daemon::messages::{hand_reach_note_over, hand_reach_note_to, NotesSettled};
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        *alice.paths.lock().unwrap() = vec!["door", "silent"];
        *bob.kept.lock().unwrap() = Some(KeptCard { written: false, held: None, clock: now_secs() });
        let contacts = vec![bob.did.to_string()];
        let mut settled = NotesSettled::new();
        let note = alice.note_at(10);

        let handed = hand_reach_note_over(alice.as_ref(), "u", bob.did, &note).await;
        assert!(
            matches!(handed, Handed::Delivery(Delivery::Unreachable { .. })),
            "a stale device's refusal beside silence is not a verdict: {handed:?}"
        );
        hand_reach_note_to(alice.as_ref(), "u", &contacts, &note, &mut settled).await;
        hand_reach_note_to(alice.as_ref(), "u", &contacts, &note, &mut settled).await;
        assert!(settled.is_empty(), "nothing of his judged it, so nothing settled");
        assert_eq!(alice.handed(), 6, "two ways to him, dialled at each of three tries");
    }

    /// A decline the card is right to give still settles on its first answer,
    /// judged by the card's own rule: a version older than the one his card
    /// holds, and a note his clock — set fast past its life — reads as expired.
    #[tokio::test]
    async fn a_note_their_card_holds_a_newer_one_than_or_reads_as_expired_settles_on_the_first_answer() {
        use crate::daemon::messages::{hand_reach_note_to, NotesSettled};
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        let contacts = vec![bob.did.to_string()];
        let mut settled = NotesSettled::new();
        *bob.kept.lock().unwrap() =
            Some(KeptCard { written: true, held: Some(alice.note_at(11)), clock: now_secs() });

        let older = alice.note_at(10);
        for _ in 0..3 {
            hand_reach_note_to(alice.as_ref(), "u", &contacts, &older, &mut settled).await;
        }
        assert_eq!(alice.handed(), 1, "a version older than his card holds is declined once and settled");
        assert_eq!(settled.get(&("u".to_string(), bob.did.to_string())), Some(&10));

        bob.kept.lock().unwrap().as_mut().unwrap().clock = now_secs() + reach_note::REACH_NOTE_TTL_SECS + 1;
        let newer = alice.note_at(12);
        for _ in 0..3 {
            hand_reach_note_to(alice.as_ref(), "u", &contacts, &newer, &mut settled).await;
        }
        assert_eq!(alice.handed(), 2, "a note his card reads as expired is declined once and settled");
        assert_eq!(settled.get(&("u".to_string(), bob.did.to_string())), Some(&12));
        assert_eq!(
            bob.kept.lock().unwrap().as_ref().unwrap().held.as_ref().map(|n| n.version),
            Some(11),
            "neither was kept"
        );
    }

    // ── Shares (RFC-0090's unit 2) ───────────────────────────────────────────
    //
    // `TASK-a-file-shared-with-a-contact-is-a-copy-of-theirs-under-shared-with-you`:
    // a share is a direct message whose body is a file, on the message
    // protocol's own path, filed by the recipient under *Shared with you*.

    /// What `key` reads inside the sealed record `record` — the opened bytes,
    /// signature and all, exactly as the seal holds them.
    fn opened_plaintext(record: &serde_json::Value, key: &SigningKey) -> String {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        let field = |k: &str| B64.decode(record[k].as_str().unwrap()).unwrap();
        let nonce: [u8; 12] = field("nonce").try_into().unwrap();
        let eph: [u8; 32] = field("ephemeral_pub").try_into().unwrap();
        let bytes = kotton_crypto::x25519::dm_decrypt(&field("body"), &nonce, &eph, key).unwrap();
        String::from_utf8_lossy(&bytes[..bytes.len() - 64]).into_owned()
    }

    async fn alice_shares(alice: &Node, name: &str, bytes: &[u8], origin: &str) -> UserResponse {
        super::super::messages::message_share(
            alice,
            "u".into(),
            alice.peer().did.into(),
            name.into(),
            bytes.to_vec(),
            Some(origin.into()),
            None,
        )
        .await
        .unwrap()
    }

    /// Clause (1) and (3): the envelope that reaches Bob carries the manifest
    /// RFC-0090 states and nothing of where Alice keeps the file — read inside
    /// the seal, byte for byte — and Bob's node files the bytes under *Shared
    /// with you/Alice*, and keeps the message in the conversation. Alice's own
    /// copy, sealed to her, names her file.
    #[tokio::test]
    async fn a_share_reaches_them_without_origin_and_is_filed_under_shared_with_you() {
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        bob.card_names.lock().unwrap().push((alice.did.into(), "Alice".into()));
        let photo: Vec<u8> = (0..20_000u32).map(|i| (i * 31 % 251) as u8).collect();

        let answer = alice_shares(&alice, "beach.jpg", &photo, "Photos/2026/beach.jpg").await;
        let UserResponse::MessageSent { delivery, .. } = answer else { panic!("{answer:?}") };
        assert_eq!(delivery, Some(Delivery::Delivered), "a device of Bob's signed for it");
        assert!(alice.outbox.lock().unwrap().is_empty(), "signed for, so out of the outbox");

        // What reached Bob, read inside the seal.
        let theirs = bob.records.lock().unwrap()[0].clone();
        assert_eq!(theirs["type"], "share");
        let opened = opened_plaintext(&theirs, &bob.identity);
        for never in ["origin", "Photos", "2026/"] {
            assert!(!opened.contains(never), "the envelope sealed to Bob carries {never:?}: {opened}");
        }
        let inner: DmInner = serde_json::from_str(&opened).unwrap();
        let manifest = inner.share.expect("a share carries its manifest");
        assert_eq!(
            (manifest.name.as_str(), manifest.kind.as_str(), manifest.mime.as_str(), manifest.size),
            ("beach.jpg", "file", "image/jpeg", photo.len() as u64)
        );
        assert_eq!(manifest.digest, crate::share::digest_of(&photo));
        assert_eq!(manifest.origin, None);
        assert_eq!(inner.text, "beach.jpg", "the conversation shows the file by its name");

        // Bob's copy is a file of his, under Shared with you, and nothing else
        // in his tree; the message stays in his conversation with Alice.
        assert_eq!(
            *bob.tree.lock().unwrap(),
            vec![("Shared with you/Alice/beach.jpg".to_string(), photo.clone())]
        );
        assert_eq!(theirs["from_did"], alice.did);
        let filed = serde_json::to_string(&theirs).unwrap();
        assert!(!filed.contains("Photos") && !filed.contains("origin"), "{filed}");

        // Alice's own copy is sealed to her, and only it names her file.
        let mine = alice.records.lock().unwrap()[0].clone();
        let mine: DmInner = serde_json::from_str(&opened_plaintext(&mine, &alice.identity)).unwrap();
        assert_eq!(mine.share.unwrap().origin.as_deref(), Some("Photos/2026/beach.jpg"));
        assert!(alice.tree.lock().unwrap().is_empty(), "nothing is copied on the sender's side");
    }

    /// Clause (3): a second share of one name lands beside the first, and a
    /// copy of one share handed over twice is filed once.
    #[tokio::test]
    async fn a_second_share_of_one_name_lands_beside_the_first_and_a_retry_files_nothing() {
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        alice_shares(&alice, "beach.jpg", b"one", "a").await;
        alice_shares(&alice, "beach.jpg", b"two", "b").await;
        // No card name: the folder is the first eight characters of the AID.
        let tree = bob.tree.lock().unwrap().clone();
        assert_eq!(
            tree,
            vec![
                ("Shared with you/alice/beach.jpg".to_string(), b"one".to_vec()),
                ("Shared with you/alice/beach 2.jpg".to_string(), b"two".to_vec()),
            ]
        );

        let again = bob.records.lock().unwrap()[1].clone();
        let sealed = SealedDm {
            body: again["body"].as_str().unwrap().into(),
            nonce: again["nonce"].as_str().unwrap().into(),
            ephemeral_pub: again["ephemeral_pub"].as_str().unwrap().into(),
        };
        let answer = delivery::accept(bob.as_ref(), "u", alice.did, &alice.public(), ContactRequest::CarryMessage { sealed }).await;
        assert!(matches!(answer, ContactResponse::SignedSealed { stored: false, .. }), "{answer:?}");
        assert_eq!(bob.tree.lock().unwrap().len(), 2, "a retried copy files no second file");
    }

    /// A share whose bytes do not match the digest it carries, signed by Alice.
    fn a_share_that_does_not_hold(alice: &Node) -> SealedDm {
        let bob = alice.peer();
        let mut manifest = crate::share::Manifest::of_file("beach.jpg", b"the photo", None).unwrap();
        manifest.digest = crate::share::digest_of(b"another photo");
        let inner = DmInner {
            from_did: alice.did.into(),
            to_did: bob.did.into(),
            thread_id: "t".into(),
            sent_at: 1,
            kind: crate::share::MESSAGE_TYPE.into(),
            text: "beach.jpg".into(),
            channel: None,
            grant: None,
            reach: None,
            ack: None,
            kel: Vec::new(),
            share: Some(manifest),
            range: None,
        };
        envelope::seal(&inner, &alice.identity, &bob.public()).unwrap()
    }

    /// Clause (3): a mismatched digest files nothing — no file, no message —
    /// and is told as a refused share naming the sender as Bob's card does; at
    /// the door and from the vault alike.
    #[tokio::test]
    async fn a_share_whose_digest_does_not_hold_files_nothing_and_names_the_sender() {
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        bob.card_names.lock().unwrap().push((alice.did.into(), "Alice".into()));

        let sealed = a_share_that_does_not_hold(&alice);
        let answer = delivery::accept(bob.as_ref(), "u", alice.did, &alice.public(), ContactRequest::CarryMessage { sealed }).await;
        let ContactResponse::Declined { reason } = answer else { panic!("{answer:?}") };
        assert!(reason.contains("a share from Alice was refused") && reason.contains("nothing was filed"), "{reason}");

        let held = PendingDelivery { handle_did: "did:key:door".into(), sealed: a_share_that_does_not_hold(&alice) };
        assert_eq!(delivery::file_from_vault(bob.as_ref(), "u", &held).await, Ok(false), "taken off the vault, not filed");

        assert!(bob.tree.lock().unwrap().is_empty(), "no file");
        assert_eq!(bob.filed(), 0, "no message");
    }

    /// Clause (2) and (3): with no device of Bob's awake, a share waits at his
    /// vault as a message does — Alice reads *sent* and keeps it in her outbox —
    /// and his device files it on the next pickup and signs for it.
    #[tokio::test]
    async fn a_share_waits_at_their_vault_and_is_filed_on_the_next_pickup() {
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        bob.awake.store(false, Ordering::SeqCst);
        bob.vault.store(true, Ordering::SeqCst);

        let answer = alice_shares(&alice, "receipt.pdf", b"%PDF-1.7 the receipt", "Documents/receipt.pdf").await;
        let UserResponse::MessageSent { delivery, .. } = answer else { panic!("{answer:?}") };
        assert_eq!(delivery, Some(Delivery::Sent));
        assert_eq!(alice.outbox.lock().unwrap().len(), 1, "kept until a device of his signs for it");
        assert!(bob.tree.lock().unwrap().is_empty(), "nothing filed while every device sleeps");

        let sealed = bob.held.lock().unwrap().pop().expect("the vault holds it");
        let held = PendingDelivery { handle_did: "did:key:door".into(), sealed };
        assert_eq!(delivery::file_from_vault(bob.as_ref(), "u", &held).await, Ok(true));
        assert_eq!(
            *bob.tree.lock().unwrap(),
            vec![("Shared with you/alice/receipt.pdf".to_string(), b"%PDF-1.7 the receipt".to_vec())]
        );
        assert!(alice.outbox.lock().unwrap().is_empty(), "signed for back over her door");
    }

    /// A share of the largest size carried inline fits the frame it travels
    /// in; one byte more streams instead. Above what the recipient's store
    /// files in one piece, a share is refused before anything is sealed, kept
    /// or handed over, with a sentence that says so.
    #[tokio::test]
    async fn a_share_at_the_inline_cap_fits_its_frame_and_one_above_what_the_store_holds_is_refused() {
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        // `message_share` makes its manifest before anything else, so this is
        // the refusal it answers with; asked of the manifest directly, so the
        // zeroed quarter-gigabyte is never copied.
        let refused = crate::share::Manifest::of_file("film.mov", &vec![0u8; crate::share::STREAM_MAX + 1], None);
        assert!(refused.unwrap_err().contains("at most 256.0 MiB"));

        bob.awake.store(false, Ordering::SeqCst);
        bob.vault.store(true, Ordering::SeqCst);
        let big = vec![7u8; crate::share::INLINE_MAX];
        alice_shares(&alice, "film.mov", &big, "Films/film.mov").await;
        let sealed = bob.held.lock().unwrap().pop().unwrap();
        let frame = serde_json::to_vec(&ContactRequest::CarryMessage { sealed }).unwrap();
        assert!(frame.len() < crate::share::FRAME_CAP, "{} bytes in a {} byte frame", frame.len(), crate::share::FRAME_CAP);
    }

    /// A share from Alice whose manifest names `name`, signed by her: the bytes
    /// hold, and the name is whatever she said.
    fn a_share_named(alice: &Node, name: &str) -> SealedDm {
        let bob = alice.peer();
        let mut manifest = crate::share::Manifest::of_file("beach.jpg", b"the photo", None).unwrap();
        manifest.name = name.into();
        let inner = DmInner {
            from_did: alice.did.into(),
            to_did: bob.did.into(),
            thread_id: "t".into(),
            sent_at: 1,
            kind: crate::share::MESSAGE_TYPE.into(),
            text: name.into(),
            channel: None,
            grant: None,
            reach: None,
            ack: None,
            kel: Vec::new(),
            share: Some(manifest),
            range: None,
        };
        envelope::seal(&inner, &alice.identity, &bob.public()).unwrap()
    }

    /// A share whose name is not one plain segment files nothing on the
    /// recipient's node — no file, no message — and is declined naming the
    /// sender, at the door and from the vault alike. `". .."` is the name that
    /// would have composed `Shared with you/Alice/..`, which the store's path
    /// normalisation collapses onto *Shared with you* itself.
    #[tokio::test]
    async fn a_share_whose_name_is_not_one_plain_segment_files_nothing_and_names_the_sender() {
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        bob.card_names.lock().unwrap().push((alice.did.into(), "Alice".into()));
        for name in [". ..", " . . ", ". .x", "..", "a/b", ".hidden", ""] {
            let sealed = a_share_named(&alice, name);
            let answer = delivery::accept(bob.as_ref(), "u", alice.did, &alice.public(), ContactRequest::CarryMessage { sealed }).await;
            let ContactResponse::Declined { reason } = answer else { panic!("{name:?}: {answer:?}") };
            assert!(reason.contains("a share from Alice was refused"), "{name:?}: {reason}");
            let held = PendingDelivery { handle_did: "did:key:door".into(), sealed: a_share_named(&alice, name) };
            assert_eq!(delivery::file_from_vault(bob.as_ref(), "u", &held).await, Ok(false), "{name:?}");
        }
        assert!(bob.tree.lock().unwrap().is_empty(), "{:?}", bob.tree.lock().unwrap());
        assert_eq!(bob.filed(), 0, "no message");
    }

    /// A card name the rule refuses is *no usable name*: the share is taken, and
    /// its folder is the record's default for a nameless card — the first eight
    /// characters of the sender's AID — never the card's word cleaned up, which
    /// is another contact's folder as easily as theirs. A friend whose name was
    /// announced with a stray space loses no share for it.
    #[tokio::test]
    async fn a_card_name_the_rule_refuses_names_no_folder_and_the_share_lands_under_the_aid() {
        for card in [". .x", "Alice ", ".Alice", "Al/ice"] {
            let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
            pair(&alice, &bob);
            bob.card_names.lock().unwrap().push((alice.did.into(), card.into()));
            bob.tree.lock().unwrap().push(("Shared with you/x/beach.jpg".into(), b"x's photo".to_vec()));
            let answer = delivery::accept(
                bob.as_ref(),
                "u",
                alice.did,
                &alice.public(),
                ContactRequest::CarryMessage { sealed: a_share_named(&alice, "beach.jpg") },
            )
            .await;
            assert!(matches!(answer, ContactResponse::SignedSealed { stored: true, .. }), "{card:?}: {answer:?}");
            assert_eq!(
                *bob.tree.lock().unwrap(),
                vec![
                    ("Shared with you/x/beach.jpg".to_string(), b"x's photo".to_vec()),
                    ("Shared with you/alice/beach.jpg".to_string(), b"the photo".to_vec()),
                ],
                "{card:?}: the share did not land under the AID's folder alone"
            );
            assert_eq!(bob.filed(), 1, "{card:?}");
        }
    }

    /// The sender's node refuses a name that is not one plain segment before
    /// anything is sealed, kept or handed over, with a sentence naming the rule.
    #[tokio::test]
    async fn a_share_named_outside_one_plain_segment_is_refused_before_it_is_sealed() {
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        for name in [". ..", " . . ", ". .x", "..", "a/b", "a\\b", "be\u{7}ach.jpg", ""] {
            let answer = alice_shares(&alice, name, b"the photo", "Photos/x").await;
            let UserResponse::Error { message } = answer else { panic!("{name:?}: {answer:?}") };
            assert!(message.contains("one plain segment"), "{name:?}: {message}");
        }
        assert_eq!((alice.filed(), alice.handed()), (0, 0), "nothing kept, nothing handed over");
        assert!(bob.tree.lock().unwrap().is_empty());
    }

    // ── Above the inline cap: a share whose bytes stream ───────────────────
    // (`TASK-a-share-above-the-frame-cap-arrives-whole-by-the-streaming-transport`)

    /// A file a little over two ranges long — three ranges, the last short —
    /// and above the inline cap, so it streams. Not text, so a transfer that
    /// re-encoded it anywhere fails the comparison.
    fn a_film(seed: u8) -> Vec<u8> {
        let len = 2 * crate::share::RANGE_LEN + 12_345;
        assert!(len > crate::share::INLINE_MAX);
        (0..len).map(|i| ((i as u32).wrapping_mul(2_654_435_761) >> 24) as u8 ^ seed).collect()
    }

    /// The manifest of a streamed share of `bytes` from Alice to Bob, sealed by
    /// hand as `message_share` seals one, with `digest` where it names its
    /// stream: the bytes' own, unless a test says otherwise.
    fn a_streamed_manifest(alice: &Node, bytes: &[u8], digest: &str) -> SealedDm {
        let mut manifest = crate::share::Manifest::of_file("film.mov", bytes, None).unwrap();
        manifest.digest = digest.into();
        manifest.stream = Some(digest.into());
        sealed_by_alice(alice, Some(manifest), None)
    }

    /// The ranges `bytes` follow the manifest `share` as, naming `digest`.
    fn its_ranges(alice: &Node, bytes: &[u8], digest: &str, share: &SealedDm) -> Vec<SealedDm> {
        crate::share::ranges(digest, &share.ephemeral_pub, bytes)
            .into_iter()
            .map(|r| sealed_by_alice(alice, None, Some(r)))
            .collect()
    }

    fn sealed_by_alice(
        alice: &Node,
        share: Option<crate::share::Manifest>,
        range: Option<crate::share::Range>,
    ) -> SealedDm {
        let bob = alice.peer();
        let inner = DmInner {
            from_did: alice.did.into(),
            to_did: bob.did.into(),
            thread_id: "t".into(),
            sent_at: 1,
            kind: crate::share::MESSAGE_TYPE.into(),
            text: String::new(),
            channel: None,
            grant: None,
            reach: None,
            ack: None,
            kel: Vec::new(),
            share,
            range,
        };
        envelope::seal(&inner, &alice.identity, &bob.public()).unwrap()
    }

    async fn at_bobs_door(alice: &Node, sealed: SealedDm) -> ContactResponse {
        let bob = alice.peer();
        delivery::accept(bob.as_ref(), "u", alice.did, &alice.public(), ContactRequest::CarryMessage { sealed }).await
    }

    /// Clauses (1) and (2): a file above the inline cap goes as its manifest —
    /// `stream` set, `inline` absent — and its bytes follow as ranges over the
    /// same door; a device of Bob's keeps them, files the copy under *Shared
    /// with you* byte-identical once they are whole and hash to the digest,
    /// and signs for it: Alice reads *delivered*, and nothing of the share is
    /// left in her outbox or on his shelf. The conversation holds one message,
    /// the share; no range is filed as one.
    #[tokio::test]
    async fn a_share_above_the_inline_cap_arrives_whole_as_ranges_and_is_filed_once_its_digest_holds() {
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        bob.card_names.lock().unwrap().push((alice.did.into(), "Alice".into()));
        let film = a_film(1);

        let answer = alice_shares(&alice, "film.mov", &film, "Films/film.mov").await;
        let UserResponse::MessageSent { delivery, .. } = answer else { panic!("{answer:?}") };
        assert_eq!(delivery, Some(Delivery::Delivered), "a device of Bob's signed for the share");

        assert_eq!(*bob.tree.lock().unwrap(), vec![("Shared with you/Alice/film.mov".to_string(), film.clone())]);
        assert_eq!(bob.filed(), 1, "one message, the share; no range is a message");
        let theirs = bob.records.lock().unwrap()[0].clone();
        let manifest = serde_json::from_str::<DmInner>(&opened_plaintext(&theirs, &bob.identity)).unwrap().share.unwrap();
        assert_eq!(manifest.inline, None, "the bytes are not inside the manifest");
        assert_eq!(manifest.stream.as_deref(), Some(crate::share::digest_of(&film).as_str()));
        assert_eq!(manifest.origin, None);

        // Manifest first, then three ranges, then the manifest again.
        assert_eq!(alice.handed(), 5, "{:?}", alice.said.lock().unwrap());
        assert!(alice.outbox.lock().unwrap().is_empty(), "every range and the share signed for");
        assert!(bob.shelf.lock().unwrap().is_empty(), "nothing of the stream left on his shelf");
        let readings = readings(alice.as_ref(), "u", bob.did).await.unwrap();
        assert_eq!(words(&readings), vec![("1", "delivered")], "the share reads as one message");
    }

    /// Clause (3), RFC-0048 ST4: what crosses the door for a streamed share is
    /// what crosses it for a message — every piece said as `CarryMessage`, an
    /// ephemeral key, a nonce and ciphertext and nothing else, each frame under
    /// the cap, the ranges on fixed boundaries so their frames are one size —
    /// and nothing in any frame names the file, the share, its stream or a
    /// byte of it. Each range opens only for Bob, signed by Alice: sealed as
    /// the message is.
    #[tokio::test]
    async fn every_range_crosses_as_a_message_does_sealed_to_them_under_the_frame_cap() {
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        let film = a_film(2);
        alice_shares(&alice, "film.mov", &film, "Films/film.mov").await;
        let frames = alice.frames.lock().unwrap().clone();
        assert_eq!(frames.len(), 5, "the manifest, three ranges, the manifest again");
        crate::daemon::messages::message_send(alice.as_ref(), "u".into(), bob.did.into(), "the milk".into(), None)
            .await
            .unwrap();
        let message = alice.frames.lock().unwrap().pop().unwrap();

        // The request's variant, its fields, and the sealed message's fields.
        let shape = |frame: &str| -> Vec<String> {
            let v: serde_json::Value = serde_json::from_str(frame).unwrap();
            let (said, body) = v.as_object().unwrap().iter().next().map(|(k, v)| (k.clone(), v.clone())).unwrap();
            let mut fields: Vec<String> = body.as_object().unwrap().keys().cloned().collect();
            let mut sealed: Vec<String> = body["sealed"].as_object().unwrap().keys().cloned().collect();
            fields.sort();
            sealed.sort();
            std::iter::once(said).chain(fields).chain(sealed).collect()
        };
        assert_eq!(shape(&message), ["CarryMessage", "sealed", "body", "ephemeral_pub", "nonce"]);
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        // On a three-byte boundary of its range, so a range carried in the clear
        // would carry exactly this text.
        let a_byte_of_it = B64.encode(&film[999..1_047]);
        // Quoted, or holding a `.`: words base64 cannot spell by chance.
        let names = ["film.mov", "\"share\"", "\"range\"", "\"digest\"", "\"stream\"", "\"offset\""];
        for frame in &frames {
            assert_eq!(shape(frame), shape(&message), "a piece of the share crossed shaped otherwise than a message");
            assert!(frame.len() < crate::share::FRAME_CAP, "{} bytes in a {} byte frame", frame.len(), crate::share::FRAME_CAP);
            for never in names.iter().copied().chain([a_byte_of_it.as_str()]) {
                assert!(!frame.contains(never), "a frame carries {never:?} outside the seal");
            }
        }
        let (full_a, full_b) = (frames[1].len(), frames[2].len());
        assert!(full_a.abs_diff(full_b) <= 16, "two full ranges crossed as {full_a} and {full_b} bytes");

        // Sealed to Bob, signed by Alice, as the manifest is — and not to anyone else.
        for frame in &frames[1..4] {
            let ContactRequest::CarryMessage { sealed } = serde_json::from_str(frame).unwrap() else { panic!() };
            let inner = envelope::open(&sealed, &bob.identity, &alice.public()).expect("opens for Bob, signed by Alice");
            let range = inner.range.expect("a range");
            assert_eq!(range.digest, crate::share::digest_of(&film));
            assert!(envelope::open(&sealed, &alice.identity, &alice.public()).is_err(), "it opens for its sender");
        }
    }

    /// Clause (2): a stream cut off part way files nothing — no file, no
    /// message — and the share reads as not signed for: *sent*, because Bob's
    /// node holds its manifest waiting for the bytes. What Bob was handed is
    /// kept toward the stream and signed for; what he was not waits in Alice's
    /// outbox.
    #[tokio::test]
    async fn a_stream_cut_off_part_way_files_nothing_and_the_share_is_not_signed_for() {
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        // The manifest and the first range are answered; then the connection drops.
        *alice.answers.lock().unwrap() = Some(2);

        let answer = alice_shares(&alice, "film.mov", &a_film(3), "Films/film.mov").await;
        let UserResponse::MessageSent { delivery, .. } = answer else { panic!("{answer:?}") };
        assert_eq!(delivery, Some(Delivery::Sent), "held waiting for its bytes, and signed for by nobody");
        assert!(bob.tree.lock().unwrap().is_empty(), "a stream that never completed filed a file");
        assert_eq!(bob.filed(), 0, "a stream that never completed filed a message");
        let shelf: Vec<String> = bob.shelf.lock().unwrap().keys().cloned().collect();
        assert_eq!(shelf.len(), 2, "the manifest waiting and the one range handed: {shelf:?}");
        assert_eq!(alice.outbox.lock().unwrap().len(), 3, "the manifest and the two ranges nobody signed for");
        let readings = readings(alice.as_ref(), "u", bob.did).await.unwrap();
        assert_eq!(words(&readings), vec![("1", "sent")]);
    }

    /// A stream cut off resumes from the first range nobody signed for: the
    /// next pass hands the two ranges Bob lacks and the manifest, and never the
    /// range he signed for — and the share is filed whole, byte-identical.
    #[tokio::test]
    async fn a_stream_cut_off_resumes_where_it_stopped_and_not_from_byte_zero() {
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        let film = a_film(4);
        *alice.answers.lock().unwrap() = Some(2);
        alice_shares(&alice, "film.mov", &film, "Films/film.mov").await;
        let first_range = alice.dialled.lock().unwrap()[1].1.clone();

        *alice.answers.lock().unwrap() = None;
        alice.dialled.lock().unwrap().clear();
        let unsigned: Vec<String> =
            alice.outbox.lock().unwrap().iter().filter(|e| e.part_of.is_some()).map(|e| e.id.clone()).collect();
        assert_eq!(unsigned.len(), 2);
        // The manifest, the two ranges Bob lacks, and the manifest again once they are whole.
        assert_eq!(retry_due(alice.as_ref(), "u", u64::MAX, NOW_AGAIN).await, 4);
        let resumed: Vec<String> = alice.dialled.lock().unwrap().iter().map(|(_, id)| id.clone()).collect();
        let mut ranges: Vec<&String> = resumed.iter().filter(|id| unsigned.contains(id) || **id == first_range).collect();
        let mut expected: Vec<&String> = unsigned.iter().collect();
        ranges.sort();
        expected.sort();
        assert_eq!(ranges, expected, "the ranges handed again: {resumed:?}");
        assert!(!resumed.contains(&first_range), "the range Bob signed for was sent again");

        assert_eq!(*bob.tree.lock().unwrap(), vec![("Shared with you/alice/film.mov".to_string(), film)]);
        assert_eq!(bob.filed(), 1);
        assert!(alice.outbox.lock().unwrap().is_empty());
        assert!(bob.shelf.lock().unwrap().is_empty());
    }

    /// Clause (2): a stream whose bytes do not hash to the digest its manifest
    /// carries files nothing, and is declined naming the sender — at the
    /// manifest that would have filed it, and at every try after.
    #[tokio::test]
    async fn a_stream_whose_bytes_do_not_hold_files_nothing_and_names_the_sender() {
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        bob.card_names.lock().unwrap().push((alice.did.into(), "Alice".into()));
        let film = a_film(5);
        let other = crate::share::digest_of(b"another film");
        let manifest = a_streamed_manifest(&alice, &film, &other);
        let ranges = its_ranges(&alice, &film, &other, &manifest);

        let first = at_bobs_door(&alice, manifest.clone()).await;
        assert!(matches!(first, ContactResponse::Delivered { stored: false, ack: None }), "kept waiting: {first:?}");
        for range in ranges {
            at_bobs_door(&alice, range).await;
        }
        let again = at_bobs_door(&alice, manifest).await;
        let ContactResponse::Declined { reason } = again else { panic!("{again:?}") };
        assert!(reason.contains("a share from Alice was refused") && reason.contains("digest"), "{reason}");
        assert!(bob.tree.lock().unwrap().is_empty(), "no file");
        assert_eq!(bob.filed(), 0, "no message");
        assert!(
            bob.shelf.lock().unwrap().keys().all(|k| k.ends_with(".refused")),
            "its bytes let go, its refusal kept: {:?}",
            bob.shelf.lock().unwrap().keys().collect::<Vec<_>>()
        );
    }

    /// With every device of Bob's asleep a streamed share waits at his vault —
    /// manifest and ranges, each *sent* — and his device files it whole on the
    /// next pickup and signs for it back over Alice's door. A range picked up
    /// before the share it is part of is taken off the vault and not kept; it
    /// stays in Alice's outbox, and her next try hands it to his door.
    #[tokio::test]
    async fn a_streamed_share_waits_at_their_vault_and_a_range_ahead_of_its_share_is_sent_again() {
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        bob.awake.store(false, Ordering::SeqCst);
        bob.vault.store(true, Ordering::SeqCst);
        let film = a_film(6);

        let answer = alice_shares(&alice, "film.mov", &film, "Films/film.mov").await;
        let UserResponse::MessageSent { delivery, .. } = answer else { panic!("{answer:?}") };
        assert_eq!(delivery, Some(Delivery::Sent));
        // Held: the manifest, three ranges, and the manifest's second try.
        let mut held = std::mem::take(&mut *bob.held.lock().unwrap());
        assert_eq!(held.len(), 5);
        // The first range ahead of its manifest at the pickup.
        held.swap(0, 1);
        for sealed in held {
            let delivery = PendingDelivery { handle_did: "did:key:door".into(), sealed };
            assert!(delivery::file_from_vault(bob.as_ref(), "u", &delivery).await.is_ok(), "taken off the vault");
        }
        assert!(bob.tree.lock().unwrap().is_empty(), "filed with its first range missing");
        assert_eq!(alice.outbox.lock().unwrap().len(), 2, "the manifest and the range not kept wait in her outbox");

        // Bob is back, and Alice's next pass hands the range to his door.
        bob.awake.store(true, Ordering::SeqCst);
        retry_due(alice.as_ref(), "u", u64::MAX, NOW_AGAIN).await;
        assert_eq!(*bob.tree.lock().unwrap(), vec![("Shared with you/alice/film.mov".to_string(), film)]);
        assert_eq!(bob.filed(), 1);
        assert!(alice.outbox.lock().unwrap().is_empty());
        let readings = readings(alice.as_ref(), "u", bob.did).await.unwrap();
        assert_eq!(words(&readings), vec![("1", "delivered")]);
    }

    /// **A share Alice's vault carries while every device of hers sleeps is
    /// filed whole on Bob's node, and every signature reaches her pickup**
    /// (`TASK-a-senders-vault-carries-a-shares-ranges-while-no-device-of-theirs-is-awake`,
    /// clause 1). Her outbox holds the manifest and its three ranges; the vault
    /// says each at Bob's door as `CarryMessage`, as it says any message. A
    /// range that reaches the door ahead of its share — the vault dials in the
    /// order it was handed, and the manifest's own dial can still fail first —
    /// is refused as something that may clear: not kept, not declined, so the
    /// vault tries it again. Once the manifest waits there, each range is kept
    /// and signed for **sealed to Alice**; the last files the share; and the
    /// manifest's next try is signed for the same way. Alice's pickup takes
    /// the signatures: her outbox is empty and the share reads *delivered*.
    #[tokio::test]
    async fn a_share_her_vault_carries_while_she_sleeps_is_filed_whole_and_signed_for_at_her_pickup() {
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        bob.awake.store(false, Ordering::SeqCst);
        let film = a_film(8);
        let answer = alice_shares(&alice, "film.mov", &film, "Films/film.mov").await;
        let UserResponse::MessageSent { delivery, .. } = answer else { panic!("{answer:?}") };
        assert!(matches!(delivery, Some(Delivery::Unreachable { .. })), "{delivery:?}");
        let held = alice.outbox.lock().unwrap().clone();
        let manifest = held.iter().find(|e| e.part_of.is_none()).unwrap().sealed.clone();
        let ranges: Vec<SealedDm> = held.iter().filter(|e| e.part_of.is_some()).map(|e| e.sealed.clone()).collect();
        assert_eq!(ranges.len(), 3);

        // Alice's devices are asleep; her vault carries. Bob is back.
        let ahead = at_bobs_door(&alice, ranges[0].clone()).await;
        assert!(matches!(ahead, ContactResponse::Refused { .. }), "a range ahead of its share: {ahead:?}");
        assert!(bob.shelf.lock().unwrap().is_empty(), "a range ahead of its share was kept");
        let waiting = at_bobs_door(&alice, manifest.clone()).await;
        assert!(matches!(waiting, ContactResponse::Delivered { stored: false, ack: None }), "{waiting:?}");
        let mut signatures = Vec::new();
        for range in &ranges {
            let answer = at_bobs_door(&alice, range.clone()).await;
            let ContactResponse::SignedSealed { stored: true, ack } = answer else { panic!("{answer:?}") };
            signatures.push((range.ephemeral_pub.clone(), ack));
        }
        assert_eq!(*bob.tree.lock().unwrap(), vec![("Shared with you/alice/film.mov".to_string(), film)]);
        let again = at_bobs_door(&alice, manifest.clone()).await;
        let ContactResponse::SignedSealed { ack, .. } = again else { panic!("the manifest, once whole: {again:?}") };
        signatures.push((manifest.ephemeral_pub.clone(), ack));
        assert_eq!(bob.filed(), 1, "one message, the share");
        assert!(bob.shelf.lock().unwrap().is_empty(), "nothing of the stream left on his shelf");

        // Sealed to Alice, each signing for what was carried; her pickup takes them.
        for (id, ack) in signatures {
            let signed = envelope::open(&ack, &alice.identity, &bob.public()).expect("sealed to Alice, by Bob");
            assert_eq!(signed.ack.expect("a signature").message_id, id);
            let delivery = PendingDelivery { handle_did: String::new(), sealed: ack };
            assert!(delivery::file_from_vault(alice.as_ref(), "u", &delivery).await.unwrap(), "{id} not taken");
        }
        assert!(alice.outbox.lock().unwrap().is_empty(), "every range and the share signed for");
        let readings = readings(alice.as_ref(), "u", bob.did).await.unwrap();
        assert_eq!(words(&readings), vec![("1", "delivered")]);
    }

    /// What a contact can make this node hold is bounded: a range is kept only
    /// for a share whose manifest is waiting, and one contact has at most
    /// `STREAMS_PER_CONTACT` waiting at once; one more is refused as something
    /// that clears with time.
    #[tokio::test]
    async fn a_contact_can_make_this_node_hold_only_bytes_of_shares_it_declared_and_only_so_many() {
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        let film = a_film(7);
        let digest = crate::share::digest_of(&film);
        let first = crate::share::ranges(&digest, "a share nobody declared", &film).remove(0);
        let undeclared = at_bobs_door(&alice, sealed_by_alice(&alice, None, Some(first))).await;
        assert!(matches!(undeclared, ContactResponse::Refused { .. }), "{undeclared:?}");
        assert!(bob.shelf.lock().unwrap().is_empty(), "kept bytes of a share nobody declared");

        for seed in 0..crate::daemon::stream::STREAMS_PER_CONTACT as u8 {
            let film = a_film(10 + seed);
            let waiting = at_bobs_door(&alice, a_streamed_manifest(&alice, &film, &crate::share::digest_of(&film))).await;
            assert!(matches!(waiting, ContactResponse::Delivered { ack: None, .. }), "{waiting:?}");
        }
        let one_more = a_film(99);
        let refused = at_bobs_door(&alice, a_streamed_manifest(&alice, &one_more, &crate::share::digest_of(&one_more))).await;
        assert!(matches!(refused, ContactResponse::Refused { .. }), "{refused:?}");
    }

    // ── The assessor's refusal at e8a897d (2026-10-08) ──────────────────────

    /// A keeper pass that runs while the first send is still handing a share's
    /// ranges does not hand them too: each range crosses once, and the send
    /// reads *delivered*, not the *sent* a range refused after the share was
    /// filed would leave it at.
    #[tokio::test]
    async fn a_keeper_pass_during_the_first_send_does_not_hand_the_same_ranges() {
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        let film = a_film(20);
        // During the first range's dial.
        *alice.keeper_at.lock().unwrap() = Some(2);
        let answer = alice_shares(&alice, "film.mov", &film, "Films/film.mov").await;
        let UserResponse::MessageSent { delivery, .. } = answer else { panic!("{answer:?}") };
        assert_eq!(delivery, Some(Delivery::Delivered), "the share was filed whole and signed for");
        let mut ids: Vec<String> = alice.dialled.lock().unwrap().iter().map(|(_, id)| id.clone()).collect();
        let dialled = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(dialled - ids.len(), 1, "only the manifest's second try repeats an id: {dialled} dials, {} ids", ids.len());
        assert_eq!(*bob.tree.lock().unwrap(), vec![("Shared with you/alice/film.mov".to_string(), film)]);
        assert!(alice.outbox.lock().unwrap().is_empty());
    }

    /// A range signed for on another path while this path's try failed is
    /// signed for: it is not written back into the outbox to be sent again for
    /// ever, and the send goes on to the rest.
    #[tokio::test]
    async fn a_range_signed_for_on_another_path_while_this_try_failed_is_not_written_back() {
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        let film = a_film(21);
        // The second range: another path hands it and has it signed for, and this one drops.
        *alice.taken_elsewhere_at.lock().unwrap() = Some(3);
        let answer = alice_shares(&alice, "film.mov", &film, "Films/film.mov").await;
        let taken = alice.dialled.lock().unwrap()[2].1.clone();
        assert!(
            !alice.outbox.lock().unwrap().iter().any(|e| e.id == taken),
            "a range signed for came back into the outbox"
        );
        let UserResponse::MessageSent { delivery, .. } = answer else { panic!("{answer:?}") };
        assert_eq!(delivery, Some(Delivery::Delivered));
        assert_eq!(*bob.tree.lock().unwrap(), vec![("Shared with you/alice/film.mov".to_string(), film)]);
    }

    /// A range of a share already filed is answered as held and signed for —
    /// a verdict the sender drops it on — never as something to try again.
    #[tokio::test]
    async fn a_range_of_a_share_already_filed_is_signed_for_and_not_asked_for_again() {
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        alice_shares(&alice, "film.mov", &a_film(22), "Films/film.mov").await;
        assert_eq!(bob.filed(), 1);
        let ContactRequest::CarryMessage { sealed: range } =
            serde_json::from_str(&alice.frames.lock().unwrap()[1]).unwrap()
        else {
            panic!()
        };
        let again = at_bobs_door(&alice, range).await;
        assert!(matches!(again, ContactResponse::SignedSealed { stored: false, .. }), "{again:?}");
    }

    /// A range answers as held only for a share its own sender's message
    /// filed: one from someone else naming Alice's filed share is not signed
    /// for, so nobody learns from Bob's door whether a message another person
    /// sent him was filed.
    #[tokio::test]
    async fn a_range_naming_a_share_someone_else_sent_is_not_signed_for() {
        let (alice, bob, carol) = (node("did:kel:alice", 1), node("did:kel:bob", 2), node("did:kel:carol", 3));
        pair(&alice, &bob);
        alice_shares(&alice, "film.mov", &a_film(24), "Films/film.mov").await;
        assert_eq!(bob.filed(), 1);
        let alices = bob.records.lock().unwrap()[0]["ephemeral_pub"].as_str().unwrap().to_string();
        let bytes = a_film(25);
        let range = crate::share::ranges(&crate::share::digest_of(&bytes), &alices, &bytes).remove(0);
        let inner = DmInner {
            from_did: carol.did.into(),
            to_did: bob.did.into(),
            thread_id: "t".into(),
            sent_at: 1,
            kind: crate::share::MESSAGE_TYPE.into(),
            text: String::new(),
            channel: None,
            grant: None,
            reach: None,
            ack: None,
            kel: Vec::new(),
            share: None,
            range: Some(range),
        };
        // Carol is a contact of Bob's: a door Bob's node opened for her.
        bob.other_cards.lock().unwrap().push((carol.did.to_string(), carol.public()));
        let sealed = envelope::seal(&inner, &carol.identity, &bob.public()).unwrap();
        let answer =
            delivery::accept(bob.as_ref(), "u", carol.did, &carol.public(), ContactRequest::CarryMessage { sealed }).await;
        assert!(matches!(answer, ContactResponse::Refused { .. }), "a share Alice sent, answered to Carol: {answer:?}");
    }

    /// Two shares of the same bytes from one person, the second's manifest
    /// arriving while the first waits for its ranges, are two shares: both are
    /// filed, and nothing of either is left waiting.
    #[tokio::test]
    async fn two_shares_of_the_same_bytes_from_one_sender_are_both_filed() {
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        bob.awake.store(false, Ordering::SeqCst);
        bob.vault.store(true, Ordering::SeqCst);
        let film = a_film(23);
        alice_shares(&alice, "film.mov", &film, "Films/film.mov").await;
        alice_shares(&alice, "film.mov", &film, "Films/film.mov").await;
        // Each share held as its manifest, three ranges, its manifest again.
        let held = std::mem::take(&mut *bob.held.lock().unwrap());
        assert_eq!(held.len(), 10);
        // Both manifests first, then every range.
        let order = [0, 5, 1, 2, 3, 6, 7, 8, 4, 9];
        for i in order {
            let delivery = PendingDelivery { handle_did: "did:key:door".into(), sealed: held[i].clone() };
            assert!(delivery::file_from_vault(bob.as_ref(), "u", &delivery).await.is_ok());
        }
        let mut tree: Vec<String> = bob.tree.lock().unwrap().iter().map(|(p, _)| p.clone()).collect();
        tree.sort();
        assert_eq!(tree, ["Shared with you/alice/film 2.mov", "Shared with you/alice/film.mov"]);
        assert!(bob.shelf.lock().unwrap().is_empty(), "{:?}", bob.shelf.lock().unwrap().keys().collect::<Vec<_>>());
    }

    /// What one contact can make this node hold waiting is bounded in bytes,
    /// not only in shares.
    #[tokio::test]
    async fn a_contact_can_have_only_so_many_bytes_waiting() {
        let (alice, bob) = (node("did:kel:alice", 1), node("did:kel:bob", 2));
        pair(&alice, &bob);
        let declared = |seed: u8| {
            let digest = crate::share::digest_of(&[seed]);
            let manifest = crate::share::Manifest {
                name: format!("film {seed}.mov"),
                kind: crate::share::KIND_FILE.into(),
                mime: "video/quicktime".into(),
                size: 200 * 1024 * 1024,
                digest: digest.clone(),
                inline: None,
                stream: Some(digest),
                origin: None,
            };
            sealed_by_alice(&alice, Some(manifest), None)
        };
        for seed in [1, 2] {
            let waiting = at_bobs_door(&alice, declared(seed)).await;
            assert!(matches!(waiting, ContactResponse::Delivered { ack: None, .. }), "{waiting:?}");
        }
        let third = at_bobs_door(&alice, declared(3)).await;
        assert!(matches!(third, ContactResponse::Refused { .. }), "600 MiB waiting from one contact: {third:?}");
    }
}
