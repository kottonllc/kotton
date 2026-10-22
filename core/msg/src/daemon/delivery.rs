// SPDX-License-Identifier: AGPL-3.0-or-later
//! Taking delivery of a message from another person (`DEC-0055`, `DEC-0056`).
//!
//! The counterpart of [`super::messages::message_send`]: that seals a message
//! and keeps the sender's copy, this files the recipient's. Between them is one
//! verb on a per-pair mailbox, and nothing that holds the message on the way
//! (`RFC-0083`).
//!
//! **What this trusts, and what it checks.** The channel proved the caller
//! holds the identity key of the contact whose mailbox this is — the mailbox's
//! verifier admits that one key. What arrives says nothing on its outside
//! (RFC-0064 MS7): the sender, the recipient, the thread and the time are
//! inside the seal, signed. So this opens it, checks the signature against the
//! contact's key, checks that the message is addressed here and names that
//! contact as its sender, and files it if it has not been filed already. A
//! message that opens but was signed by someone else is a forgery and is
//! refused — the case `DEC-0056` exists for, where a node holding the pair's
//! handle keys can answer the door but must not be able to speak through it.

use kotton_wire::ipc::{ContactRequest, ContactResponse, SealedDm};
use serde_json::Value;

use kotton_common::namespace::{NSID_CHANNEL_KEY_GRANT, NSID_MESSAGE_V1};

use super::messages::{
    co_member, current_members, filed_record, leave_not_yet, load_user_signing_key, open_channel_copy, own_grants,
    roster_admits, roster_changed, rotate_for_leave, unwrap_own_grant, AfterLeave, MessageHost, NotKept, Opened, Rosters, LEAVE_TYPE,
};
use super::stream::{self, NotTaken};
use super::{filing, outbox};
use crate::envelope::{self, ChannelGrant, DmInner};
use kotton_crypto::reach_note::{Kept, ReachNote};
use kotton_wire::ipc::{Delivery, PendingDelivery};

/// Serve one request that arrived at `user_id`'s mailbox for `contact_did`,
/// whose identity key is `contact_pub` — the key the door admitted.
pub async fn accept(
    host: &dyn MessageHost,
    user_id: &str,
    contact_did: &str,
    contact_pub: &[u8; 32],
    request: ContactRequest,
) -> ContactResponse {
    match request {
        ContactRequest::DeliverMessage { sealed } => {
            deliver(host, user_id, contact_did, contact_pub, sealed).await
        }
        ContactRequest::CarryMessage { sealed } => {
            carried(host, user_id, contact_did, contact_pub, sealed).await
        }
    }
}

/// A sealed message handed over by a device of the sender's or carried here by
/// their vault while none was awake — the door cannot tell which, and that is
/// the point
/// (`TASK-a-message-stays-in-the-outbox-until-one-of-their-devices-signs-for-it`,
/// clause 3). Filed exactly as a handed-over message; only the answer differs.
/// Whoever reads it may be a carrier and not the sender, so this device's
/// signature goes back **sealed to the sender** — the same envelope a vault
/// pickup signs back with ([`outbox::ack_envelope`]) — and a carrier keeps
/// bytes it cannot open. Anything that is not a signature (a refusal, a note or
/// a grant taken) is answered as it would be at the door.
async fn carried(
    host: &dyn MessageHost,
    user_id: &str,
    contact_did: &str,
    contact_pub: &[u8; 32],
    sealed: SealedDm,
) -> ContactResponse {
    let message_id = sealed.ephemeral_pub.clone();
    match deliver(host, user_id, contact_did, contact_pub, sealed).await {
        ContactResponse::Delivered { stored, ack: Some(_) } => {
            let Some(own) = host.user_aid(user_id) else {
                return ContactResponse::Refused {
                    reason: "this identity is not available on this node".to_string(),
                };
            };
            match outbox::ack_envelope(host, user_id, &own, contact_did, contact_pub, &message_id) {
                Ok(ack) => ContactResponse::SignedSealed { stored, ack },
                // Filed, and not signed for: the carrier tries again, and the
                // copy this device now holds is signed for on that try.
                Err(reason) => ContactResponse::Refused { reason },
            }
        }
        // Not a signature — held without one, or refused — and answered as at
        // the door. A clear acknowledgement never reaches a carrier.
        other => other,
    }
}

async fn deliver(
    host: &dyn MessageHost,
    user_id: &str,
    contact_did: &str,
    contact_pub: &[u8; 32],
    sealed: SealedDm,
) -> ContactResponse {
    let refused = |reason: String| ContactResponse::Refused { reason };

    let Some(own) = host.user_aid(user_id) else {
        return refused("this identity is not available on this node".to_string());
    };
    let Some(own_key) = load_user_signing_key(user_id, host.secrets()) else {
        return refused("this identity's key is not available on this node".to_string());
    };

    // Open, and hold the signature inside to the key the door proved — or, when
    // the envelope carries the sender's key log, to the key that log proves they
    // hold now, which is the only way a card follows them through a rotation.
    let claimed = match envelope::open_claimed(&sealed, &own_key) {
        Ok(c) => c,
        Err(e) => return refused(e),
    };
    let held_to = match sender_key(host, user_id, contact_did, contact_pub, &claimed.inner.kel) {
        Ok(h) => h,
        Err(e) => return refused(e),
    };
    if let Err(e) = claimed.verify(&held_to.key) {
        return refused(e);
    }
    let inner = claimed.inner;

    // Addressed here. A mailbox is per pair, so a message for anyone else has
    // been misrouted or is an attempt to file something in a store its sender
    // cannot reach directly; both are refusals, not stores.
    if inner.to_did != own {
        return refused("that message is addressed to someone else".to_string());
    }
    // Names the sender the door belongs to. The signature proved the key; this
    // holds the claim inside to it, so a message cannot arrive wearing a third
    // party's name.
    if inner.from_did != contact_did {
        return refused(format!(
            "that message says it is from {}, and it arrived from someone else",
            inner.from_did
        ));
    }
    // A door opened for somebody this identity holds no card for — a
    // co-member, whose door a channel's roster opened (`messages::co_members`)
    // — carries that channel's copies and nothing else: not a direct message,
    // not a reach note, not a copy for a channel whose roster does not name
    // them under the key this door was opened for.
    if host.member_public_key(user_id, contact_did).await.is_none() {
        match co_member_may_say(host, user_id, contact_did, contact_pub, &inner).await {
            InEpoch::Yes => {}
            InEpoch::NotYet(reason) => return refused(reason),
            InEpoch::No(reason) => return ContactResponse::Declined { reason },
        }
    }

    // Only now, with the envelope proved theirs and addressed here, does a key
    // the log taught reach the card.
    if let Err(e) = held_to.keep(host, user_id, contact_did).await {
        return refused(e);
    }

    // A **reach note** is not a message either: where the sender can be
    // reached, signed by them, for this user's card of them. The door proved
    // who is speaking and the seal proved they wrote it; the note carries its
    // own signature as well, and the card believes it only under the key it
    // holds for them, only if newer, and never expired.
    if let Some(note) = inner.reach {
        return keep_note(host, user_id, contact_did, note).await;
    }

    // An **acknowledgement** is not a message either: one of this contact's
    // devices signing for something this user sent them, sent back this way
    // because it was picked up from their vault rather than handed to the
    // device at its door. Believed only under a device key the card's note
    // for them lists; a refusal is said, and the message stays in the outbox.
    if let Some(ack) = inner.ack {
        return match outbox::take_ack(host, user_id, contact_did, &ack.message_id, &ack).await {
            Ok(taken) => ContactResponse::Delivered { stored: taken, ack: None },
            Err(reason) => refused(reason),
        };
    }

    // A **range** of a share's bytes is not a message either: it is kept
    // toward its stream and signed for, so the sender sends it no more and a
    // stream cut off resumes where it stopped; the share it is part of is
    // filed once the last of them lands (RFC-0090, *Above the frame cap*).
    // Nothing of it goes into the conversation. A range of a share to a group
    // is a channel copy as well, and is held to its channel's rule before its
    // bytes are opened ([`range_bytes`]).
    //
    // The sender is on the line, and tries the manifest again once its ranges
    // are handed: that try is signed for here, so this one signs only for the
    // range.
    if let Some(range) = &inner.range {
        return match take_range(host, user_id, &own, &own_key, contact_did, &inner, range).await {
            Ok(stored) => {
                file_if_whole(host, user_id, contact_did, range, None).await;
                ContactResponse::Delivered {
                    stored,
                    ack: Some(host.sign_delivery_ack(&sealed.ephemeral_pub, &own, contact_did)),
                }
            }
            Err(NotTaken::Again(reason)) => refused(reason),
            Err(NotTaken::Verdict(reason)) => ContactResponse::Declined {
                reason: refusal(host, user_id, contact_did, reason).await,
            },
        };
    }

    // A **key-grant** is admission, not a message: it is filed in the grants
    // namespace and nothing goes into the conversation ([`file_grant`], which
    // the vault pickup files one with too). Nothing signs for it: a grant is
    // handed over once and waits in no outbox.
    if let Some(grant) = &inner.grant {
        return match file_grant(host, user_id, &own, &own_key, contact_did, grant).await {
            Filing::Stored => ContactResponse::Delivered { stored: true, ack: None },
            Filing::Held | Filing::Waiting => ContactResponse::Delivered { stored: false, ack: None },
            Filing::Declined(reason) => ContactResponse::Declined { reason },
            Filing::Failed(reason) => refused(reason),
        };
    }

    // A **channel** copy has one more thing to hold it to: that its author is in
    // the channel it names, as this identity knows the channel now. Without it,
    // any contact could file a row into any channel view by naming its DID, and
    // a member removed at the last rotation could go on posting at the epoch
    // they still hold — every remaining member holds that epoch too, so each of
    // them could open it.
    //
    // This is not a second check on the door. The door proved *who is speaking*;
    // this asks *whether what they are speaking about is theirs to put here*, and
    // the roster sealed in this identity's newest grant is what answers it
    // ([`in_current_epoch`]). Until 2026-10-08 this comment said a removed member
    // was refused by a lookup of this identity's own grants; they were not, since
    // that lookup asked only whether this identity held any grant for the
    // channel, and a removed member's copy passed it
    // (`TASK-a-channel-member-who-admitted-nobody-sees-a-channel-of-one`).
    if let Some(channel) = &inner.channel {
        match in_current_epoch(host, user_id, &own, &own_key, contact_did, &channel.channel_did, channel.epoch, Carried::Message)
            .await
        {
            InEpoch::Yes => {}
            InEpoch::NotYet(reason) => return refused(reason),
            InEpoch::No(reason) => return ContactResponse::Declined { reason },
        }
    }

    // This device signs for what it holds — the first copy and every copy
    // after it alike, so a sender whose last answer went missing is answered
    // again rather than retrying for ever.
    let signed = || Some(host.sign_delivery_ack(&sealed.ephemeral_pub, &own, contact_did));
    match file_message(host, user_id, contact_did, &inner, &sealed).await {
        Filing::Stored => ContactResponse::Delivered { stored: true, ack: signed() },
        Filing::Held => ContactResponse::Delivered { stored: false, ack: signed() },
        // Held here, waiting for its bytes, and not signed for: the sender
        // reads *sent* until the stream is whole and the share filed.
        Filing::Waiting => ContactResponse::Delivered { stored: false, ack: None },
        Filing::Declined(reason) => ContactResponse::Declined { reason },
        Filing::Failed(reason) => refused(reason),
    }
}

/// File `grant`, which arrived from `author_did` and has been proved theirs and
/// addressed to `own`, in `user_id`'s grants namespace with the roster it
/// carries — and nothing in the conversation. The one filing of a key-grant,
/// whichever way it came: handed to the door ([`deliver`]) or carried by the
/// vault while no device of this person's was awake ([`file_from_vault`]).
/// Each says the answer its own way; what is filed, and what is refused, does
/// not depend on which.
///
/// It is handled before the channel-membership check a channel copy takes for
/// the obvious reason — this is what makes somebody a member, so requiring
/// membership first would make a channel spanning two daemons impossible to
/// join.
///
/// What makes accepting one safe is that it opens nothing on its own. The key
/// inside is wrapped to *this* identity's key by the contact who sealed it, so
/// a grant from someone who does not hold the channel key is inert: it will not
/// unwrap, and a channel message sealed under a key this grant cannot produce
/// will not open. The door, or the signature a pickup checks, already proved
/// who is speaking; being added to a channel by a contact is the same act as
/// being messaged by one.
///
/// Except into a channel this identity is already in. There, a grant is a
/// rotation, and who may rotate is whoever holds the current key
/// (`TASK-a-member-is-removed-from-a-channel-by-a-rotation-that-omits-them`):
/// the grant's author must be in the roster of this identity's newest grant
/// ([`in_current_epoch`]). Without it a member removed at the last rotation
/// could mint an epoch of their own, roster and all, hand it to everyone they
/// were removed from, and be read as a member again by every node that took it
/// — since the roster in the newest grant is what membership is. An author not
/// in that roster at an epoch this identity has reached is
/// [`Filing::Declined`]; at a newer one, whose rotation may not have reached
/// this identity yet, [`Filing::Failed`], which may clear.
///
/// Until 2026-10-08 the door held this inline and the pickup had no branch for
/// it, so a grant that waited at a vault fell through to [`file_message`] and
/// was filed as an empty direct message, with no key
/// (`TASK-a-key-grant-picked-up-from-a-vault-is-filed-as-an-empty-message`).
async fn file_grant(
    host: &dyn MessageHost,
    user_id: &str,
    own: &str,
    own_key: &ed25519_dalek::SigningKey,
    author_did: &str,
    grant: &ChannelGrant,
) -> Filing {
    let mut record = serde_json::json!({
        "channel_did": grant.channel_did,
        "to_did": own,
        "enc_key": grant.enc_key,
        "nonce": grant.nonce,
        "ephemeral_pub": grant.ephemeral_pub,
        "epoch": grant.epoch,
        "granted_at": grant.granted_at,
    });
    // The epoch's roster, filed as it came: sealed under the key this grant
    // carries, and opened only by unwrapping it (`messages::current_members`).
    if let Some(roster) = &grant.roster {
        record["roster"] = Value::from(roster.body.clone());
        record["roster_nonce"] = Value::from(roster.nonce.clone());
    }
    match in_current_epoch(host, user_id, own, own_key, author_did, &grant.channel_did, grant.epoch, Carried::Grant)
        .await
    {
        InEpoch::Yes => {}
        InEpoch::NotYet(reason) => return Filing::Failed(reason),
        InEpoch::No(reason) => return Filing::Declined(reason),
    }
    match after_leaving(host, user_id, own, own_key, &grant.channel_did, &record, grant.epoch).await {
        InEpoch::Yes => {}
        InEpoch::NotYet(reason) => return Filing::Failed(reason),
        InEpoch::No(reason) => return Filing::Declined(reason),
    }
    // Idempotent on the wrapping's own ephemeral key, which is fresh per
    // grant — a retried hand-off, or the same grant handed to the door and
    // carried by the vault, must not leave two rows claiming one epoch, and
    // two copies arriving at once must not both find none (`filing`).
    let _filing = filing::once(user_id, &grant.ephemeral_pub).await;
    match host
        .record_query(
            user_id,
            NSID_CHANNEL_KEY_GRANT,
            vec![("ephemeral_pub".to_string(), Value::from(grant.ephemeral_pub.clone()))],
            Some(1),
            None,
            None,
        )
        .await
    {
        Ok(existing) if !existing.is_empty() => return Filing::Held,
        Ok(_) => {}
        Err(e) => return Filing::Failed(format!("could not check for an existing grant: {e}")),
    }
    match host.record_insert(user_id, NSID_CHANNEL_KEY_GRANT, record).await {
        Ok(_) => {
            // A new roster: the members this identity holds no card for may
            // have changed, and their doors with them, and a copy waiting in
            // the outbox for somebody it omits is nobody's now. After the
            // grant's own lock, which guards only its filing.
            drop(_filing);
            roster_changed(host, user_id, &grant.channel_did).await;
            Filing::Stored
        }
        Err(e) => Filing::Failed(format!("could not store the key-grant: {e}")),
    }
}

/// Whether a key-grant for `channel_did` at `epoch` — `record` as it would be
/// filed — may be taken by `user_id`'s node **after this identity left the
/// channel** (`TASK-a-leave-sealed-before-the-leavers-node-held-the-newest-epoch-lapses`).
///
/// A node holding no grant for a channel takes one from any contact, because
/// that is how anybody joins ([`in_current_epoch`]). A node that left holds
/// none either, so a grant minted *before* its leave reached anybody — still
/// on its way, naming it among the members of an epoch newer than the one it
/// left at — would make it a member again, holding a key to what is said after
/// its leave, and listing a group it left. So, once this identity has filed a
/// leave notice of its own for the channel and holds no grant for it, a grant
/// is taken only if it is **an invitation back**: minted at an epoch above the
/// one it left at, by a rotation that admitted this identity by name — the
/// roster sealed in the grant says so (`messages::roster_admits`). Anything
/// else is declined: an in-flight grant only names it among the members, and
/// is the epoch the elector's rotation omits it from.
///
/// The epoch alone cannot tell them apart. The in-flight grant is at an epoch
/// above the one the leaver sealed at — that is what makes it in flight.
async fn after_leaving(
    host: &dyn MessageHost,
    user_id: &str,
    own: &str,
    own_key: &ed25519_dalek::SigningKey,
    channel_did: &str,
    record: &Value,
    epoch: u64,
) -> InEpoch {
    if !own_grants(host, user_id, channel_did, own).await.is_empty() {
        return InEpoch::Yes;
    }
    let filter = vec![
        ("channel_did".to_string(), Value::from(channel_did)),
        ("type".to_string(), Value::from(LEAVE_TYPE)),
        ("from_did".to_string(), Value::from(own)),
    ];
    let left_at = match host.record_query(user_id, NSID_MESSAGE_V1, filter, None, None, None).await {
        Ok(notices) => notices.iter().filter_map(|n| n.get("epoch").and_then(|e| e.as_u64())).max(),
        Err(e) if e.to_string().contains("no such table") => None,
        Err(e) => return InEpoch::NotYet(format!("could not read whether this identity left channel {channel_did}: {e}")),
    };
    let Some(left_at) = left_at else {
        return InEpoch::Yes;
    };
    let admits = unwrap_own_grant(host, user_id, record, own_key, &mut None)
        .ok()
        .and_then(|key| roster_admits(record, &key));
    if epoch > left_at && admits.as_deref() == Some(own) {
        return InEpoch::Yes;
    }
    InEpoch::No(format!(
        "this identity left channel {channel_did} at epoch {left_at}, and that key-grant (epoch {epoch}) does not \
         admit it again — it is not taken"
    ))
}

/// The channel `inner` names, as a copy (a post, a share, a leave, a range of
/// a share to a group) or as a key-grant — `None` for anything else.
fn channel_named(inner: &DmInner) -> Option<&str> {
    inner
        .channel
        .as_ref()
        .map(|c| c.channel_did.as_str())
        .or_else(|| inner.grant.as_ref().map(|g| g.channel_did.as_str()))
}

/// The key `inner`'s author, who holds no card on `user_id`'s node, is held
/// to: the one the roster of the channel `inner` names carries for them
/// (`messages::Rosters::member`) — or, for an acknowledgement, which names no
/// channel, the one any roster this identity holds carries for them
/// (`messages::co_member`). `None` for anything else, and for somebody no
/// roster here names with a key.
async fn co_member_key(host: &dyn MessageHost, user_id: &str, inner: &DmInner) -> Option<[u8; 32]> {
    match channel_named(inner) {
        Some(channel_did) => {
            Rosters::held(host, user_id, channel_did).await.member(&inner.from_did).and_then(|m| m.key)
        }
        None if inner.ack.is_some() => co_member(host, user_id, &inner.from_did).await.map(|c| c.key),
        None => None,
    }
}

/// Whether `author` — somebody `user_id` holds **no card** for — may say
/// `inner` to them under `key`, the key their door was opened for or the
/// pickup held the envelope to
/// (`TASK-a-channel-member-who-is-not-the-senders-contact-never-receives-the-senders-copies`).
///
/// A co-member's door exists because a channel's roster names them with that
/// key (`messages::co_members`), and that is the whole of what it is for: the
/// copies of **a channel whose roster this identity holds and which names
/// them under that very key** — a post, a share, a range of one, a leave, a
/// key-grant for the next epoch — and an acknowledgement for a copy this
/// identity sent them. Whether they are a member *now* is the next check's
/// (`in_current_epoch`), unchanged.
///
/// - **Anything else is a verdict** — a direct message, a reach note, a share
///   or range sent as a direct one: a roster's key is not a card, and what a
///   person may say outside a channel waits on their pairing.
/// - **A channel whose rosters here do not name them under `key`** may clear —
///   the roster that does may not have reached this node yet — so it is
///   refused for now and tried again. That includes a channel this identity is
///   in with other people: a key from one channel's roster opens no other.
async fn co_member_may_say(
    host: &dyn MessageHost,
    user_id: &str,
    author: &str,
    key: &[u8; 32],
    inner: &DmInner,
) -> InEpoch {
    let channel = channel_named(inner);
    let speaks_for_a_channel = channel.is_some() && inner.reach.is_none() && inner.ack.is_none();
    if let Some(channel_did) = channel.filter(|_| speaks_for_a_channel) {
        let rosters = Rosters::held(host, user_id, channel_did).await;
        return match rosters.member(author).and_then(|m| m.key) {
            Some(named) if named == *key => InEpoch::Yes,
            _ => InEpoch::NotYet(format!(
                "{author} is not a contact of this identity's, and no roster it holds for channel {channel_did} names \
                 them under the key they spoke with — so it is not filed"
            )),
        };
    }
    let only_an_ack = inner.ack.is_some()
        && channel.is_none()
        && inner.reach.is_none()
        && inner.range.is_none()
        && inner.share.is_none();
    if only_an_ack {
        return match co_member(host, user_id, author).await {
            Some(c) if c.key == *key => InEpoch::Yes,
            _ => InEpoch::NotYet(format!(
                "{author} is not a contact of this identity's, and no channel it holds names them under that key"
            )),
        };
    }
    InEpoch::No(format!(
        "{author} is not a contact of this identity's: a person you share only a channel with may hand you that \
         channel's copies and nothing else — pair with them to say anything else"
    ))
}

/// What a channel's author sent: a message, or a key-grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Carried {
    Message,
    Grant,
}

/// What [`in_current_epoch`] makes of a channel copy or a key-grant's author.
#[derive(Debug, PartialEq, Eq)]
enum InEpoch {
    /// They hold the current epoch as this identity knows it — or this identity
    /// holds no grant of the channel that carries a roster, and there is
    /// nothing to hold them to (see [`in_current_epoch`]).
    Yes,
    /// They are not in the roster this identity holds, at an epoch older than
    /// the one they wrote at: this identity may simply not have been handed the
    /// newer grant yet. A refusal that may clear, so the sender tries again.
    NotYet(String),
    /// They are not in the roster of an epoch at least as new as the one they
    /// wrote at: a verdict, which handing it again cannot change.
    No(String),
}

/// Whether `author_did` holds the current key of `channel_did`, as `user_id`
/// knows it: whether they are in the roster sealed in `user_id`'s **newest
/// grant they can open** (`messages::current_members`). `epoch` is the one the
/// author stamped on what they sent; `what` names it in a refusal.
///
/// A message sealed at an older epoch by somebody in the current roster is in:
/// it was in flight during a rotation, and its author is a member. One by
/// somebody not in the current roster is refused with a sentence naming the
/// epoch — the removed member's case, and the stranger's.
///
/// Holding no grant for the channel at all refuses a message (there is nothing
/// to put it in) and admits a key-grant (it is how anybody joins).
///
/// **A newest grant minted before rosters** carries none, so there is no
/// roster to hold an author to, and the two kinds part:
///
/// - A **message** is filed from anybody, as before rosters: a message cannot
///   change who is in the channel, and the count this store could offer is,
///   for anybody but the grants' writer, themselves alone.
/// - A **key-grant** is refused from everybody. A grant is a rotation, and the
///   ruling of 2026-10-08 is that a channel from before rosters is rotated by
///   the writer of the grant this identity holds and by nobody else. The grant
///   record does not name its writer — it carries `channel_did`, `to_did`, the
///   wrapped key, `epoch` and `granted_at`, and the door that filed it kept
///   nothing of who handed it over — and no channel-create record exists to
///   name a creator. So the writer cannot be read, and the escalated default
///   holds: such a channel takes no new epoch over the door
///   (`TASK-a-channel-from-before-rosters-names-nobody-who-may-rotate-it`).
///   Filing it would let any contact's roster-bearing grant become this
///   identity's membership, which is the hole a roster otherwise closes.
#[allow(clippy::too_many_arguments)]
async fn in_current_epoch(
    host: &dyn MessageHost,
    user_id: &str,
    own: &str,
    own_key: &ed25519_dalek::SigningKey,
    author_did: &str,
    channel_did: &str,
    epoch: u64,
    what: Carried,
) -> InEpoch {
    let Some(members) = current_members(host, user_id, channel_did, own, own_key, &mut None).await
    else {
        return if what == Carried::Grant {
            InEpoch::Yes
        } else {
            InEpoch::NotYet(format!(
                "that message is for channel {channel_did}, and this identity holds no key-grant \
                 it can open for it"
            ))
        };
    };
    if !members.sealed {
        return match what {
            Carried::Message => InEpoch::Yes,
            Carried::Grant => InEpoch::No(format!(
                "that key-grant is from {author_did}, and this identity's newest grant for channel \
                 {channel_did} (epoch {}) was filed before rosters and does not name who wrote \
                 it — a channel from before rosters takes a new epoch only from that writer, so \
                 it takes none over the door",
                members.epoch
            )),
        };
    }
    if members.dids.iter().any(|d| d == author_did) {
        return InEpoch::Yes;
    }
    let what = match what {
        Carried::Message => "message",
        Carried::Grant => "key-grant",
    };
    let reason = format!(
        "that {what} is from {author_did}, who is not in channel {channel_did} at epoch {}, \
         the newest this identity holds — so it is not filed",
        members.epoch
    );
    if epoch > members.epoch {
        InEpoch::NotYet(reason)
    } else {
        InEpoch::No(reason)
    }
}

/// What filing a direct message, or a key-grant ([`file_grant`]), that arrived
/// came to.
pub(crate) enum Filing {
    /// Filed now.
    Stored,
    /// Already filed — a retried or second copy.
    Held,
    /// A share whose bytes are still streaming in: kept waiting for them, and
    /// nothing filed (RFC-0090, *Above the frame cap*).
    Waiting,
    /// Nothing filed, as a verdict on what was handed, which handing it again
    /// cannot change — a share that does not hold, said naming the sender.
    Declined(String),
    /// Nothing filed, for a reason that may clear with time.
    Failed(String),
}

/// File `inner`, which arrived from `sender_did` in `sealed` and has been
/// proved theirs and addressed here, as a message in `user_id`'s conversation
/// with them — and, for a share, its file under *Shared with you* first. The
/// one filing the door, the vault pickup and a stream that comes whole all
/// take.
///
/// **A share is held to its own digest, and its name and the sender's card
/// name to one plain segment each, before anything of it is kept** (RFC-0090,
/// *Filing*, step 1). One that does not hold is a verdict on these bytes and
/// these names, which another try cannot change, so it is declined — and
/// said, by the sender's name, on this node. A share whose bytes stream is
/// filed only once they are whole and hash to its digest
/// ([`stream::bytes_of`]); until then the manifest waits for them, and nothing
/// is filed.
///
/// Deduplication is the message's own ciphertext. A delivery cut before its
/// acknowledgement is retried (`DEC-0055`: at-least-once), and the sender's
/// ephemeral public key is fresh per message (RFC-0064 MS1), so a record
/// already holding that key is this message and not another. The sender dials
/// every path at once, so a second copy can be asking this question while the
/// first is still filing; `filing::once` makes the question and the filing
/// one step for this id.
pub(crate) async fn file_message(
    host: &dyn MessageHost,
    user_id: &str,
    sender_did: &str,
    inner: &DmInner,
    sealed: &SealedDm,
) -> Filing {
    let _filing = filing::once(user_id, &sealed.ephemeral_pub).await;
    match host
        .record_query(
            user_id,
            NSID_MESSAGE_V1,
            vec![("ephemeral_pub".to_string(), Value::from(sealed.ephemeral_pub.clone()))],
            Some(1),
            None,
            None,
        )
        .await
    {
        Ok(existing) if !existing.is_empty() => return Filing::Held,
        Ok(_) => {}
        // A store that cannot be read is a store that must not be written: a
        // failed dedup read would otherwise turn every retry into a duplicate.
        Err(e) => return Filing::Failed(format!("could not check for an existing copy: {e}")),
    }

    // A leave notice sealed at an epoch newer than any this identity holds
    // waits for it ([`leave_not_yet`]): the elector rotates only at the epoch it
    // holds, so filed now it would be kept and never acted on.
    if let Some(channel) = inner.channel.as_ref().filter(|_| inner.kind == LEAVE_TYPE) {
        if let Some(reason) = leave_not_yet(host, user_id, &channel.channel_did, channel.epoch).await {
            return Filing::Failed(reason);
        }
    }

    // A direct share carries its manifest in the envelope; a share to a
    // group carries it under the channel's key, and it is opened here with the
    // keys this identity holds. Past this line the filing does not ask which
    // transport it came by: the sender is whoever sealed it — the author the
    // envelope names, whom the door or the vault has already held to their
    // key — and the share is held and filed by the same steps either way.
    let from_channel = match channel_manifest(host, user_id, sender_did, inner).await {
        Ok(m) => m,
        Err(filing) => return filing,
    };
    let shared = match inner.share.as_ref().or(from_channel.as_ref()) {
        None => None,
        Some(manifest) => {
            let bytes = if manifest.is_streamed() {
                // A manifest nobody could ever file is refused, not waited on.
                if let Err(why) = manifest
                    .stream_holds()
                    .and_then(|()| crate::share::Plain::new(&manifest.name).map(|_| ()))
                {
                    return Filing::Declined(refusal(host, user_id, sender_did, why).await);
                }
                match stream::bytes_of(host, user_id, sender_did, manifest, stream::share_id(inner, sealed)).await {
                    Ok(Some(bytes)) => Ok(bytes),
                    Ok(None) => {
                        return match stream::keep_waiting(host, user_id, sender_did, manifest, inner, sealed)
                            .await
                        {
                            Ok(()) => Filing::Waiting,
                            Err(NotTaken::Again(reason)) => Filing::Failed(reason),
                            Err(NotTaken::Verdict(why)) => {
                                Filing::Declined(refusal(host, user_id, sender_did, why).await)
                            }
                        }
                    }
                    Err(NotTaken::Again(reason)) => return Filing::Failed(reason),
                    Err(NotTaken::Verdict(why)) => Err(why),
                }
            } else {
                manifest.bytes()
            };
            match take_share(host, user_id, sender_did, manifest, bytes).await {
                Ok(taking) => Some((manifest, taking)),
                Err(reason) => return Filing::Declined(reason),
            }
        }
    };

    // The file first, then the message: a file that will not write is a
    // share not taken, and the sender tries again; the message filed first
    // would make that try a duplicate, and the file would never land.
    if let Some((_, taking)) = &shared {
        if let Err(e) = file_share(host, user_id, taking).await {
            return Filing::Failed(e);
        }
    }
    if let Err(e) = host.record_insert(user_id, NSID_MESSAGE_V1, filed_record(inner, sealed)).await {
        return Filing::Failed(format!("could not store the message: {e}"));
    }
    // Filed whole: nothing of its stream is owed any longer.
    if let Some((manifest, _)) = shared.filter(|(m, _)| m.is_streamed()) {
        stream::done(host, user_id, sender_did, manifest, stream::share_id(inner, sealed)).await;
    }
    // A **leave notice**, filed now: kept in the channel like any message, and
    // the one remaining member the roster names rotates the channel to an epoch
    // that omits its author; every other member waits for that epoch
    // ([`rotate_for_leave`]). Here, after the filing and under its `once`, so a
    // second copy of the same notice — retried, or carried by the vault too —
    // finds it [`Filing::Held`] above and rotates nothing. A rotation that does
    // not happen does not unfile the notice: the leave is said, and any member
    // holding the current key can still remove the leaver.
    if let Some(channel) = inner.channel.as_ref().filter(|_| inner.kind == LEAVE_TYPE) {
        match rotate_for_leave(host, user_id, &channel.channel_did, sender_did, channel.epoch).await {
            AfterLeave::Rotated(epoch) => {
                tracing::info!(user_id, epoch, "a member left; this node is the elector and rotated the channel")
            }
            AfterLeave::Waits { elector } => {
                tracing::info!(user_id, %elector, "a member left; another member rotates, and this node waits")
            }
            AfterLeave::Nothing(why) => tracing::info!(user_id, %why, "a leave notice was filed and rotates nothing"),
            AfterLeave::Failed(why) => {
                tracing::warn!(user_id, %why, "a member left and this node, the elector, could not rotate")
            }
        }
    }
    Filing::Stored
}

/// The manifest a **channel** copy carries, if it is a share — opened from the
/// channel ciphertext with the keys `user_id` holds (RFC-0090, *Delivery › To
/// a group*): `None` for a direct message, and for a channel copy that is not
/// a share.
///
/// What does not open files nothing (the share's clause 3). A member removed
/// before the share was sealed, or admitted after it without backfill, holds
/// no key for its epoch, so even handed the ciphertext they have no manifest
/// to file: declined, when it was sealed at an epoch they have reached; and
/// refused for now, when at one newer than any they hold, whose grant may be
/// on its way. A channel copy that carries a manifest *beside* the channel
/// ciphertext is declined — the manifest of a share to a group is the
/// ciphertext every member was handed, and a second one would be a manifest
/// the channel key did not protect.
async fn channel_manifest(
    host: &dyn MessageHost,
    user_id: &str,
    sender_did: &str,
    inner: &DmInner,
) -> Result<Option<crate::share::Manifest>, Filing> {
    let Some(channel) = &inner.channel else {
        return Ok(None);
    };
    if inner.share.is_some() {
        let why = "a share to a group carries its manifest under the channel's key, and this one \
                   carried one beside it"
            .to_string();
        return Err(Filing::Declined(refusal(host, user_id, sender_did, why).await));
    }
    if inner.kind != crate::share::MESSAGE_TYPE {
        return Ok(None);
    }
    match open_channel_copy(host, user_id, channel).await {
        Opened::Plain(plaintext) => match crate::share::Manifest::of_channel_body(&plaintext) {
            Ok(manifest) => Ok(Some(manifest)),
            Err(why) => Err(Filing::Declined(refusal(host, user_id, sender_did, why).await)),
        },
        Opened::NotYet(reason) => Err(Filing::Failed(reason)),
        Opened::NotHeld(why) => Err(Filing::Declined(refusal(host, user_id, sender_did, why).await)),
    }
}

/// Keep `range`, which arrived from `sender_did` in `inner`, toward its
/// stream ([`stream::keep_range`]), with the plaintext it carries — the one
/// taking of a range the door and the vault pickup share.
///
/// **To a person, the bytes are in the range.** **To a group, they are its
/// envelope's channel ciphertext** (the ruling of 2026-10-09 on RFC-0090: one
/// ciphertext per range, sealed under the epoch the manifest was, handed to
/// every current member), and a range of a share to a group is a channel copy
/// like any other: its author is held to the roster of this identity's newest
/// grant first ([`in_current_epoch`], the check every channel copy takes), so a
/// member removed at the last rotation is refused here as their posts are;
/// then it is opened with the keys this identity holds, so a range sealed at an
/// epoch nobody granted this identity opens to nothing and is kept nowhere. A
/// range of a share to a group that carries bytes beside its ciphertext is
/// refused: they would be bytes the channel key did not protect.
#[allow(clippy::too_many_arguments)]
async fn take_range(
    host: &dyn MessageHost,
    user_id: &str,
    own: &str,
    own_key: &ed25519_dalek::SigningKey,
    sender_did: &str,
    inner: &DmInner,
    range: &crate::share::Range,
) -> Result<bool, NotTaken> {
    let Some(channel) = &inner.channel else {
        let bytes = range.holds().map_err(NotTaken::Verdict)?;
        return stream::keep_range(host, user_id, sender_did, range, &bytes, None).await;
    };
    match in_current_epoch(host, user_id, own, own_key, sender_did, &channel.channel_did, channel.epoch, Carried::Message)
        .await
    {
        InEpoch::Yes => {}
        InEpoch::NotYet(reason) => return Err(NotTaken::Again(reason)),
        InEpoch::No(reason) => return Err(NotTaken::Verdict(reason)),
    }
    if !range.bytes.is_empty() {
        return Err(NotTaken::Verdict(
            "a range of a share to a group carries its bytes under the channel's key, and this one carried \
             them beside it"
                .to_string(),
        ));
    }
    let bytes = match open_channel_copy(host, user_id, channel).await {
        Opened::Plain(bytes) => bytes,
        Opened::NotYet(reason) => return Err(NotTaken::Again(reason)),
        Opened::NotHeld(reason) => return Err(NotTaken::Verdict(reason)),
    };
    stream::keep_range(host, user_id, sender_did, range, &bytes, Some(&channel.channel_did)).await
}

/// File the share `range` completes, if its stream is whole now and its
/// manifest is waiting here. With `sign_back`, the device signs for the share
/// back over the sender's own door, as a message picked up from a vault is:
/// the sender is not on the line.
async fn file_if_whole(
    host: &dyn MessageHost,
    user_id: &str,
    sender_did: &str,
    range: &crate::share::Range,
    sign_back: Option<(&str, &[u8; 32])>,
) {
    let Some((inner, sealed)) = stream::whole_and_waiting(host, user_id, sender_did, range).await else {
        return;
    };
    match file_message(host, user_id, sender_did, &inner, &sealed).await {
        Filing::Stored | Filing::Held => {
            tracing::info!(user_id, "a share whose bytes streamed in is filed whole");
            if let Some((own, sender_pub)) = sign_back {
                sign_for_back(host, user_id, own, sender_did, sender_pub, &sealed.ephemeral_pub).await;
            }
        }
        Filing::Waiting => {}
        Filing::Declined(reason) | Filing::Failed(reason) => {
            tracing::info!(user_id, %reason, "a share whose bytes streamed in was not filed");
        }
    }
}

/// How a share from `sender_did` that does not hold is told: naming them as
/// the folder would — the card's name where it is plain, their AID's first
/// characters otherwise — and saying that nothing was filed.
async fn refusal(host: &dyn MessageHost, user_id: &str, sender_did: &str, why: String) -> String {
    use crate::share::{aid_prefix, sender_folder};
    let card = host.contact_name(user_id, sender_did).await;
    let sender = sender_folder(card.as_deref(), sender_did)
        .map(|f| f.as_str().to_owned())
        .unwrap_or_else(|_| aid_prefix(sender_did));
    tracing::warn!(user_id, from = %sender, %why, "a share was refused, and nothing was filed");
    format!("a share from {sender} was refused, and nothing was filed: {why}")
}

/// A share that holds, ready to file: its bytes, and the folder and name it
/// lands under — each [`Plain`](crate::share::Plain), worked out once here and
/// carried to [`file_share`], so the folder listed and locked there is the
/// folder written.
pub(crate) struct Taking {
    bytes: Vec<u8>,
    folder: crate::share::Plain,
    name: crate::share::Plain,
}

/// Hold a share from `sender_did` whose plaintext came to `bytes` — inline
/// and checked against its own size and digest ([`Manifest::bytes`](crate::share::Manifest::bytes)),
/// or streamed and assembled whole ([`stream::bytes_of`]) — to its name being
/// one plain segment, and name the folder it lands in
/// ([`sender_folder`](crate::share::sender_folder): the card's name, or the
/// AID's first characters where the card has no usable name) — or, when the
/// share does not hold, the refusal as it is told ([`refusal`]).
async fn take_share(
    host: &dyn MessageHost,
    user_id: &str,
    sender_did: &str,
    manifest: &crate::share::Manifest,
    bytes: Result<Vec<u8>, String>,
) -> Result<Taking, String> {
    use crate::share::{sender_folder, Plain};
    let card = host.contact_name(user_id, sender_did).await;
    let folder = sender_folder(card.as_deref(), sender_did);
    let taking = bytes.and_then(|bytes| {
        let name = Plain::new(&manifest.name)?;
        let folder = folder.map_err(|why| format!("their AID names no folder — {why}"))?;
        Ok(Taking { bytes, folder, name })
    });
    match taking {
        Ok(taking) => Ok(taking),
        Err(why) => Err(refusal(host, user_id, sender_did, why).await),
    }
}

/// File a share that holds into `user_id`'s Personal tree, at
/// `Shared with you/<folder>/<name>`, suffixed where that name is taken
/// ([`crate::share::landing`]). Answers where it landed. The copy is a record
/// of theirs and carries no `origin` (SH1): it is the bytes, written as they
/// would write them.
///
/// Two shares of one name landing at once must not both read the folder as
/// free and write one over the other, so the listing and the write are one
/// step for the folder ([`filing::folder`]) — the same folder, worked out once
/// in [`take_share`].
pub(crate) async fn file_share(
    host: &dyn MessageHost,
    user_id: &str,
    taking: &Taking,
) -> Result<String, String> {
    use crate::share::{folder_path, landing};
    let dir = folder_path(&taking.folder);
    let _folder = filing::folder(user_id, &dir).await;
    let taken = host.personal_names(user_id, &dir).await?;
    let at = landing(&taking.folder, &taking.name, &taken);
    host.personal_write(user_id, &at, &taking.bytes)
        .await
        .map_err(|e| format!("could not file the share from {}: {e}", taking.folder.as_str()))?;
    tracing::info!(user_id, "a share was filed under Shared with you");
    Ok(at)
}

/// The key an arriving envelope is held to, and the key log to keep for its
/// sender if that log taught the card something
/// (`TASK-a-rotated-persons-contacts-keep-the-key-it-retired`).
struct HeldTo {
    key: [u8; 32],
    learned: Option<Vec<kotton_wire::kel::KelEvent>>,
}

impl HeldTo {
    /// Keep what the log taught — called once the envelope it came in has been
    /// proved the sender's under [`Self::key`]. A card that cannot be written is
    /// said, and the sender tries again.
    async fn keep(self, host: &dyn MessageHost, user_id: &str, contact_did: &str) -> Result<(), String> {
        let Some(log) = self.learned else {
            return Ok(());
        };
        host.adopt_contact_key(user_id, contact_did, &log, self.key)
            .await
            .map_err(|nk| nk.reason().to_string())?;
        tracing::debug!(user_id, contact = %contact_did, "a contact's key was learned from their key log");
        Ok(())
    }
}

/// Which key `contact_did`'s envelope must be signed by: the one the card holds,
/// `held_key`, unless the envelope carries their key log — then the key that log
/// resolves to, provided it replays from their AID and continues the log the card
/// kept (`kotton_crypto::kel_verify::contact_key_from_log`). A log that does not
/// hold refuses the envelope: it is either not theirs, or older than what the
/// card already knows, and neither is something to be held to.
///
/// This is the whole of how a stored key changes after admission. A relay or a
/// vault can hand over a log and cannot write one; the only party who can extend
/// it is the identity, with the key it pre-committed.
fn sender_key(
    host: &dyn MessageHost,
    user_id: &str,
    contact_did: &str,
    held_key: &[u8; 32],
    carried: &[kotton_wire::kel::KelEvent],
) -> Result<HeldTo, String> {
    if carried.is_empty() {
        return Ok(HeldTo { key: *held_key, learned: None });
    }
    let held = host.contact_key_log(user_id, contact_did);
    let key = kotton_crypto::kel_verify::contact_key_from_log(&held, held_key, contact_did, carried)
        .map_err(|e| format!("the key log that came with it does not hold: {e}"))?;
    let teaches = key != *held_key || carried.len() > held.len();
    Ok(HeldTo { key, learned: teaches.then(|| carried.to_vec()) })
}

/// Hold a reach note that arrived at the door on the card for its sender.
async fn keep_note(
    host: &dyn MessageHost,
    user_id: &str,
    contact_did: &str,
    note: ReachNote,
) -> ContactResponse {
    // The card's verdict is said as one, and the sender hands this note over no
    // more: asked again, the card would say the same. A refusal about this
    // node rather than the note — a card it could not read or write, no
    // contact's card, a clock behind the sender's by no more than a clock
    // explains — is not a verdict, and the
    // sender tries again past it
    // (`TASK-a-reach-note-a-contact-refused-is-sent-to-them-again-every-hour`,
    // `TASK-a-door-refusal-that-can-clear-settles-a-reach-note-version-until-the-next`).
    match host.keep_reach_note(user_id, contact_did, note).await {
        Ok(kept) => ContactResponse::Delivered { stored: kept == Kept::Replaced, ack: None },
        Err(NotKept::Refused(reason)) => ContactResponse::Declined { reason },
        Err(NotKept::Failed(reason)) => ContactResponse::Refused { reason },
    }
}

/// File a message the vault held for `user_id` while no device was awake
/// (`DEC-0056`). The vault's door proved a pair key, not a person, so this is
/// where the person is proved: open, read who it claims to be from, look that
/// contact's identity key up, and hold the signature to it. Returns whether a
/// record was filed, or a newer reach note kept (false: already held, or a
/// note, grant or channel copy refused as a verdict — either way it is taken
/// off the vault).
pub async fn file_from_vault(
    host: &dyn MessageHost,
    user_id: &str,
    delivery: &PendingDelivery,
) -> Result<bool, String> {
    let own = host
        .user_aid(user_id)
        .ok_or_else(|| "this identity is not available on this node".to_string())?;
    let own_key = load_user_signing_key(user_id, host.secrets())
        .ok_or_else(|| "this identity's key is not available on this node".to_string())?;
    let claimed = envelope::open_claimed(&delivery.sealed, &own_key)?;
    // The card's key — or, for somebody this identity holds no card for, the
    // key the roster of the channel the envelope names carries for them
    // ([`co_member_key`]): a co-member's copy waited at the vault as a
    // contact's does, and is held to that key for that channel's copies only.
    let card = host.member_public_key(user_id, &claimed.inner.from_did).await;
    let held_pub = match card {
        Some(key) => key,
        None => co_member_key(host, user_id, &claimed.inner)
            .await
            .ok_or_else(|| format!("{} is not a contact", claimed.inner.from_did))?,
    };
    // The same rule as at the door: the card's key, or the key the sender's
    // own log proves — a vault can carry a log and cannot write one.
    let held_to = sender_key(host, user_id, &claimed.inner.from_did, &held_pub, &claimed.inner.kel)?;
    claimed.verify(&held_to.key)?;
    let sender_pub = held_to.key;
    let inner = claimed.inner;
    if inner.to_did != own {
        return Err("that message is addressed to someone else".to_string());
    }
    // What a co-member may say, as at their door: one held back may clear and
    // stays at the vault; one that is not a channel's copy for them is taken
    // off it, since that only becomes more true.
    if card.is_none() {
        match co_member_may_say(host, user_id, &inner.from_did, &held_pub, &inner).await {
            InEpoch::Yes => {}
            InEpoch::NotYet(reason) => return Err(reason),
            InEpoch::No(reason) => {
                tracing::info!(user_id, from = %inner.from_did, %reason, "something held at the vault from a co-member was refused");
                return Ok(false);
            }
        }
    }
    held_to.keep(host, user_id, &inner.from_did).await?;
    // A note a vault held while this person slept: the same rule as at the
    // door, with the sender proved by the signature just checked.
    //
    // A note the card *refuses* is taken off the vault all the same, not left
    // held. What refuses it — superseded by a newer one, or expired while it
    // waited — only becomes more true with time, so holding it would retry a
    // refusal at every pickup for ever. A note this node merely *failed* to
    // keep — the card could not be read or written, or this node's clock
    // trails the sender's within the week's slack a clock explains
    // (`messages::judge_reach_note`) — stays held: it may be good, and the
    // vault's acknowledgement is what the sender took as its delivery. The
    // slack bounds how long: as this node's clock runs on, the note fits
    // within that week and is kept, or declined if a newer one was kept first.
    if let Some(note) = inner.reach {
        return match host.keep_reach_note(user_id, &inner.from_did, note).await {
            Ok(kept) => Ok(kept == Kept::Replaced),
            Err(NotKept::Refused(reason)) => {
                tracing::debug!(user_id, from = %inner.from_did, %reason, "a reach note held at the vault was refused");
                Ok(false)
            }
            Err(NotKept::Failed(reason)) => Err(reason),
        };
    }
    // An acknowledgement that waited at this person's vault: one of the
    // contact's devices signing for something this person sent them. One that
    // does not hold is taken off the vault all the same — a signature that is
    // wrong stays wrong — and the message stays in the outbox, where the next
    // try reaches the device and is signed for at the door.
    if let Some(ack) = inner.ack {
        return match outbox::take_ack(host, user_id, &inner.from_did, &ack.message_id, &ack).await {
            Ok(taken) => Ok(taken),
            Err(reason) => {
                tracing::info!(user_id, from = %inner.from_did, %reason, "an acknowledgement held at the vault does not hold");
                Ok(false)
            }
        };
    }
    // A range of a share's bytes that waited at the vault: kept toward its
    // stream as at the door, and signed for back over the sender's door, so
    // the sender sends it no more. When it is the last of its stream, the
    // share it completes is filed and signed for the same way. One whose
    // share has not arrived is not kept: it is taken off the vault all the
    // same — held there it would stand in front of everything behind it at
    // every pickup — and the sender, whom nothing signed to, sends it again.
    if let Some(range) = &inner.range {
        return match take_range(host, user_id, &own, &own_key, &inner.from_did, &inner, range).await {
            Ok(stored) => {
                file_if_whole(host, user_id, &inner.from_did, range, Some((&own, &sender_pub))).await;
                sign_for_back(host, user_id, &own, &inner.from_did, &sender_pub, &delivery.sealed.ephemeral_pub)
                    .await;
                Ok(stored)
            }
            Err(NotTaken::Again(reason)) | Err(NotTaken::Verdict(reason)) => {
                tracing::info!(user_id, from = %inner.from_did, %reason, "a range held at the vault was not kept");
                Ok(false)
            }
        };
    }
    // A key-grant that waited at the vault: filed exactly as at the door
    // ([`file_grant`]) — in the grants namespace with its roster, nothing in
    // the conversation, and signed for by nothing, as nothing signs for one at
    // the door. One whose author is not in the roster of an epoch this
    // identity has reached is taken off the vault, since what refuses it only
    // becomes more true; one that may clear stays held.
    if let Some(grant) = &inner.grant {
        return match file_grant(host, user_id, &own, &own_key, &inner.from_did, grant).await {
            Filing::Stored => Ok(true),
            Filing::Held | Filing::Waiting => Ok(false),
            Filing::Declined(reason) => {
                tracing::info!(user_id, from = %inner.from_did, %reason, "a key-grant held at the vault was refused");
                Ok(false)
            }
            Filing::Failed(reason) => Err(reason),
        };
    }
    // A channel copy is held to the same rule as at the door: its author is in
    // the roster of this identity's newest grant ([`in_current_epoch`]). One
    // from somebody outside it at an epoch this identity has reached is taken
    // off the vault, since what refuses it only becomes more true; one from
    // somebody this identity may simply not have been told of yet stays held.
    if let Some(channel) = &inner.channel {
        match in_current_epoch(host, user_id, &own, &own_key, &inner.from_did, &channel.channel_did, channel.epoch, Carried::Message)
            .await
        {
            InEpoch::Yes => {}
            InEpoch::NotYet(reason) => return Err(reason),
            InEpoch::No(reason) => {
                tracing::info!(user_id, from = %inner.from_did, %reason, "a channel message held at the vault was refused");
                return Ok(false);
            }
        }
    }
    // Filed as at the door: a share held to its digest and its names, the
    // file first, and a copy arriving there while this one is picked up from
    // the vault is the same message. One that does not hold is taken off the
    // vault all the same — what is wrong stays wrong — and nothing of it is
    // filed or signed for; one whose bytes are still streaming in is taken
    // off too, and waits for them here, where the range that completes it
    // files it. A file that will not write stays held, and the next pickup
    // files it.
    let stored = match file_message(host, user_id, &inner.from_did, &inner, &delivery.sealed).await {
        Filing::Stored => true,
        Filing::Held => false,
        Filing::Waiting | Filing::Declined(_) => return Ok(false),
        Filing::Failed(reason) => return Err(reason),
    };
    // This device holds it now, so it signs for it — back over the sender's
    // own door, sealed to them, because the vault that held it could not.
    sign_for_back(host, user_id, &own, &inner.from_did, &sender_pub, &delivery.sealed.ephemeral_pub)
        .await;
    Ok(stored)
}

/// Send `sender_did` this device's signature for `message_id`, which it picked
/// up from its vault. Best effort, and said when it fails: if nothing of the
/// sender's takes it now, the sender's next try reaches this device, which
/// finds the copy it holds and signs for it at the door.
async fn sign_for_back(
    host: &dyn MessageHost,
    user_id: &str,
    own: &str,
    sender_did: &str,
    sender_pub: &[u8; 32],
    message_id: &str,
) {
    let sealed = match outbox::ack_envelope(host, user_id, own, sender_did, sender_pub, message_id) {
        Ok(s) => s,
        Err(reason) => {
            tracing::info!(user_id, to = %sender_did, %reason, "could not sign for a message picked up from the vault");
            return;
        }
    };
    // Every path at once, like anything else handed to a contact. The answer
    // to an acknowledgement carries none of its own, so the first door that
    // takes it settles it.
    // Said as everything handed to a contact is (`outbox::hand_over`), so the
    // door cannot tell an acknowledgement from a message by the verb.
    let request = ContactRequest::CarryMessage { sealed };
    match outbox::dial(host, user_id, sender_did, &request, |_| async { true }).await {
        Delivery::Unreachable { reason } => {
            tracing::info!(
                user_id,
                to = %sender_did,
                %reason,
                "the signature for a message picked up from the vault did not reach its sender; their next try is signed for at the door"
            );
        }
        _ => {
            tracing::debug!(user_id, to = %sender_did, "signed for a message picked up from the vault");
        }
    }
}

#[cfg(test)]
mod reach_note_tests {
    //! A reach note is not a message: at the door and at the vault pickup it goes
    //! to the card and never into the conversation, and a note the card refuses
    //! is taken off the vault rather than held to be refused again
    //! (`TASK-a-persons-reach-note-is-signed-by-them-and-replaces-relay-url`).
    use super::*;
    use crate::envelope::DmInner;
    use ed25519_dalek::SigningKey;
    use kotton_crypto::reach_note::{self, RelayRef};
    use kotton_sys::secret::{SecretsResult, SecretsStore};
    use kotton_wire::ipc::SealedDm;
    use std::sync::Mutex;

    const ALICE: &str = "did:kel:alice";
    const BOB: &str = "did:kel:bob";

    fn alice() -> SigningKey {
        SigningKey::from_bytes(&[1; 32])
    }
    fn bob() -> SigningKey {
        SigningKey::from_bytes(&[2; 32])
    }

    /// Bob's keychain: his identity key under whatever label is asked for.
    struct BobsKeychain;
    impl SecretsStore for BobsKeychain {
        fn get_secret(&self, _key: &str) -> SecretsResult<Option<String>> {
            Ok(Some(hex::encode(bob().to_bytes())))
        }
        fn set_secret(&self, _key: &str, _value: &str) -> SecretsResult<()> {
            Ok(())
        }
        fn delete_secret(&self, _key: &str) -> SecretsResult<()> {
            Ok(())
        }
    }

    /// Bob's node, holding Alice as a contact. `answer` is what his card says
    /// to a note, when it does not keep it.
    struct BobsNode {
        answer: Option<NotKept>,
        kept: Mutex<Vec<ReachNote>>,
        filed: Mutex<Vec<serde_json::Value>>,
    }

    impl BobsNode {
        fn new(answer: Option<NotKept>) -> Self {
            Self { answer, kept: Mutex::new(vec![]), filed: Mutex::new(vec![]) }
        }
    }

    #[async_trait::async_trait]
    impl MessageHost for BobsNode {
        fn secrets(&self) -> &(dyn SecretsStore + Send + Sync) {
            &BobsKeychain
        }
        fn user_aid(&self, _user_id: &str) -> Option<String> {
            Some(BOB.to_string())
        }
        fn local_user_for_did(&self, _did: &str) -> Option<String> {
            None
        }
        fn user_current_key(&self, _user_id: &str) -> Option<[u8; 32]> {
            Some(bob().verifying_key().to_bytes())
        }
        async fn member_public_key(&self, _user_id: &str, did: &str) -> Option<[u8; 32]> {
            (did == ALICE).then(|| alice().verifying_key().to_bytes())
        }
        async fn contact_paths(&self, _: &str, _: &str) -> Result<Vec<outbox::Path>, String> {
            Err("nothing of Alice's is awake in these tests".to_string())
        }
        async fn deliver_on(&self, _: &str, _: &str, _: &outbox::Path, _: &ContactRequest) -> Result<ContactResponse, String> {
            unreachable!("no path to Alice is ever named in these tests")
        }
        fn sign_delivery_ack(&self, message_id: &str, from_did: &str, to_did: &str) -> kotton_wire::ipc::DeliveryAck {
            kotton_crypto::delivery_ack::sign(message_id, from_did, to_did, &SigningKey::from_bytes(&[20; 32]))
        }
        async fn contact_reach_note(&self, _: &str, _: &str) -> Option<ReachNote> {
            None
        }
        async fn outbox_entries(&self, _: &str) -> anyhow::Result<Vec<outbox::OutboxEntry>> {
            Ok(vec![])
        }
        async fn keep_outbox_entry(&self, _: &str, _: &outbox::OutboxEntry) -> anyhow::Result<()> {
            Ok(())
        }
        async fn drop_outbox_entry(&self, _: &str, _: &str) -> anyhow::Result<()> {
            Ok(())
        }
        async fn keep_signed_for(&self, _: &str, _: &outbox::SignedFor) -> anyhow::Result<()> {
            Ok(())
        }
        async fn all_signed_for(&self, _: &str) -> anyhow::Result<Vec<outbox::SignedFor>> {
            Ok(vec![])
        }
        async fn keep_reach_note(&self, _: &str, contact_did: &str, note: ReachNote) -> Result<Kept, NotKept> {
            assert_eq!(contact_did, ALICE, "the note is kept on the card of whoever sent it");
            if let Some(answer) = &self.answer {
                return Err(answer.clone());
            }
            self.kept.lock().unwrap().push(note);
            Ok(Kept::Replaced)
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
        async fn contact_name(&self, _: &str, _: &str) -> Option<String> {
            None
        }
        async fn personal_names(&self, _: &str, _: &str) -> Result<Vec<String>, String> {
            unreachable!("nothing in these tests is a share")
        }
        async fn personal_write(&self, _: &str, _: &str, _: &[u8]) -> Result<(), String> {
            unreachable!("nothing in these tests is a share")
        }
        async fn stream_keep(&self, _: &str, _: &str, _: &[u8]) -> Result<(), String> {
            unreachable!("nothing in these tests is a share")
        }
        async fn stream_keys(&self, _: &str) -> Result<Vec<String>, String> {
            unreachable!("nothing in these tests is a share")
        }
        async fn stream_read(&self, _: &str, _: &str) -> Result<Vec<u8>, String> {
            unreachable!("nothing in these tests is a share")
        }
        async fn stream_drop(&self, _: &str, _: &str) -> Result<(), String> {
            unreachable!("nothing in these tests is a share")
        }
        async fn record_insert(&self, _: &str, _: &str, record: serde_json::Value) -> anyhow::Result<String> {
            self.filed.lock().unwrap().push(record);
            Ok("row".to_string())
        }
        async fn record_delete(&self, _: &str, _: &str, _: &str) -> anyhow::Result<()> {
            anyhow::bail!("nothing in these tests deletes a record")
        }
        async fn record_query(
            &self,
            _: &str,
            _: &str,
            _: Vec<(String, serde_json::Value)>,
            _: Option<usize>,
            _: Option<usize>,
            _: Option<String>,
        ) -> anyhow::Result<Vec<serde_json::Value>> {
            Ok(vec![])
        }
    }

    /// Alice's note, sealed to Bob the way her reach keeper sends it.
    fn alices_note_to_bob() -> (ReachNote, SealedDm) {
        let note = reach_note::next(
            None,
            ALICE,
            &[RelayRef { key: None, addr: "https://relay.alice".into(), admit: None }],
            &[],
            &alice(),
            reach_note::REACH_NOTE_TTL_SECS,
        )
        .unwrap();
        let inner = DmInner {
            from_did: ALICE.into(),
            to_did: BOB.into(),
            thread_id: String::new(),
            sent_at: 1,
            kind: "reach".into(),
            text: String::new(),
            channel: None,
            grant: None,
            reach: Some(note.clone()),
            ack: None,
            kel: Vec::new(),
            share: None,
            range: None,
        };
        let sealed = envelope::seal(&inner, &alice(), &bob().verifying_key().to_bytes()).unwrap();
        (note, sealed)
    }

    #[tokio::test]
    async fn a_note_at_the_door_goes_to_the_card_and_files_no_message() {
        let node = BobsNode::new(None);
        let (note, sealed) = alices_note_to_bob();
        let answer = accept(
            &node,
            "bob",
            ALICE,
            &alice().verifying_key().to_bytes(),
            ContactRequest::DeliverMessage { sealed },
        )
        .await;
        assert!(matches!(answer, ContactResponse::Delivered { stored: true, ack: None }), "{answer:?}");
        assert_eq!(*node.kept.lock().unwrap(), vec![note]);
        assert!(node.filed.lock().unwrap().is_empty(), "a note is never a message in the conversation");
    }

    /// The card's verdict on a note is said at the door as one, so the sender
    /// hands that note over no more; a card this node failed to read or write
    /// gave no verdict, and is said as a refusal the sender tries again past
    /// (`TASK-a-reach-note-a-contact-refused-is-sent-to-them-again-every-hour`).
    #[tokio::test]
    async fn a_note_the_card_refuses_is_declined_at_the_door_and_one_it_failed_to_keep_is_refused() {
        let at_the_door = |not_kept: NotKept| async move {
            let node = BobsNode::new(Some(not_kept));
            let (_, sealed) = alices_note_to_bob();
            accept(&node, "bob", ALICE, &alice().verifying_key().to_bytes(), ContactRequest::CarryMessage { sealed })
                .await
        };
        let refused = at_the_door(NotKept::Refused("a newer reach note is already held".into())).await;
        assert!(
            matches!(&refused, ContactResponse::Declined { reason } if reason == "a newer reach note is already held"),
            "{refused:?}"
        );
        let failed = at_the_door(NotKept::Failed("could not read the card".into())).await;
        assert!(
            matches!(&failed, ContactResponse::Refused { reason } if reason == "could not read the card"),
            "{failed:?}"
        );
    }

    #[tokio::test]
    async fn a_note_held_at_the_vault_goes_to_the_card_and_files_no_message() {
        let node = BobsNode::new(None);
        let (note, sealed) = alices_note_to_bob();
        let held = PendingDelivery { handle_did: "did:key:z6Mkdoor".into(), sealed };
        assert_eq!(file_from_vault(&node, "bob", &held).await, Ok(true));
        assert_eq!(*node.kept.lock().unwrap(), vec![note]);
        assert!(node.filed.lock().unwrap().is_empty(), "a note is never a message in the conversation");
    }

    /// Superseded or expired while it waited, a note only becomes more refused
    /// with time; left on the vault it would be refused at every pickup.
    #[tokio::test]
    async fn a_note_the_card_refuses_is_taken_off_the_vault() {
        let node = BobsNode::new(Some(NotKept::Refused("a newer reach note is already held".into())));
        let (_, sealed) = alices_note_to_bob();
        let held = PendingDelivery { handle_did: "did:key:z6Mkdoor".into(), sealed };
        assert_eq!(
            file_from_vault(&node, "bob", &held).await,
            Ok(false),
            "Ok is what acknowledges it to the vault; an error would leave it held"
        );
        assert!(node.filed.lock().unwrap().is_empty());
    }

    /// A note this node only *failed* to keep is not a refusal: it may be
    /// good, so it stays on the vault for the next pickup.
    #[tokio::test]
    async fn a_note_this_node_failed_to_keep_stays_on_the_vault() {
        let node = BobsNode::new(Some(NotKept::Failed("could not read the card".into())));
        let (_, sealed) = alices_note_to_bob();
        let held = PendingDelivery { handle_did: "did:key:z6Mkdoor".into(), sealed };
        assert!(
            file_from_vault(&node, "bob", &held).await.is_err(),
            "an error is what leaves it held"
        );
    }
}

#[cfg(test)]
mod rotation_tests {
    //! A contact's card follows a person through a rotation on the person's own
    //! proof and on nothing else (`TASK-a-rotated-persons-contacts-keep-the-key-it-retired`).
    //!
    //! Bob's card holds Alice's key and the key log it kept at pairing. Alice
    //! rotates with her phrase. What reaches Bob afterwards is signed with her new
    //! key, and what carries her log teaches the card that key; what does not —
    //! or carries a log that is older, or not hers to extend — is refused, and the
    //! card is left as it was.
    use super::*;
    use crate::envelope::DmInner;
    use ed25519_dalek::SigningKey;
    use kotton_crypto::kdf::derive_kel_recovery_key;
    use kotton_crypto::kel_verify::{build_mnemonic_rotation, build_user_inception, kel_recovery_pubkey};
    use kotton_crypto::reach_note::{self, RelayRef};
    use kotton_sys::secret::{SecretsResult, SecretsStore};
    use kotton_wire::ipc::SealedDm;
    use kotton_wire::kel::KelEvent;
    use std::sync::Mutex;

    const BOB: &str = "did:kel:bob";

    fn bob() -> SigningKey {
        SigningKey::from_bytes(&[2; 32])
    }
    fn seed() -> [u8; 32] {
        [42; 32]
    }
    /// Alice's key before the rotation: the one her inception installs.
    fn alice_old() -> SigningKey {
        SigningKey::from_bytes(&kotton_crypto::kdf::derive_identity_key(&seed()))
    }
    fn alice_new() -> SigningKey {
        SigningKey::from_bytes(&[9; 32])
    }
    fn alice_later() -> SigningKey {
        SigningKey::from_bytes(&[10; 32])
    }
    /// Alice's log: her inception, then one phrase rotation per key given.
    fn alices_log(rotations: &[SigningKey]) -> Vec<KelEvent> {
        let mut log = vec![build_user_inception(&seed())];
        for (i, k) in rotations.iter().enumerate() {
            let prev = log.last().unwrap().clone();
            let rung = kel_recovery_pubkey(&derive_kel_recovery_key(&seed(), i as u64));
            log.push(build_mnemonic_rotation(&prev, &seed(), i as u64, k, 0, &[rung]));
        }
        log
    }
    fn alice_did() -> String {
        alices_log(&[])[0].aid.0.clone()
    }

    struct BobsKeychain;
    impl SecretsStore for BobsKeychain {
        fn get_secret(&self, _key: &str) -> SecretsResult<Option<String>> {
            Ok(Some(hex::encode(bob().to_bytes())))
        }
        fn set_secret(&self, _key: &str, _value: &str) -> SecretsResult<()> {
            Ok(())
        }
        fn delete_secret(&self, _key: &str) -> SecretsResult<()> {
            Ok(())
        }
    }

    /// Bob's node with one card — Alice's — holding a key and the log it kept.
    struct BobsCard {
        key: Mutex<[u8; 32]>,
        log: Mutex<Vec<KelEvent>>,
        note: Mutex<Option<ReachNote>>,
        filed: Mutex<Vec<serde_json::Value>>,
    }

    impl BobsCard {
        /// As pairing left it: her key then, and her log then.
        fn paired() -> Self {
            Self::holding(alice_old(), alices_log(&[]))
        }
        fn holding(key: SigningKey, log: Vec<KelEvent>) -> Self {
            Self {
                key: Mutex::new(key.verifying_key().to_bytes()),
                log: Mutex::new(log),
                note: Mutex::new(None),
                filed: Mutex::new(vec![]),
            }
        }
        fn key(&self) -> [u8; 32] {
            *self.key.lock().unwrap()
        }
    }

    #[async_trait::async_trait]
    impl MessageHost for BobsCard {
        fn secrets(&self) -> &(dyn SecretsStore + Send + Sync) {
            &BobsKeychain
        }
        fn user_aid(&self, _: &str) -> Option<String> {
            Some(BOB.to_string())
        }
        fn local_user_for_did(&self, _: &str) -> Option<String> {
            None
        }
        fn user_current_key(&self, _: &str) -> Option<[u8; 32]> {
            Some(bob().verifying_key().to_bytes())
        }
        async fn member_public_key(&self, _: &str, did: &str) -> Option<[u8; 32]> {
            (did == alice_did()).then(|| self.key())
        }
        async fn contact_paths(&self, _: &str, _: &str) -> Result<Vec<outbox::Path>, String> {
            Err("nothing of Alice's is awake in these tests".to_string())
        }
        async fn deliver_on(&self, _: &str, _: &str, _: &outbox::Path, _: &kotton_wire::ipc::ContactRequest) -> Result<ContactResponse, String> {
            unreachable!("no path to Alice is ever named in these tests")
        }
        fn sign_delivery_ack(&self, message_id: &str, from_did: &str, to_did: &str) -> kotton_wire::ipc::DeliveryAck {
            kotton_crypto::delivery_ack::sign(message_id, from_did, to_did, &SigningKey::from_bytes(&[20; 32]))
        }
        async fn contact_reach_note(&self, _: &str, _: &str) -> Option<ReachNote> {
            self.note.lock().unwrap().clone()
        }
        async fn outbox_entries(&self, _: &str) -> anyhow::Result<Vec<outbox::OutboxEntry>> {
            Ok(vec![])
        }
        async fn keep_outbox_entry(&self, _: &str, _: &outbox::OutboxEntry) -> anyhow::Result<()> {
            Ok(())
        }
        async fn drop_outbox_entry(&self, _: &str, _: &str) -> anyhow::Result<()> {
            Ok(())
        }
        async fn keep_signed_for(&self, _: &str, _: &outbox::SignedFor) -> anyhow::Result<()> {
            Ok(())
        }
        async fn all_signed_for(&self, _: &str) -> anyhow::Result<Vec<outbox::SignedFor>> {
            Ok(vec![])
        }
        /// The card's own rule: believed under the key the card holds.
        async fn keep_reach_note(&self, _: &str, contact_did: &str, note: ReachNote) -> Result<Kept, NotKept> {
            let held = self.note.lock().unwrap().clone();
            let card = crate::daemon::messages::NoteCard { held: held.as_ref(), key: &self.key() };
            let kept = crate::daemon::messages::judge_reach_note(Some(card), &note, contact_did, 1_000)?;
            *self.note.lock().unwrap() = Some(note);
            Ok(kept)
        }
        fn own_key_log(&self, _: &str) -> Vec<KelEvent> {
            Vec::new()
        }
        fn contact_key_log(&self, _: &str, _: &str) -> Vec<KelEvent> {
            self.log.lock().unwrap().clone()
        }
        async fn adopt_contact_key(&self, _: &str, _: &str, log: &[KelEvent], key: [u8; 32]) -> Result<(), NotKept> {
            *self.log.lock().unwrap() = log.to_vec();
            *self.key.lock().unwrap() = key;
            Ok(())
        }
        fn retired_identity_keys(&self, _: &str, _: &SigningKey) -> Vec<SigningKey> {
            Vec::new()
        }
        async fn contact_name(&self, _: &str, _: &str) -> Option<String> {
            None
        }
        async fn personal_names(&self, _: &str, _: &str) -> Result<Vec<String>, String> {
            unreachable!("nothing in these tests is a share")
        }
        async fn personal_write(&self, _: &str, _: &str, _: &[u8]) -> Result<(), String> {
            unreachable!("nothing in these tests is a share")
        }
        async fn stream_keep(&self, _: &str, _: &str, _: &[u8]) -> Result<(), String> {
            unreachable!("nothing in these tests is a share")
        }
        async fn stream_keys(&self, _: &str) -> Result<Vec<String>, String> {
            unreachable!("nothing in these tests is a share")
        }
        async fn stream_read(&self, _: &str, _: &str) -> Result<Vec<u8>, String> {
            unreachable!("nothing in these tests is a share")
        }
        async fn stream_drop(&self, _: &str, _: &str) -> Result<(), String> {
            unreachable!("nothing in these tests is a share")
        }
        async fn record_insert(&self, _: &str, _: &str, record: serde_json::Value) -> anyhow::Result<String> {
            self.filed.lock().unwrap().push(record);
            Ok("row".to_string())
        }
        async fn record_delete(&self, _: &str, _: &str, _: &str) -> anyhow::Result<()> {
            anyhow::bail!("nothing in these tests deletes a record")
        }
        async fn record_query(
            &self,
            _: &str,
            _: &str,
            _: Vec<(String, serde_json::Value)>,
            _: Option<usize>,
            _: Option<usize>,
            _: Option<String>,
        ) -> anyhow::Result<Vec<serde_json::Value>> {
            Ok(vec![])
        }
    }

    /// What Alice's node seals to Bob, signed by `signer`, carrying `log`: her
    /// reach note when `note` is set, a message otherwise.
    fn from_alice(signer: &SigningKey, log: Vec<KelEvent>, note: bool, version: u64) -> SealedDm {
        let reach = note.then(|| {
            reach_note::sign(
                &alice_did(),
                vec![RelayRef { key: None, addr: "https://relay.alice".into(), admit: None }],
                vec![],
                version,
                1_000 + reach_note::REACH_NOTE_TTL_SECS,
                signer,
            )
        });
        let inner = DmInner {
            from_did: alice_did(),
            to_did: BOB.into(),
            thread_id: if note { String::new() } else { "t".into() },
            sent_at: 1,
            kind: if note { "reach" } else { "text" }.into(),
            text: if note { String::new() } else { "the boat is at slip 4".into() },
            channel: None,
            grant: None,
            reach,
            ack: None,
            kel: log,
            share: None,
            range: None,
        };
        envelope::seal(&inner, signer, &bob().verifying_key().to_bytes()).unwrap()
    }

    async fn at_the_door(card: &BobsCard, sealed: SealedDm) -> ContactResponse {
        // The door admitted the key the card held when it was opened.
        let admitted = card.key();
        accept(card, "bob", &alice_did(), &admitted, ContactRequest::DeliverMessage { sealed }).await
    }

    #[tokio::test]
    async fn a_note_carrying_her_log_teaches_the_card_her_new_key_and_then_her_message_is_filed() {
        let card = BobsCard::paired();
        let new = alice_new();

        // Before the card learns it, her new key is a stranger's.
        let early = at_the_door(&card, from_alice(&new, vec![], false, 0)).await;
        assert!(matches!(early, ContactResponse::Refused { .. }), "{early:?}");
        assert!(card.filed.lock().unwrap().is_empty());

        let answer = at_the_door(&card, from_alice(&new, alices_log(std::slice::from_ref(&new)), true, 2)).await;
        assert!(matches!(answer, ContactResponse::Delivered { stored: true, .. }), "{answer:?}");
        assert_eq!(card.key(), new.verifying_key().to_bytes(), "the card holds the key her log proves");
        assert_eq!(*card.log.lock().unwrap(), alices_log(std::slice::from_ref(&new)), "and the log that proved it");
        assert!(card.note.lock().unwrap().is_some(), "and her note, signed with that key");

        let message = at_the_door(&card, from_alice(&new, vec![], false, 0)).await;
        assert!(matches!(message, ContactResponse::Delivered { stored: true, .. }), "{message:?}");
        assert_eq!(card.filed.lock().unwrap().len(), 1, "her message, signed with her new key, is filed");
    }

    #[tokio::test]
    async fn a_vault_holding_her_note_teaches_the_card_the_same_way() {
        let card = BobsCard::paired();
        let new = alice_new();
        let held = PendingDelivery {
            handle_did: "did:key:z6Mkdoor".into(),
            sealed: from_alice(&new, alices_log(std::slice::from_ref(&new)), true, 2),
        };
        assert_eq!(file_from_vault(&card, "bob", &held).await, Ok(true));
        assert_eq!(card.key(), new.verifying_key().to_bytes());
    }

    /// A carrier replaying the log from before a later rotation cannot put a
    /// retired key back: the card holds the longer log, and the older one does
    /// not continue it.
    #[tokio::test]
    async fn a_replayed_older_log_is_refused_and_the_card_keeps_its_key() {
        let (new, later) = (alice_new(), alice_later());
        let card = BobsCard::holding(later.clone(), alices_log(&[new.clone(), later.clone()]));
        let replayed = from_alice(&new, alices_log(std::slice::from_ref(&new)), true, 2);
        let answer = at_the_door(&card, replayed.clone()).await;
        assert!(matches!(answer, ContactResponse::Refused { .. }), "{answer:?}");
        let held = PendingDelivery { handle_did: "did:key:z6Mkdoor".into(), sealed: replayed };
        assert!(file_from_vault(&card, "bob", &held).await.is_err());
        assert_eq!(card.key(), later.verifying_key().to_bytes(), "the card keeps the newest key");
    }

    /// Someone holding Alice's *old* key — the thief a rotation evicts — cannot
    /// write a rotation of their own: they do not hold her reserve, so the log
    /// they carry does not replay, whatever they sign it with.
    #[tokio::test]
    async fn a_rotation_signed_by_the_old_key_is_not_a_rotation() {
        let card = BobsCard::paired();
        let thief = SigningKey::from_bytes(&[13; 32]);
        let inception = alices_log(&[])[0].clone();
        // A rotation built from somebody else's phrase: its revealed key is not
        // the one her inception committed.
        let forged = build_mnemonic_rotation(&inception, &[7; 32], 0, &thief, 0, &[]);
        for signer in [&thief, &alice_old()] {
            let answer = at_the_door(&card, from_alice(signer, vec![inception.clone(), forged.clone()], true, 2)).await;
            assert!(matches!(answer, ContactResponse::Refused { .. }), "{answer:?}");
        }
        assert_eq!(card.key(), alice_old().verifying_key().to_bytes(), "the card keeps her key");
        assert_eq!(card.log.lock().unwrap().len(), 1, "and her log");
    }

    /// Her log, carried with an envelope her new key did not sign, teaches the
    /// card nothing: the log proves the key, and the key must then prove the
    /// envelope.
    #[tokio::test]
    async fn her_log_under_someone_elses_signature_changes_nothing() {
        let card = BobsCard::paired();
        let new = alice_new();
        let answer = at_the_door(&card, from_alice(&alice_old(), alices_log(&[new]), true, 2)).await;
        assert!(matches!(answer, ContactResponse::Refused { .. }), "{answer:?}");
        assert_eq!(card.key(), alice_old().verifying_key().to_bytes());
        assert_eq!(card.log.lock().unwrap().len(), 1);
    }
}

/// The door's check of a channel's author: a copy or a grant is filed only if
/// whoever sent it is in the roster of the receiver's newest grant
/// (`TASK-a-channel-member-who-admitted-nobody-sees-a-channel-of-one`).
#[cfg(test)]
mod tests_channel_author {
    use super::*;
    use crate::daemon::messages::test_node::{grant, Node};
    use crate::envelope::{ChannelCopy, ChannelGrant};
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use kotton_crypto::x25519::{channel_encrypt, channel_key_generate};

    const AVERY: &str = "did:kel:avery";
    const SAM: &str = "did:kel:sam";
    const JORDAN: &str = "did:kel:jordan";
    const CHANNEL: &str = "did:key:zHousehold";

    fn seed(did: &str) -> u8 {
        match did {
            AVERY => 1,
            SAM => 2,
            JORDAN => 3,
            _ => unreachable!(),
        }
    }

    fn key_of(did: &str) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed(did); 32])
    }

    /// Avery's node after Sam removed Jordan: epoch 2 was Avery, Sam and
    /// Jordan's; epoch 3, which the removal minted, is Avery's and Sam's.
    /// Returns the node and the epoch-2 key, which Jordan still holds.
    fn avery_after_jordan_was_removed() -> (Node, [u8; 32]) {
        let avery = Node::new(AVERY, 1, &[(SAM, 2), (JORDAN, 3)]);
        let epoch2 = channel_key_generate();
        avery.keep(NSID_CHANNEL_KEY_GRANT, grant(CHANNEL, AVERY, 1, &epoch2, 2, Some(&[AVERY, SAM, JORDAN])));
        avery.keep(NSID_CHANNEL_KEY_GRANT, grant(CHANNEL, AVERY, 1, &channel_key_generate(), 3, Some(&[SAM, AVERY])));
        (avery, epoch2)
    }

    /// A channel copy from `from` to Avery, sealed under `key` at `epoch`.
    fn copy(from: &str, key: &[u8; 32], epoch: u64, text: &str) -> SealedDm {
        let (body, nonce) = channel_encrypt(text.as_bytes(), key).unwrap();
        let inner = DmInner {
            from_did: from.into(),
            to_did: AVERY.into(),
            thread_id: "t".into(),
            sent_at: 1,
            kind: "text".into(),
            text: String::new(),
            channel: Some(ChannelCopy {
                channel_did: CHANNEL.into(),
                epoch,
                body,
                nonce: B64.encode(nonce),
            }),
            grant: None,
            reach: None,
            ack: None,
            kel: Vec::new(),
            share: None,
            range: None,
        };
        envelope::seal(&inner, &key_of(from), &key_of(AVERY).verifying_key().to_bytes()).unwrap()
    }

    async fn at_averys_door(avery: &Node, from: &str, sealed: SealedDm) -> ContactResponse {
        let from_pub = key_of(from).verifying_key().to_bytes();
        accept(avery, "u", from, &from_pub, ContactRequest::DeliverMessage { sealed }).await
    }

    /// Jordan, removed, posts at the epoch they still hold. Avery holds that
    /// epoch too and could open it — the door refuses it, naming the epoch
    /// Avery is at, and nothing is filed.
    #[tokio::test]
    async fn a_removed_members_post_at_an_epoch_they_still_hold_is_refused_at_the_door() {
        let (avery, epoch2) = avery_after_jordan_was_removed();
        let answer = at_averys_door(&avery, JORDAN, copy(JORDAN, &epoch2, 2, "still here")).await;
        let ContactResponse::Declined { reason } = answer else { panic!("{answer:?}") };
        assert!(reason.contains(JORDAN) && reason.contains("at epoch 3"), "{reason}");
        assert!(avery.all(NSID_MESSAGE_V1).is_empty(), "nothing of Jordan's is filed");
    }

    /// The same post, carried to Avery's vault while nothing of Avery's was
    /// awake, is held to the same rule when it is picked up: taken off the
    /// vault, and not filed.
    #[tokio::test]
    async fn a_removed_members_post_picked_up_from_the_vault_is_not_filed() {
        let (avery, epoch2) = avery_after_jordan_was_removed();
        let held = PendingDelivery { handle_did: "did:key:door".into(), sealed: copy(JORDAN, &epoch2, 2, "still here") };
        assert_eq!(file_from_vault(&avery, "u", &held).await, Ok(false), "taken off the vault, not filed");
        assert!(avery.all(NSID_MESSAGE_V1).is_empty());
    }

    /// Avery's node holding a channel from before rosters: epoch 2, written by
    /// Avery, to Avery and Sam, with no roster in either grant.
    fn avery_holding_a_channel_from_before_rosters() -> (Node, [u8; 32]) {
        let avery = Node::new(AVERY, 1, &[(SAM, 2), (JORDAN, 3)]);
        let epoch2 = channel_key_generate();
        avery.keep(NSID_CHANNEL_KEY_GRANT, grant(CHANNEL, AVERY, 1, &epoch2, 2, None));
        avery.keep(NSID_CHANNEL_KEY_GRANT, grant(CHANNEL, SAM, 2, &epoch2, 2, None));
        (avery, epoch2)
    }

    /// Jordan's grant to Avery at `epoch`, carrying a roster of `roster`.
    fn jordans_grant_to_avery(epoch: u64, roster: &[&str]) -> SealedDm {
        let minted = grant(CHANNEL, AVERY, 1, &channel_key_generate(), epoch, Some(roster));
        let field = |k: &str| minted[k].as_str().unwrap().to_string();
        let inner = DmInner {
            from_did: JORDAN.into(),
            to_did: AVERY.into(),
            thread_id: "t".into(),
            sent_at: 1,
            kind: "text".into(),
            text: String::new(),
            channel: None,
            grant: Some(ChannelGrant {
                channel_did: CHANNEL.into(),
                epoch,
                enc_key: field("enc_key"),
                nonce: field("nonce"),
                ephemeral_pub: field("ephemeral_pub"),
                granted_at: 1,
                roster: Some(crate::envelope::SealedRoster { body: field("roster"), nonce: field("roster_nonce") }),
            }),
            reach: None,
            ack: None,
            kel: Vec::new(),
            share: None,
            range: None,
        };
        envelope::seal(&inner, &key_of(JORDAN), &key_of(AVERY).verifying_key().to_bytes()).unwrap()
    }

    /// The assessor's case. In a channel from before rosters, Jordan — a
    /// contact, and no writer of the grant Avery holds — hands Avery epoch 3
    /// with a roster of Avery and Jordan. Filed, it would become Avery's
    /// membership: her next post sealed under Jordan's key, and Sam dropped.
    /// It is refused, and Avery's membership is the one she held.
    #[tokio::test]
    async fn a_channel_from_before_rosters_takes_no_epoch_from_a_contact_who_did_not_write_its_grants() {
        let (avery, _) = avery_holding_a_channel_from_before_rosters();
        let answer = at_averys_door(&avery, JORDAN, jordans_grant_to_avery(3, &[AVERY, JORDAN])).await;
        let ContactResponse::Declined { reason } = answer else { panic!("{answer:?}") };
        assert!(reason.contains("before rosters") && reason.contains("epoch 2"), "{reason}");
        assert_eq!(avery.all(NSID_CHANNEL_KEY_GRANT).len(), 2, "no grant of Jordan's is filed");
        let members = crate::daemon::messages::current_members(&avery, "u", CHANNEL, AVERY, &key_of(AVERY), &mut None)
            .await
            .expect("avery holds epoch 2");
        assert_eq!((members.epoch, members.dids), (2, vec![AVERY.to_string(), SAM.to_string()]));
    }

    /// A message in a channel from before rosters is filed as it always was:
    /// it cannot change who is in the channel.
    #[tokio::test]
    async fn a_message_in_a_channel_from_before_rosters_is_filed_as_before() {
        let (avery, epoch2) = avery_holding_a_channel_from_before_rosters();
        let answer = at_averys_door(&avery, SAM, copy(SAM, &epoch2, 2, "as before")).await;
        assert!(matches!(answer, ContactResponse::Delivered { stored: true, .. }), "{answer:?}");
    }

    /// Sam, still in, sent at epoch 2 while the removal was in flight. Sam is
    /// in the current roster, so the copy is filed.
    #[tokio::test]
    async fn a_members_post_sealed_at_an_older_epoch_during_a_rotation_is_filed() {
        let (avery, epoch2) = avery_after_jordan_was_removed();
        let answer = at_averys_door(&avery, SAM, copy(SAM, &epoch2, 2, "in flight")).await;
        assert!(matches!(answer, ContactResponse::Delivered { stored: true, .. }), "{answer:?}");
        assert_eq!(avery.all(NSID_MESSAGE_V1).len(), 1);
    }

    /// Jordan, removed, mints an epoch of their own and hands it to Avery. A
    /// grant is a rotation once Avery is in the channel, and Jordan does not
    /// hold the current key — so it is not filed, and Avery's membership is not
    /// rewritten by somebody who was taken out of it.
    #[tokio::test]
    async fn a_removed_member_cannot_hand_a_remaining_one_an_epoch_of_their_own() {
        let (avery, _) = avery_after_jordan_was_removed();
        let sealed = jordans_grant_to_avery(4, &[AVERY, JORDAN]);
        let answer = at_averys_door(&avery, JORDAN, sealed).await;
        assert!(matches!(&answer, ContactResponse::Refused { reason } if reason.contains("at epoch 3")), "{answer:?}");
        assert_eq!(avery.all(NSID_CHANNEL_KEY_GRANT).len(), 2, "no grant of Jordan's is filed");
    }

    /// Avery was admitted while every device of hers was off, so Jordan's
    /// grant waited at her vault. Picked up, it is filed as the door files
    /// one: in the grants namespace, with the roster it carried, so she holds
    /// the key and learns who is in the channel — and nothing of it lands in
    /// the conversation. A second pickup of the same grant, and the same grant
    /// reaching her door, file nothing more; and nothing is signed back, as
    /// nothing is for a grant at the door
    /// (`TASK-a-key-grant-picked-up-from-a-vault-is-filed-as-an-empty-message`).
    #[tokio::test]
    async fn a_grant_that_waited_at_the_vault_is_filed_as_a_grant_and_not_as_a_message() {
        let avery = Node::new(AVERY, 1, &[(SAM, 2), (JORDAN, 3)]);
        let sealed = jordans_grant_to_avery(1, &[JORDAN, AVERY]);
        let held = PendingDelivery { handle_did: "did:key:door".into(), sealed: sealed.clone() };

        assert_eq!(file_from_vault(&avery, "u", &held).await, Ok(true), "filed");
        let grants = avery.all(NSID_CHANNEL_KEY_GRANT);
        assert_eq!(grants.len(), 1, "one grant row");
        assert_eq!(grants[0]["channel_did"], CHANNEL);
        assert_eq!(grants[0]["to_did"], AVERY);
        assert!(grants[0].get("roster").is_some() && grants[0].get("roster_nonce").is_some(), "with its roster");
        assert!(avery.all(NSID_MESSAGE_V1).is_empty(), "nothing in the conversation");
        let members = crate::daemon::messages::current_members(&avery, "u", CHANNEL, AVERY, &key_of(AVERY), &mut None)
            .await
            .expect("avery holds the channel now");
        assert_eq!((members.epoch, members.dids), (1, vec![JORDAN.to_string(), AVERY.to_string()]));

        assert_eq!(file_from_vault(&avery, "u", &held).await, Ok(false), "a second pickup files nothing more");
        let answer = at_averys_door(&avery, JORDAN, sealed).await;
        assert!(matches!(answer, ContactResponse::Delivered { stored: false, ack: None }), "{answer:?}");
        assert_eq!(avery.all(NSID_CHANNEL_KEY_GRANT).len(), 1, "still one grant row");
        assert!(avery.all(NSID_MESSAGE_V1).is_empty());
        assert!(avery.handed.lock().unwrap().is_empty(), "nothing signed back for a grant");
    }

    /// Jordan, removed, hands Avery an epoch of their own while she sleeps.
    /// The pickup answers as the door does: at an epoch Avery has reached it
    /// is a verdict, declined at the door and taken off the vault, and nothing
    /// is filed; at a newer one, whose rotation may not have reached her yet,
    /// it is refused at the door and stays held at the vault.
    #[tokio::test]
    async fn a_grant_from_outside_the_roster_is_refused_at_the_pickup_as_at_the_door() {
        let (avery, _) = avery_after_jordan_was_removed();

        let reached = jordans_grant_to_avery(3, &[AVERY, JORDAN]);
        let answer = at_averys_door(&avery, JORDAN, reached.clone()).await;
        assert!(matches!(&answer, ContactResponse::Declined { reason } if reason.contains("at epoch 3")), "{answer:?}");
        let held = PendingDelivery { handle_did: "did:key:door".into(), sealed: reached };
        assert_eq!(file_from_vault(&avery, "u", &held).await, Ok(false), "taken off the vault, not filed");

        let newer = jordans_grant_to_avery(4, &[AVERY, JORDAN]);
        let answer = at_averys_door(&avery, JORDAN, newer.clone()).await;
        assert!(matches!(&answer, ContactResponse::Refused { reason } if reason.contains("at epoch 3")), "{answer:?}");
        let held = PendingDelivery { handle_did: "did:key:door".into(), sealed: newer };
        let kept = file_from_vault(&avery, "u", &held).await;
        assert!(matches!(&kept, Err(reason) if reason.contains("at epoch 3")), "stays held: {kept:?}");

        assert_eq!(avery.all(NSID_CHANNEL_KEY_GRANT).len(), 2, "no grant of Jordan's is filed");
        assert!(avery.all(NSID_MESSAGE_V1).is_empty(), "nor anything in the conversation");
    }
}
