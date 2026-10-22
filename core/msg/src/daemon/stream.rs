// SPDX-License-Identifier: AGPL-3.0-or-later
//! Taking a share's bytes as they stream (RFC-0090, *Mechanism › Above the
//! frame cap*; RFC-0048 ST2–ST4;
//! `TASK-a-share-above-the-frame-cap-arrives-whole-by-the-streaming-transport`).
//!
//! **What arrives.** A share above [`INLINE_MAX`](crate::share::INLINE_MAX) is
//! its manifest, a message like any other, and its bytes as
//! [`Range`]s — each a direct message of its own, sealed to this person with a
//! fresh key and signed by the sender, handed over the contact door as every
//! message is. Nothing outside the seal says which is which. A share to a group
//! above [`GROUP_INLINE_MAX`](crate::share::GROUP_INLINE_MAX) arrives the same
//! way, except that its manifest and each range's plaintext are channel
//! ciphertext — one per range, the same for every member — inside this
//! person's envelope: its ranges are taken only from an author in the channel
//! and only opened with a key this person holds (`delivery::take_range`), and
//! they name the share by the manifest's channel nonce ([`share_id`]).
//!
//! **What this keeps, and where.** On this person's *stream shelf*
//! ([`MessageHost::stream_keep`]): a daemon object in their own store, out of
//! every app's reach and out of their tree, so nothing of a share is anywhere
//! a person or an app can see until it is filed whole. Keyed by content
//! (RFC-0048 ST3) — the share's digest and its size — and by whom it is from
//! and which share it is: two shares of the same bytes are two shares, and
//! each is filed when its own ranges are whole.
//!
//! **Nothing is filed until the stream is whole and hashes to the digest.** The
//! manifest is kept *waiting* for its bytes when it arrives first, and files
//! nothing; each range is kept, and signed for, so the sender sends it no more
//! and a stream cut off resumes from the first range nobody signed for; when
//! the last range lands, the waiting manifest is filed exactly as an inline
//! share is (`delivery::file_message`). A stream whose bytes do not hash to
//! the digest files nothing, is set aside as refused, and is declined naming
//! the sender.
//!
//! **What bounds it.** A range is kept only for a stream whose manifest is
//! waiting — so nothing is buffered for a share that was never declared — and
//! only the bytes its place in that stream holds; one contact may have
//! [`STREAMS_PER_CONTACT`] manifests waiting at once, declaring at most
//! [`STREAM_BYTES_PER_CONTACT`] between them.

use super::messages::MessageHost;
use crate::envelope::DmInner;
use crate::share::{digest_of, range_count, Manifest, Range, RANGE_LEN};
use kotton_common::namespace::NSID_MESSAGE_V1;
use kotton_wire::ipc::SealedDm;
use serde::{Deserialize, Serialize};

/// How many shares one contact may have waiting for their bytes on this
/// person's shelf at once. A bound, so what a contact can make this node hold
/// is a number — at most this many times [`STREAM_MAX`](crate::share::STREAM_MAX)
/// — and not a hope. One more is refused as something that may clear with
/// time: the sender tries it again once one of the others is filed.
pub const STREAMS_PER_CONTACT: usize = 4;

/// How many bytes the shares one contact has waiting may declare between
/// them: two of the largest a share may be. A bound in bytes beside the bound
/// in shares, so four waiting shares are not a GiB of someone else's choosing.
pub const STREAM_BYTES_PER_CONTACT: u64 = 2 * crate::share::STREAM_MAX as u64;

/// Why a range or a manifest was not taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NotTaken {
    /// May clear with time — the shelf could not be read or written, the
    /// manifest it belongs to has not arrived, the contact has as many shares
    /// waiting as they may — so the sender tries again.
    Again(String),
    /// A verdict on these bytes, which another try cannot change.
    Verdict(String),
}

/// One stream on the shelf: who it is from, which bytes, and which share.
struct Stream {
    /// `<sender>.<digest>.<size>.<share>` — the sender and the share as the
    /// first characters of their SHA-256, so a key is short and holds only
    /// characters a store path carries as they are; one prefix per stream.
    prefix: String,
    /// `<sender>.` — every stream of theirs.
    sender: String,
}

impl Stream {
    fn of(sender_did: &str, digest: &str, size: u64, share: &str) -> Self {
        let sender = format!("{}.", &digest_of(sender_did.as_bytes())[..16]);
        let share = &digest_of(share.as_bytes())[..32];
        Self { prefix: format!("{sender}{digest}.{size}.{share}"), sender }
    }

    fn range(&self, offset: u64) -> String {
        format!("{}.{offset}", self.prefix)
    }

    /// The manifest waiting for this stream's bytes.
    fn waiting(&self) -> String {
        format!("{}.manifest", self.prefix)
    }

    /// That this stream's bytes did not hash to its digest.
    fn refused(&self) -> String {
        format!("{}.refused", self.prefix)
    }

    /// Every key of this stream's: its ranges, its manifest, its refusal.
    fn owns(&self, key: &str) -> bool {
        key.strip_prefix(self.prefix.as_str()).is_some_and(|rest| rest.starts_with('.'))
    }
}

/// The size a waiting manifest's key declares: the third field of its prefix.
fn declared_size(key: &str) -> u64 {
    key.split('.').nth(2).and_then(|n| n.parse().ok()).unwrap_or(0)
}

/// A manifest waiting for its bytes: the claims, proved when it arrived, and
/// the envelope it came in — what is filed once the bytes are whole.
#[derive(Serialize, Deserialize)]
struct Waiting {
    inner: DmInner,
    sealed: SealedDm,
}

/// Which share a manifest that arrived as `inner`, in `sealed`, is — the id
/// its ranges name it by ([`Range::share`]). For a direct share, its
/// envelope's id: the ranges are sealed to the one recipient beside it. For a
/// share to a group, the nonce of the channel ciphertext the manifest is
/// sealed in: each member's manifest comes in an envelope of its own, and its
/// ranges are one ciphertext for every member, so they name the share by what
/// every member's copy holds.
pub(crate) fn share_id<'a>(inner: &'a DmInner, sealed: &'a SealedDm) -> &'a str {
    match &inner.channel {
        Some(channel) => &channel.nonce,
        None => &sealed.ephemeral_pub,
    }
}

/// Keep `range` from `sender_did` toward its stream, its plaintext `bytes`
/// already held to its place ([`Range::holds_bytes`]) — carried in it, to a
/// person, or opened from its channel ciphertext, to a group, whose
/// `channel_did` is named. `Ok(true)` when this is what kept it, `Ok(false)`
/// when it was already kept — or when the share it is part of is already
/// filed, which is a verdict: the sender is signed for it and sends it no more.
///
/// Kept only for a stream whose manifest is waiting: a range for bytes nobody
/// declared is not held, and the sender tries it again once the manifest has
/// arrived.
pub(crate) async fn keep_range(
    host: &dyn MessageHost,
    user_id: &str,
    sender_did: &str,
    range: &Range,
    bytes: &[u8],
    channel_did: Option<&str>,
) -> Result<bool, NotTaken> {
    range.holds_bytes(bytes).map_err(NotTaken::Verdict)?;
    let stream = Stream::of(sender_did, &range.digest, range.size, &range.share);
    let keys = shelf(host, user_id).await?;
    if keys.iter().any(|k| *k == stream.refused()) {
        return Err(NotTaken::Verdict("its stream did not hash to its digest, and was refused".to_string()));
    }
    if !keys.iter().any(|k| *k == stream.waiting()) {
        // A range that arrives after its share was filed — another copy of it,
        // dialled on another path — is held already, in the file.
        if is_filed(host, user_id, sender_did, &range.share, channel_did).await? {
            return Ok(false);
        }
        return Err(NotTaken::Again("the share these bytes are part of has not arrived".to_string()));
    }
    let key = stream.range(range.offset);
    if keys.contains(&key) {
        return Ok(false);
    }
    host.stream_keep(user_id, &key, bytes).await.map_err(NotTaken::Again)?;
    Ok(true)
}

/// Whether the share `id` from `sender_did` is filed in `user_id`'s store: the
/// question the door's own deduplication asks, asked of that sender's
/// messages only — by the message's envelope id for a direct share, and for a
/// share to the group `channel_did` by its channel ciphertext's nonce in that
/// channel ([`share_id`]). A range names its share, and whoever sends it
/// chooses the name: asked of every sender's, the answer would tell any
/// contact whether a message someone else sent was filed here.
async fn is_filed(
    host: &dyn MessageHost,
    user_id: &str,
    sender_did: &str,
    id: &str,
    channel_did: Option<&str>,
) -> Result<bool, NotTaken> {
    let by = match channel_did {
        None => vec![("ephemeral_pub".to_string(), serde_json::Value::from(id))],
        Some(channel_did) => vec![
            ("nonce".to_string(), serde_json::Value::from(id)),
            ("channel_did".to_string(), serde_json::Value::from(channel_did)),
        ],
    };
    host.record_query(
        user_id,
        NSID_MESSAGE_V1,
        by.into_iter().chain([("from_did".to_string(), serde_json::Value::from(sender_did))]).collect(),
        Some(1),
        None,
        None,
    )
    .await
    .map(|found| !found.is_empty())
    .map_err(|e| NotTaken::Again(format!("could not check for a filed share: {e}")))
}

/// The waiting manifest of the stream `range` belongs to, once every range
/// of it is kept — what is filed now — or `None` while it is not whole.
pub(crate) async fn whole_and_waiting(
    host: &dyn MessageHost,
    user_id: &str,
    sender_did: &str,
    range: &Range,
) -> Option<(DmInner, SealedDm)> {
    let stream = Stream::of(sender_did, &range.digest, range.size, &range.share);
    let keys = shelf(host, user_id).await.ok()?;
    if !is_whole(&stream, range.size, &keys) || !keys.contains(&stream.waiting()) {
        return None;
    }
    let bytes = host.stream_read(user_id, &stream.waiting()).await.ok()?;
    let waiting: Waiting = serde_json::from_slice(&bytes).ok()?;
    Some((waiting.inner, waiting.sealed))
}

/// The plaintext of `manifest`'s stream from `sender_did` — the share whose
/// message id is `share` — assembled and
/// checked against its size and digest — `Ok(None)` while a range of it has
/// not arrived, and why when it does not hold. A stream that does not hold is
/// set aside as refused and its ranges let go: what is wrong stays wrong.
pub(crate) async fn bytes_of(
    host: &dyn MessageHost,
    user_id: &str,
    sender_did: &str,
    manifest: &Manifest,
    share: &str,
) -> Result<Option<Vec<u8>>, NotTaken> {
    let stream = Stream::of(sender_did, &manifest.digest, manifest.size, share);
    let keys = shelf(host, user_id).await?;
    if keys.contains(&stream.refused()) {
        return Err(NotTaken::Verdict("its bytes do not match the digest it carries".to_string()));
    }
    if !is_whole(&stream, manifest.size, &keys) {
        return Ok(None);
    }
    let mut bytes = Vec::with_capacity(manifest.size as usize);
    for i in 0..range_count(manifest.size) {
        let range = host
            .stream_read(user_id, &stream.range(i * RANGE_LEN as u64))
            .await
            .map_err(NotTaken::Again)?;
        bytes.extend_from_slice(&range);
    }
    if bytes.len() as u64 != manifest.size || crate::share::digest_of(&bytes) != manifest.digest {
        // Kept first, so a node that stops between the two still refuses it.
        host.stream_keep(user_id, &stream.refused(), b"").await.map_err(NotTaken::Again)?;
        for key in keys.iter().filter(|k| stream.owns(k) && **k != stream.refused()) {
            let _ = host.stream_drop(user_id, key).await;
        }
        return Err(NotTaken::Verdict("its bytes do not match the digest it carries".to_string()));
    }
    Ok(Some(bytes))
}

/// Keep `manifest`, which arrived as `inner` in `sealed`, waiting for its
/// bytes. Refused when `sender_did` already has [`STREAMS_PER_CONTACT`]
/// shares waiting, or would have more than [`STREAM_BYTES_PER_CONTACT`]
/// declared between them.
pub(crate) async fn keep_waiting(
    host: &dyn MessageHost,
    user_id: &str,
    sender_did: &str,
    manifest: &Manifest,
    inner: &DmInner,
    sealed: &SealedDm,
) -> Result<(), NotTaken> {
    let stream = Stream::of(sender_did, &manifest.digest, manifest.size, share_id(inner, sealed));
    let keys = shelf(host, user_id).await?;
    if keys.contains(&stream.waiting()) {
        return Ok(());
    }
    let theirs: Vec<&String> =
        keys.iter().filter(|k| k.starts_with(stream.sender.as_str()) && k.ends_with(".manifest")).collect();
    if theirs.len() >= STREAMS_PER_CONTACT {
        return Err(NotTaken::Again(format!(
            "{} shares from them are already waiting for their bytes here, which is as many as are kept",
            theirs.len()
        )));
    }
    let declared: u64 = theirs.iter().map(|k| declared_size(k)).sum();
    if declared + manifest.size > STREAM_BYTES_PER_CONTACT {
        return Err(NotTaken::Again(format!(
            "shares from them already waiting here declare {declared} bytes, and this one would take them past {STREAM_BYTES_PER_CONTACT}"
        )));
    }
    let waiting = serde_json::to_vec(&Waiting { inner: inner.clone(), sealed: sealed.clone() })
        .map_err(|e| NotTaken::Again(format!("could not keep the share waiting: {e}")))?;
    host.stream_keep(user_id, &stream.waiting(), &waiting).await.map_err(NotTaken::Again)
}

/// Let go of everything the stream of `manifest` — the share whose message id
/// is `share` — from `sender_did` holds on the shelf, once the share is filed.
/// A key that will not go is said and left: the share is filed either way.
pub(crate) async fn done(host: &dyn MessageHost, user_id: &str, sender_did: &str, manifest: &Manifest, share: &str) {
    let stream = Stream::of(sender_did, &manifest.digest, manifest.size, share);
    let Ok(keys) = shelf(host, user_id).await else {
        tracing::info!(user_id, "a filed share's stream stays on the shelf: the shelf could not be listed");
        return;
    };
    // The manifest last: a node that stops part way keeps the stream waiting,
    // never ranges with no manifest to bound them.
    let (manifest_key, ranges): (Vec<&String>, Vec<&String>) =
        keys.iter().filter(|k| stream.owns(k)).partition(|k| **k == stream.waiting());
    for key in ranges.into_iter().chain(manifest_key) {
        if let Err(e) = host.stream_drop(user_id, key).await {
            tracing::info!(user_id, error = %e, "part of a filed share's stream stays on the shelf");
        }
    }
}

fn is_whole(stream: &Stream, size: u64, keys: &[String]) -> bool {
    (0..range_count(size)).all(|i| keys.contains(&stream.range(i * RANGE_LEN as u64)))
}

async fn shelf(host: &dyn MessageHost, user_id: &str) -> Result<Vec<String>, NotTaken> {
    host.stream_keys(user_id).await.map_err(NotTaken::Again)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::ChannelCopy;

    /// **A channel share kept waiting keeps its ciphertext.** A streamed share
    /// that arrived as a channel copy waits on the shelf as its claims and its
    /// envelope; what is filed once the bytes are whole is opened from the
    /// channel ciphertext those claims hold. Kept without it, the copy would be
    /// opened with nothing, read as one no key opens, and declined
    /// (`TASK-a-channel-copy-carries-its-sealed-bytes-base64-twice`, the
    /// assessor's refusal of 2026-10-09).
    #[test]
    fn a_channel_share_kept_waiting_comes_back_with_its_ciphertext() {
        let ciphertext: Vec<u8> = (0..=255u8).cycle().take(1_000).collect();
        let inner = DmInner {
            from_did: "did:kel:sam".into(),
            to_did: "did:kel:avery".into(),
            thread_id: "t".into(),
            sent_at: 1,
            kind: crate::share::MESSAGE_TYPE.into(),
            text: String::new(),
            channel: Some(ChannelCopy {
                channel_did: "did:key:zHousehold".into(),
                epoch: 4,
                body: ciphertext.clone(),
                nonce: "bm9uY2U".into(),
            }),
            grant: None,
            reach: None,
            ack: None,
            kel: Vec::new(),
            share: None,
            range: None,
        };
        let sealed = SealedDm { ephemeral_pub: "ZQ==".into(), nonce: "bg==".into(), body: "Yg==".into() };
        let kept = serde_json::to_vec(&Waiting { inner, sealed }).unwrap();
        let back: Waiting = serde_json::from_slice(&kept).unwrap();
        assert_eq!(back.inner.channel.unwrap().body, ciphertext);
    }
}
