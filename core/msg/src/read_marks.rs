// SPDX-License-Identifier: AGPL-3.0-or-later
//! What a person has read — one watermark per conversation.
//!
//! # What this is
//!
//! A message is read or unread. Nothing anywhere recorded which, so a badge had
//! no honest number to show: the inbox has a real size, and *unread* had no
//! value at all. This is the missing fact, and it is the recipient's alone.
//!
//! # Where it lives, and why not on the message
//!
//! Two properties decide this, and the second one settles it.
//!
//! **It must reach the person's other devices and nobody else.** Read state is
//! per person, not per screen: reading something on a phone should not leave it
//! bold on a laptop. It must never reach the *sender* — a sender who learns a
//! message was read knows something stronger than `delivered`, and the four
//! words the sender is owed are deliberate and do not include a fifth.
//!
//! **The record store has no update.** Records are inserted, queried and
//! deleted; nothing anywhere mutates one. So `read_at` as a field on the
//! message envelope is not a small change — it is inventing record mutation,
//! and with it a merge rule for two devices that mutate the same row.
//!
//! A VFS object satisfies both, and there is already one doing exactly this job
//! one domain over: membership records are objects on the `"local"` mount, CEK
//! encrypted like any file, which is what makes them sync across the user's own
//! nodes and readable by nobody else. Read marks are the same shape for the
//! same reasons, down to **one object per peer** — which is what keeps two
//! devices marking two different conversations from ever touching one file.
//!
//! It is also why this is not a core schema. Read state is not interoperability
//! data; no other app needs to know when you looked at something, and a core
//! schema is a commons whose whole purpose is that a second app can read the
//! same records. Putting this there would widen a commons to hold a fact that
//! belongs to one person's own surface.
//!
//! # The watermark, and whose clock it is in
//!
//! A mark is the position of the newest message the person has been shown, as
//! **`(filed_at, message_id)`** — where `filed_at` is when *this person's own
//! store* filed the message, strictly increasing in the order that device files
//! things (`kotton_record::Record::filed_at`); a row synced in from another of
//! the person's devices keeps the stamp it was filed with there — see below.
//!
//! It was `(sent_at, message_id)` until 2026-09-25, and `sent_at` is the wrong
//! clock twice over. It is whole seconds, so two messages inside one second had
//! only their ids to order them, and ids are random: a message that arrived
//! *after* the person read the conversation could carry a smaller id in the
//! same second and count as read without ever being drawn. And it is the
//! **sender's** claim — a sender whose clock ran slow, or who simply wrote an
//! earlier time, placed their new message below a mark already written, where
//! no badge would ever show it. The one thing a badge must not do is stay
//! silent about something unread, and both of those were exactly that
//! (`TASK-a-conversation-is-ordered-by-a-clock-it-does-not-hold`).
//!
//! The filing stamp is the holder's own, so nothing a sender writes moves it,
//! and it is strictly increasing, so anything *this device* files after a mark
//! sits above it. A row that arrives by sync from another of the person's
//! devices keeps the stamp it was filed with there, and can land below a mark
//! already written here — a watermark over several writers cannot see that
//! (`TASK-a-message-synced-in-below-a-read-mark-counts-as-read`). The id still rides along, only so a mark names *which* message it is;
//! the stamp alone already orders. The same key orders the conversation on
//! screen, so anything the surface drew is at or below the mark and anything
//! it did not draw is above. That makes the count exact rather than approximate.
//!
//! The position is still taken *from the messages*, never from the reading
//! device's clock at the moment of reading: the mark says how far the person
//! was shown, and only the messages know where that is.
//!
//! # What happens when two devices race
//!
//! One object per peer, written whole. Two devices marking the same
//! conversation at the same moment resolve as the store resolves any concurrent
//! write to one object. If the older write lands last, the mark moves backwards
//! and some already-read messages count as unread again.
//!
//! That is the safe direction, and it is the reason the mark is only ever
//! advanced here rather than set: a badge that says *unread* about something
//! read is a small annoyance, and one that stays silent about something unread
//! is a message the person never sees.
//!
//! # Where the implementation of the store is
//!
//! Not here. This names three methods over bytes at a path and nothing else, so
//! the domain never learns who provides them — the same inversion membership
//! uses, for the same reason. The daemon satisfies it from the user's own store,
//! beside the other things the messaging domain asks its host for.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// VFS prefix (on the `"local"` mount) under which read marks live.
const READ_PREFIX: &str = "/messages/read/";

/// The VFS path for one conversation's mark: `/messages/read/<peer-did>`.
pub fn mark_path(peer_did: &str) -> String {
    format!("{READ_PREFIX}{peer_did}")
}

/// How far a person has read in one conversation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadMark {
    /// The other person. One mark per conversation, so this is the file's name
    /// as well as its content — kept in the body so a mark read off disk is
    /// self-describing rather than only meaningful at the path it came from.
    pub peer_did: String,
    /// Where the newest message the person has been shown was filed in their
    /// own store — milliseconds on the holder's clock, never the sender's.
    ///
    /// A mark written before 2026-09-25 carries `sent_at` here instead, will
    /// not parse, and is treated as absent: that conversation reads as unread
    /// once, until it is next drawn. That is the direction DEC-0061 chose to
    /// fail in, and far cheaper than comparing a sender's seconds to a
    /// holder's milliseconds.
    pub filed_at: u64,
    /// That message's id — which message the mark names.
    pub message_id: String,
}

impl ReadMark {
    /// The order key. Everything at or below this has been read.
    fn position(&self) -> (u64, &str) {
        (self.filed_at, self.message_id.as_str())
    }
}

/// Somewhere to keep read marks — the whole of what this needs from its host.
///
/// Three methods over bytes at a path, so anything that can store bytes
/// satisfies it and this domain never learns who provides them. The same
/// inversion the membership store uses, and for the same reason: read marks are
/// the person's, not the machine's, and they only need somewhere to put bytes.
#[async_trait::async_trait]
pub trait ReadMarkStore: Send + Sync {
    async fn mark_write(&self, path: &str, data: &[u8]) -> Result<()>;
    /// `Ok(None)` when nothing is stored there — an unread conversation is the
    /// absence of a mark, not an error.
    async fn mark_read_bytes(&self, path: &str) -> Result<Option<Vec<u8>>>;
    async fn mark_list(&self, prefix: &str) -> Result<Vec<String>>;
}

/// The read-mark verbs, blanket-implemented for every [`ReadMarkStore`].
#[async_trait::async_trait]
pub trait ReadMarks: ReadMarkStore {
    /// The mark for one conversation, or `None` if nothing there has been read.
    async fn read_mark(&self, peer_did: &str) -> Result<Option<ReadMark>> {
        let Some(bytes) = self.mark_read_bytes(&mark_path(peer_did)).await? else {
            return Ok(None);
        };
        Ok(Some(serde_json::from_slice(&bytes).with_context(|| {
            format!("read mark for {peer_did} is not readable JSON")
        })?))
    }

    /// Every mark this person holds.
    ///
    /// A file that will not parse costs itself and not the list: one corrupt
    /// mark must not make every conversation unread at once, which is the
    /// louder and less recoverable failure.
    async fn all_marks(&self) -> Result<Vec<ReadMark>> {
        let paths = self.mark_list(READ_PREFIX).await.unwrap_or_default();
        let mut out = Vec::with_capacity(paths.len());
        for path in paths {
            if path.ends_with('/') {
                continue; // directory entry, not a mark
            }
            if let Ok(Some(bytes)) = self.mark_read_bytes(&path).await {
                if let Ok(mark) = serde_json::from_slice::<ReadMark>(&bytes) {
                    out.push(mark);
                }
            }
        }
        Ok(out)
    }

    /// Advance the mark for one conversation to `(filed_at, message_id)`.
    ///
    /// Only ever forwards. A caller that has drawn an older stretch of a
    /// conversation — scrolled up, reopened a thread from a stale list — is
    /// telling the truth about what it drew and would still be wrong to unread
    /// what came after. Returns whether anything moved.
    ///
    /// A mark already there that will not parse — one written in the old
    /// `sent_at` shape — is replaced rather than refused: it has no position to
    /// compare with, and refusing would leave the conversation unread forever.
    /// **Only that.** A mark that could not be *read* is an error, not an
    /// absence: writing over it uncompared could move it backwards.
    async fn mark_read(&self, peer_did: &str, filed_at: u64, message_id: &str) -> Result<bool> {
        let next = ReadMark {
            peer_did: peer_did.to_string(),
            filed_at,
            message_id: message_id.to_string(),
        };
        let held = self.mark_read_bytes(&mark_path(peer_did)).await?;
        if let Some(current) = held.and_then(|b| serde_json::from_slice::<ReadMark>(&b).ok()) {
            if current.position() >= next.position() {
                return Ok(false);
            }
        }
        let bytes = serde_json::to_vec(&next).context("serialising a read mark")?;
        self.mark_write(&mark_path(peer_did), &bytes).await?;
        Ok(true)
    }
}

#[async_trait::async_trait]
impl<T: ReadMarkStore + ?Sized> ReadMarks for T {}

/// One message, as far as counting is concerned.
///
/// Not the envelope: counting needs who it is from, where it sits, and nothing
/// else. Taking the three fields rather than the record keeps this pure, and
/// keeps a ciphertext out of a function whose whole job is arithmetic.
///
/// `sent_at` is deliberately not one of them: where a message sits is where
/// this person's store filed it, not when its sender says it was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Received {
    pub from_did: String,
    pub filed_at: u64,
    pub id: String,
}

/// Whether one message sits above the mark for the conversation it is in.
///
/// No mark means nothing in that conversation has been read, so everything in
/// it is unread — which is the right answer for a contact who has never been
/// opened, and the reason absence is not an error here.
pub fn is_unread(mark: Option<&ReadMark>, m: &Received) -> bool {
    match mark {
        None => true,
        Some(mark) => (m.filed_at, m.id.as_str()) > mark.position(),
    }
}

/// How many of `messages` are unread, given every mark this person holds.
pub fn count_unread(messages: &[Received], marks: &[ReadMark]) -> usize {
    messages
        .iter()
        .filter(|m| {
            let mark = marks.iter().find(|k| k.peer_did == m.from_did);
            is_unread(mark, m)
        })
        .count()
}

/// The position to mark a conversation read at, given what was drawn.
///
/// The maximum of what the surface showed, in the same `(filed_at, id)` order
/// the surface sorted by — so "read up to here" and "drawn down to here" are
/// the same statement. `None` when nothing was drawn, which is not a mark.
pub fn high_water(messages: &[Received]) -> Option<&Received> {
    messages.iter().max_by(|a, b| {
        (a.filed_at, a.id.as_str()).cmp(&(b.filed_at, b.id.as_str()))
    })
}

/// Read the three fields counting needs out of a message record.
///
/// The record is what the message verbs emit — `id` and `filed_at` rather than
/// the store's own `_id` and `_filed_at`. A row missing any of the three is
/// skipped rather than guessed at: a message whose position cannot be
/// established cannot be compared to a mark, and counting it either way would
/// be inventing an answer.
pub fn received_from_record(v: &serde_json::Value) -> Option<Received> {
    Some(Received {
        from_did: v.get("from_did")?.as_str()?.to_string(),
        filed_at: v.get("filed_at")?.as_u64()?,
        id: v.get("id")?.as_str()?.to_string(),
    })
}

/// How many of `inbox` this person has not read.
///
/// `inbox` is what `message_poll_inbox` answers with, so this is the whole
/// computation behind a badge: the marks say how far each conversation was
/// read, and everything above a mark is unread.
pub async fn unread_count(
    marks: &dyn ReadMarkStore,
    inbox: &[serde_json::Value],
) -> Result<u64> {
    let received: Vec<Received> = inbox.iter().filter_map(received_from_record).collect();
    let marks = marks.all_marks().await?;
    Ok(count_unread(&received, &marks) as u64)
}

/// How many of the messages `peer_did` sent this person are unread — one
/// conversation's count, where [`unread_count`] is every conversation's.
///
/// The same two halves, narrowed to one sender, so the number beside a
/// conversation and the badge that sums them cannot disagree about what
/// *unread* means (`TASK-messages-is-the-drawn-one`).
pub async fn unread_count_from(
    marks: &dyn ReadMarkStore,
    inbox: &[serde_json::Value],
    peer_did: &str,
) -> Result<u64> {
    let received: Vec<Received> = inbox
        .iter()
        .filter_map(received_from_record)
        .filter(|m| m.from_did == peer_did)
        .collect();
    let marks = marks.all_marks().await?;
    Ok(count_unread(&received, &marks) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Bytes at paths, and nothing else — which is the point of the trait.
    #[derive(Default)]
    struct MemStore(Mutex<HashMap<String, Vec<u8>>>);

    #[async_trait::async_trait]
    impl ReadMarkStore for MemStore {
        async fn mark_write(&self, path: &str, data: &[u8]) -> Result<()> {
            self.0.lock().unwrap().insert(path.to_string(), data.to_vec());
            Ok(())
        }
        async fn mark_read_bytes(&self, path: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.0.lock().unwrap().get(path).cloned())
        }
        async fn mark_list(&self, prefix: &str) -> Result<Vec<String>> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }
    }

    fn msg(from: &str, filed_at: u64, id: &str) -> Received {
        Received { from_did: from.to_string(), filed_at, id: id.to_string() }
    }

    /// The whole point of the record this implements: a conversation nobody has
    /// opened is entirely unread, and one read to the end is entirely read.
    #[tokio::test]
    async fn a_conversation_nobody_opened_is_unread_and_one_read_to_the_end_is_not() {
        let store = MemStore::default();
        let inbox = vec![
            msg("did:key:zSarah", 100, "a"),
            msg("did:key:zSarah", 200, "b"),
            msg("did:key:zMum", 150, "c"),
        ];

        let marks = store.all_marks().await.unwrap();
        assert_eq!(count_unread(&inbox, &marks), 3, "no mark anywhere means nothing is read");

        let sarahs: Vec<_> = inbox.iter().filter(|m| m.from_did == "did:key:zSarah").cloned().collect();
        let top = high_water(&sarahs).unwrap();
        assert!(store.mark_read("did:key:zSarah", top.filed_at, &top.id).await.unwrap());

        let marks = store.all_marks().await.unwrap();
        assert_eq!(count_unread(&inbox, &marks), 1, "only Mum's is left");
    }

    /// One conversation's count is that conversation's messages above that
    /// conversation's mark, and the counts of every conversation sum to the
    /// badge — the number beside a row and the number on the tile are one
    /// computation (`TASK-messages-is-the-drawn-one`).
    #[tokio::test]
    async fn one_conversations_count_is_its_own_and_they_sum_to_the_badge() {
        let store = MemStore::default();
        let rec = |from: &str, filed_at: u64, id: &str| {
            serde_json::json!({ "from_did": from, "filed_at": filed_at, "id": id })
        };
        let inbox = vec![
            rec("did:key:zSarah", 100, "a"),
            rec("did:key:zSarah", 200, "b"),
            rec("did:key:zMum", 150, "c"),
        ];
        assert!(store.mark_read("did:key:zSarah", 100, "a").await.unwrap());

        let sarah = unread_count_from(&store, &inbox, "did:key:zSarah").await.unwrap();
        let mum = unread_count_from(&store, &inbox, "did:key:zMum").await.unwrap();
        let nobody = unread_count_from(&store, &inbox, "did:key:zStranger").await.unwrap();
        assert_eq!((sarah, mum, nobody), (1, 1, 0));
        assert_eq!(sarah + mum, unread_count(&store, &inbox).await.unwrap());
    }

    /// **The defect the old key had, as a test.** The mark was `(sent_at, id)`:
    /// the sender's seconds, then a random id. A message that arrived *after*
    /// the conversation was read, in the same second and with a smaller id —
    /// or from a sender whose clock ran slow — sat below the mark and counted
    /// as read without ever being drawn. By filing position it cannot: it was
    /// filed after the mark's message, so it sits above it, whatever its id and
    /// whatever its sender claimed
    /// (`TASK-a-conversation-is-ordered-by-a-clock-it-does-not-hold`).
    #[tokio::test]
    async fn a_message_filed_after_the_mark_is_unread_whatever_its_id() {
        let store = MemStore::default();
        // Drawn and read: the one message there was.
        assert!(store.mark_read("did:key:zSarah", 1_000, "m").await.unwrap());

        // Then another arrives, filed later, with an id that sorts first.
        let inbox = vec![msg("did:key:zSarah", 1_000, "m"), msg("did:key:zSarah", 1_001, "a")];
        let marks = store.all_marks().await.unwrap();
        assert_eq!(count_unread(&inbox, &marks), 1, "the later one was never drawn");
        assert!(is_unread(marks.first(), &inbox[1]));
    }

    /// The position is read from the holder's filing stamp and never from the
    /// sender's `sent_at`, which is carried on the record and ignored here.
    #[test]
    fn a_record_is_placed_by_where_it_was_filed_not_when_its_sender_says() {
        let r = received_from_record(&serde_json::json!({
            "from_did": "did:key:zSarah",
            "id": "a",
            "sent_at": 9_999_999_999u64,
            "filed_at": 1_000u64,
        }))
        .expect("a message record");
        assert_eq!(r.filed_at, 1_000);
        assert!(
            received_from_record(&serde_json::json!({ "from_did": "d", "id": "a", "sent_at": 1u64 }))
                .is_none(),
            "a record with no filing position is not placed by its sender's claim instead"
        );
    }

    /// A mark that cannot be *read* is not a mark that is absent: the write is
    /// refused rather than made uncompared, which could move it backwards.
    #[tokio::test]
    async fn a_mark_that_cannot_be_read_is_not_overwritten() {
        struct Unreadable;
        #[async_trait::async_trait]
        impl ReadMarkStore for Unreadable {
            async fn mark_write(&self, _: &str, _: &[u8]) -> Result<()> {
                panic!("a mark was written without being compared");
            }
            async fn mark_read_bytes(&self, _: &str) -> Result<Option<Vec<u8>>> {
                anyhow::bail!("the store is locked")
            }
            async fn mark_list(&self, _: &str) -> Result<Vec<String>> {
                Ok(Vec::new())
            }
        }
        assert!(Unreadable.mark_read("did:key:zSarah", 1, "a").await.is_err());
    }

    /// A mark in the shape written before the key changed has no position to
    /// compare with. It reads as absent and the next mark replaces it, rather
    /// than refusing and leaving the conversation unread for good.
    #[tokio::test]
    async fn a_mark_in_the_old_shape_is_replaced() {
        let store = MemStore::default();
        store
            .mark_write(
                &mark_path("did:key:zSarah"),
                br#"{"peer_did":"did:key:zSarah","sent_at":1757000000,"message_id":"a"}"#,
            )
            .await
            .unwrap();
        assert!(store.all_marks().await.unwrap().is_empty(), "the old shape is no mark");
        assert!(store.mark_read("did:key:zSarah", 1_000, "a").await.unwrap());
        let mark = store.read_mark("did:key:zSarah").await.unwrap().unwrap();
        assert_eq!((mark.filed_at, mark.message_id.as_str()), (1_000, "a"));
    }

    /// Reopening an old view must not unread what arrived since.
    #[tokio::test]
    async fn a_mark_only_ever_moves_forward() {
        let store = MemStore::default();
        assert!(store.mark_read("did:key:zSarah", 200, "b").await.unwrap());
        assert!(
            !store.mark_read("did:key:zSarah", 100, "a").await.unwrap(),
            "an older position must not move the mark"
        );
        let mark = store.read_mark("did:key:zSarah").await.unwrap().unwrap();
        assert_eq!((mark.filed_at, mark.message_id.as_str()), (200, "b"));

        assert!(
            !store.mark_read("did:key:zSarah", 200, "b").await.unwrap(),
            "the same position is not a move"
        );
    }

    /// A mark is per conversation. Reading one must not touch another, which is
    /// also why there is one file per peer rather than one file of everything.
    #[tokio::test]
    async fn one_conversation_read_leaves_the_others_alone() {
        let store = MemStore::default();
        store.mark_read("did:key:zSarah", 100, "a").await.unwrap();
        assert!(store.read_mark("did:key:zMum").await.unwrap().is_none());
        assert_eq!(
            mark_path("did:key:zSarah"),
            "/messages/read/did:key:zSarah",
            "one object per peer, named by peer"
        );
    }

    /// One unreadable mark costs its own conversation and not every other one.
    #[tokio::test]
    async fn a_corrupt_mark_does_not_make_everything_unread() {
        let store = MemStore::default();
        store.mark_read("did:key:zSarah", 100, "a").await.unwrap();
        store
            .mark_write(&mark_path("did:key:zMum"), b"not json")
            .await
            .unwrap();

        let marks = store.all_marks().await.unwrap();
        assert_eq!(marks.len(), 1, "Sarah's mark survives Mum's corruption");
        assert_eq!(marks[0].peer_did, "did:key:zSarah");
    }

    /// Nothing drawn is not a mark. A surface that rendered an empty thread has
    /// not read anything, and writing a mark for it would silence a message
    /// that arrives a moment later.
    #[test]
    fn nothing_drawn_is_not_a_position() {
        assert!(high_water(&[]).is_none());
    }
}
