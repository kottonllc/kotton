// SPDX-License-Identifier: AGPL-3.0-or-later
//! A person's outbox: the direct messages they sent that no device of the
//! recipient's has signed for yet, and the ones that have been.
//!
//! Kept where membership is, for the same reasons: a daemon object in the
//! person's own store, out of every app's reach, one object per message so two
//! of the person's devices writing at once never conflict, and carried to their
//! other devices by the same sync. So a message one device queued is one any of
//! them can retry, and one any of them reads as delivered once signed for.
//!
//! **What is kept once a message is signed for is the fact and nothing else.**
//! Which of the recipient's devices signed, and when, is a reading of that
//! person's day; the sender checks the signature and keeps only that it held
//! ([`SignedFor`]). A record of which device woke when would be a history
//! someone else could be asked for, and there is no reason to keep one.
//!
//! The logic — when to try, what an answer means — and the entry types are the
//! messaging domain's (`kotton_msg::daemon::outbox`); this is the shelf it keeps
//! them on, reached through [`kotton_msg::daemon::messages::MessageHost`].

use anyhow::{Context, Result};
use kotton_msg::daemon::outbox::{OutboxEntry, SignedFor};
use kotton_peer::membership::MemberStore;

/// Where messages waiting to be signed for are kept, one object each.
const OUTBOX_PREFIX: &str = "/network/outbox/";
/// Where the fact that a message was signed for is kept, one object each.
const SIGNED_FOR_PREFIX: &str = "/network/signed-for/";

/// An id as a path segment: hex of its bytes, since a base64 id carries `/`.
fn segment(id: &str) -> String {
    hex::encode(id.as_bytes())
}

/// The outbox verbs, over any store that keeps bytes under a path.
#[async_trait::async_trait]
pub trait Outbox: MemberStore {
    /// Keep `entry`, replacing the one held under its id.
    async fn keep_outbox_entry(&self, entry: &OutboxEntry) -> Result<()> {
        let json = serde_json::to_vec(entry).context("serialize outbox entry")?;
        self.member_write(&format!("{OUTBOX_PREFIX}{}", segment(&entry.id)), &json)
            .await
            .context("keep an outbox entry")
    }

    /// Every entry waiting. A listing that cannot be taken is an error, never
    /// an empty outbox — read as empty, nothing would be retried and nothing
    /// would say so. One unreadable entry among many is skipped.
    async fn outbox_entries(&self) -> Result<Vec<OutboxEntry>> {
        read_all(self, OUTBOX_PREFIX).await
    }

    /// Take `id` out of the outbox.
    async fn drop_outbox_entry(&self, id: &str) -> Result<()> {
        self.member_delete(&format!("{OUTBOX_PREFIX}{}", segment(id)))
            .await
            .context("take a message out of the outbox")
    }

    /// Keep that a message was signed for.
    async fn keep_signed_for(&self, signed: &SignedFor) -> Result<()> {
        let json = serde_json::to_vec(signed).context("serialize signed-for")?;
        self.member_write(&format!("{SIGNED_FOR_PREFIX}{}", segment(&signed.id)), &json)
            .await
            .context("keep that a message was signed for")
    }

    /// Every message signed for.
    async fn all_signed_for(&self) -> Result<Vec<SignedFor>> {
        read_all(self, SIGNED_FOR_PREFIX).await
    }
}

#[async_trait::async_trait]
impl<T: MemberStore + ?Sized> Outbox for T {}

async fn read_all<S: MemberStore + ?Sized, T: serde::de::DeserializeOwned>(
    store: &S,
    prefix: &str,
) -> Result<Vec<T>> {
    let keys = store.member_list(prefix).await.context("list the outbox — this node may be locked")?;
    let mut out = Vec::new();
    for key in keys.into_iter().filter(|k| !k.ends_with('/')) {
        match store.member_read(&key).await.map(|b| serde_json::from_slice::<T>(&b)) {
            Ok(Ok(v)) => out.push(v),
            _ => tracing::warn!(%key, "an outbox object could not be read; it is skipped"),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotton_crypto::derive_cek;
    use kotton_wire::ipc::SealedDm;
    use kotton_store::runtime::{user::UserStore, UserKeys};
    use tempfile::TempDir;

    fn store(temp: &TempDir) -> UserStore {
        UserStore::create(
            "alice",
            "did:key:zAlice",
            temp.path().to_path_buf(),
            UserKeys::new(Some(derive_cek(&[7u8; 32]))),
            &kotton_store::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap()
    }

    fn entry(id: &str) -> OutboxEntry {
        OutboxEntry {
            id: id.into(),
            to_did: "did:kel:bob".into(),
            record_id: "7".into(),
            sealed: SealedDm { ephemeral_pub: id.into(), nonce: "n".into(), body: "b".into() },
            queued_at: 1,
            attempts: 0,
            next_at: 1,
            carried: false,
            part_of: None,
            channel_did: None,
        }
    }

    /// An entry round-trips under an id carrying `/` and `+`, is replaced in
    /// place, and leaves when dropped; a signed-for fact is kept apart from it
    /// and neither is ever listed as a member.
    #[tokio::test]
    async fn the_outbox_keeps_an_entry_until_it_is_dropped() {
        use kotton_peer::membership::Membership as _;
        let temp = TempDir::new().unwrap();
        let store = store(&temp);
        let id = "ab/c+d==";
        assert!(store.outbox_entries().await.unwrap().is_empty());
        store.keep_outbox_entry(&entry(id)).await.unwrap();
        let mut again = entry(id);
        again.attempts = 3;
        again.carried = true;
        store.keep_outbox_entry(&again).await.unwrap();
        assert_eq!(store.outbox_entries().await.unwrap(), vec![again.clone()]);

        let signed = SignedFor { id: id.into(), to_did: "did:kel:bob".into(), record_id: "7".into() };
        store.keep_signed_for(&signed).await.unwrap();
        store.drop_outbox_entry(id).await.unwrap();
        assert!(store.outbox_entries().await.unwrap().is_empty());
        assert_eq!(store.all_signed_for().await.unwrap(), vec![signed]);
        assert!(store.list_members().await.unwrap().is_empty());
    }
}
