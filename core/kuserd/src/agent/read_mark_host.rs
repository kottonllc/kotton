// SPDX-License-Identifier: AGPL-3.0-or-later
//! Where a person's read marks are kept: objects in their own store.
//!
//! The messaging domain asks for three things — write bytes at a path, read them
//! back, list a prefix — and says nothing about who provides them. This is the
//! daemon's answer: the `"local"` mount of the user's own store, CEK encrypted
//! like every other object there, which is what makes a mark reach that person's
//! **other nodes** and nobody else's. A mark is one of the daemon's own records
//! (`UserStore::write_daemon_object`), outside the person's tree, so no app's
//! `files` grant reaches it and the file browser does not show it.
//!
//! That property is the whole design. Read state must sync across a person's own
//! devices (reading something on a phone should not leave it bold on a laptop)
//! and must never reach the sender, who is owed four words and not a fifth. One
//! object per conversation in the recipient's own store is both at once, and it
//! is the same arrangement membership already uses one domain over.
//!
//! **Bound to one user, unlike [`DaemonMessageHost`].** The three verbs take a
//! path and no `user_id`, because a mark's path is a conversation and the person
//! whose conversation it is has already been decided by the time a dispatch arm
//! calls one. Passing a user through every call would let a caller name someone
//! else's mark, which is a thing this type simply cannot express.
//!
//! [`DaemonMessageHost`]: super::message_host::DaemonMessageHost

use std::sync::Arc;

use kotton_msg::read_marks::ReadMarkStore;
use kotton_store::runtime::user::UserStore;

use crate::residency::UserRegistry;

/// One person's read marks.
pub struct DaemonReadMarks {
    store: Arc<UserStore>,
}

#[async_trait::async_trait]
impl ReadMarkStore for DaemonReadMarks {
    async fn mark_write(&self, path: &str, data: &[u8]) -> anyhow::Result<()> {
        self.store.write_daemon_object(path, data).await
    }

    /// A read that fails is `None`, not an error.
    ///
    /// Callers treat absence as *"nothing in that conversation has been read"*,
    /// which is also the right answer for a mark that cannot be read at all: the
    /// safe direction is to count a message as unread, because a badge that is
    /// silent about something unread hides a message from the person, and one
    /// that is loud about something already read is an annoyance.
    async fn mark_read_bytes(&self, path: &str) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(self.store.read_daemon_object(path).await.ok())
    }

    async fn mark_list(&self, prefix: &str) -> anyhow::Result<Vec<String>> {
        self.store.list_daemon_objects(prefix).await
    }
}

/// The marks belonging to `user_id`, or an error naming why there are none.
///
/// A user who is not resident has no store open, so there is nowhere for a mark
/// to be. That is not an empty set of marks — "everything is unread" and "this
/// session is not unlocked" are different answers, and only one of them is about
/// the messages.
pub fn read_marks(users: &UserRegistry, user_id: &str) -> Result<DaemonReadMarks, String> {
    users
        .get(user_id)
        .map(|store| DaemonReadMarks { store })
        .ok_or_else(|| format!("user '{user_id}' is not unlocked on this device"))
}
