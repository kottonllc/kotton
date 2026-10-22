// SPDX-License-Identifier: AGPL-3.0-or-later
//! One copy of a message on a device, when copies of it arrive at once
//! (`TASK-a-message-reaches-them-by-every-path-at-once-and-they-keep-one-copy`).
//!
//! A sender dials every way to a person at once, so two copies of one message
//! can reach one device's door in the same moment — over two relays, or at the
//! door and from the vault. Dropping the second is a question and an answer:
//! *does a row hold this id?* and, if not, *file one*. Asked by two copies at
//! once, both hear *no* and both file. So for one message id the two steps are
//! one: whoever files holds [`once`] from the question to the answer.
//!
//! **A fixed set of locks, not one per message.** The id is hashed onto one of
//! [`STRIPES`] locks, so every copy of one message meets the same lock and two
//! different messages rarely wait on each other — and nothing grows with the
//! messages a device has ever seen, so there is nothing to forget or clean up.
//! It is process-wide because the thing it guards is: any door, any vault
//! pickup, for any person resident here, files into a store on this machine.
//! Two daemons in one process (the tests) share it and only ever wait longer.

use std::hash::{Hash, Hasher};
use tokio::sync::{Mutex, MutexGuard};

/// How many locks the ids are spread over.
const STRIPES: usize = 64;

static FILING: [Mutex<()>; STRIPES] = [const { Mutex::const_new(()) }; STRIPES];

/// Hold the one lock `id` — a message's sealed ephemeral key, or a key-grant's
/// — meets for `user_id`, from asking whether it is already filed until it is.
pub(crate) async fn once(user_id: &str, id: &str) -> MutexGuard<'static, ()> {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    (user_id, id).hash(&mut h);
    FILING[(h.finish() as usize) % STRIPES].lock().await
}

/// The locks [`folder`] takes — a set apart from [`FILING`], because a share is
/// filed while its message's lock is held, and two ids hashed onto one stripe
/// of one set would wait on themselves.
static FOLDERS: [Mutex<()>; STRIPES] = [const { Mutex::const_new(()) }; STRIPES];

/// Hold the one lock the folder `dir` of `user_id`'s tree meets, from reading
/// which names it holds until a share is written into it under one that was
/// free — so two shares of one name landing at once cannot both take it
/// (`TASK-a-file-shared-with-a-contact-is-a-copy-of-theirs-under-shared-with-you`).
pub(crate) async fn folder(user_id: &str, dir: &str) -> MutexGuard<'static, ()> {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    (user_id, dir).hash(&mut h);
    FOLDERS[(h.finish() as usize) % STRIPES].lock().await
}

/// The locks [`outbox_entry`] takes — a set of their own. An entry's lock may be
/// taken while a message's is held — a leave notice filed under its `once`
/// rotates the channel, and the new roster takes copies out of the outbox
/// (`outbox::drop_channel_copies`) — and never the other way round: nothing
/// holding an entry's lock files a message.
static ENTRIES: [Mutex<()>; STRIPES] = [const { Mutex::const_new(()) }; STRIPES];

/// Hold the one lock the outbox entry `id` of `user_id` meets: from asking
/// whether it is still in the outbox until a try's write-back of it, and
/// around a signature taking it out — so an entry signed for on one path while
/// a try on another failed is not written back after it was taken out
/// (`TASK-a-share-above-the-frame-cap-arrives-whole-by-the-streaming-transport`).
pub(crate) async fn outbox_entry(user_id: &str, id: &str) -> MutexGuard<'static, ()> {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    (user_id, id).hash(&mut h);
    ENTRIES[(h.finish() as usize) % STRIPES].lock().await
}

