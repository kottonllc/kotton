// SPDX-License-Identifier: AGPL-3.0-or-later
//! The mailboxes this node answers for its users' contacts.
//!
//! One reservation per contact pair, and behind it a handler that decodes
//! `ContactRequest` — a vocabulary of one act, handing a message over, which
//! the sender's vault may do for them (`CarryMessage`). That is the whole of what
//! another person can reach on this node, and it is reachability rather than a
//! rule: a contact cannot ask for a file and be refused, because the address
//! they can dial has no such verb behind it.
//!
//! The registry is rebuilt from membership — at startup, and whenever a pairing
//! admits someone — and `Reachability` turns it into reservations, one per
//! epoch, exactly as it does for devices.
//!
//! It holds a door too for each **co-member**: a person this
//! user shares a channel with and never paired with, whose identity key the
//! channel's roster carries. It is rebuilt whenever a roster changes as well
//! (`MessageHost::rosters_changed`), and it files that channel's copies only.
//!
//! **A read that fails keeps what it would have replaced.**
//! The rebuild has two sources for a person whose key is held — their
//! membership set, and the rosters of the channels they are in — and a source
//! that cannot be read this pass is not one that names nobody. So the doors it
//! opened last pass stand ([`Kept`]), and the rebuild is tried again on a short
//! backoff until a pass reads everything ([`keep_rebuilt`]), as well as on the
//! next change. A failed listing taken for a person with no contacts would drop
//! every door they held, and the wake that would have rebuilt them would already
//! be spent, so they would stay dropped until some other card changed.

use crate::agent::message_host::DaemonMessageHost;
use crate::residency::{RecordStores, UserRegistry};
use kotton_device::DeviceRuntime;
use kotton_msg::daemon::delivery;
use kotton_msg::daemon::messages::CoMembersRead;
use kotton_peer::contact_door::contact_door;
use kotton_peer::daemon::nodes::load_signing_key;
use kotton_peer::membership::Membership;
use kotton_peer::reachability::DmInbox;
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

/// One door: the person at the far end of the pair, and their identity key.
pub(super) type Door = (String, [u8; 32]);

/// The doors one person held after a pass, by the source each came from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Doors {
    /// One per contact card the membership set lists.
    pub(super) contacts: Vec<Door>,
    /// One per co-member, beside the channel whose roster named them — so a
    /// channel that cannot be read keeps its own co-members' doors and no
    /// other channel's.
    pub(super) co_members: Vec<(Door, String)>,
}

impl Doors {
    /// Every door, contacts' first.
    pub(super) fn all(&self) -> impl Iterator<Item = &Door> {
        self.contacts.iter().chain(self.co_members.iter().map(|(door, _)| door))
    }
}

/// Every resident person's doors as the last pass left them: what a read that
/// fails leaves standing.
///
/// Held by whoever runs the rebuild, across passes. A person the last pass did
/// not reach — whose key is not held, or who is no longer resident — has
/// nothing kept, so a failed read after an unlock opens nothing from before
/// the lock: their doors stand as they were, and as they were is none.
#[derive(Debug, Default)]
pub(super) struct Kept {
    by_user: HashMap<String, Doors>,
}

impl Kept {
    /// Start a pass. Every person the pass reaches goes through
    /// [`Pass::person`]; [`Pass::finish`] replaces what is kept with what the
    /// pass reached and nothing else.
    pub(super) fn pass(&mut self) -> Pass<'_> {
        Pass { kept: self, next: HashMap::new(), whole: true }
    }
}

/// One pass of the rebuild over the people whose key is held ([`Kept::pass`]).
pub(super) struct Pass<'a> {
    kept: &'a mut Kept,
    next: HashMap<String, Doors>,
    whole: bool,
}

impl Pass<'_> {
    /// `user_id`'s doors this pass: the contacts `store` lists and the
    /// co-members `co` names, with each source that could not be read keeping
    /// the doors it opened last pass.
    ///
    /// The membership set is listed whole or not at all
    /// ([`Membership::list_members`]), so a listing that fails keeps every
    /// contact's door. The rosters fail a channel at a time
    /// ([`CoMembersRead::unreadable`]), so an unreadable channel keeps its own
    /// co-members' doors, and a person's channels that cannot be listed at all
    /// keep every co-member's.
    pub(super) async fn person<S: Membership + ?Sized>(
        &mut self,
        user_id: &str,
        store: &S,
        co: Result<CoMembersRead, String>,
    ) -> &Doors {
        let before = self.kept.by_user.get(user_id);
        let contacts: Vec<Door> = match store.list_members().await {
            Ok(members) => members
                .into_iter()
                .filter(|m| matches!(m.role, kotton_schemas::membership::Role::Contact))
                .map(|m| (m.did, m.public_key))
                .collect(),
            Err(e) => {
                self.whole = false;
                // A user whose key is held and whose set cannot be listed is not
                // a locked one: said where a test's log keeps it, with the whole
                // chain. A half-written card failing the listing is found this
                // way.
                tracing::warn!(user_id, error = format!("{e:#}"), "membership unreadable");
                let kept = before.map(|d| d.contacts.clone()).unwrap_or_default();
                tracing::info!(
                    user_id,
                    doors = kept.len(),
                    error = format!("{e:#}"),
                    "the membership set could not be listed; this person's contacts keep the doors they had, and the rebuild is tried again"
                );
                kept
            }
        };
        let mut co_members: Vec<(Door, String)> = match co {
            Ok(read) => {
                let mut doors: Vec<(Door, String)> =
                    read.members.into_iter().map(|c| ((c.did, c.key), c.channel_did)).collect();
                if !read.unreadable.is_empty() {
                    self.whole = false;
                    let kept: Vec<(Door, String)> = before
                        .into_iter()
                        .flat_map(|d| d.co_members.iter())
                        .filter(|(_, channel)| read.unreadable.contains(channel))
                        .cloned()
                        .collect();
                    tracing::info!(
                        user_id,
                        channels = ?read.unreadable,
                        doors = kept.len(),
                        "the rosters of a channel could not be read; the co-members it named keep the doors they had, and the rebuild is tried again"
                    );
                    for (door, channel) in kept {
                        if !doors.iter().any(|(d, _)| *d == door) {
                            doors.push((door, channel));
                        }
                    }
                }
                doors
            }
            Err(e) => {
                self.whole = false;
                tracing::warn!(user_id, error = %e, "the channels this person is in are unreadable");
                let kept = before.map(|d| d.co_members.clone()).unwrap_or_default();
                tracing::info!(
                    user_id,
                    doors = kept.len(),
                    error = %e,
                    "this person's channels could not be listed; every co-member keeps the door they had, and the rebuild is tried again"
                );
                kept
            }
        };
        // A co-member kept from last pass who holds a card now has the card's
        // door already; one door per pair.
        co_members.retain(|(door, _)| !contacts.contains(door));
        self.next.insert(user_id.to_string(), Doors { contacts, co_members });
        &self.next[user_id]
    }

    /// End the pass: keep what it reached, and say whether every read held.
    pub(super) fn finish(self) -> bool {
        self.kept.by_user = self.next;
        self.whole
    }
}

/// Rebuild the mailbox registry from what every resident user's membership
/// and channels say, and answer whether every read held.
///
/// Whole-set replacement rather than a diff: membership is the truth, and a
/// registry patched from events drifts from it the first time an event is
/// missed. `Reachability` reconciles the reservations from here on its next
/// pass, so a pairing's mailbox opens within a second of the pairing.
///
/// A source that cannot be read keeps the doors it opened last pass
/// ([`Pass::person`]), and the answer is then `false`: the caller tries again
/// ([`keep_rebuilt`]).
pub async fn refresh(
    runtime: &Arc<DeviceRuntime>,
    users: &UserRegistry,
    record_stores: &RecordStores,
    kept: &mut Kept,
) -> bool {
    let mut inboxes: Vec<DmInbox> = Vec::new();
    let mut pass = kept.pass();
    for (user_id, store) in users.all() {
        let own_identity = match load_signing_key(&user_id, runtime.secrets()) {
            Ok(k) => k,
            // A user whose identity key is not available (locked, or a blind
            // node holding no key) answers no mailbox — the same rule the
            // allowlist follows for a locked user's devices. Nothing is kept
            // for them, and this is not a read that failed: nothing retries.
            Err(_) => continue,
        };
        let host = DaemonMessageHost { runtime: runtime.as_ref(), users, record_stores };
        let co = kotton_msg::daemon::messages::co_members_read(&host, &user_id).await;
        let doors = pass.person(&user_id, store.as_ref(), co).await;
        for (did, public_key) in doors.all() {
            inboxes.push(DmInbox {
                own_identity: own_identity.clone(),
                contact_pub: *public_key,
                handler: handler(
                    Arc::clone(runtime),
                    users.clone(),
                    record_stores.clone(),
                    user_id.clone(),
                    did.clone(),
                    *public_key,
                ),
            });
        }
    }
    let whole = pass.finish();
    let count = inboxes.len();
    *runtime.reachability().dm_inboxes().write().unwrap() = inboxes;
    tracing::debug!(mailboxes = count, whole, "contact mailboxes reconciled");
    whole
}

/// How soon a rebuild in which a read failed is tried again: after `first`,
/// then twice as long each time it fails again, up to `cap`; and from `first`
/// again once a pass reads everything.
#[derive(Debug, Clone, Copy)]
pub(super) struct Backoff {
    pub(super) first: Duration,
    pub(super) cap: Duration,
}

/// The daemon's: a torn read clears in milliseconds, so a second is soon
/// enough to pick up what the failed pass missed, and a store that stays
/// unreadable is asked once a minute and said in the log each time — its doors
/// stand meanwhile ([`Kept`]).
pub(super) const RETRY: Backoff = Backoff { first: Duration::from_secs(1), cap: Duration::from_secs(60) };

/// What [`keep_rebuilt`] runs.
pub(super) trait Rebuild: Send {
    /// One pass of the rebuild ([`refresh`]): `true` when every read held.
    fn rebuild(&mut self) -> impl Future<Output = bool> + Send;
    /// What else a change to a person's cards or rosters wakes, after the
    /// rebuild — the vault's doors. Not run on a retry: nothing
    /// changed, and the vault's own timer hands its doors again.
    fn after_a_change(&mut self) -> impl Future<Output = ()> + Send;
}

/// Run the rebuild on every change, and — while the last pass could not read
/// everything — again on [`Backoff`], until one can.
///
/// `held` is the answer of the pass already run before this is called (the
/// one at startup). A change is the wake it always was: `contacts_changed`,
/// which a card's write and a roster's change both notify, and which holds one
/// permit however many writes land, so a change during a pass is a second
/// pass and never a lost one. The backoff is what a change cannot be: the
/// write that woke a pass that failed has been consumed, and nothing else may
/// change for hours.
pub(super) async fn keep_rebuilt(changed: Arc<Notify>, mut held: bool, backoff: Backoff, mut it: impl Rebuild) {
    let mut wait = backoff.first;
    loop {
        let retry = if held {
            changed.notified().await;
            false
        } else {
            tokio::select! {
                _ = changed.notified() => false,
                _ = tokio::time::sleep(wait) => true,
            }
        };
        held = it.rebuild().await;
        if !retry {
            it.after_a_change().await;
        }
        wait = if held {
            backoff.first
        } else if retry {
            (wait * 2).min(backoff.cap)
        } else {
            wait
        };
    }
}

/// The daemon's rebuild: [`refresh`] over every resident person, keeping what
/// it reached, and on a change the vault's doors after it.
pub(super) struct Mailboxes {
    pub(super) runtime: Arc<DeviceRuntime>,
    pub(super) users: UserRegistry,
    pub(super) record_stores: RecordStores,
    pub(super) db: Arc<sqlx::SqlitePool>,
    pub(super) kept: Kept,
}

impl Rebuild for Mailboxes {
    async fn rebuild(&mut self) -> bool {
        refresh(&self.runtime, &self.users, &self.record_stores, &mut self.kept).await
    }

    async fn after_a_change(&mut self) {
        // A new contact needs a door at the vault too.
        crate::agent::vault_doors::sync_once(&self.runtime, &self.db, &self.users, &self.record_stores).await;
    }
}

/// The door behind one pair's mailbox: file what arrives (`delivery::accept`),
/// having held its signature to the contact's identity key.
fn handler(
    runtime: Arc<DeviceRuntime>,
    users: UserRegistry,
    record_stores: RecordStores,
    user_id: String,
    contact_did: String,
    contact_pub: [u8; 32],
) -> kotton_peer::PeerHandler {
    contact_door(move |request| {
        let runtime = Arc::clone(&runtime);
        let users = users.clone();
        let record_stores = record_stores.clone();
        let user_id = user_id.clone();
        let contact_did = contact_did.clone();
        async move {
            let host = DaemonMessageHost {
                runtime: runtime.as_ref(),
                users: &users,
                record_stores: &record_stores,
            };
            delivery::accept(&host, &user_id, &contact_did, &contact_pub, request).await
        }
    })
}

/// A source the rebuild cannot read keeps its doors, and the rebuild is tried
/// again until one can.
///
/// Against a member store whose listing is made to fail, as a listing that met
/// a half-written card did; and rosters read as `co_members_read` answers them.
/// The daemon's own pass is [`refresh`] over the same [`Kept`], and its loop
/// is [`keep_rebuilt`], which these run as they are.
#[cfg(test)]
mod tests {
    use super::*;
    use kotton_msg::daemon::messages::CoMember;
    use kotton_peer::membership::MemberStore;
    use kotton_schemas::membership::{Ceremony, Member, Role};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use tokio::sync::mpsc;

    /// A membership set held in memory, whose next `failing` listings fail.
    #[derive(Default)]
    struct Cards {
        objects: Mutex<HashMap<String, Vec<u8>>>,
        failing: AtomicUsize,
    }

    impl Cards {
        fn fail_next_listing(&self) {
            self.failing.store(1, Ordering::SeqCst);
        }

        async fn admit(&self, did: &str, key: u8) {
            let member = Member {
                did: did.to_string(),
                public_key: [key; 32],
                role: Role::Contact,
                admitted_by: Ceremony::Pairing,
                added_at: "2026-10-09T00:00:00Z".to_string(),
                posture: None,
                label: None,
                reach: None,
            };
            self.write_member(&member).await.expect("the card is written");
        }
    }

    #[async_trait::async_trait]
    impl MemberStore for Cards {
        async fn member_write(&self, path: &str, data: &[u8]) -> anyhow::Result<()> {
            self.objects.lock().unwrap().insert(path.to_string(), data.to_vec());
            Ok(())
        }
        async fn member_read(&self, path: &str) -> anyhow::Result<Vec<u8>> {
            self.objects.lock().unwrap().get(path).cloned().ok_or_else(|| anyhow::anyhow!("no object at {path}"))
        }
        async fn member_delete(&self, path: &str) -> anyhow::Result<()> {
            self.objects.lock().unwrap().remove(path);
            Ok(())
        }
        async fn member_list(&self, prefix: &str) -> anyhow::Result<Vec<String>> {
            if self.failing.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1)).is_ok() {
                anyhow::bail!("Failed to list files in '{prefix}': Backend error: encrypted blob too short for key");
            }
            Ok(self.objects.lock().unwrap().keys().filter(|k| k.starts_with(prefix)).cloned().collect())
        }
    }

    fn door(did: &str, key: u8) -> Door {
        (did.to_string(), [key; 32])
    }

    fn sorted(doors: &Doors) -> Vec<Door> {
        let mut all: Vec<Door> = doors.all().cloned().collect();
        all.sort();
        all
    }

    fn co_member(did: &str, key: u8, channel: &str) -> CoMember {
        CoMember { did: did.to_string(), key: [key; 32], reach: None, channel_did: channel.to_string() }
    }

    /// Alice's rebuild, reported a pass at a time: whether it read everything,
    /// and the doors it left.
    struct Alice {
        cards: Arc<Cards>,
        kept: Kept,
        passes: mpsc::UnboundedSender<(bool, Vec<Door>)>,
        changes: Arc<AtomicUsize>,
    }

    impl Rebuild for Alice {
        async fn rebuild(&mut self) -> bool {
            let mut pass = self.kept.pass();
            let doors = sorted(pass.person("alice", self.cards.as_ref(), Ok(CoMembersRead::default())).await);
            let whole = pass.finish();
            self.passes.send((whole, doors)).expect("the test is listening");
            whole
        }
        async fn after_a_change(&mut self) {
            self.changes.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// **A listing that fails leaves every door as it was, and the rebuild is
    /// tried again — with no further change — until a listing holds; then it
    /// stops.**
    ///
    /// Bob's card is listed; Carol's is written and its wake lands on a
    /// listing that fails. That pass must leave Bob's door (red when the
    /// failure writes an empty set: a contact who learned a rotated key would be
    /// unreachable at the new door), and a later pass, woken by nothing but the backoff, must
    /// open Carol's (red when nothing retries: the wake was spent on the pass
    /// that failed). The vault's doors follow the change once, and not the retry.
    #[tokio::test]
    async fn a_listing_that_fails_once_keeps_the_doors_and_the_rebuild_is_tried_again() {
        let cards = Arc::new(Cards::default());
        cards.admit("did:kel:bob", 1).await;
        let (tx, mut passes) = mpsc::unbounded_channel();
        let changes = Arc::new(AtomicUsize::new(0));
        let mut alice = Alice { cards: Arc::clone(&cards), kept: Kept::default(), passes: tx, changes: Arc::clone(&changes) };

        let held = alice.rebuild().await;
        assert_eq!(passes.recv().await, Some((true, vec![door("did:kel:bob", 1)])), "the first pass opens bob's door");

        cards.admit("did:kel:carol", 2).await;
        cards.fail_next_listing();
        let changed = Arc::new(Notify::new());
        changed.notify_one();
        let backoff = Backoff { first: Duration::from_millis(20), cap: Duration::from_millis(80) };
        let running = tokio::spawn(keep_rebuilt(Arc::clone(&changed), held, backoff, alice));

        let within = Duration::from_secs(10);
        let failed = tokio::time::timeout(within, passes.recv()).await.expect("carol's wake runs a pass");
        assert_eq!(
            failed,
            Some((false, vec![door("did:kel:bob", 1)])),
            "a listing that fails leaves bob's door as it was, and says the pass did not read everything"
        );
        let retried = tokio::time::timeout(within, passes.recv())
            .await
            .expect("the rebuild is tried again with no further change");
        assert_eq!(
            retried,
            Some((true, vec![door("did:kel:bob", 1), door("did:kel:carol", 2)])),
            "the retry lists the set and opens carol's door beside bob's"
        );

        tokio::time::sleep(backoff.cap * 4).await;
        assert!(passes.try_recv().is_err(), "a pass that read everything ends the retries");
        assert_eq!(changes.load(Ordering::SeqCst), 1, "the vault's doors follow the change, not the retry");
        running.abort();
    }

    /// **A person the last pass did not reach has nothing kept**: a locked
    /// person answers no mailbox, as before, and a listing that fails after
    /// their unlock opens nothing from before the lock.
    #[tokio::test]
    async fn a_person_whose_key_was_not_held_last_pass_keeps_no_door() {
        let cards = Cards::default();
        cards.admit("did:kel:bob", 1).await;
        let mut kept = Kept::default();

        let mut pass = kept.pass();
        assert_eq!(sorted(pass.person("alice", &cards, Ok(CoMembersRead::default())).await), [door("did:kel:bob", 1)]);
        assert!(pass.finish());

        // Locked: the pass does not reach her.
        assert!(kept.pass().finish(), "a locked person is no failed read");

        cards.fail_next_listing();
        let mut pass = kept.pass();
        assert_eq!(
            sorted(pass.person("alice", &cards, Ok(CoMembersRead::default())).await),
            Vec::<Door>::new(),
            "her doors as they were are none"
        );
        assert!(!pass.finish(), "and the read that failed is said");
    }

    /// **A channel whose rosters cannot be read keeps its co-members' doors,
    /// and no other channel's; channels that cannot be listed at all keep
    /// every co-member's; the next whole read rebuilds them.**
    ///
    /// Red when an unreadable roster writes its co-members out, and when an
    /// unlistable set of channels does.
    #[tokio::test]
    async fn a_roster_that_cannot_be_read_keeps_the_co_members_doors() {
        let cards = Cards::default();
        let mut kept = Kept::default();
        let (sam, pat) = (door("did:kel:sam", 3), door("did:kel:pat", 4));

        let mut pass = kept.pass();
        let read = CoMembersRead {
            members: vec![co_member("did:kel:sam", 3, "did:key:zA"), co_member("did:kel:pat", 4, "did:key:zB")],
            unreadable: vec![],
        };
        assert_eq!(sorted(pass.person("alice", &cards, Ok(read)).await), [pat.clone(), sam.clone()]);
        assert!(pass.finish());

        // Channel A cannot be read; channel B can, and no longer names Pat.
        let mut pass = kept.pass();
        let read = CoMembersRead { members: vec![], unreadable: vec!["did:key:zA".to_string()] };
        assert_eq!(
            sorted(pass.person("alice", &cards, Ok(read)).await),
            std::slice::from_ref(&sam),
            "sam's door stands with the channel that could not be read; pat's closes with the one that could"
        );
        assert!(!pass.finish());

        let mut pass = kept.pass();
        let unlisted = Err("could not read this identity's channel keys: disk I/O error".to_string());
        assert_eq!(
            sorted(pass.person("alice", &cards, unlisted).await),
            std::slice::from_ref(&sam),
            "channels that cannot be listed keep every co-member's door"
        );
        assert!(!pass.finish());

        let mut pass = kept.pass();
        let read = CoMembersRead { members: vec![], unreadable: vec![] };
        assert_eq!(
            sorted(pass.person("alice", &cards, Ok(read)).await),
            Vec::<Door>::new(),
            "a whole read rebuilds the set: A no longer names sam"
        );
        assert!(pass.finish());
    }
}
