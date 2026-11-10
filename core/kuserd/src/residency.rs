// SPDX-License-Identifier: AGPL-3.0-or-later
//! Which user runtimes are live in this daemon process.
//!
//! Residency is the daemon's bookkeeping of lifetimes it creates and destroys —
//! not a fact about the machine. `device` keeps the fingerprint -> user_id
//! routing table, which is a machine fact, and the
//! daemon owns `user_id -> Arc<UserStore>` and does the second hop itself.
//!
//! ## Why it is declared here
//!
//! `DeviceRuntime` is the machine and not the daemon's service locator: the
//! daemon creates and holds this, and the machine type cannot enumerate users
//! or resolve one to a runtime.
//!
//! The *type* is declared here too, with its owner. Declared in the runtime
//! crate, every daemon handler needing to find a user would name that crate to
//! do it, because serving a user begins by resolving which user.
//!
//! Every direct reach from the daemon asks *which* users, *how many*, *the one*,
//! or *whether anyone* — and none wants the `Arc<UserStore>`. The device/daemon boundary shows
//! up in the access pattern as well as in the types.
//!
//! ## On the name
//!
//! This module is `residency` and not `users` because the tree already holds two
//! other things a reader will call a user registry: [`crate::device_users`] is
//! `device/users.json`, the on-disk registration record, and `storage::load_users`
//! returns a `UserRecord` list whose field is literally `.users`. Those are
//! durable; this is live-in-this-process. The distinction is easy to lose — it
//! was lost once during this very move — so the module name carries it.

use anyhow::Result;
use kotton_device::users::DeviceUsers as _;
use kotton_record::SqliteRecordStore;
use kotton_store::runtime::user::UserStore;
use kotton_sys::secret::SecretsStore;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, OnceLock, RwLock};

/// The user runtimes loaded on this machine, keyed by user id.
///
/// Cloneable: the handle is shared, not the contents, so a caller holding one
/// sees the same registry rather than a snapshot of it.
#[derive(Clone, Default)]
pub struct UserRegistry {
    runtimes: Arc<RwLock<HashMap<String, Arc<UserStore>>>>,
    /// Where every resident store fetches a pack it does not keep when it is
    /// read (`kotton_store::fetch`, kotton #55): lent once, by the daemon,
    /// after its sync engine is made, and to each store as it becomes
    /// resident — here, the one door every store comes in by.
    packs: Arc<std::sync::OnceLock<Arc<dyn kotton_store::fetch::PackSource>>>,
}

impl UserRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace a user's runtime.
    ///
    /// Returns nothing deliberately: the event a registration should publish
    /// belongs to whoever owns the event bus, and threading one in here would
    /// give the registry a dependency it does not otherwise need.
    pub fn insert(&self, user_id: String, runtime: Arc<UserStore>) {
        if let Some(source) = self.packs.get() {
            runtime.lend_pack_source(Arc::clone(source));
        }
        self.runtimes.write().unwrap().insert(user_id, runtime);
    }

    /// Lend `source` to every store resident now and every one made resident
    /// after ([`Self::packs`]'s doc). Once: a second call is ignored.
    pub fn lend_packs(&self, source: Arc<dyn kotton_store::fetch::PackSource>) {
        if self.packs.set(Arc::clone(&source)).is_err() {
            return;
        }
        for store in self.runtimes.read().unwrap().values() {
            store.lend_pack_source(Arc::clone(&source));
        }
    }

    /// This user's runtime, if they are loaded.
    pub fn get(&self, user_id: &str) -> Option<Arc<UserStore>> {
        self.runtimes.read().unwrap().get(user_id).cloned()
    }

    /// Drop a user's runtime. `true` if one was loaded.
    pub fn remove(&self, user_id: &str) -> bool {
        self.runtimes.write().unwrap().remove(user_id).is_some()
    }

    /// Which users are loaded.
    ///
    /// This and the three below are the *machine's* view, and they are the whole
    /// of what callers outside this crate want: every direct reach into the
    /// map from the daemon asks which users, how many, the one, or whether
    /// anyone — and **none wants the `Arc<UserStore>`**. That is the device/daemon boundary showing
    /// up in the access pattern.
    pub fn ids(&self) -> Vec<String> {
        self.runtimes.read().unwrap().keys().cloned().collect()
    }

    /// How many users are loaded.
    pub fn count(&self) -> usize {
        self.runtimes.read().unwrap().len()
    }

    /// The one user loaded, or nobody: never a choice between two.
    ///
    /// The rule for every caller that acts for a user it was not given: the
    /// boot sidecars, the web-shell gateway at boot, the compositor channel and
    /// the system install (#432). Under supervision by `kdeviced` exactly one
    /// user is loaded, the process's principal, so this names them. With none
    /// loaded, or two, it is `None`, and the caller refuses rather than guess:
    /// a `HashMap` has no order, so "any one of two" is a coin toss over whose
    /// principal, store or registry is used.
    ///
    /// Read under one lock, so the count and the name cannot disagree.
    pub fn the_one_loaded(&self) -> Option<String> {
        only(self.runtimes.read().unwrap().keys())
    }

    /// Whether anybody is loaded at all. **Presence only**: it answers `bool`,
    /// so it cannot name a user, and nothing can act for one by it.
    ///
    /// This replaced `any() -> Option<String>`, "any one loaded user", which
    /// let a caller that only meant *is anyone here* also take the answer as
    /// *whom to act for* (#432). Its callers, each a presence check:
    ///
    /// - `DeviceDaemon::compositor_input` (`agent/compositor.rs`), read before
    ///   an input event: nobody resident means the running shell is the
    ///   pre-identity one, so a user who exists after the event was just
    ///   created there. Who that user is comes from [`Self::the_one_loaded`].
    /// - `DeviceDaemon::launch_designated_shell` (`agent/compositor.rs`):
    ///   nobody resident means there is no designation to consult, so the
    ///   system shell starts. Whose designation it is, when somebody is,
    ///   comes from [`Self::the_one_loaded`], through
    ///   `dispatch::user_db_for_compositor`.
    pub fn is_any_resident(&self) -> bool {
        !self.runtimes.read().unwrap().is_empty()
    }

    /// Every loaded runtime, for a caller that must act on all of them —
    /// shutdown being the one that does.
    ///
    /// Returns owned handles rather than lending the guard, so the lock is never
    /// held across whatever the caller does with them. Shutdown holding a read
    /// lock while it awaited each runtime is the shape this prevents.
    pub fn all(&self) -> Vec<(String, Arc<UserStore>)> {
        self.runtimes
            .read()
            .unwrap()
            .iter()
            .map(|(id, rt)| (id.clone(), Arc::clone(rt)))
            .collect()
    }
}

/// The one id `ids` holds, or `None` for none or several:
/// [`UserRegistry::the_one_loaded`]'s rule, apart from the lock.
fn only<'a>(mut ids: impl Iterator<Item = &'a String>) -> Option<String> {
    match (ids.next(), ids.next()) {
        (Some(one), None) => Some(one.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **A record write wakes a pass by its schema** (kotton #450): a store this cache opens
    /// calls the engine's wake after a note's insert and never after an access-log record's,
    /// and one opened before the wake was given calls it too. Counted, not timed.
    #[tokio::test]
    async fn a_store_opened_here_wakes_the_engine_for_a_note_and_not_for_a_log_record() {
        use kotton_record::RecordStore as _;
        use kotton_schemas::{CoreSchema, SchemaId};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let base = tempfile::tempdir().unwrap();
        let secrets = kotton_secret::MemorySecrets::new();
        secrets
            .set_secret(&kotton_common::crypto::kdf_labels::master_secret_keychain_key("alice"), &hex::encode([7u8; 32]))
            .unwrap();
        let stores = RecordStores::new();
        let store = stores.get_or_open(base.path(), "alice", &secrets).unwrap();
        let woken = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&woken);
        stores.wake_on_write(Arc::new(move || {
            count.fetch_add(1, Ordering::SeqCst);
        }));
        for cs in [CoreSchema::Notes, CoreSchema::AccessLog] {
            store.create_table(&cs.definition()).await.unwrap();
        }
        let log = SchemaId::from_static(kotton_common::namespace::NSID_ACCESS_LOG);
        let entry = serde_json::json!({ "device": "did:key:a", "at": "2026-11-10T00:00:00Z",
            "asker": "terminal", "door": "local", "act": "read", "what": "w" });
        store.insert(&log, entry).await.unwrap();
        assert_eq!(woken.load(Ordering::SeqCst), 0, "a log record woke the engine");
        let notes = SchemaId::from_static(kotton_common::namespace::NSID_NOTES);
        store.insert(&notes, serde_json::json!({ "title": "a note" })).await.unwrap();
        assert_eq!(woken.load(Ordering::SeqCst), 1, "a note woke no pass");
        assert!(Arc::ptr_eq(&store, &stores.get_or_open(base.path(), "alice", &secrets).unwrap()));
    }

    /// **Nothing that acts for a user it was not given guesses between two.**
    /// One person loaded is that person; nobody, or two, is nobody — never
    /// whichever the registry's map happens to yield first. (Moved here from
    /// `record_access`, whose compositor records host was its first reader.)
    #[test]
    fn the_one_loaded_names_one_user_and_never_chooses_between_two() {
        let ids = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(only(ids(&["alice"]).iter()), Some("alice".into()));
        assert_eq!(only(ids(&[]).iter()), None);
        assert_eq!(only(ids(&["alice", "bob"]).iter()), None);
        assert_eq!(only(ids(&["alice", "bob", "carol"]).iter()), None);
    }

    #[test]
    fn an_empty_registry_answers_all_three_questions_without_panicking() {
        let reg = UserRegistry::new();
        assert!(reg.ids().is_empty());
        assert_eq!(reg.count(), 0);
        assert!(!reg.is_any_resident());
        assert!(reg.the_one_loaded().is_none());
        assert!(reg.get("nobody").is_none());
        assert!(reg.all().is_empty());
    }

    #[test]
    fn removing_an_absent_user_is_false_rather_than_an_error() {
        // Eviction runs on paths that cannot know whether the user was ever
        // loaded — deleting an account that never logged in on this device, for
        // one — so "not there" is an answer, not a failure.
        let reg = UserRegistry::new();
        assert!(!reg.remove("alice"));
    }

    #[test]
    fn a_clone_shares_the_registry_rather_than_copying_it() {
        // The handle is shared on purpose: a caller holding a clone must see
        // registrations made through the original, or two halves of the daemon
        // would disagree about who is loaded.
        let a = UserRegistry::new();
        let b = a.clone();
        assert_eq!(a.count(), b.count());
        assert!(Arc::ptr_eq(&a.runtimes, &b.runtimes));
    }
}

/// The record stores open on this machine, keyed by user id.
///
/// The second residency map, and it is here for the same reason as the first:
/// **which stores are open is bookkeeping about lifetimes the daemon owns**, not
/// a fact about the machine. On `DeviceRuntime` it would make the machine
/// handle a path to every resident user's records — the shape `core/device`
/// states it will not have.
///
/// What it means to *open* one is [`kotton_record::open::user_record_store`]'s;
/// this only remembers which are already open, and gives each the sync engine's wake
/// ([`Self::wake_on_write`]).
#[derive(Clone, Default)]
pub struct RecordStores {
    stores: Arc<RwLock<HashMap<String, Arc<SqliteRecordStore>>>>,
    /// The sync engine's wake, which every store opened here calls after a write that wakes a
    /// pass (`kotton_record::SqliteRecordStore::with_write_signal`). Set once the engine
    /// exists, which is after this cache is lent to it; read at each write, so a store
    /// opened before it was set calls it too.
    wake: Arc<OnceLock<kotton_record::WriteSignal>>,
}

impl RecordStores {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// This user's record store, opening it if it is not already open.
    ///
    /// Two lookups rather than one: the fast path takes a read lock, and the
    /// slow path re-checks under the write lock because opening is `await`-free
    /// but not instant, and two callers can arrive together. The re-check is why
    /// a race yields one store rather than two handles to the same file.
    pub fn get_or_open(
        &self,
        base_dir: &Path,
        user_id: &str,
        secrets: &dyn SecretsStore,
    ) -> Result<Arc<SqliteRecordStore>> {
        if let Some(store) = self.stores.read().unwrap().get(user_id) {
            return Ok(Arc::clone(store));
        }

        let wake = Arc::clone(&self.wake);
        let store = Arc::new(
            kotton_record::open::user_record_store(base_dir, user_id, secrets)?
                .with_write_signal(Arc::new(move || {
                    if let Some(wake) = wake.get() {
                        wake();
                    }
                })),
        );

        let mut stores = self.stores.write().unwrap();
        Ok(Arc::clone(
            stores
                .entry(user_id.to_owned())
                .or_insert_with(|| Arc::clone(&store)),
        ))
    }

    /// Have every store opened here wake a sync pass after a record write that wakes one
    /// (kotton #450): every schema's insert or delete but `access-log`'s
    /// (`kotton_record::replication::a_write_wakes_a_pass`). The daemon gives it its sync
    /// engine's wake. A record write used to wake the engine only by changing `records.db`
    /// under the filesystem watcher, which cannot tell one schema's write from another's and
    /// no longer wakes on that file (`kotton_sync::engine::a_change_wakes_a_pass`). Set once;
    /// a second call is ignored.
    pub fn wake_on_write(&self, wake: kotton_record::WriteSignal) {
        let _ = self.wake.set(wake);
    }

    /// Forget a user's store. Called when a user is evicted; the file stays.
    pub fn remove(&self, user_id: &str) {
        self.stores.write().unwrap().remove(user_id);
    }
}

// ---------------------------------------------------------------------------
// The sync engine's view of all this
// ---------------------------------------------------------------------------

/// This daemon's answer to [`kotton_sync::UserResources`].
///
/// The sync engine used to hold [`UserRegistry`], [`RecordStores`] and the
/// per-user database map as three fields. Those types exist only in a daemon, so
/// holding them is what kept 1,621 lines of replication logic inside a binary
/// crate — the logic was never the problem.
///
/// This is the other side of that seam. It holds all three, plus the
/// `DeviceRuntime` needed to open anything, and hands the engine four questions
/// keyed by user id. Note what the engine no longer has to know: opening a record
/// store needs a base dir and a secrets store, and opening a user db needs a schema
/// registry as well. All of that is on this side of the line now.
pub struct DaemonUserResources {
    users: UserRegistry,
    record_stores: RecordStores,
    user_dbs: crate::db::user_db::UserDbMap,
    runtime: Arc<kotton_device::DeviceRuntime>,
    /// The machine's database, which a pass reads the budget and keeps what
    /// it found of the room in (`kotton_device::users::pins`); `None` in a
    /// harness that has none.
    machine_db: Option<Arc<sqlx::SqlitePool>>,
}

impl DaemonUserResources {
    /// Wrap this daemon's locators as the engine's resource host.
    pub fn new(
        users: UserRegistry,
        record_stores: RecordStores,
        user_dbs: crate::db::user_db::UserDbMap,
        runtime: Arc<kotton_device::DeviceRuntime>,
        machine_db: Option<Arc<sqlx::SqlitePool>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            users,
            record_stores,
            user_dbs,
            runtime,
            machine_db,
        })
    }
}

#[async_trait::async_trait]
impl kotton_sync::UserResources for DaemonUserResources {
    fn user_ids(&self) -> Vec<String> {
        self.users.ids()
    }

    fn user_store(&self, user_id: &str) -> Option<Arc<UserStore>> {
        self.users.get(user_id)
    }

    fn record_store(&self, user_id: &str) -> Result<Arc<SqliteRecordStore>> {
        self.record_stores
            .get_or_open(self.runtime.base_dir(), user_id, self.runtime.secrets())
    }

    async fn agent_db(&self, user_id: &str) -> Option<Arc<sqlx::SqlitePool>> {
        match crate::db::user_db::user_agent_db(
            &self.user_dbs,
            self.runtime.base_dir(),
            self.runtime.secrets(),
            user_id,
            &self.runtime.schema_registry,
        )
        .await
        {
            Ok(pool) => Some(pool),
            Err(e) => {
                // A rule that cannot be read is a pass that does not run, not a
                // crash — the engine's long-standing behaviour, kept here now that
                // the open lives on this side of the seam.
                tracing::warn!(user_id, error = %e, "sync host: user db unavailable");
                None
            }
        }
    }

    /// The machine's database, lent so a pass can find the drive it is with
    /// and keep what it found of this device's room (`kotton_device::users::pins`).
    fn machine_db(&self) -> Option<Arc<sqlx::SqlitePool>> {
        self.machine_db.clone()
    }

    /// The name another of the person's devices set arrives as a sealed record
    /// in a pass; this device's copy of it is brought up to that record here.
    async fn pass_landed(&self, user_id: &str) {
        let Some(store) = self.users.get(user_id) else {
            return;
        };
        match crate::own_name::refresh_cache(self.runtime.base_dir(), user_id, &store).await {
            Ok(true) => tracing::info!(user_id, "sync: this device's copy of the person's name follows their record"),
            Ok(false) => {}
            Err(e) => tracing::warn!(
                user_id, error = %e,
                "sync: the person's name record could not be copied; this device keeps the copy it had"
            ),
        }
    }
}

#[async_trait::async_trait]
impl kotton_sync::PeerLinks for DaemonUserResources {
    async fn open_peer_client(
        &self,
        node: kotton_wire::peer::PairedNode,
        user_id: &str,
        loaded: Option<&UserStore>,
    ) -> Result<kotton_peer::KottonPeerObjectStorage> {
        // `DeviceUsers` is kuserd's own extension trait on `DeviceRuntime`. The
        // engine used to call this method through it directly, which was the last
        // daemon type its body named. Answering it here is what frees the engine.
        self.runtime.open_peer_client(node, user_id, loaded).await
    }
}

impl kotton_device::users::residency::Residency for UserRegistry {
    /// Making a user resident in *this* daemon is what lays down their app
    /// directory: this is the daemon that has apps, and every path by which a
    /// user comes to be served here — created, unlocked, joined, loaded at
    /// start — passes through this one call. Done where the store is built, in
    /// `core/device`, it would make a vault link the app domain to create a
    /// directory it would never use. Empty and locked
    /// before the first install, as `apps_dir` says.
    fn insert(&self, user_id: String, store: Arc<UserStore>) {
        if let Err(e) = kotton_app::provision::apps_dir(store.base_dir()) {
            tracing::error!(user_id = %user_id, "could not lay down the app directory: {e:#}");
        }
        UserRegistry::insert(self, user_id, store);
    }

    fn get(&self, user_id: &str) -> Option<Arc<UserStore>> {
        UserRegistry::get(self, user_id)
    }
}
