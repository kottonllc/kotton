// SPDX-License-Identifier: AGPL-3.0-or-later
//! The end of an unlock: an unlock ends, and its end is reported.
//!
//! `SealedCustody` gives every unlocked identity a deadline and refuses reads
//! past it, so the *keys* already have an end. What this module adds is the
//! daemon's half: the window's length is the person's lock policy, not the
//! primitive's default, and a `UserStore` binds its CEK when it is loaded — so
//! a store built while custody was open keeps reading after custody closes
//! unless something rebuilds it. The sweep here does both, on a timer, the
//! same two steps `lock_as_a_restart_would` takes in the suite to model a
//! restart: drop the roots, reload the store cold, install it.
//!
//! The window is armed by a credential and by nothing else: `UnlockWithPin`
//! and `SetLockPolicy` re-arm it with [`window_secs`], and a read never does
//! (expiry is absolute, not sliding).

use crate::db::user_db::{UserDbMap, UserDbSlot};
use crate::event_log::{stop_user_log, EventLogTasks};
use crate::residency::{RecordStores, UserRegistry};
use kotton_common::time::now_secs;
use kotton_device::users::DeviceUsers as _;
use kotton_device::DeviceRuntime;
use kotton_secret::sealed_custody::DEFAULT_WINDOW_SECS;
use kotton_session::lock_policy::LockPolicy;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// How long custody stays open under this policy, in seconds.
///
/// `auto_lock_minutes` is minutes because that is what the person sets. The
/// window is *bounded*, so `0` means the default bound rather than none — read
/// as "explicit lock only", it would mean "for the life of the daemon". The
/// value a person set is honoured to the minute.
pub fn window_secs(policy: &LockPolicy) -> i64 {
    match policy.auto_lock_minutes {
        0 => DEFAULT_WINDOW_SECS,
        minutes => i64::from(minutes) * 60,
    }
}

/// Re-arm `user_id`'s window from their policy, now that a credential has
/// been presented. Returns the new deadline, or `None` if nothing is held —
/// a window is a property of held roots, never a promise to hold them.
pub fn arm(runtime: &DeviceRuntime, base: &std::path::Path, user_id: &str) -> Option<i64> {
    let policy = kotton_session::lock_policy::load(base, user_id).unwrap_or_default();
    let until = now_secs() + window_secs(&policy);
    runtime
        .custody()
        .set_open_until(user_id, until)
        .then_some(until)
}

/// How often expired identities are closed. A minute: the deadline is enforced
/// on every read regardless, so this only bounds how long a closed identity's
/// *store* stays keyed. `KOTTON_CUSTODY_SWEEP_SECS` overrides it so a test need
/// not wait that long to watch one close.
fn sweep_interval() -> Duration {
    std::env::var("KOTTON_CUSTODY_SWEEP_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(60))
}

pub fn spawn(
    runtime: Arc<DeviceRuntime>,
    users: UserRegistry,
    user_dbs: UserDbMap,
    record_stores: RecordStores,
    event_log_tasks: EventLogTasks,
) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(sweep_interval()).await;
            close_expired(
                &runtime,
                &users,
                &user_dbs,
                &record_stores,
                &event_log_tasks,
                now_secs(),
            )
            .await;
        }
    });
}

/// One pass: every identity whose window has closed by `now` is dropped from
/// custody and its resident store rebuilt without a key. Returns who closed.
///
/// The rebuild is what makes the close real. Without it the roots are gone
/// and every read still succeeds, because the store derived what it needed
/// while they were there — a lock that changes nothing observable, which is
/// the shape of defect this record is about.
pub async fn close_expired(
    runtime: &Arc<DeviceRuntime>,
    users: &UserRegistry,
    user_dbs: &UserDbMap,
    record_stores: &RecordStores,
    event_log_tasks: &EventLogTasks,
    now: i64,
) -> Vec<String> {
    let closed = runtime.custody().sweep_expired(now);
    for user_id in &closed {
        tracing::info!(user_id, "custody window closed");
        rebuild_cold(runtime, users, user_id).await;
        forget_open_databases(user_dbs, record_stores, event_log_tasks, user_id).await;
    }
    closed
}

/// Close custody for one identity now, on request rather than on the clock
/// (`LockCustody`). The same two
/// steps as the sweep — drop the roots, rebuild the store cold — so the two
/// ways custody ends cannot come to mean different things. Returns whether
/// anything was held; locking an already-locked identity is routine and
/// changes nothing.
pub async fn lock_now(
    runtime: &Arc<DeviceRuntime>,
    users: &UserRegistry,
    user_dbs: &UserDbMap,
    record_stores: &RecordStores,
    event_log_tasks: &EventLogTasks,
    user_id: &str,
) -> bool {
    let was_held = runtime.custody().lock_identity(user_id);
    if was_held {
        tracing::info!(user_id, "custody closed on request");
        rebuild_cold(runtime, users, user_id).await;
        forget_open_databases(user_dbs, record_stores, event_log_tasks, user_id).await;
    }
    was_held
}

/// **The third step of a close: forget every database handle the account opened
/// while its key was there.**
///
/// The resident store is not the only thing that binds a key when it opens. The
/// `records.db` store in [`RecordStores`] and the `agent.db` pool in the
/// [`UserDbMap`] each derived theirs from the roots at open time and hold it for
/// as long as they are cached — so a lock that only rebuilt the object store
/// cold would leave both of those open and keyed, and the vault would read as
/// *locked* while the inbox, the unread count and the app registry went on
/// answering from handles opened before the lock
/// (`restarted_daemon::locking_custody_closes_what_the_account_had_open`, and
/// `the_window_closing_closes_what_the_account_had_open` for the sweep).
///
/// Forgotten, not closed. A reach for either after this finds no cached handle,
/// opens afresh, resolves no key and refuses with *account is locked* — which is
/// the state a restarted daemon is in, and the reference this is held to. A
/// request already in flight finishes on the handle it holds.
///
/// **And the account's event-log task is stopped, first.** It owns a clone of
/// the `agent.db` pool and appends this account's events under its key; it
/// lives by the lock and not by the process, or it would be the one keyed
/// holder a lock left behind. It is stopped with the same awaited
/// [`stop_user_log`] `LogoutUser` uses, so its pool clone is gone before this
/// returns, and [`rekey_resident_store`] starts it again when a credential
/// reopens the account.
async fn forget_open_databases(
    user_dbs: &UserDbMap,
    record_stores: &RecordStores,
    event_log_tasks: &EventLogTasks,
    user_id: &str,
) {
    stop_user_log(event_log_tasks, user_id).await;
    record_stores.remove(user_id);
    // Only a live slot. A `Closing` marker is a logout in progress telling every
    // opener to stay away from files about to be deleted; removing it would read
    // as first contact and let the next background pass reopen them.
    let mut slots = user_dbs.write().unwrap();
    if matches!(slots.get(user_id), Some(UserDbSlot::Live(_))) {
        slots.remove(user_id);
    }
}

/// **The opposite move, after a credential is accepted: a resident store that
/// holds no key is rebuilt with the one the unlock restored, and installed.**
///
/// A `UserStore` binds its CEK at **load time**, so a daemon that started
/// before this identity was unlocked — every restart, and first run before
/// `id create` exists — holds a keyless store for them until something rebuilds
/// it. Without this the unlock answers *ok* while every read against that
/// person keeps being refused, and quietly: `list_members` turns its error into
/// an empty list. Both doors call it — the IPC `UnlockWithPin` arm and the
/// occupant host's `open_session`, the door the lock screen uses — or the
/// relaunch that follows a correct passphrase lands on a desk over a store with
/// no key: an account row with a fingerprint, no roots, and a Networking notice
/// saying the node holds none. One function, two doors, so the two cannot
/// disagree.
///
/// **And the same rebuild is where `agent.db` first opens in this daemon's
/// life for an identity that was locked at boot.** `user_agent_db` refused
/// with *account is locked* while no key was resolvable
/// (`open_user_agent_db`'s `Locked` arm), so the boot pass's own
/// `auto_install_bundled_apps` never ran for this person, and nothing since
/// has retried it — a fresh identity gets every bundled app and a returning,
/// locked one does not, until the next restart repeats the same miss. Once
/// the CEK is back, `agent.db` can open, so the install runs here, once,
/// the same call the boot and create-identity doors make and not a copy of it —
/// idempotent as it always was, so an identity already carrying every bundled
/// app pays only the hash check.
///
/// **And the account's event log starts here again.** A lock stops it
/// ([`forget_open_databases`]) and a daemon that booted with the account locked
/// never started it, because `agent.db` would not open; this is the first point
/// after either at which the pool opens with the key, so the log is started
/// beside the install, chained under the restored key.
///
/// Guarded on the resident store actually being keyless, so unlocking an
/// account that is already open does not churn a live handle. Returns whether
/// the store was rebuilt; a rebuild that failed is logged and the keyless store
/// stays, which is the case `app_launch`'s `keys_loaded` question exists for.
pub async fn rekey_resident_store(
    runtime: &DeviceRuntime,
    users: &UserRegistry,
    user_dbs: &crate::db::user_db::UserDbMap,
    event_log_tasks: &EventLogTasks,
    base: &Path,
    user_id: &str,
) -> bool {
    let resident_is_keyless = users
        .get(user_id)
        .map(|s| s.sealing_keys().is_none())
        .unwrap_or(false);
    if !resident_is_keyless {
        return false;
    }
    match runtime.reload_user_runtime(user_id).await {
        Ok(fresh) => {
            users.insert(user_id.to_string(), fresh);
            tracing::info!(
                user_id,
                "unlock: the resident store held no key and has been rebuilt with the restored CEK"
            );
            match crate::db::user_db::user_agent_db(
                user_dbs,
                base,
                runtime.secrets(),
                user_id,
                &runtime.schema_registry,
            )
            .await
            {
                Ok(user_db) => {
                    super::auto_install_bundled_apps(&user_db, base, user_id, runtime.secrets())
                        .await;
                    super::spawn_user_event_log(runtime, user_dbs, base, event_log_tasks, user_id)
                        .await;
                }
                Err(e) => tracing::warn!(
                    user_id,
                    error = %e,
                    "unlocked, but the database could not be opened to install this \
                     daemon's bundled apps; the next restart will retry"
                ),
            }
            true
        }
        Err(e) => {
            tracing::warn!(
                user_id,
                error = %e,
                "unlock succeeded but the resident store could not be rebuilt, so this \
                 identity's own data stays unreadable until it is loaded again"
            );
            false
        }
    }
}

/// Replace the resident store with one loaded as a cold daemon would load
/// it — no key — and install it. Called only after the roots are gone, so the
/// reload resolves nothing.
async fn rebuild_cold(runtime: &Arc<DeviceRuntime>, users: &UserRegistry, user_id: &str) {
    if users.get(user_id).is_none() {
        return;
    }
    match runtime.reload_user_runtime(user_id).await {
        Ok(cold) => {
            users.insert(user_id.to_string(), cold);
            tracing::info!(
                user_id,
                "this identity's vault is locked until its passphrase opens it again"
            );
        }
        Err(e) => tracing::warn!(
            user_id,
            error = %e,
            "custody closed but the resident store could not be rebuilt; it is dropped rather than left keyed"
        ),
    }
}

/// After a credential is proved: restore the operational roots from the vault
/// when the store does not hold them. The one presence check both doors make —
/// the `UnlockWithPin` arm and the lock screen's `open_session` — so the two
/// cannot disagree about what "absent" means.
///
/// A copy that does not open under the credential the record accepted is an
/// error, and both doors close the session they opened: an unlock that
/// restores no key is refused, not answered as open.
///
/// "Absent" is the store answering that it holds no master secret. A store that
/// could not answer is an error, and nothing is restored: the restore writes all
/// three root labels, and an unreadable read taken for absent wrote them over
/// the ones it could not read.
pub async fn restore_roots_if_absent(runtime: &DeviceRuntime, user_id: &str, credential: &str) -> std::io::Result<()> {
    let label = kotton_common::crypto::kdf_labels::master_secret_keychain_key(user_id);
    let roots_present = runtime
        .secrets()
        .get_secret(&label)
        .map_err(|e| {
            std::io::Error::other(format!(
                "the credential was right, but {label} could not be read, so nothing was restored over it: {e}. \
                 If it fails every time, `kotton id unlock {user_id} --repair` writes it back from your vault"
            ))
        })?
        .is_some();
    if !roots_present {
        // The passphrase matched the record, and the copy this device holds did
        // not open under it: the record and the copy disagree, and a session
        // opened here would restore no key. Refused, and in words that do not
        // send the person to retype a passphrase that was right.
        runtime.unlock_with_pin(user_id, credential).await.map_err(|e| {
            tracing::warn!(%user_id, "passphrase matched the record but the sealed copy did not open: {e:#}");
            std::io::Error::other(format!(
                "the passphrase is the one on record for '{user_id}', but the copy of the keys \
                 this device holds does not open under it ({e:#}), so no session was opened. \
                 No session on this device holds the keys now; restore them with the recovery \
                 phrase: `kotton id recover {user_id}`."
            ))
        })?;
    }
    Ok(())
}

/// After a credential is proved, and only when the owner asked for it: repair
/// the operational roots from the vault — write the ones the store could not
/// read or does not hold, compare the ones it did read, and refuse on a
/// mismatch, naming the label — the repair for a keychain entry that fails
/// permanently.
///
/// Returns the labels written. Reached only from the `UnlockWithPin` arm with
/// `repair` set, after `try_unlock_with_pin` has accepted the credential, so the
/// repair answers to exactly the guards the unlock does.
pub async fn repair_roots_from_vault(
    runtime: &DeviceRuntime,
    user_id: &str,
    credential: &str,
) -> std::io::Result<Vec<String>> {
    kotton_identity::provisioning::repair_roots_from_vault(runtime, user_id, credential)
        .map(|repair| repair.written)
        .map_err(|e| std::io::Error::other(format!("{e:#}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    mod repair {
        use super::*;
        use kotton_common::crypto::kdf_labels;
        use kotton_sys::secret::{SecretsError, SecretsResult, SecretsStore};
        use std::collections::HashSet;
        use std::sync::Mutex;

        pub const PASSPHRASE: &str = "canyon-orbit-velvet-fish-hospital";

        pub fn roots(user: &str) -> [String; 3] {
            [
                kdf_labels::master_secret_keychain_key(user),
                kdf_labels::identity_signing_key(user),
                kdf_labels::operational_cek(user),
            ]
        }

        /// A platform keychain whose `corrupt` entries fail every read until
        /// they are written — a keyring `BadEncoding`, which an overwrite
        /// replaces — and which records every write and delete once `watching`.
        #[derive(Default)]
        pub struct Keychain {
            pub inner: kotton_secret::MemorySecrets,
            pub corrupt: Mutex<HashSet<String>>,
            pub watching: std::sync::atomic::AtomicBool,
            pub written: Mutex<Vec<String>>,
            pub deleted: Mutex<Vec<String>>,
        }
        impl Keychain {
            fn watching(&self) -> bool {
                self.watching.load(std::sync::atomic::Ordering::SeqCst)
            }
        }
        impl SecretsStore for Keychain {
            fn get_secret(&self, key: &str) -> SecretsResult<Option<String>> {
                if self.corrupt.lock().unwrap().contains(key) {
                    return Err(SecretsError::Storage(format!("{key}: BadEncoding")));
                }
                self.inner.get_secret(key)
            }
            fn set_secret(&self, key: &str, value: &str) -> SecretsResult<()> {
                if self.watching() {
                    self.written.lock().unwrap().push(key.to_string());
                }
                self.corrupt.lock().unwrap().remove(key);
                self.inner.set_secret(key, value)
            }
            fn delete_secret(&self, key: &str) -> SecretsResult<()> {
                if self.watching() {
                    self.deleted.lock().unwrap().push(key.to_string());
                }
                self.inner.delete_secret(key)
            }
        }

        /// Alice, created with a passphrase vault, then locked — out of memory
        /// custody, as after a restart — with every root back in the platform
        /// store at the value her vault seals, as an install that keeps them
        /// there has them. Returns the runtime, the keychain, and the vault's
        /// roots by label.
        pub async fn alice_with_roots_on_the_platform(
            base: &Path,
        ) -> (DeviceRuntime, Arc<Keychain>, Vec<(String, String)>) {
            let keychain = Arc::new(Keychain::default());
            let runtime = DeviceRuntime::new_with_secrets(
                base.to_path_buf(),
                kotton_device::config::RuntimeConfig::default(),
                keychain.clone(),
            )
            .await
            .unwrap();
            runtime.create_user("alice", PASSPHRASE).await.unwrap();
            let vault: Vec<(String, String)> = roots("alice")
                .into_iter()
                .map(|label| {
                    let value = runtime.secrets().get_secret(&label).unwrap().expect("held after create");
                    (label, value)
                })
                .collect();
            assert!(runtime.custody().lock_identity("alice"));
            for (label, value) in &vault {
                keychain.inner.set_secret(label, value).unwrap();
            }
            (runtime, keychain, vault)
        }
    }

    /// **A root entry that fails every read is repaired from the vault, and
    /// nothing else is written.** `master_secret` fails every read while the
    /// identity key and the CEK read; the repair writes `master_secret` alone,
    /// from the vault, and the next `resolve_master_secret` answers the vault's
    /// value. The labels that read keep their values: the custody purge that
    /// follows every unlock moves them into memory, it does not lose them.
    #[tokio::test]
    async fn a_root_entry_that_fails_every_read_is_repaired_from_the_vault_and_nothing_else_is_written() {
        use repair::*;
        let temp = tempfile::tempdir().unwrap();
        let (runtime, keychain, vault) = alice_with_roots_on_the_platform(temp.path()).await;
        let master = kotton_common::crypto::kdf_labels::master_secret_keychain_key("alice");
        keychain.corrupt.lock().unwrap().insert(master.clone());
        assert!(
            kotton_identity::provisioning::resolve_master_secret(runtime.secrets(), "alice").is_err(),
            "the entry fails every read before the repair"
        );
        keychain.watching.store(true, std::sync::atomic::Ordering::SeqCst);

        let written = repair_roots_from_vault(&runtime, "alice", PASSPHRASE)
            .await
            .expect("a credential that opens the vault repairs the entry it seals");

        assert_eq!(written, vec![master.clone()], "the repair reports what it wrote");
        assert_eq!(
            *keychain.written.lock().unwrap(),
            vec![master.clone()],
            "only the entry that could not be read was written"
        );
        let vault_master: [u8; 32] = hex::decode(&vault[0].1).unwrap().try_into().unwrap();
        assert_eq!(
            kotton_identity::provisioning::resolve_master_secret(runtime.secrets(), "alice").unwrap(),
            Some(vault_master),
            "the next read answers the vault's value"
        );
        for (label, value) in &vault {
            assert_eq!(
                runtime.secrets().get_secret(label).unwrap().as_deref(),
                Some(value.as_str()),
                "{label} still answers the vault's value"
            );
        }
    }

    /// **A vault the key log does not install refuses the repair, and nothing is
    /// written** — the state a rotation that crashed leaves: the key log moved
    /// to a new identity key, the live vault still seals the old one, and the
    /// staged vault that would have carried the new one does not open. Writing
    /// the stale vault's roots into the entry that could not be read would
    /// replace what may be the only copy of the key the chain admits.
    #[tokio::test]
    async fn a_vault_the_key_log_does_not_install_refuses_the_repair_and_writes_nothing() {
        use repair::*;
        let temp = tempfile::tempdir().unwrap();
        let (runtime, keychain, _vault) = alice_with_roots_on_the_platform(temp.path()).await;
        // The live vault re-sealed around an identity key the key log never
        // installed — it is behind the log — and a staged vault that does not open.
        let live = kotton_identity::provisioning::open_vault_under(&runtime, "alice", PASSPHRASE).unwrap();
        let stale = kotton_crypto::OperationalRoots { identity_key: [9u8; 32], ..live };
        let sealed = kotton_crypto::seal_vault(PASSPHRASE, &stale, None).unwrap();
        let dir = temp.path().join("users").join("alice");
        std::fs::write(
            dir.join(kotton_identity::provisioning::VAULT_FILE),
            serde_json::to_string(&sealed).unwrap(),
        )
        .unwrap();
        std::fs::write(dir.join(kotton_identity::provisioning::STAGED_VAULT_FILE), b"not a vault").unwrap();
        let identity = kotton_common::crypto::kdf_labels::identity_signing_key("alice");
        keychain.corrupt.lock().unwrap().insert(identity.clone());
        keychain.watching.store(true, std::sync::atomic::Ordering::SeqCst);

        let err = repair_roots_from_vault(&runtime, "alice", PASSPHRASE)
            .await
            .expect_err("a vault the key log does not install must refuse the repair");

        assert!(err.to_string().contains("key log"), "the refusal says why: {err}");
        assert_eq!(*keychain.written.lock().unwrap(), Vec::<String>::new(), "nothing was written");
        assert_eq!(*keychain.deleted.lock().unwrap(), Vec::<String>::new(), "nothing was deleted");
    }

    /// **A key log that cannot be read refuses the repair, and nothing is
    /// written**: the vault cannot be shown current, so it is not written into
    /// an entry that could not be read.
    #[tokio::test]
    async fn a_key_log_that_cannot_be_read_refuses_the_repair_and_writes_nothing() {
        use repair::*;
        let temp = tempfile::tempdir().unwrap();
        let (runtime, keychain, _vault) = alice_with_roots_on_the_platform(temp.path()).await;
        let kel = temp.path().join("users").join("alice").join("identity").join("kel.json");
        assert!(kel.exists(), "alice's key log is where the test expects it");
        std::fs::write(&kel, b"not a key log").unwrap();
        let master = kotton_common::crypto::kdf_labels::master_secret_keychain_key("alice");
        keychain.corrupt.lock().unwrap().insert(master);
        keychain.watching.store(true, std::sync::atomic::Ordering::SeqCst);

        let err = repair_roots_from_vault(&runtime, "alice", PASSPHRASE)
            .await
            .expect_err("a key log that cannot be read must refuse the repair");

        assert!(err.to_string().contains("could not be read"), "the refusal says why: {err}");
        assert_eq!(*keychain.written.lock().unwrap(), Vec::<String>::new(), "nothing was written");
        assert_eq!(*keychain.deleted.lock().unwrap(), Vec::<String>::new(), "nothing was deleted");
    }

    /// **A root that reads and does not hold what the vault seals refuses the
    /// repair, naming the label, and nothing is written** — not even the entry
    /// that could not be read. A store that disagrees with the vault is not one
    /// the vault may be written into.
    #[tokio::test]
    async fn a_root_that_reads_and_differs_from_the_vault_refuses_the_repair_naming_it_and_writes_nothing() {
        use kotton_sys::secret::SecretsStore as _;
        use repair::*;
        let temp = tempfile::tempdir().unwrap();
        let (runtime, keychain, _vault) = alice_with_roots_on_the_platform(temp.path()).await;
        let master = kotton_common::crypto::kdf_labels::master_secret_keychain_key("alice");
        let cek = kotton_common::crypto::kdf_labels::operational_cek("alice");
        keychain.inner.set_secret(&cek, &hex::encode([7u8; 32])).unwrap();
        keychain.corrupt.lock().unwrap().insert(master.clone());
        keychain.watching.store(true, std::sync::atomic::Ordering::SeqCst);

        let err = repair_roots_from_vault(&runtime, "alice", PASSPHRASE)
            .await
            .expect_err("a root that differs from the vault must refuse the repair");

        assert!(err.to_string().contains(&cek), "the refusal names the label: {err}");
        assert_eq!(*keychain.written.lock().unwrap(), Vec::<String>::new(), "nothing was written");
        assert_eq!(*keychain.deleted.lock().unwrap(), Vec::<String>::new(), "nothing was deleted");
        assert_eq!(
            keychain.inner.get_secret(&cek).unwrap(),
            Some(hex::encode([7u8; 32])),
            "the differing entry keeps its value"
        );
    }

    /// **A credential proved over a store that cannot read the master secret
    /// refuses, and restores nothing over it.** Taking the unreadable read for
    /// "absent" ran the vault restore, whose `store_operational_roots` writes all
    /// three root labels — a write under the label it could not read.
    #[tokio::test]
    async fn a_master_secret_the_store_cannot_read_is_not_restored_over() {
        use kotton_common::crypto::kdf_labels;
        use kotton_sys::secret::{SecretsError, SecretsResult, SecretsStore};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Mutex;

        const PASSPHRASE: &str = "canyon-orbit-velvet-fish-hospital";

        /// The master secret's read fails once `broken` is set; root writes
        /// after that are recorded.
        #[derive(Default)]
        struct MasterUnreadable {
            inner: kotton_secret::MemorySecrets,
            broken: AtomicBool,
            written: Mutex<Vec<String>>,
        }
        impl SecretsStore for MasterUnreadable {
            fn get_secret(&self, key: &str) -> SecretsResult<Option<String>> {
                if self.broken.load(Ordering::SeqCst) && key == kdf_labels::master_secret_keychain_key("alice") {
                    return Err(SecretsError::Storage("the keychain did not answer".into()));
                }
                self.inner.get_secret(key)
            }
            fn set_secret(&self, key: &str, value: &str) -> SecretsResult<()> {
                if self.broken.load(Ordering::SeqCst) {
                    self.written.lock().unwrap().push(key.to_string());
                }
                self.inner.set_secret(key, value)
            }
            fn delete_secret(&self, key: &str) -> SecretsResult<()> {
                self.inner.delete_secret(key)
            }
        }

        let temp = tempfile::tempdir().unwrap();
        let platform = Arc::new(MasterUnreadable::default());
        let runtime = DeviceRuntime::new_with_secrets(
            temp.path().to_path_buf(),
            kotton_device::config::RuntimeConfig::default(),
            platform.clone(),
        )
        .await
        .unwrap();
        runtime.create_user("alice", PASSPHRASE).await.unwrap();
        // Out of memory custody, so the read reaches the platform, and failing there.
        assert!(runtime.custody().lock_identity("alice"));
        platform.broken.store(true, Ordering::SeqCst);

        let refused = restore_roots_if_absent(&runtime, "alice", PASSPHRASE).await;
        let err = refused.expect_err("an unreadable master secret must refuse the restore");
        assert!(err.to_string().contains("the keychain did not answer"), "the read's error is named: {err}");
        assert_eq!(
            *platform.written.lock().unwrap(),
            Vec::<String>::new(),
            "a root was restored over a master secret the store could not read"
        );
    }

    /// **A copy that does not open under the credential refuses the restore.**
    /// The doors call this only after the record accepted the credential, so a
    /// copy sealed under another is the record and the copy disagreeing; an
    /// `Ok` here opened a session that restored no key.
    #[tokio::test]
    async fn a_copy_that_does_not_open_under_the_credential_refuses_the_restore() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = DeviceRuntime::new_with_secrets(
            temp.path().to_path_buf(),
            kotton_device::config::RuntimeConfig::default(),
            Arc::new(kotton_secret::MemorySecrets::default()),
        )
        .await
        .unwrap();
        runtime.create_user("alice", "canyon-orbit-velvet-fish-hospital").await.unwrap();
        assert!(runtime.custody().lock_identity("alice"), "her keys were held");

        let err = restore_roots_if_absent(&runtime, "alice", "lantern-quarry-meadow-socket-ribbon")
            .await
            .expect_err("a copy that does not open must refuse the restore");
        assert!(err.to_string().contains("does not open under it"), "and say so: {err}");
        let master = kotton_common::crypto::kdf_labels::master_secret_keychain_key("alice");
        assert_eq!(runtime.secrets().get_secret(&master).unwrap(), None, "nothing was restored");
    }

    #[test]
    fn zero_means_the_default_bound_and_minutes_are_honoured() {
        let mut policy = LockPolicy::default();
        assert_eq!(window_secs(&policy), DEFAULT_WINDOW_SECS);
        policy.auto_lock_minutes = 30;
        assert_eq!(window_secs(&policy), 30 * 60);
    }
}
