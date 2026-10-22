// SPDX-License-Identifier: AGPL-3.0-or-later
//! Opening a user's record store, and deriving the key it is encrypted under.
//!
//! This is the *how*, not the *when*. Which stores are open right now is
//! residency — the daemon's bookkeeping of lifetimes it owns, beside its map of
//! resident users. What it means to open one is this domain's, and it lived on
//! `DeviceRuntime` until 2026-08-21 (RFC-0080) only because that is where the
//! cache happened to sit.
//!
//! The separation matters beyond tidiness: a cache of open per-user stores is a
//! path to user data, and `core/device` — where `DeviceRuntime` is going —
//! states that nothing in it may reach any. Splitting the opener from the cache
//! is what lets the machine keep that promise.

use anyhow::{Context, Result};
use kotton_common::crypto::kdf_labels;
use kotton_crypto::{derive_db_key, derive_master_secret};
use kotton_sys::secret::SecretsStore;
use std::path::Path;

use crate::provider::sqlite_record_store::SqliteRecordStore;

/// Open `users/<user_id>/records.db`, encrypted under this user's derived key.
///
/// ## The key
///
/// Prefers the random operational `master_secret` (RFC-0039) and falls back to
/// the legacy `seed32`-derived master for accounts created before that cutover.
///
/// ## No key is a refusal, never a plaintext store
///
/// If neither secret resolves, this returns [`LOCKED`] rather than opening an
/// unencrypted database. A user's records are encrypted or they do not open.
///
/// This used to return an unencrypted store, justified as *"what a development
/// environment looks like after `just reset`"* and as *"not a silent downgrade
/// for an account that has keys, because if a secret is present a key is derived
/// from it."* That second clause was the load-bearing one and it stopped being
/// true: a **locked** account has keys that are deliberately not resolvable, so
/// the fallback read an existing encrypted file as plaintext SQLite and cached
/// the result. `DEC-0049` rules it out; the justification cost nothing to remove,
/// because no test in the workspace depended on it.
/// Marker in the error returned when no key resolves.
///
/// A string rather than a variant because `user_record_store` is `anyhow`-typed
/// at every call site today. Callers that must *act* on locked — the daemon,
/// which should prompt for an unlock rather than report a failure — need a real
/// variant, and `DEC-0049` names that as the follow-up rather than pretending a
/// substring match is an interface.
pub const LOCKED: &str = "account is locked";

/// The locked state as a **type**, so a caller can act on it instead of matching a substring.
///
/// `DEC-0049` deferred this and named who would need it: *"a daemon that wants to prompt for
/// an unlock rather than report a failure needs a real variant"*. That daemon is here —
/// `DEC-0077` rules that the window owns onboarding, and a returning person whose account is
/// locked must be able to unlock from the window rather than be told nothing at all.
///
/// The distinction this exists to carry is **recoverable versus not**. A locked account has
/// a remedy the person can perform: type their credential. A database that is missing, or
/// that will not open, does not — and a surface that offered a credential prompt for all
/// three would be lying about two of them.
///
/// [`Display`] is unchanged from the string it replaces, so anything reading the message —
/// a log, a test, a person — sees exactly what it saw before.
///
/// [`Display`]: std::fmt::Display
#[derive(Debug, Clone)]
pub struct Locked {
    /// Whose account.
    pub user_id: String,
    /// Which file could not be opened, for the reader: `records.db`, `agent.db`.
    pub what: &'static str,
    /// Why no key resolved — both are a remedy the person can perform.
    pub by: LockedBy,
}

/// Why a locked account's key did not resolve. Both draw the unlock screen —
/// the distinction [`Locked`] exists to carry against a database that will not
/// open — and they differ in what the person is told. `NoKey` is recoverable by
/// a credential. `UnreadableStore` is recoverable only when the failure is
/// transient (a locked keychain); a permanent failure of one entry — a keyring
/// `BadEncoding`, a tampered entry — is refused at every door, a plain unlock
/// included, and is repaired only by the owner's repair verb: `UnlockWithPin`
/// with `repair` (`kotton id unlock <name> --repair`), which writes from the
/// vault only an entry that could not be read or is absent, and refuses when one
/// that read differs from the vault (`kotton_identity::provisioning::repair_roots_from_vault`,
/// `TASK-a-keychain-entry-that-fails-permanently-has-no-repair-verb-and-lockedby-says-it-is-recoverable`).
/// The lock screen does not offer it yet
/// (`TASK-the-lock-screen-cannot-offer-the-repair-a-failing-keychain-entry-needs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockedBy {
    /// The secrets store answered that it holds no key: the account's roots are
    /// in its vault, and a credential restores them (`DEC-0049`).
    NoKey,
    /// The secrets store could not be read — a locked keychain, which a
    /// credential or a moment later may answer, or an entry that fails every
    /// read, which neither does. Nothing here says the key is gone, and nothing
    /// was made in its place
    /// (`TASK-a-key-the-store-cannot-read-is-taken-for-no-key-and-a-new-one-is-minted`).
    /// Carries the store's message, which names a label and never a value.
    UnreadableStore(String),
}

impl std::fmt::Display for Locked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.by {
            LockedBy::NoKey => write!(f, "{LOCKED}: no key for '{}' ({})", self.user_id, self.what),
            LockedBy::UnreadableStore(e) => write!(
                f,
                "{LOCKED}: the keychain could not be read for '{}' ({}): {e}",
                self.user_id, self.what
            ),
        }
    }
}

impl std::error::Error for Locked {}

impl Locked {
    /// Whether `e` is a locked account, through any wrapping this error crosses.
    ///
    /// An `io::Error` from `user_agent_db`, an `anyhow::Error` from `user_record_store`, or
    /// either of those already boxed — the answer must not depend on which layer asked.
    pub fn in_error<'a>(e: &'a (dyn std::error::Error + 'static)) -> Option<&'a Locked> {
        let mut cur = Some(e);
        while let Some(err) = cur {
            if let Some(l) = err.downcast_ref::<Locked>() {
                return Some(l);
            }
            if let Some(io) = err.downcast_ref::<std::io::Error>() {
                if let Some(inner) = io.get_ref() {
                    if let Some(l) = inner.downcast_ref::<Locked>() {
                        return Some(l);
                    }
                }
            }
            cur = err.source();
        }
        None
    }
}

pub fn user_record_store(
    base_dir: &Path,
    user_id: &str,
    secrets: &dyn SecretsStore,
) -> Result<SqliteRecordStore> {
    let path = base_dir.join("users").join(user_id).join("records.db");

    fn decode32(h: String) -> Option<[u8; 32]> {
        hex::decode(h).ok().and_then(|b| b.try_into().ok())
    }

    // A store that could not be read is never the `seed32` fallback: an
    // unreadable `master_secret` taken for absent keyed — on a first open,
    // created — `records.db` under a key derived from another root
    // (`TASK-a-key-the-store-cannot-read-is-taken-for-no-key-and-a-new-one-is-minted`).
    // It is `Locked` by an unreadable store: transient, so the window offers the
    // unlock, and distinct from a database that will not open, which it does not.
    let read = |label: String| {
        secrets.get_secret(&label).map_err(|e| {
            anyhow::Error::new(Locked {
                user_id: user_id.to_string(),
                what: "records.db",
                by: LockedBy::UnreadableStore(format!("could not read {label} from the secrets store: {e}")),
            })
        })
    };
    let master: Option<[u8; 32]> = match read(kdf_labels::master_secret_keychain_key(user_id))?.and_then(decode32) {
        Some(master) => Some(master),
        None => read(kdf_labels::seed32_keychain_key(user_id))?
            .and_then(decode32)
            .map(|seed32| derive_master_secret(&seed32)),
    };

    let db_key = master
        .map(|m| derive_db_key(&m, &kdf_labels::user_records_db(user_id)))
        .ok_or_else(|| {
            anyhow::Error::new(Locked {
                user_id: user_id.to_string(),
                what: "records.db",
                by: LockedBy::NoKey,
            })
        })?;

    SqliteRecordStore::open(&path, Some(&db_key))
        .with_context(|| format!("failed to open record store for user '{user_id}'"))
}

#[cfg(test)]
mod locked_tests {
    use super::Locked;

    fn locked() -> Locked {
        Locked { user_id: "austin".into(), what: "agent.db", by: super::LockedBy::NoKey }
    }

    /// The message a person reads is the one it replaced, exactly.
    ///
    /// `LOCKED` was a string marker and things match on it — logs, a reader, and the
    /// substring check any caller not yet converted still performs. Typing it must not
    /// change a character of what it renders.
    #[test]
    fn it_reads_the_same_as_the_string_it_replaced() {
        assert_eq!(
            locked().to_string(),
            "account is locked: no key for 'austin' (agent.db)"
        );
        assert!(locked().to_string().starts_with(super::LOCKED));
    }

    /// Found through every wrapping it crosses on the way to the compositor.
    ///
    /// `user_agent_db` returns `io::Error::other(Locked)`, `user_record_store` returns it
    /// through `anyhow`, and the compositor sees whichever its caller produced. A lookup
    /// that only worked for one of them would fail exactly where the person is locked out
    /// and silent about it — which is the defect this type exists to end.
    #[test]
    fn it_is_found_through_io_and_anyhow() {
        let io_wrapped = std::io::Error::other(locked());
        assert_eq!(Locked::in_error(&io_wrapped).unwrap().user_id, "austin");

        let anyhow_wrapped = anyhow::Error::new(locked());
        assert_eq!(
            Locked::in_error(anyhow_wrapped.as_ref()).unwrap().what,
            "agent.db"
        );

        // …and an unrelated failure is not a lock, so nothing offers a credential for it.
        let other = std::io::Error::other("the database file is corrupt");
        assert!(Locked::in_error(&other).is_none());
    }
}

/// `user_record_store` over a store that cannot read the master secret
/// (`TASK-a-key-the-store-cannot-read-is-taken-for-no-key-and-a-new-one-is-minted`).
#[cfg(test)]
mod unreadable_tests {
    use super::*;
    use kotton_sys::secret::{SecretsError, SecretsResult};
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Holds a legacy `seed32`; the master secret's read fails.
    struct MasterUnreadable(Mutex<HashMap<String, String>>);
    impl SecretsStore for MasterUnreadable {
        fn get_secret(&self, key: &str) -> SecretsResult<Option<String>> {
            if key == kdf_labels::master_secret_keychain_key("u") {
                return Err(SecretsError::Storage("the keychain did not answer".into()));
            }
            Ok(self.0.lock().unwrap().get(key).cloned())
        }
        fn set_secret(&self, key: &str, value: &str) -> SecretsResult<()> {
            self.0.lock().unwrap().insert(key.into(), value.into());
            Ok(())
        }
        fn delete_secret(&self, key: &str) -> SecretsResult<()> {
            self.0.lock().unwrap().remove(key);
            Ok(())
        }
    }

    /// **A master secret the store cannot read refuses the open, never keys
    /// `records.db` with the `seed32` derivation.** Taken for absent, the read
    /// fell through to the legacy fallback and opened — or, on a first open,
    /// created — the store under a key derived from another root.
    #[test]
    fn an_unreadable_master_secret_refuses_the_open_and_creates_nothing() {
        let base = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(base.path().join("users/u")).unwrap();
        let secrets = MasterUnreadable(Mutex::new(HashMap::new()));
        secrets.set_secret(&kdf_labels::seed32_keychain_key("u"), &hex::encode([7u8; 32])).unwrap();
        let err = match user_record_store(base.path(), "u", &secrets) {
            Ok(_) => panic!("an unreadable master secret must refuse the open"),
            Err(e) => format!("{e:#}"),
        };
        assert!(err.contains("the keychain did not answer"), "the read's error is named: {err}");
        assert!(!base.path().join("users/u/records.db").exists(), "no records.db was made");
        let e = user_record_store(base.path(), "u", &secrets).err().unwrap();
        let locked = Locked::in_error(e.as_ref()).expect("an unreadable store is Locked: the window offers the unlock");
        assert!(matches!(locked.by, LockedBy::UnreadableStore(_)), "{locked:?}");
    }
}
