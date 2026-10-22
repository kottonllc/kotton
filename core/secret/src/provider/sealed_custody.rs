// SPDX-License-Identifier: AGPL-3.0-or-later
//! Custody split: the platform stores, Kotton decides (RFC-0053 step 4).
//!
//! Kotton's operational roots — `master_secret`, the identity key, the CEK —
//! were written to the OS keychain as lowercase hex. That is custody done by the
//! platform, which is the right division of labour and genuinely better than
//! Kotton rolling its own key storage. What was wrong is *what* it held:
//! anything able to read the keychain got material that opens the user's data.
//!
//! An OS keychain is keyed by the OS account, so it cannot separate two Kotton
//! identities inside one login — RFC-0053's governing constraint. If avery and
//! sam share a machine account, plaintext roots in the keychain hand each of
//! them the other's data, and no amount of Kotton-side checking changes that,
//! because the material is simply *there*.
//!
//! [`SealedCustody`] closes it by keeping unlocked roots **in this process's
//! memory and nowhere else**, while everything that is not a root continues
//! straight through to the platform store. Reads prefer memory, so nothing above
//! this layer changes: the runtime asks its `SecretsStore` for a key exactly as
//! before.
//!
//! ## What this does and does not promise
//!
//! It removes the *plaintext at rest*. It does not defend a device against code
//! already executing on it — an attacker inside the daemon's address space reads
//! the same memory the daemon does, and RFC-0053 says so plainly.
//!
//! It also does not make roots durable. Memory is lost on exit **by design**:
//! the durable copy is the vault sealed under the daily credential, so a
//! restart genuinely re-locks. That is only safe once such a vault exists, which
//! is why [`SealedCustody::adopt_root`] is called at the moment a credential is
//! set rather than unconditionally — see `user_cmds::set_user_pin`.
//!
//! ## Custody has an end that is not the process's
//!
//! Until 2026-09-12 daemon exit was the *only* thing that closed custody:
//! `lock_identity` had no production caller and `auto_lock_minutes` was stored
//! and enforced nowhere, so the daily credential opened the vault for as long
//! as the machine stayed up — while the session it minted expired in twelve
//! hours (`TASK-unlock-never-ends-and-nothing-reports-it`). Every identity held
//! here now carries a deadline, armed when its roots are adopted and re-armed
//! by a fresh credential, and every read applies it. There is no way to hold a
//! root without one and no way to read one past it — the same discipline
//! `kotton_session::service::tokens::live_user` applies to a session token.
//!
//! **Absolute, not sliding**, for the reason RFC-0066 gives for sessions: a
//! window that a read extends is a window an attacker holding the token keeps
//! open indefinitely. The deadline moves only when a credential is presented.
//! An idle timeout on top of it would be strictly additional.
//!
//! What closes here is what this process holds. A `UserStore` binds its keys at
//! load time, so the daemon must also rebuild that store when custody closes —
//! `kuserd::agent::custody_window` does, on the sweep — and a sidecar handed a
//! key at spawn is bounded by its process, as its token is.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use kotton_common::crypto::kdf_labels;
use kotton_common::time::now_secs;
use kotton_sys::secret::{SecretsError, SecretsResult, SecretsStore};

/// How long custody stays open after a credential opens it, when the person has
/// not set `auto_lock_minutes` (the "bounded, configurable window" of RFC-0066,
/// which says it is the user's to set — this is what it is until they do).
///
/// Twelve hours: **the same number as `SESSION_TTL_SECS`, and a different
/// clock.** A session starts when a token is minted; custody starts when a
/// credential opens the vault. Keeping the defaults equal means the two ends
/// arrive together in the common case — one passphrase reopens both — instead
/// of a live session meeting a closed vault, which is the state whose failures
/// are quietest (`mailbox.rs` and `vault_doors.rs` turn a custody error into
/// "nothing here"). They stay two values because they are two lifetimes.
pub const DEFAULT_WINDOW_SECS: i64 = 12 * 60 * 60;

/// One identity's unlocked roots, and when they stop being.
struct Held {
    /// label → hex. Never written anywhere.
    roots: HashMap<String, String>,
    /// Unix seconds after which this identity reads as locked and its roots
    /// are dropped on the way past.
    open_until: i64,
}

impl Held {
    fn live(&self, now: i64) -> bool {
        self.open_until > now
    }
}

/// A [`SecretsStore`] that holds operational roots in memory and delegates
/// everything else to the platform.
pub struct SealedCustody {
    /// Unlocked roots, **grouped by the identity that owns them**: user → label
    /// → hex. Never written anywhere.
    ///
    /// The grouping is RFC-0056 R4 — one identity's keys per compromise domain.
    /// A flat map was the first shape, and it made `lock_identity` impossible to
    /// express and cross-identity reads impossible to rule out by inspection:
    /// every lookup was a string comparison away from another person's data.
    /// Grouping does not create a memory boundary — that is the open question
    /// R4 leaves to a per-identity *process* — but it makes the boundary
    /// something the code states rather than something a reviewer has to
    /// reconstruct from label formats.
    ///
    /// The deadline lives in the same entry as the roots (`Held`), so an
    /// identity cannot be resident without one.
    unlocked: RwLock<HashMap<String, Held>>,
    /// The platform's own store — keychain, DPAPI, Secret Service.
    platform: Arc<dyn SecretsStore + Send + Sync>,
}

impl SealedCustody {
    /// Wrap `platform`, holding no roots yet.
    pub fn new(platform: Arc<dyn SecretsStore + Send + Sync>) -> Self {
        Self {
            unlocked: RwLock::new(HashMap::new()),
            platform,
        }
    }

    /// Take a root into memory **and remove the platform's plaintext copy**.
    ///
    /// The two halves are one operation on purpose. Holding the root in memory
    /// while leaving the keychain copy in place would be theatre — the material
    /// an attacker wants is still readable at rest — and deleting the platform
    /// copy without first holding the value would lose the key. Call this only
    /// once a durable sealed copy exists (the RFC-0039 vault), or a restart is
    /// data loss rather than a re-lock.
    ///
    /// Returns the number of platform copies actually removed, so a caller can
    /// report whether there was anything to purge.
    pub fn adopt_root(&self, label: &str) -> SecretsResult<bool> {
        let Some(owner) = kdf_labels::root_owner(label) else {
            return Err(SecretsError::Storage(format!(
                "{label} is not an operational root; refusing to move it into memory-only custody"
            )));
        };
        let existing = self.get_secret(label)?;
        let Some(value) = existing else {
            return Ok(false);
        };
        // Adoption opens the window if it is not already open. The default is
        // deliberately applied *here*, at the primitive, rather than left to the
        // caller: a caller that forgets to arm the window would reproduce the
        // defect this exists to close. A caller that knows the person's policy
        // narrows or re-arms it with [`SealedCustody::set_open_until`].
        self.evict_if_expired(owner, now_secs());
        self.unlocked
            .write()
            .unwrap()
            .entry(owner.to_string())
            .or_insert_with(|| Held {
                roots: HashMap::new(),
                open_until: now_secs() + DEFAULT_WINDOW_SECS,
            })
            .roots
            .insert(label.to_string(), value);
        // Best-effort: a platform store that never held it is not an error.
        let had_platform_copy = self.platform.get_secret(label)?.is_some();
        if had_platform_copy {
            self.platform.delete_secret(label)?;
        }
        Ok(had_platform_copy)
    }

    /// Drop one identity's roots, leaving every other identity untouched.
    ///
    /// The operation R4 exists for: on a machine two people share, avery locking
    /// their session must not disturb sam's, and — more importantly — must
    /// actually remove avery's keys rather than leaving them resident because
    /// someone else is still logged in.
    ///
    /// Returns whether anything was held.
    pub fn lock_identity(&self, user_id: &str) -> bool {
        self.unlocked.write().unwrap().remove(user_id).is_some()
    }

    /// Drop every unlocked root, re-locking this process.
    ///
    /// What daemon exit means implicitly. Roots that were adopted are
    /// recoverable only from the vault, with the daily credential.
    pub fn lock(&self) {
        self.unlocked.write().unwrap().clear();
    }

    /// Whether any root is currently held in memory, for any identity.
    pub fn is_unlocked(&self) -> bool {
        let now = now_secs();
        self.unlocked
            .read()
            .unwrap()
            .values()
            .any(|h| h.live(now) && !h.roots.is_empty())
    }

    /// Whether this identity's roots are held in memory.
    ///
    /// Scoped deliberately: "is the daemon unlocked" is not a question with a
    /// single answer once more than one person uses the machine.
    pub fn is_unlocked_for(&self, user_id: &str) -> bool {
        self.open_until(user_id).is_some()
    }

    /// When this identity's custody closes, if it is open now.
    ///
    /// The one readout of the window. `None` is *locked* — nothing held, or
    /// held past its deadline, in which case the roots are dropped here rather
    /// than reported as open for one more read.
    pub fn open_until(&self, user_id: &str) -> Option<i64> {
        self.evict_if_expired(user_id, now_secs());
        self.unlocked
            .read()
            .unwrap()
            .get(user_id)
            .filter(|h| !h.roots.is_empty())
            .map(|h| h.open_until)
    }

    /// Set when this identity's custody closes. The credential-aware caller's
    /// verb: a fresh unlock re-arms the window with the person's policy, and
    /// `set_open_until(now)` is `lock_identity` on the next read.
    ///
    /// Returns `false`, and sets nothing, for an identity holding no roots —
    /// a window is a property of something held, never a promise to hold it.
    pub fn set_open_until(&self, user_id: &str, until: i64) -> bool {
        match self.unlocked.write().unwrap().get_mut(user_id) {
            Some(held) => {
                held.open_until = until;
                true
            }
            None => false,
        }
    }

    /// Drop every identity whose window has closed by `now`, and name them.
    ///
    /// Reads already refuse an expired identity, so this changes no answer;
    /// it exists so the daemon can do the work that follows a close — rebuild
    /// the `UserStore` that bound the keys at load time — and log it, on a
    /// timer rather than on whichever request happens to arrive next.
    pub fn sweep_expired(&self, now: i64) -> Vec<String> {
        let mut g = self.unlocked.write().unwrap();
        let closed: Vec<String> = g
            .iter()
            .filter(|(_, h)| !h.live(now))
            .map(|(id, _)| id.clone())
            .collect();
        for id in &closed {
            g.remove(id);
        }
        closed
    }

    /// Drop this identity if its window has closed by `now`.
    ///
    /// Read-check first, so the common case — a live identity — never takes
    /// the write lock; re-checked under it, since another thread may have
    /// re-armed the window between the two acquisitions.
    fn evict_if_expired(&self, user_id: &str, now: i64) {
        {
            let g = self.unlocked.read().unwrap();
            match g.get(user_id) {
                Some(h) if !h.live(now) => {}
                _ => return,
            }
        }
        let mut g = self.unlocked.write().unwrap();
        if g.get(user_id).is_some_and(|h| !h.live(now)) {
            tracing::info!(user_id, "custody window closed; this identity's roots are dropped");
            g.remove(user_id);
        }
    }
}

impl SecretsStore for SealedCustody {
    /// Memory first, then the platform.
    ///
    /// The fallthrough is what keeps an install that predates RFC-0053 step 4
    /// working: its roots are still in the keychain, and it reads them from
    /// there until a daily credential exists to seal them under.
    fn get_secret(&self, key: &str) -> SecretsResult<Option<String>> {
        // Only ever looks inside the owning identity's set — a lookup cannot
        // reach across identities even if two of them somehow named the same
        // label, because the owner is derived from the label rather than
        // searched for.
        if let Some(owner) = kdf_labels::root_owner(key) {
            self.evict_if_expired(owner, now_secs());
            if let Some(held) = self
                .unlocked
                .read()
                .unwrap()
                .get(owner)
                .and_then(|held| held.roots.get(key))
            {
                return Ok(Some(held.clone()));
            }
        }
        self.platform.get_secret(key)
    }

    /// A root already in memory stays in memory; everything else is the
    /// platform's.
    ///
    /// Note the asymmetry: this does **not** divert every root to memory. Before
    /// a user has a daily credential the keychain is the only durable copy their
    /// data has, so writing a root there is correct — and `adopt_root` is the
    /// deliberate, credential-gated moment that stops being true.
    fn set_secret(&self, key: &str, value: &str) -> SecretsResult<()> {
        if let Some(owner) = kdf_labels::root_owner(key) {
            // An expired identity is not held: the value goes to the platform
            // as it would for a person who never unlocked, and the adoption
            // that follows every unlock takes it back out (`unlock_with_pin`).
            self.evict_if_expired(owner, now_secs());
            let mut unlocked = self.unlocked.write().unwrap();
            if let Some(held) = unlocked.get_mut(owner) {
                if held.roots.contains_key(key) {
                    held.roots.insert(key.to_string(), value.to_string());
                    return Ok(());
                }
            }
        }
        self.platform.set_secret(key, value)
    }

    /// Delete from both, so a logout cannot leave a copy in either place.
    fn delete_secret(&self, key: &str) -> SecretsResult<()> {
        if let Some(owner) = kdf_labels::root_owner(key) {
            let mut unlocked = self.unlocked.write().unwrap();
            if let Some(held) = unlocked.get_mut(owner) {
                held.roots.remove(key);
                // Don't leave an empty set behind, or `is_unlocked_for` and the
                // identity list would report a person as present with no keys.
                if held.roots.is_empty() {
                    unlocked.remove(owner);
                }
            }
        }
        self.platform.delete_secret(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemorySecrets;

    fn custody() -> (Arc<dyn SecretsStore + Send + Sync>, SealedCustody) {
        let platform: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
        let custody = SealedCustody::new(Arc::clone(&platform));
        (platform, custody)
    }

    /// The point of the whole file: after adoption the platform holds nothing,
    /// and the value is still readable through the store.
    #[test]
    fn adopting_a_root_removes_the_platform_plaintext() {
        let (platform, custody) = custody();
        let label = kdf_labels::master_secret_keychain_key("avery");
        custody.set_secret(&label, "aa".repeat(32).as_str()).unwrap();
        assert!(
            platform.get_secret(&label).unwrap().is_some(),
            "precondition: it starts in the platform store"
        );

        assert!(custody.adopt_root(&label).unwrap());

        assert_eq!(
            platform.get_secret(&label).unwrap(),
            None,
            "the platform must hold no plaintext root after adoption"
        );
        assert_eq!(
            custody.get_secret(&label).unwrap(),
            Some("aa".repeat(32)),
            "and the daemon must still be able to use it"
        );
    }

    /// Non-roots must keep flowing to the platform: the daemon needs some of
    /// them (a CEK epoch, a device fingerprint) before anyone has unlocked, so
    /// over-classifying would break cold start rather than harden it.
    #[test]
    fn non_roots_are_left_with_the_platform() {
        let (platform, custody) = custody();
        let label = kdf_labels::operational_cek_epoch("avery");
        custody.set_secret(&label, "7").unwrap();
        assert_eq!(platform.get_secret(&label).unwrap(), Some("7".into()));
        assert!(custody.adopt_root(&label).is_err(), "not a root");
    }

    /// An install that predates this layer keeps working: its roots are in the
    /// keychain and read straight through until a credential exists.
    #[test]
    fn a_root_still_in_the_platform_reads_through() {
        let (platform, custody) = custody();
        let label = kdf_labels::operational_cek("avery");
        platform.set_secret(&label, "bb".repeat(32).as_str()).unwrap();
        assert_eq!(custody.get_secret(&label).unwrap(), Some("bb".repeat(32)));
        assert!(!custody.is_unlocked(), "reading through is not being unlocked");
    }

    /// Once adopted, a root never leaks back to the platform on rewrite — a CEK
    /// rotation must not undo the adoption.
    #[test]
    fn rewriting_an_adopted_root_stays_in_memory() {
        let (platform, custody) = custody();
        let label = kdf_labels::operational_cek("avery");
        custody.set_secret(&label, "cc".repeat(32).as_str()).unwrap();
        custody.adopt_root(&label).unwrap();

        custody.set_secret(&label, "dd".repeat(32).as_str()).unwrap();

        assert_eq!(custody.get_secret(&label).unwrap(), Some("dd".repeat(32)));
        assert_eq!(
            platform.get_secret(&label).unwrap(),
            None,
            "a rotation must not write the new root back to the keychain"
        );
    }

    // ── RFC-0056 R4: one identity's keys per compromise domain ──────────────

    /// Adopt a root for `user` and return its label.
    fn adopt_for(custody: &SealedCustody, user: &str, byte: &str) -> String {
        let label = kdf_labels::master_secret_keychain_key(user);
        custody.set_secret(&label, byte.repeat(32).as_str()).unwrap();
        custody.adopt_root(&label).unwrap();
        label
    }

    /// The invariant: unlocking one identity gives the process nothing of the
    /// other's. This is the household case RFC-0053 is written for — avery and
    /// sam on one machine — and the reason it needed stating is that a flat map
    /// satisfies it only by nobody having written the wrong lookup yet.
    #[test]
    fn one_identity_unlocked_holds_nothing_of_anothers() {
        let (_platform, custody) = custody();
        let avery = adopt_for(&custody, "avery", "aa");

        assert!(custody.is_unlocked_for("avery"));
        assert!(
            !custody.is_unlocked_for("sam"),
            "sam has not unlocked and must be absent"
        );
        assert_eq!(
            custody
                .get_secret(&kdf_labels::master_secret_keychain_key("sam"))
                .unwrap(),
            None,
            "avery's unlock must not produce anything for sam"
        );
        assert_eq!(custody.get_secret(&avery).unwrap(), Some("aa".repeat(32)));
    }

    /// Locking one identity must be exactly that — not a no-op because someone
    /// else is still logged in, and not a lock-out of the other person.
    #[test]
    fn locking_one_identity_leaves_the_other_working() {
        let (_platform, custody) = custody();
        let avery = adopt_for(&custody, "avery", "aa");
        let sam = adopt_for(&custody, "sam", "bb");

        assert!(custody.lock_identity("avery"));

        assert!(!custody.is_unlocked_for("avery"));
        assert_eq!(
            custody.get_secret(&avery).unwrap(),
            None,
            "avery's roots must actually be gone, not merely unreachable"
        );
        assert!(custody.is_unlocked_for("sam"));
        assert_eq!(custody.get_secret(&sam).unwrap(), Some("bb".repeat(32)));
    }

    /// Two identities' roots are distinct values under distinct labels, so a
    /// lookup cannot return one for the other even though both are `Full`.
    #[test]
    fn identities_do_not_share_a_root_slot() {
        let (_platform, custody) = custody();
        let avery = adopt_for(&custody, "avery", "aa");
        let sam = adopt_for(&custody, "sam", "bb");

        assert_ne!(avery, sam);
        assert_eq!(custody.get_secret(&avery).unwrap(), Some("aa".repeat(32)));
        assert_eq!(custody.get_secret(&sam).unwrap(), Some("bb".repeat(32)));
    }

    /// Locking an identity that holds nothing is not an error, and does not
    /// disturb anyone — `kotton lock` on an already-locked identity is routine.
    #[test]
    fn locking_an_absent_identity_is_harmless() {
        let (_platform, custody) = custody();
        let sam = adopt_for(&custody, "sam", "bb");

        assert!(!custody.lock_identity("avery"));
        assert_eq!(custody.get_secret(&sam).unwrap(), Some("bb".repeat(32)));
    }

    /// Deleting the last root of an identity must not leave the person present
    /// with an empty set, or `is_unlocked_for` would say they are unlocked
    /// while holding nothing.
    #[test]
    fn removing_the_last_root_removes_the_identity() {
        let (_platform, custody) = custody();
        let avery = adopt_for(&custody, "avery", "aa");

        custody.delete_secret(&avery).unwrap();

        assert!(!custody.is_unlocked_for("avery"));
        assert!(!custody.is_unlocked());
    }

    /// Locking drops the roots, which is what a daemon restart does implicitly.
    #[test]
    fn locking_drops_adopted_roots() {
        let (_platform, custody) = custody();
        let label = kdf_labels::identity_signing_key("avery");
        custody.set_secret(&label, "ee".repeat(32).as_str()).unwrap();
        custody.adopt_root(&label).unwrap();
        assert!(custody.is_unlocked());

        custody.lock();

        assert!(!custody.is_unlocked());
        assert_eq!(
            custody.get_secret(&label).unwrap(),
            None,
            "after locking, the root is recoverable only from the sealed vault"
        );
    }

    /// Adopting something absent is not an error — it reports that there was
    /// nothing to purge, so a caller can say so honestly.
    #[test]
    fn adopting_an_absent_root_reports_nothing_purged() {
        let (_platform, custody) = custody();
        let label = kdf_labels::master_secret_keychain_key("nobody");
        assert!(!custody.adopt_root(&label).unwrap());
    }

    /// Logout must not leave a copy behind in either place.
    #[test]
    fn deleting_clears_both_layers() {
        let (platform, custody) = custody();
        let label = kdf_labels::master_secret_keychain_key("avery");
        custody.set_secret(&label, "ff".repeat(32).as_str()).unwrap();
        custody.adopt_root(&label).unwrap();
        // Put a stray platform copy back to prove delete reaches both.
        platform.set_secret(&label, "ff".repeat(32).as_str()).unwrap();

        custody.delete_secret(&label).unwrap();

        assert_eq!(custody.get_secret(&label).unwrap(), None);
        assert_eq!(platform.get_secret(&label).unwrap(), None);
    }

    // ── The window (TASK-unlock-never-ends-and-nothing-reports-it) ──────────

    /// Adoption is what opens custody, so adoption is what arms the deadline.
    /// A root in memory with no end was the defect; this is the invariant.
    #[test]
    fn adopting_a_root_arms_a_deadline() {
        let (_platform, custody) = custody();
        let before = now_secs();
        adopt_for(&custody, "avery", "aa");

        let until = custody.open_until("avery").expect("open");
        assert!(
            until >= before + DEFAULT_WINDOW_SECS && until <= now_secs() + DEFAULT_WINDOW_SECS,
            "the default window is armed from the moment of adoption"
        );
        assert_eq!(custody.open_until("sam"), None, "nothing held, nothing open");
    }

    /// The headline: past its deadline an identity reads as locked, its roots
    /// are gone from memory, and — the half that would be theatre without it —
    /// nothing has fallen back to the platform store.
    #[test]
    fn an_expired_identity_reads_as_locked_and_holds_nothing() {
        let (platform, custody) = custody();
        let avery = adopt_for(&custody, "avery", "aa");
        let sam = adopt_for(&custody, "sam", "bb");

        assert!(custody.set_open_until("avery", now_secs() - 1));

        assert!(!custody.is_unlocked_for("avery"));
        assert_eq!(custody.open_until("avery"), None);
        assert_eq!(custody.get_secret(&avery).unwrap(), None, "the root is not readable");
        assert_eq!(platform.get_secret(&avery).unwrap(), None, "and not in the keychain");
        assert!(custody.is_unlocked_for("sam"), "one person's window closing is not the other's");
        assert_eq!(custody.get_secret(&sam).unwrap(), Some("bb".repeat(32)));
    }

    /// A fresh credential re-arms the window; using the roots does not. This
    /// is the absolute-not-sliding rule, and it is the difference between a
    /// bound and a bound an attacker holding the token can keep pushing out.
    #[test]
    fn reads_do_not_extend_the_window_and_a_credential_does() {
        let (_platform, custody) = custody();
        let avery = adopt_for(&custody, "avery", "aa");
        let soon = now_secs() + 30;
        assert!(custody.set_open_until("avery", soon));

        for _ in 0..3 {
            custody.get_secret(&avery).unwrap();
        }
        assert_eq!(custody.open_until("avery"), Some(soon), "reading moved nothing");

        // Adopting again — what every unlock does — keeps the existing window;
        // only an explicit re-arm changes it.
        custody.set_secret(&avery, "aa".repeat(32).as_str()).unwrap();
        custody.adopt_root(&avery).unwrap();
        assert_eq!(custody.open_until("avery"), Some(soon));

        let later = now_secs() + 600;
        assert!(custody.set_open_until("avery", later));
        assert_eq!(custody.open_until("avery"), Some(later));

        assert!(
            !custody.set_open_until("nobody", later),
            "a window is a property of something held"
        );
    }

    /// The sweep names what it closed and leaves the live alone, so the daemon
    /// can rebuild exactly the stores whose keys just went away.
    #[test]
    fn the_sweep_names_the_identities_it_closed() {
        let (_platform, custody) = custody();
        adopt_for(&custody, "avery", "aa");
        adopt_for(&custody, "sam", "bb");
        let now = now_secs();
        assert!(custody.set_open_until("avery", now - 1));

        let closed = custody.sweep_expired(now);

        assert_eq!(closed, vec!["avery".to_string()]);
        assert!(!custody.is_unlocked_for("avery"));
        assert!(custody.is_unlocked_for("sam"));
        assert!(custody.sweep_expired(now).is_empty(), "nothing left to close");
    }

    /// Once expired, a root written through the store lands with the platform,
    /// as it would for someone who never unlocked — and the adoption that
    /// follows every unlock takes it back into memory under a fresh window.
    #[test]
    fn an_expired_identity_is_reopened_by_the_unlock_path() {
        let (platform, custody) = custody();
        let avery = adopt_for(&custody, "avery", "aa");
        assert!(custody.set_open_until("avery", now_secs() - 1));

        // `unlock_with_pin`: store the restored roots, then adopt them.
        custody.set_secret(&avery, "aa".repeat(32).as_str()).unwrap();
        assert!(
            platform.get_secret(&avery).unwrap().is_some(),
            "an expired identity is not held, so the write went to the platform"
        );
        assert!(custody.adopt_root(&avery).unwrap());

        assert!(custody.is_unlocked_for("avery"));
        assert_eq!(platform.get_secret(&avery).unwrap(), None);
        assert!(custody.open_until("avery").unwrap() > now_secs());
    }
}
