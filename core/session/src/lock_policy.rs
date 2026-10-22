// SPDX-License-Identifier: AGPL-3.0-or-later
//! Per-user lock policy — stores/verifies PIN and lock mode.
//!
//! File: `<base>/device/users/<user_id>/auth.json`
//!
//! ```json
//! {
//!   "mode": "pin",
//!   "pin_hash": "...",
//!   "pin_params": { "salt": "<hex>" },
//!   "auto_lock_minutes": 0,
//!   "failed_attempts": 0,
//!   "last_failed_at": null
//! }
//! ```
//!
//! The PIN is hashed with Argon2id using the constants from
//! `kotton_common::crypto::pin`.  The hash and salt are stored in
//! `auth.json`; the plaintext PIN is never written to disk.
//!
//! ## What the attempt counter is, and is not
//!
//! Consecutive failures impose a doubling cooldown during which the PIN is not
//! checked at all. That is an **online** brake: it bounds guessing by a party
//! who has to ask this daemon.
//!
//! It is **not** what makes a short PIN safe, and nothing here should be read as
//! claiming otherwise (RFC-0053, "Residual risks"). An attacker holding the disk
//! edits `failed_attempts` back to zero, and an attacker who copies `vault.json`
//! guesses offline and never sends this daemon a single request. Only a counter
//! inside a TPM or an enclave — one the attacker cannot reach — converts a short
//! PIN into something defensible. This brake is worth having because it is the
//! difference between a wrong PIN costing an adversary at the keyboard nothing
//! and costing them an escalating wait; it is not a substitute for that.

use crate::service::tokens as sessions;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Params, Version,
};
use kotton_wire::ipc::LockMode;
use kotton_crypto::daily_credential;
use kotton_sys::secret::AttemptLimiting;
use kotton_common::crypto::pin as PIN;
use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};

// ── Stored record ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockPolicy {
    pub mode: LockMode,
    /// Argon2id PHC string (`$argon2id$...`).  `None` when `mode == None`.
    pub pin_hash: Option<String>,
    pub auto_lock_minutes: u32,
    /// Consecutive failed unlock attempts since last success.
    #[serde(default)]
    pub failed_attempts: u8,
    /// Unix seconds of the most recent failed attempt; `None` when there has
    /// been no failure since the last success.
    ///
    /// `#[serde(default)]` so an `auth.json` written before the cooldown existed
    /// reads as `None`. That is deliberately forgiving: a user who already had
    /// five recorded failures is not locked out by the upgrade itself, and the
    /// very next failure stamps the clock and starts the brake.
    #[serde(default)]
    pub last_failed_at: Option<i64>,
}

impl Default for LockPolicy {
    fn default() -> Self {
        Self {
            mode: LockMode::None,
            pin_hash: None,
            auto_lock_minutes: 0,
            failed_attempts: 0,
            last_failed_at: None,
        }
    }
}

/// The outcome of a PIN unlock attempt.
///
/// Three states rather than a `Result<String, u8>`, because "refused without
/// being checked" is not a wrong PIN and a client that conflates them tells the
/// user to try again when trying again is exactly what will not work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinAttempt {
    /// The PIN verified; the daemon minted this session token.
    Unlocked(String),
    /// The PIN was wrong. Always at least one attempt remains — the failure that
    /// exhausts the budget reports [`PinAttempt::RateLimited`] instead, so the
    /// user is told the wait rather than a zero they cannot act on.
    Wrong { attempts_remaining: u8 },
    /// The attempt budget is spent. The PIN was **not verified**; no Argon2id
    /// work was done and a correct PIN would have been refused just the same.
    RateLimited { retry_after_secs: u64 },
}

// ── Path helper ───────────────────────────────────────────────────────────────

fn policy_path(base: &Path, user_id: &str) -> PathBuf {
    base.join("device")
        .join("users")
        .join(user_id)
        .join("auth.json")
}

// ── Load / save ───────────────────────────────────────────────────────────────

pub fn load(base: &Path, user_id: &str) -> io::Result<LockPolicy> {
    let path = policy_path(base, user_id);
    if !path.exists() {
        return Ok(LockPolicy::default());
    }
    let raw = std::fs::read_to_string(&path)?;
    serde_json::from_str(&raw).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn save(base: &Path, user_id: &str, policy: &LockPolicy) -> io::Result<()> {
    let path = policy_path(base, user_id);
    if let Some(parent) = path.parent() {
        kotton_common::fs::create_dir_all_owner_only(parent)?;
    }
    let json = serde_json::to_string_pretty(policy).map_err(|e| io::Error::other(e.to_string()))?;
    write_replacing(&path, json.as_bytes())
}

/// Replace `path` with `bytes` through a temporary file beside it and a rename,
/// the way the sealed copy is written (`provisioning::write_replacing`).
///
/// The record is the hash an unlock checks. A plain `write` truncates it first,
/// so a write that fails part-way leaves no passphrase readable at all; after
/// this a reader sees the old record or the new one. The temporary file is
/// removed on any failure.
fn write_replacing(path: &Path, bytes: &[u8]) -> io::Result<()> {
    // Same directory as the target: `rename` is only atomic within a filesystem.
    let tmp = path.with_extension("json.tmp");
    let written = (|| {
        use std::io::Write as _;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

// ── Argon2id helpers ──────────────────────────────────────────────────────────

fn argon2() -> io::Result<Argon2<'static>> {
    let params = Params::new(
        PIN::ARGON2_M_COST,
        PIN::ARGON2_T_COST,
        PIN::ARGON2_P_COST,
        Some(PIN::ARGON2_OUTPUT_LEN),
    )
    .map_err(|e| io::Error::other(e.to_string()))?;
    Ok(Argon2::new(
        argon2::Algorithm::Argon2id,
        Version::V0x13,
        params,
    ))
}

fn hash_pin(pin: &str) -> io::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    argon2()?
        .hash_password(pin.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| io::Error::other(e.to_string()))
}

fn verify_pin(pin: &str, hash: &str) -> io::Result<bool> {
    use argon2::password_hash::PasswordHash;
    let parsed = PasswordHash::new(hash).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(argon2()?.verify_password(pin.as_bytes(), &parsed).is_ok())
}

// ── Public API ─────────────────────────────────────────────────────────────────

/// The entropy this device requires of a daily credential (RFC-0053 step 3).
///
/// Re-exported, not reimplemented: it lives beside `assess`, which is the only
/// function it is ever passed to. Kept named here because [`prepare_policy`]
/// below is its main caller and a reader of this module should not have to know
/// where it moved.
pub use kotton_crypto::daily_credential::required_entropy_bits;

/// A lock policy judged and hashed, not yet on disk.
///
/// The credential on record and the copy of the keys sealed under it are two
/// writes. Every refusal the credential can meet — missing, too weak — is met
/// here, before either; [`record`](Self::record) is the last write, made once
/// the seal it names exists. A seal that fails therefore leaves the record as
/// it was, and no passphrase is set that opens nothing.
#[derive(Debug)]
pub struct PreparedPolicy(LockPolicy);

/// Judge and hash a new lock policy without writing it.
///
/// There is no call that judges and records in one step: a credential is
/// recorded only by [`PreparedPolicy::record`], which a caller that seals the
/// person's keys under it makes once the seal is written.
///
/// A new credential must clear [`required_entropy_bits`]. `LockMode::Pin` can no
/// longer be *set* while that bar is the unlimited-guessing one — a short PIN is
/// exactly what it excludes — but a PIN already on disk keeps working; see
/// [`LockMode::Pin`].
pub fn prepare_policy(
    mode: LockMode,
    auto_lock_minutes: u32,
    pin: Option<&str>,
    limiting: AttemptLimiting,
) -> io::Result<PreparedPolicy> {
    let pin_hash = match mode {
        LockMode::Pin | LockMode::Passphrase => {
            let candidate = pin
                .ok_or_else(|| io::Error::other("a credential is required for this lock mode"))?;
            // One bar for both modes, chosen by what limits guessing on *this
            // user's* vault: `limiting` is what their hardware binding answers
            // (`attempt_limiting_for`), and `None` where nothing is bound. `Pin`
            // is not rejected for *being* a PIN — it is rejected for being too
            // weak to stand alone, and where a TPM with an auth policy counts
            // the guesses, six digits are not.
            daily_credential::assess(candidate, daily_credential::required_entropy_bits_for(limiting))
                .map_err(|weak| io::Error::other(weak.to_string()))?;
            Some(hash_pin(candidate)?)
        }
        LockMode::None => None,
    };
    Ok(PreparedPolicy(LockPolicy {
        mode,
        pin_hash,
        auto_lock_minutes,
        failed_attempts: 0,
        last_failed_at: None,
    }))
}

impl PreparedPolicy {
    /// Write the policy as `user_id`'s, replacing the one on record.
    pub fn record(self, base: &Path, user_id: &str) -> io::Result<()> {
        save(base, user_id, &self.0)
    }
}

/// Forget the credential on record, keeping the person's auto-lock setting.
/// Returns whether one was set; with no policy on disk, nothing is written.
///
/// For a recovery, which removes the copy of the keys sealed under that
/// credential before it seals them under a new one: should the new seal fail,
/// the old credential seals nothing on this device, and an unlock with it is
/// refused rather than admitted to a session that restores nothing. The next
/// one is recorded by [`PreparedPolicy::record`], once it seals something.
pub fn forget_credential(base: &Path, user_id: &str) -> io::Result<bool> {
    if !policy_path(base, user_id).exists() {
        return Ok(false);
    }
    let policy = load(base, user_id)?;
    let had = policy.pin_hash.is_some();
    save(
        base,
        user_id,
        &LockPolicy {
            mode: LockMode::None,
            pin_hash: None,
            auto_lock_minutes: policy.auto_lock_minutes,
            failed_attempts: 0,
            last_failed_at: None,
        },
    )?;
    Ok(had)
}

// ── Attempt budget ────────────────────────────────────────────────────────────

/// How long a cooldown `failed_attempts` consecutive failures earn, in seconds.
///
/// Zero below [`PIN::MAX_ATTEMPTS`]; from there it doubles per further failure,
/// capped at [`PIN::MAX_COOLDOWN_SECS`].
fn cooldown_for(failed_attempts: u8) -> u64 {
    let Some(over) = failed_attempts.checked_sub(PIN::MAX_ATTEMPTS) else {
        return 0;
    };
    PIN::COOLDOWN_SECS
        .checked_shl(u32::from(over))
        .unwrap_or(PIN::MAX_COOLDOWN_SECS)
        .min(PIN::MAX_COOLDOWN_SECS)
}

/// Seconds still to wait before `policy` will accept another attempt, or `None`
/// if it will accept one now.
fn cooldown_remaining(policy: &LockPolicy) -> Option<u64> {
    let cooldown = cooldown_for(policy.failed_attempts);
    if cooldown == 0 {
        return None;
    }
    // No stamp means an `auth.json` from before the cooldown existed; see the
    // field docs. Allow the attempt — the failure will stamp it.
    let elapsed = kotton_common::time::now_secs().saturating_sub(policy.last_failed_at?);
    // A clock that moved backwards must not shorten the wait, so non-positive
    // elapsed counts as no progress rather than as a large positive remainder.
    if elapsed <= 0 {
        return Some(cooldown);
    }
    let remaining = cooldown.saturating_sub(elapsed as u64);
    (remaining > 0).then_some(remaining)
}

/// Verify a PIN, minting a session token on success.
///
/// Consecutive failures spend an attempt budget; once it is spent the PIN is not
/// verified at all until the cooldown elapses. See the module docs for what that
/// brake does and does not buy.
///
/// Returns `Err` if the policy has no PIN set.
pub fn try_unlock_with_pin(
    base: &Path,
    user_id: &str,
    pin: &str,
    sessions: &sessions::SessionMap,
) -> io::Result<PinAttempt> {
    let mut policy = load(base, user_id)?;
    let hash = policy
        .pin_hash
        .as_deref()
        .ok_or_else(|| io::Error::other("no pin configured for this user"))?;

    // Checked before `verify_pin`, deliberately: while the budget is spent a
    // correct PIN is refused too. Verifying first and discarding the answer
    // would leak the verdict through timing (Argon2id at these parameters is
    // ~100ms) and would do the attacker's work for them.
    if let Some(retry_after_secs) = cooldown_remaining(&policy) {
        return Ok(PinAttempt::RateLimited { retry_after_secs });
    }

    if verify_pin(pin, hash)? {
        // Success — clear the budget and issue a new session token.
        policy.failed_attempts = 0;
        policy.last_failed_at = None;
        save(base, user_id, &policy)?;
        let token = uuid::Uuid::new_v4().to_string();
        // A person unlocked this, so it is an ordinary session and ages out.
        sessions::insert(sessions, token.clone(), user_id.to_string());
        Ok(PinAttempt::Unlocked(token))
    } else {
        policy.failed_attempts = policy.failed_attempts.saturating_add(1);
        policy.last_failed_at = Some(kotton_common::time::now_secs());
        save(base, user_id, &policy)?;
        match cooldown_for(policy.failed_attempts) {
            0 => Ok(PinAttempt::Wrong {
                attempts_remaining: PIN::MAX_ATTEMPTS.saturating_sub(policy.failed_attempts),
            }),
            retry_after_secs => Ok(PinAttempt::RateLimited { retry_after_secs }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A credential that clears the RFC-0053 bar: five distinct wordlist words.
    const PIN_OK: &str = "abandon-ability-able-about-above";
    const PIN_BAD: &str = "absent-absorb-abstract-absurd-abuse";

    /// Judge, hash and record `avery`'s policy, with no seal between: these
    /// tests are about the record alone.
    fn record(
        base: &Path,
        mode: LockMode,
        auto_lock_minutes: u32,
        pin: Option<&str>,
        limiting: AttemptLimiting,
    ) -> io::Result<()> {
        prepare_policy(mode, auto_lock_minutes, pin, limiting)?.record(base, "avery")
    }

    /// Argon2id at the real parameters costs ~100ms per verify, so these tests
    /// spend attempts deliberately rather than looping to large numbers.
    fn user_with_pin() -> (tempfile::TempDir, sessions::SessionMap) {
        let dir = tempfile::tempdir().expect("tempdir");
        record(dir.path(), LockMode::Passphrase, 0, Some(PIN_OK), AttemptLimiting::None)
            .expect("record the policy");
        (dir, Default::default())
    }

    fn attempt(dir: &tempfile::TempDir, sessions: &sessions::SessionMap, pin: &str) -> PinAttempt {
        try_unlock_with_pin(dir.path(), "avery", pin, sessions).expect("try_unlock_with_pin")
    }

    /// The property that was missing entirely: the budget **refuses**, it does
    /// not merely count. Before this, the sixth guess — and the six-thousandth —
    /// was verified as cheerfully as the first while the response claimed zero
    /// attempts remained.
    #[test]
    fn the_budget_stops_accepting_guesses_once_it_is_spent() {
        let (dir, sessions) = user_with_pin();

        for n in 1..PIN::MAX_ATTEMPTS {
            let remaining = PIN::MAX_ATTEMPTS - n;
            assert_eq!(
                attempt(&dir, &sessions, PIN_BAD),
                PinAttempt::Wrong { attempts_remaining: remaining },
                "failure {n} should report {remaining} remaining"
            );
        }

        // The failure that spends the budget reports the wait, not a zero the
        // user cannot act on.
        assert_eq!(
            attempt(&dir, &sessions, PIN_BAD),
            PinAttempt::RateLimited { retry_after_secs: PIN::COOLDOWN_SECS }
        );

        // And now the *correct* PIN is refused too. This is the whole point: a
        // brake that only rejected wrong PINs would not be a brake, and an
        // attacker who guessed right on attempt six must not be let in.
        assert!(matches!(
            attempt(&dir, &sessions, PIN_OK),
            PinAttempt::RateLimited { .. }
        ));
        assert!(sessions.read().unwrap().is_empty(), "no session may be minted while rate-limited");
    }

    #[test]
    fn the_cooldown_expires_and_a_further_failure_doubles_it() {
        let (dir, sessions) = user_with_pin();

        let mut policy = load(dir.path(), "avery").expect("load");
        policy.failed_attempts = PIN::MAX_ATTEMPTS;
        // Older than the 30s the fifth failure earned.
        policy.last_failed_at = Some(kotton_common::time::now_secs() - 60);
        save(dir.path(), "avery", &policy).expect("save");

        // The window has passed, so an attempt is checked again — and this one
        // is wrong, which spends the *sixth* failure and earns double the wait.
        assert_eq!(
            attempt(&dir, &sessions, PIN_BAD),
            PinAttempt::RateLimited { retry_after_secs: PIN::COOLDOWN_SECS * 2 }
        );
    }

    /// A forgotten credential opens nothing: an unlock with it is refused as no
    /// credential set, mints no session, and the auto-lock setting stays. With no
    /// policy on disk, forgetting writes none.
    #[test]
    fn a_forgotten_credential_is_refused_as_none_set() {
        let dir = tempfile::tempdir().expect("tempdir");
        record(dir.path(), LockMode::Passphrase, 15, Some(PIN_OK), AttemptLimiting::None)
            .expect("record the policy");
        let sessions: sessions::SessionMap = Default::default();

        assert!(forget_credential(dir.path(), "avery").expect("forget"), "a credential was set");
        assert!(
            try_unlock_with_pin(dir.path(), "avery", PIN_OK, &sessions).is_err(),
            "the forgotten credential is refused"
        );
        assert!(sessions.read().unwrap().is_empty(), "no session was minted");
        let policy = load(dir.path(), "avery").expect("load");
        assert_eq!(policy.mode, LockMode::None);
        assert_eq!(policy.auto_lock_minutes, 15, "the auto-lock setting is kept");
        assert!(!forget_credential(dir.path(), "avery").expect("forget again"), "none was left");

        assert!(!forget_credential(dir.path(), "blake").expect("forget with no policy"));
        assert!(!policy_path(dir.path(), "blake").exists(), "no policy was written");
    }

    #[test]
    fn a_correct_pin_unlocks_and_clears_the_budget() {
        let (dir, sessions) = user_with_pin();

        assert!(matches!(
            attempt(&dir, &sessions, PIN_BAD),
            PinAttempt::Wrong { .. }
        ));
        assert!(matches!(
            attempt(&dir, &sessions, PIN_OK),
            PinAttempt::Unlocked(_)
        ));

        let policy = load(dir.path(), "avery").expect("load");
        assert_eq!(policy.failed_attempts, 0);
        assert_eq!(policy.last_failed_at, None, "a success must clear the stamp too");
    }

    /// A stale `auth.json` from before the cooldown existed carries no stamp.
    /// It must not read as "locked out forever" — the upgrade itself is not an
    /// authentication event.
    #[test]
    fn a_spent_counter_with_no_stamp_still_allows_an_attempt() {
        let (dir, sessions) = user_with_pin();

        let mut policy = load(dir.path(), "avery").expect("load");
        policy.failed_attempts = PIN::MAX_ATTEMPTS + 3;
        policy.last_failed_at = None;
        save(dir.path(), "avery", &policy).expect("save");

        assert!(matches!(
            attempt(&dir, &sessions, PIN_OK),
            PinAttempt::Unlocked(_)
        ));
    }

    /// A clock moved backwards must not shorten the wait. Otherwise the cheapest
    /// way past the brake is to set the system clock back, which an attacker
    /// with local access can do.
    #[test]
    fn a_backwards_clock_does_not_shorten_the_cooldown() {
        let policy = LockPolicy {
            failed_attempts: PIN::MAX_ATTEMPTS,
            last_failed_at: Some(kotton_common::time::now_secs() + 10_000),
            ..LockPolicy::default()
        };
        assert_eq!(cooldown_remaining(&policy), Some(PIN::COOLDOWN_SECS));
    }

    /// RFC-0053's resolved rule, enforced where the credential is chosen: a
    /// short PIN is permitted only where hardware counts failures, and no
    /// platform reports that yet.
    #[test]
    fn a_short_pin_cannot_be_set_on_a_device_with_no_hardware_limit() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Where hardware counts the guesses, the same six digits are enough:
        // the bar follows the limiter (DEC-0046), and this is the line that
        // lets a PIN be the daily credential on a bound device
        // (TASK-the-enclave-does-not-count-attempts).
        record(dir.path(), LockMode::Pin, 0, Some("135790"), AttemptLimiting::Hardware)
            .expect("six digits clear the hardware-limited bar");
        let err = record(dir.path(), LockMode::Pin, 0, Some("135790"), AttemptLimiting::None)
            .expect_err("a six-digit PIN must be refused");
        assert!(
            err.to_string().contains("hardware"),
            "the refusal should say why, got: {err}"
        );
        // And the same is true under the passphrase mode — the bar is the
        // credential's strength, not the label on it.
        assert!(record(dir.path(), LockMode::Passphrase, 0, Some("135790"), AttemptLimiting::None).is_err());
    }

    /// The continuity half: a PIN already on disk keeps unlocking. An upgrade
    /// that locked existing users out of their own device would break the
    /// identity-continuity invariant, which no strength rule outranks.
    #[test]
    fn a_pin_written_before_the_rule_still_unlocks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sessions: sessions::SessionMap = Default::default();

        // Write the policy a pre-RFC-0053-step-3 daemon would have written,
        // bypassing `prepare_policy` exactly as history did.
        let legacy = LockPolicy {
            mode: LockMode::Pin,
            pin_hash: Some(hash_pin("135790").expect("hash")),
            auto_lock_minutes: 0,
            failed_attempts: 0,
            last_failed_at: None,
        };
        save(dir.path(), "avery", &legacy).expect("save");

        assert!(matches!(
            try_unlock_with_pin(dir.path(), "avery", "135790", &sessions).expect("unlock"),
            PinAttempt::Unlocked(_)
        ));
    }

    /// A record that cannot be written leaves the old one whole: it is replaced
    /// through a temporary file and a rename, so a failed write is not a
    /// truncated record that no passphrase opens.
    #[test]
    fn a_record_that_cannot_be_written_leaves_the_old_one_whole() {
        let (dir, sessions) = user_with_pin();
        let path = policy_path(dir.path(), "avery");
        let before = std::fs::read(&path).expect("the record");
        let obstacle = path.with_extension("json.tmp");
        std::fs::create_dir(&obstacle).expect("an obstacle at the temporary path");

        let next = "absent-absorb-abstract-absurd-accident";
        record(dir.path(), LockMode::Passphrase, 0, Some(next), AttemptLimiting::None)
            .expect_err("the record cannot be written");
        assert_eq!(std::fs::read(&path).expect("the record"), before, "the old record is whole");
        std::fs::remove_dir(&obstacle).expect("the obstacle goes");
        assert!(matches!(attempt(&dir, &sessions, next), PinAttempt::Wrong { .. }));
        assert!(matches!(attempt(&dir, &sessions, PIN_OK), PinAttempt::Unlocked(_)));
    }

    /// Changing the credential must not leave the old one working.
    #[test]
    fn a_changed_passphrase_replaces_the_old_one() {
        let (dir, sessions) = user_with_pin();
        let next = "absent-absorb-abstract-absurd-accident";
        record(dir.path(), LockMode::Passphrase, 0, Some(next), AttemptLimiting::None).expect("record the policy");

        assert!(matches!(attempt(&dir, &sessions, next), PinAttempt::Unlocked(_)));
        assert!(matches!(
            attempt(&dir, &sessions, PIN_OK),
            PinAttempt::Wrong { .. }
        ));
    }

    #[test]
    fn the_cooldown_doubles_then_caps() {
        assert_eq!(cooldown_for(0), 0);
        assert_eq!(cooldown_for(PIN::MAX_ATTEMPTS - 1), 0);
        assert_eq!(cooldown_for(PIN::MAX_ATTEMPTS), PIN::COOLDOWN_SECS);
        assert_eq!(cooldown_for(PIN::MAX_ATTEMPTS + 1), PIN::COOLDOWN_SECS * 2);
        assert_eq!(cooldown_for(PIN::MAX_ATTEMPTS + 2), PIN::COOLDOWN_SECS * 4);
        // Capped, and never panicking on a shift far past u64's width.
        assert_eq!(cooldown_for(u8::MAX), PIN::MAX_COOLDOWN_SECS);
    }
}
