// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `session` domain — a bounded, revocable right to act as a user on this
//! device right now.
//!
//! Reached through [`KottonClient::session`], which binds the user once:
//!
//! ```no_run
//! # async fn example(client: &mut kotton::KottonClient) -> std::io::Result<()> {
//! let mut session = client.session("did:key:…");
//! let (mode, minutes) = session.lock_policy().await?;
//! # let _ = (mode, minutes);
//! # Ok(())
//! # }
//! ```
//!
//! Who the user *is* lives in [`crate::Identity`]. That split is deliberate: an
//! identity outlives every device and has no authority to appeal to, while a
//! session is scoped, expiring and revocable. Blurring them would make revoking
//! a device look like disowning a self.
//!
//! `contact_add` and `contact_list` are still here and belong to neither. They
//! operate on contact records, and
//! RFC-0055 routes
//! contacts to the `kotton-schemas-core` commons, which does not exist yet. They
//! are left rather than guessed into a domain, and are deliberately absent from
//! [`Session`].

use std::io;

use super::{EphemeralSession, KottonClient, LockMode, UserRequest, UserResponse, session_cache};
use kotton_wire::ipc::CustodyState;

/// The `session` domain, bound to one user.
///
/// Borrows the client, so it costs nothing to construct and cannot outlive the
/// connection it speaks over.
pub struct Session<'a> {
    client: &'a mut KottonClient,
    user_id: String,
}

impl KottonClient {
    /// Enter the `session` domain for a user.
    pub fn session(&mut self, user_id: &str) -> Session<'_> {
        Session {
            client: self,
            user_id: user_id.to_string(),
        }
    }
}

impl Session<'_> {
    /// Authenticate this connection. See [`KottonClient::authenticate`].
    pub async fn authenticate(&mut self, token: &str) -> io::Result<()> {
        self.client.authenticate(token).await
    }

    /// Authenticate with a narrowed scope. See [`KottonClient::authenticate_scoped`].
    pub async fn authenticate_scoped(
        &mut self,
        token: &str,
        scope: Option<Vec<String>>,
    ) -> io::Result<()> {
        self.client.authenticate_scoped(token, scope).await
    }

    /// Which user this connection is acting as, if any.
    /// See [`KottonClient::get_active_session`].
    pub async fn active(&mut self) -> io::Result<Option<String>> {
        self.client.get_active_session().await
    }

    /// Lock the session. See [`KottonClient::lock_session`].
    pub async fn lock(&mut self) -> io::Result<()> {
        self.client.lock_session().await
    }

    /// Unlock with a PIN. See [`KottonClient::unlock_with_pin`].
    pub async fn unlock_with_pin(&mut self, pin: &str) -> io::Result<PinUnlock> {
        let u = self.user_id.clone();
        self.client.unlock_with_pin(&u, pin).await
    }

    /// Set when and how the session locks. See [`KottonClient::set_lock_policy`].
    pub async fn set_lock_policy(
        &mut self,
        mode: LockMode,
        auto_lock_minutes: u32,
        pin: Option<&str>,
    ) -> io::Result<()> {
        let u = self.user_id.clone();
        self.client
            .set_lock_policy(&u, mode, auto_lock_minutes, pin)
            .await
    }

    /// The current lock policy. See [`KottonClient::get_lock_policy`].
    pub async fn lock_policy(&mut self) -> io::Result<(LockMode, u32)> {
        let u = self.user_id.clone();
        self.client.get_lock_policy(&u).await
    }

    /// Which unlock methods are available. See [`KottonClient::get_unlock_methods`].
    pub async fn unlock_methods(&mut self) -> io::Result<(bool, bool)> {
        let u = self.user_id.clone();
        self.client.get_unlock_methods(&u).await
    }

    /// Every ephemeral session issued to a guest. See [`KottonClient::list_sessions`].
    pub async fn guests(&mut self) -> io::Result<Vec<EphemeralSession>> {
        let u = self.user_id.clone();
        self.client.list_sessions(&u).await
    }

    /// Revoke an ephemeral session. See [`KottonClient::end_session`].
    pub async fn end_guest(&mut self, session_id: &str) -> io::Result<()> {
        let u = self.user_id.clone();
        self.client.end_session(&u, session_id).await
    }
}

/// The outcome of [`KottonClient::unlock_with_pin`].
///
/// A named three-state result rather than `Result<(), u8>`: "wrong PIN, four
/// tries left" and "the daemon refused to check at all" call for different
/// things from the user, and a nested `Result` invited callers to flatten them
/// into one "it failed" branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinUnlock {
    /// Unlocked; this connection is authenticated and the token is cached.
    Unlocked,
    /// The PIN was wrong. At least one attempt remains.
    Wrong { attempts_remaining: u8 },
    /// Too many consecutive failures: the PIN was not checked, and will not be
    /// until `retry_after_secs` have passed. A correct PIN gets this too.
    RateLimited { retry_after_secs: u64 },
}

/// Render a wait in seconds as something to say to a person ("2m 30s").
///
/// Lives beside [`PinUnlock`] because both the CLI's `kotton id unlock` and the
/// login path in `connect_as` have to report the same wait.
pub fn format_wait(secs: u64) -> String {
    match (secs / 3600, (secs % 3600) / 60, secs % 60) {
        (0, 0, s) => format!("{s}s"),
        (0, m, s) => format!("{m}m {s}s"),
        (h, m, _) => format!("{h}h {m}m"),
    }
}

/// The answer to `GetUnlockState`: the two daemon-side lifetimes behind
/// "logged in", each with its end. The third — the active identity — is a
/// client-side file, and the readout that shows all three is
/// [`UnlockState::readout`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlockState {
    /// The connection that asked holds a live session for the user.
    pub session_live: bool,
    /// When it expires, unix seconds. `None` while live: process-scoped.
    pub session_until: Option<i64>,
    /// Whether the user's vault is open, and until when.
    pub custody: CustodyState,
}

impl UnlockState {
    /// The session and vault lines of `whoami`, as label/value pairs, each
    /// value carrying its own remedy. One rendering for both surfaces, so the
    /// CLI and the shell cannot disagree about what "logged in" means —
    /// which was the report (`TASK-three-things-are-called-being-logged-in`).
    pub fn readout(&self, user_id: &str, now: i64) -> Vec<(String, String)> {
        let left = |until: i64| format_wait(until.saturating_sub(now).max(0) as u64);
        let session = match (self.session_live, self.session_until) {
            (true, Some(until)) => format!("yes, expires in {}", left(until)),
            (true, None) => "yes, for as long as the daemon runs".to_string(),
            (false, _) => format!("none — run `kotton id unlock {user_id}`"),
        };
        let vault = match self.custody {
            CustodyState::Open { until } => format!("open, locks in {}", left(until)),
            CustodyState::Locked => format!("locked — run `kotton id unlock {user_id}`"),
            CustodyState::InPlatformStore => format!(
                "open, in the keychain, with no passphrase to close it — set one with \
                 `kotton id set-passphrase {user_id}`"
            ),
        };
        vec![("session".to_string(), session), ("vault".to_string(), vault)]
    }
}

impl KottonClient {
    // -- Session cache -------------------------------------------------------
    //
    // Routed through these three so the "is this the default daemon?" question
    // is asked in one place rather than at each call site.

    /// Store a token, if this connection's tokens belong in the cache.
    pub(crate) fn cache_session(&self, user_id: &str, token: &str) {
        if self.caches_sessions {
            session_cache::save(user_id, token);
        }
    }

    /// The cached token for `user_id`, if this connection may use it.
    pub(crate) fn cached_session(&self, user_id: &str) -> Option<String> {
        self.caches_sessions.then(|| session_cache::load(user_id))?
    }

    /// Drop the cached token for `user_id`.
    pub(crate) fn clear_cached_session(&self, user_id: &str) {
        if self.caches_sessions {
            session_cache::clear(user_id);
        }
    }

    // -- User lifecycle ------------------------------------------------------






    // -- Session auth --------------------------------------------------------

    /// Send a session token to the daemon, binding this connection to a user.
    ///
    /// Called automatically by `create_user` and `login_with_recovery_key`.
    /// Call explicitly when connecting with a previously obtained token.
    pub async fn authenticate(&mut self, token: &str) -> io::Result<()> {
        let request = UserRequest::Authenticate {
            token: kotton_wire::ipc::SecretText::new(token),
            scope: None,
        };
        match self.client.send(&request).await? {
            UserResponse::ActiveSession { .. } => {
                self.session_token = Some(token.to_string());
                Ok(())
            }
            UserResponse::NoActiveSession => Err(io::Error::other("invalid or expired token")),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Like [`authenticate`] but restricts the connection to the given
    /// variant-name allow-list.  Pass `Some(vec![])` for an empty list
    /// (treated as full access) or `None` for unrestricted access.
    pub async fn authenticate_scoped(
        &mut self,
        token: &str,
        scope: Option<Vec<String>>,
    ) -> io::Result<()> {
        let request = UserRequest::Authenticate {
            token: kotton_wire::ipc::SecretText::new(token),
            scope,
        };
        match self.client.send(&request).await? {
            UserResponse::ActiveSession { .. } => {
                self.session_token = Some(token.to_string());
                Ok(())
            }
            UserResponse::NoActiveSession => Err(io::Error::other("invalid or expired token")),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Return the user_id bound to the current session, if any.
    pub async fn get_active_session(&mut self) -> io::Result<Option<String>> {
        let request = UserRequest::GetActiveSession;
        match self.client.send(&request).await? {
            UserResponse::ActiveSession { user_id } => Ok(Some(user_id)),
            UserResponse::NoActiveSession => Ok(None),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Authenticate with the cached token for `user_id` if there is one, and
    /// **never prompt**. `Ok(true)` when this connection now holds a session;
    /// `Ok(false)` when there was no token or it was stale (the stale one is
    /// cleared). A readout wants exactly this: to report a missing session, not
    /// to go and get one.
    pub async fn resume_cached_session(&mut self, user_id: &str) -> io::Result<bool> {
        let Some(token) = self.cached_session(user_id) else {
            return Ok(false);
        };
        match self.authenticate(&token).await {
            Ok(()) => Ok(true),
            Err(_) => {
                self.clear_cached_session(user_id);
                Ok(false)
            }
        }
    }

    /// Whether this connection holds a live session for `user_id` and whether
    /// their vault is open, each with its end. Session-less: it is the verb
    /// that answers whether there is one.
    pub async fn get_unlock_state(&mut self, user_id: &str) -> io::Result<UnlockState> {
        let request = UserRequest::GetUnlockState {
            user_id: user_id.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::UnlockState {
                session_live,
                session_until,
                custody,
            } => Ok(UnlockState {
                session_live,
                session_until,
                custody,
            }),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Close `user_id`'s vault now: their operational roots leave the daemon's
    /// memory until the daily credential opens it again. The session this
    /// connection holds is untouched — see [`KottonClient::lock_session`] for
    /// the other lifetime.
    pub async fn lock_custody(&mut self, user_id: &str) -> io::Result<()> {
        let request = UserRequest::LockCustody {
            user_id: user_id.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::CustodyLocked => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Invalidate the current session token on both the client and daemon.
    pub async fn lock_session(&mut self) -> io::Result<()> {
        let request = UserRequest::LockSession;
        match self.client.send(&request).await? {
            UserResponse::SessionLocked => {
                self.session_token = None;
                Ok(())
            }
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    // -- PIN / lock (M23c) ---------------------------------------------------

    /// Set or update the lock policy for a user.
    ///
    /// `pin` carries the daily credential and must be `Some` for any mode other
    /// than `LockMode::None`. It is judged against the device's required
    /// strength daemon-side (RFC-0053 step 3) and refused if it falls short.
    pub async fn set_lock_policy(
        &mut self,
        user_id: &str,
        mode: LockMode,
        auto_lock_minutes: u32,
        pin: Option<&str>,
    ) -> io::Result<()> {
        let request = UserRequest::SetLockPolicy {
            user_id: user_id.to_string(),
            mode,
            auto_lock_minutes,
            pin: pin.map(kotton_wire::ipc::SecretText::new),
        };
        match self.client.send(&request).await? {
            UserResponse::LockPolicySet => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Return the current lock policy for a user.
    pub async fn get_lock_policy(&mut self, user_id: &str) -> io::Result<(LockMode, u32)> {
        let request = UserRequest::GetLockPolicy {
            user_id: user_id.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::LockPolicy {
                mode,
                auto_lock_minutes,
            } => Ok((mode, auto_lock_minutes)),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Ask which credentials this device accepts for `user_id`, before holding a
    /// session (RFC-0053 step 2).
    ///
    /// Returns `(pin, recovery_key)`. Used by `connect_as` to decide what to
    /// prompt for; a client cannot learn this from `get_recovery_status`, which
    /// needs the session it is trying to obtain.
    pub async fn get_unlock_methods(&mut self, user_id: &str) -> io::Result<(bool, bool)> {
        let request = UserRequest::GetUnlockMethods {
            user_id: user_id.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::UnlockMethods { pin, recovery_key } => Ok((pin, recovery_key)),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Admit another identity on this device as a contact.
    pub async fn contact_add(&mut self, user_id: &str, contact_did: &str) -> io::Result<String> {
        let request = UserRequest::ContactAdd {
            user_id: user_id.to_string(),
            contact_did: contact_did.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::ContactAdded { did } => Ok(did),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// List admitted contacts as `(did, label)`.
    pub async fn contact_list(
        &mut self,
        user_id: &str,
    ) -> io::Result<Vec<(String, Option<String>)>> {
        let request = UserRequest::ContactList {
            user_id: user_id.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::ContactListing { contacts } => Ok(contacts),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }


    /// Attempt to unlock with a PIN, authenticating this connection on success.
    ///
    /// The token is cached (see [`session_cache`]) so the next command does not
    /// re-prompt — without that, wiring the PIN into the login path would trade
    /// one credential prompt per command for another.
    pub async fn unlock_with_pin(&mut self, user_id: &str, pin: &str) -> io::Result<PinUnlock> {
        Ok(self.unlock(user_id, pin, false).await?.0)
    }

    /// Unlock as [`Self::unlock_with_pin`] does, and **repair** the operational
    /// roots from the vault on the way: a root the device could not read or
    /// does not hold is written from the vault, a root that read is compared
    /// with it, and a mismatch refuses naming the label. Returns, beside the
    /// unlock's answer, the labels written — `Some(empty)` when nothing needed
    /// it, and `None` when the daemon ran no repair (one that predates `repair`
    /// ignores the field and answers a plain unlock)
    /// (`TASK-a-keychain-entry-that-fails-permanently-has-no-repair-verb-and-lockedby-says-it-is-recoverable`).
    pub async fn unlock_repairing_roots(&mut self, user_id: &str, pin: &str) -> io::Result<(PinUnlock, Option<Vec<String>>)> {
        self.unlock(user_id, pin, true).await
    }

    async fn unlock(&mut self, user_id: &str, pin: &str, repair: bool) -> io::Result<(PinUnlock, Option<Vec<String>>)> {
        let request = UserRequest::UnlockWithPin {
            user_id: user_id.to_string(),
            pin: kotton_wire::ipc::SecretText::new(pin),
            repair,
        };
        match self.client.send(&request).await? {
            UserResponse::UnlockOk { session_token, repaired } => {
                self.authenticate(session_token.expose()).await?;
                self.cache_session(user_id, session_token.expose());
                Ok((PinUnlock::Unlocked, repaired))
            }
            UserResponse::UnlockFailed { attempts_remaining } => Ok((PinUnlock::Wrong {
                attempts_remaining,
            }, None)),
            UserResponse::UnlockRateLimited { retry_after_secs } => Ok((PinUnlock::RateLimited {
                retry_after_secs,
            }, None)),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    // -- Recovery status (M25b) ----------------------------------------------


}

// Moved from network.rs: an ephemeral session is a session, wherever it was minted.
impl KottonClient {
    /// List all active ephemeral sessions for `user_id`.
    pub async fn list_sessions(&mut self, user_id: &str) -> io::Result<Vec<EphemeralSession>> {
        let request = UserRequest::SessionList {
            user_id: user_id.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::SessionList { sessions } => Ok(sessions),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Revoke an ephemeral session before it expires.
    pub async fn end_session(&mut self, user_id: &str, session_id: &str) -> io::Result<()> {
        let request = UserRequest::SessionEnd {
            user_id: user_id.to_string(),
            session_id: session_id.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::SessionEnded => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }
}
