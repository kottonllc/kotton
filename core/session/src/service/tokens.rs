// SPDX-License-Identifier: AGPL-3.0-or-later
//! Session tokens and their lifetime (RFC-0053, step 1).
//!
//! *Moved out of `kuserd/src/agent/sessions.rs` 2026-08-20.* It sat in the daemon
//! because the daemon is what holds the map, but a session token is the session
//! domain's vocabulary, not the daemon's — and `service` is where this crate
//! already says stateful coordination lives. Nothing about the behaviour
//! changed; the type simply stopped being private to one binary's internals.
//!
//! A session token authorises nearly every operation the daemon performs, so
//! what it is allowed to be matters. Until this module it was a bare UUID in a
//! `HashMap<token, user_id>` with **no expiry field at all** — valid until the
//! process ended, however long that was. A credential with no lifetime is a
//! defect regardless of how it is obtained.
//!
//! Every lookup goes through [`live_user`], which refuses an expired token and
//! drops it on the way past. Expiry is therefore not a check a caller can forget
//! to make: there is no way to resolve a token to a user that does not apply it.
//!
//! # Absolute, not sliding
//!
//! A session expires a fixed period after it was minted, and using it does not
//! extend it. A sliding window would be friendlier — it never interrupts someone
//! mid-task — but it also means an active attacker holds the token forever,
//! which is the property being removed here. An idle timeout *on top* of this
//! absolute cap is the refinement worth making later; it is strictly additional
//! and does not change this bound.

use kotton_common::time::now_secs;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// How long a freshly minted session stays valid.
///
/// Long enough to cover a working day without re-authenticating, short enough
/// that a token left behind on a shared machine stops working by the next one.
/// Sessions also die with the daemon, so this bounds the *other* case — a
/// long-lived daemon on a machine that never restarts.
pub const SESSION_TTL_SECS: i64 = 12 * 60 * 60;

/// An authenticated session.
#[derive(Debug, Clone)]
pub struct Session {
    /// The identity this token acts as.
    pub user_id: String,
    /// Unix seconds after which the token is refused. See the module note on
    /// why using the session does not push this out.
    ///
    /// `None` means **process-scoped**: the token lives exactly as long as this
    /// daemon does. See [`insert_process_scoped`] for when that is legitimate.
    pub expires_at: Option<i64>,
    /// The pid this token has been claimed by, on a process-scoped token that
    /// has authenticated at least once. `None` on a human session (never
    /// pid-bound — a person's CLI is a new process each time) and on a
    /// process-scoped token before its first connection.
    ///
    /// Set by [`claim_process_pid`] at the first `Authenticate`, and thereafter
    /// the only pid that token authenticates from. It is why a sidecar's
    /// bootstrap token, read out of the environment by another process on the
    /// same machine, is refused at the socket rather than honoured: the kernel
    /// says the second caller is a different process, and that is evidence the
    /// caller cannot forge.
    pub bound_pid: Option<i32>,
}

/// Token → session. Shared across every connection the daemon serves.
pub type SessionMap = Arc<RwLock<HashMap<String, Session>>>;

/// Record a session for `user_id`, expiring [`SESSION_TTL_SECS`] from now.
pub fn insert(sessions: &SessionMap, token: String, user_id: String) {
    sessions.write().unwrap().insert(
        token,
        Session {
            user_id,
            expires_at: Some(now_secs() + SESSION_TTL_SECS),
            bound_pid: None,
        },
    );
}

/// Record a session whose lifetime is this daemon's, with no wall-clock expiry.
///
/// Reserved for the **bootstrap tokens kuserd mints for its own sidecars**
/// (`ksyncd`, `kquicd`, `khttpd`). A wall-clock TTL is the wrong tool there: the
/// sidecar is a supervised child that starts and dies with the daemon, has no
/// human to re-authenticate it, and no mechanism to renew — so a 12-hour bound
/// would not reduce exposure, it would simply break sync and the gateways on any
/// machine left running overnight.
///
/// What bounds these instead is the process. The map is in memory, so daemon exit
/// invalidates them, and the token never leaves the machine — it is handed to a
/// child process at spawn. That is a genuinely different credential from a
/// human's session, and it is spelled differently here so it stays a deliberate
/// exception rather than an oversight that looks like one.
pub fn insert_process_scoped(sessions: &SessionMap, token: String, user_id: String) {
    sessions.write().unwrap().insert(
        token,
        Session {
            user_id,
            expires_at: None,
            bound_pid: None,
        },
    );
}

/// The outcome of a process-scoped token being presented from a connecting process.
#[derive(Debug, PartialEq, Eq)]
pub enum PidClaim {
    /// The token authenticates from this process: it just claimed the pid, it
    /// already held it, it is a human session (not pid-bound), or the platform
    /// gave no peer pid to check against.
    Ok,
    /// The token is process-scoped and already bound to a **different** process.
    /// The caller is not the sidecar the token was minted for.
    Mismatch { bound: i32, seen: i32 },
}

/// Bind a process-scoped token to the pid presenting it, and refuse a pid that
/// is not the one it was first claimed by.
///
/// This is the one decision in the daemon that rests on the kernel's word about
/// a local caller rather than on a field the caller supplied
/// (`TASK-sockets-take-the-callers-word-for-who-it-is`). It applies only to the
/// process-scoped bootstrap tokens kuserd mints for its sidecars: those are the
/// tokens handed to a single spawned process, so "the same token from a second
/// process" is exactly the theft this refuses. A human session is left alone —
/// a person's session token travels between the many short-lived processes of
/// their CLI on purpose, and binding it to one pid would break every command
/// after the first.
///
/// **Where the kernel gives no pid — Windows named pipes today — this returns
/// `Ok` and the socket's own permissions stay the only boundary.** That is a
/// decision, written here, not an `unwrap_or` that reads absence of evidence as
/// permission: on a platform that cannot answer "which process", there is no
/// claim to enforce, and the status quo is not a regression.
///
/// Call it only after [`live_user`] has resolved the token, so a token that does
/// not exist or has expired is already refused; here the token is known live.
pub fn claim_process_pid(sessions: &SessionMap, token: &str, pid: Option<i32>) -> PidClaim {
    let mut g = sessions.write().unwrap();
    let Some(session) = g.get_mut(token) else {
        return PidClaim::Ok;
    };
    // Human sessions are not pid-bound. Only the process-scoped tokens
    // (`expires_at: None`) are a single process's credential.
    if session.expires_at.is_some() {
        return PidClaim::Ok;
    }
    let Some(pid) = pid else {
        return PidClaim::Ok;
    };
    match session.bound_pid {
        None => {
            session.bound_pid = Some(pid);
            PidClaim::Ok
        }
        Some(bound) if bound == pid => PidClaim::Ok,
        Some(bound) => PidClaim::Mismatch { bound, seen: pid },
    }
}

/// The identity a **live** token acts as, or `None` if it is unknown or expired.
///
/// An expired token is removed as it is rejected, so a stale entry cannot
/// accumulate and cannot be resurrected by a clock moving backwards.
pub fn live_user(sessions: &SessionMap, token: &str) -> Option<String> {
    live_session(sessions, token).map(|s| s.user_id)
}

/// The session behind `token` if it is live — the user and, for a human
/// session, when it ends. `GetUnlockState` reports the end; everything else
/// wants only the user and goes through [`live_user`], which is this with the
/// expiry dropped, so the two cannot disagree about what "live" means.
pub fn live_session(sessions: &SessionMap, token: &str) -> Option<Session> {
    let now = now_secs();
    let live = |s: &Session| s.expires_at.is_none_or(|exp| exp > now);

    // Read first: the overwhelmingly common case is a live token, and taking the
    // write lock for every request would serialise the daemon on this map.
    {
        let g = sessions.read().unwrap();
        match g.get(token) {
            None => return None,
            Some(s) if live(s) => return Some(s.clone()),
            Some(_) => {}
        }
    }
    let mut g = sessions.write().unwrap();
    if let Some(s) = g.get(token) {
        // Re-check under the write lock: another thread may have replaced this
        // token with a fresh session between the two acquisitions.
        if live(s) {
            return Some(s.clone());
        }
        tracing::debug!("session token expired");
        g.remove(token);
    }
    None
}

/// Whether `token` names a live session.
pub fn is_live(sessions: &SessionMap, token: &str) -> bool {
    live_user(sessions, token).is_some()
}


/// Whether some live session acts as `user_id` — that is, whether the person
/// is unlocked on this daemon right now.
///
/// The question a verb asks when it is offered to the occupant before and
/// after unlock alike and must act only after: the occupant's `set-display-name`
/// is reachable from the lock screen, since the locked shell holds the same
/// world as the unlocked one, and a name is changed by the person it names.
/// Expired tokens are not live; they are left for [`live_session`] to remove
/// when next presented rather than swept here, so this stays a read.
pub fn has_live_session_for(sessions: &SessionMap, user_id: &str) -> bool {
    let now = now_secs();
    sessions
        .read()
        .unwrap()
        .values()
        .any(|s| s.user_id == user_id && s.expires_at.is_none_or(|exp| exp > now))
}

/// Forget every session belonging to `user_id` — used on logout, so a token
/// issued before it cannot be replayed after.
pub fn remove_user(sessions: &SessionMap, user_id: &str) {
    sessions.write().unwrap().retain(|_, s| s.user_id != user_id);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map() -> SessionMap {
        Arc::new(RwLock::new(HashMap::new()))
    }

    /// The property the whole module exists for: a token does not live forever.
    #[test]
    fn an_expired_token_resolves_to_nobody() {
        let sessions = map();
        sessions.write().unwrap().insert(
            "stale".into(),
            Session {
                user_id: "avery".into(),
                expires_at: Some(now_secs() - 1),
                bound_pid: None,
            },
        );

        assert_eq!(live_user(&sessions, "stale"), None);
        assert!(!is_live(&sessions, "stale"));
        assert!(
            !sessions.read().unwrap().contains_key("stale"),
            "rejecting an expired token must also drop it"
        );
    }

    /// A person is unlocked while some live token acts as them, and not once
    /// every token they held has expired — an expired session must not let a
    /// verb through that asks "is this person here?"
    #[test]
    fn a_person_is_unlocked_while_a_live_token_acts_as_them() {
        let sessions = map();
        assert!(!has_live_session_for(&sessions, "avery"));
        insert(&sessions, "live".into(), "avery".into());
        assert!(has_live_session_for(&sessions, "avery"));
        assert!(!has_live_session_for(&sessions, "blake"));

        sessions.write().unwrap().insert(
            "stale".into(),
            Session {
                user_id: "blake".into(),
                expires_at: Some(now_secs() - 1),
                bound_pid: None,
            },
        );
        assert!(!has_live_session_for(&sessions, "blake"));
    }

    #[test]
    fn a_fresh_token_resolves_to_its_user() {
        let sessions = map();
        insert(&sessions, "live".into(), "avery".into());
        assert_eq!(live_user(&sessions, "live").as_deref(), Some("avery"));
    }

    #[test]
    fn an_unknown_token_resolves_to_nobody() {
        assert_eq!(live_user(&map(), "never-issued"), None);
    }

    /// A sidecar's bootstrap token must survive a daemon that runs for days —
    /// there is no human to re-authenticate it and no renewal path, so a
    /// wall-clock TTL would break sync and the gateways rather than protect
    /// anything. Bounded by process lifetime instead.
    #[test]
    fn a_process_scoped_token_binds_to_its_first_pid_and_refuses_another() {
        let sessions = map();
        insert_process_scoped(&sessions, "sidecar".into(), "avery".into());
        // First presenter claims the token.
        assert_eq!(claim_process_pid(&sessions, "sidecar", Some(4242)), PidClaim::Ok);
        // The same process again is fine.
        assert_eq!(claim_process_pid(&sessions, "sidecar", Some(4242)), PidClaim::Ok);
        // A different process on the same machine is refused, and the refusal
        // names both pids so a log line can say who was turned away.
        assert_eq!(
            claim_process_pid(&sessions, "sidecar", Some(9999)),
            PidClaim::Mismatch { bound: 4242, seen: 9999 },
        );
        // The refusal did not rebind: the real sidecar still authenticates.
        assert_eq!(claim_process_pid(&sessions, "sidecar", Some(4242)), PidClaim::Ok);
    }

    #[test]
    fn a_human_session_is_never_pid_bound() {
        let sessions = map();
        insert(&sessions, "cli".into(), "avery".into());
        // A person's session travels between the many processes of their CLI;
        // each is a different pid and every one must be honoured.
        assert_eq!(claim_process_pid(&sessions, "cli", Some(1)), PidClaim::Ok);
        assert_eq!(claim_process_pid(&sessions, "cli", Some(2)), PidClaim::Ok);
        assert_eq!(
            sessions.read().unwrap().get("cli").unwrap().bound_pid,
            None,
            "a human session must not record a pid"
        );
    }

    #[test]
    fn no_peer_pid_leaves_the_socket_permission_as_the_only_boundary() {
        // Windows named pipes give no peer pid today. Absence of evidence is
        // not permission to rebind, and it is not a refusal either: the token
        // stays claimable and the socket's own permissions remain the boundary.
        let sessions = map();
        insert_process_scoped(&sessions, "sidecar".into(), "avery".into());
        assert_eq!(claim_process_pid(&sessions, "sidecar", None), PidClaim::Ok);
        assert_eq!(
            sessions.read().unwrap().get("sidecar").unwrap().bound_pid,
            None,
            "with no peer pid there is nothing to bind"
        );
        // A later connection that *does* carry a pid still binds normally.
        assert_eq!(claim_process_pid(&sessions, "sidecar", Some(7)), PidClaim::Ok);
    }

    #[test]
    fn a_process_scoped_token_does_not_age_out() {
        let sessions = map();
        insert_process_scoped(&sessions, "sidecar".into(), "avery".into());

        // Well past any human session's TTL.
        sessions
            .write()
            .unwrap()
            .get_mut("sidecar")
            .unwrap()
            .expires_at = None;

        assert_eq!(
            live_user(&sessions, "sidecar").as_deref(),
            Some("avery"),
            "a process-scoped token has no wall-clock expiry"
        );
    }

    /// Logout must invalidate tokens issued earlier, not just the current one.
    #[test]
    fn removing_a_user_drops_all_of_their_sessions() {
        let sessions = map();
        insert(&sessions, "a".into(), "avery".into());
        insert(&sessions, "b".into(), "avery".into());
        insert(&sessions, "c".into(), "sam".into());

        remove_user(&sessions, "avery");

        assert_eq!(live_user(&sessions, "a"), None);
        assert_eq!(live_user(&sessions, "b"), None);
        assert_eq!(
            live_user(&sessions, "c").as_deref(),
            Some("sam"),
            "another identity's sessions must survive"
        );
    }
}
