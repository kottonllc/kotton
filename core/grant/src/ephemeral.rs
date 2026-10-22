// SPDX-License-Identifier: AGPL-3.0-or-later
//! Ephemeral session management.
//!
//! An ephemeral session grants a guest device time-limited, path-scoped access
//! to a subset of a user's storage without requiring the full pairing ceremony.
//!
//! # Lifecycle
//!
//! 1. The host calls [`issue_session`] to create a session record and derive a
//!    per-session symmetric key (`SessionKey`).
//! 2. The `SessionKey` is transmitted to the guest over the mTLS QUIC connection.
//! 3. Inbound requests from the guest are validated with [`validate_session`].
//! 4. The host can revoke the session early with [`revoke_session`].
//!    Revoked sessions are rejected immediately even if they haven't expired.
//!
//! **Phase 4 note:** persistence to SQLite is added in Phase 4.
//! These functions are in-memory and carry no DB dependency.

use anyhow::{anyhow, Result};
use kotton_wire::peer::{EphemeralSession, SessionPermissions};
use kotton_wire::GrantEnvelope;
use kotton_schemas::{CapabilityGrant, CapabilityKind, CapabilityTarget};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// SessionKey
// ---------------------------------------------------------------------------

/// A 32-byte symmetric key scoped to one ephemeral session.
///
/// Derived from the user's CEK and the session ID so it can be re-derived
/// at any time without storing it. See [`derive_session_key`].
///
/// **A larger hardening remains, and it is not key separation.** Anyone holding
/// the CEK and a session id can derive that session's key. Wrapping a *random*
/// per-session key so a CEK compromise does not expose issued sessions is a
/// separate design (random key + a stored wrapped copy), tracked as future work
/// rather than attempted here. What changed on 2026-09-06 was only *where* the
/// derivation lives: it moved into `kotton_crypto`'s HKDF hierarchy with a
/// registered label, so it is auditable beside every other derived key
/// (`TASK-session-key-derives-outside-the-hierarchy`).
pub type SessionKey = [u8; 32];

// ---------------------------------------------------------------------------
// Issue
// ---------------------------------------------------------------------------

/// Issue a new ephemeral session ticket.
///
/// Returns both the session record (to be stored by the daemon) and the
/// `SessionKey` (to be transmitted to the guest over the authenticated channel).
///
/// # Arguments
///
/// * `user_cek`         — 32-byte Content Encryption Key for computing the session key.
/// * `guest_public_key` — Ed25519 public key of the guest device (32 bytes).
/// * `guest_did_str`    — DID string of the guest device.
/// * `paths`            — Paths the guest may access; each entry covers its subtree.
/// * `permissions`      — `Read` or `ReadWrite` (converted to `CapabilityGrant`s).
/// * `ttl_seconds`      — Session lifetime in seconds from now.
pub fn issue_session(
    user_cek: &[u8; 32],
    guest_public_key: [u8; 32],
    guest_did_str: String,
    paths: Vec<String>,
    permissions: SessionPermissions,
    ttl_seconds: u64,
) -> Result<(EphemeralSession, SessionKey)> {
    let session_id = Uuid::new_v4().to_string();
    let now = now_unix()? as u64;
    let expires_at = now
        .checked_add(ttl_seconds)
        .ok_or_else(|| anyhow!("TTL overflow"))?;

    let session_key = derive_session_key(user_cek, &session_id);

    // Convert paths + permissions into GrantEnvelope capability grants.
    let grants: Vec<CapabilityGrant> = paths
        .iter()
        .flat_map(|path| {
            let read = CapabilityGrant::vfs(CapabilityKind::Read, path.clone());
            if permissions == SessionPermissions::ReadWrite {
                vec![
                    read,
                    CapabilityGrant::vfs(CapabilityKind::Write, path.clone()),
                ]
            } else {
                vec![read]
            }
        })
        .collect();

    let guest_did = kotton_wire::did::Did::new("key", &guest_did_str);
    let grant = GrantEnvelope {
        id: session_id.clone(),
        // Placeholder issuer: the user's DID is not threaded into this function yet.
        // TODO(v0.4): pass the user DID explicitly.
        issuer_did: guest_did.clone(),
        subject_did: guest_did.clone(),
        node_did: None,
        grants,
        issued_at: now as i64,
        expires_at: Some(expires_at as i64),
        // TODO(v0.4): sign with the user's session key.
        // Not an app grant: this envelope authorises a guest device session, and the
        // app binding (`DEC-0052`) does not apply. `check_grant` refuses an
        // unbound envelope, which is why this must never be stored in
        // `app_grant_envelopes`.
        app_id: None,
        issuer_signature: String::new(),
    };

    let session = EphemeralSession {
        id: session_id,
        guest_did,
        guest_public_key,
        grant,
        issued_at: now as i64,
        revoked: false,
        wrapped_deks: std::collections::HashMap::new(),
    };

    Ok((session, session_key))
}

// ---------------------------------------------------------------------------
// Re-derive session key
// ---------------------------------------------------------------------------

/// Re-derive the session key from the host's CEK and a session ID.
///
/// The key is deterministic so hosts can recompute it on restart without
/// storing session keys at rest. Identical to the derivation in
/// [`issue_session`]. Thin wrapper over [`kotton_crypto::derive_session_key`],
/// which is the one place the derivation lives — HKDF-SHA256 with a label from
/// `kotton_common::crypto::kdf_labels`.
pub fn derive_session_key(user_cek: &[u8; 32], session_id: &str) -> SessionKey {
    kotton_crypto::derive_session_key(user_cek, session_id)
}

// ---------------------------------------------------------------------------
// Validate
// ---------------------------------------------------------------------------

/// Validate an inbound request against the session table.
///
/// Returns a reference to the matching session on success, or an error if:
/// - the session ID does not exist,
/// - the session has been revoked,
/// - the session has expired (`now > expires_at`), or
/// - `requested_path` is not covered by any of the session's paths.
///
/// # Arguments
///
/// * `sessions`        — The active session list (typically from DB / in-memory store).
/// * `session_id`      — ID of the incoming request's session.
/// * `requested_path`  — The VFS path being accessed.
/// * `now`             — Current Unix timestamp (seconds). Use 0 to skip expiry check.
pub fn validate_session<'a>(
    sessions: &'a [EphemeralSession],
    session_id: &str,
    requested_path: &str,
    now: i64,
) -> Result<&'a EphemeralSession> {
    let session = sessions
        .iter()
        .find(|s| s.id == session_id)
        .ok_or_else(|| anyhow!("session not found: {}", session_id))?;

    if session.revoked {
        return Err(anyhow!("session {} has been revoked", session_id));
    }

    if let Some(expires_at) = session.grant.expires_at {
        if now > expires_at {
            return Err(anyhow!(
                "session {} expired at {}, now is {}",
                session_id,
                expires_at,
                now
            ));
        }
    }

    // Collect allowed VFS paths from the grant's capability list.
    let allowed_paths: Vec<&str> = session
        .grant
        .grants
        .iter()
        .filter_map(|g| {
            if let CapabilityTarget::Vfs { path } = &g.target {
                Some(path.as_str())
            } else {
                None
            }
        })
        .collect();

    let path_allowed = allowed_paths
        .iter()
        .any(|p| requested_path == *p || requested_path.starts_with(&format!("{}/", p)));

    if !path_allowed {
        return Err(anyhow!(
            "path '{}' is not covered by session '{}' (allowed: {:?})",
            requested_path,
            session_id,
            allowed_paths,
        ));
    }

    Ok(session)
}

// ---------------------------------------------------------------------------
// Revoke
// ---------------------------------------------------------------------------

/// Revoke a session before it expires.
///
/// Sets `session.revoked = true` in place.
/// Returns an error if the session ID is not found.
///
/// **Phase 4:** this will also write the revocation to the `ephemeral_sessions`
/// table in SQLite.
pub fn revoke_session(sessions: &mut [EphemeralSession], session_id: &str) -> Result<()> {
    let session = sessions
        .iter_mut()
        .find(|s| s.id == session_id)
        .ok_or_else(|| anyhow!("session not found: {}", session_id))?;
    session.revoked = true;
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Fallible only to fit this module's `Result` plumbing.
///
/// [`kotton_common::time::now_secs`] saturates instead of failing, because the
/// only way to be before the epoch is a system clock set before 1970 — on which
/// every timestamp Kotton writes is already meaningless. The `Ok` is therefore
/// unconditional; the signature stays so callers here need no change.
fn now_unix() -> Result<i64> {
    Ok(kotton_common::time::now_secs())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use kotton_wire::peer::SessionPermissions;

    const CEK: [u8; 32] = [0xAA; 32];
    const GUEST_PK: [u8; 32] = [0xBB; 32];

    fn issue(
        paths: Vec<&str>,
        permissions: SessionPermissions,
        ttl_seconds: u64,
    ) -> (EphemeralSession, SessionKey) {
        issue_session(
            &CEK,
            GUEST_PK,
            "z6MkTest".to_string(),
            paths.into_iter().map(String::from).collect(),
            permissions,
            ttl_seconds,
        )
        .expect("issue_session should not fail")
    }

    // -- issue ----------------------------------------------------------------

    #[test]
    fn issue_produces_valid_session() {
        let (session, key) = issue(vec!["/notes"], SessionPermissions::Read, 3600);
        assert!(!session.id.is_empty());
        assert!(!session.revoked);
        let expires_at = session.grant.expires_at.expect("expires_at should be set");
        assert!(expires_at > session.issued_at);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn session_key_derives_through_the_crypto_hierarchy() {
        // The wrapper is the crate's one derivation, and it is the crypto
        // hierarchy's — not a private blake3 KDF as it was before 2026-09-06
        // (TASK-session-key-derives-outside-the-hierarchy).
        let (session, key) = issue(vec!["/notes"], SessionPermissions::Read, 3600);
        assert_eq!(key, kotton_crypto::derive_session_key(&CEK, &session.id));
    }

    #[test]
    fn session_key_is_deterministic() {
        let (session, key1) = issue(vec!["/notes"], SessionPermissions::Read, 3600);
        let key2 = derive_session_key(&CEK, &session.id);
        assert_eq!(key1, key2, "re-derived key must match");
    }

    // -- validate -------------------------------------------------------------

    #[test]
    fn valid_session_passes_validation() {
        let (session, _) = issue(vec!["/notes"], SessionPermissions::Read, 3600);
        let id = session.id.clone();
        let sessions = vec![session];
        let result = validate_session(&sessions, &id, "/notes/todo.md", 0);
        assert!(result.is_ok());
    }

    #[test]
    fn path_outside_allowed_list_is_rejected() {
        let (session, _) = issue(vec!["/notes"], SessionPermissions::Read, 3600);
        let id = session.id.clone();
        let sessions = vec![session];
        let result = validate_session(&sessions, &id, "/secrets/key.pem", 0);
        assert!(result.is_err(), "path outside scope should fail");
    }

    #[test]
    fn expired_session_is_rejected() {
        let (session, _) = issue(vec!["/"], SessionPermissions::Read, 1);
        let id = session.id.clone();
        // issue sets expires_at = now + 1; pass now = far future
        let sessions = vec![session];
        let far_future = 9_999_999_999i64;
        let result = validate_session(&sessions, &id, "/anything", far_future);
        assert!(result.is_err(), "expired session should be rejected");
    }

    // -- revoke ---------------------------------------------------------------

    #[test]
    fn revoked_session_is_rejected_before_expiry() {
        let (session, _) = issue(vec!["/"], SessionPermissions::ReadWrite, 86400);
        let id = session.id.clone();
        let mut sessions = vec![session];

        revoke_session(&mut sessions, &id).expect("revoke should succeed");

        let result = validate_session(&sessions, &id, "/", 0);
        assert!(result.is_err(), "revoked session must be rejected");
    }

    #[test]
    fn revoke_nonexistent_session_returns_error() {
        let mut sessions: Vec<EphemeralSession> = vec![];
        let result = revoke_session(&mut sessions, "no-such-id");
        assert!(result.is_err());
    }
}
