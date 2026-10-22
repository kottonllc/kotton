// SPDX-License-Identifier: AGPL-3.0-or-later
//! Persistent CLI session cache.
//!
//! After a successful login or identity creation, the daemon issues a session
//! token.  This module saves and loads those tokens so subsequent `kotton`
//! invocations can authenticate silently — no recovery key prompt on every
//! command.
//!
//! Tokens are stored under `$KOTTON_BASE_DIR/sessions/<user_id>.session`.
//! They are invalidated when the daemon restarts (the daemon holds token state
//! in memory), so a stale token causes `NoActiveSession` → the caller prompts
//! for the recovery key once and then caches the new token.
//!
//! File permissions are set to owner-only (0600 on Unix) to limit exposure.

use std::io;
use std::path::PathBuf;

// ── Path helpers ──────────────────────────────────────────────────────────────

fn session_file(user_id: &str) -> Option<PathBuf> {
    kotton_common::paths::base_dir()
        .ok()
        .map(|base| base.join("sessions").join(format!("{user_id}.session")))
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Load a cached session token for `user_id`, if one exists.
///
/// Returns `None` if the file doesn't exist or can't be read.
pub fn load(user_id: &str) -> Option<String> {
    let path = session_file(user_id)?;
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// Persist a session token for `user_id`.
///
/// Creates the `sessions/` directory if it doesn't exist.
/// Sets file permissions to owner-only on Unix.
/// Silently ignores write failures — a missing cache just means the next
/// invocation will prompt once.
pub fn save(user_id: &str, token: &str) {
    let Some(path) = session_file(user_id) else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = kotton_common::fs::create_dir_all_owner_only(parent);
    }
    if let Err(e) = write_restricted(&path, token) {
        tracing::debug!("session cache write failed for {user_id}: {e}");
    }
}

/// Delete the cached session token for `user_id`.
///
/// Called on `kotton user logout` or when the user explicitly locks their session.
pub fn clear(user_id: &str) {
    let Some(path) = session_file(user_id) else {
        return;
    };
    let _ = std::fs::remove_file(path);
}

// ── Restricted-permission write ───────────────────────────────────────────────

#[cfg(unix)]
fn write_restricted(path: &std::path::Path, content: &str) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?
        .write_all(content.as_bytes())
}

#[cfg(not(unix))]
fn write_restricted(path: &std::path::Path, content: &str) -> io::Result<()> {
    std::fs::write(path, content)
}
