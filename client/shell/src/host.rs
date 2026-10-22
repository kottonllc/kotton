// SPDX-License-Identifier: AGPL-3.0-or-later
//! The host environment the shell command engine runs against — its single door to
//! user data.
//!
//! The engine depends only on the [`ShellHost`] port; concrete transports implement it.
//! Today the only adapter is [`KottonClientHost`] (the CLI repl, backed by `KottonClient`
//! over IPC). Per `RFC-0028`, a second adapter backed by the `files`/`schema` WIT
//! capabilities will let the same engine run *inside* an app's WASM sandbox, confined to
//! the user's grants. Keeping the engine behind this port is what makes that possible.
//!

use async_trait::async_trait;
use std::io;

/// VFS operations the shell command engine performs.
///
/// The session's user id and storage mount (`local`) are constant for the lifetime of a
/// shell; an adapter binds them at construction so commands work purely in terms of
/// paths. Every method is a daemon-mediated, capability-checked operation in the adapter
/// — the engine never touches a transport directly.
#[async_trait]
pub trait ShellHost: Send + Sync {
    /// Read a file's bytes.
    async fn read_file(&self, path: &str) -> io::Result<Vec<u8>>;
    /// Write bytes to a file (creating or replacing it).
    async fn write_file(&self, path: &str, data: &[u8]) -> io::Result<()>;
    /// List the entries under `prefix`, as the store the prefix routes to lists them: the
    /// person's own store lists every file at every depth beneath it; a routed mount on a
    /// plain-keyed store lists one level, a directory carrying a trailing `/`. A caller that
    /// needs every depth lists each directory entry it is handed in turn (`keep` does).
    async fn list_files(&self, prefix: &str) -> io::Result<Vec<String>>;
    /// Delete a file.
    async fn delete_file(&self, path: &str) -> io::Result<()>;
}

// ── KottonClient-backed adapter (CLI repl) ──────────────────────────────────────
//
// NOTE (RFC-0028, sprint 03b Phase 1b): this adapter — and the `kotton` dependency
// it pulls in — moves to `client/cli` once the system commands relocate there, so the
// engine core (tier-07) no longer depends on the IPC client. The `ShellHost` trait above
// stays; only this concrete impl is transitional in tier-07.

#[cfg(feature = "cli")]
use kotton::KottonClient;
#[cfg(feature = "cli")]
use std::sync::Arc;
#[cfg(feature = "cli")]
use tokio::sync::Mutex;

/// Routes shell VFS operations through the daemon over IPC, scoped to one session's user
/// on the `local` mount.
#[cfg(feature = "cli")]
pub struct KottonClientHost {
    pub client: Arc<Mutex<KottonClient>>,
    pub user_id: String,
}

#[cfg(feature = "cli")]
#[async_trait]
impl ShellHost for KottonClientHost {
    async fn read_file(&self, path: &str) -> io::Result<Vec<u8>> {
        self.client
            .lock()
            .await
            .read_file(&self.user_id, path)
            .await
    }

    async fn write_file(&self, path: &str, data: &[u8]) -> io::Result<()> {
        self.client
            .lock()
            .await
            .write_file(&self.user_id, path, data)
            .await
    }

    async fn list_files(&self, prefix: &str) -> io::Result<Vec<String>> {
        self.client
            .lock()
            .await
            .list_files(&self.user_id, prefix)
            .await
    }

    async fn delete_file(&self, path: &str) -> io::Result<()> {
        self.client
            .lock()
            .await
            .delete_file(&self.user_id, path)
            .await
    }
}
