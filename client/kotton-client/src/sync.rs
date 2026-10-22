// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `sync` domain — moving sealed bytes between the places a user keeps them.
//!
//! Reached through [`KottonClient::sync`], which binds the user once:
//!
//! ```no_run
//! # async fn example(client: &mut kotton::KottonClient) -> std::io::Result<()> {
//! let mut sync = client.sync("did:key:…");
//! let rules = sync.rules().await?;
//! # let _ = rules;
//! # Ok(())
//! # }
//! ```
//!
//! Replication moves objects as they rest. Nothing here opens one, so nothing
//! here needs a key — which is what lets a node carry a peer's data without
//! being able to read it
//! (RFC-0041).
//!
//! The domain name is RFC-0054's;
//! grouping the verbs under it is RFC-0055.

use std::io;

use super::{KottonClient, SyncDirection, SyncResult, SyncRule, UserRequest, UserResponse};

/// The `sync` domain, bound to one user.
///
/// Borrows the client, so it costs nothing to construct and cannot outlive the
/// connection it speaks over.
pub struct Sync<'a> {
    client: &'a mut KottonClient,
    user_id: String,
}

impl KottonClient {
    /// Enter the `sync` domain for a user.
    pub fn sync(&mut self, user_id: &str) -> Sync<'_> {
        Sync {
            client: self,
            user_id: user_id.to_string(),
        }
    }
}

impl Sync<'_> {
    /// Replicate a mount to a remote. See [`KottonClient::sync_mount`].
    pub async fn mount(
        &mut self,
        mount: &str,
        remote: &str,
        direction: Option<SyncDirection>,
    ) -> io::Result<SyncResult> {
        let u = self.user_id.clone();
        self.client.sync_mount(&u, mount, remote, direction).await
    }

    /// Add a standing rule. See [`KottonClient::configure_sync`].
    pub async fn configure(
        &mut self,
        node_id: &str,
        path: &str,
        watch: bool,
    ) -> io::Result<SyncRule> {
        let u = self.user_id.clone();
        self.client.configure_sync(&u, node_id, path, watch).await
    }

    /// Every standing rule. See [`KottonClient::list_sync_rules`].
    pub async fn rules(&mut self) -> io::Result<Vec<SyncRule>> {
        let u = self.user_id.clone();
        self.client.list_sync_rules(&u).await
    }

    /// Drop a standing rule. See [`KottonClient::remove_sync_rule`].
    pub async fn remove_rule(&mut self, node_id: &str, path: &str) -> io::Result<()> {
        let u = self.user_id.clone();
        self.client.remove_sync_rule(&u, node_id, path).await
    }

    /// Start a run, returning its job id. See [`KottonClient::sync_trigger`].
    pub async fn trigger(&mut self, node_id: Option<&str>) -> io::Result<String> {
        let u = self.user_id.clone();
        self.client.sync_trigger(&u, node_id).await
    }

    /// Wait for a run to finish. See [`KottonClient::sync_await`].
    pub async fn wait(
        &mut self,
        job_id: String,
        timeout_secs: u64,
    ) -> io::Result<kotton_wire::ipc::SyncOutcome> {
        let u = self.user_id.clone();
        self.client.sync_await(&u, job_id, timeout_secs).await
    }
}

impl KottonClient {
    /// Synchronise a local mount with a named remote.
    ///
    /// - `direction = None`            → bidirectional, last-write-wins
    /// - `direction = Some(Push)`      → local → remote only
    /// - `direction = Some(Pull)`      → remote → local only
    pub async fn sync_mount(
        &mut self,
        user_id: &str,
        mount: &str,
        remote: &str,
        direction: Option<SyncDirection>,
    ) -> io::Result<SyncResult> {
        let request = UserRequest::SyncMount {
            user_id: user_id.to_string(),
            mount: mount.to_string(),
            remote: remote.to_string(),
            direction,
        };
        match self.client.send(&request).await? {
            UserResponse::SyncComplete {
                pushed,
                pulled,
                skipped,
                transfers,
            } => Ok(SyncResult {
                pushed,
                pulled,
                skipped,
                transfers,
            }),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Add or update a background sync rule.
    pub async fn configure_sync(
        &mut self,
        user_id: &str,
        node_id: &str,
        path: &str,
        watch: bool,
    ) -> io::Result<SyncRule> {
        let request = UserRequest::SyncConfigure {
            user_id: user_id.to_string(),
            node_id: node_id.to_string(),
            path: path.to_string(),
            watch,
        };
        match self.client.send(&request).await? {
            UserResponse::SyncConfigured { rule } => Ok(rule),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// List all sync rules for `user_id`.
    pub async fn list_sync_rules(&mut self, user_id: &str) -> io::Result<Vec<SyncRule>> {
        let request = UserRequest::SyncRuleList {
            user_id: user_id.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::SyncRuleList { rules } => Ok(rules),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Remove a sync rule.
    pub async fn remove_sync_rule(
        &mut self,
        user_id: &str,
        node_id: &str,
        path: &str,
    ) -> io::Result<()> {
        let request = UserRequest::SyncRuleRemove {
            user_id: user_id.to_string(),
            node_id: node_id.to_string(),
            path: path.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::SyncRuleRemoved => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Enqueue a sync pass and return a job id.
    ///
    /// `node_id = None` syncs all configured rules. Non-blocking: returns as
    /// soon as the pass is enqueued. Use [`sync_await`] to block for the result.
    pub async fn sync_trigger(
        &mut self,
        user_id: &str,
        node_id: Option<&str>,
    ) -> io::Result<String> {
        let request = UserRequest::SyncTrigger {
            user_id: user_id.to_string(),
            node_id: node_id.map(str::to_string),
        };
        match self.client.send(&request).await? {
            UserResponse::SyncStarted { job_id, .. } => Ok(job_id),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Block until the sync job `job_id` completes or `timeout_secs` elapses.
    ///
    /// Returns the `SyncOutcome` on success, or an error on failure/timeout.
    pub async fn sync_await(
        &mut self,
        user_id: &str,
        job_id: String,
        timeout_secs: u64,
    ) -> io::Result<kotton_wire::ipc::SyncOutcome> {
        let request = UserRequest::SyncAwait {
            user_id: user_id.to_string(),
            job_id: job_id.clone(),
            timeout_secs,
        };
        match self.client.send(&request).await? {
            UserResponse::SyncOutcomeMsg { outcome, .. } => Ok(outcome),
            UserResponse::SyncJobFailed { message, .. } => Err(io::Error::other(message)),
            UserResponse::SyncJobTimeout { .. } => Err(io::Error::other(format!(
                "sync job timed out after {timeout_secs}s"
            ))),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }
}
