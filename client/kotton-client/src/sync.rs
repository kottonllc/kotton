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

    /// Keep this device's rule for a drive. See [`KottonClient::configure_sync`].
    pub async fn configure(
        &mut self,
        drive: &str,
        direction: Option<SyncDirection>,
        watch: bool,
    ) -> io::Result<SyncRule> {
        let u = self.user_id.clone();
        self.client.configure_sync(&u, drive, direction, watch).await
    }

    /// Every standing rule. See [`KottonClient::list_sync_rules`].
    pub async fn rules(&mut self) -> io::Result<Vec<SyncRule>> {
        let u = self.user_id.clone();
        self.client.list_sync_rules(&u).await
    }

    /// Drop this device's rule for a drive. See [`KottonClient::remove_sync_rule`].
    pub async fn remove_rule(&mut self, drive: &str) -> io::Result<()> {
        let u = self.user_id.clone();
        self.client.remove_sync_rule(&u, drive).await
    }

    /// Sync this device's drives now, returning the run's job id. See
    /// [`KottonClient::sync_drives`].
    pub async fn drives(&mut self) -> io::Result<(String, u32)> {
        let u = self.user_id.clone();
        self.client.sync_drives(&u).await
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

    /// Keep this device's rule for one of its person's drives: `drive` is the
    /// node the drive is reached through, `direction` this device's choice
    /// (`None` both ways), `watch` whether the background pass syncs it. A
    /// rule names a drive, never a device: another of the person's devices is
    /// refused.
    pub async fn configure_sync(
        &mut self,
        user_id: &str,
        drive: &str,
        direction: Option<SyncDirection>,
        watch: bool,
    ) -> io::Result<SyncRule> {
        let request = UserRequest::SyncConfigure {
            user_id: user_id.to_string(),
            drive: drive.to_string(),
            direction,
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

    /// Remove this device's rule for a drive.
    pub async fn remove_sync_rule(&mut self, user_id: &str, drive: &str) -> io::Result<()> {
        let request = UserRequest::SyncRuleRemove {
            user_id: user_id.to_string(),
            drive: drive.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::SyncRuleRemoved => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Sync this device's drives now and return a job id: every drive the
    /// person has recorded here, each in the direction its rule chooses.
    ///
    /// Non-blocking: returns as soon as the pass is enqueued. Use
    /// [`sync_await`] to block for the result.
    ///
    /// Answers the job id and how many drives the pass syncs.
    pub async fn sync_drives(&mut self, user_id: &str) -> io::Result<(String, u32)> {
        let request = UserRequest::SyncDrives {
            user_id: user_id.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::SyncStarted { job_id, targets } => Ok((job_id, targets)),
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

/// The drive's verbs (RFC 0003): a person's drives, on one vault or many.
/// Each answers the drives it is about, as their descriptors.
impl KottonClient {
    async fn drives(&mut self, request: UserRequest) -> io::Result<Vec<kotton_wire::ipc::DriveDescriptor>> {
        match self.client.send(&request).await? {
            UserResponse::Drives { drives, .. } => Ok(drives),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// `drive create <name> [--on <vault>]`: the drive made.
    pub async fn drive_create(&mut self, user_id: &str, name: &str, on: Option<&str>) -> io::Result<Vec<kotton_wire::ipc::DriveDescriptor>> {
        self.drives(UserRequest::DriveCreate { user_id: user_id.into(), name: name.into(), on: on.map(Into::into) })
            .await
    }

    /// `drive list`: every drive the person has.
    pub async fn drive_list(&mut self, user_id: &str) -> io::Result<Vec<kotton_wire::ipc::DriveDescriptor>> {
        self.drives(UserRequest::DriveList { user_id: user_id.into() }).await
    }

    /// `drive show <name>`: the drives called `name`.
    pub async fn drive_show(&mut self, user_id: &str, name: &str) -> io::Result<Vec<kotton_wire::ipc::DriveDescriptor>> {
        self.drives(UserRequest::DriveShow { user_id: user_id.into(), name: name.into() }).await
    }

    /// `drive move <name> --to <vault> [--from <vault>]`: the drive where it
    /// now lives, and how many keys the vault it left listed that the move
    /// refused and did not carry.
    pub async fn drive_move(&mut self, user_id: &str, name: &str, to: &str, from: Option<&str>) -> io::Result<DriveMoved> {
        let request = UserRequest::DriveMove { user_id: user_id.into(), name: name.into(), to: to.into(), from: from.map(Into::into) };
        match self.client.send(&request).await? {
            UserResponse::Drives { drives, keys_refused } => Ok(DriveMoved { drives, keys_refused }),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }
}

/// What `drive move` answered: the drive where it now lives, and the keys the
/// vault it left listed that are not storage keys, refused and not carried
/// (kotton #274).
#[derive(Debug, Clone)]
pub struct DriveMoved {
    /// The drive, as its descriptor at the vault it moved to.
    pub drives: Vec<kotton_wire::ipc::DriveDescriptor>,
    /// How many keys the move refused at the source's listing.
    pub keys_refused: u32,
}

/// What this device keeps (RFC 0003, "What this device holds"; kotton #55),
/// and `status`.
impl KottonClient {
    /// `pin <scope> whole|on-demand|default`: this device's settings after.
    pub async fn pin_set(
        &mut self,
        user_id: &str,
        scope: kotton_wire::ipc::PinScope,
        value: Option<kotton_wire::ipc::PinValue>,
    ) -> io::Result<kotton_wire::ipc::PinReadout> {
        match self.client.send(&UserRequest::PinSet { user_id: user_id.into(), scope, value }).await? {
            UserResponse::Pins { pins } => Ok(pins),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// `pin list`: this device's default, its exceptions, and the notices.
    pub async fn pin_list(&mut self, user_id: &str) -> io::Result<kotton_wire::ipc::PinReadout> {
        match self.client.send(&UserRequest::PinList { user_id: user_id.into() }).await? {
            UserResponse::Pins { pins } => Ok(pins),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// `status`: when this device last synced, what it keeps of each drive,
    /// and the notices.
    pub async fn status(&mut self, user_id: &str) -> io::Result<kotton_wire::ipc::DeviceStatus> {
        match self.client.send(&UserRequest::Status { user_id: user_id.into() }).await? {
            UserResponse::Status { status } => Ok(status),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }
}
