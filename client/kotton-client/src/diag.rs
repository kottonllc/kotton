// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `diag` domain — what the node is doing, and whether its record of it holds.
//!
//! ```no_run
//! # async fn example(client: &mut kotton::KottonClient) -> std::io::Result<()> {
//! let mut diag = client.diag("did:key:…");
//! let health = diag.daemon_health().await?;
//! # let _ = health;
//! # Ok(())
//! # }
//! ```
//!
//! [`Diag::verify_log`] is the one verb here that is not merely informational.
//! The event log is hash-chained, so verifying it answers whether the node's own
//! account of itself has been altered — auditability is a property to be checked
//! rather than assumed (principle XI, `docs/design/principles.md`).

use std::io;

use kotton_sys::ipc::IpcEndpoint;
use kotton_ipc::IpcClient;
#[cfg(windows)]
use kotton_common::kuserd_ipc_name;
use tokio::sync::mpsc;

use kotton_wire::ipc::{IpcSessionInfo, SidecarInfo};

use super::{ConfigItem, EventEntry, KottonClient, UserRequest, UserResponse};

/// Response from [`KottonClient::daemon_health`].
#[derive(Debug, Clone)]
pub struct DaemonHealthInfo {
    pub version: String,
    pub uptime_secs: u64,
    pub user_count: u32,
    pub app_count: u32,
    pub event_count: u64,
    pub error_count: u64,
    pub last_event_secs_ago: u64,
}

impl KottonClient {
    // -- Event log -----------------------------------------------------------

    /// Query persisted system events with optional filters.
    ///
    /// - `category` — one of the lowercase category strings (e.g. `"wasm"`).
    /// - `min_level` — minimum severity: `"trace" | "debug" | "info" | "warn" | "error"`.
    /// - `since` — Unix-seconds cursor; only events after this timestamp are returned.
    /// - `limit` — max rows (server caps at 500; defaults to 200).
    pub async fn query_events(
        &mut self,
        category: Option<String>,
        min_level: Option<String>,
        since: Option<i64>,
        limit: Option<u32>,
    ) -> io::Result<Vec<EventEntry>> {
        let request = UserRequest::QueryEvents {
            category,
            level: min_level,
            since,
            limit,
        };
        match self.client.send(&request).await? {
            UserResponse::EventList { events } => Ok(events),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Verify the HMAC integrity chain of the event log for `user_id`.
    pub async fn verify_event_log(&mut self, user_id: &str) -> io::Result<(bool, Option<u64>)> {
        let request = UserRequest::VerifyEventLog {
            user_id: user_id.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::EventLogIntegrity {
                ok,
                first_broken_at,
            } => Ok((ok, first_broken_at)),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Open a dedicated connection and subscribe to the live event stream.
    ///
    /// Returns a channel receiver that yields [`EventEntry`] values as the
    /// daemon publishes them.  The channel is closed when the daemon shuts
    /// down or the receiver is dropped.
    ///
    /// - `category` — filter to a single category (e.g. `"wasm"`). `None` = all.
    /// - `min_level` — minimum severity. `None` = all.
    ///
    /// The current session token must be set on `self` before calling this
    /// method (i.e. `self` must be authenticated).
    pub async fn subscribe_events(
        &self,
        category: Option<String>,
        min_level: Option<String>,
    ) -> io::Result<mpsc::Receiver<EventEntry>> {
        let token = self
            .session_token
            .as_deref()
            .ok_or_else(|| io::Error::other("not authenticated"))?
            .to_owned();

        // Open a fresh connection dedicated to streaming.
        #[cfg(windows)]
        let endpoint = IpcEndpoint::NamedPipe(kuserd_ipc_name());
        #[cfg(unix)]
        // `kuserd_door`, never an inline `format!`: the real path is
        // `runtime_dir()/<name>.sock`, and its long-path fallback is
        // `/tmp/kotton-<key>/<name>.sock`. Neither is `/tmp/<name>.sock`, so this
        // stream connected to a socket nothing binds and `--follow` never worked.
        let endpoint = IpcEndpoint::UnixSocket(
            kotton_common::kuserd_door().map_err(io::Error::other)?,
        );

        let mut raw: IpcClient<UserRequest, UserResponse> = IpcClient::connect(endpoint).await?;

        // Authenticate on the new connection.
        match raw
            .send(&UserRequest::Authenticate {
                token: kotton_wire::ipc::SecretText::new(token.clone()),
                scope: None,
            })
            .await?
        {
            UserResponse::Ok => {}
            UserResponse::Error { message } => return Err(io::Error::other(message)),
            _ => return Err(io::Error::other("unexpected authenticate response")),
        }

        // Subscribe — this consumes `raw` and returns a frame channel.
        let mut frame_rx = raw
            .send_streaming(&UserRequest::SubscribeEvents {
                category,
                level: min_level,
            })
            .await?;

        // Unwrap frames from DeviceResponse::EventStream into bare EventEntry.
        let (tx, rx) = mpsc::channel(256);
        tokio::spawn(async move {
            while let Some(frame) = frame_rx.recv().await {
                match frame {
                    UserResponse::EventStream { event } => {
                        if tx.send(event).await.is_err() {
                            break;
                        }
                    }
                    UserResponse::EventStreamEnd => break,
                    _ => {} // ignore unexpected frames
                }
            }
        });

        Ok(rx)
    }

    // -- Daemon health (M22b) ------------------------------------------------

    /// Return a live snapshot of daemon health: uptime, user count, app count, event stats.
    pub async fn daemon_health(&mut self) -> io::Result<DaemonHealthInfo> {
        match self.client.send(&UserRequest::DaemonStatus).await? {
            UserResponse::DaemonStatusInfo {
                version,
                uptime_secs,
                user_count,
                app_count,
                event_count,
                error_count,
                last_event_secs_ago,
            } => Ok(DaemonHealthInfo {
                version,
                uptime_secs,
                user_count,
                app_count,
                event_count,
                error_count,
                last_event_secs_ago,
            }),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }
    /// Snapshot of every authenticated IPC session on this daemon.
    pub async fn ipc_sessions(&mut self) -> io::Result<Vec<IpcSessionInfo>> {
        match self.client.send(&UserRequest::IpcSessions).await? {
            UserResponse::IpcSessionsResult { sessions } => Ok(sessions),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Snapshot of every sidecar process the daemon supervises.
    pub async fn daemon_sidecars(&mut self) -> io::Result<Vec<SidecarInfo>> {
        match self.client.send(&UserRequest::DaemonSidecars).await? {
            UserResponse::DaemonSidecarsResult { sidecars } => Ok(sidecars),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

}

// Moved from network.rs: config status is diagnostics, not networking.
impl KottonClient {
    /// Return a summary of all device-level config items (relay, TURN, STUN, etc.).
    pub async fn config_status(&mut self) -> io::Result<Vec<ConfigItem>> {
        match self.client.send(&UserRequest::ConfigStatus).await? {
            UserResponse::ConfigStatus { items } => Ok(items),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }
}

/// The `diag` domain, bound to one user.
///
/// Only [`Diag::verify_log`] uses the bound user; the rest describe the node
/// itself and the daemon takes the user from the session.
pub struct Diag<'a> {
    client: &'a mut KottonClient,
    user_id: String,
}

impl KottonClient {
    /// Enter the `diag` domain for a user.
    pub fn diag(&mut self, user_id: &str) -> Diag<'_> {
        Diag { client: self, user_id: user_id.to_string() }
    }
}

impl Diag<'_> {
    /// Query the event log. See [`KottonClient::query_events`].
    pub async fn events(
        &mut self,
        category: Option<String>,
        min_level: Option<String>,
        since: Option<i64>,
        limit: Option<u32>,
    ) -> io::Result<Vec<EventEntry>> {
        self.client.query_events(category, min_level, since, limit).await
    }

    /// Check the event log's hash chain. See [`KottonClient::verify_event_log`].
    pub async fn verify_log(&mut self) -> io::Result<(bool, Option<u64>)> {
        let u = self.user_id.clone();
        self.client.verify_event_log(&u).await
    }

    /// Daemon health. See [`KottonClient::daemon_health`].
    pub async fn daemon_health(&mut self) -> io::Result<DaemonHealthInfo> {
        self.client.daemon_health().await
    }

    /// Live IPC sessions. See [`KottonClient::ipc_sessions`].
    pub async fn ipc_sessions(&mut self) -> io::Result<Vec<IpcSessionInfo>> {
        self.client.ipc_sessions().await
    }

    /// Running sidecars. See [`KottonClient::daemon_sidecars`].
    pub async fn sidecars(&mut self) -> io::Result<Vec<SidecarInfo>> {
        self.client.daemon_sidecars().await
    }

    /// Effective configuration. See [`KottonClient::config_status`].
    pub async fn config(&mut self) -> io::Result<Vec<ConfigItem>> {
        self.client.config_status().await
    }
}
