// SPDX-License-Identifier: AGPL-3.0-or-later
//! ksyncd — Kotton sync sidecar process (RFC-0017)
//!
//! # Responsibilities (Phase 1)
//! - Authenticate to `kuserd` with a bootstrap token received via the
//!   `KSYNCD_BOOTSTRAP_TOKEN` environment variable (cleared immediately
//!   after reading).
//! - Subscribe to `VfsWatch` on a dedicated IPC connection.
//! - Send `SyncDrives` to `kuserd` whenever a `VfsChanged` frame arrives: the
//!   engine syncs this device's drives, and nothing else (a device is not a
//!   sync target).
//! - Run a 5-minute fallback poll in case the VfsWatch stream is idle.
//! - Exit cleanly on `VfsWatchEnd` (daemon shutdown), but stay alive on
//!   `VfsWatchFailed` (no watch) and keep syncing on the fallback poll.
//!
//! # Future (Phase 2 — deferred)
//! - Bind the peer-mesh QUIC listener (currently owned by `kuserd`).
//! - Run sync passes directly using VFS/record IPC calls.

use kotton_sys::ipc::IpcEndpoint;
use kotton_ipc::IpcClient;
use kotton_wire::{UserRequest, UserResponse};
use kotton_common::kuserd_ipc_name;
use std::io;
use tokio::time::{Duration, interval};

/// Scope requested by ksyncd on authenticate.  Minimal — only what Phase 1
/// needs.  Phase 2 will extend this when sync runs inside ksyncd.
const KSYNCD_SCOPE: &[&str] = &["SyncDrives", "SyncRuleList", "VfsWatch", "VfsReport"];

/// Fallback sync poll interval (5 minutes).
const POLL_INTERVAL_SECS: u64 = 300;

#[tokio::main]
async fn main() -> io::Result<()> {
    let token = std::env::var("KSYNCD_BOOTSTRAP_TOKEN")
        .map_err(|_| io::Error::other("KSYNCD_BOOTSTRAP_TOKEN not set"))?;
    // Note: we would ideally clear this from the environment immediately, but
    // std::env::remove_var is unsafe in Rust 1.82+.  The token is a single-use
    // UUID pre-inserted by kuserd and has no value after authentication.

    let endpoint = build_endpoint()?;

    // -- Authentication connection (used for SyncNow polling) ----------------
    let mut auth_client: IpcClient<UserRequest, UserResponse> =
        IpcClient::connect(endpoint.clone()).await?;

    let scope: Option<Vec<String>> =
        Some(KSYNCD_SCOPE.iter().map(|s| s.to_string()).collect());

    // The user this process serves is in the authenticate answer. Until
    // 2026-09-15 a second request, `GetActiveSession`, asked for it again and
    // was refused on a daemon whose account was still locked at boot — the
    // ordinary state of a daemon that has just started — so `ksyncd` exited
    // before its first poll, every time.
    let user_id = match auth_client
        .send(&UserRequest::Authenticate {
            token: kotton_wire::ipc::SecretText::new(token.clone()),
            scope,
        })
        .await?
    {
        UserResponse::ActiveSession { user_id } => {
            tracing::info!(%user_id, "ksyncd authenticated");
            user_id
        }
        UserResponse::NoActiveSession => {
            return Err(io::Error::other("bootstrap token rejected"));
        }
        UserResponse::Error { message } => {
            return Err(io::Error::other(format!("auth error: {message}")));
        }
        other => {
            return Err(io::Error::other(format!("unexpected auth response: {other:?}")));
        }
    };

    // -- VfsWatch subscription connection ------------------------------------
    let mut watch_client: IpcClient<UserRequest, UserResponse> =
        IpcClient::connect(endpoint.clone()).await?;

    match watch_client
        .send(&UserRequest::Authenticate {
            token: kotton_wire::ipc::SecretText::new(token.clone()),
            scope: Some(KSYNCD_SCOPE.iter().map(|s| s.to_string()).collect()),
        })
        .await?
    {
        UserResponse::ActiveSession { .. } => {}
        _ => return Err(io::Error::other("VfsWatch connection auth failed")),
    }

    // Subscribe — this call consumes `watch_client` and returns a frame channel.
    let mut frame_rx = watch_client
        .send_streaming(&UserRequest::VfsWatch {
            user_id: user_id.clone(),
            paths: vec![],
        })
        .await?;

    // Sent, not yet established: `send_streaming` writes the request and
    // returns. The daemon says when the watch is live with `VfsWatchReady`,
    // which the loop below logs; until then only the fallback poll is real.
    tracing::info!(%user_id, "ksyncd sent VfsWatch; entering sync loop");

    // Report initial connected-peer state (empty — QUIC mesh is Phase 2).
    report_peers(&mut auth_client, &user_id, vec![]).await;

    // -- Main loop: VfsChanged → SyncNow + fallback poll ---------------------
    let mut poll_ticker = interval(Duration::from_secs(POLL_INTERVAL_SECS));
    poll_ticker.tick().await; // discard first immediate tick

    loop {
        tokio::select! {
            frame = frame_rx.recv() => {
                match on_frame(frame.as_ref()) {
                    FrameAction::Note => {}
                    FrameAction::Sync => {
                        trigger_sync_now(&mut auth_client, &user_id).await;
                    }
                    FrameAction::PollOnly => break,
                    FrameAction::Stop => {
                        tracing::info!("ksyncd: VfsWatch subscription closed; exiting");
                        return Ok(());
                    }
                }
            }
            _ = poll_ticker.tick() => {
                tracing::debug!("ksyncd: poll timer tick, triggering sync");
                trigger_sync_now(&mut auth_client, &user_id).await;
            }
        }
    }

    // -- Degraded loop: no watch, poll only ----------------------------------
    // Reached only from `FrameAction::PollOnly`. The stream is over — the
    // daemon's handler returns after `VfsWatchFailed` — so selecting on it again
    // would read `None` and be mistaken for the daemon shutting down. Drop it and
    // keep the one source of sync that still works.
    drop(frame_rx);
    loop {
        poll_ticker.tick().await;
        tracing::debug!("ksyncd: poll timer tick (no watch), triggering sync");
        trigger_sync_now(&mut auth_client, &user_id).await;
    }
}

/// What the sidecar does with one frame from the `VfsWatch` stream.
///
/// A separate decision from the loop that carries it out, because the whole bug
/// this replaced was two frames meaning the same thing to the reader: an
/// unestablished watch and a departing daemon both arrived as `VfsWatchEnd`, and
/// `Stop` was the answer to both. Split out, which frame maps to which action is
/// a fact a test can state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameAction {
    /// Log-only; the stream continues.
    Note,
    /// A change landed — trigger a sync pass.
    Sync,
    /// The watch will never be established. Keep running on the fallback poll.
    PollOnly,
    /// The daemon is going away. Exit.
    Stop,
}

fn on_frame(frame: Option<&UserResponse>) -> FrameAction {
    match frame {
        Some(UserResponse::VfsWatchReady) => {
            tracing::info!("ksyncd: the VFS watch is live");
            FrameAction::Note
        }
        Some(UserResponse::VfsChanged { path, .. }) => {
            tracing::debug!(%path, "ksyncd: file changed, triggering sync");
            FrameAction::Sync
        }
        Some(UserResponse::VfsWatchFailed { reason }) => {
            // The daemon is fine; only the watch is gone. Stopping here would
            // take the fallback poll with it, and a restart would re-subscribe
            // into the same immediate failure — on exactly the condition
            // (inotify instance exhaustion) the poll exists to survive.
            tracing::warn!(
                %reason,
                poll_interval_secs = POLL_INTERVAL_SECS,
                "ksyncd: the VFS watch could not be established; \
                 syncing on the fallback poll alone"
            );
            FrameAction::PollOnly
        }
        Some(UserResponse::VfsWatchEnd) | None => FrameAction::Stop,
        Some(other) => {
            tracing::warn!(?other, "ksyncd: unexpected frame on VfsWatch stream");
            FrameAction::Note
        }
    }
}

/// Report the current connected-peer set to kuserd via `VfsReport`.
///
/// In Phase 1 ksyncd has no QUIC mesh, so the peer list is always empty.
/// Phase 2 will populate it from live QUIC connections.
async fn report_peers(
    client: &mut IpcClient<UserRequest, UserResponse>,
    _user_id: &str,
    connected_peers: Vec<String>,
) {
    let req = UserRequest::VfsReport { connected_peers };
    match client.send(&req).await {
        Ok(UserResponse::Ok) => {
            tracing::debug!("ksyncd: VfsReport acknowledged");
        }
        Ok(UserResponse::Error { message }) => {
            tracing::warn!(%message, "ksyncd: VfsReport returned error");
        }
        Ok(other) => {
            tracing::warn!(?other, "ksyncd: unexpected VfsReport response");
        }
        Err(e) => {
            tracing::warn!(error = %e, "ksyncd: VfsReport IPC error");
        }
    }
}

/// Send a `SyncDrives` request to kuserd.  Errors are logged and ignored —
/// the sync engine will catch up on the next poll tick.
async fn trigger_sync_now(client: &mut IpcClient<UserRequest, UserResponse>, user_id: &str) {
    let req = UserRequest::SyncDrives {
        user_id: user_id.to_string(),
    };
    match client.send(&req).await {
        Ok(UserResponse::SyncStarted { targets, .. }) => {
            tracing::debug!(targets, "ksyncd: SyncDrives acknowledged");
        }
        Ok(UserResponse::Error { message }) => {
            tracing::warn!(%message, "ksyncd: SyncDrives returned error");
        }
        Ok(other) => {
            tracing::warn!(?other, "ksyncd: unexpected SyncDrives response");
        }
        Err(e) => {
            tracing::warn!(error = %e, "ksyncd: SyncDrives IPC error");
        }
    }
}

/// Build the IPC endpoint for the local kuserd instance.
fn build_endpoint() -> io::Result<IpcEndpoint> {
    let name = kuserd_ipc_name();

    #[cfg(windows)]
    {
        Ok(IpcEndpoint::NamedPipe(name))
    }

    #[cfg(unix)]
    {
        // The socket the supervisor bound, or a bare name resolved the daemon's
        // way — never a path handed to the name resolver (kotton_common).
        let _ = &name;
        let path = kotton_common::kuserd_socket_from_env()
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(IpcEndpoint::UnixSocket(path))
    }
}

#[cfg(test)]
mod frame_action_tests {
    use super::{on_frame, FrameAction};
    use kotton_wire::ipc::VfsChangeKind;
    use kotton_wire::UserResponse;

    /// The refusal this file was corrected for. A watcher that never registered
    /// and a daemon that is shutting down are different facts, and the sidecar's
    /// answer to them is opposite: keep polling, versus exit. While both arrived
    /// as `VfsWatchEnd` the sidecar could only do one of the two, and it did the
    /// wrong one on the condition its poll exists to survive.
    #[test]
    fn a_failed_watch_keeps_the_sidecar_polling_and_a_closed_one_stops_it() {
        assert_eq!(
            on_frame(Some(&UserResponse::VfsWatchFailed {
                reason: "too many open files (os error 24)".to_string(),
            })),
            FrameAction::PollOnly,
            "inotify exhaustion must not end the sidecar"
        );
        assert_eq!(
            on_frame(Some(&UserResponse::VfsWatchEnd)),
            FrameAction::Stop,
            "a departing daemon still ends the sidecar"
        );
        assert_eq!(
            on_frame(None),
            FrameAction::Stop,
            "a dropped stream still ends the sidecar"
        );
    }

    /// And the frames either side of it keep their meanings.
    #[test]
    fn readiness_is_noted_and_a_change_triggers_a_sync() {
        assert_eq!(on_frame(Some(&UserResponse::VfsWatchReady)), FrameAction::Note);
        assert_eq!(
            on_frame(Some(&UserResponse::VfsChanged {
                path: "/u/alice/notes.md".to_string(),
                kind: VfsChangeKind::Modified,
                timestamp_secs: 0,
            })),
            FrameAction::Sync
        );
    }
}
