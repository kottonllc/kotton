// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kuserd` — Kotton per-user daemon.
//!
//! One instance runs per unlocked user, spawned by `kdeviced`.
//!
//! When launched by `kdeviced` the `KOTTON_USER_DID` environment variable
//! is set to the user's DID.  The socket name is derived from it:
//!
//!   `kuserd-{last8}` where `last8` = last 8 characters of the DID string.
//!
//! When `KOTTON_USER_DID` is absent (direct dev launch) the binary falls back
//! to the `KUSERD_IPC_NAME` variable (default: `kuserd`) so dev workflows work
//! without needing `kdeviced` running.
//!
//! ```sh
//! # Direct dev launch:
//! KOTTON_BASE_DIR=.kotton.dev KUSERD_IPC_NAME=kuserd-dev cargo run -p kuserd
//!
//! # Spawned by kdeviced (normal production / dev mode):
//! KOTTON_BASE_DIR=.kotton.dev KOTTON_USER_DID=did:key:z6Mk... cargo run -p kuserd
//! ```

#[cfg(unix)]
use kotton_common::{daemon_socket_path, kuserd_door};
#[cfg(windows)]
use kotton_common::kuserd_ipc_name;
use kotton_sys::ipc::IpcEndpoint;
use kuserd::DeviceDaemon;
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();
    tracing_log::LogTracer::init().ok();
    // Spawned by kdeviced: a per-user door, named from the user DID. That is a
    // different door from the direct-launch one, which `kuserd_door` composes for
    // every caller, so it is composed here and only here.
    let per_user = std::env::var("KOTTON_USER_DID").ok().map(|did| {
        let short = if did.len() >= 8 {
            &did[did.len() - 8..]
        } else {
            &did
        };
        format!("kuserd-{}", short)
    });

    #[cfg(windows)]
    let endpoint = IpcEndpoint::NamedPipe(per_user.unwrap_or_else(kuserd_ipc_name));
    #[cfg(unix)]
    let endpoint = IpcEndpoint::UnixSocket(
        match per_user {
            Some(name) => daemon_socket_path(&name),
            // Direct launch / dev mode: the door every client asks for.
            None => kuserd_door(),
        }
        .map_err(|e| std::io::Error::other(e.to_string()))?,
    );

    // An installed Kotton carries its shell beside the daemon; stage it before the
    // daemon can be asked to draw (`kuserd::installed`). A checkout has none there,
    // and xtask has already staged.
    stage_the_shell_that_shipped();

    let daemon = std::sync::Arc::new(DeviceDaemon::new(endpoint).await?);
    daemon.run().await
}

/// Stage the shell that shipped beside this executable, if one did.
///
/// A failure is logged and the daemon starts anyway: a daemon with no shell to
/// draw still serves the CLI, and `app_launch_system_shell` names the missing
/// body when the window asks for it.
fn stage_the_shell_that_shipped() {
    let exe_dir = match std::env::current_exe() {
        Ok(exe) => exe.parent().map(std::path::Path::to_path_buf),
        Err(e) => {
            tracing::warn!("cannot tell where this daemon runs from, so no shipped shell is staged: {e}");
            None
        }
    };
    let (Some(exe_dir), Ok(base)) = (exe_dir, kotton_common::paths::base_dir()) else {
        return;
    };
    match kuserd::installed::stage_the_shell_that_shipped(&exe_dir, &base) {
        Ok(Some(dst)) => {
            tracing::info!("staged the shell that shipped with this daemon into {}", dst.display())
        }
        Ok(None) => {}
        Err(e) => tracing::error!("could not stage the shell that shipped with this daemon: {e}"),
    }
}
