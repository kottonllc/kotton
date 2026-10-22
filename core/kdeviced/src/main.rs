// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kdeviced` — Kotton device daemon.
//!
//! Manages per-user `kuserd` instances and holds the device-layer IPC socket.
//!
//! Socket name is controlled by `KDEVICED_IPC_NAME` (default: `kdeviced`).
//! For dev isolation, set `KDEVICED_IPC_NAME=kdeviced-dev` alongside
//! `KOTTON_BASE_DIR=.kotton.dev` so dev and production sockets never collide.
//! OS-keychain entries scope to the base dir automatically (a non-default
//! base dir gets its own keyring service), so dev secrets — the device
//! operational key included — never touch production's.
//!
//! ```sh
//! KOTTON_BASE_DIR=.kotton.dev KDEVICED_IPC_NAME=kdeviced-dev cargo run -p kdeviced
//! ```

use kdeviced::system::SystemDaemon;
use kotton_sys::ipc::IpcEndpoint;
#[cfg(unix)]
use kotton_common::kdeviced_door;
#[cfg(windows)]
use kotton_common::kdeviced_ipc_name;
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();
    tracing_log::LogTracer::init().ok();
    #[cfg(windows)]
    let endpoint = IpcEndpoint::NamedPipe(kdeviced_ipc_name());
    #[cfg(unix)]
    let endpoint = IpcEndpoint::UnixSocket(
        kdeviced_door().map_err(|e| std::io::Error::other(e.to_string()))?,
    );

    let daemon = SystemDaemon::new(endpoint)?;
    daemon.run().await
}
