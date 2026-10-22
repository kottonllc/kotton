// SPDX-License-Identifier: AGPL-3.0-or-later
/// Daemon error types
use thiserror::Error;

/// Errors that can occur during daemon operations
#[derive(Error, Debug)]
pub enum DaemonError {
    /// IPC communication error
    #[error("IPC error: {0}")]
    Ipc(#[from] kotton_sys::ipc::IpcError),

    /// Path or file system error
    #[error("Path error: {0}")]
    Path(#[from] std::io::Error),

    /// Generic daemon error
    #[error("{0}")]
    Other(String),
}

impl From<anyhow::Error> for DaemonError {
    fn from(err: anyhow::Error) -> Self {
        DaemonError::Other(err.to_string())
    }
}

/// Result type for daemon operations
pub type Result<T> = std::result::Result<T, DaemonError>;
