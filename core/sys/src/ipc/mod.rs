// SPDX-License-Identifier: AGPL-3.0-or-later
//! Inter-Process Communication abstraction
//!
//! Provides local process communication via:
//! - Unix domain sockets (Unix/macOS)
//! - Named pipes (Windows)
//!
//! Platform provides byte stream traits only. Services handle message framing and serialization.

use async_trait::async_trait;
use thiserror::Error;

#[cfg(unix)]
use std::path::PathBuf;

/// Errors that can occur during IPC operations
#[derive(Debug, Error)]
pub enum IpcError {
    /// Failed to connect to IPC endpoint
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    /// Failed to bind/create IPC listener
    #[error("Bind failed: {0}")]
    BindFailed(String),

    /// I/O operation failed
    #[error("I/O error: {0}")]
    IoError(String),

    /// Permission denied
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Endpoint not found
    #[error("Not found: {0}")]
    NotFound(String),

    /// Connection closed
    #[error("Connection closed")]
    ConnectionClosed,
}

/// Result type for IPC operations
pub type IpcResult<T> = Result<T, IpcError>;

/// IPC connection endpoint specification
#[derive(Debug, Clone)]
pub enum IpcEndpoint {
    /// Unix domain socket path
    #[cfg(unix)]
    UnixSocket(PathBuf),
    /// Windows named pipe name (e.g., "kotton-daemon")
    #[cfg(windows)]
    NamedPipe(String),
}

/// Trait for IPC connections (byte streams)
///
/// Implementations provide platform-specific local connections:
/// - Unix: Unix domain sockets
/// - Windows: Named pipes
#[async_trait]
pub trait Connection: Send + Sync {
    /// Read data into buffer
    ///
    /// Returns the number of bytes read, or 0 if connection closed
    async fn read(&mut self, buf: &mut [u8]) -> IpcResult<usize>;

    /// Write data from buffer
    ///
    /// Returns the number of bytes written
    async fn write(&mut self, buf: &[u8]) -> IpcResult<usize>;

    /// Shutdown the connection
    async fn shutdown(&mut self) -> IpcResult<()>;
}

/// A boxed connection is a connection.
///
/// So a holder can name *"a channel"* without naming its transport. `SurfaceProxy`
/// is the case that wanted it: it keeps one end of a handed channel and has no
/// business knowing whether the halves underneath are a `socketpair` or two pipes
/// — and without this it had to know, because the type of a field cannot be
/// `#[cfg]`-ed without every method that touches it being `#[cfg]`-ed too.
#[async_trait]
impl Connection for Box<dyn Connection> {
    async fn read(&mut self, buf: &mut [u8]) -> IpcResult<usize> {
        (**self).read(buf).await
    }

    async fn write(&mut self, buf: &[u8]) -> IpcResult<usize> {
        (**self).write(buf).await
    }

    async fn shutdown(&mut self) -> IpcResult<()> {
        (**self).shutdown().await
    }
}

/// Trait for IPC listeners (accept incoming connections)
#[async_trait]
pub trait Listener: Send + Sync {
    /// Accept a new incoming connection
    ///
    /// Returns a boxed Connection
    async fn accept(&self) -> IpcResult<Box<dyn Connection>>;

    /// Get the endpoint this listener is bound to
    fn endpoint(&self) -> &IpcEndpoint;
}
