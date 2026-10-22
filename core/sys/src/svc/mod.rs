// SPDX-License-Identifier: AGPL-3.0-or-later
//! Service lifecycle management abstraction
//!
//! This trait defines the interface for managing long-running Kotton services
//! (daemons, MCP servers, etc.). 
//!
//! Currently, services are implemented as OS processes. In a future Kotton OS,
//! these would become native processes managed by the Process abstraction.

use anyhow::Result;
use std::future::Future;

/// Service lifecycle management
///
/// Implementations are responsible for their own lifecycle - starting,
/// stopping, checking status, etc. This allows domain-specific implementations
/// (e.g., daemon uses IPC for shutdown, MCP might use HTTP).
///
/// In a future Kotton OS, services implementing this trait would be
/// scheduled by the kernel Process abstraction.
pub trait Service: Sync {
    /// Short name for the service (e.g., "daemon", "mcp")
    fn name(&self) -> &str;

    /// Human-readable description
    fn description(&self) -> &str;

    /// Start the service
    fn start(
        &self,
        username: Option<String>,
        config: Option<String>,
        foreground: bool,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Stop the service
    fn stop(&self) -> impl Future<Output = Result<()>> + Send;

    /// Restart the service
    fn restart(
        &self,
        username: Option<String>,
        config: Option<String>,
        foreground: bool,
    ) -> impl Future<Output = Result<()>> + Send
    where
        Self: Sized,
    {
        async move {
            let _ = self.stop().await;
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            self.start(username, config, foreground).await
        }
    }

    /// Get service status
    fn status(&self) -> impl Future<Output = Result<ServiceStatus>> + Send;

    /// Check if service is running
    fn is_running(&self) -> impl Future<Output = bool> + Send
    where
        Self: Sized,
    {
        async move { self.status().await.map(|s| s.running).unwrap_or(false) }
    }
}

/// Service status information
#[derive(Debug, Clone)]
pub struct ServiceStatus {
    pub name: String,
    pub running: bool,
    pub responsive: bool,
    pub message: Option<String>,
}
