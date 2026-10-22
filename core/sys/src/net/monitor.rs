// SPDX-License-Identifier: AGPL-3.0-or-later
//! Network monitoring abstraction
//!
//! Platform-independent interface for detecting network topology changes.
//! OS-specific implementations live in providers/network.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Network topology information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkTopology {
    /// Type of network connection
    pub network_type: NetworkType,
    
    /// Whether we're on a trusted network (home, work)
    pub is_trusted: bool,
    
    /// Whether we're on a metered connection (cellular)
    pub is_metered: bool,
    
    /// Estimated bandwidth (Mbps, None if unknown)
    pub bandwidth_mbps: Option<u32>,
}

/// Type of network connection
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum NetworkType {
    /// WiFi connection
    WiFi,
    
    /// Cellular/mobile data
    Cellular,
    
    /// Wired ethernet
    Ethernet,
    
    /// Offline/no connection
    Offline,
    
    /// Unknown connection type
    Unknown,
}

/// Errors from network monitoring
#[derive(Debug, Error)]
pub enum NetworkMonitorError {
    /// Platform-specific error
    #[error("Platform error: {0}")]
    Platform(String),
    
    /// Permission denied
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    
    /// Not supported on this platform
    #[error("Not supported on this platform")]
    NotSupported,
}

pub type NetworkMonitorResult<T> = Result<T, NetworkMonitorError>;

/// Network monitor - Detects network topology changes
///
/// Platform-specific implementations:
/// - Windows: Network List Manager API
/// - macOS: SystemConfiguration framework
/// - Linux: NetworkManager D-Bus
/// - Mobile: Platform connectivity APIs
#[async_trait]
pub trait NetworkMonitor: Send + Sync {
    /// Get current network topology
    async fn get_topology(&self) -> NetworkMonitorResult<NetworkTopology>;
    
    /// Check if topology has changed since last check
    ///
    /// Returns Some(new_topology) if changed, None if unchanged.
    async fn detect_change(&mut self) -> NetworkMonitorResult<Option<NetworkTopology>>;
}
