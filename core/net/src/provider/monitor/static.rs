// SPDX-License-Identifier: AGPL-3.0-or-later
//! Static network monitor - Always reports the same topology
//!
//! Useful for:
//! - Development/testing
//! - Servers with stable network config
//! - Environments where dynamic detection isn't needed

use async_trait::async_trait;
use kotton_sys::net::{
    NetworkMonitor, NetworkMonitorResult, NetworkTopology, NetworkType,
};

/// Static network monitor that always reports configured topology
pub struct StaticNetworkMonitor {
    topology: NetworkTopology,
}

impl StaticNetworkMonitor {
    /// Create new static monitor with default topology
    pub fn new() -> Self {
        Self {
            topology: NetworkTopology {
                network_type: NetworkType::WiFi,
                is_trusted: true,
                is_metered: false,
                bandwidth_mbps: Some(100),
            },
        }
    }

    /// Create static monitor with custom topology
    pub fn with_topology(topology: NetworkTopology) -> Self {
        Self { topology }
    }
}

impl Default for StaticNetworkMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NetworkMonitor for StaticNetworkMonitor {
    async fn get_topology(&self) -> NetworkMonitorResult<NetworkTopology> {
        Ok(self.topology.clone())
    }

    async fn detect_change(&mut self) -> NetworkMonitorResult<Option<NetworkTopology>> {
        // Static monitor never changes
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_static_monitor() {
        let mut monitor = StaticNetworkMonitor::new();
        
        let topology = monitor.get_topology().await.unwrap();
        assert_eq!(topology.network_type, NetworkType::WiFi);
        assert!(topology.is_trusted);
        
        // Should never report changes
        let change = monitor.detect_change().await.unwrap();
        assert!(change.is_none());
    }

    #[tokio::test]
    async fn test_custom_topology() {
        let custom = NetworkTopology {
            network_type: NetworkType::Cellular,
            is_trusted: false,
            is_metered: true,
            bandwidth_mbps: Some(10),
        };
        
        let monitor = StaticNetworkMonitor::with_topology(custom.clone());
        let topology = monitor.get_topology().await.unwrap();
        
        assert_eq!(topology.network_type, NetworkType::Cellular);
        assert!(topology.is_metered);
    }
}
