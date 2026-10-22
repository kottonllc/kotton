// SPDX-License-Identifier: AGPL-3.0-or-later
//! macOS network monitoring via SystemConfiguration framework

use async_trait::async_trait;
use core_foundation::string::CFString;
use kotton_sys::net::{
    NetworkMonitor, NetworkMonitorResult, NetworkTopology, NetworkType,
};
use system_configuration::dynamic_store::SCDynamicStoreBuilder;

/// macOS network monitor using SystemConfiguration framework
pub struct MacOSNetworkMonitor {
    last_topology: Option<NetworkTopology>,
}

impl MacOSNetworkMonitor {
    pub fn new() -> Self {
        Self {
            last_topology: None,
        }
    }

    /// Detect network type using SystemConfiguration
    fn detect_network_type(&self) -> NetworkType {
        let store = SCDynamicStoreBuilder::new("Kotton-monitor").build();

        // Check for WiFi interface (en0 typically)
        let wifi_key = CFString::new("State:/Network/Interface/en0/IPv4");
        if store.get(wifi_key).is_some() {
            return NetworkType::WiFi;
        }

        // Check for Ethernet (en1 or en2 typically)
        let ethernet_key = CFString::new("State:/Network/Interface/en1/IPv4");
        if store.get(ethernet_key).is_some() {
            return NetworkType::Ethernet;
        }

        // TODO: Check for cellular via pdp_ip0 interface

        NetworkType::Unknown
    }
}

impl Default for MacOSNetworkMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NetworkMonitor for MacOSNetworkMonitor {
    async fn get_topology(&self) -> NetworkMonitorResult<NetworkTopology> {
        let network_type = self.detect_network_type();

        // TODO: Check network service priority for trust
        // TODO: Detect metered via specific service flags
        // TODO: Get bandwidth from interface properties

        Ok(NetworkTopology {
            network_type,
            is_trusted: false, // Conservative default
            is_metered: network_type == NetworkType::Cellular,
            bandwidth_mbps: None,
        })
    }

    async fn detect_change(&mut self) -> NetworkMonitorResult<Option<NetworkTopology>> {
        let current = self.get_topology().await?;

        if let Some(ref last) = self.last_topology {
            if last.network_type != current.network_type || last.is_metered != current.is_metered {
                self.last_topology = Some(current.clone());
                return Ok(Some(current));
            }
        } else {
            self.last_topology = Some(current.clone());
            return Ok(Some(current));
        }

        Ok(None)
    }
}
