// SPDX-License-Identifier: AGPL-3.0-or-later
//! Linux network monitoring via sysfs and procfs

use async_trait::async_trait;
use kotton_sys::net::{
    NetworkMonitor, NetworkMonitorResult, NetworkTopology, NetworkType,
};
use std::fs;
use std::path::Path;

/// Linux network monitor using /sys/class/net
pub struct LinuxNetworkMonitor {
    last_topology: Option<NetworkTopology>,
}

impl LinuxNetworkMonitor {
    pub fn new() -> Self {
        Self {
            last_topology: None,
        }
    }

    /// Detect network type by checking interface types in /sys/class/net
    fn detect_network_type(&self) -> NetworkType {
        let net_path = Path::new("/sys/class/net");
        
        if !net_path.exists() {
            return NetworkType::Unknown;
        }
        
        // Read network interfaces
        let Ok(entries) = fs::read_dir(net_path) else {
            return NetworkType::Unknown;
        };
        
        for entry in entries.flatten() {
            let iface_name = entry.file_name();
            let iface_str = iface_name.to_string_lossy();
            
            // Skip loopback
            if iface_str == "lo" {
                continue;
            }
            
            // Check if interface is up
            let operstate_path = entry.path().join("operstate");
            if let Ok(state) = fs::read_to_string(&operstate_path) {
                if state.trim() != "up" {
                    continue;
                }
            }
            
            // Detect type by interface name prefix (common conventions)
            if iface_str.starts_with("wl") || iface_str.starts_with("wlan") {
                return NetworkType::WiFi;
            } else if iface_str.starts_with("eth") || iface_str.starts_with("en") {
                // Could be WiFi or Ethernet - check wireless directory
                let wireless_path = entry.path().join("wireless");
                if wireless_path.exists() {
                    return NetworkType::WiFi;
                } else {
                    return NetworkType::Ethernet;
                }
            } else if iface_str.starts_with("ww") || iface_str.starts_with("usb") {
                // Mobile broadband
                return NetworkType::Cellular;
            }
        }
        
        NetworkType::Unknown
    }
}

impl Default for LinuxNetworkMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NetworkMonitor for LinuxNetworkMonitor {
    async fn get_topology(&self) -> NetworkMonitorResult<NetworkTopology> {
        let network_type = self.detect_network_type();
        
        // TODO: Read /proc/net/route to determine default gateway
        // TODO: Check for metered connection hints (harder on Linux)
        // TODO: Read speed from /sys/class/net/*/speed
        
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
            if last.network_type != current.network_type ||
               last.is_metered != current.is_metered {
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
