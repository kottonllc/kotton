// SPDX-License-Identifier: AGPL-3.0-or-later
//! Windows network monitoring via Network List Manager API

use async_trait::async_trait;
use kotton_sys::net::{
    NetworkMonitor, NetworkMonitorResult, NetworkTopology, NetworkType,
};
use windows::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
use windows::Win32::NetworkManagement::IpHelper::{GetAdaptersInfo, IP_ADAPTER_INFO};

/// Windows network monitor using Win32 APIs
pub struct WindowsNetworkMonitor {
    last_topology: Option<NetworkTopology>,
}

impl WindowsNetworkMonitor {
    pub fn new() -> Self {
        Self {
            last_topology: None,
        }
    }

    /// Detect network type using adapter information
    #[allow(unsafe_code)]
    fn detect_network_type(&self) -> NetworkType {
        unsafe {
            let mut buf_len = 0u32;

            // First call to get buffer size
            let result = GetAdaptersInfo(None, &mut buf_len);

            if result != ERROR_BUFFER_OVERFLOW.0 && result != 0 {
                return NetworkType::Unknown;
            }

            // Allocate buffer and get adapter info
            let mut buffer = vec![0u8; buf_len as usize];
            let adapter_info = buffer.as_mut_ptr() as *mut IP_ADAPTER_INFO;

            if GetAdaptersInfo(Some(adapter_info), &mut buf_len) != 0 {
                return NetworkType::Unknown;
            }

            // Check first active adapter
            let adapter = &*adapter_info;

            // Convert i8 array to u8 for UTF-8 processing
            let description_bytes: Vec<u8> = adapter
                .Description
                .iter()
                .take_while(|&&b| b != 0)
                .map(|&b| b as u8)
                .collect();
            let description = String::from_utf8_lossy(&description_bytes);

            // Heuristic: Check adapter description for type
            if description.to_lowercase().contains("wireless")
                || description.to_lowercase().contains("wi-fi")
            {
                NetworkType::WiFi
            } else if description.to_lowercase().contains("cellular")
                || description.to_lowercase().contains("mobile")
            {
                NetworkType::Cellular
            } else if description.to_lowercase().contains("ethernet") {
                NetworkType::Ethernet
            } else {
                NetworkType::Unknown
            }
        }
    }
}

impl Default for WindowsNetworkMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NetworkMonitor for WindowsNetworkMonitor {
    async fn get_topology(&self) -> NetworkMonitorResult<NetworkTopology> {
        let network_type = self.detect_network_type();

        // TODO: Detect metered connection via NetworkInformation API
        // TODO: Detect trusted network via Network Location Awareness
        // TODO: Estimate bandwidth from adapter speed

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
