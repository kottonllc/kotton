// SPDX-License-Identifier: AGPL-3.0-or-later
//! Discovery instantiation helpers
//!
//! Handles creating and configuring discovery implementations from DiscoveryMethod.

use crate::config::DiscoveryMethod;
use anyhow::Result;
use kotton_sys::net::Discovery;
use kotton_diag::{Event, EventBus, EventCategory, EventLevel};
use std::sync::Arc;

/// Instantiate a discovery mechanism from configuration
pub async fn instantiate_discovery(
    discovery_method: &DiscoveryMethod,
    event_bus: &Arc<EventBus>,
) -> Result<Box<dyn Discovery>> {
    match discovery_method {
        DiscoveryMethod::Dht { bootstrap_nodes: _bootstrap_nodes } => {
            use kotton_net::DhtDiscovery;

            // TODO: Convert bootstrap_nodes (SocketAddr) to (PeerId, Multiaddr) format
            // For now, use default listen address and empty bootstrap list
            let listen_addr = "/ip4/0.0.0.0/tcp/0".parse().unwrap();
            let discovery = DhtDiscovery::new(listen_addr, vec![])
                .await
                .map_err(|e| anyhow::anyhow!("Failed to create DHT discovery: {}", e))?;

            event_bus
                .publish(Event::new(
                    EventCategory::Network,
                    EventLevel::Info,
                    "DHT discovery initialized".to_string(),
                ))
                .ok();

            Ok(Box::new(discovery) as Box<dyn Discovery>)
        }

        DiscoveryMethod::BluetoothScan {
            scan_duration_secs: _,
        } => {
            // TODO: Implement BluetoothDiscovery when Bluetooth transport is complete
            // For now, return error as stub
            event_bus
                .publish(Event::new(
                    EventCategory::Network,
                    EventLevel::Warn,
                    "Bluetooth discovery not yet implemented".to_string(),
                ))
                .ok();

            anyhow::bail!("BluetoothScan discovery not yet implemented")
        }

        DiscoveryMethod::HttpRendezvous {
            server_url,
            auth: _,
        } => {
            // TODO: Implement HttpRendezvousDiscovery for cloud-based rendezvous
            // For now, return error as stub
            event_bus
                .publish(Event::new(
                    EventCategory::Network,
                    EventLevel::Warn,
                    format!(
                        "HTTP Rendezvous discovery not yet implemented (server: {})",
                        server_url
                    ),
                ))
                .ok();

            anyhow::bail!("HttpRendezvous discovery not yet implemented")
        }

        DiscoveryMethod::Manual { peers } => {
            use kotton_sys::net::Peer;
            use kotton_net::StaticDiscovery;

            // Convert SocketAddr peers to Peer structs
            let peer_list: Vec<Peer> = peers
                .iter()
                .map(|addr| Peer {
                    id: addr.to_string(),
                    addresses: vec![kotton_sys::net::Address::Tcp(*addr)],
                    metadata: std::collections::HashMap::new(),
                })
                .collect();

            let discovery = StaticDiscovery::new(peer_list);

            event_bus
                .publish(Event::new(
                    EventCategory::Network,
                    EventLevel::Info,
                    format!(
                        "Manual/static discovery initialized with {} peers",
                        peers.len()
                    ),
                ))
                .ok();

            Ok(Box::new(discovery) as Box<dyn Discovery>)
        }
    }
}
