// SPDX-License-Identifier: AGPL-3.0-or-later
//! Static peer discovery from configuration
//!
//! Discovers peers from a pre-configured list. Useful for:
//! - Testing and development
//! - Cloud deployments with known endpoints
//! - Bootstrap nodes for P2P networks

use kotton_sys::net::{Address, Discovery, DiscoveryResult, Peer};
use std::collections::HashMap;
use std::net::SocketAddr;

/// Static discovery provider with pre-configured peers.
///
/// Returns a fixed list of peers. Useful for testing, cloud deployments,
/// and as bootstrap nodes for other discovery mechanisms.
pub struct StaticDiscovery {
    peers: Vec<Peer>,
}

impl StaticDiscovery {
    /// Create a new static discovery with a list of peers.
    pub fn new(peers: Vec<Peer>) -> Self {
        Self { peers }
    }

    /// Create from a list of addresses.
    ///
    /// Convenience method to create peers from socket addresses.
    pub fn from_addresses(addresses: Vec<SocketAddr>) -> Self {
        let peers = addresses
            .into_iter()
            .map(|addr| Peer {
                id: addr.to_string(),
                addresses: vec![Address::Tcp(addr)],
                metadata: HashMap::new(),
            })
            .collect();

        Self { peers }
    }

    /// Add a peer to the static list.
    pub fn add_peer(&mut self, peer: Peer) {
        self.peers.push(peer);
    }

    /// Remove a peer by ID.
    pub fn remove_peer(&mut self, peer_id: &str) {
        self.peers.retain(|p| p.id != peer_id);
    }
}

impl Discovery for StaticDiscovery {
    fn discover_peers(&self) -> DiscoveryResult<Vec<Peer>> {
        Ok(self.peers.clone())
    }

    fn start_discovery(&self) -> DiscoveryResult<()> {
        // Static discovery is always "running"
        Ok(())
    }

    fn stop_discovery(&self) -> DiscoveryResult<()> {
        // Nothing to stop
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_discovery_empty() {
        let discovery = StaticDiscovery::new(vec![]);
        let peers = discovery.discover_peers().unwrap();
        assert!(peers.is_empty());
    }

    #[test]
    fn test_static_discovery_with_peers() {
        let peer1 = Peer {
            id: "peer1".to_string(),
            addresses: vec![Address::Tcp("127.0.0.1:8080".parse().unwrap())],
            metadata: HashMap::new(),
        };
        let peer2 = Peer {
            id: "peer2".to_string(),
            addresses: vec![Address::Tcp("127.0.0.1:8081".parse().unwrap())],
            metadata: HashMap::new(),
        };

        let discovery = StaticDiscovery::new(vec![peer1.clone(), peer2.clone()]);
        let peers = discovery.discover_peers().unwrap();

        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].id, "peer1");
        assert_eq!(peers[1].id, "peer2");
    }

    #[test]
    fn test_from_addresses() {
        let addresses = vec![
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.1:8081".parse().unwrap(),
        ];

        let discovery = StaticDiscovery::from_addresses(addresses);
        let peers = discovery.discover_peers().unwrap();

        assert_eq!(peers.len(), 2);
        assert!(peers[0].id.contains("127.0.0.1:8080"));
        assert!(peers[1].id.contains("127.0.0.1:8081"));
    }

    #[test]
    fn test_add_remove_peer() {
        let mut discovery = StaticDiscovery::new(vec![]);

        let peer = Peer {
            id: "test-peer".to_string(),
            addresses: vec![Address::Tcp("127.0.0.1:8080".parse().unwrap())],
            metadata: HashMap::new(),
        };

        discovery.add_peer(peer);
        assert_eq!(discovery.discover_peers().unwrap().len(), 1);

        discovery.remove_peer("test-peer");
        assert_eq!(discovery.discover_peers().unwrap().len(), 0);
    }
}
