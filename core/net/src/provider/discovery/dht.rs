// SPDX-License-Identifier: AGPL-3.0-or-later
//! libp2p DHT-based network discovery
//!
//! Discovers peers using Kademlia DHT for decentralized P2P networks.

use kotton_sys::net::{Address, Discovery, DiscoveryError, DiscoveryResult, Peer};
use libp2p::{
    core::upgrade, futures::StreamExt, identity, kad, noise, swarm::SwarmEvent, yamux, Multiaddr,
    PeerId, StreamProtocol, Swarm, Transport,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

/// DHT-based discovery using libp2p Kademlia.
///
/// Provides decentralized peer discovery for P2P mesh networks.
/// Uses Kademlia DHT to find and track peers without central coordination.
pub struct DhtDiscovery {
    local_peer_id: PeerId,
    peers: Arc<Mutex<HashMap<String, Peer>>>,
    command_tx: mpsc::UnboundedSender<DhtCommand>,
}

enum DhtCommand {
    Bootstrap,
    GetPeers(mpsc::Sender<Vec<Peer>>),
    Shutdown,
}

impl DhtDiscovery {
    /// Create a new DHT discovery instance.
    ///
    /// # Arguments
    ///
    /// * listen_addr - Address to listen on (e.g., "/ip4/0.0.0.0/tcp/0")
    /// * Bootstrap_peers - Initial peers to bootstrap DHT (optional)
    pub async fn new(
        listen_addr: Multiaddr,
        bootstrap_peers: Vec<(PeerId, Multiaddr)>,
    ) -> DiscoveryResult<Self> {
        // Generate local peer identity
        let local_key = identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());

        // Create Kademlia behavior with custom protocol
        let kad_config = kad::Config::new(StreamProtocol::new("/Kotton/kad/1.0.0"));

        let mut kad = kad::Behaviour::with_config(
            local_peer_id,
            kad::store::MemoryStore::new(local_peer_id),
            kad_config,
        );

        // Add bootstrap peers to routing table
        for (peer_id, addr) in bootstrap_peers {
            kad.add_address(&peer_id, addr);
        }

        // Build transport using SwarmBuilder approach (from libp2p examples)
        use libp2p::tcp;

        let transport = tcp::tokio::Transport::default()
            .upgrade(upgrade::Version::V1)
            .authenticate(noise::Config::new(&local_key).map_err(|e| {
                DiscoveryError::Failed(format!("Failed to create noise config: {}", e))
            })?)
            .multiplex(yamux::Config::default())
            .boxed();

        // Build swarm with explicit config
        let swarm = Swarm::new(
            transport,
            kad,
            local_peer_id,
            libp2p::swarm::Config::with_tokio_executor(),
        );

        let peers = Arc::new(Mutex::new(HashMap::new()));
        let (command_tx, command_rx) = mpsc::unbounded_channel();

        // Spawn swarm event loop
        let peers_clone = Arc::clone(&peers);
        tokio::spawn(Self::run_event_loop(
            swarm,
            command_rx,
            peers_clone,
            listen_addr,
        ));

        Ok(Self {
            local_peer_id,
            peers,
            command_tx,
        })
    }

    /// Main event loop for the swarm
    async fn run_event_loop(
        mut swarm: Swarm<kad::Behaviour<kad::store::MemoryStore>>,
        mut command_rx: mpsc::UnboundedReceiver<DhtCommand>,
        peers: Arc<Mutex<HashMap<String, Peer>>>,
        listen_addr: Multiaddr,
    ) {
        // Start listening on the provided address
        if let Err(e) = swarm.listen_on(listen_addr.clone()) {
            eprintln!("DHT: Failed to listen on {}: {}", listen_addr, e);
            return;
        }

        loop {
            tokio::select! {
                // Handle commands
                Some(cmd) = command_rx.recv() => {
                    match cmd {
                        DhtCommand::Bootstrap => {
                            if let Err(e) = swarm.behaviour_mut().bootstrap() {
                                eprintln!("DHT: Bootstrap failed: {:?}", e);
                            } else {
                                println!("DHT: Bootstrap initiated");
                            }
                        }
                        DhtCommand::GetPeers(tx) => {
                            let peers_lock = peers.lock().await;
                            let peer_list = peers_lock.values().cloned().collect();
                            drop(peers_lock); // Release lock before await
                            let _ = tx.send(peer_list).await;
                        }
                        DhtCommand::Shutdown => {
                            println!("DHT: Shutting down");
                            break;
                        }
                    }
                }

                // Handle swarm events
                event = swarm.select_next_some() => {
                    match event {
                        SwarmEvent::Behaviour(kad_event) => {
                            Self::handle_kad_event(kad_event, &peers).await;
                        }
                        SwarmEvent::NewListenAddr { address, .. } => {
                            println!("DHT: Listening on {}", address);
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                            println!("DHT: Connected to {} at {}", peer_id, endpoint.get_remote_address());

                            // Add peer to our list
                            let mut peers_lock = peers.lock().await;
                            peers_lock.insert(
                                peer_id.to_string(),
                                Peer {
                                    id: peer_id.to_string(),
                                    addresses: vec![], // Would extract from endpoint
                                    metadata: HashMap::new(),
                                },
                            );
                        }
                        SwarmEvent::ConnectionClosed { peer_id, .. } => {
                            println!("DHT: Disconnected from {}", peer_id);
                            let mut peers_lock = peers.lock().await;
                            peers_lock.remove(&peer_id.to_string());
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    /// Handle Kademlia-specific events
    async fn handle_kad_event(event: kad::Event, peers: &Arc<Mutex<HashMap<String, Peer>>>) {
        match event {
            kad::Event::RoutingUpdated {
                peer, addresses, ..
            } => {
                println!("DHT: Routing table updated for {}", peer);

                let mut peers_lock = peers.lock().await;

                // Convert Multiaddr to SocketAddr where possible
                let socket_addrs = addresses
                    .iter()
                    .filter_map(Self::multiaddr_to_socketaddr)
                    .collect::<Vec<_>>();

                peers_lock.insert(
                    peer.to_string(),
                    Peer {
                        id: peer.to_string(),
                        addresses: socket_addrs
                            .into_iter()
                            .map(Address::Tcp)
                            .collect(),
                        metadata: HashMap::new(),
                    },
                );
            }
            kad::Event::InboundRequest { request } => {
                println!("DHT: Inbound request: {:?}", request);
            }
            kad::Event::OutboundQueryProgressed { result, .. } => {
                println!("DHT: Query progressed: {:?}", result);
            }
            _ => {}
        }
    }

    /// Convert Multiaddr to SocketAddr (best effort)
    fn multiaddr_to_socketaddr(addr: &Multiaddr) -> Option<std::net::SocketAddr> {
        use libp2p::multiaddr::Protocol;

        let mut ip = None;
        let mut port = None;

        for proto in addr.iter() {
            match proto {
                Protocol::Ip4(addr) => ip = Some(std::net::IpAddr::V4(addr)),
                Protocol::Ip6(addr) => ip = Some(std::net::IpAddr::V6(addr)),
                Protocol::Tcp(p) => port = Some(p),
                _ => {}
            }
        }

        match (ip, port) {
            (Some(ip), Some(port)) => Some(std::net::SocketAddr::new(ip, port)),
            _ => None,
        }
    }

    /// Bootstrap the DHT by querying bootstrap nodes
    pub async fn bootstrap(&self) -> DiscoveryResult<()> {
        self.command_tx.send(DhtCommand::Bootstrap).map_err(|e| {
            DiscoveryError::Failed(format!("Failed to send bootstrap command: {}", e))
        })?;
        Ok(())
    }

    /// Get current peer list (async version)
    pub async fn get_peers_async(&self) -> DiscoveryResult<Vec<Peer>> {
        let (tx, mut rx) = mpsc::channel(1);

        self.command_tx
            .send(DhtCommand::GetPeers(tx))
            .map_err(|e| DiscoveryError::Failed(format!("Failed to request peers: {}", e)))?;

        rx.recv()
            .await
            .ok_or_else(|| DiscoveryError::Failed("Failed to receive peer list".to_string()))
    }

    /// Get local peer ID
    pub fn local_peer_id(&self) -> &PeerId {
        &self.local_peer_id
    }
}

impl Discovery for DhtDiscovery {
    fn discover_peers(&self) -> DiscoveryResult<Vec<Peer>> {
        // For sync trait, return cached peers
        // Caller should use async version for real-time discovery
        let peers_lock = self.peers.blocking_lock();
        Ok(peers_lock.values().cloned().collect())
    }

    fn start_discovery(&self) -> DiscoveryResult<()> {
        // DHT is always running via event loop
        Ok(())
    }

    fn stop_discovery(&self) -> DiscoveryResult<()> {
        let _ = self.command_tx.send(DhtCommand::Shutdown);
        Ok(())
    }
}

impl Drop for DhtDiscovery {
    fn drop(&mut self) {
        let _ = self.command_tx.send(DhtCommand::Shutdown);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dht_discovery_creation() {
        let listen_addr: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
        let discovery = DhtDiscovery::new(listen_addr, vec![]).await;
        assert!(discovery.is_ok());
    }

    #[tokio::test]
    async fn test_dht_get_peers() {
        let listen_addr: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
        let discovery = DhtDiscovery::new(listen_addr, vec![]).await.unwrap();

        // Give it a moment to initialize
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let peers = discovery.get_peers_async().await.unwrap();
        // Initially should have no peers
        assert_eq!(peers.len(), 0);
    }

    #[tokio::test]
    async fn test_dht_bootstrap() {
        let listen_addr: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
        let discovery = DhtDiscovery::new(listen_addr, vec![]).await.unwrap();

        let result = discovery.bootstrap().await;
        // Should succeed even with no bootstrap peers
        assert!(result.is_ok());
    }
}
