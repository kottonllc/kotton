// SPDX-License-Identifier: AGPL-3.0-or-later
//! Network discovery abstraction
//!
//! Provides platform-independent peer discovery primitives.

use super::address::Address;
use std::collections::HashMap;
use thiserror::Error;

pub type DiscoveryResult<T> = Result<T, DiscoveryError>;

#[derive(Error, Debug)]
pub enum DiscoveryError {
    #[error("Discovery failed: {0}")]
    Failed(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Invalid peer data: {0}")]
    InvalidPeer(String),

    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

/// Discovered peer on the network
#[derive(Debug, Clone)]
pub struct Peer {
    /// Unique identifier for this peer
    pub id: String,

    /// Network addresses where this peer can be reached
    ///
    /// Changed from `Vec<SocketAddr>` to `Vec<Address>` to support heterogeneous transports.
    /// A peer might be reachable via TCP, Bluetooth, and WebRTC simultaneously.
    pub addresses: Vec<Address>,

    /// Arbitrary metadata about this peer (device type, capabilities, etc.)
    pub metadata: HashMap<String, String>,
}

/// Network discovery trait (read-only).
///
/// Find peers on the network using various mechanisms:
/// - mDNS/Bonjour (local network)
/// - DHT (P2P networks)
/// - Bluetooth scanning
/// - Cloud rendezvous servers
pub trait Discovery: Send + Sync {
    /// Discover peers on the network.
    ///
    /// Returns a list of discovered peers. May block for a discovery period.
    fn discover_peers(&self) -> DiscoveryResult<Vec<Peer>>;

    /// Start continuous discovery (optional).
    ///
    /// Some discovery mechanisms benefit from continuous scanning.
    /// Default implementation does nothing.
    fn start_discovery(&self) -> DiscoveryResult<()> {
        Ok(())
    }

    /// Stop continuous discovery (optional).
    fn stop_discovery(&self) -> DiscoveryResult<()> {
        Ok(())
    }
}

/// Network advertising trait (write-only).
///
/// Announce your presence on the network with metadata.
/// Separate from Discovery to support asymmetric protocols.
pub trait Advertiser: Send + Sync {
    /// Start advertising presence on the network.
    ///
    /// # Arguments
    /// * `service_name` - Unique identifier for this service instance
    /// * `port` - Port this service is listening on
    /// * `metadata` - Key-value metadata (device name, pairing code, capabilities, etc.)
    fn start_advertising(
        &self,
        service_name: String,
        port: u16,
        metadata: HashMap<String, String>,
    ) -> DiscoveryResult<()>;

    /// Update advertised metadata.
    ///
    /// Useful for changing pairing codes, status, etc. without restarting advertising.
    fn update_metadata(&self, metadata: HashMap<String, String>) -> DiscoveryResult<()>;

    /// Stop advertising.
    fn stop_advertising(&self) -> DiscoveryResult<()>;
}
