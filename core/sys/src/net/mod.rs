// SPDX-License-Identifier: AGPL-3.0-or-later
//! Network abstraction
//!
//! Provides platform-independent network primitives:
//! - Address: Universal addressing for all transports (address.rs)
//! - Transport: Connection establishment abstraction (transport.rs)
//! - Connection: Encrypted P2P communication channels (connection.rs)
//! - Discovery: Peer discovery mechanisms (discovery.rs)
//! - Monitor: Network topology detection (monitor.rs)
//! - UDP: Datagram-oriented sockets (future)
//! - DNS: Hostname resolution (future)

pub mod address;
pub mod connection;
pub mod discovery;
pub mod monitor;
pub mod transport;

pub use address::{Address, AddressType, HttpAuth, IceCandidate, MacAddress};
pub use connection::{Connection, ConnectionError, ConnectionQuality, ConnectionResult, RequestHandler};
pub use discovery::{Advertiser, Discovery, DiscoveryError, DiscoveryResult, Peer};
pub use monitor::{
    NetworkMonitor, NetworkMonitorError, NetworkMonitorResult, NetworkTopology, NetworkType,
};
pub use transport::{Listener, Transport, TransportCapability, TransportError, TransportResult};
