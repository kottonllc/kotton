// SPDX-License-Identifier: AGPL-3.0-or-later
//! Discovery method configuration
//!
//! Discovery finds peers, transports connect to them.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use url::Url;

use super::transport::HttpAuth;

/// Discovery method configuration - separate from transport
///
/// Discovery finds peers, transports connect to them.
///
/// There is no mDNS method, and none is meant to return. Naming one would make
/// `DeviceRuntime::start` register `Kotton-<uuid>` on `_kotton._tcp` for the
/// runtime's life — a standing announcement on every network the
/// device was carried onto, which is a join key that composes into a location history.
/// Nothing browsed through it; the runtime only counted it. The local network is reached
/// through the door (`runtime::network::local_door`), which announces only while the
/// person holds it open, under names that change with the day. A
/// config file that still names `MDns` fails to parse rather than announcing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiscoveryMethod {
    /// Distributed Hash Table - P2P discovery across internet
    Dht {
        /// Bootstrap nodes to connect to initially
        bootstrap_nodes: Vec<SocketAddr>,
    },

    /// Bluetooth Low Energy scanning - mobile devices
    BluetoothScan {
        /// How long to scan for devices
        scan_duration_secs: u64,
    },

    /// HTTP rendezvous server - centralized discovery
    HttpRendezvous {
        /// Server URL
        server_url: Url,
        /// Authentication
        auth: Option<HttpAuth>,
    },

    /// Manual discovery - explicit peer list
    Manual {
        /// Known peer addresses
        peers: Vec<SocketAddr>,
    },
}
