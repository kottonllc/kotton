// SPDX-License-Identifier: AGPL-3.0-or-later
//! Transport configuration types
//!
//! Each variant corresponds to a specific Transport implementation.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use url::Url;

/// Transport configuration - each variant corresponds to a specific Transport implementation
///
/// Separates transport configuration from discovery configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransportConfig {
    /// TCP transport with TLS
    Tcp {
        listen_addr: SocketAddr,
        tls: TlsConfig,
    },

    /// QUIC transport (UDP-based, multiplexed, built-in TLS 1.3)
    Quic {
        listen_addr: SocketAddr,
        /// Use ephemeral self-signed certs (true) or load from secrets store (false)
        ephemeral: bool,
        /// Key ID in secrets store (only used if ephemeral = false)
        cert_key_id: Option<String>,
    },

    /// WebSocket transport (HTTP/HTTPS upgrade)
    WebSocket {
        /// Listen address for server mode (None = client-only)
        listen_addr: Option<SocketAddr>,
        /// Endpoint URL for client mode
        endpoint: Option<Url>,
        /// HTTP authentication
        auth: Option<HttpAuth>,
    },

    /// Bluetooth Low Energy transport (mobile devices)
    Bluetooth {
        /// Service UUID for BLE advertising/scanning
        service_uuid: String,
        /// Adapter name (None = default adapter)
        adapter: Option<String>,
    },

    /// WebRTC transport (browser clients, NAT traversal)
    WebRtc {
        /// STUN servers for ICE candidate gathering
        stun_servers: Vec<Url>,
        /// TURN servers for relaying when P2P fails
        turn_servers: Vec<TurnServer>,
        /// Signaling server URL
        signaling_url: Url,
    },
}

/// TLS configuration for mutual authentication
///
/// Both client and server present certificates to establish identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to certificate file (None = auto-generate self-signed)
    pub cert_path: Option<PathBuf>,

    /// Path to private key file (None = auto-generate)
    pub key_path: Option<PathBuf>,

    /// Require client certificate for mutual TLS (default: true)
    #[serde(default = "default_require_client_cert")]
    pub require_client_cert: bool,
}

fn default_require_client_cert() -> bool {
    true
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cert_path: None, // Auto-generate
            key_path: None,  // Auto-generate
            require_client_cert: true,
        }
    }
}

/// HTTP authentication for WebSocket
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HttpAuth {
    /// Bearer token authentication
    Bearer { token: String },
    /// Basic authentication (username + password)
    Basic { username: String, password: String },
}

/// TURN server configuration for WebRTC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnServer {
    /// TURN server URL (turn: or turns:)
    pub url: Url,
    /// Username for TURN authentication
    pub username: String,
    /// Credential for TURN authentication
    pub credential: String,
}
