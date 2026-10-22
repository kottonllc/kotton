// SPDX-License-Identifier: AGPL-3.0-or-later
//! Universal addressing for heterogeneous transports
//!
//! Different transport protocols use different addressing schemes:
//! - TCP/UDP: IP address + port (SocketAddr)
//! - Bluetooth: MAC address + optional service UUID
//! - HTTP(S): URL with optional authentication
//! - WebRTC: ICE candidates + signaling server URL
//!
//! The `Address` enum provides a unified type that can represent any of these.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::SocketAddr;
use url::Url;
use uuid::Uuid;

/// Universal address type for all transport protocols
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Address {
    /// TCP socket address (IPv4 or IPv6)
    Tcp(SocketAddr),

    /// UDP socket address (IPv4 or IPv6)
    Udp(SocketAddr),

    /// QUIC socket address (runs over UDP)
    Quic(SocketAddr),

    /// Bluetooth MAC address with optional service UUID
    Bluetooth {
        mac: MacAddress,
        service_uuid: Option<Uuid>,
    },

    /// HTTP(S) endpoint with optional authentication
    Http { url: Url, auth: Option<HttpAuth> },

    /// WebSocket URL with optional authentication
    WebSocket { url: Url, auth: Option<HttpAuth> },

    /// WebRTC peer with ICE candidates and signaling channel
    WebRtc {
        ice_candidates: Vec<IceCandidate>,
        signaling_url: Url,
    },
}

impl Address {
    /// Get the address type
    pub fn address_type(&self) -> AddressType {
        match self {
            Self::Tcp(_) => AddressType::Tcp,
            Self::Udp(_) => AddressType::Udp,
            Self::Quic(_) => AddressType::Quic,
            Self::Bluetooth { .. } => AddressType::Bluetooth,
            Self::Http { .. } => AddressType::Http,
            Self::WebSocket { .. } => AddressType::WebSocket,
            Self::WebRtc { .. } => AddressType::WebRtc,
        }
    }

    /// Check if this is an IP-based address (TCP, UDP, QUIC)
    pub fn is_ip_based(&self) -> bool {
        matches!(self, Self::Tcp(_) | Self::Udp(_) | Self::Quic(_))
    }

    /// Check if this address requires internet connectivity
    pub fn requires_internet(&self) -> bool {
        match self {
            Self::Bluetooth { .. } => false, // Local only
            _ => true,
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp(addr) => write!(f, "tcp://{}", addr),
            Self::Udp(addr) => write!(f, "udp://{}", addr),
            Self::Quic(addr) => write!(f, "quic://{}", addr),
            Self::Bluetooth { mac, service_uuid } => {
                if let Some(uuid) = service_uuid {
                    write!(f, "bluetooth://{}?service={}", mac, uuid)
                } else {
                    write!(f, "bluetooth://{}", mac)
                }
            }
            Self::Http { url, .. } => write!(f, "{}", url),
            Self::WebSocket { url, .. } => write!(f, "{}", url),
            Self::WebRtc { signaling_url, .. } => {
                write!(f, "webrtc://{}", signaling_url)
            }
        }
    }
}

/// Address type discriminator
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressType {
    Tcp,
    Udp,
    Quic,
    Bluetooth,
    Http,
    WebSocket,
    WebRtc,
}

impl fmt::Display for AddressType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
            Self::Quic => write!(f, "QUIC"),
            Self::Bluetooth => write!(f, "Bluetooth"),
            Self::Http => write!(f, "HTTP"),
            Self::WebSocket => write!(f, "WebSocket"),
            Self::WebRtc => write!(f, "WebRTC"),
        }
    }
}

/// Bluetooth MAC address (6 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MacAddress(pub [u8; 6]);

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl std::str::FromStr for MacAddress {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return Err(format!(
                "Invalid MAC address format: expected 6 parts, got {}",
                parts.len()
            ));
        }

        let mut bytes = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            bytes[i] = u8::from_str_radix(part, 16)
                .map_err(|e| format!("Invalid hex byte '{}': {}", part, e))?;
        }

        Ok(MacAddress(bytes))
    }
}

/// HTTP authentication credentials
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HttpAuth {
    /// Bearer token authentication
    Bearer { token: String },

    /// Basic authentication (username + password)
    Basic { username: String, password: String },
}

/// WebRTC ICE candidate
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IceCandidate {
    /// Candidate string (SDP format)
    pub candidate: String,

    /// SDP media stream identification
    pub sdp_mid: Option<String>,

    /// SDP media stream index
    pub sdp_m_line_index: Option<u16>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_address() {
        let addr = Address::Tcp("127.0.0.1:8080".parse().unwrap());
        assert_eq!(addr.address_type(), AddressType::Tcp);
        assert!(addr.is_ip_based());
        assert_eq!(addr.to_string(), "tcp://127.0.0.1:8080");
    }

    #[test]
    fn test_quic_address() {
        let addr = Address::Quic("192.168.1.1:7735".parse().unwrap());
        assert_eq!(addr.address_type(), AddressType::Quic);
        assert!(addr.is_ip_based());
        assert_eq!(addr.to_string(), "quic://192.168.1.1:7735");
    }

    #[test]
    fn test_bluetooth_address() {
        let mac = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let addr = Address::Bluetooth {
            mac,
            service_uuid: None,
        };
        assert_eq!(addr.address_type(), AddressType::Bluetooth);
        assert!(!addr.is_ip_based());
        assert!(!addr.requires_internet());
        assert_eq!(addr.to_string(), "bluetooth://AA:BB:CC:DD:EE:FF");
    }

    #[test]
    fn test_bluetooth_with_service_uuid() {
        let mac = MacAddress([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let uuid = Uuid::parse_str("00001101-0000-1000-8000-00805F9B34FB").unwrap();
        let addr = Address::Bluetooth {
            mac,
            service_uuid: Some(uuid),
        };
        assert!(addr.to_string().contains("service="));
    }

    #[test]
    fn test_http_address() {
        let url = Url::parse("https://api.example.com/Kotton").unwrap();
        let addr = Address::Http {
            url,
            auth: Some(HttpAuth::Bearer {
                token: "secret123".to_string(),
            }),
        };
        assert_eq!(addr.address_type(), AddressType::Http);
        assert!(addr.requires_internet());
    }

    #[test]
    fn test_websocket_address() {
        let url = Url::parse("wss://ws.example.com/Kotton").unwrap();
        let addr = Address::WebSocket { url, auth: None };
        assert_eq!(addr.address_type(), AddressType::WebSocket);
    }

    #[test]
    fn test_webrtc_address() {
        let ice = IceCandidate {
            candidate: "candidate:1 1 UDP 2130706431 192.168.1.1 54321 typ host".to_string(),
            sdp_mid: Some("0".to_string()),
            sdp_m_line_index: Some(0),
        };
        let signaling = Url::parse("wss://signal.example.com").unwrap();
        let addr = Address::WebRtc {
            ice_candidates: vec![ice],
            signaling_url: signaling,
        };
        assert_eq!(addr.address_type(), AddressType::WebRtc);
    }

    #[test]
    fn test_mac_address_display() {
        let mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(mac.to_string(), "00:11:22:33:44:55");
    }

    #[test]
    fn test_mac_address_parse() {
        let mac: MacAddress = "AA:BB:CC:DD:EE:FF".parse().unwrap();
        assert_eq!(mac.0, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_mac_address_parse_error() {
        let result: Result<MacAddress, _> = "AA:BB:CC".parse();
        assert!(result.is_err());

        let result: Result<MacAddress, _> = "ZZ:BB:CC:DD:EE:FF".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_address_type_display() {
        assert_eq!(AddressType::Tcp.to_string(), "TCP");
        assert_eq!(AddressType::Bluetooth.to_string(), "Bluetooth");
        assert_eq!(AddressType::WebRtc.to_string(), "WebRTC");
    }
}
