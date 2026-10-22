// SPDX-License-Identifier: AGPL-3.0-or-later
//! WebRTC transport stub
//!
//! Placeholder implementation for WebRTC data channels.
//! Returns unavailable() until proper implementation is added in future milestone.
//!
//! Future implementation will support:
//! - Peer-to-peer data channels
//! - ICE candidate exchange
//! - STUN/TURN server integration
//! - Signaling via WebSocket or HTTP
//! - Browser compatibility

use async_trait::async_trait;
use kotton_sys::net::{
    Address, AddressType, Connection, Listener, Transport, TransportCapability, TransportError,
    TransportResult,
};

/// WebRTC data channel transport (stub - not yet implemented)
///
/// This is a placeholder that returns unavailable() for all operations.
/// Validates the Transport abstraction for WebRTC addressing (ICE candidates).
///
/// # Future Implementation
///
/// Will use webrtc-rs or similar WebRTC stack:
/// - ICE candidate gathering and exchange
/// - STUN server for NAT traversal
/// - Optional TURN server for relay
/// - Signaling server for peer discovery
/// - Data channel API for bidirectional communication
///
/// Will support:
/// - Browser-to-server communication
/// - Peer-to-peer NAT traversal
/// - Multiple simultaneous data channels
/// - Low-latency real-time communication
pub struct WebRtcTransport;

impl WebRtcTransport {
    /// Create a new WebRTC transport (always unavailable for now)
    pub fn new() -> Self {
        Self
    }
}

impl Default for WebRtcTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Transport for WebRtcTransport {
    fn supported_address_types(&self) -> &[AddressType] {
        &[AddressType::WebRtc]
    }

    fn supports_listening(&self) -> bool {
        false // Will be true once implemented (via signaling server)
    }

    async fn connect(&self, address: &Address) -> TransportResult<Box<dyn Connection>> {
        match address {
            Address::WebRtc { .. } => Err(TransportError::Unavailable(
                "WebRTC transport not yet implemented".to_string(),
            )),
            _ => Err(TransportError::UnsupportedAddress(address.address_type())),
        }
    }

    async fn listen(&self, _bind_addr: &Address) -> TransportResult<Box<dyn Listener>> {
        Err(TransportError::Unavailable(
            "WebRTC transport not yet implemented".to_string(),
        ))
    }

    fn detect_capability() -> TransportCapability {
        // TODO: Detect WebRTC stack availability
        // - Check if webrtc-rs or libwebrtc is available
        // - Validate signaling server connectivity
        // - Test STUN server reachability
        TransportCapability::unavailable("WebRTC transport not yet implemented")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotton_sys::net::IceCandidate;
    use url::Url;

    #[test]
    fn test_webrtc_transport_creation() {
        let transport = WebRtcTransport::new();
        assert_eq!(transport.supported_address_types(), &[AddressType::WebRtc]);
        assert!(!transport.supports_listening());
    }

    #[test]
    fn test_webrtc_capability_detection() {
        let cap = WebRtcTransport::detect_capability();
        assert!(!cap.available, "Stub should be unavailable");
        assert!(cap.reason.as_ref().unwrap().contains("not yet implemented"));
    }

    #[tokio::test]
    async fn test_webrtc_connect_unavailable() {
        let transport = WebRtcTransport::new();
        let addr = Address::WebRtc {
            ice_candidates: vec![IceCandidate {
                candidate: "candidate:1 1 UDP 2130706431 192.168.1.1 54321 typ host".to_string(),
                sdp_mid: Some("0".to_string()),
                sdp_m_line_index: Some(0),
            }],
            signaling_url: Url::parse("wss://signal.example.com").unwrap(),
        };

        let result = transport.connect(&addr).await;
        assert!(result.is_err());
        if let Err(TransportError::Unavailable(msg)) = result {
            assert!(msg.contains("not yet implemented"));
        } else {
            panic!("Expected Unavailable error");
        }
    }

    #[tokio::test]
    async fn test_webrtc_listen_unavailable() {
        let transport = WebRtcTransport::new();
        let addr = Address::WebRtc {
            ice_candidates: vec![],
            signaling_url: Url::parse("wss://signal.example.com").unwrap(),
        };

        let result = transport.listen(&addr).await;
        assert!(result.is_err());
        if let Err(TransportError::Unavailable(msg)) = result {
            assert!(msg.contains("not yet implemented"));
        } else {
            panic!("Expected Unavailable error");
        }
    }

    #[tokio::test]
    async fn test_webrtc_unsupported_address() {
        let transport = WebRtcTransport::new();
        let addr = Address::Tcp("127.0.0.1:8080".parse().unwrap());

        let result = transport.connect(&addr).await;
        assert!(result.is_err());
        if let Err(TransportError::UnsupportedAddress(addr_type)) = result {
            assert_eq!(addr_type, AddressType::Tcp);
        } else {
            panic!("Expected UnsupportedAddress error");
        }
    }
}
