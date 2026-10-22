// SPDX-License-Identifier: AGPL-3.0-or-later
//! QUIC transport implementation
//!
//! Implements the Transport trait for QUIC connections with mandatory TLS 1.3.
//! QUIC provides:
//! - Built-in TLS 1.3 (RFC 9000 mandated, not swappable)
//! - 0-RTT and 1-RTT connection establishment
//! - Multiple bidirectional streams per connection
//! - Built-in congestion control
//!
//! # Peer-to-peer connections
//!
//! Use `QuicTransport::new_peer()` for Kotton-to-Kotton device connections.
//! This sets up mutual TLS (mTLS) using the device's Ed25519 identity key, so
//! any unpaired device is rejected at the TLS handshake before it can exchange
//! any messages.

pub mod connection;
pub mod introduced;
pub mod knocked;
pub mod punch;
pub mod tls;

pub use punch::{simultaneous_punch, PunchError, PunchResult, PunchRole};
pub use tls::{
    build_bootstrap_client_config, build_bootstrap_server_config,
    build_peer_client_config, build_peer_rustls_client_config, build_peer_rustls_server_config,
    build_peer_server_config, extract_ed25519_pubkey_from_cert,
    BootstrapCertVerifier, Ed25519DeviceCert, PairedDeviceVerifier,
};

use async_trait::async_trait;
use connection::{QuicConnection, QuicListenerImpl};
use kotton_sys::net::{
    Address, AddressType, Connection, Listener, Transport, TransportCapability, TransportError,
    TransportResult,
};
use quinn::{ClientConfig, Endpoint, ServerConfig};
use std::collections::HashSet;
use std::sync::{Arc, RwLock};

/// QUIC transport with mandatory TLS 1.3.
pub struct QuicTransport {
    server_config: Option<Arc<ServerConfig>>,
    client_config: Arc<ClientConfig>,
}

impl QuicTransport {
    /// Create a client-only QUIC transport with default (permissive) TLS.
    pub fn new() -> Result<Self, TransportError> {
        let client_config = Self::default_client_config()?;
        Ok(Self {
            server_config: None,
            client_config: Arc::new(client_config),
        })
    }

    /// Create a QUIC transport with server support (requires certificates).
    ///
    /// For Kotton peer-to-peer connections, prefer [`QuicTransport::new_peer()`]
    /// which derives the certificate from the device's Ed25519 identity key and
    /// enforces allowlist-based mTLS.
    pub fn with_server(server_config: ServerConfig) -> Result<Self, TransportError> {
        let client_config = Self::default_client_config()?;
        Ok(Self {
            server_config: Some(Arc::new(server_config)),
            client_config: Arc::new(client_config),
        })
    }

    /// Create a QUIC transport for Kotton peer-to-peer connections.
    ///
    /// Both sides of the connection present mTLS certificates derived from their
    /// Ed25519 device identity keys. Only devices whose public key is in
    /// `paired_keys` can complete the TLS handshake.
    ///
    /// `paired_keys` is live — remove a key to revoke access immediately without
    /// restarting the daemon.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let paired = Arc::new(RwLock::new(HashSet::from([remote_pubkey_bytes])));
    /// let transport = QuicTransport::new_peer(&device_signing_key, paired)?;
    /// ```
    pub fn new_peer(
        device_key: &ed25519_dalek::SigningKey,
        paired_keys: Arc<RwLock<HashSet<[u8; 32]>>>,
    ) -> Result<Self, TransportError> {
        Self::new_peer_with_admission(device_key, paired_keys, tls::Admission::default())
    }

    /// As [`QuicTransport::new_peer`], for a node that hosts identities and can therefore
    /// admit a device on proof rather than on a key it was told about (`RFC-0081`).
    pub fn new_peer_with_admission(
        device_key: &ed25519_dalek::SigningKey,
        paired_keys: Arc<RwLock<HashSet<[u8; 32]>>>,
        admission: tls::Admission,
    ) -> Result<Self, TransportError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let device_cert = tls::Ed25519DeviceCert::from_signing_key(device_key)?;
        let verifier = tls::PairedDeviceVerifier::new_with_admission(
            paired_keys,
            admission,
            Arc::clone(&provider),
        );

        let server_config = tls::build_peer_server_config(
            &device_cert,
            Arc::clone(&verifier),
            Arc::clone(&provider),
            None,
        )?;
        let client_config = tls::build_peer_client_config(&device_cert, verifier, provider, None)?;

        Ok(Self {
            server_config: Some(Arc::new(server_config)),
            client_config: Arc::new(client_config),
        })
    }

    /// Create a QUIC transport for the pairing ceremony bootstrap connection.
    ///
    /// Unlike [`QuicTransport::new_peer`], this transport accepts **any**
    /// certificate from the remote peer — it does NOT check the allowlist.
    /// Authentication is handled at the application layer by the ECDH pairing
    /// protocol. Use only for the one-time device-pairing bootstrap step.
    ///
    /// Both sides present their Ed25519 device certificates so each can
    /// extract the other's public key after the TLS handshake.
    pub fn new_bootstrap(device_key: &ed25519_dalek::SigningKey) -> Result<Self, TransportError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let device_cert = tls::Ed25519DeviceCert::from_signing_key(device_key)?;

        let server_config =
            tls::build_bootstrap_server_config(&device_cert, Arc::clone(&provider))?;
        let client_config = tls::build_bootstrap_client_config(&device_cert, provider)?;

        Ok(Self {
            server_config: Some(Arc::new(server_config)),
            client_config: Arc::new(client_config),
        })
    }

    /// Default client config — accepts self-signed certs (used for non-peer connections).
    fn default_client_config() -> Result<ClientConfig, TransportError> {
        let crypto = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();

        let mut config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .map_err(|e| TransportError::ConfigError(e.to_string()))?,
        ));

        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_concurrent_bidi_streams(100u32.into());
        transport_config.max_concurrent_uni_streams(100u32.into());
        config.transport_config(Arc::new(transport_config));

        Ok(config)
    }

    /// Bind a QUIC listener whose UDP socket is first **STUN-probed** against
    /// `relay_stun`, so the returned reflexive address is the one peers will use to
    /// reach this node (RFC-0024 / sprint 07 — the relay subsumes STUN).
    ///
    /// Unlike [`Transport::listen`] (which lets quinn bind its own socket and never
    /// learns a reflexive address), this binds the socket, probes it, then hands the
    /// **same** socket to quinn via `Endpoint::new` — the pattern proven in `punch`.
    /// Returns the listener and the learned reflexive `SocketAddr`.
    pub async fn listen_with_stun(
        &self,
        bind_addr: std::net::SocketAddr,
        relay_stun: std::net::SocketAddr,
    ) -> TransportResult<(Box<dyn Listener>, std::net::SocketAddr)> {
        let server_config = self
            .server_config
            .as_ref()
            .ok_or_else(|| {
                TransportError::ConfigError("Server config required for listening".to_string())
            })?
            .clone();

        // Bind the UDP socket and STUN-probe it against the relay's responder, so the
        // reflexive address is for the *same* socket quinn will accept on.
        let udp = tokio::net::UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        let reflexive = crate::stun::discover(&udp, relay_stun)
            .await
            .map_err(|e| TransportError::ConnectionFailed(format!("STUN discover: {e}")))?;

        // Convert to a non-blocking std socket and build the endpoint from it.
        let std_sock = udp
            .into_std()
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        std_sock
            .set_nonblocking(true)
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        let endpoint = Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config.as_ref().clone()),
            std_sock,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        let actual_addr = endpoint
            .local_addr()
            .map_err(|e| TransportError::ConnectionFailed(format!("local_addr: {e}")))?;

        Ok((
            Box::new(QuicListenerImpl {
                endpoint,
                local_addr: Address::Quic(actual_addr),
            }),
            reflexive,
        ))
    }
}

impl Default for QuicTransport {
    fn default() -> Self {
        Self::new().expect("Failed to create default QuicTransport")
    }
}

#[async_trait]
impl Transport for QuicTransport {
    fn supported_address_types(&self) -> &[AddressType] {
        &[AddressType::Quic]
    }

    fn supports_listening(&self) -> bool {
        self.server_config.is_some()
    }

    async fn connect(&self, address: &Address) -> TransportResult<Box<dyn Connection>> {
        let socket_addr = match address {
            Address::Quic(addr) => addr,
            _ => return Err(TransportError::UnsupportedAddress(address.address_type())),
        };

        // Bind to match the destination — see `transport::bind`. The fixed IPv4
        // wildcard this replaced could not dial an IPv6 peer at all.
        let endpoint = Endpoint::client(crate::transport::outbound_bind_addr(*socket_addr))
            .map_err(|e| TransportError::ConfigError(e.to_string()))?;

        let connection = endpoint
            .connect_with((*self.client_config).clone(), *socket_addr, "localhost")
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        Ok(Box::new(QuicConnection::new(
            connection,
            address.to_string(),
        )))
    }

    async fn listen(&self, bind_addr: &Address) -> TransportResult<Box<dyn Listener>> {
        let socket_addr = match bind_addr {
            Address::Quic(addr) => addr,
            _ => return Err(TransportError::UnsupportedAddress(bind_addr.address_type())),
        };

        let server_config = self
            .server_config
            .as_ref()
            .ok_or_else(|| {
                TransportError::ConfigError("Server config required for listening".to_string())
            })?
            .clone();

        let endpoint = Endpoint::server(server_config.as_ref().clone(), *socket_addr)
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        let actual_addr = endpoint.local_addr().map_err(|e| {
            TransportError::ConnectionFailed(format!("Failed to get local address: {}", e))
        })?;

        Ok(Box::new(QuicListenerImpl {
            endpoint,
            local_addr: Address::Quic(actual_addr),
        }))
    }

    fn detect_capability() -> TransportCapability {
        let test_bind = std::net::UdpSocket::bind("127.0.0.1:0");
        match test_bind {
            Ok(_) => TransportCapability::available()
                .with_metadata("protocol", "QUIC")
                .with_metadata("tls", "1.3 (mandatory)")
                .with_metadata("streams", "multiplexed"),
            Err(e) => {
                TransportCapability::unavailable(format!("Cannot bind UDP socket for QUIC: {}", e))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tls::test_server_config;

    fn init_crypto() {
        use std::sync::Once;
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            rustls::crypto::ring::default_provider()
                .install_default()
                .ok();
        });
    }

    // -----------------------------------------------------------------------
    // Existing transport tests (unchanged behaviour)
    // -----------------------------------------------------------------------

    #[test]
    fn test_quic_transport_creation() {
        init_crypto();
        let transport = QuicTransport::new().unwrap();
        assert_eq!(transport.supported_address_types(), &[AddressType::Quic]);
        assert!(!transport.supports_listening());
    }

    #[test]
    fn test_quic_transport_with_server() {
        init_crypto();
        let server_config = test_server_config().unwrap();
        let transport = QuicTransport::with_server(server_config).unwrap();
        assert!(transport.supports_listening());
    }

    #[test]
    fn test_quic_capability_detection() {
        let cap = QuicTransport::detect_capability();
        assert!(cap.available);
        assert_eq!(cap.metadata.get("protocol"), Some(&"QUIC".to_string()));
        assert_eq!(
            cap.metadata.get("tls"),
            Some(&"1.3 (mandatory)".to_string())
        );
    }

    #[tokio::test]
    async fn test_quic_connect_unsupported_address() {
        init_crypto();
        let transport = QuicTransport::new().unwrap();
        let addr = Address::Tcp("127.0.0.1:8080".parse().unwrap());
        let result = transport.connect(&addr).await;
        assert!(matches!(
            result.err().unwrap(),
            TransportError::UnsupportedAddress(AddressType::Tcp)
        ));
    }

    #[tokio::test]
    async fn test_quic_listen_unsupported_address() {
        init_crypto();
        let server_config = test_server_config().unwrap();
        let transport = QuicTransport::with_server(server_config).unwrap();
        let addr = Address::Bluetooth {
            mac: kotton_sys::net::MacAddress([0; 6]),
            service_uuid: None,
        };
        let result = transport.listen(&addr).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_quic_listen_bind() {
        init_crypto();
        let server_config = test_server_config().unwrap();
        let transport = QuicTransport::with_server(server_config).unwrap();
        // Loopback: this asserts the bind path works, and a wildcard bind here
        // would only add a firewall dialog to every test run (see kotton_peer::scope).
        let addr = Address::Quic("127.0.0.1:0".parse().unwrap());
        let listener = transport.listen(&addr).await.unwrap();
        match listener.local_addr() {
            Address::Quic(socket_addr) => assert!(socket_addr.port() > 0),
            _ => panic!("Expected QUIC address"),
        }
        listener.close().await.unwrap();
    }

    #[tokio::test]
    async fn test_quic_connect_and_send() {
        init_crypto();
        let server_config = test_server_config().unwrap();
        let server_transport = QuicTransport::with_server(server_config).unwrap();
        let listener = server_transport
            .listen(&Address::Quic("127.0.0.1:0".parse().unwrap()))
            .await
            .unwrap();
        let bound_addr = listener.local_addr().clone();
        let accept_handle = tokio::spawn(async move { listener.accept().await });

        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();
        let mut client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap(),
        ));
        let mut tc = quinn::TransportConfig::default();
        tc.max_concurrent_bidi_streams(100u32.into());
        client_config.transport_config(Arc::new(tc));
        let client_transport = QuicTransport {
            server_config: None,
            client_config: Arc::new(client_config),
        };

        let client_conn = client_transport.connect(&bound_addr).await.unwrap();
        let server_conn = accept_handle.await.unwrap().unwrap();

        client_conn.send(b"Hello, QUIC server!").await.unwrap();
        let received = server_conn.receive().await.unwrap();
        assert_eq!(received, b"Hello, QUIC server!");

        server_conn.send(b"Hello, QUIC client!").await.unwrap();
        let received = client_conn.receive().await.unwrap();
        assert_eq!(received, b"Hello, QUIC client!");

        client_conn.close().await.unwrap();
        server_conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn test_quic_large_message() {
        init_crypto();
        let server_config = test_server_config().unwrap();
        let server_transport = QuicTransport::with_server(server_config).unwrap();
        let listener = server_transport
            .listen(&Address::Quic("127.0.0.1:0".parse().unwrap()))
            .await
            .unwrap();
        let bound_addr = listener.local_addr().clone();
        let accept_handle = tokio::spawn(async move { listener.accept().await });

        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();
        let client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap(),
        ));
        let client_transport = QuicTransport {
            server_config: None,
            client_config: Arc::new(client_config),
        };

        let client_conn = client_transport.connect(&bound_addr).await.unwrap();
        let server_conn = accept_handle.await.unwrap().unwrap();

        let large_message = vec![42u8; 1024 * 1024];
        client_conn.send(&large_message).await.unwrap();
        let received = server_conn.receive().await.unwrap();
        assert_eq!(received.len(), large_message.len());

        client_conn.close().await.unwrap();
        server_conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn test_quic_message_too_large() {
        init_crypto();
        let server_config = test_server_config().unwrap();
        let server_transport = QuicTransport::with_server(server_config).unwrap();
        let listener = server_transport
            .listen(&Address::Quic("127.0.0.1:0".parse().unwrap()))
            .await
            .unwrap();
        let bound_addr = listener.local_addr().clone();
        let accept_handle = tokio::spawn(async move { listener.accept().await });

        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();
        let client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap(),
        ));
        let client_transport = QuicTransport {
            server_config: None,
            client_config: Arc::new(client_config),
        };

        let client_conn = client_transport.connect(&bound_addr).await.unwrap();
        let _server_conn = accept_handle.await.unwrap().unwrap();

        use connection::MAX_MESSAGE_SIZE;
        let too_large = vec![0u8; (MAX_MESSAGE_SIZE + 1) as usize];
        let result = client_conn.send(&too_large).await;
        assert!(result.is_err());
        use kotton_sys::net::ConnectionError;
        match result.unwrap_err() {
            ConnectionError::Framing(msg) => assert!(msg.contains("too large")),
            _ => panic!("Expected Framing error"),
        }
    }

    // -----------------------------------------------------------------------
    // Peer mTLS tests — Phase 1 (new)
    // -----------------------------------------------------------------------

    /// Two paired devices can establish a QUIC connection and send a message.
    #[tokio::test]
    async fn test_peer_mtls_paired_devices_connect() {
        init_crypto();
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let key_server = SigningKey::generate(&mut OsRng);
        let key_client = SigningKey::generate(&mut OsRng);

        let server_pubkey = key_server.verifying_key().to_bytes();
        let client_pubkey = key_client.verifying_key().to_bytes();

        // Server knows client; client knows server
        let server_allowlist = Arc::new(RwLock::new(HashSet::from([client_pubkey])));
        let client_allowlist = Arc::new(RwLock::new(HashSet::from([server_pubkey])));

        let server_transport = QuicTransport::new_peer(&key_server, server_allowlist).unwrap();
        let client_transport = QuicTransport::new_peer(&key_client, client_allowlist).unwrap();

        let listener = server_transport
            .listen(&Address::Quic("127.0.0.1:0".parse().unwrap()))
            .await
            .unwrap();
        let bound_addr = listener.local_addr().clone();
        let accept_handle = tokio::spawn(async move { listener.accept().await });

        let client_conn = client_transport.connect(&bound_addr).await.unwrap();
        let server_conn = accept_handle.await.unwrap().unwrap();

        client_conn.send(b"hello from paired client").await.unwrap();
        let msg = server_conn.receive().await.unwrap();
        assert_eq!(msg, b"hello from paired client");

        client_conn.close().await.unwrap();
        server_conn.close().await.unwrap();
    }

    /// Minimal STUN binding responder (IPv4) standing in for the relay's UDP
    /// responder: echo the observed source in an XOR-MAPPED-ADDRESS attribute.
    async fn run_test_stun_responder(sock: tokio::net::UdpSocket) {
        const MAGIC: u32 = 0x2112_A442;
        let mut buf = [0u8; 256];
        loop {
            let (n, src) = match sock.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => return,
            };
            // Binding Request (0x0001), 20-byte header minimum.
            if n < 20 || u16::from_be_bytes([buf[0], buf[1]]) != 0x0001 {
                continue;
            }
            let (ip, port) = match src {
                std::net::SocketAddr::V4(a) => (u32::from(*a.ip()), a.port()),
                _ => continue,
            };
            let mut resp = Vec::with_capacity(32);
            resp.extend_from_slice(&0x0101u16.to_be_bytes()); // Binding Response
            resp.extend_from_slice(&12u16.to_be_bytes()); // attr header (4) + value (8)
            resp.extend_from_slice(&MAGIC.to_be_bytes());
            resp.extend_from_slice(&buf[8..20]); // transaction id
            resp.extend_from_slice(&0x0020u16.to_be_bytes()); // XOR-MAPPED-ADDRESS
            resp.extend_from_slice(&8u16.to_be_bytes());
            resp.push(0); // reserved
            resp.push(0x01); // family IPv4
            resp.extend_from_slice(&(port ^ ((MAGIC >> 16) as u16)).to_be_bytes());
            resp.extend_from_slice(&(ip ^ MAGIC).to_be_bytes());
            let _ = sock.send_to(&resp, src).await;
        }
    }

    /// `listen_with_stun` probes the responder, learns its reflexive address, and
    /// the resulting listener still accepts a paired connection (the accept path is
    /// intact on the STUN-probed socket).
    #[tokio::test]
    async fn test_listen_with_stun_probes_and_accepts() {
        init_crypto();
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let stun_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stun_addr = stun_sock.local_addr().unwrap();
        tokio::spawn(run_test_stun_responder(stun_sock));

        let key_server = SigningKey::generate(&mut OsRng);
        let key_client = SigningKey::generate(&mut OsRng);
        let server_allowlist =
            Arc::new(RwLock::new(HashSet::from([key_client.verifying_key().to_bytes()])));
        let client_allowlist =
            Arc::new(RwLock::new(HashSet::from([key_server.verifying_key().to_bytes()])));

        let server_transport = QuicTransport::new_peer(&key_server, server_allowlist).unwrap();
        let client_transport = QuicTransport::new_peer(&key_client, client_allowlist).unwrap();

        let (listener, reflexive) = server_transport
            .listen_with_stun("127.0.0.1:0".parse().unwrap(), stun_addr)
            .await
            .unwrap();
        // Localhost has no NAT, so the reflexive address is the bound socket itself.
        assert_eq!(reflexive.ip(), std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        assert_ne!(reflexive.port(), 0);

        let bound_addr = listener.local_addr().clone();
        let accept_handle = tokio::spawn(async move { listener.accept().await });

        let client_conn = client_transport.connect(&bound_addr).await.unwrap();
        let server_conn = accept_handle.await.unwrap().unwrap();
        client_conn.send(b"hello via stun-probed listener").await.unwrap();
        let msg = server_conn.receive().await.unwrap();
        assert_eq!(msg, b"hello via stun-probed listener");
        client_conn.close().await.unwrap();
    }

    /// A device NOT in the server's allowlist is rejected — connection unusable.
    ///
    /// In QUIC / TLS 1.3, the server's client-cert verification runs at 1-RTT,
    /// meaning `connect()` may return before the server's TLS alert arrives. We
    /// therefore verify that any attempt to *use* the connection fails promptly.
    #[tokio::test]
    async fn test_peer_mtls_unknown_device_rejected() {
        init_crypto();
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let key_server = SigningKey::generate(&mut OsRng);
        let key_unknown = SigningKey::generate(&mut OsRng);

        let server_pubkey = key_server.verifying_key().to_bytes();

        // Server allowlist is empty — it does not know the connecting client
        let server_allowlist = Arc::new(RwLock::new(HashSet::new()));
        // Client knows the server (server cert will pass client-side check)
        let client_allowlist = Arc::new(RwLock::new(HashSet::from([server_pubkey])));

        let server_transport = QuicTransport::new_peer(&key_server, server_allowlist).unwrap();
        let client_transport = QuicTransport::new_peer(&key_unknown, client_allowlist).unwrap();

        let listener = server_transport
            .listen(&Address::Quic("127.0.0.1:0".parse().unwrap()))
            .await
            .unwrap();
        let bound_addr = listener.local_addr().clone();

        // Server accept task: if a connection comes in and cert verification
        // fails, accept() might itself return an error or return a connection
        // that is immediately closed.
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        // In QUIC 1-RTT, connect() may succeed before the server sends its
        // TLS rejection alert. Try to use the connection — it must fail.
        match client_transport.connect(&bound_addr).await {
            Err(_) => {
                // connect() itself rejected — ideal path
            }
            Ok(conn) => {
                // Connection appeared to open; any use must fail quickly
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                let result = conn.send(b"should be rejected").await;
                assert!(
                    result.is_err(),
                    "Expected send() to fail on rejected mTLS connection"
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Revocation holds on reconnection: no session is resumed past the allowlist
    // -----------------------------------------------------------------------

    /// Answer every message on every connection `listener` admits with the message itself.
    fn echo(listener: Box<dyn Listener>) {
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok(conn) => {
                        tokio::spawn(async move {
                            while let Ok(msg) = conn.receive().await {
                                if conn.send(&msg).await.is_err() {
                                    return;
                                }
                            }
                        });
                    }
                    Err(TransportError::ListenerClosed) => return,
                    Err(_) => continue,
                }
            }
        });
    }

    /// Whether `transport` can dial `addr` and have a message answered on the connection.
    ///
    /// A server that refuses the client's certificate does so after the client has finished
    /// its half of the handshake, so `connect()` alone can succeed; the answer is the proof.
    /// It also arrives after any ticket the server issued, so a client that dialled once and
    /// was answered holds whatever it would need to resume.
    async fn answered(transport: &QuicTransport, addr: &Address) -> bool {
        let Ok(conn) = transport.connect(addr).await else {
            return false;
        };
        if conn.send(b"ping").await.is_err() {
            return false;
        }
        let reply = tokio::time::timeout(std::time::Duration::from_secs(5), conn.receive()).await;
        let answered = matches!(reply, Ok(Ok(ref m)) if m == b"ping");
        let _ = conn.close().await;
        answered
    }

    /// A paired listener and dialler, built as every peer is: the listener echoes, and both
    /// allowlists stay live in the test's hands.
    struct Paired {
        dialler: QuicTransport,
        addr: Address,
        listener_allows: Arc<RwLock<HashSet<[u8; 32]>>>,
        dialler_allows: Arc<RwLock<HashSet<[u8; 32]>>>,
        listener_key: [u8; 32],
        dialler_key: [u8; 32],
    }

    async fn paired() -> Paired {
        init_crypto();
        let listener_sk = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
        let dialler_sk = ed25519_dalek::SigningKey::from_bytes(&[6u8; 32]);
        let listener_key = listener_sk.verifying_key().to_bytes();
        let dialler_key = dialler_sk.verifying_key().to_bytes();
        let listener_allows = Arc::new(RwLock::new(HashSet::from([dialler_key])));
        let dialler_allows = Arc::new(RwLock::new(HashSet::from([listener_key])));
        let listening = QuicTransport::new_peer(&listener_sk, Arc::clone(&listener_allows)).unwrap();
        let dialler = QuicTransport::new_peer(&dialler_sk, Arc::clone(&dialler_allows)).unwrap();
        let listener = listening
            .listen(&Address::Quic("127.0.0.1:0".parse().unwrap()))
            .await
            .unwrap();
        let addr = listener.local_addr().clone();
        echo(listener);
        Paired {
            dialler,
            addr,
            listener_allows,
            dialler_allows,
            listener_key,
            dialler_key,
        }
    }

    /// A device the listener revokes after answering it is refused when it dials again, with
    /// the same transport that held the first connection and anything it was issued there.
    #[tokio::test]
    async fn a_revoked_device_is_refused_when_it_reconnects() {
        let p = paired().await;

        assert!(answered(&p.dialler, &p.addr).await, "a paired device is answered");
        p.listener_allows.write().unwrap().remove(&p.dialler_key);
        assert!(
            !answered(&p.dialler, &p.addr).await,
            "a revoked device is refused on reconnection"
        );
    }

    /// A device that revokes the listener it dialled refuses it on the next dial, though that
    /// listener answered it before.
    #[tokio::test]
    async fn a_revoked_listener_is_refused_when_its_peer_reconnects() {
        let p = paired().await;

        assert!(answered(&p.dialler, &p.addr).await, "a paired listener answers");
        p.dialler_allows.write().unwrap().remove(&p.listener_key);
        assert!(
            !answered(&p.dialler, &p.addr).await,
            "a revoked listener is refused on reconnection"
        );
    }

    // -----------------------------------------------------------------------
    // Test helper: skip TLS certificate verification (existing tests only)
    // -----------------------------------------------------------------------

    #[derive(Debug)]
    struct SkipServerVerification;

    impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ED25519,
            ]
        }
    }
}
