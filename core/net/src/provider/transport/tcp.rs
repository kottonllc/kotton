// SPDX-License-Identifier: AGPL-3.0-or-later
//! TCP transport implementation
//!
//! Implements the Transport trait for TCP connections with TLS support.

use async_trait::async_trait;
use kotton_sys::net::{
    Address, AddressType, Connection, ConnectionError, ConnectionQuality, ConnectionResult,
    Listener, Transport, TransportCapability, TransportError, TransportResult,
};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream as TokioTcpStream};
use tokio::sync::Mutex;

/// TCP transport with TLS support
pub struct TcpTransport {
    tls_config: Option<TlsConfig>,
}

/// TLS configuration for TCP transport
#[derive(Debug, Clone)]
pub struct TlsConfig {
    // TODO: Integrate with Kotton-platform SecretsStore
    // For now, placeholder for TLS configuration
}

impl TcpTransport {
    /// Create a new TCP transport without TLS
    pub fn new() -> Self {
        Self { tls_config: None }
    }

    /// Create a new TCP transport with TLS
    pub fn with_tls(tls_config: TlsConfig) -> Self {
        Self {
            tls_config: Some(tls_config),
        }
    }
}

impl Default for TcpTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Transport for TcpTransport {
    fn supported_address_types(&self) -> &[AddressType] {
        &[AddressType::Tcp]
    }

    fn supports_listening(&self) -> bool {
        true
    }

    async fn connect(&self, address: &Address) -> TransportResult<Box<dyn Connection>> {
        let socket_addr = match address {
            Address::Tcp(addr) => addr,
            _ => return Err(TransportError::UnsupportedAddress(address.address_type())),
        };

        // Connect directly via tokio
        let stream = TokioTcpStream::connect(*socket_addr)
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        // TODO: Wrap in TLS if tls_config is Some
        let connection = TcpConnection::new(stream, address.to_string());

        Ok(Box::new(connection))
    }

    async fn listen(&self, bind_addr: &Address) -> TransportResult<Box<dyn Listener>> {
        let socket_addr = match bind_addr {
            Address::Tcp(addr) => addr,
            _ => return Err(TransportError::UnsupportedAddress(bind_addr.address_type())),
        };

        // Bind directly via tokio
        let listener = TokioTcpListener::bind(*socket_addr)
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        // Get the actual bound address (important for ephemeral ports)
        let actual_addr = listener
            .local_addr()
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        let tcp_listener = TcpListenerImpl {
            inner: listener,
            local_addr: Address::Tcp(actual_addr),
            tls_config: self.tls_config.clone(),
        };

        Ok(Box::new(tcp_listener))
    }

    fn detect_capability() -> TransportCapability {
        // Try binding to ephemeral port to verify TCP works
        let runtime = tokio::runtime::Handle::try_current();

        if runtime.is_err() {
            return TransportCapability::unavailable("No tokio runtime available");
        }

        // Simple check: Can we bind to any port?
        let test_bind = std::net::TcpListener::bind("127.0.0.1:0");

        match test_bind {
            Ok(_) => TransportCapability::available()
                .with_metadata("protocol", "TCP")
                .with_metadata("tls", "supported"),
            Err(e) => TransportCapability::unavailable(format!("Cannot bind TCP socket: {}", e)),
        }
    }
}

/// TCP connection wrapper (implements Connection trait)
struct TcpConnection {
    stream: Arc<Mutex<TokioTcpStream>>,
    peer_id: String,
}

/// Maximum message size (10 MB)
const MAX_MESSAGE_SIZE: u32 = 10 * 1024 * 1024;

impl TcpConnection {
    fn new(stream: TokioTcpStream, peer_id: String) -> Self {
        Self {
            stream: Arc::new(Mutex::new(stream)),
            peer_id,
        }
    }
}

#[async_trait]
impl Connection for TcpConnection {
    async fn send(&self, message: &[u8]) -> ConnectionResult<()> {
        let len = message.len() as u32;
        if len > MAX_MESSAGE_SIZE {
            return Err(ConnectionError::Framing(format!(
                "Message too large: {} bytes (max {})",
                len, MAX_MESSAGE_SIZE
            )));
        }

        let mut stream = self.stream.lock().await;

        // Write length prefix (4 bytes, big-endian)
        stream.write_u32(len).await?;

        // Write message
        stream.write_all(message).await?;
        stream.flush().await?;

        Ok(())
    }

    async fn receive(&self) -> ConnectionResult<Vec<u8>> {
        let mut stream = self.stream.lock().await;

        // Read length prefix (4 bytes, big-endian)
        let len = stream.read_u32().await?;

        if len > MAX_MESSAGE_SIZE {
            return Err(ConnectionError::Framing(format!(
                "Message too large: {} bytes (max {})",
                len, MAX_MESSAGE_SIZE
            )));
        }

        // Read message
        let mut buffer = vec![0u8; len as usize];
        stream.read_exact(&mut buffer).await?;

        Ok(buffer)
    }

    async fn send_stream(
        &self,
        stream_in: &mut (dyn tokio::io::AsyncRead + Send + Unpin),
    ) -> ConnectionResult<u64> {
        let mut stream = self.stream.lock().await;
        tokio::io::copy(stream_in, &mut *stream)
            .await
            .map_err(ConnectionError::Io)
    }

    async fn receive_stream(
        &self,
        sink: &mut (dyn tokio::io::AsyncWrite + Send + Unpin),
    ) -> ConnectionResult<u64> {
        let mut stream = self.stream.lock().await;
        tokio::io::copy(&mut *stream, sink)
            .await
            .map_err(ConnectionError::Io)
    }

    async fn close(&self) -> ConnectionResult<()> {
        let mut stream = self.stream.lock().await;
        stream.shutdown().await?;
        Ok(())
    }

    fn peer_id(&self) -> &str {
        &self.peer_id
    }

    fn quality(&self) -> ConnectionQuality {
        ConnectionQuality::default()
    }

    fn transport_type(&self) -> AddressType {
        AddressType::Tcp
    }
}

/// TCP listener wrapper (implements Listener trait)
struct TcpListenerImpl {
    inner: TokioTcpListener,
    local_addr: Address,
    // TLS support planned for M5 — field reserved
    #[allow(dead_code)]
    tls_config: Option<TlsConfig>,
}

#[async_trait]
impl Listener for TcpListenerImpl {
    async fn accept(&self) -> TransportResult<Box<dyn Connection>> {
        let (stream, addr) = self
            .inner
            .accept()
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        // TODO: Wrap in TLS if tls_config is Some
        let connection = TcpConnection::new(stream, addr.to_string());

        Ok(Box::new(connection))
    }

    fn local_addr(&self) -> &Address {
        &self.local_addr
    }

    async fn close(&self) -> TransportResult<()> {
        // Tokio TcpListener doesn't have explicit close - it's closed on drop
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_transport_creation() {
        let transport = TcpTransport::new();
        assert_eq!(transport.supported_address_types(), &[AddressType::Tcp]);
        assert!(transport.supports_listening());
    }

    #[test]
    fn test_tcp_transport_default() {
        let transport = TcpTransport::default();
        assert!(transport.tls_config.is_none());
    }

    #[tokio::test]
    async fn test_tcp_capability_detection() {
        let cap = TcpTransport::detect_capability();
        assert!(cap.available, "TCP should be available");
        assert_eq!(cap.metadata.get("protocol"), Some(&"TCP".to_string()));
    }

    #[tokio::test]
    async fn test_tcp_connect_unsupported_address() {
        let transport = TcpTransport::new();
        let addr = Address::Udp("127.0.0.1:8080".parse().unwrap());

        let result = transport.connect(&addr).await;
        assert!(result.is_err());
        assert!(matches!(
            result.err().unwrap(),
            TransportError::UnsupportedAddress(AddressType::Udp)
        ));
    }

    #[tokio::test]
    async fn test_tcp_listen_unsupported_address() {
        let transport = TcpTransport::new();
        let addr = Address::Bluetooth {
            mac: kotton_sys::net::MacAddress([0; 6]),
            service_uuid: None,
        };

        let result = transport.listen(&addr).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tcp_listen_bind() {
        let transport = TcpTransport::new();
        let addr = Address::Tcp("127.0.0.1:0".parse().unwrap()); // Loopback, ephemeral port

        let result = transport.listen(&addr).await;
        assert!(result.is_ok(), "Should be able to bind a loopback listener");

        let listener = result.unwrap();
        // Verify local address is set (port will be different due to ephemeral)
        match listener.local_addr() {
            Address::Tcp(socket_addr) => {
                assert!(socket_addr.port() > 0, "Should have ephemeral port");
            }
            _ => panic!("Expected TCP address"),
        }
    }

    #[tokio::test]
    async fn test_tcp_connect_and_send() {
        let transport = TcpTransport::new();

        // Start listener
        let listener_addr = Address::Tcp("127.0.0.1:0".parse().unwrap());
        let listener = transport.listen(&listener_addr).await.unwrap();

        // Bound on loopback, so the listener's own address is dialable as-is.
        let bound_addr = listener.local_addr().clone();
        assert!(matches!(bound_addr, Address::Tcp(_)), "Expected TCP address");

        // Spawn accept task
        let accept_handle = tokio::spawn(async move { listener.accept().await });

        // Connect from client
        let client_conn = transport.connect(&bound_addr).await.unwrap();

        // Accept connection
        let server_conn = accept_handle.await.unwrap().unwrap();

        // Send message from client to server
        let message = b"Hello, server!";
        client_conn.send(message).await.unwrap();

        // Receive on server
        let received = server_conn.receive().await.unwrap();
        assert_eq!(received, message);

        // Send response from server to client
        let response = b"Hello, client!";
        server_conn.send(response).await.unwrap();

        // Receive on client
        let received = client_conn.receive().await.unwrap();
        assert_eq!(received, response);

        // Close connections
        client_conn.close().await.unwrap();
        server_conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn test_tcp_large_message() {
        let transport = TcpTransport::new();

        // Start listener
        let listener_addr = Address::Tcp("127.0.0.1:0".parse().unwrap());
        let listener = transport.listen(&listener_addr).await.unwrap();

        // Bound on loopback, so the listener's own address is dialable as-is.
        let bound_addr = listener.local_addr().clone();
        assert!(matches!(bound_addr, Address::Tcp(_)), "Expected TCP address");

        let accept_handle = tokio::spawn(async move { listener.accept().await });

        let client_conn = transport.connect(&bound_addr).await.unwrap();
        let server_conn = accept_handle.await.unwrap().unwrap();

        // Send 1MB message — run send and receive concurrently.
        // Sequential send-then-receive deadlocks on macOS: its default TCP
        // kernel buffer (~128 KB) fills up before receive() starts reading,
        // blocking send() forever.
        let large_message = vec![42u8; 1024 * 1024];
        let (send_res, recv_res) = tokio::join!(
            client_conn.send(&large_message),
            server_conn.receive()
        );
        send_res.unwrap();
        let received = recv_res.unwrap();
        assert_eq!(received.len(), large_message.len());
        assert_eq!(received, large_message);

        client_conn.close().await.unwrap();
        server_conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn test_tcp_message_too_large() {
        let transport = TcpTransport::new();

        let listener_addr = Address::Tcp("127.0.0.1:0".parse().unwrap());
        let listener = transport.listen(&listener_addr).await.unwrap();

        // Bound on loopback, so the listener's own address is dialable as-is.
        let bound_addr = listener.local_addr().clone();
        assert!(matches!(bound_addr, Address::Tcp(_)), "Expected TCP address");

        let accept_handle = tokio::spawn(async move { listener.accept().await });

        let client_conn = transport.connect(&bound_addr).await.unwrap();
        let _server_conn = accept_handle.await.unwrap().unwrap();

        // Try to send message larger than MAX_MESSAGE_SIZE (10 MB)
        let too_large = vec![0u8; (MAX_MESSAGE_SIZE + 1) as usize];
        let result = client_conn.send(&too_large).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ConnectionError::Framing(msg) => {
                assert!(msg.contains("too large"));
            }
            _ => panic!("Expected Framing error"),
        }
    }
}
