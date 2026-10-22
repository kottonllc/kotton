// SPDX-License-Identifier: AGPL-3.0-or-later
//! WebSocket transport implementation
//!
//! Implements the Transport trait for WebSocket connections.
//! WebSocket provides:
//! - Browser compatibility (runs in WASM)
//! - Firewall-friendly (runs over HTTP/HTTPS ports 80/443)
//! - Bidirectional full-duplex communication
//! - Text and binary message framing

use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use kotton_sys::net::{
    Address, AddressType, Connection, ConnectionError, ConnectionQuality, ConnectionResult,
    Listener, Transport, TransportCapability, TransportError, TransportResult,
};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_tungstenite::{accept_async, connect_async, WebSocketStream};
use url::Url;

/// WebSocket transport supporting ws:// and wss:// protocols
pub struct WebSocketTransport {
    supports_server: bool,
}

impl WebSocketTransport {
    /// Create a new WebSocket transport (client-only)
    pub fn new() -> Self {
        Self {
            supports_server: false,
        }
    }

    /// Create a WebSocket transport with server support
    pub fn with_server() -> Self {
        Self {
            supports_server: true,
        }
    }

    /// Convert Address to URL for WebSocket client
    fn address_to_url(address: &Address) -> TransportResult<Url> {
        match address {
            Address::WebSocket { url, .. } => Ok(url.clone()),
            _ => Err(TransportError::UnsupportedAddress(address.address_type())),
        }
    }
}

impl Default for WebSocketTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Transport for WebSocketTransport {
    fn supported_address_types(&self) -> &[AddressType] {
        &[AddressType::WebSocket]
    }

    fn supports_listening(&self) -> bool {
        self.supports_server
    }

    async fn connect(&self, address: &Address) -> TransportResult<Box<dyn Connection>> {
        let url = Self::address_to_url(address)?;

        // For now, we'll connect without auth headers (TODO: add auth support via custom request)
        // Connect to WebSocket server
        let (ws_stream, _) = connect_async(url.as_str())
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        let connection = WebSocketConnection::new(ws_stream, address.to_string());
        Ok(Box::new(connection))
    }

    async fn listen(&self, bind_addr: &Address) -> TransportResult<Box<dyn Listener>> {
        if !self.supports_server {
            return Err(TransportError::ListeningNotSupported);
        }

        // Extract socket address from WebSocket URL
        let url = match bind_addr {
            Address::WebSocket { url, .. } => url,
            _ => return Err(TransportError::UnsupportedAddress(bind_addr.address_type())),
        };

        // Parse host and port from URL
        let host = url.host_str().ok_or_else(|| {
            TransportError::ConfigError("Missing host in WebSocket URL".to_string())
        })?;
        let port = url
            .port()
            .unwrap_or(if url.scheme() == "wss" { 443 } else { 80 });

        let bind_socket = format!("{}:{}", host, port);
        let tcp_listener = TcpListener::bind(&bind_socket)
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        let actual_addr = tcp_listener
            .local_addr()
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        // Build WebSocket URL from actual bound address
        let scheme = if url.scheme() == "wss" { "wss" } else { "ws" };
        let ws_url = Url::parse(&format!("{}://{}", scheme, actual_addr))
            .map_err(|e| TransportError::ConfigError(e.to_string()))?;

        let listener = WebSocketListenerImpl {
            tcp_listener,
            local_addr: Address::WebSocket {
                url: ws_url,
                auth: None,
            },
        };

        Ok(Box::new(listener))
    }

    fn detect_capability() -> TransportCapability {
        // WebSocket requires TCP support
        let test_bind = std::net::TcpListener::bind("127.0.0.1:0");

        match test_bind {
            Ok(_) => TransportCapability::available()
                .with_metadata("protocol", "WebSocket")
                .with_metadata("schemes", "ws, wss")
                .with_metadata("browser", "compatible"),
            Err(e) => TransportCapability::unavailable(format!(
                "Cannot bind TCP socket for WebSocket: {}",
                e
            )),
        }
    }
}

/// WebSocket connection wrapper
struct WebSocketConnection<S> {
    stream: Arc<Mutex<WebSocketStream<S>>>,
    peer_id: String,
}

impl<S> WebSocketConnection<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    fn new(stream: WebSocketStream<S>, peer_id: String) -> Self {
        Self {
            stream: Arc::new(Mutex::new(stream)),
            peer_id,
        }
    }
}

#[async_trait]
impl<S> Connection for WebSocketConnection<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    async fn send(&self, message: &[u8]) -> ConnectionResult<()> {
        use tokio_tungstenite::tungstenite::Message;

        let mut stream = self.stream.lock().await;
        stream
            .send(Message::Binary(message.to_vec()))
            .await
            .map_err(|e| ConnectionError::Io(std::io::Error::other(e)))?;

        Ok(())
    }

    async fn receive(&self) -> ConnectionResult<Vec<u8>> {
        use tokio_tungstenite::tungstenite::Message;

        let mut stream = self.stream.lock().await;

        loop {
            match stream.next().await {
                Some(Ok(Message::Binary(data))) => return Ok(data),
                Some(Ok(Message::Text(text))) => return Ok(text.into_bytes()),
                Some(Ok(Message::Close(_))) => {
                    return Err(ConnectionError::Closed);
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {
                    // Auto-handled by tungstenite, continue waiting for data
                    continue;
                }
                Some(Err(e)) => {
                    return Err(ConnectionError::Io(std::io::Error::other(e)));
                }
                None => {
                    return Err(ConnectionError::Closed);
                }
                _ => continue,
            }
        }
    }

    async fn send_stream(
        &self,
        stream_in: &mut (dyn tokio::io::AsyncRead + Send + Unpin),
    ) -> ConnectionResult<u64> {
        use tokio::io::AsyncReadExt;
        use tokio_tungstenite::tungstenite::Message;

        let mut ws = self.stream.lock().await;
        let mut total_bytes = 0u64;
        let mut buffer = vec![0u8; 64 * 1024]; // 64KB chunks

        loop {
            let n = stream_in
                .read(&mut buffer)
                .await
                .map_err(ConnectionError::Io)?;

            if n == 0 {
                break; // EOF
            }

            ws.send(Message::Binary(buffer[..n].to_vec()))
                .await
                .map_err(|e| ConnectionError::Io(std::io::Error::other(e)))?;

            total_bytes += n as u64;
        }

        Ok(total_bytes)
    }

    async fn receive_stream(
        &self,
        sink: &mut (dyn tokio::io::AsyncWrite + Send + Unpin),
    ) -> ConnectionResult<u64> {
        use tokio::io::AsyncWriteExt;
        use tokio_tungstenite::tungstenite::Message;

        let mut ws = self.stream.lock().await;
        let mut total_bytes = 0u64;

        loop {
            match ws.next().await {
                Some(Ok(Message::Binary(data))) => {
                    sink.write_all(&data)
                        .await
                        .map_err(ConnectionError::Io)?;
                    total_bytes += data.len() as u64;
                }
                Some(Ok(Message::Close(_))) | None => {
                    break;
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {
                    continue;
                }
                Some(Err(e)) => {
                    return Err(ConnectionError::Io(std::io::Error::other(e)));
                }
                _ => continue,
            }
        }

        sink.flush().await.map_err(ConnectionError::Io)?;
        Ok(total_bytes)
    }

    async fn close(&self) -> ConnectionResult<()> {
        use tokio_tungstenite::tungstenite::Message;

        let mut stream = self.stream.lock().await;
        stream
            .send(Message::Close(None))
            .await
            .map_err(|e| ConnectionError::Io(std::io::Error::other(e)))?;

        Ok(())
    }

    fn peer_id(&self) -> &str {
        &self.peer_id
    }

    fn quality(&self) -> ConnectionQuality {
        ConnectionQuality::default()
    }

    fn transport_type(&self) -> AddressType {
        AddressType::WebSocket
    }
}

/// WebSocket listener wrapper
struct WebSocketListenerImpl {
    tcp_listener: TcpListener,
    local_addr: Address,
}

#[async_trait]
impl Listener for WebSocketListenerImpl {
    async fn accept(&self) -> TransportResult<Box<dyn Connection>> {
        let (tcp_stream, addr) = self
            .tcp_listener
            .accept()
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        let ws_stream = accept_async(tcp_stream)
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        let connection = WebSocketConnection::new(ws_stream, addr.to_string());
        Ok(Box::new(connection))
    }

    fn local_addr(&self) -> &Address {
        &self.local_addr
    }

    async fn close(&self) -> TransportResult<()> {
        // TCP listener closes on drop
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_websocket_transport_creation() {
        let transport = WebSocketTransport::new();
        assert_eq!(
            transport.supported_address_types(),
            &[AddressType::WebSocket]
        );
        assert!(
            !transport.supports_listening(),
            "Client-only transport should not support listening"
        );
    }

    #[test]
    fn test_websocket_transport_with_server() {
        let transport = WebSocketTransport::with_server();
        assert!(
            transport.supports_listening(),
            "Server transport should support listening"
        );
    }

    #[test]
    fn test_websocket_capability_detection() {
        let cap = WebSocketTransport::detect_capability();
        assert!(cap.available, "WebSocket should be available");
        assert_eq!(cap.metadata.get("protocol"), Some(&"WebSocket".to_string()));
        assert_eq!(cap.metadata.get("schemes"), Some(&"ws, wss".to_string()));
    }

    #[tokio::test]
    async fn test_websocket_connect_unsupported_address() {
        let transport = WebSocketTransport::new();
        let addr = Address::Tcp("127.0.0.1:8080".parse().unwrap());

        let result = transport.connect(&addr).await;
        assert!(result.is_err());
        assert!(matches!(
            result.err().unwrap(),
            TransportError::UnsupportedAddress(AddressType::Tcp)
        ));
    }

    #[tokio::test]
    async fn test_websocket_listen_unsupported_address() {
        let transport = WebSocketTransport::with_server();
        let addr = Address::Quic("127.0.0.1:8080".parse().unwrap());

        let result = transport.listen(&addr).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_websocket_listen_bind() {
        let transport = WebSocketTransport::with_server();
        let url = Url::parse("ws://127.0.0.1:0").unwrap();
        let addr = Address::WebSocket { url, auth: None };

        let result = transport.listen(&addr).await;
        assert!(result.is_ok(), "Should be able to bind to localhost");

        let listener = result.unwrap();
        match listener.local_addr() {
            Address::WebSocket { url, .. } => {
                assert!(url.port().unwrap() > 0, "Should have ephemeral port");
            }
            _ => panic!("Expected WebSocket address"),
        }

        listener.close().await.unwrap();
    }

    #[tokio::test]
    async fn test_websocket_connect_and_send() {
        let transport = WebSocketTransport::with_server();

        // Start listener
        let listener_url = Url::parse("ws://127.0.0.1:0").unwrap();
        let listener = transport
            .listen(&Address::WebSocket {
                url: listener_url,
                auth: None,
            })
            .await
            .unwrap();

        // Get actual bound URL
        let bound_addr = listener.local_addr().clone();

        // Spawn accept task
        let accept_handle = tokio::spawn(async move { listener.accept().await });

        // Give server a moment to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Connect from client
        let client_conn = transport.connect(&bound_addr).await.unwrap();

        // Accept connection
        let server_conn = accept_handle.await.unwrap().unwrap();

        // Send message from client to server
        let message = b"Hello, WebSocket server!";
        client_conn.send(message).await.unwrap();

        // Receive on server
        let received = server_conn.receive().await.unwrap();
        assert_eq!(received, message);

        // Send response from server to client
        let response = b"Hello, WebSocket client!";
        server_conn.send(response).await.unwrap();

        // Receive on client
        let received = client_conn.receive().await.unwrap();
        assert_eq!(received, response);

        // Close connections
        client_conn.close().await.unwrap();
        server_conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn test_websocket_large_message() {
        let transport = WebSocketTransport::with_server();

        let listener_url = Url::parse("ws://127.0.0.1:0").unwrap();
        let listener = transport
            .listen(&Address::WebSocket {
                url: listener_url,
                auth: None,
            })
            .await
            .unwrap();

        let bound_addr = listener.local_addr().clone();
        let accept_handle = tokio::spawn(async move { listener.accept().await });

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let client_conn = transport.connect(&bound_addr).await.unwrap();
        let server_conn = accept_handle.await.unwrap().unwrap();

        // Send 1MB message
        let large_message = vec![42u8; 1024 * 1024];
        client_conn.send(&large_message).await.unwrap();

        let received = server_conn.receive().await.unwrap();
        assert_eq!(received.len(), large_message.len());
        assert_eq!(received, large_message);

        client_conn.close().await.unwrap();
        server_conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn test_websocket_text_message() {
        let transport = WebSocketTransport::with_server();

        let listener_url = Url::parse("ws://127.0.0.1:0").unwrap();
        let listener = transport
            .listen(&Address::WebSocket {
                url: listener_url,
                auth: None,
            })
            .await
            .unwrap();

        let bound_addr = listener.local_addr().clone();
        let accept_handle = tokio::spawn(async move { listener.accept().await });

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let client_conn = transport.connect(&bound_addr).await.unwrap();
        let server_conn = accept_handle.await.unwrap().unwrap();

        // Send text as binary (Connection trait uses bytes)
        let text_message = "Hello, WebSocket!";
        client_conn.send(text_message.as_bytes()).await.unwrap();

        let received = server_conn.receive().await.unwrap();
        assert_eq!(received, text_message.as_bytes());

        client_conn.close().await.unwrap();
        server_conn.close().await.unwrap();
    }
}
