// SPDX-License-Identifier: AGPL-3.0-or-later
use super::address::AddressType;
use async_trait::async_trait;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite};

/// Result type for connection operations
pub type ConnectionResult<T> = Result<T, ConnectionError>;

/// Encrypted communication channel between two devices
#[async_trait]
pub trait Connection: Send + Sync {
    /// Send encrypted message to peer
    ///
    /// Message is encrypted and framed before transmission.
    /// Blocks until message is fully sent or error occurs.
    async fn send(&self, message: &[u8]) -> ConnectionResult<()>;

    /// Receive encrypted message from peer
    ///
    /// Blocks until complete message is received or error occurs.
    /// Returns decrypted message bytes.
    async fn receive(&self) -> ConnectionResult<Vec<u8>>;

    /// Send large payload as stream
    ///
    /// Reads from `stream` and transmits in chunks to avoid loading
    /// entire payload into memory. Returns total bytes sent.
    ///
    /// Use for: file transfers, media uploads, large data
    async fn send_stream(
        &self,
        stream: &mut (dyn AsyncRead + Send + Unpin),
    ) -> ConnectionResult<u64>;

    /// Receive large payload as stream
    ///
    /// Writes received data to `sink` in chunks. Returns total bytes received.
    ///
    /// Use for: file downloads, media streaming, large data
    async fn receive_stream(
        &self,
        sink: &mut (dyn AsyncWrite + Send + Unpin),
    ) -> ConnectionResult<u64>;

    /// Close connection gracefully
    ///
    /// Sends close frame, waits for peer acknowledgment, releases resources.
    async fn close(&self) -> ConnectionResult<()>;

    /// Get peer device ID (DID)
    fn peer_id(&self) -> &str;

    /// Get connection quality metrics
    ///
    /// Returns current RTT, packet loss, bandwidth, jitter.
    /// Updated periodically by provider.
    fn quality(&self) -> ConnectionQuality;

    /// Get underlying transport type
    ///
    /// Allows service layer to select appropriate connection for use case.
    fn transport_type(&self) -> AddressType;

    /// Server-side request-response: accept one inbound bidi-stream, read the
    /// request bytes, invoke `handler`, and write the response bytes.
    ///
    /// The framing is 4-byte-BE length prefix + payload — the same as
    /// `QuicPeerChannel::request()` on the client side.
    ///
    /// Returns `Ok(true)` on success, `Ok(false)` when the peer has closed the
    /// connection cleanly (no more streams to accept), `Err(_)` on framing or
    /// I/O failure.
    ///
    /// The default implementation returns `Err(ConnectionError::Framing(...))`
    /// so transports that do not need request-response compile without change.
    async fn serve_one_request(&self, handler: RequestHandler) -> ConnectionResult<bool> {
        let _ = handler;
        Err(ConnectionError::Framing(
            "serve_one_request is not supported on this transport".to_string(),
        ))
    }
}

/// What [`Connection::serve_one_request`] calls with one request's bytes: the
/// response bytes, produced once, on any task.
pub type RequestHandler =
    Box<dyn FnOnce(Vec<u8>) -> Pin<Box<dyn Future<Output = Vec<u8>> + Send + 'static>> + Send + 'static>;

/// Connection quality metrics
#[derive(Debug, Clone)]
pub struct ConnectionQuality {
    /// Round-trip time in milliseconds
    pub rtt_ms: u64,
    /// Packet loss percentage (0.0-100.0)
    pub packet_loss: f64,
    /// Available bandwidth estimate (bytes/sec)
    pub bandwidth: u64,
    /// Jitter in milliseconds (variance in latency)
    pub jitter_ms: u64,
}

impl Default for ConnectionQuality {
    fn default() -> Self {
        Self {
            rtt_ms: 0,
            packet_loss: 0.0,
            bandwidth: 0,
            jitter_ms: 0,
        }
    }
}

/// Connection errors
#[derive(Debug)]
pub enum ConnectionError {
    /// Connection closed by peer
    Closed,
    /// I/O error during read/write
    Io(std::io::Error),
    /// Encryption/decryption failed
    Encryption(String),
    /// Framing error (invalid message format)
    Framing(String),
    /// Authentication failed
    AuthenticationFailed,
    /// Timeout waiting for peer
    Timeout,
    /// Connection already closed
    AlreadyClosed,
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => write!(f, "connection closed by peer"),
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::Encryption(msg) => write!(f, "encryption error: {}", msg),
            Self::Framing(msg) => write!(f, "framing error: {}", msg),
            Self::AuthenticationFailed => write!(f, "authentication failed"),
            Self::Timeout => write!(f, "connection timeout"),
            Self::AlreadyClosed => write!(f, "connection already closed"),
        }
    }
}

impl std::error::Error for ConnectionError {}

impl From<std::io::Error> for ConnectionError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_is_object_safe() {
        // Verify trait can be used as dyn Connection
        let _: Option<Box<dyn Connection>> = None;
    }

    #[test]
    fn address_type_display() {
        assert_eq!(format!("{:?}", AddressType::Tcp), "Tcp");
        assert_eq!(format!("{:?}", AddressType::Quic), "Quic");
        assert_eq!(format!("{:?}", AddressType::WebSocket), "WebSocket");
    }

    #[test]
    fn connection_quality_default() {
        let quality = ConnectionQuality::default();
        assert_eq!(quality.rtt_ms, 0);
        assert_eq!(quality.packet_loss, 0.0);
        assert_eq!(quality.bandwidth, 0);
        assert_eq!(quality.jitter_ms, 0);
    }

    #[test]
    fn connection_error_display() {
        let err = ConnectionError::Closed;
        assert_eq!(err.to_string(), "connection closed by peer");

        let err = ConnectionError::Framing("invalid length".to_string());
        assert_eq!(err.to_string(), "framing error: invalid length");
    }
}
