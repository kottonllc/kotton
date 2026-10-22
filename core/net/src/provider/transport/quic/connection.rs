// SPDX-License-Identifier: AGPL-3.0-or-later
//! QUIC connection and listener wrappers.
//!
//! `QuicConnection` implements the `Connection` trait over a `quinn::Connection`.
//! `QuicListenerImpl` implements the `Listener` trait over a `quinn::Endpoint`.

use async_trait::async_trait;
use kotton_sys::net::{
    Address, AddressType, Connection, ConnectionError, ConnectionQuality, ConnectionResult,
    Listener, RequestHandler, TransportError, TransportResult,
};
use kotton_crypto::DidKeyMethod;
use quinn::{Endpoint, RecvStream, SendStream};
use rustls::pki_types::CertificateDer;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Maximum message size (10 MB, same as TCP).
pub(super) const MAX_MESSAGE_SIZE: u32 = 10 * 1024 * 1024;

// ---------------------------------------------------------------------------
// QuicConnection
// ---------------------------------------------------------------------------

/// QUIC connection wrapper — supports multiple bidirectional streams per connection.
pub(super) struct QuicConnection {
    connection: Arc<quinn::Connection>,
    peer_id: String,
}

impl QuicConnection {
    pub(super) fn new(connection: quinn::Connection, peer_id: String) -> Self {
        Self {
            connection: Arc::new(connection),
            peer_id,
        }
    }

    /// Open a new bidirectional stream for one send/receive operation.
    async fn open_stream(&self) -> ConnectionResult<(SendStream, RecvStream)> {
        self.connection
            .open_bi()
            .await
            .map_err(|e| ConnectionError::Io(std::io::Error::other(e)))
    }
}

#[async_trait]
impl Connection for QuicConnection {
    async fn send(&self, message: &[u8]) -> ConnectionResult<()> {
        let len = message.len() as u32;
        if len > MAX_MESSAGE_SIZE {
            return Err(ConnectionError::Framing(format!(
                "Message too large: {} bytes (max {})",
                len, MAX_MESSAGE_SIZE
            )));
        }

        let (mut send, _recv) = self.open_stream().await?;

        send.write_u32(len)
            .await
            .map_err(|e| ConnectionError::Io(std::io::Error::other(e)))?;
        send.write_all(message)
            .await
            .map_err(|e| ConnectionError::Io(std::io::Error::other(e)))?;
        send.finish()
            .map_err(|e| ConnectionError::Io(std::io::Error::other(e)))?;

        Ok(())
    }

    async fn receive(&self) -> ConnectionResult<Vec<u8>> {
        let (_send, mut recv) = self
            .connection
            .accept_bi()
            .await
            .map_err(|e| ConnectionError::Io(std::io::Error::other(e)))?;

        let len = recv
            .read_u32()
            .await
            .map_err(|e| ConnectionError::Io(std::io::Error::other(e)))?;

        if len > MAX_MESSAGE_SIZE {
            return Err(ConnectionError::Framing(format!(
                "Message too large: {} bytes (max {})",
                len, MAX_MESSAGE_SIZE
            )));
        }

        let mut buffer = vec![0u8; len as usize];
        recv.read_exact(&mut buffer)
            .await
            .map_err(|e| ConnectionError::Io(std::io::Error::other(e)))?;

        Ok(buffer)
    }

    async fn send_stream(
        &self,
        stream_in: &mut (dyn tokio::io::AsyncRead + Send + Unpin),
    ) -> ConnectionResult<u64> {
        let (mut send, _recv) = self.open_stream().await?;
        tokio::io::copy(stream_in, &mut send)
            .await
            .map_err(ConnectionError::Io)
    }

    async fn receive_stream(
        &self,
        sink: &mut (dyn tokio::io::AsyncWrite + Send + Unpin),
    ) -> ConnectionResult<u64> {
        let (_send, mut recv) = self
            .connection
            .accept_bi()
            .await
            .map_err(|e| ConnectionError::Io(std::io::Error::other(e)))?;
        tokio::io::copy(&mut recv, sink)
            .await
            .map_err(ConnectionError::Io)
    }

    async fn close(&self) -> ConnectionResult<()> {
        self.connection.close(0u32.into(), b"connection closed");
        Ok(())
    }

    fn peer_id(&self) -> &str {
        &self.peer_id
    }

    fn quality(&self) -> ConnectionQuality {
        ConnectionQuality::default()
    }

    fn transport_type(&self) -> AddressType {
        AddressType::Quic
    }

    async fn serve_one_request(&self, handler: RequestHandler) -> ConnectionResult<bool> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Accept the next inbound bidi-stream opened by the peer.
        // Any error (including clean close) means no more requests to serve.
        let (mut send, mut recv) = match self.connection.accept_bi().await {
            Ok(pair) => pair,
            Err(_) => return Ok(false),
        };

        // Read 4-byte BE length + payload (mirrors QuicPeerChannel::request).
        let len = recv
            .read_u32()
            .await
            .map_err(|e| ConnectionError::Io(std::io::Error::other(e)))?;

        if len > MAX_MESSAGE_SIZE {
            return Err(ConnectionError::Framing(format!(
                "peer request too large: {} bytes (max {})",
                len, MAX_MESSAGE_SIZE
            )));
        }

        let mut buf = vec![0u8; len as usize];
        recv.read_exact(&mut buf)
            .await
            .map_err(|e| ConnectionError::Io(std::io::Error::other(e)))?;

        // Dispatch through the caller-supplied handler.
        let resp = handler(buf).await;

        // Write 4-byte BE length + response.
        let resp_len = resp.len() as u32;
        send.write_u32(resp_len)
            .await
            .map_err(|e| ConnectionError::Io(std::io::Error::other(e)))?;
        send.write_all(&resp)
            .await
            .map_err(|e| ConnectionError::Io(std::io::Error::other(e)))?;
        send.finish()
            .map_err(|e| ConnectionError::Io(std::io::Error::other(e)))?;

        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// QuicListenerImpl
// ---------------------------------------------------------------------------

/// QUIC listener wrapper — accepts incoming connections from a bound endpoint.
pub(super) struct QuicListenerImpl {
    pub(super) endpoint: Endpoint,
    pub(super) local_addr: Address,
}

#[async_trait]
impl Listener for QuicListenerImpl {
    async fn accept(&self) -> TransportResult<Box<dyn Connection>> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or(TransportError::ListenerClosed)?;

        let connection = incoming
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        let remote_addr = connection.remote_address();

        // Try to derive the peer's did:key DID from their TLS certificate.
        // Falls back to the remote socket address string if the cert is absent
        // or not an Ed25519 certificate (e.g. non-peer QUIC connections).
        let peer_id = connection
            .peer_identity()
            .and_then(|id| id.downcast::<Vec<CertificateDer<'static>>>().ok())
            .and_then(|certs| certs.into_iter().next())
            .and_then(|cert| super::tls::extract_ed25519_pubkey_from_cert(&cert))
            .and_then(|pubkey| DidKeyMethod::from_public_key_bytes(&pubkey).ok())
            .map(|did| did.to_string())
            .unwrap_or_else(|| remote_addr.to_string());

        let quic_conn = QuicConnection::new(connection, peer_id);

        Ok(Box::new(quic_conn))
    }

    fn local_addr(&self) -> &Address {
        &self.local_addr
    }

    async fn close(&self) -> TransportResult<()> {
        self.endpoint.close(0u32.into(), b"listener closed");
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        Ok(())
    }
}
