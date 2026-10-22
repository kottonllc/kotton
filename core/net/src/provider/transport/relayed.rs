// SPDX-License-Identifier: AGPL-3.0-or-later
//! Relayed mTLS connection — the node side of the relayed connectivity fallback
//! (RFC-0024 sprint 07 item 2).
//!
//! When direct connection and NAT hole-punching both fail, two paired nodes reach
//! each other through the Kotton relay, which bridges a WebSocket between them (see
//! `infra/relay`). Over that bridged byte stream we run **TLS 1.3 mTLS** using the
//! same device certificate and paired-key verifier as the QUIC path — so a relayed
//! peer is authenticated identically to a direct one, and the relay, which only
//! forwards opaque frames, can read nothing.
//!
//! We use plain TLS (not QUIC) because the bridged channel is already reliable;
//! running QUIC over it would stack congestion control on TCP. Request/response is
//! framed directly over the single TLS stream (4-byte big-endian length prefix +
//! payload) — the same framing the QUIC path uses per stream.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use futures::{Sink, Stream, StreamExt};
use kotton_sys::net::TransportError;
use kotton_crypto::DidKeyMethod;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use tracing::warn;
use crate::provider::rendezvous::AdmissionKey;

use super::quic::{
    build_peer_rustls_client_config, build_peer_rustls_server_config,
    extract_ed25519_pubkey_from_cert, Ed25519DeviceCert, PairedDeviceVerifier,
};

/// Maximum framed message size (10 MB), matching the QUIC path.
const MAX_MESSAGE_SIZE: u32 = 10 * 1024 * 1024;

/// TLS server name the dialer presents. The peer is authenticated by its
/// certificate's public key against the paired-key allowlist, never by name, so
/// this is a fixed placeholder.
const PEER_SERVER_NAME: &str = "kotton-peer";

/// An mTLS connection to a paired peer over a relay-bridged byte stream.
///
/// `T` is the post-handshake TLS stream (`tokio_rustls::client::TlsStream<S>` for a
/// dialer, `server::TlsStream<S>` for an accepter). The stream is behind a mutex so
/// `request` / `serve_one_request` serialise framing over the single channel.
pub struct RelayedConnection<T> {
    stream: Mutex<T>,
    peer_did: String,
}

impl<T> RelayedConnection<T> {
    /// The verified DID (`did:key:z6Mk…`) of the peer, from its TLS certificate.
    pub fn peer_did(&self) -> &str {
        &self.peer_did
    }
}

impl<S> RelayedConnection<tokio_rustls::client::TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Dial a paired peer over `stream` (the relay-bridged channel), running the
    /// client side of the mTLS handshake and verifying the peer's key against the
    /// allowlist.
    pub async fn connect(
        stream: S,
        device_cert: &Ed25519DeviceCert,
        verifier: Arc<PairedDeviceVerifier>,
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> Result<Self, TransportError> {
        let config = build_peer_rustls_client_config(device_cert, verifier, provider)?;
        let connector = TlsConnector::from(Arc::new(config));
        let server_name = rustls::pki_types::ServerName::try_from(PEER_SERVER_NAME)
            .map_err(|e| TransportError::ConfigError(e.to_string()))?;
        let tls = connector
            .connect(server_name, stream)
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        let peer_did = peer_did_from_certs(tls.get_ref().1.peer_certificates())?;
        Ok(Self {
            stream: Mutex::new(tls),
            peer_did,
        })
    }
}

impl<S> RelayedConnection<tokio_rustls::server::TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Accept a relayed circuit on `stream`, running the server side of the mTLS
    /// handshake and verifying the dialing peer's key against the allowlist.
    pub async fn accept(
        stream: S,
        device_cert: &Ed25519DeviceCert,
        verifier: Arc<PairedDeviceVerifier>,
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> Result<Self, TransportError> {
        let config = build_peer_rustls_server_config(device_cert, verifier, provider)?;
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let tls = acceptor
            .accept(stream)
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        let peer_did = peer_did_from_certs(tls.get_ref().1.peer_certificates())?;
        Ok(Self {
            stream: Mutex::new(tls),
            peer_did,
        })
    }
}

impl<T> RelayedConnection<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Send a framed request and read the framed response (dialer side).
    pub async fn request(&self, req: &[u8]) -> Result<Vec<u8>, TransportError> {
        let mut stream = self.stream.lock().await;
        write_frame(&mut *stream, req).await?;
        read_frame(&mut *stream).await
    }

    /// Read one framed request, invoke `handler`, and write the framed response.
    /// Returns `Ok(false)` when the peer closed the channel cleanly.
    pub async fn serve_one_request<F, Fut>(&self, handler: F) -> Result<bool, TransportError>
    where
        F: FnOnce(Vec<u8>) -> Fut,
        Fut: std::future::Future<Output = Vec<u8>>,
    {
        let mut stream = self.stream.lock().await;
        let req = match read_frame_opt(&mut *stream).await? {
            Some(req) => req,
            None => return Ok(false), // peer closed
        };
        let resp = handler(req).await;
        write_frame(&mut *stream, &resp).await?;
        Ok(true)
    }
}

/// Derive the peer DID from a TLS handshake's peer certificates.
fn peer_did_from_certs(
    certs: Option<&[rustls::pki_types::CertificateDer<'static>]>,
) -> Result<String, TransportError> {
    let cert = certs
        .and_then(|c| c.first())
        .ok_or_else(|| TransportError::AuthenticationFailed("peer presented no certificate".into()))?;
    let pubkey = extract_ed25519_pubkey_from_cert(cert).ok_or_else(|| {
        TransportError::AuthenticationFailed("peer certificate is not a Kotton Ed25519 cert".into())
    })?;
    let did = DidKeyMethod::from_public_key_bytes(&pubkey)
        .map_err(|e| TransportError::AuthenticationFailed(format!("bad peer key: {e}")))?;
    Ok(did.to_string())
}

async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    payload: &[u8],
) -> Result<(), TransportError> {
    let len = payload.len() as u32;
    if payload.len() as u64 > MAX_MESSAGE_SIZE as u64 {
        return Err(TransportError::ConfigError(format!(
            "message too large: {} bytes (max {MAX_MESSAGE_SIZE})",
            payload.len()
        )));
    }
    w.write_u32(len).await.map_err(io_err)?;
    w.write_all(payload).await.map_err(io_err)?;
    w.flush().await.map_err(io_err)?;
    Ok(())
}

async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>, TransportError> {
    read_frame_opt(r)
        .await?
        .ok_or_else(|| TransportError::ConnectionFailed("peer closed mid-response".into()))
}

/// Read a framed message, or `None` if the peer closed cleanly before the length.
async fn read_frame_opt<R: AsyncRead + Unpin>(
    r: &mut R,
) -> Result<Option<Vec<u8>>, TransportError> {
    let len = match r.read_u32().await {
        Ok(len) => len,
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(io_err(e)),
    };
    if len > MAX_MESSAGE_SIZE {
        return Err(TransportError::ConfigError(format!(
            "message too large: {len} bytes (max {MAX_MESSAGE_SIZE})"
        )));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf).await.map_err(io_err)?;
    Ok(Some(buf))
}

fn io_err(e: std::io::Error) -> TransportError {
    TransportError::ConnectionFailed(e.to_string())
}

// ---------------------------------------------------------------------------
// WebSocket ↔ byte-stream adapter
// ---------------------------------------------------------------------------

/// Presents a binary WebSocket as an `AsyncRead + AsyncWrite` byte stream, so the
/// relayed mTLS layer can run TLS over the relay-bridged WebSocket.
///
/// Each write is sent as one binary WebSocket frame; reads drain inbound binary
/// frames in order (buffering any bytes a single `poll_read` cannot take). TLS
/// supplies its own record framing on top, so frame boundaries do not matter.
/// Non-binary control frames (ping/pong/text) are ignored; a close frame or stream
/// end is surfaced as EOF.
pub struct WsByteStream<S> {
    inner: S,
    /// Bytes from the last inbound frame not yet handed to a `poll_read`.
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl<S> WsByteStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            read_buf: Vec::new(),
            read_pos: 0,
        }
    }
}

impl<S> AsyncRead for WsByteStream<S>
where
    S: Stream<Item = Result<Message, WsError>> + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            // Drain buffered bytes from a previous frame first.
            if this.read_pos < this.read_buf.len() {
                let avail = &this.read_buf[this.read_pos..];
                let n = avail.len().min(buf.remaining());
                buf.put_slice(&avail[..n]);
                this.read_pos += n;
                return Poll::Ready(Ok(()));
            }
            // Otherwise pull the next inbound frame.
            match Pin::new(&mut this.inner).poll_next(cx) {
                Poll::Ready(Some(Ok(Message::Binary(data)))) => {
                    if data.is_empty() {
                        continue; // empty frame carries no bytes
                    }
                    this.read_buf = data;
                    this.read_pos = 0;
                    // loop to drain into buf
                }
                Poll::Ready(Some(Ok(Message::Close(_)))) | Poll::Ready(None) => {
                    return Poll::Ready(Ok(())); // EOF: zero bytes read
                }
                Poll::Ready(Some(Ok(_))) => continue, // ignore ping/pong/text
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(std::io::Error::other(e)))
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> AsyncWrite for WsByteStream<S>
where
    S: Sink<Message, Error = WsError> + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_ready(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(std::io::Error::other(e))),
            Poll::Pending => return Poll::Pending,
        }
        match Pin::new(&mut this.inner).start_send(Message::Binary(data.to_vec())) {
            Ok(()) => Poll::Ready(Ok(data.len())),
            Err(e) => Poll::Ready(Err(std::io::Error::other(e))),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match Pin::new(&mut self.get_mut().inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match Pin::new(&mut self.get_mut().inner).poll_close(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}

// ---------------------------------------------------------------------------
// Relay client (node ↔ relay circuit endpoints)
// ---------------------------------------------------------------------------

/// The relay-bridged WebSocket type returned by `connect_async`.
type RelayWs = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// Outbound relayed connection (dialer side): mTLS client over the bridged WebSocket.
pub type RelayedDial = RelayedConnection<tokio_rustls::client::TlsStream<WsByteStream<RelayWs>>>;
/// Inbound relayed connection (reserved/accepter side): mTLS server over the bridge.
pub type RelayedInbound =
    RelayedConnection<tokio_rustls::server::TlsStream<WsByteStream<RelayWs>>>;

/// Client for the relay's circuit endpoints (`/relay/reserve`, `/relay/open`,
/// `/relay/accept`) — the node's side of the relayed connectivity fallback
/// (RFC-0024 sprint 07 item 2; relay side in `infra/relay`).
/// The relay-bridged byte stream itself, before anything runs over it.
pub type RelayedByteStream = WsByteStream<RelayWs>;

/// `ws://` / `wss://` base for a relay's HTTP URL.
fn ws_base_of(relay_url: &str) -> String {
    relay_url
        .replacen("https://", "wss://", 1)
        .replacen("http://", "ws://", 1)
        .trim_end_matches('/')
        .to_string()
}

/// Signed `Authorization` header (same scheme as rendezvous lookups):
/// `Ed25519 fingerprint=<fp> ts=<ts> sig=<sig over "fp\nts"> [admit=<tag>]` —
/// the tag under the relay's admission key when the device holds one, which a
/// relay whose rule is narrowed reads at the upgrade.
fn auth_header_for(
    fingerprint: &str,
    signing_key: &SigningKey,
    admission: Option<&AdmissionKey>,
) -> Result<String, TransportError> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|e| TransportError::ConfigError(e.to_string()))?;
    let payload = format!("{fingerprint}\n{ts}");
    let sig = URL_SAFE_NO_PAD.encode(signing_key.sign(payload.as_bytes()).to_bytes());
    let mut header = format!("Ed25519 fingerprint={fingerprint} ts={ts} sig={sig}");
    if let Some(k) = admission {
        header.push_str(&format!(" admit={}", k.tag(fingerprint, ts)));
    }
    Ok(header)
}

/// A reservation held under a one-time handle, for a ceremony rather than a
/// peer: the bridged bytes come back **raw**, with no mTLS, because the party
/// on the other end is a stranger whose key the ceremony exists to learn
/// (RFC-0022). What authenticates the stream is what runs over it — a PAKE
/// keyed by the spoken code — and the handle itself is derived from that code,
/// so the relay learns a label that names nobody and is never used twice.
pub struct RendezvousReservation {
    ws_base: String,
    control: RelayWs,
}

/// Hold a reservation under `fingerprint` (a handle `signing_key` proves) at
/// `relay_url`. Exists from the moment this returns.
pub async fn rendezvous_reserve(
    relay_url: &str,
    fingerprint: &str,
    signing_key: &SigningKey,
    admission: Option<&AdmissionKey>,
) -> Result<RendezvousReservation, TransportError> {
    let ws_base = ws_base_of(relay_url);
    let url = format!("{ws_base}/relay/reserve");
    let control =
        connect_ws(&url, Some(&auth_header_for(fingerprint, signing_key, admission)?)).await?;
    Ok(RendezvousReservation { ws_base, control })
}

impl RendezvousReservation {
    /// Wait for the first circuit to this handle, dial back its data leg, and
    /// hand over the raw bridged stream. The reservation is consumed: a
    /// ceremony handle admits exactly one party.
    pub async fn accept_one(mut self) -> Result<RelayedByteStream, TransportError> {
        while let Some(msg) = self.control.next().await {
            let circuit_id = match msg {
                Ok(Message::Text(id)) => id,
                Ok(Message::Close(_)) => break,
                Err(e) => return Err(TransportError::ConnectionFailed(e.to_string())),
                Ok(_) => continue,
            };
            let accept_url = format!("{}/relay/accept?circuit={}", self.ws_base, circuit_id);
            let data_ws = connect_ws(&accept_url, None).await?;
            return Ok(WsByteStream::new(data_ws));
        }
        Err(TransportError::ConnectionFailed(
            "relay closed the reservation before anyone arrived".into(),
        ))
    }
}

/// Open a raw circuit to the handle `target` at `relay_url`, authenticating the
/// dial as `fingerprint` (a one-time key — the dialer is a stranger too).
pub async fn rendezvous_dial(
    relay_url: &str,
    fingerprint: &str,
    signing_key: &SigningKey,
    target: &str,
    admission: Option<&AdmissionKey>,
) -> Result<RelayedByteStream, TransportError> {
    let url = format!("{}/relay/open?to={}", ws_base_of(relay_url), target);
    let ws = connect_ws(&url, Some(&auth_header_for(fingerprint, signing_key, admission)?)).await?;
    Ok(WsByteStream::new(ws))
}

pub struct RelayClient {
    /// WebSocket base URL (`ws://` / `wss://`) derived from the relay URL.
    ws_base: String,
    fingerprint: String,
    signing_key: SigningKey,
    device_cert: Ed25519DeviceCert,
    verifier: Arc<PairedDeviceVerifier>,
    provider: Arc<rustls::crypto::CryptoProvider>,
    /// The relay's admission key this device holds, if any
    /// ([`Self::with_admission`]).
    admission: Option<AdmissionKey>,
}

impl RelayClient {
    pub fn new(
        relay_url: &str,
        fingerprint: String,
        signing_key: SigningKey,
        device_cert: Ed25519DeviceCert,
        verifier: Arc<PairedDeviceVerifier>,
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> Self {
        let ws_base = ws_base_of(relay_url);
        Self {
            ws_base,
            fingerprint,
            signing_key,
            device_cert,
            verifier,
            provider,
            admission: None,
        }
    }

    /// Present a tag under `key` at every reservation and circuit this client
    /// makes.
    pub fn with_admission(mut self, key: Option<AdmissionKey>) -> Self {
        self.admission = key;
        self
    }

    /// Signed `Authorization` header (same scheme as rendezvous lookups), with
    /// the admission tag when this client holds a key.
    fn auth_header(&self) -> Result<String, TransportError> {
        auth_header_for(&self.fingerprint, &self.signing_key, self.admission.as_ref())
    }

    /// Dial a paired peer through the relay (the relayed fallback tier). Opens a
    /// circuit to `target_did` and runs the mTLS client handshake over the bridge.
    pub async fn dial(&self, target_did: &str) -> Result<RelayedDial, TransportError> {
        let url = format!("{}/relay/open?to={}", self.ws_base, target_did);
        let ws = connect_ws(&url, Some(&self.auth_header()?)).await?;
        RelayedConnection::connect(
            WsByteStream::new(ws),
            &self.device_cert,
            Arc::clone(&self.verifier),
            Arc::clone(&self.provider),
        )
        .await
    }

    /// Open a reservation on the relay. It exists from the moment this returns —
    /// the relay routes circuits for this fingerprint to it until
    /// [`Reservation::serve`] ends — which is what lets a holder say *held* as a
    /// fact rather than *attempted* (RFC-0083 R6's readout reads this moment).
    pub async fn reserve(&self) -> Result<Reservation<'_>, TransportError> {
        let url = format!("{}/relay/reserve", self.ws_base);
        let control = connect_ws(&url, Some(&self.auth_header()?)).await?;
        Ok(Reservation { client: self, control })
    }

    /// Hold a reservation on the relay and accept inbound relayed circuits, sending
    /// each established mTLS connection to `out`. Runs until the reservation drops
    /// or `out` is closed. [`reserve`](Self::reserve) then [`Reservation::serve`].
    pub async fn run_reservation(
        &self,
        out: mpsc::Sender<RelayedInbound>,
    ) -> Result<(), TransportError> {
        self.reserve().await?.serve(out).await
    }
}

/// A reservation held on the relay: the open control socket circuits arrive on.
pub struct Reservation<'a> {
    client: &'a RelayClient,
    control: RelayWs,
}

impl Reservation<'_> {
    /// Accept inbound relayed circuits for as long as the reservation holds,
    /// sending each established mTLS connection to `out`. Returns when the relay
    /// closes the control socket or `out` is closed.
    pub async fn serve(mut self, out: mpsc::Sender<RelayedInbound>) -> Result<(), TransportError> {
        let client = self.client;
        while let Some(msg) = self.control.next().await {
            let circuit_id = match msg {
                Ok(Message::Text(id)) => id,
                Ok(Message::Close(_)) => break,
                Err(e) => return Err(TransportError::ConnectionFailed(e.to_string())),
                Ok(_) => continue, // ping/pong/binary on the control channel: ignore
            };
            // Dial back the data leg; the circuit id is the capability (no auth).
            let accept_url = format!("{}/relay/accept?circuit={}", client.ws_base, circuit_id);
            let data_ws = match connect_ws(&accept_url, None).await {
                Ok(ws) => ws,
                Err(e) => {
                    warn!(circuit = %circuit_id, error = %e, "relay accept dial-back failed");
                    continue;
                }
            };
            match RelayedConnection::accept(
                WsByteStream::new(data_ws),
                &client.device_cert,
                Arc::clone(&client.verifier),
                Arc::clone(&client.provider),
            )
            .await
            {
                Ok(conn) => {
                    if out.send(conn).await.is_err() {
                        break; // consumer gone
                    }
                }
                Err(e) => warn!(circuit = %circuit_id, error = %e, "relayed mTLS accept failed"),
            }
        }
        Ok(())
    }
}

/// Open a WebSocket to `url`, optionally with an `Authorization` header.
///
/// A relay that answers the upgrade `403` has refused it by its rule — the one
/// refusal it gives, whatever the caller lacked (`not admitted by this relay's
/// rule`) — and that is returned as [`TransportError::AuthenticationFailed`],
/// apart from every failure to reach the relay at all, which stays
/// [`TransportError::ConnectionFailed`]. A caller that says *why* to a person
/// tells the two apart by the variant
/// (`TASK-a-first-contact-ceremony-meets-at-a-relay-whose-rule-refuses-a-stranger`).
async fn connect_ws(url: &str, auth: Option<&str>) -> Result<RelayWs, TransportError> {
    let mut req = url
        .into_client_request()
        .map_err(|e| TransportError::ConfigError(e.to_string()))?;
    if let Some(a) = auth {
        let value = a
            .parse()
            .map_err(|_| TransportError::ConfigError("invalid Authorization header".into()))?;
        req.headers_mut().insert("Authorization", value);
    }
    let (ws, _) = connect_async(req).await.map_err(|e| match e {
        WsError::Http(ref answer) if answer.status() == 403 => {
            TransportError::AuthenticationFailed(format!("the relay refused: {e}"))
        }
        e => TransportError::ConnectionFailed(e.to_string()),
    })?;
    Ok(ws)
}

#[cfg(test)]
mod tests {
    //! In-process verification with `tokio::io::duplex` (no relay, no WebSocket, no
    //! two real nodes): paired peers complete the mTLS handshake and exchange a
    //! framed request/response, and — the security invariant — an unpaired peer's
    //! handshake is rejected.

    use super::*;
    use ed25519_dalek::SigningKey;
    use std::collections::HashSet;
    use std::sync::RwLock;

    fn provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    fn cert_for(sk: &SigningKey) -> Ed25519DeviceCert {
        Ed25519DeviceCert::from_signing_key(sk).unwrap()
    }

    fn verifier(
        allowed: HashSet<[u8; 32]>,
        p: &Arc<rustls::crypto::CryptoProvider>,
    ) -> Arc<PairedDeviceVerifier> {
        PairedDeviceVerifier::new(Arc::new(RwLock::new(allowed)), Arc::clone(p))
    }

    fn did_of(pk: &[u8; 32]) -> String {
        DidKeyMethod::from_public_key_bytes(pk).unwrap().to_string()
    }

    #[tokio::test]
    async fn paired_peers_handshake_and_exchange_requests() {
        let p = provider();
        let server_sk = SigningKey::from_bytes(&[1u8; 32]);
        let client_sk = SigningKey::from_bytes(&[2u8; 32]);
        let server_pk = server_sk.verifying_key().to_bytes();
        let client_pk = client_sk.verifying_key().to_bytes();

        let (s_io, c_io) = tokio::io::duplex(64 * 1024);

        // Server trusts the client's key.
        let server_cert = cert_for(&server_sk);
        let server_verifier = verifier(HashSet::from([client_pk]), &p);
        let p2 = Arc::clone(&p);
        let server = tokio::spawn(async move {
            let conn = RelayedConnection::accept(s_io, &server_cert, server_verifier, p2)
                .await
                .expect("server handshake");
            assert_eq!(conn.peer_did(), did_of(&client_pk));
            let served = conn
                .serve_one_request(|req| async move {
                    let mut resp = b"echo:".to_vec();
                    resp.extend_from_slice(&req);
                    resp
                })
                .await
                .expect("serve");
            assert!(served);
        });

        // Client trusts the server's key.
        let client_cert = cert_for(&client_sk);
        let client_verifier = verifier(HashSet::from([server_pk]), &p);
        let conn = RelayedConnection::connect(c_io, &client_cert, client_verifier, Arc::clone(&p))
            .await
            .expect("client handshake");
        assert_eq!(conn.peer_did(), did_of(&server_pk));
        let resp = conn.request(b"ping").await.expect("request");
        assert_eq!(resp, b"echo:ping");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn unpaired_peer_is_rejected() {
        let p = provider();
        let server_sk = SigningKey::from_bytes(&[3u8; 32]);
        let client_sk = SigningKey::from_bytes(&[4u8; 32]);
        let server_pk = server_sk.verifying_key().to_bytes();

        let (s_io, c_io) = tokio::io::duplex(64 * 1024);

        // Server allowlist is EMPTY — the client is not a paired device.
        let server_cert = cert_for(&server_sk);
        let server_verifier = verifier(HashSet::new(), &p);
        let p2 = Arc::clone(&p);
        let server =
            tokio::spawn(
                async move { RelayedConnection::accept(s_io, &server_cert, server_verifier, p2).await },
            );

        // Client trusts the server, but the server will reject the client's cert.
        let client_cert = cert_for(&client_sk);
        let client_verifier = verifier(HashSet::from([server_pk]), &p);
        let client_outcome = async {
            let conn =
                RelayedConnection::connect(c_io, &client_cert, client_verifier, Arc::clone(&p))
                    .await?;
            // Even if the client's handshake "completes" (TLS 1.3 finishes early),
            // the first request must fail once the server aborts.
            conn.request(b"ping").await?;
            Ok::<(), TransportError>(())
        }
        .await;

        assert!(
            server.await.unwrap().is_err(),
            "server must reject an unpaired client's certificate"
        );
        assert!(
            client_outcome.is_err(),
            "client must not complete a request to a server that rejected it"
        );
    }

    #[tokio::test]
    async fn mtls_runs_over_a_real_websocket() {
        // Exercise the full node-side wire stack — WsByteStream + mTLS — over a real
        // tokio-tungstenite WebSocket pair. These are the exact bytes the relay would
        // bridge opaquely between two nodes; only the relay hop is absent here.
        use tokio::net::TcpListener;

        let p = provider();
        let server_sk = SigningKey::from_bytes(&[5u8; 32]);
        let client_sk = SigningKey::from_bytes(&[6u8; 32]);
        let server_pk = server_sk.verifying_key().to_bytes();
        let client_pk = client_sk.verifying_key().to_bytes();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_cert = cert_for(&server_sk);
        let server_verifier = verifier(HashSet::from([client_pk]), &p);
        let p2 = Arc::clone(&p);
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let conn = RelayedConnection::accept(
                WsByteStream::new(ws),
                &server_cert,
                server_verifier,
                p2,
            )
            .await
            .expect("server mTLS over ws");
            assert_eq!(conn.peer_did(), did_of(&client_pk));
            let served = conn
                .serve_one_request(|req| async move {
                    let mut resp = b"echo:".to_vec();
                    resp.extend_from_slice(&req);
                    resp
                })
                .await
                .expect("serve");
            assert!(served);
        });

        let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}"))
            .await
            .unwrap();
        let client_cert = cert_for(&client_sk);
        let client_verifier = verifier(HashSet::from([server_pk]), &p);
        let conn =
            RelayedConnection::connect(WsByteStream::new(ws), &client_cert, client_verifier, p)
                .await
                .expect("client mTLS over ws");
        assert_eq!(conn.peer_did(), did_of(&server_pk));
        let resp = conn.request(b"ping").await.expect("request");
        assert_eq!(resp, b"echo:ping");

        server.await.unwrap();
    }
}
