// SPDX-License-Identifier: AGPL-3.0-or-later
//! An introduced connection: a QUIC socket that hears one address and one token,
//! and nothing else.
//!
//! A relay both of a person's devices are on introduces them — each hands the
//! other its local address and a token over the sealed channel the relay carries
//! but cannot read — and the pair then dials direct. The listener that dial lands
//! on is on a network the person does not control, so what it must not do is
//! parse a stranger's packet: QUIC's admission is the TLS handshake, and a
//! handshake is a parse. [`IntroducedSocket`] sits under quinn and drops every
//! datagram that is not **from the introduced address** and **prefixed with the
//! token** before quinn sees a byte of it. A dropped datagram gets no reply,
//! because nothing that could reply ever learned it arrived.
//!
//! Both ends wrap their socket the same way — the listener and the dialer each
//! hear only the other — and both prefix the token to everything they send, so
//! the prefix is the whole framing: sixteen bytes on the front of every datagram,
//! stripped on the way in.
//!
//! What the token is not: a secret against someone on the path. It crosses the
//! network in the clear on every datagram, so a machine that can see the pair's
//! traffic can copy it and forge the source address. That reaches quinn's parse
//! and no further — the handshake still admits only the one key the listener was
//! opened for. The filter's job is the stranger who is merely *on the network*,
//! which is every device at the café, and for them it is the whole door.
//!
//! `TASK-a-relay-introduces-your-devices`.

use super::tls::{self, CertOffer, Ed25519DeviceCert, PairedDeviceVerifier};
use kotton_crypto::DidKeyMethod;
use kotton_sys::net::{
    Address, Connection, Listener, TransportError, TransportResult,
};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, Endpoint, UdpPoller};
use rustls::pki_types::CertificateDer;
use std::collections::HashSet;
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;

/// How long the token is: 128 random bits, which no stranger guesses.
pub const INTRODUCTION_TOKEN_LEN: usize = 16;

/// The other end of an introduction: where it said it is, and the token both ends
/// put on every datagram.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IntroducedPeer {
    pub addr: SocketAddr,
    pub token: [u8; INTRODUCTION_TOKEN_LEN],
}

impl fmt::Debug for IntroducedPeer {
    // The token is a capability for the socket's parse; it does not go in logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntroducedPeer")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

/// What the filter let through and what it dropped — the instrument a test reads
/// to say *no parse*: a datagram counted as dropped never reached quinn.
#[derive(Debug, Default)]
pub struct FilterCounts {
    pub(super) admitted: AtomicU64,
    pub(super) dropped: AtomicU64,
}

impl FilterCounts {
    /// Datagrams handed to quinn.
    pub fn admitted(&self) -> u64 {
        self.admitted.load(Ordering::Relaxed)
    }

    /// Datagrams dropped before quinn saw them.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// A UDP socket that hears one address and one token.
pub struct IntroducedSocket {
    socket: Arc<UdpSocket>,
    expect: IntroducedPeer,
    counts: Arc<FilterCounts>,
}

impl fmt::Debug for IntroducedSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntroducedSocket")
            .field("local", &self.socket.local_addr().ok())
            .field("expect", &self.expect)
            .finish_non_exhaustive()
    }
}

impl IntroducedSocket {
    /// Wrap an already-bound socket. It must be non-blocking; a `tokio` socket is
    /// made from it here.
    pub fn new(socket: std::net::UdpSocket, expect: IntroducedPeer) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        Ok(Self {
            socket: Arc::new(UdpSocket::from_std(socket)?),
            expect,
            counts: Arc::new(FilterCounts::default()),
        })
    }

    /// The counters, shared with whoever asked for them before the socket moved
    /// into quinn.
    pub fn counts(&self) -> Arc<FilterCounts> {
        Arc::clone(&self.counts)
    }

    /// Whether `datagram`, from `from`, is the introduced peer's. The token is
    /// compared in constant time, so a stranger cannot learn it a byte at a time
    /// from how long a refusal takes — a refusal it never sees, but the rule costs
    /// nothing.
    fn admits(&self, from: SocketAddr, datagram: &[u8]) -> bool {
        if from != self.expect.addr || datagram.len() <= INTRODUCTION_TOKEN_LEN {
            return false;
        }
        let differ = datagram[..INTRODUCTION_TOKEN_LEN]
            .iter()
            .zip(self.expect.token.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        differ == 0
    }
}

/// Write-readiness from the socket itself, so a full send buffer parks quinn
/// rather than spinning it.
pub(super) struct Writable(pub(super) Arc<UdpSocket>);

impl fmt::Debug for Writable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Writable")
    }
}

impl UdpPoller for Writable {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.0.poll_send_ready(cx)
    }
}

impl AsyncUdpSocket for IntroducedSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Writable(Arc::clone(&self.socket)))
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // Nobody else was ever heard from, so quinn has nobody else to answer; this
        // is the same rule on the way out, so it holds by construction rather than
        // by inference.
        if transmit.destination != self.expect.addr {
            return Ok(());
        }
        let mut datagram = Vec::with_capacity(INTRODUCTION_TOKEN_LEN + transmit.contents.len());
        datagram.extend_from_slice(&self.expect.token);
        datagram.extend_from_slice(transmit.contents);
        self.socket
            .try_send_to(&datagram, transmit.destination)
            .map(|_| ())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let Some(buf) = bufs.first_mut() else {
            return Poll::Ready(Ok(0));
        };
        loop {
            let mut read = ReadBuf::new(buf);
            let from = match self.socket.poll_recv_from(cx, &mut read) {
                Poll::Ready(Ok(from)) => from,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            let n = read.filled().len();
            if !self.admits(from, &buf[..n]) {
                self.counts.dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            buf.copy_within(INTRODUCTION_TOKEN_LEN..n, 0);
            let len = n - INTRODUCTION_TOKEN_LEN;
            meta[0] = RecvMeta {
                addr: from,
                len,
                stride: len,
                ecn: None,
                dst_ip: None,
            };
            self.counts.admitted.fetch_add(1, Ordering::Relaxed);
            return Poll::Ready(Ok(1));
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

/// The transport settings every introduced endpoint uses: the peer defaults, and no
/// path-MTU probing, since every datagram is sixteen bytes longer than quinn thinks
/// it is and a probe sized to the link would not fit.
pub(super) fn introduced_transport() -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(100u32.into());
    transport.max_concurrent_uni_streams(100u32.into());
    transport.mtu_discovery_config(None);
    Arc::new(transport)
}

/// A verifier that admits one key: the device the introduction named.
pub(super) fn one_key(peer_key: [u8; 32], provider: &Arc<rustls::crypto::CryptoProvider>) -> Arc<PairedDeviceVerifier> {
    PairedDeviceVerifier::new(
        Arc::new(RwLock::new(HashSet::from([peer_key]))),
        Arc::clone(provider),
    )
}

/// Open the listener an introduction asked for: on `bind`, hearing only `expect`,
/// completing a handshake only with `peer_key`, and accepting **one** connection.
///
/// Returns the listener and its filter's counters.
pub fn listen_introduced(
    device_key: &ed25519_dalek::SigningKey,
    peer_key: [u8; 32],
    bind: SocketAddr,
    expect: IntroducedPeer,
) -> TransportResult<(IntroducedListener, Arc<FilterCounts>)> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cert = Ed25519DeviceCert::from_signing_key(device_key)?;
    let mut server =
        tls::build_peer_server_config(&cert, one_key(peer_key, &provider), provider, None)?;
    server.transport_config(introduced_transport());

    let std_socket = std::net::UdpSocket::bind(bind)
        .map_err(|e| TransportError::ConnectionFailed(format!("bind {bind}: {e}")))?;
    let socket = IntroducedSocket::new(std_socket, expect)
        .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
    let counts = socket.counts();
    let local = socket
        .local_addr()
        .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
    let endpoint = Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server),
        Arc::new(socket),
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
    Ok((
        IntroducedListener {
            endpoint,
            local_addr: Address::Quic(local),
            taken: AtomicBool::new(false),
        },
        counts,
    ))
}

/// Dial the other end of an introduction from `socket` — the socket whose address
/// this device handed over, so the far filter hears it — admitting only
/// `peer_key`.
///
/// Returns the connection and this end's filter counters. The endpoint lives as
/// long as the connection does.
pub async fn dial_introduced(
    device_key: &ed25519_dalek::SigningKey,
    offer: &CertOffer,
    peer_key: [u8; 32],
    socket: std::net::UdpSocket,
    expect: IntroducedPeer,
) -> TransportResult<(quinn::Connection, Arc<FilterCounts>)> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cert = Ed25519DeviceCert::from_signing_key_with_offer(device_key, offer)?;
    let mut client =
        tls::build_peer_client_config(&cert, one_key(peer_key, &provider), provider, None)?;
    client.transport_config(introduced_transport());

    let socket = IntroducedSocket::new(socket, expect)
        .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
    let counts = socket.counts();
    let endpoint = Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        Arc::new(socket),
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
    let conn = endpoint
        .connect_with(client, expect.addr, "kotton-peer")
        .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?
        .await
        .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
    Ok((conn, counts))
}

/// The introduced listener: one connection, then no more.
pub struct IntroducedListener {
    endpoint: Endpoint,
    local_addr: Address,
    taken: AtomicBool,
}

impl IntroducedListener {
    /// Where it is bound — the address handed back over the sealed channel.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match self.local_addr {
            Address::Quic(addr) => Some(addr),
            _ => None,
        }
    }
}

#[async_trait::async_trait]
impl Listener for IntroducedListener {
    /// The one connection. A second call is refused: the introduction named one
    /// session, and once it is open the endpoint takes no new handshake from
    /// anyone, the introduced device included.
    async fn accept(&self) -> TransportResult<Box<dyn Connection>> {
        if self.taken.swap(true, Ordering::SeqCst) {
            return Err(TransportError::ListenerClosed);
        }
        // A handshake that fails — a key the verifier refuses — does not spend the
        // introduction; the token's lifetime, which the caller holds, is what ends
        // the wait. The first that completes is the session.
        let connection = loop {
            let incoming = self
                .endpoint
                .accept()
                .await
                .ok_or(TransportError::ListenerClosed)?;
            match incoming.await {
                Ok(connection) => break connection,
                Err(e) => tracing::debug!(error = %e, "an introduced handshake failed"),
            }
        };
        self.endpoint.set_server_config(None);
        // The verifier admitted one key, so the certificate names it.
        let peer_id = connection
            .peer_identity()
            .and_then(|id| id.downcast::<Vec<CertificateDer<'static>>>().ok())
            .and_then(|certs| certs.into_iter().next())
            .and_then(|cert| tls::extract_ed25519_pubkey_from_cert(&cert))
            .and_then(|pubkey| DidKeyMethod::from_public_key_bytes(&pubkey).ok())
            .map(|did| did.to_string())
            .ok_or_else(|| {
                TransportError::ConnectionFailed("introduced peer presented no device key".into())
            })?;
        Ok(Box::new(super::connection::QuicConnection::new(
            connection, peer_id,
        )))
    }

    fn local_addr(&self) -> &Address {
        &self.local_addr
    }

    async fn close(&self) -> TransportResult<()> {
        self.endpoint.close(0u32.into(), b"introduction over");
        self.endpoint.wait_idle().await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const TOKEN: [u8; INTRODUCTION_TOKEN_LEN] = [7; INTRODUCTION_TOKEN_LEN];

    fn key(n: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[n; 32])
    }

    fn loopback() -> std::net::UdpSocket {
        std::net::UdpSocket::bind("127.0.0.1:0").unwrap()
    }

    /// Nothing comes back to `socket` within half a second.
    fn hears_nothing(socket: &std::net::UdpSocket) -> bool {
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let mut buf = [0u8; 2048];
        socket.recv_from(&mut buf).is_err()
    }

    /// A listener opened for device 2 at `dialer`'s address, on loopback.
    fn open_for(dialer: SocketAddr) -> (IntroducedListener, Arc<FilterCounts>, SocketAddr) {
        let (listener, counts) = listen_introduced(
            &key(1),
            key(2).verifying_key().to_bytes(),
            "127.0.0.1:0".parse().unwrap(),
            IntroducedPeer {
                addr: dialer,
                token: TOKEN,
            },
        )
        .unwrap();
        let at = listener.socket_addr().unwrap();
        (listener, counts, at)
    }

    /// The Done-when's own test: a stranger's packet to an introduced listener is
    /// dropped with no reply and no parse. Four strangers, each missing one thing —
    /// no token, the right token from the wrong address, junk from the right
    /// address, and a whole QUIC handshake carrying the right token *and* the
    /// introduced device's own key from the wrong address — and not one datagram of
    /// theirs reaches quinn.
    #[tokio::test]
    async fn a_strangers_packet_to_an_introduced_listener_gets_no_reply_and_no_parse() {
        let dialer = loopback();
        let (listener, counts, at) = open_for(dialer.local_addr().unwrap());

        let stranger = loopback();
        // A QUIC Initial's first byte and some length, with no token.
        stranger.send_to(&[0xc0; 1200], at).unwrap();
        // The token, from an address the introduction did not name.
        let mut with_token = TOKEN.to_vec();
        with_token.extend_from_slice(&[0xc0; 1200]);
        stranger.send_to(&with_token, at).unwrap();
        // The right address, without the token.
        dialer.send_to(&[0xc0; 1200], at).unwrap();
        // The token alone is not a datagram.
        dialer.send_to(&TOKEN, at).unwrap();
        assert!(hears_nothing(&stranger), "a stranger was answered");
        assert!(hears_nothing(&dialer), "a tokenless datagram was answered");

        // A full handshake from elsewhere, with the token and the introduced key.
        let (introduced_key, offer) = (key(2), CertOffer::default());
        let elsewhere = dial_introduced(
            &introduced_key,
            &offer,
            key(1).verifying_key().to_bytes(),
            loopback(),
            IntroducedPeer { addr: at, token: TOKEN },
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(2), elsewhere).await.is_err(),
            "a handshake from an address the introduction did not name completed"
        );

        assert_eq!(counts.admitted(), 0, "a stranger's datagram reached quinn");
        assert!(counts.dropped() >= 5, "dropped {}", counts.dropped());
        drop(listener);
    }

    /// The introduced device, from the address it gave and with the token, is
    /// admitted, and a request round-trips; the listener then takes no second
    /// connection.
    #[tokio::test]
    async fn the_introduced_device_is_admitted_once() {
        let dialer = loopback();
        let dialer_at = dialer.local_addr().unwrap();
        let (listener, counts, at) = open_for(dialer_at);

        let serve = tokio::spawn(async move {
            let conn = listener.accept().await.expect("accept the introduced device");
            assert_eq!(
                conn.peer_id(),
                DidKeyMethod::from_public_key_bytes(&key(2).verifying_key().to_bytes())
                    .unwrap()
                    .to_string()
            );
            let served = conn
                .serve_one_request(Box::new(|req: Vec<u8>| {
                    Box::pin(async move { [b"echo:".as_slice(), &req].concat() })
                }))
                .await
                .unwrap();
            assert!(served);
            assert!(matches!(
                listener.accept().await,
                Err(TransportError::ListenerClosed)
            ));
            // Held until the dialler closes it, which is the session ending.
            assert!(!conn.serve_one_request(Box::new(|_| Box::pin(async { Vec::new() }))).await.unwrap());
        });

        let (conn, dial_counts) = dial_introduced(
            &key(2),
            &CertOffer::default(),
            key(1).verifying_key().to_bytes(),
            dialer,
            IntroducedPeer { addr: at, token: TOKEN },
        )
        .await
        .expect("dial the introduced listener");
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(&3u32.to_be_bytes()).await.unwrap();
        send.write_all(b"hey").await.unwrap();
        send.finish().unwrap();
        let reply = recv.read_to_end(1024).await.unwrap();
        assert_eq!(&reply[4..], b"echo:hey");
        conn.close(0u32.into(), b"done");
        serve.await.unwrap();
        assert!(counts.admitted() > 0 && dial_counts.admitted() > 0);
        assert_eq!(counts.dropped(), 0);
    }

    /// A handshake from the introduced address with the token, by a device whose key
    /// the introduction did not name, does not complete: the filter is not the only
    /// door, and the one-key verifier behind it still holds.
    #[tokio::test]
    async fn the_right_address_and_token_with_another_key_is_refused() {
        let dialer = loopback();
        let (listener, _counts, at) = open_for(dialer.local_addr().unwrap());
        let serve = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(3), listener.accept())
                .await
                .is_ok()
        });
        let (other_key, offer) = (key(3), CertOffer::default());
        // In TLS 1.3 the client finishes before the server has judged its
        // certificate, so the dial may resolve; the listener is what must refuse.
        let _dialled = tokio::time::timeout(
            Duration::from_secs(3),
            dial_introduced(
                &other_key,
                &offer,
                key(1).verifying_key().to_bytes(),
                dialer,
                IntroducedPeer { addr: at, token: TOKEN },
            ),
        )
        .await;
        assert!(
            !serve.await.unwrap(),
            "the listener opened a session for a key the introduction did not name"
        );
    }
}
