// SPDX-License-Identifier: AGPL-3.0-or-later
//! Peer communication channel abstraction.
//!
//! [`PeerChannel`] is the single I/O primitive used by [`KottonPeerObjectStorage`].
//! [`QuicPeerChannel`] wraps a live `quinn::Connection` — one bi-directional QUIC
//! stream is opened per request, matching the same 4-byte-BE-length-prefix framing
//! used by the local IPC channel (see `crates/03_providers/ipc/src/client.rs`).

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ---------------------------------------------------------------------------
// PeerChannel trait
// ---------------------------------------------------------------------------

/// Abstraction over the peer wire transport.
///
/// Each call to [`request`] sends `req_bytes` to the remote peer and returns
/// the response bytes. Implementations may reuse a single connection across
/// multiple calls (expected) or open a new connection per call (valid but
/// wasteful).
///
/// The framing details (length prefix, encoding) are the responsibility of
/// the implementation — callers just pass and receive raw bytes.
#[async_trait]
pub trait PeerChannel: Send + Sync {
    /// Send `req_bytes` to the peer and return the response bytes.
    async fn request(&self, req_bytes: &[u8]) -> anyhow::Result<Vec<u8>>;

    /// Whether this link is already known to be dead — closed by either end, or
    /// timed out idle — so that no request sent on it can succeed.
    ///
    /// `false` means "not known to be dead", never "alive": a link can die the
    /// moment after this answers. [`RedialingChannel`] asks it before a request
    /// and dials again only on `true`, so a request is never sent twice.
    fn is_closed(&self) -> bool {
        false
    }

    /// The peer's refusal of this side's key at the handshake, when that is
    /// how this link ended ([`RefusedAtHandshake`]). `None` for a link that is
    /// alive, or that ended any other way.
    fn refused(&self) -> Option<RefusedAtHandshake> {
        None
    }
}

/// **The peer refused this side's key at the handshake.** The pinned peer
/// closed the connection with a TLS alert after this side's certificate
/// reached it — the one way a peer says *your key is not one I admit*, since
/// a key it does not admit never gets past the handshake to be answered a
/// request. The close arrives under the handshake's keys, which only the peer
/// that proved its pinned key holds, so a relay or a forwarder between the two
/// cannot send it; a connection dropped, reset or timed out is never one.
///
/// A request on a link that ended this way fails with this as its error,
/// found with [`refused_at_handshake`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the peer refused this key at the handshake (TLS alert {alert})")]
pub struct RefusedAtHandshake {
    /// The TLS alert the peer closed with.
    pub alert: u8,
}

/// The peer's refusal of this side's key at the handshake, if `error` is one —
/// a request's error, wherever in its chain the refusal was set.
pub fn refused_at_handshake(error: &anyhow::Error) -> Option<RefusedAtHandshake> {
    error.chain().find_map(|e| e.downcast_ref::<RefusedAtHandshake>().copied())
}

/// The refusal a QUIC connection's close is, if it is one: the peer closed it
/// with a crypto error, which carries a TLS alert (RFC 9001 §4.8). A close by
/// this side, an application's close, a reset or a timeout is not.
fn refusal_of(reason: &quinn::ConnectionError) -> Option<RefusedAtHandshake> {
    match reason {
        quinn::ConnectionError::ConnectionClosed(close) => {
            let code = u64::from(close.error_code);
            (0x100..=0x1ff).contains(&code).then_some(RefusedAtHandshake { alert: (code & 0xff) as u8 })
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// RedialingChannel
// ---------------------------------------------------------------------------

/// How a [`RedialingChannel`] makes a fresh link: the same dial, to the same
/// pinned peer, that made the first one.
pub type Redial = Box<
    dyn Fn() -> std::pin::Pin<
            Box<dyn std::future::Future<Output = anyhow::Result<std::sync::Arc<dyn PeerChannel>>> + Send>,
        > + Send
        + Sync,
>;

/// A peer link that outlives the connection under it.
///
/// A remote is registered once and used for the rest of the session, but a QUIC
/// connection is not a session. The idle close is held off by the keep-alive
/// every rung of the dial now carries (`NatConfig::keepalive`); what is left is
/// a connection that dies anyway — the peer restarted, the path changed, the
/// peer closed it. A remote that held one connection for life would be dead
/// from then on, and every request on it would fail until the remote was added
/// again.
///
/// So the connection is held as a cache of the dial, not as the link. Before
/// each request the current connection is asked [`PeerChannel::is_closed`], and
/// only a connection already known to be dead is replaced — nothing was sent on
/// it, so nothing is sent twice. A request whose connection dies *during* it
/// fails as it did before; the next one dials. That window cannot be closed
/// from this side, which is why the keep-alive, and not this, is what keeps an
/// idle remote alive.
///
/// **A new dial is a new handshake.** It runs the whole mTLS exchange against
/// the peer's pinned key, and the peer checks this device against its allowlist
/// as it stands *now*: a device unpaired or a tenant dropped since the first
/// dial is refused at the handshake, exactly as a first dial would be. That
/// holds **by construction**, and it is load-bearing: every rung of the dial
/// builds a fresh client config (and the relay rung a fresh client), so there is
/// no TLS session ticket to resume — and a resumed TLS 1.3 session would not
/// run the peer's client-certificate check again. A redial that reused a config
/// would carry a stale admission. `a_device_unpaired_since_the_first_dial_is_refused_on_the_redial`
/// shows the peer re-asks its allowlist on a fresh handshake; that `open_channel`
/// never reuses a config is the by-construction half, and no test holds it.
pub struct RedialingChannel {
    link: tokio::sync::Mutex<std::sync::Arc<dyn PeerChannel>>,
    redial: Redial,
}

impl RedialingChannel {
    /// Hold `link`, the connection the first dial made, and `redial`, the dial
    /// that makes another when it has closed.
    pub fn new(link: std::sync::Arc<dyn PeerChannel>, redial: Redial) -> Self {
        Self {
            link: tokio::sync::Mutex::new(link),
            redial,
        }
    }
}

#[async_trait]
impl PeerChannel for RedialingChannel {
    async fn request(&self, req_bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
        // Held across the dial, so requests that find the same dead connection
        // wait for one new one rather than each dialling their own.
        let link = {
            let mut link = self.link.lock().await;
            if link.is_closed() {
                tracing::debug!("peer connection closed; dialling the peer again");
                *link = (self.redial)().await?;
            }
            std::sync::Arc::clone(&link)
        };
        link.request(req_bytes).await
    }
}

// ---------------------------------------------------------------------------
// QuicPeerChannel
// ---------------------------------------------------------------------------

/// A [`PeerChannel`] backed by a live `quinn::Connection`.
///
/// Each [`request`] call opens a single bidirectional QUIC stream, writes the
/// request (4-byte BE length prefix + payload) on the send half, reads the
/// response (4-byte BE length prefix + payload) from the recv half, then closes
/// the send half. The quinn connection is kept alive across multiple calls.
///
/// Concurrency: all operations are safe to call concurrently — quinn multiplexes
/// streams over the same connection in parallel.
#[derive(Clone)]
pub struct QuicPeerChannel {
    conn: std::sync::Arc<quinn::Connection>,
}

impl QuicPeerChannel {
    /// Wrap an established [`quinn::Connection`].
    pub fn new(conn: quinn::Connection) -> Self {
        Self {
            conn: std::sync::Arc::new(conn),
        }
    }

    /// The maximum response size the channel will read (10 MB).
    ///
    /// Responses larger than this are rejected to prevent memory exhaustion by
    /// a misbehaving peer.
    pub const MAX_RESPONSE_BYTES: u32 = 10 * 1024 * 1024;
}

#[async_trait]
impl PeerChannel for QuicPeerChannel {
    /// One exchange ([`Self::exchange`]); when it fails because the peer
    /// refused this key at the handshake, that refusal is its error.
    async fn request(&self, req_bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.exchange(req_bytes).await.map_err(|e| match self.refused() {
            Some(refused) => anyhow::Error::new(refused).context(format!("{e:#}")),
            None => e,
        })
    }

    fn is_closed(&self) -> bool {
        self.conn.close_reason().is_some()
    }

    fn refused(&self) -> Option<RefusedAtHandshake> {
        self.conn.close_reason().as_ref().and_then(refusal_of)
    }
}

impl QuicPeerChannel {
    /// Open a stream, write the framed request, and read the framed answer.
    async fn exchange(&self, req_bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
        // Open a bidirectional stream for this single request/response exchange.
        let (mut send, mut recv) = self
            .conn
            .open_bi()
            .await
            .map_err(|e| anyhow::anyhow!("open_bi failed: {e}"))?;

        // Write 4-byte BE length + payload
        let len = req_bytes.len() as u32;
        send.write_u32(len)
            .await
            .map_err(|e| anyhow::anyhow!("write length failed: {e}"))?;
        send.write_all(req_bytes)
            .await
            .map_err(|e| anyhow::anyhow!("write payload failed: {e}"))?;
        send.finish()
            .map_err(|e| anyhow::anyhow!("finish send failed: {e}"))?;

        // Read 4-byte BE length + response payload
        let resp_len = recv
            .read_u32()
            .await
            .map_err(|e| anyhow::anyhow!("read response length failed: {e}"))?;

        if resp_len > Self::MAX_RESPONSE_BYTES {
            anyhow::bail!(
                "peer response too large: {} bytes (max {})",
                resp_len,
                Self::MAX_RESPONSE_BYTES
            );
        }

        let mut buf = vec![0u8; resp_len as usize];
        recv.read_exact(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("read response payload failed: {e}"))?;

        Ok(buf)
    }
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// An in-process mock channel pre-loaded with (request_matcher → response) pairs.
///
/// Each call to [`request`] pops the first entry from the response queue and
/// returns it.  Returns an error if the queue is empty.
#[cfg(test)]
pub(crate) mod mock {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    pub struct MockPeerChannel {
        responses: Mutex<VecDeque<Vec<u8>>>,
        received: Mutex<Vec<Vec<u8>>>,
    }

    impl MockPeerChannel {
        pub fn new(responses: Vec<Vec<u8>>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                received: Mutex::new(Vec::new()),
            }
        }

        pub fn take_received(&self) -> Vec<Vec<u8>> {
            self.received.lock().unwrap().drain(..).collect()
        }
    }

    #[async_trait]
    impl PeerChannel for MockPeerChannel {
        async fn request(&self, req_bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
            self.received.lock().unwrap().push(req_bytes.to_vec());
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("MockPeerChannel: no more responses queued"))
        }
    }
}

/// A link that outlives its connection, against a real QUIC peer on loopback
/// whose idle timeout is short enough to pass inside a test.
#[cfg(test)]
pub(crate) mod redial_tests {
    use super::*;
    use kotton_net::transport::quic::tls::{self, Ed25519DeviceCert, PairedDeviceVerifier};
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, RwLock};
    use std::time::Duration;

    /// What the peer advertises. Quinn's default is 30 s — the half-minute a
    /// registered remote used to survive — and a connection lives by the
    /// smaller of the two ends' values, so the peer's alone decides it here.
    const IDLE: Duration = Duration::from_millis(300);

    fn allowing(key: &ed25519_dalek::SigningKey) -> Arc<PairedDeviceVerifier> {
        let mut keys = HashSet::new();
        keys.insert(key.verifying_key().to_bytes());
        PairedDeviceVerifier::new(
            Arc::new(RwLock::new(keys)),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
    }

    /// A paired peer on loopback that answers every request with its own
    /// bytes, and times a connection out after `idle` with nothing received.
    pub(crate) fn echo_peer(
        server: &ed25519_dalek::SigningKey,
        client: &ed25519_dalek::SigningKey,
        idle: Duration,
    ) -> std::net::SocketAddr {
        let mut keys = HashSet::new();
        keys.insert(client.verifying_key().to_bytes());
        echo_peer_admitting(server, Arc::new(RwLock::new(keys)), idle)
    }

    /// [`echo_peer`], admitting whoever `allowed` holds *at each handshake* —
    /// the live allowlist a real peer keeps, so a test can unpair a device.
    fn echo_peer_admitting(
        server: &ed25519_dalek::SigningKey,
        allowed: Arc<RwLock<HashSet<[u8; 32]>>>,
        idle: Duration,
    ) -> std::net::SocketAddr {
        let cert = Ed25519DeviceCert::from_signing_key(server).unwrap();
        let mut config = tls::build_peer_server_config(
            &cert,
            PairedDeviceVerifier::new(allowed, Arc::new(rustls::crypto::ring::default_provider())),
            Arc::new(rustls::crypto::ring::default_provider()),
            None,
        )
        .unwrap();
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(idle.try_into().unwrap()));
        config.transport_config(Arc::new(transport));
        let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                tokio::spawn(async move {
                    let Ok(conn) = incoming.await else { return };
                    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                        let len = recv.read_u32().await.unwrap();
                        let mut buf = vec![0u8; len as usize];
                        recv.read_exact(&mut buf).await.unwrap();
                        send.write_u32(len).await.unwrap();
                        send.write_all(&buf).await.unwrap();
                        send.finish().unwrap();
                    }
                });
            }
        });
        addr
    }

    async fn dial(
        client: &ed25519_dalek::SigningKey,
        server: &ed25519_dalek::SigningKey,
        addr: std::net::SocketAddr,
    ) -> anyhow::Result<Arc<dyn PeerChannel>> {
        let cert = Ed25519DeviceCert::from_signing_key(client)?;
        let config = tls::build_peer_client_config(
            &cert,
            allowing(server),
            Arc::new(rustls::crypto::ring::default_provider()),
            None,
        )?;
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
        let conn = endpoint.connect_with(config, addr, "kotton-peer")?.await?;
        Ok(Arc::new(QuicPeerChannel::new(conn)))
    }

    pub(crate) fn keys() -> (ed25519_dalek::SigningKey, ed25519_dalek::SigningKey) {
        (
            ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]),
            ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]),
        )
    }

    /// The defect, stated on the bare connection: one left quiet past the idle
    /// timeout is dead, says so, and fails the next request with the error the
    /// landlord-drop tests saw.
    #[tokio::test]
    async fn a_connection_left_quiet_past_its_idle_timeout_is_dead_and_says_so() {
        let (server, client) = keys();
        let addr = echo_peer(&server, &client, IDLE);
        let link = dial(&client, &server, addr).await.unwrap();
        assert_eq!(link.request(b"hello").await.unwrap(), b"hello");
        assert!(!link.is_closed());

        tokio::time::sleep(IDLE * 4).await;

        assert!(link.is_closed(), "an idle connection past its timeout is closed");
        let err = link.request(b"again").await.unwrap_err().to_string();
        assert!(err.contains("open_bi failed: timed out"), "{err}");
    }

    fn counting_redial(
        client: ed25519_dalek::SigningKey,
        server: ed25519_dalek::SigningKey,
        addr: std::net::SocketAddr,
        dials: Arc<AtomicUsize>,
    ) -> Redial {
        Box::new(move || {
            let (client, server, dials) = (client.clone(), server.clone(), Arc::clone(&dials));
            Box::pin(async move {
                dials.fetch_add(1, Ordering::SeqCst);
                dial(&client, &server, addr).await
            })
        })
    }

    /// The fix: the same quiet half-minute, and the next request is answered —
    /// over a second dial, because the first connection is gone.
    #[tokio::test]
    async fn a_link_whose_connection_idled_out_dials_again_and_is_answered() {
        let (server, client) = keys();
        let addr = echo_peer(&server, &client, IDLE);
        let dials = Arc::new(AtomicUsize::new(0));
        let link = RedialingChannel::new(
            dial(&client, &server, addr).await.unwrap(),
            counting_redial(client.clone(), server.clone(), addr, Arc::clone(&dials)),
        );
        assert_eq!(link.request(b"hello").await.unwrap(), b"hello");

        tokio::time::sleep(IDLE * 4).await;

        assert_eq!(link.request(b"again").await.unwrap(), b"again");
        assert_eq!(dials.load(Ordering::SeqCst), 1, "one new dial, for the dead connection");
    }

    /// A connection that is alive is used, never replaced: the dial is for a
    /// link known to be dead, not a reflex before every request.
    #[tokio::test]
    async fn a_live_connection_is_used_and_not_dialled_again() {
        let (server, client) = keys();
        let addr = echo_peer(&server, &client, IDLE);
        let dials = Arc::new(AtomicUsize::new(0));
        let link = RedialingChannel::new(
            dial(&client, &server, addr).await.unwrap(),
            counting_redial(client.clone(), server.clone(), addr, Arc::clone(&dials)),
        );
        for i in 0u8..5 {
            assert_eq!(link.request(&[i]).await.unwrap(), vec![i]);
        }
        assert_eq!(dials.load(Ordering::SeqCst), 0);
    }

    /// A redial is a first dial, so the peer's allowlist is asked again: a
    /// device unpaired since the first connection is refused on the second,
    /// and the request fails rather than reaching the peer. The dial builds a
    /// fresh client config each time — as every rung of `open_channel` does —
    /// so there is no TLS session to resume and no admission carried over.
    #[tokio::test]
    async fn a_device_unpaired_since_the_first_dial_is_refused_on_the_redial() {
        let (server, client) = keys();
        let mut keys = HashSet::new();
        keys.insert(client.verifying_key().to_bytes());
        let allowed = Arc::new(RwLock::new(keys));
        let addr = echo_peer_admitting(&server, Arc::clone(&allowed), IDLE);
        let dials = Arc::new(AtomicUsize::new(0));
        let link = RedialingChannel::new(
            dial(&client, &server, addr).await.unwrap(),
            counting_redial(client.clone(), server.clone(), addr, Arc::clone(&dials)),
        );
        assert_eq!(link.request(b"hello").await.unwrap(), b"hello");

        allowed.write().unwrap().clear();
        tokio::time::sleep(IDLE * 4).await;

        let refused = link.request(b"again").await;
        assert!(refused.is_err(), "an unpaired device was answered on the redial: {refused:?}");
        assert!(refused.as_ref().is_err_and(|e| refused_at_handshake(e).is_some()), "not said as a refusal: {refused:?}");
        assert_eq!(dials.load(Ordering::SeqCst), 1, "the refusal came from a new handshake");
    }

    /// **A key the peer does not admit is said as its refusal.** The peer's
    /// allowlist holds nobody: the dial's own half of the handshake completes,
    /// the peer closes with a TLS alert once it reads this key, and the request
    /// fails with [`RefusedAtHandshake`]. A [`RedialingChannel`] dials again —
    /// an allowlist changes, and a key admitted a moment after its first
    /// handshake is answered on the next — and a peer that still refuses it
    /// says so again.
    #[tokio::test]
    async fn a_key_the_peer_does_not_admit_is_said_as_its_refusal() {
        let (server, client) = keys();
        let addr = echo_peer_admitting(&server, Arc::new(RwLock::new(HashSet::new())), Duration::from_secs(5));
        let dials = Arc::new(AtomicUsize::new(0));
        let link = RedialingChannel::new(
            dial(&client, &server, addr).await.expect("this side's half of the handshake completes"),
            counting_redial(client.clone(), server.clone(), addr, Arc::clone(&dials)),
        );
        let err = link.request(b"hello").await.expect_err("an unadmitted key was answered");
        assert!(refused_at_handshake(&err).is_some(), "not said as a refusal: {err:#}");
        let again = link.request(b"again").await.expect_err("an unadmitted key was answered");
        assert!(refused_at_handshake(&again).is_some(), "{again:#}");
        assert_eq!(dials.load(Ordering::SeqCst), 1, "the second request was a new handshake");
    }

    /// **A connection cut after the handshake is no refusal.** A stand-in that
    /// admits this key, takes the connection and closes it — what a forwarder
    /// dropping the wire, or a peer going away, looks like from here — fails
    /// the request without [`RefusedAtHandshake`]: nothing said the key is not
    /// admitted.
    #[tokio::test]
    async fn a_connection_cut_after_the_handshake_is_no_refusal() {
        let (server, client) = keys();
        let cert = Ed25519DeviceCert::from_signing_key(&server).unwrap();
        let config = tls::build_peer_server_config(&cert, allowing(&client), Arc::new(rustls::crypto::ring::default_provider()), None)
            .unwrap();
        let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                if let Ok(conn) = incoming.await {
                    conn.close(0u32.into(), b"gone");
                }
            }
        });
        let link = dial(&client, &server, addr).await.expect("the handshake completes");
        let err = link.request(b"hello").await.expect_err("a closed connection answered");
        assert!(refused_at_handshake(&err).is_none(), "a cut wire was said as a refusal: {err:#}");
        assert!(link.refused().is_none());
    }

    /// A dial that fails is the request's error, not a silent success: a peer
    /// that has gone refuses nothing on this side's say-so.
    #[tokio::test]
    async fn a_redial_that_fails_fails_the_request() {
        let (server, client) = keys();
        let addr = echo_peer(&server, &client, IDLE);
        let first = dial(&client, &server, addr).await.unwrap();
        let link = RedialingChannel::new(
            first,
            Box::new(|| Box::pin(async { Err(anyhow::anyhow!("the peer is not there")) })),
        );
        tokio::time::sleep(IDLE * 4).await;
        let err = link.request(b"again").await.unwrap_err().to_string();
        assert!(err.contains("the peer is not there"), "{err}");
    }
}
