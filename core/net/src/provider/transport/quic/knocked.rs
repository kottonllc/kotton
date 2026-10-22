// SPDX-License-Identifier: AGPL-3.0-or-later
//! A person's door on the local network, as their contacts reach it: one socket,
//! and behind it one door per contact pair, each chosen by a knock that pair alone
//! derives (`TASK-a-contacts-message-can-reach-their-device-over-the-local-network-while-its-door-is-open`).
//!
//! The door is on a network the person does not control, so what it must not do is
//! parse a stranger's packet — the rule [`super::introduced`] set for an introduced
//! listener, and the same framing: sixteen bytes on the front of every datagram,
//! stripped on the way in. What differs is who the sixteen bytes are for. An
//! introduction names one peer and one address in advance; a contact on the same
//! network is not known in advance, so the front hears **any** address, and routes a
//! datagram only by its knock. A knock is derived from the two people's identity keys
//! and the door's nonce (`kotton_crypto::contact_knock_to_open`), so a datagram
//! whose knock the front does not hold is dropped before quinn sees a byte of it,
//! with no reply.
//!
//! Behind the knock is the pair door exactly as a relay serves it: the person's
//! handle for the pair and the hour as the certificate, a verifier that admits one
//! key — the contact's handle for the same pair and hour — and whatever handler the
//! caller hands it, which is the one-verb contact door. One quinn endpoint per pair
//! door, each fed only its own knock's datagrams: nothing on one pair's endpoint can
//! be reached with another pair's knock, so there is no check here of *which*
//! contact arrived — the knock already chose the only door they can reach.
//!
//! What the knock is not: a secret against someone on the path. It travels in the
//! clear on every datagram of the session, as an introduction's token does; a
//! machine that copies it reaches quinn's parse and no further, since the one-key
//! handshake still holds. It is also not a name: the door's nonce is new each time
//! the door opens, so a knock heard in one session is noise in the next.

use super::introduced::{introduced_transport, one_key, FilterCounts, IntroducedPeer, Writable};
use super::tls::{self, CertOffer, Ed25519DeviceCert};
use kotton_crypto::DidKeyMethod;
use kotton_sys::net::{Address, Connection, Listener, TransportError, TransportResult};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, Endpoint, UdpPoller};
use rustls::pki_types::CertificateDer;
use std::collections::HashMap;
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// How long a knock is — the introduction token's length, since both are the same
/// framing on the same kind of socket.
pub const KNOCK_LEN: usize = super::introduced::INTRODUCTION_TOKEN_LEN;

/// One pair's knock for one session and hour.
pub type Knock = [u8; KNOCK_LEN];

/// How many datagrams a pair door may have queued before the front drops the next.
/// A LAN handshake is a handful; this bounds what one contact can make the front
/// hold, and a dropped datagram is one QUIC retransmits.
const DOOR_QUEUE: usize = 256;

type Datagram = (SocketAddr, Vec<u8>);

/// The one socket a person's contacts knock on.
pub struct KnockFront {
    socket: Arc<UdpSocket>,
    doors: Arc<RwLock<HashMap<Knock, mpsc::Sender<Datagram>>>>,
    counts: Arc<FilterCounts>,
    pump: tokio::task::JoinHandle<()>,
    local: SocketAddr,
}

impl fmt::Debug for KnockFront {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KnockFront")
            .field("local", &self.local)
            .field("doors", &self.doors.read().unwrap().len())
            .finish_non_exhaustive()
    }
}

impl KnockFront {
    /// Bind the front on `bind` with no door behind it: until a door is opened, every
    /// datagram is dropped.
    pub fn bind(bind: SocketAddr) -> TransportResult<Self> {
        let std_socket = std::net::UdpSocket::bind(bind)
            .map_err(|e| TransportError::ConnectionFailed(format!("bind {bind}: {e}")))?;
        std_socket
            .set_nonblocking(true)
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        let socket = Arc::new(
            UdpSocket::from_std(std_socket)
                .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?,
        );
        let local = socket
            .local_addr()
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        let doors: Arc<RwLock<HashMap<Knock, mpsc::Sender<Datagram>>>> = Arc::default();
        let counts = Arc::new(FilterCounts::default());
        let pump = tokio::spawn(pump(
            Arc::clone(&socket),
            Arc::clone(&doors),
            Arc::clone(&counts),
        ));
        Ok(Self { socket, doors, counts, pump, local })
    }

    /// Where the front is bound — the address and port the door announces.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// What the front routed and what it dropped before any parse.
    pub fn counts(&self) -> Arc<FilterCounts> {
        Arc::clone(&self.counts)
    }

    /// The knocks a door is open for right now.
    pub fn knocks(&self) -> Vec<Knock> {
        self.doors.read().unwrap().keys().copied().collect()
    }

    /// Open one pair's door behind the front: datagrams carrying `knock` reach an
    /// endpoint that presents `cert_key` and completes a handshake with `admit`
    /// alone. A knock already open is refused rather than replaced: the endpoint
    /// behind it would go deaf and stay open, which is a leak, not a door.
    pub fn open_door(
        &self,
        knock: Knock,
        cert_key: &ed25519_dalek::SigningKey,
        admit: [u8; 32],
    ) -> TransportResult<KnockedDoor> {
        if self.doors.read().unwrap().contains_key(&knock) {
            return Err(TransportError::ConnectionFailed("a door is already open for this knock".into()));
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cert = Ed25519DeviceCert::from_signing_key(cert_key)?;
        let mut server =
            tls::build_peer_server_config(&cert, one_key(admit, &provider), provider, None)?;
        server.transport_config(introduced_transport());

        let (tx, rx) = mpsc::channel(DOOR_QUEUE);
        let socket = DoorSocket {
            socket: Arc::clone(&self.socket),
            knock,
            rx: std::sync::Mutex::new(rx),
        };
        let endpoint = Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server),
            Arc::new(socket),
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        self.doors.write().unwrap().insert(knock, tx);
        Ok(KnockedDoor {
            endpoint,
            local_addr: Address::Quic(self.local),
        })
    }

    /// Shut the door behind `knock`: its datagrams are dropped from now on.
    pub fn shut_door(&self, knock: &Knock) {
        self.doors.write().unwrap().remove(knock);
    }
}

impl Drop for KnockFront {
    fn drop(&mut self) {
        self.pump.abort();
        self.doors.write().unwrap().clear();
    }
}

/// Read the front's socket for as long as the front lives, handing each datagram
/// whose knock is held to that door and dropping every other before any parse.
async fn pump(
    socket: Arc<UdpSocket>,
    doors: Arc<RwLock<HashMap<Knock, mpsc::Sender<Datagram>>>>,
    counts: Arc<FilterCounts>,
) {
    let mut buf = vec![0u8; 65_535];
    loop {
        let (n, from) = match socket.recv_from(&mut buf).await {
            Ok(got) => got,
            Err(e) => {
                tracing::debug!(error = %e, "the knock front's socket reported an error");
                continue;
            }
        };
        let door = (n > KNOCK_LEN)
            .then(|| <Knock>::try_from(&buf[..KNOCK_LEN]).ok())
            .flatten()
            .and_then(|knock| doors.read().unwrap().get(&knock).cloned());
        let routed = door.is_some_and(|tx| tx.try_send((from, buf[KNOCK_LEN..n].to_vec())).is_ok());
        let count = if routed { &counts.admitted } else { &counts.dropped };
        count.fetch_add(1, Ordering::Relaxed);
    }
}

/// One pair door's view of the front: it hears only its own knock's datagrams and
/// puts its knock on everything it sends.
struct DoorSocket {
    socket: Arc<UdpSocket>,
    knock: Knock,
    rx: std::sync::Mutex<mpsc::Receiver<Datagram>>,
}

impl fmt::Debug for DoorSocket {
    // The knock is a capability for the door's parse; it does not go in logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DoorSocket").finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for DoorSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Writable(Arc::clone(&self.socket)))
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let mut datagram = Vec::with_capacity(KNOCK_LEN + transmit.contents.len());
        datagram.extend_from_slice(&self.knock);
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
        match self.rx.lock().unwrap().poll_recv(cx) {
            Poll::Ready(Some((from, datagram))) => {
                let len = datagram.len().min(buf.len());
                buf[..len].copy_from_slice(&datagram[..len]);
                meta[0] = RecvMeta {
                    addr: from,
                    len,
                    stride: len,
                    ecn: None,
                    dst_ip: None,
                };
                Poll::Ready(Ok(1))
            }
            // The front shut this door: nothing will arrive again, and the endpoint
            // is closed by whoever held it.
            Poll::Ready(None) | Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

/// One pair's door behind a [`KnockFront`]: accepts the contact's connections, each
/// admitted by the one key the door was opened for.
pub struct KnockedDoor {
    endpoint: Endpoint,
    local_addr: Address,
}

#[async_trait::async_trait]
impl Listener for KnockedDoor {
    async fn accept(&self) -> TransportResult<Box<dyn Connection>> {
        // A handshake the verifier refuses does not end the door; the next one is
        // waited for.
        let connection = loop {
            let incoming = self
                .endpoint
                .accept()
                .await
                .ok_or(TransportError::ListenerClosed)?;
            match incoming.await {
                Ok(connection) => break connection,
                Err(e) => tracing::debug!(error = %e, "a knocked handshake failed"),
            }
        };
        let peer_id = connection
            .peer_identity()
            .and_then(|id| id.downcast::<Vec<CertificateDer<'static>>>().ok())
            .and_then(|certs| certs.into_iter().next())
            .and_then(|cert| tls::extract_ed25519_pubkey_from_cert(&cert))
            .and_then(|pubkey| DidKeyMethod::from_public_key_bytes(&pubkey).ok())
            .map(|did| did.to_string())
            .ok_or_else(|| {
                TransportError::ConnectionFailed("a knocked peer presented no key".into())
            })?;
        Ok(Box::new(super::connection::QuicConnection::new(
            connection, peer_id,
        )))
    }

    fn local_addr(&self) -> &Address {
        &self.local_addr
    }

    async fn close(&self) -> TransportResult<()> {
        self.endpoint.close(0u32.into(), b"door shut");
        self.endpoint.wait_idle().await;
        Ok(())
    }
}

/// Dial a contact's door at `front` with `knock` on every datagram, from `socket`,
/// presenting `auth_key` and admitting only `target_pub` — the pair's two handles
/// for the hour, as a relayed dial presents them.
pub async fn dial_knocked(
    auth_key: &ed25519_dalek::SigningKey,
    target_pub: [u8; 32],
    socket: std::net::UdpSocket,
    front: SocketAddr,
    knock: Knock,
) -> TransportResult<quinn::Connection> {
    // The introduced dial is this dial: a socket that hears one address and puts
    // sixteen bytes on the front of everything, and a one-key handshake.
    super::introduced::dial_introduced(
        auth_key,
        &CertOffer::default(),
        target_pub,
        socket,
        IntroducedPeer { addr: front, token: knock },
    )
    .await
    .map(|(conn, _)| conn)
}

/// Send one request on `conn` and read its answer, in the peer framing every door
/// serves: a four-byte big-endian length, then the bytes, each way.
pub async fn request_once(conn: &quinn::Connection, body: &[u8]) -> TransportResult<Vec<u8>> {
    let io = |e: &dyn fmt::Display| TransportError::ConnectionFailed(e.to_string());
    let len = u32::try_from(body.len()).map_err(|e| io(&e))?;
    if len > super::connection::MAX_MESSAGE_SIZE {
        return Err(TransportError::ConnectionFailed("request too large".into()));
    }
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| io(&e))?;
    send.write_u32(len).await.map_err(|e| io(&e))?;
    send.write_all(body).await.map_err(|e| io(&e))?;
    send.finish().map_err(|e| io(&e))?;
    let n = recv.read_u32().await.map_err(|e| io(&e))?;
    if n > super::connection::MAX_MESSAGE_SIZE {
        return Err(TransportError::ConnectionFailed("answer too large".into()));
    }
    let mut answer = vec![0u8; n as usize];
    recv.read_exact(&mut answer).await.map_err(|e| io(&e))?;
    Ok(answer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn key(n: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[n; 32])
    }

    fn loopback() -> std::net::UdpSocket {
        std::net::UdpSocket::bind("127.0.0.1:0").unwrap()
    }

    fn front() -> KnockFront {
        KnockFront::bind("127.0.0.1:0".parse().unwrap()).unwrap()
    }

    /// Serve `door` with an echo until it closes.
    fn echo(door: KnockedDoor) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            while let Ok(conn) = door.accept().await {
                tokio::spawn(async move {
                    while let Ok(true) = conn
                        .serve_one_request(Box::new(|req: Vec<u8>| {
                            Box::pin(async move { [b"echo:".as_slice(), &req].concat() })
                        }))
                        .await
                    {}
                });
            }
        })
    }

    /// Nothing comes back to `socket` within half a second.
    fn hears_nothing(socket: &std::net::UdpSocket) -> bool {
        socket.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        let mut buf = [0u8; 2048];
        socket.recv_from(&mut buf).is_err()
    }

    /// A stranger on the network gets no reply and no parse: no knock, a knock the
    /// front does not hold, a knock alone with nothing after it, and a full
    /// handshake under a wrong knock carrying the contact's own key — not one of
    /// their datagrams reaches quinn.
    #[tokio::test]
    async fn a_strangers_packet_to_a_contacts_door_gets_no_reply_and_no_parse() {
        let front = front();
        let at = front.local_addr();
        let knock = [7u8; KNOCK_LEN];
        let door = front.open_door(knock, &key(1), key(2).verifying_key().to_bytes()).unwrap();
        let _serve = echo(door);
        let counts = front.counts();

        let stranger = loopback();
        stranger.send_to(&[0xc0; 1200], at).unwrap();
        let mut wrong = [9u8; KNOCK_LEN].to_vec();
        wrong.extend_from_slice(&[0xc0; 1200]);
        stranger.send_to(&wrong, at).unwrap();
        stranger.send_to(&knock, at).unwrap();
        assert!(hears_nothing(&stranger), "a stranger was answered");

        let contact = key(2);
        let wrong_knock = dial_knocked(
            &contact,
            key(1).verifying_key().to_bytes(),
            loopback(),
            at,
            [9u8; KNOCK_LEN],
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(2), wrong_knock).await.is_err(),
            "a handshake under a knock the front does not hold completed"
        );
        assert_eq!(counts.admitted(), 0, "a stranger's datagram reached quinn");
        assert!(counts.dropped() >= 4, "dropped {}", counts.dropped());
    }

    /// The contact, with the pair's knock and key, is admitted and a request
    /// round-trips; two pairs behind one front each reach their own door and only
    /// it.
    #[tokio::test]
    async fn each_contact_reaches_their_own_door_behind_one_front() {
        let front = front();
        let at = front.local_addr();
        let (k_bob, k_carol) = ([2u8; KNOCK_LEN], [3u8; KNOCK_LEN]);
        let bob_door = front.open_door(k_bob, &key(10), key(2).verifying_key().to_bytes()).unwrap();
        let carol_door =
            front.open_door(k_carol, &key(11), key(3).verifying_key().to_bytes()).unwrap();
        let _a = echo(bob_door);
        let _b = echo(carol_door);

        let conn = dial_knocked(&key(2), key(10).verifying_key().to_bytes(), loopback(), at, k_bob)
            .await
            .expect("bob reaches his door");
        assert_eq!(request_once(&conn, b"hi").await.unwrap(), b"echo:hi");

        // Carol's knock with Bob's door's key: her knock routes to her door, which
        // presents its own key, and her dial — expecting Bob's door — refuses it.
        let crossed = tokio::time::timeout(
            Duration::from_secs(2),
            dial_knocked(&key(3), key(10).verifying_key().to_bytes(), loopback(), at, k_carol),
        )
        .await;
        assert!(!matches!(crossed, Ok(Ok(_))), "a knock reached another pair's door");

        let carol = dial_knocked(&key(3), key(11).verifying_key().to_bytes(), loopback(), at, k_carol)
            .await
            .expect("carol reaches hers");
        assert_eq!(request_once(&carol, b"yo").await.unwrap(), b"echo:yo");
    }

    /// A door shut behind the front hears nothing more, and a dropped front
    /// releases its port.
    #[tokio::test]
    async fn a_shut_door_hears_nothing_and_a_dropped_front_releases_its_port() {
        let front = front();
        let at = front.local_addr();
        let knock = [4u8; KNOCK_LEN];
        let door = front.open_door(knock, &key(1), key(2).verifying_key().to_bytes()).unwrap();
        assert!(
            front.open_door(knock, &key(1), key(2).verifying_key().to_bytes()).is_err(),
            "a second door for one knock replaced the first"
        );
        front.shut_door(&knock);
        assert!(front.knocks().is_empty());
        let contact = key(2);
        let dial = dial_knocked(&contact, key(1).verifying_key().to_bytes(), loopback(), at, knock);
        assert!(tokio::time::timeout(Duration::from_secs(2), dial).await.is_err());
        // The door's endpoint shares the front's socket, so the port goes when both
        // have: the door closed, then the front dropped.
        door.close().await.unwrap();
        drop(door);
        drop(front);
        let mut freed = false;
        for _ in 0..50 {
            if std::net::UdpSocket::bind(at).is_ok() {
                freed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(freed, "the front's port is released");
    }
}
