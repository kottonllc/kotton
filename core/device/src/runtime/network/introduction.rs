// SPDX-License-Identifier: AGPL-3.0-or-later
//! Answering an introduction: a listener for one of the person's devices, at the
//! address it gave, with the token it carried, for one session.
//!
//! The filter and the handshake are the transport's
//! (`kotton_net::transport::quic::introduced`); the timings and the ask are
//! [`kotton_peer::introduction`]'s. What is here is the device's part — binding the
//! listener, serving its one session with the handler every peer path uses, and
//! closing it when the session ends or the token dies unused — because the device
//! owns the accept loops (`peer_listener.rs` says why).
//!
//! A relay introduces your devices.

use crate::runtime::DeviceRuntime;
use kotton_net::transport::quic::introduced::{listen_introduced, IntroducedListener, IntroducedPeer};
use kotton_peer::PeerHandler;
use kotton_sys::net::{Connection, Listener};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// How many introductions may wait at once. A person has a handful of devices, and
/// each introduction is one short-lived socket; the cap is so a device of theirs that
/// misbehaves cannot hold ports open without end.
pub const MAX_OPEN: usize = 8;

/// One listener an introduction opened, while it is open.
struct Open {
    addr: SocketAddr,
    listener: Arc<IntroducedListener>,
    task: tokio::task::JoinHandle<()>,
}

/// The device's introductions: the handler that serves them, the key an introduced
/// listener presents, and the listeners open now. Empty on a fresh device — nothing
/// is bound until one of the person's devices asks.
///
/// Held behind its own `Arc`, apart from the runtime, so the one verb that opens a
/// listener can be lent without the machine ([`Introducer`]).
pub(crate) struct Introductions {
    /// The device's operational key, which an introduced listener's handshake
    /// presents — the same key the peer listener presents.
    signing_key: ed25519_dalek::SigningKey,
    /// Set at boot by the daemon ([`DeviceRuntime::serve_introductions`]); cleared at
    /// shutdown, which is what breaks the introductions → handler → introductions
    /// cycle (the peer handler holds an [`Introducer`]).
    handler: std::sync::Mutex<Option<PeerHandler>>,
    open: std::sync::Mutex<HashMap<u64, Open>>,
    next: AtomicU64,
    /// Sessions that completed a handshake, and requests served over them — for a
    /// reader asking whether the pair went direct.
    sessions: AtomicU64,
    requests: Arc<AtomicU64>,
}

impl Introductions {
    pub(crate) fn new(signing_key: ed25519_dalek::SigningKey) -> Self {
        Self {
            signing_key,
            handler: Default::default(),
            open: Default::default(),
            next: Default::default(),
            sessions: Default::default(),
            requests: Default::default(),
        }
    }

    /// [`DeviceRuntime::open_introduction_on`]'s work, on the introductions alone.
    async fn open_on(
        self: &Arc<Self>,
        peer_key: [u8; 32],
        expect: IntroducedPeer,
        their_router: Option<kotton_peer::local_door::RouterKey>,
        here: Option<kotton_peer::local_door::RouterKey>,
        local_only: bool,
        token_lifetime: Duration,
    ) -> anyhow::Result<SocketAddr> {
        if !kotton_peer::introduction::on_one_network(their_router, here, local_only) {
            anyhow::bail!("not on the network the asking device is on");
        }
        // One critical section from the count to the insert, so two asks served at once
        // cannot both find room: nothing between here and the insert awaits, and the
        // task that removes an entry waits on this lock.
        let mut open = self.open.lock().unwrap();
        if open.len() >= MAX_OPEN {
            anyhow::bail!("{MAX_OPEN} introductions already wait");
        }
        let handler = self
            .handler
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| anyhow::anyhow!("this device answers no introductions"))?;
        let ip = kotton_peer::introduction::introduced_bind_ip()
            .ok_or_else(|| anyhow::anyhow!("this device is on no local network it can name"))?;
        let (listener, _counts) = listen_introduced(
            &self.signing_key,
            peer_key,
            SocketAddr::new(ip, 0),
            expect,
        )
        .map_err(|e| anyhow::anyhow!("the introduced listener could not open: {e}"))?;
        let listener = Arc::new(listener);
        let addr = listener
            .socket_addr()
            .ok_or_else(|| anyhow::anyhow!("the introduced listener is not on a socket"))?;
        let id = self.next.fetch_add(1, Ordering::Relaxed);

        let this = Arc::clone(self);
        let held = Arc::clone(&listener);
        // Registered before the task can finish and remove it: the task waits for
        // the map's lock, which is held across the insert.
        let task = tokio::spawn(async move {
            match tokio::time::timeout(token_lifetime, held.accept()).await {
                Ok(Ok(conn)) => {
                    this.sessions.fetch_add(1, Ordering::Relaxed);
                    tracing::info!(%addr, "introduced session open");
                    serve(conn, handler, &this.requests).await;
                    tracing::info!(%addr, "introduced session ended");
                }
                Ok(Err(e)) => tracing::debug!(%addr, error = %e, "introduction not taken"),
                Err(_) => tracing::debug!(%addr, "introduction token expired unused"),
            }
            let _ = held.close().await;
            this.open.lock().unwrap().remove(&id);
        });
        open.insert(id, Open { addr, listener, task });
        Ok(addr)
    }
}

/// The one verb of introductions a peer request may ask: open a listener for one of
/// the person's devices ([`DeviceRuntime::open_introduction`]). Lent by
/// [`DeviceRuntime::introducer`] so a peer's path is handed this and not the machine:
/// it holds the introductions and the key their listeners present, and nothing else
/// of the runtime's.
#[derive(Clone)]
pub struct Introducer(Arc<Introductions>);

impl Introducer {
    /// [`DeviceRuntime::open_introduction`], through the lent handle.
    pub async fn open(
        &self,
        peer_key: [u8; 32],
        expect: IntroducedPeer,
        their_router: Option<kotton_peer::local_door::RouterKey>,
        token_lifetime: Duration,
    ) -> anyhow::Result<SocketAddr> {
        self.0
            .open_on(
                peer_key,
                expect,
                their_router,
                kotton_peer::local_door::network_here().router,
                kotton_peer::local_only(),
                token_lifetime,
            )
            .await
    }
}

impl DeviceRuntime {
    /// Lend the one verb that opens an introduced listener ([`Introducer`]).
    pub fn introducer(&self) -> Introducer {
        Introducer(Arc::clone(&self.introductions))
    }

    /// Serve introductions with `handler` — the same handler the peer listener serves,
    /// so an introduced session answers exactly what a relayed one would.
    pub fn serve_introductions(&self, handler: PeerHandler) {
        *self.introductions.handler.lock().unwrap() = Some(handler);
    }

    /// Open a listener for `peer_key`, hearing only `expect`, and serve its one
    /// session. Returns where it is bound — the answer that goes back over the
    /// sealed channel.
    ///
    /// The listener binds this device's own address on the local network, never the
    /// wildcard, and closes when its session ends or, with no session,
    /// `token_lifetime` after it opened. It opens only when `their_router` is the
    /// network this device is on ([`kotton_peer::introduction::on_one_network`]), and
    /// only while fewer than [`MAX_OPEN`] wait.
    pub async fn open_introduction(
        self: &Arc<Self>,
        peer_key: [u8; 32],
        expect: IntroducedPeer,
        their_router: Option<kotton_peer::local_door::RouterKey>,
        token_lifetime: Duration,
    ) -> anyhow::Result<SocketAddr> {
        self.introducer().open(peer_key, expect, their_router, token_lifetime).await
    }

    /// [`Self::open_introduction`] with the network and the scope as arguments, so a
    /// test can put the two devices on two networks.
    #[cfg(test)]
    pub(crate) async fn open_introduction_on(
        &self,
        peer_key: [u8; 32],
        expect: IntroducedPeer,
        their_router: Option<kotton_peer::local_door::RouterKey>,
        here: Option<kotton_peer::local_door::RouterKey>,
        local_only: bool,
        token_lifetime: Duration,
    ) -> anyhow::Result<SocketAddr> {
        self.introductions
            .open_on(peer_key, expect, their_router, here, local_only, token_lifetime)
            .await
    }

    /// Where the introduced listeners open now are bound. Empty is the property a
    /// fresh device holds, and the state after every session has ended.
    pub fn introductions_open(&self) -> Vec<SocketAddr> {
        self.introductions.open.lock().unwrap().values().map(|o| o.addr).collect()
    }

    /// How many introduced sessions have completed a handshake on this device.
    pub fn introduced_sessions(&self) -> u64 {
        self.introductions.sessions.load(Ordering::Relaxed)
    }

    /// How many requests introduced sessions have served on this device.
    pub fn introduced_requests(&self) -> u64 {
        self.introductions.requests.load(Ordering::Relaxed)
    }

    /// Close every introduced listener and stop answering: the runtime's shutdown
    /// calls this, so no introduction outlives the device.
    pub(crate) async fn close_introductions(&self) {
        self.introductions.handler.lock().unwrap().take();
        let open: Vec<Open> = self
            .introductions
            .open
            .lock()
            .unwrap()
            .drain()
            .map(|(_, o)| o)
            .collect();
        for o in open {
            o.task.abort();
            let _ = o.task.await;
            let _ = o.listener.close().await;
        }
    }
}

/// What `Connection::serve_one_request` is handed: one request's bytes to the
/// response's.
type OneRequest = Box<
    dyn FnOnce(Vec<u8>) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<u8>> + Send + 'static>>
        + Send
        + 'static,
>;

/// Serve requests on the one session until the peer closes it.
async fn serve(conn: Box<dyn Connection>, handler: PeerHandler, served: &AtomicU64) {
    let peer = conn.peer_id().to_owned();
    loop {
        let h = Arc::clone(&handler);
        let pf = peer.clone();
        let one: OneRequest = Box::new(move |req: Vec<u8>| Box::pin(async move { h(pf, req).await }));
        match conn.serve_one_request(one).await {
            Ok(true) => {
                served.fetch_add(1, Ordering::Relaxed);
            }
            Ok(false) => break,
            Err(e) => {
                tracing::warn!(error = %e, "introduced session: request error; closing");
                break;
            }
        }
    }
    let _ = conn.close().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RuntimeConfig;
    use kotton_net::transport::quic::introduced::dial_introduced;
    use kotton_net::transport::quic::tls::CertOffer;

    async fn runtime(temp: &tempfile::TempDir) -> Arc<DeviceRuntime> {
        Arc::new(
            DeviceRuntime::new_with_secrets(
                temp.path().to_path_buf(),
                RuntimeConfig::default(),
                Arc::new(kotton_secret::MemorySecrets::new()),
            )
            .await
            .unwrap(),
        )
    }

    fn echo() -> PeerHandler {
        Arc::new(|_, req| Box::pin(async move { [b"echo:".as_slice(), &req].concat() }))
    }

    fn device_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[9; 32])
    }

    /// Where the introduced device will dial from: a socket on the address an
    /// introduction binds, and the introduction that names it.
    fn dialler() -> (std::net::UdpSocket, IntroducedPeer) {
        let ip = kotton_peer::introduction::introduced_bind_ip().expect("an address to bind");
        let socket = std::net::UdpSocket::bind(SocketAddr::new(ip, 0)).unwrap();
        let expect = IntroducedPeer {
            addr: socket.local_addr().unwrap(),
            token: kotton_peer::introduction::new_token(),
        };
        (socket, expect)
    }

    /// Something else can bind exactly where the listener was, within a second.
    async fn released(addr: SocketAddr) -> bool {
        for _ in 0..50 {
            if std::net::UdpSocket::bind(addr).is_ok() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }

    async fn none_open(rt: &DeviceRuntime) -> bool {
        for _ in 0..100 {
            if rt.introductions_open().is_empty() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }

    /// A fresh device holds no introduced listener, and until the daemon says it
    /// serves introductions an ask binds nothing.
    #[tokio::test]
    async fn a_fresh_device_has_no_introduced_listener_and_opens_none_unasked() {
        let temp = tempfile::tempdir().unwrap();
        let rt = runtime(&temp).await;
        assert!(rt.introductions_open().is_empty());
        let (_socket, expect) = dialler();
        let refused = rt
            .open_introduction(device_key().verifying_key().to_bytes(), expect, None, Duration::from_secs(5))
            .await;
        assert!(refused.is_err(), "an introduction opened with no handler to serve it");
        assert!(rt.introductions_open().is_empty());
    }

    /// An introduction nobody takes closes when its token expires, and its port is
    /// free.
    #[tokio::test]
    async fn an_unused_introduction_closes_when_its_token_expires() {
        let temp = tempfile::tempdir().unwrap();
        let rt = runtime(&temp).await;
        rt.serve_introductions(echo());
        let (_socket, expect) = dialler();
        let at = rt
            .open_introduction(device_key().verifying_key().to_bytes(), expect, None, Duration::from_millis(300))
            .await
            .unwrap();
        assert_eq!(rt.introductions_open(), vec![at]);
        assert!(std::net::UdpSocket::bind(at).is_err(), "the port is held while it waits");
        assert!(none_open(&rt).await, "the listener outlived its token");
        assert!(released(at).await, "the port is still held after the token expired");
        assert_eq!(rt.introduced_sessions(), 0);
    }

    /// The introduced device's session is served with the daemon's handler, and when
    /// it ends the listener is gone and its port free.
    #[tokio::test]
    async fn an_introduced_session_is_served_and_its_listener_closes_when_it_ends() {
        let temp = tempfile::tempdir().unwrap();
        let rt = runtime(&temp).await;
        rt.serve_introductions(echo());
        let (socket, expect) = dialler();
        let at = rt
            .open_introduction(device_key().verifying_key().to_bytes(), expect, None, Duration::from_secs(10))
            .await
            .unwrap();

        let (conn, _) = dial_introduced(
            &device_key(),
            &CertOffer::default(),
            rt.device_signing_key().verifying_key().to_bytes(),
            socket,
            IntroducedPeer { addr: at, token: expect.token },
        )
        .await
        .expect("the introduced device dials the listener");
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(&2u32.to_be_bytes()).await.unwrap();
        send.write_all(b"hi").await.unwrap();
        send.finish().unwrap();
        let reply = recv.read_to_end(1024).await.unwrap();
        assert_eq!(&reply[4..], b"echo:hi");
        assert_eq!(rt.introduced_sessions(), 1);
        assert_eq!(rt.introduced_requests(), 1);
        assert_eq!(rt.introductions_open(), vec![at], "open while the session is");

        conn.close(0u32.into(), b"done");
        assert!(none_open(&rt).await, "the listener outlived its session");
        assert!(released(at).await, "the port is still held after the session ended");
    }

    /// A device on another network, or one that cannot name its own, is declined and
    /// nothing is bound; the same router on both sides opens.
    #[tokio::test]
    async fn an_introduction_from_another_network_opens_nothing() {
        use kotton_peer::local_door::RouterKey;
        let temp = tempfile::tempdir().unwrap();
        let rt = runtime(&temp).await;
        rt.serve_introductions(echo());
        let home = RouterKey::of_gateway_mac([0x3c, 0x22, 0xfb, 0, 0, 1]);
        let cafe = RouterKey::of_gateway_mac([0x3c, 0x22, 0xfb, 0, 0, 9]);
        let peer = device_key().verifying_key().to_bytes();
        for (theirs, here) in [(Some(cafe), Some(home)), (None, Some(home)), (Some(home), None)] {
            let (_socket, expect) = dialler();
            let declined = rt
                .open_introduction_on(peer, expect, theirs, here, false, Duration::from_secs(5))
                .await;
            assert!(declined.is_err(), "opened for {theirs:?} on {here:?}");
            assert!(rt.introductions_open().is_empty());
        }
        let (_socket, expect) = dialler();
        rt.open_introduction_on(peer, expect, Some(home), Some(home), false, Duration::from_millis(200))
            .await
            .expect("one network opens");
    }

    /// No more than `MAX_OPEN` introductions wait at once.
    #[tokio::test]
    async fn introductions_waiting_at_once_are_capped() {
        let temp = tempfile::tempdir().unwrap();
        let rt = runtime(&temp).await;
        rt.serve_introductions(echo());
        let peer = device_key().verifying_key().to_bytes();
        let mut held = Vec::new();
        for _ in 0..MAX_OPEN {
            let (socket, expect) = dialler();
            held.push(socket);
            rt.open_introduction(peer, expect, None, Duration::from_secs(30)).await.unwrap();
        }
        let (_socket, expect) = dialler();
        assert!(rt.open_introduction(peer, expect, None, Duration::from_secs(30)).await.is_err());
        assert_eq!(rt.introductions_open().len(), MAX_OPEN);
        rt.close_introductions().await;
    }

    /// Asks served at once cannot overshoot the cap: forty at a time, on a
    /// multi-threaded runtime, open exactly `MAX_OPEN`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn introductions_asked_at_once_are_capped_too() {
        let temp = tempfile::tempdir().unwrap();
        let rt = runtime(&temp).await;
        rt.serve_introductions(echo());
        let peer = device_key().verifying_key().to_bytes();
        let barrier = Arc::new(tokio::sync::Barrier::new(40));
        let asks: Vec<_> = (0..40)
            .map(|_| {
                let (rt, barrier) = (Arc::clone(&rt), Arc::clone(&barrier));
                tokio::spawn(async move {
                    let (socket, expect) = dialler();
                    barrier.wait().await;
                    let opened = rt.open_introduction(peer, expect, None, Duration::from_secs(30)).await;
                    (opened.is_ok(), socket)
                })
            })
            .collect();
        let mut opened = 0;
        for ask in asks {
            opened += usize::from(ask.await.unwrap().0);
        }
        assert_eq!(opened, MAX_OPEN);
        assert_eq!(rt.introductions_open().len(), MAX_OPEN);
        rt.close_introductions().await;
    }

    /// Shutting the runtime down closes an introduction still waiting.
    #[tokio::test]
    async fn shutting_down_the_runtime_closes_every_introduction() {
        let temp = tempfile::tempdir().unwrap();
        let rt = runtime(&temp).await;
        rt.start().await.unwrap();
        rt.serve_introductions(echo());
        let (_socket, expect) = dialler();
        let at = rt
            .open_introduction(device_key().verifying_key().to_bytes(), expect, None, Duration::from_secs(60))
            .await
            .unwrap();
        rt.shutdown().await.unwrap();
        assert!(rt.introductions_open().is_empty());
        assert!(released(at).await, "an introduction outlived the device");
        let (_socket, expect) = dialler();
        assert!(
            rt.open_introduction(device_key().verifying_key().to_bytes(), expect, None, Duration::from_secs(5))
                .await
                .is_err(),
            "a shut-down device still answers introductions"
        );
    }
}
