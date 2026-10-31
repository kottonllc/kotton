// SPDX-License-Identifier: AGPL-3.0-or-later
//! Dialing a paired peer — NAT traversal, TURN, and the relayed fallback.
//!
//! Wires the NAT traversal stack ([`nat_connect`]) to
//! [`KottonPeerObjectStorage`] so that any caller can obtain a live
//! `ObjectStorage` backed by a paired peer.
//!
//! It bridges two tier-03 providers that may not depend on one another, from
//! inside `peer`, which has `kotton-net` as a real dependency.
//!
//! That matters beyond tidiness: as a method on `DeviceRuntime`, every caller
//! would name the machine, and so could not live in `peer` (`peer ->
//! kotton-runtime -> kotton-device -> kotton-peer` is a cycle). Naming what
//! dialing actually needs is what breaks that.
//!
//! # Layer split
//!
//! Resolving a `peer_did` to a [`PairedNode`] happens in the caller, which has
//! the database. This receives an already-resolved node.

use crate::nat::{nat_connect, NatConfig, NatResult};
use kotton_wire::peer::PairedNode;
use kotton_wire::ipc::SealedVerb;
use kotton_wire::{UserRequest, UserResponse};
use kotton_net::transport::quic::tls::{
    self, Ed25519DeviceCert, PairedDeviceVerifier,
};
use kotton_net::transport::{RelayClient, RelayedDial};
use kotton_net::TurnUdpSocket;
use crate::channel::PeerChannel;
use crate::{KottonPeerObjectStorage, QuicPeerChannel};
use std::sync::{Arc, RwLock};

/// Open a live [`KottonPeerObjectStorage`] to a paired peer.
///
/// Steps performed:
/// 1. Build [`NatConfig`] from `rt.config.nat`.
/// 2. Run [`nat_connect`] — tries direct QUIC, then hole-punch, then TURN.
/// 3. Wrap the resulting `quinn::Connection` in a [`QuicPeerChannel`].
/// 4. Wrap the channel in a [`KottonPeerObjectStorage`] targeting `user_id`'s
///    `"local"` mount on the remote daemon.
///
/// Returns an error if NAT traversal fails.
#[derive(Clone)]
pub struct Dialer {
    signing_key: ed25519_dalek::SigningKey,
    reachability: Arc<crate::Reachability>,
    events: Arc<kotton_diag::EventBus>,
    /// What this dial's certificate carries beyond the device key. Empty — and
    /// byte-identical to carrying nothing — unless the caller is recovering,
    /// which is the only dial that has something to offer.
    offer: tls::CertOffer,
}

impl Dialer {
    /// The three things dialing a peer needs, and the co-travel test passes on
    /// them: the device key that authenticates the link, the live reachability
    /// config the NAT stack reads, and the bus the attempt reports to. Every
    /// verb below uses all three.
    pub fn new(
        signing_key: ed25519_dalek::SigningKey,
        reachability: Arc<crate::Reachability>,
        events: Arc<kotton_diag::EventBus>,
    ) -> Self {
        Self {
            signing_key,
            reachability,
            events,
            offer: tls::CertOffer::default(),
        }
    }

    /// Carry `offer` in this dialer's certificate — the events since the peer's
    /// tip, or a recovery claim. Every path the dial can take presents it.
    #[must_use]
    pub fn with_offer(mut self, offer: tls::CertOffer) -> Self {
        self.offer = offer;
        self
    }

    /// Open a live [`KottonPeerObjectStorage`] to a paired peer.
    pub async fn connect(
        &self,
        node: PairedNode,
        user_id: &str,
    ) -> anyhow::Result<KottonPeerObjectStorage> {
        connect_peer(self, node, user_id).await
    }
}

async fn connect_peer(
    rt: &Dialer,
    node: PairedNode,
    user_id: &str,
) -> anyhow::Result<KottonPeerObjectStorage> {
    let (link, observed_direct_addr) = open_channel(rt, &node, user_id).await?;

    // The storage outlives this connection: a remote is used for the rest of
    // the session, and a connection can die under it however well it is kept
    // alive — the peer restarts, the path changes. What it holds is the dial,
    // so a dead connection is replaced by the same dial — a full handshake
    // against the same pinned key — rather than failing every request after it
    // (`RedialingChannel`).
    let redial: crate::channel::Redial = {
        let dialer = rt.clone();
        let node = node.clone();
        let user_id = user_id.to_owned();
        Box::new(move || {
            let dialer = dialer.clone();
            let node = node.clone();
            let user_id = user_id.clone();
            Box::pin(async move {
                open_channel(&dialer, &node, &user_id).await.map(|(link, _)| link)
            })
        })
    };
    let channel: Arc<dyn crate::channel::PeerChannel> =
        Arc::new(crate::channel::RedialingChannel::new(link, redial));

    // The node the answer is weighed by: its key and the posture this device
    // recorded for it, together.
    let answering = node.clone();
    let storage =
        KottonPeerObjectStorage::new(channel, node, user_id.to_owned(), kotton_common::LOCAL_MOUNT)
            .with_observed_direct_addr(observed_direct_addr);

    // The pair is the resolver. Every connect asks the peer where it
    // reserves, so a relay change follows the pair without a re-pairing and
    // without any public identity→relay record. A peer that does not answer
    // (older, or refusing) teaches nothing, and the row keeps what it had.
    let learned = match storage
        .send_sealed(SealedVerb::NodeRelay {
            user_id: user_id.to_owned(),
        })
        .await
    {
        Ok(UserResponse::NodeRelayResult { relay_url, relay_key, admission }) => {
            let relay_url = relay_url.filter(|u| !u.is_empty());
            // The key to present there, when the peer handed one: a vault to
            // its tenant, one of this person's devices to another. Held in
            // memory under the relay's key the peer named — never its address —
            // and learned again at the next connect, and only once the relay at
            // the address the peer named proves that key: a peer's word alone
            // would let it name this device's own relay beside an address it
            // runs, and be sent *mine* (`RelayKeyring::learn_proven`). A peer
            // that names no key teaches no key, and one this device did not
            // record as *full* teaches no key it offers on
            // (`relay_keys::offers_from`).
            if let (Some(url), Some(relay)) = (&relay_url, crate::relay_keys::relay_id(relay_key.as_deref())) {
                rt.reachability.relay_keys().learn_proven(user_id, &answering, url, &relay, admission.as_ref()).await;
            }
            relay_url
        }
        _ => None,
    };
    Ok(storage.with_learned_relay(learned))
}

/// One connection to `node` down the NAT ladder — direct, punched, TURN, then
/// the relay — and, on the direct and punched paths, the address it was
/// reached at.
async fn open_channel(
    rt: &Dialer,
    node: &PairedNode,
    // Whose introduction a relayed fallback asks for (`introduced`).
    user_id: &str,
) -> anyhow::Result<(Arc<dyn crate::channel::PeerChannel>, Option<std::net::SocketAddr>)> {
    // Read the LIVE reachability config (a `relay set` at runtime updates this
    // without a restart), not the immutable boot config.
    let nat = rt.reachability.nat();
    let mut config = NatConfig::from(&nat);
    // The keys to present are held under the relay's key, never its address:
    // this
    // device's own relay by the key it recorded; a peer's relay gets only what
    // that peer handed over.
    let keys = rt.reachability.relay_keys();
    let own = crate::relay_keys::relay_id(nat.relay_key.as_deref());
    config.admission = own.and_then(|r| keys.present_at(&r));
    // At the relay a peer named, only the key that peer handed over — never
    // this person's own keys, whatever relay key the peer named beside the
    // address (`RelayKeyring::present_for_peer`). At this device's own relay by
    // its own record, however the peer spelled it, the key this machine
    // presents there for its own reservations, and the handed key only when it
    // holds none: a dial is the machine's reach, whoever it is for — the
    // operator's, for no pool, included.
    let handed = node
        .relay_url
        .as_deref()
        .and_then(|url| keys.present_for_peer(user_id, &node.public_key, url));
    let peer_admission = keys.dialing_supplied_address(peer_relay(node, &config), handed, &nat.relay_url, own.as_ref());

    let direct_addr = node.addresses.first().copied();

    let result = nat_connect(
        &rt.signing_key,
        &rt.offer,
        node.public_key,
        direct_addr,
        &config,
        Some(Arc::clone(&rt.events)),
    )
    .await;

    // The peer's directly-dialable address, captured only on the direct/punched
    // paths where `remote_address()` is the peer itself (not a TURN/relay hop).
    // The daemon persists this to refresh the stale enrollment-bootstrap address.
    let mut observed_direct_addr: Option<std::net::SocketAddr> = None;

    let channel: Arc<dyn crate::channel::PeerChannel> = match result {
        NatResult::Direct(conn) | NatResult::Punched(conn) => {
            observed_direct_addr = Some(conn.remote_address());
            Arc::new(QuicPeerChannel::new(conn))
        }
        NatResult::TurnRelay {
            client,
            alloc,
            peer_relay_addr,
            peer_reflexive_ip: _,
        } => {
            // `channel_bind` was called in nat.rs; extract the live socket.
            let (socket, channel) = client
                .into_socket_and_channel(peer_relay_addr)
                .map_err(|e| anyhow::anyhow!("TURN socket extraction failed: {e}"))?;

            let turn_socket = Arc::new(TurnUdpSocket::new(
                socket,
                channel,
                alloc.relay_addr, // our relay addr reported as local_addr to quinn
                peer_relay_addr,
            ));

            // Build a quinn endpoint backed by the TURN socket.
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let device_cert =
                Ed25519DeviceCert::from_signing_key_with_offer(&rt.signing_key, &rt.offer)
                    .map_err(|e| anyhow::anyhow!("TURN TLS cert: {e}"))?;
            let mut paired = std::collections::HashSet::new();
            paired.insert(node.public_key);
            let verifier =
                PairedDeviceVerifier::new(Arc::new(RwLock::new(paired)), Arc::clone(&provider));
            let client_cfg =
                tls::build_peer_client_config(&device_cert, verifier, Arc::clone(&provider), config.keepalive())
                    .map_err(|e| anyhow::anyhow!("TURN TLS config: {e}"))?;

            let endpoint = quinn::Endpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                None, // outbound-only — no server_config
                turn_socket,
                Arc::new(quinn::TokioRuntime),
            )
            .map_err(|e| anyhow::anyhow!("TURN quinn endpoint: {e}"))?;

            let conn = endpoint
                .connect_with(client_cfg, peer_relay_addr, "kotton-peer")
                .map_err(|e| anyhow::anyhow!("TURN connect: {e}"))?
                .await
                .map_err(|e| anyhow::anyhow!("TURN QUIC handshake: {e}"))?;

            tracing::info!(
                relay = %alloc.relay_addr,
                peer_relay = %peer_relay_addr,
                "NAT: QUIC connection established over TURN relay",
            );

            Arc::new(QuicPeerChannel::new(conn))
        }
        NatResult::Failed(e) => {
            // Tier 4: relayed fallback through the Kotton relay. The relay bridges a WebSocket; mTLS runs end-to-end inside,
            // so the peer is authenticated exactly as on the direct path.
            if peer_relay(node, &config).is_empty() {
                return Err(anyhow::anyhow!(
                    "NAT traversal to peer '{}' failed: {}",
                    node.device_did,
                    e
                ));
            }
            tracing::info!(
                peer = %node.device_did,
                "NAT direct/punch/TURN failed; trying relayed fallback",
            );
            match relayed_dial(rt, node, &config, peer_admission).await {
                Ok(conn) => {
                    tracing::info!(
                        peer = %node.device_did,
                        "NAT: relayed fallback connection established",
                    );
                    let relayed = Arc::new(RelayedPeerChannel::new(conn))
                        as Arc<dyn crate::channel::PeerChannel>;
                    // The relay both are on introduces them, and the pair goes
                    // direct whenever it can. The introduced address is good for
                    // one session, so it is never `observed_direct_addr`: that
                    // would write a door that has already shut into the node's row.
                    match introduced(rt, &relayed, node.public_key, user_id).await {
                        Ok(conn) => {
                            tracing::info!(
                                peer = %node.device_did,
                                "introduced by the relay; the pair is direct",
                            );
                            Arc::new(QuicPeerChannel::new(conn))
                                as Arc<dyn crate::channel::PeerChannel>
                        }
                        Err(e) => {
                            tracing::debug!(
                                peer = %node.device_did,
                                error = %e,
                                "no introduction; the relay carries this connection",
                            );
                            relayed
                        }
                    }
                }
                Err(relay_err) => {
                    return Err(anyhow::anyhow!(
                        "NAT traversal to peer '{}' failed ({}); relay fallback failed ({})",
                        node.device_did,
                        e,
                        relay_err
                    ));
                }
            }
        }
    };

    Ok((channel, observed_direct_addr))
}

/// Ask the device at the far end of `relayed` for an introduction, and dial it.
///
/// Binds this end's socket first, on this device's own address on the local network
/// ([`introduced_bind_ip`](crate::introduction::introduced_bind_ip)), because that
/// address is what the far listener will hear and nothing else. The ask and its
/// answer travel inside the TLS the relay bridges. The whole of it — ask, answer,
/// handshake — gets [`DIRECT_WITHIN`](crate::introduction::DIRECT_WITHIN); a pair
/// on two networks never answers, and the relayed connection stands.
async fn introduced(
    rt: &Dialer,
    relayed: &Arc<dyn crate::channel::PeerChannel>,
    peer_key: [u8; 32],
    user_id: &str,
) -> anyhow::Result<quinn::Connection> {
    use kotton_net::transport::quic::introduced::{dial_introduced, IntroducedPeer};
    // The network this device is on, which the far device must share. One that cannot
    // be named is no introduction, and nothing is bound or sent.
    let router = crate::local_door::network_here().router;
    if router.is_none() && !crate::scope::local_only() {
        anyhow::bail!("this device cannot name the network it is on");
    }
    let ip = crate::introduction::introduced_bind_ip()
        .ok_or_else(|| anyhow::anyhow!("this device is on no local network it can name"))?;
    let socket = std::net::UdpSocket::bind((ip, 0))?;
    let here = socket.local_addr()?;
    let token = crate::introduction::new_token();
    let ask = UserRequest::Introduce {
        user_id: user_id.to_owned(),
        addr: here.to_string(),
        token: kotton_wire::ipc::SecretText::new(hex::encode(token)),
        router: router.map(|r| r.to_hex()),
    };
    let attempt = async {
        let answer = relayed.request(&serde_json::to_vec(&ask)?).await?;
        let there: std::net::SocketAddr = match serde_json::from_slice::<UserResponse>(&answer)? {
            UserResponse::Introduced { addr } => addr.parse()?,
            UserResponse::Error { message } => anyhow::bail!("introduction refused: {message}"),
            _ => anyhow::bail!("introduction answered with something else"),
        };
        let (conn, _) = dial_introduced(
            &rt.signing_key,
            &rt.offer,
            peer_key,
            socket,
            IntroducedPeer { addr: there, token },
        )
        .await?;
        Ok(conn)
    };
    tokio::time::timeout(crate::introduction::DIRECT_WITHIN, attempt)
        .await
        .map_err(|_| anyhow::anyhow!("no direct answer within {:?}", crate::introduction::DIRECT_WITHIN))?
}

/// The relay to reach `node` through: the one it told us it reserves at, else
/// this device's own (the two are one relay in the cheapest configuration).
fn peer_relay<'a>(node: &'a PairedNode, config: &'a NatConfig) -> &'a str {
    match node.relay_url.as_deref() {
        Some(url) if !url.is_empty() => url,
        _ => config.relay_url.as_str(),
    }
}

/// Dial a paired peer through the Kotton relay (the tier-4 relayed fallback).
///
/// The circuit is named at both ends by **per-pair, per-epoch handles**
/// (ROTATING-RENDEZVOUS-HANDLES step 6): the dial authenticates as this
/// device's own handle for the pair and names the target by the handle the
/// peer reserves under — current epoch first, then previous, which covers a
/// clock running ahead of the target's. While the coexistence window holds, a
/// final attempt uses the durable DIDs at both ends, so an un-upgraded peer
/// (or a membership-mode relay, which cannot admit a rotating identifier) is
/// still reachable. The mTLS inside the circuit is the device certificate
/// against this pair's key either way — the label is how the relay routes,
/// never who the peer authenticates.
async fn relayed_dial(
    rt: &Dialer,
    node: &PairedNode,
    config: &NatConfig,
    admission: Option<kotton_net::rendezvous::AdmissionKey>,
) -> anyhow::Result<RelayedDial> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut paired = std::collections::HashSet::new();
    paired.insert(node.public_key);
    let verifier = PairedDeviceVerifier::new(Arc::new(RwLock::new(paired)), Arc::clone(&provider));

    // The attempt order — (handle, handle) current then previous epoch, then
    // durable at both ends while the coexistence window holds — is
    // `kotton_peer::rendezvous`'s policy, kept there so step 5 deletes it in
    // one place.
    let attempts = crate::rendezvous::circuit_attempts(
        &rt.signing_key,
        &node.public_key,
        crate::rendezvous::unix_now(),
    )?;

    let mut last_err: Option<anyhow::Error> = None;
    for attempt in attempts {
        let device_cert =
            Ed25519DeviceCert::from_signing_key_with_offer(&rt.signing_key, &rt.offer)
                .map_err(|e| anyhow::anyhow!("relayed TLS cert: {e}"))?;
        let relay = peer_relay(node, config);
        let admission = admission.clone();
        let client = RelayClient::new(
            relay,
            attempt.auth_did,
            attempt.auth_key,
            device_cert,
            Arc::clone(&verifier),
            Arc::clone(&provider),
        )
        .with_admission(admission);
        match client.dial(&attempt.target).await {
            Ok(conn) => return Ok(conn),
            Err(e) => last_err = Some(anyhow::anyhow!("relay dial: {e}")),
        }
    }
    Err(last_err.expect("circuit_attempts is never empty"))
}

/// A [`PeerChannel`] backed by a relayed mTLS connection — the tier-4 relayed
/// fallback. Defined here, in `peer`, because it bridges two tier-03 providers (the `PeerChannel` trait from peer-storage and the
/// `RelayedDial` transport from network) that may not depend on one another.
///
/// The relayed channel is a single mTLS stream (not multiplexed like QUIC), so its
/// requests serialise on the connection's internal mutex; the blind relay only
/// forwards the opaque mTLS frames.
struct RelayedPeerChannel {
    conn: Arc<RelayedDial>,
}

impl RelayedPeerChannel {
    fn new(conn: RelayedDial) -> Self {
        Self {
            conn: Arc::new(conn),
        }
    }
}

#[async_trait::async_trait]
impl PeerChannel for RelayedPeerChannel {
    async fn request(&self, req_bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.conn
            .request(req_bytes)
            .await
            .map_err(|e| anyhow::anyhow!("relayed request failed: {e}"))
    }
}

#[cfg(test)]
mod tests {
    //! The dialler's half of an introduction, over the relayed mTLS it really runs
    //! on, with a relay in the middle that keeps every byte it carries.

    use super::*;
    use kotton_net::transport::quic::introduced::{listen_introduced, IntroducedPeer};
    use kotton_net::transport::relayed::RelayedConnection;
    use kotton_sys::net::Listener;
    use std::collections::HashSet;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn key(n: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[n; 32])
    }

    fn provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    fn dialer(k: &ed25519_dalek::SigningKey) -> Dialer {
        Dialer::new(
            k.clone(),
            Arc::new(crate::Reachability::new(Default::default(), k.clone())),
            Arc::new(kotton_diag::EventBus::with_default_capacity()),
        )
    }

    /// A relay that forwards both ways and keeps a copy of everything.
    fn tapping_relay(
        left: tokio::io::DuplexStream,
        right: tokio::io::DuplexStream,
    ) -> Arc<std::sync::Mutex<Vec<u8>>> {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (lr, lw) = tokio::io::split(left);
        let (rr, rw) = tokio::io::split(right);
        for (mut from, mut to, seen) in [
            (Box::new(lr) as Box<dyn tokio::io::AsyncRead + Unpin + Send>, Box::new(rw) as Box<dyn tokio::io::AsyncWrite + Unpin + Send>, Arc::clone(&seen)),
            (Box::new(rr) as Box<dyn tokio::io::AsyncRead + Unpin + Send>, Box::new(lw) as Box<dyn tokio::io::AsyncWrite + Unpin + Send>, Arc::clone(&seen)),
        ] {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    let n = match from.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    seen.lock().unwrap().extend_from_slice(&buf[..n]);
                    if to.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
        seen
    }

    /// The far device, answering the one request it is sent with `answer`.
    type Answer = Box<dyn FnOnce(UserRequest) -> UserResponse + Send>;

    /// A relayed channel from device 2 to device 1 through a tapping relay, device 1
    /// answering with `answer`. Returns the channel and what the relay saw.
    async fn relayed_to(answer: Answer) -> (Arc<dyn crate::channel::PeerChannel>, Arc<std::sync::Mutex<Vec<u8>>>) {
        let p = provider();
        let (near, relay_left) = tokio::io::duplex(64 * 1024);
        let (relay_right, far) = tokio::io::duplex(64 * 1024);
        let seen = tapping_relay(relay_left, relay_right);

        let far_cert = Ed25519DeviceCert::from_signing_key(&key(1)).unwrap();
        let far_verifier = PairedDeviceVerifier::new(
            Arc::new(RwLock::new(HashSet::from([key(2).verifying_key().to_bytes()]))),
            Arc::clone(&p),
        );
        let p2 = Arc::clone(&p);
        tokio::spawn(async move {
            let conn = RelayedConnection::accept(far, &far_cert, far_verifier, p2)
                .await
                .expect("far handshake");
            let _ = conn
                .serve_one_request(|bytes| async move {
                    let req: UserRequest = serde_json::from_slice(&bytes).unwrap();
                    serde_json::to_vec(&answer(req)).unwrap()
                })
                .await;
            // Held open, as a relayed session is, until the test ends.
            std::future::pending::<()>().await;
        });

        let near_cert = Ed25519DeviceCert::from_signing_key(&key(2)).unwrap();
        let near_verifier = PairedDeviceVerifier::new(
            Arc::new(RwLock::new(HashSet::from([key(1).verifying_key().to_bytes()]))),
            Arc::clone(&p),
        );
        let conn = RelayedConnection::connect(near, &near_cert, near_verifier, p)
            .await
            .expect("near handshake");
        struct Relayed<T>(T);
        #[async_trait::async_trait]
        impl<T: Send + Sync> crate::channel::PeerChannel for Relayed<RelayedConnection<T>>
        where
            T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
        {
            async fn request(&self, req: &[u8]) -> anyhow::Result<Vec<u8>> {
                Ok(self.0.request(req).await?)
            }
        }
        (Arc::new(Relayed(conn)), seen)
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// The introduction crosses the relay and the relay learns neither address nor
    /// token: every byte it carried is searched for both, in every form they take on
    /// the wire. The pair then goes direct.
    #[tokio::test]
    async fn the_relay_carries_the_introduction_and_sees_no_address_and_no_token() {
        let seen_request: Arc<std::sync::Mutex<Option<(std::net::SocketAddr, String, std::net::SocketAddr)>>> =
            Arc::default();
        let keep = Arc::clone(&seen_request);
        let (channel, relay_saw) = relayed_to(Box::new(move |req| {
            let UserRequest::Introduce { addr, token, .. } = req else {
                return UserResponse::Error { message: "not an introduction".into() };
            };
            let from: std::net::SocketAddr = addr.parse().unwrap();
            let expect = IntroducedPeer {
                addr: from,
                token: crate::introduction::parse_token(token.expose()).unwrap(),
            };
            let (listener, _) = listen_introduced(
                &key(1),
                key(2).verifying_key().to_bytes(),
                std::net::SocketAddr::new(from.ip(), 0),
                expect,
            )
            .unwrap();
            let at = listener.socket_addr().unwrap();
            *keep.lock().unwrap() = Some((from, token.expose().to_owned(), at));
            tokio::spawn(async move {
                let conn = listener.accept().await.expect("the introduced dial");
                let _ = conn.serve_one_request(Box::new(|_| Box::pin(async { Vec::new() }))).await;
            });
            UserResponse::Introduced { addr: at.to_string() }
        }))
        .await;

        let direct = introduced(&dialer(&key(2)), &channel, key(1).verifying_key().to_bytes(), "alice")
            .await
            .expect("the pair goes direct");
        let (from, token, at) = seen_request.lock().unwrap().clone().expect("asked");
        assert_eq!(direct.remote_address(), at);

        let saw = relay_saw.lock().unwrap().clone();
        assert!(saw.len() > 200, "the relay carried the handshake and the ask");
        // The control: in the bytes of the ask and its answer as they would travel
        // unsealed, every needle below is found. The search can see what it looks for.
        let plain = [
            serde_json::to_vec(&UserRequest::Introduce {
                user_id: "alice".into(),
                addr: from.to_string(),
                token: kotton_wire::ipc::SecretText::new(token.clone()),
                router: None,
            })
            .unwrap(),
            serde_json::to_vec(&UserResponse::Introduced { addr: at.to_string() }).unwrap(),
        ]
        .concat();
        for (what, needle) in [
            ("the dialler's address", from.to_string().into_bytes()),
            ("the listener's address", at.to_string().into_bytes()),
            ("the dialler's port", from.port().to_string().into_bytes()),
            ("the listener's port", at.port().to_string().into_bytes()),
            ("the token, hex", token.clone().into_bytes()),
            ("the token", hex::decode(&token).unwrap()),
        ] {
            // A port's decimal digits are short enough to occur by chance in a few
            // KB of ciphertext; they are checked as the JSON field that would carry
            // them, which is how they would appear if the channel were readable.
            let needle = if what.ends_with("port") {
                [b":".as_slice(), &needle, b"\"".as_slice()].concat()
            } else {
                needle
            };
            if what != "the token" {
                assert!(contains(&plain, &needle), "the control does not find {what}");
            }
            assert!(!contains(&saw, &needle), "the relay saw {what}");
        }
    }

    /// A far device that refuses the introduction — a vault, an older device — leaves
    /// the relayed connection standing, at once.
    #[tokio::test]
    async fn a_refused_introduction_is_an_error_and_the_relay_stands() {
        let (channel, _) = relayed_to(Box::new(|_| UserResponse::Error {
            message: "request type not permitted".into(),
        }))
        .await;
        let started = std::time::Instant::now();
        let refused =
            introduced(&dialer(&key(2)), &channel, key(1).verifying_key().to_bytes(), "alice").await;
        assert!(refused.is_err());
        assert!(started.elapsed() < crate::introduction::DIRECT_WITHIN);
    }

    /// A far device on another network answers with an address this one cannot reach;
    /// the dial gives up within its budget and the relayed connection stands.
    #[tokio::test]
    async fn an_introduction_that_does_not_answer_gives_up_within_its_budget() {
        let unanswered = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let at = unanswered.local_addr().unwrap();
        let (channel, _) = relayed_to(Box::new(move |_| UserResponse::Introduced {
            addr: at.to_string(),
        }))
        .await;
        let started = std::time::Instant::now();
        let gave_up =
            introduced(&dialer(&key(2)), &channel, key(1).verifying_key().to_bytes(), "alice").await;
        assert!(gave_up.is_err());
        assert!(started.elapsed() < crate::introduction::DIRECT_WITHIN + Duration::from_millis(500));
        drop(unanswered);
    }
}
