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
use kotton_crypto::ed25519::VerifyingKey;
use kotton_wire::peer::PairedNode;
use kotton_wire::ipc::SealedVerb;
use kotton_wire::{UserRequest, UserResponse};
use kotton_net::transport::quic::tls::{
    self, Ed25519DeviceCert, PairedDeviceVerifier,
};
use kotton_net::transport::{CircuitOffer, MakesClaim, RelayClient, RelayedDial};
use kotton_net::TurnUdpSocket;
use crate::channel::PeerChannel;
use crate::{KottonPeerObjectStorage, QuicPeerChannel};
use std::sync::{Arc, RwLock};

/// What a key is to a person, by that person's rows: whether an `offer` is
/// learned from the node holding it, or that the rows could not be read. The
/// question the dialling end asks, answered by the daemon that holds the rows
/// from the store it holds, which is never handed here: the dialler is handed
/// the question and nothing it is read from, as it is handed [`MakesClaim`]
/// and not the authority behind it.
///
/// The answer is the narrowest of the person's rows for the key, the rule the
/// listening end answers `NodeRelay` by ([`crate::relay_keys::offers_from`]
/// over [`crate::daemon::db::paired_posture_for_user`]), so both ends read one
/// answer for a key.
#[async_trait::async_trait]
pub trait WhatKeyIs: Send + Sync {
    /// What `key` is to `user`, by `user`'s rows alone.
    async fn to_person(&self, key: &[u8; 32], user: &str) -> RowsSay;
}

/// What a person's rows say of a key, as [`WhatKeyIs`] answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowsSay {
    /// An `offer` is learned from it: the narrowest row says `full`, or names
    /// no posture.
    Offer,
    /// No `offer` is learned from it: no row, or a narrowest row that is not
    /// `full`. Its relay, and a key handed with no `offer`, still are.
    NoOffer,
    /// The rows could not be read. Nothing is learned from the answer.
    Unreadable,
}

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
    /// What makes a circuit's recovery claim, for a dial whose offer is one: answered by the
    /// caller that holds the authority, which is never handed here. A circuit asks it for one
    /// claim, inside the handshake's channel, for that one connection; the certificate carries
    /// the signed claim in `offer`.
    claim: Option<Arc<dyn MakesClaim>>,
    /// What a key is to the person a connect names, asked once a peer's answer
    /// names where it reserves. `None` reads as no row: no `offer` is learned
    /// from any node, and its relay, and a key handed with no `offer`, are.
    what_key_is: Option<Arc<dyn WhatKeyIs>>,
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
            claim: None,
            what_key_is: None,
        }
    }

    /// Weigh what a peer answers by what its key is to the person, asked of
    /// `what_key_is`. A dialer built without it ([`Self::new`] alone, the
    /// operator's) reads every node as one the person has no row for.
    #[must_use]
    pub fn asking(mut self, what_key_is: Arc<dyn WhatKeyIs>) -> Self {
        self.what_key_is = Some(what_key_is);
        self
    }

    /// Whether this dialer asks what a key is to the person, for a test that
    /// holds a dialer some caller built.
    #[cfg(test)]
    pub(crate) fn asks(&self) -> bool {
        self.what_key_is.is_some()
    }

    /// Carry `offer` in this dialer's certificate — the events since the peer's
    /// tip, or a recovery claim. Every path the dial can take presents it.
    #[must_use]
    pub fn with_offer(mut self, offer: tls::CertOffer) -> Self {
        self.offer = offer;
        self
    }

    /// Claim a recovery authority, in place of events, on every path the dial can take: in
    /// the certificate as `signed`, the claim the authority's holder signed over this device's
    /// key, and on a circuit as the claim `maker` makes for that connection. The authority's
    /// key stays with its holder; neither form carries it.
    #[must_use]
    pub fn with_recovery_claim(mut self, signed: tls::RecoveryClaim, maker: Arc<dyn MakesClaim>) -> Self {
        self.offer = tls::CertOffer::claim(signed);
        self.claim = Some(maker);
        self
    }

    /// What a circuit offers a door that asks: the same events the certificate carries, or
    /// the claim.
    fn circuit_offer(&self) -> CircuitOffer {
        CircuitOffer {
            events: self.offer.admission.clone(),
            claim: self.claim.clone(),
        }
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
    Ok(connected(rt, channel, observed_direct_addr, node, user_id).await)
}

/// The storage over `channel`, a connection to `node` for `user_id`, once the
/// peer has been asked where it reserves and its answer weighed.
async fn connected(
    rt: &Dialer,
    channel: Arc<dyn crate::channel::PeerChannel>,
    observed_direct_addr: Option<std::net::SocketAddr>,
    node: PairedNode,
    user_id: &str,
) -> KottonPeerObjectStorage {
    // The key the answer is weighed by. What the key is to the person is read
    // from the person's rows when the answer comes, never from the node the
    // caller handed in.
    let key = node.public_key;
    let storage =
        KottonPeerObjectStorage::new(channel, node, user_id.to_owned(), kotton_common::LOCAL_MOUNT)
            .with_observed_direct_addr(observed_direct_addr);

    let learned = learn_where_it_reserves(rt, &storage, &key, user_id).await;
    storage.with_learned_relay(learned)
}

/// Ask the peer behind `storage`, whose key is `key`, where it reserves, and
/// learn what it answers for `user_id`. Returns the relay to record for it.
///
/// The pair is the resolver. Every connect asks the peer where it reserves, so
/// a relay change follows the pair without a re-pairing and without any public
/// identity→relay record. A peer that does not answer (older, or refusing)
/// teaches nothing, and the row keeps what it had.
async fn learn_where_it_reserves(
    rt: &Dialer,
    storage: &KottonPeerObjectStorage,
    key: &[u8; 32],
    user_id: &str,
) -> Option<String> {
    match storage
        .send_sealed(SealedVerb::NodeRelay {
            user_id: user_id.to_owned(),
        })
        .await
    {
        Ok(UserResponse::NodeRelayResult { relay_url, relay_key, admission, .. }) => {
            let relay_url = relay_url.filter(|u| !u.is_empty());
            // The key to present there, when the peer handed one: a vault to
            // its tenant, one of this person's devices to another. Held in
            // memory under the relay's key the peer named — never its address —
            // and learned again at the next connect, and only once the relay at
            // the address the peer named proves that key: a peer's word alone
            // would let it name this device's own relay beside an address it
            // runs, and be sent *mine* (`RelayKeyring::learn_proven`). A peer
            // that names no key teaches no key.
            if let (Some(url), Some(relay)) = (&relay_url, crate::relay_keys::relay_id(relay_key.as_deref())) {
                // Whether an `offer` is learned from it is what the key is to
                // this person by the narrowest of their rows, asked once, here,
                // before the relay is asked to prove its key: the same answer
                // the listening end gives. No row, or no question to ask, is no
                // `offer`. Rows that cannot be read teach nothing: no key is
                // held under the relay the peer named, no relay is recorded for
                // the node, and the connect records no relay for it.
                let offers = match &rt.what_key_is {
                    None => {
                        tracing::debug!("this dialler holds no question what a paired node's key is to the person; no offer learned from its answer");
                        false
                    }
                    Some(asked) => match asked.to_person(key, user_id).await {
                        RowsSay::Offer => true,
                        RowsSay::NoOffer => false,
                        RowsSay::Unreadable => {
                            tracing::warn!("what a paired node's key is to the person could not be read; nothing learned from its answer");
                            return None;
                        }
                    },
                };
                rt.reachability.relay_keys().learn_proven(user_id, key, offers, url, &relay, admission.as_ref()).await;
            }
            relay_url
        }
        _ => None,
    }
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
            // Bytes the Ed25519 rule refuses are no key, and admit nothing.
            let paired: std::collections::HashSet<_> =
                VerifyingKey::from_bytes(&node.public_key).into_iter().collect();
            let verifier = PairedDeviceVerifier::new(Arc::new(RwLock::new(paired)));
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
            // Tier 4: relayed fallback through the Kotton relay. The relay bridges a WebSocket;
            // the handshake runs end to end inside it, to the peer's key.
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

/// Where the far device's answer to `Introduce` says it is, or why not. What
/// the answer did not read as, and the far device's `Error`, are printed as
/// data to a bounded length ([`kotton_wire::note::quoted_cut`]; how another
/// node's text is printed); an answer not asked for by its name and no field of
/// it ([`kotton_wire::ipc::unasked`]).
fn introduced_at(answer: &[u8]) -> anyhow::Result<std::net::SocketAddr> {
    let answer = serde_json::from_slice::<UserResponse>(answer).map_err(|e| {
        anyhow::anyhow!("the introduction's answer did not read: {}", kotton_wire::note::quoted_cut(&e.to_string()))
    })?;
    match answer {
        UserResponse::Introduced { addr } => Ok(addr.parse()?),
        UserResponse::Error { message } => anyhow::bail!("introduction refused: {}", kotton_wire::note::quoted_cut(&message)),
        other => anyhow::bail!("introduction answered {}", kotton_wire::ipc::unasked(&other)),
    }
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
        let there = introduced_at(&answer)?;
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
/// still reachable. The handshake inside the circuit is under this device's key, to the
/// peer's key, either way — the label is how the relay routes, never who answers.
async fn relayed_dial(
    rt: &Dialer,
    node: &PairedNode,
    config: &NatConfig,
    admission: Option<kotton_net::rendezvous::AdmissionKey>,
) -> anyhow::Result<RelayedDial> {
    let offer = rt.circuit_offer();

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
        let relay = peer_relay(node, config);
        let client = RelayClient::new(relay, attempt.auth_did, attempt.auth_key)
            .with_admission(admission.clone());
        match client
            .dial(&attempt.target, &rt.signing_key, &node.public_key, &offer)
            .await
        {
            Ok(conn) => return Ok(conn),
            Err(e) => last_err = Some(anyhow::anyhow!("relay dial: {e}")),
        }
    }
    Err(last_err.expect("circuit_attempts is never empty"))
}

/// A [`PeerChannel`] backed by a relayed connection — the tier-4 relayed
/// fallback. Defined here, in `peer`, because it bridges two tier-03 providers (the `PeerChannel` trait from peer-storage and the
/// `RelayedDial` transport from network) that may not depend on one another.
///
/// The relayed channel is one handshake's channel (not multiplexed like QUIC), so its
/// requests serialise on the connection's internal mutex; the blind relay only
/// forwards sealed frames.
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
    //! The dialler's half of an introduction, over the relayed handshake it really runs
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

    fn dialer(k: &ed25519_dalek::SigningKey) -> Dialer {
        Dialer::new(
            k.clone(),
            Arc::new(crate::Reachability::new(Default::default(), k.clone())),
            Arc::new(kotton_diag::EventBus::with_default_capacity()),
        )
    }

    /// A peer that answers every request with `answer`, as a device asked
    /// `NodeRelay` over a connection already open.
    struct Answers(UserResponse);

    #[async_trait::async_trait]
    impl crate::channel::PeerChannel for Answers {
        async fn request(&self, _: &[u8]) -> anyhow::Result<Vec<u8>> {
            Ok(serde_json::to_vec(&self.0)?)
        }
    }

    /// The person's rows for one key, each what a row says of its posture,
    /// answered by the rule the listening end answers by: the narrowest of
    /// them ([`crate::daemon::db::narrowest`]), read by
    /// [`crate::relay_keys::offers_from`].
    struct Rows(Vec<Option<&'static str>>);

    #[async_trait::async_trait]
    impl WhatKeyIs for Rows {
        async fn to_person(&self, _: &[u8; 32], _: &str) -> RowsSay {
            match crate::relay_keys::offers_from(crate::daemon::db::narrowest(self.0.iter().copied())) {
                true => RowsSay::Offer,
                false => RowsSay::NoOffer,
            }
        }
    }

    /// Rows that cannot be read.
    struct Unread;

    #[async_trait::async_trait]
    impl WhatKeyIs for Unread {
        async fn to_person(&self, _: &[u8; 32], _: &str) -> RowsSay {
            RowsSay::Unreadable
        }
    }

    /// A full device's answer to `NodeRelay`: the relay at `url`, by its key
    /// `relay`, and *mine* with an `offer`.
    fn full_answer(url: &str, relay: &[u8; 32]) -> UserResponse {
        UserResponse::NodeRelayResult {
            relay_url: Some(url.to_owned()),
            relay_key: Some(hex::encode(relay)),
            admission: Some(kotton_wire::rendezvous::RelayAdmission {
                present: kotton_wire::ipc::SecretText::new(kotton_net::rendezvous::AdmissionKey::from_bytes([9; 32]).to_text()),
                offer: Some(kotton_wire::ipc::SecretText::new(kotton_net::rendezvous::AdmissionKey::from_bytes([8; 32]).to_text())),
            }),
            invited_held: false,
        }
    }

    /// The peer the connect dialled, handed in as the caller read it: a row
    /// that says `full`.
    fn dialled_as_full() -> PairedNode {
        PairedNode {
            id: "desktop".into(),
            device_did: kotton_wire::did::Did::new("key", "desktop"),
            public_key: key(1).verifying_key().to_bytes(),
            paired_at: 0,
            addresses: vec![],
            relay_url: None,
            posture: Some("full".into()),
        }
    }

    /// A relay proving its key at a loopback address, and the two.
    async fn a_relay() -> (String, [u8; 32]) {
        let relay = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let id = relay.verifying_key().to_bytes();
        (crate::relay_keys::tests::proving(relay).await, id)
    }

    /// **The dialling end reads the narrowest of the person's rows for the
    /// key, not the node it was handed.** A node answers `NodeRelay` with an
    /// `offer`. Dialled through a row that says `full` while another of the
    /// person's rows for the same key says `blind-storage`, no `offer` and no
    /// *mine* is held, and its relay is still learned. Where every row says
    /// `full` or nothing, both are held.
    #[tokio::test]
    async fn the_dialling_end_weighs_an_answer_by_the_narrowest_of_the_persons_rows() {
        let (url, relay) = a_relay().await;
        for (rows, offers) in [
            (vec![Some("full"), Some("blind-storage")], false),
            (vec![Some("blind-storage"), Some("full")], false),
            (vec![Some("full"), None], true),
        ] {
            let what = format!("rows {rows:?}");
            let dialer = dialer(&key(2)).asking(Arc::new(Rows(rows)));
            let storage = connected(&dialer, Arc::new(Answers(full_answer(&url, &relay))), None, dialled_as_full(), "alice").await;
            let keys = dialer.reachability.relay_keys();
            let node = key(1).verifying_key().to_bytes();
            assert_eq!(keys.offer_for("alice", &relay).is_some(), offers, "{what}: the offer");
            assert_eq!(keys.present_for("alice", &relay).is_some(), offers, "{what}: mine");
            assert_eq!(keys.relay_of("alice", &node, &url), Some(relay), "{what}: the relay was not learned");
            assert_eq!(storage.learned_relay(), Some(url.as_str()), "{what}");
        }
    }

    /// **Rows that cannot be read teach nothing.** The same answer, and the
    /// question fails: no key is held under the relay the node named, no relay
    /// is recorded for the node, and the connect records no relay for it.
    #[tokio::test]
    async fn rows_that_cannot_be_read_learn_nothing_from_the_answer() {
        let (url, relay) = a_relay().await;
        let dialer = dialer(&key(2)).asking(Arc::new(Unread));
        let storage = connected(&dialer, Arc::new(Answers(full_answer(&url, &relay))), None, dialled_as_full(), "alice").await;
        let keys = dialer.reachability.relay_keys();
        let node = key(1).verifying_key().to_bytes();
        assert_eq!(keys.present_for("alice", &relay), None, "a key was held");
        assert_eq!(keys.offer_for("alice", &relay), None, "an offer was held");
        assert_eq!(keys.relay_of("alice", &node, &url), None, "a relay was recorded for the node");
        assert_eq!(keys.told_relay("alice", &node), None, "a relay was recorded for the node");
        assert_eq!(storage.learned_relay(), None, "the connect recorded a relay");
    }

    /// **A dialler built with no question reads every node as one the person
    /// has no row for** — `Dialer::new` alone, which the operator's dialler
    /// is. The same answer teaches no `offer` and no *mine*, and the relay it
    /// named, as from an answer with no `offer`, is learned.
    #[tokio::test]
    async fn a_dialler_with_no_question_learns_no_offer_and_learns_the_relay() {
        let (url, relay) = a_relay().await;
        let dialer = dialer(&key(2));
        let storage = connected(&dialer, Arc::new(Answers(full_answer(&url, &relay))), None, dialled_as_full(), "alice").await;
        let keys = dialer.reachability.relay_keys();
        let node = key(1).verifying_key().to_bytes();
        assert_eq!(keys.offer_for("alice", &relay), None, "an offer was learned with no question");
        assert_eq!(keys.present_for("alice", &relay), None, "mine was learned with no question");
        assert_eq!(keys.relay_of("alice", &node, &url), Some(relay), "the relay was not learned");
        assert_eq!(storage.learned_relay(), Some(url.as_str()));
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
        let (near, relay_left) = tokio::io::duplex(64 * 1024);
        let (relay_right, far) = tokio::io::duplex(64 * 1024);
        let seen = tapping_relay(relay_left, relay_right);

        let far_door = kotton_net::transport::Door::new(
            &[key(1)],
            Arc::new(kotton_net::transport::HeldKeys::only(Arc::new(RwLock::new(
                HashSet::from([VerifyingKey::from_bytes(&key(2).verifying_key().to_bytes()).unwrap()]),
            )))),
        )
        .unwrap();
        tokio::spawn(async move {
            let opening = kotton_net::transport::relayed::Openings::default().admit().unwrap();
            let conn = RelayedConnection::accept(far, &far_door, opening)
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

        let conn = RelayedConnection::connect(
            near,
            &key(2),
            &key(1).verifying_key().to_bytes(),
            &CircuitOffer::default(),
        )
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

#[cfg(test)]
mod an_introductions_answer {
    use super::*;
    use kotton_wire::note::{quoted_cut, MAX_SAID_CHARS};

    fn said(answer: &UserResponse) -> String {
        introduced_at(&serde_json::to_vec(answer).unwrap()).expect_err("a refusal was read as an address").to_string()
    }

    /// **The far device's `Error` to `Introduce` is printed as data and to the
    /// bound, what did not read as an answer too, and an answer not asked for
    /// by its name and no field** (how another node's text is printed; how an
    /// answer not asked for is said).
    #[test]
    fn a_refused_introduction_is_printed_as_data_and_to_the_bound() {
        let long = "i".repeat(MAX_SAID_CHARS + 5);
        for text in ["no `door`\nhere", long.as_str()] {
            let refused = said(&UserResponse::Error { message: text.to_string() });
            assert_eq!(refused, format!("introduction refused: {}", quoted_cut(text)));
            assert!(!refused.contains('\n') && !refused.contains(text), "{refused}");
        }
        assert_eq!(said(&UserResponse::Error { message: "no `door`\nhere".into() }), "introduction refused: `no \\u{60}door\\u{60}\\nhere`");
        assert_eq!(said(&UserResponse::VaultFull { held: 17, quota: 9 }), "introduction answered `VaultFull`");
        let unread = introduced_at(b"{\"no `door`\": 1}").expect_err("no answer was read").to_string();
        assert!(unread.starts_with("the introduction's answer did not read: `"), "{unread}");
        assert!(!unread.contains("no `door`"), "{unread}");
        let at = introduced_at(&serde_json::to_vec(&UserResponse::Introduced { addr: "127.0.0.1:9".into() }).unwrap());
        assert_eq!(at.unwrap(), "127.0.0.1:9".parse::<std::net::SocketAddr>().unwrap());
    }
}
