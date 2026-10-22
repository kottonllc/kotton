// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAT traversal orchestration for peer-to-peer QUIC connections.
//!
//! # Connection ladder
//!
//! Attempts three paths from cheapest to most expensive, short-circuiting as
//! soon as one succeeds:
//!
//! 1. **Direct** — connect straight to the peer's last-known address.  Works
//!    when both devices are on the same LAN or one has a public IP.
//!
//! 2. **STUN + coord + hole-punch** — discover the local reflexive (public)
//!    address via STUN, publish it to the coord server, look up the peer's
//!    coord entry, then perform a simultaneous QUIC hole-punch.  Works for
//!    most full-cone, restricted-cone, and port-restricted-cone NATs.
//!
//! 3. **TURN relay** — allocate a relay address on the TURN server so all
//!    traffic is forwarded through it.  Works for symmetric NATs but incurs
//!    server cost and latency.
//!
//! # Wiring
//!
//! [`nat_connect`]'s caller is `crate::dialer`, and the sync flow is:
//! 1. Call `nat_connect(...)` → `NatResult::Direct(conn) | NatResult::Punched(conn) | NatResult::TurnRelay { .. }`
//! 2. Wrap the result in a `QuicPeerChannel` (or `TurnUdpSocket` for the relay path)
//! 3. Pass `Arc::new(channel)` to `KottonPeerObjectStorage::new(...)`
//! 4. Use that storage as the `RemoteBackend::Kotton` mount target
//!
//! # Usage
//!
//! ```rust,ignore
//! let result = nat_connect(
//!     &device_signing_key,
//!     peer_pubkey,
//!     None,                        // no last-known direct addr
//!     &NatConfig::default(),
//!     Some(Arc::clone(&event_bus)),
//! ).await;
//!
//! match result {
//!     NatResult::Direct(conn) | NatResult::Punched(conn) => { /* use quinn conn */ }
//!     NatResult::TurnRelay { alloc, peer_relay_addr, .. } => { /* open TurnUdpSocket */ }
//!     NatResult::Failed(e) => { /* all paths failed */ }
//! }
//! ```


use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::{Arc, RwLock},
    time::Duration,
};

use crate::rendezvous;
use kotton_net::{
    rendezvous::client::RendezvousClient,
    stun,
    transport::quic::{
        punch::{simultaneous_punch, PunchResult, PunchRole},
        tls::{self, Ed25519DeviceCert, PairedDeviceVerifier},
    },
    TurnAllocation, TurnClient,
};
use kotton_diag::{Event, EventBus, EventCategory, EventLevel};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

// ── Config ────────────────────────────────────────────────────────────────────

/// NAT traversal parameters, derived from `RuntimeConfig`.
#[derive(Debug, Clone)]
pub struct NatConfig {
    /// STUN server (`host:port`) for reflexive address discovery.
    pub stun_server: String,

    /// Relay server base URL for peer-address exchange and DM inbox.
    pub relay_url: String,

    /// TURN server address (`host:port`).
    pub turn_url: String,

    /// TURN long-term credential username.
    pub turn_username: String,

    /// TURN long-term credential password.
    pub turn_password: String,

    /// Deadline for step 1 (direct QUIC connect).
    pub direct_timeout: Duration,

    /// Deadline for step 2 hole-punch.
    pub punch_timeout: Duration,

    /// How long to wait for the peer to appear on the coord server.
    pub coord_poll_timeout: Duration,

    /// How long to wait for the peer's `turn_relay_addr` to appear on coord
    /// during TURN relay address exchange (step 3). Generous timeout because
    /// both peers allocate TURN concurrently and neither side is faster.
    pub turn_relay_poll_timeout: Duration,

    /// Delay between coord lookup retries.
    pub coord_poll_interval: Duration,

    /// QUIC keep-alive ping interval for peer connections (seconds).
    ///
    /// Sent periodically to keep NAT bindings open.  0 disables keepalive.
    /// Loaded from `RuntimeConfig::nat.keepalive_interval_secs`.
    pub keepalive_interval_secs: u64,

    /// The admission key this device holds for `relay_url`, if any: every
    /// push and lookup made there carries a tag under it.
    /// Never persisted; the dialer reads it from the reachability's keyring for
    /// each attempt.
    pub admission: Option<kotton_net::rendezvous::AdmissionKey>,
}

impl NatConfig {
    /// The keep-alive every QUIC path this ladder opens carries — direct,
    /// punched and TURN alike — or `None` when `keepalive_interval_secs` is 0.
    ///
    /// **One answer for every rung.** A path built with none — a direct
    /// connection, the one on a LAN and on loopback — would be closed by quinn's
    /// idle timeout (30 s) after any quiet half-minute. A remote holds its
    /// connection for the session, so that would be every remote left alone that
    /// long, and the next request on it would fail with `open_bi failed: timed
    /// out`.
    /// quinn restarts the idle clock on a packet *received*, never on one sent,
    /// so no check before a request can close that race; only traffic can.
    pub fn keepalive(&self) -> Option<Duration> {
        (self.keepalive_interval_secs > 0).then(|| Duration::from_secs(self.keepalive_interval_secs))
    }
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            stun_server: String::new(),
            relay_url: String::new(),
            turn_url: String::new(),
            turn_username: String::new(),
            turn_password: String::new(),
            direct_timeout: Duration::from_secs(2),
            punch_timeout: Duration::from_secs(5),
            coord_poll_timeout: Duration::from_secs(8),
            turn_relay_poll_timeout: Duration::from_secs(15),
            coord_poll_interval: Duration::from_millis(500),
            keepalive_interval_secs: 20,
            admission: None,
        }
    }
}

/// The persisted form of the same parameters.
///
/// [`NatConfig`] is what one dial attempt is handed; this is what a device
/// stores and what an operator edits. It carries a list of STUN servers rather
/// than one, and the relay's own STUN responder, because those are choices made
/// once per device rather than once per connection; the per-attempt timeouts are
/// not persisted at all.
///
/// It is `peer`'s, not the runtime's config: "how do I reach my own devices"
/// is peer authority, and the configuration of it is not a different
/// question from the code that acts on it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatNetworkConfig {
    /// STUN servers used to discover the local reflexive address.
    /// The first reachable server wins.  Set to `[]` to disable STUN.
    /// Defaults to empty — must be configured via `device_config` (DB) or env.
    #[serde(default)]
    pub stun_servers: Vec<String>,

    /// Relay server base URL for peer-address exchange and DM inbox.
    /// Leave empty (`""`) to disable relay-based hole-punching.
    #[serde(default)]
    pub relay_url: String,

    /// The relay this device held reservations at before the current one, kept
    /// for a forwarding window after a change so a peer that still names it
    /// lands and learns the new one. Empty when there is none.
    #[serde(default)]
    pub relay_url_previous: String,

    /// Unix time the forwarding window closes; the previous relay is ignored
    /// after it.
    #[serde(default)]
    pub relay_url_previous_until: i64,

    /// The key the relay at `relay_url` proved when this device learned it, hex
    /// ([`crate::relay_key::prove_relay`]). `None` when it showed none — a relay
    /// that keeps no key, or did not answer when it was named. The key is what
    /// the relay is; the URL is where it was last found.
    #[serde(default)]
    pub relay_key: Option<String>,

    /// The key of `relay_url_previous`, moved beside it when the device left it.
    #[serde(default)]
    pub relay_key_previous: Option<String>,

    /// The relay's own UDP STUN responder (`host:port`) — reflexive-address
    /// discovery without a 3rd-party STUN server. When set
    /// (with `relay_url`), the peer listener binds a STUN-probed socket and keeps
    /// an always-on presence registration. `None` = legacy path (external STUN).
    #[serde(default)]
    pub relay_stun_addr: Option<String>,

    /// TURN relay server address (`host:port`).
    /// Leave empty to disable TURN relay fallback.
    #[serde(default)]
    pub turn_url: String,

    /// TURN long-term credential username.
    #[serde(default)]
    pub turn_username: String,

    /// TURN long-term credential password.
    #[serde(default)]
    pub turn_password: String,

    /// QUIC keep-alive ping interval in seconds.
    /// 0 means disabled (use the transport default).
    #[serde(default = "default_keepalive_secs")]
    pub keepalive_interval_secs: u64,
}

const fn default_keepalive_secs() -> u64 {
    20
}

impl Default for NatNetworkConfig {
    fn default() -> Self {
        Self {
            stun_servers: Vec::new(),
            relay_url: String::new(),
            relay_url_previous: String::new(),
            relay_url_previous_until: 0,
            relay_key: None,
            relay_key_previous: None,
            relay_stun_addr: None,
            turn_url: String::new(),
            turn_username: String::new(),
            turn_password: String::new(),
            keepalive_interval_secs: default_keepalive_secs(),
        }
    }
}

impl NatNetworkConfig {
    /// The relay still worth holding reservations at besides the current one:
    /// the previous relay, while its forwarding window is open and it differs
    /// from the current. A relay change is a forwarding address,
    /// not a disappearance.
    pub fn forwarding_relay(&self, now: i64) -> Option<&str> {
        if self.relay_url_previous.is_empty()
            || self.relay_url_previous == self.relay_url
            || now >= self.relay_url_previous_until
        {
            return None;
        }
        Some(self.relay_url_previous.as_str())
    }
}

impl From<&NatNetworkConfig> for NatConfig {
    /// Per-attempt parameters from the persisted ones: the first configured STUN
    /// server, and [`NatConfig::default`]'s timeouts for the fields a device does
    /// not persist.
    fn from(nat: &NatNetworkConfig) -> Self {
        let defaults = Self::default();
        Self {
            stun_server: nat
                .stun_servers
                .first()
                .cloned()
                .unwrap_or(defaults.stun_server),
            relay_url: nat.relay_url.clone(),
            turn_url: nat.turn_url.clone(),
            turn_username: nat.turn_username.clone(),
            turn_password: nat.turn_password.clone(),
            keepalive_interval_secs: nat.keepalive_interval_secs,
            ..defaults
        }
    }
}

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum NatError {
    #[error("STUN discovery failed: {0}")]
    Stun(String),

    #[error("Coord exchange failed: {0}")]
    Coord(String),

    #[error("TURN allocation failed: {0}")]
    Turn(String),

    #[error("All NAT paths exhausted — no reachable path to peer")]
    AllPathsFailed,
}

// ── Result ────────────────────────────────────────────────────────────────────

/// Outcome of a [`nat_connect`] attempt.
#[derive(Debug)]
pub enum NatResult {
    /// Direct QUIC path succeeded (LAN / open firewall).
    Direct(quinn::Connection),

    /// Simultaneous hole-punch succeeded.
    Punched(quinn::Connection),

    /// Direct and hole-punch failed; a TURN relay has been set up and the
    /// peer's relay address has been obtained via coord. Use `TurnUdpSocket`
    /// over `client` to connect QUIC to `peer_relay_addr`.
    TurnRelay {
        /// Boxed: a TURN client is about ten times the size of every other variant.
        client: Box<TurnClient>,
        alloc: TurnAllocation,
        /// The peer's relay address; pass as the QUIC remote address.
        peer_relay_addr: SocketAddr,
        /// The peer's STUN reflexive IP; used for `CreatePermission`.
        peer_reflexive_ip: IpAddr,
    },

    /// All three paths failed.
    Failed(NatError),
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Attempt to establish a QUIC connection to `peer_pubkey` via the NAT ladder.
///
/// * `device_signing_key` — local Ed25519 signing key (mTLS + coord auth). The
///   coord/relay identity is `did:key(its pubkey)`, derived internally, so peers
///   that look us up by `did:key(our pubkey)` and the relay's push-auth agree.
/// * `peer_pubkey` — remote device's 32-byte Ed25519 public key.
/// * `direct_addr` — peer's last-known IP:port; `None` skips step 1.
/// * `config` — NAT traversal parameters.
/// * `event_bus` — optional structured event sink.
pub async fn nat_connect(
    device_signing_key: &ed25519_dalek::SigningKey,
    offer: &tls::CertOffer,
    peer_pubkey: [u8; 32],
    direct_addr: Option<SocketAddr>,
    config: &NatConfig,
    event_bus: Option<Arc<EventBus>>,
) -> NatResult {
    let emit = |level: EventLevel, msg: String| {
        if let Some(eb) = &event_bus {
            let _ = eb.publish(Event::new(EventCategory::Network, level, msg));
        }
    };

    // Step 1: direct QUIC
    if let Some(addr) = direct_addr {
        debug!(peer = %addr, "NAT: trying direct QUIC");
        match try_direct_quic(device_signing_key, offer, peer_pubkey, addr, config).await {
            Ok(conn) => {
                info!(peer = %addr, "NAT: direct path succeeded");
                emit(EventLevel::Info, format!("Direct QUIC to {addr}"));
                return NatResult::Direct(conn);
            }
            Err(e) => debug!(peer = %addr, err = %e, "NAT: direct failed"),
        }
    }

    // Pre-step: STUN discovery + initial coord push (needed by step 2 and step 3).
    // Kept as Option so that steps 1-only deployments (no coord) still work.
    let coord_state: Option<(SocketAddr, CoordIdentities)> = if !config.relay_url.is_empty()
        && !config.stun_server.is_empty()
    {
        match setup_stun_and_coord(device_signing_key, peer_pubkey, config, &emit).await {
            Ok(r) => Some(r),
            Err(e) => {
                warn!(err = %e, "NAT: STUN/coord setup failed");
                None
            }
        }
    } else {
        None
    };

    // Step 2: hole-punch (requires coord)
    if let Some((stun_addr, coord)) = &coord_state {
        match punch_via_coord(
            device_signing_key,
            offer,
            peer_pubkey,
            config,
            &emit,
            *stun_addr,
            coord,
        )
        .await
        {
            Ok(conn) => {
                info!("NAT: hole-punch succeeded");
                emit(EventLevel::Info, "Hole-punch succeeded".into());
                return NatResult::Punched(conn);
            }
            Err(e) => {
                warn!(err = %e, "NAT: hole-punch failed, trying TURN");
                emit(EventLevel::Warn, format!("Hole-punch: {e}"));
            }
        }
    }

    // Step 3: TURN relay
    if !config.turn_url.is_empty() {
        let candidates = match rendezvous::lookup_candidates(
            device_signing_key,
            &peer_pubkey,
            rendezvous::unix_now(),
        ) {
            Ok(candidates) => candidates,
            Err(e) => {
                warn!(err = %e, "NAT: no rendezvous identifier for the peer");
                emit(EventLevel::Error, format!("TURN: peer rendezvous: {e}"));
                return NatResult::Failed(NatError::AllPathsFailed);
            }
        };
        let stun_and_coord = coord_state.as_ref().map(|(s, c)| (*s, c));
        match allocate_turn(stun_and_coord, &candidates, config, &emit).await {
            Ok((client, alloc, peer_relay_addr, peer_reflexive_ip)) => {
                info!(
                    relay = %alloc.relay_addr,
                    peer_relay = %peer_relay_addr,
                    "NAT: TURN relay ready"
                );
                emit(EventLevel::Info, format!("TURN relay {}", alloc.relay_addr));
                return NatResult::TurnRelay {
                    client: Box::new(client),
                    alloc,
                    peer_relay_addr,
                    peer_reflexive_ip,
                };
            }
            Err(e) => {
                warn!(err = %e, "NAT: TURN failed");
                emit(EventLevel::Error, format!("TURN: {e}"));
            }
        }
    }

    emit(EventLevel::Error, "All NAT paths failed".into());
    NatResult::Failed(NatError::AllPathsFailed)
}

// ── Private helpers ───────────────────────────────────────────────────────────

async fn try_direct_quic(
    device_signing_key: &ed25519_dalek::SigningKey,
    offer: &tls::CertOffer,
    peer_pubkey: [u8; 32],
    peer_addr: SocketAddr,
    config: &NatConfig,
) -> Result<quinn::Connection, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let device_cert = Ed25519DeviceCert::from_signing_key_with_offer(device_signing_key, offer)
        .map_err(|e| e.to_string())?;
    let mut paired = HashSet::new();
    paired.insert(peer_pubkey);
    let verifier = PairedDeviceVerifier::new(Arc::new(RwLock::new(paired)), Arc::clone(&provider));
    let client_cfg = tls::build_peer_client_config(&device_cert, verifier, provider, config.keepalive())
        .map_err(|e| e.to_string())?;

    let bind = kotton_net::transport::outbound_bind_addr(peer_addr);
    let endpoint = quinn::Endpoint::client(bind).map_err(|e| e.to_string())?;

    let conn_fut = async {
        endpoint
            .connect_with(client_cfg, peer_addr, "kotton-peer")
            .map_err(|e| e.to_string())?
            .await
            .map_err(|e| e.to_string())
    };

    match tokio::time::timeout(config.direct_timeout, conn_fut).await {
        Ok(Ok(conn)) => Ok(conn),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(format!("direct timeout {:?}", config.direct_timeout)),
    }
}

/// The identities this dial announces its address under.
///
/// The handle is the one *this peer* derives ([`crate::rendezvous`]), so the
/// coordination server is handed a label meaningless to anyone else — including
/// on the lookups, whose `Authorization` header carries the requester's own
/// fingerprint. `durable` is the coexistence window; deleting the field is
/// ROTATING-RENDEZVOUS-HANDLES step 5, and the compiler finds the rest.
struct CoordIdentities {
    handle: RendezvousClient,
}

impl CoordIdentities {
    /// Announce under every identity, and fail only if the address landed under
    /// **none** of them — being findable under one name is what the peer needs,
    /// and which name it was is the coexistence window's business.
    ///
    /// There is no asymmetric case: no relay mode admits durable DIDs and
    /// refuses rotating handles — a relay's admission rule is set by its operator
    /// over the wire, and it refuses a handle and a durable DID alike when the device
    /// presents no admission tag ([`rendezvous::is_identity_refusal`]).
    async fn push(
        &self,
        addr: SocketAddr,
        turn_relay: Option<SocketAddr>,
        relayable: bool,
    ) -> Result<(), String> {
        let handle = self.handle.push(addr, turn_relay, relayable).await;
        if let Err(e) = &handle {
            if rendezvous::is_identity_refusal(e) {
                warn!(
                    "NAT: the relay's admission rule refused this handle — its operator \
                     narrowed who may use it and this device presents no admission tag it \
                     accepts, so this device is not findable through it"
                );
            } else {
                debug!(err = %e, "NAT: pair-handle coord push failed");
            }
        }

        handle.map(|_| ()).map_err(|e| format!("coord push: {e}"))
    }
}

/// Discover the local reflexive address via STUN and do the initial coord push
/// (without relay addr). Returns `(reflexive_addr, coord_identities)`.
async fn setup_stun_and_coord(
    device_signing_key: &ed25519_dalek::SigningKey,
    peer_pubkey: [u8; 32],
    config: &NatConfig,
    emit: &impl Fn(EventLevel, String),
) -> Result<(SocketAddr, CoordIdentities), String> {
    let stun_server_addr: SocketAddr = config
        .stun_server
        .to_socket_addrs()
        .map_err(|e| format!("STUN addr '{}': {e}", config.stun_server))?
        .next()
        .ok_or_else(|| format!("STUN addr '{}' resolved to nothing", config.stun_server))?;
    let udp_sock = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("UDP bind: {e}"))?;
    let stun_addr = stun::discover(&udp_sock, stun_server_addr)
        .await
        .map_err(|e| format!("STUN: {e}"))?;
    debug!(reflexive = %stun_addr, "NAT: STUN reflexive");
    emit(EventLevel::Info, format!("STUN reflexive: {stun_addr}"));

    // Announce under the handle only this peer derives. The relay verifies it
    // exactly as it verifies any other identifier — the handle *is* a did:key
    // whose key signs the push — so this needs no server change.
    let handle = rendezvous::publish_to(device_signing_key, &peer_pubkey, rendezvous::unix_now())
        .map_err(|e| format!("pair handle: {e}"))?;
    let coord = CoordIdentities {
        handle: RendezvousClient::new(
            &config.relay_url,
            handle.did.to_string(),
            handle.signing_key,
        )
        .with_admission(config.admission.clone()),
    };
    // relayable: this node accepts a relayed fallback
    coord.push(stun_addr, None, true).await?;
    Ok((stun_addr, coord))
}

/// Run the hole-punch attempt using an already-established STUN reflexive
/// address and coord client (from [`setup_stun_and_coord`]).
async fn punch_via_coord(
    device_signing_key: &ed25519_dalek::SigningKey,
    offer: &tls::CertOffer,
    peer_pubkey: [u8; 32],
    config: &NatConfig,
    emit: &impl Fn(EventLevel, String),
    stun_addr: SocketAddr,
    coord: &CoordIdentities,
) -> Result<quinn::Connection, String> {
    let local_pubkey = device_signing_key.verifying_key().to_bytes();

    let candidates =
        rendezvous::lookup_candidates(device_signing_key, &peer_pubkey, rendezvous::unix_now())
            .map_err(|e| format!("peer rendezvous identifiers: {e}"))?;
    let peer_addr = poll_coord_for_peer(&coord.handle, &candidates, config).await?;
    debug!(peer = %peer_addr, "NAT: peer coord addr");
    emit(EventLevel::Info, format!("Peer addr: {peer_addr}"));

    let role = PunchRole::determine(&local_pubkey, &peer_pubkey);
    let keepalive = config.keepalive();
    match simultaneous_punch(
        device_signing_key,
        offer,
        stun_addr,
        peer_addr,
        peer_pubkey,
        role,
        Some(config.punch_timeout),
        keepalive,
    )
    .await
    {
        PunchResult::Direct(conn) => Ok(conn),
        PunchResult::NeedsTurn => Err("punch timeout".into()),
        PunchResult::Failed(e) => Err(format!("punch: {e}")),
    }
}

/// Poll coord for the peer, trying each identifier it might have announced under
/// (`candidates`, in order: this epoch's pair handle, one either side, then the
/// durable DID while the coexistence window is open).
async fn poll_coord_for_peer(
    coord: &RendezvousClient,
    candidates: &[String],
    config: &NatConfig,
) -> Result<SocketAddr, String> {
    let deadline = tokio::time::Instant::now() + config.coord_poll_timeout;
    loop {
        for candidate in candidates {
            if let Ok((addr, _relay)) = coord.lookup(candidate).await {
                return Ok(addr);
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "peer not on coord under any of {} identifiers after {:?}",
                candidates.len(),
                config.coord_poll_timeout
            ));
        }
        tokio::time::sleep(config.coord_poll_interval).await;
    }
}

/// Poll coord until the peer's entry has `turn_relay_addr` populated.
///
/// Returns `(peer_relay_addr, peer_reflexive_ip)` on success.
async fn poll_coord_for_peer_relay(
    coord: &RendezvousClient,
    candidates: &[String],
    config: &NatConfig,
) -> Result<(SocketAddr, IpAddr), String> {
    let deadline = tokio::time::Instant::now() + config.turn_relay_poll_timeout;
    loop {
        for candidate in candidates {
            if let Ok((reflexive_addr, Some(relay_addr))) = coord.lookup(candidate).await {
                return Ok((relay_addr, reflexive_addr.ip()));
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "peer did not publish a relay addr under any of {} identifiers within {:?}",
                candidates.len(),
                config.turn_relay_poll_timeout
            ));
        }
        tokio::time::sleep(config.coord_poll_interval).await;
    }
}

/// Allocate a TURN relay, exchange relay addresses via coord, bind a channel
/// to the peer, and return the live `(TurnClient, TurnAllocation,
/// peer_relay_addr, peer_reflexive_ip)` tuple ready for `TurnUdpSocket`.
async fn allocate_turn(
    // STUN reflexive address + coord client obtained during pre-step setup.
    // `None` when coord is not configured; in that case `allocate_turn` returns
    // an error because relay address exchange is impossible without coord.
    stun_and_coord: Option<(SocketAddr, &CoordIdentities)>,
    peer_candidates: &[String],
    config: &NatConfig,
    emit: &impl Fn(EventLevel, String),
) -> Result<(TurnClient, TurnAllocation, SocketAddr, IpAddr), String> {
    let Some((stun_addr, coord)) = stun_and_coord else {
        return Err(
            "TURN relay requires a coord server for relay address exchange; \
             set relay_url and stun_server in NatConfig"
                .into(),
        );
    };

    let turn_addr: SocketAddr = config
        .turn_url
        .parse()
        .map_err(|e| format!("bad TURN addr '{}': {e}", config.turn_url))?;

    let mut turn = TurnClient::new(turn_addr, &config.turn_username, &config.turn_password)
        .await
        .map_err(|e| format!("TurnClient::new: {e}"))?;

    let alloc = turn
        .allocate()
        .await
        .map_err(|e| format!("allocate: {e}"))?;
    emit(
        EventLevel::Info,
        format!("TURN relay: {}", alloc.relay_addr),
    );

    // Re-push to coord with relay addr so the peer can find us — under the same
    // identities the first push used, or the peer looks in the wrong place.
    coord.push(stun_addr, Some(alloc.relay_addr), true).await?;
    debug!(relay = %alloc.relay_addr, "NAT: pushed relay addr to coord");

    // Wait for peer to publish its relay addr.
    let (peer_relay_addr, peer_reflexive_ip) =
        poll_coord_for_peer_relay(&coord.handle, peer_candidates, config).await?;
    emit(EventLevel::Info, format!("Peer relay: {peer_relay_addr}"));

    // Authorise the peer's reflexive IP and open a ChannelData binding.
    turn.create_permission(peer_reflexive_ip)
        .await
        .map_err(|e| format!("create_permission: {e}"))?;
    turn.channel_bind(peer_relay_addr)
        .await
        .map_err(|e| format!("channel_bind: {e}"))?;

    Ok((turn, alloc, peer_relay_addr, peer_reflexive_ip))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nat_config_defaults_are_sensible() {
        let cfg = NatConfig::default();
        // STUN/relay endpoints have no safe default — they must be configured
        // explicitly via RuntimeConfig before NAT traversal can run.
        assert!(cfg.stun_server.is_empty());
        assert!(cfg.direct_timeout < cfg.punch_timeout);
    }

    #[test]
    fn nat_result_debug() {
        let err = NatResult::Failed(NatError::AllPathsFailed);
        assert!(format!("{:?}", err).contains("AllPathsFailed"));
    }

    /// The direct rung carries the configured keep-alive, so a connection a
    /// remote holds outlives a quiet spell longer than the idle timeout. Red
    /// while `try_direct_quic` built its client with no keep-alive — the
    /// landlord-drop tests' `open_bi failed: timed out`.
    #[tokio::test]
    async fn a_direct_connection_outlives_a_quiet_spell_longer_than_its_idle_timeout() {
        use crate::channel::redial_tests::{echo_peer, keys};
        use crate::channel::PeerChannel;
        let (server, client) = keys();
        let idle = Duration::from_millis(2500);
        let addr = echo_peer(&server, &client, idle);
        let config = NatConfig {
            keepalive_interval_secs: 1,
            ..NatConfig::default()
        };
        let conn = try_direct_quic(
            &client,
            &tls::CertOffer::default(),
            server.verifying_key().to_bytes(),
            addr,
            &config,
        )
        .await
        .expect("a direct dial on loopback");

        tokio::time::sleep(idle + Duration::from_millis(1500)).await;

        assert!(conn.close_reason().is_none(), "kept alive: {:?}", conn.close_reason());
        let link = crate::QuicPeerChannel::new(conn);
        assert_eq!(link.request(b"still here").await.unwrap(), b"still here");
    }

    #[test]
    fn a_keepalive_of_zero_is_none_and_any_other_is_that_many_seconds() {
        let off = NatConfig {
            keepalive_interval_secs: 0,
            ..NatConfig::default()
        };
        assert_eq!(off.keepalive(), None);
        assert_eq!(NatConfig::default().keepalive(), Some(Duration::from_secs(20)));
    }
}
