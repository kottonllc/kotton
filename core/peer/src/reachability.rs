// SPDX-License-Identifier: AGPL-3.0-or-later
//! Being reachable: the inbound half of the mesh.
//!
//! [`nat`](crate::nat) is how this device reaches another one. This is how it
//! arranges to *be* reached — the QUIC socket peers dial, the presence
//! registration that says where to dial it, and the relay reservation that
//! carries a circuit when nothing direct works.
//!
//! Four pieces of state — the live NAT config, the STUN-learned reflexive
//! address, the presence task, and the relay-changed signal — are here and not
//! on `DeviceRuntime`, where every method could reach them though only these
//! three tasks use them. They are one
//! piece of state with one lifetime, and it is peer authority: reachability is
//! about which of a user's devices can find this one, not about the machine.
//!
//! # What stays behind
//!
//! The accept loop for the directly-bound socket is still
//! `DeviceRuntime::spawn_accept_loop`: it ends the loop on device shutdown and
//! publishes to the device's event bus, so it is device lifecycle. This module
//! hands back a bound [`Listener`] and lets the device drive it. The relayed
//! circuits are served here because their loop is the reservation's — it
//! reconnects when the relay changes, and there is no reservation to serve
//! without one.
//!
//! # What the coordination server learns
//!
//! The presence registrar announces one entry **per paired peer**, under the
//! handle only that peer derives — see [`crate::rendezvous`], which owns that
//! decision and the coexistence window that has not closed yet.

use kotton_wire::ipc::{RelayReadout, RelayState};
use crate::nat::NatNetworkConfig;
use crate::rendezvous;
use crate::relay_keys::{relay_id, RelayId};
use anyhow::Result;
use ed25519_dalek::SigningKey;
use kotton_net::rendezvous::client::RendezvousClient;
use kotton_net::transport::quic::tls::{Admission, Ed25519DeviceCert, PairedDeviceVerifier};
use kotton_net::transport::{RelayClient, RelayedInbound};
use kotton_net::QuicTransport;
use kotton_sys::net::{Address, Listener, Transport};
use std::collections::HashSet;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// Type-erased async handler for inbound peer requests.
///
/// The daemon builds one of these (capturing its database and runtime) and hands
/// it to whatever is listening. The first argument is the connecting peer's DID
/// string (e.g. `did:key:z6Mk…`), derived from the peer's TLS certificate; the
/// second is the raw request bytes.
pub type PeerHandler = Arc<
    dyn Fn(String, Vec<u8>) -> Pin<Box<dyn Future<Output = Vec<u8>> + Send>> + Send + Sync,
>;

/// Re-push interval for the presence registrar. The relay TTL defaults to 60s, so
/// re-pushing at ~ttl/2 keeps the entry continuously live.
const PRESENCE_REPUSH_INTERVAL: Duration = Duration::from_secs(25);

/// Reconnect interval after a relay reservation drops (e.g. the relay restarts).
const RELAY_RECONNECT_INTERVAL: Duration = Duration::from_secs(5);

/// How often the reservation set is reconciled against the paired-peer set and
/// the current epoch.
///
/// One second, because a newly paired peer must be able to dial straight away:
/// the reservation under its handle is the *only* way in — there is no durable
/// one — and it did not exist a moment ago. Thirty seconds would leave a gap a
/// durable reservation would quietly cover. The check is a set comparison and a few key derivations; the network
/// is touched only when something changed. Well under the two-epoch window, so
/// an epoch boundary crossed between checks never leaves the device undialable.
const RESERVATION_RECHECK_INTERVAL: Duration = Duration::from_secs(1);

/// This device's reachability: the state and the tasks that keep its paired
/// peers able to open a connection to it.
///
/// Configuration is live rather than boot-time. A runtime `relay set` calls
/// [`reconfigure`](Self::reconfigure) and both the presence registration and the
/// inbound reservation move to the new relay without a restart — which is what
/// lets a device boot with no relay at all and become reachable afterwards.
/// One contact pair's mailbox: where a message from them lands, and who may
/// land it.
///
/// The identity keys are the user's and the contact's — the same pair
/// `dm_encrypt` runs its ECDH over — because a message is between *people*.
/// What the circuit itself proves, on both ends, is the pair's key for the
/// epoch (`dm_door`), derived from those two and opening nothing: that is what
/// lets a vault handed the same keys answer this door identically
/// ([`DmDoor`]), while *who wrote* is proved inside the seal.
pub struct DmInbox {
    /// The user's identity signing key: derives the door for each epoch. Never
    /// presented inside the circuit.
    pub own_identity: SigningKey,
    /// The contact's identity key: derives the one key each epoch's door
    /// admits, and is what the handler holds the message's signature to.
    pub contact_pub: [u8; 32],
    /// Serves what arrives. One pair, one handler, one verb.
    pub handler: PeerHandler,
}

/// One door held on someone's behalf: a pair handle for one
/// epoch, handed to this node by a device that derived it. A vault holds these
/// for a person whose devices may all be asleep; it can answer the door and
/// open nothing behind it.
pub struct DmDoor {
    pub epoch: u64,
    /// Reserves the label and is the certificate inside a served circuit.
    pub handle: kotton_crypto::PairHandle,
    /// The one key the door admits: the contact's handle for the same epoch.
    pub admit: [u8; 32],
    pub handler: PeerHandler,
}

pub struct Reachability {
    /// The device's operational Ed25519 key. It authenticates the mTLS handshake,
    /// signs presence pushes, and *is* the identifier peers look this device up
    /// by — the relay extracts the verifying key from the DID it is given.
    signing_key: SigningKey,

    /// The live reachability config — the source of truth both the dial side and
    /// the tasks here read, so a change takes effect without a restart.
    nat: RwLock<NatNetworkConfig>,

    /// This device's STUN-probed reflexive address, captured when the peer
    /// listener binds. Reused to re-register presence on a relay change (the
    /// socket is unchanged across the swap). `None` until a STUN-probed bind.
    reflexive: RwLock<Option<SocketAddr>>,

    /// Where this device's peer listener actually bound — read back off the
    /// socket, never copied from the config that asked for it. `None` until
    /// [`bind_peer_listener`](Self::bind_peer_listener) returns.
    ///
    /// It exists because a device has to be able to *say* where it is reached,
    /// and the two other places that claimed to know were both wrong: the
    /// configured port is `None` on a node whose listener was started by an
    /// explicit call, and a bind on port 0 has no configured port at all. The
    /// socket is the only thing that knows.
    peer_listen_addr: RwLock<Option<SocketAddr>>,

    /// The running presence registrar, so a relay change can abort and respawn it
    /// against the new relay.
    presence_task: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,

    /// Signals the always-running reservation listener to reconnect. This is the
    /// load-bearing inbound path: it needs only the relay URL, no STUN and no
    /// reflexive address.
    relay_changed: tokio::sync::Notify,

    /// The reservations whose control socket is open on the relay right now,
    /// by fingerprint — what [`relay_readout`](Self::relay_readout) counts as
    /// *live*. A holder inserts itself once the relay has accepted the
    /// reservation and removes itself when it ends; the reconcile loop drops
    /// whatever it aborts, since an aborted task runs no cleanup.
    relay_live: Arc<RwLock<HashSet<String>>>,

    /// How many reservations the last reconcile wanted held — the denominator
    /// of the readout.
    relay_wanted: std::sync::atomic::AtomicUsize,

    /// The live allowlist of paired device keys — raw Ed25519 public keys,
    /// consulted at every TLS handshake, so removing one revokes access without a
    /// restart.
    ///
    /// It lives here because it answers two questions that must not diverge: who
    /// may connect, and who this device announces itself to. The daemon seeds it
    /// from its own records and keeps it current
    /// ([`paired_keys`](Self::paired_keys)).
    paired_keys: Arc<RwLock<HashSet<[u8; 32]>>>,

    /// The per-pair mailboxes this node answers for its users' contacts.
    ///
    /// A separate door, not a second check on the device door: each entry is
    /// reserved under an address only the two identity keys derive, admits
    /// exactly one key at the handshake, and serves a handler that decodes
    /// `ContactRequest` — one verb. So a contact is not refused a storage verb;
    /// there is no storage verb at the address they can reach.
    ///
    /// The daemon owns what is in here (it knows users and contacts); this crate
    /// owns the epochs and the reservations, exactly as it does for devices.
    dm_inboxes: Arc<RwLock<Vec<DmInbox>>>,
    /// Doors handed to this node to hold for someone else. Held
    /// by epoch: the reconcile reserves the current and previous one, exactly
    /// as it does for a mailbox this node derives itself.
    dm_doors: Arc<RwLock<Vec<DmDoor>>>,

    /// What lets this node admit a device it was never told about: the identity
    /// tips it hosts, the recovery authorities they committed, and the verdicts
    /// the handshake has handed the request handler to persist.
    ///
    /// One handle, shared with every verifier this reachability builds, for the
    /// same reason `paired_keys` is: a copy would drift.
    admission: Admission,

    /// The relay admission keys this device holds, by relay
    /// ([`crate::relay_keys`]). Read at every reservation, circuit, lookup and
    /// push this reachability makes.
    relay_keys: crate::relay_keys::RelayKeyring,
}

impl Reachability {
    /// Build the handle from the device's boot config and operational key.
    ///
    /// The paired-key allowlist starts empty; the daemon seeds it from its own
    /// records through [`paired_keys`](Self::paired_keys) before the listener
    /// starts. An empty set admits nobody, which is the safe direction to be
    /// wrong in.
    pub fn new(nat: NatNetworkConfig, signing_key: SigningKey) -> Self {
        Self {
            signing_key,
            nat: RwLock::new(nat),
            reflexive: RwLock::new(None),
            peer_listen_addr: RwLock::new(None),
            presence_task: tokio::sync::Mutex::new(None),
            relay_changed: tokio::sync::Notify::new(),
            relay_live: Arc::new(RwLock::new(HashSet::new())),
            relay_wanted: std::sync::atomic::AtomicUsize::new(0),
            paired_keys: Arc::new(RwLock::new(HashSet::new())),
            dm_inboxes: Arc::new(RwLock::new(Vec::new())),
            dm_doors: Arc::new(RwLock::new(Vec::new())),
            admission: Admission::default(),
            relay_keys: crate::relay_keys::RelayKeyring::default(),
        }
    }

    /// The relay admission keys this device holds — see the field. Cloning
    /// shares.
    pub fn relay_keys(&self) -> crate::relay_keys::RelayKeyring {
        self.relay_keys.clone()
    }

    /// What to present at an address a contact supplied, for `user`'s
    /// delivery: at this device's own relay by its own record, `user`'s own key
    /// there, and what the contact `handed` only when `user` holds none; at any
    /// other address, what the contact handed and nothing of `user`'s
    /// ([`crate::relay_keys::RelayKeyring::at_supplied_address`]). A relayed
    /// dial is the machine's reach and does not come here
    /// ([`crate::relay_keys::RelayKeyring::dialing_supplied_address`]).
    pub fn present_at_supplied(
        &self,
        user: &str,
        dialing: &str,
        handed: Option<kotton_net::rendezvous::AdmissionKey>,
    ) -> Option<kotton_net::rendezvous::AdmissionKey> {
        let nat = self.nat.read().unwrap().clone();
        let own = relay_id(nat.relay_key.as_deref());
        self.relay_keys.at_supplied_address(user, dialing, handed, &nat.relay_url, own.as_ref())
    }

    /// The key this machine presents at its own relay: the one held under the
    /// key that relay proved when this device recorded it. `None` when it holds
    /// none, or recorded no key for its relay — the keyring is by the relay's
    /// key and never its address (`crate::relay_keys`).
    pub fn present_at_own_relay(&self) -> Option<kotton_net::rendezvous::AdmissionKey> {
        self.presenting_at_own_relay().into_key()
    }

    /// [`Self::present_at_own_relay`], with what the key is — for a contact's
    /// spoken code, which meets at this relay and says what it presented when
    /// the relay refuses it ([`crate::relay_keys::RefusedAtTheRelay`]).
    pub fn presenting_at_own_relay(&self) -> crate::relay_keys::Presenting {
        let relay = relay_id(self.nat.read().unwrap().relay_key.as_deref());
        crate::relay_keys::Presenting::held(relay.and_then(|r| self.relay_keys.presented_at(&r)))
    }

    /// Where this device's peer listener bound, once it has. The address a
    /// peer must dial to reach this node's protocol — as opposed to the
    /// short-lived bootstrap socket a pairing ceremony runs over.
    ///
    /// The IP may be unspecified (`0.0.0.0`), which is the honest answer for a
    /// wide bind: the port is this node's, and which of its addresses a given
    /// peer should use is that peer's question, not this one's.
    pub fn peer_listen_addr(&self) -> Option<SocketAddr> {
        *self.peer_listen_addr.read().unwrap()
    }

    /// The live admission state — see the field. Cloning shares.
    pub fn admission(&self) -> Admission {
        self.admission.clone()
    }

    /// A snapshot of the live reachability config — what the dial side reads
    /// before each attempt, so it picks up a runtime change.
    pub fn nat(&self) -> NatNetworkConfig {
        self.nat.read().unwrap().clone()
    }

    /// Whether this device can be reached through its relay right now.
    /// Read from the reservation listener's own state: a
    /// reservation is a live control socket on the relay, so *held* is
    /// *reachable*, and the readout never says more than the relay has
    /// accepted. `Down` covers a relay named with nothing held at it — down,
    /// unreachable, or nothing paired to hold for; the counts tell those apart.
    /// During a forwarding window the counts include the relay being left.
    pub fn relay_readout(&self) -> RelayReadout {
        if self.nat.read().unwrap().relay_url.is_empty() {
            return RelayReadout::NONE;
        }
        let reservations_live = self.relay_live.read().unwrap().len() as u32;
        let reservations_wanted =
            self.relay_wanted.load(std::sync::atomic::Ordering::Relaxed) as u32;
        RelayReadout {
            state: if reservations_live > 0 { RelayState::Up } else { RelayState::Down },
            reservations_wanted,
            reservations_live,
        }
    }

    /// The live paired-key allowlist, for the daemon to seed and keep current as
    /// devices are paired and revoked.
    ///
    /// One set, shared: the TLS verifier admits exactly the devices the presence
    /// registrar announces to. Handing out the `Arc` rather than copies is what
    /// keeps that true — a second copy would drift the day one of them was updated
    /// and the other was not.
    /// The live mailbox registry — see the field. The daemon replaces its
    /// contents when a contact is admitted or removed; the reservation loop
    /// picks the change up on its next reconcile.
    pub fn dm_inboxes(&self) -> Arc<RwLock<Vec<DmInbox>>> {
        Arc::clone(&self.dm_inboxes)
    }

    /// The doors this node holds for others — see the field.
    pub fn dm_doors(&self) -> Arc<RwLock<Vec<DmDoor>>> {
        Arc::clone(&self.dm_doors)
    }

    pub fn paired_keys(&self) -> Arc<RwLock<HashSet<[u8; 32]>>> {
        Arc::clone(&self.paired_keys)
    }

    /// Bind the QUIC peer-listener on `port` and start maintaining presence.
    ///
    /// Returns the bound listener; the caller owns the accept loop. Only devices
    /// in [`paired_keys`](Self::paired_keys) can complete the handshake, and the
    /// set is consulted at each one — removing a key revokes access without a
    /// restart.
    ///
    /// When the relay's STUN responder is configured, the socket is STUN-probed
    /// first so the device learns its reflexive address, and a presence registrar
    /// keeps it findable through the relay even while it initiates nothing.
    ///
    /// Under [`crate::scope::local_only`] the socket binds `127.0.0.1` and the STUN
    /// probe and presence registration are skipped: the run has declared that
    /// nothing off this machine will dial it.
    /// Read the bound address back off the socket and keep it, so this node can
    /// tell a peer where to dial it. `local_addr()` is the only source that is
    /// right for a port-0 bind.
    fn remember_peer_listen_addr(&self, listener: &dyn Listener) {
        if let Address::Quic(addr) = listener.local_addr() {
            *self.peer_listen_addr.write().unwrap() = Some(*addr);
        }
    }

    /// Bind the local-network door's listener
    /// ([`crate::local_door`]): an ephemeral port, admitting exactly the devices
    /// [`paired_keys`](Self::paired_keys) admits, with no STUN probe and no presence
    /// registration — it is a door on one network, not a way to be found on the
    /// internet, and it is not [`peer_listen_addr`](Self::peer_listen_addr).
    ///
    /// A fresh port each time the door opens — and the device's keeper reopens an
    /// *Always* door at each day's turn — so two recordings of the door on two days share
    /// no port. Under [`crate::scope::local_only`] it binds loopback, as every inbound
    /// socket does.
    pub async fn bind_door_listener(&self) -> Result<Box<dyn Listener>> {
        let transport = QuicTransport::new_peer_with_admission(
            &self.signing_key,
            self.paired_keys(),
            self.admission(),
        )
        .map_err(|e| anyhow::anyhow!("failed to create door QUIC transport: {e}"))?;
        let bind = SocketAddr::from((crate::scope::inbound_bind_ip(), 0));
        let listener = transport
            .listen(&Address::Quic(bind))
            .await
            .map_err(|e| anyhow::anyhow!("failed to bind the local door on {bind}: {e}"))?;
        tracing::info!(%bind, "local-network door open");
        Ok(listener)
    }

    /// The names this device announces its open door under on the network keyed
    /// `router`, on `day`: one per paired device, each recognisable by that device
    /// alone (`kotton_crypto::door_announce_name`). A pair whose key is not a curve
    /// point is skipped rather than announced under something guessable.
    pub fn door_names(&self, router: &[u8; 32], day: u64) -> Vec<String> {
        let peers: Vec<[u8; 32]> = self.paired_keys.read().unwrap().iter().copied().collect();
        peers
            .iter()
            .filter_map(|peer| {
                kotton_crypto::door_announce_name(&self.signing_key, peer, router, day).ok()
            })
            .collect()
    }

    pub async fn bind_peer_listener(&self, port: u16) -> Result<Box<dyn Listener>> {
        let transport = QuicTransport::new_peer_with_admission(
            &self.signing_key,
            self.paired_keys(),
            self.admission(),
        )
        .map_err(|e| anyhow::anyhow!("failed to create peer QUIC transport: {e}"))?;

        // A same-machine run binds loopback: peers on this host dial 127.0.0.1, so
        // the wide bind reaches nobody it needs to and costs a firewall dialog.
        // See [`crate::scope`] for why the switch is not pairing's to own.
        let local_only = crate::scope::local_only();
        let bind = SocketAddr::from((crate::scope::bind_ip_for(local_only), port));

        // Snapshot the LIVE config; a later `relay set` re-registers presence
        // against the new value through `reconfigure`.
        let nat = self.nat();
        // A loopback socket has no reflexive address worth learning and nothing
        // off-machine could act on the presence entry, so local-only skips both
        // rather than failing the bind when the STUN probe cannot leave the host.
        let relay_stun = if local_only {
            None
        } else {
            nat.relay_stun_addr
                .as_deref()
                .and_then(|s| s.parse::<SocketAddr>().ok())
        };

        let Some(relay_stun) = relay_stun else {
            let listener = transport.listen(&Address::Quic(bind)).await.map_err(|e| {
                anyhow::anyhow!("failed to bind QUIC peer listener on port {port}: {e}")
            })?;
            self.remember_peer_listen_addr(listener.as_ref());
            tracing::info!(%bind, "QUIC peer listener bound");
            return Ok(listener);
        };

        let (listener, reflexive) =
            transport.listen_with_stun(bind, relay_stun).await.map_err(|e| {
                anyhow::anyhow!("failed to bind STUN-probed QUIC listener on port {port}: {e}")
            })?;
        self.remember_peer_listen_addr(listener.as_ref());
        tracing::info!(port, %reflexive, "QUIC peer listener bound (STUN-probed)");

        // Remember the reflexive address so a relay change can re-register
        // presence without rebinding the socket.
        *self.reflexive.write().unwrap() = Some(reflexive);

        if nat.relay_url.is_empty() {
            tracing::warn!(
                "relay_stun_addr set but relay_url empty — presence will not be maintained"
            );
        } else {
            self.spawn_presence_registrar(&nat.relay_url, relay_id(nat.relay_key.as_deref()), reflexive).await?;
            tracing::info!(%reflexive, "presence registrar started");
        }
        Ok(listener)
    }

    /// Hold a reservation on the relay and serve the circuits that arrive on it
    /// — the inbound path for when direct, punch and
    /// TURN all fail.
    ///
    /// Always started, whether or not a relay is configured: it idles until one is
    /// and reconnects live when [`reconfigure`](Self::reconfigure) changes it,
    /// which is what makes a relay-less boot recoverable at runtime. Admits from
    /// the same live allowlist as the direct socket, so revocation applies here
    /// too.
    pub fn spawn_relay_listener(self: &Arc<Self>, handler: PeerHandler) {
        let this = Arc::clone(self);
        tokio::spawn(async move { this.run_relay_listener(handler).await });
        tracing::info!("relay reservation listener started");
    }

    /// Apply a reachability config change (e.g. a runtime `relay set`) to the
    /// running device: update the live cell the dial side reads, move the inbound
    /// reservation to the new relay, and re-register presence. No restart.
    pub async fn reconfigure(&self, nat: NatNetworkConfig) -> Result<()> {
        let relay_url = nat.relay_url.clone();
        let relay = relay_id(nat.relay_key.as_deref());
        *self.nat.write().unwrap() = nat;

        // Inbound reachability: the reservation listener needs only the URL, so it
        // works even from a relay-less boot. This is the load-bearing path.
        self.relay_changed.notify_one();

        // Direct-dial presence (secondary): only meaningful once a STUN-probed
        // bind has given us a reflexive address. Best-effort.
        let reflexive = *self.reflexive.read().unwrap();
        if let Some(reflexive) = reflexive {
            self.spawn_presence_registrar(&relay_url, relay, reflexive).await?;
        }
        Ok(())
    }

    /// Spawn the presence registrar against `relay_url`, replacing any prior one.
    /// No-op when `relay_url` is empty.
    ///
    /// Presence is what makes this device findable. It announces the address once
    /// per paired peer, under the per-pair handle that peer derives
    /// ([`crate::rendezvous`]) — plus, during the coexistence window, under the
    /// durable DID an un-upgraded peer still looks for.
    async fn spawn_presence_registrar(
        &self,
        relay_url: &str,
        relay: Option<RelayId>,
        reflexive: SocketAddr,
    ) -> Result<()> {
        let mut slot = self.presence_task.lock().await;
        if let Some(old) = slot.take() {
            old.abort();
        }
        if relay_url.is_empty() {
            return Ok(());
        }
        *slot = Some(tokio::spawn(run_presence_registrar(
            relay_url.to_string(),
            relay,
            self.signing_key.clone(),
            Arc::clone(&self.paired_keys),
            reflexive,
            self.relay_keys(),
        )));
        Ok(())
    }

    /// The reservation manager: keep one live reservation per identity this
    /// device should be dialable under, reconciled as epochs roll and peers are
    /// paired or revoked.
    ///
    /// The identities are per-pair, per-epoch handles ([`crate::rendezvous`],
    /// step 6): each paired peer gets a reservation under the handle only it
    /// derives, held for the **current and previous** epoch — a reservation is a
    /// live connection, so unlike a push it cannot absorb clock skew after the
    /// fact. While [`rendezvous::ANNOUNCE_DURABLE_DID`] holds, the durable
    /// reservation stays beside them so an un-upgraded peer's dial still lands.
    ///
    /// `2N + 1` held connections during coexistence. The set is re-reconciled
    /// every [`RESERVATION_RECHECK_INTERVAL`]; an epoch boundary is therefore
    /// picked up within that interval, which the two-epoch window covers — a
    /// dialer that names the new epoch before this device reserved it falls back
    /// to the previous epoch's reservation, which is still held.
    async fn run_relay_listener(self: Arc<Self>, handler: PeerHandler) {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        // "<relay> <fingerprint>" → the task holding that reservation.
        let mut held: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
            std::collections::HashMap::new();

        loop {
            // Re-read the live relay each cycle — and the one being left, while
            // its forwarding window is open: a peer that still
            // names it lands there and learns the current one.
            let now = rendezvous::unix_now();
            // Each with the key it proved, which is what the keys to present
            // there are held under.
            let (relay_url, forwarding) = {
                let nat = self.nat.read().unwrap();
                (
                    (nat.relay_url.clone(), relay_id(nat.relay_key.as_deref())),
                    nat.forwarding_relay(now as i64)
                        .map(|u| (u.to_string(), relay_id(nat.relay_key_previous.as_deref()))),
                )
            };
            if relay_url.0.is_empty() {
                // No relay configured — drop everything and idle until one is set.
                for (_, task) in held.drain() {
                    task.abort();
                }
                self.relay_live.write().unwrap().clear();
                self.relay_wanted.store(0, std::sync::atomic::Ordering::Relaxed);
                self.relay_changed.notified().await;
                continue;
            }

            // The identities this device should currently be dialable under, at
            // each relay it holds.
            let relays: Vec<(String, Option<RelayId>)> = std::iter::once(relay_url).chain(forwarding).collect();
            let peers: Vec<[u8; 32]> = self.paired_keys.read().unwrap().iter().copied().collect();
            let mut desired: Vec<Wanted> = Vec::with_capacity(2 * peers.len() * relays.len());
            for (relay, relay_key) in &relays {
                for peer in &peers {
                    for handle in rendezvous::reservation_handles(&self.signing_key, peer, now) {
                        let fingerprint = handle.did.to_string();
                        desired.push(Wanted {
                            slot: format!("{relay} {fingerprint}"),
                            relay: relay.clone(),
                            relay_key: *relay_key,
                            fingerprint,
                            reservation_key: handle.signing_key,
                            cert_key: self.signing_key.clone(),
                            admit: Arc::clone(&self.paired_keys),
                            admission: self.admission(),
                            handler: Arc::clone(&handler),
                        });
                    }
                }
            }

            // The mailboxes, on the same epochs and the same relays. Each is its
            // own door: its own address, a verifier holding one key, and a
            // handler that can serve one verb. Both ends of a
            // served circuit prove the pair's key for the epoch, never an
            // identity — so a vault handed the same keys answers identically,
            // and who wrote is settled inside the seal.
            let inboxes: Vec<(SigningKey, [u8; 32], PeerHandler)> = self
                .dm_inboxes
                .read()
                .unwrap()
                .iter()
                .map(|i| (i.own_identity.clone(), i.contact_pub, Arc::clone(&i.handler)))
                .collect();
            let epoch = kotton_crypto::epoch_at(now);
            let live_epochs = [Some(epoch), epoch.checked_sub(1)];
            let mut doors: Vec<(u64, kotton_crypto::PairHandle, [u8; 32], PeerHandler)> = Vec::new();
            for (own_identity, contact_pub, inbox_handler) in &inboxes {
                for e in live_epochs.iter().flatten() {
                    match rendezvous::dm_door(own_identity, contact_pub, *e) {
                        Ok(k) => doors.push((*e, k.handle, k.admit, Arc::clone(inbox_handler))),
                        Err(err) => tracing::warn!(error = %err, "mailbox: no handle for a contact"),
                    }
                }
            }
            for d in self.dm_doors.read().unwrap().iter() {
                if live_epochs.contains(&Some(d.epoch)) {
                    doors.push((
                        d.epoch,
                        kotton_crypto::PairHandle {
                            did: d.handle.did.clone(),
                            signing_key: d.handle.signing_key.clone(),
                        },
                        d.admit,
                        Arc::clone(&d.handler),
                    ));
                }
            }
            for (relay, relay_key) in &relays {
                for (epoch, handle, admit_key, door_handler) in &doors {
                    let fingerprint = handle.did.to_string();
                    // The one thing that could not be seen from outside. A relay
                    // reports a truncated device id per reservation and nothing
                    // maps it back to a handle, so "reservations are open" and "a
                    // reservation for *this* door is open" read identically —
                    // which is how a vault holding a person's doors and a sender
                    // getting 404 from the same relay would stay indistinguishable.
                    // The sender logs the address it dials; this is the other half
                    // of that comparison.
                    tracing::debug!(
                        epoch,
                        relay = %relay,
                        door = %fingerprint,
                        "reserving a pair door"
                    );
                    let mut admit = HashSet::new();
                    admit.insert(*admit_key);
                    desired.push(Wanted {
                        slot: format!("{relay} {fingerprint}"),
                        relay: relay.clone(),
                        relay_key: *relay_key,
                        fingerprint,
                        reservation_key: handle.signing_key.clone(),
                        // The pair's key for this epoch, not the device's and
                        // not the identity's: the contact knows the pair and
                        // nothing about the machine answering for it.
                        cert_key: handle.signing_key.clone(),
                        admit: Arc::new(RwLock::new(admit)),
                        // No admission-by-proof at a mailbox: the one key
                        // above is the whole of who may arrive.
                        admission: Admission::default(),
                        handler: Arc::clone(door_handler),
                    });
                }
            }
            // Coexistence (step 4/6): deleting this block is part of step 5, and
            // until then the relay still holds a durable identifier → live socket.

            // Reconcile: drop reservations no longer wanted (a revoked peer, an
            // aged-out epoch — aborting the task drops its control socket, which
            // is how the relay learns), keep the ones still wanted, start the new.
            let wanted: std::collections::HashSet<&String> =
                desired.iter().map(|w| &w.slot).collect();
            self.relay_wanted
                .store(desired.len(), std::sync::atomic::Ordering::Relaxed);
            held.retain(|slot, task| {
                let keep = wanted.contains(slot) && !task.is_finished();
                if !keep {
                    task.abort();
                    self.relay_live.write().unwrap().remove(slot);
                }
                keep
            });
            for w in desired {
                if held.contains_key(&w.slot) {
                    continue;
                }
                let slot = w.slot.clone();
                let task = tokio::spawn(hold_reservation(
                    w.relay,
                    w.relay_key,
                    w.fingerprint,
                    w.reservation_key,
                    w.cert_key,
                    w.admit,
                    w.admission,
                    w.handler,
                    Arc::clone(&provider),
                    Arc::clone(&self.relay_live),
                    slot.clone(),
                    self.relay_keys(),
                ));
                held.insert(slot, task);
            }

            // Wake early on a relay change — everything must move to the new
            // relay — otherwise re-reconcile on the interval.
            tokio::select! {
                _ = self.relay_changed.notified() => {
                    tracing::info!("relay changed; moving reservations to the new relay");
                    for (_, task) in held.drain() {
                        task.abort();
                    }
                    self.relay_live.write().unwrap().clear();
                }
                _ = tokio::time::sleep(RESERVATION_RECHECK_INTERVAL) => {}
            }
        }
    }
}

/// One reservation the reconcile wants held: where, under what label, and what
/// is behind it.
///
/// Both kinds of door are described by this — a device reservation and a
/// contact's mailbox differ only in the values, which is the point: the loop
/// holds reservations and has no opinion about who is on the other end.
struct Wanted {
    slot: String,
    relay: String,
    /// The key `relay` proved, which the keys presented there are held under.
    relay_key: Option<RelayId>,
    fingerprint: String,
    /// Proves the label to the relay.
    reservation_key: SigningKey,
    /// The certificate presented inside a served circuit.
    cert_key: SigningKey,
    /// Whose keys the handshake admits there.
    admit: Arc<RwLock<HashSet<[u8; 32]>>>,
    admission: Admission,
    handler: PeerHandler,
}

/// Hold one reservation under `fingerprint`, reconnecting until aborted.
///
/// The reservation *label* is the identity given here (a pair handle, or the
/// durable DID during coexistence); the mTLS inside a served circuit is always
/// the device's own certificate against the live paired-key allowlist — the
/// label is how a dial finds this device, never who it authenticates as.
#[allow(clippy::too_many_arguments)]
async fn hold_reservation(
    relay_url: String,
    relay: Option<RelayId>,
    fingerprint: String,
    reservation_key: SigningKey,
    device_key: SigningKey,
    paired_keys: Arc<RwLock<HashSet<[u8; 32]>>>,
    admission: Admission,
    handler: PeerHandler,
    provider: Arc<rustls::crypto::CryptoProvider>,
    live: Arc<RwLock<HashSet<String>>>,
    slot: String,
    keys: crate::relay_keys::RelayKeyring,
) {
    // Drain inbound circuits onto per-connection serve tasks. One consumer for
    // the task's lifetime: it ends when the last sender is dropped with it.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<RelayedInbound>(16);
    let serve_handler = Arc::clone(&handler);
    tokio::spawn(async move {
        while let Some(conn) = rx.recv().await {
            tokio::spawn(serve_relayed_conn(conn, Arc::clone(&serve_handler)));
        }
    });

    loop {
        let device_cert = match Ed25519DeviceCert::from_signing_key(&device_key) {
            Ok(cert) => cert,
            Err(e) => {
                tracing::error!(error = %e, "reservation: device cert build failed; giving up");
                return;
            }
        };
        let verifier = PairedDeviceVerifier::new_with_admission(
            Arc::clone(&paired_keys),
            admission.clone(),
            Arc::clone(&provider),
        );
        let client = RelayClient::new(
            &relay_url,
            fingerprint.clone(),
            reservation_key.clone(),
            device_cert,
            verifier,
            Arc::clone(&provider),
        )
        // Read at every attempt, so a key learned or rotated while this waited
        // is the one the next reservation presents.
        .with_admission(relay.and_then(|r| keys.present_at(&r)));
        // Held only once the relay has accepted the reservation: that is the
        // moment a dial by this handle lands, and the moment the readout counts.
        match client.reserve().await {
            Ok(reservation) => {
                live.write().unwrap().insert(slot.clone());
                if let Err(e) = reservation.serve(tx.clone()).await {
                    tracing::warn!(error = %e, "relay reservation ended; reconnecting");
                }
                live.write().unwrap().remove(&slot);
            }
            Err(e) => tracing::warn!(error = %e, "relay reservation refused; retrying"),
        }
        tokio::time::sleep(RELAY_RECONNECT_INTERVAL).await;
    }
}

/// Serve requests from one inbound relayed circuit until the peer closes it.
async fn serve_relayed_conn(conn: RelayedInbound, handler: PeerHandler) {
    let peer_did = conn.peer_did().to_string();
    loop {
        let h = Arc::clone(&handler);
        let pd = peer_did.clone();
        match conn
            .serve_one_request(move |req| async move { h(pd, req).await })
            .await
        {
            Ok(true) => {}      // served one request; continue
            Ok(false) => break, // peer closed cleanly
            Err(e) => {
                // A gateway drops its circuit when the browser behind it goes
                // away, and at this layer that is a reset, not a close. It is
                // the ordinary end of a session, not a fault.
                let text = e.to_string();
                if text.contains("reset") || text.contains("closed") {
                    tracing::info!(peer = %peer_did, "relayed circuit ended without a close");
                } else {
                    tracing::warn!(peer = %peer_did, error = %e, "relayed request error");
                }
                break;
            }
        }
    }
}

/// Persistent presence registrar: re-push this device's
/// reflexive address (with `relayable = true`) every
/// [`PRESENCE_REPUSH_INTERVAL`], so a peer can find it via `/lookup` even when it
/// is initiating nothing. Runs until aborted or the process exits.
///
/// **One announcement per paired peer**, each under the handle only that peer can
/// derive ([`crate::rendezvous`]). A device announcing one address under one
/// durable name hands the coordination server a join key; announcing the same
/// address under names no two peers can connect hands it nothing that composes.
/// The cost is one small request per peer per cycle instead of one in total, and
/// the gain is that a curious peer learns nothing about the rest of the mesh
/// either.
///
/// While [`ANNOUNCE_DURABLE_DID`] holds, the durable announcement goes out beside
/// them so an un-upgraded peer still finds this device. That is the coexistence
/// window, and it is why the property is not yet true.
async fn run_presence_registrar(
    relay_url: String,
    relay: Option<RelayId>,
    signing_key: SigningKey,
    paired_keys: Arc<RwLock<HashSet<[u8; 32]>>>,
    reflexive: SocketAddr,
    keys: crate::relay_keys::RelayKeyring,
) {
    // Coexistence only (ROTATING-RENDEZVOUS-HANDLES step 4); `None` once the
    // window closes, or if this device's own DID will not derive — in which case
    // the rotating handles are still fine, since they derive from the same key by
    // a different path.
    // What the current announcement covers. Rebuilt only when the epoch rolls
    // over or the paired set changes: a `RendezvousClient` owns an HTTP
    // connection pool, and rebuilding one per cycle would drop the relay's
    // keep-alive on every push.
    let mut covers: Option<(u64, HashSet<[u8; 32]>, Option<String>)> = None;
    let mut clients: Vec<RendezvousClient> = Vec::new();

    loop {
        let now = rendezvous::unix_now();
        let epoch = kotton_crypto::epoch_at(now);
        let peers: HashSet<[u8; 32]> = paired_keys.read().unwrap().clone();
        // The key this device presents here, compared by its text so a
        // rotation rebuilds the clients that carry it.
        let admit = relay.and_then(|r| keys.present_at(&r));
        let admit_text = admit.as_ref().map(|k| k.to_text());

        let stale = match &covers {
            Some((covered_epoch, covered_peers, covered_admit)) => {
                *covered_epoch != epoch || *covered_peers != peers || *covered_admit != admit_text
            }
            None => true,
        };
        if stale {
            clients = peers
                .iter()
                .filter_map(|peer| match rendezvous::publish_to(&signing_key, peer, now) {
                    Ok(handle) => Some(
                        RendezvousClient::new(
                            relay_url.clone(),
                            handle.did.to_string(),
                            handle.signing_key,
                        )
                        .with_admission(admit.clone()),
                    ),
                    Err(e) => {
                        tracing::warn!(error = %e, "presence: no handle for a paired peer");
                        None
                    }
                })
                .collect();
            covers = Some((epoch, peers, admit_text));
        }

        let mut announced = 0usize;
        for client in &clients {
            match client.push(reflexive, None, true).await {
                Ok(_) => announced += 1,
                Err(e) if rendezvous::is_identity_refusal(&e) => tracing::warn!(
                    "presence: the relay's admission rule refused this handle — its operator \
                     narrowed who may use it and this device presents no admission tag it \
                     accepts, so this device is not findable through it"
                ),
                Err(e) => tracing::warn!(error = %e, "presence push failed for a pair handle"),
            }
        }
        tracing::debug!(addr = %reflexive, epoch, announced, "presence re-pushed");

        tokio::time::sleep(PRESENCE_REPUSH_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reachability(nat: NatNetworkConfig) -> Reachability {
        Reachability::new(nat, SigningKey::generate(&mut rand::rngs::OsRng))
    }

    /// The config is live, not boot-time: what the dial side reads after a
    /// `relay set` is the new value, with no restart and no rebind.
    #[tokio::test]
    async fn reconfigure_replaces_what_the_dial_side_reads() {
        let device = reachability(NatNetworkConfig::default());
        assert_eq!(device.nat().relay_url, "");

        device
            .reconfigure(NatNetworkConfig {
                relay_url: "https://relay.example".to_string(),
                ..NatNetworkConfig::default()
            })
            .await
            .expect("no reflexive address yet, so presence is skipped rather than failing");

        assert_eq!(device.nat().relay_url, "https://relay.example");
    }

    /// The readout says `None` with no relay named and `Down` the
    /// moment one is — nothing has been held yet, and the readout never says
    /// more than the relay has accepted.
    #[tokio::test]
    async fn the_readout_never_claims_more_than_the_relay_accepted() {
        let device = reachability(NatNetworkConfig::default());
        assert_eq!(device.relay_readout(), RelayReadout::NONE);

        device
            .reconfigure(NatNetworkConfig {
                relay_url: "https://relay.example".to_string(),
                ..NatNetworkConfig::default()
            })
            .await
            .expect("presence is skipped without a reflexive address");

        let named = device.relay_readout();
        assert_eq!(named.state, RelayState::Down, "{named:?}");
        assert_eq!((named.reservations_wanted, named.reservations_live), (0, 0));
    }

    /// A device with no relay configured still binds and is reachable directly —
    /// the relay is a fallback for when it is not, not a precondition.
    ///
    /// The bound address is asserted against [`crate::scope`] rather than against a
    /// literal, so the listener cannot quietly go back to naming its own address —
    /// which is what made every two-node test raise a firewall dialog.
    #[tokio::test]
    async fn binds_without_a_relay() {
        let device = reachability(NatNetworkConfig::default());

        // Port 0 — the OS picks one, so the test cannot collide with anything.
        let listener = device
            .bind_peer_listener(0)
            .await
            .expect("binding needs no relay, no STUN, and no paired peers");

        let Address::Quic(addr) = listener.local_addr() else {
            panic!("the peer listener is QUIC");
        };
        assert_eq!(
            addr.ip(),
            std::net::IpAddr::V4(crate::scope::inbound_bind_ip()),
            "the peer listener binds the address this run's scope allows"
        );
    }

    /// The allowlist the TLS handshake admits from is the one the caller seeds —
    /// one set, not a copy, or "who may connect" and "who I announce to" drift.
    #[tokio::test]
    async fn the_allowlist_is_shared_not_copied() {
        let device = reachability(NatNetworkConfig::default());
        let peer = SigningKey::generate(&mut rand::rngs::OsRng)
            .verifying_key()
            .to_bytes();

        device.paired_keys().write().unwrap().insert(peer);

        assert!(
            device.paired_keys().read().unwrap().contains(&peer),
            "a second handle sees what the first one wrote"
        );
    }
}
