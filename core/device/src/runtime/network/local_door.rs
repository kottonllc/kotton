// SPDX-License-Identifier: AGPL-3.0-or-later
//! Keeping the local-network door: a listener and an announcement that exist only
//! while the person's answer says so.
//!
//! The answer and the clock are [`kotton_peer::local_door`]'s; what is here is the
//! device's part — holding the socket, the accept loop and the mDNS records, and
//! removing all three when the door shuts. It is the device's because the accept loop
//! is (`peer_listener.rs` says why), and a door that closed its state but kept its
//! socket would be the failure this exists to prevent.
//!
//! [`DeviceRuntime::reconcile_local_door`] takes the clock and the network as
//! arguments, so *closed at eleven minutes* is a test that calls it twice, and the
//! keeper task ([`DeviceRuntime::spawn_local_door_keeper`]) is a loop that calls it
//! with the real ones.

use crate::runtime::DeviceRuntime;
use kotton_peer::local_door::{
    lan_ip_here, network_here, DoorAnswer, DoorRefusal, LocalDoor, NetworkHere, RouterKey,
};
use kotton_net::transport::quic::knocked::{Knock, KnockFront, KnockedDoor};
use kotton_peer::local_network::{self, Announced, Beacon, LocalNetwork};
use kotton_peer::PeerHandler;
use kotton_sys::net::{Address, Listener};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

/// How often the keeper looks at which network the device is on, when nothing else
/// wakes it. With the door closed that look is two file reads and binds nothing
/// ([`network_here`]); a device carried from home to a café is closed within this long
/// of arriving.
const LOOK_EVERY: Duration = Duration::from_secs(5);

/// The door's live parts. Dropping the announcement withdraws it; closing the listener
/// and aborting its loop releases the port.
struct OpenDoor {
    listener: Arc<dyn Listener>,
    accept: tokio::task::JoinHandle<()>,
    addr: SocketAddr,
    /// The network it was opened on; a different one closes it.
    router: Option<RouterKey>,
    /// The day it was opened on. For an *Always* door a new day closes it and opens a
    /// fresh one — a new port under new names — so two recordings on two days share
    /// neither. A ten-minute door keeps its day until its timer ends.
    day: u64,
    announcement: Option<kotton_net::DoorAnnouncement>,
    /// How many paired devices the announcement was built for, so a new one rebuilds
    /// it rather than leaving it unannounced to.
    announced_for: usize,
    /// The contacts' side of the door, when it can have one here.
    contacts: Option<ContactFront>,
    /// Held for as long as this opening stands. Every [`LocalWay`] minted from it
    /// watches this, and dropping it — the first thing [`close`] does — ends them all.
    standing: tokio::sync::watch::Sender<()>,
}

/// The opening a [`LocalWay`] is minted from: the network it stands on, and the end
/// every way minted from it watches.
#[derive(Clone)]
struct Opening {
    router: Option<RouterKey>,
    shut: tokio::sync::watch::Receiver<()>,
}

/// The door as a person's contacts reach it, while it is open: one socket that drops every datagram whose knock it does not hold, the pair door
/// of each contact behind it — its one-key verifier and its one verb, as a relay
/// serves it — and one beacon naming the socket by a nonce drawn when it opened.
///
/// A contact is never checked here. Their knock reaches their pair's door and
/// nothing else, and that door admits their handle for the hour and nothing else;
/// nobody else's knock is held, so nobody else reaches a byte of it.
struct ContactFront {
    front: KnockFront,
    nonce: [u8; 16],
    /// The network the knocks are bound to; another one opens a new front.
    network: [u8; 32],
    doors: HashMap<Knock, (Arc<KnockedDoor>, tokio::task::JoinHandle<()>)>,
    /// Dropped with the front, which withdraws the beacon.
    _beacon: Announced,
}

/// The door's state, and its parts when it is open.
#[derive(Default)]
pub(crate) struct DoorKeeper {
    door: std::sync::Mutex<LocalDoor>,
    open: tokio::sync::Mutex<Option<OpenDoor>>,
    changed: tokio::sync::Notify,
    /// The keeper task, so shutdown can stop it before closing the door behind it.
    task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// The local network the door's beacon goes on and other doors are heard on.
    /// `None` is the real one, mDNS; a test hands two runtimes one [`Room`].
    ///
    /// [`Room`]: kotton_peer::local_network::Room
    network: std::sync::RwLock<Option<Arc<dyn LocalNetwork>>>,
    /// The opening that stands now, if any — what [`LocalWay`]s are minted from.
    opening: std::sync::Mutex<Option<Opening>>,
}

/// A way to a contact's door on the local network, and the only one: minted by
/// [`DeviceRuntime::local_way_here`] from the door's opening while it stands, and
/// ending when that opening shuts — a value, not a string, so the local network
/// is checked once.
///
/// Finding a contact's door and being findable are one capability, so the way is the
/// door's and not a name for it: nothing outside this module can make one, and one
/// made while the door was open dials nothing once it has shut — [`Self::hand_over`]
/// asks the way, never the door.
///
/// Its `Debug` prints nothing. The network key is derived from the router, so two
/// logged ways would say where a device was on two days.
#[derive(Clone)]
pub struct LocalWay {
    network: [u8; 32],
    bind_ip: IpAddr,
    /// Ends when the opening this way was minted from shuts.
    shut: tokio::sync::watch::Receiver<()>,
    /// Where the door's beacon goes, and so where a contact's door is heard.
    heard_on: Arc<dyn LocalNetwork>,
}

impl std::fmt::Debug for LocalWay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LocalWay(..)")
    }
}

impl LocalWay {
    /// Whether the opening this way was minted from has shut.
    pub fn has_shut(&self) -> bool {
        self.shut.has_changed().is_err()
    }

    /// Resolves once the opening has shut — at once if it already has.
    async fn shut(&self) {
        let mut shut = self.shut.clone();
        while shut.changed().await.is_ok() {}
    }

    /// Listen on the local network for `within`, and hand `request` to
    /// `contact_pub`'s door if one heard is theirs
    /// ([`kotton_peer::contact_delivery::deliver_here`]).
    ///
    /// Cut when the door shuts: a way whose opening has already shut neither looks
    /// nor dials, and one that shuts mid-dial abandons it. A look already started
    /// runs out its `within` on its blocking thread, which cannot be interrupted, and
    /// nothing it hears is dialled.
    pub async fn hand_over(
        &self,
        within: Duration,
        own_identity: &ed25519_dalek::SigningKey,
        contact_pub: &[u8; 32],
        request: &kotton_wire::ipc::ContactRequest,
    ) -> anyhow::Result<kotton_wire::ipc::ContactResponse> {
        let dial = async {
            let heard_on = Arc::clone(&self.heard_on);
            let heard = tokio::task::spawn_blocking(move || heard_on.look(within))
                .await
                .unwrap_or_default();
            kotton_peer::contact_delivery::deliver_here(
                &heard,
                &self.network,
                self.bind_ip,
                own_identity,
                contact_pub,
                request,
            )
            .await
        };
        tokio::select! {
            biased;
            () = self.shut() => anyhow::bail!("this device's door has shut"),
            answer = dial => answer,
        }
    }
}

/// What the row *Open to your devices here* draws, and what a test reads back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoorReading {
    /// The one lit answer on this network.
    pub answer: DoorAnswer,
    /// Time left on *10 minutes*, when it is running here.
    pub remaining: Option<Duration>,
    /// Where the door's listener is bound, when one exists. `None` is the property:
    /// no socket.
    pub listening: Option<SocketAddr>,
    /// How many names are being announced. Zero when the door is closed.
    pub announced: usize,
    /// How many contact pair doors stand behind the contacts' front — one per
    /// contact per live hour. Zero when the door is closed.
    pub contact_doors: usize,
    /// Whether this device can tell which network it is on — whether *Always* is
    /// available here.
    pub network_known: bool,
}

impl DeviceRuntime {
    /// Take the person's answer for the network the device is on (`here`), and wake
    /// the keeper so the socket follows at once.
    pub fn choose_local_door(
        &self,
        answer: DoorAnswer,
        here: NetworkHere,
    ) -> Result<(), DoorRefusal> {
        self.local_door
            .door
            .lock()
            .unwrap()
            .choose(answer, Instant::now(), here.router)?;
        self.local_door.changed.notify_one();
        Ok(())
    }

    /// The network *Always* is kept for, for the daemon to persist after a choice.
    pub fn local_door_always_router(&self) -> Option<RouterKey> {
        self.local_door.door.lock().unwrap().always_router()
    }

    /// Put back the one thing the door persists — the network *Always* is kept for —
    /// as read from `device_config` at boot. The timer is never restored.
    pub fn restore_local_door(&self, always_on: Option<RouterKey>) {
        *self.local_door.door.lock().unwrap() = LocalDoor::always_on(always_on);
        self.local_door.changed.notify_one();
    }

    /// Read the door at `now` on `here`.
    pub async fn local_door_reading(&self, now: Instant, here: NetworkHere) -> DoorReading {
        let (answer, remaining) = {
            let door = self.local_door.door.lock().unwrap();
            let state = door.state(now, here.router);
            let remaining = match state {
                kotton_peer::local_door::DoorState::OpenFor { remaining } => Some(remaining),
                _ => None,
            };
            (door.answer(now, here.router), remaining)
        };
        let open = self.local_door.open.lock().await;
        DoorReading {
            answer,
            remaining,
            listening: open.as_ref().map(|o| o.addr),
            announced: open
                .as_ref()
                .and_then(|o| o.announcement.as_ref())
                .map_or(0, |a| a.names().len()),
            contact_doors: open
                .as_ref()
                .and_then(|o| o.contacts.as_ref())
                .map_or(0, |c| c.doors.len()),
            network_known: here.router.is_some(),
        }
    }

    /// Make the socket and the announcement match the door at `now`, on `day`, on
    /// `here`: open them when it is open and they are not, close them when it is closed,
    /// when the device is on a different network from the one they were opened on, or,
    /// for an *Always* door, when the day has turned — which reopens it at once on a
    /// fresh port under the new day's names.
    ///
    /// `handler` serves what an admitted device asks through the door — the same
    /// handler the peer listener serves.
    pub async fn reconcile_local_door(
        self: &Arc<Self>,
        now: Instant,
        day: u64,
        here: NetworkHere,
        handler: PeerHandler,
    ) -> DoorReading {
        let state = self.local_door.door.lock().unwrap().state(now, here.router);
        let should_open = state.is_open();
        // A new day renews only a standing door. A ten-minute one that spans midnight
        // keeps its port and names until its timer ends, minutes later, rather than
        // dropping the sessions through it partway.
        let standing = matches!(state, kotton_peer::local_door::DoorState::AlwaysHere);
        {
            let mut open = self.local_door.open.lock().await;
            let moved = open
                .as_ref()
                .is_some_and(|o| o.router != here.router || (standing && o.day != day));
            if (!should_open || moved) && open.is_some() {
                close(open.take().expect("checked is_some")).await;
            }
            if should_open && open.is_none() {
                match self.open_local_door(here, day, handler).await {
                    Ok(door) => {
                        *self.local_door.opening.lock().unwrap() =
                            Some(Opening { router: door.router, shut: door.standing.subscribe() });
                        *open = Some(door);
                    }
                    Err(e) => tracing::warn!(error = %e, "the local door could not open"),
                }
            }
            if let Some(door) = open.as_mut() {
                self.refresh_announcement(door, here);
                self.refresh_contact_front(door, here).await;
            }
        }
        self.local_door_reading(now, here).await
    }

    /// Run the keeper: reconcile now, then whenever the answer changes, the timer runs
    /// out, or [`LOOK_EVERY`] passes. Started once at boot; it holds nothing open until
    /// the person opens the door, and [`Self::close_local_door`] stops it.
    ///
    /// The device's address is asked for ([`lan_ip_here`], which binds a socket for the
    /// length of the call) only when the door is open and will announce — a closed
    /// door's look binds nothing, and neither does a `KOTTON_PAIR_LOCAL_ONLY` run's.
    pub fn spawn_local_door_keeper(self: &Arc<Self>, handler: PeerHandler) {
        let this = Arc::clone(self);
        let handle = tokio::spawn(async move {
            loop {
                let now = Instant::now();
                let mut here = network_here();
                // Only an open door that will announce needs the address, and asking
                // binds a socket: a closed door, or a run that promised to stay on this
                // machine (which announces nothing), does not ask.
                if !kotton_peer::local_only()
                    && this.local_door.door.lock().unwrap().state(now, here.router).is_open()
                {
                    here.lan_ip = lan_ip_here();
                }
                let day = kotton_crypto::door_day(kotton_peer::rendezvous::unix_now());
                this.reconcile_local_door(now, day, here, handler.clone()).await;
                let wait = this
                    .local_door
                    .door
                    .lock()
                    .unwrap()
                    .next_change(now)
                    .map_or(LOOK_EVERY, |at| (at - now).min(LOOK_EVERY));
                tokio::select! {
                    _ = this.local_door.changed.notified() => {}
                    _ = tokio::time::sleep(wait) => {}
                }
            }
        });
        if let Some(old) = self.local_door.task.lock().unwrap().replace(handle) {
            old.abort();
        }
    }

    /// Stop the keeper and shut the door: the runtime's shutdown calls this, so an open
    /// door never outlives the device that opened it. The answer is left as it was —
    /// *Always* is restored at the next boot from `device_config`, and the timer, which
    /// is never restored, is gone with the process.
    pub async fn close_local_door(&self) {
        let task = self.local_door.task.lock().unwrap().take();
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
        if let Some(door) = self.local_door.open.lock().await.take() {
            close(door).await;
        }
    }

    async fn open_local_door(
        self: &Arc<Self>,
        here: NetworkHere,
        day: u64,
        handler: PeerHandler,
    ) -> anyhow::Result<OpenDoor> {
        let listener: Arc<dyn Listener> =
            Arc::from(self.reachability.bind_door_listener().await?);
        let addr = match listener.local_addr() {
            Address::Quic(a) => *a,
            other => anyhow::bail!("the door bound something that is not QUIC: {other:?}"),
        };
        let accept = self.spawn_accept_loop(
            Arc::clone(&listener),
            format!("local door ({addr})"),
            handler,
        );
        Ok(OpenDoor {
            listener,
            accept,
            addr,
            router: here.router,
            day,
            announcement: None,
            announced_for: usize::MAX,
            contacts: None,
            standing: tokio::sync::watch::channel(()).0,
        })
    }

    /// Use `network` for the door's beacon and for hearing other doors, in place of
    /// mDNS — for two runtimes in one test process, which share one machine.
    pub fn use_local_network(&self, network: Arc<dyn LocalNetwork>) {
        *self.local_door.network.write().unwrap() = Some(network);
    }

    fn local_network(&self) -> Arc<dyn LocalNetwork> {
        self.local_door
            .network
            .read()
            .unwrap()
            .clone()
            .unwrap_or_else(|| Arc::new(local_network::Mdns))
    }

    /// A way to look for a contact's door where this device is now: only while its
    /// own door is open and standing on this network — finding and being findable are
    /// one capability, as the door's record has it — and only on a network a knock can
    /// be bound to. The way ends when that opening shuts ([`LocalWay`]).
    pub fn local_way_here(&self) -> Option<LocalWay> {
        self.local_way_at(Instant::now(), network_here(), kotton_peer::local_only(), || {
            kotton_peer::introduction::introduced_bind_ip()
        })
    }

    /// [`Self::local_way_here`] at `now` on `here`. `bind_ip` is asked only when the
    /// door is open, because finding the address binds a socket.
    fn local_way_at(
        &self,
        now: Instant,
        here: NetworkHere,
        local_only: bool,
        bind_ip: impl FnOnce() -> Option<IpAddr>,
    ) -> Option<LocalWay> {
        if !self.local_door.door.lock().unwrap().state(now, here.router).is_open() {
            return None;
        }
        let opening = self.local_door.opening.lock().unwrap().clone()?;
        if opening.router != here.router || opening.shut.has_changed().is_err() {
            return None;
        }
        let network = local_network::knock_network(here.router, local_only)?;
        Some(LocalWay {
            network,
            bind_ip: bind_ip()?,
            shut: opening.shut,
            heard_on: self.local_network(),
        })
    }

    /// Stand the contacts' side of an open door up, or bring it level with the
    /// contacts this device answers for and the hour: a pair door for each contact
    /// for this hour and the last — the same slack a relay reservation keeps — each
    /// behind the knock that pair derives from this opening's nonce.
    ///
    /// No front on a network a knock cannot be bound to, or with no address to
    /// announce: a door nobody can find is a socket for nothing.
    async fn refresh_contact_front(self: &Arc<Self>, door: &mut OpenDoor, here: NetworkHere) {
        let local_only = kotton_peer::local_only();
        let network = local_network::knock_network(here.router, local_only);
        let ip = if local_only { Some(IpAddr::V4(Ipv4Addr::LOCALHOST)) } else { here.lan_ip.map(IpAddr::V4) };
        let (Some(network), Some(ip)) = (network, ip) else {
            if let Some(front) = door.contacts.take() {
                shut_contact_front(front).await;
            }
            return;
        };
        if door.contacts.as_ref().is_some_and(|c| c.network != network) {
            shut_contact_front(door.contacts.take().expect("checked is_some")).await;
        }
        if door.contacts.is_none() {
            match self.open_contact_front(network, ip) {
                Ok(front) => door.contacts = Some(front),
                Err(e) => {
                    tracing::warn!(error = %e, "the local door is open but not to contacts");
                    return;
                }
            }
        }
        let front = door.contacts.as_mut().expect("opened above");

        let epoch = kotton_crypto::epoch_at(kotton_peer::rendezvous::unix_now());
        let mut wanted: HashMap<Knock, (ed25519_dalek::SigningKey, [u8; 32], PeerHandler)> =
            HashMap::new();
        for inbox in self.reachability.dm_inboxes().read().unwrap().iter() {
            for e in [Some(epoch), epoch.checked_sub(1)].into_iter().flatten() {
                let keys = kotton_peer::rendezvous::dm_door(&inbox.own_identity, &inbox.contact_pub, e);
                let knock = kotton_crypto::contact_knock_to_open(
                    &inbox.own_identity,
                    &inbox.contact_pub,
                    &front.nonce,
                    e,
                    &front.network,
                );
                match (keys, knock) {
                    (Ok(keys), Ok(knock)) => {
                        wanted.insert(knock, (keys.handle.signing_key, keys.admit, inbox.handler.clone()));
                    }
                    _ => tracing::warn!("a contact's door could not be derived"),
                }
            }
        }
        let gone: Vec<Knock> = front.doors.keys().filter(|k| !wanted.contains_key(*k)).copied().collect();
        for knock in gone {
            front.front.shut_door(&knock);
            if let Some((pair_door, accept)) = front.doors.remove(&knock) {
                shut_pair_door(pair_door, accept).await;
            }
        }
        for (knock, (cert_key, admit, handler)) in wanted {
            if front.doors.contains_key(&knock) {
                continue;
            }
            match front.front.open_door(knock, &cert_key, admit) {
                Ok(pair_door) => {
                    let pair_door = Arc::new(pair_door);
                    let accept = self.spawn_accept_loop(
                        Arc::clone(&pair_door) as Arc<dyn Listener>,
                        "a contact's door on the local network".to_owned(),
                        handler,
                    );
                    front.doors.insert(knock, (pair_door, accept));
                }
                Err(e) => tracing::warn!(error = %e, "a contact's door could not open"),
            }
        }
    }

    fn open_contact_front(&self, network: [u8; 32], ip: IpAddr) -> anyhow::Result<ContactFront> {
        let front = KnockFront::bind(SocketAddr::from((kotton_peer::scope::inbound_bind_ip(), 0)))?;
        let (nonce, name) = local_network::door_nonce();
        let beacon = self
            .local_network()
            .announce(Beacon { name, addr: SocketAddr::new(ip, front.local_addr().port()) })?;
        tracing::info!(port = front.local_addr().port(), "local-network door open to contacts");
        Ok(ContactFront { front, nonce, network, doors: HashMap::new(), _beacon: beacon })
    }

    /// Announce the open door under the names for its network and its day, or rebuild
    /// the announcement when the set of paired devices has changed since it was made.
    ///
    /// Nothing is announced on a run that promised to stay on this machine
    /// ([`kotton_peer::local_only`]) or when the device has no address on the router's
    /// interface to announce. With no readable router the names are keyed to a fresh
    /// random value, which links nothing and which no device recognises yet — the
    /// honest cost of not knowing the network, stated in the record's Next.
    fn refresh_announcement(&self, door: &mut OpenDoor, here: NetworkHere) {
        if kotton_peer::local_only() {
            return;
        }
        let Some(ip) = here.lan_ip else {
            door.announcement = None;
            return;
        };
        let day = door.day;
        let paired = self.reachability.paired_keys().read().unwrap().len();
        if door.announcement.is_some() && door.announced_for == paired {
            return;
        }
        let router: [u8; 32] = match here.router {
            Some(r) => *r.as_bytes(),
            None => {
                let mut nonce = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
                nonce
            }
        };
        let names = self.reachability.door_names(&router, day);
        // The old records go before the new ones arrive.
        door.announcement = None;
        door.announced_for = paired;
        if names.is_empty() {
            return;
        }
        match kotton_net::announce_door(&names, ip, door.addr.port()) {
            Ok(a) => door.announcement = Some(a),
            Err(e) => tracing::warn!(error = %e, "the local door is open but not announced"),
        }
    }
}

/// Shut an open door: withdraw the announcement, stop the loop, close the endpoint.
/// Awaited to the end, so when this returns the port is released — the loop's handle
/// on the listener is gone and the endpoint has closed every connection through it.
async fn close(door: OpenDoor) {
    let OpenDoor { listener, accept, addr, announcement, contacts, standing, .. } = door;
    // First, so no way minted from this opening starts a dial while the rest shuts.
    drop(standing);
    drop(announcement);
    if let Some(front) = contacts {
        shut_contact_front(front).await;
    }
    accept.abort();
    let _ = accept.await;
    let _ = listener.close().await;
    drop(listener);
    tracing::info!(%addr, "local-network door closed");
}

/// Shut the contacts' side of the door: every pair door behind it closed, the
/// beacon withdrawn, and the socket released.
async fn shut_contact_front(front: ContactFront) {
    let ContactFront { front, doors, _beacon, .. } = front;
    drop(_beacon);
    for (knock, (pair_door, accept)) in doors {
        front.shut_door(&knock);
        shut_pair_door(pair_door, accept).await;
    }
    drop(front);
}

async fn shut_pair_door(pair_door: Arc<KnockedDoor>, accept: tokio::task::JoinHandle<()>) {
    accept.abort();
    let _ = accept.await;
    let _ = pair_door.close().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RuntimeConfig;

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

    /// A day, as `door_day` counts them.
    const DAY: u64 = 20_000;

    fn handler() -> PeerHandler {
        kotton_peer::door::PeerDoor::<(), ()>::serving(|_, ()| async {}, |_| ())
    }

    /// A network this device can name, with no address to announce on — so the tests
    /// hold the socket and never open a multicast one.
    fn at(mac_tail: u8) -> NetworkHere {
        NetworkHere {
            router: Some(RouterKey::of_gateway_mac([0x3c, 0x22, 0xfb, 0, 0, mac_tail])),
            lan_ip: None,
        }
    }

    /// The port is held: nothing else can bind exactly where the door is.
    fn held(addr: SocketAddr) -> bool {
        std::net::UdpSocket::bind(addr).is_err()
    }

    /// The port is released: something else can bind exactly where the door was,
    /// within a second of the door closing. The endpoint's driver task owns the socket
    /// and drops it the next time it runs after the last handle goes, so the release
    /// is a moment after `close` returns, not at it.
    async fn released(addr: SocketAddr) -> bool {
        for _ in 0..50 {
            if std::net::UdpSocket::bind(addr).is_ok() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }

    /// A fresh device holds no door socket, on any network, however often the keeper
    /// looks.
    #[tokio::test]
    async fn a_fresh_device_opens_no_door() {
        let temp = tempfile::tempdir().unwrap();
        let rt = runtime(&temp).await;
        for here in [at(1), at(2), NetworkHere::default()] {
            let r = rt.reconcile_local_door(Instant::now(), DAY, here, handler()).await;
            assert_eq!(r.answer, DoorAnswer::Closed);
            assert_eq!(r.listening, None, "no socket on a fresh device");
            assert_eq!(r.announced, 0);
        }
    }

    /// *10 minutes* binds a socket at once and releases it by eleven: the reading says
    /// closed and the port can be bound by anyone else.
    #[tokio::test]
    async fn the_door_is_closed_and_its_port_released_at_eleven_minutes() {
        let temp = tempfile::tempdir().unwrap();
        let rt = runtime(&temp).await;
        let cafe = at(9);

        rt.choose_local_door(DoorAnswer::TenMinutes, cafe).unwrap();
        let t0 = Instant::now();
        let open = rt.reconcile_local_door(t0, DAY, cafe, handler()).await;
        assert_eq!(open.answer, DoorAnswer::TenMinutes);
        let addr = open.listening.expect("the door is open for ten minutes");
        assert!(open.remaining.is_some_and(|r| r <= Duration::from_secs(600)));
        assert!(held(addr), "the door holds its port while open");

        let nine = rt.reconcile_local_door(t0 + Duration::from_secs(9 * 60), DAY, cafe, handler()).await;
        assert_eq!(nine.listening, Some(addr), "still the same door at nine minutes");

        let eleven =
            rt.reconcile_local_door(t0 + Duration::from_secs(11 * 60), DAY, cafe, handler()).await;
        assert_eq!(eleven.answer, DoorAnswer::Closed);
        assert_eq!(eleven.listening, None);
        assert!(released(addr).await, "the door's port is free at eleven minutes");
    }

    /// Carried to another network, an open door is closed there, and *Always* opens
    /// only on the network it was chosen on.
    #[tokio::test]
    async fn an_open_door_closes_when_the_device_changes_network() {
        let temp = tempfile::tempdir().unwrap();
        let rt = runtime(&temp).await;
        let (home, cafe) = (at(1), at(9));

        rt.choose_local_door(DoorAnswer::Always, home).unwrap();
        let now = Instant::now();
        let at_home = rt.reconcile_local_door(now, DAY, home, handler()).await;
        let addr = at_home.listening.expect("open at home");
        assert_eq!(at_home.answer, DoorAnswer::Always);
        assert_eq!(rt.local_door_always_router(), home.router);

        let at_cafe = rt.reconcile_local_door(now, DAY, cafe, handler()).await;
        assert_eq!(at_cafe.answer, DoorAnswer::Closed);
        assert_eq!(at_cafe.listening, None);
        assert!(released(addr).await);

        assert!(rt.reconcile_local_door(now, DAY, home, handler()).await.listening.is_some());
    }

    /// *Always* on a network this device cannot name is refused, and nothing opens.
    #[tokio::test]
    async fn always_needs_a_router() {
        let temp = tempfile::tempdir().unwrap();
        let rt = runtime(&temp).await;
        let nowhere = NetworkHere::default();
        assert_eq!(
            rt.choose_local_door(DoorAnswer::Always, nowhere),
            Err(DoorRefusal::NoRouterHere)
        );
        let r = rt.reconcile_local_door(Instant::now(), DAY, nowhere, handler()).await;
        assert_eq!((r.listening, r.network_known), (None, false));
    }

    /// *Always* is not one door for ever: at the day's turn the keeper closes it and
    /// opens a fresh one on a new port, so two recordings of it on two days share no
    /// port (and, by `door_announce_name`, no name).
    #[tokio::test]
    async fn an_always_door_reopens_on_a_fresh_port_each_day() {
        let temp = tempfile::tempdir().unwrap();
        let rt = runtime(&temp).await;
        let home = at(1);
        rt.choose_local_door(DoorAnswer::Always, home).unwrap();
        let now = Instant::now();
        let monday = rt.reconcile_local_door(now, DAY, home, handler()).await;
        let a = monday.listening.expect("open on monday");
        let again = rt.reconcile_local_door(now, DAY, home, handler()).await;
        assert_eq!(again.listening, Some(a), "the same day keeps the same door");
        let tuesday = rt.reconcile_local_door(now, DAY + 1, home, handler()).await;
        let b = tuesday.listening.expect("open on tuesday");
        assert_eq!(tuesday.answer, DoorAnswer::Always);
        assert_ne!(a.port(), b.port(), "a new day is a new port");
        assert!(released(a).await, "monday's port is let go");
    }

    /// Shutdown shuts the door: an open door's port is released and the keeper stops.
    #[tokio::test]
    async fn shutting_down_the_runtime_shuts_an_open_door() {
        let temp = tempfile::tempdir().unwrap();
        let rt = runtime(&temp).await;
        rt.start().await.unwrap();
        let cafe = at(9);
        rt.choose_local_door(DoorAnswer::TenMinutes, cafe).unwrap();
        rt.spawn_local_door_keeper(handler());
        let addr = rt
            .reconcile_local_door(Instant::now(), DAY, cafe, handler())
            .await
            .listening
            .expect("open");
        rt.shutdown().await.unwrap();
        assert_eq!(rt.local_door_reading(Instant::now(), cafe).await.listening, None);
        assert!(released(addr).await, "the door's port is free after shutdown");
        assert!(rt.local_door.task.lock().unwrap().is_none(), "the keeper is stopped");
    }

    /// *Always* survives a restart: what the daemon persists
    /// (`local_door_always_router`, as hex) and restores (`restore_local_door`) opens
    /// the door on the same network in a new runtime, and on no other.
    #[tokio::test]
    async fn always_survives_a_restart_and_the_timer_does_not() {
        let (home, cafe) = (at(1), at(9));
        let stored = {
            let temp = tempfile::tempdir().unwrap();
            let rt = runtime(&temp).await;
            rt.choose_local_door(DoorAnswer::Always, home).unwrap();
            rt.choose_local_door(DoorAnswer::TenMinutes, cafe).unwrap();
            rt.local_door_always_router().map(RouterKey::to_hex)
        };
        let temp = tempfile::tempdir().unwrap();
        let rt = runtime(&temp).await;
        rt.restore_local_door(stored.as_deref().and_then(RouterKey::from_hex));
        let now = Instant::now();
        assert!(rt.reconcile_local_door(now, DAY, home, handler()).await.listening.is_some());
        let r = rt.reconcile_local_door(now, DAY, cafe, handler()).await;
        assert_eq!((r.answer, r.listening), (DoorAnswer::Closed, None), "the timer is not restored");
    }

    // --- The contacts' side: a contact's message reaches the device over the local network while its door is open

    fn identity(n: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[n; 32])
    }

    /// A network this device can name, with loopback as its address on it, so a
    /// beacon names somewhere a test can dial.
    fn room_at(mac_tail: u8) -> NetworkHere {
        NetworkHere { lan_ip: Some(Ipv4Addr::LOCALHOST), ..at(mac_tail) }
    }

    /// Alice's runtime, in `room`, answering Bob's messages with a door that says
    /// what it took.
    async fn alice_in(room: &kotton_peer::local_network::Room, temp: &tempfile::TempDir) -> Arc<DeviceRuntime> {
        let rt = runtime(temp).await;
        rt.use_local_network(Arc::new(room.clone()));
        let door = kotton_peer::contact_door::contact_door(|request| async move {
            kotton_wire::ipc::ContactResponse::Refused { reason: format!("took {}", request.sealed().body) }
        });
        rt.reachability().dm_inboxes().write().unwrap().push(kotton_peer::reachability::DmInbox {
            own_identity: identity(1),
            contact_pub: identity(2).verifying_key().to_bytes(),
            handler: door,
        });
        rt
    }

    /// Bob hands Alice a message over whatever he hears in `room`, on `here`.
    async fn bob_sends(
        room: &kotton_peer::local_network::Room,
        here: NetworkHere,
        body: &str,
    ) -> anyhow::Result<kotton_wire::ipc::ContactResponse> {
        let request = kotton_wire::ipc::ContactRequest::DeliverMessage {
            sealed: kotton_wire::ipc::SealedDm {
                ephemeral_pub: String::new(),
                nonce: String::new(),
                body: body.to_owned(),
            },
        };
        kotton_peer::contact_delivery::deliver_here(
            &room.heard(),
            &local_network::knock_network(here.router, false).unwrap(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &identity(2),
            &identity(1).verifying_key().to_bytes(),
            &request,
        )
        .await
    }

    /// The door end to end: while Alice's door is open, Bob — a contact, on the
    /// same network — finds it and hands a message to her contact door there; when
    /// it closes, nothing answers him and nothing is announced.
    #[tokio::test]
    async fn a_contact_reaches_an_open_door_and_nothing_once_it_closes() {
        let temp = tempfile::tempdir().unwrap();
        let room = kotton_peer::local_network::Room::new();
        let rt = alice_in(&room, &temp).await;
        let cafe = room_at(9);

        let closed = rt.reconcile_local_door(Instant::now(), DAY, cafe, handler()).await;
        assert_eq!((closed.contact_doors, room.heard().len()), (0, 0), "closed: no door, no beacon");
        assert!(bob_sends(&room, cafe, "early").await.is_err(), "a closed door answered");

        rt.choose_local_door(DoorAnswer::TenMinutes, cafe).unwrap();
        let t0 = Instant::now();
        let open = rt.reconcile_local_door(t0, DAY, cafe, handler()).await;
        assert_eq!(open.contact_doors, 2, "Bob's pair door for this hour and the last");
        let heard = room.heard();
        assert_eq!(heard.len(), 1, "one beacon, whatever the number of contacts");
        let answer = bob_sends(&room, cafe, "hello").await.expect("bob reaches alice's door");
        assert!(
            matches!(&answer, kotton_wire::ipc::ContactResponse::Refused { reason } if reason == "took hello"),
            "{answer:?}"
        );

        let eleven = rt.reconcile_local_door(t0 + Duration::from_secs(11 * 60), DAY, cafe, handler()).await;
        assert_eq!(eleven.contact_doors, 0);
        assert!(room.heard().is_empty(), "the beacon is withdrawn with the door");
        assert!(released(heard[0].addr).await, "the contacts' socket is released");
        let late = kotton_peer::contact_delivery::deliver_here(
            &heard,
            &local_network::knock_network(cafe.router, false).unwrap(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &identity(2),
            &identity(1).verifying_key().to_bytes(),
            &kotton_wire::ipc::ContactRequest::DeliverMessage {
                sealed: kotton_wire::ipc::SealedDm { ephemeral_pub: String::new(), nonce: String::new(), body: "late".into() },
            },
        )
        .await;
        assert!(late.is_err(), "the old beacon still reached a door: {late:?}");
    }

    /// Only a contact the door holds keys for gets in: a third person hearing the
    /// same beacon derives no knock the door holds, and a contact on another
    /// network — whose knock is bound to that network — derives none either.
    #[tokio::test]
    async fn a_stranger_and_another_network_find_no_door() {
        let temp = tempfile::tempdir().unwrap();
        let room = kotton_peer::local_network::Room::new();
        let rt = alice_in(&room, &temp).await;
        let cafe = room_at(9);
        rt.choose_local_door(DoorAnswer::TenMinutes, cafe).unwrap();
        rt.reconcile_local_door(Instant::now(), DAY, cafe, handler()).await;

        let request = kotton_wire::ipc::ContactRequest::DeliverMessage {
            sealed: kotton_wire::ipc::SealedDm { ephemeral_pub: String::new(), nonce: String::new(), body: "x".into() },
        };
        let carol = kotton_peer::contact_delivery::deliver_here(
            &room.heard(),
            &local_network::knock_network(cafe.router, false).unwrap(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &identity(3),
            &identity(1).verifying_key().to_bytes(),
            &request,
        )
        .await;
        assert!(carol.is_err(), "a stranger reached a contact's door: {carol:?}");
        assert!(bob_sends(&room, room_at(1), "elsewhere").await.is_err(), "a knock for another network opened the door");
        assert!(bob_sends(&room, cafe, "here").await.is_ok());
    }

    /// A contact's door answers every message of the hour, not the first: Bob hands
    /// two, one after the other, to the same open door, and both are taken.
    #[tokio::test]
    async fn a_contact_hands_two_messages_to_one_open_door() {
        let temp = tempfile::tempdir().unwrap();
        let room = kotton_peer::local_network::Room::new();
        let rt = alice_in(&room, &temp).await;
        let cafe = room_at(9);
        rt.choose_local_door(DoorAnswer::TenMinutes, cafe).unwrap();
        rt.reconcile_local_door(Instant::now(), DAY, cafe, handler()).await;

        for body in ["hello", "again"] {
            let answer = bob_sends(&room, cafe, body).await;
            assert!(
                matches!(&answer, Ok(kotton_wire::ipc::ContactResponse::Refused { reason }) if *reason == format!("took {body}")),
                "{body}: {answer:?}"
            );
        }
    }

    /// Finding a contact's door and being findable are one capability: with this
    /// device's own door closed it does not look — its address is not even asked —
    /// and while open it looks only on a network a knock can be bound to.
    #[tokio::test]
    async fn a_closed_door_does_not_look_for_a_contacts_door() {
        let temp = tempfile::tempdir().unwrap();
        let rt = runtime(&temp).await;
        let cafe = at(9);
        let lo = || Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let now = Instant::now();
        let asked = std::cell::Cell::new(false);
        let way = rt.local_way_at(now, cafe, false, || {
            asked.set(true);
            lo()
        });
        assert!(way.is_none(), "a closed door looked");
        assert!(!asked.get(), "a closed door asked for its address");

        rt.choose_local_door(DoorAnswer::TenMinutes, cafe).unwrap();
        assert!(rt.local_way_at(now, cafe, false, lo).is_none(), "a way before the door stands");
        rt.reconcile_local_door(now, DAY, cafe, handler()).await;
        let way = rt.local_way_at(now, cafe, false, lo).expect("an open door looks");
        assert_eq!(way.network, *cafe.router.unwrap().as_bytes());
        assert_eq!(format!("{way:?}"), "LocalWay(..)", "a way's Debug names no network");
        assert!(rt.local_way_at(now, NetworkHere::default(), false, lo).is_none(), "no network to bind a knock to");
        assert!(rt.local_way_at(now, at(1), false, lo).is_none(), "a way on a network the door is not open on");
        assert!(rt.local_way_at(now + Duration::from_secs(11 * 60), cafe, false, lo).is_none(), "the timer ran out");
    }

    /// A [`Room`] that counts how often it is looked in.
    ///
    /// [`Room`]: kotton_peer::local_network::Room
    #[derive(Clone)]
    struct Counted(kotton_peer::local_network::Room, Arc<std::sync::atomic::AtomicUsize>);

    impl LocalNetwork for Counted {
        fn announce(&self, beacon: Beacon) -> anyhow::Result<Announced> {
            self.0.announce(beacon)
        }
        fn look(&self, within: Duration) -> Vec<Beacon> {
            self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.0.look(within)
        }
    }

    /// A way made while Bob's door was open dials nothing on the local network once
    /// that door has shut — it does not look, and nothing reaches Alice, whose door is
    /// still open — and reopening Bob's door does not revive it: only a way minted
    /// from the new opening reaches her.
    #[tokio::test]
    async fn a_way_made_while_the_door_was_open_dials_nothing_once_it_has_shut() {
        use std::sync::atomic::Ordering::SeqCst;
        let room = kotton_peer::local_network::Room::new();
        let cafe = room_at(9);
        let (a_temp, b_temp) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let alice = alice_in(&room, &a_temp).await;
        alice.choose_local_door(DoorAnswer::Always, cafe).unwrap();
        alice.reconcile_local_door(Instant::now(), DAY, cafe, handler()).await;

        let looks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let bob = runtime(&b_temp).await;
        bob.use_local_network(Arc::new(Counted(room.clone(), Arc::clone(&looks))));
        bob.choose_local_door(DoorAnswer::TenMinutes, cafe).unwrap();
        let t0 = Instant::now();
        bob.reconcile_local_door(t0, DAY, cafe, handler()).await;
        let lo = || Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let made_open = bob.local_way_at(t0, cafe, false, lo).expect("bob's door is open");
        assert!(!made_open.has_shut());

        bob.reconcile_local_door(t0 + Duration::from_secs(11 * 60), DAY, cafe, handler()).await;
        assert!(made_open.has_shut(), "the way outlived bob's door");
        let send = |body: &str| kotton_wire::ipc::ContactRequest::DeliverMessage {
            sealed: kotton_wire::ipc::SealedDm { ephemeral_pub: String::new(), nonce: String::new(), body: body.into() },
        };
        let alice_pub = identity(1).verifying_key().to_bytes();
        let late = made_open.hand_over(Duration::ZERO, &identity(2), &alice_pub, &send("shut")).await;
        assert!(late.is_err(), "a way reached a door after its own had shut: {late:?}");
        assert_eq!(looks.load(SeqCst), 0, "a shut way looked");
        assert_eq!(room.heard().len(), 1, "alice's door is still there to be reached");

        bob.choose_local_door(DoorAnswer::TenMinutes, cafe).unwrap();
        let t1 = Instant::now();
        bob.reconcile_local_door(t1, DAY, cafe, handler()).await;
        assert!(made_open.has_shut(), "a new opening revived an old way");
        let reopened = bob.local_way_at(t1, cafe, false, lo).expect("bob's door is open again");
        let answer = reopened
            .hand_over(Duration::ZERO, &identity(2), &alice_pub, &send("open"))
            .await
            .expect("a way from the open door reaches alice");
        assert!(
            matches!(&answer, kotton_wire::ipc::ContactResponse::Refused { reason } if reason == "took open"),
            "{answer:?}"
        );
        assert_eq!(looks.load(SeqCst), 1, "the open way looked once");
    }

    /// An *Always* door is one opening per day, not one for as long as it stays open:
    /// at the day's turn the keeper closes it and opens a fresh one, so the
    /// contacts' beacon takes a new nonce and a new port, and Monday's is withdrawn.
    #[tokio::test]
    async fn an_always_door_draws_a_new_beacon_each_day() {
        let temp = tempfile::tempdir().unwrap();
        let room = kotton_peer::local_network::Room::new();
        let rt = alice_in(&room, &temp).await;
        let home = room_at(1);
        rt.choose_local_door(DoorAnswer::Always, home).unwrap();
        let now = Instant::now();
        rt.reconcile_local_door(now, DAY, home, handler()).await;
        let monday = room.heard();
        rt.reconcile_local_door(now, DAY, home, handler()).await;
        assert_eq!(room.heard(), monday, "the same day keeps the same beacon");
        rt.reconcile_local_door(now, DAY + 1, home, handler()).await;
        let tuesday = room.heard();
        assert_eq!((monday.len(), tuesday.len()), (1, 1), "one beacon at a time");
        assert_ne!(monday[0].name, tuesday[0].name, "a new day is a new name");
        assert_ne!(monday[0].addr.port(), tuesday[0].addr.port(), "and a new port");
        assert!(bob_sends(&room, home, "tuesday").await.is_ok(), "and Bob still reaches it");
    }

    /// What a passive listener records of two openings shares no field but the
    /// network's lease of the address: a new name — the nonce — and a new port each
    /// time, one beacon each time whatever the number of contacts, and nothing else
    /// in it.
    #[tokio::test]
    async fn two_openings_of_the_door_announce_nothing_in_common_but_the_lease() {
        let temp = tempfile::tempdir().unwrap();
        let room = kotton_peer::local_network::Room::new();
        let rt = alice_in(&room, &temp).await;
        for n in 3..6u8 {
            rt.reachability().dm_inboxes().write().unwrap().push(kotton_peer::reachability::DmInbox {
                own_identity: identity(1),
                contact_pub: identity(n).verifying_key().to_bytes(),
                handler: handler(),
            });
        }
        let cafe = room_at(9);
        let mut recordings = Vec::new();
        for _ in 0..2 {
            rt.choose_local_door(DoorAnswer::TenMinutes, cafe).unwrap();
            let t0 = Instant::now();
            let open = rt.reconcile_local_door(t0, DAY, cafe, handler()).await;
            assert_eq!(open.contact_doors, 8, "four contacts, two hours each");
            let heard = room.heard();
            assert_eq!(heard.len(), 1, "one beacon for four contacts");
            recordings.push(heard[0].clone());
            rt.reconcile_local_door(t0 + Duration::from_secs(11 * 60), DAY, cafe, handler()).await;
            assert!(room.heard().is_empty());
        }
        let (a, b) = (&recordings[0], &recordings[1]);
        assert_ne!(a.name, b.name, "a name heard once is not heard again");
        assert_ne!(a.addr.port(), b.addr.port(), "nor a port");
        assert_eq!(a.addr.ip(), b.addr.ip(), "the lease is the network's, and repeats");
        assert_eq!(a.name.len(), 32, "the name is sixteen random bytes and nothing else");
        assert!(local_network::beacon_nonce(a).is_some());
    }

    /// A ten-minute door open at the day's turn keeps its port until its timer ends:
    /// renewing it would drop the sessions through it for a door minutes from closing.
    #[tokio::test]
    async fn a_ten_minute_door_keeps_its_port_across_midnight() {
        let temp = tempfile::tempdir().unwrap();
        let rt = runtime(&temp).await;
        let cafe = at(9);
        rt.choose_local_door(DoorAnswer::TenMinutes, cafe).unwrap();
        let now = Instant::now();
        let before = rt.reconcile_local_door(now, DAY, cafe, handler()).await.listening;
        let after = rt.reconcile_local_door(now, DAY + 1, cafe, handler()).await.listening;
        assert!(before.is_some());
        assert_eq!(before, after);
    }
}
