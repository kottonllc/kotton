// SPDX-License-Identifier: AGPL-3.0-or-later
//! The local network as the door sees it: somewhere to put one beacon while the
//! door is open, and somewhere to hear the beacons of other open doors.
//!
//! A beacon is a name and an address, and the name is a nonce the door drew when it
//! opened — nothing a stranger could recognise, and nothing the next opening shares.
//! Which beacon is a contact's is never read off the network: the contact derives a
//! knock from the nonce and the two people's keys, and only the door that knock was
//! derived for lets a byte of the dial through
//! (`kotton_net::transport::quic::knocked`).
//!
//! Two networks implement it. [`Mdns`] is the real one, `_kotton-door._udp`, and
//! under [`crate::scope::local_only`] it neither announces nor hears, because that
//! run promised to keep off the network. [`Room`] is one machine's: an in-process
//! list that two daemons in one test process share, so the path a message takes
//! across a room can be driven with no multicast socket at all. Nothing else can
//! see a `Room`.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// One open door, as the network carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Beacon {
    /// The door's nonce, hex — its whole name.
    pub name: String,
    /// Where its front answers.
    pub addr: SocketAddr,
}

/// A beacon on the network. Dropping it withdraws the beacon.
pub type Announced = Box<dyn std::any::Any + Send + Sync>;

/// The local network, for the door.
pub trait LocalNetwork: Send + Sync {
    /// Put `beacon` on the network until the returned handle is dropped.
    fn announce(&self, beacon: Beacon) -> anyhow::Result<Announced>;

    /// Every beacon heard within `within`. May block for that long; callers off a
    /// blocking thread run it on one.
    fn look(&self, within: Duration) -> Vec<Beacon>;
}

/// The real local network: `_kotton-door._udp` over mDNS, IPv4 only, as the door's
/// own announcement is.
#[derive(Debug, Default, Clone, Copy)]
pub struct Mdns;

impl LocalNetwork for Mdns {
    fn announce(&self, beacon: Beacon) -> anyhow::Result<Announced> {
        Mdns::announce_on(beacon, crate::scope::local_only())
    }

    fn look(&self, within: Duration) -> Vec<Beacon> {
        Mdns::look_on(within, crate::scope::local_only())
    }
}

impl Mdns {
    /// [`LocalNetwork::announce`], with the run's promise read once by the caller:
    /// a `local_only` run puts nothing on the network and opens no socket.
    fn announce_on(beacon: Beacon, local_only: bool) -> anyhow::Result<Announced> {
        if local_only {
            return Ok(Box::new(()));
        }
        let std::net::IpAddr::V4(ip) = beacon.addr.ip() else {
            anyhow::bail!("a door beacon carries an IPv4 address only");
        };
        let announced = kotton_net::announce_door(&[beacon.name], ip, beacon.addr.port())
            .map_err(|e| anyhow::anyhow!("announce the door's beacon: {e}"))?;
        Ok(Box::new(announced))
    }

    /// [`LocalNetwork::look`]: a `local_only` run hears nothing and opens no socket.
    fn look_on(within: Duration, local_only: bool) -> Vec<Beacon> {
        if local_only {
            return Vec::new();
        }
        match kotton_net::browse_doors(within) {
            Ok(heard) => heard
                .into_iter()
                .flat_map(|door| {
                    door.addresses
                        .into_iter()
                        .map(move |addr| Beacon { name: door.name.clone(), addr })
                })
                .collect(),
            Err(e) => {
                tracing::debug!(error = %e, "listening for doors failed");
                Vec::new()
            }
        }
    }
}

/// One machine's local network: every beacon announced into it is heard by every
/// device looking in it. For two daemons in one process, which share a machine
/// and so share a network.
#[derive(Debug, Default, Clone)]
pub struct Room {
    beacons: Arc<Mutex<Vec<(u64, Beacon)>>>,
    next: Arc<std::sync::atomic::AtomicU64>,
}

impl Room {
    pub fn new() -> Self {
        Self::default()
    }

    /// What a listener in the room hears right now — the whole of what any door
    /// in it announced.
    pub fn heard(&self) -> Vec<Beacon> {
        self.beacons.lock().unwrap().iter().map(|(_, b)| b.clone()).collect()
    }
}

struct InRoom {
    beacons: Arc<Mutex<Vec<(u64, Beacon)>>>,
    id: u64,
}

impl Drop for InRoom {
    fn drop(&mut self) {
        self.beacons.lock().unwrap().retain(|(id, _)| *id != self.id);
    }
}

impl LocalNetwork for Room {
    fn announce(&self, beacon: Beacon) -> anyhow::Result<Announced> {
        let id = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.beacons.lock().unwrap().push((id, beacon));
        Ok(Box::new(InRoom { beacons: Arc::clone(&self.beacons), id }))
    }

    fn look(&self, _within: Duration) -> Vec<Beacon> {
        self.heard()
    }
}

/// The network key a knock is bound to: the router's, when this device can read
/// it, or — on a run that promised to stay on this machine, where both ends share
/// one — a constant for *this machine*. `None` is no contact door here: a knock not
/// bound to a network could be carried to another one.
pub fn knock_network(
    router: Option<crate::local_door::RouterKey>,
    local_only: bool,
) -> Option<[u8; 32]> {
    router
        .map(|r| *r.as_bytes())
        .or_else(|| local_only.then_some(ONE_MACHINE))
}

/// [`knock_network`]'s key for a run on one machine.
const ONE_MACHINE: [u8; 32] = *b"kotton:one-machine:local-only:v1";

/// A fresh nonce for a door that is opening, and the name its beacon carries.
pub fn door_nonce() -> ([u8; 16], String) {
    use rand::RngCore;
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    (nonce, hex::encode(nonce))
}

/// The nonce a beacon's name carries, or `None` for a name that is not one — which
/// is every other kind of door on the network, and is skipped.
pub fn beacon_nonce(beacon: &Beacon) -> Option<[u8; 16]> {
    hex::decode(&beacon.name).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A room hears what is announced in it, and stops hearing it when the
    /// announcement is dropped.
    #[test]
    fn a_room_hears_a_beacon_until_it_is_withdrawn() {
        let room = Room::new();
        let (_, name) = door_nonce();
        let b = Beacon { name, addr: "127.0.0.1:4000".parse().unwrap() };
        let held = room.announce(b.clone()).unwrap();
        assert_eq!(room.look(Duration::ZERO), vec![b]);
        drop(held);
        assert!(room.look(Duration::ZERO).is_empty());
    }

    /// Two openings draw two names, and a name is its nonce.
    #[test]
    fn each_opening_is_a_new_name() {
        let (n1, a) = door_nonce();
        let (_, b) = door_nonce();
        assert_ne!(a, b);
        let beacon = Beacon { name: a, addr: "127.0.0.1:1".parse().unwrap() };
        assert_eq!(beacon_nonce(&beacon), Some(n1));
        assert_eq!(beacon_nonce(&Beacon { name: "a-device-door".into(), ..beacon }), None);
    }

    /// A run that promised to stay on this machine announces nothing and hears
    /// nothing over mDNS, and opens no socket to do either: the announcement handed
    /// back is empty, and a look asked to wait ten seconds returns at once, because
    /// no browse started.
    #[test]
    fn mdns_is_silent_on_a_run_that_stays_on_this_machine() {
        let beacon = Beacon { name: door_nonce().1, addr: "192.168.1.20:4000".parse().unwrap() };
        let announced = Mdns::announce_on(beacon, true).unwrap();
        assert!(announced.downcast_ref::<()>().is_some(), "a local-only run announced something");
        let started = std::time::Instant::now();
        assert!(Mdns::look_on(Duration::from_secs(10), true).is_empty());
        assert!(started.elapsed() < Duration::from_secs(1), "a local-only look browsed");
    }

    /// The real network, both ways: a beacon announced over mDNS is heard by a
    /// browse with its nonce and address intact.
    #[test]
    #[ignore = "binds the mDNS multicast socket on :5353 — the socket that raises the OS firewall dialog; run with --include-ignored"]
    fn an_mdns_beacon_is_heard_with_its_name_and_address() {
        let Some(ip) = crate::local_door::lan_ip_here() else { return };
        let (_, name) = door_nonce();
        let beacon = Beacon { name, addr: std::net::SocketAddr::new(ip.into(), 45_123) };
        let _held = Mdns::announce_on(beacon.clone(), false).unwrap();
        assert!(Mdns::look_on(Duration::from_secs(4), false).contains(&beacon));
    }

    #[test]
    fn a_knock_is_bound_to_a_network_or_to_this_machine() {
        let home = crate::local_door::RouterKey::of_gateway_mac([0x3c, 0x22, 0xfb, 0, 0, 1]);
        assert_eq!(knock_network(Some(home), false), Some(*home.as_bytes()));
        assert_eq!(knock_network(Some(home), true), Some(*home.as_bytes()));
        assert_eq!(knock_network(None, true), Some(ONE_MACHINE));
        assert_eq!(knock_network(None, false), None);
    }
}
