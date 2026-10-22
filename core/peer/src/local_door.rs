// SPDX-License-Identifier: AGPL-3.0-or-later
//! The local-network door: closed by default, opened on purpose, and shut by itself.
//!
//! The local network is a door opened on purpose, for ten minutes; a relay
//! introduces your devices otherwise. Not [`crate::door`], which is a *vocabulary* door on a peer
//! circuit; this one is a socket on a network, and the thing it decides is whether
//! there is one at all.
//!
//! # Why a door and not a check
//!
//! The data was never the exposure: every path carries sealed frames and admission is
//! by key. A listening port on a hostile network is — it can be probed, flooded and
//! attacked through whatever parses its first packet, and encryption protects none of
//! that. The second design test in `CLAUDE.md` says a check at the door is evidence the
//! door is reachable; on a strange network the better move is a door that is not there.
//! So this module holds no admission rule. It holds the one fact that decides whether a
//! local listener and a local announcement exist: which of three answers the person
//! gave, for which network, and until when.
//!
//! # The three answers, one control
//!
//! *Closed · 10 minutes · Always* — AirDrop's *No One / Contacts Only / Everyone for 10
//! minutes* is the shape: a risky openness gets a timer, not a switch, and the standing
//! exception is a third answer to the same question rather than a second row.
//!
//! - **Closed** is the default everywhere, and what a fresh device holds.
//! - **10 minutes** opens the door on the network the device is on now and shuts it
//!   [`DOOR_OPEN_FOR`] later. Nothing is remembered: it lives in memory, so a restart
//!   closes it too, and where the devices met is never written down.
//! - **Always** keeps the door open on **one** network, keyed by its router
//!   ([`RouterKey`]) and never by the Wi-Fi name, which macOS 14 gates behind Location
//!   Services and which any café can copy. A home with no relay needs it; on every other
//!   network the door stays closed.
//!
//! The clock is a parameter everywhere here, so *closed at eleven minutes* is a test
//! and not a wait.

use sha2::{Digest, Sha256};
use std::fmt;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::time::Instant;

/// How long *10 minutes* keeps the door open. Apple's number (AirDrop's *Everyone for
/// 10 Minutes*) until the owner names another; `ui/tokens.css` carries the same
/// value as `--door-open-minutes`, and xtask's
/// `the_door_timer_is_the_token_files_number` holds the two together there, where the file is.
pub const DOOR_OPEN_FOR: Duration = Duration::from_secs(10 * 60);

/// The person's answer on the row *Open to your devices here*.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DoorAnswer {
    /// No listener, no announcement. The default.
    #[default]
    Closed,
    /// Open on this network for [`DOOR_OPEN_FOR`], then closed.
    TenMinutes,
    /// Open on this one network, keyed by its router, until the person says otherwise.
    Always,
}

impl DoorAnswer {
    /// The word on the wire and on the command line.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::TenMinutes => "10m",
            Self::Always => "always",
        }
    }

    /// Parse the word [`Self::as_str`] writes. `10` and `10-minutes` are accepted for
    /// a person typing; nothing else is guessed.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "closed" => Some(Self::Closed),
            "10m" | "10" | "10-minutes" => Some(Self::TenMinutes),
            "always" => Some(Self::Always),
            _ => None,
        }
    }
}

impl fmt::Display for DoorAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An opaque key for the network the device is on, derived from its router.
///
/// SHA-256 over a domain separator and the default gateway's hardware address. The
/// hardware address is what a copied Wi-Fi name cannot copy. The hash is **not** a
/// secret: a MAC is 48 bits under a known vendor prefix, so anyone holding the stored
/// value can recover the router by trying the vendor's range. What it buys is narrower —
/// the one row *Always* writes is not the router's address in plain text, and the same
/// key is what two of the person's devices on that router both derive, which is why it
/// cannot be salted per device. The row lives on the person's own disk, beside keys worth
/// far more.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RouterKey([u8; 32]);

impl RouterKey {
    /// The key for a router whose hardware address is `mac`.
    pub fn of_gateway_mac(mac: [u8; 6]) -> Self {
        let mut h = Sha256::new();
        h.update(b"kotton:door-router:v1");
        h.update(mac);
        Self(h.finalize().into())
    }

    /// The raw bytes, for deriving an announcement name.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Hex, as stored in `device_config`.
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    /// Read back what [`Self::to_hex`] wrote. Anything else is `None` — a stored
    /// value this cannot read is a door that stays closed, never one that guesses.
    pub fn from_hex(s: &str) -> Option<Self> {
        let raw = hex::decode(s.trim()).ok()?;
        Some(Self(raw.as_slice().try_into().ok()?))
    }
}

impl fmt::Debug for RouterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Short, so a log line can say *which* without printing a stored value whole.
        write!(f, "RouterKey({}…)", &self.to_hex()[..8])
    }
}

/// What the device can say about the network it is on right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetworkHere {
    /// The router's key, when the platform lets this device read the router's hardware
    /// address. `None` means *Always* cannot be chosen here, and says so.
    pub router: Option<RouterKey>,
    /// This device's IPv4 address on the router's interface — the one address the
    /// announcement carries. [`network_here`] leaves it empty, because finding it binds
    /// a socket; the keeper fills it from [`lan_ip_here`] only while the door is open.
    pub lan_ip: Option<Ipv4Addr>,
}

/// Where the door stands at one instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoorState {
    /// No listener and no announcement.
    Closed,
    /// Open on this network for `remaining` more.
    OpenFor { remaining: Duration },
    /// Open because this is the one network the person keeps it open on.
    AlwaysHere,
}

impl DoorState {
    /// Whether a local listener and announcement should exist.
    pub fn is_open(self) -> bool {
        !matches!(self, Self::Closed)
    }
}

/// Why an answer could not be taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DoorRefusal {
    /// *Always* needs a router to key to, and this device cannot read one here.
    NoRouterHere,
}

impl fmt::Display for DoorRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRouterHere => f.write_str(
                "this device cannot tell which network it is on, so it cannot keep the door \
                 open on this one; choose 10 minutes instead",
            ),
        }
    }
}

impl std::error::Error for DoorRefusal {}

/// The door's state: when the timer runs out, and which network, if any, keeps it open.
///
/// Default is closed. The two fields are the whole of what the three answers leave
/// behind; `open_until` is never persisted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalDoor {
    /// When *10 minutes* runs out, and the network it was opened on. The timer is
    /// for that network: a device that walks to another is closed there.
    open_until: Option<(Instant, Option<RouterKey>)>,
    always_on: Option<RouterKey>,
}

impl LocalDoor {
    /// A door that keeps open on `router`, as read back from `device_config` at boot.
    pub fn always_on(router: Option<RouterKey>) -> Self {
        Self { open_until: None, always_on: router }
    }

    /// The network *Always* is kept for, to persist.
    pub fn always_router(&self) -> Option<RouterKey> {
        self.always_on
    }

    /// Where the door stands at `now`, on the network whose router is `here`.
    pub fn state(&self, now: Instant, here: Option<RouterKey>) -> DoorState {
        if here.is_some() && self.always_on == here {
            return DoorState::AlwaysHere;
        }
        match self.open_until {
            Some((until, on)) if until > now && on == here => {
                DoorState::OpenFor { remaining: until - now }
            }
            _ => DoorState::Closed,
        }
    }

    /// The answer the row shows at `now` on `here`: the three are one control, so
    /// exactly one is lit.
    pub fn answer(&self, now: Instant, here: Option<RouterKey>) -> DoorAnswer {
        match self.state(now, here) {
            DoorState::Closed => DoorAnswer::Closed,
            DoorState::OpenFor { .. } => DoorAnswer::TenMinutes,
            DoorState::AlwaysHere => DoorAnswer::Always,
        }
    }

    /// When the door next changes by itself, if it will — the timer's end.
    pub fn next_change(&self, now: Instant) -> Option<Instant> {
        self.open_until.map(|(until, _)| until).filter(|until| *until > now)
    }

    /// Take the person's answer, given at `now` on the network whose router is `here`.
    ///
    /// Each answer replaces the other two *for this network*: choosing *Closed* or *10
    /// minutes* here stops keeping this network open, and choosing *Always* stops the
    /// timer. An *Always* kept for a different network is left alone by *Closed* and
    /// *10 minutes* — the row speaks only for the network it names — and replaced by an
    /// *Always* here, because only one network is kept open.
    pub fn choose(
        &mut self,
        answer: DoorAnswer,
        now: Instant,
        here: Option<RouterKey>,
    ) -> Result<(), DoorRefusal> {
        let kept_here = here.is_some() && self.always_on == here;
        match answer {
            DoorAnswer::Closed => {
                self.open_until = None;
                if kept_here {
                    self.always_on = None;
                }
            }
            DoorAnswer::TenMinutes => {
                self.open_until = Some((now + DOOR_OPEN_FOR, here));
                if kept_here {
                    self.always_on = None;
                }
            }
            DoorAnswer::Always => {
                let router = here.ok_or(DoorRefusal::NoRouterHere)?;
                self.open_until = None;
                self.always_on = Some(router);
            }
        }
        Ok(())
    }
}

/// Read the network this device is on: the default gateway's hardware address, hashed.
///
/// Linux reads `/proc/net/route` and `/proc/net/arp` — two file reads, no socket, no
/// privilege, nothing sent — so the keeper can call it every few seconds on a device
/// whose door is closed and open nothing by doing so. `lan_ip` is left `None` here; the
/// one address an open door announces is [`lan_ip_here`]'s, asked only while it is open.
/// Other platforms return no router yet, which makes *Always* unavailable there and says
/// so rather than keying to something weaker; *10 minutes* still opens. That gap is this
/// record's Next.
pub fn network_here() -> NetworkHere {
    #[cfg(target_os = "linux")]
    {
        let route = std::fs::read_to_string("/proc/net/route").unwrap_or_default();
        let arp = std::fs::read_to_string("/proc/net/arp").unwrap_or_default();
        let Some((iface, gateway)) = default_gateway(&route) else {
            return NetworkHere::default();
        };
        NetworkHere {
            router: gateway_mac(&arp, gateway, &iface).map(RouterKey::of_gateway_mac),
            lan_ip: None,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        NetworkHere::default()
    }
}

/// This device's IPv4 address on the default route's interface — the one address an
/// open door announces.
///
/// **Binds a socket**: an unconnected-then-connected UDP socket on an ephemeral port,
/// whose local address the routing table fills in (`connect` on UDP sends nothing). It
/// lives for the length of this call. That is why it is not part of [`network_here`]:
/// a device whose door is closed must bind nothing, and only the keeper of an *open*
/// door calls this.
pub fn lan_ip_here() -> Option<Ipv4Addr> {
    #[cfg(target_os = "linux")]
    {
        let route = std::fs::read_to_string("/proc/net/route").unwrap_or_default();
        let (_, gateway) = default_gateway(&route)?;
        lan_ip_towards(gateway)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// The interface and gateway of the default route in `/proc/net/route`'s text.
///
/// Fields are whitespace-separated; destination `00000000` is the default route, and
/// the gateway is a little-endian hex IPv4 address.
pub fn default_gateway(route: &str) -> Option<(String, Ipv4Addr)> {
    route.lines().skip(1).find_map(|line| {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 3 || f[1] != "00000000" {
            return None;
        }
        let raw = u32::from_str_radix(f[2], 16).ok()?;
        let gw = Ipv4Addr::from(raw.to_le_bytes());
        (!gw.is_unspecified()).then(|| (f[0].to_owned(), gw))
    })
}

/// The hardware address `/proc/net/arp` holds for `gateway` on `iface`.
pub fn gateway_mac(arp: &str, gateway: Ipv4Addr, iface: &str) -> Option<[u8; 6]> {
    arp.lines().skip(1).find_map(|line| {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 6 || f[0].parse::<Ipv4Addr>().ok()? != gateway || f[5] != iface {
            return None;
        }
        let bytes: Vec<u8> =
            f[3].split(':').filter_map(|b| u8::from_str_radix(b, 16).ok()).collect();
        let mac: [u8; 6] = bytes.as_slice().try_into().ok()?;
        // An incomplete ARP entry reads all zeros; that is no router, not a router.
        (mac != [0; 6]).then_some(mac)
    })
}

/// This device's source address towards `gateway`: a connected UDP socket's local
/// address. `connect` on UDP sends nothing; it only asks the routing table.
#[cfg(target_os = "linux")]
fn lan_ip_towards(gateway: Ipv4Addr) -> Option<Ipv4Addr> {
    let s = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    s.connect((gateway, 9)).ok()?;
    match s.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(ip) if !ip.is_unspecified() => Some(ip),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home() -> RouterKey {
        RouterKey::of_gateway_mac([0x3c, 0x22, 0xfb, 0x01, 0x02, 0x03])
    }

    fn cafe() -> RouterKey {
        RouterKey::of_gateway_mac([0xa4, 0x2b, 0xb0, 0x09, 0x08, 0x07])
    }

    /// A fresh device's door is closed on every network, the one with no router
    /// included.
    #[test]
    fn a_fresh_door_is_closed_everywhere() {
        let door = LocalDoor::default();
        let now = Instant::now();
        for here in [None, Some(home()), Some(cafe())] {
            assert_eq!(door.state(now, here), DoorState::Closed);
            assert_eq!(door.answer(now, here), DoorAnswer::Closed);
        }
        assert_eq!(door.next_change(now), None);
    }

    /// *10 minutes* is open at nine and closed at eleven, and nothing is remembered:
    /// after the timer the door is exactly a fresh one.
    #[test]
    fn ten_minutes_is_closed_at_eleven_minutes() {
        let t0 = Instant::now();
        let mut door = LocalDoor::default();
        door.choose(DoorAnswer::TenMinutes, t0, Some(cafe())).unwrap();

        let nine = t0 + Duration::from_secs(9 * 60);
        assert_eq!(
            door.state(nine, Some(cafe())),
            DoorState::OpenFor { remaining: Duration::from_secs(60) }
        );
        assert_eq!(door.next_change(t0), Some(t0 + DOOR_OPEN_FOR));

        let eleven = t0 + Duration::from_secs(11 * 60);
        assert_eq!(door.state(eleven, Some(cafe())), DoorState::Closed);
        assert_eq!(door.answer(eleven, Some(cafe())), DoorAnswer::Closed);
        assert_eq!(door.next_change(eleven), None);
        assert_eq!(door.always_router(), None, "the timer leaves nothing to persist");
    }

    /// *10 minutes* is for the network it was opened on: carried to another, the door
    /// is closed there, and on a network with no readable router it still opens.
    #[test]
    fn ten_minutes_is_for_the_network_it_was_opened_on() {
        let t0 = Instant::now();
        let mut door = LocalDoor::default();
        door.choose(DoorAnswer::TenMinutes, t0, Some(cafe())).unwrap();
        assert_eq!(door.state(t0, Some(home())), DoorState::Closed);
        assert_eq!(door.state(t0, None), DoorState::Closed);

        let mut unknown = LocalDoor::default();
        unknown.choose(DoorAnswer::TenMinutes, t0, None).unwrap();
        assert!(unknown.state(t0, None).is_open());
        assert_eq!(unknown.state(t0, Some(cafe())), DoorState::Closed);
    }

    /// *Always* opens on its one network and on no other — not on the café, and not
    /// on a network whose router this device cannot read.
    #[test]
    fn always_is_one_network_keyed_by_its_router() {
        let now = Instant::now();
        let mut door = LocalDoor::default();
        door.choose(DoorAnswer::Always, now, Some(home())).unwrap();

        assert_eq!(door.state(now, Some(home())), DoorState::AlwaysHere);
        assert_eq!(door.state(now, Some(cafe())), DoorState::Closed);
        assert_eq!(door.state(now, None), DoorState::Closed);
        assert_eq!(door.always_router(), Some(home()));

        // Read back from storage, it is the same door.
        let back = LocalDoor::always_on(RouterKey::from_hex(&home().to_hex()));
        assert_eq!(back.state(now, Some(home())), DoorState::AlwaysHere);
    }

    /// With no router to key to, *Always* is refused rather than kept for "whatever
    /// network this is", which would be every network.
    #[test]
    fn always_without_a_router_is_refused() {
        let mut door = LocalDoor::default();
        assert_eq!(
            door.choose(DoorAnswer::Always, Instant::now(), None),
            Err(DoorRefusal::NoRouterHere)
        );
        assert_eq!(door, LocalDoor::default());
    }

    /// One control: each answer replaces the others on this network, and *Closed* or
    /// *10 minutes* at the café leaves home's *Always* alone.
    #[test]
    fn the_three_answers_are_one_control() {
        let now = Instant::now();
        let mut door = LocalDoor::default();
        door.choose(DoorAnswer::Always, now, Some(home())).unwrap();

        door.choose(DoorAnswer::TenMinutes, now, Some(home())).unwrap();
        assert_eq!(door.answer(now, Some(home())), DoorAnswer::TenMinutes);
        assert_eq!(door.always_router(), None);

        door.choose(DoorAnswer::Always, now, Some(home())).unwrap();
        assert_eq!(door.answer(now, Some(home())), DoorAnswer::Always);
        assert_eq!(door.next_change(now), None, "choosing Always stops the timer");

        door.choose(DoorAnswer::Closed, now, Some(cafe())).unwrap();
        assert_eq!(door.answer(now, Some(home())), DoorAnswer::Always);
        door.choose(DoorAnswer::Closed, now, Some(home())).unwrap();
        assert_eq!(door, LocalDoor::default());
    }

    #[test]
    fn the_default_route_and_its_router_are_read_from_proc() {
        let route = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n\
                     wlan0\t0000A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\n\
                     wlan0\t00000000\t0100A8C0\t0003\t0\t0\t600\t00000000\n";
        let (iface, gw) = default_gateway(route).expect("a default route");
        assert_eq!((iface.as_str(), gw), ("wlan0", Ipv4Addr::new(192, 168, 0, 1)));

        let arp = "IP address       HW type     Flags       HW address            Mask     Device\n\
                   192.168.0.1      0x1         0x2         3c:22:fb:01:02:03     *        wlan0\n\
                   192.168.0.7      0x1         0x0         00:00:00:00:00:00     *        wlan0\n";
        assert_eq!(gateway_mac(arp, gw, "wlan0"), Some([0x3c, 0x22, 0xfb, 1, 2, 3]));
        assert_eq!(gateway_mac(arp, gw, "eth0"), None, "same address, other interface");
        assert_eq!(gateway_mac(arp, Ipv4Addr::new(192, 168, 0, 7), "wlan0"), None);
        assert_eq!(default_gateway("Iface\tDestination\tGateway\n"), None);
    }

    #[test]
    fn answers_round_trip_through_their_words() {
        for a in [DoorAnswer::Closed, DoorAnswer::TenMinutes, DoorAnswer::Always] {
            assert_eq!(DoorAnswer::parse(a.as_str()), Some(a));
        }
        assert_eq!(DoorAnswer::parse("open"), None);
        assert_eq!(RouterKey::from_hex("zz"), None);
    }
}
