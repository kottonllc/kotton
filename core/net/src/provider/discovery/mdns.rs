// SPDX-License-Identifier: AGPL-3.0-or-later
//! mDNS-based network discovery
//!
//! Discovers Kotton peers on the local network using mDNS/DNS-SD.

use kotton_sys::net::{
    Address, Advertiser, Discovery, DiscoveryError, DiscoveryResult, Peer,
};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const SERVICE_TYPE: &str = "_kotton._tcp.local.";
const DEFAULT_DISCOVERY_DURATION: Duration = Duration::from_secs(5);

/// mDNS-based discovery for Kotton peers on local network.
///
/// Uses DNS-SD to advertise and discover Kotton instances.
/// Automatically advertises the local instance when created.
pub struct MdnsDiscovery {
    /// mDNS service daemon
    daemon: ServiceDaemon,
    /// Local instance ID
    instance_id: String,
    /// Port this instance is listening on
    port: u16,
    /// Local instance metadata
    metadata: HashMap<String, String>,
    /// Whether advertising is currently active
    advertising: bool,
    /// Discovered peers cache
    peers: Arc<Mutex<HashMap<String, Peer>>>,
}

impl MdnsDiscovery {
    /// Create a new mDNS discovery instance.
    ///
    /// # Arguments
    ///
    /// * `instance_id` - Unique identifier for this instance
    /// * `port` - Port this instance is listening on
    /// * `metadata` - Additional metadata to advertise (DID, version, etc.)
    pub fn new(
        instance_id: String,
        port: u16,
        metadata: HashMap<String, String>,
    ) -> DiscoveryResult<Self> {
        let daemon = ServiceDaemon::new()
            .map_err(|e| DiscoveryError::Failed(format!("Failed to create mDNS daemon: {}", e)))?;

        let mut discovery = Self {
            daemon,
            instance_id,
            port,
            metadata,
            advertising: false,
            peers: Arc::new(Mutex::new(HashMap::new())),
        };

        // Advertise this instance
        discovery.advertise()?;
        discovery.advertising = true;

        Ok(discovery)
    }

    /// Advertise this instance on the local network.
    fn advertise(&mut self) -> DiscoveryResult<()> {
        let service_info = ServiceInfo::new(
            SERVICE_TYPE,
            &self.instance_id,
            &format!("{}.local.", self.instance_id),
            (),
            self.port,
            self.metadata.clone(),
        )
        .map_err(|e| DiscoveryError::Failed(format!("Failed to create service info: {}", e)))?;

        self.daemon
            .register(service_info)
            .map_err(|e| DiscoveryError::Failed(format!("Failed to register service: {}", e)))?;

        Ok(())
    }

    /// Scan for peers with a custom duration.
    fn scan_with_duration(&self, duration: Duration) -> DiscoveryResult<Vec<Peer>> {
        // Browse for Kotton services
        let receiver = self
            .daemon
            .browse(SERVICE_TYPE)
            .map_err(|e| DiscoveryError::Failed(format!("Failed to browse services: {}", e)))?;

        // Collect results for the specified duration
        let peers = Arc::clone(&self.peers);
        let start = std::time::Instant::now();

        while start.elapsed() < duration {
            // Check for events with a short timeout
            let timeout = duration
                .saturating_sub(start.elapsed())
                .min(Duration::from_millis(100));

            if let Ok(event) = receiver.recv_timeout(timeout) {
                match event {
                    ServiceEvent::ServiceResolved(info) => {
                        if let Some(peer) = self.service_info_to_peer(&info) {
                            let mut peers_lock = peers.lock().unwrap();
                            peers_lock.insert(peer.id.clone(), peer);
                        }
                    }
                    ServiceEvent::ServiceRemoved(_, fullname) => {
                        let mut peers_lock = peers.lock().unwrap();
                        peers_lock.retain(|_, p| !fullname.contains(&p.id));
                    }
                    _ => {}
                }
            }
        }

        let peers_lock = self.peers.lock().unwrap();
        Ok(peers_lock.values().cloned().collect())
    }

    /// Convert ServiceInfo to Peer.
    fn service_info_to_peer(&self, info: &ServiceInfo) -> Option<Peer> {
        // Skip our own instance
        if info.get_fullname().contains(&self.instance_id) {
            return None;
        }

        let id = info.get_hostname().trim_end_matches(".local.").to_string();

        // Collect all IP addresses
        let addresses: Vec<SocketAddr> = info
            .get_addresses()
            .iter()
            .map(|ip| match ip {
                IpAddr::V4(addr) => SocketAddr::new(IpAddr::V4(*addr), info.get_port()),
                IpAddr::V6(addr) => SocketAddr::new(IpAddr::V6(*addr), info.get_port()),
            })
            .collect();

        if addresses.is_empty() {
            return None;
        }

        // Extract metadata from TXT records
        let metadata: HashMap<String, String> = info
            .get_properties()
            .iter()
            .map(|prop| (prop.key().to_string(), prop.val_str().to_string()))
            .collect();

        Some(Peer {
            id,
            addresses: addresses
                .into_iter()
                .map(Address::Tcp)
                .collect(),
            metadata,
        })
    }
}

impl Discovery for MdnsDiscovery {
    fn discover_peers(&self) -> DiscoveryResult<Vec<Peer>> {
        self.scan_with_duration(DEFAULT_DISCOVERY_DURATION)
    }

    fn start_discovery(&self) -> DiscoveryResult<()> {
        // mDNS discovery is passive - we're always listening
        Ok(())
    }

    fn stop_discovery(&self) -> DiscoveryResult<()> {
        // Shutdown is handled by Drop
        Ok(())
    }
}

impl Advertiser for MdnsDiscovery {
    fn start_advertising(
        &self,
        service_name: String,
        port: u16,
        metadata: HashMap<String, String>,
    ) -> DiscoveryResult<()> {
        // Create service info
        let service_info = ServiceInfo::new(
            SERVICE_TYPE,
            &service_name,
            &format!("{}.local.", service_name),
            (),
            port,
            metadata,
        )
        .map_err(|e| {
            DiscoveryError::Failed(format!("Failed to create service info: {}", e))
        })?;

        // Register with daemon
        self.daemon.register(service_info).map_err(|e| {
            DiscoveryError::Failed(format!("Failed to register service: {}", e))
        })?;

        Ok(())
    }

    fn update_metadata(&self, metadata: HashMap<String, String>) -> DiscoveryResult<()> {
        // mDNS doesn't support updating TXT records dynamically
        // Need to unregister and re-register
        self.daemon
            .unregister(&format!("{}.{}", self.instance_id, SERVICE_TYPE))
            .map_err(|e| DiscoveryError::Failed(format!("Failed to unregister: {}", e)))?;

        let service_info = ServiceInfo::new(
            SERVICE_TYPE,
            &self.instance_id,
            &format!("{}.local.", self.instance_id),
            (),
            self.port,
            metadata,
        )
        .map_err(|e| {
            DiscoveryError::Failed(format!("Failed to create service info: {}", e))
        })?;

        self.daemon
            .register(service_info)
            .map_err(|e| DiscoveryError::Failed(format!("Failed to re-register: {}", e)))?;

        Ok(())
    }

    fn stop_advertising(&self) -> DiscoveryResult<()> {
        self.daemon
            .unregister(&format!("{}.{}", self.instance_id, SERVICE_TYPE))
            .map_err(|e| DiscoveryError::Failed(format!("Failed to unregister: {}", e)))?;
        Ok(())
    }
}

impl Drop for MdnsDiscovery {
    fn drop(&mut self) {
        shutdown_daemon(&self.daemon);
    }
}

/// Shut down an mDNS [`ServiceDaemon`] and wait (briefly) for its confirmation.
///
/// `ServiceDaemon::shutdown` hands back a receiver on which the daemon thread
/// sends one `DaemonStatus::Shutdown` after it has actually exited. Dropping that
/// receiver eagerly — the natural `let _ = daemon.shutdown()` — loses a race: the
/// daemon thread then can't deliver the confirmation and mdns-sd logs it at ERROR
/// (`exit: failed to send response of shutdown: sending on a closed channel`).
/// Because `kuserd` bridges the `log` crate into tracing, that dependency-internal
/// line surfaced as a spurious `[kuserd] ERROR` at the end of every pairing
/// ceremony. Holding the receiver until the send lands makes shutdown clean and
/// silent. The wait is bounded so a wedged daemon thread can never stall teardown.
fn shutdown_daemon(daemon: &ServiceDaemon) {
    if let Ok(rx) = daemon.shutdown() {
        let _ = rx.recv_timeout(Duration::from_secs(1));
    }
}

// ---------------------------------------------------------------------------
// RFC-0040 anonymous pairing-offer discovery (`_kotton-pair._udp`)
// ---------------------------------------------------------------------------

/// mDNS service type for RFC-0040 pairing offers — a **distinct** type from the
/// general `_kotton._tcp` presence, so a browse for "devices offering to pair" is
/// precise.
const PAIR_SERVICE_TYPE: &str = "_kotton-pair._udp.local.";
/// Pairing-offer protocol version advertised in the TXT record.
const PAIR_OFFER_VERSION: &str = "1";

/// A live pairing-offer advertisement. Unregisters on drop, so the offer
/// disappears from the network the moment the ceremony ends or times out.
pub struct PairingOffer {
    daemon: ServiceDaemon,
    fullname: String,
}

impl Drop for PairingOffer {
    fn drop(&mut self) {
        // Wait for the unregister confirmation, same as shutdown: `unregister` hands
        // back a receiver the daemon thread sends on, and dropping it eagerly loses
        // the race — mdns-sd then logs `unregister: failed to send response` at ERROR,
        // which surfaced as a `[kuserd] ERROR` at the end of every pairing ceremony.
        if let Ok(rx) = self.daemon.unregister(&self.fullname) {
            let _ = rx.recv_timeout(Duration::from_secs(1));
        }
        shutdown_daemon(&self.daemon);
    }
}

/// Advertise an **anonymous** pairing offer (RFC-0040 §1). The instance name is
/// the random session id, the TXT record carries only `sid` + `v`, and the SRV
/// target host name is the sid too — an opaque per-session name. The device's
/// human label is **never broadcast**; it travels inside the encrypted channel of
/// the handshake, so only a peer that actually connects learns it. A passive
/// observer learns just "some Kotton device is pairing", bounded to the offer's
/// lifetime.
///
/// `sid_hex` is the 32-char hex of the 16-byte session id; `port` is the bootstrap
/// QUIC listener's port. Hold the returned [`PairingOffer`] for the ceremony's
/// duration — dropping it withdraws the offer.
pub fn advertise_pairing_offer(sid_hex: &str, port: u16) -> DiscoveryResult<PairingOffer> {
    let daemon = ServiceDaemon::new()
        .map_err(|e| DiscoveryError::Failed(format!("mDNS daemon: {e}")))?;
    let info = build_pairing_service_info(sid_hex, port)?;
    let fullname = info.get_fullname().to_string();
    daemon
        .register(info)
        .map_err(|e| DiscoveryError::Failed(format!("register pairing offer: {e}")))?;
    Ok(PairingOffer { daemon, fullname })
}

/// Build the anonymous pairing-offer `ServiceInfo` (RFC-0040 §1). Factored out so
/// the anonymity invariant — TXT is exactly `{sid, v}`, instance + host names are
/// the opaque sid, no label — is unit-testable without touching the network.
fn build_pairing_service_info(sid_hex: &str, port: u16) -> DiscoveryResult<ServiceInfo> {
    let mut props = HashMap::new();
    props.insert("sid".to_string(), sid_hex.to_string());
    props.insert("v".to_string(), PAIR_OFFER_VERSION.to_string());
    // Instance name AND host name are the sid — opaque, no machine identity leaked.
    let host = format!("{sid_hex}.local.");
    ServiceInfo::new(PAIR_SERVICE_TYPE, sid_hex, &host, (), port, props)
        .map(|i| i.enable_addr_auto())
        .map_err(|e| DiscoveryError::Failed(format!("pairing ServiceInfo: {e}")))
}

/// A discovered anonymous pairing offer: the session id + every resolved
/// bootstrap address the peer advertised.
///
/// A dual-stack host (a Mac especially) resolves to many addresses — Wi-Fi,
/// Ethernet, VPN/`utun`, link-local, and IPv6 — and only some are dialable from
/// the joiner. We keep the whole set here rather than gambling on one; the caller
/// ranks and tries them in order. Collapsing to a single arbitrary address is what
/// made mDNS pairing a coin toss (an IPv6-first pick against an IPv4-only client
/// fails outright).
#[derive(Debug, Clone)]
pub struct DiscoveredOffer {
    /// The offer's session id (hex) — goes into `PairHello.sid`.
    pub sid_hex: String,
    /// Every resolved bootstrap address, in mDNS resolution order. The caller is
    /// responsible for filtering (loopback/link-local) and ranking before dialing.
    pub addresses: Vec<SocketAddr>,
}

/// Browse for anonymous pairing offers for `duration`, returning the resolved
/// offers (deduped by sid). No labels are learned here — §1 keeps them off the
/// wire; the joiner learns each offer's label only after connecting (the
/// `PairInfo` frame). With exactly one offer the caller preselects it.
pub fn browse_pairing_offers(duration: Duration) -> DiscoveryResult<Vec<DiscoveredOffer>> {
    let daemon = ServiceDaemon::new()
        .map_err(|e| DiscoveryError::Failed(format!("mDNS daemon: {e}")))?;
    let receiver = daemon
        .browse(PAIR_SERVICE_TYPE)
        .map_err(|e| DiscoveryError::Failed(format!("browse pairing offers: {e}")))?;

    let mut offers: HashMap<String, DiscoveredOffer> = HashMap::new();
    let start = std::time::Instant::now();
    while start.elapsed() < duration {
        let timeout = duration
            .saturating_sub(start.elapsed())
            .min(Duration::from_millis(200));
        if let Ok(ServiceEvent::ServiceResolved(info)) = receiver.recv_timeout(timeout) {
            let sid_hex = info
                .get_properties()
                .get_property_val_str("sid")
                .map(|s| s.to_string())
                .unwrap_or_else(|| {
                    // Fall back to the instance name (also the sid).
                    info.get_fullname()
                        .split('.')
                        .next()
                        .unwrap_or_default()
                        .to_string()
                });
            let port = info.get_port();
            let resolved: Vec<SocketAddr> = info
                .get_addresses()
                .iter()
                .map(|ip| SocketAddr::new(*ip, port))
                .collect();
            if resolved.is_empty() {
                continue;
            }
            // A peer can resolve across several `ServiceResolved` events as more of
            // its addresses arrive — merge, don't overwrite, so we keep the full set.
            offers
                .entry(sid_hex.clone())
                .and_modify(|o| {
                    for a in &resolved {
                        if !o.addresses.contains(a) {
                            o.addresses.push(*a);
                        }
                    }
                })
                .or_insert(DiscoveredOffer {
                    sid_hex,
                    addresses: resolved,
                });
        }
    }
    shutdown_daemon(&daemon);
    Ok(offers.into_values().collect())
}

// ---------------------------------------------------------------------------
// The local-network door's announcement (`_kotton-door._udp`)
// ---------------------------------------------------------------------------

/// mDNS service type for an open local-network door
/// (`TASK-the-local-network-is-a-door-opened-on-purpose-for-ten-minutes-and-a-relay-introduces-your-devices`).
/// Its own type, apart from `_kotton._tcp` presence and `_kotton-pair._udp` offers,
/// so a device browsing for its own devices' doors finds nothing else and nothing
/// else finds it by accident.
const DOOR_SERVICE_TYPE: &str = "_kotton-door._udp.local.";

/// A live door announcement: one service per name. Unregisters every one and shuts
/// the daemon on drop, so the announcement ends the moment the door closes.
pub struct DoorAnnouncement {
    daemon: ServiceDaemon,
    fullnames: Vec<String>,
}

impl DoorAnnouncement {
    /// The instance names being announced, for a status readout and a test.
    pub fn names(&self) -> Vec<String> {
        self.fullnames
            .iter()
            .map(|f| f.split('.').next().unwrap_or_default().to_owned())
            .collect()
    }
}

impl Drop for DoorAnnouncement {
    fn drop(&mut self) {
        for fullname in &self.fullnames {
            if let Ok(rx) = self.daemon.unregister(fullname) {
                let _ = rx.recv_timeout(Duration::from_secs(1));
            }
        }
        shutdown_daemon(&self.daemon);
    }
}

/// Announce an open door under each of `names` — one per paired device, each derived
/// by `kotton_crypto::door_announce_name` so that only that device recognises it —
/// at `ip:port`.
///
/// **Nameless by construction** ([`build_door_service_info`]): the instance and host
/// names are the derived name, the TXT record is empty, the one address is the IPv4
/// address on the router's interface, and the port is the door listener's ephemeral
/// one. No hostname, DID, device name, version string or hardware-derived address
/// goes out. IPv6 is left off deliberately: an EUI-64 address is the MAC in another
/// form, and it is the same on every network the device joins.
pub fn announce_door(names: &[String], ip: std::net::Ipv4Addr, port: u16) -> DiscoveryResult<DoorAnnouncement> {
    let daemon = ServiceDaemon::new()
        .map_err(|e| DiscoveryError::Failed(format!("mDNS daemon: {e}")))?;
    let mut fullnames = Vec::with_capacity(names.len());
    for name in names {
        let info = build_door_service_info(name, ip, port)?;
        fullnames.push(info.get_fullname().to_string());
        daemon
            .register(info)
            .map_err(|e| DiscoveryError::Failed(format!("register door: {e}")))?;
    }
    Ok(DoorAnnouncement { daemon, fullnames })
}

/// One door heard on the local network: the name it announced — which is all it
/// announced — and where it said it answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeardDoor {
    pub name: String,
    pub addresses: Vec<SocketAddr>,
}

/// Listen for open doors on the local network for `duration`
/// (`TASK-a-contacts-message-can-reach-their-device-over-the-local-network-while-its-door-is-open`).
///
/// Every door is returned, recognised or not: a door's name is a nonce that names
/// nobody, and which of them is a contact's is settled by a knock only that pair
/// derives, never by anything read here.
pub fn browse_doors(duration: Duration) -> DiscoveryResult<Vec<HeardDoor>> {
    let daemon = ServiceDaemon::new()
        .map_err(|e| DiscoveryError::Failed(format!("mDNS daemon: {e}")))?;
    let receiver = daemon
        .browse(DOOR_SERVICE_TYPE)
        .map_err(|e| DiscoveryError::Failed(format!("browse doors: {e}")))?;
    let mut doors: HashMap<String, HeardDoor> = HashMap::new();
    let start = std::time::Instant::now();
    while start.elapsed() < duration {
        let timeout = duration
            .saturating_sub(start.elapsed())
            .min(Duration::from_millis(200));
        if let Ok(ServiceEvent::ServiceResolved(info)) = receiver.recv_timeout(timeout) {
            let name = info.get_fullname().split('.').next().unwrap_or_default().to_owned();
            let port = info.get_port();
            let door = doors.entry(name.clone()).or_insert(HeardDoor { name, addresses: Vec::new() });
            for ip in info.get_addresses() {
                let at = SocketAddr::new(*ip, port);
                if !door.addresses.contains(&at) {
                    door.addresses.push(at);
                }
            }
        }
    }
    shutdown_daemon(&daemon);
    Ok(doors.into_values().filter(|d| !d.addresses.is_empty()).collect())
}

/// The one door record, factored out so its namelessness is testable without a
/// multicast socket.
fn build_door_service_info(
    name: &str,
    ip: std::net::Ipv4Addr,
    port: u16,
) -> DiscoveryResult<ServiceInfo> {
    let host = format!("{name}.local.");
    let props: HashMap<String, String> = HashMap::new();
    ServiceInfo::new(DOOR_SERVICE_TYPE, name, &host, IpAddr::V4(ip), port, props)
        .map_err(|e| DiscoveryError::Failed(format!("door ServiceInfo: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "binds the mDNS multicast socket on :5353 — the socket that raises the OS firewall dialog; run with --include-ignored"]
    fn test_mdns_discovery_creation() {
        let mut metadata = HashMap::new();
        metadata.insert("did".to_string(), "did:key:abc123".to_string());
        metadata.insert("version".to_string(), "0.1.0".to_string());

        let discovery = MdnsDiscovery::new("test-instance".to_string(), 8080, metadata);
        assert!(discovery.is_ok());
    }

    #[test]
    fn pairing_offer_advertisement_is_anonymous() {
        // RFC-0040 §1 + P2 done criterion: the advertisement carries no label and
        // no identifying hostname — only the opaque sid + version.
        let sid = "0123456789abcdef0123456789abcdef";
        let info = build_pairing_service_info(sid, 4433).expect("build offer");

        // Instance name is the sid; host name is the sid — never the machine's.
        assert!(
            info.get_fullname().starts_with(sid),
            "instance name must be the opaque sid: {}",
            info.get_fullname()
        );
        assert!(
            info.get_hostname().starts_with(sid),
            "host name must be the opaque sid, not the machine hostname: {}",
            info.get_hostname()
        );

        // TXT record is exactly {sid, v} — no label, no device name, no identity.
        let props = info.get_properties();
        assert_eq!(props.get_property_val_str("sid"), Some(sid));
        assert_eq!(props.get_property_val_str("v"), Some(PAIR_OFFER_VERSION));
        for prop in props.iter() {
            assert!(
                matches!(prop.key(), "sid" | "v"),
                "unexpected TXT key '{}' — the offer must be anonymous",
                prop.key()
            );
        }
    }

    /// Every field of a door record, as a passive listener on the network records it.
    fn door_fields(info: &ServiceInfo) -> Vec<String> {
        let mut fields = vec![
            info.get_fullname().to_owned(),
            info.get_hostname().to_owned(),
            info.get_port().to_string(),
        ];
        fields.extend(info.get_addresses().iter().map(|a| a.to_string()));
        fields.extend(info.get_properties().iter().map(|p| p.to_string()));
        fields
    }

    /// The door's announcement carries only its derived name, one IPv4 address and an
    /// ephemeral port — no TXT, no hostname, no identity. Two recordings on different
    /// networks share no field but the service type. Two on **one** network on two days
    /// (the name and the port both change with the day; see the device keeper's
    /// `an_always_door_reopens_on_a_fresh_port_each_day`) may share one more: the IPv4
    /// address the network leased this device. That address is the network's, and it is
    /// in every packet this device sends there, announced or not; the announcement adds
    /// nothing an observer on that network does not already hold. The test pins exactly
    /// that, so a field that starts to repeat — a TXT key, a host name, a port — is red.
    #[test]
    fn a_door_announcement_is_nameless_and_two_recordings_share_no_field() {
        let record = |name: &str, ip: [u8; 4], port| {
            build_door_service_info(name, std::net::Ipv4Addr::from(ip), port).expect("build")
        };
        // Names as `door_announce_name` makes them for two routers or two days, and the
        // address and ephemeral port each opening happened to get.
        let home_monday = record("5f1c0e7a9b2d4c6e8f0a1b2c3d4e5f60", [192, 168, 1, 23], 50112);
        let home_tuesday = record("9e4b27c0d1f35a6b7c8d9e0f1a2b3c4d", [192, 168, 1, 23], 43391);
        let cafe = record("c3a9e1f07b5d42e6a8b0c1d2e3f40516", [10, 0, 0, 5], 61877);

        for info in [&home_monday, &home_tuesday, &cafe] {
            let name = info.get_fullname().split('.').next().unwrap().to_owned();
            assert_eq!(info.get_hostname(), format!("{name}.local."));
            assert_eq!(info.get_type(), DOOR_SERVICE_TYPE);
            assert_eq!(info.get_properties().iter().count(), 0, "no TXT at all");
            assert!(info.get_addresses().iter().all(|a| a.is_ipv4()));
            assert_eq!(info.get_addresses().len(), 1, "one address, the lease's");
        }

        let shared = |a: &ServiceInfo, b: &ServiceInfo| -> Vec<String> {
            let (fa, fb) = (door_fields(a), door_fields(b));
            fa.into_iter()
                .filter(|f| fb.iter().any(|g| g == f || (g.contains(f.as_str()) && f.len() > 8)))
                .collect()
        };
        assert_eq!(shared(&home_monday, &cafe), Vec::<String>::new());
        assert_eq!(shared(&home_tuesday, &cafe), Vec::<String>::new());
        assert_eq!(
            shared(&home_monday, &home_tuesday),
            vec!["192.168.1.23".to_owned()],
            "on one network across two days only the network's own lease repeats"
        );
    }

    #[test]
    #[ignore = "binds the mDNS multicast socket on :5353 — the socket that raises the OS firewall dialog; run with --include-ignored"]
    fn holding_the_shutdown_receiver_gets_a_clean_confirmation() {
        // Regression for the spurious `[kuserd] ERROR exit: failed to send response
        // of shutdown` at ceremony teardown: mdns-sd's daemon thread sends one
        // `DaemonStatus::Shutdown` on the receiver returned by `shutdown()`, and
        // logs at ERROR if that receiver was already dropped. `shutdown_daemon`
        // holds it; prove the confirmation is delivered (and well within the 1s
        // bound the helper waits), so the send never fails.
        let daemon = ServiceDaemon::new().expect("mdns daemon");
        let rx = daemon.shutdown().expect("shutdown returns a receiver");
        let status = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("daemon thread confirms shutdown to a held receiver");
        assert!(matches!(status, mdns_sd::DaemonStatus::Shutdown));
    }

    #[test]
    #[ignore = "binds the mDNS multicast socket on :5353 — the socket that raises the OS firewall dialog; run with --include-ignored"]
    fn test_discover_peers() {
        let mut metadata = HashMap::new();
        metadata.insert("did".to_string(), "did:key:abc123".to_string());

        let discovery = MdnsDiscovery::new("test-instance".to_string(), 8080, metadata).unwrap();

        // The claim is that the call succeeds — how many peers a developer's LAN
        // happens to hold is not this test's business. (It previously asserted
        // `peers.is_empty() || !peers.is_empty()`, which is true of every Vec.)
        discovery.discover_peers().expect("discover_peers returns without error");
    }
}
