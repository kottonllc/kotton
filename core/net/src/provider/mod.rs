// SPDX-License-Identifier: AGPL-3.0-or-later
//! Network provider implementations

pub mod advertise;
pub mod discovery;
pub mod monitor;
pub mod rendezvous;
pub mod stun;
pub mod transport;

pub use advertise::{advertise_from_env, resolve_advertise};
pub use discovery::{
    advertise_pairing_offer, announce_door, browse_doors, browse_pairing_offers, DhtDiscovery, DiscoveredOffer,
    DoorAnnouncement, HeardDoor, MdnsDiscovery, PairingOffer, StaticDiscovery,
};
pub use monitor::{OsNetworkMonitor, StaticNetworkMonitor};
pub use rendezvous::{RendezvousClient, RendezvousError};
pub use stun::StunError;
pub use transport::{
    build_bootstrap_client_config, build_bootstrap_server_config,
    build_peer_client_config, build_peer_server_config,
    extract_ed25519_pubkey_from_cert,
    simultaneous_punch, BluetoothTransport, BootstrapCertVerifier, Ed25519DeviceCert,
    PairedDeviceVerifier, PunchError, PunchResult, PunchRole, QuicTransport, TcpTransport,
    TlsConfig, TurnAllocation, TurnClient, TurnError, TurnUdpSocket, WebRtcTransport,
    WebSocketTransport,
};
