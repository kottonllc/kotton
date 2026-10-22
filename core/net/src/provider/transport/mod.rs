// SPDX-License-Identifier: AGPL-3.0-or-later
//! Network transport implementations

pub mod bind;
pub mod bluetooth;
pub mod quic;
pub mod relayed;
pub mod tcp;
pub mod turn;
pub mod webrtc;
pub mod websocket;

pub use bind::outbound_bind_addr;
pub use bluetooth::BluetoothTransport;
pub use relayed::{
    rendezvous_dial, rendezvous_reserve, RelayClient, RelayedByteStream, RelayedConnection,
    RelayedDial, RelayedInbound, RendezvousReservation,
};
pub use quic::{
    build_bootstrap_client_config, build_bootstrap_server_config,
    build_peer_client_config, build_peer_server_config,
    extract_ed25519_pubkey_from_cert,
    simultaneous_punch, BootstrapCertVerifier, Ed25519DeviceCert, PairedDeviceVerifier, PunchError,
    PunchResult, PunchRole, QuicTransport,
};
pub use tcp::{TcpTransport, TlsConfig};
pub use turn::{TurnAllocation, TurnClient, TurnError, TurnUdpSocket};
pub use webrtc::WebRtcTransport;
pub use websocket::WebSocketTransport;
