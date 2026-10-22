// SPDX-License-Identifier: AGPL-3.0-or-later
//! M36e — End-to-end QUIC-over-TURN integration test.
//!
//! Verifies the full relay path:
//!   TurnClient A allocates relay_A
//!   TurnClient B allocates relay_B
//!   A ← channel-bind → B via their respective relay addrs
//!   QUIC handshake A (client) → B (server) over the TURN relay
//!   Bidirectional data exchange to confirm both streams work
//!
//! # Running
//!
//! Requires a running TURN server (coturn). Start via `just dev_services`,
//! then run:
//!
//! ```sh
//! COTURN_ADDR=127.0.0.1:3478 \
//!   cargo test -p kotton-integration-tests -- turn_relay --include-ignored
//! ```
//!
//! Or use `just e2e_turn` which sets env vars and runs the docker stack.
//!
//! Environment variables:
//!   `COTURN_ADDR` — `host:port` of the TURN server  (required; the test fails naming it if absent)
//!   `COTURN_USER` — TURN username   (default: `kotton`)
//!   `COTURN_PASS` — TURN password   (default: `kottondev`)

use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use ed25519_dalek::SigningKey;
use kotton_net::{
    transport::quic::tls::{
        build_peer_client_config, build_peer_server_config, Ed25519DeviceCert, PairedDeviceVerifier,
    },
    TurnClient, TurnUdpSocket,
};

// ── helpers ───────────────────────────────────────────────────────────────────

fn random_signing_key() -> SigningKey {
    SigningKey::generate(&mut rand::rngs::OsRng)
}

fn make_verifier(
    peer_pubkey: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Arc<PairedDeviceVerifier> {
    let mut set = HashSet::new();
    set.insert(peer_pubkey);
    PairedDeviceVerifier::new(Arc::new(RwLock::new(set)), provider)
}

// ── test ──────────────────────────────────────────────────────────────────────

/// End-to-end QUIC handshake and bidirectional data exchange through a TURN relay.
///
/// Fails when `COTURN_ADDR` is not set: it is `#[ignore]`d, so asking for it is asking
/// for a TURN server, and a run that finds none has not tested anything.
#[tokio::test]
#[ignore = "requires a running TURN server; set COTURN_ADDR to enable"]
async fn quic_over_turn_relay() {
    let turn_addr: SocketAddr = std::env::var("COTURN_ADDR")
        .expect(
            "this test was asked for and has no TURN server to run against: set COTURN_ADDR to \
             host:port (e.g. 127.0.0.1:3478)",
        )
        .parse()
        .expect("COTURN_ADDR must be host:port (e.g. 127.0.0.1:3478)");
    let turn_user = std::env::var("COTURN_USER").unwrap_or_else(|_| "kotton".into());
    let turn_pass = std::env::var("COTURN_PASS").unwrap_or_else(|_| "kottondev".into());

    // ── Step 1: Device identities ─────────────────────────────────────────────
    let key_a = random_signing_key();
    let key_b = random_signing_key();
    let pubkey_a: [u8; 32] = key_a.verifying_key().to_bytes();
    let pubkey_b: [u8; 32] = key_b.verifying_key().to_bytes();

    // ── Step 2: Allocate TURN for both devices ────────────────────────────────
    let mut client_a = TurnClient::new(turn_addr, &turn_user, &turn_pass)
        .await
        .expect("TurnClient A: connect to TURN server");
    let mut client_b = TurnClient::new(turn_addr, &turn_user, &turn_pass)
        .await
        .expect("TurnClient B: connect to TURN server");

    let alloc_a = client_a.allocate().await.expect("TurnClient A: allocate");
    let alloc_b = client_b.allocate().await.expect("TurnClient B: allocate");

    let relay_a = alloc_a.relay_addr;
    let relay_b = alloc_b.relay_addr;
    println!("relay_a = {relay_a},  relay_b = {relay_b}");

    // ── Step 3: Cross-permission and channel-bind ─────────────────────────────
    // Each side must permit traffic originating from the other's relay IP.
    client_a
        .create_permission(relay_b.ip())
        .await
        .expect("A: CreatePermission for relay_b.ip()");
    client_b
        .create_permission(relay_a.ip())
        .await
        .expect("B: CreatePermission for relay_a.ip()");

    client_a
        .channel_bind(relay_b)
        .await
        .expect("A: ChannelBind relay_b");
    client_b
        .channel_bind(relay_a)
        .await
        .expect("B: ChannelBind relay_a");

    // ── Step 4: Extract sockets → TurnUdpSocket ───────────────────────────────
    let (raw_a, ch_a) = client_a
        .into_socket_and_channel(relay_b)
        .expect("A: into_socket_and_channel");
    let (raw_b, ch_b) = client_b
        .into_socket_and_channel(relay_a)
        .expect("B: into_socket_and_channel");

    // A's socket: local = relay_A, peer = relay_B
    let turn_a = Arc::new(TurnUdpSocket::new(raw_a, ch_a, relay_a, relay_b));
    // B's socket: local = relay_B, peer = relay_A
    let turn_b = Arc::new(TurnUdpSocket::new(raw_b, ch_b, relay_b, relay_a));

    // ── Step 5: mTLS configs (B = server, A = client) ─────────────────────────
    let provider_a = Arc::new(rustls::crypto::ring::default_provider());
    let provider_b = Arc::new(rustls::crypto::ring::default_provider());

    let cert_a = Ed25519DeviceCert::from_signing_key(&key_a).expect("cert A");
    let cert_b = Ed25519DeviceCert::from_signing_key(&key_b).expect("cert B");

    // Server B: presents cert_b, requires client to present a cert with pubkey_a
    let server_cfg = build_peer_server_config(
        &cert_b,
        make_verifier(pubkey_a, Arc::clone(&provider_b)),
        Arc::clone(&provider_b),
        None,
    )
    .expect("server TLS config");

    // Client A: presents cert_a, requires server to present a cert with pubkey_b
    let client_cfg = build_peer_client_config(
        &cert_a,
        make_verifier(pubkey_b, Arc::clone(&provider_a)),
        Arc::clone(&provider_a),
        None,
    )
    .expect("client TLS config");

    // ── Step 6: Quinn endpoints over TURN sockets ─────────────────────────────
    let ep_b = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server_cfg),
        turn_b,
        Arc::new(quinn::TokioRuntime),
    )
    .expect("server endpoint");

    let ep_a = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None, // client-only; no server_config
        turn_a,
        Arc::new(quinn::TokioRuntime),
    )
    .expect("client endpoint");

    // ── Step 7: QUIC handshake ────────────────────────────────────────────────
    // B accepts in a background task; A connects concurrently.
    let server_task = tokio::spawn(async move {
        let incoming = ep_b
            .accept()
            .await
            .expect("B: endpoint closed before accepting a connection");
        incoming
            .accept()
            .expect("B: accept() failed")
            .await
            .expect("B: QUIC handshake failed")
    });

    let conn_a = ep_a
        .connect_with(client_cfg, relay_b, "kotton-peer")
        .expect("A: connect_with config error")
        .await
        .expect("A: QUIC handshake over TURN failed");

    let conn_b = server_task.await.expect("server task panicked");

    println!("QUIC handshake over TURN: OK");

    // ── Step 8: Bidirectional data exchange ───────────────────────────────────
    const MSG_A_TO_B: &[u8] = b"ping-from-a-over-turn";
    const MSG_B_TO_A: &[u8] = b"pong-from-b-over-turn";

    // A → B
    {
        let mut send = conn_a.open_uni().await.expect("A: open_uni");
        send.write_all(MSG_A_TO_B).await.expect("A: write");
        send.finish().expect("A: finish");
    }
    {
        let mut recv = conn_b.accept_uni().await.expect("B: accept_uni");
        let data = recv.read_to_end(1024).await.expect("B: read_to_end");
        assert_eq!(data, MSG_A_TO_B, "A→B: data mismatch");
    }

    // B → A
    {
        let mut send = conn_b.open_uni().await.expect("B: open_uni");
        send.write_all(MSG_B_TO_A).await.expect("B: write");
        send.finish().expect("B: finish");
    }
    {
        let mut recv = conn_a.accept_uni().await.expect("A: accept_uni");
        let data = recv.read_to_end(1024).await.expect("A: read_to_end");
        assert_eq!(data, MSG_B_TO_A, "B→A: data mismatch");
    }

    println!("Bidirectional data exchange over TURN: OK");
}
