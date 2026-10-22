// SPDX-License-Identifier: AGPL-3.0-or-later
//! End-to-end relayed-circuit test (RFC-0024 sprint 07 item 2).
//!
//! Drives two `RelayClient`s against a **real** `kotton-relay` process: a target
//! holds a reservation, a dialer opens a circuit, and they complete mTLS over the
//! relay-bridged WebSocket and exchange a request/response. This verifies the full
//! node ↔ relay ↔ node relayed path against the actual relay binary — the relay
//! forwards only opaque frames, so the working inner mTLS proves it can neither read
//! the traffic nor impersonate either peer.
//!
//! # Running
//!
//! ```sh
//! just test_suite relay_circuit::relayed_mtls_circuit_through_real_relay
//! ```
//!
//! Starts a `kotton-relay` of its own (`common::relay::spawn`, which asks `common::bins`
//! for the built binary and fails naming it when it is not). `KOTTON_RELAY_ADDR` names a
//! relay already running to use in its place.
//! `just e2e_relay` builds the relay and runs the relay suites.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use kotton_crypto::DidKeyMethod;
use kotton_net::transport::quic::tls::{Ed25519DeviceCert, PairedDeviceVerifier};
use kotton_net::transport::relayed::RelayClient;

fn random_key() -> SigningKey {
    SigningKey::generate(&mut rand::rngs::OsRng)
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn verifier(peer: [u8; 32], p: Arc<rustls::crypto::CryptoProvider>) -> Arc<PairedDeviceVerifier> {
    PairedDeviceVerifier::new(Arc::new(RwLock::new(HashSet::from([peer]))), p)
}

fn did_of(pubkey: &[u8; 32]) -> String {
    DidKeyMethod::from_public_key_bytes(pubkey).unwrap().to_string()
}

/// Full relayed mTLS circuit through a real relay process.
///
/// Runs against a relay the test starts, or the one `KOTTON_RELAY_ADDR` names.
#[tokio::test]
async fn relayed_mtls_circuit_through_real_relay() {
    let (_relay, relay_addr) = crate::common::relay::spawn().await;
    let relay_url = format!("http://{relay_addr}");

    // Two paired devices: A dials, B is the relayable target.
    let key_a = random_key();
    let key_b = random_key();
    let pub_a = key_a.verifying_key().to_bytes();
    let pub_b = key_b.verifying_key().to_bytes();
    let did_a = did_of(&pub_a);
    let did_b = did_of(&pub_b);

    let cert_a = Ed25519DeviceCert::from_signing_key(&key_a).unwrap();
    let cert_b = Ed25519DeviceCert::from_signing_key(&key_b).unwrap();
    let pa = provider();
    let pb = provider();

    // B trusts A; A trusts B (the paired-key allowlists).
    let client_a = RelayClient::new(
        &relay_url,
        did_a.clone(),
        key_a,
        cert_a,
        verifier(pub_b, Arc::clone(&pa)),
        pa,
    );
    let client_b = RelayClient::new(
        &relay_url,
        did_b.clone(),
        key_b,
        cert_b,
        verifier(pub_a, Arc::clone(&pb)),
        pb,
    );

    // B holds a reservation and serves one echo request over the inbound circuit.
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let did_a_seen_by_b = did_a.clone();
    let reservation = tokio::spawn(async move { client_b.run_reservation(tx).await });
    let serve = tokio::spawn(async move {
        let conn = rx.recv().await.expect("B: inbound relayed circuit");
        assert_eq!(conn.peer_did(), did_a_seen_by_b, "B sees A's verified DID");
        let served = conn
            .serve_one_request(|req| async move {
                let mut resp = b"echo:".to_vec();
                resp.extend_from_slice(&req);
                resp
            })
            .await
            .expect("B: serve");
        assert!(served);
    });

    // Let B's reservation register on the relay.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // A dials B through the relay and exchanges a request.
    let conn = client_a.dial(&did_b).await.expect("A: dial via relay");
    assert_eq!(conn.peer_did(), did_b, "A sees B's verified DID");
    let resp = conn.request(b"ping").await.expect("A: request");
    assert_eq!(resp, b"echo:ping");

    serve.await.expect("B serve task");
    reservation.abort(); // stop the reservation loop
    println!("relayed mTLS circuit through real relay: OK");
}
