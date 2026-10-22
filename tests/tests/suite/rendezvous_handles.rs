// SPDX-License-Identifier: AGPL-3.0-or-later
//! The rotating-handle round trip, against a real relay.
//!
//! `IDEA-rotating-rendezvous-handles`
//! rests on one claim about the server: a per-pair handle is a `did:key` whose key
//! signs the push, so **the relay verifies it exactly as it verifies a device DID
//! and needs no change at all**. That claim is what lets a deployed relay keep
//! working through the rollout, and it is worth checking against the relay rather
//! than against a reading of it.
//!
//! ```sh
//! just test_suite rendezvous_handles::a_pair_handle_is_published_and_found_through_a_real_relay
//! ```
//!
//! Starts a `kotton-relay` of its own (`common::relay::spawn`, which asks `common::bins`
//! for the built binary and fails naming it when it is not). `KOTTON_RELAY_ADDR` names a
//! relay already running to use in its place (`just dev_services` provides one).

use ed25519_dalek::SigningKey;
use kotton_net::rendezvous::client::RendezvousClient;
use kotton_peer::rendezvous;

use crate::common::relay;

async fn relay_url() -> (relay::Relay, String) {
    let (relay, addr) = relay::spawn().await;
    (relay, format!("http://{addr}"))
}

/// A publishes under the handle only B derives; B finds it there, having exchanged
/// nothing — and the relay, which was told neither device's identity, serves the
/// lookup as if the handle were an ordinary device DID.
#[tokio::test]
async fn a_pair_handle_is_published_and_found_through_a_real_relay() {
    let (_relay, url) = relay_url().await;
    let (a, b) = (
        SigningKey::generate(&mut rand::rngs::OsRng),
        SigningKey::generate(&mut rand::rngs::OsRng),
    );
    let now = rendezvous::unix_now();
    let address: std::net::SocketAddr = "203.0.113.9:7734".parse().unwrap();

    // A announces to B, under a label B can derive and nobody else can.
    let handle = rendezvous::publish_to(&a, &b.verifying_key().to_bytes(), now).unwrap();
    let publisher = RendezvousClient::new(&url, handle.did.to_string(), handle.signing_key);
    publisher
        .push(address, None, true)
        .await
        .expect("the relay accepts a push signed by the handle's own key — no server change");

    // B derives the same label from its own key and A's public key.
    let candidates =
        rendezvous::lookup_candidates(&b, &a.verifying_key().to_bytes(), now).unwrap();
    // The looker authenticates under its own handle for this pair, never under
    // a durable identity — a lookup is a route too (RFC-0083 R4).
    let own = rendezvous::publish_to(&b, &a.verifying_key().to_bytes(), now).unwrap();
    let looker = RendezvousClient::new(&url, own.did.to_string(), own.signing_key);
    let (found, _relay) = looker
        .lookup(&candidates[0])
        .await
        .expect("the handle B derives is the one A published under");

    assert_eq!(found, address);
}

/// Step 6's claim, measured the way step 3's was: a reservation labelled by a
/// pair handle is reserved, dialed, and served by the relay exactly as a durable
/// one — the reserve auth verifies against the handle's own key, the dial names
/// the handle, and the mTLS inside is still the device certificates. No relay
/// change.
#[tokio::test]
async fn a_relayed_circuit_connects_under_pair_handles() {
    use kotton_net::transport::quic::tls::{Ed25519DeviceCert, PairedDeviceVerifier};
    use kotton_net::transport::RelayClient;
    use std::collections::HashSet;
    use std::sync::{Arc, RwLock};

    let (_relay, url) = relay_url().await;
    let (a, b) = (
        SigningKey::generate(&mut rand::rngs::OsRng),
        SigningKey::generate(&mut rand::rngs::OsRng),
    );
    let (a_pub, b_pub) = (a.verifying_key().to_bytes(), b.verifying_key().to_bytes());
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    // A (target): hold a reservation under the handle only B derives, and serve
    // one echo request off it.
    let handle = rendezvous::reservation_handles(&a, &b_pub, rendezvous::unix_now())
        .into_iter()
        .next()
        .expect("a current-epoch reservation handle derives");
    let a_client = RelayClient::new(
        &url,
        handle.did.to_string(),
        handle.signing_key,
        Ed25519DeviceCert::from_signing_key(&a).unwrap(),
        PairedDeviceVerifier::new(
            Arc::new(RwLock::new(HashSet::from([b_pub]))),
            Arc::clone(&provider),
        ),
        Arc::clone(&provider),
    );
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let reservation = tokio::spawn(async move {
        let _ = a_client.run_reservation(tx).await;
    });
    let server = tokio::spawn(async move {
        let conn = rx.recv().await.expect("an inbound circuit arrives");
        conn.serve_one_request(|req| async move {
            let mut resp = b"echo:".to_vec();
            resp.extend_from_slice(&req);
            resp
        })
        .await
        .expect("the inbound circuit serves a request");
    });

    // B (dialer): the policy's first attempt is (own handle) → (A's handle).
    // Retry briefly — the reservation above lands asynchronously.
    let attempt = rendezvous::circuit_attempts(&b, &a_pub, rendezvous::unix_now())
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let b_client = RelayClient::new(
        &url,
        attempt.auth_did,
        attempt.auth_key,
        Ed25519DeviceCert::from_signing_key(&b).unwrap(),
        PairedDeviceVerifier::new(
            Arc::new(RwLock::new(HashSet::from([a_pub]))),
            Arc::clone(&provider),
        ),
        provider,
    );
    let mut conn = None;
    for _ in 0..20 {
        match b_client.dial(&attempt.target).await {
            Ok(c) => {
                conn = Some(c);
                break;
            }
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(250)).await,
        }
    }
    let conn = conn.expect("a dial naming the pair handle reaches the reservation");

    let resp = conn.request(b"ping").await.expect("request over the circuit");
    assert_eq!(resp, b"echo:ping");

    server.await.expect("the serve side completed");
    reservation.abort();
}

/// The coexistence window (step 4): a device that has not upgraded still looks for
/// the durable DID, and must still find an address there. When
/// `ANNOUNCE_DURABLE_DID` goes to `false` this assertion is what fails first.
/// The window closed (RFC-0083 R4): a durable `did:key` pushed to a relay by hand
/// is not something any peer asks for. The relay itself cannot tell a durable
/// identifier from a handle — both are `did:key` strings — so the property lives
/// on the client side, and this is where it is held.
#[tokio::test]
async fn a_durable_identifier_is_never_what_a_peer_looks_up() {
    let (_relay, url) = relay_url().await;
    let (a, b) = (
        SigningKey::generate(&mut rand::rngs::OsRng),
        SigningKey::generate(&mut rand::rngs::OsRng),
    );
    let address: std::net::SocketAddr = "203.0.113.10:7734".parse().unwrap();
    let a_durable = kotton_crypto::DidKeyMethod::from_public_key_bytes(&a.verifying_key().to_bytes())
        .unwrap()
        .to_string();

    // Pushed by hand, under the durable identity, as an un-upgraded device once did.
    let durable = RendezvousClient::new(&url, a_durable.clone(), a.clone());
    durable.push(address, None, true).await.unwrap();

    let candidates =
        rendezvous::lookup_candidates(&b, &a.verifying_key().to_bytes(), rendezvous::unix_now())
            .unwrap();
    assert!(
        !candidates.contains(&a_durable),
        "no peer asks a relay for a device by its durable identifier"
    );
    assert!(!candidates.is_empty(), "the handles are what it asks for");
}
