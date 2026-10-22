// SPDX-License-Identifier: AGPL-3.0-or-later
//! Presence push + lookup against a real relay (RFC-0024 sprint 07 item 1).
//!
//! Verifies the registrar identity fix: a node registers presence under
//! `did:key(signing-key)` — the same DID peers look it up by and the relay derives
//! push auth from — and is then found by that DID. Catches the bug where presence
//! was registered under the stable identity DID while signed by the (different)
//! ephemeral signing key, which the relay rejected (401).
//!
//! # Running
//!
//! ```sh
//! just test_suite relay_presence::presence_push_and_lookup_via_real_relay
//! ```
//!
//! Starts a `kotton-relay` of its own (`common::relay::spawn`, which asks `common::bins`
//! for the built binary and fails naming it when it is not). `KOTTON_RELAY_ADDR` names a
//! relay already running to use in its place.

use std::net::SocketAddr;

use ed25519_dalek::SigningKey;
use kotton_crypto::DidKeyMethod;
use kotton_net::rendezvous::client::RendezvousClient;

fn did_of(sk: &SigningKey) -> String {
    DidKeyMethod::from_public_key_bytes(&sk.verifying_key().to_bytes())
        .unwrap()
        .to_string()
}

/// Push presence, then look it up by the signing-key DID.
///
/// Runs against a relay the test starts, or the one `KOTTON_RELAY_ADDR` names.
#[tokio::test]
async fn presence_push_and_lookup_via_real_relay() {
    let (_relay, relay_addr) = crate::common::relay::spawn().await;
    let relay_url = format!("http://{relay_addr}");

    let key_a = SigningKey::generate(&mut rand::rngs::OsRng);
    let key_b = SigningKey::generate(&mut rand::rngs::OsRng);
    let did_a = did_of(&key_a);

    // A registers presence under did:key(A) — the push auth must verify (this is the
    // fix: fingerprint == did:key(signing key), so the relay's derived key matches).
    let coord_a = RendezvousClient::new(relay_url.clone(), did_a.clone(), key_a);
    let reflexive: SocketAddr = "203.0.113.7:5555".parse().unwrap();
    let ttl = coord_a
        .push(reflexive, None, true)
        .await
        .expect("presence push accepted by relay");
    assert!(ttl > 0, "relay returned a positive TTL");

    // B looks A up by the same DID and finds the registered address.
    let coord_b = RendezvousClient::new(relay_url.clone(), did_of(&key_b), key_b);
    let (addr, _turn) = coord_b.lookup(&did_a).await.expect("lookup finds A");
    assert_eq!(addr, reflexive, "looked-up reflexive address matches the push");

    println!("presence push + lookup via real relay: OK");
}
