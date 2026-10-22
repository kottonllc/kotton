// SPDX-License-Identifier: AGPL-3.0-or-later
//! The one FROST test that needs a real network.
//!
//! The other six moved to `core/org` with the code they exercise — they are pure
//! unit tests and had no reason to sit here. This one drives two participants
//! over loopback QUIC via `open_pair_listener`, which lives in this crate, so
//! moving it would make `org` depend on the runtime.
//!
//! When `pairing` moves, this follows it.

use kotton_crypto::frost;
use kotton_org::frost_signing::*;
use ed25519_dalek::{Signature, Verifier};
use kotton_crypto::DidKeyMethod;

/// Verify a 64-byte aggregate as a standard Ed25519 signature under the group
/// key. Deliberately duplicated from `core/org`'s test module rather than
/// exported: six lines of test scaffolding is a smaller cost than widening a
/// crate's public API to serve a test in another crate.
fn verify_under_group(did: &str, sig: &[u8], message: &[u8]) {
    let vk = DidKeyMethod::to_public_key(&did.parse().unwrap()).unwrap();
    let arr: [u8; 64] = sig.try_into().expect("64-byte signature");
    vk.verify(message, &Signature::from_bytes(&arr))
        .expect("threshold signature verifies under the group key");
}

#[tokio::test]
async fn distributed_two_of_two_signs_over_loopback_quic() {
    use crate::pairing::open_pair_listener;
    use ed25519_dalek::SigningKey;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    let (shares, pubkey_package, did) = frost::generate_key_shares(2, 2).unwrap();
    let coordinator_share = shares[0].1.clone();
    let participant_share = shares[1].1.clone();

    // The participant binds a bootstrap QUIC listener (its share lives here).
    let participant_key = SigningKey::from_bytes(&[42u8; 32]);
    let (_code, listen_addr, _expires, endpoint) =
        open_pair_listener(&participant_key, 0, 30).await.unwrap();
    let dial = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_addr.port());

    // Participant: accept one connection and serve a single signing session.
    let participant = tokio::spawn(async move {
        let incoming = endpoint.accept().await.expect("a connection arrives");
        let connection = incoming.await.expect("handshake completes");
        serve_frost_signing(&connection, &participant_share)
            .await
            .expect("participant serves the signing rounds");
        connection.closed().await;
    });

    // Coordinator: dial the participant, then drive both rounds across the
    // local share + the remote QUIC-backed share.
    let coordinator_key = SigningKey::from_bytes(&[7u8; 32]);
    let client_config = {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let device_cert =
            kotton_net::Ed25519DeviceCert::from_signing_key(&coordinator_key)
                .unwrap();
        kotton_net::build_bootstrap_client_config(&device_cert, provider).unwrap()
    };
    // Loopback: the dial target is 127.0.0.1, and a wildcard client socket
    // buys nothing here but a firewall dialog on every run.
    let client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let connection = client
        .connect_with(client_config, dial, "kotton-pairing")
        .unwrap()
        .await
        .expect("coordinator connects to participant");

    let local = LocalFrostSigner::new(coordinator_share);
    let remote = QuicFrostSigner::open(&connection).await.unwrap();
    let signers: Vec<&dyn FrostSigner> = vec![&local, &remote];

    let message = b"constitutional act co-signed across two nodes";
    let sig = coordinate_threshold_sign(&signers, &pubkey_package, message)
        .await
        .expect("distributed signing succeeds");

    assert_eq!(sig.len(), 64);
    verify_under_group(&did, &sig, message);

    connection.close(0u32.into(), b"done");
    participant.await.unwrap();
}
