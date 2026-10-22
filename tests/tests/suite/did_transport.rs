// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — RFC-0004: DID-Addressed Transport
//!
//! All tests are pure in-process (no external services). An in-process axum
//! mock relay handles rendezvous and inbox tests so `cargo test` works with
//! zero external infrastructure.
//!
//! Task 9 (TURN fallback) lives in `turn_relay.rs` — no new code needed here.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};

use axum::{
    extract::{Path, State},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use ed25519_dalek::SigningKey;
use kotton_sys::net::{Address, Discovery, Transport};
use kotton_wire::rendezvous::{RendezvousErrorResponse, RendezvousPushResponse};
use kotton_wire::RendezvousLookupResponse;
use kotton_net::{
    rendezvous::client::RendezvousClient, Ed25519DeviceCert, QuicTransport,
};
use kotton_schemas::AppManifest;
use rand::rngs::OsRng;

// ---------------------------------------------------------------------------
// Mock relay helpers (shared by tasks 7 and 8)
// ---------------------------------------------------------------------------

#[derive(Default, Clone)]
struct MockRelayState {
    /// fingerprint → addr string
    addresses: Arc<Mutex<HashMap<String, String>>>,
}

async fn mock_push_handler(
    State(state): State<MockRelayState>,
    Json(payload): Json<kotton_wire::rendezvous::RendezvousPushPayload>,
) -> Json<RendezvousPushResponse> {
    state
        .addresses
        .lock()
        .unwrap()
        .insert(payload.fingerprint, payload.addr);
    Json(RendezvousPushResponse { expires_in: 300 })
}

async fn mock_lookup_handler(
    State(state): State<MockRelayState>,
    Path(fp): Path<String>,
) -> axum::response::Response {
    let addr = state.addresses.lock().unwrap().get(&fp).cloned();
    match addr {
        Some(addr) => (
            axum::http::StatusCode::OK,
            Json(RendezvousLookupResponse {
                addr,
                expires_in: 300,
                turn_relay_addr: None,
                online: true,
                relayable: false,
            }),
        )
            .into_response(),
        None => (
            axum::http::StatusCode::NOT_FOUND,
            Json(RendezvousErrorResponse {
                error: "not found".to_string(),
            }),
        )
            .into_response(),
    }
}

async fn spawn_mock_relay() -> (String, MockRelayState, tokio::task::JoinHandle<()>) {
    let state = MockRelayState::default();
    let app = Router::new()
        .route("/push", post(mock_push_handler))
        .route("/lookup/:fp", get(mock_lookup_handler))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{port}");
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (base_url, state, handle)
}

// ---------------------------------------------------------------------------
// Task 1 — Ed25519DeviceCert pubkey invariant
// ---------------------------------------------------------------------------

#[test]
fn cert_pubkey_matches_signing_key() {
    let key = SigningKey::generate(&mut OsRng);
    let cert =
        Ed25519DeviceCert::from_signing_key(&key).expect("Ed25519DeviceCert::from_signing_key");
    assert_eq!(
        cert.public_key_bytes,
        key.verifying_key().to_bytes(),
        "cert.public_key_bytes must equal key.verifying_key().to_bytes()"
    );
}

// ---------------------------------------------------------------------------
// Task 2 — QUIC mTLS bidirectional data
// ---------------------------------------------------------------------------

#[tokio::test]
async fn quic_mtls_bidirectional_data() {
    let key_a = SigningKey::generate(&mut OsRng);
    let key_b = SigningKey::generate(&mut OsRng);
    let pub_a = key_a.verifying_key().to_bytes();
    let pub_b = key_b.verifying_key().to_bytes();

    let allowlist_a = Arc::new(RwLock::new(HashSet::from([pub_b])));
    let allowlist_b = Arc::new(RwLock::new(HashSet::from([pub_a])));

    let transport_a = QuicTransport::new_peer(&key_a, allowlist_a).unwrap();
    let transport_b = QuicTransport::new_peer(&key_b, allowlist_b).unwrap();

    let listener = transport_a
        .listen(&Address::Quic("127.0.0.1:0".parse().unwrap()))
        .await
        .unwrap();
    let server_addr = listener.local_addr().clone();

    // One-shot channel: client signals server once it has received the echo,
    // so the server keeps its Quinn connection alive until delivery is certain.
    let (echo_received_tx, echo_received_rx) = tokio::sync::oneshot::channel::<()>();

    // Server: accept one connection, receive a message, echo it back.
    let server = tokio::spawn(async move {
        let conn = listener.accept().await.expect("server accept");
        let data = conn.receive().await.expect("server receive");
        conn.send(&data).await.expect("server echo");
        // Hold connection alive until client confirms receipt.
        let _ = echo_received_rx.await;
        data
    });

    let conn_b = transport_b
        .connect(&server_addr)
        .await
        .expect("client connect");
    let msg = b"hello quic mTLS";
    conn_b.send(msg).await.expect("client send");
    let echo = conn_b.receive().await.expect("client receive");
    // Signal server it may now drop the connection.
    let _ = echo_received_tx.send(());

    assert_eq!(echo, msg, "echo must match sent payload");

    let server_received = server.await.expect("server task");
    assert_eq!(server_received, msg, "server received the same payload");
}

// ---------------------------------------------------------------------------
// Task 3 — Allowlist rejection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn quic_mtls_rejects_unpaired_device() {
    let key_a = SigningKey::generate(&mut OsRng);
    let key_b = SigningKey::generate(&mut OsRng);
    let key_c = SigningKey::generate(&mut OsRng);
    let pub_a = key_a.verifying_key().to_bytes();
    let pub_b = key_b.verifying_key().to_bytes();

    // A allows only B; C is unknown to A.
    let allowlist_a = Arc::new(RwLock::new(HashSet::from([pub_b])));
    // C trusts A so C's TLS verifier accepts A's server cert — only A's
    // verifier of C's client cert matters for the rejection.
    let allowlist_c = Arc::new(RwLock::new(HashSet::from([pub_a])));

    let transport_a = QuicTransport::new_peer(&key_a, allowlist_a).unwrap();
    let transport_c = QuicTransport::new_peer(&key_c, allowlist_c).unwrap();

    let listener = transport_a
        .listen(&Address::Quic("127.0.0.1:0".parse().unwrap()))
        .await
        .unwrap();
    let server_addr = listener.local_addr().clone();

    // C attempts to connect; A rejects C's client cert at the TLS handshake.
    let result = transport_c.connect(&server_addr).await;
    assert!(
        result.is_err(),
        "unpaired device must be rejected at TLS handshake"
    );
}

// ---------------------------------------------------------------------------
// Task 4 — Revocation (live allowlist update)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn quic_mtls_revocation_live() {
    let key_a = SigningKey::generate(&mut OsRng);
    let key_b = SigningKey::generate(&mut OsRng);
    let pub_a = key_a.verifying_key().to_bytes();
    let pub_b = key_b.verifying_key().to_bytes();

    let allowlist_a = Arc::new(RwLock::new(HashSet::from([pub_b])));
    let allowlist_b = Arc::new(RwLock::new(HashSet::from([pub_a])));

    // Keep a clone of allowlist_a to modify after transport creation.
    let transport_a = QuicTransport::new_peer(&key_a, Arc::clone(&allowlist_a)).unwrap();
    let transport_b = QuicTransport::new_peer(&key_b, allowlist_b).unwrap();

    let listener = transport_a
        .listen(&Address::Quic("127.0.0.1:0".parse().unwrap()))
        .await
        .unwrap();
    let server_addr = listener.local_addr().clone();

    // Pre-revocation: connection from B must succeed.
    let (conn_result, _server_conn) =
        tokio::join!(transport_b.connect(&server_addr), listener.accept());
    assert!(
        conn_result.is_ok(),
        "pre-revocation connection must succeed; error: {:?}",
        conn_result.err()
    );

    // Revoke B — write to the shared allowlist without restarting any process.
    allowlist_a.write().unwrap().remove(&pub_b);

    // Post-revocation: B's next connection must be rejected.
    let result = transport_b.connect(&server_addr).await;
    assert!(
        result.is_err(),
        "post-revocation connection must fail without daemon restart"
    );
}

// ---------------------------------------------------------------------------
// Task 7 — Rendezvous push + lookup (in-process mock relay)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rendezvous_push_lookup_mock() {
    let (base_url, _state, _handle) = spawn_mock_relay().await;

    let key = SigningKey::generate(&mut OsRng);
    let fingerprint = format!(
        "did:key:z6Mk{}",
        hex::encode(&key.verifying_key().to_bytes()[..8])
    );
    let client = RendezvousClient::new(&base_url, fingerprint.clone(), key);

    let external_addr: SocketAddr = "203.0.113.45:51820".parse().unwrap();
    let ttl = client.push(external_addr, None, false).await.expect("push");
    assert!(ttl > 0, "server must return a positive TTL");

    let (returned_addr, relay_addr) = client.lookup(&fingerprint).await.expect("lookup");
    assert_eq!(
        returned_addr, external_addr,
        "lookup must return the pushed address"
    );
    assert!(relay_addr.is_none(), "no TURN relay was pushed");
}

// ---------------------------------------------------------------------------
// Task 8 — the relay inbox — was deleted 2026-09-04 (RFC-0083 R1): the relay
// carries and keeps nothing, so there is no inbox to be opaque about.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Task 9 — TURN fallback: see turn_relay.rs
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Task 10 — mDNS loopback peer discovery
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires mDNS multicast on loopback; may not be available in all CI environments"]
fn mdns_loopback_peer_discovery() {
    use kotton_net::MdnsDiscovery;

    let did_a = "did:key:z6MkTestNodeA".to_string();
    let did_b = "did:key:z6MkTestNodeB".to_string();

    let mut meta_a = HashMap::new();
    meta_a.insert("did".to_string(), did_a.clone());
    let mut meta_b = HashMap::new();
    meta_b.insert("did".to_string(), did_b.clone());

    let _discovery_a = MdnsDiscovery::new("kotton-test-peer-a".to_string(), 51824, meta_a)
        .expect("create mDNS discovery A");
    let discovery_b = MdnsDiscovery::new("kotton-test-peer-b".to_string(), 51825, meta_b)
        .expect("create mDNS discovery B");

    // Allow time for mDNS advertisement to propagate on the local network.
    std::thread::sleep(std::time::Duration::from_secs(3));

    let peers = discovery_b.discover_peers().expect("discover peers");
    let found = peers
        .iter()
        .any(|p| p.metadata.get("did").map(|d| d == &did_a).unwrap_or(false));
    assert!(found, "peer A should be discoverable via mDNS on loopback");
}

// ---------------------------------------------------------------------------
// Task 11 — WASM network capability: defaults to false when not declared
// ---------------------------------------------------------------------------

const MANIFEST_NO_NETWORK_CAPS: &str = r#"
[app]
id = "test.kotton.app.no-net"
name = "No-network test app"
version = "0.1.0"

[[permissions]]
type = "storage:read"
path = "/test"
"#;

#[test]
fn wasm_network_cap_not_set_defaults_false() {
    let manifest = AppManifest::from_toml(MANIFEST_NO_NETWORK_CAPS).expect("manifest must parse");
    assert!(
        !manifest.call_initiate,
        "call_initiate must default to false when not declared in manifest"
    );
    assert!(
        !manifest.call_receive,
        "call_receive must default to false when not declared in manifest"
    );
}
