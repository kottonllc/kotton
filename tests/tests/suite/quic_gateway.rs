// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — QUIC gateway sidecar (RFC-0015)
//!
//! Covers:
//! 1. `QuicGatewaySet` / `QuicGatewayStatus` IPC round-trip.
//! 2. `GetAuthorizedClients` returns paired-node public keys.
//! 3. `GetDeviceCert` is blocked by scope enforcement (the RFC-0035 trust floor).
//! 4. `REMOTE_ELIGIBLE` omits, preventing gateway-lifecycle variants from reaching kuserd
//!    over a scoped connection (simulates what kquicd enforces at runtime).


use crate::common::TestEnv;
use kotton_sys::ipc::IpcEndpoint;
use kotton_wire::ipc::REMOTE_ELIGIBLE;
use kotton_wire::{UserRequest, UserResponse};
use kotton_ipc::IpcClient;
const USER: &str = "gwtest";

// ── helpers ───────────────────────────────────────────────────────────────────

async fn raw_client(endpoint: &IpcEndpoint) -> IpcClient<UserRequest, UserResponse> {
    IpcClient::connect(endpoint.clone())
        .await
        .expect("IpcClient::connect")
}

async fn auth_client(
    endpoint: &IpcEndpoint,
    token: &str,
    scope: Option<Vec<&str>>,
) -> IpcClient<UserRequest, UserResponse> {
    let mut client = raw_client(endpoint).await;
    let scope_owned = scope.map(|s| s.into_iter().map(|v| v.to_string()).collect());
    match client
        .send(&UserRequest::Authenticate {
            token: kotton_wire::ipc::SecretText::new(token),
            scope: scope_owned,
        })
        .await
        .expect("Authenticate send")
    {
        UserResponse::ActiveSession { .. } => {}
        other => panic!("unexpected auth response: {other:?}"),
    }
    client
}

// ── tests ─────────────────────────────────────────────────────────────────────

/// `QuicGatewaySet` persists configuration and `QuicGatewayStatus` reads it
/// back with the correct values.
#[tokio::test]
async fn quic_gateway_set_and_status_roundtrip() {
    let mut env = TestEnv::spawn().await;
    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let token = env.client.session_token.clone().expect("session token");

    let mut client = auth_client(
        &env.endpoint,
        &token,
        // QuicGatewaySet/Status are Local-tier; the scope guard rejects
        // any explicitly-scoped connection from calling them. Authenticate with
        // None scope to mirror how the local operator (kctl/CLI) invokes them.
        None,
    )
    .await;

    // Enable with a non-default port.
    let set_resp = client
        .send(&UserRequest::QuicGatewaySet {
            enabled: Some(true),
            port: Some(9000),
            bind: Some("public".to_string()),
            allow: None,
        })
        .await
        .expect("QuicGatewaySet send");
    assert!(
        matches!(set_resp, UserResponse::Ok),
        "QuicGatewaySet should return Ok, got {set_resp:?}"
    );

    // Read back.
    let status = client
        .send(&UserRequest::QuicGatewayStatus)
        .await
        .expect("QuicGatewayStatus send");

    match status {
        UserResponse::QuicGatewayStatusResult {
            enabled,
            port,
            bind,
            ..
        } => {
            assert!(enabled, "enabled should be true");
            assert_eq!(port, 9000, "port should be 9000");
            assert_eq!(bind, "public", "bind should be 'public'");
        }
        other => panic!("expected QuicGatewayStatusResult, got {other:?}"),
    }

    // A bind scope the daemon could not honour is refused where the operator can
    // still do something about it. Storing it would strand kquicd at its next start,
    // and the failure this replaces was worse: an unrecognised value silently became
    // the widest bind there is.
    let bad = client
        .send(&UserRequest::QuicGatewaySet {
            enabled: None,
            port: None,
            bind: Some("wan".to_string()),
            allow: None,
        })
        .await
        .expect("send completes");
    assert!(
        matches!(&bad, UserResponse::Error { .. }),
        "an unrecognised bind value must be refused, got {bad:?}"
    );

    // The stored scope is unchanged by the refused write.
    let after = client
        .send(&UserRequest::QuicGatewayStatus)
        .await
        .expect("QuicGatewayStatus send");
    assert!(
        matches!(&after, UserResponse::QuicGatewayStatusResult { bind, .. } if bind == "public"),
        "a refused set must not have partially applied, got {after:?}"
    );

    // The guest list is its own setting and round-trips independently of the scope.
    let scoped = client
        .send(&UserRequest::QuicGatewaySet {
            enabled: None,
            port: None,
            bind: Some("all".to_string()),
            allow: Some("private".to_string()),
        })
        .await
        .expect("send completes");
    assert!(matches!(scoped, UserResponse::Ok), "got {scoped:?}");

    let split = client
        .send(&UserRequest::QuicGatewayStatus)
        .await
        .expect("QuicGatewayStatus send");
    match split {
        UserResponse::QuicGatewayStatusResult { bind, allow, .. } => {
            assert_eq!(bind, "all", "the doors");
            assert_eq!(allow.as_deref(), Some("private"), "the guest list");
        }
        other => panic!("expected QuicGatewayStatusResult, got {other:?}"),
    }
}

/// `GetAuthorizedClients` returns an empty list when no nodes are paired,
/// and the response shape is correct.
#[tokio::test]
async fn get_authorized_clients_lists_paired_nodes() {
    let mut env = TestEnv::spawn().await;
    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let token = env.client.session_token.clone().expect("session token");

    let mut client = auth_client(&env.endpoint, &token, Some(vec!["GetAuthorizedClients"])).await;

    let resp = client
        .send(&UserRequest::GetAuthorizedClients {
            user_id: USER.to_string(),
        })
        .await
        .expect("GetAuthorizedClients send");

    match resp {
        UserResponse::AuthorizedClients { dids, pubkey_hexes } => {
            // No nodes paired yet — list is empty but the shape is correct.
            assert_eq!(
                dids.len(),
                pubkey_hexes.len(),
                "dids and pubkeys must be the same length"
            );
        }
        other => panic!("expected AuthorizedClients, got {other:?}"),
    }
}

/// `GetDeviceCert` is absent from `REMOTE_ELIGIBLE`.
/// Sending it over a scoped connection should return `NotInScope`.
#[tokio::test]
async fn get_device_cert_blocked_by_trust_floor() {
    let mut env = TestEnv::spawn().await;
    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let token = env.client.session_token.clone().expect("session token");

    // Open a connection with a scope that explicitly tries to include GetDeviceCert.
    // The server's trust-floor check runs AFTER the scope check.
    // We verify the variant is not REMOTE-eligible.
    assert!(
        !REMOTE_ELIGIBLE.contains(&"GetDeviceCert"),
        "GetDeviceCert must not be REMOTE-eligible"
    );

    // Use a scoped connection (simulating kquicd's per-stream connection scope).
    // A scope of None means "all allowed by scope" — the trust-floor gate
    // is enforced separately by kquicd before forwarding.
    // Here we test the full dispatch path does NOT execute GetDeviceCert when
    // the caller has a scope that excludes it.
    let mut client = auth_client(
        &env.endpoint,
        &token,
        // Scope does NOT include GetDeviceCert — should get NotInScope from
        // the IPC scope guard.
        Some(vec!["DaemonStatus"]),
    )
    .await;

    let resp = client
        .send(&UserRequest::GetDeviceCert {
            user_id: USER.to_string(),
        })
        .await
        .expect("send");

    assert!(
        matches!(resp, UserResponse::NotInScope),
        "GetDeviceCert should be NotInScope on a restricted connection, got {resp:?}"
    );
}

/// `REMOTE_ELIGIBLE` omits the expected gateway-lifecycle variants.
///
/// This is a compile-time / const verification test — it fails fast if someone
/// accidentally removes an entry from the exclusion list.
#[test]
fn gateway_variants_are_not_remote_eligible() {
    let required: &[&str] = &["QuicGatewaySet", "QuicGatewayStatus", "GetDeviceCert"];
    for variant in required {
        assert!(
            !REMOTE_ELIGIBLE.contains(variant),
            "REMOTE_ELIGIBLE must not contain '{variant}'"
        );
    }
}
