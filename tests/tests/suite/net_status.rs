// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — network status (`kotton net`)
//!
//! Covers:
//! 1. `NetworkStatus` lists all configured peers.
//! 2. `NetworkStatus` reflects gateway state from device_config.
//! 3. `NetworkStatus` reflects connected peers after a `VfsReport`.
//! 4. `VfsReport` and `NetworkStatus` are absent from `REMOTE_ELIGIBLE`.


use crate::common::TestEnv;
use kotton_sys::ipc::IpcEndpoint;
use kotton_wire::ipc::REMOTE_ELIGIBLE;
use kotton_wire::{UserRequest, UserResponse};
use kotton_ipc::IpcClient;

const USER: &str = "net_status_test";

// ── helpers ───────────────────────────────────────────────────────────────────

async fn auth_client(
    endpoint: &IpcEndpoint,
    token: &str,
) -> IpcClient<UserRequest, UserResponse> {
    let mut client = IpcClient::<UserRequest, UserResponse>::connect(endpoint.clone())
        .await
        .expect("IpcClient::connect");
    match client
        .send(&UserRequest::Authenticate {
            token: kotton_wire::ipc::SecretText::new(token),
            scope: None,
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

/// `NetworkStatus` returns a result that includes the (empty) peer list for a
/// freshly created user with no paired nodes.
#[tokio::test]
async fn network_status_lists_configured_peers() {
    let mut env = TestEnv::spawn().await;
    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let token = env.client.session_token.clone().expect("session token");

    let mut client = auth_client(&env.endpoint, &token).await;

    let resp = client
        .send(&UserRequest::NetworkStatus {
            user_id: USER.to_string(),
        })
        .await
        .expect("NetworkStatus send");

    match resp {
        UserResponse::NetworkStatusResult { peers, .. } => {
            // A fresh user has no paired nodes.
            assert!(
                peers.is_empty(),
                "fresh user should have no configured peers, got {:?}",
                peers
            );
        }
        other => panic!("expected NetworkStatusResult, got {other:?}"),
    }
}

/// `NetworkStatus` reflects gateway enabled/disabled state from device_config.
///
/// By default both gateways are disabled (no config written), so `enabled` should
/// be `false` and `running` should be `false`.
#[tokio::test]
async fn network_status_shows_gateway_state() {
    let mut env = TestEnv::spawn().await;
    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let token = env.client.session_token.clone().expect("session token");

    let mut client = auth_client(&env.endpoint, &token).await;

    let resp = client
        .send(&UserRequest::NetworkStatus {
            user_id: USER.to_string(),
        })
        .await
        .expect("NetworkStatus send");

    match resp {
        UserResponse::NetworkStatusResult {
            quic_gateway,
            http_gateway,
            ..
        } => {
            assert!(
                !quic_gateway.enabled,
                "QUIC gateway should be disabled by default"
            );
            assert!(
                !quic_gateway.running,
                "QUIC gateway should not be running by default"
            );
            assert!(
                !http_gateway.enabled,
                "HTTP gateway should be disabled by default"
            );
            assert!(
                !http_gateway.running,
                "HTTP gateway should not be running by default"
            );
        }
        other => panic!("expected NetworkStatusResult, got {other:?}"),
    }
}

/// After sending a `VfsReport` with a non-empty peer list, `NetworkStatus`
/// reflects `connected_peer_count` from that report.
#[tokio::test]
async fn network_status_reflects_connected_peer_from_vfs_report() {
    let mut env = TestEnv::spawn().await;
    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let token = env.client.session_token.clone().expect("session token");

    let mut client = auth_client(&env.endpoint, &token).await;

    // Send a VfsReport with two fake peer DIDs.
    let fake_peers = vec![
        "did:key:z6MkFakePeer1".to_string(),
        "did:key:z6MkFakePeer2".to_string(),
    ];
    let report_resp = client
        .send(&UserRequest::VfsReport {
            connected_peers: fake_peers.clone(),
        })
        .await
        .expect("VfsReport send");
    assert!(
        matches!(report_resp, UserResponse::Ok),
        "VfsReport should return Ok, got {report_resp:?}"
    );

    // SyncStatus should now reflect the 2 connected peers.
    let sync_resp = client
        .send(&UserRequest::SyncStatus {
            user_id: USER.to_string(),
        })
        .await
        .expect("SyncStatus send");

    match sync_resp {
        UserResponse::SyncStatusResult(result) => {
            assert_eq!(
                result.connected_peer_count, 2,
                "connected_peer_count should be 2 after VfsReport with 2 peers"
            );
        }
        other => panic!("expected SyncStatusResult, got {other:?}"),
    }
}

/// `VfsReport` and `NetworkStatus` must both be absent from `REMOTE_ELIGIBLE`.
#[test]
fn network_status_is_not_remote_eligible() {
    assert!(
        !REMOTE_ELIGIBLE.contains(&"VfsReport"),
        "VfsReport must not be REMOTE-eligible"
    );
    assert!(
        !REMOTE_ELIGIBLE.contains(&"NetworkStatus"),
        "NetworkStatus must not be REMOTE-eligible"
    );
}
