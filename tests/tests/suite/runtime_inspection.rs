// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — runtime inspection (`kotton sidecars`, `kotton ipc`)
//!
//! Covers:
//! 1. `DaemonSidecars` returns a row for the running `kuserd` sidecar.
//! 2. `IpcSessions` includes the caller's session after authentication.
//! 3. Both `DaemonSidecars` and `IpcSessions` are absent from `REMOTE_ELIGIBLE`.


use crate::common::TestEnv;
use kotton_sys::ipc::IpcEndpoint;
use kotton_wire::ipc::REMOTE_ELIGIBLE;
use kotton_wire::{UserRequest, UserResponse};
use kotton_ipc::IpcClient;

const USER: &str = "ri_test";

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

/// `DaemonSidecars` returns at least one entry (`kuserd`) with `running = true`.
///
/// The supervision tree tracking is seeded at daemon startup, so a freshly
/// spawned test daemon should always report `kuserd` as running.
#[tokio::test]
async fn daemon_sidecars_lists_running_sidecar() {
    let mut env = TestEnv::spawn().await;
    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let token = env.client.session_token.clone().expect("session token");

    let mut client = auth_client(&env.endpoint, &token).await;

    let resp = client
        .send(&UserRequest::DaemonSidecars)
        .await
        .expect("DaemonSidecars send");

    let sidecars = match resp {
        UserResponse::DaemonSidecarsResult { sidecars } => sidecars,
        other => panic!("unexpected response: {other:?}"),
    };

    let kuserd_row = sidecars
        .iter()
        .find(|s| s.name == "kuserd")
        .expect("kuserd must appear in DaemonSidecars result");

    assert!(kuserd_row.running, "kuserd row must report running = true");
    assert_eq!(kuserd_row.role, "user daemon");
    assert!(
        kuserd_row.pid.is_some(),
        "kuserd row must have a non-None pid"
    );
}

/// After authenticating, `IpcSessions` should include at least one entry whose
/// `user_id` matches the authenticated user and whose `request_count` is >= 1.
#[tokio::test]
async fn ipc_sessions_shows_authenticated_connection() {
    let mut env = TestEnv::spawn().await;
    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let token = env.client.session_token.clone().expect("session token");

    // Open a new authenticated connection.
    let mut client = auth_client(&env.endpoint, &token).await;

    // Send one additional request to bump the counter.
    let _status = client
        .send(&UserRequest::DaemonStatus)
        .await
        .expect("DaemonStatus send");

    // Now query sessions — our entry should be present.
    let resp = client
        .send(&UserRequest::IpcSessions)
        .await
        .expect("IpcSessions send");

    let sessions = match resp {
        UserResponse::IpcSessionsResult { sessions } => sessions,
        other => panic!("unexpected response: {other:?}"),
    };

    let our_session = sessions
        .iter()
        .find(|s| s.user_id == USER)
        .expect("IpcSessions must include our authenticated session");

    assert!(
        our_session.request_count >= 1,
        "request_count should be >= 1 after at least one request, got {}",
        our_session.request_count
    );

    assert_eq!(
        our_session.token_prefix.len(),
        8,
        "token_prefix must be 8 chars"
    );
}

/// `DaemonSidecars` and `IpcSessions` must both be absent from `REMOTE_ELIGIBLE`.
///
/// These expose internal runtime state and must never be callable over a
/// remote gateway connection.
#[test]
fn ipc_sessions_is_not_remote_eligible() {
    assert!(
        !REMOTE_ELIGIBLE.contains(&"DaemonSidecars"),
        "DaemonSidecars must not be REMOTE-eligible"
    );
    assert!(
        !REMOTE_ELIGIBLE.contains(&"IpcSessions"),
        "IpcSessions must not be REMOTE-eligible"
    );
}
