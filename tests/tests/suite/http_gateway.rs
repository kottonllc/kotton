// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — HTTP gateway sidecar (RFC-0016)
//!
//! Covers:
//! 1. `WebShellSet` / `WebShellStatus` IPC round-trip.
//! 2. `REMOTE_ELIGIBLE` omits all `WebShell*` variants.
//!
//! The bearer-credential lifecycle that lived here (`WebShellAuth*`) was deleted
//! 2026-09-04 with the door (DEC-0053): a browser is paired like a device.


use crate::common::TestEnv;
use kotton_sys::ipc::IpcEndpoint;
use kotton_wire::ipc::REMOTE_ELIGIBLE;
use kotton_wire::{UserRequest, UserResponse};
use kotton_ipc::IpcClient;

const USER: &str = "httpgwtest";

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

/// `WebShellSet` persists configuration and `WebShellStatus` reads it back with
/// the correct values.
#[tokio::test]
async fn web_shell_set_and_status_roundtrip() {
    let mut env = TestEnv::spawn().await;
    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let token = env.client.session_token.clone().expect("session token");

    let mut client = auth_client(&env.endpoint, &token, None).await;

    // Enable with a non-default port and custom bind mode.
    let set_resp = client
        .send(&UserRequest::WebShellSet {
            enabled: Some(true),
            port: Some(9443),
            bind: Some("public".to_string()),
            static_dir: None,
            allow: None,
        })
        .await
        .expect("WebShellSet send");
    assert!(
        matches!(set_resp, UserResponse::Ok),
        "WebShellSet should return Ok, got {set_resp:?}"
    );

    // Read back and verify values are persisted.
    let status = client
        .send(&UserRequest::WebShellStatus)
        .await
        .expect("WebShellStatus send");

    match status {
        UserResponse::WebShellStatusResult {
            enabled,
            port,
            bind,
            ..
        } => {
            assert!(enabled, "should be enabled after WebShellSet");
            assert_eq!(port, 9443, "port should match");
            assert_eq!(bind, "public", "bind mode should match");
        }
        other => panic!("expected WebShellStatusResult, got {other:?}"),
    }
}

/// Full browser-credential lifecycle: add, list (verify present), revoke,
/// list again (verify absent).
#[test]
fn web_shell_variants_are_not_remote_eligible() {
    let required = [
        "WebShellSet",
        "WebShellStatus",
        "WebShellAuthAdd",
        "WebShellAuthList",
        "WebShellAuthRevoke",
        "WebShellAuthValidate",
    ];
    for variant in &required {
        assert!(
            !REMOTE_ELIGIBLE.contains(variant),
            "REMOTE_ELIGIBLE must not contain '{variant}'"
        );
    }
}
