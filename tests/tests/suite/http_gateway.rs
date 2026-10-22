// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — HTTP gateway sidecar (RFC-0016)
//!
//! Covers:
//! 1. `WebShellSet` / `WebShellStatus` IPC round-trip.
//! 2. `REMOTE_ELIGIBLE` omits all `WebShell*` variants.
//!
//! The bearer-credential lifecycle that lived here (`WebShellAuth*`) was deleted
//! 2026-09-04 with the door (DEC-0053): a browser is paired like a device.


use crate::common::{khttpd, TestEnv};
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


/// A sidecar's bootstrap token authenticates only from the process it was minted
/// for: a second process presenting the same token is refused at the socket.
///
/// This is the decision `TASK-sockets-take-the-callers-word-for-who-it-is` asked
/// for, on kuserd's live path and between two real processes. The real `khttpd`
/// child authenticates on startup, so by the time `spawn_as` returns the token
/// is bound to khttpd's pid (SO_PEERCRED, kernel-supplied). This test process is
/// a different pid, so its in-process `Authenticate` with the same token — the
/// theft the token being an env var invites — is turned away. Nothing the caller
/// said changed; the kernel's word about which process connected did.
#[tokio::test]
async fn a_bootstrap_token_is_refused_from_a_second_process() {
    let mut env = TestEnv::spawn().await;
    env.client
        .create_user(USER, crate::common::TEST_PASSPHRASE)
        .await
        .expect("create_user");

    // Configure and start a real khttpd, handing it a fresh gateway token. It
    // authenticates before it announces its address, so the token is bound to
    // khttpd's pid once this returns.
    let mut operator = auth_client(
        &env.endpoint,
        &env.client.session_token.clone().expect("session token"),
        None,
    )
    .await;
    let set = operator
        .send(&UserRequest::WebShellSet {
            enabled: Some(true),
            port: Some(khttpd::free_port()),
            bind: Some("loopback".to_string()),
            static_dir: Some(std::env::temp_dir().display().to_string()),
            allow: None,
        })
        .await
        .expect("WebShellSet send");
    assert!(matches!(set, UserResponse::Ok), "WebShellSet: {set:?}");

    let token = env.daemon.mint_gateway_bootstrap_token(USER);
    let (_gateway, _addr) = khttpd::spawn_as(&env, token.clone()).await;

    // The same token, from this process — a different pid than khttpd's.
    let mut thief = raw_client(&env.endpoint).await;
    let resp = thief
        .send(&UserRequest::Authenticate {
            token: kotton_wire::ipc::SecretText::new(token),
            scope: None,
        })
        .await
        .expect("Authenticate send");
    assert!(
        matches!(resp, UserResponse::NoActiveSession),
        "a bootstrap token bound to khttpd's process must be refused from another; got {resp:?}"
    );
}
