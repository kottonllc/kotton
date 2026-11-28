// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — app launch and message with the mock runner.
//!
//! Covers install + launch + message round trips against the daemon wired to
//! `kotton-mock-runner`. Error path tests (runner exits or returns Error) use
//! `#[serial_test::serial]` because they mutate the process-wide
//! `MOCK_RUNNER_MODE` environment variable.

use crate::common::InstallApprovingAll;
use crate::common::TestEnv;
use serial_test::serial;

const USER: &str = "";

/// Minimal valid WASM magic bytes — the daemon validates WASM only at launch
/// time via the runner, so these bytes are sufficient for install.
const STUB_WASM: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

const SIMPLE_MANIFEST: &str = r#"
[app]
id      = "sh.kotton.test-launch-msg"
name    = "Launch Message Test App"
version = "0.1.0"
"#;

// ── helpers ───────────────────────────────────────────────────────────────────

/// Install the test app and return its assigned `app_id`.
async fn install_test_app(env: &mut TestEnv) -> String {
    // Authenticate the connection. `app_launch`/`app_message` now require an
    // authenticated session (audit C2 — the control plane no longer dispatches
    // session-less), mirroring production where the authenticated kuid launches
    // apps. `create_user` establishes the session on this connection via the SDK.
    env.client
        .create_user("owner", crate::common::TEST_PASSPHRASE)
        .await
        .expect("create_user (authenticates the connection)");
    let (app_id, _name, _caps) = env
        .client
        .app_install_approving_all(USER, SIMPLE_MANIFEST.to_string(), STUB_WASM.to_vec())
        .await
        .expect("app_install");
    app_id
}

// ── launch ────────────────────────────────────────────────────────────────────

#[tokio::test]
#[serial]
async fn launch_installed_app_succeeds() {
    let mut env = TestEnv::spawn_with_mock_runner().await;
    let app_id = install_test_app(&mut env).await;

    let output = env
        .client
        .app_launch(&app_id, vec![])
        .await
        .expect("app_launch");

    // Mock runner always returns Launched — just asserting no error is sufficient.
    let _ = output;
}

#[tokio::test]
#[serial]
async fn launch_returns_patches() {
    // The mock runner returns `patches: []` on launch (no surface commits).
    // This test documents that behaviour.
    let mut env = TestEnv::spawn_with_mock_runner().await;
    let app_id = install_test_app(&mut env).await;

    let output = env
        .client
        .app_launch(&app_id, vec![])
        .await
        .expect("app_launch");

    // patches may be empty — that is the documented mock behaviour.
    let _ = output.patches;
}

// ── message ───────────────────────────────────────────────────────────────────

#[tokio::test]
#[serial]
async fn message_installed_app_succeeds() {
    let mut env = TestEnv::spawn_with_mock_runner().await;
    let app_id = install_test_app(&mut env).await;
    env.client.app_launch(&app_id, vec![]).await.expect("app_launch");

    env.client
        .app_message(&app_id, r#"{"type":"ping"}"#.to_string())
        .await
        .expect("app_message");
}

#[tokio::test]
#[serial]
async fn message_returns_response_patches() {
    let mut env = TestEnv::spawn_with_mock_runner().await;
    let app_id = install_test_app(&mut env).await;
    env.client.app_launch(&app_id, vec![]).await.expect("app_launch");

    let patches = env
        .client
        .app_message(&app_id, r#"{"type":"ping"}"#.to_string())
        .await
        .expect("app_message");

    let has_counter = patches.iter().any(|p| {
        p.first() == Some(&0x00)
            && std::str::from_utf8(&p[1..]).is_ok_and(|s| s.contains("counter:"))
    });
    assert!(has_counter, "expected counter patch, got {patches:?}");
}

// ── error paths (serial — mutate MOCK_RUNNER_MODE) ────────────────────────────

/// H7: a guest that never returns must not hang the key-holding daemon. With a
/// hanging runner and a short deadline, `app_launch` fails with a timeout/kill
/// error instead of blocking forever.
#[tokio::test]
#[serial]
#[allow(unsafe_code)] // env::set_var/remove_var are unsafe in Rust 1.81+; serialised by #[serial]
async fn runner_that_hangs_is_killed_by_the_deadline() {
    // SAFETY: serialised by #[serial]; restored before assertions so a panic
    // cannot leave a short deadline set for other tests.
    unsafe {
        std::env::set_var("MOCK_RUNNER_MODE", "hang");
        std::env::set_var("KOTTON_RUNNER_DEADLINE_MS", "500");
    }

    let mut env = TestEnv::spawn_with_mock_runner().await;
    let app_id = install_test_app(&mut env).await;
    let result = env.client.app_launch(&app_id, vec![]).await;

    unsafe {
        std::env::remove_var("MOCK_RUNNER_MODE");
        std::env::remove_var("KOTTON_RUNNER_DEADLINE_MS");
    }

    let err = result.expect_err("app_launch must fail when the runner hangs past the deadline");
    assert!(
        err.to_string().contains("time budget"),
        "expected a deadline/kill error, got: {err}"
    );
}

/// The mock runner's `Error` in its `error` mode, as the daemon prints it:
/// between backticks, its own backtick and line break by their escapes.
const MOCK_ERROR_SAID: &str = "`mock \\u{60}error\\u{60}\\nFORGED: launched`";

/// The `error` field of the `wasm` event the daemon published as `message`,
/// read from the owner's event log. A bounded wait: the log is a task on the bus.
async fn logged_error(env: &mut TestEnv, message: &str) -> String {
    for _ in 0..300 {
        let entries = env
            .client
            .query_events(Some("wasm".to_string()), None, None, Some(500))
            .await
            .expect("the owner's event log is read");
        if let Some(entry) = entries.into_iter().find(|e| e.message == message) {
            let payload: serde_json::Value =
                serde_json::from_str(&entry.payload.expect("the event carries a payload"))
                    .expect("the payload is JSON");
            return payload["error"]
                .as_str()
                .expect("the payload names the error")
                .to_string();
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("no `wasm` event {message:?} reached the owner's event log");
}

/// **An app runner's `Error` at launch is printed as data**: the launch fails
/// with the daemon's word and then the runner's words between backticks, and
/// the event the daemon keeps of it holds the same quoted words.
#[tokio::test]
#[serial]
#[allow(unsafe_code)] // env::set_var/remove_var are unsafe in Rust 1.81+; serialised by #[serial]
async fn launch_runner_error_surfaces_as_ipc_error() {
    // SAFETY: serialised by #[serial] so no other test runs concurrently.
    // Restored unconditionally before assertions so a panic can't dirty state.
    unsafe { std::env::set_var("MOCK_RUNNER_MODE", "error") };

    let mut env = TestEnv::spawn_with_mock_runner().await;
    let app_id = install_test_app(&mut env).await;

    let result = env.client.app_launch(&app_id, vec![]).await;

    unsafe { std::env::remove_var("MOCK_RUNNER_MODE") };

    let err = result.expect_err("app_launch fails when the runner returns Error");
    assert_eq!(err.to_string(), format!("runner: {MOCK_ERROR_SAID}"));
    assert_eq!(
        logged_error(&mut env, &format!("App launch error: {app_id}")).await,
        MOCK_ERROR_SAID
    );
}

/// **An app runner's `Error` for a message is printed as data**, as at launch:
/// in the failure and in the event the daemon keeps of it.
#[tokio::test]
#[serial]
#[allow(unsafe_code)] // env::set_var/remove_var are unsafe in Rust 1.81+; serialised by #[serial]
async fn message_runner_error_surfaces_as_ipc_error() {
    // SAFETY: serialised by #[serial] so no other test runs concurrently.
    unsafe { std::env::set_var("MOCK_RUNNER_MODE", "error") };

    let mut env = TestEnv::spawn_with_mock_runner().await;
    let app_id = install_test_app(&mut env).await;

    let result = env.client.app_message(&app_id, r#"{"type":"ping"}"#.to_string()).await;

    unsafe { std::env::remove_var("MOCK_RUNNER_MODE") };

    let err = result.expect_err("app_message fails when the runner returns Error");
    assert_eq!(err.to_string(), format!("runner: {MOCK_ERROR_SAID}"));
    assert_eq!(
        logged_error(&mut env, &format!("App message error: {app_id}")).await,
        MOCK_ERROR_SAID
    );
}
