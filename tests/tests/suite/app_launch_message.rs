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

/// When the runner returns `Error`, `app_launch` should surface an error.
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

    assert!(
        result.is_err(),
        "expected app_launch to fail when runner returns Error"
    );
}

/// When the runner returns `Error` for a message, `app_message` should surface an error.
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

    assert!(
        result.is_err(),
        "expected app_message to fail when runner returns Error"
    );
}
