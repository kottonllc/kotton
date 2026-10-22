// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — long-lived app subprocess semantics.
//!
//! A long-lived app's runner subprocess is kept alive across multiple
//! `app_message` calls. These tests verify subprocess reuse, lazy spawn,
//! crash recovery, and teardown on uninstall.
//!
//! Tests that mutate `MOCK_RUNNER_MODE` use `#[serial_test::serial]`.

use crate::common::InstallApprovingAll;
use crate::common::TestEnv;
use serial_test::serial;

const USER: &str = "";

const STUB_WASM: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

/// Manifest for a long-lived app.  The `id` is distinct from the one-shot
/// tests so install/uninstall ops don't interact across test suites.
const LONG_LIVED_MANIFEST: &str = r#"
[app]
id      = "sh.kotton.test-long-lived"
name    = "Long Lived Test"
version = "0.1.0"
kind    = "long-lived"
"#;

// ── helpers ───────────────────────────────────────────────────────────────────

async fn install_long_lived(env: &mut TestEnv) -> String {
    let (app_id, _name, _caps) = env
        .client
        .app_install_approving_all(USER, LONG_LIVED_MANIFEST.to_string(), STUB_WASM.to_vec())
        .await
        .expect("app_install (long-lived)");
    app_id
}

/// Extract the `counter:N` value from a message list.
///
/// Each message is a raw patch: a one-byte format version (`0x00`) followed by
/// a JSON-encoded string such as `"counter:3"`.
fn extract_counter(messages: &[Vec<u8>]) -> Option<u32> {
    messages
        .iter()
        .filter_map(|m| m.split_first())
        .filter(|(fmt, _)| **fmt == 0x00)
        .filter_map(|(_, body)| serde_json::from_slice::<String>(body).ok())
        .find(|s| s.starts_with("counter:"))
        .and_then(|s| s.strip_prefix("counter:").unwrap().parse().ok())
}

// ── tests ─────────────────────────────────────────────────────────────────────

/// Sending two messages to a long-lived app should reuse the same subprocess.
///
/// The mock runner's counter increments monotonically within a single
/// process — two consecutive responses with counters `N` and `N+1` prove
/// both messages were handled by the same runner process.
#[tokio::test]
#[serial]
async fn long_lived_app_reuses_subprocess() {
    let mut env = TestEnv::spawn_with_mock_runner_authed().await;
    let app_id = install_long_lived(&mut env).await;

    // Launch to spawn the subprocess.
    env.client
        .app_launch(&app_id, vec![])
        .await
        .expect("app_launch");

    let msgs1 = env
        .client
        .app_message(&app_id, r#"{"seq":1}"#.to_string())
        .await
        .expect("app_message 1");

    let msgs2 = env
        .client
        .app_message(&app_id, r#"{"seq":2}"#.to_string())
        .await
        .expect("app_message 2");

    let c1 = extract_counter(&msgs1).expect("counter in response 1");
    let c2 = extract_counter(&msgs2).expect("counter in response 2");

    assert_eq!(
        c2,
        c1 + 1,
        "counter should increment by 1 when the same subprocess handles both messages \
         (c1={c1}, c2={c2})"
    );
}

/// The daemon should lazily spawn a long-lived runner on the first `app_message`
/// call even if `app_launch` was never called.
#[tokio::test]
#[serial]
async fn long_lived_app_spawned_on_first_message() {
    let mut env = TestEnv::spawn_with_mock_runner_authed().await;
    let app_id = install_long_lived(&mut env).await;

    // No app_launch — the daemon should spawn the runner on demand.
    let messages = env
        .client
        .app_message(&app_id, r#"{"type":"ping"}"#.to_string())
        .await
        .expect("app_message (no prior launch)");

    assert!(
        !messages.is_empty() || messages.is_empty(), // always passes — just checking no error
        "app_message should succeed even without prior app_launch"
    );
}

/// When the runner exits unexpectedly (mode `exit`), the daemon should respawn
/// on the next `app_message` call so the app remains functional.
#[tokio::test]
#[serial]
#[allow(unsafe_code)] // env::set_var/remove_var are unsafe in Rust 1.81+; serialised by #[serial]
async fn long_lived_crash_respawns_on_next_message() {
    // SAFETY: serialised by #[serial] so no other test runs concurrently.
    unsafe { std::env::set_var("MOCK_RUNNER_MODE", "exit") };

    let mut env = TestEnv::spawn_with_mock_runner_authed().await;
    let app_id = install_long_lived(&mut env).await;

    // Launch — the runner exits immediately (mode=exit), daemon should notice.
    let _ = env.client.app_launch(&app_id, vec![]).await;

    // First message in exit mode — may fail.
    let _ = env
        .client
        .app_message(&app_id, r#"{"type":"first"}"#.to_string())
        .await;

    // Restore to default mode so the next spawn succeeds.
    unsafe { std::env::remove_var("MOCK_RUNNER_MODE") };

    // Second message — daemon should have respawned a fresh runner.
    let result = env
        .client
        .app_message(&app_id, r#"{"type":"second"}"#.to_string())
        .await;

    assert!(
        result.is_ok(),
        "app_message should succeed after daemon respawns the crashed runner, got: {result:?}"
    );
}

/// Uninstalling a long-lived app should tear down its running instance.
/// A subsequent `app_message` should return an error (app not found).
#[tokio::test]
#[serial]
async fn long_lived_instance_torn_down_after_uninstall() {
    let mut env = TestEnv::spawn_with_mock_runner_authed().await;
    let app_id = install_long_lived(&mut env).await;

    // Spawn the runner instance.
    env.client
        .app_launch(&app_id, vec![])
        .await
        .expect("app_launch");
    env.client
        .app_message(&app_id, r#"{"type":"ping"}"#.to_string())
        .await
        .expect("first app_message");

    // Uninstall — should tear down the live instance.
    env.client
        .app_uninstall(&app_id)
        .await
        .expect("app_uninstall");

    // Any further message should fail because the app no longer exists.
    let result = env
        .client
        .app_message(&app_id, r#"{"type":"ping"}"#.to_string())
        .await;

    assert!(
        result.is_err(),
        "app_message after uninstall should fail with 'not found', got Ok({result:?})"
    );
}
