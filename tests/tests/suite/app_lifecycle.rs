// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — app lifecycle
//!
//! Covers: install, list, reinstall (upsert), uninstall, and error cases for
//! launch and message against an unknown app.
//!
//! Launch and message against a real WASM module (including long-lived mode)
//! are covered by the `app_test_coverage` sprint, which requires a
//! `kotton-runner` binary fixture in the test environment.

use crate::common::InstallApprovingAll;
use crate::common::TestEnv;

const USER: &str = "";

/// Minimal valid WASM module magic + version bytes.
///
/// The daemon stores bytes on disk and validates the component model only at
/// launch time, so this is sufficient for install/list/uninstall tests.
/// Using an empty user_id (bundled-app install pattern) avoids the session
/// auth guard so tests don't need to create and log in a user.
const STUB_WASM: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

const SIMPLE_MANIFEST: &str = r#"
[app]
id      = "sh.kotton.test-lifecycle"
name    = "Lifecycle Test App"
version = "0.1.0"
"#;

const MANIFEST_WITH_CAPS: &str = r#"
[app]
id      = "sh.kotton.test-caps"
name    = "Caps Test App"
version = "0.2.0"

[capabilities]
"schema.read"  = ["sh.kotton.notes"]
"schema.write" = ["sh.kotton.notes"]
"#;

// ── install ───────────────────────────────────────────────────────────────────

/// app_install returns the app_id, name, and capability strings from the manifest.
#[tokio::test]
async fn app_install_returns_correct_metadata() {
    let mut env = TestEnv::spawn_authed().await;

    let (app_id, name, caps) = env
        .client
        .app_install_approving_all(USER, MANIFEST_WITH_CAPS.to_string(), STUB_WASM.to_vec())
        .await
        .expect("app_install");

    assert_eq!(app_id, "sh.kotton.test-caps");
    assert_eq!(name, "Caps Test App");
    assert!(
        caps.contains(&"schema.read:sh.kotton.notes".to_string()),
        "expected schema.read cap in {caps:?}"
    );
    assert!(
        caps.contains(&"schema.write:sh.kotton.notes".to_string()),
        "expected schema.write cap in {caps:?}"
    );
}

/// After install the app appears in app_list with correct metadata.
#[tokio::test]
async fn installed_app_appears_in_list() {
    let mut env = TestEnv::spawn_authed().await;

    env.client
        .app_install_approving_all(USER, SIMPLE_MANIFEST.to_string(), STUB_WASM.to_vec())
        .await
        .expect("app_install");

    let apps = env.client.app_list().await.expect("app_list");
    let found = apps
        .iter()
        .find(|a| a.app_id == "sh.kotton.test-lifecycle");

    assert!(
        found.is_some(),
        "installed app should appear in app_list; list: {apps:?}"
    );
    let app = found.unwrap();
    assert_eq!(app.name, "Lifecycle Test App");
    assert_eq!(app.version, "0.1.0");
}

/// Installing the same app_id a second time replaces the existing row (upsert).
#[tokio::test]
async fn reinstall_same_id_replaces_existing() {
    let mut env = TestEnv::spawn_authed().await;

    env.client
        .app_install_approving_all(USER, SIMPLE_MANIFEST.to_string(), STUB_WASM.to_vec())
        .await
        .expect("first install");

    let updated_manifest = r#"
[app]
id      = "sh.kotton.test-lifecycle"
name    = "Lifecycle Test App v2"
version = "0.2.0"
"#;

    env.client
        .app_install_approving_all(USER, updated_manifest.to_string(), STUB_WASM.to_vec())
        .await
        .expect("second install (update)");

    let apps = env.client.app_list().await.expect("app_list");
    let matching: Vec<_> = apps
        .iter()
        .filter(|a| a.app_id == "sh.kotton.test-lifecycle")
        .collect();

    assert_eq!(
        matching.len(),
        1,
        "reinstall should not duplicate the entry; list: {apps:?}"
    );
    assert_eq!(
        matching[0].version, "0.2.0",
        "version should reflect the updated manifest"
    );
}

// ── uninstall ─────────────────────────────────────────────────────────────────

/// After uninstall the app no longer appears in app_list.
#[tokio::test]
async fn uninstall_removes_app_from_list() {
    let mut env = TestEnv::spawn_authed().await;

    env.client
        .app_install_approving_all(USER, SIMPLE_MANIFEST.to_string(), STUB_WASM.to_vec())
        .await
        .expect("app_install");

    env.client
        .app_uninstall("sh.kotton.test-lifecycle")
        .await
        .expect("app_uninstall");

    let apps = env.client.app_list().await.expect("app_list");
    assert!(
        apps.iter().all(|a| a.app_id != "sh.kotton.test-lifecycle"),
        "uninstalled app should not appear in app_list; list: {apps:?}"
    );
}

/// Reinstalling after uninstall succeeds cleanly.
#[tokio::test]
async fn reinstall_after_uninstall_succeeds() {
    let mut env = TestEnv::spawn_authed().await;

    env.client
        .app_install_approving_all(USER, SIMPLE_MANIFEST.to_string(), STUB_WASM.to_vec())
        .await
        .expect("first install");

    env.client
        .app_uninstall("sh.kotton.test-lifecycle")
        .await
        .expect("uninstall");

    env.client
        .app_install_approving_all(USER, SIMPLE_MANIFEST.to_string(), STUB_WASM.to_vec())
        .await
        .expect("reinstall after uninstall");

    let apps = env.client.app_list().await.expect("app_list");
    assert!(
        apps.iter().any(|a| a.app_id == "sh.kotton.test-lifecycle"),
        "reinstalled app should be present; list: {apps:?}"
    );
}

/// Uninstalling an app that is not installed returns an error.
#[tokio::test]
async fn uninstall_nonexistent_app_returns_error() {
    let mut env = TestEnv::spawn_authed().await;
    let result = env.client.app_uninstall("sh.kotton.does-not-exist").await;
    assert!(
        result.is_err(),
        "uninstall of a non-installed app should return an error"
    );
}

// ── error cases (no runner required) ─────────────────────────────────────────

/// Launching an app that is not installed returns an error, not a panic.
#[tokio::test]
async fn launch_unknown_app_returns_error() {
    let mut env = TestEnv::spawn_authed().await;
    let result = env
        .client
        .app_launch("sh.kotton.does-not-exist", vec![])
        .await;
    assert!(
        result.is_err(),
        "launching a non-installed app should return an error"
    );
}

/// Sending a message to an app that is not installed returns an error, not a panic.
#[tokio::test]
async fn message_unknown_app_returns_error() {
    let mut env = TestEnv::spawn_authed().await;
    let result = env
        .client
        .app_message("sh.kotton.does-not-exist", "hello".to_string())
        .await;
    assert!(
        result.is_err(),
        "messaging a non-installed app should return an error"
    );
}
