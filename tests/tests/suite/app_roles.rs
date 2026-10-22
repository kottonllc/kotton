// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — app role registry
//!
//! Covers: default role seeding, get_role, set_role roundtrip, capability
//! contract enforcement (reject app without required caps), and role override.

use crate::common::InstallApprovingAll;
use crate::common::TestEnv;

const USER: &str = "";

/// Minimal valid WASM module bytes (magic + version). Sufficient for install tests.
/// Using an empty user_id (bundled-app install pattern) avoids the session
/// auth guard so tests don't need to create and log in a user.
const STUB_WASM: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

/// A shell-like app: broad `files.read`, as a real confined shell declares. The "shell"
/// role has no required capability (RFC-0028) — it denotes surface ownership only — so any
/// installed app may fill it; this one is representative.
const SHELL_APP_MANIFEST: &str = r#"
[app]
id      = "com.example.test-shell"
name    = "Test Shell"
version = "0.1.0"

[capabilities]
"files.read" = ["/"]
"#;

/// Satisfies the "dock" role contract (`events.subscribe` capability required).
const DOCK_APP_MANIFEST: &str = r#"
[app]
id      = "com.example.test-dock"
name    = "Test Dock"
version = "0.1.0"

[capabilities]
"events.subscribe" = []
"#;

/// No capabilities — cannot satisfy any role contract.
const NO_CAPS_MANIFEST: &str = r#"
[app]
id      = "com.example.test-nocaps"
name    = "NoCaps App"
version = "0.1.0"
"#;

/// A second shell-like app, for override tests.
const SHELL_APP_B_MANIFEST: &str = r#"
[app]
id      = "com.example.test-shell-b"
name    = "Test Shell B"
version = "0.1.0"

[capabilities]
"files.read" = ["/"]
"#;

// ── default state ─────────────────────────────────────────────────────────────

/// A fresh daemon has the "shell" role pre-seeded to "sh.kotton.shell".
#[tokio::test]
async fn fresh_daemon_has_default_shell_role() {
    let mut env = TestEnv::spawn_authed().await;
    let app_id = env
        .client
        .app_get_role("shell")
        .await
        .expect("app_get_role")
        .expect("shell role should be set by default on a fresh daemon");

    assert_eq!(
        app_id, "sh.kotton.shell",
        "default shell role should be sh.kotton.shell"
    );
}

/// get_role for a role that has never been assigned returns None.
#[tokio::test]
async fn get_role_unregistered_returns_none() {
    let mut env = TestEnv::spawn_authed().await;
    let result = env
        .client
        .app_get_role("completely-unknown-role-xyz")
        .await
        .expect("app_get_role should not error");

    assert!(
        result.is_none(),
        "get_role for an unregistered role should return None"
    );
}

// ── set_role ──────────────────────────────────────────────────────────────────

/// set_role with an app that has the required capability succeeds; get_role
/// returns the updated app_id.
#[tokio::test]
async fn set_role_shell_roundtrip() {
    let mut env = TestEnv::spawn_authed().await;

    env.client
        .app_install_approving_all(USER, SHELL_APP_MANIFEST.to_string(), STUB_WASM.to_vec())
        .await
        .expect("app_install");

    env.client
        .app_set_role("shell", "com.example.test-shell")
        .await
        .expect("app_set_role");

    let app_id = env
        .client
        .app_get_role("shell")
        .await
        .expect("app_get_role")
        .expect("shell role should be set after set_role");

    assert_eq!(app_id, "com.example.test-shell");
}

/// set_role for the "dock" role succeeds when the app declares `events.subscribe`.
#[tokio::test]
async fn set_role_dock_roundtrip() {
    let mut env = TestEnv::spawn_authed().await;

    env.client
        .app_install_approving_all(USER, DOCK_APP_MANIFEST.to_string(), STUB_WASM.to_vec())
        .await
        .expect("app_install");

    env.client
        .app_set_role("dock", "com.example.test-dock")
        .await
        .expect("app_set_role dock");

    let app_id = env
        .client
        .app_get_role("dock")
        .await
        .expect("app_get_role")
        .expect("dock role should be set");

    assert_eq!(app_id, "com.example.test-dock");
}

/// The "shell" role has no capability contract (RFC-0028 — surface ownership only), so any
/// installed app may fill it, even one declaring no capabilities. The rejection mechanism
/// itself is covered by the "dock" role test below.
#[tokio::test]
async fn set_role_shell_accepts_app_without_special_caps() {
    let mut env = TestEnv::spawn_authed().await;

    env.client
        .app_install_approving_all(USER, NO_CAPS_MANIFEST.to_string(), STUB_WASM.to_vec())
        .await
        .expect("app_install");

    env.client
        .app_set_role("shell", "com.example.test-nocaps")
        .await
        .expect("set_role 'shell' should accept any installed app (no role cap contract)");

    let app_id = env
        .client
        .app_get_role("shell")
        .await
        .expect("app_get_role")
        .expect("shell role should be set");

    assert_eq!(app_id, "com.example.test-nocaps");
}

/// set_role rejects a dock assignment when the app lacks `events.subscribe`.
#[tokio::test]
async fn set_role_dock_rejects_app_without_events_subscribe() {
    let mut env = TestEnv::spawn_authed().await;

    env.client
        .app_install_approving_all(USER, SHELL_APP_MANIFEST.to_string(), STUB_WASM.to_vec())
        .await
        .expect("app_install");

    let result = env
        .client
        .app_set_role("dock", "com.example.test-shell")
        .await;

    assert!(
        result.is_err(),
        "set_role 'dock' should fail for an app without events.subscribe"
    );
}

/// set_role for an app that is not installed returns an error.
#[tokio::test]
async fn set_role_unknown_app_returns_error() {
    let mut env = TestEnv::spawn_authed().await;
    let result = env
        .client
        .app_set_role("shell", "com.example.does-not-exist")
        .await;

    assert!(
        result.is_err(),
        "set_role for a non-installed app should return an error"
    );
}

/// set_role can override an existing role assignment.
#[tokio::test]
async fn set_role_override_existing() {
    let mut env = TestEnv::spawn_authed().await;

    env.client
        .app_install_approving_all(USER, SHELL_APP_MANIFEST.to_string(), STUB_WASM.to_vec())
        .await
        .expect("install shell-a");

    env.client
        .app_install_approving_all(USER, SHELL_APP_B_MANIFEST.to_string(), STUB_WASM.to_vec())
        .await
        .expect("install shell-b");

    env.client
        .app_set_role("shell", "com.example.test-shell")
        .await
        .expect("set role to shell-a");

    env.client
        .app_set_role("shell", "com.example.test-shell-b")
        .await
        .expect("override role to shell-b");

    let app_id = env
        .client
        .app_get_role("shell")
        .await
        .expect("app_get_role")
        .expect("shell role should be set");

    assert_eq!(
        app_id, "com.example.test-shell-b",
        "role should reflect the latest override"
    );
}

/// Roles for unknown role names (no contract) can be set to any installed app.
#[tokio::test]
async fn set_role_custom_role_no_contract() {
    let mut env = TestEnv::spawn_authed().await;

    env.client
        .app_install_approving_all(USER, NO_CAPS_MANIFEST.to_string(), STUB_WASM.to_vec())
        .await
        .expect("app_install");

    // "editor" has no role contract, so any installed app can fill it.
    env.client
        .app_set_role("editor", "com.example.test-nocaps")
        .await
        .expect("set_role with no contract should accept any installed app");

    let app_id = env
        .client
        .app_get_role("editor")
        .await
        .expect("app_get_role")
        .expect("editor role should be set");

    assert_eq!(app_id, "com.example.test-nocaps");
}
