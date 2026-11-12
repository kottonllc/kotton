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
"schema.read"  = ["did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/notes"]
"schema.write" = ["did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/notes"]
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
        caps.contains(&format!("schema.read:{}", kotton_common::namespace::NSID_NOTES)),
        "expected schema.read cap in {caps:?}"
    );
    assert!(
        caps.contains(&format!("schema.write:{}", kotton_common::namespace::NSID_NOTES)),
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

/// **A manifest claiming to handle `secret` or `petname` is refused at install**, naming the
/// schema, and leaves no handler for it (kotton #449, #471: both are kept from every app).
#[tokio::test]
async fn a_manifest_claiming_to_handle_secret_is_refused_at_install() {
    let mut env = TestEnv::spawn_authed().await;
    for secret in [kotton_common::namespace::NSID_SECRET, kotton_common::namespace::NSID_PETNAME] {
        let manifest = format!(
            "[app]\nid = \"sh.kotton.test-keys\"\nname = \"Keys\"\nversion = \"0.1.0\"\nhandler_for = [\"{secret}\"]\n"
        );
        let err = env
            .client
            .app_install_approving_all(USER, manifest, STUB_WASM.to_vec())
            .await
            .expect_err("a handler claim on a kept schema");
        assert!(err.to_string().contains(secret) && err.to_string().contains("handler_for"), "{err}");
        assert!(env.client.handler_get_for(secret).await.is_err(), "a handler for {secret} was registered");
        let apps = env.client.app_list().await.expect("app_list");
        assert!(!apps.iter().any(|a| a.app_id == "sh.kotton.test-keys"), "the app was installed: {apps:?}");
    }
}

// ── a path the person bound ───────────────────────────────────────────────────

/// `words`, typed at the REPL of `env`'s daemon as its session: the exit and all it said.
async fn typed(env: &TestEnv, words: &[&str]) -> (kotton_shell::ExitCode, String) {
    let mut client = kotton::KottonClient::connect_to(env.endpoint.clone()).await.expect("a REPL connection");
    client
        .authenticate(env.client.session_token.as_deref().expect("the owner's session"))
        .await
        .expect("the REPL's identity");
    let mut state = kotton_shell::ShellState::new("owner".to_string(), std::sync::Arc::new(tokio::sync::Mutex::new(client)));
    state.asking = kotton_shell::Asking::Nobody;
    let words: Vec<String> = words.iter().map(|w| w.to_string()).collect();
    let out = kotton_cli::bridge::repl_executor()
        .registry()
        .execute(&words[0], &words[1..], &mut state)
        .await
        .unwrap_or_else(|e| panic!("$ {}: {e}", words.join(" ")));
    let mut text: String = out.out.iter().map(kotton_shell::out::render_shape).collect::<Vec<_>>().join("\n");
    for stream in [&out.stdout, &out.stderr].into_iter().flatten() {
        text.push('\n');
        text.push_str(stream);
    }
    eprintln!("$ {}\n{text}\n", words.join(" "));
    (out.exit_code, text)
}

/// An app's directory as `app sideload` reads one, `com.example.<id>`, with one shape, `home`,
/// that reads and writes where the app suggests: `/notes`.
fn a_shaped_app(dir: &std::path::Path, id: &str) -> String {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("app.wasm"), STUB_WASM).unwrap();
    std::fs::write(
        dir.join("manifest.toml"),
        format!(
            "[app]\nid = \"com.example.{id}\"\nname = \"Ledger\"\nversion = \"1.0.0\"\n\n\
             [[capabilities]]\nid = \"home\"\ntype = \"vfs-tree\"\naccess = [\"read\", \"write\"]\ndefault = \"/notes\"\n"
        ),
    )
    .unwrap();
    dir.to_str().unwrap().to_string()
}

/// **An approved grant keeps which paths the person chose** (kotton #499's done-when): a
/// sideload preview given `--bind` shows the files where they are bound and repeats the bind
/// in the line to type; the install's receipt and `app grants` then say the bound path is
/// the person's, and an app installed where it suggests has the app's path in both. Neither
/// says the path is one or the other.
#[tokio::test]
async fn a_bound_path_is_said_to_be_the_persons_in_the_receipt_and_in_app_grants() {
    let env = TestEnv::spawn_authed().await;
    let apps = tempfile::tempdir().unwrap();
    let both_ways = "the app's, or one you bound";

    let bound = a_shaped_app(&apps.path().join("bound"), "bound");
    let (exit, preview) = typed(&env, &["app", "sideload", &bound, "--bind", "home=/journal"]).await;
    assert_eq!(exit, kotton_shell::ExitCode::Success, "{preview}");
    assert!(preview.contains("  read + write files at a path you bound\n"), "{preview}");
    assert!(preview.contains("  | a path you bound: \"/journal\"\n"), "{preview}");
    assert!(
        preview.contains(&format!("To install:  app sideload {bound} --bind home=/journal --approve\n")),
        "{preview}"
    );
    let (exit, receipt) = typed(&env, &["app", "sideload", &bound, "--bind", "home=/journal", "--approve"]).await;
    assert_eq!(exit, kotton_shell::ExitCode::Success, "{receipt}");
    for kind in ["read", "write"] {
        assert!(
            receipt.contains(&format!("  {kind} your files under this path\n  | a path you bound: \"/journal\"")),
            "{receipt}"
        );
    }
    let (exit, grants) = typed(&env, &["app", "grants", "com.example.bound"]).await;
    assert_eq!(exit, kotton_shell::ExitCode::Success, "{grants}");
    let holds = grants.split("Holds:").nth(1).expect("what it holds");
    assert!(holds.contains("  | a path you bound: \"/journal\""), "{grants}");
    assert!(!holds.contains("/notes"), "{grants}");
    // What it asked for is the app's, wherever the person put it.
    let asked = grants.split("Holds:").next().unwrap();
    assert!(asked.contains("  | the app's path: \"/notes\""), "{grants}");

    let unbound = a_shaped_app(&apps.path().join("unbound"), "unbound");
    let (exit, preview) = typed(&env, &["app", "sideload", &unbound]).await;
    assert_eq!(exit, kotton_shell::ExitCode::Success, "{preview}");
    assert!(preview.contains("  read + write files at a place the app suggests\n"), "{preview}");
    assert!(preview.contains(&format!("To install:  app sideload {unbound} --approve\n")), "{preview}");
    let (exit, receipt) = typed(&env, &["app", "sideload", &unbound, "--approve"]).await;
    assert_eq!(exit, kotton_shell::ExitCode::Success, "{receipt}");
    assert!(receipt.contains("  | the app's path: \"/notes\""), "{receipt}");
    assert!(!receipt.contains("a path you bound"), "{receipt}");
    let (exit, grants) = typed(&env, &["app", "grants", "com.example.unbound"]).await;
    assert_eq!(exit, kotton_shell::ExitCode::Success, "{grants}");
    let holds = grants.split("Holds:").nth(1).expect("what it holds");
    assert!(holds.contains("  | the app's path: \"/notes\""), "{grants}");
    assert!(!grants.contains("a path you bound"), "{grants}");

    for said in [&receipt, &grants, &preview] {
        assert!(!said.contains(both_ways), "{said}");
    }
}
