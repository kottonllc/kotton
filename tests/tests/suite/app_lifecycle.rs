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

// ── list ──────────────────────────────────────────────────────────────────────

/// A fresh identity already has the apps it needs, and only those.
///
/// This asserted `apps.is_empty()` until 2026-09-17, which was true and was the defect:
/// nothing installed a new identity's shell or editor, and `xtask::run` covered it with a
/// sideload inside a branch that never ran twice. So an identity created in the window had
/// no surface, and the failure was a `WARN` in a log file (`DEC-0077`).
///
/// Two claims, and the second is the one worth the assertion. The shell and editor are
/// there — and the editor holds **only** its two `/documents` grants, not the shell's
/// breadth. A bundled app is installed with `ConsentSource::SystemBundled`, which is the
/// one install path no human approves, so if it ever widened a grant it would do so with
/// nobody in the room. That is exactly the case to pin.
#[tokio::test]
async fn a_fresh_identity_has_the_apps_it_needs_and_no_more() {
    let mut env = TestEnv::spawn_authed().await;
    let apps = env.client.app_list().await.expect("app_list");

    let mut ids: Vec<&str> = apps.iter().map(|a| a.app_id.as_str()).collect();
    ids.sort_unstable();
    assert_eq!(
        ids,
        vec!["sh.kotton.editor", "sh.kotton.records", "sh.kotton.shell"],
        "a fresh identity should hold exactly the bundled apps; got: {apps:?}"
    );

    let editor = apps
        .iter()
        .find(|a| a.app_id == "sh.kotton.editor")
        .expect("the editor is bundled");
    let mut caps: Vec<&str> = editor.capabilities.iter().map(String::as_str).collect();
    caps.sort_unstable();
    assert_eq!(
        caps,
        vec!["vfs.read:/documents", "vfs.write:/documents"],
        "the bundled editor must hold only its own narrow grant"
    );

    // The records app (RFC-0088 phase two) is bundled too, and holds one schema and nothing
    // else — no files, no write.
    let records = apps
        .iter()
        .find(|a| a.app_id == "sh.kotton.records")
        .expect("the records app is bundled");
    assert_eq!(
        records.capabilities,
        vec!["schema.read:sh.kotton.governance.record".to_string()],
        "the bundled records app must hold only its one schema"
    );
}

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

// ── unlock reinstalls what boot could not ────────────────────────────────────

/// An identity with a passphrase is locked at boot: `auto_install_bundled_apps`
/// ran over `loaded_users` in the daemon's constructors and, before this, only
/// there — a database that cannot open (*account is locked*) is skipped and
/// nothing retries it. So a person's identity made before an app joined the
/// bundle carried on without it forever, across every restart, because the one
/// later moment its database *does* open — unlock — never ran the install
/// (`TASK-an-app-bundled-after-an-identity-was-made-never-reaches-it`). A fresh
/// identity never shows the gap: `create-identity`'s own door installs while
/// the database is already open.
///
/// `bundled_apps()` is fixed at compile time (`core/kuserd/src/bundled.rs`), so
/// the suite cannot spawn a daemon bundling one app more than another to prove
/// this the literal way the record asks for. The fix does not look at *why* an
/// app the running daemon's bundle names is missing from the registry — only
/// that it is — so uninstalling one of the three real bundled apps before
/// locking reaches the identical code path: an app `bundled_apps()` says this
/// identity should hold, that its registry does not. A real process restart is
/// `TASK-the-suite-never-restarts-a-daemon`, still open;
/// `TestEnv::lock_as_a_restart_would` already models the half that matters
/// here — roots dropped from custody and the `agent.db` pool cache evicted —
/// so the reopen this test drives through unlock is the same reopen a boot's
/// `user_agent_db` call would have refused with *account is locked*.
///
/// `#[serial]`: the final `app_launch` spawns the mock runner for real, and
/// `MOCK_RUNNER_MODE` is process-wide — `app_launch_message.rs`,
/// `app_long_lived.rs` and `runner_confinement.rs` all mark their own
/// MOCK_RUNNER_MODE-mutating tests `#[serial]` for exactly this reason, but
/// `#[serial]` only excludes other `#[serial]` tests, not an unmarked one
/// racing alongside them. This is the first test here to call a
/// success-path `app_launch` against the mock runner without also mutating
/// that variable, and it inherited a stray `MOCK_RUNNER_MODE=error` from a
/// concurrently-running serial test often enough to be a real flake
/// (`runner init: mock error`) before this attribute was added — confirmed
/// by running this file alongside those three, unserialised, and by the fix
/// then holding across repeated runs.
#[tokio::test]
#[serial_test::serial]
async fn an_app_bundled_after_the_identity_was_made_reaches_it_at_unlock() {
    use kotton::{KottonClient, LockMode, PinUnlock};

    const OWNER: &str = "owner";
    // Five distinct wordlist words — the shape `kotton id set-passphrase`
    // offers, and above the RFC-0053 strength bar (`daily_credential.rs`).
    const DAILY_CREDENTIAL: &str = "abandon-ability-able-about-above";

    let mut env = TestEnv::spawn_authed().await;
    env.client
        .set_lock_policy(OWNER, LockMode::Passphrase, 0, Some(DAILY_CREDENTIAL))
        .await
        .expect("set_lock_policy");

    // The editor is one of the three bundled apps a fresh identity receives —
    // see `a_fresh_identity_has_the_apps_it_needs_and_no_more` above.
    let before = env.client.app_list().await.expect("app_list");
    assert!(
        before.iter().any(|a| a.app_id == "sh.kotton.editor"),
        "the editor should already be bundled at creation; got: {before:?}"
    );

    // The shell is left alone throughout this test — never uninstalled — so its
    // `installed_at` is the idempotency witness: `auto_install_bundled_apps`
    // hashes the compiled-in WASM before deciding to reinstall
    // (`agent::auto_install_bundled_apps`'s `stored_hash == current_hash` skip),
    // and a reinstall always rewrites this timestamp
    // (`kotton_app::daemon::apps::app_install`). If the unlock-triggered pass
    // below reinstalled an app that was already up to date, this would move.
    let shell_installed_at = before
        .iter()
        .find(|a| a.app_id == "sh.kotton.shell")
        .expect("the shell should already be bundled at creation")
        .installed_at
        .clone();

    // Model an app that reached the bundle after this identity was made: take
    // one away, as if it had never been installed here.
    env.client
        .app_uninstall("sh.kotton.editor")
        .await
        .expect("app_uninstall");
    let gone = env
        .client
        .app_list()
        .await
        .expect("app_list after uninstall");
    assert!(
        gone.iter().all(|a| a.app_id != "sh.kotton.editor"),
        "the editor must actually be gone before the fix is asked to bring it back: {gone:?}"
    );

    // The state a restart leaves a passphrase identity in: locked, with
    // `agent.db` evicted from the pool cache — the precondition is asserted,
    // not assumed, exactly as `daily_credential.rs` does for the same helper.
    env.lock_as_a_restart_would(OWNER).await;
    env.client
        .app_list()
        .await
        .expect_err("precondition: a locked identity's registry must refuse, not answer");

    // Unlock, on a fresh connection, as the next CLI invocation after a real
    // restart would.
    let mut fresh = KottonClient::connect_to(env.endpoint.clone())
        .await
        .expect("connect_to");
    assert_eq!(
        fresh
            .unlock_with_pin(OWNER, DAILY_CREDENTIAL)
            .await
            .expect("unlock"),
        PinUnlock::Unlocked
    );

    let after = fresh.app_list().await.expect("app_list after unlock");
    assert!(
        after.iter().any(|a| a.app_id == "sh.kotton.editor"),
        "the editor should have been reinstalled at unlock, the same as it would be at boot \
         or at creation; got: {after:?}"
    );

    // Idempotency: the shell was already up to date, and the unlock-triggered
    // pass must have skipped it rather than reinstalled it alongside the editor.
    let shell_installed_at_after = after
        .iter()
        .find(|a| a.app_id == "sh.kotton.shell")
        .expect("the shell should still be installed after unlock")
        .installed_at
        .clone();
    assert_eq!(
        shell_installed_at_after, shell_installed_at,
        "an app already up to date must not be reinstalled by the unlock's bundled-app pass"
    );

    let grants = fresh
        .app_grants("sh.kotton.editor")
        .await
        .expect("app_grants");
    assert!(
        grants.approved.is_some(),
        "a bundled app installs with its grant already approved, the same as at boot"
    );

    fresh
        .app_launch("sh.kotton.editor", vec![])
        .await
        .expect("the reinstalled app must be launchable");
}
