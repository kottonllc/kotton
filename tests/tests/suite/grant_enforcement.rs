// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — GrantEnvelope enforcement (Step 7)
//!
//! These tests operate at the daemon IPC boundary via `KottonClient`.  They
//! verify that:
//!
//! 1. `app_install` with a logged-in user produces a stored `GrantEnvelope`
//!    (indirectly, via successful round-trip and `app_list` output).
//! 2. `app_install` with an empty `user_id` (bundled-app boot pattern) still
//!    succeeds — the daemon skips the envelope gracefully.
//! 3. After uninstall the app no longer appears in `app_list`.
//! 4. Reinstalling an app (same `app_id`) after uninstall succeeds cleanly.

use crate::common::InstallApprovingAll;
use crate::common::TestEnv;

// ── fixtures ─────────────────────────────────────────────────────────────────

const USER: &str = "alice";

/// Minimal valid WASM component in binary form.
///
/// This is the canonical empty WASM module magic + version bytes.  The daemon
/// stores the bytes on disk and does not validate the component model at
/// install time (only at launch), so this is sufficient for install tests.
const STUB_WASM: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

/// An app asking for read **and** write, so an approval can narrow it.
const RW_MANIFEST: &str = r#"
[app]
id      = "sh.kotton.test-rw"
name    = "Read Write"
version = "0.1.0"

[capabilities]
"files.read"  = ["/notes"]
"files.write" = ["/notes"]
"#;

/// A minimal app manifest that declares `sh.kotton.notes` read capability.
const NOTES_MANIFEST: &str = r#"
[app]
id      = "sh.kotton.test-notes"
name    = "Test Notes"
version = "0.1.0"

[capabilities]
"schema.read" = ["sh.kotton.notes"]
"#;

/// A manifest with no capabilities (useful for testing zero-grant install).
const NO_CAPS_MANIFEST: &str = r#"
[app]
id      = "sh.kotton.test-nocaps"
name    = "Test NoCaps"
version = "0.1.0"
"#;

// ── helpers ───────────────────────────────────────────────────────────────────

/// Create a user and give it a recovery phrase; return `(did, recovery_key)`.
///
/// Two steps now, because creation mints no phrase — an identity starts with a
/// random key and no recovery authority.
async fn setup_user(env: &mut TestEnv) -> (String, String) {
    let (did, _) = env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let recovery_key = env
        .client
        .add_recovery_phrase(USER)
        .await
        .expect("add_recovery_phrase");
    (did, recovery_key)
}

// ── tests ─────────────────────────────────────────────────────────────────────

/// Installing an app for a logged-in user succeeds and the app appears in the
/// list with the declared capabilities.
#[tokio::test]
async fn install_with_user_stores_app() {
    let mut env = TestEnv::spawn_authed().await;
    let (_, recovery_key) = setup_user(&mut env).await;

    // User must be logged in so the identity key is in the keychain.
    env.client
        .login_with_recovery_key(&recovery_key, Some(USER.to_string()), None)
        .await
        .expect("login_with_recovery_key");

    let (app_id, name, caps) = env
        .client
        .app_install_approving_all(USER, NOTES_MANIFEST.to_string(), STUB_WASM.to_vec())
        .await
        .expect("app_install should succeed for logged-in user");

    assert_eq!(app_id, "sh.kotton.test-notes", "app_id from manifest");
    assert_eq!(name, "Test Notes");
    assert!(
        !caps.is_empty(),
        "installed app should have at least one capability string"
    );

    // The app must now appear in the list.
    let apps = env.client.app_list().await.expect("app_list");
    assert!(
        apps.iter().any(|a| a.app_id == app_id),
        "installed app should appear in app_list; got: {apps:?}"
    );
}

/// Installing an app with `user_id = ""` (bundled-app / daemon boot pattern)
/// succeeds.  The daemon skips GrantEnvelope creation gracefully when the
/// identity key is absent.
#[tokio::test]
async fn install_without_user_succeeds_gracefully() {
    let mut env = TestEnv::spawn_authed().await;

    // Pass an empty user_id: this is the system/bundled-install path, which is
    // session-exempt (AppInstall mirrors target_user_id — audit C2). The session
    // from spawn_authed is only needed for the app_list verification below, which
    // is a control-plane read.
    let (app_id, _name, _caps) = env
        .client
        .app_install_approving_all("", NO_CAPS_MANIFEST.to_string(), STUB_WASM.to_vec())
        .await
        .expect("app_install with empty user_id should succeed");

    assert_eq!(app_id, "sh.kotton.test-nocaps");

    let apps = env.client.app_list().await.expect("app_list");
    assert!(apps.iter().any(|a| a.app_id == app_id));
}

/// Installing the same app twice succeeds (daemon upserts the registry row).
/// The second call should return the same app_id without error.
#[tokio::test]
async fn install_duplicate_app_idempotent() {
    let mut env = TestEnv::spawn_authed().await;

    env.client
        .app_install_approving_all("", NO_CAPS_MANIFEST.to_string(), STUB_WASM.to_vec())
        .await
        .expect("first install");

    // Second install: daemon uses INSERT OR REPLACE, so this must also succeed.
    env.client
        .app_install_approving_all("", NO_CAPS_MANIFEST.to_string(), STUB_WASM.to_vec())
        .await
        .expect("second install of same app_id should succeed (upsert)");

    // Only one app in the list after two installs.
    let apps = env.client.app_list().await.expect("app_list");
    assert_eq!(
        apps.iter()
            .filter(|a| a.app_id == "sh.kotton.test-nocaps")
            .count(),
        1,
        "duplicate install should result in exactly one registry entry"
    );
}

/// After uninstall the app no longer appears in `app_list`.
#[tokio::test]
async fn uninstall_removes_app() {
    let mut env = TestEnv::spawn_authed().await;

    env.client
        .app_install_approving_all("", NO_CAPS_MANIFEST.to_string(), STUB_WASM.to_vec())
        .await
        .expect("app_install");

    env.client
        .app_uninstall("sh.kotton.test-nocaps")
        .await
        .expect("app_uninstall");

    let apps = env.client.app_list().await.expect("app_list");
    assert!(
        apps.iter().all(|a| a.app_id != "sh.kotton.test-nocaps"),
        "uninstalled app should not appear in app_list; got: {apps:?}"
    );
}

/// After uninstall, reinstalling the same app succeeds (DB row and file
/// cleaned up).
#[tokio::test]
async fn reinstall_after_uninstall_succeeds() {
    let mut env = TestEnv::spawn_authed().await;

    env.client
        .app_install_approving_all("", NO_CAPS_MANIFEST.to_string(), STUB_WASM.to_vec())
        .await
        .expect("first install");

    env.client
        .app_uninstall("sh.kotton.test-nocaps")
        .await
        .expect("uninstall");

    env.client
        .app_install_approving_all("", NO_CAPS_MANIFEST.to_string(), STUB_WASM.to_vec())
        .await
        .expect("reinstall after uninstall should succeed");

    let apps = env.client.app_list().await.expect("app_list");
    assert!(apps.iter().any(|a| a.app_id == "sh.kotton.test-nocaps"));
}

/// Uninstalling a non-existent app returns an error.
#[tokio::test]
async fn uninstall_unknown_app_errors() {
    let mut env = TestEnv::spawn_authed().await;

    let result = env.client.app_uninstall("sh.kotton.does-not-exist").await;

    assert!(
        result.is_err(),
        "uninstalling a non-existent app should return an error"
    );
}

/// Capability strings reported by the daemon match the declared manifest grants.
#[tokio::test]
async fn install_reports_correct_capability_strings() {
    let mut env = TestEnv::spawn_authed().await;

    let (_app_id, _name, caps) = env
        .client
        .app_install_approving_all("", NOTES_MANIFEST.to_string(), STUB_WASM.to_vec())
        .await
        .expect("app_install");

    assert!(
        caps.contains(&"schema.read:sh.kotton.notes".to_string()),
        "expected 'schema.read:sh.kotton.notes' in capabilities; got: {caps:?}"
    );
}

// ── The consent gate (security-audit H2) ─────────────────────────────────────
//
// Until 2026-08-30 `app_install` signed `manifest.capabilities` with the user's
// identity key, unattended: the signature attested "the user's key signed these
// bytes" and was produced automatically for whatever the app asked for. These
// drive the two-phase ceremony at the IPC boundary, which is the boundary that
// matters — the defect was reachable by *any* caller, so a client-side prompt
// would not have fixed it and a client-side test would not catch its return.

/// A preview reports what the app wants, and installs nothing.
#[tokio::test]
async fn a_preview_reports_what_is_asked_for_and_installs_nothing() {
    let mut env = TestEnv::spawn_authed().await;
    let (_, recovery_key) = setup_user(&mut env).await;
    env.client
        .login_with_recovery_key(&recovery_key, Some(USER.to_string()), None)
        .await
        .expect("login_with_recovery_key");

    let preview = env
        .client
        .app_install_preview(USER, NOTES_MANIFEST.to_string(), STUB_WASM.to_vec())
        .await
        .expect("preview");

    assert_eq!(preview.app_id, "sh.kotton.test-notes");
    assert!(
        preview
            .requested_display
            .iter()
            .any(|d| d.contains("sh.kotton.notes")),
        "the preview must name what it wants: {:?}",
        preview.requested_display
    );
    assert!(
        !preview.publisher_verified,
        "an unsigned stub must not read as publisher-verified"
    );

    // Nothing was installed — a preview the user declines leaves no trace.
    let apps = env.client.app_list().await.expect("app_list");
    assert!(
        !apps.iter().any(|a| a.app_id == "sh.kotton.test-notes"),
        "preview installed the app: {apps:?}"
    );
}

/// Approving nothing grants nothing — asserted against what the daemon stored.
///
/// **This test was theatre until 2026-09-03 and its own doc said so.** It was
/// written as `an_install_approving_nothing_grants_nothing`, planting the H2
/// auto-mint left it green, and it was renamed to `an_install_may_approve_nothing`
/// because installing succeeds either way and nothing could observe the stored
/// decision. `AppGrants` is that observation channel, so the assertion the name
/// always claimed is now actually made: the app is installed, it asked for
/// something, and it holds nothing.
#[tokio::test]
async fn an_install_approving_nothing_grants_nothing() {
    let mut env = TestEnv::spawn_authed().await;
    let (_, recovery_key) = setup_user(&mut env).await;
    env.client
        .login_with_recovery_key(&recovery_key, Some(USER.to_string()), None)
        .await
        .expect("login_with_recovery_key");

    let (app_id, _name, _caps) = env
        .client
        .app_install(USER, NOTES_MANIFEST.to_string(), STUB_WASM.to_vec(), vec![], vec![])
        .await
        .expect("install approving nothing must succeed");

    let grants = env.client.app_grants(&app_id).await.expect("app_grants");

    assert!(
        !grants.requested_display.is_empty(),
        "the fixture must ask for something, or this proves nothing"
    );
    match &grants.approved {
        Some(g) => assert!(
            g.is_empty(),
            "approved nothing must read back empty, got {:?}",
            grants.approved_display
        ),
        None => panic!(
            "an explicit empty approval must read back as Some(empty), not as \
             'never approved' — the two mean different things"
        ),
    }
    assert!(
        grants.approved_display.is_empty(),
        "an app approved for nothing must hold nothing, got {:?}",
        grants.approved_display
    );
}

/// The approval that was sent is the approval that is stored.
///
/// The narrowing case, and the one that shows `AppGrants` reports the decision
/// rather than echoing the manifest back: the app asks for read **and** write,
/// only read is approved, and what it holds is read alone.
#[tokio::test]
async fn a_partial_approval_is_stored_as_sent() {
    use kotton_schemas::{CapabilityGrant, CapabilityKind};

    let mut env = TestEnv::spawn_authed().await;
    let (_, recovery_key) = setup_user(&mut env).await;
    env.client
        .login_with_recovery_key(&recovery_key, Some(USER.to_string()), None)
        .await
        .expect("login_with_recovery_key");

    let preview = env
        .client
        .app_install_preview(USER, RW_MANIFEST.to_string(), STUB_WASM.to_vec())
        .await
        .expect("preview");
    assert_eq!(preview.requested.len(), 2, "fixture asks for read and write");

    let read_only: Vec<CapabilityGrant> = preview
        .requested
        .iter()
        .filter(|g| g.kind == CapabilityKind::Read)
        .cloned()
        .collect();
    assert_eq!(read_only.len(), 1);

    let (app_id, _, _) = env
        .client
        .app_install(
            USER,
            RW_MANIFEST.to_string(),
            STUB_WASM.to_vec(),
            read_only.clone(),
            vec![],
        )
        .await
        .expect("a narrowed install must succeed");

    let grants = env.client.app_grants(&app_id).await.expect("app_grants");
    assert_eq!(
        grants.requested_display.len(),
        2,
        "what it asked for is still reported"
    );
    assert_eq!(
        grants.approved_display,
        read_only
            .iter()
            .map(|g| g.display_string())
            .collect::<Vec<_>>(),
        "what it holds is exactly what was approved"
    );
}

/// The daemon refuses to sign a capability the app never requested.
///
/// This is the one that stops the approval channel becoming a new way to mint:
/// a compromised or buggy client cannot approve `media.camera` for an app whose
/// manifest asks only to read notes.
#[tokio::test]
async fn the_daemon_refuses_to_sign_what_the_app_never_asked_for() {
    use kotton_schemas::{CapabilityGrant, MediaDevice};

    let mut env = TestEnv::spawn_authed().await;
    let (_, recovery_key) = setup_user(&mut env).await;
    env.client
        .login_with_recovery_key(&recovery_key, Some(USER.to_string()), None)
        .await
        .expect("login_with_recovery_key");

    let err = env
        .client
        .app_install(
            USER,
            NOTES_MANIFEST.to_string(),
            STUB_WASM.to_vec(),
            vec![CapabilityGrant::media(MediaDevice::Camera)],
            vec![],
        )
        .await
        .expect_err("approving an unrequested capability must be refused");

    let text = err.to_string();
    assert!(
        text.contains("never declared") || text.contains("subset"),
        "the refusal should say why: {text}"
    );

    // And the refusal is total — no half-installed app left behind.
    let apps = env.client.app_list().await.expect("app_list");
    assert!(
        !apps.iter().any(|a| a.app_id == "sh.kotton.test-notes"),
        "a refused install left the app installed: {apps:?}"
    );
}


// ── Binding (RFC-0021), end to end ───────────────────────────────────────────

/// The user puts an app's storage somewhere the manifest did not suggest.
///
/// RFC-0021: "The user can accept the default or type any path they like. The
/// grant is issued against whatever they choose." Until 2026-09-03 the daemon
/// refused exactly this, because a rebound grant is not one the manifest
/// requested and `is_subset_of` said no — the rule that stops a client widening
/// also stopped the ceremony
/// (`TASK-the-subset-rule-forbids-the-binding`).
#[tokio::test]
async fn a_user_can_bind_a_shape_to_a_path_of_their_own() {
    let mut env = TestEnv::spawn_authed().await;
    let (_, recovery_key) = setup_user(&mut env).await;
    env.client
        .login_with_recovery_key(&recovery_key, Some(USER.to_string()), None)
        .await
        .expect("login_with_recovery_key");

    // RW_MANIFEST, not NOTES_MANIFEST: only `files.*` declares a resource with a
    // location. A schema NSID is not somewhere the user puts anything, and
    // `vfs_shapes()` correctly reports none for it — which is what the first
    // draft of this test got wrong.
    let preview = env
        .client
        .app_install_preview(USER, RW_MANIFEST.to_string(), STUB_WASM.to_vec())
        .await
        .expect("preview");

    // The preview must offer something to bind, or this proves nothing.
    let shape = preview
        .shapes
        .first()
        .expect("a files.* manifest must report a bindable shape")
        .clone();
    assert_eq!(shape.default_target, "/notes", "the manifest's suggestion");

    let (app_id, _, _) = env
        .client
        .app_install(
            USER,
            RW_MANIFEST.to_string(),
            STUB_WASM.to_vec(),
            vec![],
            vec![(shape.id.clone(), "/journal".to_owned())],
        )
        .await
        .expect("binding a declared shape to a chosen path must be accepted");

    let grants = env.client.app_grants(&app_id).await.expect("app_grants");
    assert!(
        grants.approved_display.iter().any(|d| d == "vfs.read:/journal"),
        "the app must hold what the user chose, got {:?}",
        grants.approved_display
    );
    assert!(
        !grants.approved_display.iter().any(|d| d == "vfs.read:/notes"),
        "and not what the manifest suggested: {:?}",
        grants.approved_display
    );
    assert!(
        grants.requested_display.iter().any(|d| d == "vfs.read:/notes"),
        "while the request is still reported as made"
    );
}

/// A binding cannot name a shape the app never declared.
///
/// The other half: the ceremony moves a target, it does not add a capability.
/// The daemon builds the grant from its own reading of the manifest, so there is
/// no shape to name and nothing to check.
#[tokio::test]
async fn a_binding_cannot_invent_a_shape() {
    let mut env = TestEnv::spawn_authed().await;
    let (_, recovery_key) = setup_user(&mut env).await;
    env.client
        .login_with_recovery_key(&recovery_key, Some(USER.to_string()), None)
        .await
        .expect("login_with_recovery_key");

    let err = env
        .client
        .app_install(
            USER,
            RW_MANIFEST.to_string(),
            STUB_WASM.to_vec(),
            vec![],
            vec![("files.read:9".to_owned(), "/".to_owned())],
        )
        .await
        .expect_err("an undeclared shape id must be refused");

    assert!(
        err.to_string().contains("files.read:9"),
        "the refusal should name it: {err}"
    );

    let apps = env.client.app_list().await.expect("app_list");
    assert!(
        !apps.iter().any(|a| a.app_id == "sh.kotton.test-rw"),
        "a refused install left the app behind: {apps:?}"
    );
}
