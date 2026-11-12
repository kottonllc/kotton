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

// ── the publisher's signature ─────────────────────────────────────────────────

/// What a test publisher signs: a manifest with no `[publisher]` and a code of its own.
const SIGNED_MANIFEST: &str = r#"
[app]
id      = "sh.kotton.test-signed"
name    = "Signed Test App"
version = "0.3.0"

[capabilities]
"schema.read" = ["did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/notes"]
"#;

fn a_publisher(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

/// `manifest` with a `[publisher]` block naming `key` and carrying `signature`.
fn with_publisher(manifest: &str, key: &ed25519_dalek::SigningKey, signature: &str) -> String {
    let did = kotton_app::app_signature::publisher_of(key);
    format!("{manifest}\n[publisher]\ndid = \"{did}\"\nsignature = \"{signature}\"\n")
}

/// The preview's word on the signature, and the install's answer, for `manifest` and `code`.
async fn preview_then_install(env: &mut TestEnv, manifest: String, code: &[u8]) -> (bool, std::io::Result<String>) {
    let preview = env
        .client
        .app_install_preview(USER, manifest.clone(), code.to_vec())
        .await
        .expect("a preview describes a package whatever its signature");
    let installed = env
        .client
        .app_install(USER, manifest, code.to_vec(), preview.requested, vec![])
        .await
        .map(|(id, _, _)| id);
    (preview.publisher_verified, installed)
}

/// **A manifest and its code signed together install as signed**, and a reordered copy of
/// the same manifest keeps the signature.
#[tokio::test]
async fn an_app_signed_over_its_manifest_and_code_installs_as_signed() {
    let mut env = TestEnv::spawn_authed().await;
    let key = a_publisher(21);
    let signed = kotton_app::app_signature::signed_manifest(SIGNED_MANIFEST, STUB_WASM, &key).unwrap();
    let (verified, installed) = preview_then_install(&mut env, signed, STUB_WASM).await;
    assert!(verified, "the preview did not find the signature good");
    assert_eq!(installed.expect("a signed app installs"), "sh.kotton.test-signed");
}

/// **A signature is over a manifest and a code as a pair**: the publisher's code under
/// someone else's manifest, and the publisher's manifest over someone else's code, are each
/// not shown as signed and not installed.
#[tokio::test]
async fn a_signature_does_not_carry_to_another_manifest_or_another_code() {
    let mut env = TestEnv::spawn_authed().await;
    let key = a_publisher(21);
    let signature = kotton_app::app_signature::sign(SIGNED_MANIFEST, STUB_WASM, &key).unwrap();

    let theirs = SIGNED_MANIFEST.replace("Signed Test App", "Another App").replace("schema.read", "schema.write");
    let (verified, installed) = preview_then_install(&mut env, with_publisher(&theirs, &key, &signature), STUB_WASM).await;
    assert!(!verified, "the code's signature carried to another manifest");
    let err = installed.expect_err("another manifest over the signed code installed").to_string();
    assert!(err.contains("publisher signature invalid"), "{err}");

    let other_code = [STUB_WASM, b"other"].concat();
    let (verified, installed) =
        preview_then_install(&mut env, with_publisher(SIGNED_MANIFEST, &key, &signature), &other_code).await;
    assert!(!verified, "the manifest's signature carried to another code");
    let err = installed.expect_err("the signed manifest over another code installed").to_string();
    assert!(err.contains("publisher signature invalid"), "{err}");
}

/// **A signature over the code's digest alone is no app signature**: refused at install,
/// and not shown as signed.
#[tokio::test]
async fn a_signature_over_the_code_alone_is_refused() {
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;
    let mut env = TestEnv::spawn_authed().await;
    let key = a_publisher(21);
    let code_only = key.sign(blake3::hash(STUB_WASM).as_bytes());
    let signature = base64::engine::general_purpose::STANDARD.encode(code_only.to_bytes());
    let (verified, installed) =
        preview_then_install(&mut env, with_publisher(SIGNED_MANIFEST, &key, &signature), STUB_WASM).await;
    assert!(!verified);
    let err = installed.expect_err("a code-only signature installed").to_string();
    assert!(err.contains("publisher signature invalid"), "{err}");
}

/// **A signed manifest with a key outside its types is refused as signed, naming the key**,
/// in `[app]` or beside the two strings of `[publisher]`; an unsigned manifest with the same
/// key installs, as before, with the key dropped.
#[tokio::test]
async fn a_key_outside_the_types_refuses_a_signed_manifest_and_not_an_unsigned_one() {
    let mut env = TestEnv::spawn_authed().await;
    let key = a_publisher(21);
    let extra = SIGNED_MANIFEST.replace("version = \"0.3.0\"\n", "version = \"0.3.0\"\nrole    = \"shell\"\n");
    assert_ne!(extra, SIGNED_MANIFEST);
    // Signed as the publisher's tool would sign the manifest without the key, then the key
    // added: the signature is good for what it signed, and the manifest is not that.
    let signature = kotton_app::app_signature::sign(SIGNED_MANIFEST, STUB_WASM, &key).unwrap();
    let (verified, installed) = preview_then_install(&mut env, with_publisher(&extra, &key, &signature), STUB_WASM).await;
    assert!(!verified, "a signed manifest with a key outside its types was shown as signed");
    let err = installed.expect_err("a signed manifest with a key outside its types installed").to_string();
    assert!(err.contains("`app.role`"), "the refusal does not name the key: {err}");

    // A good signature, with a key beside it in `[publisher]`, which no signature covers.
    let good = kotton_app::app_signature::signed_manifest(SIGNED_MANIFEST, STUB_WASM, &key).unwrap();
    let noted = format!("{good}note = \"signed by the bank\"\n");
    let (verified, installed) = preview_then_install(&mut env, noted, STUB_WASM).await;
    assert!(!verified, "a [publisher] with a key beside its two strings was shown as signed");
    let err = installed.expect_err("a [publisher] with a key beside its two strings installed").to_string();
    assert!(err.contains("`publisher.note`"), "the refusal does not name the key: {err}");

    let (verified, installed) = preview_then_install(&mut env, extra, STUB_WASM).await;
    assert!(!verified);
    assert_eq!(installed.expect("an unsigned manifest with a key outside its types installs"), "sh.kotton.test-signed");
}
