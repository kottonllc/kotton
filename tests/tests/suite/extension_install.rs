// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — extension install (RFC-0049 / RFC-0050).
//!
//! The acceptance path for program authoring: a package goes in through the
//! real IPC verbs, the daemon verifies it, and it lands with the capabilities
//! its *class* implies rather than the ones it asked for.

use crate::common::cli::{said, Cli};
use crate::common::TestEnv;

const USER: &str = "";

/// Enough bytes to be stored; the daemon validates the component model at
/// *load*, not install, so the structural checks under test do not need a real
/// component.
const STUB_WASM: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

const FETCHER: &str = r#"
[extension]
id = "sh.kotton.test-fetcher"
name = "Test Fetcher"
version = "0.1.0"
class = "fetcher"
description = "A fetcher for tests."

[network]
purpose = "Fetch the configured feed."
endpoints = ["*.substack.com", "hnrss.org"]
"#;

#[tokio::test]
async fn an_extension_installs_and_lists_with_its_declared_endpoints() {
    let mut env = TestEnv::spawn_authed().await;

    let outcome = env
        .client
        .extension_install(USER, FETCHER.to_string(), STUB_WASM.to_vec())
        .await
        .expect("extension_install");

    assert_eq!(outcome.extension_id, "sh.kotton.test-fetcher");
    assert_eq!(outcome.class, "fetcher");
    assert!(!outcome.signed, "no [publisher] section means unsigned");
    assert_eq!(outcome.content_hash.len(), 64, "BLAKE3 hex");

    // The consent summary the daemon produced — clients render this rather than
    // composing their own, so no surface can show a softer version.
    let consent = outcome.consent_summary.join("\n");
    assert!(consent.contains("*.substack.com"), "got:\n{consent}");
    assert!(consent.contains("UNSIGNED"), "got:\n{consent}");

    let listed = env.client.extension_list(USER).await.expect("extension_list");
    let found = listed
        .iter()
        .find(|e| e.extension_id == "sh.kotton.test-fetcher")
        .expect("installed extension appears in the listing");
    assert_eq!(found.class, "fetcher");
    assert_eq!(found.endpoints, vec!["*.substack.com", "hnrss.org"]);
    assert!(found.publisher_did.is_none());
}

/// A manifest the daemon cannot fully understand must be **refused**, not
/// installed with silently narrower reach than its author intended.
#[tokio::test]
async fn an_unenforceable_endpoint_pattern_is_refused() {
    let mut env = TestEnv::spawn_authed().await;

    let bad = r#"
[extension]
id = "sh.kotton.test-bad-pattern"
name = "Bad Pattern"
version = "0.1.0"
class = "fetcher"

[network]
purpose = "Anywhere."
endpoints = ["https://example.com/path"]
"#;

    let err = env
        .client
        .extension_install(USER, bad.to_string(), STUB_WASM.to_vec())
        .await
        .expect_err("an unparseable endpoint must fail the install");
    let msg = err.to_string();
    assert!(msg.contains("endpoint") || msg.contains("rejected"), "got: {msg}");

    let listed = env.client.extension_list(USER).await.expect("extension_list");
    assert!(
        !listed.iter().any(|e| e.extension_id == "sh.kotton.test-bad-pattern"),
        "a refused install must leave nothing behind"
    );
}

/// The escape hatch removed on 2026-08-10 stays removed: a manifest written
/// against the older draft fails loudly rather than installing with narrower
/// reach than its author expected.
#[tokio::test]
async fn dynamic_endpoints_is_refused() {
    let mut env = TestEnv::spawn_authed().await;

    let legacy = r#"
[extension]
id = "sh.kotton.test-dynamic"
name = "Dynamic"
version = "0.1.0"
class = "fetcher"

[network]
purpose = "Anywhere."
dynamic-endpoints = true
"#;

    let err = env
        .client
        .extension_install(USER, legacy.to_string(), STUB_WASM.to_vec())
        .await
        .expect_err("dynamic-endpoints must be refused");
    assert!(
        err.to_string().contains("dynamic-endpoints"),
        "the error should name the offending key: {err}"
    );
}

#[tokio::test]
async fn removing_an_extension_takes_it_out_of_the_listing() {
    let mut env = TestEnv::spawn_authed().await;

    env.client
        .extension_install(USER, FETCHER.to_string(), STUB_WASM.to_vec())
        .await
        .expect("install");

    env.client
        .extension_remove(USER, "sh.kotton.test-fetcher")
        .await
        .expect("remove");

    let listed = env.client.extension_list(USER).await.expect("extension_list");
    assert!(
        !listed.iter().any(|e| e.extension_id == "sh.kotton.test-fetcher"),
        "removed extension must not be listed"
    );

    // Removing something that is not installed is an error, not a silent no-op.
    assert!(
        env.client
            .extension_remove(USER, "sh.kotton.test-fetcher")
            .await
            .is_err(),
        "removing an absent extension should report it"
    );
}

/// **`kotton extension install` installs for the person it names, from the terminal.** A fresh
/// `kotton` process, holding only that person's cached session, installs the package from its
/// directory; the extension is then in their listing. `list` and `remove` reach the daemon by
/// the same `connect_as(--user)`.
#[tokio::test]
async fn an_extension_is_installed_from_the_terminal_as_the_user_it_names() {
    const ALICE: &str = "alice";
    let mut env = TestEnv::spawn_cli_reachable().await;
    env.client.create_user(ALICE, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let package = tempfile::tempdir().expect("tempdir");
    std::fs::write(package.path().join("manifest.toml"), FETCHER).expect("write manifest");
    std::fs::write(package.path().join("extension.wasm"), STUB_WASM).expect("write wasm");
    let cli = Cli::for_env(&env);
    cli.seed_session(ALICE, env.client.session_token.as_deref().expect("alice logged in"));

    let dir = package.path().to_str().expect("utf-8 path");
    let installed = cli.run(&["extension", "install", dir, "--user", ALICE, "--yes"]);
    assert!(installed.status.success(), "`kotton extension install` failed.\n{}", said(&installed));
    assert_eq!(
        String::from_utf8_lossy(&installed.stdout).lines().next(),
        Some("Installed Test Fetcher (sh.kotton.test-fetcher)"),
        "{}",
        said(&installed)
    );
    let listed = env.client.extension_list(ALICE).await.expect("extension_list");
    assert!(
        listed.iter().any(|e| e.extension_id == "sh.kotton.test-fetcher"),
        "the extension is in alice's listing: {listed:?}"
    );
}
