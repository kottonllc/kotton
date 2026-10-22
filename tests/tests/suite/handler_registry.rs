// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — handler registry
//!
//! Covers: handler_list (empty), register first (auto-default), register
//! second (doesn't steal default), handler_get_for, handler_set_default
//! (explicit switch), handler_unregister (promotes remaining), unregister last.

use crate::common::cli::{said, Cli};
use crate::common::TestEnv;

const NSID: &str = "com.test.handler-registry-tests";
const APP_A: &str = "com.example.app-a";
const APP_B: &str = "com.example.app-b";

// ── empty state ───────────────────────────────────────────────────────────────

/// handler_list returns an empty vec on a fresh daemon.
#[tokio::test]
async fn handler_list_empty_on_fresh_daemon() {
    let mut env = TestEnv::spawn_authed().await;
    let entries = env.client.handler_list().await.expect("handler_list");
    let test_entries: Vec<_> = entries.iter().filter(|e| e.nsid == NSID).collect();
    assert!(
        test_entries.is_empty(),
        "expected no handlers for '{NSID}' on fresh daemon, got: {test_entries:?}"
    );
}

/// handler_get_for returns an error when no handler is registered.
#[tokio::test]
async fn handler_get_for_unregistered_nsid_errors() {
    let mut env = TestEnv::spawn_authed().await;
    let result = env.client.handler_get_for(NSID).await;
    assert!(
        result.is_err(),
        "handler_get_for should error for an unregistered NSID"
    );
}

// ── register ──────────────────────────────────────────────────────────────────

/// Registering the first handler for an NSID makes it the default automatically.
#[tokio::test]
async fn first_registered_handler_becomes_default() {
    let mut env = TestEnv::spawn_authed().await;
    env.client
        .handler_register(APP_A, NSID)
        .await
        .expect("handler_register");

    let entry = env
        .client
        .handler_get_for(NSID)
        .await
        .expect("handler_get_for");

    assert_eq!(entry.app_id, APP_A, "first handler should be the default");
    assert!(
        entry.is_default,
        "first handler should be marked is_default"
    );
}

/// Registering a second handler for the same NSID does NOT steal the default.
#[tokio::test]
async fn second_handler_does_not_steal_default() {
    let mut env = TestEnv::spawn_authed().await;
    env.client
        .handler_register(APP_A, NSID)
        .await
        .expect("register app-a");
    env.client
        .handler_register(APP_B, NSID)
        .await
        .expect("register app-b");

    let default_entry = env
        .client
        .handler_get_for(NSID)
        .await
        .expect("handler_get_for");

    assert_eq!(
        default_entry.app_id, APP_A,
        "original default should remain after second registration"
    );
}

/// handler_list returns both registrations after two apps register.
#[tokio::test]
async fn handler_list_shows_all_registrations() {
    let mut env = TestEnv::spawn_authed().await;
    env.client
        .handler_register(APP_A, NSID)
        .await
        .expect("register app-a");
    env.client
        .handler_register(APP_B, NSID)
        .await
        .expect("register app-b");

    let entries = env.client.handler_list().await.expect("handler_list");
    let app_ids: Vec<&str> = entries.iter().map(|e| e.app_id.as_str()).collect();

    assert!(
        app_ids.contains(&APP_A),
        "app-a should appear in handler list"
    );
    assert!(
        app_ids.contains(&APP_B),
        "app-b should appear in handler list"
    );
}

/// Registering the same (app_id, nsid) pair twice is idempotent.
#[tokio::test]
async fn duplicate_register_is_idempotent() {
    let mut env = TestEnv::spawn_authed().await;
    env.client
        .handler_register(APP_A, NSID)
        .await
        .expect("first register");
    env.client
        .handler_register(APP_A, NSID)
        .await
        .expect("idempotent second register");

    let entries = env.client.handler_list().await.expect("handler_list");
    let count = entries.iter().filter(|e| e.app_id == APP_A).count();
    assert_eq!(
        count, 1,
        "duplicate registration should not create two entries"
    );
}

// ── set_default ───────────────────────────────────────────────────────────────

/// handler_set_default switches which app is the default.
#[tokio::test]
async fn handler_set_default_changes_default() {
    let mut env = TestEnv::spawn_authed().await;
    env.client
        .handler_register(APP_A, NSID)
        .await
        .expect("register app-a");
    env.client
        .handler_register(APP_B, NSID)
        .await
        .expect("register app-b");

    env.client
        .handler_set_default(APP_B, NSID)
        .await
        .expect("handler_set_default");

    let entry = env
        .client
        .handler_get_for(NSID)
        .await
        .expect("handler_get_for after set_default");

    assert_eq!(
        entry.app_id, APP_B,
        "default should now be app-b after explicit set_default"
    );
}

/// handler_set_default on an unregistered app returns an error.
#[tokio::test]
async fn handler_set_default_on_unregistered_errors() {
    let mut env = TestEnv::spawn_authed().await;
    // Register only app-a; try to promote app-b as default.
    env.client
        .handler_register(APP_A, NSID)
        .await
        .expect("register app-a");

    let result = env.client.handler_set_default(APP_B, NSID).await;
    assert!(
        result.is_err(),
        "set_default for unregistered app-b should error"
    );
}

// ── unregister ────────────────────────────────────────────────────────────────

/// Unregistering the default when another handler exists promotes the other.
#[tokio::test]
async fn unregister_default_promotes_remaining() {
    let mut env = TestEnv::spawn_authed().await;
    env.client
        .handler_register(APP_A, NSID)
        .await
        .expect("register app-a");
    env.client
        .handler_register(APP_B, NSID)
        .await
        .expect("register app-b");

    // Unregister the default (app-a).
    env.client
        .handler_unregister(APP_A, NSID)
        .await
        .expect("unregister app-a");

    // app-b should now be the default.
    let entry = env
        .client
        .handler_get_for(NSID)
        .await
        .expect("handler_get_for after unregister");

    assert_eq!(
        entry.app_id, APP_B,
        "app-b should become default after app-a is removed"
    );
}

/// Unregistering the last handler leaves the registry empty for that NSID.
#[tokio::test]
async fn unregister_last_handler_leaves_nsid_empty() {
    let mut env = TestEnv::spawn_authed().await;
    env.client
        .handler_register(APP_A, NSID)
        .await
        .expect("register app-a");
    env.client
        .handler_unregister(APP_A, NSID)
        .await
        .expect("unregister app-a");

    let result = env.client.handler_get_for(NSID).await;
    assert!(
        result.is_err(),
        "handler_get_for should error when no handlers remain"
    );

    let entries = env.client.handler_list().await.expect("handler_list");
    let test_entries: Vec<_> = entries.iter().filter(|e| e.nsid == NSID).collect();
    assert!(
        test_entries.is_empty(),
        "handler_list should have no entries for '{NSID}' after last handler is removed"
    );
}

// ── from the terminal ─────────────────────────────────────────────────────────

/// **`kotton handler register` writes the registry of the person it names, from the
/// terminal.** A fresh `kotton` process, holding only the owner's cached session, registers an
/// app for a schema; the owner's registry then names it the default. The other four verbs
/// reach the daemon by the same `connect_as(--user)`.
#[tokio::test]
async fn a_handler_is_registered_from_the_terminal_as_the_user_it_names() {
    const OWNER: &str = "owner";
    let mut env = TestEnv::spawn_cli_reachable().await;
    env.client.create_user(OWNER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let cli = Cli::for_env(&env);
    cli.seed_session(OWNER, env.client.session_token.as_deref().expect("owner logged in"));

    let registered = cli.run(&["handler", "register", APP_A, NSID, "--user", OWNER]);
    assert!(registered.status.success(), "`kotton handler register` failed.\n{}", said(&registered));
    let entry = env.client.handler_get_for(NSID).await.expect("handler_get_for");
    assert_eq!(entry.app_id, APP_A, "the owner's registry names the app registered from the terminal");
    assert!(entry.is_default);
}
