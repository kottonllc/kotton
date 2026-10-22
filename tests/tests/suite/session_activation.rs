// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — session activation flow
//!
//! Verifies the mechanism the Tauri host's session watcher relies on:
//! a session token produced by one client connection (simulating `just user::create`
//! or `just login`) can authenticate a completely separate new connection to the
//! same daemon (simulating `try_activate_session` in the host).
//!
//! These tests cover the criterion:
//!   "`just up` → `just login <user>` → shell activates without a host restart"
//! at the IPC level, without requiring a running Tauri process.

use crate::common::TestEnv;
use kotton::KottonClient;

// ── helpers ──────────────────────────────────────────────────────────────────

const USER: &str = "alice";

// ── tests ────────────────────────────────────────────────────────────────────

/// A session token issued at `create_user` time authenticates a fresh
/// connection to the same daemon.
///
/// This mirrors what the host session watcher does:
/// 1. `just user::create <name>` → daemon issues a session token (saved to disk).
/// 2. Host opens a new client connection and calls `authenticate(token)`.
/// 3. The session is active; the shell can make authenticated API calls.
#[tokio::test]
async fn session_token_activates_fresh_connection() {
    let mut env = TestEnv::spawn().await;

    // Step 1: create a user — the client is now authenticated.
    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let token = env
        .client
        .session_token
        .clone()
        .expect("create_user must set a session token");

    // Step 2: open a brand-new, unauthenticated connection (simulates the
    // Tauri host waking up after `start_session_watcher` detects a .session file).
    let mut fresh = KottonClient::connect_to(env.endpoint.clone())
        .await
        .expect("connect_to");

    // Step 3: authenticate with the token — must succeed.
    fresh
        .authenticate(&token)
        .await
        .expect("authenticate with token from create_user");

    // Step 4: verify the fresh connection can make authenticated calls.
    let users = fresh
        .list_users()
        .await
        .expect("list_users on fresh connection");
    assert!(
        users.contains(&USER.to_string()),
        "authenticated fresh connection should see user '{USER}', got: {users:?}"
    );
}

/// A session token issued by `login_with_recovery_key` (the `just login` path
/// after a daemon restart) authenticates a fresh connection.
///
/// This mirrors the production restart flow:
/// 1. `just daemon` restarts — in-memory sessions cleared.
/// 2. `just login <name>` → `connect_as` tries cached token (fails), prompts
///    for recovery key, calls `login_with_recovery_key` → new token saved.
/// 3. Session watcher detects the new `.session` file and calls
///    `try_activate_session` → `authenticate(new_token)` succeeds.
///
/// Ignored for a reason that is not about sessions. Step 2 needs a working
/// recovery login, and the "daemon restart" in step 1 is simulated with
/// `logout_user`, which does not restart anything — it removes the identity and
/// its key history from the device. That was survivable while the phrase could
/// rebuild the identity; it is not now. The token half of this is already covered
/// by `session_token_activates_fresh_connection` above, which is why this one can
/// wait rather than be rewritten around the gap.
#[tokio::test]
#[ignore = "blocked on TASK-recovery-on-a-device-with-no-chain-has-nothing-to-verify-against"]
async fn session_token_from_recovery_key_activates_fresh_connection() {
    let mut env = TestEnv::spawn().await;

    // Create the user to register the identity with the daemon.
    let (_, _) = env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");

    // A phrase to log back in with — creation does not mint one.
    let recovery_key = env
        .client
        .add_recovery_phrase(USER)
        .await
        .expect("add_recovery_phrase");

    // Simulate a daemon restart by logging out (invalidates the current token).
    env.client.logout_user(USER).await.expect("logout_user");

    // Step 1: `just login` → login_with_recovery_key → new session token saved.
    env.client
        .login_with_recovery_key(&recovery_key, Some(USER.to_string()), None)
        .await
        .expect("login_with_recovery_key");
    let token = env
        .client
        .session_token
        .clone()
        .expect("login_with_recovery_key must set a session token");

    // Step 2: fresh connection (simulates host session watcher waking up).
    let mut fresh = KottonClient::connect_to(env.endpoint.clone())
        .await
        .expect("connect_to");

    // Step 3: authenticate.
    fresh
        .authenticate(&token)
        .await
        .expect("authenticate with recovery-key-issued token");

    // Step 4: verify.
    let users = fresh
        .list_users()
        .await
        .expect("list_users on fresh connection");
    assert!(
        users.contains(&USER.to_string()),
        "authenticated fresh connection should see user '{USER}', got: {users:?}"
    );
}

/// A stale token (from a logged-out session) is rejected by `authenticate`.
///
/// Verifies that `try_activate_session` will correctly fail and fall back to
/// prompting for re-authentication when the daemon has been restarted.
#[tokio::test]
async fn stale_token_is_rejected() {
    let mut env = TestEnv::spawn().await;

    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let stale_token = env
        .client
        .session_token
        .clone()
        .expect("create_user must set a session token");

    // Invalidate the token by logging out.
    env.client.logout_user(USER).await.expect("logout_user");

    // A fresh connection using the now-stale token must fail.
    let mut fresh = KottonClient::connect_to(env.endpoint.clone())
        .await
        .expect("connect_to");
    let result = fresh.authenticate(&stale_token).await;
    assert!(
        result.is_err(),
        "authenticate with a stale token should fail"
    );
}
