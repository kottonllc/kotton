// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — user lifecycle
//!
//! Covers: create_user, list_users, login_with_recovery_key, duplicate-user
//! error, and logout_user — the full "user on a device" happy path.

use crate::common::TestEnv;

// ── helpers ──────────────────────────────────────────────────────────────────

const USER: &str = "alice";

// ── tests ─────────────────────────────────────────────────────────────────────

/// Fresh daemon has no users.
#[tokio::test]
async fn list_users_empty_on_fresh_daemon() {
    let mut env = TestEnv::spawn().await;
    let users = env.client.list_users().await.expect("list_users");
    assert!(
        users.is_empty(),
        "expected no users on a fresh daemon, got: {users:?}"
    );
}

/// create_user returns a DID, recovery key, and device fingerprint.
#[tokio::test]
async fn create_user_returns_credentials() {
    let mut env = TestEnv::spawn().await;
    let (did, fingerprint) = env
        .client
        .create_user(USER, crate::common::TEST_PASSPHRASE)
        .await
        .expect("create_user");

    assert!(did.starts_with("did:"), "DID should start with 'did:' — got {did:?}");
    assert!(!fingerprint.is_empty(), "device fingerprint should not be empty");

    // No recovery phrase comes back, and that is the assertion rather than an
    // omission: creation mints one no longer, so an identity begins with no way
    // back in and a person sets that up when they want it.
    let phrase = env
        .client
        .add_recovery_phrase(USER)
        .await
        .expect("add_recovery_phrase");
    assert!(!phrase.is_empty(), "setting up recovery returns a phrase");
}

/// After create_user the user appears in list_users.
#[tokio::test]
async fn created_user_appears_in_list() {
    let mut env = TestEnv::spawn().await;
    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");

    let users = env.client.list_users().await.expect("list_users");
    assert!(
        users.contains(&USER.to_string()),
        "expected '{USER}' in user list, got: {users:?}"
    );
}

/// Creating the same user_id twice returns an error.
#[tokio::test]
async fn create_duplicate_user_errors() {
    let mut env = TestEnv::spawn().await;
    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("first create_user");

    let result = env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await;
    assert!(
        result.is_err(),
        "duplicate create_user should return an error"
    );
}

/// RFC-0038 recovery rotation over IPC: rotating with the mnemonic returns a new
/// operational key while the `did:kel` identity is preserved, and a foreign
/// mnemonic is rejected.
#[tokio::test]
async fn rotate_identity_preserves_the_did() {
    let mut env = TestEnv::spawn().await;
    // Create bob first (grabs his mnemonic) so alice remains the authenticated
    // session for the wrong-mnemonic check below.
    let (_bob_did, _bf) = env.client.create_user("bob", crate::common::TEST_PASSPHRASE).await.expect("create bob");
    let bob_key = env
        .client
        .add_recovery_phrase("bob")
        .await
        .expect("bob's phrase");
    let (did, _af) = env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create alice");
    let alice_key = env
        .client
        .add_recovery_phrase(USER)
        .await
        .expect("alice's phrase");
    assert!(did.starts_with("did:kel:"), "new identity is did:kel, got {did}");

    // A foreign mnemonic cannot rotate alice's identity.
    assert!(
        env.client.rotate_identity(USER, &bob_key, Some(crate::common::TEST_PASSPHRASE)).await.is_err(),
        "a foreign mnemonic must be rejected"
    );

    // Alice's own mnemonic rotates the key and returns the new operational key.
    let new_key = env
        .client
        .rotate_identity(USER, &alice_key, Some(crate::common::TEST_PASSPHRASE))
        .await
        .expect("rotate_identity");
    assert_eq!(new_key.len(), 64, "new operational verifying key is 32-byte hex");

    // The identity (DID) is unchanged — the user is still present under the same AID.
    let users = env.client.list_users().await.expect("list_users");
    assert!(users.contains(&USER.to_string()));
}

/// login_with_recovery_key re-loads the user from the 24-word phrase and
/// returns the same user_id.
///
/// Ignored, not deleted: this is the product goal, and the assertion should stay
/// legible while the capability behind it is built. `logout_user` is not a session
/// logout — it removes the identity from the device, and the key history goes with
/// it. The phrase used to rebuild that history because the inception derived from
/// the mnemonic; a random identity key means it cannot, and the chain has to come
/// from somewhere else. Un-ignore when it can.
#[tokio::test]
#[ignore = "blocked on TASK-recovery-on-a-device-with-no-chain-has-nothing-to-verify-against"]
async fn login_with_recovery_key_roundtrip() {
    let mut env = TestEnv::spawn().await;
    let (_, _) = env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    // Creation mints no phrase, so a login-by-phrase test sets one up first. That
    // is the sequence a person follows, and a test that skipped it would exercise
    // a state the product no longer produces.
    let recovery_key = env
        .client
        .add_recovery_phrase(USER)
        .await
        .expect("add_recovery_phrase");

    // Log out first so the key is no longer loaded.
    env.client.logout_user(USER).await.expect("logout_user");

    let (returned_user, _fingerprint) = env
        .client
        .login_with_recovery_key(&recovery_key, Some(USER.to_string()), None)
        .await
        .expect("login_with_recovery_key");

    assert_eq!(returned_user, USER);
}

/// A phrase alice's key log does not commit, with her name, is refused by the
/// daemon while she is resident and unlocked, and leaves her roots, her sealed
/// copy and the registry as they were. The name says which log to check; it is
/// not the answer.
#[tokio::test]
async fn a_phrase_her_log_does_not_commit_does_not_open_resident_alice() {
    use kotton_identity::provisioning::{
        recovery_bundle_path, resolve_master_secret, resolve_operational_cek,
    };
    use kotton_sys::crypto::MnemonicProvider as _;

    let mut env = TestEnv::spawn().await;
    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let phrase = env.client.add_recovery_phrase(USER).await.expect("add_recovery_phrase");
    env.client
        .login_with_recovery_key(&phrase, Some(USER.to_string()), None)
        .await
        .expect("alice's own phrase opens her session");
    assert!(env.users.get(USER).is_some(), "alice is resident");

    let held = |env: &TestEnv| {
        let secrets = env.runtime.secrets();
        let label = kotton_common::crypto::kdf_labels::identity_signing_key(USER);
        (
            resolve_master_secret(secrets, USER).expect("the master secret reads"),
            resolve_operational_cek(secrets, USER).expect("the cek reads"),
            secrets.get_secret(&label).expect("the identity key reads"),
            std::fs::read(recovery_bundle_path(&env.base_dir, USER)).ok(),
            std::fs::read(env.base_dir.join("system").join("users.json")).ok(),
        )
    };
    let before = held(&env);
    assert!(before.0.is_some(), "alice is unlocked: her master secret is held");

    let wrong = kotton_crypto::Bip39MnemonicProvider.generate().expect("a phrase nobody holds");
    let refused = env
        .client
        .login_with_recovery_key(&wrong, Some(USER.to_string()), None)
        .await;
    let err = refused.expect_err("a phrase alice's log does not commit opened her session");
    assert!(
        err.to_string().contains("not an authority in 'alice's key log"),
        "the refusal says why: {err}"
    );
    assert!(held(&env) == before, "a refused phrase login changed alice's roots, copy or record");
}

/// After logout_user the user no longer appears in list_users.
#[tokio::test]
async fn logout_user_removes_from_list() {
    let mut env = TestEnv::spawn().await;
    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    env.client.logout_user(USER).await.expect("logout_user");

    let users = env.client.list_users().await.expect("list_users");
    assert!(
        !users.contains(&USER.to_string()),
        "user '{USER}' should be absent after logout, got: {users:?}"
    );
}

/// logout_user on an unknown user returns an error.
#[tokio::test]
async fn logout_unknown_user_errors() {
    let mut env = TestEnv::spawn().await;
    let result = env.client.logout_user("nobody").await;
    assert!(result.is_err(), "logout of unknown user should fail");
}

/// **A recovery login naming what is not a user id is refused before anything
/// is read or written under it** (kotton #262). A name given to
/// `LoginWithRecoveryKey` can become a user on this device — a cold device's
/// locked claim, which `Recover` then acts for — so it is held to the rule
/// `CreateUser` holds, and every user id this device registers is one the peer
/// path's `UserId::parse` accepts. A name that climbs out of `users/` is
/// refused with the rule's words, leaves no directory where it points, and
/// lists no user.
#[tokio::test]
async fn a_recovery_login_naming_no_valid_user_id_is_refused_and_leaves_nothing() {
    use kotton_sys::crypto::MnemonicProvider as _;
    let mut env = TestEnv::spawn().await;
    let phrase = kotton_crypto::Bip39MnemonicProvider.generate().expect("a phrase");
    let unique = uuid::Uuid::new_v4().simple().to_string();
    let escaping = format!("../x-{unique}");
    for named in [escaping.as_str(), "Alice", ""] {
        let refused = env
            .client
            .login_with_recovery_key(&phrase, Some(named.to_string()), None)
            .await;
        let err = refused.expect_err("a recovery login under a name that is not a user id was taken");
        assert!(
            err.to_string().contains("user_id"),
            "the refusal for {named:?} names the rule: {err}"
        );
    }
    assert!(
        !env.base_dir.join("users").join(&escaping).exists(),
        "a refused recovery login created a directory at users/{escaping}"
    );
    let users = env.client.list_users().await.expect("list_users");
    assert!(users.is_empty(), "a refused recovery login left a user: {users:?}");
}
