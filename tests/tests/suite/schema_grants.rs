// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — schema grants, quota enforcement, and register permission
//!
//! Covers (RFC-0003 done-criteria):
//!  - Grant set/revoke persists and is immediately enforced
//!  - record_insert / record_query denied without a write/read grant
//!  - schema_register denied without can_register when app_id is present
//!  - Quota counters increment on insert and block at the limit
//!  - Quota override (set to larger limit) unblocks further inserts
//!  - Grants persist across daemon restart (re-spawn)

use crate::common::{connect_when_ready, wait_for_daemon, TestEnv};
use kotton_wire::ipc::{UserRequest, UserResponse};

trait UserResponseExt {
    fn is_error_containing(&self, fragment: &str) -> bool;
    fn is_error(&self) -> bool;
}

impl UserResponseExt for UserResponse {
    fn is_error_containing(&self, fragment: &str) -> bool {
        matches!(self, UserResponse::Error { message } if message.to_lowercase().contains(fragment))
    }

    fn is_error(&self) -> bool {
        matches!(self, UserResponse::Error { .. })
    }
}

const USER: &str = "alice";
const APP: &str = "com.test.notes-app";
const NOTES: &str = "sh.kotton.notes";
const APP_SCHEMA_NSID: &str = "com.test.grants-test-schema";

const APP_SCHEMA_DEF: &str = r#"{
  "nsid": "com.test.grants-test-schema",
  "version": 1,
  "fields": [
    { "name": "title", "type": "string", "nullable": false }
  ]
}"#;

/// Bootstrap helper — create user and return a TestEnv.
async fn env_with_user() -> TestEnv {
    let mut env = TestEnv::spawn_authed().await;
    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    env
}

// ── grant list ────────────────────────────────────────────────────────────────

/// A fresh daemon has no schema grants for an unknown app.
#[tokio::test]
async fn schema_grant_list_empty_for_new_app() {
    let mut env = TestEnv::spawn_authed().await;
    let grants = env
        .client
        .schema_grant_list(APP)
        .await
        .expect("schema_grant_list");
    assert!(
        grants.is_empty(),
        "expected no grants for a new app, got: {grants:?}"
    );
}

// ── grant set + list round-trip ───────────────────────────────────────────────

/// SchemaGrantSet creates a row visible via SchemaGrantList.
#[tokio::test]
async fn schema_grant_set_visible_in_list() {
    let mut env = TestEnv::spawn_authed().await;

    env.client
        .schema_grant_set(APP, NOTES, true, true, false)
        .await
        .expect("schema_grant_set");

    let grants = env
        .client
        .schema_grant_list(APP)
        .await
        .expect("schema_grant_list");

    assert_eq!(grants.len(), 1, "expected one grant row");
    let g = &grants[0];
    assert_eq!(g.app_id, APP);
    assert_eq!(g.nsid, NOTES);
    assert!(g.can_read, "can_read should be true");
    assert!(g.can_write, "can_write should be true");
    assert!(!g.can_register, "can_register should be false");
}

/// Updating a grant overwrites the previous can_* flags.
#[tokio::test]
async fn schema_grant_set_overwrites_existing() {
    let mut env = TestEnv::spawn_authed().await;

    env.client
        .schema_grant_set(APP, NOTES, true, true, false)
        .await
        .expect("initial set");

    // Narrow the grant: remove write access.
    env.client
        .schema_grant_set(APP, NOTES, true, false, false)
        .await
        .expect("update set");

    let grants = env.client.schema_grant_list(APP).await.expect("list");
    assert_eq!(grants.len(), 1);
    assert!(grants[0].can_read);
    assert!(!grants[0].can_write, "can_write should have been removed");
}

// ── grant revoke ──────────────────────────────────────────────────────────────

/// SchemaGrantRevoke removes the row.
#[tokio::test]
async fn schema_grant_revoke_removes_row() {
    let mut env = TestEnv::spawn_authed().await;

    env.client
        .schema_grant_set(APP, NOTES, true, false, false)
        .await
        .expect("set");

    env.client
        .schema_grant_revoke(APP, NOTES)
        .await
        .expect("revoke");

    let grants = env.client.schema_grant_list(APP).await.expect("list");
    assert!(
        grants.is_empty(),
        "grant row should be gone after revoke; got: {grants:?}"
    );
}

// ── read enforcement ──────────────────────────────────────────────────────────

/// record_query with app_id denied when no read grant exists.
#[tokio::test]
async fn record_query_denied_without_read_grant() {
    let mut env = env_with_user().await;

    // No grant row at all.
    let req = UserRequest::RecordQuery {
        user_id: USER.to_owned(),
        schema_nsid: NOTES.to_owned(),
        field_eq: vec![],
        limit: None,
        offset: None,
        root: None,
        app_id: Some(APP.to_owned()),
    };
    let resp = env.client.inner().send(&req).await.expect("send RecordQuery");

    assert!(
        resp.is_error_containing("permission denied"),
        "expected permission denied, got: {resp:?}"
    );
}

/// record_query allowed after a read grant is set.
#[tokio::test]
async fn record_query_allowed_with_read_grant() {
    let mut env = env_with_user().await;

    env.client
        .schema_grant_set(APP, NOTES, true, false, false)
        .await
        .expect("grant set");

    let req = UserRequest::RecordQuery {
        user_id: USER.to_owned(),
        schema_nsid: NOTES.to_owned(),
        field_eq: vec![],
        limit: None,
        offset: None,
        root: None,
        app_id: Some(APP.to_owned()),
    };
    let resp = env.client.inner().send(&req).await.expect("send RecordQuery");

    assert!(
        !resp.is_error(),
        "expected success after granting read, got: {resp:?}"
    );
}

/// record_query denied immediately after grant is revoked.
#[tokio::test]
async fn record_query_denied_after_revoke() {
    let mut env = env_with_user().await;

    env.client
        .schema_grant_set(APP, NOTES, true, false, false)
        .await
        .expect("grant set");

    env.client
        .schema_grant_revoke(APP, NOTES)
        .await
        .expect("revoke");

    let req = UserRequest::RecordQuery {
        user_id: USER.to_owned(),
        schema_nsid: NOTES.to_owned(),
        field_eq: vec![],
        limit: None,
        offset: None,
        root: None,
        app_id: Some(APP.to_owned()),
    };
    let resp = env.client.inner().send(&req).await.expect("send");
    assert!(
        resp.is_error_containing("permission denied"),
        "expected denied after revoke, got: {resp:?}"
    );
}

// ── write enforcement ─────────────────────────────────────────────────────────

/// record_insert with app_id denied when no write grant exists.
#[tokio::test]
async fn record_insert_denied_without_write_grant() {
    let mut env = env_with_user().await;

    let req = UserRequest::RecordInsert {
        user_id: USER.to_owned(),
        schema_nsid: NOTES.to_owned(),
        record: serde_json::json!({ "title": "t", "body": "b" }),
        root: None,
        app_id: Some(APP.to_owned()),
    };
    let resp = env.client.inner().send(&req).await.expect("send");
    assert!(
        resp.is_error_containing("permission denied"),
        "expected denied, got: {resp:?}"
    );
}

/// record_insert allowed after write grant set.
#[tokio::test]
async fn record_insert_allowed_with_write_grant() {
    let mut env = env_with_user().await;

    env.client
        .schema_grant_set(APP, NOTES, false, true, false)
        .await
        .expect("grant set");

    let req = UserRequest::RecordInsert {
        user_id: USER.to_owned(),
        schema_nsid: NOTES.to_owned(),
        record: serde_json::json!({ "title": "hello", "body": "world" }),
        root: None,
        app_id: Some(APP.to_owned()),
    };
    let resp = env.client.inner().send(&req).await.expect("send");
    assert!(
        !resp.is_error(),
        "expected success after write grant, got: {resp:?}"
    );
}

// ── schema.register enforcement ───────────────────────────────────────────────

/// schema_register with app_id denied when no can_register grant.
#[tokio::test]
async fn schema_register_denied_without_can_register() {
    let mut env = TestEnv::spawn_authed().await;

    // Grant read+write but NOT register.
    env.client
        .schema_grant_set(APP, APP_SCHEMA_NSID, true, true, false)
        .await
        .expect("grant set");

    let req = UserRequest::SchemaRegister {
        user_id: "owner".to_owned(),
        definition_json: APP_SCHEMA_DEF.to_owned(),
        app_id: Some(APP.to_owned()),
    };
    let resp = env.client.inner().send(&req).await.expect("send");
    assert!(
        resp.is_error_containing("permission denied"),
        "expected denied for schema.register without can_register, got: {resp:?}"
    );
}

/// schema_register with app_id succeeds when can_register is set.
#[tokio::test]
async fn schema_register_allowed_with_can_register() {
    let mut env = TestEnv::spawn_authed().await;

    env.client
        .schema_grant_set(APP, APP_SCHEMA_NSID, false, false, true)
        .await
        .expect("grant set");

    let req = UserRequest::SchemaRegister {
        user_id: "owner".to_owned(),
        definition_json: APP_SCHEMA_DEF.to_owned(),
        app_id: Some(APP.to_owned()),
    };
    let resp = env.client.inner().send(&req).await.expect("send");
    assert!(
        !resp.is_error(),
        "expected success with can_register, got: {resp:?}"
    );

    // Schema now appears in the list.
    let schemas = env.client.schema_list("owner").await.expect("schema_list");
    assert!(
        schemas.contains(&APP_SCHEMA_NSID.to_string()),
        "registered schema should appear in schema_list"
    );
}

/// schema_register without app_id (CLI/owner path) always succeeds.
#[tokio::test]
async fn schema_register_owner_path_always_succeeds() {
    let mut env = TestEnv::spawn_authed().await;

    // No grant row at all — owner path bypasses grant check.
    env.client
        .schema_register("owner", APP_SCHEMA_DEF)
        .await
        .expect("owner schema_register should always succeed");
}

// ── quota counters ────────────────────────────────────────────────────────────

/// record_count increments after each insert and is visible via schema_grant_list.
#[tokio::test]
async fn quota_record_count_increments_on_insert() {
    let mut env = env_with_user().await;

    env.client
        .schema_grant_set(APP, NOTES, false, true, false)
        .await
        .expect("grant set");

    let req = || UserRequest::RecordInsert {
        user_id: USER.to_owned(),
        schema_nsid: NOTES.to_owned(),
        record: serde_json::json!({ "title": "x", "body": "y" }),
        root: None,
        app_id: Some(APP.to_owned()),
    };

    env.client.inner().send(&req()).await.expect("insert 1");
    env.client.inner().send(&req()).await.expect("insert 2");
    env.client.inner().send(&req()).await.expect("insert 3");

    let grants = env.client.schema_grant_list(APP).await.expect("list");
    let g = grants.iter().find(|g| g.nsid == NOTES).expect("grant row");
    assert_eq!(
        g.record_count, 3,
        "record_count should be 3 after 3 inserts"
    );
}

/// Inserting beyond record_quota returns a quota-exceeded error.
#[tokio::test]
async fn quota_record_limit_enforced() {
    let mut env = env_with_user().await;

    env.client
        .schema_grant_set(APP, NOTES, false, true, false)
        .await
        .expect("grant set");

    // Set a tiny record quota of 2.
    env.client
        .schema_quota_set(APP, NOTES, 2, 0)
        .await
        .expect("quota_set");

    let req = || UserRequest::RecordInsert {
        user_id: USER.to_owned(),
        schema_nsid: NOTES.to_owned(),
        record: serde_json::json!({ "title": "x", "body": "y" }),
        root: None,
        app_id: Some(APP.to_owned()),
    };

    env.client.inner().send(&req()).await.expect("insert 1");
    env.client.inner().send(&req()).await.expect("insert 2");

    // Third insert must fail.
    let resp = env.client.inner().send(&req()).await.expect("send insert 3");
    assert!(
        resp.is_error_containing("quota exceeded"),
        "expected quota exceeded on 3rd insert with limit=2, got: {resp:?}"
    );
}

/// Raising the quota unblocks further inserts.
#[tokio::test]
async fn quota_override_unblocks_inserts() {
    let mut env = env_with_user().await;

    env.client
        .schema_grant_set(APP, NOTES, false, true, false)
        .await
        .expect("grant set");

    env.client
        .schema_quota_set(APP, NOTES, 1, 0)
        .await
        .expect("quota_set limit=1");

    let req = || UserRequest::RecordInsert {
        user_id: USER.to_owned(),
        schema_nsid: NOTES.to_owned(),
        record: serde_json::json!({ "title": "x", "body": "y" }),
        root: None,
        app_id: Some(APP.to_owned()),
    };

    env.client.inner().send(&req()).await.expect("insert 1");

    // Raise quota to 10.
    env.client
        .schema_quota_set(APP, NOTES, 10, 0)
        .await
        .expect("quota override to 10");

    // Now inserts succeed again.
    let resp = env.client.inner().send(&req()).await.expect("send insert 2");
    assert!(
        !resp.is_error(),
        "expected success after quota override, got: {resp:?}"
    );
}

// ── grant persistence across restart ─────────────────────────────────────────

/// Grants written before daemon shutdown are visible after a restart.
#[tokio::test]
async fn grants_persist_across_restart() {
    let base = tempfile::tempdir().expect("tempdir");
    let base_path = base.path().to_owned();
    let endpoint = crate::common::unique_ipc();

    // First daemon instance. Setting a grant is a control-plane op and now
    // requires a session (audit C2), so create the user under a device
    // credential and unlock with it after the restart.
    //
    // This used to log back in with the recovery phrase. The credential took the
    // roots out of platform storage at creation, so that login was reading the
    // signing key out of the phrase-sealed bundle — the silent path `DEC-0051`
    // closed. The phrase now opens data, never a key; the credential is what
    // reopens this device.
    let secrets: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    {
        let mut env =
            spawn_daemon_at(base_path.clone(), endpoint.clone(), Arc::clone(&secrets)).await;
        let (_did, _fp) = env.client.create_user("owner", crate::common::TEST_PASSPHRASE).await.expect("create_user");
        env.client
            .schema_grant_set(APP, NOTES, true, false, false)
            .await
            .expect("set grant");
        // env drops here — daemon is stopped.
    };

    // Second daemon instance at the same base_dir (reads from the same SQLite).
    // The user persisted; unlock with the device credential to re-establish a session.
    {
        let mut env = spawn_daemon_at(base_path, endpoint.clone(), secrets).await;
        let unlocked = env
            .client
            .unlock_with_pin("owner", crate::common::TEST_PASSPHRASE)
            .await
            .expect("unlock after restart");
        assert!(
            matches!(unlocked, kotton::PinUnlock::Unlocked),
            "the device credential reopens the account after a restart: {unlocked:?}"
        );
        let grants = env
            .client
            .schema_grant_list(APP)
            .await
            .expect("list after restart");
        assert_eq!(grants.len(), 1, "grant should persist after restart");
        assert_eq!(grants[0].nsid, NOTES);
        assert!(grants[0].can_read);
    }
}

// ── helpers for restart test ──────────────────────────────────────────────────

use kuserd::DeviceDaemon;
use kotton_sys::ipc::IpcEndpoint;
use kotton_secret::MemorySecrets;
use kotton_sys::secret::SecretsStore;
use kotton::KottonClient;
use std::path::PathBuf;
use std::sync::Arc;

/// Spawn a daemon at a fixed `base_path` and return a connected client.
///
/// The daemon task is aborted when the returned struct drops.
struct BoundEnv {
    client: KottonClient,
    _task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Drop for BoundEnv {
    fn drop(&mut self) {
        self._task.abort();
    }
}

/// `secrets` is shared across spawns at the same base dir: the OS keychain
/// persists across daemon restarts in production, and per-user databases are
/// keyed from it (RFC-0063 stage 3b) — a fresh store per spawn would model a
/// wiped keychain, which is not what a restart is.
async fn spawn_daemon_at(
    base_path: PathBuf,
    endpoint: IpcEndpoint,
    secrets: Arc<dyn SecretsStore + Send + Sync>,
) -> BoundEnv {
    let daemon = DeviceDaemon::new_with_base_and_secrets(base_path, endpoint.clone(), secrets)
        .await
        .expect("DeviceDaemon::new");

    let task = tokio::spawn(async move { std::sync::Arc::new(daemon).run().await });
    wait_for_daemon(&endpoint, "daemon").await;

    let client = connect_when_ready(&endpoint, "daemon").await;

    BoundEnv {
        client,
        _task: task,
    }
}
