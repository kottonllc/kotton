// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — schema management
//!
//! Covers: schema_list (core schemas present on fresh daemon), schema_register
//! (app schema), schema_get (registered + not found).

use crate::common::cli::{said, Cli};
use crate::common::TestEnv;

/// The six core schemas that every daemon must register at boot.
const CORE_SCHEMAS: &[&str] = &[
    "sh.kotton.notes",
    "sh.kotton.contacts",
    "sh.kotton.calendar",
    "sh.kotton.messages",
    "sh.kotton.tasks",
    "sh.kotton.clipboard",
];

/// A minimal bookmark schema used for app-registration tests.
const BOOKMARK_NSID: &str = "com.test.bookmark";
const BOOKMARK_DEF: &str = r#"{
  "nsid": "com.test.bookmark",
  "version": 1,
  "fields": [
    { "name": "url",   "type": "string", "nullable": false },
    { "name": "title", "type": "string", "nullable": true  }
  ]
}"#;

// ── core schemas ──────────────────────────────────────────────────────────────

/// All six core schemas are present on a fresh daemon.
#[tokio::test]
async fn schema_list_includes_all_core_schemas() {
    let mut env = TestEnv::spawn_authed().await;
    let schemas = env.client.schema_list("owner").await.expect("schema_list");

    for nsid in CORE_SCHEMAS {
        assert!(
            schemas.contains(&nsid.to_string()),
            "expected core schema '{nsid}' in schema_list, got: {schemas:?}"
        );
    }
}

/// schema_get returns non-empty JSON for each core schema.
#[tokio::test]
async fn schema_get_returns_json_for_core_schemas() {
    let mut env = TestEnv::spawn_authed().await;

    for nsid in CORE_SCHEMAS {
        let json_str = env
            .client
            .schema_get("owner", nsid)
            .await
            .unwrap_or_else(|e| panic!("schema_get({nsid}) failed: {e}"));

        assert!(
            !json_str.is_empty(),
            "schema definition for '{nsid}' should not be empty"
        );

        // Must parse as a JSON object.
        let parsed: serde_json::Value =
            serde_json::from_str(&json_str).expect("schema definition should be valid JSON");
        assert_eq!(
            parsed["nsid"].as_str().unwrap_or(""),
            *nsid,
            "nsid field in definition should match {nsid}"
        );
    }
}

// ── schema_get not found ──────────────────────────────────────────────────────

/// schema_get returns an error for an unregistered NSID.
#[tokio::test]
async fn schema_get_unknown_nsid_errors() {
    let mut env = TestEnv::spawn_authed().await;
    let result = env.client.schema_get("owner", "com.unknown.schema").await;
    assert!(
        result.is_err(),
        "schema_get for an unknown NSID should return an error"
    );
}

// ── schema_register ───────────────────────────────────────────────────────────

/// Registering an app schema makes it appear in schema_list.
#[tokio::test]
async fn schema_register_appears_in_list() {
    let mut env = TestEnv::spawn_authed().await;

    env.client
        .schema_register("owner", BOOKMARK_DEF)
        .await
        .expect("schema_register");

    let schemas = env.client.schema_list("owner").await.expect("schema_list");
    assert!(
        schemas.contains(&BOOKMARK_NSID.to_string()),
        "registered schema '{BOOKMARK_NSID}' should appear in schema_list"
    );
}

/// After registering an app schema, schema_get returns a valid definition.
#[tokio::test]
async fn schema_register_then_get() {
    let mut env = TestEnv::spawn_authed().await;

    env.client
        .schema_register("owner", BOOKMARK_DEF)
        .await
        .expect("schema_register");

    let json_str = env
        .client
        .schema_get("owner", BOOKMARK_NSID)
        .await
        .expect("schema_get after register");

    let parsed: serde_json::Value =
        serde_json::from_str(&json_str).expect("definition should parse as JSON");

    assert_eq!(parsed["nsid"].as_str().unwrap_or(""), BOOKMARK_NSID);

    // The two registered fields must be present.
    let fields = parsed["fields"].as_array().expect("fields array");
    let field_names: Vec<&str> = fields.iter().filter_map(|f| f["name"].as_str()).collect();

    assert!(field_names.contains(&"url"), "url field should be present");
    assert!(
        field_names.contains(&"title"),
        "title field should be present"
    );
}

/// Registering invalid JSON returns an error.
#[tokio::test]
async fn schema_register_invalid_json_errors() {
    let mut env = TestEnv::spawn_authed().await;
    let result = env.client.schema_register("owner", "not json at all").await;
    assert!(
        result.is_err(),
        "registering invalid JSON should return an error"
    );
}

/// Re-registering the same schema definition is idempotent.
#[tokio::test]
async fn schema_register_idempotent() {
    let mut env = TestEnv::spawn_authed().await;

    env.client
        .schema_register("owner", BOOKMARK_DEF)
        .await
        .expect("first schema_register");

    // A second call with the same definition must not error.
    env.client
        .schema_register("owner", BOOKMARK_DEF)
        .await
        .expect("idempotent second schema_register");

    // NSID appears exactly once in the list.
    let schemas = env.client.schema_list("owner").await.expect("schema_list");
    let count = schemas
        .iter()
        .filter(|s| s.as_str() == BOOKMARK_NSID)
        .count();
    assert_eq!(
        count, 1,
        "schema should appear exactly once after idempotent register"
    );
}

// ── principal scoping ─────────────────────────────────────────────────────────

/// One user's registration is invisible to another: absent from their list, and
/// `schema_get` answers exactly as it does for a schema that does not exist.
/// (SCHEMA-REGISTRY-IS-MACHINE-WIDE — `SchemaList` was a readout of which apps
/// the other people on a machine run.)
#[tokio::test]
async fn another_users_registration_is_invisible() {
    let mut env = TestEnv::spawn_authed().await; // session user: "owner"

    env.client
        .schema_register("owner", BOOKMARK_DEF)
        .await
        .expect("schema_register as owner");

    // A second user on the same daemon, over its own authenticated connection.
    let mut other = kotton::KottonClient::connect_to(env.endpoint.clone())
        .await
        .expect("second client connects");
    other.create_user("neighbor", crate::common::TEST_PASSPHRASE).await.expect("create neighbor");

    let their_list = other.schema_list("neighbor").await.expect("schema_list");
    assert!(
        !their_list.contains(&BOOKMARK_NSID.to_string()),
        "another user's registration must not appear in neighbor's list"
    );

    let their_get = other.schema_get("neighbor", BOOKMARK_NSID).await;
    let unknown_get = other.schema_get("neighbor", "com.never.registered").await;
    assert!(
        their_get.is_err() && unknown_get.is_err(),
        "an unowned schema must answer like an absent one"
    );
}

/// The session guard owns the `user_id` on schema verbs like any other user
/// verb: a session for one user cannot list as another.
#[tokio::test]
async fn schema_list_for_another_user_is_refused() {
    let mut env = TestEnv::spawn_authed().await; // session user: "owner"

    let result = env.client.schema_list("somebody-else").await;
    assert!(
        result.is_err(),
        "a session for 'owner' must not list schemas as 'somebody-else'"
    );
}

// ── from the terminal ─────────────────────────────────────────────────────────

/// **`kotton schema register` registers as the person it names, from the terminal.** A fresh
/// `kotton` process, holding only the owner's cached session, registers a schema from a file;
/// it is then among the schemas the owner sees. `list` and `show` reach the daemon by the same
/// `connect_as(--user)`.
#[tokio::test]
async fn a_schema_is_registered_from_the_terminal_as_the_user_it_names() {
    const OWNER: &str = "owner";
    let mut env = TestEnv::spawn_cli_reachable().await;
    env.client.create_user(OWNER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("bookmark.json");
    std::fs::write(&path, BOOKMARK_DEF).expect("write the definition");
    let cli = Cli::for_env(&env);
    cli.seed_session(OWNER, env.client.session_token.as_deref().expect("owner logged in"));

    let registered = cli.run(&["schema", "register", path.to_str().expect("utf-8 path"), "--user", OWNER]);
    assert!(registered.status.success(), "`kotton schema register` failed.\n{}", said(&registered));
    let schemas = env.client.schema_list(OWNER).await.expect("schema_list");
    assert!(
        schemas.contains(&BOOKMARK_NSID.to_string()),
        "the schema registered from the terminal is the owner's: {schemas:?}"
    );
}
