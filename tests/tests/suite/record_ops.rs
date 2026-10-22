// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — schema-aware record operations
//!
//! Covers: record_insert, record_query (all + filter), record_delete,
//! record_open (found), record_open (not found).
//!
//! Uses the built-in `sh.kotton.notes` core schema so no registration step
//! is needed.

use crate::common::cli::{said, Cli};
use crate::common::TestEnv;

const USER: &str = "bob";
const NOTES: &str = "sh.kotton.notes";

/// Helper — ensure user exists and return a `TestEnv`.
async fn env_with_user() -> TestEnv {
    let mut env = TestEnv::spawn().await;
    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    env
}

// ── insert ────────────────────────────────────────────────────────────────────

/// record_insert returns a non-empty record ID.
#[tokio::test]
async fn record_insert_returns_id() {
    let mut env = env_with_user().await;
    let record = serde_json::json!({ "title": "Hello", "body": "World" });
    let id = env
        .client
        .record_insert(USER, NOTES, record)
        .await
        .expect("record_insert");
    assert!(!id.is_empty(), "record id should not be empty");
}

// ── query ─────────────────────────────────────────────────────────────────────

/// Inserted records appear in a query with no predicates.
#[tokio::test]
async fn record_query_returns_inserted_records() {
    let mut env = env_with_user().await;

    env.client
        .record_insert(
            USER,
            NOTES,
            serde_json::json!({ "title": "A", "body": "a body" }),
        )
        .await
        .expect("insert A");
    env.client
        .record_insert(
            USER,
            NOTES,
            serde_json::json!({ "title": "B", "body": "b body" }),
        )
        .await
        .expect("insert B");

    let records = env
        .client
        .record_query(USER, NOTES, vec![], None, None)
        .await
        .expect("record_query");

    assert_eq!(
        records.len(),
        2,
        "expected 2 records, got {}",
        records.len()
    );
}

/// A field_eq predicate filters results correctly.
#[tokio::test]
async fn record_query_with_field_filter() {
    let mut env = env_with_user().await;

    env.client
        .record_insert(
            USER,
            NOTES,
            serde_json::json!({ "title": "Keep", "body": "keep me" }),
        )
        .await
        .expect("insert Keep");
    env.client
        .record_insert(
            USER,
            NOTES,
            serde_json::json!({ "title": "Drop", "body": "ignore me" }),
        )
        .await
        .expect("insert Drop");

    let results = env
        .client
        .record_query(
            USER,
            NOTES,
            vec![("title".to_string(), serde_json::json!("Keep"))],
            None,
            None,
        )
        .await
        .expect("record_query with filter");

    assert_eq!(results.len(), 1, "filter should return exactly 1 record");
    assert_eq!(results[0]["title"], "Keep");
}

/// Limit + offset paginates correctly.
#[tokio::test]
async fn record_query_limit_offset() {
    let mut env = env_with_user().await;

    for i in 0..5u32 {
        env.client
            .record_insert(
                USER,
                NOTES,
                serde_json::json!({ "title": format!("note-{i}"), "body": "" }),
            )
            .await
            .expect("insert");
    }

    // page 1 — first 2
    let page1 = env
        .client
        .record_query(USER, NOTES, vec![], Some(2), Some(0))
        .await
        .expect("page 1");
    assert_eq!(page1.len(), 2);

    // page 2 — next 2
    let page2 = env
        .client
        .record_query(USER, NOTES, vec![], Some(2), Some(2))
        .await
        .expect("page 2");
    assert_eq!(page2.len(), 2);

    // No overlap between pages.
    assert_ne!(page1[0]["id"], page2[0]["id"], "pages must not overlap");
}

// ── delete ────────────────────────────────────────────────────────────────────

/// record_delete soft-deletes a record; it no longer appears in queries.
#[tokio::test]
async fn record_delete_removes_from_query() {
    let mut env = env_with_user().await;

    let id = env
        .client
        .record_insert(
            USER,
            NOTES,
            serde_json::json!({ "title": "Bye", "body": "going away" }),
        )
        .await
        .expect("insert");

    env.client
        .record_delete(USER, NOTES, &id)
        .await
        .expect("record_delete");

    let records = env
        .client
        .record_query(USER, NOTES, vec![], None, None)
        .await
        .expect("query after delete");

    let still_there = records.iter().any(|r| r["id"] == id);
    assert!(
        !still_there,
        "deleted record should not appear in query results"
    );
}

// ── record_open ───────────────────────────────────────────────────────────────

/// record_open returns the correct body for an existing record URL.
#[tokio::test]
async fn record_open_returns_existing_record() {
    let mut env = env_with_user().await;

    let id = env
        .client
        .record_insert(
            USER,
            NOTES,
            serde_json::json!({ "title": "Opened", "body": "open body" }),
        )
        .await
        .expect("insert");

    let url = format!("kotton://records/{NOTES}/{id}");
    let result = env
        .client
        .record_open(USER, &url)
        .await
        .expect("record_open");

    let (nsid, body) = result.expect("record should be found");
    assert_eq!(nsid, NOTES);
    assert_eq!(body["title"], "Opened");
}

/// record_open returns None for a URL that doesn't match any record.
#[tokio::test]
async fn record_open_returns_none_for_missing_record() {
    let mut env = env_with_user().await;
    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.ok(); // already created above in other tests

    let phantom_id = uuid::Uuid::new_v4().to_string();
    let url = format!("kotton://records/{NOTES}/{phantom_id}");

    let result = env
        .client
        .record_open(USER, &url)
        .await
        .expect("record_open should not error for missing records");

    assert!(result.is_none(), "non-existent record should return None");
}

/// record_open on a malformed URL returns an error.
#[tokio::test]
async fn record_open_rejects_malformed_url() {
    let mut env = env_with_user().await;
    let result = env.client.record_open(USER, "not-a-kotton-url").await;
    assert!(result.is_err(), "malformed URL should return an error");
}

// ── forks are not subtypes (DEC-0027) ─────────────────────────────────────────

/// A fork of a core schema records where it came from and nothing else.
const PINNABLE_NSID: &str = "com.test.pinnable-note";
const PINNABLE_DEF: &str = r#"{
    "nsid": "com.test.pinnable-note",
    "version": 1,
    "forked_from": "sh.kotton.notes",
    "description": "A note, copied and given a pinned flag.",
    "fields": [
        { "name": "title",  "type": "string", "nullable": false },
        { "name": "body",   "type": "string", "nullable": false },
        { "name": "pinned", "type": "bool",   "nullable": false }
    ]
}"#;

/// **The proof for `TASK-a-schema-grant-widens-to-subtypes`.**
///
/// Under the old subtype model, a query for the base returned the fork's records
/// too — and the grant was checked once, against the base, so an app granted
/// notes read every extension of notes that any other app had registered. A fork
/// is not a subtype: asking for notes returns notes.
#[tokio::test]
async fn a_query_for_the_origin_does_not_return_records_of_a_fork() {
    let mut env = env_with_user().await;

    env.client
        .schema_register(USER, PINNABLE_DEF)
        .await
        .expect("register the fork");

    let pinned = serde_json::json!({ "title": "Pinned", "body": "b", "pinned": true });
    env.client
        .record_insert(USER, PINNABLE_NSID, pinned)
        .await
        .expect("insert under the fork");

    let plain = serde_json::json!({ "title": "Plain", "body": "b" });
    env.client
        .record_insert(USER, NOTES, plain)
        .await
        .expect("insert under the origin");

    let notes = env
        .client
        .record_query(USER, NOTES, vec![], None, None)
        .await
        .expect("query the origin");

    assert_eq!(notes.len(), 1, "the origin's query must answer with the origin's records only");
    assert_eq!(notes[0]["title"], "Plain");
    assert!(
        notes.iter().all(|r| r["pinned"].is_null()),
        "a fork's records must not appear in a query for what it was forked from: {notes:?}"
    );
}

/// Every row a query returns can be addressed — the `_id` asymmetry the fan-out
/// used to create cannot recur while there is one branch producing rows.
#[tokio::test]
async fn every_queried_row_carries_its_id() {
    let mut env = env_with_user().await;
    env.client
        .record_insert(USER, NOTES, serde_json::json!({ "title": "t", "body": "b" }))
        .await
        .expect("insert");

    let rows = env
        .client
        .record_query(USER, NOTES, vec![], None, None)
        .await
        .expect("query");

    assert!(!rows.is_empty());
    for row in &rows {
        assert!(
            row["_id"].as_str().is_some_and(|s| !s.is_empty()),
            "every row needs an addressable id: {row:?}"
        );
    }
}

// ── from the terminal ─────────────────────────────────────────────────────────

/// **`kotton record open` reads the record as the person it names, from the terminal.** A
/// fresh `kotton` process, holding only Bob's cached session, opens his note by its URL.
#[tokio::test]
async fn a_record_is_opened_from_the_terminal_as_its_owner() {
    let mut env = TestEnv::spawn_cli_reachable().await;
    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let id = env
        .client
        .record_insert(USER, NOTES, serde_json::json!({ "title": "Opened", "body": "from a terminal" }))
        .await
        .expect("insert");
    let cli = Cli::for_env(&env);
    cli.seed_session(USER, env.client.session_token.as_deref().expect("bob logged in"));

    let url = format!("kotton://records/{NOTES}/{id}");
    let opened = cli.run(&["record", "open", &url, "--user", USER]);
    assert!(opened.status.success(), "`kotton record open` failed.\n{}", said(&opened));
    let stdout = String::from_utf8_lossy(&opened.stdout).into_owned();
    assert_eq!(stdout.lines().next(), Some(format!("nsid: {NOTES}").as_str()), "{}", said(&opened));
    assert!(stdout.contains("\"title\": \"Opened\""), "the note's body is printed.\n{}", said(&opened));
}

/// **A bare `kotton record open <url>` opens as the user `KOTTON_USER` names**, the way
/// `--user` does: a person who has set it in their shell does not name themselves again.
#[tokio::test]
async fn a_record_is_opened_from_the_terminal_as_the_user_the_environment_names() {
    let (env, cli, url) = a_note_and_a_terminal_holding_only_its_owners_session().await;
    let opened = cli.run_with_env(&["record", "open", &url], &[("KOTTON_USER", USER)]);
    assert_opened_as_its_owner(&opened);
    drop(env);
}

/// **A bare `kotton record open <url>` opens as the active identity** when neither
/// `--user` nor `KOTTON_USER` is given, the identity `kotton id use` made active.
#[tokio::test]
async fn a_record_is_opened_from_the_terminal_as_the_active_identity() {
    let (env, cli, url) = a_note_and_a_terminal_holding_only_its_owners_session().await;
    let used = cli.run(&["id", "use", USER]);
    assert!(used.status.success(), "`kotton id use {USER}` failed.\n{}", said(&used));
    let opened = cli.run(&["record", "open", &url]);
    assert_opened_as_its_owner(&opened);
    drop(env);
}

/// Bob's note, and a CLI holding only Bob's cached session.
async fn a_note_and_a_terminal_holding_only_its_owners_session() -> (TestEnv, Cli, String) {
    let mut env = TestEnv::spawn_cli_reachable().await;
    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let id = env
        .client
        .record_insert(USER, NOTES, serde_json::json!({ "title": "Opened", "body": "from a terminal" }))
        .await
        .expect("insert");
    let cli = Cli::for_env(&env);
    cli.seed_session(USER, env.client.session_token.as_deref().expect("bob logged in"));
    (env, cli, format!("kotton://records/{NOTES}/{id}"))
}

fn assert_opened_as_its_owner(opened: &std::process::Output) {
    assert!(opened.status.success(), "`kotton record open` failed.\n{}", said(opened));
    let stdout = String::from_utf8_lossy(&opened.stdout).into_owned();
    assert_eq!(stdout.lines().next(), Some(format!("nsid: {NOTES}").as_str()), "{}", said(opened));
    assert!(stdout.contains("\"title\": \"Opened\""), "the note's body is printed.\n{}", said(opened));
}
