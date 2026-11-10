// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — schema-aware record operations
//!
//! Covers: record_insert, record_query (all + filter), record_delete,
//! record_open (found), record_open (not found).
//!
//! Uses the built-in `notes` core schema so no registration step is needed.

use crate::common::cli::{said, Cli};
use crate::common::{suite_schema, TestEnv};
use std::sync::LazyLock;

const USER: &str = "bob";
const NOTES: &str = kotton_common::namespace::NSID_NOTES;

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

/// A fork of a core schema records where it came from and nothing else. Published and
/// signed by the suite's key; the provenance is not under the signature.
static PINNABLE_NSID: LazyLock<String> = LazyLock::new(|| suite_schema("pinnable-note"));
static PINNABLE_DEF: LazyLock<String> = LazyLock::new(|| {
    use kotton_schemas::{FieldType, SchemaDefinition, SchemaField, SchemaId};
    // The description is under the digest, so it is written before the signature; the
    // provenance is not, and could be written after.
    let mut def = SchemaDefinition::new(
        SchemaId::parse(&*PINNABLE_NSID).unwrap(),
        1,
        vec![
            SchemaField::required("title", FieldType::String),
            SchemaField::required("body", FieldType::String),
            SchemaField::required("pinned", FieldType::Bool),
        ],
    )
    .with_description("A note, copied and given a pinned flag.")
    .with_forked_from(SchemaId::from_static(NOTES));
    kotton_crypto::schema_signature::sign(&mut def, &crate::common::suite_publisher_key()).unwrap();
    serde_json::to_string(&def).unwrap()
});

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
        .schema_register(USER, &PINNABLE_DEF)
        .await
        .expect("register the fork");

    let pinned = serde_json::json!({ "title": "Pinned", "body": "b", "pinned": true });
    env.client
        .record_insert(USER, &PINNABLE_NSID, pinned)
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

/// **`kotton record get` reads the record as the person it names, from the terminal.** A
/// fresh `kotton` process, holding only Bob's cached session, reads his note by its schema
/// and its id, and prints it as JSON on stdout.
#[tokio::test]
async fn a_record_is_read_from_the_terminal_as_its_owner() {
    let (env, cli, id) = a_note_and_a_terminal_holding_only_its_owners_session().await;
    let got = cli.run(&["record", "--user", USER, "get", "--schema", NOTES, &id]);
    assert_got_as_its_owner(&got, &id);
    drop(env);
}

/// **`kotton record list --schema kotton/notes` works on a fresh device** (kotton #471):
/// `kotton` names Kotton's key on every device with no petname record, so the short form
/// resolves, the note is listed, and `get` by it reads the note; a petname no key has is refused, exit 2,
/// saying so, and `schema show` takes the short form too.
#[tokio::test]
async fn record_list_takes_the_short_form_on_a_fresh_device() {
    let (env, cli, id) = a_note_and_a_terminal_holding_only_its_owners_session().await;
    let listed = cli.run(&["record", "--user", USER, "list", "--schema", "kotton/notes"]);
    assert!(listed.status.success(), "`record list --schema kotton/notes` failed.\n{}", said(&listed));
    // A table is a message, on stderr off a terminal; what matters is that the note is in it.
    assert!(said(&listed).contains(&id), "the note was not listed.\n{}", said(&listed));
    let got = cli.run(&["record", "--user", USER, "get", "--schema", "kotton/notes", &id]);
    assert_got_as_its_owner(&got, &id);
    let missing = cli.run(&["record", "--user", USER, "get", "--schema", "kotton/notes", "no-such-record"]);
    assert!(String::from_utf8_lossy(&missing.stderr).contains("kotton/notes"), "{}", said(&missing));
    let unknown = cli.run(&["record", "--user", USER, "list", "--schema", "acme/notes"]);
    assert_eq!(unknown.status.code(), Some(2), "{}", said(&unknown));
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("no key has the name 'acme'"), "{}", said(&unknown));
    let shown = cli.run(&["schema", "show", "kotton/notes", "--user", USER]);
    assert!(shown.status.success(), "`schema show kotton/notes` failed.\n{}", said(&shown));
    assert!(String::from_utf8_lossy(&shown.stdout).contains("\"notes\""), "{}", said(&shown));
    let schemas = cli.run(&["schema", "list", "--user", USER]);
    assert!(String::from_utf8_lossy(&schemas.stdout).contains("  kotton/notes\n"), "{}", said(&schemas));
    drop(env);
}

/// **`kotton` is Kotton's in any case, through the record verbs** (kotton #471): `record put
/// --schema kotton/petname` naming another key `Kotton` or `kotton ` is refused, exit 1, by
/// the daemon's rule, and nothing is stored; naming Kotton's own key so renames the built-in
/// name. **And a name is given one at a time**: `record import` under `petname`, by the short
/// form or whole, is refused, exit 2, before the file is read, and stores nothing.
#[tokio::test]
async fn record_put_keeps_kotton_for_kottons_key_and_import_refuses_names() {
    const PETNAME: &str = kotton_common::namespace::NSID_PETNAME;
    const ACME: &str = "did:key:z6MkeXBLjYiSvqnhFb6D7sHm8yKm4jV45wwBFRaatf1cfZ76";
    let (mut env, cli, _id) = a_note_and_a_terminal_holding_only_its_owners_session().await;
    for name in ["Kotton", "kotton ", "KOTTON"] {
        let body = serde_json::json!({ "key": ACME, "name": name }).to_string();
        let put = cli.run(&["record", "--user", USER, "put", "--schema", "kotton/petname", &body]);
        assert_eq!(put.status.code(), Some(1), "{name:?}: {}", said(&put));
        assert!(said(&put).contains("`kotton` names Kotton's publisher"), "{name:?}: {}", said(&put));
    }
    let personal = Some(kotton_wire::ipc::PERSONAL_ROOT);
    let held = env.client.record_query_in(USER, personal, None, PETNAME, vec![], None, None).await.expect("query");
    assert!(held.is_empty(), "a refused name was stored: {held:?}");

    let kottons = serde_json::json!({ "key": kotton_common::namespace::NSID_PREFIX, "name": "Kotton LLC" });
    let put = cli.run(&["record", "--user", USER, "put", "--schema", "kotton/petname", &kottons.to_string()]);
    assert!(put.status.success(), "renaming Kotton's key: {}", said(&put));
    let renamed = cli.run(&["record", "--user", USER, "list", "--schema", "Kotton LLC/notes"]);
    assert!(renamed.status.success(), "the new name resolves: {}", said(&renamed));
    let gone = cli.run(&["record", "--user", USER, "list", "--schema", "kotton/notes"]);
    assert_eq!(gone.status.code(), Some(2), "the built-in name is replaced: {}", said(&gone));

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("names.jsonl");
    std::fs::write(&file, format!("{}\n", serde_json::json!({ "key": ACME, "name": "My Bank" }))).unwrap();
    for schema in ["Kotton LLC/petname", PETNAME] {
        let import = cli.run(&["record", "--user", USER, "import", "--schema", schema, file.to_str().unwrap()]);
        assert_eq!(import.status.code(), Some(2), "{schema}: {}", said(&import));
        assert!(said(&import).contains("a name is given one at a time"), "{schema}: {}", said(&import));
    }
    let held = env.client.record_query_in(USER, personal, None, PETNAME, vec![], None, None).await.expect("query");
    assert_eq!(held.len(), 1, "an import stored a name: {held:?}");
    drop(env);
}

/// **`RecordSearch` returns no petname** (kotton #471), unfiltered, by its name, or by the
/// name a petname holds.
#[tokio::test]
async fn record_search_returns_no_petname() {
    const PETNAME: &str = kotton_common::namespace::NSID_PETNAME;
    const NAME: &str = "search-suite-petname-3a7c";
    let mut env = env_with_user().await;
    env.client
        .record_insert_in(
            USER,
            Some(kotton_wire::ipc::PERSONAL_ROOT),
            None,
            PETNAME,
            serde_json::json!({ "key": "did:key:z6MkeXBLjYiSvqnhFb6D7sHm8yKm4jV45wwBFRaatf1cfZ76", "name": NAME }),
        )
        .await
        .expect("the person's petname");
    for (filter, rows) in [
        ("none", env.client.record_search(USER, None, None, None).await.expect("search")),
        ("petname", env.client.record_search(USER, Some(PETNAME), None, None).await.expect("by schema")),
        ("its name", env.client.record_search(USER, None, Some(NAME), None).await.expect("by text")),
    ] {
        assert!(
            rows.iter().all(|r| r["schema_nsid"] != PETNAME && !r.to_string().contains(NAME)),
            "search ({filter}) returned a petname: {rows:?}"
        );
    }
}

/// **A bare `kotton record get` reads as the user `KOTTON_USER` names**, the way `--user`
/// does: a person who has set it in their shell does not name themselves again.
#[tokio::test]
async fn a_record_is_read_from_the_terminal_as_the_user_the_environment_names() {
    let (env, cli, id) = a_note_and_a_terminal_holding_only_its_owners_session().await;
    let got = cli.run_with_env(&["record", "get", "--schema", NOTES, &id], &[("KOTTON_USER", USER)]);
    assert_got_as_its_owner(&got, &id);
    drop(env);
}

/// **A bare `kotton record get` reads as the active identity** when neither `--user` nor
/// `KOTTON_USER` is given, the identity `kotton id use` made active.
#[tokio::test]
async fn a_record_is_read_from_the_terminal_as_the_active_identity() {
    let (env, cli, id) = a_note_and_a_terminal_holding_only_its_owners_session().await;
    let used = cli.run(&["id", "use", USER]);
    assert!(used.status.success(), "`kotton id use {USER}` failed.\n{}", said(&used));
    let got = cli.run(&["record", "get", "--schema", NOTES, &id]);
    assert_got_as_its_owner(&got, &id);
    drop(env);
}

/// **A missing id exits 1 at the terminal, and a retired word exits 2.** `kotton record get`
/// of an id no record has is a refusal, with the reason on stderr and nothing on stdout;
/// the word the command-tree decision's table retired for `get` is refused before any session.
#[tokio::test]
async fn a_missing_id_exits_one_and_the_retired_word_exits_two_at_the_terminal() {
    let (env, cli, _id) = a_note_and_a_terminal_holding_only_its_owners_session().await;
    let missing = cli.run(&["record", "--user", USER, "get", "--schema", NOTES, "no-such-record"]);
    assert_eq!(missing.status.code(), Some(1), "{}", said(&missing));
    assert!(missing.stdout.is_empty(), "a missing record printed a payload.\n{}", said(&missing));
    let retired = cli.run(&["record", "--user", USER, "open", &format!("kotton://records/{NOTES}/x")]);
    assert_eq!(retired.status.code(), Some(2), "{}", said(&retired));
    drop(env);
}

/// **A record put back with a daemon field added is refused, and stores no `_root`.** `record
/// get` prints Bob's note without the fields an answer adds; a hand that adds `_root` back, as
/// the query's answer spelled it, and puts the result is refused naming the field, and the
/// stored row is the note as it was: no `_root` in its body, and no new version of it.
#[tokio::test]
async fn a_record_put_back_with_a_daemon_field_is_refused_and_stores_no_root() {
    let (mut env, cli, id) = a_note_and_a_terminal_holding_only_its_owners_session().await;
    let got = cli.run(&["record", "--user", USER, "get", "--schema", NOTES, &id]);
    assert_got_as_its_owner(&got, &id);
    let mut body: serde_json::Value = serde_json::from_slice(&got.stdout).expect("the record as JSON");
    let rows = env.client.record_query(USER, NOTES, vec![], None, None).await.expect("query");
    let root = rows[0]["_root"].as_str().expect("an answer names the row's root").to_owned();
    body["_root"] = serde_json::json!(root);
    body["title"] = serde_json::json!("put back");
    let before = stored_note(&env, &id).await;

    let put = cli.run(&["record", "--user", USER, "put", "--schema", NOTES, &body.to_string()]);
    assert_eq!(put.status.code(), Some(1), "{}", said(&put));
    assert!(String::from_utf8_lossy(&put.stderr).contains("_root"), "the refusal names no field.\n{}", said(&put));

    let after = stored_note(&env, &id).await;
    assert!(after.0.get("_root").is_none(), "a daemon field was stored: {:?}", after.0);
    assert_eq!(after, before, "the refused put changed the stored note");
    drop(env);
}

/// Bob's note `id` as the store holds it: its body and its version, `(updated_at, revision)`,
/// read from the daemon's own `records.db`, under the key the person's secrets hold.
async fn stored_note(env: &TestEnv, id: &str) -> (serde_json::Value, (i64, i64)) {
    use kotton_record::record_store::RecordStore as _;
    let store = kotton_record::open::user_record_store(env.runtime.base_dir(), USER, env.runtime.secrets())
        .expect("Bob's record store");
    let changeset = store.export_changeset(0).await.expect("the store's rows");
    let row = changeset
        .into_iter()
        .find(|row| row.schema_nsid == NOTES && row.id == id)
        .unwrap_or_else(|| panic!("no note {id} is stored"));
    (row.body, (row.updated_at, row.revision))
}

/// Bob's note, and a CLI holding only Bob's cached session. Returns the note's id.
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
    (env, cli, id)
}

/// What `record get` printed is Bob's note, as JSON on stdout.
fn assert_got_as_its_owner(got: &std::process::Output, id: &str) {
    assert!(got.status.success(), "`kotton record get` failed.\n{}", said(got));
    let body: serde_json::Value = serde_json::from_slice(&got.stdout)
        .unwrap_or_else(|e| panic!("stdout is not the record as JSON: {e}\n{}", said(got)));
    assert_eq!(body["title"], "Opened", "{}", said(got));
    assert_eq!(body["id"], id, "{}", said(got));
    assert!(body.get("_root").is_none() && body.get("_id").is_none(), "get printed a daemon field: {}", said(got));
}

/// **`RecordSearch` returns no secret** (kotton #449): not across every schema, and not with
/// `secret` named as the filter, though the person keeps one in Personal and a note beside it
/// is found.
#[tokio::test]
async fn record_search_returns_no_secret_unfiltered_or_by_name() {
    const SECRET: &str = kotton_common::namespace::NSID_SECRET;
    const VALUE: &str = "search-suite-value-61f0";
    let mut env = env_with_user().await;
    env.client
        .record_insert_in(
            USER,
            Some(kotton_wire::ipc::PERSONAL_ROOT),
            None,
            SECRET,
            serde_json::json!({ "label": "bank", "value": VALUE, "kind": "password" }),
        )
        .await
        .expect("the person's secret");
    env.client
        .record_insert(USER, NOTES, serde_json::json!({ "title": "beside it", "body": "a note" }))
        .await
        .expect("a note");

    let all = env.client.record_search(USER, None, None, None).await.expect("search");
    assert!(all.iter().any(|r| r["body"]["title"] == "beside it"), "the note was not found: {all:?}");
    for (filter, rows) in [
        ("none", all),
        ("secret", env.client.record_search(USER, Some(SECRET), None, None).await.expect("search by secret")),
        ("its value", env.client.record_search(USER, None, Some(VALUE), None).await.expect("search by text")),
    ] {
        assert!(
            rows.iter().all(|r| r["schema_nsid"] != SECRET && !r.to_string().contains(VALUE)),
            "search ({filter}) returned a secret: {rows:?}"
        );
    }
}
