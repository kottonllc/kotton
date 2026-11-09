// SPDX-License-Identifier: AGPL-3.0-or-later
//! `record export` and `record import`, at the terminal: a file of records out of one device
//! and into another, and an `.ics` in (kotton #454).
//!
//! Every line is a real `kotton` process, holding only the person's cached session, so the
//! path it is given is read and written by the process it was typed at, and never by a
//! daemon. The second device is a second daemon with its own store, not paired with the
//! first: what reaches it is the file, and nothing else.

use std::collections::BTreeMap;

use crate::common::cli::{said, Cli};
use crate::common::TestEnv;
use kotton_common::namespace::{NSID_CALENDAR, NSID_IMPORTED_CALENDAR, NSID_NOTES};

const USER: &str = "bob";

/// A device of Bob's, with a terminal holding only his cached session.
async fn a_device() -> (TestEnv, Cli) {
    let mut env = TestEnv::spawn_cli_reachable().await;
    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let cli = Cli::for_env(&env);
    cli.seed_session(USER, env.client.session_token.as_deref().expect("bob logged in"));
    (env, cli)
}

/// Bob's notes on `env`, as `record get` prints them (no daemon `_`-field), by id.
async fn notes_on(env: &mut TestEnv) -> BTreeMap<String, serde_json::Value> {
    let rows = env.client.record_query(USER, NSID_NOTES, vec![], None, None).await.expect("query");
    rows.into_iter()
        .map(|mut r| {
            r.as_object_mut().expect("a row is an object").retain(|k, _| !k.starts_with('_'));
            (r["id"].as_str().expect("a row's id").to_string(), r)
        })
        .collect()
}

/// **Records exported on one device import on a second as they were, and a second import
/// of the file changes nothing** (kotton #454's done-when). The file is JSON Lines, a
/// record per line, each with its `id` and none of the fields a daemon adds, so it carries
/// no identifier the records did not already have; and an export does not write over a file
/// that is already there.
#[tokio::test]
async fn records_exported_on_one_device_import_on_a_second_and_again_change_nothing() {
    let (mut a, cli_a) = a_device().await;
    for (title, body) in [("milk", "two pints"), ("bread", "a loaf"), ("tea", "a box of it")] {
        a.client
            .record_insert(USER, NSID_NOTES, serde_json::json!({ "title": title, "body": body }))
            .await
            .expect("insert on A");
    }
    let held_on_a = notes_on(&mut a).await;
    assert_eq!(held_on_a.len(), 3);

    let dir = tempfile::tempdir().expect("a directory of Bob's");
    let file = dir.path().join("notes.jsonl");
    let file_arg = file.to_str().expect("utf-8 path");
    let exported = cli_a.run(&["record", "--user", USER, "export", "--schema", NSID_NOTES, file_arg]);
    assert!(exported.status.success(), "`kotton record export` failed.\n{}", said(&exported));

    let written = std::fs::read_to_string(&file).expect("the export is at the path Bob typed");
    let lines: Vec<serde_json::Value> =
        written.lines().map(|l| serde_json::from_str(l).expect("each line is one JSON record")).collect();
    assert_eq!(lines.len(), 3, "one line per record:\n{written}");
    for line in &lines {
        let fields = line.as_object().expect("a line is an object");
        assert!(fields.keys().all(|k| !k.starts_with('_')), "the export carries a daemon field: {line}");
        let id = line["id"].as_str().expect("a line keeps its record's id");
        assert_eq!(Some(line), held_on_a.get(id), "the export changed a record");
    }

    // A second export to the same path is refused, and the file is as it was.
    let again = cli_a.run(&["record", "--user", USER, "export", "--schema", NSID_NOTES, file_arg]);
    assert_eq!(again.status.code(), Some(1), "an export wrote over a file.\n{}", said(&again));
    assert_eq!(std::fs::read_to_string(&file).expect("still there"), written);

    // The second device holds nothing of Bob's notes until the file is imported there.
    let (mut b, cli_b) = a_device().await;
    assert!(notes_on(&mut b).await.is_empty(), "B held notes before the import");
    let imported = cli_b.run(&["record", "--user", USER, "import", "--schema", NSID_NOTES, file_arg]);
    assert!(imported.status.success(), "`kotton record import` failed.\n{}", said(&imported));
    assert_eq!(notes_on(&mut b).await, held_on_a, "B does not hold what A exported");

    // A second import of the same file puts each record by its id again: nothing new.
    let twice = cli_b.run(&["record", "--user", USER, "import", "--schema", NSID_NOTES, file_arg]);
    assert!(twice.status.success(), "the second import failed.\n{}", said(&twice));
    assert_eq!(notes_on(&mut b).await, held_on_a, "a second import changed B's records");

    // A file that is not records is refused whole: nothing of it is put.
    let bad = dir.path().join("bad.jsonl");
    std::fs::write(&bad, "{\"title\":\"kept out\",\"body\":\"x\"}\nnot a record\n").expect("write");
    let refused = cli_b.run(&["record", "--user", USER, "import", "--schema", NSID_NOTES, bad.to_str().unwrap()]);
    assert_eq!(refused.status.code(), Some(1), "{}", said(&refused));
    assert_eq!(notes_on(&mut b).await, held_on_a, "a refused file put a record");
    drop((a, b));
}

/// The export under test in `import_ics`, with five importable events and one mangled.
const ICS: &[u8] = include_bytes!("../../fixtures/calendar/a-life.ics");

/// **An `.ics` imports at the terminal as calendar events, and `kotton import` points
/// there.** `record import` reads the file by its extension and the daemon writes its
/// events as the one schema a calendar is read as; the calendar schema, for an `.ics`, is
/// refused with that line; and the retired word exits 2 naming it, before any session.
#[tokio::test]
async fn an_ics_imports_at_the_terminal_and_the_old_word_names_the_new_one() {
    let (mut env, cli) = a_device().await;
    let dir = tempfile::tempdir().expect("a directory of Bob's");
    let file = dir.path().join("a-life.ics");
    std::fs::write(&file, ICS).expect("write the calendar");
    let file_arg = file.to_str().expect("utf-8 path");

    let as_calendar = cli.run(&["record", "--user", USER, "import", "--schema", NSID_CALENDAR, file_arg]);
    assert_eq!(as_calendar.status.code(), Some(2), "{}", said(&as_calendar));
    assert!(String::from_utf8_lossy(&as_calendar.stderr).contains(NSID_IMPORTED_CALENDAR), "{}", said(&as_calendar));

    let imported = cli.run(&["record", "--user", USER, "import", "--schema", NSID_IMPORTED_CALENDAR, file_arg]);
    assert!(imported.status.success(), "`kotton record import` of an .ics failed.\n{}", said(&imported));
    let events = env.client.record_query(USER, NSID_IMPORTED_CALENDAR, vec![], None, None).await.expect("query");
    assert_eq!(events.len(), 5, "the five importable events, and not the mangled one");
    for event in &events {
        assert_eq!(event["source"]["file"], "a-life.ics", "provenance is the file's name, never its path");
    }

    let old = cli.run(&["import", file_arg, "--user", USER]);
    assert_eq!(old.status.code(), Some(2), "{}", said(&old));
    let want = format!("record import --schema {NSID_IMPORTED_CALENDAR} <path>");
    assert!(String::from_utf8_lossy(&old.stderr).contains(&want), "{}", said(&old));
    drop(env);
}
