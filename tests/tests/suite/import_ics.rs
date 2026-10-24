// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — a person brings their calendar with them.
//!
//! `TASK-a-person-brings-their-history-with-them`, first unit: `.ics`. The
//! fixture is one an incumbent could have written — a UTC appointment, a
//! recurring standup with an alarm and one moved occurrence, an all-day
//! holiday, a flight given as a `DURATION`, a `VTIMEZONE` block, and one
//! mangled event with no start — so what these tests count is what a real
//! export costs, not what a tidy one does.

use std::sync::Arc;

use kotton::ImportFormat;
use kotton_record::import_cmds::{imported_calendar_schema, IMPORTED_CALENDAR_NSID};
use kotton_schemas::membership::Posture;
use kotton_secret::MemorySecrets;
use kotton_sys::secret::SecretsStore;
use kuserd::DeviceDaemon;

use crate::common::{
    connect_when_ready, enroll_streamed, init_crypto, unique_ipc, wait_for_daemon, TestEnv,
};

const USER: &str = "ada";

/// The export under test. A file rather than a string literal: the reader's job
/// is to survive what an export actually looks like — CRLF, folded lines,
/// escaped text — and a literal in a test is quietly normalised by whoever edits
/// it next.
const FIXTURE: &[u8] = include_bytes!("../../fixtures/calendar/a-life.ics");

/// Five importable `VEVENT`s and one the export mangled.
const IMPORTABLE: usize = 5;
const MANGLED: usize = 1;

async fn env_with_user() -> TestEnv {
    let mut env = TestEnv::spawn().await;
    env.client
        .create_user(USER, crate::common::TEST_PASSPHRASE)
        .await
        .expect("create_user");
    env
}

/// Every event in the export is a record in the person's own store afterwards,
/// and the one the export mangled is reported rather than folded into the total.
#[tokio::test]
async fn an_ics_export_becomes_records_in_the_persons_store() {
    let mut env = env_with_user().await;

    let (nsid, imported, skipped) = env
        .client
        .import(USER, ImportFormat::Ics, "a-life.ics", FIXTURE.to_vec())
        .await
        .expect("import");

    assert_eq!(nsid, IMPORTED_CALENDAR_NSID);
    assert_eq!(imported as usize, IMPORTABLE);
    assert_eq!(
        skipped as usize, MANGLED,
        "an event with no start is counted, not invented"
    );

    let records = env
        .client
        .record_query(USER, IMPORTED_CALENDAR_NSID, vec![], None, None)
        .await
        .expect("record_query");
    assert_eq!(records.len(), IMPORTABLE, "every event is a record");
}

/// The two events that cost an importer its honesty: a recurring series and an
/// all-day holiday. A reader that drops the rule brings one Monday morning
/// instead of a standing meeting; one that stamps a date with `Z` moves a
/// holiday by however far the person is from Greenwich.
#[tokio::test]
async fn the_recurring_and_the_all_day_event_survive_the_trip() {
    let mut env = env_with_user().await;
    env.client
        .import(USER, ImportFormat::Ics, "a-life.ics", FIXTURE.to_vec())
        .await
        .expect("import");

    let records = env
        .client
        .record_query(USER, IMPORTED_CALENDAR_NSID, vec![], None, None)
        .await
        .expect("record_query");
    let by_title = |title: &str| {
        records
            .iter()
            .find(|r| r["title"] == title)
            .unwrap_or_else(|| panic!("no record titled {title}"))
            .clone()
    };

    let standup = by_title("Standup");
    assert_eq!(
        standup["recurrence"], "FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR",
        "the rule travels with the event, unexpanded"
    );
    assert_eq!(standup["time_zone"], "America/New_York");
    assert_eq!(
        standup["start_at"], "2026-01-05T09:30:00",
        "a zoned wall-clock time is not relabelled UTC"
    );
    assert_eq!(standup["participants"].as_array().unwrap().len(), 2);
    assert_eq!(
        standup["description"],
        serde_json::Value::Null,
        "the VALARM's description belongs to the alarm"
    );

    let holiday = by_title("Independence Day");
    assert_eq!(holiday["all_day"], true);
    assert_eq!(holiday["start_at"], "2026-07-04T00:00:00");
    assert_eq!(
        holiday["end_at"], "2026-07-05T00:00:00",
        "RFC 5545 makes an all-day end exclusive, and `all_day` says which convention this is"
    );

    // The moved occurrence is its own record and says so, so it is not read as a
    // duplicate of the series.
    let moved = by_title("Standup (moved)");
    assert_eq!(moved["recurrence_id"], "20260112T093000");

    // A `DURATION` resolves against its start rather than being dropped.
    let flight = by_title("Flight to Lisbon");
    assert_eq!(flight["end_at"], "2026-03-02T13:55:00Z");
}

/// Provenance is a field, and it is the export's **name** — not the path it was
/// read from. A record travels to every device the person owns; where they keep
/// their downloads is not part of their calendar.
#[tokio::test]
async fn every_imported_record_says_where_it_came_from() {
    let mut env = env_with_user().await;
    env.client
        .import(
            USER,
            ImportFormat::Ics,
            "/home/ada/Downloads/a-life.ics",
            FIXTURE.to_vec(),
        )
        .await
        .expect("import");

    let records = env
        .client
        .record_query(USER, IMPORTED_CALENDAR_NSID, vec![], None, None)
        .await
        .expect("record_query");
    assert_eq!(records.len(), IMPORTABLE);
    for record in &records {
        assert_eq!(
            record["source"]["file"], "a-life.ics",
            "provenance is the file's name; the path is not in the record"
        );
        assert!(
            record["source"]["imported_at"].as_str().is_some_and(|t| !t.is_empty()),
            "provenance says when, or it answers half the question"
        );
    }
}

/// The shape the importer declares is the person's, registered under their
/// identity — and it is a fork of the commons, not a rewrite of it
/// (`DEC-0027`, `DEC-0042`).
#[tokio::test]
async fn the_import_declares_a_shape_the_person_owns() {
    let mut env = env_with_user().await;
    env.client
        .import(USER, ImportFormat::Ics, "a-life.ics", FIXTURE.to_vec())
        .await
        .expect("import");

    let schemas = env.client.schema_list(USER).await.expect("schema_list");
    assert!(
        schemas.iter().any(|s| s == IMPORTED_CALENDAR_NSID),
        "the declaration is visible to the person who owns the records: {schemas:?}"
    );

    // A fork is not a subtype: asking the commons for events does not return
    // these, which is why the assistant reads across schemas rather than one.
    let core = env
        .client
        .record_query(USER, "sh.kotton.calendar", vec![], None, None)
        .await
        .expect("record_query on the core schema");
    assert!(
        core.is_empty(),
        "a query for the origin does not return records of a fork (DEC-0027)"
    );

    // …and cross-schema search, which is how the assistant will reach them, does.
    let hits = env
        .client
        .record_search(USER, None, Some("Dentist"), None)
        .await
        .expect("record_search");
    assert_eq!(hits.len(), 1, "imported events are reachable across schemas");
}

/// Re-importing the same export today writes the events again.
///
/// **Pinning what is true, not what is wanted.** Deduplication is one of the
/// three unknowns `TASK-a-person-brings-their-history-with-them` names, and this
/// test is what makes the answer visible when someone picks it up: the day
/// import becomes idempotent, this assertion fails and is rewritten to the
/// count it should then be.
#[tokio::test]
async fn re_importing_the_same_export_duplicates_it_today() {
    let mut env = env_with_user().await;
    for _ in 0..2 {
        env.client
            .import(USER, ImportFormat::Ics, "a-life.ics", FIXTURE.to_vec())
            .await
            .expect("import");
    }
    let records = env
        .client
        .record_query(USER, IMPORTED_CALENDAR_NSID, vec![], None, None)
        .await
        .expect("record_query");
    assert_eq!(
        records.len(),
        IMPORTABLE * 2,
        "import is not idempotent yet — see the record's open questions"
    );
}

/// **A hostile export gets an answer, not a dropped socket.**
///
/// The reader runs inside the daemon, on the task serving this connection, so a
/// panic there is not a parse failure the person can act on — the connection
/// closes and nothing says why. `DURATION:P200000000000D` and
/// `P100000000000D` each did exactly that, in two different chrono calls, until
/// the reader's arithmetic went through the checked forms.
///
/// This asserts at the boundary that matters: the client still gets a reply,
/// the good events are in the store, and the bad one is *counted* — the same
/// contract as any other malformed `VEVENT`.
#[tokio::test]
async fn a_hostile_duration_answers_instead_of_dropping_the_connection() {
    let mut env = env_with_user().await;

    let hostile = "BEGIN:VCALENDAR\n\
         BEGIN:VEVENT\nUID:ok\nDTSTART:20260115T130000Z\nSUMMARY:Ordinary\nEND:VEVENT\n\
         BEGIN:VEVENT\nUID:past-the-constructor\nDTSTART:20260115T130000Z\nDURATION:P200000000000D\nSUMMARY:One\nEND:VEVENT\n\
         BEGIN:VEVENT\nUID:past-the-calendar\nDTSTART:20260115T130000Z\nDURATION:P100000000000D\nSUMMARY:Two\nEND:VEVENT\n\
         END:VCALENDAR\n";

    let (_nsid, imported, skipped) = env
        .client
        .import(
            USER,
            ImportFormat::Ics,
            "hostile.ics",
            hostile.as_bytes().to_vec(),
        )
        .await
        .expect("the daemon answers a hostile export");

    assert_eq!(imported, 1, "the ordinary event still arrives");
    assert_eq!(skipped, 2, "and the two that cannot exist are counted");

    // The connection is still usable — the proof that nothing unwound the task
    // serving it.
    let records = env
        .client
        .record_query(USER, IMPORTED_CALENDAR_NSID, vec![], None, None)
        .await
        .expect("the same connection still answers afterwards");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["title"], "Ordinary");
}

fn free_port() -> u16 {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind :0 for port probe");
    s.local_addr().expect("local_addr").port()
}

/// **The other half of the record's `Done when`, and the gap in it.**
///
/// An imported event reaches a second paired device the way every other record
/// does — sealed into the history log on the device that wrote it, carried as a
/// pack, merged on the other side (RFC-0046). The rows travel.
///
/// **The declaration does not.** `apply_record_segments` skips a row whose
/// schema the receiving device does not know, and a registration lives in that
/// device's own `app_schemas` table, so a shape declared by an import on one
/// device is unknown on the other until something declares it there too. This
/// test shows both halves: nothing arrives, then the shape is registered on the
/// second device by hand, and everything arrives. The hand-registration is the
/// gap, and the argument for closing it — the commons adopting the shape, or a
/// declaration travelling beside the records it describes, as `DEC-0042` says it
/// should — is
/// `IDEA-imported-records-have-nowhere-to-say-where-they-came-from`.
///
/// Its sibling `a_record_written_on_one_device_syncs_to_a_joined_device` has to
/// register `com.test.notes` on both devices for the same reason, so this is a
/// standing property of custom shapes, not something import introduced.
#[tokio::test]
async fn imported_events_reach_a_second_device_once_it_knows_the_shape() {
    init_crypto();

    let base_e = tempfile::tempdir().expect("base_e");
    let ipc_e = unique_ipc();
    let secrets_e: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    let daemon_e = DeviceDaemon::new_with_base_and_secrets(
        base_e.path().to_owned(),
        ipc_e.clone(),
        Arc::clone(&secrets_e),
    )
    .await
    .expect("daemon E");

    let base_n = tempfile::tempdir().expect("base_n");
    let ipc_n = unique_ipc();
    let secrets_n: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    let daemon_n = DeviceDaemon::new_with_base_and_secrets(
        base_n.path().to_owned(),
        ipc_n.clone(),
        Arc::clone(&secrets_n),
    )
    .await
    .expect("daemon N");

    let _task_e = tokio::spawn(async move { Arc::new(daemon_e).run().await });
    let daemon_n = Arc::new(daemon_n);
    let _task_n = tokio::spawn({
        let d = Arc::clone(&daemon_n);
        async move { d.run().await }
    });
    wait_for_daemon(&ipc_e, "daemon E").await;
    wait_for_daemon(&ipc_n, "daemon N").await;

    let mut client_e = connect_when_ready(&ipc_e, "client_e").await;
    let client_n = connect_when_ready(&ipc_n, "client_n").await;

    client_e
        .create_user(USER, crate::common::TEST_PASSPHRASE)
        .await
        .expect("create_user E");
    // E keeps the person's things on a drive, enrolled before N joins so the
    // join introduces N to it: N receives E's records by way of the drive.
    let (client_e, drive) = crate::drive_sync::a_drive_for(client_e, "device-e", USER).await;

    let bootstrap_port = free_port();
    let (mut client_e, mut client_n, _node_n) = enroll_streamed(
        client_e,
        client_n,
        USER,
        "device-n",
        bootstrap_port,
        Posture::Full,
    )
    .await;
    // N is told where the drive is; neither device is given the other's address.
    crate::drive_sync::tell_of_the_drive(&daemon_n, USER, &drive).await;

    // The import happens on E, where the person's export is.
    let (_nsid, imported, _skipped) = client_e
        .import(USER, ImportFormat::Ics, "a-life.ics", FIXTURE.to_vec())
        .await
        .expect("import on E");
    assert_eq!(imported as usize, IMPORTABLE);

    // E's sync to the drive seals its records into the packs it sends; N takes
    // them from there.
    client_e
        .sync_mount(USER, "local", "vault", Some(kotton::SyncDirection::Push))
        .await
        .expect("E pushes to the drive");
    client_n
        .sync_mount(USER, "local", "vault", Some(kotton::SyncDirection::Pull))
        .await
        .expect("N pulls from the drive");

    let before = client_n
        .record_query(USER, IMPORTED_CALENDAR_NSID, vec![], None, None)
        .await;
    let Err(refusal) = before else {
        panic!("N answered for a shape it has never been told about");
    };
    assert!(
        refusal.to_string().contains("unknown schema"),
        "the gap, and it is sharper than an empty answer: N cannot even name the \
         shape, because the declaration never left E — {refusal}"
    );

    // Give N the declaration. This is the step that should not have to be taken
    // by hand — see the doc above.
    let definition = serde_json::to_string(&imported_calendar_schema()).unwrap();
    client_n
        .schema_register(USER, &definition)
        .await
        .expect("declare the import shape on N");
    client_n
        .sync_mount(USER, "local", "vault", Some(kotton::SyncDirection::Pull))
        .await
        .expect("N pulls from the drive again");

    let after = client_n
        .record_query(USER, IMPORTED_CALENDAR_NSID, vec![], None, None)
        .await
        .expect("record_query on N");
    assert_eq!(
        after.len(),
        IMPORTABLE,
        "every imported event reached the second paired device through the sealed log"
    );
    assert!(
        after.iter().any(|r| r["title"] == "Standup"),
        "and arrived whole, recurrence rule and all"
    );
}
