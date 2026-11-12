// SPDX-License-Identifier: AGPL-3.0-or-later
//! The access log is records kept on the device unless pinned to a drive (kotton #450): a log
//! record written on one device never reaches a second by default, and the vault keeping
//! `personal` holds none of its bytes; once the first device's own setting pins its log to
//! `personal`, its log reaches the second after a bare `sync` on each; unpinned again, no new
//! record leaves. No app is granted the log, an app's record verbs on it are refused, and
//! record search returns none of it. A removal follows the record (kotton #484): a record the
//! drive already carries, removed on a device that has not pinned its log, is removed from the
//! drive and every device, and nothing else of that device's log leaves. Every record here is
//! written by the person's own session, at the local door, naming no app.

use crate::common::{connect_when_ready, enroll_streamed_as, init_crypto, TestEnv};
use crate::drive_sync::personal_tree;
use crate::records_drive::the_vault_keeping_it_reads_none_of;
use crate::vault::{enrol_vault_from, spawn_device, spawn_vault, RunningDevice, RunningVault};
use kotton::KottonClient;
use kotton_schemas::membership::Posture;
use kotton_wire::ipc::{UserRequest, FIRST_DRIVE_NAME, PERSONAL_ROOT};

/// The user `drive_sync`'s helpers read.
const USER: &str = "alice";
const LOG: &str = kotton_common::namespace::NSID_ACCESS_LOG;

/// One thing the daemon was asked, with `what` naming `what`: the distinctive bytes.
fn entry(what: &str) -> serde_json::Value {
    serde_json::json!({ "device": "did:key:z6MkdeviceA", "at": "2026-11-10T00:00:00Z",
        "asker": "terminal", "door": "local", "act": "read", "what": what })
}

/// A bare `sync` of `who`'s drives, to its end.
async fn synced(client: &mut KottonClient, who: &str) {
    let (job, _) = client.sync_drives(USER).await.unwrap_or_else(|e| panic!("{who}'s sync: {e}"));
    client.sync_await(USER, job, 120).await.unwrap_or_else(|e| panic!("{who}'s sync pass: {e}"));
}

/// The person's own log record, written in Personal at `client`'s local door.
async fn written(client: &mut KottonClient, what: &str) -> String {
    client
        .record_insert_in(USER, Some(PERSONAL_ROOT), None, LOG, entry(what))
        .await
        .expect("the person's own log record")
}

/// What the device at `client` holds of the log, by `what`.
async fn held(client: &mut KottonClient) -> Vec<String> {
    let rows = client
        .record_query_in(USER, Some(PERSONAL_ROOT), None, LOG, vec![], None, None)
        .await
        .expect("the person's own query of the log");
    let mut whats: Vec<String> = rows.iter().filter_map(|r| r["what"].as_str().map(str::to_owned)).collect();
    whats.sort();
    whats
}

/// Two devices of alice's, A and B, joined, `personal` on one vault, each synced once.
struct TwoDevices {
    vault: RunningVault,
    tree: String,
    a: RunningDevice,
    b: RunningDevice,
    client_a: KottonClient,
    client_b: KottonClient,
}

async fn two_devices() -> TwoDevices {
    init_crypto();
    let vault = spawn_vault("vault").await;
    let a = spawn_device("device A").await;
    let mut client_a = connect_when_ready(&a.ipc, "client A").await;
    client_a.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user on A");
    let (client_a, first) = enrol_vault_from(client_a, "device-a", &vault, USER, "vault").await;
    let b = spawn_device("device B").await;
    let client_b = connect_when_ready(&b.ipc, "client B").await;
    let (mut client_a, mut client_b, _node_b) =
        enroll_streamed_as(client_a, client_b, USER, "device-a", "device-b", Posture::Full).await;
    synced(&mut client_a, "A").await;
    synced(&mut client_b, "B").await;
    let tree = personal_tree(&a, &first.pubkey_hex).await;
    TwoDevices { vault, tree, a, b, client_a, client_b }
}

/// **By default a log record written on one device never reaches a second**, after a bare
/// `sync` on each, and the vault keeping `personal` holds none of its bytes; a note written
/// beside it does reach the second, so the pass is shown to carry records.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_log_record_written_on_one_device_never_reaches_another() {
    const WHAT: &str = "access-log-kept-here-3f8a1c";
    const NOTE: &str = "access-log-beside-it-0b5e";
    let mut d = two_devices().await;

    written(&mut d.client_a, WHAT).await;
    d.client_a
        .record_insert(USER, kotton_common::namespace::NSID_NOTES, serde_json::json!({ "title": NOTE }))
        .await
        .expect("a note beside it");
    assert_eq!(held(&mut d.client_a).await, [WHAT], "A keeps its log record");
    synced(&mut d.client_a, "A").await;
    synced(&mut d.client_b, "B").await;

    let notes = d.client_b.record_query(USER, kotton_common::namespace::NSID_NOTES, vec![], None, None).await.expect("B's notes");
    assert!(notes.iter().any(|n| n["title"] == NOTE), "the pass carried no record, so the case was not held");
    assert!(held(&mut d.client_b).await.is_empty(), "B holds A's log record");
    the_vault_keeping_it_reads_none_of(&d.vault, &d.tree, &[WHAT]).await;
}

/// **Once A's own setting pins its log to `personal`, A's log reaches B** after a bare `sync`
/// on each, the record written before the pin with it; the vault reads none of either. Pinned
/// to another drive is refused. **Unpinned again, no new record leaves A**, and what B already
/// holds stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_log_pinned_to_personal_reaches_another_device_and_unpinned_stops() {
    const BEFORE: &str = "access-log-before-the-pin-6d02";
    const PINNED: &str = "access-log-pinned-a91f47";
    const AFTER: &str = "access-log-after-the-unpin-c3e8";
    let mut d = two_devices().await;
    let db = d.a.daemon.machine_db();

    written(&mut d.client_a, BEFORE).await;
    synced(&mut d.client_a, "A").await;
    synced(&mut d.client_b, "B").await;
    assert!(held(&mut d.client_b).await.is_empty(), "B holds A's log record before the pin");

    assert!(kotton_device::users::log_pin::set(&db, USER, Some("photos")).await.is_err(), "another drive");
    kotton_device::users::log_pin::set(&db, USER, Some(FIRST_DRIVE_NAME)).await.expect("the pin");
    written(&mut d.client_a, PINNED).await;
    synced(&mut d.client_a, "A").await;
    synced(&mut d.client_b, "B").await;
    assert_eq!(held(&mut d.client_b).await, [BEFORE, PINNED], "B does not hold A's pinned log");
    the_vault_keeping_it_reads_none_of(&d.vault, &d.tree, &[BEFORE, PINNED]).await;

    kotton_device::users::log_pin::set(&db, USER, None).await.expect("the unpin");
    written(&mut d.client_a, AFTER).await;
    synced(&mut d.client_a, "A").await;
    synced(&mut d.client_b, "B").await;
    assert_eq!(held(&mut d.client_b).await, [BEFORE, PINNED], "a record written after the unpin left A");
    assert_eq!(held(&mut d.client_a).await, [AFTER, BEFORE, PINNED], "A keeps its whole log");
}

/// The person's own removal of their log record `id`, in Personal at `client`'s local door.
async fn removed(client: &mut KottonClient, id: &str) {
    client
        .record_delete_in(USER, Some(PERSONAL_ROOT), None, LOG, id)
        .await
        .expect("the person's own removal of a log record");
}

/// **A removal follows the record** (kotton #484). B pins its log and writes R; A, which has
/// not pinned, receives R and removes it, and writes a record of its own beside it. After a
/// bare `sync` on each, R is gone from B, and gone from the drive: a third device, C, joined
/// after the removal, never holds it. A's own record reaches neither. Neither device runs a
/// peer listener, so every record reaches B and C by way of the vault keeping `personal`,
/// which reads none of either record's bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_record_the_drive_carries_removed_on_an_unpinned_device_is_removed_everywhere() {
    const R: &str = "access-log-pinned-on-b-then-removed-on-a-5e21";
    const OWN: &str = "access-log-a-own-unpinned-7b90";
    let mut d = two_devices().await;
    let db_b = d.b.daemon.machine_db();
    kotton_device::users::log_pin::set(&db_b, USER, Some(FIRST_DRIVE_NAME)).await.expect("B's pin");

    let r = written(&mut d.client_b, R).await;
    synced(&mut d.client_b, "B").await;
    synced(&mut d.client_a, "A").await;
    assert_eq!(held(&mut d.client_a).await, [R], "A did not receive B's pinned record");

    removed(&mut d.client_a, &r).await;
    written(&mut d.client_a, OWN).await;
    assert_eq!(held(&mut d.client_a).await, [OWN], "A still holds R");
    synced(&mut d.client_a, "A").await;
    synced(&mut d.client_b, "B").await;
    assert!(held(&mut d.client_b).await.is_empty(), "B keeps R, or holds A's own record");

    let c = spawn_device("device C").await;
    let client_c = connect_when_ready(&c.ipc, "client C").await;
    let (_client_a, mut client_c, _node_c) =
        enroll_streamed_as(d.client_a, client_c, USER, "device-a", "device-c", Posture::Full).await;
    synced(&mut client_c, "C").await;
    assert!(held(&mut client_c).await.is_empty(), "the drive keeps R, or carries A's own record");
    the_vault_keeping_it_reads_none_of(&d.vault, &d.tree, &[R, OWN]).await;
}

/// **The same on one device that pinned, wrote R, unpinned, then removed R** (kotton #484):
/// the drive carried R because it was sent while pinned, so the removal leaves, and B, which
/// held R, holds it no more after a bare `sync` on each.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_record_sent_while_pinned_and_removed_after_the_unpin_leaves_the_drive() {
    const R: &str = "access-log-sent-pinned-removed-unpinned-2c4d";
    let mut d = two_devices().await;
    let db = d.a.daemon.machine_db();

    kotton_device::users::log_pin::set(&db, USER, Some(FIRST_DRIVE_NAME)).await.expect("the pin");
    let r = written(&mut d.client_a, R).await;
    synced(&mut d.client_a, "A").await;
    synced(&mut d.client_b, "B").await;
    assert_eq!(held(&mut d.client_b).await, [R], "B did not receive A's pinned record");

    kotton_device::users::log_pin::set(&db, USER, None).await.expect("the unpin");
    removed(&mut d.client_a, &r).await;
    synced(&mut d.client_a, "A").await;
    synced(&mut d.client_b, "B").await;
    assert!(held(&mut d.client_b).await.is_empty(), "the drive keeps R");
    assert!(held(&mut d.client_a).await.is_empty());
}

/// **No app is granted the access log, and an app's record verb on it is refused**: a grant
/// on it is refused by name and nothing is stored, and an app's query is refused, naming the
/// schema. One assertion each: the refusal is the one `secret` passes through (kotton #449).
#[tokio::test]
async fn no_app_is_granted_the_log_and_its_record_verbs_refuse_an_app() {
    const APP: &str = "com.test.notes-app";
    let mut env = TestEnv::spawn_authed().await;
    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");

    let err = env.client.schema_grant_set(APP, LOG, true, false, false).await.expect_err("a grant on the log");
    assert!(err.to_string().contains("no app is granted it") && err.to_string().contains(LOG), "{err}");
    assert!(env.client.schema_grant_list(APP).await.expect("schema_grant_list").is_empty());

    written(&mut env.client, "access-log-an-app-asks-2a7d").await;
    let query = UserRequest::RecordQuery {
        user_id: USER.to_owned(),
        schema_nsid: LOG.to_owned(),
        field_eq: vec![],
        limit: None,
        offset: None,
        root: None,
        app_id: Some(APP.to_owned()),
    };
    let resp = env.client.inner().send(&query).await.expect("send RecordQuery");
    let kotton_wire::ipc::UserResponse::Error { message } = &resp else {
        panic!("an app's query of the log was answered");
    };
    assert!(message.contains("permission denied") && message.contains(LOG), "{message}");
    assert!(!format!("{resp:?}").contains("access-log-an-app-asks"), "an app was told the log: {resp:?}");
}

/// **Record search returns none of the log**: not across every schema, not with the log named
/// as the filter, and not by what a record of it says, though the person keeps one.
#[tokio::test]
async fn record_search_returns_none_of_the_log() {
    const WHAT: &str = "access-log-searched-for-58b1";
    let mut env = TestEnv::spawn_authed().await;
    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    written(&mut env.client, WHAT).await;
    assert_eq!(held(&mut env.client).await, [WHAT], "the person keeps the record");

    for (filter, rows) in [
        ("none", env.client.record_search(USER, None, None, None).await.expect("search")),
        ("the log", env.client.record_search(USER, Some(LOG), None, None).await.expect("search by the log")),
        ("its what", env.client.record_search(USER, None, Some(WHAT), None).await.expect("search by text")),
    ] {
        assert!(
            rows.iter().all(|r| r["schema_nsid"] != LOG && !r.to_string().contains(WHAT)),
            "search ({filter}) returned a log record: {rows:?}"
        );
    }
}

/// **Writing a log record tells no `VfsWatch` subscriber anything** (kotton #450). The sync
/// sidecar is one, with no path filter, and syncs on every frame it is sent; a session at
/// `Remote` may be another. The suite runs no sidecar (it is spawned only for a daemon that
/// has paired nodes when it boots, from a binary beside the daemon's), so this holds what it
/// would be told: the person's subscription, filtering nothing, is sent no frame for a log
/// record written, and the first frame it is sent after it is for a directory made beside the
/// record database after it. The watcher reads one inotify queue in order, so a frame for the
/// record would come first or never. The deadline is a hang guard.
///
/// The person's first record verb lays down their roots index (`core/`) and writes their
/// `agent.db`, once, whatever the schema: their first use, not a log write. So a first log
/// record is written and its frames read up to a first marker, and what is held is what the
/// next one does.
///
/// The issue's check that a log write on a device with a paired node starts no pass rests on
/// this: a pass starts from the engine's wake, which a log record never calls (`kuserd`'s
/// `write_wake_tests`), or from a frame sent to the sidecar, which this shows is never sent.
#[tokio::test]
async fn a_log_record_written_tells_a_subscriber_nothing() {
    use kotton_wire::UserResponse;
    let mut env = TestEnv::spawn_authed().await;
    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let token = env.client.session_token.clone().expect("session token");
    let mut watch: kotton_ipc::IpcClient<UserRequest, UserResponse> =
        kotton_ipc::IpcClient::connect(env.endpoint.clone()).await.expect("a second connection");
    let auth = UserRequest::Authenticate { token: kotton_wire::ipc::SecretText::new(token), scope: None };
    assert!(matches!(watch.send(&auth).await.expect("auth"), UserResponse::ActiveSession { .. }));
    let mut frames = watch
        .send_streaming(&UserRequest::VfsWatch { user_id: USER.to_owned(), paths: vec![] })
        .await
        .expect("VfsWatch");
    let hang = std::time::Duration::from_secs(30);
    let first = tokio::time::timeout(hang, frames.recv()).await.expect("the watch answers").expect("open");
    assert!(matches!(first, UserResponse::VfsWatchReady), "{first:?}");
    let person = env.base_dir.join("users").join(USER);
    let mut next_path = async || {
        let frame = tokio::time::timeout(hang, frames.recv()).await.expect("a frame").expect("open");
        let UserResponse::VfsChanged { path, .. } = frame else {
            panic!("a VfsChanged frame, got {frame:?}");
        };
        path
    };

    written(&mut env.client, "access-log-the-first-use-17c0").await;
    let first_use = person.join("marker-after-the-first-use");
    tokio::fs::create_dir(&first_use).await.expect("the first marker");
    while next_path().await != first_use.to_string_lossy() {}

    written(&mut env.client, "access-log-watched-for-9e64").await;
    let after = person.join("marker-after-the-log-record");
    tokio::fs::create_dir(&after).await.expect("the second marker");
    assert_eq!(next_path().await, after.to_string_lossy(), "a subscriber was told of the log record's write");
}
