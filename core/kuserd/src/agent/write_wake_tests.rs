// SPDX-License-Identifier: AGPL-3.0-or-later
//! A record write wakes the sync engine by its schema, as the daemon wires it (kotton #450).
//!
//! The daemon these tests boot is built and never run, so its background loop is not
//! spawned and nothing takes a wake but the test: each holds the wait the loop would hold
//! (`SyncEngine::next_turn`) and polls it once, with a tick that never comes. Ready is a pass
//! the loop would run; pending is none. Nothing sleeps and nothing is timed.

use super::session_read_tests::alice_and_bob;
use super::*;
use kotton_sync::engine::{SyncEngine, Turn};
use kotton_wire::ipc::{Principal, PERSONAL_ROOT};

const ALICE_SESSION: &str = "alice-write-wake-session";

/// What the engine's loop would do at its next wait, now.
fn next(engine: &SyncEngine) -> Option<Turn> {
    let turn = engine.next_turn(std::future::pending());
    tokio::pin!(turn);
    match std::future::Future::poll(turn, &mut std::task::Context::from_waker(std::task::Waker::noop())) {
        std::task::Poll::Ready(t) => Some(t),
        std::task::Poll::Pending => None,
    }
}

async fn ask(ctx: &super::super::AgentContext, request: UserRequest) -> UserResponse {
    let conn = Arc::new(Mutex::new(Some(ConnSessionData {
        origin: Principal::LocalOperator.trust_origin(),
        token: ALICE_SESSION.to_string(),
        scope: None,
        cek_available: true,
        principal: Principal::LocalOperator,
        browser_key: None,
    })));
    handle_request(ctx, request, Caller::anonymous(), conn).await.expect("answered")
}

fn insert(schema: &str, record: serde_json::Value) -> UserRequest {
    UserRequest::RecordInsert {
        user_id: "alice".into(),
        schema_nsid: schema.into(),
        record,
        root: Some(PERSONAL_ROOT.into()),
        app_id: None,
    }
}

/// **A note the person writes leaves one pass pending, and a log record none**: through the
/// daemon's own record verb, so through the store `RecordStores::get_or_open` opened with the
/// engine's wake. Two notes while no wait is held, as while a pass runs, leave one pass.
#[tokio::test]
async fn a_record_written_at_the_daemon_wakes_its_engine_by_schema() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = alice_and_bob(dir.path()).await;
    let ctx = daemon.agent_context();
    sessions::insert(&ctx.sessions, ALICE_SESSION.to_string(), "alice".to_string());
    // Whatever booting left pending is taken first: the test is of what the writes do.
    let _ = next(&ctx.sync_engine);
    assert_eq!(next(&ctx.sync_engine), None, "an idle daemon's engine has a pass pending");

    let entry = serde_json::json!({ "device": "did:key:a", "at": "2026-11-10T00:00:00Z",
        "asker": "terminal", "door": "local", "act": "read", "what": "write-wake-what-41d9" });
    let resp = ask(&ctx, insert(kotton_common::namespace::NSID_ACCESS_LOG, entry)).await;
    assert!(matches!(resp, UserResponse::RecordInserted { .. }), "the person's log record");
    assert_eq!(next(&ctx.sync_engine), None, "a log record left a pass pending");

    for title in ["a note", "another"] {
        let resp = ask(&ctx, insert(kotton_common::namespace::NSID_NOTES, serde_json::json!({ "title": title }))).await;
        assert!(matches!(resp, UserResponse::RecordInserted { .. }), "the person's note");
    }
    assert_eq!(next(&ctx.sync_engine), Some(Turn::Woken), "a note left no pass pending");
    assert_eq!(next(&ctx.sync_engine), None, "two notes left two passes");
}

/// **A pass's own write leaves no pass pending**: the whole-keeper claim a pass makes
/// (`pins::claim`, which with no setting stated claims the first drive whole) written through
/// the handle a pass writes through (`kotton_sync::engine::records_for_a_pass`), on the
/// daemon's own host. The claim is written, and the engine is not woken for it.
#[tokio::test]
async fn a_pass_s_own_claim_wakes_no_pass() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = alice_and_bob(dir.path()).await;
    let ctx = daemon.agent_context();
    let _ = next(&ctx.sync_engine);
    let me = ctx.runtime.operational_did();
    let store = kotton_sync::engine::records_for_a_pass(&*ctx.sync_resources, "alice").expect("alice's records");
    let wrote = kotton_device::users::pins::claim(&ctx.runtime.schema_registry, &store, &[], &me)
        .await
        .expect("the claim");
    assert!(wrote, "no claim was written, so the case was not held");
    assert_eq!(next(&ctx.sync_engine), None, "a pass's own claim left a pass pending");
}
