// SPDX-License-Identifier: AGPL-3.0-or-later
//! A schema kept from apps answers only the person's own terminal (#449).
//!
//! `secret` is refused to an app by the grant check, but the record verbs are open to the
//! `Remote` tier and to a browser at `Paired`, and neither names an app. Naming none is what
//! the terminal does; it is not evidence of being the terminal. So the door hands each record
//! verb the origin `Authenticate` bound, and a kept schema is answered only at `Local`.
//!
//! Each test boots a daemon holding alice and bob, and asks from a connection holding alice's
//! session under one principal: a local operator (`Local`), a paired node `kquicd` minted a
//! session for (`Remote`), and a browser admitted by ceremony (`Paired`).

use super::session_read_tests::alice_and_bob;
use super::*;
use kotton_wire::ipc::{Principal, PERSONAL_ROOT};

const ALICE_SESSION: &str = "alice-kept-session";
const SECRET: &str = kotton_common::namespace::NSID_SECRET;
/// The distinctive test value: the only value a failure message may show.
const VALUE: &str = "terminal-only-5d1e8b";

fn connection(principal: Principal) -> Arc<Mutex<Option<ConnSessionData>>> {
    Arc::new(Mutex::new(Some(ConnSessionData {
        origin: principal.trust_origin(),
        token: ALICE_SESSION.to_string(),
        scope: None,
        cek_available: true,
        principal,
        browser_key: None,
    })))
}

fn remote() -> Principal {
    Principal::RemoteClient { did: "did:key:z6MkpairedNodeOfAlice".to_string() }
}

fn paired() -> Principal {
    Principal::Browser { credential_id: "alices-phone".to_string() }
}

async fn ask(
    ctx: &super::super::AgentContext,
    principal: Principal,
    request: UserRequest,
) -> UserResponse {
    handle_request(ctx, request, Caller::anonymous(), connection(principal))
        .await
        .expect("answered")
}

fn insert() -> UserRequest {
    UserRequest::RecordInsert {
        user_id: "alice".into(),
        schema_nsid: SECRET.into(),
        record: serde_json::json!({ "label": "bank", "value": VALUE, "kind": "password" }),
        root: Some(PERSONAL_ROOT.into()),
        app_id: None,
    }
}

fn query() -> UserRequest {
    UserRequest::RecordQuery {
        user_id: "alice".into(),
        schema_nsid: SECRET.into(),
        field_eq: vec![],
        limit: None,
        offset: None,
        root: Some(PERSONAL_ROOT.into()),
        app_id: None,
    }
}

fn delete(record_id: &str) -> UserRequest {
    UserRequest::RecordDelete {
        user_id: "alice".into(),
        schema_nsid: SECRET.into(),
        record_id: record_id.into(),
        root: Some(PERSONAL_ROOT.into()),
        app_id: None,
    }
}

fn open(record_id: &str) -> UserRequest {
    UserRequest::RecordOpen {
        user_id: "alice".into(),
        url: format!("kotton://records/{SECRET}/{record_id}"),
    }
}

/// The refusal names the schema as the terminal's, and carries no value.
fn refused_as_the_terminals(tier: &str, verb: &str, resp: &UserResponse) {
    let UserResponse::Error { message } = resp else {
        panic!("{verb} on {SECRET} at {tier}, naming no app, was answered: {}", shape(resp));
    };
    assert!(message.contains(SECRET), "{tier} {verb}: {message}");
    assert!(message.contains("the person's own terminal's"), "{tier} {verb}: {message}");
    assert!(!message.contains(VALUE), "{tier} {verb}: the refusal carries the value");
}

/// A response's variant, never its body: a body would carry the value.
fn shape(resp: &UserResponse) -> &'static str {
    match resp {
        UserResponse::RecordInserted { .. } => "RecordInserted",
        UserResponse::RecordQueryResult { .. } => "RecordQueryResult",
        UserResponse::RecordDeleted => "RecordDeleted",
        UserResponse::RecordOpenResult { .. } => "RecordOpenResult",
        UserResponse::RecordOpenNotFound { .. } => "RecordOpenNotFound",
        UserResponse::NotAllowed => "NotAllowed",
        UserResponse::Error { .. } => "Error",
        _ => "another response",
    }
}

/// **At `Remote` and at `Paired`, a record insert, query, delete and open on `secret` naming
/// no app is refused; at `Local` each works.**
///
/// The record is put by the person at `Local` first, so the refused query and open are
/// refusals of a row that is there, and the refused delete leaves it there. Then the person
/// queries, opens and deletes it at `Local`.
#[tokio::test]
async fn a_kept_schema_answers_the_terminal_and_no_remote_or_paired_session() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = alice_and_bob(dir.path()).await;
    let ctx = daemon.agent_context();
    sessions::insert(&ctx.sessions, ALICE_SESSION.to_string(), "alice".to_string());

    let local = || Principal::LocalOperator;
    let UserResponse::RecordInserted { record_id } = ask(&ctx, local(), insert()).await else {
        panic!("the person's insert at Local");
    };

    for (tier, principal) in [("Remote", remote as fn() -> Principal), ("Paired", paired)] {
        assert_ne!(principal().trust_origin(), kotton_wire::ConnTrustOrigin::Local, "{tier}");
        refused_as_the_terminals(tier, "insert", &ask(&ctx, principal(), insert()).await);
        refused_as_the_terminals(tier, "query", &ask(&ctx, principal(), query()).await);
        refused_as_the_terminals(tier, "delete", &ask(&ctx, principal(), delete(&record_id)).await);
        refused_as_the_terminals(tier, "open", &ask(&ctx, principal(), open(&record_id)).await);
    }

    // At Local: the one row the person put, untouched by the refused insert and delete.
    let UserResponse::RecordQueryResult { records } = ask(&ctx, local(), query()).await else {
        panic!("the person's query at Local");
    };
    assert_eq!(records.len(), 1, "one secret, the person's: the refused insert stored nothing");
    assert_eq!(records[0]["value"], VALUE);
    let opened = ask(&ctx, local(), open(&record_id)).await;
    let UserResponse::RecordOpenResult { record, nsid } = opened else {
        panic!("the person's open at Local: {}", shape(&opened));
    };
    assert_eq!(nsid, SECRET);
    assert_eq!(record["value"], VALUE);
    let gone = ask(&ctx, local(), delete(&record_id)).await;
    assert!(matches!(gone, UserResponse::RecordDeleted), "the person's delete: {}", shape(&gone));
}

/// **The rule is the kept schema's, not the tier's**: at `Remote` and at `Paired` a record
/// verb on a schema not kept from apps is answered as before.
#[tokio::test]
async fn a_remote_or_paired_session_still_reaches_a_schema_not_kept() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = alice_and_bob(dir.path()).await;
    let ctx = daemon.agent_context();
    sessions::insert(&ctx.sessions, ALICE_SESSION.to_string(), "alice".to_string());

    for (tier, principal) in [("Remote", remote as fn() -> Principal), ("Paired", paired)] {
        let resp = ask(
            &ctx,
            principal(),
            UserRequest::RecordQuery {
                user_id: "alice".into(),
                schema_nsid: kotton_common::namespace::NSID_NOTES.into(),
                field_eq: vec![],
                limit: None,
                offset: None,
                root: Some(PERSONAL_ROOT.into()),
                app_id: None,
            },
        )
        .await;
        assert!(
            matches!(resp, UserResponse::RecordQueryResult { .. }),
            "{tier}: a notes query was refused: {resp:?}"
        );
    }
}

/// **`access-log` answers the terminal alone, as `secret` does** (kotton #450): the person's
/// insert at `Local` is kept, and at `Remote` an insert and a query of it naming no app are
/// refused as the terminal's, before any row is read. One assertion each: the door is the one
/// `secret` passes through.
#[tokio::test]
async fn the_access_log_answers_the_terminal_and_no_remote_session() {
    const LOG: &str = kotton_common::namespace::NSID_ACCESS_LOG;
    const WHAT: &str = "access-log-what-7c2e";
    let dir = tempfile::tempdir().unwrap();
    let daemon = alice_and_bob(dir.path()).await;
    let ctx = daemon.agent_context();
    sessions::insert(&ctx.sessions, ALICE_SESSION.to_string(), "alice".to_string());
    let insert = || UserRequest::RecordInsert {
        user_id: "alice".into(),
        schema_nsid: LOG.into(),
        record: serde_json::json!({ "device": "did:key:a", "at": "2026-11-10T00:00:00Z",
            "asker": "terminal", "door": "local", "act": "read", "what": WHAT }),
        root: Some(PERSONAL_ROOT.into()),
        app_id: None,
    };
    let query = || UserRequest::RecordQuery {
        user_id: "alice".into(),
        schema_nsid: LOG.into(),
        field_eq: vec![],
        limit: None,
        offset: None,
        root: Some(PERSONAL_ROOT.into()),
        app_id: None,
    };
    let kept = ask(&ctx, Principal::LocalOperator, insert()).await;
    assert!(matches!(kept, UserResponse::RecordInserted { .. }), "the person's insert: {}", shape(&kept));
    for (verb, resp) in [("insert", ask(&ctx, remote(), insert()).await), ("query", ask(&ctx, remote(), query()).await)] {
        let UserResponse::Error { message } = &resp else {
            panic!("{verb} on {LOG} at Remote was answered: {}", shape(&resp));
        };
        assert!(message.contains(LOG) && message.contains("the person's own terminal's"), "{verb}: {message}");
        assert!(!message.contains(WHAT), "{verb}: the refusal carries what the record says");
    }
    let UserResponse::RecordQueryResult { records } = ask(&ctx, Principal::LocalOperator, query()).await else {
        panic!("the person's query at Local");
    };
    assert_eq!(records.len(), 1, "the refused insert stored a row");
}

/// **`petname` answers the terminal alone, as `secret` does** (kotton #471): a grant prompt
/// trusts what a petname says, so nothing but the person's own terminal writes one. The
/// person's insert at `Local` is kept; at `Remote` and at `Paired` an insert and a query naming
/// no app are refused as the terminal's, before any row is read or written.
#[tokio::test]
async fn a_petname_answers_the_terminal_and_no_remote_or_paired_session() {
    const PETNAME: &str = kotton_common::namespace::NSID_PETNAME;
    const NAME: &str = "petname-name-4b8d";
    let dir = tempfile::tempdir().unwrap();
    let daemon = alice_and_bob(dir.path()).await;
    let ctx = daemon.agent_context();
    sessions::insert(&ctx.sessions, ALICE_SESSION.to_string(), "alice".to_string());
    let insert = || UserRequest::RecordInsert {
        user_id: "alice".into(),
        schema_nsid: PETNAME.into(),
        record: serde_json::json!({
            "key": "did:key:z6MkeXBLjYiSvqnhFb6D7sHm8yKm4jV45wwBFRaatf1cfZ76",
            "name": NAME,
        }),
        root: Some(PERSONAL_ROOT.into()),
        app_id: None,
    };
    let query = || UserRequest::RecordQuery {
        user_id: "alice".into(),
        schema_nsid: PETNAME.into(),
        field_eq: vec![],
        limit: None,
        offset: None,
        root: Some(PERSONAL_ROOT.into()),
        app_id: None,
    };
    for (tier, principal) in [("Remote", remote as fn() -> Principal), ("Paired", paired)] {
        for (verb, resp) in
            [("insert", ask(&ctx, principal(), insert()).await), ("query", ask(&ctx, principal(), query()).await)]
        {
            let UserResponse::Error { message } = &resp else {
                panic!("{verb} on {PETNAME} at {tier} was answered: {}", shape(&resp));
            };
            assert!(message.contains(PETNAME) && message.contains("the person's own terminal's"), "{verb}: {message}");
            assert!(!message.contains(NAME), "{tier} {verb}: the refusal carries the name");
        }
    }
    let kept = ask(&ctx, Principal::LocalOperator, insert()).await;
    assert!(matches!(kept, UserResponse::RecordInserted { .. }), "the person's insert: {}", shape(&kept));
    let UserResponse::RecordQueryResult { records } = ask(&ctx, Principal::LocalOperator, query()).await else {
        panic!("the person's query at Local");
    };
    assert_eq!(records.len(), 1, "a refused insert stored a row");
}
