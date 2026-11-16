// SPDX-License-Identifier: AGPL-3.0-or-later
//! The node listing's notes travel wherever its answer is given (kottonllc/kotton#597, 22A).
//!
//! `NodeList` is in `RemoteRequest`: a paired node of the person's, through `kquicd`, and a
//! browser the person admitted ask it beside the terminal. A note says only what a row of the
//! same answer already says, so the answer is the same to each asker.

use super::session_read_tests::alice_and_bob;
use super::*;
use kotton_wire::ipc::Principal;

const ALICE_SESSION: &str = "alice-node-notes-session";

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

/// **A remote `NodeList` answer carries the same notes as the local one**: a row under
/// bytes the Ed25519 rule refuses and a row under another spelling of its key's `did:key`,
/// asked at `Local`, by a paired node at `Remote` (the request decoded as the gateway
/// decodes it), and by a browser at `Paired`.
#[tokio::test]
async fn a_remote_node_listing_carries_the_same_notes_as_the_local_one() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = alice_and_bob(dir.path()).await;
    let ctx = daemon.agent_context();
    sessions::insert(&ctx.sessions, ALICE_SESSION.to_string(), "alice".to_string());
    // The machine's pool, where a person's paired rows are kept.
    let db = daemon.machine_db();

    let (_, refused) = kotton_crypto::ed25519::refused_keys().remove(0);
    let old = kotton_crypto::DidKeyMethod::spelled_over(&refused).to_string();
    kotton_peer::daemon::db::insert_paired_node(&db, "old", "alice", &old, &refused, "[]", 0, None).await.unwrap();
    let honest = kotton_crypto::ed25519::verifying_key(&ed25519_dalek::SigningKey::from_bytes(&[41u8; 32]));
    let otherwise = kotton_crypto::DidKeyMethod::spelled_otherwise(honest.as_bytes()).to_string();
    kotton_peer::daemon::db::insert_paired_node(&db, "phone", "alice", &otherwise, honest.as_bytes(), "[]", 0, None)
        .await
        .unwrap();

    let ask = |principal: Principal, request: UserRequest| {
        let ctx = &ctx;
        async move { handle_request(ctx, request, Caller::anonymous(), connection(principal)).await.expect("answered") }
    };
    let notes_of = |said: UserResponse| match said {
        UserResponse::NodeList { notes, .. } => notes,
        other => panic!("the listing answered {other:?}"),
    };
    let local = notes_of(ask(Principal::LocalOperator, UserRequest::NodeList { user_id: "alice".into() }).await);
    assert_eq!(local.len(), 2, "{local:?}");
    let remote_request: UserRequest = kotton_wire::RemoteRequest::NodeList { user_id: "alice".into() }.into();
    let remote = notes_of(
        ask(Principal::RemoteClient { did: "did:key:z6MkpairedNodeOfAlice".to_string() }, remote_request.clone()).await,
    );
    assert_eq!(remote, local, "a remote asker was answered other notes");
    let paired = notes_of(ask(Principal::Browser { credential_id: "alices-phone".to_string() }, remote_request).await);
    assert_eq!(paired, local, "a browser was answered other notes");
}
