// SPDX-License-Identifier: AGPL-3.0-or-later
//! The node listing's notes of rows travel wherever its answer is given (kottonllc/kotton#597,
//! 22A), and a note of a member with no row, and its revoke, stay at the machine
//! (kottonllc/kotton#610).
//!
//! `NodeList` and `NodeRevoke` are in `RemoteRequest`: a paired node of the person's, through
//! `kquicd`, and a browser the person admitted ask them beside the terminal. A note of a row
//! says only what a row of the same answer already says, so it is the same to each asker. A
//! member of the set with no row is in no row: it is noted, and resolved by `device revoke`,
//! for the person at their own device only.

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

/// **A remote `NodeList` answer carries the same notes of rows as the local one**: a row under
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
    kotton_peer::daemon::db::seed_paired_node_as_stored(&db, "old", "alice", &old, &refused, "[]", 0, None).await.unwrap();
    let honest = kotton_crypto::ed25519::verifying_key(&ed25519_dalek::SigningKey::from_bytes(&[41u8; 32]));
    let otherwise = kotton_crypto::DidKeyMethod::spelled_otherwise(honest.as_bytes()).to_string();
    kotton_peer::daemon::db::seed_paired_node_as_stored(&db, "phone", "alice", &otherwise, honest.as_bytes(), "[]", 0, None)
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

/// **A member of the set with no row is noted and revoked for a local asker only**
/// (kottonllc/kotton#610), asked as the gateway decodes a request: for every key vector the
/// Ed25519 rule refuses, an own-device member under that vector with no row is noted in the
/// answer at the machine and in no remote one; `NodeRevoke` by its DID as stored, from a paired
/// node at `Remote` and a browser at `Paired`, is not found and leaves it; the revoke by the
/// local note's name, as `device revoke` types it, removes it, and the listing notes it no more.
#[tokio::test]
async fn a_member_with_no_row_is_noted_and_revoked_at_the_machine_only() {
    use kotton_peer::membership::{MemberStore as _, Membership as _};
    let dir = tempfile::tempdir().unwrap();
    let daemon = alice_and_bob(dir.path()).await;
    let ctx = daemon.agent_context();
    sessions::insert(&ctx.sessions, ALICE_SESSION.to_string(), "alice".to_string());
    let set = daemon.users().get("alice").expect("alice is loaded");

    let ask = |principal: Principal, request: UserRequest| {
        let ctx = &ctx;
        async move { handle_request(ctx, request, Caller::anonymous(), connection(principal)).await.expect("answered") }
    };
    let notes_of = |said: UserResponse| match said {
        UserResponse::NodeList { notes, .. } => notes,
        other => panic!("the listing answered {other:?}"),
    };
    let remotely = [
        Principal::RemoteClient { did: "did:key:z6MkpairedNodeOfAlice".to_string() },
        Principal::Browser { credential_id: "alices-phone".to_string() },
    ];
    for (name, bytes) in kotton_crypto::ed25519::refused_keys() {
        let did = kotton_crypto::DidKeyMethod::spelled_over(&bytes).to_string();
        let member = kotton_schemas::membership::Member {
            did: did.clone(),
            public_key: bytes,
            role: kotton_schemas::membership::Role::OwnDevice,
            admitted_by: kotton_schemas::membership::Ceremony::DeviceEnroll,
            added_at: "2026-11-17T00:00:00Z".to_string(),
            posture: Some(kotton_schemas::membership::Posture::Full),
            label: Some("old".to_string()),
            reach: None,
        };
        // As an earlier build wrote it: `write_member` refuses such bytes.
        set.member_write(&member.vfs_path(), &serde_json::to_vec(&member).unwrap()).await.unwrap();

        let local = notes_of(ask(Principal::LocalOperator, UserRequest::NodeList { user_id: "alice".into() }).await);
        assert_eq!(local, vec![kotton_wire::note::RowNote::names_no_key(did.clone())], "{name}");
        assert!(
            kotton_wire::note::sentence(&local[0], "device revoke").contains(&format!("`device revoke {did}`")),
            "{name}: the sentence names no revoke"
        );
        for principal in remotely.clone() {
            let listing: UserRequest = kotton_wire::RemoteRequest::NodeList { user_id: "alice".into() }.into();
            assert!(notes_of(ask(principal.clone(), listing).await).is_empty(), "{name}: a remote asker was told of the member");
            let revoke: UserRequest =
                kotton_wire::RemoteRequest::NodeRevoke { user_id: "alice".into(), node_id: did.clone() }.into();
            let said = ask(principal.clone(), revoke).await;
            assert!(
                matches!(&said, UserResponse::Error { message } if message.contains("not found")),
                "{name}: {principal:?} was answered {said:?}"
            );
            assert_eq!(set.list_members().await.unwrap(), vec![member.clone()], "{name}: a remote asker removed it");
        }

        let said = ask(
            Principal::LocalOperator,
            UserRequest::NodeRevoke { user_id: "alice".into(), node_id: local[0].name.clone() },
        )
        .await;
        assert!(matches!(said, UserResponse::NodeRevoked), "{name}: {said:?}");
        assert!(set.list_members().await.unwrap().is_empty(), "{name}: the member is still in the set");
        let after = notes_of(ask(Principal::LocalOperator, UserRequest::NodeList { user_id: "alice".into() }).await);
        assert!(after.is_empty(), "{name}: {after:?}");
    }
}
