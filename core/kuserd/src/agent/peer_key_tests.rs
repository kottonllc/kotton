// SPDX-License-Identifier: AGPL-3.0-or-later
//! What a peer's key is to the peer path when rows are each person's
//! (kotton #99): one key may be paired by two people, so the two decisions
//! `handle_peer_request` reads from a key are held here, each for the person
//! the request names and never across persons (kotton #119) — the gateway's
//! confinement and the person its frames reach ([`peer_ask`]), and
//! `NodeRelay`'s own-device check.

use super::browser_channel::gateway_key;
use super::{asks_as_own_device, peer_ask, PeerAsk};
use kotton_wire::ipc::PeerRequest;
use kotton_peer::daemon::db as network_db;
use sqlx::SqlitePool;
use std::sync::Arc;

async fn machine_db(dir: &std::path::Path) -> Arc<SqlitePool> {
    let pool = kotton_record::open_sqlite(&dir.join("agent.db")).await.unwrap();
    kotton_device::db::MIGRATOR.run(&pool).await.unwrap();
    Arc::new(pool)
}

fn key_and_did(seed: u8) -> ([u8; 32], String) {
    let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes();
    let did = kotton_crypto::DidKeyMethod::from_public_key_bytes(&key).unwrap().to_string();
    (key, did)
}

fn frame_for(user: Option<&str>) -> PeerRequest {
    PeerRequest::BrowserFrame {
        bytes: vec![1, 2, 3],
        channel: Some("tab".to_string()),
        user_id: user.map(str::to_string),
    }
}

/// A verb that is not a gateway's: a recovery fetch for `user`.
fn other_for(user: &str) -> PeerRequest {
    PeerRequest::RecoveryFetch { user_id: user.to_string() }
}

/// **One key, paired as a gateway by two people: each frame reaches the
/// person it names, not the first by name** (kotton #119). Alice and bob both
/// enrol the same gateway. Bob sorts after alice and is paired first, so
/// neither the name order nor the insertion order can be what answers. A
/// frame for bob is bob's browser's, a frame for alice is alice's, and their
/// channels under one channel name are two channels. A frame naming carol,
/// who pairs the key nowhere, or naming no one, reaches no one.
#[tokio::test]
async fn one_gateway_two_people_each_frame_reaches_the_person_it_names() {
    let dir = tempfile::tempdir().unwrap();
    let db = machine_db(dir.path()).await;
    let (key, did) = key_and_did(25);
    network_db::insert_paired_node(&db, "front-door", "bob", &did, &key, "[]", 0, Some("gateway")).await.unwrap();
    network_db::insert_paired_node(&db, "front-door", "alice", &did, &key, "[]", 0, Some("gateway")).await.unwrap();

    assert_eq!(peer_ask(&db, Some(&key), &frame_for(Some("bob"))).await, Ok(PeerAsk::Gateway("bob".into())));
    assert_eq!(peer_ask(&db, Some(&key), &frame_for(Some("alice"))).await, Ok(PeerAsk::Gateway("alice".into())));
    assert_ne!(
        gateway_key(&did, "alice", Some("tab")),
        gateway_key(&did, "bob", Some("tab")),
        "two people's browsers behind one gateway shared a channel"
    );

    assert!(peer_ask(&db, Some(&key), &frame_for(Some("carol"))).await.is_err(), "a frame reached a person who pairs no gateway here");
    assert!(peer_ask(&db, Some(&key), &frame_for(None)).await.is_err(), "a frame naming no one was taken for someone");

    // Bob revokes his gateway: his frames stop, alice's still reach her.
    sqlx::query("DELETE FROM paired_nodes WHERE user_id = 'bob'").execute(db.as_ref()).await.unwrap();
    assert!(peer_ask(&db, Some(&key), &frame_for(Some("bob"))).await.is_err());
    assert_eq!(peer_ask(&db, Some(&key), &frame_for(Some("alice"))).await, Ok(PeerAsk::Gateway("alice".into())));
}

/// **A key is held to the gateway's verbs for the person who pairs it as
/// one, and only for them.** Alice pairs the key as her full device and bob
/// as his gateway. Asked for bob, the key is his gateway whatever it asks:
/// his browser's frames reach him, and any other verb for him is held to the
/// gateway's verbs. Asked for alice, it is not a gateway: a verb for her goes
/// on to her own standing, and a frame naming her is refused, since she
/// enrolled no gateway. A key paired nowhere carries no frame for anyone.
#[tokio::test]
async fn a_key_is_held_to_the_gateway_verb_for_the_person_who_pairs_it_as_one() {
    let dir = tempfile::tempdir().unwrap();
    let db = machine_db(dir.path()).await;
    let (key, did) = key_and_did(21);
    network_db::insert_paired_node(&db, "laptop", "alice", &did, &key, "[]", 0, Some("full")).await.unwrap();
    network_db::insert_paired_node(&db, "front-door", "bob", &did, &key, "[]", 0, Some("gateway")).await.unwrap();

    assert_eq!(peer_ask(&db, Some(&key), &frame_for(Some("bob"))).await, Ok(PeerAsk::Gateway("bob".into())));
    assert_eq!(peer_ask(&db, Some(&key), &other_for("bob")).await, Ok(PeerAsk::Gateway("bob".into())));
    assert_eq!(peer_ask(&db, Some(&key), &other_for("alice")).await, Ok(PeerAsk::Person("alice".into())));
    assert!(peer_ask(&db, Some(&key), &frame_for(Some("alice"))).await.is_err(), "alice's full device carried a frame as her gateway");

    let (unpaired, _) = key_and_did(22);
    assert!(peer_ask(&db, Some(&unpaired), &frame_for(Some("bob"))).await.is_err());
    assert_eq!(peer_ask(&db, Some(&unpaired), &other_for("bob")).await, Ok(PeerAsk::Person("bob".into())));
    // A peer whose DID names no key is no one's gateway.
    assert!(peer_ask(&db, None, &frame_for(Some("bob"))).await.is_err());
}

/// **`NodeRelay` hands this node's relay admission to the asking person's own
/// full device, decided by that person's row.** One key, paired by alice as
/// her full device and by bob as a vault he keeps a drive on: asked for
/// alice it is her device, asked for bob it is not, and asked for someone who
/// pairs it nowhere it is not.
#[tokio::test]
async fn the_asking_persons_own_row_decides_whether_a_key_is_their_device() {
    let dir = tempfile::tempdir().unwrap();
    let db = machine_db(dir.path()).await;
    let (key, did) = key_and_did(23);
    network_db::insert_paired_node(&db, "vault", "bob", &did, &key, "[]", 0, Some("blind-storage")).await.unwrap();
    network_db::insert_paired_node(&db, "desktop", "alice", &did, &key, "[]", 0, Some("full")).await.unwrap();

    assert!(asks_as_own_device(&db, &key, "alice").await, "alice's full device was refused as hers");
    assert!(!asks_as_own_device(&db, &key, "bob").await, "bob's vault was taken for his device by alice's row");
    assert!(!asks_as_own_device(&db, &key, "carol").await);

    // A row from before postures is a full device.
    let (old, old_did) = key_and_did(24);
    network_db::insert_paired_node(&db, "old", "carol", &old_did, &old, "[]", 0, None).await.unwrap();
    assert!(asks_as_own_device(&db, &old, "carol").await);
}
