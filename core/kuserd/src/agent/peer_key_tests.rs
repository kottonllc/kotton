// SPDX-License-Identifier: AGPL-3.0-or-later
//! What a peer's key is to the peer path when rows are each person's
//! (kotton #99): one key may be paired by two people, so the two decisions
//! `handle_peer_request` reads from a key are held here — the gateway's
//! confinement, read before the frame names a person, and `NodeRelay`'s
//! own-device check, read for the person it names.

use super::{asks_as_own_device, gateway_user_for};
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

/// **A key any person here pairs as a gateway is held to the gateway's verb,
/// whatever other row it has.** Alice pairs the key as a full device and bob
/// as his gateway: the person-less read finds bob's gateway row, so the key
/// speaks one verb for bob, never a full device's reach. The narrower verb
/// wins. Alone, alice's full row confines nothing.
#[tokio::test]
async fn a_key_one_person_pairs_as_a_gateway_is_held_to_the_gateway_verb() {
    let dir = tempfile::tempdir().unwrap();
    let db = machine_db(dir.path()).await;
    let (key, did) = key_and_did(21);
    network_db::insert_paired_node(&db, "laptop", "alice", &did, &key, "[]", 0, Some("full")).await.unwrap();
    assert_eq!(gateway_user_for(&db, &key).await.unwrap(), None, "a full device was confined as a gateway");

    // Inserted after alice's, and sorting after her by user, so the answer
    // is the gateway ordering's and not the insertion's or the name's.
    network_db::insert_paired_node(&db, "front-door", "bob", &did, &key, "[]", 0, Some("gateway")).await.unwrap();
    assert_eq!(gateway_user_for(&db, &key).await.unwrap().as_deref(), Some("bob"));

    let (unpaired, _) = key_and_did(22);
    assert_eq!(gateway_user_for(&db, &unpaired).await.unwrap(), None);
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
