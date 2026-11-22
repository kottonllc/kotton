// SPDX-License-Identifier: AGPL-3.0-or-later
//! What a peer's key is to the peer path when rows are each person's
//! (kotton #99): one key may be paired by two people, so the two decisions
//! `handle_peer_request` reads from a key are held here, each for the person
//! the request names and never across persons (kotton #119) — the gateway's
//! confinement and the person its frames reach ([`peer_ask`]), and
//! `NodeRelay`'s own-device check.

use super::browser_channel::gateway_key;
use super::{asks_as_own_device, peer_ask, MachineRows, PeerAsk};
use kotton_peer::dialer::{RowsSay, WhatKeyIs};
use kotton_wire::ipc::PeerRequest;
use kotton_peer::daemon::db as network_db;
use sqlx::SqlitePool;
use std::sync::Arc;

async fn machine_db(dir: &std::path::Path) -> Arc<SqlitePool> {
    let pool = kotton_record::open_sqlite(&dir.join("agent.db")).await.unwrap();
    kotton_device::db::MIGRATOR.run(&pool).await.unwrap();
    Arc::new(pool)
}

fn uid(s: &str) -> crate::device_users::UserId {
    crate::device_users::UserId::parse(s).unwrap()
}

/// The rule's key for `key`'s bytes, as the store's writer takes it.
fn vk(key: &[u8; 32]) -> kotton_crypto::ed25519::VerifyingKey {
    kotton_crypto::ed25519::VerifyingKey::from_bytes(key).unwrap()
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
    network_db::insert_paired_node(&db, "front-door", "bob", &vk(&key), "[]", 0, Some("gateway")).await.unwrap();
    network_db::insert_paired_node(&db, "front-door", "alice", &vk(&key), "[]", 0, Some("gateway")).await.unwrap();

    assert_eq!(peer_ask(&db, Some(&key), &frame_for(Some("bob"))).await, Ok(PeerAsk::Gateway(uid("bob"))));
    assert_eq!(peer_ask(&db, Some(&key), &frame_for(Some("alice"))).await, Ok(PeerAsk::Gateway(uid("alice"))));
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
    assert_eq!(peer_ask(&db, Some(&key), &frame_for(Some("alice"))).await, Ok(PeerAsk::Gateway(uid("alice"))));
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
    let (key, _) = key_and_did(21);
    network_db::insert_paired_node(&db, "laptop", "alice", &vk(&key), "[]", 0, Some("full")).await.unwrap();
    network_db::insert_paired_node(&db, "front-door", "bob", &vk(&key), "[]", 0, Some("gateway")).await.unwrap();

    assert_eq!(peer_ask(&db, Some(&key), &frame_for(Some("bob"))).await, Ok(PeerAsk::Gateway(uid("bob"))));
    assert_eq!(peer_ask(&db, Some(&key), &other_for("bob")).await, Ok(PeerAsk::Gateway(uid("bob"))));
    assert_eq!(peer_ask(&db, Some(&key), &other_for("alice")).await, Ok(PeerAsk::Person(uid("alice"))));
    assert!(peer_ask(&db, Some(&key), &frame_for(Some("alice"))).await.is_err(), "alice's full device carried a frame as her gateway");

    let (unpaired, _) = key_and_did(22);
    assert!(peer_ask(&db, Some(&unpaired), &frame_for(Some("bob"))).await.is_err());
    assert_eq!(peer_ask(&db, Some(&unpaired), &other_for("bob")).await, Ok(PeerAsk::Person(uid("bob"))));
    // A peer whose DID names no key is no one's gateway.
    assert!(peer_ask(&db, None, &frame_for(Some("bob"))).await.is_err());
}

/// **A name that is not a user id is refused before anything is read for
/// it** (kotton #262). `peer_ask` is where the peer path first holds the
/// person a request names; a climb out of `users/`, an absolute path, nothing,
/// or an over-long name is answered there with a refusal, for a paired key and
/// an unpaired one alike, and never becomes a [`PeerAsk`].
#[tokio::test]
async fn a_request_naming_no_valid_user_id_is_refused_at_peer_ask() {
    let dir = tempfile::tempdir().unwrap();
    let db = machine_db(dir.path()).await;
    let (key, _) = key_and_did(24);
    network_db::insert_paired_node(&db, "laptop", "alice", &vk(&key), "[]", 0, Some("full")).await.unwrap();
    let over_long = "a".repeat(65);
    for bad in ["../../x", "/tmp/abs", "alice/../bob", "..", "", over_long.as_str()] {
        for pk in [Some(&key), None] {
            let refused = peer_ask(&db, pk, &other_for(bad)).await;
            assert!(
                matches!(&refused, Err(m) if m.contains("not a user id")),
                "{bad:?} was taken for a person: {refused:?}"
            );
        }
    }
    assert_eq!(peer_ask(&db, Some(&key), &other_for("alice")).await, Ok(PeerAsk::Person(uid("alice"))));
}

/// **A minted user id passes the parse, for a gateway and a device alike**
/// (kotton #262). Every request now passes `UserId::parse` before the posture
/// row is read; the ids the window mints (`u` and thirty-two hex digits) are
/// the shape most persons have, so the happy path is held for that shape, not
/// only for a hand-picked name.
#[tokio::test]
async fn a_minted_user_id_is_taken_as_the_person_it_names() {
    let dir = tempfile::tempdir().unwrap();
    let db = machine_db(dir.path()).await;
    let gateway_person = crate::device_users::mint_user_id();
    let device_person = crate::device_users::mint_user_id();
    let (key, _) = key_and_did(25);
    network_db::insert_paired_node(&db, "front-door", &gateway_person, &vk(&key), "[]", 0, Some("gateway")).await.unwrap();
    network_db::insert_paired_node(&db, "laptop", &device_person, &vk(&key), "[]", 0, Some("full")).await.unwrap();
    assert_eq!(
        peer_ask(&db, Some(&key), &frame_for(Some(&gateway_person))).await,
        Ok(PeerAsk::Gateway(uid(&gateway_person)))
    );
    assert_eq!(
        peer_ask(&db, Some(&key), &other_for(&device_person)).await,
        Ok(PeerAsk::Person(uid(&device_person)))
    );
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
    let (key, _) = key_and_did(23);
    network_db::insert_paired_node(&db, "vault", "bob", &vk(&key), "[]", 0, Some("blind-storage")).await.unwrap();
    network_db::insert_paired_node(&db, "desktop", "alice", &vk(&key), "[]", 0, Some("full")).await.unwrap();

    assert!(asks_as_own_device(&db, &key, "alice").await, "alice's full device was refused as hers");
    assert!(!asks_as_own_device(&db, &key, "bob").await, "bob's vault was taken for his device by alice's row");
    assert!(!asks_as_own_device(&db, &key, "carol").await);

    // A row from before postures is a full device.
    let (old, _) = key_and_did(24);
    network_db::insert_paired_node(&db, "old", "carol", &vk(&old), "[]", 0, None).await.unwrap();
    assert!(asks_as_own_device(&db, &old, "carol").await);
}

/// **Two rows of one person's under one key: the peer path reads the narrowest
/// of them** (kottonllc/kotton#597: the narrowest of a key's rows answers what
/// it may ask). For every pair of what a row can say, under both arrangements
/// of DID and of time: the key is the person's own device at `NodeRelay` only
/// where both rows say `full` or nothing, and is the person's gateway, held to
/// the gateway's verb, where either says `gateway`.
#[tokio::test]
async fn of_two_rows_under_one_key_the_peer_path_reads_the_narrowest() {
    let dir = tempfile::tempdir().unwrap();
    let db = machine_db(dir.path()).await;
    let says = [Some("gateway"), Some("blind-storage"), Some("cosigner"), Some("posture-of-a-later-build"), Some("full"), None];
    let mut seed = 100u8;
    for a in says {
        for b in says {
            let own = [a, b].iter().all(|p| matches!(p, None | Some("full")));
            let gateway = [a, b].contains(&Some("gateway"));
            for (a_derived, a_first) in [(true, true), (true, false), (false, true), (false, false)] {
                seed = seed.wrapping_add(1);
                let (key, derived) = key_and_did(seed);
                let spelled = kotton_crypto::DidKeyMethod::spelled_otherwise(&key).to_string();
                let (a_did, b_did) = if a_derived { (&derived, &spelled) } else { (&spelled, &derived) };
                let (a_at, b_at) = if a_first { (100, 200) } else { (200, 100) };
                network_db::seed_paired_node_as_stored(&db, "a", "alice", a_did, &key, "[]", a_at, a).await.unwrap();
                network_db::seed_paired_node_as_stored(&db, "b", "alice", b_did, &key, "[]", b_at, b).await.unwrap();
                let case = format!("rows {a:?} and {b:?}, the first under the key's did:key: {a_derived}, paired first: {a_first}");

                assert_eq!(asks_as_own_device(&db, &key, "alice").await, own, "{case}: NodeRelay's own-device check");
                let other = peer_ask(&db, Some(&key), &other_for("alice")).await;
                let frame = peer_ask(&db, Some(&key), &frame_for(Some("alice"))).await;
                if gateway {
                    assert_eq!(other, Ok(PeerAsk::Gateway(uid("alice"))), "{case}: not held to the gateway's verb");
                    assert_eq!(frame, Ok(PeerAsk::Gateway(uid("alice"))), "{case}: the gateway's frame was refused");
                } else {
                    assert_eq!(other, Ok(PeerAsk::Person(uid("alice"))), "{case}: taken for a gateway");
                    assert!(frame.is_err(), "{case}: a frame was carried for a key no row says is a gateway");
                }
                sqlx::query("DELETE FROM paired_nodes").execute(db.as_ref()).await.unwrap();
            }
        }
    }
}

/// **Both ends read one answer for a key.** What the daemon hands its dialler
/// ([`MachineRows`]) says an `offer` is learned from a key exactly where
/// `NodeRelay`'s own-device check hands one: for no row, for each thing a row
/// can say alone, and for every pair of them under both arrangements of DID and
/// of time, the narrowest of the person's rows answers, at both ends.
#[tokio::test]
async fn the_dialling_end_and_the_listening_end_read_one_answer_for_a_key() {
    let dir = tempfile::tempdir().unwrap();
    let db = machine_db(dir.path()).await;
    let asked = MachineRows(Arc::clone(&db));
    let says = [Some("gateway"), Some("blind-storage"), Some("cosigner"), Some("posture-of-a-later-build"), Some("full"), None];
    let both = |own: bool| if own { RowsSay::Offer } else { RowsSay::NoOffer };

    // No row.
    let (nobody, _) = key_and_did(90);
    assert_eq!(asked.to_person(&nobody, "alice").await, RowsSay::NoOffer, "no row");
    assert!(!asks_as_own_device(&db, &nobody, "alice").await, "no row");

    // One row, of each.
    let mut seed = 160u8;
    for a in says {
        seed = seed.wrapping_add(1);
        let (key, did) = key_and_did(seed);
        network_db::seed_paired_node_as_stored(&db, "a", "alice", &did, &key, "[]", 100, a).await.unwrap();
        let own = matches!(a, None | Some("full"));
        assert_eq!(asked.to_person(&key, "alice").await, both(own), "one row {a:?}: the dialling end");
        assert_eq!(asks_as_own_device(&db, &key, "alice").await, own, "one row {a:?}: the listening end");
        sqlx::query("DELETE FROM paired_nodes").execute(db.as_ref()).await.unwrap();
    }

    // Two rows, every pair, both arrangements of DID and of time.
    for a in says {
        for b in says {
            let own = [a, b].iter().all(|p| matches!(p, None | Some("full")));
            for (a_derived, a_first) in [(true, true), (true, false), (false, true), (false, false)] {
                seed = seed.wrapping_add(1);
                let (key, derived) = key_and_did(seed);
                let spelled = kotton_crypto::DidKeyMethod::spelled_otherwise(&key).to_string();
                let (a_did, b_did) = if a_derived { (&derived, &spelled) } else { (&spelled, &derived) };
                let (a_at, b_at) = if a_first { (100, 200) } else { (200, 100) };
                network_db::seed_paired_node_as_stored(&db, "a", "alice", a_did, &key, "[]", a_at, a).await.unwrap();
                network_db::seed_paired_node_as_stored(&db, "b", "alice", b_did, &key, "[]", b_at, b).await.unwrap();
                let case = format!("rows {a:?} and {b:?}, the first under the key's did:key: {a_derived}, paired first: {a_first}");
                assert_eq!(asked.to_person(&key, "alice").await, both(own), "{case}: the dialling end");
                assert_eq!(asks_as_own_device(&db, &key, "alice").await, own, "{case}: the listening end");
                // Another person's rows for the key say nothing of it to alice.
                assert_eq!(asked.to_person(&key, "bob").await, RowsSay::NoOffer, "{case}: read across persons");
                sqlx::query("DELETE FROM paired_nodes").execute(db.as_ref()).await.unwrap();
            }
        }
    }
}

/// **Rows that cannot be read are said so to the dialler**, which then learns
/// nothing from the answer; the listening end reads the same failure as no.
#[tokio::test]
async fn rows_that_cannot_be_read_are_unreadable_to_the_dialler() {
    let dir = tempfile::tempdir().unwrap();
    let db = machine_db(dir.path()).await;
    let (key, _) = key_and_did(91);
    network_db::insert_paired_node(&db, "desktop", "alice", &vk(&key), "[]", 0, Some("full")).await.unwrap();
    let asked = MachineRows(Arc::clone(&db));
    assert_eq!(asked.to_person(&key, "alice").await, RowsSay::Offer);
    db.close().await;
    assert_eq!(asked.to_person(&key, "alice").await, RowsSay::Unreadable, "a failed read was answered");
    assert!(!asks_as_own_device(&db, &key, "alice").await);
}
