// SPDX-License-Identifier: AGPL-3.0-or-later
//! Two people, two nodes, a relay that keeps nothing: M2's sentence.
//!
//! *Two strangers, two nodes, different networks. They pair on a spoken code
//! and matching emoji* — six digits here, RFC-0076's — *and no account existed
//! at any point.* Alice starts, reads three words out; Bob types them; both
//! screens show the same digits; both say yes; each now holds the other as a
//! contact with the key the ceremony authenticated (RFC-0022, DEC-0055).
//!
//! Then *they message*: Alice's node hands Bob's node one sealed record over a
//! per-pair mailbox, and Bob reads it (`DEC-0055`). The relay in the loop is a
//! real `kotton-relay`, and what it saw was two circuits between labels that
//! name nobody — a handle derived from the spoken code, a key Bob made for the
//! dial, and a pair of mailbox handles that rotate hourly. Nothing durable,
//! nothing that composes (Article VII).
//!
//! Two daemons share this process, so "different networks" is not literal
//! here: nothing crosses a NAT. What is literal is that neither daemon holds a
//! route, a key, or a name for the other before the ceremony, and every byte
//! between them goes through the relay.

use crate::common::{self, TestEnv, TEST_PASSPHRASE};
use kotton_schemas::membership::Posture;
use kotton::KottonClient;
use kotton_wire::ipc::{Delivery, UserResponse};
use tokio::sync::oneshot;

/// What one side of the ceremony saw.
pub(crate) struct Outcome {
    sas: Option<u32>,
    paired: Option<(String, String)>,
    failed: Option<String>,
}

pub(crate) async fn two_nodes() -> (common::relay::Relay, TestEnv, String, TestEnv, String) {
    let (relay, relay_addr) = common::relay::spawn().await;
    let (mut a, mut b) = (
        common::relay::env_on(&relay_addr).await,
        common::relay::env_on(&relay_addr).await,
    );
    let (alice, _) = a.client.create_user("alice", TEST_PASSPHRASE).await.expect("alice");
    let (bob, _) = b.client.create_user("bob", TEST_PASSPHRASE).await.expect("bob");
    (relay, a, alice, b, bob)
}

/// Drive the issuer's stream: hand the code out, answer the digits with
/// `verdict`, and report what happened.
async fn issuer(client: &KottonClient, user: &str, ttl: u64, verdict: bool, code_tx: oneshot::Sender<String>) -> Outcome {
    let mut rx = client
        .contact_pair_start_stream(user, None, ttl)
        .await
        .expect("contact_pair_start_stream");
    let mut code_tx = Some(code_tx);
    let mut out = Outcome { sas: None, paired: None, failed: None };
    while let Some(frame) = rx.recv().await {
        match frame {
            UserResponse::PairAdvertising { code, .. } => {
                let code = code.expose().to_string();
                assert_eq!(code.split('-').count(), 3, "three spoken words: {code}");
                let _ = code_tx.take().expect("one advertising frame").send(code);
            }
            UserResponse::PairShowCode { token, sas, .. } => {
                out.sas = Some(sas);
                client.pair_confirm_code(user, token.expose(), verdict).await.expect("issuer confirm");
            }
            UserResponse::ContactPaired { did, label } => {
                out.paired = Some((did, label));
                break;
            }
            UserResponse::PairFailed { reason } => {
                out.failed = Some(reason);
                break;
            }
            _ => {}
        }
    }
    out
}

/// Drive the joiner's stream with `code`, answering the digits with `verdict`.
async fn joiner(client: &KottonClient, user: &str, code: String, verdict: bool) -> Outcome {
    joiner_of(client, user, "alice", code, verdict).await
}

/// [`joiner`], pairing with an issuer whose screen name is `issuer`.
async fn joiner_of(client: &KottonClient, user: &str, issuer: &str, code: String, verdict: bool) -> Outcome {
    let mut rx = client
        .contact_pair_join_stream(user, &code, Some("Bob from the bakery"))
        .await
        .expect("contact_pair_join_stream");
    let mut out = Outcome { sas: None, paired: None, failed: None };
    while let Some(frame) = rx.recv().await {
        match frame {
            UserResponse::PairShowCode { token, sas, peer_label } => {
                assert_eq!(peer_label.as_deref(), Some(issuer), "the joiner's screen names who it is pairing with");
                out.sas = Some(sas);
                client.pair_confirm_code(user, token.expose(), verdict).await.expect("joiner confirm");
            }
            UserResponse::ContactPaired { did, label } => {
                out.paired = Some((did, label));
                break;
            }
            UserResponse::PairFailed { reason } => {
                out.failed = Some(reason);
                break;
            }
            _ => {}
        }
    }
    out
}

/// Run the ceremony to completion between two spawned nodes, as a person would.
pub(crate) async fn pair(a: &TestEnv, b: &TestEnv) -> (Outcome, Outcome) {
    pair_as(a, "alice", b, "bob").await
}

/// [`pair`], naming both sides — for a scenario with more than two people in it.
pub(crate) async fn pair_as(a: &TestEnv, a_user: &str, b: &TestEnv, b_user: &str) -> (Outcome, Outcome) {
    let (code_tx, code_rx) = oneshot::channel();
    tokio::join!(issuer(&a.client, a_user, 60, true, code_tx), async {
        let code = code_rx.await.expect("the issuer produced a code");
        // As heard, not as printed: case and spacing are the listener's.
        let heard = code.replace('-', " ").to_uppercase();
        joiner_of(&b.client, b_user, a_user, heard, true).await
    })
}

#[tokio::test]
async fn two_strangers_pair_on_a_spoken_code_through_a_relay() {
    let (_relay, mut a, alice_did, mut b, bob_did) = two_nodes().await;
    assert!(a.client.contact_list("alice").await.unwrap().is_empty());
    assert!(b.client.contact_list("bob").await.unwrap().is_empty());

    let (oa, ob) = pair(&a, &b).await;

    assert_eq!(oa.failed, None, "alice");
    assert_eq!(ob.failed, None, "bob");
    assert_eq!(oa.sas, ob.sas, "both screens showed the same six digits");
    assert!(oa.sas.is_some());
    assert_eq!(oa.paired.as_ref().unwrap().0, bob_did, "alice holds bob's identity");
    assert_eq!(oa.paired.as_ref().unwrap().1, "Bob from the bakery");
    assert_eq!(ob.paired.as_ref().unwrap().0, alice_did, "bob holds alice's identity");
    assert_eq!(ob.paired.as_ref().unwrap().1, "alice");

    // Each is now a contact of the other: an authenticated key, and nothing more.
    let alices = a.client.contact_list("alice").await.unwrap();
    assert_eq!(alices, vec![(bob_did.clone(), Some("Bob from the bakery".to_string()))]);
    let bobs = b.client.contact_list("bob").await.unwrap();
    assert_eq!(bobs, vec![(alice_did.clone(), Some("alice".to_string()))]);

    // The key is real: a message to the contact seals under it.
    a.client.message_send("alice", &bob_did, "hello from across the relay", None).await.expect("seal to bob");
    b.client.message_send("bob", &alice_did, "hello back", None).await.expect("seal to alice");
}

/// **A contact is given a door, and not this device's**
/// (`TASK-a-reply-sent-at-once-can-find-no-door-open-for-it`).
///
/// A contact reaches a node at their own door, one per pair (`DEC-0055`), and
/// nowhere else. Pairing used to write their identity key into the device door's
/// allowlist as well, until the daemon restarted. So each node held two device
/// reservations for the contact beside the two doors, and "two reservations are
/// up" could be read before either door was. That is how Bob's first reply found
/// no door of Alice's. After a pairing, the allowlist is as it was, and the relay
/// listener wants exactly the contact's door for this epoch and the one before.
#[tokio::test]
async fn a_contact_is_given_a_door_and_not_this_devices() {
    let (_relay, mut a, _alice_did, mut b, _bob_did) = two_nodes().await;
    let allowlist = |env: &TestEnv| env.runtime.reachability().paired_keys().read().unwrap().clone();
    let (a_before, b_before) = (allowlist(&a), allowlist(&b));

    let (oa, ob) = pair(&a, &b).await;
    assert_eq!((oa.failed, ob.failed), (None, None), "paired");
    mailbox_open(&mut a, "alice").await;
    mailbox_open(&mut b, "bob").await;

    for (env, user, before) in [(&mut a, "alice", a_before), (&mut b, "bob", b_before)] {
        assert_eq!(allowlist(env), before, "{user}: a contact's key entered the device door's allowlist");
        let relay = env.client.network_status(user).await.expect("network status").relay;
        assert_eq!(
            (relay.reservations_wanted, relay.reservations_live),
            (2, 2),
            "{user} holds the contact's two doors and nothing else"
        );
    }
}

/// Wait until `user`'s node is holding the mailbox reservations its contacts
/// imply — RFC-0083 R6's readout, used for what it is for. A message sent
/// before the mailbox is open would be an honest `Unreachable`, and asserting
/// on the race rather than on the behaviour is how a test becomes flaky.
///
/// **Every** reservation the node wants, not some number of them. Until
/// 2026-09-26 this waited for two, which was one contact's two doors only while
/// nothing else was held. A node also held two for the contact at the device
/// door, and two of the four could be up with a door not among them
/// (`TASK-a-reply-sent-at-once-can-find-no-door-open-for-it`).
pub(crate) async fn mailbox_open(env: &mut TestEnv, user: &str) {
    mailbox_open_for(env, user, 1).await
}

/// [`mailbox_open`] for a node paired with `contacts` people: two doors each,
/// this epoch's and the last (`a_contact_is_given_a_door_and_not_this_devices`).
///
/// The count is the point. Right after a second or third pairing, the node can
/// still be wanting only the first contact's two doors, and two live out of two
/// wanted then reads as open while the newest contact's door is not held. A
/// copy handed to that door finds *"no mailbox answered"*. That is how the
/// three-daemon channel test failed on its first grouped run, 2026-10-08
/// (`household_channel::a_member_who_wrote_no_grant_removes_another_and_the_rest_read_on`).
pub(crate) async fn mailbox_open_for(env: &mut TestEnv, user: &str, contacts: u32) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let doors = 2 * contacts.max(1);
    loop {
        let status = env.client.network_status(user).await.expect("network status");
        if status.relay.reservations_wanted >= doors && status.relay.reservations_live >= status.relay.reservations_wanted {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no mailbox opened for {user}: {} of {} reservations live",
            status.relay.reservations_live,
            status.relay.reservations_wanted
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

/// M2's second half: *they message*. One sealed record crosses from one
/// person's node to another's and is read there (`DEC-0055`).
#[tokio::test]
async fn a_message_reaches_the_other_person_and_they_read_it() {
    let (_relay, mut a, _alice_did, mut b, bob_did) = two_nodes().await;
    pair(&a, &b).await;
    mailbox_open(&mut b, "bob").await;

    let (_id, delivery) = a
        .client
        .message_send_delivery("alice", &bob_did, "the milk is in the fridge", None)
        .await
        .expect("send");
    assert_eq!(
        delivery,
        Some(Delivery::Delivered),
        "the recipient's node took the message"
    );

    // Bob's copy is his: in his own store, readable with his own key, and its
    // existence does not depend on Alice's (Article V).
    let inbox = b.client.message_poll_inbox("bob").await.expect("bob's inbox");
    assert_eq!(inbox.len(), 1, "one message, once: {inbox:?}");
    let (body, nonce, eph) = crypto_fields(&inbox[0]);
    assert_ne!(body, "the milk is in the fridge", "what crossed was ciphertext");
    let plaintext = b
        .client
        .message_decrypt_dm("bob", &body, &nonce, &eph)
        .await
        .expect("bob decrypts");
    assert_eq!(plaintext, "the milk is in the fridge");

    // At-least-once, and the ciphertext is the identity: handing the same
    // record over again files nothing new.
    let again = a
        .client
        .message_send_delivery("alice", &bob_did, "the milk is in the fridge", None)
        .await
        .expect("send again");
    assert_eq!(again.1, Some(Delivery::Delivered), "a second message is a second message");
    assert_eq!(
        b.client.message_poll_inbox("bob").await.unwrap().len(),
        2,
        "two sends are two messages — the dedup is per record, not per text"
    );
}

/// **A sender reads back what they sent, from their own node, with no page
/// holding it** (`TASK-a-sender-cannot-reopen-what-they-sent`).
///
/// Until this, the record a sender filed carried the envelope that travelled —
/// sealed to the recipient, so it opened on the recipient's key and on nobody
/// else's, the sender's included. It is now sealed a second time, to the
/// sender, and the envelope stays in the outbox where it belongs.
///
/// Four readings, and each is one half of the property:
/// - the sender's filed copy opens on the sender's key — the Done-when;
/// - the envelope that travelled still does **not** open on the sender's key —
///   the bytes the sender used to file, refusing as the record measured;
/// - the sender's copy does **not** open on the recipient's key, so the second
///   seal gave nobody else a way in;
/// - the two copies share no `ephemeral_pub` — the one value the relay and any
///   vault also saw is not in the sender's store to join on.
#[tokio::test]
async fn a_sender_reads_back_what_they_sent_and_nobody_else_can() {
    let (_relay, mut a, _alice_did, mut b, bob_did) = two_nodes().await;
    pair(&a, &b).await;
    mailbox_open(&mut b, "bob").await;

    let (_id, delivery) = a
        .client
        .message_send_delivery("alice", &bob_did, "the ferry leaves at 6:40, not 7", None)
        .await
        .expect("send");
    assert_eq!(delivery, Some(Delivery::Delivered), "bob's node took it");

    // What Alice filed for what she sent, read from her own store — no page,
    // no in-memory copy of what she typed.
    let filed = a
        .client
        .record_query(
            "alice",
            "sh.kotton.message.v1",
            vec![("to_did".to_string(), serde_json::json!(bob_did))],
            None,
            None,
        )
        .await
        .expect("alice's own store");
    assert_eq!(filed.len(), 1, "one message was sent: {filed:?}");
    let (body, nonce, eph) = crypto_fields(&filed[0]);
    assert_ne!(body, "the ferry leaves at 6:40, not 7", "her copy is sealed, not filed in the clear");

    let read_back = a.client.message_decrypt_dm("alice", &body, &nonce, &eph).await;
    assert_eq!(
        read_back.as_deref().ok(),
        Some("the ferry leaves at 6:40, not 7"),
        "the sender's own copy opens on the sender's key: {read_back:?}"
    );

    // The envelope that travelled — what Bob holds, and what Alice's record
    // held before this — is sealed to Bob, and still refuses Alice.
    let inbox = b.client.message_poll_inbox("bob").await.expect("bob's inbox");
    assert_eq!(inbox.len(), 1, "bob has it once: {inbox:?}");
    let (t_body, t_nonce, t_eph) = crypto_fields(&inbox[0]);
    assert!(
        a.client.message_decrypt_dm("alice", &t_body, &t_nonce, &t_eph).await.is_err(),
        "the envelope sealed to the recipient must not open on the sender's key"
    );
    assert_eq!(
        b.client.message_decrypt_dm("bob", &t_body, &t_nonce, &t_eph).await.expect("bob opens his"),
        "the ferry leaves at 6:40, not 7"
    );

    // The second seal is to Alice alone.
    assert!(
        b.client.message_decrypt_dm("bob", &body, &nonce, &eph).await.is_err(),
        "the sender's copy must not open on the recipient's key"
    );

    // And nothing in her store joins to what crossed the relay.
    assert_ne!(eph, t_eph, "the sender's copy carries its own ephemeral key, not the transport's");
    assert_ne!(body, t_body, "and its own ciphertext");
}

/// A person who rotates their identity key keeps the conversation they already
/// had (`TASK-a-rotated-identity-key-leaves-every-older-message-sealed-to-a-key-the-node-no-longer-holds`).
///
/// Bob writes to Alice and Alice writes to Bob, across two daemons and a real
/// relay. Alice then rotates her identity key with her recovery phrase. Both
/// records she filed before it — the one she received, and her own copy of the
/// one she sent — were sealed to the key the rotation retired, and both still
/// open with `MessageDecryptDm` on her node: the very bytes read before the
/// rotation, and the records as her store holds them after it — though the new
/// key alone opens neither. Bob's node, which holds none of Alice's keys, still
/// opens neither of Alice's copies.
#[tokio::test]
async fn a_rotated_key_still_opens_what_was_received_and_sent_before_it() {
    let (_relay, mut a, alice_did, mut b, bob_did) = two_nodes().await;
    pair(&a, &b).await;
    mailbox_open(&mut a, "alice").await;
    mailbox_open(&mut b, "bob").await;

    let (_id, delivery) = b
        .client
        .message_send_delivery("bob", &alice_did, "the boat is at slip 4", None)
        .await
        .expect("bob sends");
    assert_eq!(delivery, Some(Delivery::Delivered), "alice's node took bob's message");
    let (_id, delivery) = a
        .client
        .message_send_delivery("alice", &bob_did, "see you on the dock", None)
        .await
        .expect("alice sends");
    assert_eq!(delivery, Some(Delivery::Delivered), "bob's node took alice's message");

    // Alice's two records, read from her own store: what she received, and her
    // copy of what she sent.
    let received = a.client.message_poll_inbox("alice").await.expect("alice's inbox");
    assert_eq!(received.len(), 1, "alice received one message: {received:?}");
    let sent = a
        .client
        .record_query(
            "alice",
            "sh.kotton.message.v1",
            vec![("to_did".to_string(), serde_json::json!(bob_did))],
            None,
            None,
        )
        .await
        .expect("alice's own store");
    assert_eq!(sent.len(), 1, "alice sent one message: {sent:?}");
    let before = [
        (crypto_fields(&received[0]), "the boat is at slip 4"),
        (crypto_fields(&sent[0]), "see you on the dock"),
    ];
    for ((body, nonce, eph), text) in &before {
        assert_eq!(
            a.client.message_decrypt_dm("alice", body, nonce, eph).await.expect("opens before"),
            *text
        );
    }

    // The rotation: a new identity key, the same identity.
    let alice_key = || {
        let label = kotton_common::crypto::kdf_labels::identity_signing_key("alice");
        let hex_key = a.runtime.secrets().get_secret(&label).unwrap().expect("alice's key is held");
        let bytes: [u8; 32] = hex::decode(hex_key).unwrap().try_into().unwrap();
        ed25519_dalek::SigningKey::from_bytes(&bytes)
    };
    let old_key = alice_key();
    let phrase = a.client.add_recovery_phrase("alice").await.expect("alice's phrase");
    let new_key = a.client.rotate_identity("alice", &phrase, Some(TEST_PASSPHRASE)).await.expect("rotate_identity");
    let current = alice_key();
    assert_eq!(hex::encode(current.verifying_key().to_bytes()), new_key, "the node holds the new key");
    assert_ne!(current.to_bytes(), old_key.to_bytes(), "the rotation replaced the key");

    // The current key alone does not open what came before it — so what opens
    // below is the retired key, kept, and nothing else.
    use base64::Engine as _;
    let b64 = |s: &str| base64::engine::general_purpose::STANDARD.decode(s).unwrap();
    for ((body, nonce, eph), _) in &before {
        let (ct, nonce, eph) = (b64(body), b64(nonce), b64(eph));
        let (nonce, eph): ([u8; 12], [u8; 32]) = (nonce.try_into().unwrap(), eph.try_into().unwrap());
        assert!(
            kotton_crypto::x25519::dm_decrypt(&ct, &nonce, &eph, &current).is_err(),
            "a record sealed before the rotation must not open on the new key alone"
        );
        assert!(
            kotton_crypto::x25519::dm_decrypt(&ct, &nonce, &eph, &old_key).is_ok(),
            "it was sealed to the key the rotation retired"
        );
    }

    // The bytes read before the rotation still open on Alice's node.
    for ((body, nonce, eph), text) in &before {
        let opened = a.client.message_decrypt_dm("alice", body, nonce, eph).await;
        assert_eq!(
            opened.as_deref().ok(),
            Some(*text),
            "a message filed before the rotation opens after it: {opened:?}"
        );
    }

    // And as her store holds them now — nothing was rewritten, nothing lost.
    let received_after = a.client.message_poll_inbox("alice").await.expect("alice's inbox");
    let sent_after = a
        .client
        .record_query(
            "alice",
            "sh.kotton.message.v1",
            vec![("to_did".to_string(), serde_json::json!(bob_did))],
            None,
            None,
        )
        .await
        .expect("alice's own store");
    assert_eq!((received_after.len(), sent_after.len()), (1, 1));
    for (record, text) in [(&received_after[0], "the boat is at slip 4"), (&sent_after[0], "see you on the dock")] {
        let (body, nonce, eph) = crypto_fields(record);
        assert_eq!(
            a.client.message_decrypt_dm("alice", &body, &nonce, &eph).await.expect("opens from the store"),
            text
        );
    }

    // Kept for Alice alone: Bob's node opens neither of her copies.
    for ((body, nonce, eph), _) in &before {
        assert!(
            b.client.message_decrypt_dm("bob", body, nonce, eph).await.is_err(),
            "alice's records must not open on bob's node"
        );
    }
}

/// A contact follows a person through a rotation on the person's own proof
/// (`TASK-a-rotated-persons-contacts-keep-the-key-it-retired`).
///
/// Alice and Bob pair on two daemons, so Bob's card holds Alice's key and the
/// key log it was proved by. Alice rotates with her phrase. Nobody tells Bob
/// anything: Alice's daemon re-signs her reach note with the new key and hands
/// it, with her key log, over the door the pair still shares. Bob's card then
/// holds the new key — the key her log resolves to from the AID he already
/// holds, and from nothing a relay said. After that, all three things the
/// record names: her note is believed under the new key, a message she signs
/// with it is accepted, and a channel grant Bob wraps next is wrapped to it —
/// it opens on her new key and not on the one she retired.
#[tokio::test]
async fn a_contact_learns_a_rotated_key_from_the_persons_own_key_log() {
    const CHANNEL: &str = "did:key:zTheBoatThread";
    use kotton_peer::membership::Membership as _;
    let (_relay, mut a, alice_did, mut b, bob_did) = two_nodes().await;
    let (oa, ob) = pair(&a, &b).await;
    assert_eq!((oa.failed, ob.failed), (None, None), "paired");
    mailbox_open(&mut a, "alice").await;
    mailbox_open(&mut b, "bob").await;

    let alice_key = || {
        let label = kotton_common::crypto::kdf_labels::identity_signing_key("alice");
        let hex_key = a.runtime.secrets().get_secret(&label).unwrap().expect("alice's key is held");
        let bytes: [u8; 32] = hex::decode(hex_key).unwrap().try_into().unwrap();
        ed25519_dalek::SigningKey::from_bytes(&bytes)
    };
    let bobs = b.users.get("bob").expect("bob is resident");
    let card = || async {
        bobs.read_member(&alice_did).await.expect("bob's card").expect("alice is a contact")
    };
    let old_key = alice_key();
    assert_eq!(card().await.public_key, old_key.verifying_key().to_bytes(), "paired under her key");

    let phrase = a.client.add_recovery_phrase("alice").await.expect("alice's phrase");
    let new_hex = a.client.rotate_identity("alice", &phrase, Some(TEST_PASSPHRASE)).await.expect("rotate_identity");
    let new_key = alice_key();
    let new_pub = new_key.verifying_key().to_bytes();
    assert_eq!(hex::encode(new_pub), new_hex, "the node holds the new key");
    assert_ne!(new_pub, old_key.verifying_key().to_bytes(), "the rotation replaced the key");

    // Bob's card comes to hold the new key, and her note signed with it.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        if card().await.public_key == new_pub {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "bob's card never learned alice's rotated key; it still holds the one she retired"
        );
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }
    let held = card().await;
    let note = held.reach.expect("the card holds her note");
    assert_eq!(
        kotton_crypto::reach_note::verify(&note, &new_pub, &alice_did, kotton_peer::rendezvous::unix_now()),
        Ok(()),
        "the note the card holds is the one she signed with the new key"
    );
    // Learning a key admits nobody to Bob's device door: a contact is reached at
    // the pair's own door, and the device allowlist is not theirs to be on.
    {
        let paired = b.runtime.paired_keys();
        let paired = paired.read().unwrap();
        assert!(
            !paired.contains(&new_pub) && !paired.contains(&old_key.verifying_key().to_bytes()),
            "a contact's key, new or retired, is not in the device allowlist"
        );
    }
    // The key came from her log: the one the card kept now resolves to it.
    let kept = kotton_identity::kel_store::load_contact_chain(&b.base_dir, "bob", &alice_did).expect("the kept log");
    assert_eq!(
        kotton_crypto::kel_verify::resolve_current_key(&kept, &kotton_crypto::kel_verify::LocalArbiter, false),
        Ok(new_pub),
        "the card's key is what the kept log resolves to"
    );

    // A message she signs with the new key is accepted and read.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
    loop {
        let (_id, delivery) = a
            .client
            .message_send_delivery("alice", &bob_did, "same person, new key", None)
            .await
            .expect("alice sends");
        if delivery == Some(Delivery::Delivered) {
            break;
        }
        if std::time::Instant::now() >= deadline {
            // Seen twice under a loaded suite and never alone
            // (`TASK-a-contact-who-learned-a-rotated-key-is-sometimes-unreachable-at-the-new-door`):
            // say what each node held, so the next failure is a measurement.
            let bob_status = b.client.network_status("bob").await.expect("bob's status");
            let doors: Vec<bool> = b
                .runtime
                .reachability()
                .dm_inboxes()
                .read()
                .unwrap()
                .iter()
                .map(|i| i.contact_pub == new_pub)
                .collect();
            panic!(
                "bob's node never took a message alice signed with her new key: {delivery:?}; \
                 bob's reservations {}/{}, his card holds the new key: {}, his doors for alice \
                 derive from the new key: {doors:?}",
                bob_status.relay.reservations_live,
                bob_status.relay.reservations_wanted,
                card().await.public_key == new_pub,
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    let inbox = b.client.message_poll_inbox("bob").await.expect("bob's inbox");
    let (body, nonce, eph) = crypto_fields(inbox.last().expect("bob holds her message"));
    assert_eq!(
        b.client.message_decrypt_dm("bob", &body, &nonce, &eph).await.expect("bob decrypts"),
        "same person, new key"
    );

    // The next grant Bob wraps is wrapped to her new key.
    b.client.message_channel_create("bob", CHANNEL).await.expect("bob creates a channel");
    b.client
        .message_channel_grant_key("bob", CHANNEL, &alice_did, false)
        .await
        .expect("bob admits alice");
    let grants = b
        .client
        .record_query(
            "bob",
            "sh.kotton.channel.key-grant",
            vec![("to_did".to_string(), serde_json::json!(alice_did))],
            None,
            None,
        )
        .await
        .expect("bob's copy of alice's grant");
    assert_eq!(grants.len(), 1, "one grant to alice: {grants:?}");
    use base64::Engine as _;
    let field = |k: &str| {
        base64::engine::general_purpose::STANDARD
            .decode(grants[0][k].as_str().unwrap_or_else(|| panic!("{k} in {:?}", grants[0])))
            .unwrap()
    };
    let (enc, nonce, eph) = (field("enc_key"), field("nonce"), field("ephemeral_pub"));
    let (nonce, eph): ([u8; 12], [u8; 32]) = (nonce.try_into().unwrap(), eph.try_into().unwrap());
    assert!(
        kotton_crypto::x25519::channel_key_unwrap(&enc, &nonce, &eph, &new_key).is_ok(),
        "the grant opens on her new key"
    );
    assert!(
        kotton_crypto::x25519::channel_key_unwrap(&enc, &nonce, &eph, &old_key).is_err(),
        "and not on the key she retired"
    );
}

/// A person who moves relay is followed without pairing again
/// (`TASK-a-persons-reach-note-is-signed-by-them-and-replaces-relay-url`).
///
/// Alice and Bob pair on one relay. Alice then moves — to a second relay, to a
/// third, and back to the second — so the relay they met at is neither the one
/// she is on nor the one she is still forwarding from, and she holds no door
/// there. Nobody tells Bob. Alice's daemon re-signs her reach note on its own
/// and seals it to Bob over the relationship they already have, and Bob's next
/// message reaches her at the relay her note names. Until the note arrives,
/// Bob's card names only the relay they met at, and a message there finds no
/// door; so the delivery that succeeds is the note's doing and nothing else's.
#[tokio::test]
async fn a_persons_new_relay_reaches_their_contact_without_pairing_again() {
    let (_met_at, mut a, alice_did, mut b, _bob_did) = two_nodes().await;
    let (_second, second_addr) = common::relay::spawn().await;
    let (_third, third_addr) = common::relay::spawn().await;
    let (oa, ob) = pair(&a, &b).await;
    assert_eq!((oa.failed, ob.failed), (None, None), "paired");
    mailbox_open(&mut a, "alice").await;
    mailbox_open(&mut b, "bob").await;

    let second = format!("http://{second_addr}");
    let third = format!("http://{third_addr}");
    for relay in [&second, &third, &second] {
        a.client.node_rendezvous_set(Some(relay)).await.expect("alice moves relay");
    }
    let nat = a.runtime.reachability().nat();
    assert_eq!(nat.relay_url, second, "alice is on the second relay");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert_eq!(
        nat.forwarding_relay(now),
        Some(third.as_str()),
        "and forwarding from the third, not from the relay they met at"
    );

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
    let mut attempts = 0;
    loop {
        attempts += 1;
        let (_id, delivery) = b
            .client
            .message_send_delivery("bob", &alice_did, "did you move?", None)
            .await
            .expect("send");
        if delivery == Some(Delivery::Delivered) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "bob's message never reached alice at her new relay after {attempts} tries: {delivery:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    // And it is hers: in her store, opened with her key.
    let inbox = a.client.message_poll_inbox("alice").await.expect("alice's inbox");
    assert!(!inbox.is_empty(), "alice holds bob's message");
    let (body, nonce, eph) = crypto_fields(inbox.last().unwrap());
    let plaintext = a
        .client
        .message_decrypt_dm("alice", &body, &nonce, &eph)
        .await
        .expect("alice decrypts");
    assert_eq!(plaintext, "did you move?");
}

/// **A contact's device is admitted under *the people I invite***
/// (`TASK-a-device-presents-its-relays-admission-tag-and-the-reach-row-sets-the-rule`,
/// Done-when 3).
///
/// Alice runs a host, and she and Bob are both on its relay. They pair while it
/// admits anyone. Alice's desktop then narrows it to *the people I invite*:
/// the invited key rides in her reach note, re-signed because it changed and
/// sealed to Bob over the relationship they already have. Bob holds no key of
/// his own for the relay; the one his delivery presents is the one her note
/// handed him, and his message reaches her. A stranger is refused. And the key
/// is what admitted him: narrowed again to *only my devices*, Bob's next
/// delivery is refused at the relay, as a stranger's is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_contacts_device_is_admitted_under_the_people_i_invite() {
    use kotton_wire::ipc::OperatorVerb;
    use kotton_wire::rendezvous::AdmissionRule;

    let bx = crate::vault::a_box().await;
    let mut a = common::relay::env_on(&bx.relay_addr).await;
    let mut b = common::relay::env_on(&bx.relay_addr).await;
    let (alice_did, _) = a.client.create_user("alice", TEST_PASSPHRASE).await.expect("alice");
    b.client.create_user("bob", TEST_PASSPHRASE).await.expect("bob");
    bx.enrol_on(&mut a.client, "alice").await;
    let (oa, ob) = pair(&a, &b).await;
    assert_eq!((oa.failed, ob.failed), (None, None), "paired");
    mailbox_open(&mut a, "alice").await;
    mailbox_open(&mut b, "bob").await;

    let set = |rule| OperatorVerb::SetRule { rule };
    match a.client.as_operator("alice", "kotton", set(AdmissionRule::PeopleIInvite)).await.expect("answered") {
        UserResponse::RelayRule { rule } => assert_eq!(rule, AdmissionRule::PeopleIInvite),
        other => panic!("the rule was not set: {other:?}"),
    }
    assert!(
        crate::vault::refused_by_the_rule(&crate::vault::a_push_at(&bx.relay_url, None).await),
        "a stranger is refused under the people I invite"
    );
    assert_eq!(
        b.runtime.reachability().relay_keys().present_at(&bx.relay_id),
        None,
        "bob holds no key of his own for alice's relay"
    );

    // Bob's message reaches Alice once her note, carrying the key, has reached him.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let (_id, delivery) = b
            .client
            .message_send_delivery("bob", &alice_did, "let me in", None)
            .await
            .expect("send");
        if delivery == Some(Delivery::Delivered) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "bob was never admitted under the people I invite: {delivery:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    let inbox = a.client.message_poll_inbox("alice").await.expect("alice's inbox");
    assert!(!inbox.is_empty(), "alice holds bob's message");

    // The key is what let him in: under only my devices his delivery is refused.
    match a.client.as_operator("alice", "kotton", set(AdmissionRule::OnlyMyDevices)).await.expect("answered") {
        UserResponse::RelayRule { rule } => assert_eq!(rule, AdmissionRule::OnlyMyDevices),
        other => panic!("the rule was not set: {other:?}"),
    }
    let (_id, delivery) = b
        .client
        .message_send_delivery("bob", &alice_did, "and now?", None)
        .await
        .expect("send");
    assert!(
        matches!(delivery, Some(Delivery::Unreachable { .. })),
        "bob was admitted under only my devices: {delivery:?}"
    );
}

/// **Two people pair on a spoken code at a relay whose rule is *the people I
/// invite*, and a stranger with no key is refused there**
/// (`TASK-a-first-contact-ceremony-meets-at-a-relay-whose-rule-refuses-a-stranger`).
///
/// A spoken code carries no key — a voice cannot — so the ceremony meets at
/// each side's own relay, and each presents the key it holds there: Alice, the
/// relay's operator, *mine*; Bob, who stands at her relay by the relay's invite
/// she minted, the *invited* key it carried. Carol stands at the same relay by
/// its address alone and holds no key: her dial to Alice's code is refused at
/// the relay, and spends nothing — Bob joins the same code after her, and the
/// two are paired. Nobody pairs Carol. And Bob, who holds the invited key as an
/// invitee, mints no vault-style invite from his device: it could carry no key
/// the relay reads.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_people_pair_on_a_spoken_code_at_a_narrowed_relay_and_a_stranger_is_refused() {
    use kotton_wire::ipc::OperatorVerb;
    use kotton_wire::rendezvous::AdmissionRule;

    let bx = crate::vault::a_box().await;
    let mut a = common::relay::env_on(&bx.relay_addr).await;
    let (_alice_did, _) = a.client.create_user("alice", TEST_PASSPHRASE).await.expect("alice");
    bx.enrol_on(&mut a.client, "alice").await;
    match a.client.as_operator("alice", "kotton", OperatorVerb::SetRule { rule: AdmissionRule::PeopleIInvite }).await.expect("answered") {
        UserResponse::RelayRule { rule } => assert_eq!(rule, AdmissionRule::PeopleIInvite),
        other => panic!("the rule was not set: {other:?}"),
    }
    let invite = match a.client.as_operator("alice", "kotton", OperatorVerb::RelayInvite).await.expect("answered") {
        UserResponse::RelayInvite { invite } => invite.expose().to_string(),
        other => panic!("no relay invite was minted: {other:?}"),
    };

    // Bob stands at Alice's relay by her relay's invite, holding the invited key.
    let mut b = common::relay::env_without().await;
    let (bob_did, _) = b.client.create_user("bob", TEST_PASSPHRASE).await.expect("bob");
    b.client.relay_stand("bob", &invite).await.expect("bob stands at alice's relay by her invite");
    assert!(b.runtime.reachability().present_at_own_relay().is_some(), "bob presents the invited key there");
    // Bob holds that key as an invitee, and may hand it to nobody: an invite
    // minted on his device would carry no key the relay reads, so none is.
    let mut frames = b.client.device_invite_stream("bob", 60, None).await.expect("bob's daemon answers");
    match frames.recv().await {
        Some(UserResponse::Error { message }) => assert!(message.contains("holds no key there it may hand on"), "{message}"),
        other => panic!("an invitee minted an invite to a relay that reads a key: {other:?}"),
    }

    // Carol stands there by its address alone, and holds no key.
    let mut c = common::relay::env_on(&bx.relay_addr).await;
    c.client.create_user("carol", TEST_PASSPHRASE).await.expect("carol");
    assert_eq!(c.runtime.reachability().present_at_own_relay(), None, "carol holds no key at the relay");
    assert!(
        crate::vault::refused_by_the_rule(&crate::vault::a_push_at(&bx.relay_url, None).await),
        "the relay refuses a stranger"
    );

    let (code_tx, code_rx) = oneshot::channel();
    let (oa, (oc, ob)) = tokio::join!(issuer(&a.client, "alice", 90, true, code_tx), async {
        let code = code_rx.await.expect("alice produced a code");
        let started = std::time::Instant::now();
        let oc = joiner(&c.client, "carol", code.clone(), true).await;
        // Refused at the relay's door, not waited out as nobody reserved yet.
        assert!(started.elapsed() < std::time::Duration::from_secs(10), "carol's refusal was retried: {:?}", started.elapsed());
        let ob = joiner(&b.client, "bob", code, true).await;
        (oc, ob)
    });
    assert!(oc.failed.is_some() && oc.sas.is_none() && oc.paired.is_none(), "carol, holding no key, met alice");
    let said = oc.failed.as_deref().unwrap_or_default();
    assert!(
        said.contains("refused") && said.contains("presented no key there") && said.contains("`relay set <invite>`"),
        "carol is told what her device presented and which invite admits it there: {said}"
    );
    assert!(c.client.contact_list("carol").await.unwrap().is_empty(), "carol paired somebody");
    assert_eq!((oa.failed, ob.failed), (None, None), "alice and bob, each holding a key the relay reads");
    assert_eq!(oa.sas, ob.sas, "both screens showed the same six digits");
    assert_eq!(oa.paired.as_ref().map(|p| p.0.as_str()), Some(bob_did.as_str()), "alice holds bob, and not carol");
    assert_eq!(a.client.contact_list("alice").await.unwrap().len(), 1, "alice paired one person");
}

/// Someone who is not a contact cannot be messaged: there is no key, and no
/// mailbox to hand anything to (RFC-0022 — the ceremony is what makes a
/// recipient reachable, and nothing else does).
#[tokio::test]
async fn a_stranger_cannot_be_messaged() {
    let (_relay, mut a, _alice_did, _b, bob_did) = two_nodes().await;
    let err = a
        .client
        .message_send_delivery("alice", &bob_did, "hello", None)
        .await
        .expect_err("a stranger has no key here");
    assert!(
        err.to_string().contains("pair with them first"),
        "the refusal says what to do: {err}"
    );
}

/// The record fields a message record carries, as `messaging.rs` reads them.
fn crypto_fields(msg: &serde_json::Value) -> (String, String, String) {
    let get = |k: &str| {
        msg.get(k)
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("message record missing `{k}`: {msg}"))
            .to_string()
    };
    (get("body"), get("nonce"), get("ephemeral_pub"))
}

/// A wrong code reaches nobody: the joiner fails saying so, and the issuer
/// waits out its window with no contact written on either side.
#[tokio::test]
async fn a_wrong_code_reaches_nobody_and_writes_nothing() {
    let (_relay, mut a, _alice_did, mut b, _bob_did) = two_nodes().await;
    let (code_tx, code_rx) = oneshot::channel();
    let (oa, ob) = tokio::join!(issuer(&a.client, "alice", 30, true, code_tx), async {
        let code = code_rx.await.expect("alice produced a code");
        let mut words: Vec<&str> = code.split('-').collect();
        words[2] = "wrongword";
        joiner(&b.client, "bob", words.join("-"), true).await
    });
    assert!(ob.sas.is_none(), "no digits were shown for a wrong code");
    assert!(ob.failed.is_some(), "bob was told");
    assert!(oa.sas.is_none() && oa.paired.is_none(), "alice saw nobody");
    assert!(a.client.contact_list("alice").await.unwrap().is_empty());
    assert!(b.client.contact_list("bob").await.unwrap().is_empty());
}

/// One person saying the digits do not match ends it for both, with nothing
/// exchanged (CP3: no auto-accept, ever).
#[tokio::test]
async fn a_declined_comparison_pairs_nobody() {
    let (_relay, mut a, _alice_did, mut b, _bob_did) = two_nodes().await;
    let (code_tx, code_rx) = oneshot::channel();
    let (oa, ob) = tokio::join!(issuer(&a.client, "alice", 60, false, code_tx), async {
        let code = code_rx.await.expect("alice produced a code");
        joiner(&b.client, "bob", code, true).await
    });
    assert!(oa.failed.is_some() && ob.failed.is_some());
    assert!(oa.paired.is_none() && ob.paired.is_none());
    assert!(a.client.contact_list("alice").await.unwrap().is_empty());
    assert!(b.client.contact_list("bob").await.unwrap().is_empty());
}

/// `DEC-0056`: a message sent while every one of the recipient's devices is
/// dark lands at their vault, which holds the pair's doors and nothing that
/// opens, and is read when a device wakes. The sender is told one word.
#[tokio::test]
async fn a_message_waits_at_the_vault_while_every_device_sleeps() {
    // The device tops up its vault window and picks up what waited on a timer,
    // a minute by default. Set here, before bob's daemon starts, so the test
    // does not depend on the caller having exported it — it failed under a
    // plain `cargo test` and passed under `just test`, which is the worst way
    // for a test to be wrong. No lock: nothing else in the suite reads this,
    // and shortening a pickup cannot change another test's outcome.
    std::env::set_var("KOTTON_VAULT_PICKUP_SECS", "2");

    let (_relay, mut a, _alice_did, mut b, bob_did) = two_nodes().await;
    pair(&a, &b).await;
    mailbox_open(&mut a, "alice").await;
    mailbox_open(&mut b, "bob").await;
    let relay_url = a.runtime.reachability().nat().relay_url;

    // Bob's vault, on the same relay, told nothing about who Bob talks to — told
    // only where to stand, as its operator's desktop tells it. Bob's device
    // hands it the doors for alice, a week ahead.
    let (vault, _) = holding_a_vault(&mut b, "bob", &relay_url).await;
    let held = vault.vault.doors_held("bob").await;
    assert!(held >= 24 * 7, "a week of doors, not a day: {held}");

    // Every device of Bob's goes dark: his node leaves the relay, so nothing
    // of his answers there but the vault.
    b.client.node_rendezvous_set(None).await.expect("bob leaves the relay");
    tokio::time::sleep(std::time::Duration::from_secs(7)).await;

    let (_id, delivery) = a
        .client
        .message_send_delivery("alice", &bob_did, "the milk is in the fridge", None)
        .await
        .expect("send");
    assert_eq!(
        delivery,
        Some(Delivery::Sent),
        "one word: something of bob's holds it, and no device of his has signed for it — a \
         vault holds and cannot sign (TASK-a-message-stays-in-the-outbox-until-one-of-their-devices-signs-for-it)"
    );
    assert!(
        b.client.message_poll_inbox("bob").await.unwrap().is_empty(),
        "bob's device has not seen it — it was dark"
    );

    // A device wakes and takes what waited; it proves who wrote it against
    // alice's identity key, which the vault never held.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let inbox = loop {
        let inbox = b.client.message_poll_inbox("bob").await.expect("bob's inbox");
        if !inbox.is_empty() {
            break inbox;
        }
        assert!(std::time::Instant::now() < deadline, "bob's device never took the message from the vault");
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    };
    assert_eq!(inbox.len(), 1, "{inbox:?}");
    let (body, nonce, eph) = crypto_fields(&inbox[0]);
    let plaintext = b
        .client
        .message_decrypt_dm("bob", &body, &nonce, &eph)
        .await
        .expect("bob decrypts");
    assert_eq!(plaintext, "the milk is in the fridge");
    assert_eq!(
        inbox[0].get("from_did").and_then(|v| v.as_str()),
        Some(_alice_did.as_str()),
        "filed as from alice, because alice's signature said so"
    );

    // Acknowledged: the vault dropped it, and a second pass files nothing.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    assert_eq!(b.client.message_poll_inbox("bob").await.unwrap().len(), 1, "once, not again");

    // And the device that took it signed for it, back over alice's door, so
    // what alice sent reads `delivered` without her sending it again.
    delivered_reads_once(&mut a, &bob_did, "the vault's pickup was signed for").await;
}

/// Wait until `alice`'s one message to `peer` reads `delivered`, and then see
/// it read that way exactly once.
async fn delivered_reads_once(a: &mut TestEnv, peer: &str, what: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
    loop {
        let readings = a.client.message_deliveries("alice", peer).await.expect("readings");
        if readings.iter().any(|r| r.word == "delivered") {
            assert_eq!(readings.len(), 1, "one message, read once: {readings:?}");
            assert_eq!(readings[0].retry_at, None, "nothing is tried again once signed for");
            return;
        }
        assert!(std::time::Instant::now() < deadline, "{what}: never read delivered: {readings:?}");
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

/// The parent record's second test, and this unit's first: a message to a
/// person whose every device is off waits in the sender's outbox, is tried
/// again when a device of theirs is back, and is signed for once
/// (`TASK-a-message-stays-in-the-outbox-until-one-of-their-devices-signs-for-it`).
///
/// No vault anywhere: nothing of bob's holds the message while he is away, so
/// the only thing that can bring it to him is alice's outbox trying again.
#[tokio::test]
async fn a_message_to_someone_whose_every_device_is_off_is_delivered_and_signed_for_once_when_one_returns() {
    // The outbox tries again after thirty seconds, doubling; set flat and short
    // here, before either daemon starts, so the test waits on the behaviour and
    // not on the clock. No lock: a retry sends the same sealed bytes as the
    // first try, and a copy that arrives twice is kept once, so a shorter wait
    // cannot change what another test in the suite sees.
    std::env::set_var("KOTTON_OUTBOX_RETRY_SECS", "1");

    let (_relay, mut a, _alice_did, mut b, bob_did) = two_nodes().await;
    pair(&a, &b).await;
    mailbox_open(&mut b, "bob").await;
    let relay_url = b.runtime.reachability().nat().relay_url;

    // Every device of bob's goes dark: his node leaves the relay.
    b.client.node_rendezvous_set(None).await.expect("bob leaves the relay");
    tokio::time::sleep(std::time::Duration::from_secs(7)).await;

    let (_id, delivery) = a
        .client
        .message_send_delivery("alice", &bob_did, "the milk is in the fridge", None)
        .await
        .expect("send");
    assert!(
        matches!(delivery, Some(Delivery::Unreachable { .. })),
        "nothing of bob's answered: {delivery:?}"
    );
    let waiting = a.client.message_deliveries("alice", &bob_did).await.expect("readings");
    assert_eq!(waiting.len(), 1, "{waiting:?}");
    assert_eq!(waiting[0].word, "waiting at home");
    assert!(waiting[0].retry_at.is_some(), "the wait says when it is tried next");

    // Still away for a few of alice's tries: still waiting, nothing arrived.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    assert!(b.client.message_poll_inbox("bob").await.unwrap().is_empty(), "bob was away");
    assert_eq!(
        a.client.message_deliveries("alice", &bob_did).await.unwrap()[0].word,
        "waiting at home"
    );

    // A device of bob's comes back, with nobody resending anything.
    b.client.node_rendezvous_set(Some(&relay_url)).await.expect("bob returns");
    mailbox_open(&mut b, "bob").await;
    delivered_reads_once(&mut a, &bob_did, "alice's outbox never reached bob once he was back").await;

    // Delivered and signed for exactly once: bob holds one copy, and however
    // long alice's keeper keeps passing, nothing more is sent.
    let inbox = b.client.message_poll_inbox("bob").await.expect("bob's inbox");
    assert_eq!(inbox.len(), 1, "one copy: {inbox:?}");
    let (body, nonce, eph) = crypto_fields(&inbox[0]);
    assert_eq!(
        b.client.message_decrypt_dm("bob", &body, &nonce, &eph).await.expect("bob decrypts"),
        "the milk is in the fridge"
    );
    tokio::time::sleep(std::time::Duration::from_secs(4)).await;
    assert_eq!(b.client.message_poll_inbox("bob").await.unwrap().len(), 1, "once, not again");
    delivered_reads_once(&mut a, &bob_did, "still").await;
}

/// Clause (3) of the outbox's record: **the sender's own vault carries the
/// retrying while the sending device is off**
/// (`TASK-a-message-stays-in-the-outbox-until-one-of-their-devices-signs-for-it`;
/// RFC-0083 R1, the relay never keeps, and R2, the vault is the person's node).
///
/// Alice rents a vault; Bob has none. Alice sends while every device of Bob's
/// is off: one try, *waiting at home*, and her pickup pass hands her outbox to
/// her vault. Then Alice's device goes off — it leaves the relay and is taken
/// to the state a restart leaves it in, where its outbox cannot even be read,
/// so nothing of hers but the vault can try the message again. Bob comes back.
/// The vault hands the message to his door, his device files it and signs for
/// it sealed to Alice, and the vault keeps that envelope and stops carrying.
/// Alice comes back, her pickup takes the signature, and her message reads
/// *delivered* once, with Bob holding one copy.
#[tokio::test]
async fn a_message_her_vault_carries_while_her_device_is_off_is_delivered_and_signed_for_once() {
    // Set before either daemon or the vault starts, as the tests above do: a
    // two-second pickup and a one-second carry, so the test waits on the
    // behaviour and not on the clock. No lock: a shorter pickup or carry sends
    // the same bytes sooner, and a copy that arrives twice is kept once.
    std::env::set_var("KOTTON_VAULT_PICKUP_SECS", "2");
    std::env::set_var("KOTTON_VAULT_CARRY_SECS", "1");
    const PASSPHRASE: &str = "abandon-ability-able-about-above";

    let (_relay, mut a, _alice_did, mut b, bob_did) = two_nodes().await;
    // A credential Alice can come back with once her device has been off.
    a.client
        .set_lock_policy("alice", kotton::LockMode::Passphrase, 0, Some(PASSPHRASE))
        .await
        .expect("alice sets a daily passphrase");
    pair(&a, &b).await;
    mailbox_open(&mut a, "alice").await;
    mailbox_open(&mut b, "bob").await;
    let relay_url = a.runtime.reachability().nat().relay_url;

    // Alice's vault, on the same relay, told to stand there.
    let (vault, _) = holding_a_vault(&mut a, "alice", &relay_url).await;

    // Every device of Bob's is off.
    b.client.node_rendezvous_set(None).await.expect("bob leaves the relay");
    tokio::time::sleep(std::time::Duration::from_secs(7)).await;

    // One try, and it fails.
    let (_id, delivery) = a
        .client
        .message_send_delivery("alice", &bob_did, "the milk is in the fridge", None)
        .await
        .expect("send");
    assert!(
        matches!(delivery, Some(Delivery::Unreachable { .. })),
        "nothing of bob's answered: {delivery:?}"
    );
    // Alice's pickup pass hands her outbox to her vault.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while vault.vault.carried("alice").await != 1 {
        assert!(std::time::Instant::now() < deadline, "alice's vault was never handed her outbox");
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }

    // Alice's device goes off: it leaves the relay, and is taken to where a
    // restart leaves it — its outbox unreadable, so it can try nothing.
    a.client.node_rendezvous_set(None).await.expect("alice leaves the relay");
    a.lock_as_a_restart_would("alice").await;
    assert!(
        a.client.message_deliveries("alice", &bob_did).await.is_err(),
        "alice's outbox cannot be read, so her device retries nothing"
    );

    // A device of Bob's comes back, and nothing of Alice's is awake.
    b.client.node_rendezvous_set(Some(&relay_url)).await.expect("bob returns");
    mailbox_open(&mut b, "bob").await;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
    let inbox = loop {
        let inbox = b.client.message_poll_inbox("bob").await.expect("bob's inbox");
        if !inbox.is_empty() {
            break inbox;
        }
        assert!(std::time::Instant::now() < deadline, "alice's vault never carried the message to bob");
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    };
    assert_eq!(inbox.len(), 1, "{inbox:?}");
    let (body, nonce, eph) = crypto_fields(&inbox[0]);
    assert_eq!(
        b.client.message_decrypt_dm("bob", &body, &nonce, &eph).await.expect("bob decrypts"),
        "the milk is in the fridge"
    );
    // Signed for: the vault stops carrying it and holds the signature, sealed
    // to Alice, for her pickup.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while vault.vault.carried("alice").await != 0 {
        assert!(std::time::Instant::now() < deadline, "the vault kept carrying a message bob signed for");
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    // The signature waits there — and it may not be alone: Bob's return to the
    // relay changes his reach, so his note is signed again and handed to
    // Alice's doors, which her vault holds while she is away. That is right,
    // and it made `== 1` a race between his note and this read; it lost
    // deterministically once the suite's relays kept keys
    // (`TASK-the-desktop-tells-the-vault-which-relays-to-stand-at`,
    // reproduced on main by giving the relay a state directory). *Once* is held
    // below, where it is: one copy at Bob, one *delivered* at Alice, and nothing
    // left at the vault after her pickup.
    assert!(vault.vault.deliveries_held("alice").await >= 1, "the signature waits at alice's vault");

    // Alice comes back; her pickup takes the signature.
    assert_eq!(
        a.client.unlock_with_pin("alice", PASSPHRASE).await.expect("unlock"),
        kotton::PinUnlock::Unlocked
    );
    a.client.node_rendezvous_set(Some(&relay_url)).await.expect("alice returns");
    delivered_reads_once(&mut a, &bob_did, "alice's pickup never took the signature her vault held").await;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while vault.vault.deliveries_held("alice").await != 0 {
        assert!(std::time::Instant::now() < deadline, "alice's pickup left the signature at the vault");
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }

    // Once, however long either side keeps passing.
    tokio::time::sleep(std::time::Duration::from_secs(4)).await;
    assert_eq!(b.client.message_poll_inbox("bob").await.unwrap().len(), 1, "one copy, once");
    assert_eq!(vault.vault.carried("alice").await, 0, "nothing is carried once signed for");
    delivered_reads_once(&mut a, &bob_did, "still").await;
}

/// The parent record's third test, and the multi-path unit's
/// (`TASK-a-message-reaches-them-by-every-path-at-once-and-they-keep-one-copy`):
/// a message is dialled on two paths at once, both carry it, and the
/// recipient keeps one copy.
///
/// Alice and Bob pair at one relay. Bob moves to a second and, for its window,
/// still answers at the first (RFC-0083 R5), and his daemon signs a note
/// listing both and sends it to Alice on its own. Alice's paths to Bob are
/// then the second relay (first in his note) and the first (in his note, and
/// her own) — each once. She sends three messages. Both relays bridge a
/// circuit, each message reaches Bob by more than one way, and Bob holds each
/// once; Alice's readings are three *delivered*, and none of what she reads
/// names either relay.
#[tokio::test]
async fn a_message_dialled_on_two_relays_at_once_is_kept_once() {
    use kotton_peer::membership::Membership as _;

    let (_met_at, mut a, _alice_did, mut b, bob_did) = two_nodes().await;
    let met_at = b.runtime.reachability().nat().relay_url;
    let (_second, second_addr) = common::relay::spawn().await;
    let second = format!("http://{second_addr}");
    let (oa, ob) = pair(&a, &b).await;
    assert_eq!((oa.failed, ob.failed), (None, None), "paired");
    mailbox_open(&mut a, "alice").await;
    mailbox_open(&mut b, "bob").await;

    b.client.node_rendezvous_set(Some(&second)).await.expect("bob moves relay");
    let now = || {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
    };
    assert_eq!(
        b.runtime.reachability().nat().forwarding_relay(now() as i64),
        Some(met_at.as_str()),
        "bob still answers where they met, for the window"
    );

    // Alice's card comes to hold Bob's new note, listing both relays, with
    // nobody but Bob's daemon doing anything.
    let alices = a.users.get("alice").expect("alice is resident");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
    loop {
        let card = alices.read_member(&bob_did).await.expect("alice's card").expect("bob is a contact");
        if card.reach_relays(now()) == vec![second.as_str(), met_at.as_str()] {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "alice's card never held bob's note naming both relays: {:?}",
            card.reach_relays(now())
        );
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }
    // And Bob holds his doors at the second relay, as he does at the first.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while common::relay::reservations(&second_addr).await < 2 {
        assert!(std::time::Instant::now() < deadline, "bob never reserved his doors at the second relay");
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    let met_at_addr = met_at.trim_start_matches("http://").to_string();
    let before = (
        common::relay::circuits_bridged(&met_at_addr).await,
        common::relay::circuits_bridged(&second_addr).await,
    );
    let texts = ["one", "two", "three"];
    for text in texts {
        let (_id, delivery) = a
            .client
            .message_send_delivery("alice", &bob_did, text, None)
            .await
            .expect("send");
        assert_eq!(delivery, Some(Delivery::Delivered), "{text}: a device of bob's signed for it");
        let said = serde_json::to_string(&delivery).unwrap();
        assert!(!said.contains(&second_addr) && !said.contains(&met_at_addr), "{said}");
    }
    let after = (
        common::relay::circuits_bridged(&met_at_addr).await,
        common::relay::circuits_bridged(&second_addr).await,
    );
    assert!(after.0 > before.0, "the relay they met at carried a dial: {before:?} -> {after:?}");
    assert!(after.1 > before.1, "the relay bob moved to carried a dial: {before:?} -> {after:?}");

    // Bob keeps each once, whichever way it came.
    let inbox = b.client.message_poll_inbox("bob").await.expect("bob's inbox");
    assert_eq!(inbox.len(), texts.len(), "one copy of each: {inbox:?}");
    let mut read: Vec<String> = Vec::new();
    for msg in &inbox {
        let (body, nonce, eph) = crypto_fields(msg);
        read.push(b.client.message_decrypt_dm("bob", &body, &nonce, &eph).await.expect("bob decrypts"));
    }
    read.sort();
    let mut want: Vec<String> = texts.iter().map(|t| t.to_string()).collect();
    want.sort();
    assert_eq!(read, want);

    // Alice reads three words and no path.
    let readings = a.client.message_deliveries("alice", &bob_did).await.expect("readings");
    assert_eq!(readings.len(), texts.len(), "{readings:?}");
    assert!(readings.iter().all(|r| r.word == "delivered" && r.retry_at.is_none()), "{readings:?}");
    let said = serde_json::to_string(&readings).unwrap();
    assert!(!said.contains(&second_addr) && !said.contains(&met_at_addr), "{said}");
}

/// `user` on `env` holds a vault standing at `relay_url`, enrolled from their
/// device as blind storage, and handed their doors — every step
/// a test of something a vault holds takes before the devices go dark. Returns
/// the vault and its DID, once the vault holds a door.
///
/// Used by `a_message_waits_at_the_vault_while_every_device_sleeps`,
/// `a_message_her_vault_carries_while_her_device_is_off_is_delivered_and_signed_for_once`,
/// `share::a_share_waits_at_the_vault_while_every_device_sleeps_and_is_filed_on_the_next_pickup`
/// and `household_channel::a_member_admitted_while_every_device_is_off_reads_the_channel_when_one_wakes`.
pub(crate) async fn holding_a_vault(env: &mut TestEnv, user: &str, relay_url: &str) -> (TestVault, String) {
    let vault = spawn_vault_for_test(&format!("{user}'s vault")).await;
    common::relay::stand_at(&vault.vault, relay_url.trim_start_matches("http://")).await;
    let mut client_v = common::connect_when_ready(&vault.ipc, "vault door").await;
    let (vault_did, vault_pubkey_hex) = client_v.get_node_identity().await.expect("vault identity");
    // `enroll_streamed` takes the issuer's client by value; swap a bare
    // connection in so the session-holding client can be lent and returned.
    let placeholder = common::connect_when_ready(&env.endpoint, "placeholder").await;
    let own_client = std::mem::replace(&mut env.client, placeholder);
    let (client, _client_v, node) = common::enroll_streamed(
        own_client,
        client_v,
        user,
        "vault",
        common::free_port(),
        Posture::BlindStorage,
    )
    .await;
    env.client = client;
    assert_eq!(node.id, "vault");
    let op_addr: std::net::SocketAddr = format!("127.0.0.1:{}", vault.op_port).parse().unwrap();
    env.client
        .peer_add(user, "vault", &vault_did, &vault_pubkey_hex, op_addr)
        .await
        .expect("the device knows where its vault is");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while vault.vault.doors_held(user).await == 0 {
        assert!(std::time::Instant::now() < deadline, "the vault was never handed {user}'s doors");
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    (vault, vault_did)
}

/// A vault for the test above: its own base, door and peer port.
pub(crate) struct TestVault {
    _base: tempfile::TempDir,
    pub(crate) ipc: common::Door,
    pub(crate) op_port: u16,
    pub(crate) vault: std::sync::Arc<kvaultd::Vault>,
    _task: tokio::task::JoinHandle<std::io::Result<()>>,
}

pub(crate) async fn spawn_vault_for_test(label: &str) -> TestVault {
    use kotton_sys::secret::SecretsStore;
    let base = tempfile::tempdir().expect("vault base");
    let ipc = common::unique_ipc();
    let secrets: std::sync::Arc<dyn SecretsStore + Send + Sync> =
        std::sync::Arc::new(kotton_secret::MemorySecrets::new());
    common::create_vault(base.path(), secrets.as_ref()).await;
    let vault = std::sync::Arc::new(
        kvaultd::Vault::new_with_shelves(base.path().to_owned(), ipc.clone(), secrets, kvaultd::shelf::local())
            .await
            .expect("vault"),
    );
    let op_port = common::free_port();
    vault
        .start_peer_listener_background(op_port)
        .await
        .expect("vault peer listener");
    let task = tokio::spawn(std::sync::Arc::clone(&vault).run());
    common::wait_for_daemon(&ipc, label).await;
    TestVault {
        _base: base,
        ipc,
        op_port,
        vault,
        _task: task,
    }
}

/// Three people, three daemons, one channel message — `DEC-0055`'s sentence
/// where a single daemon cannot fake it.
///
/// **Why three daemons and not three identities.** Every channel test before this
/// one had all its members on one machine, where a member's copy is a second row
/// written by the same process. That shape cannot tell a working fan-out from an
/// absent one, and it hid two things at once: a member on another daemon was
/// never handed the messages, and — found while fixing that — was never handed
/// the **key-grant** either, so a channel spanning two people who had only paired
/// could be created and could never be opened by anyone but its creator.
///
/// Both halves travel the contact door the pairing ceremony opened. That is the
/// whole of `DEC-0055`'s *a group message is the same verb to each current
/// member*: there is no group transport, because a channel has no node.
#[tokio::test]
async fn three_people_on_three_daemons_read_one_channel_message() {
    const CHANNEL: &str = "did:key:zTheFerryThread";

    let (relay, relay_addr) = common::relay::spawn().await;
    let (mut a, mut b, mut c) = (
        common::relay::env_on(&relay_addr).await,
        common::relay::env_on(&relay_addr).await,
        common::relay::env_on(&relay_addr).await,
    );
    let _relay = relay;
    a.client.create_user("alice", TEST_PASSPHRASE).await.expect("alice");
    let (bob_did, _) = b.client.create_user("bob", TEST_PASSPHRASE).await.expect("bob");
    let (carol_did, _) = c.client.create_user("carol", TEST_PASSPHRASE).await.expect("carol");

    // Alice knows both of them; they do not know each other. Only the sender
    // needs a door to each member, which is what makes the fan-out possible
    // between people who have never met.
    let (oa, ob) = pair_as(&a, "alice", &b, "bob").await;
    assert!(oa.paired.is_some() && ob.paired.is_some(), "alice and bob did not pair: {:?} / {:?}", oa.failed, ob.failed);
    let (oa, oc) = pair_as(&a, "alice", &c, "carol").await;
    assert!(oa.paired.is_some() && oc.paired.is_some(), "alice and carol did not pair: {:?} / {:?}", oa.failed, oc.failed);

    // Their mailboxes have to be open before anything is handed over, or the
    // assertion would be on a race rather than on the behaviour.
    mailbox_open(&mut b, "bob").await;
    mailbox_open(&mut c, "carol").await;

    a.client.message_channel_create("alice", CHANNEL).await.expect("create the channel");
    a.client
        .message_channel_grant_key("alice", CHANNEL, &bob_did, false)
        .await
        .expect("grant the channel key to bob");
    a.client
        .message_channel_grant_key("alice", CHANNEL, &carol_did, false)
        .await
        .expect("grant the channel key to carol");

    let (_id, fanout) = a
        .client
        .message_channel_send_with_fanout("alice", CHANNEL, "the ferry leaves at 6:40, not 7")
        .await
        .expect("alice posts to the channel");

    // One answer per member, and each is its own. Nothing about this send is a
    // single verdict: the sender's copy is written before any of it.
    assert_eq!(fanout.len(), 2, "one entry per current member but the sender: {fanout:?}");
    for member in &fanout {
        assert!(
            matches!(member.delivery, Delivery::Delivered | Delivery::AlreadyHeld),
            "{}'s copy was not handed over: {:?}",
            member.member_did,
            member.delivery
        );
    }
    let named: Vec<&str> = fanout.iter().map(|m| m.member_did.as_str()).collect();
    assert!(named.contains(&bob_did.as_str()) && named.contains(&carol_did.as_str()), "{named:?}");

    // And the point of all of it: each of them reads the same sentence out of
    // their own store, with their own key-grant.
    for (env, user) in [(&mut b, "bob"), (&mut c, "carol")] {
        let history = env
            .client
            .message_channel_history(user, CHANNEL, None, 50)
            .await
            .unwrap_or_else(|e| panic!("{user} reads the channel: {e}"));
        let msg = history
            .first()
            .unwrap_or_else(|| panic!("{user} was handed no copy of the channel message"));
        let plaintext = env
            .client
            .message_decrypt_channel(
                user,
                CHANNEL,
                msg["body"].as_str().expect("body"),
                msg["nonce"].as_str().expect("nonce"),
            )
            .await
            .unwrap_or_else(|e| panic!("{user} opens it with the granted key: {e}"));
        assert_eq!(plaintext, "the ferry leaves at 6:40, not 7", "{user} read something else");
    }
}

/// **Two friends in one room reach each other without any relay**
/// (`TASK-a-contacts-message-can-reach-their-device-over-the-local-network-while-its-door-is-open`,
/// DEC-0082 step 4).
///
/// Alice and Bob pair, then leave their relay and the relay is gone: neither has a
/// relay configured, and the one Bob's note still names answers nobody. With their
/// doors closed Alice's message has nowhere to go and the room hears nothing. Each
/// opens their door for ten minutes; one beacon each goes into the room, named by a
/// nonce; Alice's daemon hears Bob's, knocks with the knock their pair derives, and
/// hands the message to Bob's contact door there — and Bob's device signs for it.
///
/// The room is one machine's local network (`kotton_peer::local_network::Room`),
/// because two daemons in one process share one, and the suite promises to open no
/// multicast socket. Everything behind the beacon — the knock front, the pair door's
/// one-key handshake, the one verb, the signature — is the daemons' own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_message_reaches_a_contact_across_a_room_with_no_relay() {
    let (relay, mut a, _alice_did, mut b, bob_did) = two_nodes().await;
    let (oa, ob) = pair(&a, &b).await;
    assert_eq!((oa.failed, ob.failed), (None, None), "paired");

    a.client.node_rendezvous_set(None).await.expect("alice leaves the relay");
    b.client.node_rendezvous_set(None).await.expect("bob leaves the relay");
    drop(relay);
    assert!(a.runtime.reachability().nat().relay_url.is_empty(), "alice has no relay");
    assert!(b.runtime.reachability().nat().relay_url.is_empty(), "bob has no relay");

    let room = kotton_peer::local_network::Room::new();
    a.runtime.use_local_network(std::sync::Arc::new(room.clone()));
    b.runtime.use_local_network(std::sync::Arc::new(room.clone()));

    // Doors closed: nothing is announced and nothing of Bob's answers.
    let (_id, closed) = a
        .client
        .message_send_delivery("alice", &bob_did, "anyone there?", None)
        .await
        .expect("send");
    assert_ne!(closed, Some(Delivery::Delivered), "delivered with every door closed");
    assert!(room.heard().is_empty(), "a closed door announced: {:?}", room.heard());

    for env in [&mut a, &mut b] {
        let door = env.client.local_door(Some("10m".to_owned())).await.expect("open the door");
        assert_eq!(door.answer, "10m");
    }

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
    let mut tries = 0;
    loop {
        tries += 1;
        let (_id, delivery) = a
            .client
            .message_send_delivery("alice", &bob_did, "across the room", None)
            .await
            .expect("send");
        if delivery == Some(Delivery::Delivered) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "alice's message never reached bob across the room after {tries} tries: {delivery:?}; heard {:?}",
            room.heard()
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    assert_eq!(room.heard().len(), 2, "one beacon per open door: {:?}", room.heard());

    // Bob holds it, in his own store, opened with his own key.
    let inbox = b.client.message_poll_inbox("bob").await.expect("bob's inbox");
    let mut read = Vec::new();
    for msg in &inbox {
        let (body, nonce, eph) = crypto_fields(msg);
        read.push(b.client.message_decrypt_dm("bob", &body, &nonce, &eph).await.expect("bob decrypts"));
    }
    assert!(read.iter().any(|t| t == "across the room"), "bob holds the message: {read:?}");

    // Bob closes his door: the room no longer hears it, and nothing of his answers.
    b.client.local_door(Some("closed".to_owned())).await.expect("close bob's door");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while room.heard().len() > 1 {
        assert!(std::time::Instant::now() < deadline, "bob's beacon outlived his door");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let (_id, after) = a
        .client
        .message_send_delivery("alice", &bob_did, "still there?", None)
        .await
        .expect("send");
    assert_ne!(after, Some(Delivery::Delivered), "a closed door took a message");
}

/// One side's conversation with `peer`, oldest first, as the surfaces read it:
/// what came in from the inbox and what went out from the store, merged on the
/// one key both halves share — where this person's node filed each message
/// (`TASK-a-conversation-is-ordered-by-a-clock-it-does-not-hold`). Each entry is
/// `(text, filed_at, sent_at)`.
async fn conversation(env: &mut TestEnv, user: &str, peer: &str) -> Vec<(String, i64, u64)> {
    let inbox = env.client.message_poll_inbox(user).await.expect("inbox");
    let sent = env
        .client
        .record_query(
            user,
            "sh.kotton.message.v1",
            vec![("to_did".to_string(), serde_json::json!(peer))],
            None,
            None,
        )
        .await
        .expect("what was sent");
    let mut out = Vec::new();
    for (m, filed_key) in inbox
        .iter()
        .filter(|m| m["from_did"] == peer)
        .map(|m| (m, "filed_at"))
        .chain(sent.iter().map(|m| (m, "_filed_at")))
    {
        let (body, nonce, eph) = crypto_fields(m);
        let text = env
            .client
            .message_decrypt_dm(user, &body, &nonce, &eph)
            .await
            .unwrap_or_else(|e| panic!("{user} opens a message in the thread: {e}"));
        let filed_at = m[filed_key]
            .as_i64()
            .unwrap_or_else(|| panic!("every message carries where it was filed: {m}"));
        out.push((text, filed_at, m["sent_at"].as_u64().expect("sent_at")));
    }
    out.sort_by_key(|(_, filed_at, _)| *filed_at);
    out
}

/// **A reply sent with no wait reads after the message it answers, on both
/// sides, every time** — the Done-when of
/// `TASK-a-conversation-is-ordered-by-a-clock-it-does-not-hold`.
///
/// Ten exchanges back to back. Each message's own `sent_at` is whole seconds on
/// the clock of the machine that sent it, so a message and its reply inside one
/// second tie, and across two machines a reply can even claim to be earlier.
/// Neither person's conversation is ordered by that claim any more: each is
/// ordered by where their own node filed the message, which is strictly
/// increasing in the order that node filed it. This repeats the exchange so that a
/// coin flip would have shown.
#[tokio::test]
async fn a_reply_sent_with_no_wait_reads_after_the_message_it_answers() {
    let (_relay, mut a, alice_did, mut b, bob_did) = two_nodes().await;
    pair(&a, &b).await;
    mailbox_open(&mut a, "alice").await;
    mailbox_open(&mut b, "bob").await;

    const ROUNDS: usize = 10;
    let mut said = Vec::new();
    for i in 0..ROUNDS {
        let ask = format!("question {i}");
        let (_, delivery) =
            a.client.message_send_delivery("alice", &bob_did, &ask, None).await.expect("alice asks");
        assert_eq!(delivery, Some(Delivery::Delivered), "bob's node took question {i}");
        // No wait: the reply leaves the moment the question has landed.
        let answer = format!("answer {i}");
        let (_, delivery) =
            b.client.message_send_delivery("bob", &alice_did, &answer, None).await.expect("bob answers");
        assert_eq!(delivery, Some(Delivery::Delivered), "alice's node took answer {i}");
        said.push(ask);
        said.push(answer);
    }

    for (env, user, peer) in [(&mut a, "alice", &bob_did), (&mut b, "bob", &alice_did)] {
        let thread = conversation(env, user, peer).await;
        let texts: Vec<&str> = thread.iter().map(|(t, _, _)| t.as_str()).collect();
        assert_eq!(
            texts,
            said.iter().map(String::as_str).collect::<Vec<_>>(),
            "{user}'s conversation reads in the order it happened"
        );
        for pair in thread.windows(2) {
            assert!(pair[0].1 < pair[1].1, "{user}: two messages share a filing position: {pair:?}");
        }
    }

    // Not asserted: how many questions shared a second with their answer. That
    // is a fact about this machine's speed, and a test that fails on a slow host
    // is the flake this record was opened for. What shows the ordering above is
    // a measurement rather than luck is that it fails with the merge key set
    // back to `sent_at` — recorded as a mutation in the record's gate table.
}
