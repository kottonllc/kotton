// SPDX-License-Identifier: AGPL-3.0-or-later
//! A file shared with a contact is a copy of theirs under *Shared with you*
//! (`TASK-a-file-shared-with-a-contact-is-a-copy-of-theirs-under-shared-with-you`,
//! RFC-0090's unit 2).
//!
//! Two people on two daemons, paired on a spoken code through a relay, as
//! `contact_pairing::` pairs them. Alice shares a photo through the verb the
//! shell's share sheet reaches — the occupant host's `message_share`, which is
//! `messages.share` — and nothing else: no transport is driven by hand. It is a
//! direct message whose body is the file, so it travels the message's own path:
//! handed over Bob's contact door while a device of his is awake, held at his
//! vault while none is, and filed by his node under
//! `Shared with you/<the name his card shows for her>/<name>` either way.
//!
//! Each test reads the copy back byte for byte on Bob's side and the original
//! on Alice's, and holds the one property a share must not lose on the wire:
//! nothing Bob holds names where Alice keeps the file.
//!
//! A file shared with a **group** is the same filing on every current member's
//! node (RFC-0090's unit 3): one channel ciphertext under the newest epoch,
//! handed to each, filed under *Shared with you* by each — and nothing for a
//! member removed before it (the last test of this file).
//!
//! A file above the inline cap streams (RFC-0090's unit 4): its manifest goes
//! first and its bytes follow as sealed ranges over the same door, and Bob's
//! node files it only once they are whole and hash to its digest. Two
//! tests share twenty MiB — twice the frame cap — once whole and once with the
//! stream cut short; and a third shares six MiB from a device that then goes
//! off, so only the sender's vault carries its ranges (unit 4's clause 5).

use crate::common::{self, TestEnv};
use crate::contact_pairing::{holding_a_vault, mailbox_open, pair, spawn_vault_for_test, two_nodes};
use kotton_app::daemon::apps::OccupantHost as _;
use kotton_schemas::membership::Posture;

/// Bytes that are not text, so a transfer that re-encoded them anywhere fails
/// the comparison rather than passing it.
fn a_photo(seed: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

/// Wait until `path` reads back on `env` as `user`, and return it.
async fn filed(env: &mut TestEnv, user: &str, path: &str, what: &str) -> Vec<u8> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
    loop {
        if let Ok(bytes) = env.client.read_file(user, path).await {
            return bytes;
        }
        assert!(std::time::Instant::now() < deadline, "{what}: {path} was never filed");
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

/// Everything under *Shared with you* in `user`'s tree, as paths from its root.
async fn shared_with(env: &mut TestEnv, user: &str) -> Vec<String> {
    let mut all: Vec<String> = env
        .client
        .list_files(user, "Shared with you/")
        .await
        .expect("the tree lists")
        .into_iter()
        .map(|p| p.trim_start_matches('/').to_owned())
        .collect();
    all.sort();
    all
}

/// **Clause (4), the door.** Alice keeps a photo in her own tree and shares it
/// with Bob through `messages.share`. A device of Bob's is awake, so it is
/// handed over his contact door and signed for: Alice reads *delivered*. Bob's
/// node files it under *Shared with you/alice* — the name his card shows for
/// her — byte-identical, and nothing else lands there; the message stays in
/// his conversation with her, opening to the file's name, and the record he
/// holds names nothing of where Alice keeps it. Alice's original is unchanged,
/// and nothing was copied on her side.
#[tokio::test]
async fn a_file_shared_with_a_contact_lands_under_shared_with_you_byte_identical() {
    let (_relay, mut a, alice_did, mut b, bob_did) = two_nodes().await;
    pair(&a, &b).await;
    mailbox_open(&mut a, "alice").await;
    mailbox_open(&mut b, "bob").await;

    let photo = a_photo(7, 180_000);
    a.client.write_file("alice", "Photos/beach.jpg", &photo).await.expect("alice's photo");

    // The sheet lists Alice's contacts — Bob, by his card's name, and nobody
    // else on her roster.
    let contacts = a.daemon.occupant_host().list_contacts().await.expect("alice's contacts");
    assert_eq!(contacts.len(), 1, "{contacts:?}");
    assert_eq!((contacts[0].did.as_str(), contacts[0].label.as_deref()), (bob_did.as_str(), Some("Bob from the bakery")));

    let (id, word) = a
        .daemon
        .occupant_host()
        .message_share(&bob_did, "beach.jpg", &photo, Some("/Photos/beach.jpg"))
        .await
        .expect("the share");
    assert!(!id.is_empty());
    assert_eq!(word.as_deref(), Some("delivered"), "a device of Bob's signed for it at his door");

    let copy = filed(&mut b, "bob", "Shared with you/alice/beach.jpg", "bob's node").await;
    assert_eq!(copy, photo, "the copy is not the photo");
    assert_eq!(shared_with(&mut b, "bob").await, vec!["Shared with you/alice/beach.jpg".to_owned()]);
    assert!(
        b.client.read_file("bob", "Photos/beach.jpg").await.is_err(),
        "the share landed somewhere beside Shared with you"
    );

    // Kept in the conversation with Alice: a share, opening to its name, and
    // nothing in what Bob holds says where Alice keeps it.
    let inbox = b.client.message_poll_inbox("bob").await.expect("bob's inbox");
    assert_eq!(inbox.len(), 1, "{inbox:?}");
    assert_eq!(inbox[0]["type"], "share");
    assert_eq!(inbox[0]["from_did"], alice_did.as_str());
    let field = |k: &str| inbox[0][k].as_str().unwrap().to_owned();
    let opened = b
        .client
        .message_decrypt_dm("bob", &field("body"), &field("nonce"), &field("ephemeral_pub"))
        .await
        .expect("bob opens it");
    assert_eq!(opened, "beach.jpg");
    let held = serde_json::to_string(&inbox[0]).unwrap();
    assert!(!held.contains("Photos") && !held.contains("origin"), "{held}");

    // Alice's original is unchanged, and she holds no second copy.
    assert_eq!(a.client.read_file("alice", "Photos/beach.jpg").await.expect("the original"), photo);
    assert!(shared_with(&mut a, "alice").await.is_empty(), "the sender's side gained a copy");
    let readings = a.client.message_deliveries("alice", &bob_did).await.expect("readings");
    assert_eq!(readings.len(), 1, "{readings:?}");
    assert_eq!((readings[0].message_id.as_str(), readings[0].word.as_str()), (id.as_str(), "delivered"));
}

/// **Clause (4), the vault.** Every device of Bob's is off the relay, so
/// nothing of his answers at his door but his vault; Alice shares two photos
/// with him and reads *sent* for each: his vault holds them, as it holds a
/// message, and no device of his has signed. His device takes both from the
/// vault on its next pickup — the only way anything reaches it — and files
/// each under *Shared with you/alice*, the second suffixed, both
/// byte-identical, and signs for them back over Alice's door. The two are
/// four MiB each, so two of them do not fit one pickup's frame; whether they
/// wait together or one at a time is the pickup timer's, and the vault's own
/// test (`kvaultd`'s `a_pickup_answer_fits_one_frame_and_nothing_held_is_stuck_behind_it`)
/// holds the case where they do.
#[tokio::test]
async fn a_share_waits_at_the_vault_while_every_device_sleeps_and_is_filed_on_the_next_pickup() {
    // A pickup every two seconds rather than every minute, set before Bob's
    // daemon starts, as `contact_pairing::a_message_waits_at_the_vault_while_every_device_sleeps`
    // sets it.
    std::env::set_var("KOTTON_VAULT_PICKUP_SECS", "2");

    let (_relay, mut a, _alice_did, mut b, bob_did) = two_nodes().await;
    pair(&a, &b).await;
    mailbox_open(&mut a, "alice").await;
    mailbox_open(&mut b, "bob").await;
    let relay_url = a.runtime.reachability().nat().relay_url;

    let (_vault, vault_did) = holding_a_vault(&mut b, "bob", &relay_url).await;

    // Bob's own share sheet would not offer his vault as a person: it is a
    // device row on his roster, and his contacts are Alice alone.
    let his = b.daemon.occupant_host().list_contacts().await.expect("bob's contacts");
    assert_eq!(his.len(), 1, "{his:?}");
    assert_ne!(his[0].did, vault_did, "a vault was listed as a contact");

    // Every device of Bob's goes dark.
    b.client.node_rendezvous_set(None).await.expect("bob leaves the relay");
    tokio::time::sleep(std::time::Duration::from_secs(7)).await;

    let (beach, dunes) = (a_photo(3, 4 * 1024 * 1024), a_photo(5, 4 * 1024 * 1024));
    for (name, bytes) in [("beach.jpg", &beach), ("beach.jpg", &dunes)] {
        let (_id, word) = a
            .daemon
            .occupant_host()
            .message_share(&bob_did, name, bytes, Some("/Photos/beach.jpg"))
            .await
            .expect("the share");
        assert_eq!(word.as_deref(), Some("sent"), "his vault holds it, and a vault cannot sign");
    }

    // A device of Bob's takes what waited from his vault — still off the relay,
    // so nothing reaches him but the pickup.
    let first = filed(&mut b, "bob", "Shared with you/alice/beach.jpg", "the first share").await;
    let second = filed(&mut b, "bob", "Shared with you/alice/beach 2.jpg", "the second share").await;
    // Which arrived first is the vault's order; each is one of the two, whole.
    assert!(
        (first == beach && second == dunes) || (first == dunes && second == beach),
        "a share did not come back byte-identical"
    );
    assert_eq!(
        shared_with(&mut b, "bob").await,
        vec!["Shared with you/alice/beach 2.jpg".to_owned(), "Shared with you/alice/beach.jpg".to_owned()]
    );

    // Signed for back over Alice's door, so both read delivered.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
    loop {
        let readings = a.client.message_deliveries("alice", &bob_did).await.expect("readings");
        if readings.len() == 2 && readings.iter().all(|r| r.word == "delivered") {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "never signed for: {readings:?}");
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

/// **The sender's side of the frame**
/// (`TASK-an-outbox-holding-two-shares-is-handed-to-its-vault-in-one-frame-that-cannot-hold-them`,
/// clause 2). Every device of Bob's is off, so Alice's two shares at the
/// inline cap and her message all wait in her outbox. Then she rents a vault,
/// and her device's pass hands it what her outbox holds — and the vault
/// carries all three. Two shares at the cap do not fit one peer frame, so they
/// go one frame at a time; handed whole, as until 2026-10-08, the request is
/// near eighteen MiB, the vault's link refuses to read it, and the vault
/// carries none of the three, the message beside them included.
///
/// The vault is rented only once all three wait, so the first pass that
/// reaches it finds the whole outbox new — one pass per message would have
/// handed each alone and passed with no bound at all.
#[tokio::test]
async fn an_outbox_of_two_shares_at_the_inline_cap_and_a_message_is_carried_by_her_vault() {
    // A pickup every two seconds, set before either daemon starts, as the
    // vault tests beside this set it.
    std::env::set_var("KOTTON_VAULT_PICKUP_SECS", "2");
    // `kotton_msg::share::INLINE_MAX`, which this crate does not link: the
    // largest share carried inline rather than streamed.
    const INLINE_MAX: usize = 5 * 1024 * 1024;

    let (_relay, mut a, _alice_did, mut b, bob_did) = two_nodes().await;
    pair(&a, &b).await;
    mailbox_open(&mut a, "alice").await;
    mailbox_open(&mut b, "bob").await;
    let relay_url = a.runtime.reachability().nat().relay_url;

    // Every device of Bob's goes dark, and Alice's outbox fills.
    b.client.node_rendezvous_set(None).await.expect("bob leaves the relay");
    tokio::time::sleep(std::time::Duration::from_secs(7)).await;
    for (seed, name) in [(3, "beach.jpg"), (5, "dunes.jpg")] {
        a.daemon
            .occupant_host()
            .message_share(&bob_did, name, &a_photo(seed, INLINE_MAX), None)
            .await
            .expect("the share");
    }
    a.client
        .message_send_delivery("alice", &bob_did, "both are from the coast", None)
        .await
        .expect("the message");

    // Alice's vault, on the same relay.
    let vault = spawn_vault_for_test("alice's vault").await;
    common::relay::stand_at(&vault.vault, relay_url.trim_start_matches("http://")).await;
    let client_v = common::connect_when_ready(&vault.ipc, "vault door").await;
    let mut probe = common::connect_when_ready(&vault.ipc, "vault identity").await;
    let (vault_did, vault_pubkey_hex) = probe.get_node_identity().await.expect("vault identity");
    let placeholder = common::connect_when_ready(&a.endpoint, "alice placeholder").await;
    let alice_client = std::mem::replace(&mut a.client, placeholder);
    let (client_a, _client_v, node) = common::enroll_streamed(
        alice_client,
        client_v,
        "alice",
        "vault",
        common::khttpd::free_port(),
        Posture::BlindStorage,
    )
    .await;
    a.client = client_a;
    assert_eq!(node.id, "vault");
    let op_addr: std::net::SocketAddr = format!("127.0.0.1:{}", vault.op_port).parse().unwrap();
    a.client
        .peer_add("alice", "vault", &vault_did, &vault_pubkey_hex, op_addr)
        .await
        .expect("alice's device knows where its vault is");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
    loop {
        let carried = vault.vault.carried("alice").await;
        if carried == 3 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "alice's vault carries {carried} of the three her outbox holds"
        );
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
}

// ── Above the inline cap ─────────────────────────────────────────────────────
// (`TASK-a-share-above-the-frame-cap-arrives-whole-by-the-streaming-transport`,
// RFC-0090's unit 4)

/// Twenty MiB: four times the inline cap, and twice the frame cap, so it
/// travels as a manifest and five ranges or not at all. Made here, never kept.
const TWENTY_MIB: usize = 20 * 1024 * 1024;

/// The daemon objects on `user`'s stream shelf, by path.
async fn on_the_shelf(env: &TestEnv, user: &str) -> Vec<String> {
    let store = env.users.get(user).expect("resident");
    store.list_daemon_objects("/network/streams/").await.unwrap_or_default()
}

/// **Clause (4), whole.** Alice shares a twenty MiB film with Bob through
/// `messages.share`. It is twice the frame cap, so it goes as its manifest and
/// its bytes follow as sealed ranges over Bob's contact door; his node files
/// it under *Shared with you/alice* once they are whole and hash to the
/// digest, and signs for it — Alice reads *delivered*. It reads back
/// byte-identical, the conversation holds one message, and nothing of the
/// stream is left on his shelf or in her outbox.
#[tokio::test]
async fn a_twenty_mib_file_shared_with_a_contact_streams_and_lands_byte_identical() {
    let (_relay, mut a, alice_did, mut b, bob_did) = two_nodes().await;
    pair(&a, &b).await;
    mailbox_open(&mut a, "alice").await;
    mailbox_open(&mut b, "bob").await;

    let film = a_photo(11, TWENTY_MIB);
    a.client.write_file("alice", "Films/coast.mov", &film).await.expect("alice's film");

    let (id, word) = a
        .daemon
        .occupant_host()
        .message_share(&bob_did, "coast.mov", &film, Some("/Films/coast.mov"))
        .await
        .expect("the share");
    assert_eq!(word.as_deref(), Some("delivered"), "a device of Bob's signed for it whole");

    let copy = filed(&mut b, "bob", "Shared with you/alice/coast.mov", "bob's node").await;
    assert_eq!(copy.len(), film.len());
    assert!(copy == film, "the copy is not the film");
    assert_eq!(shared_with(&mut b, "bob").await, vec!["Shared with you/alice/coast.mov".to_owned()]);

    let inbox = b.client.message_poll_inbox("bob").await.expect("bob's inbox");
    assert_eq!(inbox.len(), 1, "one message, the share, and no range filed as one: {inbox:?}");
    assert_eq!((inbox[0]["type"].as_str(), inbox[0]["from_did"].as_str()), (Some("share"), Some(alice_did.as_str())));
    assert!(on_the_shelf(&b, "bob").await.is_empty(), "the stream was left on his shelf");

    assert_eq!(a.client.read_file("alice", "Films/coast.mov").await.expect("the original"), film);
    let readings = a.client.message_deliveries("alice", &bob_did).await.expect("readings");
    assert_eq!(readings.len(), 1, "the share reads as one message: {readings:?}");
    assert_eq!((readings[0].message_id.as_str(), readings[0].word.as_str()), (id.as_str(), "delivered"));
}

/// **Clause (4), truncated.** Every device of Bob's is off when Alice shares a
/// twenty MiB film, so the share and its five ranges wait in her outbox. One
/// range is lost from it — the stream can now never complete — and Bob comes
/// back. Alice's outbox hands him the manifest and the four ranges it still
/// holds, and his node keeps them toward the stream and files nothing: no
/// file under *Shared with you*, no message in the conversation. The share
/// reads as not signed for — *sent*, because his node holds it waiting for
/// its bytes — however many passes go by.
#[tokio::test]
async fn a_share_whose_stream_never_completes_files_nothing_and_is_not_signed_for() {
    // Tried again every second rather than after thirty doubling; set before
    // either daemon starts, as the outbox's own suite test sets it.
    std::env::set_var("KOTTON_OUTBOX_RETRY_SECS", "1");

    let (_relay, mut a, _alice_did, mut b, bob_did) = two_nodes().await;
    pair(&a, &b).await;
    mailbox_open(&mut a, "alice").await;
    mailbox_open(&mut b, "bob").await;
    let relay_url = b.runtime.reachability().nat().relay_url;

    b.client.node_rendezvous_set(None).await.expect("bob leaves the relay");
    tokio::time::sleep(std::time::Duration::from_secs(7)).await;

    let film = a_photo(13, TWENTY_MIB);
    let (_id, word) = a
        .daemon
        .occupant_host()
        .message_share(&bob_did, "coast.mov", &film, Some("/Films/coast.mov"))
        .await
        .expect("the share");
    assert_eq!(word.as_deref(), Some("waiting at home"), "nothing of bob's answered");

    // One range of it is lost from Alice's outbox. Her keeper writes back an
    // entry it read before a try, so it is taken again until it stays gone.
    let alice = a.users.get("alice").expect("alice is resident");
    let range = loop {
        let mut ranges = Vec::new();
        for path in alice.list_daemon_objects("/network/outbox/").await.expect("her outbox") {
            let entry: serde_json::Value =
                serde_json::from_slice(&alice.read_daemon_object(&path).await.expect("an entry")).unwrap();
            if entry.get("part_of").is_some() {
                ranges.push(path);
            }
        }
        if ranges.len() == 5 {
            break ranges[0].clone();
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    };
    let mut gone_for = 0;
    while gone_for < 3 {
        if alice.read_daemon_object(&range).await.is_ok() {
            alice.delete_daemon_object(&range).await.expect("the range is lost");
            gone_for = 0;
        } else {
            gone_for += 1;
        }
        tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;
    }

    // Bob comes back, and Alice's outbox hands him what it holds.
    b.client.node_rendezvous_set(Some(&relay_url)).await.expect("bob returns");
    mailbox_open(&mut b, "bob").await;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    loop {
        // The manifest waiting, and the four ranges that were handed.
        let shelf = on_the_shelf(&b, "bob").await;
        if shelf.len() == 5 {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "the stream never reached bob's shelf: {shelf:?}");
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    // Passes go by; nothing is filed, and the share is signed for by nobody.
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    assert!(shared_with(&mut b, "bob").await.is_empty(), "a share whose stream never completed was filed");
    assert!(
        b.client.read_file("bob", "Shared with you/alice/coast.mov").await.is_err(),
        "a share whose stream never completed was filed"
    );
    assert!(b.client.message_poll_inbox("bob").await.expect("bob's inbox").is_empty(), "a message was filed");
    let readings = a.client.message_deliveries("alice", &bob_did).await.expect("readings");
    assert_eq!(readings.len(), 1, "{readings:?}");
    assert_eq!(readings[0].word, "sent", "held waiting for its bytes, and never signed for");
}

/// **Clause (1) of the vault's half**
/// (`TASK-a-senders-vault-carries-a-shares-ranges-while-no-device-of-theirs-is-awake`,
/// unit 4's clause 5). Alice rents a vault; Bob has none. She shares a six MiB
/// film with him while every device of his is off — above the inline cap, so
/// her outbox holds its manifest and two ranges, and her pickup pass hands all
/// three to her vault. Then her device goes off: it leaves the relay and is
/// taken to where a restart leaves it, its outbox unreadable, so nothing of
/// hers but the vault can hand Bob anything. Bob comes back. The vault hands
/// him the manifest and the ranges as it hands any message, his node files the
/// film whole under *Shared with you/alice* byte-identical, and every piece is
/// signed for, sealed to Alice, so the vault carries nothing more. Alice comes
/// back, her pickup takes the signatures, and the share reads *delivered*.
///
/// Red when the vault is not handed the ranges (`carried_for` leaving out
/// every entry that is `part_of` a share, as until 2026-10-08): the vault
/// carries the manifest alone — *alice's vault carries 1 of the manifest and
/// its two ranges* — and Bob's node would keep it waiting for bytes that never
/// come.
#[tokio::test]
async fn a_share_her_vault_carries_while_her_device_is_off_is_filed_whole() {
    // A two-second pickup and a one-second carry, set before either daemon or
    // the vault starts, as `contact_pairing::a_message_her_vault_carries_…`
    // sets them.
    std::env::set_var("KOTTON_VAULT_PICKUP_SECS", "2");
    std::env::set_var("KOTTON_VAULT_CARRY_SECS", "1");
    const PASSPHRASE: &str = "abandon-ability-able-about-above";
    // Above `kotton_msg::share::INLINE_MAX` (5 MiB), which this crate does not
    // link: a manifest, a full range of 4 MiB and a range of two.
    const SIX_MIB: usize = 6 * 1024 * 1024;

    let (_relay, mut a, _alice_did, mut b, bob_did) = two_nodes().await;
    a.client
        .set_lock_policy("alice", kotton::LockMode::Passphrase, 0, Some(PASSPHRASE))
        .await
        .expect("alice sets a daily passphrase");
    pair(&a, &b).await;
    mailbox_open(&mut a, "alice").await;
    mailbox_open(&mut b, "bob").await;
    let relay_url = a.runtime.reachability().nat().relay_url;

    // Alice's vault, on the same relay.
    let vault = spawn_vault_for_test("alice's vault").await;
    common::relay::stand_at(&vault.vault, relay_url.trim_start_matches("http://")).await;
    let client_v = common::connect_when_ready(&vault.ipc, "vault door").await;
    let mut probe = common::connect_when_ready(&vault.ipc, "vault identity").await;
    let (vault_did, vault_pubkey_hex) = probe.get_node_identity().await.expect("vault identity");
    let placeholder = common::connect_when_ready(&a.endpoint, "alice placeholder").await;
    let alice_client = std::mem::replace(&mut a.client, placeholder);
    let (client_a, _client_v, node) = common::enroll_streamed(
        alice_client,
        client_v,
        "alice",
        "vault",
        common::khttpd::free_port(),
        Posture::BlindStorage,
    )
    .await;
    a.client = client_a;
    assert_eq!(node.id, "vault");
    let op_addr: std::net::SocketAddr = format!("127.0.0.1:{}", vault.op_port).parse().unwrap();
    a.client
        .peer_add("alice", "vault", &vault_did, &vault_pubkey_hex, op_addr)
        .await
        .expect("alice's device knows where its vault is");

    // Every device of Bob's is off when she shares.
    b.client.node_rendezvous_set(None).await.expect("bob leaves the relay");
    tokio::time::sleep(std::time::Duration::from_secs(7)).await;
    let film = a_photo(17, SIX_MIB);
    let (id, word) = a
        .daemon
        .occupant_host()
        .message_share(&bob_did, "harbour.mov", &film, None)
        .await
        .expect("the share");
    assert_eq!(word.as_deref(), Some("waiting at home"), "nothing of bob's answered");

    // Her pickup pass hands the manifest and both ranges to her vault.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
    loop {
        let carried = vault.vault.carried("alice").await;
        if carried == 3 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "alice's vault carries {carried} of the manifest and its two ranges"
        );
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }

    // Alice's device goes off: off the relay, its outbox unreadable.
    a.client.node_rendezvous_set(None).await.expect("alice leaves the relay");
    a.lock_as_a_restart_would("alice").await;
    assert!(
        a.client.message_deliveries("alice", &bob_did).await.is_err(),
        "alice's outbox cannot be read, so her device hands nothing"
    );

    // A device of Bob's comes back, and nothing of Alice's is awake.
    b.client.node_rendezvous_set(Some(&relay_url)).await.expect("bob returns");
    mailbox_open(&mut b, "bob").await;
    let copy = filed(&mut b, "bob", "Shared with you/alice/harbour.mov", "alice's vault").await;
    assert_eq!(copy.len(), film.len());
    assert!(copy == film, "the copy is not the film");
    assert_eq!(shared_with(&mut b, "bob").await, vec!["Shared with you/alice/harbour.mov".to_owned()]);
    let inbox = b.client.message_poll_inbox("bob").await.expect("bob's inbox");
    assert_eq!(inbox.len(), 1, "one message, the share, and no range filed as one: {inbox:?}");
    assert!(on_the_shelf(&b, "bob").await.is_empty(), "the stream was left on his shelf");

    // Every piece signed for: the vault carries nothing more.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while vault.vault.carried("alice").await != 0 {
        assert!(std::time::Instant::now() < deadline, "the vault kept carrying what bob signed for");
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }

    // Alice comes back; her pickup takes the signatures.
    assert_eq!(
        a.client.unlock_with_pin("alice", PASSPHRASE).await.expect("unlock"),
        kotton::PinUnlock::Unlocked
    );
    a.client.node_rendezvous_set(Some(&relay_url)).await.expect("alice returns");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
    loop {
        let readings = a.client.message_deliveries("alice", &bob_did).await.expect("readings");
        if readings.iter().any(|r| r.word == "delivered") {
            assert_eq!(readings.len(), 1, "the share reads as one message: {readings:?}");
            assert_eq!(readings[0].message_id, id);
            break;
        }
        assert!(std::time::Instant::now() < deadline, "alice's pickup never took the signatures: {readings:?}");
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    let outbox = a.users.get("alice").expect("alice is resident").list_daemon_objects("/network/outbox/").await;
    assert_eq!(outbox.expect("her outbox"), Vec::<String>::new(), "a range was left in her outbox");
}

/// The household of RFC-0090's group tests: four people on four daemons
/// through one relay. Avery makes the household channel and admits Sam, Jordan
/// and Pat, then removes Pat: epoch 4 is Avery's, Sam's and Jordan's, and Pat
/// still holds epoch 3. Sam issues the code to everyone Sam shares with, so
/// each of their cards shows Sam by the name Sam announced; Pat is paired with
/// Sam, so a fan-out that reached Pat would have a door to reach Pat by.
struct Household {
    _relay: common::relay::Relay,
    a: TestEnv,
    s: TestEnv,
    j: TestEnv,
    p: TestEnv,
    sam_did: String,
}

const AVERY: &str = "avery";
const SAM: &str = "sam";
const JORDAN: &str = "jordan";
const PAT: &str = "pat";
const GRANT: &str = "sh.kotton.channel.key-grant";

async fn holds_epoch(env: &mut TestEnv, user: &str, channel: &str, epoch: u64) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let grants = env
            .client
            .record_query(user, GRANT, vec![("channel_did".to_string(), serde_json::json!(channel))], None, None)
            .await
            .expect("grants");
        if grants.iter().any(|g| g["epoch"].as_u64() == Some(epoch)) {
            return;
        }
        assert!(std::time::Instant::now() < deadline, "{user} was never granted epoch {epoch}");
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

/// Four daemons, paired, holding `channel` at epoch 4 without Pat.
async fn a_household_without_pat(channel: &str) -> Household {
    use crate::common::TEST_PASSPHRASE;
    use crate::contact_pairing::{mailbox_open_for, pair_as};

    let (relay, relay_addr) = common::relay::spawn().await;
    let (mut a, mut s, mut j, mut p) = (
        common::relay::env_on(&relay_addr).await,
        common::relay::env_on(&relay_addr).await,
        common::relay::env_on(&relay_addr).await,
        common::relay::env_on(&relay_addr).await,
    );
    let (_avery_did, _) = a.client.create_user(AVERY, TEST_PASSPHRASE).await.expect("avery");
    let (sam_did, _) = s.client.create_user(SAM, TEST_PASSPHRASE).await.expect("sam");
    let (jordan_did, _) = j.client.create_user(JORDAN, TEST_PASSPHRASE).await.expect("jordan");
    let (pat_did, _) = p.client.create_user(PAT, TEST_PASSPHRASE).await.expect("pat");

    // Avery pairs with Jordan and Pat to admit them.
    pair_as(&s, SAM, &a, AVERY).await;
    pair_as(&s, SAM, &j, JORDAN).await;
    pair_as(&s, SAM, &p, PAT).await;
    pair_as(&a, AVERY, &j, JORDAN).await;
    pair_as(&a, AVERY, &p, PAT).await;
    for (env, user, contacts) in [(&mut a, AVERY, 3), (&mut s, SAM, 3), (&mut j, JORDAN, 2), (&mut p, PAT, 2)] {
        mailbox_open_for(env, user, contacts).await;
    }

    // Epochs: 0 is Avery's alone; admitting Sam, Jordan and Pat mints 1, 2 and
    // 3; removing Pat mints 4, to Avery, Sam and Jordan.
    a.client.message_channel_create(AVERY, channel).await.expect("create the channel");
    for did in [&sam_did, &jordan_did, &pat_did] {
        a.client
            .message_channel_grant_key(AVERY, channel, did, false)
            .await
            .unwrap_or_else(|e| panic!("admit {did}: {e}"));
    }
    holds_epoch(&mut p, PAT, channel, 3).await;
    a.client.message_channel_remove_member(AVERY, channel, &pat_did).await.expect("avery removes pat");
    for (env, user) in [(&mut a, AVERY), (&mut s, SAM), (&mut j, JORDAN)] {
        holds_epoch(env, user, channel, 4).await;
    }
    Household { _relay: relay, a, s, j, p, sam_did }
}

/// What a removed member holds of a share to the household: nothing under
/// *Shared with you*, and no share in the channel.
async fn pat_holds_nothing(p: &mut TestEnv, channel: &str) {
    let pats = p.client.list_files(PAT, "Shared with you/").await.unwrap_or_default();
    assert!(pats.is_empty(), "something landed on pat's node: {pats:?}");
    let history = p.client.message_channel_history(PAT, channel, None, 50).await.expect("pat's history");
    assert!(history.iter().all(|m| m["type"] != "share"), "pat's channel holds the share: {history:?}");
}

/// **A file shared with a group lands under *Shared with you* on each current
/// member's node, and nothing lands on a member removed before it**
/// (`TASK-a-file-shared-with-a-group-is-a-copy-of-each-members-under-shared-with-you`,
/// clause 5; RFC-0090, *Delivery › To a group*).
///
/// The household ([`a_household_without_pat`]). Sam — who wrote none of the
/// grants — lists the groups they hold a key for through the verb the share
/// sheet reads (the household, three people), and shares a photo with it
/// through the verb the sheet calls (`messages.channel-share`). Avery's node
/// and Jordan's each file it under *Shared with you/sam* — the name each card
/// shows for Sam — byte-identical, and keep the message in the channel,
/// opening to the file's name and naming nothing of where Sam keeps it. Pat's
/// node files nothing, and Pat's channel holds no share. Sam's original is
/// unchanged and Sam holds no second copy.
///
/// Red when the fan-out hands the share to the removed member's old epoch:
/// sealed under epoch 3 and handed to its roster, Pat holds the key and files
/// it.
#[tokio::test]
async fn a_file_shared_with_a_group_lands_under_shared_with_you_on_each_current_member_and_not_on_one_removed() {
    const CHANNEL: &str = "did:key:zHouseholdShare";
    let Household { _relay, mut a, mut s, mut j, mut p, sam_did } = a_household_without_pat(CHANNEL).await;

    // The sheet's third target kind, as Sam's node answers it: the household,
    // by its DID, three people.
    let groups = s.daemon.occupant_host().message_groups().await.expect("sam's groups");
    assert_eq!(groups.len(), 1, "{groups:?}");
    assert_eq!((groups[0].channel_did.as_str(), groups[0].members), (CHANNEL, 3));

    let photo = a_photo(11, 180_000);
    s.client.write_file(SAM, "Photos/beach.jpg", &photo).await.expect("sam's photo");
    let id = s
        .daemon
        .occupant_host()
        .message_channel_share(CHANNEL, "beach.jpg", &photo, Some("/Photos/beach.jpg"))
        .await
        .expect("the share");
    assert!(!id.is_empty());

    for (env, user) in [(&mut a, AVERY), (&mut j, JORDAN)] {
        let copy = filed(env, user, "Shared with you/sam/beach.jpg", user).await;
        assert_eq!(copy, photo, "{user}'s copy is not the photo");
        assert_eq!(shared_with(env, user).await, vec!["Shared with you/sam/beach.jpg".to_owned()], "{user}");

        // Kept in the channel: a share, opening to its name, naming nothing
        // of where Sam keeps it.
        let history = env.client.message_channel_history(user, CHANNEL, None, 50).await.expect("history");
        let shares: Vec<&serde_json::Value> = history.iter().filter(|m| m["type"] == "share").collect();
        assert_eq!(shares.len(), 1, "{user}: {history:?}");
        assert_eq!(shares[0]["from_did"], sam_did.as_str());
        assert_eq!(shares[0]["epoch"].as_u64(), Some(4), "sealed under the newest epoch Sam holds");
        let opened = env
            .client
            .message_decrypt_channel(user, CHANNEL, shares[0]["body"].as_str().unwrap(), shares[0]["nonce"].as_str().unwrap())
            .await
            .expect("it opens");
        assert_eq!(opened, "beach.jpg", "{user}");
        let held = serde_json::to_string(shares[0]).unwrap();
        assert!(!held.contains("Photos") && !held.contains("origin"), "{held}");
    }

    // Pat, removed before it, files nothing and holds no share in the channel.
    pat_holds_nothing(&mut p, CHANNEL).await;

    // Sam's original is unchanged, and Sam holds no second copy.
    assert_eq!(s.client.read_file(SAM, "Photos/beach.jpg").await.expect("the original"), photo);
    assert!(s.client.list_files(SAM, "Shared with you/").await.unwrap_or_default().is_empty(), "the sender gained a copy");
}

/// **A file above the group's inline cap, shared with the group, streams under
/// the channel's key and lands whole on each current member's node**
/// (`TASK-a-share-to-a-group-above-the-inline-cap-is-a-stream-to-each-member`;
/// RFC-0090, *Delivery › To a group*, the ruling of 2026-10-09).
///
/// The household ([`a_household_without_pat`]). Sam shares six MiB — above
/// `GROUP_INLINE_MAX`, so its manifest carries `stream` and its bytes follow
/// as two ranges, each sealed once under epoch 4's key and handed to Avery and
/// Jordan as channel copies of their own — through the verb the sheet calls.
/// Each node keeps the manifest waiting, the ranges on its shelf, and files the
/// file whole under *Shared with you/sam* once they hash to the digest:
/// byte-identical on both, one share in the channel, nothing left on either
/// shelf. Pat, removed before it, holds nothing. Sam's original is unchanged,
/// and Sam's outbox empties as each member's device signs for each piece.
#[tokio::test]
async fn a_file_above_the_inline_cap_shared_with_a_group_streams_under_the_channel_key_and_lands_whole_on_each_member() {
    const CHANNEL: &str = "did:key:zHouseholdStream";
    let Household { _relay, mut a, mut s, mut j, mut p, sam_did } = a_household_without_pat(CHANNEL).await;

    // Above `kotton_msg::share::GROUP_INLINE_MAX` (5 MiB), which this crate
    // does not link: a manifest and two ranges, or nothing.
    let film = a_photo(23, 6 * 1024 * 1024);
    s.client.write_file(SAM, "Films/ferry.mov", &film).await.expect("sam's film");
    let id = s
        .daemon
        .occupant_host()
        .message_channel_share(CHANNEL, "ferry.mov", &film, Some("/Films/ferry.mov"))
        .await
        .expect("the share");
    assert!(!id.is_empty());

    for (env, user) in [(&mut a, AVERY), (&mut j, JORDAN)] {
        let copy = filed(env, user, "Shared with you/sam/ferry.mov", user).await;
        assert_eq!(copy.len(), film.len(), "{user}");
        assert!(copy == film, "{user}'s copy is not the film");
        assert_eq!(shared_with(env, user).await, vec!["Shared with you/sam/ferry.mov".to_owned()], "{user}");

        let history = env.client.message_channel_history(user, CHANNEL, None, 50).await.expect("history");
        let shares: Vec<&serde_json::Value> = history.iter().filter(|m| m["type"] == "share").collect();
        assert_eq!(shares.len(), 1, "{user}: one share, and no range filed as a message: {history:?}");
        assert_eq!(history.len(), 1, "{user}: {history:?}");
        assert_eq!((shares[0]["from_did"].as_str(), shares[0]["epoch"].as_u64()), (Some(sam_did.as_str()), Some(4)));
        assert!(on_the_shelf(env, user).await.is_empty(), "{user}: the stream was left on the shelf");
    }

    pat_holds_nothing(&mut p, CHANNEL).await;
    assert!(p.client.list_files(PAT, "Shared with you/").await.unwrap_or_default().is_empty());
    assert!(on_the_shelf(&p, PAT).await.is_empty(), "pat's shelf holds a range");

    assert_eq!(s.client.read_file(SAM, "Films/ferry.mov").await.expect("the original"), film);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
    loop {
        let outbox = s.users.get(SAM).expect("sam is resident").list_daemon_objects("/network/outbox/").await;
        if outbox.as_ref().is_ok_and(|o| o.is_empty()) {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "sam's outbox kept a piece nobody signed for: {outbox:?}");
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

/// **A file above the inline cap shared with a group reaches a member whose
/// every device sleeps, through their vault, and is filed whole on the next
/// pickup** (`TASK-a-share-to-a-group-above-the-inline-cap-is-a-stream-to-each-member`;
/// the vault-pickup arm of `delivery::take_range`).
///
/// The household ([`a_household_without_pat`]), with Jordan holding a vault
/// and every device of Jordan's off the relay. Sam shares six MiB with the
/// group: Avery's device takes it at the door; Jordan's vault holds the
/// manifest and both ranges — channel ciphertext it cannot open — and Jordan's
/// device, still off the relay, takes them at its pickups, opens each range
/// under epoch 4 and files the film whole under *Shared with you/sam*,
/// byte-identical, with one share in the channel and nothing on the shelf.
#[tokio::test]
async fn a_file_above_the_inline_cap_shared_with_a_group_waits_at_a_sleeping_members_vault_and_is_filed_whole() {
    // A pickup every two seconds rather than every minute, set before any
    // daemon starts, as the vault tests above set it.
    std::env::set_var("KOTTON_VAULT_PICKUP_SECS", "2");
    const CHANNEL: &str = "did:key:zHouseholdAsleep";
    let Household { _relay, mut a, mut s, mut j, p: _, sam_did: _ } = a_household_without_pat(CHANNEL).await;
    let relay_url = j.runtime.reachability().nat().relay_url;
    let (_vault, _vault_did) = holding_a_vault(&mut j, JORDAN, &relay_url).await;

    // Every device of Jordan's goes dark.
    j.client.node_rendezvous_set(None).await.expect("jordan leaves the relay");
    tokio::time::sleep(std::time::Duration::from_secs(7)).await;

    let film = a_photo(29, 6 * 1024 * 1024);
    s.client.write_file(SAM, "Films/ferry.mov", &film).await.expect("sam's film");
    s.daemon
        .occupant_host()
        .message_channel_share(CHANNEL, "ferry.mov", &film, Some("/Films/ferry.mov"))
        .await
        .expect("the share");

    for (env, user) in [(&mut a, AVERY), (&mut j, JORDAN)] {
        let copy = filed(env, user, "Shared with you/sam/ferry.mov", user).await;
        assert!(copy == film, "{user}'s copy is not the film");
        let history = env.client.message_channel_history(user, CHANNEL, None, 50).await.expect("history");
        assert_eq!(history.iter().filter(|m| m["type"] == "share").count(), 1, "{user}: {history:?}");
        assert!(on_the_shelf(env, user).await.is_empty(), "{user}: the stream was left on the shelf");
    }
}
