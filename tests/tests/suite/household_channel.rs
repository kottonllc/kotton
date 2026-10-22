// SPDX-License-Identifier: AGPL-3.0-or-later
//! The household conversation — contacts → admission → channel key grant.
//!
//! This is the hole the project's status log named as the critical path for a long time:
//! "messaging today only lets a channel's *creator* post."
//!
//! The diagnosis needed one correction, which these tests encode. There *is* an
//! admission verb — `message_channel_grant_key`. What was missing sat one step
//! earlier: that handler resolves the member's public key from the **membership
//! registry**, and the only production writer of that registry was device
//! pairing. So the registry could hold your own laptop and nobody else, and
//! another person could not exist as a known key.
//!
//! Admission now **rotates the channel key** rather than re-wrapping it, which
//! is what makes a member's reach begin where they joined instead of where the
//! channel did. The tests below pin both directions of that: what a new member
//! cannot read, and what the admitter can deliberately choose to share.
//!
//! Two identities on one daemon is not a contrivance here — it is precisely the
//! household case RFC-0053's governing constraint is written for, and it is
//! testable on one machine.

use crate::common::cli::{said, Cli};
use crate::common::TestEnv;
use kotton::KottonClient;

const AVERY: &str = "avery";
const SAM: &str = "sam";
const CHANNEL: &str = "did:key:zHousehold";

/// Create an identity on its own connection and return `(aid, authed client)`.
///
/// `create_user` authenticates the connection it ran on, so giving each identity
/// its own connection is both simpler than minting sessions afterwards and a
/// truer model of two people using one machine.
async fn identity(env: &TestEnv, user: &str) -> (String, KottonClient) {
    let mut client = KottonClient::connect_to(env.endpoint.clone())
        .await
        .expect("connect");
    let (did, _) = client.create_user(user, crate::common::TEST_PASSPHRASE).await.expect("create user");
    (did, client)
}

/// A member admitted while every device of theirs is off is handed the
/// key-grant by their vault, and reads the channel when a device wakes and
/// picks it up. Until 2026-10-08 the pickup filed that grant as an empty
/// direct message from the admitter, and no key: the member could not open
/// the channel, and the channel's posts waited at the vault for a key that
/// never came
/// (`TASK-a-key-grant-picked-up-from-a-vault-is-filed-as-an-empty-message`).
#[tokio::test]
async fn a_member_admitted_while_every_device_is_off_reads_the_channel_when_one_wakes() {
    use crate::contact_pairing::{holding_a_vault, mailbox_open, pair, two_nodes};
    const FERRY: &str = "did:key:zTheFerryThread";
    // A pickup every two seconds, set before Bob's daemon starts, as
    // `contact_pairing::a_message_waits_at_the_vault_while_every_device_sleeps` sets it.
    // Process-wide, so it reaches every daemon the suite starts after it: the
    // existing shape, the one
    // `TASK-a-process-global-relay-url-is-shared-by-tests-that-run-in-parallel`
    // records for `KOTTON_RELAY_URL`. Every setter of this one writes the same
    // "2", and a shorter pickup only takes the same bytes sooner, so no test
    // reads another's value as a different answer.
    std::env::set_var("KOTTON_VAULT_PICKUP_SECS", "2");

    let (_relay, mut a, _alice_did, mut b, bob_did) = two_nodes().await;
    pair(&a, &b).await;
    mailbox_open(&mut a, "alice").await;
    mailbox_open(&mut b, "bob").await;
    let relay_url = a.runtime.reachability().nat().relay_url;
    let (_vault, _) = holding_a_vault(&mut b, "bob", &relay_url).await;

    // Every device of Bob's goes dark.
    b.client.node_rendezvous_set(None).await.expect("bob leaves the relay");
    tokio::time::sleep(std::time::Duration::from_secs(7)).await;

    // Alice admits him and posts. Both wait at his vault.
    a.client.message_channel_create("alice", FERRY).await.expect("create the channel");
    a.client
        .message_channel_grant_key("alice", FERRY, &bob_did, false)
        .await
        .expect("admit bob");
    a.client
        .message_channel_send("alice", FERRY, "the ferry leaves at 6:40, not 7")
        .await
        .expect("alice posts");

    // A device of Bob's takes what waited — still off the relay, so nothing
    // reaches it but the pickup — and reads the post with the grant it took.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
    let post = loop {
        let history = b.client.message_channel_history("bob", FERRY, None, 50).await.expect("bob's history");
        if let Some(post) = history.into_iter().next() {
            break post;
        }
        assert!(std::time::Instant::now() < deadline, "bob's device never read the channel from the vault");
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    };
    let plaintext = b
        .client
        .message_decrypt_channel("bob", FERRY, post["body"].as_str().expect("body"), post["nonce"].as_str().expect("nonce"))
        .await
        .expect("bob opens it with the grant his vault carried");
    assert_eq!(plaintext, "the ferry leaves at 6:40, not 7");
    assert!(
        b.client.message_poll_inbox("bob").await.expect("bob's inbox").is_empty(),
        "the grant is not a message: nothing from alice lands in the conversation"
    );
}

/// The headline: a second person can be admitted to a channel and read what was
/// posted there. Before contacts existed this failed at the key lookup with
/// "no key known for … — pair with them first".
#[tokio::test]
async fn a_household_member_can_be_admitted_and_read_the_channel() {
    let env = TestEnv::spawn().await;
    let (_a, mut avery) = identity(&env, AVERY).await;
    // Sam's connection is held rather than re-established: `session_cache`
    // resolves an ambient per-machine path, so a reconnect can pick up a token
    // another test's daemon minted (see AGENTS.md, "what is still shared").
    let (sam_did, mut sam) = identity(&env, SAM).await;

    avery
        .message_channel_create(AVERY, CHANNEL)
        .await
        .expect("create channel");

    // The step that was impossible: admit sam as someone avery knows.
    avery
        .contact_add(AVERY, &sam_did)
        .await
        .expect("admit sam as a contact");

    // Now the pre-existing grant path works, unchanged.
    avery
        .message_channel_grant_key(AVERY, CHANNEL, &sam_did, false)
        .await
        .expect("grant the channel key to sam");

    avery
        .message_channel_send(AVERY, CHANNEL, "dinner at seven")
        .await
        .expect("avery posts");

    // The whole loop: sam reads the channel from *sam's own store*. This is what
    // local delivery added — before it, the key reached sam but the messages did
    // not, because records travel by sync and two identities on one daemon never
    // sync with each other.
    let history = sam
        .message_channel_history(SAM, CHANNEL, None, 50)
        .await
        .expect("sam reads the channel from their own store");
    let msg = history.first().expect("the message was delivered to sam");

    let plaintext = sam
        .message_decrypt_channel(
            SAM,
            CHANNEL,
            msg["body"].as_str().expect("body"),
            msg["nonce"].as_str().expect("nonce"),
        )
        .await
        .expect("sam decrypts with the granted channel key");
    assert_eq!(
        plaintext, "dinner at seven",
        "the admitted member must be able to read the channel"
    );
}

/// Admission is what grants reach: without the contact, the grant is refused,
/// and the refusal names the missing thing rather than failing obscurely.
#[tokio::test]
async fn granting_a_key_to_a_stranger_is_refused() {
    let env = TestEnv::spawn().await;
    let (_a, mut avery) = identity(&env, AVERY).await;
    let (sam_did, _sam) = identity(&env, SAM).await;
    avery
        .message_channel_create(AVERY, CHANNEL)
        .await
        .expect("create channel");

    let err = avery
        .message_channel_grant_key(AVERY, CHANNEL, &sam_did, false)
        .await
        .expect_err("a key must not be granted to an unadmitted identity");
    assert!(
        err.to_string().contains("no key known"),
        "the refusal should name the missing key, got: {err}"
    );
}

/// The admission a person makes from a terminal: `kotton message channel admit`,
/// each command its own process with the session a person would have.
///
/// Avery names Sam by the name `kotton contact list` shows for him, Sam reads
/// Avery's next post with `kotton message channel read`, and Casey — whom Avery
/// never paired with — is refused with the daemon's own words. The refusal is
/// taken from the daemon through the client first and then looked for in what
/// the terminal said, so this holds the verb to passing the daemon's answer on,
/// not to any wording of its own.
#[tokio::test]
async fn a_contact_is_admitted_from_the_terminal_and_a_stranger_is_refused_in_the_daemons_words() {
    let env = TestEnv::spawn_cli_reachable().await;
    let (_a, mut avery) = identity(&env, AVERY).await;
    let (sam_did, sam) = identity(&env, SAM).await;
    let (casey_did, _casey) = identity(&env, "casey").await;
    let cli = Cli::for_env(&env);
    cli.seed_session(AVERY, avery.session_token.as_deref().expect("create_user bound avery a session"));
    cli.seed_session(SAM, sam.session_token.as_deref().expect("create_user bound sam a session"));

    avery.message_channel_create(AVERY, CHANNEL).await.expect("create channel");
    avery.contact_add(AVERY, &sam_did).await.expect("sam is avery's contact");

    let admitted = cli.run(&["message", "channel", "admit", CHANNEL, SAM, "--user", AVERY]);
    assert!(admitted.status.success(), "`kotton message channel admit` failed.\n{}", said(&admitted));
    assert!(
        String::from_utf8_lossy(&admitted.stdout).contains(&sam_did),
        "the admission names whom the name resolved to.\n{}",
        said(&admitted)
    );

    let posted = cli.run(&["message", "channel", "send", CHANNEL, "dinner at seven", "--user", AVERY]);
    assert!(posted.status.success(), "avery's post failed.\n{}", said(&posted));
    let read = cli.run(&["message", "channel", "read", CHANNEL, "--user", SAM]);
    assert!(read.status.success(), "sam's read failed.\n{}", said(&read));
    assert!(
        String::from_utf8_lossy(&read.stdout).contains("dinner at seven"),
        "sam, admitted from the terminal, reads avery's next post.\n{}",
        said(&read)
    );

    let refusal = avery
        .message_channel_grant_key(AVERY, CHANNEL, &casey_did, false)
        .await
        .expect_err("casey is nobody avery holds a key for")
        .to_string();
    let refused = cli.run(&["message", "channel", "admit", CHANNEL, &casey_did, "--user", AVERY]);
    assert_eq!(refused.status.code(), Some(1), "a stranger must not be admitted.\n{}", said(&refused));
    assert_eq!(
        String::from_utf8_lossy(&refused.stderr),
        format!("{refusal}\n"),
        "the terminal says the daemon's refusal as the daemon said it, and nothing else.\n{}",
        said(&refused)
    );
}

/// A direct message from the terminal names its recipient the way `admit` does:
/// Avery sends to Sam by the name `kotton contact list` shows, the terminal
/// prints the DID the name stood for, and Sam reads it in his inbox.
#[tokio::test]
async fn a_message_is_sent_to_a_contact_by_name_from_the_terminal_and_names_their_did() {
    let env = TestEnv::spawn_cli_reachable().await;
    let (avery_did, mut avery) = identity(&env, AVERY).await;
    let (sam_did, mut sam) = identity(&env, SAM).await;
    let cli = Cli::for_env(&env);
    cli.seed_session(AVERY, avery.session_token.as_deref().expect("create_user bound avery a session"));
    cli.seed_session(SAM, sam.session_token.as_deref().expect("create_user bound sam a session"));
    avery.contact_add(AVERY, &sam_did).await.expect("sam is avery's contact");
    sam.contact_add(SAM, &avery_did).await.expect("avery is sam's contact");

    let sent = cli.run(&["message", "send", SAM, "the photos are up", "--user", AVERY]);
    assert!(sent.status.success(), "`kotton message send` by name failed.\n{}", said(&sent));
    let stdout = String::from_utf8_lossy(&sent.stdout).into_owned();
    let mut lines = stdout.lines();
    // The first line is the delivery word and the message id, as a script reads it
    // (`head -1 | sed 's/ (.*//'`): another account on this machine is filed locally.
    let word = lines.next().and_then(|l| l.split(" (").next());
    assert_eq!(word, Some("local"), "line one is the delivery word alone.\n{}", said(&sent));
    assert_eq!(
        lines.next(),
        Some(format!("to {SAM} ({sam_did})").as_str()),
        "the next line names whom the name resolved to.\n{}",
        said(&sent)
    );

    let inbox = cli.run(&["message", "inbox", "--user", SAM]);
    assert!(inbox.status.success(), "sam's inbox failed.\n{}", said(&inbox));
    assert!(
        String::from_utf8_lossy(&inbox.stdout).contains("the photos are up"),
        "the message sent by name reaches sam.\n{}",
        said(&inbox)
    );
}

/// Removal has a verb in the terminal: `kotton message channel remove`.
///
/// Avery admits Sam and Jordan, then removes Sam by the name `kotton contact
/// list` shows. Sam still reads what was said while he was in and nothing posted
/// after; Jordan, who stays, reads both. Casey — in no channel of Avery's — is
/// refused with the daemon's own words, taken through the client first and then
/// looked for in what the terminal said.
#[tokio::test]
async fn a_member_is_removed_from_the_terminal_and_reads_nothing_posted_after() {
    const JORDAN: &str = "jordan";
    let env = TestEnv::spawn_cli_reachable().await;
    let (_a, mut avery) = identity(&env, AVERY).await;
    let (sam_did, sam) = identity(&env, SAM).await;
    let (jordan_did, jordan) = identity(&env, JORDAN).await;
    let (casey_did, _casey) = identity(&env, "casey").await;
    let cli = Cli::for_env(&env);
    for (user, client) in [(AVERY, &avery), (SAM, &sam), (JORDAN, &jordan)] {
        cli.seed_session(user, client.session_token.as_deref().expect("create_user bound a session"));
    }

    avery.message_channel_create(AVERY, CHANNEL).await.expect("create channel");
    for did in [&sam_did, &jordan_did] {
        avery.contact_add(AVERY, did).await.expect("a contact of avery's");
        avery.message_channel_grant_key(AVERY, CHANNEL, did, false).await.expect("admit");
    }
    let before = cli.run(&["message", "channel", "send", CHANNEL, "while sam was in", "--user", AVERY]);
    assert!(before.status.success(), "avery's first post failed.\n{}", said(&before));

    let removed = cli.run(&["message", "channel", "remove", CHANNEL, SAM, "--user", AVERY]);
    assert!(removed.status.success(), "`kotton message channel remove` failed.\n{}", said(&removed));
    assert!(
        String::from_utf8_lossy(&removed.stdout).contains(&sam_did),
        "the removal names whom the name resolved to.\n{}",
        said(&removed)
    );

    let after = cli.run(&["message", "channel", "send", CHANNEL, "after sam was removed", "--user", AVERY]);
    assert!(after.status.success(), "avery's post after the removal failed.\n{}", said(&after));

    let sams = cli.run(&["message", "channel", "read", CHANNEL, "--user", SAM]);
    let sams = String::from_utf8_lossy(&sams.stdout).into_owned();
    assert!(sams.contains("while sam was in"), "sam keeps what was said while he was in.\n{sams}");
    assert!(!sams.contains("after sam was removed"), "sam, removed from the terminal, reads nothing posted after.\n{sams}");
    for user in [AVERY, JORDAN] {
        let read = cli.run(&["message", "channel", "read", CHANNEL, "--user", user]);
        let read = String::from_utf8_lossy(&read.stdout).into_owned();
        assert!(
            read.contains("while sam was in") && read.contains("after sam was removed"),
            "{user}, who remains, reads both posts.\n{read}"
        );
    }

    let refusal = avery
        .message_channel_remove_member(AVERY, CHANNEL, &casey_did)
        .await
        .expect_err("casey is in no channel of avery's, so there is nobody to remove")
        .to_string();
    let refused = cli.run(&["message", "channel", "remove", CHANNEL, &casey_did, "--user", AVERY]);
    assert_eq!(refused.status.code(), Some(1), "a stranger must not be removed.\n{}", said(&refused));
    assert_eq!(
        String::from_utf8_lossy(&refused.stderr),
        format!("{refusal}\n"),
        "the terminal says the daemon's refusal as the daemon said it, and nothing else.\n{}",
        said(&refused)
    );
}

/// A contact on another machine must be refused rather than admitted on an
/// asserted DID. Accepting one would let anyone who can reach the IPC socket
/// install themselves as anyone — the key has to arrive authenticated.
#[tokio::test]
async fn a_did_with_no_local_identity_cannot_be_admitted() {
    let env = TestEnv::spawn().await;
    let (_a, mut avery) = identity(&env, AVERY).await;
    let (_s, _sam) = identity(&env, SAM).await;

    let err = avery
        .contact_add(AVERY, "did:key:zStrangerFromTheInternet")
        .await
        .expect_err("an identity this device has never seen must not be admitted");
    assert!(
        err.to_string().contains("paired"),
        "the refusal should point at pairing, got: {err}"
    );
}

/// Contacts are listed, and an identity is not its own contact.
#[tokio::test]
async fn contacts_are_listed_and_exclude_yourself() {
    let env = TestEnv::spawn().await;
    let (avery_did, mut avery) = identity(&env, AVERY).await;
    let (sam_did, _sam) = identity(&env, SAM).await;

    assert!(avery
        .contact_add(AVERY, &avery_did)
        .await
        .is_err(), "an identity must not be able to admit itself");

    avery.contact_add(AVERY, &sam_did).await.expect("admit sam");
    let contacts = avery.contact_list(AVERY).await.expect("list contacts");
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].0, sam_did);
    assert_eq!(
        contacts[0].1.as_deref(),
        Some(SAM),
        "the label should say who this is, in local terms"
    );
}

/// Joining does not show you yesterday's conversation — and this pins that the
/// boundary is **cryptographic**, not a matter of which rows were copied.
///
/// The distinction is the whole point of channel key epochs. Before them a
/// channel had one long-lived symmetric key, so admitting sam handed sam the key
/// that opens every message the channel has ever carried; the only thing between
/// sam and the earlier conversation was that nobody had copied those rows. That
/// is a delivery policy wearing a confidentiality property's clothes, and it
/// would have evaporated the moment channel ciphertext reached a member from a
/// hosting node (which `RFC-0064` specifies it will).
///
/// So the assertion that matters is the second one: sam is handed the earlier
/// ciphertext **directly**, bypassing delivery entirely, and still cannot read
/// it. Admission minted a new epoch; sam holds no key for the old one.
#[tokio::test]
async fn a_member_admitted_later_cannot_read_earlier_messages_even_given_the_ciphertext() {
    let env = TestEnv::spawn().await;
    let (_a, mut avery) = identity(&env, AVERY).await;
    let (sam_did, mut sam) = identity(&env, SAM).await;

    avery
        .message_channel_create(AVERY, CHANNEL)
        .await
        .expect("create channel");
    avery
        .message_channel_send(AVERY, CHANNEL, "before sam joined")
        .await
        .expect("avery posts alone");

    avery.contact_add(AVERY, &sam_did).await.expect("admit sam");
    avery
        .message_channel_grant_key(AVERY, CHANNEL, &sam_did, false)
        .await
        .expect("grant");
    avery
        .message_channel_send(AVERY, CHANNEL, "after sam joined")
        .await
        .expect("avery posts again");

    let history = sam
        .message_channel_history(SAM, CHANNEL, None, 50)
        .await
        .expect("sam reads");
    assert_eq!(
        history.len(),
        1,
        "sam should hold only the message sent after admission"
    );
    let plaintext = sam
        .message_decrypt_channel(
            SAM,
            CHANNEL,
            history[0]["body"].as_str().expect("body"),
            history[0]["nonce"].as_str().expect("nonce"),
        )
        .await
        .expect("decrypt");
    assert_eq!(plaintext, "after sam joined");

    // The earlier message, taken from avery's own store and handed straight to
    // sam. No delivery decision is involved in this step at all.
    let averys = avery
        .message_channel_history(AVERY, CHANNEL, None, 50)
        .await
        .expect("avery reads");
    let earlier = averys
        .iter()
        .find(|m| m["epoch"].as_u64() == Some(0))
        .expect("avery still holds the epoch-0 message");

    let err = sam
        .message_decrypt_channel(
            SAM,
            CHANNEL,
            earlier["body"].as_str().expect("body"),
            earlier["nonce"].as_str().expect("nonce"),
        )
        .await
        .expect_err("sam must not be able to read a message sealed before they joined");
    assert!(
        err.to_string().contains("epoch you do not hold"),
        "the refusal should name the epoch boundary, got: {err}"
    );
}

/// Leaving is the same boundary from the other side: a member removed by a
/// rotation that omits them cannot read what follows, **even given the
/// ciphertext**, and keeps what they already held
/// (`TASK-a-member-is-removed-from-a-channel-by-a-rotation-that-omits-them`).
///
/// RFC-0064's sentence — *a rotation that omits someone is how a member stops
/// being one; there is no second protocol* — held where a single daemon cannot
/// fake it: three people on three daemons, so every grant and every copy
/// crosses a contact door, and the removed member's node is one nobody else
/// writes into. Avery admits Sam and Jordan, posts, removes Sam, posts again.
///
/// The assertion that matters is the one the admitted-later test above makes
/// in the other direction: the message sealed after the removal is taken from
/// Avery's store and handed straight to Sam, bypassing delivery, and does not
/// open — Sam's node holds no grant for the epoch the removal minted. Jordan
/// reads on both sides of it, and Sam still opens what was said while they
/// were in.
#[tokio::test]
async fn a_member_removed_later_cannot_read_later_messages_even_given_the_ciphertext() {
    use crate::common::{self, TEST_PASSPHRASE};
    use crate::contact_pairing::{mailbox_open, pair_as};
    use kotton_wire::ipc::Delivery;
    const JORDAN: &str = "jordan";
    const GRANT: &str = "sh.kotton.channel.key-grant";

    let (relay, relay_addr) = common::relay::spawn().await;
    let (mut a, mut s, mut j) = (
        common::relay::env_on(&relay_addr).await,
        common::relay::env_on(&relay_addr).await,
        common::relay::env_on(&relay_addr).await,
    );
    let _relay = relay;
    let (avery_did, _) = a.client.create_user(AVERY, TEST_PASSPHRASE).await.expect("avery");
    let (sam_did, _) = s.client.create_user(SAM, TEST_PASSPHRASE).await.expect("sam");
    let (jordan_did, _) = j.client.create_user(JORDAN, TEST_PASSPHRASE).await.expect("jordan");

    // Avery knows both of them; they need not know each other. Only the person
    // rotating needs a door to each member.
    for (other, user) in [(&s, SAM), (&j, JORDAN)] {
        pair_as(&a, AVERY, other, user).await;
    }
    let contacts: Vec<String> = a.client.contact_list(AVERY).await.expect("avery's contacts").into_iter().map(|(did, _)| did).collect();
    assert!(contacts.contains(&sam_did) && contacts.contains(&jordan_did), "avery paired with both: {contacts:?}");
    mailbox_open(&mut s, SAM).await;
    mailbox_open(&mut j, JORDAN).await;

    // Epoch 0 is Avery's alone; admitting Sam mints 1, admitting Jordan mints 2.
    a.client.message_channel_create(AVERY, CHANNEL).await.expect("create the channel");
    for did in [&sam_did, &jordan_did] {
        a.client
            .message_channel_grant_key(AVERY, CHANNEL, did, false)
            .await
            .unwrap_or_else(|e| panic!("admit {did}: {e}"));
    }
    let (_id, fanout) = a
        .client
        .message_channel_send_with_fanout(AVERY, CHANNEL, "while sam was in")
        .await
        .expect("avery posts to all three");
    assert_eq!(fanout.len(), 2, "one copy each for sam and jordan: {fanout:?}");
    assert!(
        fanout.iter().all(|m| matches!(m.delivery, Delivery::Delivered | Delivery::AlreadyHeld)),
        "a copy was not handed over: {fanout:?}"
    );

    // Removing yourself is not this verb: the remover mints the next key.
    let err = a
        .client
        .message_channel_remove_member(AVERY, CHANNEL, &avery_did)
        .await
        .expect_err("a person cannot remove themselves by a rotation they mint");
    assert!(err.to_string().contains("leaving is a different verb"), "{err}");

    // The removal: epoch 3, granted to Avery and Jordan and not to Sam.
    a.client
        .message_channel_remove_member(AVERY, CHANNEL, &sam_did)
        .await
        .expect("avery removes sam");

    let (_id, fanout) = a
        .client
        .message_channel_send_with_fanout(AVERY, CHANNEL, "after sam was removed")
        .await
        .expect("avery posts to who is left");

    // Sam's node holds no key for the epoch the removal minted — nothing it
    // could try. Read from Sam's own store, on Sam's own daemon.
    let averys = a.client.message_channel_history(AVERY, CHANNEL, None, 50).await.expect("avery reads");
    let after = averys
        .iter()
        .max_by_key(|m| m["epoch"].as_u64().unwrap_or(0))
        .expect("avery holds the message sent after the removal");
    let removal_epoch = after["epoch"].as_u64().expect("a channel message carries its epoch");
    assert_eq!(removal_epoch, 3, "create, two admissions and a removal are four epochs");
    let sams_grants = s
        .client
        .record_query(SAM, GRANT, vec![("channel_did".to_string(), serde_json::json!(CHANNEL))], None, None)
        .await
        .expect("sam's grants");
    let held: Vec<u64> = sams_grants.iter().map(|g| g["epoch"].as_u64().unwrap_or(0)).collect();
    assert!(!held.is_empty(), "sam was granted epochs while in the channel");
    assert!(!held.contains(&removal_epoch), "sam's node holds a grant for the epoch that removed them: {held:?}");

    // The message sealed after the removal, taken from Avery's store and handed
    // to Sam directly. No delivery decision is involved in this step.
    let err = s
        .client
        .message_decrypt_channel(
            SAM,
            CHANNEL,
            after["body"].as_str().expect("body"),
            after["nonce"].as_str().expect("nonce"),
        )
        .await
        .expect_err("sam must not read a message sealed after they were removed");
    assert!(err.to_string().contains("epoch you do not hold"), "the refusal should name the epoch boundary, got: {err}");

    // Sam keeps what was theirs to read: the message from while they were in,
    // out of their own store, and nothing after it.
    let sams = s.client.message_channel_history(SAM, CHANNEL, None, 50).await.expect("sam reads");
    let mut read = Vec::new();
    for msg in &sams {
        read.push(
            s.client
                .message_decrypt_channel(SAM, CHANNEL, msg["body"].as_str().expect("body"), msg["nonce"].as_str().expect("nonce"))
                .await
                .expect("sam opens what they were handed while in the channel"),
        );
    }
    assert_eq!(read, vec!["while sam was in".to_string()], "sam holds the earlier message and nothing later");

    // Jordan reads on both sides of the removal, out of their own store.
    let jordans = j.client.message_channel_history(JORDAN, CHANNEL, None, 50).await.expect("jordan reads");
    let mut read = Vec::new();
    for msg in &jordans {
        read.push(
            j.client
                .message_decrypt_channel(JORDAN, CHANNEL, msg["body"].as_str().expect("body"), msg["nonce"].as_str().expect("nonce"))
                .await
                .expect("jordan opens every message, before and after"),
        );
    }
    read.sort();
    assert_eq!(read, vec!["after sam was removed".to_string(), "while sam was in".to_string()]);

    // And the membership the next message is handed to is the one the removal
    // left: Jordan's copy, and none for Sam. Removing Sam again is refused,
    // since there is nobody left to remove.
    let named: Vec<&str> = fanout.iter().map(|m| m.member_did.as_str()).collect();
    assert_eq!(named, vec![jordan_did.as_str()], "the next message goes to jordan alone");
    assert!(
        matches!(fanout[0].delivery, Delivery::Delivered | Delivery::AlreadyHeld),
        "jordan's copy was not handed over: {fanout:?}"
    );
    let err = a
        .client
        .message_channel_remove_member(AVERY, CHANNEL, &sam_did)
        .await
        .expect_err("sam is no longer a member, so there is nobody to remove");
    assert!(err.to_string().contains("not a member"), "{err}");
}

/// A member who admitted nobody changes the membership without forking it
/// (`TASK-a-channel-member-who-admitted-nobody-sees-a-channel-of-one`).
///
/// Avery admits Sam and Jordan, everyone on their own daemon. Sam wrote none of
/// the grants and holds only their own, and reads the whole membership from the
/// roster sealed inside it. So:
///
/// - Sam's post reaches both others.
/// - Sam admits a fourth person, Pat, and everyone reads what Pat says next,
///   Avery included. Pat reads what Sam says after that.
/// - Sam removes Jordan, and leaves nobody else on the old epoch: Avery, Sam and
///   Pat read what is said next, and Jordan does not.
/// - Jordan, posting at the epoch they still hold, is refused at every
///   remaining member's door.
///
/// Until 2026-10-08 the membership was counted from the caller's own store,
/// where only the grants' writer holds everybody's. Sam's admission minted an
/// epoch for Sam and the newcomer alone, Sam's removal of Jordan was refused
/// with "not a member", and Sam's post reached nobody.
#[tokio::test]
async fn a_member_who_wrote_no_grant_removes_another_and_the_rest_read_on() {
    use crate::common::{self, TestEnv, TEST_PASSPHRASE};
    use crate::contact_pairing::{mailbox_open_for, pair_as};
    use kotton_wire::ipc::Delivery;
    const JORDAN: &str = "jordan";
    const PAT: &str = "pat";
    const GRANT: &str = "sh.kotton.channel.key-grant";

    let (relay, relay_addr) = common::relay::spawn().await;
    let (mut a, mut s, mut j, mut p) = (
        common::relay::env_on(&relay_addr).await,
        common::relay::env_on(&relay_addr).await,
        common::relay::env_on(&relay_addr).await,
        common::relay::env_on(&relay_addr).await,
    );
    let _relay = relay;
    let (avery_did, _) = a.client.create_user(AVERY, TEST_PASSPHRASE).await.expect("avery");
    let (sam_did, _) = s.client.create_user(SAM, TEST_PASSPHRASE).await.expect("sam");
    let (jordan_did, _) = j.client.create_user(JORDAN, TEST_PASSPHRASE).await.expect("jordan");
    let (pat_did, _) = p.client.create_user(PAT, TEST_PASSPHRASE).await.expect("pat");

    // Everyone knows everyone: a member hands a copy to each other member over
    // a door of their own, so each needs one to each. Then every node waits for
    // all three contacts' doors, not just the first pair it opened.
    pair_as(&a, AVERY, &s, SAM).await;
    pair_as(&a, AVERY, &j, JORDAN).await;
    pair_as(&a, AVERY, &p, PAT).await;
    pair_as(&s, SAM, &j, JORDAN).await;
    pair_as(&s, SAM, &p, PAT).await;
    pair_as(&j, JORDAN, &p, PAT).await;
    for (env, user) in [(&mut a, AVERY), (&mut s, SAM), (&mut j, JORDAN), (&mut p, PAT)] {
        mailbox_open_for(env, user, 3).await;
    }

    // A rotation's grants are handed over its doors as part of it; this waits
    // until `user`'s own store holds `epoch`, and says who never got it.
    async fn holds_epoch(env: &mut TestEnv, user: &str, epoch: u64) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            let grants = env
                .client
                .record_query(user, GRANT, vec![("channel_did".to_string(), serde_json::json!(CHANNEL))], None, None)
                .await
                .expect("grants");
            if grants.iter().any(|g| g["epoch"].as_u64() == Some(epoch)) {
                return;
            }
            assert!(std::time::Instant::now() < deadline, "{user} was never granted epoch {epoch}: the rotation forked the channel");
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    }

    // Every copy of a post handed over, to exactly `to`.
    fn handed_to(who: &str, fanout: &[kotton_wire::ipc::MemberDelivery], to: &[&String]) {
        let mut named: Vec<&str> = fanout.iter().map(|m| m.member_did.as_str()).collect();
        named.sort();
        let mut want: Vec<&str> = to.iter().map(|d| d.as_str()).collect();
        want.sort();
        assert_eq!(named, want, "{who}'s post goes to every other current member: {fanout:?}");
        assert!(
            fanout.iter().all(|m| matches!(m.delivery, Delivery::Delivered | Delivery::AlreadyHeld)),
            "a copy of {who}'s post was not handed over: {fanout:?}"
        );
    }

    // Epochs: 0 is Avery's alone; admitting Sam mints 1, admitting Jordan mints 2.
    a.client.message_channel_create(AVERY, CHANNEL).await.expect("create the channel");
    for did in [&sam_did, &jordan_did] {
        a.client
            .message_channel_grant_key(AVERY, CHANNEL, did, false)
            .await
            .unwrap_or_else(|e| panic!("admit {did}: {e}"));
    }

    // Sam wrote no grant, and Sam's post reaches both other members.
    let (_id, fanout) = s.client.message_channel_send_with_fanout(SAM, CHANNEL, "sam, before").await.expect("sam posts");
    handed_to("sam", &fanout, &[&avery_did, &jordan_did]);

    // Sam admits Pat: epoch 3, to all four. Everyone holds it, Avery included.
    s.client
        .message_channel_grant_key(SAM, CHANNEL, &pat_did, false)
        .await
        .expect("sam, who admitted nobody, admits pat");
    for (env, user) in [(&mut a, AVERY), (&mut s, SAM), (&mut j, JORDAN), (&mut p, PAT)] {
        holds_epoch(env, user, 3).await;
    }
    let (_id, fanout) = p
        .client
        .message_channel_send_with_fanout(PAT, CHANNEL, "pat, admitted by sam")
        .await
        .expect("pat posts");
    handed_to("pat", &fanout, &[&avery_did, &sam_did, &jordan_did]);
    let (_id, fanout) = s.client.message_channel_send_with_fanout(SAM, CHANNEL, "sam, to pat").await.expect("sam posts");
    handed_to("sam", &fanout, &[&avery_did, &jordan_did, &pat_did]);

    // Sam removes Jordan: epoch 4, to Avery, Sam and Pat.
    s.client
        .message_channel_remove_member(SAM, CHANNEL, &jordan_did)
        .await
        .expect("sam, who admitted nobody, removes jordan");
    for (env, user) in [(&mut a, AVERY), (&mut s, SAM), (&mut p, PAT)] {
        holds_epoch(env, user, 4).await;
    }
    let (_id, fanout) = s.client.message_channel_send_with_fanout(SAM, CHANNEL, "sam, after").await.expect("sam posts after");
    handed_to("sam", &fanout, &[&avery_did, &pat_did]);
    let (_id, fanout) = a.client.message_channel_send_with_fanout(AVERY, CHANNEL, "avery, after").await.expect("avery posts after");
    handed_to("avery", &fanout, &[&sam_did, &pat_did]);

    // Each reads what their own store holds and their own keys open.
    async fn read_all(client: &mut kotton::KottonClient, user: &str) -> Vec<String> {
        let history = client.message_channel_history(user, CHANNEL, None, 50).await.expect("history");
        let mut read = Vec::new();
        for msg in &history {
            if let Ok(text) = client
                .message_decrypt_channel(user, CHANNEL, msg["body"].as_str().expect("body"), msg["nonce"].as_str().expect("nonce"))
                .await
            {
                read.push(text);
            }
        }
        read.sort();
        read
    }
    let sorted = |texts: &[&str]| {
        let mut v: Vec<String> = texts.iter().map(|t| t.to_string()).collect();
        v.sort();
        v
    };
    let everything = sorted(&["avery, after", "pat, admitted by sam", "sam, after", "sam, before", "sam, to pat"]);
    assert_eq!(read_all(&mut a.client, AVERY).await, everything, "avery reads every post, pat's included");
    assert_eq!(read_all(&mut s.client, SAM).await, everything, "sam reads every post");
    assert_eq!(
        read_all(&mut p.client, PAT).await,
        sorted(&["avery, after", "pat, admitted by sam", "sam, after", "sam, to pat"]),
        "pat reads from their admission on, sam's next post included"
    );
    assert_eq!(
        read_all(&mut j.client, JORDAN).await,
        sorted(&["pat, admitted by sam", "sam, before", "sam, to pat"]),
        "jordan reads nothing after the removal"
    );

    // Avery's post after the removal, handed to Jordan directly, does not open.
    let averys = a.client.message_channel_history(AVERY, CHANNEL, None, 50).await.expect("avery's history");
    let after = averys.iter().max_by_key(|m| m["epoch"].as_u64().unwrap_or(0)).expect("a message after the removal");
    assert_eq!(after["epoch"].as_u64(), Some(4), "create, three admissions and a removal are five epochs");
    let err = j
        .client
        .message_decrypt_channel(JORDAN, CHANNEL, after["body"].as_str().expect("body"), after["nonce"].as_str().expect("nonce"))
        .await
        .expect_err("jordan must not read a message sealed after the removal, even given it");
    assert!(err.to_string().contains("epoch you do not hold"), "{err}");

    // Jordan posts at the epoch they still hold, which every remaining member
    // holds too and could open. Each remaining member's door refuses it, naming
    // the epoch they are at, and none files it.
    let (_id, from_jordan) = j
        .client
        .message_channel_send_with_fanout(JORDAN, CHANNEL, "jordan, removed")
        .await
        .expect("jordan's own copy is written; the doors answer for themselves");
    assert_eq!(from_jordan.len(), 3, "jordan's node still reads the epoch it holds: {from_jordan:?}");
    for m in &from_jordan {
        let Delivery::Unreachable { reason } = &m.delivery else {
            panic!("a remaining member's door took jordan's post: {from_jordan:?}")
        };
        assert!(reason.contains("at epoch 4"), "the refusal names the epoch: {reason}");
    }
    assert_eq!(read_all(&mut a.client, AVERY).await, everything, "nothing of jordan's is filed at avery's");
    assert_eq!(read_all(&mut s.client, SAM).await, everything, "nothing of jordan's is filed at sam's");
}

/// **A member leaves by saying so, and one remaining member rotates**
/// (`TASK-a-member-leaves-a-channel-by-saying-so-and-one-remaining-member-rotates`)
/// — **and the leaver and the elector never paired**
/// (`TASK-a-channel-member-who-is-not-the-senders-contact-never-receives-the-senders-copies`).
///
/// Four people on four daemons. Who is who is read from their DIDs, which are
/// random: the one whose DID sorts first leaves, so the one who sorts second
/// is the elector — the first DID in the roster without the leaver. Those two
/// are the one pair that never paired; everybody else pairs with everybody.
/// The admitter is the one who sorts last, a contact of all three, and makes
/// the household and admits the others: epoch 3 is all four's. The roster each
/// grant carries names every member with the key and the reach note the
/// admitter's cards hold, so the leaver's node and the elector's each open a
/// door for the other, and each one's post reaches the other.
///
/// The leaver's node posts a `leave` notice into the channel, handed to the
/// other three — to the elector by the roster — and drops every key it holds
/// for it. The elector's node rotates once, on filing the notice, to epoch 4
/// for the three of them, and the other two wait for it. So:
///
/// - each remaining node holds **exactly one** grant of its own at epoch 4,
///   and none newer — one epoch, everywhere;
/// - the two who did not rotate read on at it, each other's posts and the
///   elector's;
/// - the leaver's node holds no grant for the channel, the share sheet's
///   groups no longer list it, and the leaver reads nothing said after the
///   notice — nothing reaches their store, and a post handed to them directly
///   does not open; what their store held stays in it;
/// - every remaining member keeps the notice in the channel.
///
/// Red when the elector rule is removed: every remaining node rotates on the
/// notice, each mints its own epoch 4 and takes the others', and the epoch
/// forks. Red when the leaver keeps a grant. Red when a copy to a member who
/// is not the sender's contact is dropped: the leaver's post never reaches the
/// elector, the elector never files the notice, and nobody rotates.
#[tokio::test]
async fn a_member_leaves_by_saying_so_and_the_elector_alone_rotates() {
    use crate::common::{self, TestEnv, TEST_PASSPHRASE};
    use crate::contact_pairing::{mailbox_open_for, pair_as};
    use kotton_app::daemon::apps::OccupantHost as _;
    use kotton_wire::ipc::Delivery;
    const GRANT: &str = "sh.kotton.channel.key-grant";
    const LEAVING: &str = "did:key:zHouseholdLeave";

    let (relay, relay_addr) = common::relay::spawn().await;
    let mut people: Vec<(TestEnv, &'static str, String)> = Vec::new();
    for user in ["avery", "sam", "jordan", "pat"] {
        let mut env = common::relay::env_on(&relay_addr).await;
        let (did, _) = env.client.create_user(user, TEST_PASSPHRASE).await.unwrap_or_else(|e| panic!("{user}: {e}"));
        people.push((env, user, did));
    }
    let _relay = relay;
    // Who is who, from the DIDs: 0 leaves, 1 is the elector, 3 admits.
    people.sort_by(|a, b| a.2.cmp(&b.2));
    let (leaver, elector, other, admitter) = (0usize, 1usize, 2usize, 3usize);
    let did = |people: &[(TestEnv, &str, String)], i: usize| people[i].2.clone();
    fn name(people: &[(TestEnv, &'static str, String)], i: usize) -> &'static str {
        people[i].1
    }
    eprintln!(
        "{} leaves; {} is the elector and never paired with them; {} admits",
        name(&people, leaver),
        name(&people, elector),
        name(&people, admitter)
    );

    // Everyone knows everyone but the leaver and the elector, who know each
    // other only from the roster.
    for i in 0..4 {
        for j in (i + 1)..4 {
            if (i, j) == (leaver, elector) {
                continue;
            }
            pair_as(&people[i].0, people[i].1, &people[j].0, people[j].1).await;
        }
    }
    for (i, (env, user, _)) in people.iter_mut().enumerate() {
        let contacts = if i == leaver || i == elector { 2 } else { 3 };
        mailbox_open_for(env, user, contacts).await;
    }

    async fn grants(env: &mut TestEnv, user: &str) -> Vec<serde_json::Value> {
        env.client
            .record_query(user, GRANT, vec![("channel_did".to_string(), serde_json::json!(LEAVING))], None, None)
            .await
            .expect("grants")
    }
    async fn holds_epoch(env: &mut TestEnv, user: &str, epoch: u64) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while !grants(env, user).await.iter().any(|g| g["epoch"].as_u64() == Some(epoch)) {
            assert!(std::time::Instant::now() < deadline, "{user} was never granted epoch {epoch}");
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    }
    /// The epochs of the grants addressed to `did` in their own store, sorted.
    async fn own_epochs(env: &mut TestEnv, user: &str, did: &str) -> Vec<u64> {
        let mut epochs: Vec<u64> = grants(env, user)
            .await
            .iter()
            .filter(|g| g["to_did"] == did)
            .map(|g| g["epoch"].as_u64().unwrap_or(0))
            .collect();
        epochs.sort();
        epochs
    }
    async fn read_all(client: &mut kotton::KottonClient, user: &str) -> Vec<String> {
        let history = client.message_channel_history(user, LEAVING, None, 50).await.expect("history");
        let mut read = Vec::new();
        for msg in history.iter().filter(|m| m["type"] == "text") {
            if let Ok(text) = client
                .message_decrypt_channel(user, LEAVING, msg["body"].as_str().expect("body"), msg["nonce"].as_str().expect("nonce"))
                .await
            {
                read.push(text);
            }
        }
        read.sort();
        read
    }
    fn handed_to(who: &str, fanout: &[kotton_wire::ipc::MemberDelivery], to: &[String]) {
        let mut named: Vec<&str> = fanout.iter().map(|m| m.member_did.as_str()).collect();
        named.sort();
        let mut want: Vec<&str> = to.iter().map(|d| d.as_str()).collect();
        want.sort();
        assert_eq!(named, want, "{who}'s post goes to every other current member: {fanout:?}");
        assert!(
            fanout.iter().all(|m| matches!(m.delivery, Delivery::Delivered | Delivery::AlreadyHeld)),
            "a copy of {who}'s post was not handed over: {fanout:?}"
        );
    }
    let others_than = |people: &[(TestEnv, &str, String)], me: usize, among: &[usize]| -> Vec<String> {
        among.iter().filter(|i| **i != me).map(|i| people[*i].2.clone()).collect()
    };

    // Epochs: 0 is the admitter's alone; admitting the other three mints 1, 2, 3.
    let admitting = name(&people, admitter);
    people[admitter].0.client.message_channel_create(admitting, LEAVING).await.expect("create the channel");
    for i in [other, elector, leaver] {
        let member = did(&people, i);
        people[admitter]
            .0
            .client
            .message_channel_grant_key(admitting, LEAVING, &member, false)
            .await
            .unwrap_or_else(|e| panic!("admit {member}: {e}"));
    }
    for (env, user, _) in people.iter_mut() {
        holds_epoch(env, user, 3).await;
    }
    // The leaver and the elector each open a door for the other, from the
    // roster: two contacts' and one co-member's.
    for i in [leaver, elector] {
        let user = people[i].1;
        mailbox_open_for(&mut people[i].0, user, 3).await;
    }

    let all = [leaver, elector, other, admitter];
    let mut before = Vec::new();
    for i in [other, leaver, elector] {
        let (user, text) = (people[i].1, format!("{}, before the leave", people[i].1));
        let (_id, fanout) = people[i]
            .0
            .client
            .message_channel_send_with_fanout(user, LEAVING, &text)
            .await
            .unwrap_or_else(|e| panic!("{user} posts: {e}"));
        handed_to(user, &fanout, &others_than(&people, i, &all));
        before.push(text);
    }
    before.sort();
    for i in all {
        let user = people[i].1;
        assert_eq!(read_all(&mut people[i].0.client, user).await, before, "{user} reads every post while all four are in");
    }

    // The leaver leaves: the notice to each of the three, the elector by the
    // roster and last, then the keys go.
    let leaving = name(&people, leaver);
    let (_id, fanout) = people[leaver].0.client.message_channel_leave(leaving, LEAVING).await.expect("the leaver leaves");
    handed_to("the leave notice", &fanout, &others_than(&people, leaver, &all));

    // One epoch, everywhere: each remaining node holds exactly one grant of
    // its own at epoch 4 and none newer — the elector's, and no other.
    let remaining = [elector, other, admitter];
    for i in remaining {
        let (user, own) = (people[i].1, people[i].2.clone());
        holds_epoch(&mut people[i].0, user, 4).await;
        let epochs = own_epochs(&mut people[i].0, user, &own).await;
        let at_four = epochs.iter().filter(|e| **e == 4).count();
        assert_eq!((at_four, epochs.last()), (1, Some(&4)), "{user}: the epoch forked, or was not minted once: {epochs:?}");
    }
    // The elector wrote every grant of epoch 4: their store holds one for each
    // of the three, and none for the leaver.
    let electing = name(&people, elector);
    let mut granted: Vec<String> = grants(&mut people[elector].0, electing)
        .await
        .iter()
        .filter(|g| g["epoch"].as_u64() == Some(4))
        .map(|g| g["to_did"].as_str().expect("to_did").to_string())
        .collect();
    granted.sort();
    let mut three: Vec<String> = remaining.iter().map(|i| people[*i].2.clone()).collect();
    three.sort();
    assert_eq!(granted, three, "{electing} granted epoch 4 to the three who remain, and only them");

    // The leaver's node holds no key for the channel, and the share sheet does
    // not offer it; a remaining member's sheet offers it, three people.
    assert_eq!(grants(&mut people[leaver].0, leaving).await, Vec::<serde_json::Value>::new(), "the leaver's node kept a grant");
    assert!(
        people[leaver].0.daemon.occupant_host().message_groups().await.expect("the leaver's groups").is_empty(),
        "the leaver's sheet offers the channel"
    );
    let groups = people[other].0.daemon.occupant_host().message_groups().await.expect("a remaining member's groups");
    assert_eq!(groups.iter().map(|g| (g.channel_did.as_str(), g.members)).collect::<Vec<_>>(), vec![(LEAVING, 3)]);

    // The other two read on at the elector's epoch, and so does the elector.
    let mut everything = before.clone();
    for i in remaining {
        let user = people[i].1;
        let text = format!("{user}, after the leave");
        let (_id, fanout) =
            people[i].0.client.message_channel_send_with_fanout(user, LEAVING, &text).await.expect("a post");
        handed_to(user, &fanout, &others_than(&people, i, &remaining));
        everything.push(text);
    }
    everything.sort();
    let leaver_did = did(&people, leaver);
    for i in remaining {
        let user = people[i].1;
        assert_eq!(read_all(&mut people[i].0.client, user).await, everything, "{user} reads every post, before and after");
        let history = people[i].0.client.message_channel_history(user, LEAVING, None, 50).await.expect("history");
        let notices: Vec<&serde_json::Value> = history.iter().filter(|m| m["type"] == "leave").collect();
        assert_eq!(notices.len(), 1, "{user} keeps the leaver's notice in the channel: {history:?}");
        assert_eq!(notices[0]["from_did"], leaver_did.as_str());
    }

    // The leaver reads nothing after the notice: nothing of it reached their
    // store, and a post handed to them directly does not open. What their
    // store held is still in it — the posts from before, and their own notice.
    let theirs = people[leaver].0.client.message_channel_history(leaving, LEAVING, None, 50).await.expect("their history");
    let mut types: Vec<&str> = theirs.iter().map(|m| m["type"].as_str().unwrap_or("")).collect();
    types.sort();
    assert_eq!(types, ["leave", "text", "text", "text"], "the leaver's store holds what it held, and nothing after: {theirs:?}");
    let admitters = people[admitter]
        .0
        .client
        .message_channel_history(admitting, LEAVING, None, 50)
        .await
        .expect("the admitter's history");
    let after = admitters.iter().find(|m| m["epoch"].as_u64() == Some(4)).expect("a post at epoch 4");
    let err = people[leaver]
        .0
        .client
        .message_decrypt_channel(leaving, LEAVING, after["body"].as_str().expect("body"), after["nonce"].as_str().expect("nonce"))
        .await
        .expect_err("the leaver must not read what was said after they left, even given it");
    assert!(err.to_string().contains("no channel key grant"), "{err}");
}

/// Backfill is the admitter's deliberate choice, made per admission.
///
/// The same mechanism that closes the history also opens it: granting the
/// earlier epochs is an act, so "does joining a household channel show you
/// yesterday's conversation?" stops being one answer fixed for everybody and
/// becomes something the person doing the admitting decides.
#[tokio::test]
async fn backfill_is_granted_by_the_admitter_and_opens_the_history() {
    let env = TestEnv::spawn().await;
    let (_a, mut avery) = identity(&env, AVERY).await;
    let (sam_did, mut sam) = identity(&env, SAM).await;

    avery
        .message_channel_create(AVERY, CHANNEL)
        .await
        .expect("create channel");
    avery
        .message_channel_send(AVERY, CHANNEL, "before sam joined")
        .await
        .expect("avery posts alone");

    avery.contact_add(AVERY, &sam_did).await.expect("admit sam");
    avery
        .message_channel_grant_key(AVERY, CHANNEL, &sam_did, true)
        .await
        .expect("admit sam with the history");

    // Same ciphertext as the refused case above — the difference is only which
    // epochs sam was granted.
    let averys = avery
        .message_channel_history(AVERY, CHANNEL, None, 50)
        .await
        .expect("avery reads");
    let earlier = averys
        .iter()
        .find(|m| m["epoch"].as_u64() == Some(0))
        .expect("the epoch-0 message");

    let plaintext = sam
        .message_decrypt_channel(
            SAM,
            CHANNEL,
            earlier["body"].as_str().expect("body"),
            earlier["nonce"].as_str().expect("nonce"),
        )
        .await
        .expect("a backfilled member can read what came before");
    assert_eq!(plaintext, "before sam joined");
}

/// A rotation must carry the existing membership across, not quietly evict it.
///
/// This is the easiest thing to get wrong: admission mints a new key, the sender
/// moves to it on their very next message, and anyone not re-granted would
/// silently stop being able to read a channel they are still in. Three people
/// are needed to catch it — with two, the only other member is the granter.
#[tokio::test]
async fn admitting_a_third_person_does_not_evict_the_second() {
    let env = TestEnv::spawn().await;
    let (_a, mut avery) = identity(&env, AVERY).await;
    let (sam_did, mut sam) = identity(&env, SAM).await;
    let (jordan_did, _jordan) = identity(&env, "jordan").await;

    avery
        .message_channel_create(AVERY, CHANNEL)
        .await
        .expect("create channel");
    avery.contact_add(AVERY, &sam_did).await.expect("admit sam");
    avery
        .message_channel_grant_key(AVERY, CHANNEL, &sam_did, false)
        .await
        .expect("grant to sam");

    // A second admission rotates the key again, off the epoch sam holds.
    avery
        .contact_add(AVERY, &jordan_did)
        .await
        .expect("admit jordan");
    avery
        .message_channel_grant_key(AVERY, CHANNEL, &jordan_did, false)
        .await
        .expect("grant to jordan");

    avery
        .message_channel_send(AVERY, CHANNEL, "everyone is here")
        .await
        .expect("avery posts");

    let history = sam
        .message_channel_history(SAM, CHANNEL, None, 50)
        .await
        .expect("sam reads");
    let msg = history
        .first()
        .expect("sam is still a member and must still receive messages");
    let plaintext = sam
        .message_decrypt_channel(
            SAM,
            CHANNEL,
            msg["body"].as_str().expect("body"),
            msg["nonce"].as_str().expect("nonce"),
        )
        .await
        .expect("sam must still be able to read after someone else joined");
    assert_eq!(plaintext, "everyone is here");
}

/// Rotation must not cost the granter their own history.
///
/// avery posts at epoch 0, admits sam (which rotates to epoch 1), and must still
/// be able to read what they wrote before — they hold both epochs. Without this,
/// making membership structural would quietly delete the past for the one person
/// who was always there, which the identity-continuity invariant forbids.
#[tokio::test]
async fn rotating_does_not_close_the_granters_own_earlier_messages() {
    let env = TestEnv::spawn().await;
    let (_a, mut avery) = identity(&env, AVERY).await;
    let (sam_did, _sam) = identity(&env, SAM).await;

    avery
        .message_channel_create(AVERY, CHANNEL)
        .await
        .expect("create channel");
    avery
        .message_channel_send(AVERY, CHANNEL, "the first thing said here")
        .await
        .expect("avery posts");

    avery.contact_add(AVERY, &sam_did).await.expect("admit sam");
    avery
        .message_channel_grant_key(AVERY, CHANNEL, &sam_did, false)
        .await
        .expect("grant");

    let history = avery
        .message_channel_history(AVERY, CHANNEL, None, 50)
        .await
        .expect("avery reads");
    let earlier = history
        .iter()
        .find(|m| m["epoch"].as_u64() == Some(0))
        .expect("the epoch-0 message is still there");

    let plaintext = avery
        .message_decrypt_channel(
            AVERY,
            CHANNEL,
            earlier["body"].as_str().expect("body"),
            earlier["nonce"].as_str().expect("nonce"),
        )
        .await
        .expect("the granter keeps every epoch they have held");
    assert_eq!(plaintext, "the first thing said here");
}

/// A person who rotates their identity key keeps the channels they were already in
/// (`TASK-a-channel-key-grant-wrapped-to-a-retired-identity-key-does-not-open`).
///
/// Every grant below is wrapped before either rotation: Avery's own, to Avery's
/// key, and Sam's, wrapped by Avery to Sam's key. Both people then rotate with
/// their recovery phrases, and each still opens the channel with
/// `MessageDecryptChannel` — through the retired key their own node kept, since
/// the current one opens none of those grants. The fallback widens nothing: Sam,
/// admitted without the history, still cannot read what came before, retired
/// keys or not.
#[tokio::test]
async fn a_grant_wrapped_before_a_rotation_still_opens_the_channel_after_it() {
    let env = TestEnv::spawn().await;
    let (_a, mut avery) = identity(&env, AVERY).await;
    let (sam_did, mut sam) = identity(&env, SAM).await;

    avery
        .message_channel_create(AVERY, CHANNEL)
        .await
        .expect("create channel");
    avery
        .message_channel_send(AVERY, CHANNEL, "before sam joined")
        .await
        .expect("avery posts alone");
    avery.contact_add(AVERY, &sam_did).await.expect("admit sam");
    avery
        .message_channel_grant_key(AVERY, CHANNEL, &sam_did, false)
        .await
        .expect("grant sam the current epoch only");
    avery
        .message_channel_send(AVERY, CHANNEL, "dinner at seven")
        .await
        .expect("avery posts to both");

    let averys = avery
        .message_channel_history(AVERY, CHANNEL, None, 50)
        .await
        .expect("avery reads");
    let sams = sam
        .message_channel_history(SAM, CHANNEL, None, 50)
        .await
        .expect("sam reads");
    let at = |history: &[serde_json::Value], epoch: u64| {
        let m = history
            .iter()
            .find(|m| m["epoch"].as_u64() == Some(epoch))
            .unwrap_or_else(|| panic!("an epoch-{epoch} message in {history:?}"));
        (
            m["body"].as_str().expect("body").to_string(),
            m["nonce"].as_str().expect("nonce").to_string(),
        )
    };
    let (first_body, first_nonce) = at(&averys, 0);
    let (dinner_body, dinner_nonce) = at(&sams, 1);

    // Both rotate: a new identity key each, the same identities.
    for (client, user) in [(&mut avery, AVERY), (&mut sam, SAM)] {
        let phrase = client.add_recovery_phrase(user).await.expect("recovery phrase");
        let new_key = client.rotate_identity(user, &phrase, Some(crate::common::TEST_PASSPHRASE)).await.expect("rotate_identity");
        assert_eq!(new_key.len(), 64, "a new operational key for {user}: {new_key}");
    }

    // The grant Avery wrapped to Sam's old key still opens on Sam's node.
    let opened = sam
        .message_decrypt_channel(SAM, CHANNEL, &dinner_body, &dinner_nonce)
        .await;
    assert_eq!(
        opened.as_deref().ok(),
        Some("dinner at seven"),
        "a member's grant wrapped before their rotation opens after it: {opened:?}"
    );

    // And Avery's own grants, wrapped to Avery's old key, open both epochs.
    for ((body, nonce), text) in [
        ((&first_body, &first_nonce), "before sam joined"),
        ((&dinner_body, &dinner_nonce), "dinner at seven"),
    ] {
        let opened = avery.message_decrypt_channel(AVERY, CHANNEL, body, nonce).await;
        assert_eq!(
            opened.as_deref().ok(),
            Some(text),
            "the creator's grants wrapped before the rotation open after it: {opened:?}"
        );
    }

    // Reach is unchanged: Sam holds no epoch-0 grant, and a retired key is no
    // substitute for one.
    let refused = sam
        .message_decrypt_channel(SAM, CHANNEL, &first_body, &first_nonce)
        .await;
    assert!(
        refused.is_err(),
        "sam was admitted without the history and must not read it: {refused:?}"
    );
}

/// A person who rotates their identity key still speaks in the channels they were
/// already in, and still admits people to them
/// (`TASK-a-person-who-rotated-cannot-post-to-or-admit-into-a-channel-they-were-in`).
///
/// Every grant Avery holds is wrapped before the rotation, to the key it retires.
/// After it, `MessageChannelSend` seals under the newest of them and
/// `MessageChannelGrantKey` proves membership with it and backfills the older
/// epochs to a newcomer — each opening a grant through the retired key Avery's own
/// node kept, since the current one opens none of them. Casey reading both earlier
/// epochs is what shows the backfill loop opened them, not only the newest.
#[tokio::test]
async fn a_person_who_rotated_posts_to_and_admits_into_a_channel_they_were_in() {
    let env = TestEnv::spawn().await;
    let (_a, mut avery) = identity(&env, AVERY).await;
    let (sam_did, _sam) = identity(&env, SAM).await;
    let (casey_did, mut casey) = identity(&env, "casey").await;

    avery
        .message_channel_create(AVERY, CHANNEL)
        .await
        .expect("create channel");
    avery
        .message_channel_send(AVERY, CHANNEL, "before sam joined")
        .await
        .expect("avery posts alone");
    avery.contact_add(AVERY, &sam_did).await.expect("admit sam");
    avery
        .message_channel_grant_key(AVERY, CHANNEL, &sam_did, false)
        .await
        .expect("grant sam");
    avery
        .message_channel_send(AVERY, CHANNEL, "dinner at seven")
        .await
        .expect("avery posts to both");

    let phrase = avery.add_recovery_phrase(AVERY).await.expect("recovery phrase");
    avery
        .rotate_identity(AVERY, &phrase, Some(crate::common::TEST_PASSPHRASE))
        .await
        .expect("rotate_identity");

    // Posting: the newest grant was wrapped to the retired key.
    avery
        .message_channel_send(AVERY, CHANNEL, "after the rotation")
        .await
        .expect("a person who rotated posts to a channel they were in");

    // Admitting, with the history: membership proved on the newest grant, and
    // every earlier epoch opened to be passed on.
    avery.contact_add(AVERY, &casey_did).await.expect("admit casey");
    avery
        .message_channel_grant_key(AVERY, CHANNEL, &casey_did, true)
        .await
        .expect("a person who rotated admits into a channel they were in");

    let history = avery
        .message_channel_history(AVERY, CHANNEL, None, 50)
        .await
        .expect("avery reads");
    for text in ["before sam joined", "dinner at seven", "after the rotation"] {
        let mut opened = None;
        for m in &history {
            let body = m["body"].as_str().expect("body");
            let nonce = m["nonce"].as_str().expect("nonce");
            if let Ok(plain) = casey.message_decrypt_channel("casey", CHANNEL, body, nonce).await {
                if plain == text {
                    opened = Some(plain);
                }
            }
        }
        assert_eq!(
            opened.as_deref(),
            Some(text),
            "casey, admitted with the history by a person who rotated, reads {text:?}"
        );
    }

    // And the admission's own epoch is one Avery speaks in.
    avery
        .message_channel_send(AVERY, CHANNEL, "welcome, casey")
        .await
        .expect("avery posts at the epoch the admission minted");
}

/// A token minted by a test daemon must not enter the machine-wide session
/// cache.
///
/// The cache lives at an ambient per-machine path keyed by `user_id` alone, so
/// it cannot tell which daemon issued a token. Before this, every integration
/// test wrote `sessions/<user>.session` into the developer's real Kotton
/// directory — and worse, `connect_as` against the *real* daemon would then
/// present a token a test daemon had minted. It is a soundness bug that merely
/// looked like test pollution.
#[tokio::test]
async fn a_test_daemons_token_never_reaches_the_machine_wide_cache() {
    let env = TestEnv::spawn().await;
    let user = "cache-scope-probe";

    // Whatever is on disk before — this test must not change it.
    let before = kotton::session_cache::load(user);

    let (_did, _client) = identity(&env, user).await;

    assert_eq!(
        kotton::session_cache::load(user),
        before,
        "a client connected to a named endpoint must not write the shared cache"
    );
}
