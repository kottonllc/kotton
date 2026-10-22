// SPDX-License-Identifier: AGPL-3.0-or-later
//! A co-member's door opens, and a hand-over to them is dialled from the roster,
//! so a channel member who is not the sender's contact receives the sender's
//! copies.
//!
//! Through a booted daemon, as `message_open_tests` boots one: alice holds a
//! household channel whose roster names Sam — whom she never paired with —
//! with his key, his reach note and the key log that yields the key, and Pat
//! by DID alone, as a roster from
//! before keys travelled names a member. Nothing here stands in for the
//! mailbox, the host or the vault's window: they are the daemon's.

use super::*;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use kotton_crypto::reach_note::{self, RelayRef};
use kotton_msg::daemon::messages::{self as msgs, MessageHost as _, RosterMember};

const PASSPHRASE: &str = "canyon-orbit-velvet-fish-hospital";
const CHANNEL: &str = "did:key:zTheHousehold";
const PAT: &str = "did:kel:pat";
const SAMS_RELAY: &str = "https://relay.sam.example";

/// A daemon booted at `base` with alice created and unlocked — the boot
/// `message_open_tests` uses.
async fn alice_unlocked(base: &Path) -> DeviceDaemon {
    let keychain: Arc<dyn SecretsStore + Send + Sync> = Arc::new(kotton_secret::MemorySecrets::new());
    let runtime = DeviceRuntime::new_with_secrets(
        base.to_path_buf(),
        kotton_device::config::RuntimeConfig::default(),
        keychain.clone(),
    )
    .await
    .unwrap();
    runtime.create_user("alice", PASSPHRASE).await.unwrap();
    drop(runtime);
    #[cfg(unix)]
    let endpoint = IpcEndpoint::UnixSocket(base.join("kuserd.sock"));
    #[cfg(windows)]
    let endpoint = IpcEndpoint::NamedPipe(format!("kotton-test-{}", uuid::Uuid::new_v4().simple()));
    let daemon = DeviceDaemon::new_with_base_secrets_and_relay(base.to_path_buf(), endpoint, keychain, RelayChoice::None)
        .await
        .expect("the daemon boots");
    let resp = dispatch::handle_request(
        &daemon.agent_context(),
        kotton_wire::ipc::UserRequest::UnlockWithPin { user_id: "alice".into(), pin: kotton_wire::ipc::SecretText::new(PASSPHRASE), repair: false },
        kotton_ipc::Caller::anonymous(),
        Arc::new(std::sync::Mutex::new(None)),
    )
    .await
    .unwrap();
    assert!(matches!(resp, kotton_wire::ipc::UserResponse::UnlockOk { .. }), "alice unlocks: {resp:?}");
    daemon
}

/// **A co-member's door opens, keyed by the pair as a contact's is, and a
/// hand-over to them is dialled at the relay their roster note lists.**
///
/// Alice's grant for the household names Sam with his key, his note and his
/// log, and Pat with a key and no log. After the mailbox is rebuilt, alice's node holds one
/// door — for Sam's key — and none for Pat, whose key no log yields;
/// alice has no contacts, so it is the only door. A hand-over to Sam is dialled
/// at his note's relay; one to Pat finds no way. The vault is handed the pair's
/// window for Sam's key beside the contacts' — here, none.
///
/// Red when `mailbox::refresh` opens doors for contacts only, and when the
/// host dials from the card alone.
#[tokio::test]
async fn a_co_members_door_opens_and_a_hand_over_to_them_is_dialled_from_the_roster() {
    let temp = tempfile::tempdir().unwrap();
    let daemon = alice_unlocked(temp.path()).await;
    let ctx = daemon.agent_context();
    let msg = message_host::msg_host(&ctx.runtime, &ctx.users, &ctx.record_stores);
    let alice = msg.user_aid("alice").expect("alice's AID");
    let alice_key = kotton_peer::daemon::nodes::load_signing_key("alice", ctx.runtime.secrets()).expect("alice's key");
    // Sam, a `did:kel` identity of his own: his AID is his inception's digest,
    // and the roster carries his log beside his key, as a pairing keeps it.
    let sam = ed25519_dalek::SigningKey::from_bytes(&[2; 32]);
    let sam_pub = sam.verifying_key().to_bytes();
    let sam_log = vec![kotton_crypto::kel_verify::build_fresh_inception(&sam)];
    let sam_did = sam_log[0].aid.0.clone();
    let sam_did = sam_did.as_str();
    let now = kotton_peer::rendezvous::unix_now();
    let relay = RelayRef { key: None, addr: SAMS_RELAY.into(), admit: None };
    let sams_note = reach_note::next(None, sam_did, &[relay], &[], &sam, now).expect("sam's note");

    // Alice's grant at epoch 1: her key, wrapped to her, and the roster.
    let channel_key = kotton_crypto::x25519::channel_key_generate();
    let (enc_key, nonce, eph) =
        kotton_crypto::x25519::channel_key_wrap(&channel_key, &alice_key.verifying_key().to_bytes()).unwrap();
    let roster = msgs::seal_roster(
        &channel_key,
        &[
            RosterMember {
                did: alice.clone(),
                key: Some(alice_key.verifying_key().to_bytes()),
                reach: None,
                kel: msg.own_key_log("alice"),
            },
            RosterMember { did: sam_did.into(), key: Some(sam_pub), reach: Some(sams_note), kel: sam_log.clone() },
            // Pat with a key and no log: the roster's word alone, not believed.
            RosterMember {
                did: PAT.into(),
                key: Some(ed25519_dalek::SigningKey::from_bytes(&[4; 32]).verifying_key().to_bytes()),
                reach: None,
                kel: Vec::new(),
            },
        ],
    )
    .unwrap();
    let grant = serde_json::json!({
        "channel_did": CHANNEL,
        "to_did": alice,
        "enc_key": B64.encode(enc_key),
        "nonce": B64.encode(nonce),
        "ephemeral_pub": B64.encode(eph),
        "epoch": 1,
        "granted_at": now,
        "roster": roster.body,
        "roster_nonce": roster.nonce,
    });
    msg.record_insert("alice", kotton_common::namespace::NSID_CHANNEL_KEY_GRANT, grant).await.expect("the grant is filed");

    let co = msgs::co_members(&msg, "alice").await.expect("alice's co-members");
    assert_eq!(co.iter().map(|c| (c.did.as_str(), c.key)).collect::<Vec<_>>(), [(sam_did, sam_pub)], "sam, and not pat");

    assert!(
        mailbox::refresh(&ctx.runtime, &ctx.users, &ctx.record_stores, &mut mailbox::Kept::default()).await,
        "every read held"
    );
    let doors: Vec<[u8; 32]> =
        ctx.runtime.reachability().dm_inboxes().read().unwrap().iter().map(|d| d.contact_pub).collect();
    assert_eq!(doors, [sam_pub], "one door, sam's, keyed by his key as the roster carries it");

    let paths = msg.contact_paths("alice", sam_did).await.expect("sam is dialled from the roster");
    let relays: Vec<String> = paths
        .iter()
        .filter_map(|p| match p.way::<message_host::Way>() {
            Some(message_host::Way::Relay(r)) => Some(r.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(relays, [SAMS_RELAY], "at the relay his roster note lists");
    let err = msg.contact_paths("alice", PAT).await.expect_err("pat has no key to be dialled under");
    assert!(err.contains("not a contact"), "{err}");

    let store = ctx.users.get("alice").expect("alice is resident");
    assert!(
        vault_doors::doors_for(&store, &alice_key, &[]).await.unwrap().is_empty(),
        "alice has no contacts: no window without the co-member"
    );
    assert!(
        !vault_doors::doors_for(&store, &alice_key, &[sam_pub]).await.unwrap().is_empty(),
        "the vault is handed sam's window"
    );
}
