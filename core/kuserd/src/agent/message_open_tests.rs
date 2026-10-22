// SPDX-License-Identifier: AGPL-3.0-or-later
//! The occupant host opens a channel message that came from another member.
//!
//! Through a booted daemon, as `unlock_tests` drives the lock screen's door:
//! the host built by [`occupant_host::occupant_host`] over the daemon's own
//! context, its `messages.channel-history` listing what the person's store
//! holds, and its `messages.open` opening each line. Nothing here is a stand-in
//! for the host — the store, the keys and the grants are the daemon's.

use super::*;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use kotton_app::daemon::apps::OccupantHost as _;
use kotton_msg::daemon::messages::{self as msgs, MessageHost as _};
use kotton_msg::envelope::{ChannelCopy, DmInner};

const PASSPHRASE: &str = "canyon-orbit-velvet-fish-hospital";
const CHANNEL: &str = "did:key:zTheFerryThread";
const SAM: &str = "did:kel:sam";
const POST: &str = "the ferry leaves at 6:40, not 7";

/// A daemon booted at `base` with alice created and unlocked: her roots
/// restored from the passphrase vault, as an unlock after a restart restores
/// them.
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
        UserRequest::UnlockWithPin { user_id: "alice".into(), pin: kotton_wire::ipc::SecretText::new(PASSPHRASE), repair: false },
        kotton_ipc::Caller::anonymous(),
        Arc::new(std::sync::Mutex::new(None)),
    )
    .await
    .unwrap();
    assert!(matches!(resp, UserResponse::UnlockOk { .. }), "alice unlocks: {resp:?}");
    daemon
}

/// **The host opens a channel post from another member to its text, and a
/// channel share from them to its file's name.**
///
/// Alice holds the channel's key. Her own post and share give the channel's
/// ciphertext under that key; each is then filed again as the door files a
/// copy that arrived from Sam — by `messages::filed_record`, the function the
/// door's `file_message` writes with, so the record carries Sam as its author
/// and the **envelope's** `ephemeral_pub` beside the channel's `body` and
/// `nonce`. The door's own checks (Sam's signature, Sam in the roster) are not
/// what is under test, and are left to `delivery`'s tests; the record they
/// let through is.
///
/// Listed through the host and opened through the host, Sam's two lines read
/// as the post and the share's name, and so do alice's own. Opening a record
/// that carries an `ephemeral_pub` as a direct message turns this red.
#[tokio::test]
async fn the_host_opens_a_channel_message_from_another_member_and_a_share_to_its_name() {
    let temp = tempfile::tempdir().unwrap();
    let daemon = alice_unlocked(temp.path()).await;
    let ctx = daemon.agent_context();
    let host = occupant_host::occupant_host(
        &ctx.runtime,
        &ctx.users,
        &ctx.sessions,
        &ctx.base,
        &ctx.db,
        &ctx.record_stores,
        &ctx.ceremonies,
        &ctx.user_dbs,
        &ctx.event_log_tasks,
        &ctx.device_db,
        &ctx.connected_peers,
        &ctx.surface_proxy,
        ctx.browser_admissions(),
    );
    let msg = message_host::msg_host(&ctx.runtime, &ctx.users, &ctx.record_stores);
    let alice = msg.user_aid("alice").expect("alice's AID");
    // The host's person is the one this device lists, as `CreateUser` lists them.
    crate::device_users::register(temp.path(), "alice", &alice, None).unwrap();

    let created = msgs::message_channel_create(&msg, "alice".into(), CHANNEL.into()).await.unwrap();
    assert!(!matches!(created, UserResponse::Error { .. }), "alice creates the channel: {created:?}");
    host.message_channel_send(CHANNEL, POST).await.expect("alice posts");
    host.message_channel_share(CHANNEL, "beach.jpg", &[7u8; 2_000], None).await.expect("alice shares");
    let own = host.message_channel_history(CHANNEL, None, 50).await.expect("alice's channel");
    assert_eq!(own.len(), 2, "{own:?}");

    // Each, as it would be filed had Sam sent it to alice's door.
    for (i, line) in own.iter().enumerate() {
        assert_eq!(line.ephemeral_pub, None, "the sender's own copy carries no envelope key");
        let inner = DmInner {
            from_did: SAM.into(),
            to_did: alice.clone(),
            thread_id: "t".into(),
            sent_at: 1,
            kind: line.message_type.clone(),
            text: String::new(),
            channel: Some(ChannelCopy {
                channel_did: CHANNEL.into(),
                epoch: 1,
                body: B64.decode(&line.body).expect("the stored ciphertext is base64"),
                nonce: line.nonce.clone(),
            }),
            grant: None,
            reach: None,
            ack: None,
            kel: Vec::new(),
            share: None,
            range: None,
        };
        let envelope = kotton_wire::ipc::SealedDm {
            ephemeral_pub: B64.encode([i as u8 + 1; 32]),
            nonce: B64.encode([9u8; 12]),
            body: B64.encode(b"the envelope, finished with at the door"),
        };
        msg.record_insert("alice", kotton_common::namespace::NSID_MESSAGE_V1, msgs::filed_record(&inner, &envelope))
            .await
            .expect("filed as the door files it");
    }

    let lines = host.message_channel_history(CHANNEL, None, 50).await.expect("alice's channel");
    assert_eq!(lines.len(), 4, "{lines:?}");
    let (mut from_sam, mut hers) = (Vec::new(), Vec::new());
    for line in lines {
        let from = line.from_did.clone();
        let carried = line.ephemeral_pub.is_some();
        let opened = host
            .message_open(line)
            .await
            .unwrap_or_else(|e| panic!("a line from {from} does not open: {e}"));
        if from == SAM {
            assert!(carried, "sam's copy carries the envelope's key, as the door files it");
            from_sam.push(opened);
        } else {
            hers.push(opened);
        }
    }
    from_sam.sort();
    hers.sort();
    assert_eq!(from_sam, ["beach.jpg", POST], "another member's post opens to its text, and a share to its name");
    assert_eq!(hers, ["beach.jpg", POST], "and the sender's own copies open the same way");
}
