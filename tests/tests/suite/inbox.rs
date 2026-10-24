// SPDX-License-Identifier: AGPL-3.0-or-later
//! A file handed to a device of yours lands in Inbox
//! (`TASK-a-file-handed-to-a-device-of-yours-lands-in-inbox`, RFC-0090's unit 1).
//!
//! A hand-over to a device of the person's is a write into `Inbox/<name>` in their
//! own tree, and the replication model carries the tree to every device that holds
//! it (RFC-0071 R15, R16) — so these tests add no transport and drive none: one
//! device writes through the store's ordinary file write (the verb the shell's
//! `files.write` reaches through `PersonalTree::write`), the sync that already
//! carries the tree carries it, and the other device reads it back, byte for byte.
//! Each way, because the phone hands things to the computer as well.
//!
//! One carrier: the person's drive, a vault holding ciphertext between two
//! devices that never meet — a device recovered from the phrase, and a device
//! that joined. A device syncs to its drives and never to another device, so
//! the direct carrier these tests once drove — two devices pulling from each
//! other over the paired peer channel — left with the mesh; handing a thing
//! straight to a device nearby is a verb of its own, not a sync.
//!
//! Each also reads the roster the share sheet lists from — the occupant's own
//! `list-devices` — and holds the one fact the sheet filters on: a device of the
//! person's opens their files, a vault on the same roster does not.

use kotton::SyncDirection;
use kotton_app::daemon::apps::OccupantHost as _;
use kotton_schemas::membership::Posture;
use kotton_secret::MemorySecrets;
use kotton_sys::secret::SecretsStore;
use kuserd::DeviceDaemon;
use std::sync::Arc;

use crate::common::{connect_when_ready, enroll_streamed, init_crypto, unique_ipc, wait_for_daemon};
use crate::vault::{enrol_vault, recover_from, spawn_vault};

/// Bytes that are not text, so a transfer that re-encoded them anywhere fails
/// the comparison rather than passing it.
fn a_photo(seed: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

/// A device daemon whose handle the test keeps, so it can ask the occupant's
/// own verbs — what the share sheet reads.
struct KeptDevice {
    _base: tempfile::TempDir,
    ipc: crate::common::Door,
    daemon: Arc<DeviceDaemon>,
    _task: tokio::task::JoinHandle<std::io::Result<()>>,
}

async fn a_device(label: &str) -> KeptDevice {
    let base = tempfile::tempdir().expect("device base");
    let ipc = unique_ipc();
    let secrets: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    let daemon = Arc::new(
        DeviceDaemon::new_with_base_secrets_and_relay(
            base.path().to_owned(),
            ipc.clone(),
            secrets,
            kotton_device::config::db::RelayChoice::None,
        )
        .await
        .expect("device daemon"),
    );
    let task = tokio::spawn({
        let d = Arc::clone(&daemon);
        async move { d.run().await }
    });
    wait_for_daemon(&ipc, label).await;
    KeptDevice { _base: base, ipc, daemon, _task: task }
}

/// **Through a vault, each way.** The computer hands a photo to the phone: it
/// writes `Inbox/beach.jpg`, pushes to the vault Personal is kept at, and a
/// second device of the same person — one that has nothing but the phrase and
/// the vault — reads it back byte-identical. The phone hands a receipt back the
/// same way. Neither device ever reaches the other; the vault holds sealed
/// bytes between them. And the computer's roster, the one the sheet lists
/// from, carries the vault as a row that opens nothing.
#[tokio::test]
async fn a_file_handed_to_a_device_of_yours_lands_in_its_inbox_through_a_vault_each_way() {
    init_crypto();
    let vault = spawn_vault("vault").await;
    let pc = a_device("the computer").await;
    let mut client = connect_when_ready(&pc.ipc, "the computer's client").await;
    client
        .create_user("alice", crate::common::TEST_PASSPHRASE)
        .await
        .expect("create_user");
    let phrase = client.add_recovery_phrase("alice").await.expect("add_recovery_phrase");
    let (mut pc_client, identity) = enrol_vault(client, &vault, "alice", "vault").await;

    // The roster the sheet reads: the vault is on it, as a row that does not
    // open the person's files, so the sheet never offers it.
    let roster = pc.daemon.occupant_host().list_devices().await.expect("the roster");
    let row = roster
        .iter()
        .find(|d| d.did == identity.did)
        .expect("the enrolled vault is a row on the roster");
    assert!(!row.opens_your_files, "a vault read as a device that opens the person's files");

    // The computer hands a photo over: a write into Inbox, carried to the vault.
    let photo = a_photo(7, 70_000);
    pc_client
        .write_file("alice", "Inbox/beach.jpg", &photo)
        .await
        .expect("the hand-over's write");
    pc_client
        .sync_mount("alice", "local", "vault", Some(SyncDirection::Push))
        .await
        .expect("push to the vault");

    // The phone: the same person, with only the phrase and the vault.
    let (_phone_device, mut phone) = recover_from(&phrase, "alice", &identity).await;
    assert_eq!(
        phone.read_file("alice", "Inbox/beach.jpg").await.expect("the photo on the phone"),
        photo,
        "the photo did not arrive byte for byte"
    );
    let listed = phone.list_files("alice", "Inbox").await.expect("list Inbox on the phone");
    assert!(
        listed.iter().any(|f| f.trim_start_matches('/') == "Inbox/beach.jpg"),
        "Inbox on the phone does not list the photo: {listed:?}"
    );

    // And back: the phone hands a receipt to the computer the same way.
    let receipt = a_photo(91, 9_000);
    phone
        .write_file("alice", "Inbox/receipt.pdf", &receipt)
        .await
        .expect("the phone's write");
    phone
        .sync_mount("alice", "local", "vault", Some(SyncDirection::Push))
        .await
        .expect("the phone pushes to the vault");
    pc_client
        .sync_mount("alice", "local", "vault", Some(SyncDirection::Pull))
        .await
        .expect("the computer pulls from the vault");
    assert_eq!(
        pc_client.read_file("alice", "Inbox/receipt.pdf").await.expect("the receipt on the computer"),
        receipt,
        "the receipt did not arrive byte for byte"
    );
    // The photo it handed over is still where it put it: a hand-over is a copy.
    assert_eq!(pc_client.read_file("alice", "Inbox/beach.jpg").await.unwrap(), photo);
}

/// **To a device that joined, each way, by way of the drive.** Two devices of
/// one person, paired by the streamed ceremony: the computer enrols the
/// person's drive first, so the phone's join introduces the phone to it. The
/// computer writes `Inbox/beach.jpg` and syncs; the phone syncs and reads it;
/// the phone writes `Inbox/receipt.pdf` and syncs; the computer syncs and reads
/// it. Neither device reaches the other: a device syncs to its drives and never
/// to another device. The computer's roster lists the phone as a device that
/// opens the person's files — the row the sheet offers.
#[tokio::test]
async fn a_file_handed_to_a_joined_device_lands_in_its_inbox_by_way_of_the_drive_each_way() {
    init_crypto();
    let pc = a_device("the computer").await;
    let phone_device = a_device("the phone").await;

    let mut pc_client = connect_when_ready(&pc.ipc, "the computer's client").await;
    pc_client
        .create_user("alice", crate::common::TEST_PASSPHRASE)
        .await
        .expect("create_user");
    let (pc_client, _drive) = crate::drive_sync::a_drive_for(pc_client, "device-e", "alice").await;
    let phone_client = connect_when_ready(&phone_device.ipc, "the phone's client").await;
    let (mut pc_client, mut phone, phone_node) =
        enroll_streamed(pc_client, phone_client, "alice", "the phone", Posture::Full).await;

    let roster = pc.daemon.occupant_host().list_devices().await.expect("the roster");
    let row = roster
        .iter()
        .find(|d| d.did == phone_node.device_did.to_string())
        .expect("the phone is a row on the computer's roster");
    assert!(row.opens_your_files, "a device of the person's read as one that opens nothing");
    assert!(!row.is_this_device);
    assert_eq!(row.name.as_deref(), Some("the phone"), "the roster's name for the phone");

    // The phone learned the drive at the join; it is never told where the computer is.

    let photo = a_photo(3, 40_000);
    pc_client
        .write_file("alice", "Inbox/beach.jpg", &photo)
        .await
        .expect("the hand-over's write");
    pc_client
        .sync_mount("alice", "local", "vault", Some(SyncDirection::Push))
        .await
        .expect("the computer syncs to the drive");
    phone
        .sync_mount("alice", "local", "vault", Some(SyncDirection::Pull))
        .await
        .expect("the phone syncs from the drive");
    assert_eq!(
        phone.read_file("alice", "Inbox/beach.jpg").await.expect("the photo on the phone"),
        photo,
        "the photo did not arrive byte for byte"
    );

    let receipt = a_photo(200, 5_000);
    phone
        .write_file("alice", "Inbox/receipt.pdf", &receipt)
        .await
        .expect("the phone's write");
    phone
        .sync_mount("alice", "local", "vault", Some(SyncDirection::Push))
        .await
        .expect("the phone syncs to the drive");
    pc_client
        .sync_mount("alice", "local", "vault", Some(SyncDirection::Pull))
        .await
        .expect("the computer syncs from the drive");
    assert_eq!(
        pc_client.read_file("alice", "Inbox/receipt.pdf").await.expect("the receipt on the computer"),
        receipt,
        "the receipt did not arrive byte for byte"
    );
}
