// SPDX-License-Identifier: AGPL-3.0-or-later
//! Two devices of one person, and one drive: a drive accepts a connection only
//! from a key in the set it admits, and pairing introduces a device's key to
//! that set.
//!
//! A drive is a tenancy on a vault. It holds no data keys, so it cannot read
//! the person's member list; the enrolment admits the device that ran it, and
//! every other device of the person's is introduced to it by the device that
//! admitted that one — a `TenantDevice` request, signed under the identity —
//! and withdrawn the same way at `device revoke` (`kvaultd::devices`,
//! `kotton_device::users::drive_devices`).
//!
//! Real daemons throughout: an in-process `kvaultd::Vault`, and two device
//! daemons paired through the streamed ceremony. Nothing is mocked.

use crate::common::{connect_when_ready, enroll_streamed_as, free_port, init_crypto};
use crate::vault::{enrol_vault_from, recover_from, spawn_device, spawn_vault, tenants_at_the_door, try_ask_the_vault_as, RunningDevice, RunningVault, VaultIdentity};
use kotton::SyncDirection;
use kotton_schemas::membership::Posture;
use kotton_wire::ipc::{TenantDeviceAct, TenantDeviceChange, UserRequest, UserResponse};
use kotton_wire::remote::RemoteBackend;

const USER: &str = "alice";

/// How many of `user`'s devices the vault pairs, as `kvaultd tenants` prints it.
async fn devices_at(vault: &RunningVault, user: &str) -> u32 {
    tenants_at_the_door(&vault.ipc)
        .await
        .into_iter()
        .find(|t| t.user_id == user)
        .map(|t| t.devices)
        .unwrap_or(0)
}

/// What the vault answers `device`, dialling it under its own key, for `alice`'s capacity.
async fn capacity_as(device: &RunningDevice, vault: &VaultIdentity) -> Result<UserResponse, String> {
    let request = serde_json::to_vec(&UserRequest::VaultCapacity { user_id: USER.into() }).unwrap();
    try_ask_the_vault_as(device, vault, request).await
}

/// Whether the vault answered as to a device it admits for `alice`.
fn admitted(answer: &Result<UserResponse, String>) -> bool {
    matches!(answer, Ok(UserResponse::VaultCapacityResult { .. }))
}

/// The person's first device A, with their identity and a drive it enrolled.
async fn a_person_with_a_drive(vault: &RunningVault) -> (RunningDevice, kotton::KottonClient, VaultIdentity) {
    let a = spawn_device("device A").await;
    let mut client_a = connect_when_ready(&a.ipc, "client A").await;
    client_a.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user on A");
    let (client_a, drive) = enrol_vault_from(client_a, "device-a", vault, USER, "vault").await;
    (a, client_a, drive)
}

/// **The device that admits a new device introduces it to the person's drive,
/// and `device revoke` withdraws it.** A enrols the drive, then admits B; the
/// vault then pairs both of alice's devices, B reaches the drive under its own
/// key, and a file A pushes there is pulled by B from there. A revokes B, and
/// the drive pairs one device again and refuses B.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_its_admitter_introduces_reaches_the_persons_drive_until_revoked() {
    init_crypto();
    let vault = spawn_vault("vault").await;
    let (_a, client_a, drive) = a_person_with_a_drive(&vault).await;
    assert_eq!(devices_at(&vault, USER).await, 1, "the enrolment pairs the device that ran it");

    let b = spawn_device("device B").await;
    let client_b = connect_when_ready(&b.ipc, "client B").await;
    assert!(!admitted(&capacity_as(&b, &drive).await), "B is a stranger at the drive before it joins");

    let (mut client_a, mut client_b, node_b) =
        enroll_streamed_as(client_a, client_b, USER, "device-a", "device-b", free_port(), Posture::Full).await;
    assert_eq!(devices_at(&vault, USER).await, 2, "the drive pairs both of alice's devices");
    assert!(admitted(&capacity_as(&b, &drive).await), "B reaches the drive under its own key");

    // B learned the drive at the join, and pulls what A kept there.
    for client in [&mut client_a, &mut client_b] {
        let _ = client
            .remote_add(
                USER,
                "vault",
                RemoteBackend::Kotton { peer_did: drive.did.clone(), label: "vault".into() },
                None,
            )
            .await;
    }
    client_a.write_file(USER, "from-a.txt", b"written on A").await.expect("write on A");
    let pushed = client_a.sync_mount(USER, "local", "vault", Some(SyncDirection::Push)).await.expect("A pushes to the drive");
    assert!(pushed.pushed >= 1, "{pushed:?}");
    client_b.sync_mount(USER, "local", "vault", Some(SyncDirection::Pull)).await.expect("B pulls from the drive");
    assert_eq!(client_b.read_file(USER, "from-a.txt").await.expect("read on B"), b"written on A");

    client_a.node_revoke(USER, &node_b.id).await.expect("A revokes B");
    assert_eq!(devices_at(&vault, USER).await, 1, "the drive pairs one device again");
    assert!(!admitted(&capacity_as(&b, &drive).await), "the drive refuses the revoked device");
}

/// **A key nobody introduced is still refused**, and an introduction signed by
/// anything but the identity introduces nobody. C is a device that never
/// joined alice; A — a device the drive admits — sends the drive an admit for
/// C's key signed under A's own device key rather than the identity's, and the
/// drive refuses it and keeps refusing C.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_key_not_introduced_under_the_identity_is_refused_at_the_drive() {
    use ed25519_dalek::Signer as _;
    init_crypto();
    let vault = spawn_vault("vault").await;
    let (a, _client_a, drive) = a_person_with_a_drive(&vault).await;
    let c = spawn_device("device C").await;
    let mut client_c = connect_when_ready(&c.ipc, "client C").await;
    let (c_did, c_key_hex) = client_c.get_node_identity().await.expect("C's identity");

    let refused = capacity_as(&c, &drive).await;
    assert!(!admitted(&refused), "a key nobody introduced was admitted: {refused:?}");
    if let Ok(UserResponse::Error { message }) = &refused {
        assert!(message.contains(kotton_device::users::admission::NOT_PAIRED_WITH), "{message}");
    }

    let change = TenantDeviceChange {
        act: TenantDeviceAct::Admit,
        device_did: c_did,
        public_key: hex::decode(&c_key_hex).unwrap().try_into().unwrap(),
        said_at_ms: 1,
    };
    let not_the_identity = kotton_peer::daemon::nodes::load_device_operational_key(&*a.secrets).expect("A's device key");
    let signature = not_the_identity.sign(&change.signed_bytes(USER)).to_bytes().to_vec();
    let request = serde_json::to_vec(&UserRequest::TenantDevice { user_id: USER.into(), change, signature }).unwrap();
    let answer = try_ask_the_vault_as(&a, &drive, request).await.expect("A reaches the drive");
    match answer {
        UserResponse::Error { message } => assert!(message.contains("not signed under the tenant's identity"), "{message}"),
        other => panic!("an admit not signed under the identity was taken: {other:?}"),
    }
    assert_eq!(devices_at(&vault, USER).await, 1, "nobody was added");
    assert!(!admitted(&capacity_as(&c, &drive).await), "C is still refused");
}


/// The person's first device A, set up to recover from: their identity, a
/// recovery phrase, then a drive A enrolled — which is handed the sealed copy
/// the phrase opens — and a file A pushed to it. Returns A, the phrase and the drive.
async fn a_person_who_can_recover(vault: &RunningVault) -> (RunningDevice, String, VaultIdentity) {
    let a = spawn_device("device A").await;
    let mut client_a = connect_when_ready(&a.ipc, "client A").await;
    client_a.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user on A");
    let phrase = client_a.add_recovery_phrase(USER).await.expect("add_recovery_phrase on A");
    let (mut client_a, drive) = enrol_vault_from(client_a, "device-a", vault, USER, "vault").await;
    client_a.write_file(USER, "kept.txt", b"kept on the drive").await.expect("write on A");
    let pushed = client_a.sync_mount(USER, "local", "vault", Some(SyncDirection::Push)).await.expect("A pushes to the drive");
    assert!(pushed.pushed >= 1, "{pushed:?}");
    (a, phrase, drive)
}

/// What a drive record says, without the row it is reached through: the
/// vault's key and the tenancy, and the node's label and posture.
fn said_of(drives: &[kotton_peer::daemon::drives::Drive]) -> Vec<(String, String, String, Option<String>)> {
    drives
        .iter()
        .map(|d| (hex::encode(d.vault_key), d.tenancy.clone(), d.node.id.clone(), d.node.posture.clone()))
        .collect()
}

/// **A recovered device sees its vault as a drive.** A enrols the drive and is
/// lost; a cold device given only the phrase and the vault's line recovers, as
/// `kotton id recover` does, and its record names the vault's key and the
/// person's tenancy. Then it acts on it as on a drive: the recovered device
/// holds the identity, so when it admits a new device B it introduces B to the
/// drive, and B reaches the drive under its own key — which it could not when
/// the recovered device's vault was a row with no posture and no record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_recovered_device_sees_its_vault_as_a_drive_and_introduces_the_next_device_to_it() {
    init_crypto();
    let vault = spawn_vault("vault").await;
    let (phrase, drive) = {
        let (_a, phrase, drive) = a_person_who_can_recover(&vault).await;
        (phrase, drive)
    };

    let (r, mut client_r) = recover_from(&phrase, USER, &drive).await;
    assert_eq!(client_r.read_file(USER, "kept.txt").await.expect("read on R"), b"kept on the drive");
    let drives = r.daemon.drives(USER).await.expect("R's drives");
    assert_eq!(
        said_of(&drives),
        [(drive.pubkey_hex.clone(), USER.to_string(), "vault".to_string(), Some("blind-storage".to_string()))],
        "the recovered device does not record its vault as a drive"
    );

    let b = spawn_device("device B").await;
    let client_b = connect_when_ready(&b.ipc, "client B").await;
    assert!(!admitted(&capacity_as(&b, &drive).await), "B is a stranger at the drive before it joins");
    let (_client_r, _client_b, _node_b) =
        enroll_streamed_as(client_r, client_b, USER, "device-r", "device-b", free_port(), Posture::Full).await;
    assert!(admitted(&capacity_as(&b, &drive).await), "the recovered device did not introduce B to its drive");
}

/// **Enrolment and recovery record the same drive.** The record the device
/// that enrolled the vault keeps, and the record the device that recovered
/// from it keeps, are one: the vault's key, the person's tenancy, reached
/// through the node labelled as the person named it, whose row says
/// `blind-storage`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enrolment_and_recovery_record_the_same_drive() {
    init_crypto();
    let vault = spawn_vault("vault").await;
    let (enrolled, phrase, drive) = {
        let (a, phrase, drive) = a_person_who_can_recover(&vault).await;
        (said_of(&a.daemon.drives(USER).await.expect("A's drives")), phrase, drive)
    };
    assert_eq!(enrolled.len(), 1, "enrolment recorded {enrolled:?}");
    assert_eq!(enrolled[0].0, drive.pubkey_hex, "enrolment recorded another key than the vault's");

    let (r, _client_r) = recover_from(&phrase, USER, &drive).await;
    let recovered = said_of(&r.daemon.drives(USER).await.expect("R's drives"));
    assert_eq!(recovered, enrolled, "recovery recorded a drive other than the one enrolment recorded");
}

/// **A device that joins learns its person's drives at the join.** A enrols
/// a drive, then admits B. With nothing more — no `peer add`, and no sync pass
/// before — B records the drive A records (the vault's key, the person's
/// tenancy, the node it is reached through, `blind-storage`), the drive admits
/// B, and B's first `sync` takes what A wrote from it. The join carried the
/// drive both ways: to B, and B to the drive.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_that_joins_learns_the_persons_drives_at_the_join() {
    init_crypto();
    let vault = spawn_vault("vault").await;
    let (a, mut client_a, b, mut client_b, drive) = two_devices_and_a_drive(&vault).await;

    let enrolled = said_of(&a.daemon.drives(USER).await.expect("A's drives"));
    let joined = said_of(&b.daemon.drives(USER).await.expect("B's drives"));
    assert_eq!(
        joined,
        [(drive.pubkey_hex.clone(), USER.to_string(), "vault".to_string(), Some("blind-storage".to_string()))],
        "the joined device does not record the drive"
    );
    assert_eq!(joined, enrolled, "the joined device records another drive than the admitting one");
    assert!(admitted(&capacity_as(&b, &drive).await), "the drive does not admit the joined device");

    client_a.write_file(USER, "from-a.txt", b"written on A").await.expect("write on A");
    let pushed = synced(&mut client_a, "A").await;
    assert!(pushed.files >= 1, "A sent nothing to the drive: {pushed:?}");
    let first = synced(&mut client_b, "B").await;
    assert!(first.files >= 1, "B's first sync took nothing from the drive: {first:?}");
    assert_eq!(client_b.read_file(USER, "from-a.txt").await.expect("read on B"), b"written on A");
}

/// **A device learns a drive enrolled after it joined from the drive it
/// already syncs.** A enrols a first vault and admits B, which is introduced
/// to it; then A enrols a second vault, which is in the person's membership
/// set as A wrote it at that enrolment. B is told of the first drive, as a
/// drive, and syncs its drives: the pass pulls the person's things from the
/// first drive, the set among them, and reprojects it, so B's record then
/// names both drives — each vault's key and the person's tenancy — as A's
/// does. B never reached A: what it knows of the second drive came by way of
/// the first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_drive_enrolled_after_a_device_joined_reaches_that_device_by_way_of_a_drive() {
    init_crypto();
    let vault = spawn_vault("vault").await;
    let second = spawn_vault("second vault").await;
    let (a, client_a, _drive) = a_person_with_a_drive(&vault).await;

    let b = spawn_device("device B").await;
    let client_b = connect_when_ready(&b.ipc, "client B").await;
    let (client_a, mut client_b, _node_b) =
        enroll_streamed_as(client_a, client_b, USER, "device-a", "device-b", free_port(), Posture::Full).await;
    let (mut client_a, _second_drive) = enrol_vault_from(client_a, "device-a", &second, USER, "vault-2").await;
    let enrolled = said_of(&a.daemon.drives(USER).await.expect("A's drives"));
    assert_eq!(enrolled.len(), 2, "A records both drives: {enrolled:?}");
    client_a.write_file(USER, "from-a.txt", b"written on A").await.expect("write on A");
    synced(&mut client_a, "A").await;

    // B learned the first drive at the join; the second, enrolled after,
    // it learns from the first.
    let outcome = synced(&mut client_b, "B").await;
    assert!(outcome.files >= 1, "B pulled nothing from the drive: {outcome:?}");

    // The drive itself — the vault's key and the tenancy — not the label: the
    // second drive's node is the membership set's, named by its DID on B.
    let drive_of = |said: Vec<(String, String, String, Option<String>)>| -> Vec<(String, String)> {
        let mut d: Vec<(String, String)> = said.into_iter().map(|(key, tenancy, _, _)| (key, tenancy)).collect();
        d.sort();
        d
    };
    let joined = said_of(&b.daemon.drives(USER).await.expect("B's drives"));
    assert_eq!(drive_of(joined), drive_of(enrolled), "B does not record the drives A does");
}

/// `sync`, as the shell's bare verb runs it: this device's drives, now, and
/// the pass's outcome. Panics with `who` when it does not finish.
async fn synced(client: &mut kotton::KottonClient, who: &str) -> kotton_wire::ipc::SyncOutcome {
    let (job, drives) = client.sync_drives(USER).await.unwrap_or_else(|e| panic!("{who}'s sync: {e}"));
    assert!(drives >= 1, "{who} syncs no drive");
    client.sync_await(USER, job, 120).await.unwrap_or_else(|e| panic!("{who}'s sync pass: {e}"))
}

/// Two of alice's devices, A and B, and one drive both reach: A enrolled it and
/// admitted B, and the join carried the drive both ways — B to the drive, the
/// drive to B. Neither device listens for the other: no peer listener runs on
/// either.
async fn two_devices_and_a_drive(
    vault: &RunningVault,
) -> (RunningDevice, kotton::KottonClient, RunningDevice, kotton::KottonClient, VaultIdentity) {
    let (a, client_a, drive) = a_person_with_a_drive(vault).await;
    let b = spawn_device("device B").await;
    let client_b = connect_when_ready(&b.ipc, "client B").await;
    let (client_a, client_b, _node_b) =
        enroll_streamed_as(client_a, client_b, USER, "device-a", "device-b", free_port(), Posture::Full).await;
    (a, client_a, b, client_b, drive)
}

/// **A write on one device reaches the other only by way of the drive.** A
/// writes and runs `sync`; B runs `sync` and reads it. Nothing else moved it:
/// neither device listens, B's only route to A's writes is the drive, and the
/// drive holds them only as packs it cannot open. Then the other way: what B
/// writes reaches A the same way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_write_on_one_device_reaches_the_other_only_by_way_of_the_drive() {
    init_crypto();
    let vault = spawn_vault("vault").await;
    let (a, mut client_a, b, mut client_b, _drive) = two_devices_and_a_drive(&vault).await;
    // Neither device listens: there is no address at which one could reach the
    // other, so the drive is the only way between them.
    assert!(a.daemon.runtime().peer_listen_addr().is_none(), "A runs a peer listener");
    assert!(b.daemon.runtime().peer_listen_addr().is_none(), "B runs a peer listener");

    client_a.write_file(USER, "from-a.txt", b"written on A").await.expect("write on A");
    assert!(client_b.read_file(USER, "from-a.txt").await.is_err(), "B holds A's write before any sync");
    let pushed = synced(&mut client_a, "A").await;
    assert!(pushed.files >= 1, "A sent nothing to the drive: {pushed:?}");
    crate::vault::the_pool_holds_only_packs(&vault, USER);
    synced(&mut client_b, "B").await;
    assert_eq!(client_b.read_file(USER, "from-a.txt").await.expect("read on B"), b"written on A");

    client_b.write_file(USER, "from-b.txt", b"written on B").await.expect("write on B");
    synced(&mut client_b, "B").await;
    synced(&mut client_a, "A").await;
    assert_eq!(client_a.read_file(USER, "from-b.txt").await.expect("read on A"), b"written on B");
}

/// **A device is refused as a sync target.** B pairs A — the device that
/// admitted it — but a rule for it, an ad-hoc sync with it, and a peer remote
/// to it are each refused by name: a device syncs to its drives and never to
/// another device. And `sync` on B names the drive and nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_is_refused_as_a_sync_target() {
    init_crypto();
    let vault = spawn_vault("vault").await;
    let (_a, mut client_a, _b, mut client_b, _drive) = two_devices_and_a_drive(&vault).await;
    let (a_did, _) = client_a.get_node_identity().await.expect("A's identity");
    let a_node = client_b
        .list_nodes(USER)
        .await
        .expect("B's nodes")
        .into_iter()
        .find(|n| n.device_did.to_string() == a_did)
        .expect("B pairs A")
        .id;

    let rule = client_b.configure_sync(USER, &a_node, None, true).await.expect_err("a rule for A was kept");
    assert!(rule.to_string().contains("a device is not one"), "{rule}");
    let adhoc = client_b
        .sync_mount(USER, "local", &a_node, Some(SyncDirection::Pull))
        .await
        .expect_err("B synced with A");
    assert!(adhoc.to_string().contains("a device is not a sync target"), "{adhoc}");
    let remote = client_b
        .remote_add(USER, "a", RemoteBackend::Kotton { peer_did: a_did.clone(), label: "a".into() }, None)
        .await
        .expect_err("B opened A as a remote");
    assert!(remote.to_string().contains("a device is not a sync target"), "{remote}");
    assert!(client_b.list_sync_rules(USER).await.expect("B's rules").is_empty());

    let kept = client_b.configure_sync(USER, "vault", Some(SyncDirection::Pull), true).await.expect("a rule for the drive");
    assert_eq!(kept.drive, "vault");
    let (_job, drives) = client_b.sync_drives(USER).await.expect("B's sync");
    assert_eq!(drives, 1, "B's sync names its one drive and nothing else");
}

/// What a test whose subject is a second device of the person's receiving a
/// first one's things uses, now that devices reach each other's writes only by
/// way of a drive: a vault, enrolled as the person's drive by `client` — the
/// device holding the identity, which announces itself as `device_name` —
/// *before* the second device joins, so the join carries the drive both ways:
/// the drive learns the joining device, and the joining device learns the drive.
pub(crate) struct ADrive {
    pub(crate) _vault: RunningVault,
}

/// Enrol a fresh vault as `user`'s drive, labelled `vault`, from `client`.
pub(crate) async fn a_drive_for(client: kotton::KottonClient, device_name: &str, user: &str) -> (kotton::KottonClient, ADrive) {
    let vault = spawn_vault("vault").await;
    let (client, _) = enrol_vault_from(client, device_name, &vault, user, "vault").await;
    (client, ADrive { _vault: vault })
}

/// **A drive serving another key domain's packs**: what the key-domain gate is
/// for, now that a device syncs only with a drive.
///
/// What runs. Two people both named `user` — the one behind `owner`, and the
/// one behind `other` — each enrol a vault as their own drive, the way a
/// person enrols one. The owner keeps three files on theirs. The other keeps a
/// file on theirs too, so their vault records the other's key domain for the
/// mount (a vault records it on a mount's first sealed write). Then the
/// other's vault is made to serve the owner's pool whole, as it rests on the
/// owner's vault: its packs, and the key domain recorded for them — a
/// landlord's mistake or malice, which a vault that cannot open what it holds
/// cannot itself notice. A pull by the other then meets objects the vault says
/// are in the owner's key domain, which the other's device refuses at the
/// boundary (`KottonPeerObjectStorage::get_sealed`).
///
/// Returns both clients, the owner's three files, the two key domains (the
/// owner's, then the other's), and both vaults, which stay up while held.
pub(crate) async fn a_drive_serving_another_domains_packs(
    owner: kotton::KottonClient,
    other: kotton::KottonClient,
    user: &str,
) -> (
    kotton::KottonClient,
    kotton::KottonClient,
    Vec<(String, Vec<u8>)>,
    (String, String),
    (RunningVault, RunningVault),
) {
    let owners_vault = spawn_vault("the owner's vault").await;
    let others_vault = spawn_vault("the other's vault").await;
    let (mut owner, _) = enrol_vault_from(owner, "owners-device", &owners_vault, user, "vault").await;
    let files: Vec<(String, Vec<u8>)> = (1u8..=3).map(|i| (format!("obj{i}.bin"), vec![i; 64])).collect();
    for (name, body) in &files {
        owner.write_file(user, name, body).await.expect("the owner's write");
    }
    owner
        .sync_mount(user, "local", "vault", Some(SyncDirection::Push))
        .await
        .expect("the owner keeps their files on their drive");
    let (mut other, _) = enrol_vault_from(other, "others-device", &others_vault, user, "vault").await;
    other.write_file(user, "mine.txt", b"the other's own").await.expect("the other's write");
    other
        .sync_mount(user, "local", "vault", Some(SyncDirection::Push))
        .await
        .expect("the other keeps a file on their drive");

    let label = kotton_common::crypto::kdf_labels::sealed_mount_domain(user, "local");
    let domain_of = |vault: &RunningVault| {
        vault
            .vault
            .runtime()
            .secrets()
            .get_secret(&label)
            .expect("the vault's secrets read")
            .expect("the vault recorded the mount's key domain at its first sealed write")
    };
    let (owners_domain, others_domain) = (domain_of(&owners_vault), domain_of(&others_vault));
    assert_ne!(owners_domain, others_domain, "two people's key domains are one");

    // The owner's pool, whole, served as the other's.
    let pool = |vault: &RunningVault| vault.base_path.join("users").join(user).join("data");
    let (from, to) = (pool(&owners_vault), pool(&others_vault));
    std::fs::remove_dir_all(&to).expect("the other's pool cleared");
    copy_tree(&from, &to);
    others_vault
        .vault
        .runtime()
        .secrets()
        .set_secret(&label, &owners_domain)
        .expect("the owner's key domain recorded for the other's mount");
    (owner, other, files, (owners_domain, others_domain), (owners_vault, others_vault))
}

fn copy_tree(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).expect("the pool's directory");
    for entry in std::fs::read_dir(from).expect("the owner's pool").flatten() {
        let target = to.join(entry.file_name());
        if entry.path().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("a pool file copied");
        }
    }
}

/// The sealed objects a vault keeps for `USER` in `tree`, by key, with their bytes.
async fn sealed_in(vault: &RunningVault, tree: &str) -> Vec<(String, Vec<u8>)> {
    use kotton_device::users::residency::Residency as _;
    let pool = vault.vault.pools().get(USER).expect("the vault keeps a pool for the person");
    let mut out = Vec::new();
    for (key, _, _) in pool.list_sealed(tree, "").await.expect("the tree lists") {
        let blob = pool.read_sealed(tree, &key).await.expect("the object reads");
        out.push((key, blob));
    }
    out.sort();
    out
}

/// The drives a vault keeps for `USER`, by tree.
fn trees_at(vault: &RunningVault) -> Vec<String> {
    use kotton_device::users::residency::Residency as _;
    let pool = vault.vault.pools().get(USER).expect("the vault keeps a pool for the person");
    let mut trees: Vec<String> = pool.shelf_mounts().into_iter().map(|(tree, _)| tree).collect();
    trees.sort();
    trees
}

/// Where the device records the drive `name`: each vault's key and the tree.
async fn where_recorded(device: &RunningDevice, name: &str) -> Vec<(String, String)> {
    device
        .daemon
        .drives(USER)
        .await
        .expect("the drive record")
        .into_iter()
        .filter(|d| d.name == name)
        .map(|d| (hex::encode(d.vault_key), d.tree))
        .collect()
}

/// **Several drives for one person on one vault, and a drive moved between
/// two vaults, with every device following it** (kotton #56).
///
/// One fixture: alice's devices A and B, and two vaults she enrolled from A
/// before B joined, so B reaches both. Each vault keeps her first drive,
/// `personal`, the tree her devices sync. A makes a second drive, `photos`, on
/// the first vault, and objects sealed under her key are kept in it: the vault
/// then keeps two sealed trees for her, each with its own contents. B follows
/// the new drive at its next sync without being told, and lists it. A moves
/// `photos` to the second vault: the very sealed bytes are there under a tree
/// of their own, nothing of the drive is left at the first, and B's next sync
/// follows it there. `personal`, kept at both, does not move.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_vault_keeps_several_drives_and_a_moved_drive_is_followed_by_every_device() {
    use kotton_wire::ipc::FIRST_DRIVE_TREE;
    init_crypto();
    let first = spawn_vault("vault").await;
    let second = spawn_vault("second vault").await;
    let a = spawn_device("device A").await;
    let mut client_a = connect_when_ready(&a.ipc, "client A").await;
    client_a.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user on A");
    let (client_a, first_id) = enrol_vault_from(client_a, "device-a", &first, USER, "vault").await;
    let (client_a, second_id) = enrol_vault_from(client_a, "device-a", &second, USER, "vault-2").await;
    let b = spawn_device("device B").await;
    let client_b = connect_when_ready(&b.ipc, "client B").await;
    let (mut client_a, mut client_b, _node_b) =
        enroll_streamed_as(client_a, client_b, USER, "device-a", "device-b", free_port(), Posture::Full).await;

    // The first drive at each vault: what A's tree syncs with.
    client_a.write_file(USER, "from-a.txt", b"written on A").await.expect("write on A");
    synced(&mut client_a, "A").await;
    let domain = first
        .vault
        .runtime()
        .secrets()
        .get_secret(&kotton_common::crypto::kdf_labels::sealed_mount_domain(USER, FIRST_DRIVE_TREE))
        .expect("the vault's secrets read")
        .expect("the first drive pinned the person's key domain at its first write");

    // A second drive on the first vault.
    let made = client_a.drive_create(USER, "photos", Some("vault")).await.expect("drive create");
    assert_eq!(made.len(), 1, "{made:?}");
    assert_eq!((made[0].name.as_str(), made[0].vault_key.as_str()), ("photos", first_id.pubkey_hex.as_str()));
    let at_first = where_recorded(&a, "photos").await;
    assert_eq!(at_first.len(), 1, "{at_first:?}");
    let tree = at_first[0].1.clone();
    assert_ne!(tree, FIRST_DRIVE_TREE);
    let refused = client_a.drive_create(USER, "photos", Some("vault-2")).await.expect_err("a second drive called photos");
    assert!(refused.to_string().contains("already"), "{refused}");

    // Kept in it: two objects sealed under alice's key, as a device writes them.
    let objects: Vec<(String, Vec<u8>)> = vec![("p/one".into(), vec![1; 300]), ("p/two".into(), vec![2; 500])];
    for (key, body) in &objects {
        let request = serde_json::to_vec(&UserRequest::WriteSealed {
            user_id: USER.into(),
            mount: tree.clone(),
            path: key.clone(),
            blob: body.clone(),
            domain_id: domain.clone(),
            offset: 0,
            total_size: body.len() as u64,
            content_hash: blake3::hash(body).to_hex().to_string(),
        })
        .unwrap();
        let answer = try_ask_the_vault_as(&a, &first_id, request).await.expect("A reaches the vault");
        assert!(matches!(answer, UserResponse::Ok), "{answer:?}");
    }

    // Two drives on one vault, each a tree of its own.
    assert_eq!(trees_at(&first), {
        let mut t = vec![FIRST_DRIVE_TREE.to_string(), tree.clone()];
        t.sort();
        t
    });
    assert_eq!(sealed_in(&first, &tree).await, objects, "the second drive holds what was kept in it");
    let first_drive = sealed_in(&first, FIRST_DRIVE_TREE).await;
    assert!(!first_drive.is_empty(), "the first drive holds A's sync");
    assert!(
        first_drive.iter().all(|(key, _)| !objects.iter().any(|(k, _)| k == key)),
        "an object of the second drive is in the first"
    );

    // B follows the new drive at its next sync, told by nobody.
    assert!(where_recorded(&b, "photos").await.is_empty(), "B knew of photos before any pass");
    synced(&mut client_b, "B").await;
    assert_eq!(where_recorded(&b, "photos").await, at_first, "B's sync did not follow the new drive");
    let listed = client_b.drive_list(USER).await.expect("drive list on B");
    let mut said: Vec<(String, String)> = listed.iter().map(|d| (d.name.clone(), d.vault_key.clone())).collect();
    said.sort();
    let mut want = vec![
        ("personal".to_string(), first_id.pubkey_hex.clone()),
        ("personal".to_string(), second_id.pubkey_hex.clone()),
        ("photos".to_string(), first_id.pubkey_hex.clone()),
    ];
    want.sort();
    assert_eq!(said, want, "B's drive list");
    let photos = listed.iter().find(|d| d.name == "photos").unwrap();
    assert!(photos.size.unwrap_or(0) >= 800, "the drive's size is what it holds: {photos:?}");
    assert!(photos.pinned_whole.is_empty(), "no device pins a drive yet: {photos:?}");

    // The move: the sealed bytes to the second vault, under the same key.
    let first_drive = sealed_in(&first, FIRST_DRIVE_TREE).await;
    let moved = client_a.drive_move(USER, "photos", "vault-2", None).await.expect("drive move");
    assert_eq!(moved.len(), 1, "{moved:?}");
    assert_eq!(moved[0].vault_key, second_id.pubkey_hex);
    let now = where_recorded(&a, "photos").await;
    assert_eq!(now.len(), 1, "{now:?}");
    assert_eq!(now[0].0, second_id.pubkey_hex);
    let new_tree = now[0].1.clone();
    assert_ne!(new_tree, tree, "the second vault holds the drive under the id the first held");
    assert_eq!(sealed_in(&second, &new_tree).await, objects, "the second vault holds the very sealed bytes");
    assert_eq!(trees_at(&first), [FIRST_DRIVE_TREE.to_string()], "the first vault still keeps the moved drive");
    assert!(sealed_in(&first, FIRST_DRIVE_TREE).await == first_drive, "the move touched the first drive at the vault it left");

    // B follows it there at its next sync.
    synced(&mut client_b, "B").await;
    assert_eq!(where_recorded(&b, "photos").await, now, "B's sync did not follow the moved drive");
    let shown = client_b.drive_show(USER, "photos").await.expect("drive show on B");
    assert_eq!(shown.iter().map(|d| d.vault_key.as_str()).collect::<Vec<_>>(), [second_id.pubkey_hex.as_str()]);

    // The first drive is kept at both vaults and does not move.
    let refused = client_b.drive_move(USER, "personal", "vault-2", None).await.expect_err("personal moved");
    assert!(refused.to_string().contains("tenancy's own tree"), "{refused}");
}
