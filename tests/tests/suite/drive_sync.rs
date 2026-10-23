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

    // B is told where the drive is, as a device is, and pulls what A kept there.
    client_b
        .peer_add(USER, "vault", &drive.did, &drive.pubkey_hex, drive.op_addr)
        .await
        .expect("tell B where the drive is");
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

    let (r, mut client_r) = recover_from(&phrase, USER, &drive, "vault").await;
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

    let (r, _client_r) = recover_from(&phrase, USER, &drive, "vault").await;
    let recovered = said_of(&r.daemon.drives(USER).await.expect("R's drives"));
    assert_eq!(recovered, enrolled, "recovery recorded a drive other than the one enrolment recorded");
}

/// **A device that joins after the drive was enrolled learns it as a drive.**
/// A enrols the vault, then admits B. The vault is in the person's membership
/// set as A wrote it at the enrolment. B is told where the vault is by address
/// and key alone — a plain `peer add`, which says nothing of what the node
/// keeps — and its sync engine pulls the person's things from it, the set
/// among them; B's record then names the drive, the vault's key and the
/// person's tenancy, as A's does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_that_joins_after_the_drive_was_enrolled_records_it_as_a_drive() {
    init_crypto();
    let vault = spawn_vault("vault").await;
    let (a, client_a, drive) = a_person_with_a_drive(&vault).await;
    let enrolled = said_of(&a.daemon.drives(USER).await.expect("A's drives"));

    let b = spawn_device("device B").await;
    let client_b = connect_when_ready(&b.ipc, "client B").await;
    let (mut client_a, mut client_b, _node_b) =
        enroll_streamed_as(client_a, client_b, USER, "device-a", "device-b", free_port(), Posture::Full).await;
    client_a.write_file(USER, "from-a.txt", b"written on A").await.expect("write on A");
    client_a.sync_mount(USER, "local", "vault", Some(SyncDirection::Push)).await.expect("A pushes to the drive");

    client_b
        .peer_add(USER, "vault", &drive.did, &drive.pubkey_hex, drive.op_addr)
        .await
        .expect("tell B where the vault is, by address and key");
    assert!(b.daemon.drives(USER).await.expect("B's drives").is_empty(), "an address and a key made a drive");
    // The sync engine's pass, which reprojects the membership set it pulled
    // (`project_membership_into_allowlist`).
    client_b.configure_sync(USER, "vault", "/", false).await.expect("a sync rule for the drive on B");
    let job = client_b.sync_trigger(USER, Some("vault")).await.expect("trigger B's engine");
    let outcome = client_b.sync_await(USER, job, 120).await.expect("B's engine pass");
    assert!(outcome.files >= 1, "B pulled nothing from the drive: {outcome:?}");

    let joined = said_of(&b.daemon.drives(USER).await.expect("B's drives"));
    assert_eq!(joined, enrolled, "the joined device does not record the drive the enrolling device does");
}
