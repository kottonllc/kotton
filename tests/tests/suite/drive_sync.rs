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
use crate::vault::{enrol_vault_from, spawn_device, spawn_vault, tenants_at_the_door, try_ask_the_vault_as, RunningDevice, RunningVault, VaultIdentity};
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
        said_at: 1,
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
