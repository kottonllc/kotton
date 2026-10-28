// SPDX-License-Identifier: AGPL-3.0-or-later
//! The sync engine's tests, exercised against the daemon's real host.
//!
//! The engine is `core/sync`'s; these tests are here. They build a real `DeviceRuntime`, create real users, open real sqlite and write real
//! files — they are integration tests, and the host they integrate with
//! (`residency::DaemonUserResources`) is this crate's. Moving them would mean
//! writing a second `SyncHost` in `core/sync` that could drift from the one that
//! ships, which is a weaker test, not a better-placed one.

#![cfg(test)]

use kotton_sync::engine::*;
/// The unlock credential these fixtures create identities with — five BIP-39
/// words, 55.00 bits by the wordlist path. Mirrors the integration suite's
/// `TEST_PASSPHRASE`; a literal rather than a shared import because this crate
/// does not depend on the test harness.
const TEST_PASSPHRASE: &str = "canyon-orbit-velvet-fish-hospital";

// Previously inherited through `use super::*` from the engine file; named here now
// that the engine lives in another crate.
use kotton_device::users::DeviceUsers as _;
use kotton_device::DeviceRuntime;
use kotton_peer::membership::Membership as _;
use kotton_wire::remote::{RemoteBackend, RemoteConfig};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
mod b3_tests {
    use super::*;
    // `resources` is an `Arc<DaemonUserResources>`; the methods are the trait's.
    use kotton_sync::UserResources as _;
    // Only the tests need this now: they build the daemon's host, so they name
    // daemon types on purpose. The engine's own body no longer names any.
    use kotton_schemas::membership::{Ceremony, Member, Posture, Role};

    fn member(did: &str, posture: Option<Posture>) -> Member {
        Member {
            did: did.to_string(),
            public_key: [0u8; 32],
            role: Role::OwnDevice,
            admitted_by: Ceremony::DeviceEnroll,
            added_at: "2026-07-23T00:00:00Z".to_string(),
            posture,
            label: None,
            reach: None,
        }
    }

    /// Returns the registry as well: residency is the daemon's, so a test that
    /// wants a resident user must hold the registry it registered into.
    async fn env() -> (
        tempfile::TempDir,
        Arc<DeviceRuntime>,
        Arc<crate::residency::DaemonUserResources>,
    ) {
        let users = crate::residency::UserRegistry::new();
        let dir = tempfile::tempdir().expect("tempdir");
        let secrets: Arc<dyn kotton_sys::secret::SecretsStore + Send + Sync> =
            Arc::new(kotton_secret::MemorySecrets::new());
        let rt = DeviceRuntime::new_with_secrets(
            dir.path().to_owned(),
            kotton_device::config::RuntimeConfig::default(),
            secrets,
        )
        .await
        .expect("DeviceRuntime");
        let (_, alice_rt) = rt
            .create_user("alice", TEST_PASSPHRASE)
            .await
            .expect("create_user");
        users.insert("alice".to_string(), alice_rt);
        let rt = Arc::new(rt);
        let resources = crate::residency::DaemonUserResources::new(
            users,
            crate::residency::RecordStores::new(),
            Arc::new(RwLock::new(HashMap::new())),
            Arc::clone(&rt),
            None,
        );
        (dir, rt, resources)
    }

    /// A mount with no pack layer, and beside it a remote reaching `peer_did`.
    ///
    /// A plain store answers `pack_loose()` with `None`, so a pass that tries to
    /// pack it toward a keyless peer is refused, and one that never tries goes
    /// through. Both remotes are memory stores; what is under test is which
    /// passes reach the pack, not what a pack holds.
    fn a_plain_mount_and_a_peer(
        user_rt: &kotton_store::runtime::user::UserStore,
        peer_did: &str,
    ) {
        let plain: Arc<dyn kotton_sys::store::SyncableStore> =
            Arc::new(kotton_store::MemoryObjectStorage::new());
        user_rt
            .add_remote(
                "plain".to_string(),
                plain,
                RemoteConfig {
                    backend: RemoteBackend::Local {
                        path: std::path::PathBuf::from("/dev/null"),
                    },
                    cache_dir: None,
                    key_format: kotton_wire::remote::KeyFormat::default(),
                },
            )
            .expect("add_remote plain");
        let peer: Arc<dyn kotton_sys::store::SyncableStore> =
            Arc::new(kotton_store::MemoryObjectStorage::new());
        user_rt
            .add_remote(
                "peer".to_string(),
                peer,
                RemoteConfig {
                    backend: RemoteBackend::Kotton {
                        peer_did: peer_did.to_string(),
                        label: "peer".to_string(),
                    },
                    cache_dir: None,
                    key_format: kotton_wire::remote::KeyFormat::default(),
                },
            )
            .expect("add_remote peer");
    }

    /// **A peer is held to packs whatever its posture** (#80). A `Full` peer was
    /// once let through without a pack pass, because one of the person's own
    /// devices could be a sync target; since no writer of the drive record can
    /// make a device a drive, that branch went, and a mount that cannot pack is
    /// refused toward a `Full` member as toward any peer. Asked through
    /// `sync_mount_with_records`, the one function both entry points sync by.
    #[tokio::test]
    async fn a_full_peer_is_held_to_packs_as_any_peer_is() {
        let (_dir, runtime, resources) = env().await;
        let user_rt = resources.user_store("alice").expect("user runtime");
        user_rt
            .write_member(&member("did:key:zFull", Some(Posture::Full)))
            .await
            .expect("write_member");
        a_plain_mount_and_a_peer(&user_rt, "did:key:zFull");

        let err = sync_mount_with_records(
            &runtime,
            &*resources,
            "alice",
            "plain",
            "peer",
            Some(kotton_wire::ipc::SyncDirection::Push),
        )
        .await
        .expect_err("a full peer was pushed loose objects");
        assert!(err.to_string().contains("no pack layer"), "unexpected reason: {err}");
    }

    /// The packing boundary: a peer holding no data keys must not be sent
    /// loose objects, because their sizes are the channel packing closes. A
    /// mount with no pack layer therefore fails closed — on the function the
    /// `SyncMount` request and the background engine both sync by, so neither
    /// can push around it. A pull sends the peer nothing and is not refused.
    #[tokio::test]
    async fn a_keyless_peer_is_refused_a_mount_that_cannot_pack() {
        let (_dir, runtime, resources) = env().await;
        let user_rt = resources.user_store("alice").expect("user runtime");
        user_rt
            .write_member(&member("did:key:zBlind", Some(Posture::BlindStorage)))
            .await
            .expect("write_member");
        a_plain_mount_and_a_peer(&user_rt, "did:key:zBlind");

        for direction in [Some(kotton_wire::ipc::SyncDirection::Push), None] {
            let err = sync_mount_with_records(&runtime, &*resources, "alice", "plain", "peer", direction.clone())
                .await
                .expect_err("a keyless peer must not receive loose objects");
            assert!(err.to_string().contains("no pack layer"), "unexpected reason ({direction:?}): {err}");
        }
        sync_mount_with_records(
            &runtime,
            &*resources,
            "alice",
            "plain",
            "peer",
            Some(kotton_wire::ipc::SyncDirection::Pull),
        )
        .await
        .expect("a pull hands the peer nothing, so it needs no pack");
    }
}
