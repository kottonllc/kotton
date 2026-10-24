// SPDX-License-Identifier: AGPL-3.0-or-later
//! Tests for three `kotton_peer` membership helpers.
//!
//! **Not tests of the pairing ceremony**, which is `kotton_device::users::pairing`'s.
//! They call `resolve_data_keys`, `record_own_device_member` and
//! `project_membership_into_allowlist` — all in `kotton_peer::daemon::nodes` — and
//! use a `UserRegistry` only to hold a `UserStore` while they do it.
//!
//! They belong in `core/peer` beside what they test. Left here for now because
//! moving them needs a `UserStore` built without the daemon, which `core/sync`'s
//! maintenance tests show how to do (`UserStore::create`) but which is a separate
//! change from relocating the ceremony.

#![cfg(test)]

// Previously inherited through `use super::*` from the ceremony file.
use kotton_device::users::DeviceUsers as _;
/// The unlock credential these fixtures create identities with — five BIP-39
/// words, 55.00 bits by the wordlist path. Mirrors the integration suite's
/// `TEST_PASSPHRASE`; a literal rather than a shared import because this crate
/// does not depend on the test harness.
const TEST_PASSPHRASE: &str = "canyon-orbit-velvet-fish-hospital";

use ed25519_dalek::SigningKey;
use kotton_common::crypto::kdf_labels;
use kotton_peer::daemon::db as network_db;
use kotton_peer::membership::Membership as _;
use kotton_schemas::membership::Posture;
use kotton_wire::ipc::UserResponse;
use sqlx::SqlitePool;
use std::collections::HashSet;
use std::sync::{Arc, RwLock};
#[cfg(test)]
mod enrollment_tests {
    // Needed by the tests only: the non-test build of this file no longer calls
    // through the trait, so clippy reports it unused at module scope.
    use super::*;
    use kotton_sys::secret::SecretsStore as _;
    // These were in scope via `use super::*` when the verbs lived in this file.
    // They are `peer`'s now, so the tests name where they went.
    use kotton_crypto::{derive_cek, derive_master_secret};
    use kotton_crypto::{derive_identity_key, DidKeyMethod};
    use kotton_peer::daemon::nodes::{
        node_revoke, own_device_member, project_membership_into_allowlist,
        record_own_device_member, reproject_allowlist, resolve_cek, resolve_data_keys,
    };
    use kotton_record::open_sqlite;
    use kotton_schemas::membership::{Ceremony, Role};
    use kotton_secret::MemorySecrets;
    use kotton_wire::peer::PairedNode;
    use std::path::Path;

    async fn migrated_pool(path: &Path) -> Arc<SqlitePool> {
        let pool = open_sqlite(path).await.expect("open sqlite");
        kotton_device::db::MIGRATOR
            .run(&pool)
            .await
            .expect("run migrations");
        Arc::new(pool)
    }

    /// Seed a user's identity material the way `user create` does.
    fn seed_identity(secrets: &MemorySecrets, user: &str, seed: [u8; 32]) {
        let id_key = derive_identity_key(&seed);
        secrets
            .set_secret(
                &kdf_labels::identity_signing_key(user),
                &hex::encode(id_key),
            )
            .unwrap();
        secrets
            .set_secret(&kdf_labels::seed32_keychain_key(user), &hex::encode(seed))
            .unwrap();
        // The device-level operational key the real daemon persists at startup
        // (distinct from the identity key — the bootstrap presents this one).
        secrets
            .set_secret(&kdf_labels::device_operational_key(), &hex::encode(seed))
            .unwrap();
    }

    /// A legacy `seed32`-bootstrapped account resolves the **whole** data
    /// capability, both roots derived from the one seed. This is the path an
    /// account created before roots were generated and sealed takes, and it must
    /// not silently yield a CEK-only capability.
    #[test]
    fn seed32_account_resolves_both_domain_roots() {
        let secrets = MemorySecrets::new();
        let seed = [4u8; 32];
        seed_identity(&secrets, "alice", seed);

        let keys = resolve_data_keys("alice", &secrets).unwrap().expect("data capability resolves");
        assert_eq!(keys.cek, derive_cek(&seed), "object-domain root");
        assert_eq!(
            keys.master_secret,
            derive_master_secret(&seed),
            "db-domain root"
        );
        assert_ne!(
            keys.cek, keys.master_secret,
            "the two domains must not collapse into one root"
        );
        assert_eq!(keys.cek_epoch, 0, "no rotation recorded yet");
    }

    /// The half-provisioned state is not resolvable. A device holding the CEK
    /// alone — the shape of a device joined by FROST before distributed signing — must report
    /// *no* data capability rather than a partial one, so a `Full` enrollment
    /// from it fails loudly instead of producing another device that cannot
    /// open the fleet's record log.
    #[test]
    fn a_cek_without_the_db_root_is_not_a_data_capability() {
        let secrets = MemorySecrets::new();
        secrets
            .set_secret(
                &kdf_labels::operational_cek("alice"),
                &hex::encode([7u8; 32]),
            )
            .unwrap();

        assert!(
            resolve_cek("alice", &secrets).unwrap().is_some(),
            "precondition: the CEK alone is present"
        );
        assert!(
            resolve_data_keys("alice", &secrets).unwrap().is_none(),
            "half a data capability must not pass as one"
        );
    }

    /// The recorded CEK epoch rides along, rather than the hardcoded 0 a joiner
    /// used to be told — a joined device should record the epoch its copy is
    /// actually for.
    #[test]
    fn the_recorded_cek_epoch_is_delivered() {
        let secrets = MemorySecrets::new();
        seed_identity(&secrets, "alice", [4u8; 32]);
        secrets
            .set_secret(&kdf_labels::operational_cek_epoch("alice"), "5")
            .unwrap();

        let keys = resolve_data_keys("alice", &secrets).unwrap().expect("data capability resolves");
        assert_eq!(keys.cek_epoch, 5);
    }

    /// Reads of `broken` fail; every other label is the inner store's.
    struct OneUnreadable {
        inner: MemorySecrets,
        broken: String,
    }
    impl kotton_sys::secret::SecretsStore for OneUnreadable {
        fn get_secret(&self, key: &str) -> kotton_sys::secret::SecretsResult<Option<String>> {
            if key == self.broken {
                return Err(kotton_sys::secret::SecretsError::Storage("the keychain did not answer".into()));
            }
            self.inner.get_secret(key)
        }
        fn set_secret(&self, key: &str, value: &str) -> kotton_sys::secret::SecretsResult<()> {
            self.inner.set_secret(key, value)
        }
        fn delete_secret(&self, key: &str) -> kotton_sys::secret::SecretsResult<()> {
            self.inner.delete_secret(key)
        }
    }

    /// **A data capability whose roots the store cannot read is an error, never
    /// the `seed32` derivation handed to a joiner.** Taken for absent, each
    /// unreadable root fell through to the legacy fallback, and a `Full`
    /// enrollment delivered — and the joiner kept — keys derived from another
    /// root; an unreadable epoch was delivered as 0.
    #[test]
    fn a_data_capability_the_store_cannot_read_is_an_error_not_the_seed_derivation() {
        for broken in [
            kdf_labels::operational_cek("alice"),
            kdf_labels::master_secret_keychain_key("alice"),
            kdf_labels::operational_cek_epoch("alice"),
        ] {
            let inner = MemorySecrets::new();
            seed_identity(&inner, "alice", [4u8; 32]);
            inner.set_secret(&kdf_labels::operational_cek("alice"), &hex::encode([8u8; 32])).unwrap();
            inner
                .set_secret(&kdf_labels::master_secret_keychain_key("alice"), &hex::encode([9u8; 32]))
                .unwrap();
            let s = OneUnreadable { inner, broken: broken.clone() };
            let got = format!("{:?}", resolve_data_keys("alice", &s));
            assert!(got.contains("the keychain did not answer"), "{broken}: the read's error is returned: {got}");
        }
    }

    #[test]
    fn own_device_member_maps_a_paired_node() {
        let pubkey = [9u8; 32];
        let did = DidKeyMethod::from_public_key_bytes(&pubkey).unwrap();
        let node = PairedNode {
            id: "laptop".to_string(),
            device_did: did.clone(),
            public_key: pubkey,
            paired_at: 0,
            addresses: vec![],
            relay_url: None,
            posture: None,
        };
        let m = own_device_member(&node, Posture::Full, "2026-06-26T00:00:00Z");
        assert_eq!(m.did, did.to_string());
        assert_eq!(m.public_key, pubkey);
        assert!(matches!(m.role, Role::OwnDevice));
        assert!(matches!(m.admitted_by, Ceremony::DeviceEnroll));
        assert_eq!(m.posture, Some(Posture::Full));
        assert_eq!(m.label.as_deref(), Some("laptop"));
        // It lands in both the paired-key allowlist and the device-list views.
        assert!(m.in_paired_key_allowlist() && m.is_own_device());
    }

    #[tokio::test]
    async fn record_own_device_member_writes_to_the_membership_set() {
        let users = crate::residency::UserRegistry::new();
        use kotton_device::DeviceRuntime;
        use kotton_secret::MemorySecrets;

        let temp = tempfile::tempdir().unwrap();
        let secrets = Arc::new(MemorySecrets::new());
        let runtime = DeviceRuntime::new_with_secrets(
            temp.path().to_path_buf(),
            kotton_device::config::RuntimeConfig::default(),
            secrets,
        )
        .await
        .unwrap();
        let (_, alice_rt) = runtime.create_user("alice", TEST_PASSPHRASE).await.unwrap();
        users.insert("alice".to_string(), alice_rt);

        let pubkey = SigningKey::from_bytes(&[4u8; 32])
            .verifying_key()
            .to_bytes();
        let did = DidKeyMethod::from_public_key_bytes(&pubkey).unwrap();
        let node = PairedNode {
            id: "vps".to_string(),
            device_did: did.clone(),
            public_key: pubkey,
            paired_at: 0,
            addresses: vec![],
            relay_url: None,
            posture: None,
        };

        record_own_device_member(users.get("alice").unwrap().as_ref(), &node, Posture::Full)
            .await
            .unwrap();

        // The membership set now contains the node as an own-device member.
        let members = users.get("alice").unwrap().list_members().await.unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].did, did.to_string());
        assert!(members[0].is_own_device());
        assert_eq!(
            members[0].posture,
            Some(kotton_schemas::membership::Posture::Full)
        );
    }

    /// The allowlist is the union of the *loaded* users' contributions — a peer
    /// paired only with a user who is not loaded is not admitted.
    ///
    /// A peer paired only with a locked user fails the TLS handshake exactly as
    /// an unpaired device. Seeded by `SELECT public_key FROM paired_nodes` across
    /// every user, that peer would complete the handshake and fail later on keys
    /// — which says "the machine is up and your user is not available", the
    /// sentence per-user daemons exist to unsay.
    #[tokio::test]
    async fn the_allowlist_omits_users_who_are_not_loaded() {
        let users = crate::residency::UserRegistry::new();
        use kotton_device::DeviceRuntime;
        use kotton_secret::MemorySecrets;

        let dir = tempfile::tempdir().unwrap();
        let db = migrated_pool(&dir.path().join("agent.db")).await;
        let rt_temp = tempfile::tempdir().unwrap();
        let runtime = DeviceRuntime::new_with_secrets(
            rt_temp.path().to_path_buf(),
            kotton_device::config::RuntimeConfig::default(),
            Arc::new(MemorySecrets::new()),
        )
        .await
        .unwrap();
        // Only alice is loaded. bob exists on the machine as paired_nodes rows,
        // exactly as a second user who is simply not unlocked right now.
        let (_, alice_rt) = runtime.create_user("alice", TEST_PASSPHRASE).await.unwrap();
        users.insert("alice".to_string(), alice_rt);

        let alices_peer = SigningKey::from_bytes(&[11u8; 32])
            .verifying_key()
            .to_bytes();
        let bobs_peer = SigningKey::from_bytes(&[22u8; 32])
            .verifying_key()
            .to_bytes();
        for (user, key, id) in [
            ("alice", alices_peer, "alice-laptop"),
            ("bob", bobs_peer, "bob-laptop"),
        ] {
            let did = DidKeyMethod::from_public_key_bytes(&key).unwrap();
            network_db::insert_paired_node(&db, id, user, &did.to_string(), &key, "[]", 0, None)
                .await
                .unwrap();
        }

        let paired_keys = Arc::new(RwLock::new(HashSet::<[u8; 32]>::new()));
        let resolved: Vec<(
            String,
            std::sync::Arc<dyn kotton_peer::membership::MemberStore>,
        )> = users
            .all()
            .into_iter()
            .map(|(id, rt)| {
                (
                    id,
                    rt as std::sync::Arc<dyn kotton_peer::membership::MemberStore>,
                )
            })
            .collect();
        reproject_allowlist(&resolved, &db, &paired_keys).await;

        let live = paired_keys.read().unwrap().clone();
        assert!(
            live.contains(&alices_peer),
            "the loaded user's peer must be admitted"
        );
        assert!(
            !live.contains(&bobs_peer),
            "a peer paired only with a user who is not loaded must not be admitted — \
             this is the whole point of the per-user contribution"
        );
    }

    /// The membership set projects into the live allowlist + paired_nodes cache,
    /// additively and idempotently — the path a sync-pulled member takes to become
    /// admitted + dialable (a view computed from the membership set).
    #[tokio::test]
    async fn project_membership_into_allowlist_adds_member_keys() {
        let users = crate::residency::UserRegistry::new();
        use kotton_device::DeviceRuntime;
        use kotton_secret::MemorySecrets;

        let dir = tempfile::tempdir().unwrap();
        let db = migrated_pool(&dir.path().join("agent.db")).await;
        let rt_temp = tempfile::tempdir().unwrap();
        let runtime = DeviceRuntime::new_with_secrets(
            rt_temp.path().to_path_buf(),
            kotton_device::config::RuntimeConfig::default(),
            Arc::new(MemorySecrets::new()),
        )
        .await
        .unwrap();
        let (_, alice_rt) = runtime.create_user("alice", TEST_PASSPHRASE).await.unwrap();
        users.insert("alice".to_string(), alice_rt);

        // A member is in the set but not yet in the live allowlist / paired_nodes —
        // exactly the state after a sync pass pulls a member admitted elsewhere.
        let pubkey = SigningKey::from_bytes(&[6u8; 32])
            .verifying_key()
            .to_bytes();
        let did = DidKeyMethod::from_public_key_bytes(&pubkey).unwrap();
        let node = PairedNode {
            id: "synced-vps".to_string(),
            device_did: did.clone(),
            public_key: pubkey,
            paired_at: 0,
            addresses: vec![],
            relay_url: None,
            posture: None,
        };
        record_own_device_member(users.get("alice").unwrap().as_ref(), &node, Posture::Full)
            .await
            .unwrap();
        let paired_keys = Arc::new(RwLock::new(HashSet::<[u8; 32]>::new()));

        let added = project_membership_into_allowlist(
            users.get("alice").unwrap().as_ref(),
            &db,
            &paired_keys,
            "alice",
        )
        .await;
        assert_eq!(
            added, 1,
            "the member's key is newly added to the live allowlist"
        );
        assert!(
            paired_keys.read().unwrap().contains(&pubkey),
            "key projected into the live allowlist"
        );
        assert!(
            network_db::paired_node_named(&db, "alice", &did.to_string())
                .await
                .unwrap()
                .is_some(),
            "a paired_nodes cache row was created (keyed by DID) so the member is dialable"
        );

        // Idempotent: a second projection adds nothing.
        let again = project_membership_into_allowlist(
            users.get("alice").unwrap().as_ref(),
            &db,
            &paired_keys,
            "alice",
        )
        .await;
        assert_eq!(again, 0, "projection is additive and idempotent");
    }

    /// A contact is **neither a paired device nor in the device allowlist**, and
    /// a row from an earlier build that says otherwise is repaired.
    ///
    /// `paired_nodes` is what `peer_standing` reads to answer
    /// `PeerStanding::Paired`, and that standing serves `ReadFile`,
    /// `ReadSealed`, `ListSealed`, `ApplyRecordChangeset` and `RecoveryFetch`.
    /// A contact holding it would contradict *pairing exchanges authenticated
    /// public keys and nothing else* — for a party who is, by construction, on
    /// another machine.
    ///
    /// **And a contact is not on the allowlist.** A contact has their own door —
    /// a per-pair mailbox whose verifier admits one key and whose vocabulary is
    /// one verb — so the device allowlist, which gates peer mTLS, is this
    /// device's fleet and nobody else (`Member::in_paired_key_allowlist`).
    ///
    /// That contacts still reach doors is measured rather than argued:
    /// `contact_pairing::a_message_reaches_the_other_person_and_they_read_it` and
    /// `three_people_on_three_daemons_read_one_channel_message` run over a real
    /// relay between separate daemons, and every peer in them is a
    /// `Role::Contact`.
    #[tokio::test]
    async fn a_contact_is_neither_a_paired_device_nor_in_the_device_allowlist() {
        let users = crate::residency::UserRegistry::new();
        use kotton_device::DeviceRuntime;
        use kotton_schemas::membership::Member;

        let dir = tempfile::tempdir().unwrap();
        let db = migrated_pool(&dir.path().join("agent.db")).await;
        let rt_temp = tempfile::tempdir().unwrap();
        let runtime = DeviceRuntime::new_with_secrets(
            rt_temp.path().to_path_buf(),
            kotton_device::config::RuntimeConfig::default(),
            Arc::new(MemorySecrets::new()),
        )
        .await
        .unwrap();
        let (_, alice_rt) = runtime.create_user("alice", TEST_PASSPHRASE).await.unwrap();
        users.insert("alice".to_string(), alice_rt);

        // Bob, as contact pairing writes him: another person's identity key.
        let bob_key = SigningKey::from_bytes(&[9u8; 32])
            .verifying_key()
            .to_bytes();
        let bob_did = DidKeyMethod::from_public_key_bytes(&bob_key)
            .unwrap()
            .to_string();
        users
            .get("alice")
            .unwrap()
            .write_member(&Member {
                did: bob_did.clone(),
                public_key: bob_key,
                role: Role::Contact,
                admitted_by: Ceremony::Pairing,
                added_at: "2026-09-06T00:00:00Z".to_string(),
                posture: None,
                label: Some("bob".to_string()),
                reach: None,
            })
            .await
            .unwrap();

        // A row an earlier build would have written, so the projection is asked
        // to repair rather than only to stop.
        network_db::insert_paired_node(&db, &bob_did, "alice", &bob_did, &bob_key, "[]", 0, None)
            .await
            .unwrap();
        assert!(network_db::is_pubkey_paired_to_user(&db, &bob_key, "alice")
            .await
            .unwrap());

        let paired_keys = Arc::new(RwLock::new(HashSet::<[u8; 32]>::new()));
        project_membership_into_allowlist(
            users.get("alice").unwrap().as_ref(),
            &db,
            &paired_keys,
            "alice",
        )
        .await;

        assert!(
            !paired_keys.read().unwrap().contains(&bob_key),
            "a contact must not be in the device allowlist: it gates peer mTLS, and their \
             messages arrive through their own per-pair door instead"
        );
        assert!(
            !network_db::is_pubkey_paired_to_user(&db, &bob_key, "alice")
                .await
                .unwrap(),
            "a contact must not be a paired device: that standing serves ReadFile, ReadSealed \
             and RecoveryFetch, and a contact is granted the ability to be messaged and nothing \
             else (RFC-0022 CP5)"
        );
    }

    #[tokio::test]
    async fn node_revoke_removes_membership_and_allowlist() {
        let users = crate::residency::UserRegistry::new();
        use kotton_device::DeviceRuntime;
        use kotton_secret::MemorySecrets;

        let dir = tempfile::tempdir().unwrap();
        let db = migrated_pool(&dir.path().join("agent.db")).await;

        let rt_temp = tempfile::tempdir().unwrap();
        let runtime = DeviceRuntime::new_with_secrets(
            rt_temp.path().to_path_buf(),
            kotton_device::config::RuntimeConfig::default(),
            Arc::new(MemorySecrets::new()),
        )
        .await
        .unwrap();
        let (_, alice_rt) = runtime.create_user("alice", TEST_PASSPHRASE).await.unwrap();
        users.insert("alice".to_string(), alice_rt);

        // A paired node + its membership record + a live allowlist entry.
        let pubkey = SigningKey::from_bytes(&[5u8; 32])
            .verifying_key()
            .to_bytes();
        let did = DidKeyMethod::from_public_key_bytes(&pubkey).unwrap();
        let node = PairedNode {
            id: "vps".to_string(),
            device_did: did.clone(),
            public_key: pubkey,
            paired_at: 0,
            addresses: vec![],
            relay_url: None,
            posture: None,
        };
        let addresses_json = serde_json::to_string(&node.addresses).unwrap();
        network_db::insert_paired_node(
            &db,
            &node.id,
            "alice",
            &did.to_string(),
            &node.public_key,
            &addresses_json,
            0,
            None,
        )
        .await
        .unwrap();
        record_own_device_member(users.get("alice").unwrap().as_ref(), &node, Posture::Full)
            .await
            .unwrap();
        let paired_keys = Arc::new(RwLock::new(HashSet::from([pubkey])));

        // Sanity: the member is present before revoke.
        let members_before = users.get("alice").unwrap().list_members().await.unwrap();
        assert_eq!(members_before.len(), 1);

        let resp = node_revoke(
            users.get("alice").unwrap().as_ref(),
            &db,
            "alice".to_string(),
            "vps".to_string(),
            &paired_keys,
        )
        .await
        .unwrap();
        assert!(matches!(resp, UserResponse::NodeRevoked));

        // Revoke once → every view closed: membership record, live allowlist, and
        // the paired-nodes row are all gone.
        assert!(users
            .get("alice")
            .unwrap()
            .list_members()
            .await
            .unwrap()
            .is_empty());
        assert!(!paired_keys.read().unwrap().contains(&pubkey));
        assert!(network_db::paired_node_named(&db, "alice", "vps")
            .await
            .unwrap()
            .is_none());
    }

    /// A runtime with alice, a device of hers (`laptop`) and a drive (`vault`)
    /// whose row has no address, so nothing can reach it.
    async fn alice_with_a_device_and_an_unreachable_drive(
        dir: &Path,
    ) -> (kotton_device::DeviceRuntime, crate::residency::UserRegistry, Arc<SqlitePool>) {
        let users = crate::residency::UserRegistry::new();
        let db = migrated_pool(&dir.join("agent.db")).await;
        let runtime = kotton_device::DeviceRuntime::new_with_secrets(
            dir.join("rt"),
            kotton_device::config::RuntimeConfig::default(),
            Arc::new(MemorySecrets::new()),
        )
        .await
        .unwrap();
        let (_, alice_rt) = runtime.create_user("alice", TEST_PASSPHRASE).await.unwrap();
        users.insert("alice".to_string(), alice_rt);
        for (id, seed, posture) in [("laptop", 6u8, Posture::Full), ("vault", 9u8, Posture::BlindStorage)] {
            let key = SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes();
            let did = DidKeyMethod::from_public_key_bytes(&key).unwrap();
            network_db::insert_paired_node(&db, id, "alice", &did.to_string(), &key, "[]", 0, Some(posture.as_str()))
                .await
                .unwrap();
            // A vault is a drive as enrolling it records one.
            if posture == Posture::BlindStorage {
                kotton_peer::daemon::drives::record(&db, "alice", &key).await.unwrap();
            }
        }
        (runtime, users, db)
    }

    /// **A revoke on a device that does not hold the identity is refused**,
    /// and says which device can do it: the drives admit the device until the
    /// identity withdraws it, so a success here would be untrue. Nothing is
    /// revoked.
    #[tokio::test]
    async fn a_revoke_on_a_device_without_the_identity_is_refused_and_names_the_device_that_can() {
        let dir = tempfile::tempdir().unwrap();
        let (runtime, users, db) = alice_with_a_device_and_an_unreachable_drive(dir.path()).await;
        runtime.secrets().delete_secret(&kdf_labels::identity_signing_key("alice")).unwrap();

        let resp = kotton_device::users::drive_devices::revoke(
            &runtime,
            users.get("alice").unwrap().as_ref(),
            &db,
            "alice".to_string(),
            "laptop".to_string(),
        )
        .await
        .unwrap();
        match resp {
            UserResponse::Error { message } => {
                assert!(message.starts_with("not revoked"), "{message}");
                assert!(message.contains("vault"), "the drive is named: {message}");
                assert!(message.contains("the device that holds the identity"), "{message}");
            }
            other => panic!("a revoke that withdrew from no drive answered {other:?}"),
        }
        assert!(
            network_db::paired_node_named(&db, "alice", "laptop").await.unwrap().is_some(),
            "a refused revoke revoked"
        );
    }

    /// **A revoke a drive did not take is not reported as success.** The
    /// device is revoked here, and the answer is an error naming the drive
    /// that still admits it.
    #[tokio::test]
    async fn a_revoke_a_drive_did_not_take_names_the_drive_and_is_not_success() {
        let dir = tempfile::tempdir().unwrap();
        let (runtime, users, db) = alice_with_a_device_and_an_unreachable_drive(dir.path()).await;

        let resp = kotton_device::users::drive_devices::revoke(
            &runtime,
            users.get("alice").unwrap().as_ref(),
            &db,
            "alice".to_string(),
            "laptop".to_string(),
        )
        .await
        .unwrap();
        match resp {
            UserResponse::Error { message } => {
                assert!(message.contains("revoked on this device"), "{message}");
                assert!(message.contains("still admits it: vault ("), "the drive is named: {message}");
                assert!(message.contains("will not reach it"), "the retry is not invited: {message}");
                assert!(message.contains("nothing retries the withdrawal yet"), "{message}");
            }
            other => panic!("a revoke no drive took answered {other:?}"),
        }
        assert!(
            network_db::paired_node_named(&db, "alice", "laptop").await.unwrap().is_none(),
            "the device is still revoked here"
        );
    }
}
