// SPDX-License-Identifier: AGPL-3.0-or-later
//! The rentable node (RFC-0084): a vault keeps, meters, admits, and is left.
//!
//! Every test here runs a real `kvaultd::Vault` in-process — the same shape a
//! landlord runs, minus the socket path — and real device daemons around it.
//! Nothing is mocked; the vault holds bytes it cannot open and the tests read
//! them back only on a device that can.

use kotton::SyncDirection;
use serial_test::serial;
use kotton_schemas::membership::Posture;
use kotton_secret::MemorySecrets;
use kotton_sys::secret::SecretsStore;
use kotton_wire::ipc::{UserRequest, UserResponse, VaultRequest};
use kotton_wire::remote::RemoteBackend;
use kuserd::DeviceDaemon;
use kvaultd::Vault;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::common::{connect_when_ready, enroll_streamed, enroll_streamed_as, init_crypto, unique_ipc, wait_for_daemon};
use kotton_sys::ipc::IpcEndpoint;

const NOTE: &[u8] = b"the whole of what alice owns";

/// A running vault: its directory, its door, its peer port, and the handle a
/// landlord would hold (to raise the quota while it serves).
pub(crate) struct RunningVault {
    _base: tempfile::TempDir,
    pub(crate) base_path: std::path::PathBuf,
    pub(crate) ipc: crate::common::Door,
    op_port: u16,
    pub(crate) vault: Arc<Vault>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
    /// The operator the vault was created for (RFC-0084 V18): the suite's own,
    /// which no test speaks under — a test's operators are enrolled beside it.
    creator: ed25519_dalek::SigningKey,
}

pub(crate) async fn spawn_vault(label: &str) -> RunningVault {
    spawn_vault_on(label, kvaultd::shelf::local()).await
}

/// A vault whose pools rest on `shelves` — the landlord's disk, or a bucket.
async fn spawn_vault_on(label: &str, shelves: Arc<dyn kotton_sys::store::Shelves>) -> RunningVault {
    let base = tempfile::tempdir().expect("vault base");
    let ipc = unique_ipc();
    let secrets: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    let creator = crate::common::create_vault(base.path(), secrets.as_ref()).await;
    let vault = Arc::new(
        Vault::new_with_shelves(base.path().to_owned(), ipc.clone(), secrets, shelves)
            .await
            .expect("vault"),
    );
    vault
        .start_peer_listener_background(0)
        .await
        .expect("vault peer listener");
    let op_port = crate::common::peer_port(vault.runtime());
    let task = tokio::spawn(Arc::clone(&vault).run());
    wait_for_daemon(&ipc, label).await;
    RunningVault {
        base_path: base.path().to_owned(),
        _base: base,
        ipc,
        op_port,
        vault,
        task,
        creator,
    }
}

/// A vault standing at the relay at `relay_addr`, told so in process
/// (`common::relay::stand_at`) — where `docs/use/` has its operator's desktop
/// tell it.
async fn spawn_vault_at(relay_addr: &str, label: &str) -> RunningVault {
    let vault = spawn_vault(label).await;
    crate::common::relay::stand_at(&vault.vault, relay_addr).await;
    vault
}

pub(crate) struct RunningDevice {
    _base: tempfile::TempDir,
    pub(crate) ipc: crate::common::Door,
    pub(crate) secrets: Arc<dyn SecretsStore + Send + Sync>,
    /// The daemon itself, for what no request reads back — the drives it
    /// records (`DeviceDaemon::drives`).
    pub(crate) daemon: Arc<DeviceDaemon>,
    _task: tokio::task::JoinHandle<std::io::Result<()>>,
}

pub(crate) async fn spawn_device(label: &str) -> RunningDevice {
    let base = tempfile::tempdir().expect("device base");
    let ipc = unique_ipc();
    let secrets: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    // No relay, stated to this daemon. A bare device here has never wanted one,
    // and reading `KOTTON_RELAY_URL` for it meant picking up whatever another
    // test had set process-wide in the same window
    // (`TASK-a-process-global-relay-url-is-shared-by-tests-that-run-in-parallel`).
    let daemon = DeviceDaemon::new_with_base_secrets_and_relay(
        base.path().to_owned(),
        ipc.clone(),
        Arc::clone(&secrets),
        kotton_device::config::db::RelayChoice::None,
    )
    .await
    .expect("device daemon");
    let daemon = Arc::new(daemon);
    let running = Arc::clone(&daemon);
    let task = tokio::spawn(async move { running.run().await });
    wait_for_daemon(&ipc, label).await;
    RunningDevice {
        _base: base,
        ipc,
        secrets,
        daemon,
        _task: task,
    }
}

/// A vault as a device sees it once enrolled: its DID and signing key.
pub(crate) struct VaultIdentity {
    pub(crate) did: String,
    pub(crate) pubkey_hex: String,
    pub(crate) op_addr: SocketAddr,
}

impl VaultIdentity {
    /// The vault's line, as the recovery card prints it under the words:
    /// `kotton-instance:vault:<key>@<address>`. What `Recover` takes.
    pub(crate) fn line(&self) -> String {
        let key: [u8; 32] = hex::decode(&self.pubkey_hex)
            .expect("the vault's key is hex")
            .try_into()
            .expect("the vault's key is 32 bytes");
        kotton_wire::line::InstanceLine {
            kind: kotton_wire::ipc::OperatedService::Vault,
            hint: self.op_addr.to_string(),
            key,
        }
        .to_text()
    }
}

/// Enrol `vault` blind for `user` from the device behind `client`, then tell
/// the device where the vault listens and name it as a remote. Returns the
/// device's client, now paired.
pub(crate) async fn enrol_vault(
    client: kotton::KottonClient,
    vault: &RunningVault,
    user: &str,
    label: &str,
) -> (kotton::KottonClient, VaultIdentity) {
    enrol_vault_from(client, "device-e", vault, user, label).await
}

/// [`enrol_vault`] from a device that announces itself as `device_name`.
pub(crate) async fn enrol_vault_from(
    client: kotton::KottonClient,
    device_name: &str,
    vault: &RunningVault,
    user: &str,
    label: &str,
) -> (kotton::KottonClient, VaultIdentity) {
    let client_v = connect_when_ready(&vault.ipc, "vault door").await;
    let (mut client, _client_v, node) = enroll_streamed_as(
        client,
        client_v,
        user,
        device_name,
        label,
        Posture::BlindStorage,
    )
    .await;
    assert_eq!(node.id, label);
    // The ceremony is where this device learns who the vault is and where it
    // answers. `get_node_identity` was asked for the DID until 2026-09-12, and
    // it returns the routing fingerprint from `identity.json` — a key nobody
    // holds — beside the operational key's public half, so the pair did not
    // agree with itself (`TASK-a-node-identity-is-two-keys-pretending-to-be-one`).
    let did = node.device_did.to_string();
    let pubkey_hex = hex::encode(node.public_key);
    // No `peer_add` here. Until 2026-09-12 this line injected
    // `127.0.0.1:{vault.op_port}` — the address the ceremony should have
    // carried and did not — which is how the defect stayed invisible to a
    // suite that looked for it
    // (`TASK-admitting-a-vault-records-the-wrong-port-for-it`).
    let op_addr: SocketAddr = format!("127.0.0.1:{}", vault.op_port).parse().unwrap();
    let recorded = *node
        .addresses
        .first()
        .expect("the ceremony recorded an address for the vault");
    assert_eq!(recorded, op_addr, "the ceremony carried the vault's peer listener");
    client
        .remote_add(
            user,
            label,
            RemoteBackend::Kotton {
                peer_did: did.clone(),
                label: label.to_string(),
            },
            None,
        )
        .await
        .expect("remote_add vault");
    (
        client,
        VaultIdentity {
            did,
            pubkey_hex,
            op_addr,
        },
    )
}

fn notes_schema() -> String {
    let schema = kotton_schemas::definition::SchemaDefinition::new(
        kotton_schemas::nsid::Nsid::new("com.test.notes").unwrap(),
        1,
        vec![kotton_schemas::field::SchemaField::required(
            "title",
            kotton_schemas::field::FieldType::String,
        )],
    );
    serde_json::to_string(&schema).unwrap()
}

/// A person with one device and a file and a record, ready to push.
async fn a_person_with_things(
    client: &mut kotton::KottonClient,
    user: &str,
    note: &[u8],
) -> String {
    client
        .create_user(user, crate::common::TEST_PASSPHRASE)
        .await
        .expect("create_user");
    let phrase = client.add_recovery_phrase(user).await.expect("add_recovery_phrase");
    client.write_file(user, "notes.txt", note).await.expect("write_file");
    client.schema_register(user, &notes_schema()).await.expect("schema");
    client
        .record_insert(user, "com.test.notes", serde_json::json!({ "title": "survives" }))
        .await
        .expect("record_insert");
    phrase
}

/// A phrase-only device recovers everything from `vault`, and the caller
/// checks what came back.
///
/// The recovery is the one `kotton id recover` and the REPL's `id recover` send:
/// `Recover` with the vault's line, in which the daemon adds the vault as the node
/// `vault`, proves the phrase and records the vault as the person's drive. Nothing
/// here adds the vault or says it is a drive.
///
/// The cold device comes back with its client, so the caller holds it for as
/// long as it reads and it drops at the caller's scope end, its [`Door`] and
/// base with it. Until 2026-09-28 it was forgotten here to keep it
/// alive, which skipped that drop: nine sockets per `vault::` run
/// (`TASK-the-vault-suite-forgets-its-cold-devices-and-their-doors-with-them`).
///
/// [`Door`]: crate::common::Door
pub(crate) async fn recover_from(
    phrase: &str,
    user: &str,
    vault: &VaultIdentity,
) -> (RunningDevice, kotton::KottonClient) {
    let cold = spawn_device("cold device").await;
    let mut client = connect_when_ready(&cold.ipc, "cold client").await;
    client
        .login_with_recovery_key(phrase, Some(user.to_string()), None)
        .await
        .expect("the phrase alone claims the identity on a cold device");
    let recovered = client
        .recover(user, phrase, crate::common::TEST_PASSPHRASE, &vault.line())
        .await
        .expect("recover from the phrase and the vault's line alone");
    assert!(recovered.did.starts_with("did:kel:"), "{}", recovered.did);
    assert_eq!(recovered.drive_not_recorded, None, "the line's vault was not recorded as the drive");
    client.schema_register(user, &notes_schema()).await.expect("schema on cold");
    client
        .remote_add(
            user,
            "vault",
            RemoteBackend::Kotton {
                peer_did: vault.did.clone(),
                label: "vault".to_string(),
            },
            None,
        )
        .await
        .expect("remote_add on cold");
    client
        .sync_mount(user, "local", "vault", Some(SyncDirection::Pull))
        .await
        .expect("pull everything back from the vault");
    (cold, client)
}

/// The M1 recovery, through a vault instead of a daemon enrolled blind: a pool
/// over one local shelf serves it unchanged, and the door's meter shows what
/// the person pushed.
#[tokio::test]
async fn a_vault_keeps_what_a_device_pushes_and_gives_it_back_from_the_phrase() {
    init_crypto();
    let vault = spawn_vault("vault").await;
    let phrase;
    let identity;
    {
        let device = spawn_device("device E").await;
        let mut client = connect_when_ready(&device.ipc, "client E").await;
        phrase = a_person_with_things(&mut client, "alice", NOTE).await;
        let (mut client, id) = enrol_vault(client, &vault, "alice", "vault").await;
        identity = id;
        let pushed = client
            .sync_mount("alice", "local", "vault", Some(SyncDirection::Push))
            .await
            .expect("push everything to the vault");
        assert!(pushed.pushed >= 1);

        // The meter, at the landlord's door: bytes, and only bytes.
        let mut door = connect_when_ready(&vault.ipc, "door").await;
        let (held, quota) = door.vault_capacity("alice").await.expect("capacity");
        assert!(held > 0, "the vault holds what was pushed: {held}");
        assert_eq!(quota, None, "no quota was set");
        // Every device is lost here.
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    let (_cold_device, mut cold) = recover_from(&phrase, "alice", &identity).await;
    assert_eq!(cold.read_file("alice", "notes.txt").await.expect("file").as_slice(), NOTE);
    let recs = cold
        .record_query("alice", "com.test.notes", vec![], None, None)
        .await
        .expect("records");
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0]["title"], "survives");
    assert!(vault.base_path.join("users").exists());
}

/// The person's old passphrase: the one their identity was created under.
const OLD_PASSPHRASE: &str = crate::common::TEST_PASSPHRASE;
/// The passphrase chosen for the recovering device: five distinct wordlist
/// words, above the bar a passphrase is held to.
const NEW_PASSPHRASE: &str = "abandon-ability-able-about-above";

/// When `Recover` has answered on `device`, hold that the device unlocks the
/// recovered key with the passphrase the recovery was given and with no other, at
/// the daemon and across a restart, and return the key a restart's unlock puts in
/// place.
///
/// There is no window between the recovery and the seal to test: the sealed copy
/// under the new passphrase is on disk when `Recover` answers, before anything else
/// is asked of the daemon. The old passphrase is refused as wrong and the new one
/// opens a session; then a restart — a fresh runtime over the device's directory
/// and the platform store it kept, with nothing in memory — unlocks under the new
/// passphrase and not the old, to the recovered key.
async fn only_the_chosen_passphrase_unlocks(device: &RunningDevice, user: &str, recovered_key_hex: &str) -> [u8; 32] {
    use kotton::PinUnlock;
    use kotton_common::crypto::kdf_labels;
    use kotton_device::DeviceRuntime;

    let base = device._base.path().to_owned();
    assert!(
        base.join("users").join(user).join(kotton_identity::provisioning::VAULT_FILE).exists(),
        "no sealed copy is on disk when `Recover` has answered"
    );
    // Each unlock on a connection of its own: an unlock replaces the session of
    // the connection it is sent on.
    let unlock = |passphrase: &'static str| {
        let ipc = device.ipc.clone();
        async move {
            let mut door = connect_when_ready(&ipc, "unlock").await;
            door.unlock_with_pin(user, passphrase).await
        }
    };
    assert!(
        matches!(unlock(OLD_PASSPHRASE).await, Ok(PinUnlock::Wrong { .. })),
        "the old passphrase is not refused as wrong"
    );
    assert!(
        matches!(unlock(NEW_PASSPHRASE).await, Ok(PinUnlock::Unlocked)),
        "the new passphrase does not unlock at the daemon"
    );

    let restarted = DeviceRuntime::new_with_secrets(
        base,
        kotton_device::config::RuntimeConfig::default(),
        Arc::clone(&device.secrets),
    )
    .await
    .expect("a fresh runtime over the device's directory");
    assert!(
        kotton_identity::provisioning::unlock_with_pin(&restarted, user, OLD_PASSPHRASE).await.is_err(),
        "the old passphrase opens the sealed copy after a restart"
    );
    kotton_identity::provisioning::unlock_with_pin(&restarted, user, NEW_PASSPHRASE)
        .await
        .expect("the new passphrase unlocks after a restart");
    let in_place = restarted
        .secrets()
        .get_secret(&kdf_labels::identity_signing_key(user))
        .expect("read the identity key")
        .expect("the unlock restored an identity key");
    let key: [u8; 32] = hex::decode(&in_place).expect("hex").try_into().expect("32 bytes");
    let in_place = ed25519_dalek::SigningKey::from_bytes(&key).verifying_key().to_bytes();
    assert_eq!(
        hex::encode(in_place),
        recovered_key_hex,
        "the unlock restored a key other than the one the recovery installed"
    );
    in_place
}

/// **Recovering on a device that kept its sealed copy seals it again, in the same
/// act, under the passphrase chosen for it.**
///
/// The device the person used keeps the copy of their keys sealed under their old
/// passphrase. Recovered there, against the vault it is enrolled with and with a
/// new passphrase, the daemon replaces that copy and says so: it sealed the key the
/// recovery replaced. [`only_the_chosen_passphrase_unlocks`] holds the rest, and
/// the key a restart's unlock restores is not the replaced one. Red without the
/// replacement: the old passphrase unlocks, and a restart's unlock under it restores
/// the replaced key.
#[tokio::test]
async fn recovering_on_a_device_that_kept_its_sealed_copy_reseals_under_the_new_passphrase() {
    init_crypto();
    let vault = spawn_vault("vault").await;
    let device = spawn_device("device D").await;
    let mut client = connect_when_ready(&device.ipc, "client D").await;
    let phrase = a_person_with_things(&mut client, "alice", NOTE).await;
    let (mut client, identity) = enrol_vault(client, &vault, "alice", "vault").await;
    let base = device._base.path().to_owned();
    assert!(
        base.join("users").join("alice").join(kotton_identity::provisioning::VAULT_FILE).exists(),
        "the premise: this device kept a sealed copy"
    );
    let replaced = kotton_identity::kel_store::resolve_current_key_for(&base, "alice", false)
        .expect("the key log replays")
        .expect("a key before the recovery");

    let recovered = client
        .recover("alice", &phrase, NEW_PASSPHRASE, &identity.line())
        .await
        .expect("recover on the device that kept its copy");
    assert!(recovered.sealed_copy_removed, "the daemon did not say it replaced the copy");

    let in_place = only_the_chosen_passphrase_unlocks(&device, "alice", &recovered.new_key_hex).await;
    assert_ne!(in_place, replaced, "the unlock restored the key the recovery replaced");
}

/// **A device that never held the identity is sealed, in the same act, under the
/// passphrase chosen at the recovery, and no other.** `id login` claims the name with
/// no passphrase and no sealed copy; the recovery removes nothing and says so, and
/// [`only_the_chosen_passphrase_unlocks`] holds that the person's passphrase on the
/// device they lost opens nothing here.
#[tokio::test]
async fn recovering_on_a_fresh_device_seals_under_the_passphrase_chosen_there() {
    init_crypto();
    let vault = spawn_vault("vault").await;
    let (phrase, identity) = {
        let device = spawn_device("device E").await;
        let mut client = connect_when_ready(&device.ipc, "client E").await;
        let phrase = a_person_with_things(&mut client, "alice", NOTE).await;
        let (_client, identity) = enrol_vault(client, &vault, "alice", "vault").await;
        (phrase, identity)
        // Every device is lost here.
    };
    tokio::time::sleep(Duration::from_millis(200)).await;

    let cold = spawn_device("cold device").await;
    let mut client = connect_when_ready(&cold.ipc, "cold client").await;
    client
        .login_with_recovery_key(&phrase, Some("alice".to_string()), None)
        .await
        .expect("the phrase alone claims the identity on a cold device");
    let recovered =
        client.recover("alice", &phrase, NEW_PASSPHRASE, &identity.line()).await.expect("recover on a cold device");
    assert!(!recovered.sealed_copy_removed, "a device that never held the identity had a copy to replace");

    only_the_chosen_passphrase_unlocks(&cold, "alice", &recovered.new_key_hex).await;
}

/// The same demonstration with the vault's pools on an S3-compatible bucket
/// (RFC-0084 V5): the shelf is beneath, the device never sees it, and the
/// landlord's bucket holds sealed packs and nothing readable. The server is a
/// real one in this process (`s3s-fs`), so the vault's requests are signed
/// and checked, not mocked.
#[tokio::test]
async fn a_vault_on_a_bucket_keeps_what_a_device_pushes_and_gives_it_back_from_the_phrase() {
    init_crypto();
    let bucket = crate::common::s3::serve("kotton").await;
    let vault = spawn_vault_on("vault", bucket.shelves(Some("vault-1"))).await;
    let phrase;
    let identity;
    {
        let device = spawn_device("device S").await;
        let mut client = connect_when_ready(&device.ipc, "client S").await;
        phrase = a_person_with_things(&mut client, "alice", NOTE).await;
        let (mut client, id) = enrol_vault(client, &vault, "alice", "vault").await;
        identity = id;
        let pushed = client
            .sync_mount("alice", "local", "vault", Some(SyncDirection::Push))
            .await
            .expect("push everything to the vault");
        assert!(pushed.pushed >= 1);

        // The meter reads the bucket, and it is the same meter.
        let mut door = connect_when_ready(&vault.ipc, "door").await;
        let (held, _) = door.vault_capacity("alice").await.expect("capacity");
        assert!(held > 0, "the vault holds what was pushed: {held}");
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    // What the landlord has: keys under their prefix and the pool's name,
    // sealed bytes, and not one of them the note.
    let keys = bucket.keys();
    assert!(!keys.is_empty(), "the bucket holds the pool");
    assert!(
        keys.iter().all(|k| k.starts_with("vault-1/alice/local/")),
        "every object is under the landlord's prefix and the pool: {keys:?}"
    );
    for key in &keys {
        let bytes = std::fs::read(bucket.bucket_dir().join(key)).unwrap();
        assert!(
            !bytes.windows(NOTE.len()).any(|w| w == NOTE),
            "the note is readable in the bucket at {key}"
        );
    }
    // And the vault's own disk holds no pool data: the shelf is the bucket.
    let on_disk = std::fs::read_dir(vault.base_path.join("users").join("alice").join("data"))
        .map(|d| d.count())
        .unwrap_or(0);
    assert_eq!(on_disk, 0, "the pool's objects are on the shelf, not beside the vault");

    let (_cold_device, mut cold) = recover_from(&phrase, "alice", &identity).await;
    assert_eq!(cold.read_file("alice", "notes.txt").await.expect("file").as_slice(), NOTE);
    let recs = cold
        .record_query("alice", "com.test.notes", vec![], None, None)
        .await
        .expect("records");
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0]["title"], "survives");
}

/// Everything a vault holds for `user` in its pool, as `(key, length)`.
fn pool_of(vault: &RunningVault, user: &str) -> Vec<(String, u64)> {
    let pool = vault.base_path.join("users").join(user).join("data");
    let mut held: Vec<(String, u64)> = Vec::new();
    let mut pending = vec![pool.clone()];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                let rel = path.strip_prefix(&pool).unwrap().to_string_lossy().replace('\\', "/");
                held.push((rel, entry.metadata().unwrap().len()));
            }
        }
    }
    held
}

/// RFC-0070 M3 at the vault: everything in `user`'s pool is a pack of its
/// class's fixed size (a content pack `PACK_SIZE`, an index pack
/// `INDEX_PACK_SIZE` or `PACK_SIZE`, kotton #55) or a superblock, every
/// superblock is one length, and there is at least one pack — so no object
/// there says how large anything was.
pub(crate) fn the_pool_holds_only_packs(vault: &RunningVault, user: &str) {
    use kotton_store::packed::{has_its_fixed_size, PACK_PREFIX};
    use kotton_store::superblock::SUPERBLOCK_PREFIX;

    let held = pool_of(vault, user);
    assert!(
        held.iter().any(|(k, _)| k.starts_with(&format!("{PACK_PREFIX}/"))),
        "the vault holds at least one pack: {held:?}"
    );
    let mut superblock_lengths = std::collections::BTreeSet::new();
    for (key, len) in &held {
        if key.starts_with(&format!("{PACK_PREFIX}/")) {
            assert!(has_its_fixed_size(key, *len), "pack {key} is {len} bytes, not its class's fixed size");
        } else if key.starts_with(&format!("{SUPERBLOCK_PREFIX}/")) {
            superblock_lengths.insert(*len);
        } else {
            panic!("the vault holds {key} at {len} bytes, which is neither a pack nor a superblock: {held:?}");
        }
    }
    assert!(
        superblock_lengths.len() <= 1,
        "every superblock is one length: {superblock_lengths:?}"
    );
}

/// Sizes no pack and no superblock could be mistaken for, each different, so a
/// loose copy of any of them would rest at the vault at its own length.
const SIZED: [(&str, usize); 3] = [("a.bin", 1_000), ("b.bin", 37_000), ("c.bin", 300_000)];

/// A person with things and the [`SIZED`] files, ready to push.
async fn a_person_with_sized_files(client: &mut kotton::KottonClient, user: &str) -> String {
    let phrase = a_person_with_things(client, user, NOTE).await;
    for (name, len) in SIZED {
        client
            .write_file(user, name, &vec![0x5a; len])
            .await
            .expect("write_file");
    }
    phrase
}

/// What reached the vault is the person's: a phrase-only device recovers
/// every [`SIZED`] file from it. A push that withheld a loose file rather than
/// packing it would leave the vault holding only packs and still fail here.
async fn every_sized_file_comes_back(phrase: &str, user: &str, identity: &VaultIdentity) {
    let (_cold_device, mut cold) = recover_from(phrase, user, identity).await;
    for (name, len) in SIZED {
        assert_eq!(
            cold.read_file(user, name).await.unwrap_or_else(|e| panic!("{name} from the vault: {e}")),
            vec![0x5a; len],
            "{name} came back whole"
        );
    }
}

/// Files pushed to a vault by hand rest there only in packs (RFC-0070 M3,
/// `TASK-a-manual-sync-to-a-vault-sends-loose-objects-without-packing-first`).
///
/// A blind vault cannot open what it holds, but it can measure it, and a loose
/// object's length is its file's length plus a constant. So the push a person
/// starts with `kotton sync` — the `SyncMount` request — packs first and sends
/// only packs, as the background engine's push does. Several files of
/// different sizes are pushed; afterwards the pool holds only packs and
/// superblocks, and a phrase-only device gets every file back from it.
#[tokio::test]
async fn files_pushed_by_hand_rest_at_the_vault_only_in_packs() {
    init_crypto();
    let vault = spawn_vault("vault").await;
    let phrase;
    let identity;
    {
        let device = spawn_device("device P").await;
        let mut client = connect_when_ready(&device.ipc, "client P").await;
        phrase = a_person_with_sized_files(&mut client, "alice").await;
        let (mut client, id) = enrol_vault(client, &vault, "alice", "vault").await;
        identity = id;
        let pushed = client
            .sync_mount("alice", "local", "vault", Some(SyncDirection::Push))
            .await
            .expect("push by hand to the vault");
        assert!(pushed.pushed >= 1, "something was pushed: {pushed:?}");
    }
    the_pool_holds_only_packs(&vault, "alice");
    every_sized_file_comes_back(&phrase, "alice", &identity).await;
}

/// The background engine's half of the same property: a pass the engine runs
/// toward a vault — `SyncDrives`, through its transient `__sync_bg__` remote
/// with a `Kotton` backend — leaves the pool holding only packs and
/// superblocks, and every file comes back from it.
#[tokio::test]
async fn files_the_engine_syncs_rest_at_the_vault_only_in_packs() {
    init_crypto();
    let vault = spawn_vault("vault").await;
    let phrase;
    let identity;
    {
        let device = spawn_device("device Q").await;
        let mut client = connect_when_ready(&device.ipc, "client Q").await;
        phrase = a_person_with_sized_files(&mut client, "alice").await;
        let (mut client, id) = enrol_vault(client, &vault, "alice", "vault").await;
        identity = id;
        client
            .configure_sync("alice", "vault", Some(SyncDirection::Push), false)
            .await
            .expect("a sync rule for the vault");
        let (job, _drives) = client.sync_drives("alice").await.expect("trigger the engine");
        let outcome = client.sync_await("alice", job, 120).await.expect("the engine's pass");
        assert!(outcome.files >= 1, "the engine pushed something: {outcome:?}");
    }
    the_pool_holds_only_packs(&vault, "alice");
    every_sized_file_comes_back(&phrase, "alice", &identity).await;
}

/// A vault answers its verbs and nothing else — at its door, and over the
/// authenticated peer transport a paired device dials. The plaintext verbs are
/// not refused by a check; they are absent, and the refusal names the verbs
/// that exist.
#[tokio::test]
async fn a_vault_answers_its_verbs_and_nothing_else() {
    use ed25519_dalek::SigningKey;
    use kotton_net::transport::quic::tls::CertOffer;
    use kotton_peer::nat::{nat_connect, NatConfig, NatResult};
    use kotton_peer::{PeerChannel as _, QuicPeerChannel};

    init_crypto();
    let vault = spawn_vault("vault").await;
    let device = spawn_device("device").await;
    let mut client = connect_when_ready(&device.ipc, "client").await;
    let _phrase = a_person_with_things(&mut client, "alice", NOTE).await;
    let (_client, identity) = enrol_vault(client, &vault, "alice", "vault").await;

    // At the door: a data verb is not a vault's. The door decodes its own
    // request type, so `ReadFile` is unconstructible there — the acceptor
    // closes the connection rather than answering, and the client sees an
    // error with no reply in it.
    let mut door = connect_when_ready(&vault.ipc, "door").await;
    door.read_file("alice", "notes.txt")
        .await
        .expect_err("a vault's door reads no file");
    // The door still answers what it has, on a fresh connection.
    let mut door = connect_when_ready(&vault.ipc, "door").await;
    let (_, quota) = door.vault_capacity("alice").await.expect("capacity at the door");
    assert_eq!(quota, None);

    // Over the peer transport, as the paired device itself: the same absence.
    // The dial is the device's own — its operational key, a direct address —
    // and the request rides one bidirectional stream, as every peer verb does.
    let key: SigningKey =
        kotton_peer::daemon::nodes::load_device_operational_key(&*device.secrets).expect("device key");
    let vault_pub: [u8; 32] = hex::decode(&identity.pubkey_hex)
        .unwrap()
        .try_into()
        .unwrap();
    let offer = CertOffer {
        admission: vec![],
        claim: None,
    };
    let conn = match nat_connect(
        &key,
        &offer,
        vault_pub,
        Some(identity.op_addr),
        &NatConfig::default(),
        None,
    )
    .await
    {
        NatResult::Direct(c) | NatResult::Punched(c) => c,
        other => panic!("the paired device's key opens the vault directly: {other:?}"),
    };
    let channel = QuicPeerChannel::new(conn);
    let ask = |req: UserRequest| {
        let channel = &channel;
        async move {
            let raw = channel
                .request(&serde_json::to_vec(&req).unwrap())
                .await
                .expect("the vault answers");
            serde_json::from_slice::<UserResponse>(&raw).unwrap()
        }
    };
    match ask(UserRequest::ReadFile {
        user_id: "alice".into(),
        path: "notes.txt".into(),
        offset: 0,
        length: 0,
    })
    .await
    {
        UserResponse::Error { message } => {
            assert!(message.contains("not a vault's verb"), "{message}")
        }
        other => panic!("a vault answered a plaintext verb: {other:?}"),
    }
    // Plaintext record rows have no verb on the peer wire at all (kotton #173):
    // records move as sealed segments of the record log, and the verb that once
    // pushed rows for a device to merge is gone, so a vault cannot be asked to
    // take them and a paired peer cannot push them into a device. The request
    // is written as the bytes such a peer would send, because the type no longer
    // has the variant to build it from. Both daemons decode a peer's request as
    // `UserRequest`, so the refusal is the decoder's, before any standing is read
    // — and were the verb back, the vault would answer "not a vault's verb"
    // instead, which this does not accept.
    let pushed = serde_json::json!({
        "ApplyRecordChangeset": {
            "user_id": "alice",
            "nsid": "com.test.notes",
            "rows": [{
                "id": "00000000-0000-4000-8000-000000000000",
                "schema_nsid": "com.test.notes",
                "body": { "text": "planted" },
                "updated_at": 1,
                "deleted_at": null
            }]
        }
    });
    let raw = channel
        .request(&serde_json::to_vec(&pushed).unwrap())
        .await
        .expect("the vault answers");
    match serde_json::from_slice::<UserResponse>(&raw).unwrap() {
        UserResponse::Error { message } => assert!(
            message.contains("invalid peer request") && message.contains("unknown variant `ApplyRecordChangeset`"),
            "plaintext record rows are no request on the peer wire: {message}"
        ),
        other => panic!("a peer request carrying plaintext record rows was taken: {other:?}"),
    }
    // And the meter answers over the same connection.
    match ask(UserRequest::VaultCapacity {
        user_id: "alice".into(),
    })
    .await
    {
        UserResponse::VaultCapacityResult { quota, .. } => assert_eq!(quota, None),
        other => panic!("no capacity readout: {other:?}"),
    }
}

/// A pool fills to its quota and no further, the refusal carries the two
/// numbers, and the landlord raises the number while the vault serves.
#[tokio::test]
async fn a_pool_fills_to_its_quota_and_the_number_is_shown() {
    init_crypto();
    let vault = spawn_vault("vault").await;
    let device = spawn_device("device").await;
    let mut client = connect_when_ready(&device.ipc, "client").await;
    let _phrase = a_person_with_things(&mut client, "alice", NOTE).await;
    let (mut client, _identity) = enrol_vault(client, &vault, "alice", "vault").await;

    // A quota between one pack and two. A push to a vault sends packs only
    // (RFC-0070 M3) — the 64 KiB file crosses inside one, never as an object
    // of its own — and this push is two: the files' and the record log's.
    // Packs sort first and cross first, so the pool takes one pack, fills to
    // its number, and refuses the next. Until 2026-10-08 a 16 KiB quota here
    // refused the loose 64 KiB object itself
    // (`TASK-a-manual-sync-to-a-vault-sends-loose-objects-without-packing-first`).
    use kotton_store::pack::PACK_SIZE;
    const QUOTA: u64 = PACK_SIZE as u64 + PACK_SIZE as u64 / 2;
    let big = vec![7u8; 64 * 1024];
    client.write_file("alice", "big.bin", &big).await.expect("write big");
    vault.vault.meter().set_default_quota(Some(QUOTA));

    let outcome = client
        .sync_mount("alice", "local", "vault", Some(SyncDirection::Push))
        .await;
    let refused = outcome.expect_err("a push past the quota does not land whole").to_string();
    assert!(
        refused.contains("VaultFull") && refused.contains(&format!("quota: {QUOTA}")),
        "the refusal carries the number: {refused}"
    );
    let mut door = connect_when_ready(&vault.ipc, "door").await;
    let (held, quota) = door.vault_capacity("alice").await.expect("capacity");
    assert_eq!(quota, Some(QUOTA));
    assert!(
        (PACK_SIZE as u64..=QUOTA).contains(&held),
        "the pool filled to one pack and no further: held {held}"
    );

    // The landlord raises the number. No restart, no ceremony.
    vault.vault.meter().set_default_quota(Some(64 * 1024 * 1024));
    let pushed = client
        .sync_mount("alice", "local", "vault", Some(SyncDirection::Push))
        .await
        .expect("the push lands once the number is larger");
    assert!(pushed.pushed >= 1);
    let (held, quota) = door.vault_capacity("alice").await.expect("capacity");
    assert_eq!(quota, Some(64 * 1024 * 1024));
    assert!(held >= big.len() as u64, "held {held} counts the big object");
}

/// What `kvaultd invite <user> --quota <bytes>` sends once the invite is
/// minted, and what `kvaultd capacity <user> --set <bytes>` sends: the door's
/// own verb, which no device's wire can say. Answers the pool's readout.
async fn set_quota_at_the_door(ipc: &IpcEndpoint, user: &str, quota: u64) -> (u64, Option<u64>) {
    let mut door = kotton_ipc::IpcClient::<VaultRequest, UserResponse>::connect(ipc.clone())
        .await
        .expect("the landlord reaches the door");
    match door
        .send(&VaultRequest::SetQuota {
            user_id: user.to_string(),
            quota,
        })
        .await
        .expect("the door answers")
    {
        UserResponse::VaultCapacityResult { held, quota } => (held, quota),
        other => panic!("the door did not set {user}'s quota: {other:?}"),
    }
}

/// Send `request` to the vault over the peer transport as `device` itself —
/// its operational key, the vault's direct address — and read the answer.
/// `request` is raw JSON so a test can send what a device's wire cannot build.
async fn ask_the_vault_as(device: &RunningDevice, vault: &VaultIdentity, request: Vec<u8>) -> UserResponse {
    try_ask_the_vault_as(device, vault, request)
        .await
        .unwrap_or_else(|e| panic!("the device's key opens the vault directly and it answers: {e}"))
}

/// [`ask_the_vault_as`], with a refusal at the handshake or on the stream as
/// an `Err` rather than a panic — for a device the vault no longer admits.
pub(crate) async fn try_ask_the_vault_as(
    device: &RunningDevice,
    vault: &VaultIdentity,
    request: Vec<u8>,
) -> Result<UserResponse, String> {
    use kotton_net::transport::quic::tls::CertOffer;
    let key = kotton_peer::daemon::nodes::load_device_operational_key(&*device.secrets).expect("device key");
    let offer = CertOffer {
        admission: vec![],
        claim: None,
    };
    try_ask_the_vault_with(&key, &offer, vault, request).await
}

/// Dial the vault under `key`, offering `offer` in the certificate — a
/// recovery claim, say, as a phrase-only device does — and send `request`.
/// `Err` is a refusal at the handshake or on the stream.
async fn try_ask_the_vault_with(
    key: &ed25519_dalek::SigningKey,
    offer: &kotton_net::transport::quic::tls::CertOffer,
    vault: &VaultIdentity,
    request: Vec<u8>,
) -> Result<UserResponse, String> {
    use kotton_peer::nat::{nat_connect, NatConfig, NatResult};
    use kotton_peer::{PeerChannel as _, QuicPeerChannel};

    let vault_pub: [u8; 32] = hex::decode(&vault.pubkey_hex).unwrap().try_into().unwrap();
    let conn = match nat_connect(key, offer, vault_pub, Some(vault.op_addr), &NatConfig::default(), None).await {
        NatResult::Direct(c) | NatResult::Punched(c) => c,
        other => return Err(format!("no connection: {other:?}")),
    };
    let raw = QuicPeerChannel::new(conn)
        .request(&request)
        .await
        .map_err(|e| format!("no answer: {e}"))?;
    serde_json::from_slice::<UserResponse>(&raw).map_err(|e| e.to_string())
}

/// Two tenants at one vault, each with the number the landlord set aside for
/// them at the invite: one fills to its number and is refused past it, and the
/// other, holding more than that number, still writes. The landlord's default
/// (`KVAULTD_QUOTA_BYTES`) is smaller than both, so a meter that held either
/// pool to the default, or to the other's number, fails here. And neither
/// tenant can read the other's numbers or set any.
///
/// Bounded and multi-threaded, as the enrolment tests below are and for their
/// reason: a step that stops says which step.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_tenants_are_each_held_to_the_quota_set_aside_for_them() {
    // Pack-sized numbers: a push to a vault sends packs only (RFC-0070 M3),
    // and each tenant's push is two 16 MiB packs, so alice's number takes one
    // and refuses the second while bob's takes both. Until 2026-10-08 these
    // were 16 KiB and 32 KiB, against a loose 64 KiB object
    // (`TASK-a-manual-sync-to-a-vault-sends-loose-objects-without-packing-first`).
    const MIB: u64 = 1024 * 1024;
    const DEFAULT: u64 = 16 * MIB;
    const ALICE: u64 = 24 * MIB;
    const BOB: u64 = 96 * MIB;
    const { assert!(DEFAULT < ALICE && ALICE < BOB) };
    let big = vec![7u8; 64 * 1024];

    init_crypto();
    let vault = within("starting the vault", spawn_vault("vault")).await;
    // What `KVAULTD_QUOTA_BYTES` sets at start, set in-process: the
    // environment is shared by every test running beside this one.
    vault.vault.meter().set_default_quota(Some(DEFAULT));
    // The invite's `--quota`, sent before either is admitted.
    let (_, a) = within("setting alice's quota", set_quota_at_the_door(&vault.ipc, "alice", ALICE)).await;
    let (_, b) = within("setting bob's quota", set_quota_at_the_door(&vault.ipc, "bob", BOB)).await;
    assert_eq!((a, b), (Some(ALICE), Some(BOB)), "the door answers each pool's own number");

    let alice_device = within("starting alice's device", spawn_device("alice")).await;
    let mut alice = within("alice's client", connect_when_ready(&alice_device.ipc, "alice")).await;
    within("alice's things", a_person_with_things(&mut alice, "alice", b"alice's note")).await;
    // Each tenant's device announces its own name: two that share one unpair
    // each other at a vault today, which is its own record
    // (`TASK-two-tenants-whose-devices-share-a-name-unpair-each-other-at-a-vault`).
    let (mut alice, _alice_vault) = within(
        "enrolling alice",
        enrol_vault_from(alice, "alice's laptop", &vault, "alice", "vault"),
    )
    .await;

    let bob_device = within("starting bob's device", spawn_device("bob")).await;
    let mut bob = within("bob's client", connect_when_ready(&bob_device.ipc, "bob")).await;
    within("bob's things", a_person_with_things(&mut bob, "bob", b"bob's note")).await;
    let (mut bob, bob_vault) = within(
        "enrolling bob",
        enrol_vault_from(bob, "bob's laptop", &vault, "bob", "vault"),
    )
    .await;

    // Alice fills to her number: the pack past it is refused, and the
    // refusal is the one the single quota gave — `VaultFull`, naming her own
    // number, not the default and not bob's.
    within("alice writes", alice.write_file("alice", "big.bin", &big))
        .await
        .expect("write big");
    let outcome = within(
        "alice's push",
        alice.sync_mount("alice", "local", "vault", Some(SyncDirection::Push)),
    )
    .await;
    let refused = outcome.expect_err("a push past alice's number does not land").to_string();
    assert!(
        refused.contains("VaultFull") && refused.contains(&format!("quota: {ALICE}")),
        "the refusal is VaultFull at alice's own number: {refused}"
    );
    let mut door = within("the landlord's door", connect_when_ready(&vault.ipc, "door")).await;
    let (alice_held, alice_quota) = within("alice's capacity", door.vault_capacity("alice"))
        .await
        .expect("capacity");
    assert_eq!(alice_quota, Some(ALICE), "capacity prints alice's own number");
    assert!(alice_held <= ALICE, "alice holds {alice_held}, past her {ALICE}");

    // Bob, beside her, writes the same object and more than her whole number.
    within("bob writes", bob.write_file("bob", "big.bin", &big))
        .await
        .expect("write big");
    let pushed = within(
        "bob's push",
        bob.sync_mount("bob", "local", "vault", Some(SyncDirection::Push)),
    )
    .await
    .expect("bob is still writable while alice is full");
    assert!(pushed.pushed >= 1);
    let (bob_held, bob_quota) = within("bob's capacity", door.vault_capacity("bob"))
        .await
        .expect("capacity");
    assert_eq!(bob_quota, Some(BOB), "capacity prints bob's own number");
    // The default is smaller than alice's number, so past hers is past both.
    assert!(
        bob_held > ALICE,
        "bob holds {bob_held}: more than alice's number and the default, under his own"
    );

    // The numbers are the landlord's and each tenant's own. Bob's device,
    // paired with bob's pool, asks for alice's: a stranger to her pool.
    let asked = serde_json::to_vec(&UserRequest::VaultCapacity {
        user_id: "alice".into(),
    })
    .unwrap();
    match within("bob asks for alice's numbers", ask_the_vault_as(&bob_device, &bob_vault, asked)).await {
        // Refused, naming bob's own pool and the one he asked as — what a
        // key paired here learns, and nothing about alice's but the name he
        // sent (`TASK-a-vault-invite-names-a-tenant-the-device-does-not-sync-as`).
        UserResponse::Error { message } => assert!(
            message.contains("not paired")
                && message.contains("this device is paired here as tenant `bob`, and asked as `alice`"),
            "{message}"
        ),
        other => panic!("bob read alice's capacity: {other:?}"),
    }
    // And his own is his to read.
    let own = serde_json::to_vec(&UserRequest::VaultCapacity { user_id: "bob".into() }).unwrap();
    match within("bob asks for his own", ask_the_vault_as(&bob_device, &bob_vault, own)).await {
        UserResponse::VaultCapacityResult { quota, .. } => assert_eq!(quota, Some(BOB)),
        other => panic!("bob could not read his own capacity: {other:?}"),
    }
    // No tenant sets a number. The verb is on the peer transport — the vault's
    // operator credential says it there — and a tenant's device, paired and
    // not the operator, is refused it by standing
    // (`TASK-the-landlords-verbs-reach-the-desktop-over-the-wire`).
    let set = serde_json::to_vec(&VaultRequest::SetQuota {
        user_id: "bob".into(),
        quota: u64::MAX,
    })
    .unwrap();
    match within("bob tries to set his own number", ask_the_vault_as(&bob_device, &bob_vault, set)).await {
        UserResponse::Error { message } => {
            assert!(message.contains("a tenant's device does not say it"), "{message}")
        }
        other => panic!("a tenant set a quota over the peer transport: {other:?}"),
    }
    assert_eq!(vault.vault.meter().quota("bob"), Some(BOB), "and bob's number is unchanged");
}

/// Enrol `key`'s public half at `vault`'s door, as `kvaultd operator enrol`
/// does at its terminal.
async fn admit_at_the_door(vault: &RunningVault, key: &ed25519_dalek::SigningKey) {
    let public = hex::encode(key.verifying_key().to_bytes());
    let mut door = kotton_ipc::IpcClient::<VaultRequest, UserResponse>::connect(vault.ipc.clone())
        .await
        .expect("the landlord reaches the door");
    match door
        .send(&VaultRequest::OperatorAdmit { key: public })
        .await
        .expect("the door answers")
    {
        UserResponse::Ok => {}
        other => panic!("the door did not enrol the operator credential: {other:?}"),
    }
}

/// A vault's operator credential, whole, in the `kotton-operator 2` form
/// (DEC-0087) under the name `kotton`, for `key` — what `mint vault` and
/// the vault's `enrol` leave in a desktop's store, written out so a test can hand it
/// over in one step. It names no relay: where the vault stands is what the
/// desktop tells it (`TASK-the-desktop-tells-the-vault-which-relays-to-stand-at`).
fn vault_credential_text(vault: &RunningVault, vault_key_hex: &str, key: &ed25519_dalek::SigningKey) -> String {
    format!(
        "kotton-operator 2\nname=kotton\noperator={}\nkey={}\nvault={vault_key_hex}\naddr=127.0.0.1:{}\n",
        hex::encode(key.to_bytes()),
        hex::encode(key.verifying_key().to_bytes()),
        vault.op_port,
    )
}

/// A relay's operator credential, whole, in the `kotton-operator 2` form under
/// the name `kotton`, for `key` — what `mint relay` and the relay's `enrol` leave.
fn relay_credential_text(relay_url: &str, key: &ed25519_dalek::SigningKey) -> String {
    format!(
        "kotton-operator 2\nname=kotton\noperator={}\nkey={}\nrelay={relay_url}\n",
        hex::encode(key.to_bytes()),
        hex::encode(key.verifying_key().to_bytes()),
    )
}

/// A vault's operator credential: a fresh key, enrolled at the vault's door by
/// its public half (`kvaultd operator enrol`), and the credential text the
/// desktop takes.
async fn operator_credential(vault: &RunningVault, vault_key_hex: &str) -> (ed25519_dalek::SigningKey, String) {
    let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    admit_at_the_door(vault, &key).await;
    let text = vault_credential_text(vault, vault_key_hex, &key);
    (key, text)
}

/// A vault and a relay as `docs/use/` stands them up, each with its own
/// operator key enrolled at its own terminal (DEC-0087)
/// (`TASK-a-device-presents-its-relays-admission-tag-and-the-reach-row-sets-the-rule`):
/// the relay and the vault as released binaries under systemd, the vault
/// reserving at the relay, then `kvaultd operator enrol <key>` for the vault's
/// key and the relay's `operator enrol <key>` for the relay's, against its
/// `--state-dir`. Here the relay is the built `kotton-relay` with its key
/// enrolled at its terminal into a state directory of its own to keep its rule
/// in, and the vault runs in-process with its key enrolled at its door —
/// beside the two credentials' texts for a desktop to enrol. The vault stands
/// nowhere until a desktop holding both credentials tells it where
/// (`TASK-the-desktop-tells-the-vault-which-relays-to-stand-at`): the two meet
/// only there. Nobody has set a rule, so the relay admits every signed handle.
pub(crate) struct ABox {
    pub _relay: crate::common::relay::Relay,
    pub relay_addr: String,
    pub relay_url: String,
    /// The key the relay proves — what it is named by, and what every key
    /// presented there is held under.
    pub relay_id: [u8; 32],
    pub vault: RunningVault,
    pub vault_credential: String,
    pub relay_credential: String,
    /// The vault's credential's key.
    pub vault_key: ed25519_dalek::SigningKey,
    /// The relay's credential's key, for asking the relay directly what it
    /// holds — what no desktop's answer can stand in for.
    pub relay_key: ed25519_dalek::SigningKey,
}

impl ABox {
    /// The rule the relay itself reports, asked under the relay's operator key
    /// and through no desktop.
    pub async fn rule_at_the_relay(&self) -> kotton_wire::rendezvous::AdmissionRule {
        use kotton_wire::rendezvous::{RelayOperatorRequest, RelayOperatorResponse};
        match kotton_net::rendezvous::say_as_operator(&self.relay_url, &self.relay_key, &RelayOperatorRequest::ReadRule)
            .await
            .expect("the relay answers its operator")
        {
            RelayOperatorResponse::Rule { rule, .. } => rule,
            other => panic!("the relay did not say its rule: {other:?}"),
        }
    }

    /// Keep both credentials on `client`'s desktop as `user`: the vault's
    /// first, then the relay's — the order `docs/use/run-a-vault.md` types, so
    /// a rule the relay's carries is set with a vault there to hand keys to.
    pub async fn enrol_on(&self, client: &mut kotton::KottonClient, user: &str) {
        within("keeping the vault's credential", client.operator_enrol(user, &self.vault_credential))
            .await
            .expect("the desktop keeps the vault's credential");
        within("keeping the relay's credential", client.operator_enrol(user, &self.relay_credential))
            .await
            .expect("the desktop keeps the relay's credential");
    }
}

pub(crate) async fn a_box() -> ABox {
    let vault_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let relay_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let (relay, relay_addr) = within(
        "starting the relay",
        crate::common::relay::spawn_with_operator(&hex::encode(relay_key.verifying_key().to_bytes())),
    )
    .await;
    let relay_url = format!("http://{relay_addr}");
    let relay_id = within("the relay's key", crate::common::relay::key_of(&relay_addr)).await;
    let vault = within("starting the vault", spawn_vault("vault")).await;
    let mut door = within("the landlord's door", connect_when_ready(&vault.ipc, "door")).await;
    let (_, vault_key_hex) = within("the vault's identity", door.get_node_identity())
        .await
        .expect("the door says who the vault is");
    admit_at_the_door(&vault, &vault_key).await;
    let vault_credential = vault_credential_text(&vault, &vault_key_hex, &vault_key);
    let relay_credential = relay_credential_text(&relay_url, &relay_key);
    ABox {
        _relay: relay,
        relay_addr,
        relay_url,
        relay_id,
        vault,
        vault_credential,
        relay_credential,
        vault_key,
        relay_key,
    }
}

/// A stranger at `relay_url`: a handle nobody was given, pushing an address
/// with a tag under `key` if one is named. The relay's answer, as the device's
/// own client reads it.
pub(crate) async fn a_push_at(
    relay_url: &str,
    key: Option<kotton_net::rendezvous::AdmissionKey>,
) -> Result<u32, kotton_net::rendezvous::RendezvousError> {
    let handle = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let did = kotton_crypto::DidKeyMethod::from_public_key_bytes(&handle.verifying_key().to_bytes())
        .unwrap()
        .to_string();
    kotton_net::rendezvous::RendezvousClient::new(relay_url, did, handle)
        .with_admission(key)
        .push("203.0.113.7:4000".parse().unwrap(), None, true)
        .await
}

/// A lookup by the same kind of stranger, for an address nobody pushed.
async fn a_lookup_at(
    relay_url: &str,
    key: Option<kotton_net::rendezvous::AdmissionKey>,
) -> Result<(SocketAddr, Option<SocketAddr>), kotton_net::rendezvous::RendezvousError> {
    let handle = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let did = kotton_crypto::DidKeyMethod::from_public_key_bytes(&handle.verifying_key().to_bytes())
        .unwrap()
        .to_string();
    kotton_net::rendezvous::RendezvousClient::new(relay_url, did.clone(), handle)
        .with_admission(key)
        .lookup(&did)
        .await
}

/// Whether the relay refused a request at its door: 403, the one answer its
/// rule gives, whatever the caller lacked.
pub(crate) fn refused_by_the_rule<T: std::fmt::Debug>(r: &Result<T, kotton_net::rendezvous::RendezvousError>) -> bool {
    matches!(r, Err(kotton_net::rendezvous::RendezvousError::HttpError { status: 403, .. }))
}

/// Say `verb` from `client` as `user`, and read the rule the relay answered.
async fn rule_said(
    client: &mut kotton::KottonClient,
    user: &str,
    verb: kotton_wire::ipc::OperatorVerb,
) -> kotton_wire::rendezvous::AdmissionRule {
    match within_for(WHOLE, "the relay's rule", client.as_operator(user, "kotton", verb))
        .await
        .expect("the desktop's daemon answers")
    {
        UserResponse::RelayRule { rule } => rule,
        other => panic!("the relay's rule was not answered: {other:?}"),
    }
}

/// **A desktop holding the relay's operator credential sets the relay's rule,
/// and a stranger is refused at its door**
/// (`TASK-a-device-presents-its-relays-admission-tag-and-the-reach-row-sets-the-rule`,
/// Done-when 1 and 2).
///
/// Against the relay `common::relay` spawns, with the operator's key enrolled
/// at its terminal as `docs/use/run-a-vault.md`'s `kotton-relay operator enrol`
/// does. Before any set the relay admits every signed handle. The desktop reads *anyone*, sets *only my devices*,
/// and reads it back; from then a stranger's push and lookup are refused, and
/// a request tagged under the desktop's own key — the key it minted, kept
/// sealed and holds in its keyring — is admitted, where one under the invited
/// key is not. The vault was handed *mine* before the set, and presents it:
/// an invite the desktop asks for after the narrowing is reserved at the relay,
/// which a vault without the key could not do. A second desktop holding no
/// credential cannot set it, and a key that is not an operator's is refused
/// by the relay itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_desktop_holding_the_operator_credential_sets_the_relays_rule_and_a_stranger_is_refused() {
    use kotton_wire::ipc::OperatorVerb;
    use kotton_wire::rendezvous::{AdmissionRule, RelayOperatorRequest};

    init_crypto();
    let bx = a_box().await;
    let mut desk = within("the operator's desktop", crate::common::relay::env_on(&bx.relay_addr)).await;
    within("the operator's identity", desk.client.create_user("lee", crate::common::TEST_PASSPHRASE))
        .await
        .expect("create_user");
    bx.enrol_on(&mut desk.client, "lee").await;

    // Nobody has set a rule: anyone is admitted.
    assert!(a_push_at(&bx.relay_url, None).await.is_ok(), "a relay with no rule set refused a stranger");
    assert_eq!(rule_said(&mut desk.client, "lee", OperatorVerb::ReadRule).await, AdmissionRule::Anyone);

    // The set, and the read back.
    let set = rule_said(&mut desk.client, "lee", OperatorVerb::SetRule { rule: AdmissionRule::OnlyMyDevices }).await;
    assert_eq!(set, AdmissionRule::OnlyMyDevices);
    assert_eq!(rule_said(&mut desk.client, "lee", OperatorVerb::ReadRule).await, AdmissionRule::OnlyMyDevices);

    // A stranger is refused at every door it reaches.
    let push = a_push_at(&bx.relay_url, None).await;
    assert!(refused_by_the_rule(&push), "a stranger's push: {push:?}");
    let lookup = a_lookup_at(&bx.relay_url, None).await;
    assert!(refused_by_the_rule(&lookup), "a stranger's lookup: {lookup:?}");

    // The desktop's own key is the one the relay reads; the invited key is not
    // read under *only my devices*.
    let keys = desk.runtime.reachability().relay_keys();
    let mine = keys.present_at(&bx.relay_id).expect("the desktop holds the key it minted");
    let invited = keys.offer_for("lee", &bx.relay_id).expect("and the invited key, as the operator");
    assert_ne!(mine, invited);
    assert!(a_push_at(&bx.relay_url, Some(mine.clone())).await.is_ok(), "a tag under mine was refused");
    assert!(a_lookup_at(&bx.relay_url, Some(mine.clone())).await.is_err_and(|e| !matches!(e, kotton_net::rendezvous::RendezvousError::HttpError { status: 403, .. })), "a lookup under mine was refused at the door");
    assert!(refused_by_the_rule(&a_push_at(&bx.relay_url, Some(invited)).await), "only my devices read the invited key");

    // The vault holds mine, and presents it: an invite asked for now is
    // reserved at the relay.
    let vault_keys = bx.vault.vault.runtime().reachability().relay_keys();
    assert_eq!(vault_keys.present_at(&bx.relay_id), Some(mine.clone()), "the vault was handed mine");
    let before = crate::common::relay::reservations(&bx.relay_addr).await;
    match within_for(
        WHOLE,
        "an invite after the narrowing",
        desk.client.as_operator("lee", "kotton", OperatorVerb::Invite { pool: "sam".into(), quota: None, ttl_seconds: 60 }),
    )
    .await
    .expect("the desktop's daemon answers")
    {
        UserResponse::PairAdvertising { code, .. } => match kotton_wire::line::InviteCode::parse(code.expose()) {
            Ok(kotton_wire::line::InviteCode::Vault { relay_hint, .. }) => {
                assert_eq!(relay_hint, bx.relay_url, "the invite names the vault's relay: {}", code.expose())
            }
            other => panic!("not a vault's invite in the grammar: {other:?} — {}", code.expose()),
        },
        other => panic!("no invite: {other:?}"),
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while crate::common::relay::reservations(&bx.relay_addr).await <= before {
        assert!(
            std::time::Instant::now() < deadline,
            "the vault's invite was never reserved at the narrowed relay"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // A desktop holding no credential has nothing to set it under.
    let mut other = within("another desktop", crate::common::relay::env_on(&bx.relay_addr)).await;
    within("its identity", other.client.create_user("jo", crate::common::TEST_PASSPHRASE))
        .await
        .expect("create_user");
    match other
        .client
        .as_operator("jo", "kotton", OperatorVerb::SetRule { rule: AdmissionRule::Anyone })
        .await
        .expect("its daemon answers")
    {
        UserResponse::Error { message } => assert!(message.contains("holds no operator credential"), "{message}"),
        other => panic!("a desktop with no credential set the rule: {other:?}"),
    }
    // And a key that is not an operator's is refused by the relay itself.
    let stranger = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let said = kotton_net::rendezvous::say_as_operator(&bx.relay_url, &stranger, &RelayOperatorRequest::ReadRule).await;
    assert!(refused_by_the_rule(&said), "{said:?}");
    assert_eq!(rule_said(&mut desk.client, "lee", OperatorVerb::ReadRule).await, AdmissionRule::OnlyMyDevices);
}

/// **A person handed a vault's invite under *the people I invite* admits it
/// and joins, and a stranger with neither the invite's key nor one of their
/// own is refused**
/// (`TASK-a-first-contact-ceremony-meets-at-a-relay-whose-rule-refuses-a-stranger`).
///
/// The admitting device is by definition a stranger at the vault's relay: the
/// ceremony is the first thing it does there. So the invite carries the relay's
/// *invited* key — the one the operator's desktop keeps, and told the vault with
/// its reach set — and the admit presents it on its one dial. Here the operator
/// narrows the relay, asks the vault for an invite from the desktop, and the
/// code carries exactly that key. The same code with the key cut out, admitted
/// by a device holding no key of its own, is refused at the relay and pairs
/// nobody — and spends nothing, so the friend's admit of the code as minted
/// completes after it. A vault told no key for the relay mints no invite at
/// all: the relay refuses its reservation, made before the code is handed out.
/// The friend's device then joins: its push reaches the
/// vault, which keeps for them, and from then it holds the invited key the way
/// every tenant does — handed by the vault, not kept from the invite.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_vaults_invite_admits_its_holder_under_the_people_i_invite_and_a_stranger_is_refused() {
    use kotton_wire::ipc::OperatorVerb;
    use kotton_wire::line::InviteCode;
    use kotton_wire::rendezvous::AdmissionRule;

    init_crypto();
    let bx = a_box().await;
    let mut desk = within("the operator's desktop", crate::common::relay::env_on(&bx.relay_addr)).await;
    within("the operator's identity", desk.client.create_user("lee", crate::common::TEST_PASSPHRASE))
        .await
        .expect("create_user");
    bx.enrol_on(&mut desk.client, "lee").await;
    assert_eq!(
        rule_said(&mut desk.client, "lee", OperatorVerb::SetRule { rule: AdmissionRule::PeopleIInvite }).await,
        AdmissionRule::PeopleIInvite
    );
    assert!(refused_by_the_rule(&a_push_at(&bx.relay_url, None).await), "the relay reads a key now");
    let invited = desk.runtime.reachability().relay_keys().offer_for("lee", &bx.relay_id).expect("the operator keeps the invited key");

    // The invite, minted at the vault from the desktop, carries that key.
    let invite = match within_for(
        WHOLE,
        "an invite under the people I invite",
        desk.client.as_operator("lee", "kotton", OperatorVerb::Invite { pool: "sam".into(), quota: None, ttl_seconds: 120 }),
    )
    .await
    .expect("the desktop's daemon answers")
    {
        UserResponse::PairAdvertising { code, .. } => code.expose().to_string(),
        other => panic!("no invite: {other:?}"),
    };
    let without_its_key = match InviteCode::parse(&invite).expect("a vault's invite in the grammar") {
        InviteCode::Vault { key, words, relay_key, relay_hint, invited: carried } => {
            assert_eq!(relay_key, bx.relay_id, "the invite names the vault's relay by its key: {invite}");
            assert_eq!(carried, Some(invited.to_bytes()), "the invite carries the relay's invited key: {invite}");
            InviteCode::Vault { key, words, relay_key, relay_hint, invited: None }.to_text()
        }
        other => panic!("not a vault's invite: {other:?}"),
    };

    // A vault told no key for the relay mints nothing: the relay refuses its
    // reservation of the invite's handle, which is made before any code is
    // handed out, so nobody is handed a code they would be refused on.
    let keyless = within("a vault told no keys", spawn_vault_at(&bx.relay_addr, "keyless")).await;
    let keyless_door = within("its door", connect_when_ready(&keyless.ipc, "keyless door")).await;
    let mut frames = keyless_door.device_invite_stream("jo", 60, Some("vault")).await.expect("the door answers");
    match within("the keyless vault's answer", frames.recv()).await {
        Some(UserResponse::Error { message }) => assert!(
            message.contains("refused this node's reservation") && message.contains("nothing was minted"),
            "{message}"
        ),
        other => panic!("a vault the relay refuses minted an invite: {other:?}"),
    }

    // A stranger with neither: the code with its key cut out, at a device that
    // holds no key of its own there. Refused at the relay; nobody is paired.
    let mut stranger = within("a stranger's device", crate::common::relay::env_without()).await;
    within("the stranger's things", a_person_with_things(&mut stranger.client, "sam", NOTE)).await;
    let shown = Shown::AtTheDesktop { client: &mut desk.client, user: "lee", vault: "kotton", pool: "sam" };
    match the_admit_as(&mut stranger.client, "sam", &without_its_key, shown).await {
        UserResponse::PairFailed { .. } => {}
        other => panic!("a stranger holding no key was admitted under the people I invite: {other:?}"),
    }
    assert!(
        within("the stranger's paired nodes", stranger.client.list_nodes("sam")).await.expect("node list").is_empty(),
        "the stranger recorded a vault"
    );

    // The person handed the invite as minted admits it.
    let mut friend = within("the friend's device", crate::common::relay::env_without()).await;
    within("the friend's things", a_person_with_things(&mut friend.client, "sam", NOTE)).await;
    let shown = Shown::AtTheDesktop { client: &mut desk.client, user: "lee", vault: "kotton", pool: "sam" };
    let vault_node = match the_admit_as(&mut friend.client, "sam", &invite, shown).await {
        UserResponse::PairingComplete { node, .. } => node,
        other => panic!("the person handed the invite was refused under the people I invite: {other:?}"),
    };

    // And joins: their push reaches the vault, which keeps for them.
    within(
        "the vault as a remote",
        friend.client.remote_add(
            "sam",
            "vault",
            RemoteBackend::Kotton { peer_did: vault_node.device_did.to_string(), label: "vault".to_string() },
            None,
        ),
    )
    .await
    .expect("remote_add");
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        match friend.client.sync_mount("sam", "local", "vault", Some(SyncDirection::Push)).await {
            Ok(r) if r.pushed >= 1 => break,
            other => assert!(std::time::Instant::now() < deadline, "the friend's push never reached the vault: {other:?}"),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let mut door = within("the landlord's door", connect_when_ready(&bx.vault.ipc, "door")).await;
    let (held, _) = within("sam's capacity", door.vault_capacity("sam")).await.expect("capacity");
    assert!(held > 0, "the vault keeps what the friend pushed: {held}");
    // What the friend holds at the relay now is what the vault hands every
    // tenant in its answer to `NodeRelay` — the invited key, and never *mine*.
    let mine = desk.runtime.reachability().relay_keys().present_at(&bx.relay_id).expect("the operator's own key");
    let holds = friend.runtime.reachability().relay_keys().present_at(&bx.relay_id);
    assert_eq!(holds, Some(invited), "the friend is handed the invited key as a tenant");
    assert_ne!(holds, Some(mine), "a tenant is never handed mine");
    assert!(refused_by_the_rule(&a_push_at(&bx.relay_url, None).await), "a stranger is still refused");
}

/// **A first-contact dial the relay refuses at its door is said as what this
/// device presented there, and is not retried as a vault not there yet.**
///
/// The relay answers every refusal with one `403` and says nothing more; the
/// device knows what it presented. Here a vault's invite has its key cut out of
/// the text and is admitted, under *the people I invite*, by a device that holds
/// no key of its own at the relay: it presents nothing. The admit ends at the
/// relay's first answer — not after the twenty seconds a dial waits for a vault
/// between reservations — and the person is told that the relay refused this
/// device, that it presented no key there, and which invite admits its holder:
/// the vault's invite as it was minted. Never *lost the connection*, which sends
/// them to try the same code again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_relays_refusal_of_a_first_contact_dial_is_said_as_what_the_device_presented_and_not_retried() {
    use kotton_wire::ipc::OperatorVerb;
    use kotton_wire::line::InviteCode;
    use kotton_wire::rendezvous::AdmissionRule;

    init_crypto();
    let bx = a_box().await;
    let mut desk = within("the operator's desktop", crate::common::relay::env_on(&bx.relay_addr)).await;
    within("the operator's identity", desk.client.create_user("lee", crate::common::TEST_PASSPHRASE))
        .await
        .expect("create_user");
    bx.enrol_on(&mut desk.client, "lee").await;
    assert_eq!(
        rule_said(&mut desk.client, "lee", OperatorVerb::SetRule { rule: AdmissionRule::PeopleIInvite }).await,
        AdmissionRule::PeopleIInvite
    );
    let invite = match within_for(
        WHOLE,
        "an invite under the people I invite",
        desk.client.as_operator("lee", "kotton", OperatorVerb::Invite { pool: "sam".into(), quota: None, ttl_seconds: 120 }),
    )
    .await
    .expect("the desktop's daemon answers")
    {
        UserResponse::PairAdvertising { code, .. } => code.expose().to_string(),
        other => panic!("no invite: {other:?}"),
    };
    let without_its_key = match InviteCode::parse(&invite).expect("a vault's invite in the grammar") {
        InviteCode::Vault { key, words, relay_key, relay_hint, invited: Some(_) } => {
            InviteCode::Vault { key, words, relay_key, relay_hint, invited: None }.to_text()
        }
        other => panic!("not a vault's invite carrying the relay's key: {other:?}"),
    };

    let mut stranger = within("a stranger's device", crate::common::relay::env_without()).await;
    within("the stranger's things", a_person_with_things(&mut stranger.client, "sam", NOTE)).await;
    let shown = Shown::AtTheDesktop { client: &mut desk.client, user: "lee", vault: "kotton", pool: "sam" };
    let started = std::time::Instant::now();
    let reason = match the_admit_as(&mut stranger.client, "sam", &without_its_key, shown).await {
        UserResponse::PairFailed { reason } => reason,
        other => panic!("a stranger holding no key was admitted under the people I invite: {other:?}"),
    };
    let took = started.elapsed();
    assert!(!reason.contains("Lost the connection"), "a refusal was said as a lost connection: {reason}");
    assert!(
        reason.contains(&format!("The relay at {} refused", bx.relay_url)),
        "the copy does not say which relay refused: {reason}"
    );
    assert!(reason.contains("presented no key there"), "the copy does not say what was presented: {reason}");
    assert!(
        reason.contains("the vault's invite as it was minted"),
        "the copy does not name the invite that admits its holder there: {reason}"
    );
    assert!(took < Duration::from_secs(10), "a refusal was retried as a vault not there yet: {}s", took.as_secs());
    assert!(
        within("the stranger's paired nodes", stranger.client.list_nodes("sam")).await.expect("node list").is_empty(),
        "the stranger recorded a vault"
    );
}

/// Push `client`'s mount to its vault — a connect that asks the vault where it
/// reserves, which is when a tenant is handed the invited key.
async fn a_push_to_the_vault(client: &mut kotton::KottonClient, user: &str) {
    a_push_to(client, user, "vault").await
}

async fn a_push_to(client: &mut kotton::KottonClient, user: &str, remote: &str) {
    within_for(WHOLE, "a push to the vault", client.sync_mount(user, "local", remote, Some(SyncDirection::Push)))
        .await
        .expect("the push reached the vault");
}

/// A tenant's next connect to its vault. A remote holds its connection for the
/// session, so a push to the same remote asks nothing new; a device connects
/// afresh when it opens the remote again (a restart, a sync pass), and this
/// opens it again under a new name, as that does.
async fn a_fresh_connect(tenant: &mut Tenant, user: &str) {
    tenant.connects += 1;
    let name = format!("vault-{}", tenant.connects);
    tenant
        .env
        .client
        .remote_add(
            user,
            &name,
            RemoteBackend::Kotton {
                peer_did: tenant.vault_did.clone(),
                label: "vault".to_string(),
            },
            None,
        )
        .await
        .expect("remote_add");
    a_push_to(&mut tenant.env.client, user, &name).await;
}

/// A tenant's device, and the vault as it was enrolled there.
struct Tenant {
    env: crate::common::TestEnv,
    vault_did: String,
    connects: u32,
}

/// A tenant of the host's vault, on the host's relay: a person with things,
/// enrolled at the vault, with the handle of the daemon behind them.
async fn a_tenant(bx: &ABox, user: &str) -> Tenant {
    let mut env = within("a tenant's device", crate::common::relay::env_on(&bx.relay_addr)).await;
    let spare = within("a spare client", connect_when_ready(&env.endpoint, user)).await;
    let mut client = std::mem::replace(&mut env.client, spare);
    within("the tenant's things", a_person_with_things(&mut client, user, NOTE)).await;
    let (mut client, vault) = within(
        "enrolling the tenant",
        enrol_vault_from(client, &format!("{user}'s laptop"), &bx.vault, user, "vault"),
    )
    .await;
    a_push_to_the_vault(&mut client, user).await;
    // The client the person signed in on, for everything after.
    env.client = client;
    Tenant { env, vault_did: vault.did, connects: 0 }
}

/// Wait until `env`'s daemon holds every reservation it wants at its relay,
/// and at least one — what a relay whose rule refused it would never let it do.
async fn every_reservation_held(env: &mut crate::common::TestEnv, user: &str, within_secs: u64) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(within_secs);
    loop {
        let status = env.client.network_status(user).await.expect("network status");
        if status.relay.reservations_wanted > 0 && status.relay.reservations_live >= status.relay.reservations_wanted {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Wait until `env`'s daemon wants reservations at its relay and holds none —
/// what a relay that dropped them leaves it with.
async fn no_reservation_held(env: &mut crate::common::TestEnv, user: &str, within_secs: u64) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(within_secs);
    loop {
        let status = env.client.network_status(user).await.expect("network status");
        if status.relay.reservations_wanted > 0 && status.relay.reservations_live == 0 {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Whether `env`'s daemon holds no reservation at any reading for `secs` — long
/// enough for its reconnect to have been tried at the door and refused — for as
/// long as it holds no key for the relay `relay`.
///
/// A daemon learns the invited key at any connect to its vault that `NodeRelay`
/// answers (`RelayKeyring::learn`), not only the connect a test makes, and a
/// reservation it then presents the key with is admitted rightly. A key once
/// learned is not forgotten, so a reservation seen held with no key held after
/// it was admitted without one — that is the failure, and the key is read again
/// after the reservations to be sure of it. Seen 2026-09-26 in a full
/// `just test`: the window ended with a reservation held, where the old check
/// could not tell a keyless admission from a key learned in the background.
async fn none_held_throughout(env: &mut crate::common::TestEnv, user: &str, relay: &[u8; 32], secs: u64) -> bool {
    let holds_a_key = |env: &crate::common::TestEnv| env.runtime.reachability().relay_keys().present_at(relay).is_some();
    let deadline = std::time::Instant::now() + Duration::from_secs(secs);
    while std::time::Instant::now() < deadline {
        if holds_a_key(env) {
            return true;
        }
        let status = env.client.network_status(user).await.expect("network status");
        if status.relay.reservations_live > 0 {
            return holds_a_key(env);
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    true
}

/// **A tenant of the host's vault is admitted under *the people I invite***
/// (`TASK-a-device-presents-its-relays-admission-tag-and-the-reach-row-sets-the-rule`,
/// Done-when 3).
///
/// A tenant enrolled while the relay admitted anyone. The operator's desktop
/// then enrols the vault's credential and the relay's, the relay's carrying
/// the rule it asked for — *the people I invite* — and sets it at the relay on
/// enrolling, handing the keys to the vault whose `relay=` is that URL
/// (Done-when 5: nothing sets it before a desktop holds the keys, and enrolling
/// the same file again later does not undo a rule set since). The tenant's
/// reservations, made again, are
/// refused — it holds no key — until its next connect to the vault, whose
/// answer to `NodeRelay` hands it the invited key, and never *mine*. From then
/// its reservations are held at the relay again, and a stranger is still
/// refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_tenant_of_the_boxs_vault_is_admitted_under_the_people_i_invite() {
    use kotton_wire::ipc::OperatorVerb;
    use kotton_wire::rendezvous::AdmissionRule;

    init_crypto();
    let bx = a_box().await;
    // The vault stood at the relay before this desktop knew it — told by an
    // earlier telling, here in process — so a tenant can be enrolled while the
    // relay admits anyone.
    crate::common::relay::stand_at(&bx.vault.vault, &bx.relay_addr).await;
    let mut sam = a_tenant(&bx, "sam").await;
    assert!(every_reservation_held(&mut sam.env, "sam", 30).await, "sam's reservations under anyone");
    assert_eq!(sam.env.runtime.reachability().relay_keys().present_at(&bx.relay_id), None);

    // The relay's credential as `mint relay --rule people_i_invite` left it,
    // with the rule it asked for. Enrolling it tells the vault this desktop
    // operates and has told nothing yet to stand there, then sets that rule at
    // the relay, telling the vault again with the relay's keys; no verb is
    // said. The vault's credential is kept first, as the guide orders it.
    let with_rule = format!("{}rule=people_i_invite\n", bx.relay_credential);
    let mut desk = within("the operator's desktop", crate::common::relay::env_on(&bx.relay_addr)).await;
    within("the operator's identity", desk.client.create_user("lee", crate::common::TEST_PASSPHRASE))
        .await
        .expect("create_user");
    within("keeping the vault's credential", desk.client.operator_enrol("lee", &bx.vault_credential))
        .await
        .expect("the desktop keeps the vault's credential");
    let sam_held = sam.env.client.network_status("sam").await.expect("network status").relay.reservations_live;
    assert!(sam_held > 0, "sam held no reservation before the rule narrowed, so there is nothing to see dropped");
    let held_before = crate::common::relay::reservations(&bx.relay_addr).await;
    within("keeping the credential", desk.client.operator_enrol("lee", &with_rule))
        .await
        .expect("the desktop keeps the credential");
    // The relay's own count, read the moment the set has answered and not
    // waited for. Every reservation it held was made under *anyone* presenting
    // no tag — sam's and the vault's (measured 2026-09-27: 6 before, 0 at the
    // answer, the vault's back about 6 s later with the operator's key) — and
    // the new rule admits none of them, so the set's sweep leaves nothing.
    // The count is never less than the number of sam's reservations still
    // held, so a zero here cannot hide one, however loaded the machine. A
    // non-zero is a survivor, or a reservation made after the answer: a dropped
    // holder waits `RELAY_RECONNECT_INTERVAL` (5 s) before it tries again, so
    // the failure says how late the read was, and nothing else here reserves
    // presenting a key (the desktop wants none). Per holder, the same moment
    // is `a_reservation_the_narrowed_rule_no_longer_admits_is_dropped` in
    // `infra/relay`.
    let answered = std::time::Instant::now();
    let held_after = crate::common::relay::reservations(&bx.relay_addr).await;
    let read_after = answered.elapsed();
    assert_eq!(
        held_after, 0,
        "the relay still held {held_after} of {held_before} reservations, all made presenting no tag, when the set to the people I invite answered (sam held {sam_held}; read {read_after:?} after the answer; a dropped holder retries after 5 s)"
    );
    assert_eq!(
        bx.rule_at_the_relay().await,
        AdmissionRule::PeopleIInvite,
        "enrolling the credential set the rule init asked for"
    );

    // Sam does nothing. The reservations sam made under *anyone* were dropped at
    // the relay because the rule no longer admits them — not because sam's
    // daemon re-made them — and every reconnect after is refused at the door.
    // Sam's daemon learns of the drop when the relay closes its sockets, so its
    // readout is waited on here; the relay's own state was read above.
    assert!(
        no_reservation_held(&mut sam.env, "sam", 30).await,
        "a tenant holding no key was still carried after the rule narrowed"
    );
    // The window below ends when sam holds a key, so it opens with none held,
    // or it would observe nothing.
    assert_eq!(sam.env.runtime.reachability().relay_keys().present_at(&bx.relay_id), None, "sam held a key before the window opened");
    assert!(
        none_held_throughout(&mut sam.env, "sam", &bx.relay_id, 8).await,
        "a tenant holding no key was admitted under the people I invite"
    );

    // Sam's next connect to the vault hands the invited key, and never mine.
    a_fresh_connect(&mut sam, "sam").await;
    let held = sam.env.runtime.reachability().relay_keys();
    let invited = desk.runtime.reachability().relay_keys().offer_for("lee", &bx.relay_id).expect("the operator's invited key");
    let mine = desk.runtime.reachability().relay_keys().present_at(&bx.relay_id).expect("the operator's own key");
    assert_eq!(held.present_at(&bx.relay_id), Some(invited.clone()), "the vault handed sam the invited key");
    assert_ne!(held.present_at(&bx.relay_id), Some(mine), "a tenant is never handed mine");
    assert_eq!(held.offer_for("sam", &bx.relay_id), None, "a tenant offers the key to nobody");

    // Admitted: sam's reservations are held again, presenting it.
    within("sam's reservations, with the key", sam.env.client.node_rendezvous_set(Some(&bx.relay_url)))
        .await
        .expect("relay set");
    assert!(every_reservation_held(&mut sam.env, "sam", 30).await, "sam holds the invited key and was refused");
    assert!(a_push_at(&bx.relay_url, Some(invited)).await.is_ok());
    assert!(refused_by_the_rule(&a_push_at(&bx.relay_url, None).await), "a stranger is still refused");

    // `init`'s answer is the first rule and only that: set to anyone from
    // Settings, the relay keeps anyone when the same file is enrolled again.
    assert_eq!(
        rule_said(&mut desk.client, "lee", OperatorVerb::SetRule { rule: AdmissionRule::Anyone }).await,
        AdmissionRule::Anyone
    );
    within("enrolling the file again", desk.client.operator_enrol("lee", &with_rule))
        .await
        .expect("the desktop keeps the credential");
    assert_eq!(bx.rule_at_the_relay().await, AdmissionRule::Anyone);
    assert_eq!(rule_said(&mut desk.client, "lee", OperatorVerb::ReadRule).await, AdmissionRule::Anyone);
}

/// **A dropped tenant is refused after the key rotates**
/// (`TASK-a-device-presents-its-relays-admission-tag-and-the-reach-row-sets-the-rule`,
/// Done-when 3; revocation is rotation).
///
/// Sam and Jo are tenants under *the people I invite*, each holding the invited
/// key. Dropping Sam rotates it. The relay still reads the key before the
/// current one — a device that has not yet learned the new key is not refused
/// in between — so Sam's key is admitted for that one rotation, and that is
/// the grace as built, asserted here rather than hidden. Jo's next connect
/// learns the new key; Sam, dropped, can learn nothing. At the next rotation —
/// another pool dropped — Sam's key is refused at the relay, and Jo's current
/// one is admitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_dropped_tenant_is_refused_after_the_key_rotates() {
    use kotton_wire::ipc::OperatorVerb;
    use kotton_wire::rendezvous::AdmissionRule;

    init_crypto();
    let bx = a_box().await;
    let mut desk = within("the operator's desktop", crate::common::relay::env_on(&bx.relay_addr)).await;
    within("the operator's identity", desk.client.create_user("lee", crate::common::TEST_PASSPHRASE))
        .await
        .expect("create_user");
    bx.enrol_on(&mut desk.client, "lee").await;
    let mut sam = a_tenant(&bx, "sam").await;
    let mut jo = a_tenant(&bx, "jo").await;
    // A third pool, set aside and never joined, for the second rotation.
    match within_for(
        WHOLE,
        "inviting priya",
        desk.client.as_operator(
            "lee",
            "kotton",
            OperatorVerb::Invite { pool: "priya".into(), quota: Some(1 << 20), ttl_seconds: 60 },
        ),
    )
    .await
    .expect("the desktop's daemon answers")
    {
        UserResponse::PairAdvertising { .. } => {}
        other => panic!("no invite for priya: {other:?}"),
    }
    assert_eq!(
        rule_said(&mut desk.client, "lee", OperatorVerb::SetRule { rule: AdmissionRule::PeopleIInvite }).await,
        AdmissionRule::PeopleIInvite
    );
    a_fresh_connect(&mut sam, "sam").await;
    a_fresh_connect(&mut jo, "jo").await;
    let first = desk.runtime.reachability().relay_keys().offer_for("lee", &bx.relay_id).unwrap();
    let sams = sam.env.runtime.reachability().relay_keys().present_at(&bx.relay_id).expect("sam learned the key");
    assert_eq!(sams, first);
    assert!(a_push_at(&bx.relay_url, Some(sams.clone())).await.is_ok());

    // Sam is dropped: the invited key rotates, at the desktop and the vault.
    match within_for(WHOLE, "dropping sam", desk.client.as_operator("lee", "kotton", OperatorVerb::Drop { pool: "sam".into() }))
        .await
        .expect("the desktop's daemon answers")
    {
        UserResponse::TenantDropped { tenant } => assert_eq!(tenant.user_id, "sam"),
        other => panic!("sam was not dropped: {other:?}"),
    }
    let second = desk.runtime.reachability().relay_keys().offer_for("lee", &bx.relay_id).unwrap();
    assert_ne!(second, first, "dropping a tenant rotated nothing");
    assert_eq!(bx.vault.vault.runtime().reachability().relay_keys().offer_for("", &bx.relay_id), Some(second.clone()));
    assert_eq!(rule_said(&mut desk.client, "lee", OperatorVerb::ReadRule).await, AdmissionRule::PeopleIInvite);
    // The grace: the key before the current one is still read.
    assert!(a_push_at(&bx.relay_url, Some(sams.clone())).await.is_ok(), "the previous key is read for one rotation");

    // Jo learns the new key on her next connect.
    a_fresh_connect(&mut jo, "jo").await;
    assert_eq!(jo.env.runtime.reachability().relay_keys().present_at(&bx.relay_id), Some(second.clone()));

    // The next rotation, and Sam's key is refused. Jo's is admitted.
    match within_for(WHOLE, "dropping priya", desk.client.as_operator("lee", "kotton", OperatorVerb::Drop { pool: "priya".into() }))
        .await
        .expect("the desktop's daemon answers")
    {
        UserResponse::TenantDropped { .. } => {}
        other => panic!("priya was not dropped: {other:?}"),
    }
    let push = a_push_at(&bx.relay_url, Some(sams.clone())).await;
    assert!(refused_by_the_rule(&push), "a dropped tenant's key is admitted two rotations on: {push:?}");
    assert_eq!(sam.env.runtime.reachability().relay_keys().present_at(&bx.relay_id), Some(sams), "sam learned nothing new");
    a_fresh_connect(&mut jo, "jo").await;
    let jos = jo.env.runtime.reachability().relay_keys().present_at(&bx.relay_id).unwrap();
    assert!(a_push_at(&bx.relay_url, Some(jos)).await.is_ok(), "a tenant still invited was refused");
}

/// What `kvaultd operator revoke --all --keep <key>` sends, keeping the
/// operator the vault was created for: every one a test enrolled goes.
async fn revoke_at_the_door(vault: &RunningVault) {
    revoke_at_the_door_as(
        vault,
        VaultRequest::OperatorRevokeAllBut { keep: hex::encode(vault.creator.verifying_key().to_bytes()) },
    )
    .await
}

/// What `kvaultd operator revoke <key>` sends.
async fn revoke_one_at_the_door(vault: &RunningVault, key: &ed25519_dalek::SigningKey) {
    revoke_at_the_door_as(vault, VaultRequest::OperatorRevoke { key: hex::encode(key.verifying_key().to_bytes()) }).await
}

async fn revoke_at_the_door_as(vault: &RunningVault, request: VaultRequest) {
    let mut door = kotton_ipc::IpcClient::<VaultRequest, UserResponse>::connect(vault.ipc.clone())
        .await
        .expect("the landlord reaches the door");
    match door.send(&request).await.expect("the door answers") {
        UserResponse::Ok => {}
        other => panic!("the door did not revoke the operator credential: {other:?}"),
    }
}

/// A desktop with a person on it and nothing else: its own daemon, the
/// person's store unlocked.
async fn a_desktop(label: &str, user: &str) -> (RunningDevice, kotton::KottonClient) {
    let device = spawn_device(label).await;
    let mut client = connect_when_ready(&device.ipc, label).await;
    client
        .create_user(user, crate::common::TEST_PASSPHRASE)
        .await
        .expect("create_user");
    (device, client)
}

/// **The landlord's verbs reach the desktop over the wire**
/// (`TASK-the-landlords-verbs-reach-the-desktop-over-the-wire`).
///
/// A tenant keeps sealed packs at a vault. The vault's landlord enrols the
/// operator credential on their own desktop, and from there — no terminal,
/// the same sealed channel a device uses — mints an invite for a new person
/// with the number set aside for them, sets the tenant's number, and lists
/// who keeps here. Refused from one that does not hold the credential: a
/// second desktop has nothing to speak under, and the tenant's own device,
/// paired with the vault, is refused each of the four by standing. And the
/// tenant's packs are unreadable to both: the credential's key is refused
/// every verb that reads, and the other desktop is refused at the handshake.
///
/// **And inviting a name the vault already keeps is refused, and resets
/// nothing** (`TASK-networking-is-the-drawn-one`, 2026-09-23). What happened
/// before, established by this clause's first form (a test of its own, run
/// against `faa79963`): *Invite…* for `alice`, a tenant here with her number
/// at 40 MiB, first set her number to the sheet's (25 MiB, at once, whether or
/// not anyone took the invite), then minted an invite naming her pool. A
/// stranger's device that took it ran the whole ceremony — six digits, the
/// transfer — and was told `PairingComplete`, with the vault recorded as a
/// paired node; the vault then refused to save it (`provision_joined_user`:
/// *"the name 'alice' already belongs to a different identity"*), so alice
/// still had one device and the stranger's requests to her pool lost their
/// connection. Refused, but late, silently to the landlord, and after her
/// number was reset. Now the vault refuses the invite before minting it, at
/// both doors, and the desktop asks for the number only after the invite is
/// answered. The clause lives here rather than in a test of its own because
/// that test, `#[serial]` and fifteen seconds of setup this one already does,
/// moved the readout tests below into the window of the parallel tests that
/// write the process-global registry: `vault::` went red twice in two runs
/// with it, green without it
/// (`TASK-the-device-user-registry-is-read-from-a-process-global-base`).
///
/// `#[serial]` with the readout test below, which holds a base directory of
/// its own: every `create_user` here writes the process-global device registry
/// (`TASK-the-device-user-registry-is-read-from-a-process-global-base`), and
/// run beside it these made its occupant host read two identities.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_desktop_holding_the_operator_credential_invites_and_sets_a_quota_and_reads_no_pack() {
    use kotton_wire::ipc::OperatorVerb;
    const SAM: u64 = 50 * 1024 * 1024;
    const ALICE: u64 = 40 * 1024 * 1024;
    const ALICE_BEFORE: u64 = 30 * 1024 * 1024;

    init_crypto();
    let (_relay, relay_addr) = within("starting the relay", crate::common::relay::spawn()).await;
    let relay_url = format!("http://{relay_addr}");
    let vault = within(
        "starting the vault at the relay",
        spawn_vault_at(&relay_addr, "vault"),
    )
    .await;

    // A tenant, with sealed packs at the vault.
    let alice_device = within("starting alice's device", spawn_device("alice")).await;
    let mut alice = within("alice's client", connect_when_ready(&alice_device.ipc, "alice")).await;
    within("alice's things", a_person_with_things(&mut alice, "alice", NOTE)).await;
    let (mut alice, alice_vault) = within(
        "enrolling alice",
        enrol_vault_from(alice, "alice's laptop", &vault, "alice", "vault"),
    )
    .await;
    within(
        "alice's push",
        alice.sync_mount("alice", "local", "vault", Some(SyncDirection::Push)),
    )
    .await
    .expect("alice's packs reach the vault");

    // The vault mints the credential and enrols its public half; the landlord's
    // desktop keeps the text.
    let (operator_key, credential) =
        within("minting the credential", operator_credential(&vault, &alice_vault.pubkey_hex)).await;
    let (_desk, mut landlord) = within("the landlord's desktop", a_desktop("landlord", "lee")).await;
    within("enrolling the credential", landlord.operator_enrol("lee", &credential))
        .await
        .expect("the desktop keeps the credential");

    // *Invite…* for alice, who is kept here, with a number of the sheet's:
    // refused as kept (`VaultKeepsAlready`), and alice's number is the one she had.
    set_quota_at_the_door(&vault.ipc, "alice", ALICE_BEFORE).await;
    match within(
        "inviting alice, who is kept here",
        landlord.as_operator(
            "lee",
            "kotton",
            OperatorVerb::Invite {
                pool: "alice".into(),
                quota: Some(SAM),
                ttl_seconds: 120,
            },
        ),
    )
    .await
    .expect("the desktop's daemon answers")
    {
        UserResponse::VaultKeepsAlready { user_id } => assert_eq!(user_id, "alice"),
        other => panic!("the vault minted an invite naming a pool it keeps: {other:?}"),
    }
    assert_eq!(
        vault.vault.meter().quota("alice"),
        Some(ALICE_BEFORE),
        "a refused invite reset alice's number"
    );
    // The terminal's `kvaultd invite alice`: the same body, the same refusal,
    // in the stream's first frame and with no invite before it.
    let terminal = kotton_ipc::IpcClient::<VaultRequest, UserResponse>::connect(vault.ipc.clone())
        .await
        .expect("the landlord reaches the door");
    let mut frames = terminal
        .send_streaming(&VaultRequest::DeviceInvite {
            user_id: "alice".into(),
            ttl_seconds: 120,
            as_name: None,
        })
        .await
        .expect("the door answers");
    match within("the door's answer", frames.recv()).await {
        Some(UserResponse::VaultKeepsAlready { user_id }) => assert_eq!(user_id, "alice"),
        other => panic!("the terminal's door minted an invite naming a pool it keeps: {other:?}"),
    }
    // And the door ends the stream after it, so a reader that does not name
    // the refusal is not left waiting on it (#112).
    assert!(within("the door's end of the stream", frames.recv()).await.is_none(), "the door's stream went on after its refusal");
    let alice_row = tenants_at_the_door(&vault.ipc)
        .await
        .into_iter()
        .find(|t| t.user_id == "alice")
        .expect("the vault keeps for alice");
    assert_eq!((alice_row.devices, alice_row.quota), (1, Some(ALICE_BEFORE)), "{alice_row:?}");

    // Mint an invite for a new person, with their number.
    let invited = within(
        "inviting sam from the desktop",
        landlord.as_operator(
            "lee",
            "kotton",
            OperatorVerb::Invite {
                pool: "sam".into(),
                quota: Some(SAM),
                ttl_seconds: 120,
            },
        ),
    )
    .await
    .expect("the desktop's daemon answers");
    let invite = match invited {
        UserResponse::PairAdvertising { code, .. } => {
            let code = code.expose().to_string();
            assert!(
                code.starts_with("kotton-invite:vault:") && code.ends_with(&format!("@{relay_url}")),
                "the invite meets at the vault's relay: {code}"
            );
            code
        }
        other => panic!("the desktop minted no invite: {other:?}"),
    };
    let mut door = within("the landlord's door", connect_when_ready(&vault.ipc, "door")).await;
    let (_, sam_quota) = within("sam's capacity", door.vault_capacity("sam")).await.expect("capacity");
    assert_eq!(sam_quota, Some(SAM), "the invite set sam's number before it was answered");

    // Sam's device takes the invite. Nobody is at the host: the vault confirms
    // the six digits on sight, as `kvaultd invite` does, and sam compares them
    // on his own device. The vault is admitted blind — the only way an invite
    // the credential minted can admit it.
    let sam_device = within("starting sam's device", spawn_device("sam")).await;
    let mut sam = within("sam's client", connect_when_ready(&sam_device.ipc, "sam")).await;
    within("sam's identity", sam.create_user("sam", crate::common::TEST_PASSPHRASE))
        .await
        .expect("create_user");
    let mut rx = within(
        "sam admits the invite",
        sam.device_admit_stream("sam", &invite, 60, Posture::BlindStorage),
    )
    .await
    .expect("device_admit_stream");
    let mut admitted = None;
    while let Some(frame) = within_for(STEP, "sam's ceremony", rx.recv()).await {
        match frame {
            UserResponse::PairShowCode { token, .. } => {
                within("sam confirms", sam.pair_confirm_code("sam", token.expose(), true))
                    .await
                    .expect("sam's confirm");
            }
            UserResponse::PairingComplete { node, .. } => {
                admitted = Some(node);
                break;
            }
            UserResponse::PairFailed { reason } => panic!("sam's ceremony failed: {reason}"),
            _ => {}
        }
    }
    admitted.expect("sam's device admitted the vault the desktop's invite named");
    let sam_row = tenants_at_the_door(&vault.ipc)
        .await
        .into_iter()
        .find(|t| t.user_id == "sam")
        .expect("the vault keeps for sam");
    assert_eq!(sam_row.devices, 1, "sam's device is paired with the vault");
    assert_eq!(sam_row.quota, Some(SAM), "under the number the invite set");
    let nodes = within("sam's paired nodes", sam.list_nodes("sam")).await.expect("node list");
    assert_eq!(nodes.len(), 1, "sam's device paired the one vault: {nodes:?}");

    // Set the tenant's number.
    match within(
        "setting alice's number from the desktop",
        landlord.as_operator("lee", "kotton", OperatorVerb::SetQuota { pool: "alice".into(), quota: ALICE }),
    )
    .await
    .expect("the desktop's daemon answers")
    {
        UserResponse::VaultCapacityResult { quota, held } => {
            assert_eq!(quota, Some(ALICE));
            assert!(held > 0, "alice's packs are held");
        }
        other => panic!("the desktop set no quota: {other:?}"),
    }
    assert_eq!(vault.vault.meter().quota("alice"), Some(ALICE));

    // And who keeps here: numbers and counts, nothing of anyone's.
    match within("the pools, from the desktop", landlord.as_operator("lee", "kotton", OperatorVerb::Pools))
        .await
        .expect("the desktop's daemon answers")
    {
        UserResponse::VaultTenants { tenants } => {
            let alice_row = tenants.iter().find(|t| t.user_id == "alice").expect("alice is listed");
            assert_eq!(alice_row.quota, Some(ALICE));
            assert_eq!(alice_row.devices, 1);
            let sam_row = tenants.iter().find(|t| t.user_id == "sam").expect("sam is listed");
            assert_eq!(sam_row.quota, Some(SAM));
        }
        other => panic!("the desktop listed no pools: {other:?}"),
    }

    // Refused from a desktop that does not hold it: nothing to speak under.
    let (other_desk, mut other) = within("a second desktop", a_desktop("other", "olly")).await;
    match within(
        "the second desktop tries",
        other.as_operator("olly", "kotton", OperatorVerb::SetQuota { pool: "alice".into(), quota: 1 }),
    )
    .await
    .expect("the second desktop's daemon answers")
    {
        UserResponse::Error { message } => {
            assert!(message.contains("holds no operator credential"), "{message}")
        }
        other => panic!("a desktop with no credential spoke for the landlord: {other:?}"),
    }
    // And from the tenant's own device, paired with this vault: each of the
    // four, built and sent, and refused by standing.
    for verb in [
        UserRequest::DeviceInvite {
            user_id: "mallory".into(),
            ttl_seconds: 60,
            as_name: None,
        },
        UserRequest::Tenants,
        UserRequest::SetQuota {
            user_id: "alice".into(),
            quota: u64::MAX,
        },
        UserRequest::DropTenant { user_id: "sam".into() },
    ] {
        let name = verb.variant_name();
        match within(
            "the tenant's device tries the landlord's verb",
            ask_the_vault_as(&alice_device, &alice_vault, serde_json::to_vec(&verb).unwrap()),
        )
        .await
        {
            // Refused by standing, in the sentence for the standing the device
            // has to the pool the verb names: paired to its own (`SetQuota`
            // for alice), a stranger to anyone else's, and not the operator
            // for the vault as a whole (`Tenants`). Never "not a vault's verb"
            // and never undecodable: the verb exists here, and this key does
            // not reach it.
            UserResponse::Error { message } => assert!(
                message.contains("a tenant's device does not say it")
                    || message.contains("is not paired with user")
                    || message.contains("is not this vault's operator"),
                "{name}: {message}"
            ),
            other => panic!("a tenant's device said {name}: {other:?}"),
        }
    }
    assert_eq!(vault.vault.meter().quota("alice"), Some(ALICE), "alice's number is the landlord's");
    let still: Vec<String> = tenants_at_the_door(&vault.ipc).await.into_iter().map(|t| t.user_id).collect();
    assert!(still.contains(&"sam".to_string()), "sam was not dropped by a tenant: {still:?}");
    assert!(!still.contains(&"mallory".to_string()), "a tenant minted no invite: {still:?}");

    // The tenant's packs, unreadable to both. The credential's key, admitted
    // at the handshake, is refused every verb that reads.
    let no_offer = kotton_net::transport::quic::tls::CertOffer {
        admission: vec![],
        claim: None,
    };
    for read in [
        UserRequest::ListSealed {
            user_id: "alice".into(),
            mount: "local".into(),
            prefix: String::new(),
        },
        UserRequest::ReadSealed {
            user_id: "alice".into(),
            mount: "local".into(),
            path: "notes.txt".into(),
            offset: 0,
            length: 0,
        },
        UserRequest::RecoveryFetch { user_id: "alice".into() },
    ] {
        let name = read.variant_name();
        match within(
            "the credential's key asks for alice's packs",
            try_ask_the_vault_with(&operator_key, &no_offer, &alice_vault, serde_json::to_vec(&read).unwrap()),
        )
        .await
        {
            Ok(UserResponse::Error { message }) => assert!(
                message.contains("the landlord's four verbs and nothing else"),
                "{name}: {message}"
            ),
            other => panic!("the operator credential read alice's {name}: {other:?}"),
        }
    }
    // The desktop without it is no one the vault admits.
    let list = serde_json::to_vec(&UserRequest::ListSealed {
        user_id: "alice".into(),
        mount: "local".into(),
        prefix: String::new(),
    })
    .unwrap();
    let refused = within(
        "the second desktop asks for alice's packs",
        try_ask_the_vault_as(&other_desk, &alice_vault, list),
    )
    .await;
    assert!(
        refused.is_err() || matches!(refused, Ok(UserResponse::Error { .. })),
        "a desktop with no standing read alice's packs: {refused:?}"
    );
}

/// **The landlord's own vault is listed as theirs** — Settings › Networking's
/// readout, read through the occupant host the shell calls — the moment the
/// desktop keeps its credential, though the landlord keeps nothing at it: the
/// row is the vault's name, *yours*, holding nothing of theirs. Serial, with a
/// base of its own, for `OwnBaseDir`'s reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn the_landlords_own_box_is_listed_as_theirs_once_the_desktop_keeps_its_credential() {
    use kotton_app::daemon::apps::OccupantHost;
    init_crypto();
    let _base = OwnBaseDir::take();
    let vault = within("starting the vault", spawn_vault("vault")).await;
    let mut door = within("the landlord's door", connect_when_ready(&vault.ipc, "door")).await;
    let (_, vault_key_hex) = within("the vault's identity", door.get_node_identity())
        .await
        .expect("the door says who the vault is");
    let (_key, credential) =
        within("minting the credential", operator_credential(&vault, &vault_key_hex)).await;

    let mut env = within("starting the desktop daemon", crate::common::relay::env_without()).await;
    within("the landlord's identity", env.client.create_user("lee", crate::common::TEST_PASSPHRASE))
        .await
        .expect("create_user");
    let before = within(
        "the readout before",
        OccupantHost::enrolled_vaults(&env.daemon.occupant_host()),
    )
    .await
    .expect("the readout answers");
    assert!(before.is_empty(), "nothing is listed before the credential is kept: {before:?}");

    within("keeping the credential", env.client.operator_enrol("lee", &credential))
        .await
        .expect("the desktop keeps the credential");
    let rows = vaults_in_the_readout(&env.daemon).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].label.as_deref(), Some("kotton"), "the vault by the name it was given");
    assert!(rows[0].yours, "listed as yours: {rows:?}");
    assert_eq!(rows[0].holds, "nothing of yours");
}

/// **A vault's operator credential is born in the landlord's own store, and
/// the vault holds only its public half** (DEC-0083, DEC-0087). The desktop
/// mints the key (`mint vault`) and is answered with the public half alone;
/// the vault's door enrols that half, as `kvaultd operator enrol` does at its
/// terminal; the desktop is handed back the vault's lines — `vault=` and
/// `addr=`, no secret — and the credential is whole: the landlord's verb
/// reaches the vault under it. Lines for a name nothing was minted for are
/// refused, and so is a second mint for a vault whose credential is already
/// kept. Serial, with a base of its own, for `OwnBaseDir`'s reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_key_minted_on_the_desktop_is_enrolled_at_the_vault_by_its_public_half_and_speaks_for_the_landlord() {
    use kotton_wire::ipc::OperatedService;
    init_crypto();
    let _base = OwnBaseDir::take();
    let vault = within("starting the vault", spawn_vault("vault")).await;
    let mut door = within("the landlord's door", connect_when_ready(&vault.ipc, "door")).await;
    let (_, vault_key_hex) = within("the vault's identity", door.get_node_identity())
        .await
        .expect("the door says who the vault is");

    let mut env = within("starting the desktop daemon", crate::common::relay::env_without()).await;
    within("the landlord's identity", env.client.create_user("lee", crate::common::TEST_PASSPHRASE))
        .await
        .expect("create_user");

    let public = within("minting on the desktop", env.client.operator_mint("lee", OperatedService::Vault, Some("kotton"), None))
        .await
        .expect("the desktop mints");
    assert_eq!(public.len(), 64, "the public half, in hex: {public}");
    assert!(public.chars().all(|c| c.is_ascii_hexdigit()), "{public}");

    // The vault enrols the public half at its terminal, as `docs/use/run-a-vault.md` orders it.
    admit_public_at_the_door(&vault, &public).await;

    // A name nothing was minted for: the vault's line completes nothing.
    let line = vault_line(&vault, &vault_key_hex);
    let refused = within("a line for a vault never minted", env.client.operator_complete("lee", "elsewhere", &line))
        .await
        .expect_err("a line for a vault nothing was minted for is refused");
    assert!(refused.to_string().contains("no key waiting for a vault called 'elsewhere'"), "{refused}");
    // The minted key is not whole until its instance's line completes it.
    let half = format!("name=kotton\nvault={vault_key_hex}\naddr=127.0.0.1:{}\n", vault.op_port);
    let refused = within("the vault's lines without its line", env.client.operator_enrol("lee", &half))
        .await
        .expect_err("a half is not a credential");
    assert!(refused.to_string().contains("`enrol <line>`"), "{refused}");

    within("completing the credential", env.client.operator_complete("lee", "kotton", &line))
        .await
        .expect("the vault's line completes the minted key");

    let answer = within(
        "the landlord's verb, under the minted key",
        env.client.as_operator("lee", "kotton", kotton_wire::ipc::OperatorVerb::Pools),
    )
    .await
    .expect("the daemon answers");
    assert!(
        matches!(answer, UserResponse::VaultTenants { .. }),
        "the vault did not stand the minted key as its operator: {answer:?}"
    );

    let again = within(
        "minting for a vault already kept",
        env.client.operator_mint("lee", OperatedService::Vault, Some("kotton"), None),
    )
    .await
    .expect_err("a second key for an enrolled vault is refused");
    assert!(again.to_string().contains("you already hold a vault called kotton; name this one (`mint vault <name>`)"), "{again}");
}

/// The line `vault` prints — kind, where it is reached, its key — as creation
/// returns it (RFC-0084 V20). The suite's vaults are created in process for the
/// suite's own key, so a test's desktop key is enrolled at the door beside it
/// and the line is composed from what the vault says of itself.
fn vault_line(vault: &RunningVault, vault_key_hex: &str) -> String {
    kotton_wire::line::InstanceLine {
        kind: kotton_wire::ipc::OperatedService::Vault,
        hint: format!("127.0.0.1:{}", vault.op_port),
        key: hex::decode(vault_key_hex).expect("hex").try_into().expect("32 bytes"),
    }
    .to_text()
}

/// The line the relay at `url` prints, under the key it proves.
fn relay_line(url: &str, key: &[u8; 32]) -> String {
    kotton_wire::line::InstanceLine { kind: kotton_wire::ipc::OperatedService::Relay, hint: url.to_string(), key: *key }.to_text()
}

/// `enrol <line> [<line>…]` as the shell sends it: the lines, and no name
/// (`TASK-enrol-takes-the-lines-an-instance-printed-and-a-vaults-ends-on-an-offer`).
async fn enrol_lines(client: &mut kotton::KottonClient, user: &str, lines: &[&str]) -> Vec<kotton_wire::ipc::LineEnrolled> {
    let given = lines.iter().map(|l| kotton_wire::ipc::LineToEnrol { line: l.to_string(), mint: None }).collect();
    within_for(WHOLE, "enrol <lines>", client.operator_enrol_lines(user, given)).await.expect("the daemon answers each line")
}

/// The one line `enrol` came to, and why it was refused — panicking when it
/// was not.
fn refused_line(came: &[kotton_wire::ipc::LineEnrolled]) -> (&kotton_wire::ipc::LineEnrolled, &str) {
    match came {
        [one] => match &one.came_to {
            kotton_wire::ipc::LineCame::Refused { why } => (one, why.as_str()),
            other => panic!("the line was not refused: {other:?}"),
        },
        other => panic!("one line was given: {other:?}"),
    }
}

/// The names of the keys still waiting for `service`.
async fn waiting_for(client: &mut kotton::KottonClient, user: &str, service: kotton_wire::ipc::OperatedService) -> Vec<String> {
    within("mint", client.operator_mints(user)).await.expect("the keys waiting").into_iter().filter(|m| m.service == service).map(|m| m.name).collect()
}

/// `kvaultd operator enrol <public>` at `vault`'s door, for a key minted on a
/// desktop — the public half is all the vault is ever handed.
async fn admit_public_at_the_door(vault: &RunningVault, public: &str) {
    let mut admit = kotton_ipc::IpcClient::<VaultRequest, UserResponse>::connect(vault.ipc.clone())
        .await
        .expect("the landlord reaches the door");
    match admit
        .send(&VaultRequest::OperatorAdmit { key: public.to_string() })
        .await
        .expect("the door answers")
    {
        UserResponse::Ok => {}
        other => panic!("the door did not enrol the minted key: {other:?}"),
    }
}

/// **`mint vault` and `mint relay` make two keys, and each service refuses
/// the other's** (DEC-0087). One name, two mints: two different public halves.
/// Then, at a vault and a relay each with its own key enrolled at its own
/// terminal, a desktop that speaks to the relay under the vault's key is
/// refused by the relay (*not an operator of this relay*), and one that speaks
/// to the vault under the relay's key is refused by the vault, which lets no
/// unenrolled key past its handshake — each kept as the other service's
/// credential, so the only thing wrong is the key. Under its own key, each
/// answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_vault_key_is_refused_at_the_relay_and_a_relay_key_at_the_vault() {
    use kotton_wire::ipc::{OperatedService, OperatorVerb};

    init_crypto();
    let _base = OwnBaseDir::take();
    let mut desk = within("the operator's desktop", crate::common::relay::env_without()).await;
    within("the operator's identity", desk.client.create_user("lee", crate::common::TEST_PASSPHRASE))
        .await
        .expect("create_user");
    let vault_half = within("mint vault kotton", desk.client.operator_mint("lee", OperatedService::Vault, Some("kotton"), None))
        .await
        .expect("the desktop mints the vault's key");
    let relay_half = within("mint relay kotton", desk.client.operator_mint("lee", OperatedService::Relay, Some("kotton"), None))
        .await
        .expect("the desktop mints the relay's key");
    assert_ne!(vault_half, relay_half, "one name, one key for both services");

    let bx = a_box().await;
    // Each key crossed: the vault's under a relay's credential, the relay's
    // under a vault's, on a desktop of its own.
    let crossed_relay = relay_credential_text(&bx.relay_url, &bx.vault_key);
    let mut door = within("the landlord's door", connect_when_ready(&bx.vault.ipc, "door")).await;
    let (_, vault_key_hex) = within("the vault's identity", door.get_node_identity())
        .await
        .expect("the door says who the vault is");
    let crossed_vault = vault_credential_text(&bx.vault, &vault_key_hex, &bx.relay_key);
    let mut other = within("a second desktop", crate::common::relay::env_on(&bx.relay_addr)).await;
    within("its identity", other.client.create_user("jo", crate::common::TEST_PASSPHRASE))
        .await
        .expect("create_user");
    within("keeping the crossed vault credential", other.client.operator_enrol("jo", &crossed_vault))
        .await
        .expect("the desktop keeps it — the key is the vault's to judge");
    within("keeping the crossed relay credential", other.client.operator_enrol("jo", &crossed_relay))
        .await
        .expect("the desktop keeps it — the key is the relay's to judge");
    match within_for(WHOLE, "the relay's rule under the vault's key", other.client.as_operator("jo", "kotton", OperatorVerb::ReadRule))
        .await
        .expect("the daemon answers")
    {
        UserResponse::Error { message } => assert!(message.contains("not an operator of this relay"), "{message}"),
        other => panic!("the relay answered the vault's key: {other:?}"),
    }
    match within_for(WHOLE, "the vault's people under the relay's key", other.client.as_operator("jo", "kotton", OperatorVerb::Pools))
        .await
        .expect("the daemon answers")
    {
        // A key the vault never enrolled is not let past its handshake: the
        // connection ends before any request is read.
        UserResponse::Error { message } => assert!(message.contains("the vault 'kotton' could not be reached"), "{message}"),
        other => panic!("the vault answered the relay's key: {other:?}"),
    }
    // Under its own key, each answers.
    bx.enrol_on(&mut desk.client, "lee").await;
    assert!(matches!(
        within_for(WHOLE, "vault people", desk.client.as_operator("lee", "kotton", OperatorVerb::Pools)).await.expect("answers"),
        UserResponse::VaultTenants { .. }
    ));
    assert!(matches!(
        within_for(WHOLE, "relay rule", desk.client.as_operator("lee", "kotton", OperatorVerb::ReadRule)).await.expect("answers"),
        UserResponse::RelayRule { .. }
    ));
}

/// **A relay minted with no rule is *only my devices* once the desktop
/// enrols it, and the vault that reserves there is handed its keys**
/// (`TASK-a-relays-admission-rule-is-set-by-its-operator-over-the-wire`, its
/// Done-when's rule clause as amended for DEC-0083 and DEC-0087).
///
/// The order, end to end — each step is typed in `docs/use/run-a-vault.md`, in
/// the order it numbers them: `mint vault kotton` and `mint relay kotton` on
/// the desktop, the second with no `--rule`, and two different keys; the
/// vault's door enrols its half and the relay's terminal its own; the vault's `enrol`
/// hands the desktop the vault's line, and `enrol <the relay's line>` names
/// the relay — which is what sets its rule, handing the keys first to the vault
/// the desktop has told nothing yet, which it now tells to stand there. Nothing else is said — no verb — and the relay,
/// which admitted every signed handle until then, now holds *only my devices*.
/// It is read at the relay itself, by what it admits, because the desktop's
/// own `ReadRule` would set a rule still waiting on the credential and so could
/// not tell an enrol that set it from one that did not: a stranger is refused,
/// a tag under the invited key is refused, and a tag under the desktop's own
/// key is admitted. The vault holds that same key. Only then is the desktop
/// asked, and it reads the same rule back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_relay_minted_with_no_rule_is_only_my_devices_once_enrolled_and_its_vault_holds_the_keys() {
    use kotton_wire::ipc::{OperatedService, OperatorVerb};
    use kotton_wire::rendezvous::AdmissionRule;

    init_crypto();
    let _base = OwnBaseDir::take();
    let mut desk = within("the operator's desktop", crate::common::relay::env_without()).await;
    within("the operator's identity", desk.client.create_user("lee", crate::common::TEST_PASSPHRASE))
        .await
        .expect("create_user");
    let vault_public = within("mint vault kotton", desk.client.operator_mint("lee", OperatedService::Vault, Some("kotton"), None))
        .await
        .expect("the desktop mints the vault's key");
    let relay_public = within("mint relay kotton, no rule named", desk.client.operator_mint("lee", OperatedService::Relay, Some("kotton"), None))
        .await
        .expect("the desktop mints the relay's key");
    assert_ne!(vault_public, relay_public);

    // Each service enrols its own half: the relay's terminal, the vault's door.
    let (_relay, relay_addr) =
        within("starting the relay", crate::common::relay::spawn_with_operator(&relay_public)).await;
    let relay_url = format!("http://{relay_addr}");
    let relay_id = within("the relay's key", crate::common::relay::key_of(&relay_addr)).await;
    // The vault stands nowhere: nothing but its operator's desktop tells it where.
    let vault = within("starting the vault", spawn_vault("vault")).await;
    let mut door = within("the landlord's door", connect_when_ready(&vault.ipc, "door")).await;
    let (_, vault_key_hex) = within("the vault's identity", door.get_node_identity())
        .await
        .expect("the door says who the vault is");
    admit_public_at_the_door(&vault, &vault_public).await;
    assert!(a_push_at(&relay_url, None).await.is_ok(), "a relay nobody has set refused a stranger");

    // `enrol <the vault's line>`: the vault is kept, and no rule is set.
    within("the vault's credential", desk.client.operator_complete("lee", "kotton", &vault_line(&vault, &vault_key_hex)))
        .await
        .expect("the vault's line completes the minted key");
    assert!(a_push_at(&relay_url, None).await.is_ok(), "a vault's enrol set the relay's rule");

    // `enrol <the relay's line>`, and nothing after it.
    within("the relay's credential", desk.client.operator_complete("lee", "kotton", &relay_line(&relay_url, &relay_id)))
        .await
        .expect("the relay's line completes the minted key");

    // Read at the relay, by what it admits: only my devices.
    let stranger = a_push_at(&relay_url, None).await;
    assert!(refused_by_the_rule(&stranger), "the enrol set no rule: a stranger was admitted: {stranger:?}");
    let keys = desk.runtime.reachability().relay_keys();
    let mine = keys.present_at(&relay_id).expect("the enrol minted and holds the operator's own key");
    let invited = keys.offer_for("lee", &relay_id).expect("and the invited key, as the operator");
    let invitee = a_push_at(&relay_url, Some(invited)).await;
    assert!(refused_by_the_rule(&invitee), "the rule reads the invited key, so it is not only my devices: {invitee:?}");
    assert!(a_push_at(&relay_url, Some(mine.clone())).await.is_ok(), "a tag under the operator's own key was refused");
    // The vault the desktop told to stand at this relay stands there, by its
    // key, and was handed the same key with it.
    let nat = vault.vault.runtime().reachability().nat();
    assert_eq!((nat.relay_url.as_str(), nat.relay_key.as_deref()), (relay_url.as_str(), Some(hex::encode(relay_id).as_str())));
    assert_eq!(
        vault.vault.runtime().reachability().relay_keys().present_at(&relay_id),
        Some(mine),
        "the vault that stands at the relay was not handed its keys"
    );

    // And the desktop reads the same rule back.
    assert_eq!(rule_said(&mut desk.client, "lee", OperatorVerb::ReadRule).await, AdmissionRule::OnlyMyDevices);
}

/// **A relay stood alone takes its rule from the desktop, and hands its keys
/// to no vault** (DEC-0087). A relay-only machine is operable: `mint relay`,
/// the relay's terminal enrols the half, `enrol <the relay's line>` — which sets
/// the mint's *only my devices* — and then `relay rule <r> people_i_invite`
/// sets it again, answered with what the relay holds. The desktop operates a
/// vault too, but one it told to stand at another relay it operates: it is
/// handed nothing, because the vaults at a relay are the ones the desktop
/// told to stand there, found by the relay's key
/// (`TASK-the-desktop-tells-the-vault-which-relays-to-stand-at`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_relay_alone_takes_its_rule_and_hands_keys_to_no_vault() {
    use kotton_wire::ipc::{OperatedService, OperatorVerb};
    use kotton_wire::rendezvous::AdmissionRule;

    init_crypto();
    let _base = OwnBaseDir::take();
    let (relay, relay_addr) = within("a relay, alone", crate::common::relay::spawn_with_state()).await;
    let relay_url = format!("http://{relay_addr}");
    let mut desk = within("the operator's desktop", crate::common::relay::env_without()).await;
    within("the operator's identity", desk.client.create_user("lee", crate::common::TEST_PASSPHRASE))
        .await
        .expect("create_user");

    // A vault this person operates, told by this desktop to stand at some
    // other relay it operates.
    let (_other, other_addr) = within("another relay", crate::common::relay::spawn_with_state()).await;
    let other_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let other = relay_credential_text(&format!("http://{other_addr}"), &other_key).replace("name=kotton", "name=elsewhere");
    within("keeping the other relay", desk.client.operator_enrol("lee", &other))
        .await
        .expect("the desktop keeps the other relay's credential");
    let vault = within("a vault elsewhere", spawn_vault("vault")).await;
    let mut door = within("the landlord's door", connect_when_ready(&vault.ipc, "door")).await;
    let (_, vault_key_hex) = within("the vault's identity", door.get_node_identity())
        .await
        .expect("the door says who the vault is");
    let (_key, elsewhere) =
        within("its credential", operator_credential(&vault, &vault_key_hex)).await;
    within("keeping it", desk.client.operator_enrol("lee", &elsewhere))
        .await
        .expect("the desktop keeps the vault's credential");
    let told = vault.vault.runtime().reachability().nat();
    assert_eq!(told.relay_url, format!("http://{other_addr}"), "the vault's enrol told it to stand at the relay operated");

    let public = within("mint relay gate", desk.client.operator_mint("lee", OperatedService::Relay, Some("gate"), None))
        .await
        .expect("the desktop mints the relay's key");
    relay.operator_enrol(&public);
    let gate = relay_line(&relay_url, &crate::common::relay::key_of(&relay_addr).await);
    within("enrol <the relay's line>", desk.client.operator_complete("lee", "gate", &gate))
        .await
        .expect("the relay's line completes the minted key");
    let stranger = a_push_at(&relay_url, None).await;
    assert!(refused_by_the_rule(&stranger), "the enrol set no rule: {stranger:?}");

    let set = within_for(
        WHOLE,
        "relay rule gate people_i_invite",
        desk.client.as_operator("lee", "gate", OperatorVerb::SetRule { rule: AdmissionRule::PeopleIInvite }),
    )
    .await
    .expect("the daemon answers");
    assert!(
        matches!(set, UserResponse::RelayRule { rule: AdmissionRule::PeopleIInvite }),
        "the relay alone did not take its rule: {set:?}"
    );
    let relay_id = crate::common::relay::key_of(&relay_addr).await;
    let invited = desk.runtime.reachability().relay_keys().offer_for("lee", &relay_id).expect("the invited key");
    assert!(a_push_at(&relay_url, Some(invited)).await.is_ok(), "people I invite refused the invited key");
    assert_eq!(
        vault.vault.runtime().reachability().relay_keys().present_at(&relay_id),
        None,
        "a vault told to stand at another relay was handed this relay's keys"
    );
    assert_eq!(
        vault.vault.runtime().reachability().nat().relay_url,
        format!("http://{other_addr}"),
        "a relay enrolled later moved a vault that was already told where to stand"
    );
}

/// The vault's identity, as a device dialling it directly sees it.
async fn identity_of(vault: &RunningVault) -> VaultIdentity {
    let mut door = within("the landlord's door", connect_when_ready(&vault.ipc, "door")).await;
    let (did, pubkey_hex) = within("the vault's identity", door.get_node_identity())
        .await
        .expect("the door says who the vault is");
    VaultIdentity {
        did,
        pubkey_hex,
        op_addr: format!("127.0.0.1:{}", vault.op_port).parse().unwrap(),
    }
}

/// Say `StandAt { relays }` to `vault` over the peer transport under the
/// operator key `key`, as a desktop does (`agent::operator::tell`).
async fn tell_as_operator(
    key: &ed25519_dalek::SigningKey,
    vault: &VaultIdentity,
    relays: Vec<kotton_wire::rendezvous::Stand>,
) -> UserResponse {
    let offer = kotton_net::transport::quic::tls::CertOffer {
        admission: vec![],
        claim: None,
    };
    let request = serde_json::to_vec(&UserRequest::StandAt { relays }).unwrap();
    try_ask_the_vault_with(key, &offer, vault, request)
        .await
        .unwrap_or_else(|e| panic!("the operator's key reaches the vault: {e}"))
}

/// **A vault enrolled after its relay's rule was set is admitted under *only
/// my devices*, with nothing said twice**
/// (`TASK-the-desktop-tells-the-vault-which-relays-to-stand-at`, Done-when 6,
/// first; closes `TASK-a-vault-enrolled-after-its-relays-rule-holds-no-relay-key`).
///
/// The relay first: the relay's `enrol` with the mint's *only my devices*, which sets
/// the rule at the relay with no vault to tell. Then the vault's `enrol`, and nothing
/// else — no `relay rule` said again. The enrol tells the vault its reach set:
/// the relay by the key it proved, its URL as the hint, and the keys the rule
/// reads. The vault stands there by that key, holds *mine* under it, and an
/// invite asked of it is reserved at the narrowed relay — which a vault
/// presenting no key could not do.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_vault_enrolled_after_its_relays_rule_is_admitted_under_only_my_devices_with_nothing_said_twice() {
    use kotton_wire::ipc::OperatorVerb;
    use kotton_wire::rendezvous::AdmissionRule;

    init_crypto();
    let bx = a_box().await;
    let mut desk = within("the operator's desktop", crate::common::relay::env_on(&bx.relay_addr)).await;
    within("the operator's identity", desk.client.create_user("lee", crate::common::TEST_PASSPHRASE))
        .await
        .expect("create_user");

    // The relay, with the rule its mint asked for, and no vault yet.
    let with_rule = format!("{}rule=only_my_devices\n", bx.relay_credential);
    within("the relay's credential", desk.client.operator_enrol("lee", &with_rule))
        .await
        .expect("the desktop keeps the relay's credential");
    assert_eq!(bx.rule_at_the_relay().await, AdmissionRule::OnlyMyDevices, "the relay's enrol set the mint's rule");
    assert!(refused_by_the_rule(&a_push_at(&bx.relay_url, None).await), "a stranger is refused");
    assert!(bx.vault.vault.runtime().reachability().nat().relay_url.is_empty(), "the vault stands nowhere yet");

    // the vault's `enrol`, and nothing after it.
    within("the vault's credential", desk.client.operator_enrol("lee", &bx.vault_credential))
        .await
        .expect("the desktop keeps the vault's credential and tells it where to stand");

    let nat = bx.vault.vault.runtime().reachability().nat();
    assert_eq!(nat.relay_url, bx.relay_url, "the vault stands at the relay it was told");
    assert_eq!(nat.relay_key, Some(hex::encode(bx.relay_id)), "by the key the relay proved");
    let mine = desk.runtime.reachability().relay_keys().present_at(&bx.relay_id).expect("the desktop holds mine");
    assert_eq!(
        bx.vault.vault.runtime().reachability().relay_keys().present_at(&bx.relay_id),
        Some(mine),
        "the vault was told the keys the rule reads with the relay"
    );
    let before = crate::common::relay::reservations(&bx.relay_addr).await;
    match within_for(
        WHOLE,
        "an invite at the narrowed relay",
        desk.client.as_operator("lee", "kotton", OperatorVerb::Invite { pool: "sam".into(), quota: None, ttl_seconds: 60 }),
    )
    .await
    .expect("the desktop's daemon answers")
    {
        UserResponse::PairAdvertising { code, .. } => match kotton_wire::line::InviteCode::parse(code.expose()) {
            Ok(kotton_wire::line::InviteCode::Vault { relay_hint, .. }) => {
                assert_eq!(relay_hint, bx.relay_url, "the invite names the vault's relay: {}", code.expose())
            }
            other => panic!("not a vault's invite in the grammar: {other:?} — {}", code.expose()),
        },
        other => panic!("no invite: {other:?}"),
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while crate::common::relay::reservations(&bx.relay_addr).await <= before {
        assert!(
            std::time::Instant::now() < deadline,
            "the vault's invite was never reserved at the relay under only my devices"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(bx.rule_at_the_relay().await, AdmissionRule::OnlyMyDevices, "nothing moved the rule");
}

/// **A vault enrolled while another key answers at its relay's address is
/// answered *enrolled*, with why it stands at no relay yet**
/// (`TASK-a-kept-claim-is-answered-as-a-failure-and-its-unit-left-stale-lines`,
/// Done-when, the enrol).
///
/// The relay is enrolled with its rule; then it goes down and a stranger's
/// relay comes up at its address. the vault's `enrol` keeps the vault's credential —
/// the vault answers this desktop as its operator — and the vault, told to
/// stand at the relay by its key, finds another key there and refuses the
/// telling (RFC-0084 V9). The answer is the enrol, carrying why, and never an
/// error: a key minted here is spent on its enrol, so an error sending the
/// person to enrol again sends them to a refusal. `vault stand` is the remedy
/// the shell names beside it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_vault_enrolled_while_a_stranger_holds_its_relays_address_is_answered_enrolled_with_why() {
    use kotton_wire::ipc::OperatorVerb;

    init_crypto();
    let bx = a_box().await;
    let mut desk = within("the operator's desktop", crate::common::relay::env_on(&bx.relay_addr)).await;
    within("the operator's identity", desk.client.create_user("lee", crate::common::TEST_PASSPHRASE))
        .await
        .expect("create_user");
    let with_rule = format!("{}rule=only_my_devices\n", bx.relay_credential);
    let relay = within("the relay's credential", desk.client.operator_enrol("lee", &with_rule))
        .await
        .expect("the desktop keeps the relay's credential");
    assert_eq!(relay.unstood, None, "a relay's enrol has no vault to leave untold");
    drop(bx._relay);
    let elsewhere = tempfile::tempdir().expect("a stranger's relay state");
    crate::common::relay::create_at(elsewhere.path(), &hex::encode(ed25519_dalek::SigningKey::from_bytes(&rand::random()).verifying_key().to_bytes()));
    // At the address the relay it replaces was given: the point of the case is a
    // stranger where the vault's relay was, so this one port is not the OS's pick.
    let (mut stranger, _, _) = crate::common::relay::relay_at(elsewhere.path(), &bx.relay_addr, &bx.relay_url).await;

    let kept = within("the vault's credential, a stranger at the relay's address", desk.client.operator_enrol("lee", &bx.vault_credential))
        .await
        .expect("a vault that could not be told where to stand is enrolled all the same");
    assert_eq!(kept.name, "kotton");
    let why = kept.unstood.expect("the answer says the vault stands at no relay yet");
    assert_eq!(why.why, kotton_wire::ipc::UnstoodWhy::NotTold, "{why}");
    assert!(why.reason.contains("kotton"), "the reason names the vault: {why}");
    assert!(bx.vault.vault.runtime().reachability().nat().relay_url.is_empty(), "the vault stands nowhere yet");
    assert!(
        matches!(
            within("vault people", desk.client.as_operator("lee", "kotton", OperatorVerb::Pools))
                .await
                .expect("the desktop's daemon answers"),
            UserResponse::VaultTenants { .. }
        ),
        "the credential is kept: the vault answers this desktop as its operator"
    );
    let _ = stranger.kill();
    let _ = stranger.wait();
}

/// **A vault told a new reach set stands at the new relay, and its tenant
/// follows with nothing re-paired**
/// (`TASK-the-desktop-tells-the-vault-which-relays-to-stand-at`, Done-when 1 and
/// 6, second).
///
/// The vault stands at the host's relay, told by its desktop, and has a tenant.
/// A second relay is started. First a telling that names the second relay's
/// address with the first relay's key: the vault asks the relay at the address
/// who it is, is shown another key, and refuses the whole set — it still stands
/// where it stood. Then the set is told as it is, over the peer transport under
/// the operator's key: the vault stands at the second relay by its key, and
/// reserves there; it answers `NodeRelay` with the second relay's key and
/// address. The tenant's next connect — to the vault it paired, never paired
/// again — learns the new relay by its key and pushes. And a tenant's key
/// saying the same verb is refused: the reach set is the operator's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_vault_told_a_new_relay_stands_there_and_its_tenant_follows_with_nothing_re_paired() {
    init_crypto();
    let bx = a_box().await;
    let mut desk = within("the operator's desktop", crate::common::relay::env_on(&bx.relay_addr)).await;
    within("the operator's identity", desk.client.create_user("lee", crate::common::TEST_PASSPHRASE))
        .await
        .expect("create_user");
    bx.enrol_on(&mut desk.client, "lee").await;
    assert_eq!(bx.vault.vault.runtime().reachability().nat().relay_url, bx.relay_url, "the desktop told the vault");
    let mut sam = a_tenant(&bx, "sam").await;
    let vault = identity_of(&bx.vault).await;
    let vault_pub: [u8; 32] = hex::decode(&vault.pubkey_hex).unwrap().try_into().unwrap();

    let (_second, second_addr) = within("a second relay", crate::common::relay::spawn()).await;
    let second_url = format!("http://{second_addr}");
    let second_id = crate::common::relay::key_of(&second_addr).await;
    let stand = |key: [u8; 32]| kotton_wire::rendezvous::Stand {
        key: hex::encode(key),
        hint: second_url.clone(),
        mine: None,
        invited: None,
    };

    // A stranger at the address: the first relay's key named at the second's.
    match tell_as_operator(&bx.vault_key, &vault, vec![stand(bx.relay_id)]).await {
        UserResponse::Error { message } => assert!(message.contains("is not the relay"), "{message}"),
        other => panic!("the vault stood at a relay that proved another key: {other:?}"),
    }
    assert_eq!(bx.vault.vault.runtime().reachability().nat().relay_url, bx.relay_url, "a refused set moved nothing");

    // A tenant's device cannot say it.
    let sams_key = kotton_peer::daemon::nodes::load_device_operational_key(sam.env.runtime.secrets()).expect("sam's key");
    let offer = kotton_net::transport::quic::tls::CertOffer { admission: vec![], claim: None };
    let said = try_ask_the_vault_with(
        &sams_key,
        &offer,
        &vault,
        serde_json::to_vec(&UserRequest::StandAt { relays: vec![stand(second_id)] }).unwrap(),
    )
    .await;
    assert!(
        matches!(said, Ok(UserResponse::Error { .. }) | Err(_)),
        "a tenant told the vault where to stand: {said:?}"
    );
    assert_eq!(bx.vault.vault.runtime().reachability().nat().relay_url, bx.relay_url);

    // The set as it is, under the operator's key.
    match tell_as_operator(&bx.vault_key, &vault, vec![stand(second_id)]).await {
        UserResponse::Ok => {}
        other => panic!("the vault did not take its reach set: {other:?}"),
    }
    let nat = bx.vault.vault.runtime().reachability().nat();
    assert_eq!((nat.relay_url.as_str(), nat.relay_key), (second_url.as_str(), Some(hex::encode(second_id))));
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while crate::common::relay::reservations(&second_addr).await == 0 {
        assert!(std::time::Instant::now() < deadline, "the vault never reserved at the relay it was told");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let (answered_url, answered_key, _) = kvaultd::reach::for_tenant(bx.vault.vault.runtime());
    assert_eq!((answered_url, answered_key), (Some(second_url.clone()), Some(hex::encode(second_id))));

    // The tenant's next connect follows, by the key, and pushes.
    a_fresh_connect(&mut sam, "sam").await;
    assert_eq!(
        sam.env.runtime.reachability().relay_keys().relay_of("sam", &vault_pub, &second_url),
        Some(second_id),
        "sam learned where the vault stands now, by the relay's key"
    );
    assert_eq!(sam.vault_did, vault.did, "the same vault, never paired again");

    // A restart keeps it: the set is the vault's own state.
    let kept = kvaultd::reach::read(&kotton_device::db::open_machine_db(bx.vault.base_path.join("system").join("agent.db")).await.expect("the vault's db"))
        .await
        .expect("the reach set reads");
    assert_eq!(kept.iter().map(|s| s.key.clone()).collect::<Vec<_>>(), [hex::encode(second_id)]);
}

/// **Recovery works with the host's relay narrowed to *only my devices***
/// (asked by the driver's recovery check, 2026-09-30). A tenant keeps things at
/// the host's vault while its relay admits anyone; the operator's desktop then
/// sets *only my devices*, so a stranger is refused at the relay. Every device of
/// the tenant's is lost, and a cold device given only the phrase recovers from
/// the vault and reads back what was kept: recovery dials the vault's own
/// address and never needs the relay, so a keyed, narrowed relay does not stand
/// in its way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn recovery_works_while_the_boxs_relay_admits_only_my_devices() {
    use kotton_wire::ipc::OperatorVerb;
    use kotton_wire::rendezvous::AdmissionRule;

    init_crypto();
    let bx = a_box().await;
    let mut desk = within("the operator's desktop", crate::common::relay::env_on(&bx.relay_addr)).await;
    within("the operator's identity", desk.client.create_user("lee", crate::common::TEST_PASSPHRASE))
        .await
        .expect("create_user");
    bx.enrol_on(&mut desk.client, "lee").await;

    // Sam keeps things at the vault while the relay admits anyone.
    let phrase;
    let identity;
    {
        let mut env = within("sam's device", crate::common::relay::env_on(&bx.relay_addr)).await;
        let spare = within("a spare client", connect_when_ready(&env.endpoint, "sam")).await;
        let mut client = std::mem::replace(&mut env.client, spare);
        phrase = within("sam's things", a_person_with_things(&mut client, "sam", NOTE)).await;
        let (mut client, id) =
            within("enrolling sam", enrol_vault_from(client, "sam's laptop", &bx.vault, "sam", "vault")).await;
        identity = id;
        a_push_to_the_vault(&mut client, "sam").await;
        // Every device of sam's is lost here.
    }

    assert_eq!(
        rule_said(&mut desk.client, "lee", OperatorVerb::SetRule { rule: AdmissionRule::OnlyMyDevices }).await,
        AdmissionRule::OnlyMyDevices
    );
    assert!(refused_by_the_rule(&a_push_at(&bx.relay_url, None).await), "a stranger is refused at the relay");

    let (_cold_device, mut cold) = within_for(WHOLE, "recovering from the phrase", recover_from(&phrase, "sam", &identity)).await;
    assert_eq!(cold.read_file("sam", "notes.txt").await.expect("file").as_slice(), NOTE);
    assert_eq!(bx.rule_at_the_relay().await, AdmissionRule::OnlyMyDevices, "recovery ran with the rule in place");
}

/// **The operator reaches their own vault relayed at their own relay under
/// *only my devices*, as a tenant and as the operator**
/// (`TASK-the-supplied-address-check-refuses-the-person-at-their-own-relay`).
///
/// The operator's desktop holds the host's credentials and is also a tenant of
/// its vault (`vault invite kotton --me`); its own relay is the host's relay. The
/// relay is narrowed to *only my devices*, and a connect as the tenant, at the
/// vault's address, is handed *invited* by the vault's `NodeRelay`. The vault's
/// direct address is then made unreachable, so both dials go through the relay — the path 0.1 never
/// takes because a vault with a public address is dialled direct. The tenant's
/// dial presents *mine*, not what the vault handed, and the operator's dial —
/// which names no pool — presents *mine* too: each is admitted by a relay that
/// reads only *mine*, and carries a request to the vault and back. *Invited*
/// is refused there, so an admitted dial is one that presented *mine*.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn the_operator_dials_their_own_vault_relayed_at_their_own_relay_under_only_my_devices() {
    use kotton_wire::ipc::OperatorVerb;
    use kotton_wire::rendezvous::AdmissionRule;

    init_crypto();
    let bx = a_box().await;
    let mut desk = within("the operator's desktop", crate::common::relay::env_on(&bx.relay_addr)).await;
    within("the operator's things", a_person_with_things(&mut desk.client, "lee", NOTE)).await;
    bx.enrol_on(&mut desk.client, "lee").await;
    assert_eq!(desk.runtime.reachability().nat().relay_url, bx.relay_url, "the desktop's own relay is the host's");

    // The operator becomes a tenant of their own vault while the relay admits
    // anyone: an admit at a narrowed relay is
    // `TASK-a-first-contact-ceremony-meets-at-a-relay-whose-rule-refuses-a-stranger`.
    let rx = within_for(WHOLE, "vault invite kotton --me", desk.client.vault_invite_me_stream("lee", "kotton", 60))
        .await
        .expect("the vault minted an invite for the desktop's own user");
    let kotton::InvitedMe::Admitting(mut rx) = rx else { panic!("the vault keeps for the desktop's own user already") };
    let node = the_operators_own_admit(&mut rx)
        .await
        .unwrap_or_else(|why| panic!("the operator's desktop was not admitted: {why}"));
    // The relay narrowed: that is when the keys are minted and the vault is
    // handed them. The first connect, at the vault's address, asks it where it
    // stands, and it answers its tenant with *invited*, at this relay.
    assert_eq!(
        rule_said(&mut desk.client, "lee", OperatorVerb::SetRule { rule: AdmissionRule::OnlyMyDevices }).await,
        AdmissionRule::OnlyMyDevices
    );
    // The vault takes the new device's key a moment after the admit ends, as
    // `the_boxs_operator_invites_themselves_in_one_act_and_pushes` waits for.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let remote = RemoteBackend::Kotton { peer_did: node.device_did.to_string(), label: "vault".to_string() };
        match desk.client.remote_add("lee", "vault", remote, None).await {
            Ok(_) => break,
            Err(_) if std::time::Instant::now() < deadline => tokio::time::sleep(Duration::from_millis(500)).await,
            Err(e) => panic!("the operator's desktop could not reach its own vault at its address: {e}"),
        }
    }
    a_push_to_the_vault(&mut desk.client, "lee").await;
    let keys = desk.runtime.reachability().relay_keys();
    let mine = keys.present_for("lee", &bx.relay_id).expect("the desktop keeps mine");
    let invited = keys.offer_for("lee", &bx.relay_id).expect("and offers invited, as the operator");
    assert_eq!(keys.relay_of("lee", &node.public_key, &bx.relay_url), Some(bx.relay_id), "the vault stands at the desktop's own relay");
    assert_eq!(
        keys.present_for_peer("lee", &node.public_key, &bx.relay_url),
        Some(invited.clone()),
        "the vault handed its tenant invited"
    );

    assert!(refused_by_the_rule(&a_push_at(&bx.relay_url, Some(invited)).await), "only my devices reads invited");
    assert!(a_push_at(&bx.relay_url, Some(mine)).await.is_ok(), "only my devices reads mine");

    // Nothing answers at this address, so the dial is the relay's.
    let unreachable: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let events = Arc::clone(desk.runtime.event_bus());

    // As the tenant: the device's own key, for lee's pool.
    let device_key = kotton_peer::daemon::nodes::load_device_operational_key(desk.runtime.secrets()).expect("the desktop's key");
    let tenant = kotton_peer::dialer::Dialer::new(device_key, Arc::clone(desk.runtime.reachability()), Arc::clone(&events));
    let as_tenant = kotton_wire::peer::PairedNode {
        addresses: vec![unreachable],
        relay_url: Some(bx.relay_url.clone()),
        ..node.clone()
    };
    let conn = within_for(WHOLE, "the tenant's relayed dial", tenant.connect(as_tenant, "lee"))
        .await
        .unwrap_or_else(|e| panic!("the tenant's dial at its own relay was refused: {e:#}"));
    let answer = within("the vault answers the tenant", conn.send(&UserRequest::NodeRelay { user_id: "lee".into() }))
        .await
        .expect("the relayed connection carries a request");
    assert!(matches!(answer, UserResponse::NodeRelayResult { .. }), "{answer:?}");

    // As the operator: the credential's key, for no pool — `say`'s dial.
    let credential = kotton_peer::operator::OperatorCredential::parse(&bx.vault_credential).expect("the vault's credential");
    let operator = credential.dialer(Arc::clone(desk.runtime.reachability()), Arc::clone(&events));
    let mut as_operator = credential.vault_node(Some(&bx.relay_url)).expect("the vault as a node");
    as_operator.addresses = vec![unreachable];
    let conn = within_for(WHOLE, "the operator's relayed dial", operator.connect(as_operator, ""))
        .await
        .unwrap_or_else(|e| panic!("the operator's dial at their own relay was refused: {e:#}"));
    within("the vault answers its operator", conn.send(&UserRequest::NodeRelay { user_id: String::new() }))
        .await
        .expect("the relayed connection carries a request");
    assert_eq!(bx.rule_at_the_relay().await, AdmissionRule::OnlyMyDevices, "both dials ran with the rule in place");
}

/// **A vault with no reach set stands nowhere, whatever its environment says**
/// (`TASK-the-desktop-tells-the-vault-which-relays-to-stand-at`, Done-when 4 and
/// 6, third; closes `TASK-the-vault-reads-its-relay-from-the-process-environment`).
///
/// A live relay, and `KOTTON_RELAY_URL` naming it in the process while the vault
/// is constructed — the line an install before 2026-09-29 left in
/// `/etc/kotton/vault.env`. The vault reads none of it: it holds no relay,
/// reserves nothing there, answers `NodeRelay` with none, and refuses an invite
/// with the sentence that names the act that tells it — not a file.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_vault_with_no_reach_set_and_a_stale_relay_url_in_its_environment_stands_nowhere() {
    init_crypto();
    let (_relay, relay_addr) = within("a relay", crate::common::relay::spawn()).await;
    let previous = std::env::var_os("KOTTON_RELAY_URL");
    std::env::set_var("KOTTON_RELAY_URL", format!("http://{relay_addr}"));
    let vault = spawn_vault("vault").await;
    match previous {
        Some(v) => std::env::set_var("KOTTON_RELAY_URL", v),
        None => std::env::remove_var("KOTTON_RELAY_URL"),
    }

    let nat = vault.vault.runtime().reachability().nat();
    assert_eq!((nat.relay_url.as_str(), nat.relay_key), ("", None), "the vault read a relay from its environment");
    let mut raw = kotton_ipc::IpcClient::<VaultRequest, UserResponse>::connect(vault.ipc.clone())
        .await
        .expect("the landlord reaches the door");
    let door = within("the landlord's door", connect_when_ready(&vault.ipc, "door")).await;
    match within("where the vault stands", raw.send(&VaultRequest::NodeRelay { user_id: String::new() }))
        .await
        .expect("the door answers")
    {
        UserResponse::NodeRelayResult { relay_url, relay_key, .. } => assert_eq!((relay_url, relay_key), (None, None)),
        other => panic!("{other:?}"),
    }
    let mut rx = door.device_invite_stream("sam", 60, None).await.expect("the door takes the ask");
    match within("the invite's answer", rx.recv()).await {
        Some(UserResponse::Error { message }) => {
            assert_eq!(message, kvaultd::control::NO_RELAY);
            assert!(!message.contains("vault.env") && !message.contains("KOTTON_RELAY_URL"), "{message}");
        }
        other => panic!("a vault standing nowhere minted an invite: {other:?}"),
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(crate::common::relay::reservations(&relay_addr).await, 0, "the vault reserved at the relay its environment named");
}

/// **A relay's line completes nothing until its terminal enrols the key, and
/// then completes it and sets its first rule** (decision 0008).
///
/// The guides order a relay's key enrolled there — by its install, or at its
/// terminal for a further operator (`docs/use/run-a-relay.md`, "A second
/// operator") — before the desktop's `enrol <the relay's line>`, and `enrol`
/// holds the relay to the minted key at its operator door before it keeps
/// anything. Here the order is taken the other way round: a relay created for
/// another key, the line given first. The relay proves the key its line names
/// and refuses the minted one at its door, so nothing is kept, the key still
/// waits, the relay's rule is untouched — a stranger is still admitted — and
/// the refusal says what was presented there and the enrol at the host that
/// admits it, never the relay's rule. Then `kotton-relay operator enrol <key>`
/// at its terminal, which sets nothing; and the same line, given again,
/// completes the key and sets the mint's *only my devices*: a stranger
/// refused, a tag under the desktop's own key admitted, and the credential
/// carrying no rule still to set. Said a third time, and `mint relay` said
/// again, both are refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_relays_line_completes_nothing_until_its_terminal_enrols_the_key() {
    use kotton_wire::ipc::{LineCame, OperatedService, OperatorVerb};

    init_crypto();
    let _base = OwnBaseDir::take();
    let mut desk = within("the operator's desktop", crate::common::relay::env_without()).await;
    within("the operator's identity", desk.client.create_user("lee", crate::common::TEST_PASSPHRASE))
        .await
        .expect("create_user");
    let public = within("mint relay kotton, no rule named", desk.client.operator_mint("lee", OperatedService::Relay, Some("kotton"), None))
        .await
        .expect("the desktop mints the relay's key");

    // A relay created for another key: this one is not enrolled there yet.
    let (relay, relay_addr) = within("starting the relay", crate::common::relay::spawn_with_state()).await;
    let relay_url = format!("http://{relay_addr}");
    let relay_id = within("the relay's key", crate::common::relay::key_of(&relay_addr)).await;
    let line = relay_line(&relay_url, &relay_id);

    // `enrol <the relay's line>` first: refused at its door, nothing kept.
    let came = enrol_lines(&mut desk.client, "lee", &[&line]).await;
    let (said, why) = refused_line(&came);
    assert_eq!((said.dialled, said.reached, said.matched), (true, Some(true), None), "{said:?}");
    assert!(
        why.contains("proved the key its line names and, asked as its operator under the key minted for the relay 'kotton', answered a refusal nothing signed"),
        "{why}"
    );
    assert!(why.contains("nothing is kept, and the key still waits") && why.contains(&format!("operator enrol {public}`")), "{why}");
    assert!(!why.contains("choose that one"), "one key waited, and the refusal speaks of choosing: {why}");
    for word in ["holds", "forget", "only my devices", "only_my_devices", "anyone"] {
        assert!(!why.contains(word), "the refusal says {word:?}: {why}");
    }
    assert_eq!(waiting_for(&mut desk.client, "lee", OperatedService::Relay).await, vec!["kotton".to_string()], "the refused line spent the key");
    match within("relay rule, with nothing kept", desk.client.as_operator("lee", "kotton", OperatorVerb::ReadRule)).await.expect("answers") {
        UserResponse::Error { message } => assert!(message.contains("holds no operator credential for the relay 'kotton'"), "{message}"),
        other => panic!("a credential was kept for a relay that refused its key: {other:?}"),
    }
    let stranger = a_push_at(&relay_url, None).await;
    assert!(stranger.is_ok(), "a refused enrol set the relay's rule: {stranger:?}");

    // `kotton-relay operator enrol <key>` at the relay's terminal: nothing is set by it.
    relay.operator_enrol(&public);
    let stranger = a_push_at(&relay_url, None).await;
    assert!(stranger.is_ok(), "enrolling the operator at the terminal set a rule: {stranger:?}");

    // The same line, given again: kept, and the mint's first rule set.
    let came = enrol_lines(&mut desk.client, "lee", &[&line]).await;
    assert!(matches!(&came[0].came_to, LineCame::Kept { name, .. } if name == "kotton"), "{came:?}");
    assert_eq!((came[0].dialled, came[0].reached, came[0].matched), (true, Some(true), Some(true)), "{came:?}");
    assert!(waiting_for(&mut desk.client, "lee", OperatedService::Relay).await.is_empty(), "the key kept still waits");
    let stranger = a_push_at(&relay_url, None).await;
    assert!(refused_by_the_rule(&stranger), "the enrol set no rule: a stranger was admitted: {stranger:?}");
    let mine = desk.runtime.reachability().relay_keys().present_at(&relay_id).expect("the desktop holds the operator's own key");
    assert!(a_push_at(&relay_url, Some(mine)).await.is_ok(), "a tag under the operator's own key was refused");
    assert_eq!(rule_carried(&desk, "lee", "kotton"), None, "the rule is set and the credential still carries it");

    // Said again, and minted again: both refused.
    let again = within("enrol <the relay's line> said again", desk.client.operator_complete("lee", "kotton", &line))
        .await
        .expect_err("the relay's line completes nothing twice");
    assert!(again.to_string().contains("already operates the relay at"), "{again}");
    let again = within("mint relay said again", desk.client.operator_mint("lee", OperatedService::Relay, Some("kotton"), None))
        .await
        .expect_err("a second key for an enrolled relay is refused");
    assert!(again.to_string().contains("you already hold a relay called kotton; name this one (`mint relay <name>`)"), "{again}");
}

/// **With two relay keys waiting, a line completed under the wrong one keeps
/// nothing and spends no mint** (decision 0008).
///
/// Two relays minted, `gate` and `porch`; a relay created for `gate`'s key.
/// Its line asks which, dialling nothing. Answered `porch`, the relay proves
/// the key its line names and refuses `porch`'s at its operator door: nothing
/// is kept, both keys still wait, the relay's rule is untouched, and the
/// readout says it was reached and its key did not match — the refusal saying
/// what was presented there, and that the line can be given again under
/// another key. Answered `gate`, it is kept, `matched` meaning the relay's own
/// key and its operator door both answered, and the mint's rule is set; `porch`
/// still waits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn with_two_relay_keys_waiting_a_line_completed_under_the_wrong_one_keeps_nothing() {
    use kotton_wire::ipc::{LineCame, LineToEnrol, OperatedService, OperatorVerb};

    init_crypto();
    let _base = OwnBaseDir::take();
    let mut desk = within("the operator's desktop", crate::common::relay::env_without()).await;
    within("the operator's identity", desk.client.create_user("lee", crate::common::TEST_PASSPHRASE))
        .await
        .expect("create_user");
    let gate = within("mint relay gate", desk.client.operator_mint("lee", OperatedService::Relay, Some("gate"), None))
        .await
        .expect("the desktop mints gate's key");
    let porch = within("mint relay porch", desk.client.operator_mint("lee", OperatedService::Relay, Some("porch"), None))
        .await
        .expect("the desktop mints porch's key");
    assert_ne!(gate, porch);
    let (_relay, relay_addr) = within("the relay, created for gate's key", crate::common::relay::spawn_with_operator(&gate)).await;
    let relay_url = format!("http://{relay_addr}");
    let relay_id = within("the relay's key", crate::common::relay::key_of(&relay_addr)).await;
    let line = relay_line(&relay_url, &relay_id);
    let both = vec!["gate".to_string(), "porch".to_string()];

    let came = enrol_lines(&mut desk.client, "lee", &[&line]).await;
    assert_eq!(came[0].came_to, LineCame::Which { names: both.clone() }, "{came:?}");
    assert!(!came[0].dialled, "a question dialled the relay: {came:?}");

    // The wrong answer to which.
    let chosen = |mint: &str| vec![LineToEnrol { line: line.clone(), mint: Some(mint.to_string()) }];
    let came = within_for(WHOLE, "enrol, porch chosen", desk.client.operator_enrol_lines("lee", chosen("porch"))).await.expect("answers");
    let (said, why) = refused_line(&came);
    assert_eq!((said.dialled, said.reached, said.matched), (true, Some(true), None), "{said:?}");
    assert!(
        why.contains("proved the key its line names and, asked as its operator under the key minted for the relay 'porch', answered a refusal nothing signed"),
        "{why}"
    );
    assert!(why.contains("nothing is kept, and the key still waits") && why.contains("`enrol` its line again and choose that one"), "{why}");
    for word in ["holds", "forget", "only my devices", "only_my_devices", "anyone"] {
        assert!(!why.contains(word), "the refusal says {word:?}: {why}");
    }
    assert_eq!(waiting_for(&mut desk.client, "lee", OperatedService::Relay).await, both, "the wrong answer spent a mint");
    for name in ["porch", "gate"] {
        match within("relay rule, with nothing kept", desk.client.as_operator("lee", name, OperatorVerb::ReadRule)).await.expect("answers") {
            UserResponse::Error { message } => assert!(message.contains(&format!("holds no operator credential for the relay '{name}'")), "{message}"),
            other => panic!("a credential was kept under '{name}' for a relay that refused porch's key: {other:?}"),
        }
    }
    let stranger = a_push_at(&relay_url, None).await;
    assert!(stranger.is_ok(), "a refused enrol set the relay's rule: {stranger:?}");

    // The right one.
    let came = within_for(WHOLE, "enrol, gate chosen", desk.client.operator_enrol_lines("lee", chosen("gate"))).await.expect("answers");
    assert!(matches!(&came[0].came_to, LineCame::Kept { name, .. } if name == "gate"), "{came:?}");
    assert_eq!((came[0].dialled, came[0].reached, came[0].matched), (true, Some(true), Some(true)), "{came:?}");
    assert_eq!(waiting_for(&mut desk.client, "lee", OperatedService::Relay).await, vec!["porch".to_string()], "gate's key still waits, or porch's was spent");
    let stranger = a_push_at(&relay_url, None).await;
    assert!(refused_by_the_rule(&stranger), "the enrol set no rule: a stranger was admitted: {stranger:?}");
}

/// The rule the relay credential `user`'s desktop keeps under `name` still
/// carries — the one asked for at the mint and not yet taken by the relay —
/// read from the person's sealed store, since no verb reads it without also
/// setting it.
fn rule_carried(env: &crate::common::TestEnv, user: &str, name: &str) -> Option<kotton_wire::rendezvous::AdmissionRule> {
    let store = env.daemon.users().get(user).expect("the person is resident");
    let bytes = kotton_store::runtime::private::read(&store, "operators")
        .expect("their private objects open")
        .expect("they keep an operator credential");
    let texts: Vec<String> = serde_json::from_slice(&bytes).expect("the kept credentials are a list");
    texts
        .iter()
        .map(|t| kotton_peer::operator::OperatorCredential::parse(t).expect("a kept credential reads"))
        .find_map(|c| match c.operates {
            kotton_peer::operator::Operates::Relay { rule, .. } if c.name == name => Some(rule),
            _ => None,
        })
        .expect("a relay's credential by that name")
}

/// **Settings › Networking's landlord verbs reach the vault from the shell's
/// world** (`TASK-networking-is-the-drawn-one`).
///
/// Driven through the occupant host the designated shell calls — the same
/// three verbs *People on this network*, *Invite…* and *Drop…* send — against
/// a real vault at a real relay, with the landlord's desktop holding the vault's
/// operator credential and nothing else. The readout names the vault on the row
/// that is yours, which is what the pane speaks to; an invite sets the space
/// aside and answers with the string to send; the people list reads it back
/// as bytes of bytes; a drop takes the pool away; and a vault this desktop
/// holds no credential for is refused in words, before anything is dialled.
/// Serial, with a base of its own, for `OwnBaseDir`'s reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn the_shell_invites_lists_and_drops_at_a_box_the_person_runs() {
    use kotton_app::daemon::apps::OccupantHost;
    const PRIYA: u64 = 25_000_000_000;

    init_crypto();
    let _base = OwnBaseDir::take();
    let (_relay, relay_addr) = within("starting the relay", crate::common::relay::spawn()).await;
    let relay_url = format!("http://{relay_addr}");
    let vault = within(
        "starting the vault at the relay",
        spawn_vault_at(&relay_addr, "vault"),
    )
    .await;
    let mut door = within("the landlord's door", connect_when_ready(&vault.ipc, "door")).await;
    let (_, vault_key_hex) = within("the vault's identity", door.get_node_identity())
        .await
        .expect("the door says who the vault is");
    let (_key, credential) = within(
        "minting the credential",
        operator_credential(&vault, &vault_key_hex),
    )
    .await;

    let mut env = within("starting the desktop daemon", crate::common::relay::env_without()).await;
    within("the landlord's identity", env.client.create_user("lee", crate::common::TEST_PASSPHRASE))
        .await
        .expect("create_user");
    within("keeping the credential", env.client.operator_enrol("lee", &credential))
        .await
        .expect("the desktop keeps the credential");

    // The row that is yours names the vault the pane speaks to.
    let rows = vaults_in_the_readout(&env.daemon).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(rows[0].yours);
    assert_eq!(rows[0].vault_name.as_deref(), Some("kotton"), "{rows:?}");

    // *Invite…*: who, and how much — the invite, then the number.
    let host = env.daemon.occupant_host();
    let invite = within_for(
        WHOLE,
        "inviting priya from the shell",
        OccupantHost::landlord_invite(&host, "kotton".into(), "priya".into(), PRIYA),
    )
    .await
    .expect("the vault minted an invite");
    assert!(
        invite.starts_with("kotton-invite:vault:") && invite.ends_with(&format!("@{relay_url}")),
        "the invite meets at the host's relay: {invite}"
    );

    // *People on this network*: priya, with the space set aside and no device
    // yet — bytes of bytes, and a count, never a name of anyone's device.
    let people = within_for(WHOLE, "the people, from the shell", OccupantHost::landlord_people(&host, "kotton".into()))
        .await
        .expect("the vault says who it keeps for");
    let priya = people.iter().find(|t| t.name == "priya").unwrap_or_else(|| panic!("{people:?}"));
    assert_eq!(priya.space_bytes, Some(PRIYA), "the invite set priya's space: {people:?}");
    assert_eq!(priya.devices, 0, "nobody has met the invite yet: {people:?}");
    assert_eq!(vault.vault.meter().quota("priya"), Some(PRIYA));

    // *Drop…*: the verb's door asks the person on the platform's own prompt
    // (`DEC-0081`). With no desk to ask on, nothing is dropped — the prompt is
    // the verb's guard, not a courtesy.
    let refused = within_for(WHOLE, "dropping with no desk", OccupantHost::landlord_drop(&host, "kotton".into(), "priya".into()))
        .await
        .expect_err("a drop no one was asked about is refused");
    assert_eq!(refused, kuserd::surface_proxy::NO_DESK);
    assert!(
        tenants_at_the_door(&vault.ipc).await.iter().any(|t| t.user_id == "priya"),
        "priya was dropped with no one asked"
    );
    // A desk where the person types the name back, standing where `kuid` would:
    // on the daemon's end of the pair. It answers every frame as the compositor
    // does and a prompt with the name — read as JSON, never as a `KuidRequest`,
    // for `channel-check`'s one-acceptor rule.
    let (kuid_read, daemon_write) = tokio::io::duplex(64 * 1024);
    let (daemon_read, mut kuid_write) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        use tokio::io::AsyncReadExt as _;
        let mut kuid_read = kuid_read;
        loop {
            let mut len = [0u8; 4];
            if kuid_read.read_exact(&mut len).await.is_err() {
                break;
            }
            let mut body = vec![0u8; u32::from_le_bytes(len) as usize];
            if kuid_read.read_exact(&mut body).await.is_err() {
                break;
            }
            let reply = kotton_wire::FromCompositor::Response(kotton_wire::KuidResponse::SurfaceOk);
            if kotton_ipc::write_frame(&mut kuid_write, &reply).await.is_err() {
                break;
            }
            let frame: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            if let Some(id) = frame["PromptRaise"]["id"].as_u64() {
                assert_eq!(frame["PromptRaise"]["prompt"]["DropTenant"]["pool"], "priya", "{frame}");
                let answer = kotton_wire::CompositorEvent::PromptAnswered { id, typed: Some("priya".into()) };
                if kotton_ipc::write_frame(&mut kuid_write, &kotton_wire::FromCompositor::Event(answer)).await.is_err() {
                    break;
                }
            }
        }
    });
    env.daemon.desk().attach(daemon_write, daemon_read).await;
    within_for(WHOLE, "dropping priya from the shell", OccupantHost::landlord_drop(&host, "kotton".into(), "priya".into()))
        .await
        .expect("the vault dropped priya");
    let after = within_for(WHOLE, "the people, after", OccupantHost::landlord_people(&host, "kotton".into()))
        .await
        .expect("the vault answers");
    assert!(after.iter().all(|t| t.name != "priya"), "priya is still kept: {after:?}");
    assert!(
        tenants_at_the_door(&vault.ipc).await.iter().all(|t| t.user_id != "priya"),
        "the door still lists priya"
    );

    // A vault this desktop holds no credential for: refused, in words.
    let refused = within("asking a vault it does not run", OccupantHost::landlord_people(&host, "attic".into()))
        .await
        .expect_err("a vault with no credential here is refused");
    assert!(refused.contains("holds no operator credential"), "{refused}");
}

/// Drive `vault invite <v> --me`'s ceremony to its end on the operator's
/// desktop, failing the test if a single frame asks for the six digits: the
/// act has none to ask for (DEC-0086). The node admitted, or the reason it
/// was not.
async fn the_operators_own_admit(rx: &mut tokio::sync::mpsc::Receiver<UserResponse>) -> Result<kotton_wire::peer::PairedNode, String> {
    while let Some(frame) = within_for(STEP, "the operator's admit", rx.recv()).await {
        match frame {
            UserResponse::PairShowCode { .. } => panic!("the operator was asked for six digits (DEC-0086)"),
            UserResponse::PairingComplete { node, .. } => return Ok(node),
            UserResponse::PairFailed { reason } => return Err(reason),
            UserResponse::Error { message } => return Err(message),
            _ => {}
        }
    }
    Err("the admit ended with no answer".into())
}

/// **The vault's operator invites themselves in one act** (DEC-0086).
///
/// The desktop holds the vault's operator credential and nothing else of the
/// vault's. `vault invite kotton --me` — the SDK's `vault_invite_me_stream`, which
/// the shell's verb calls — mints an invite over the operator channel for a
/// pool named by the desktop's own user, and admits it on this desktop blind,
/// as `drive enrol … --blind` does. No invite words are typed and no six
/// digits are asked: in their place the vault that answers the admit proved
/// the key the credential pins. The vault then keeps for `lee` with this one
/// device, and a push lands there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn the_boxs_operator_invites_themselves_in_one_act_and_pushes() {
    init_crypto();
    let bx = a_box().await;
    let mut desk = within("the operator's desktop", crate::common::relay::env_on(&bx.relay_addr)).await;
    within("the operator's things", a_person_with_things(&mut desk.client, "lee", NOTE)).await;
    bx.enrol_on(&mut desk.client, "lee").await;

    let rx = within_for(WHOLE, "vault invite kotton --me", desk.client.vault_invite_me_stream("lee", "kotton", 60))
        .await
        .expect("the vault minted an invite for the desktop's own user");
    let kotton::InvitedMe::Admitting(mut rx) = rx else { panic!("the vault keeps for the desktop's own user already") };
    let node = the_operators_own_admit(&mut rx)
        .await
        .unwrap_or_else(|why| panic!("the operator's desktop was not admitted: {why}"));

    let mut door = within("the landlord's door", connect_when_ready(&bx.vault.ipc, "door")).await;
    let (_, vault_key_hex) = within("the vault's identity", door.get_node_identity())
        .await
        .expect("the door says who the vault is");
    assert_eq!(hex::encode(node.public_key), vault_key_hex, "the desktop paired the vault its credential pins");
    let lee = tenants_at_the_door(&bx.vault.ipc)
        .await
        .into_iter()
        .find(|t| t.user_id == "lee")
        .expect("the vault keeps for the desktop's own user");
    assert_eq!(lee.devices, 1, "the desktop is the one device paired there: {lee:?}");

    // The operator and the tenant stay two credentials: the desktop still
    // speaks as the operator, and its tenant key is not one.
    match within_for(WHOLE, "vault people kotton", desk.client.as_operator("lee", "kotton", kotton_wire::ipc::OperatorVerb::Pools))
        .await
        .expect("the desktop's daemon answers")
    {
        UserResponse::VaultTenants { tenants } => assert!(tenants.iter().any(|t| t.user_id == "lee"), "{tenants:?}"),
        other => panic!("the operator lost its standing: {other:?}"),
    }

    // And `sync` pushes.
    desk.client
        .remote_add(
            "lee",
            "vault",
            RemoteBackend::Kotton {
                peer_did: node.device_did.to_string(),
                label: "vault".to_string(),
            },
            None,
        )
        .await
        .expect("remote_add vault");
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        match desk.client.sync_mount("lee", "local", "vault", Some(SyncDirection::Push)).await {
            Ok(r) if r.pushed >= 1 => break,
            Ok(_) | Err(_) if std::time::Instant::now() < deadline => tokio::time::sleep(Duration::from_millis(500)).await,
            Ok(r) => panic!("the operator's desktop pushed nothing: {r:?}"),
            Err(e) => panic!("the operator's desktop could not push to its own vault: {e}"),
        }
    }
    let (held, _) = within("lee's capacity", door.vault_capacity("lee")).await.expect("capacity");
    assert!(held > 0, "the vault holds what the operator's desktop pushed: {held}");
}

/// **A vault whose key is not the one the credential pins is refused, and
/// nothing is handed over** (DEC-0086). The desktop holds the credential for
/// the vault `kotton`; a second vault on the same relay mints an invite of its
/// own, and the desktop admits it as the operator of `kotton` would admit its
/// own. The ceremony runs, the other vault proves its own key, and the admit
/// is refused with a sentence naming both keys — no digits offered as a way
/// round it, no node recorded here, no device paired there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_vault_that_is_not_the_credentials_is_refused_at_the_operators_admit() {
    init_crypto();
    let bx = a_box().await;
    let other = within(
        "another vault at the same relay",
        spawn_vault_at(&bx.relay_addr, "other vault"),
    )
    .await;
    let mut desk = within("the operator's desktop", crate::common::relay::env_on(&bx.relay_addr)).await;
    within("the operator's things", a_person_with_things(&mut desk.client, "lee", NOTE)).await;
    bx.enrol_on(&mut desk.client, "lee").await;

    // The other vault's invite, confirmed on sight at its door.
    let other_door = within("the other vault's door", connect_when_ready(&other.ipc, "other door")).await;
    let mut rx_v = other_door.device_invite_stream("lee", 120, Some("vault")).await.expect("device_invite_stream");
    let invite = match within("the other vault's invite", rx_v.recv()).await {
        Some(UserResponse::PairAdvertising { code, .. }) => code.expose().to_string(),
        other => panic!("the first frame is the invite, got {other:?}"),
    };
    let other_ipc = other.ipc.clone();
    tokio::spawn(async move {
        while let Some(frame) = rx_v.recv().await {
            if let UserResponse::PairShowCode { token, .. } = frame {
                let confirm = connect_when_ready(&other_ipc, "other confirm").await;
                let _ = confirm.pair_confirm_code("lee", token.expose(), true).await;
            }
        }
    });

    let mut rx = within(
        "admitting it as the operator of kotton",
        desk.client.device_admit_as_operator_stream("lee", &invite, 60, "kotton"),
    )
    .await
    .expect("device_admit_as_operator_stream");
    let why = the_operators_own_admit(&mut rx)
        .await
        .expect_err("a vault the credential does not pin was admitted");
    let mut door = within("the other vault's door", connect_when_ready(&other.ipc, "door")).await;
    let (_, other_key) = within("the other vault's identity", door.get_node_identity()).await.expect("identity");
    assert!(why.contains("is not the vault your operator credential for 'kotton' pins"), "{why}");
    assert!(why.contains(&other_key), "the refusal names the key that answered: {why}");
    assert!(why.contains("nothing was handed over"), "{why}");

    let nodes = within("the desktop's paired nodes", desk.client.list_nodes("lee")).await.expect("node list");
    assert!(nodes.is_empty(), "the desktop recorded a vault it refused: {nodes:?}");
    assert!(
        tenants_at_the_door(&other.ipc).await.iter().all(|t| t.user_id != "lee" || t.devices == 0),
        "the other vault paired the desktop"
    );
}

/// **Revoking the credential on the host ends the desktop's standing at once**
/// (`kvaultd operator revoke`). A connection already open under the
/// credential is refused on its very next frame — standing is read per
/// request — and a fresh dial is refused at the handshake, because the key
/// left the allowlist in the same step as its row. The desktop's own daemon
/// is refused too. A TLS session resumed after the revocation is
/// `TASK-a-resumed-tls-session-may-skip-the-allowlist-a-revocation-emptied`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn revoking_the_operator_credential_ends_the_desktops_standing_at_once() {
    use kotton_peer::nat::{nat_connect, NatConfig, NatResult};
    use kotton_peer::{PeerChannel as _, QuicPeerChannel};
    use kotton_wire::ipc::OperatorVerb;

    init_crypto();
    let vault = within("starting the vault", spawn_vault("vault")).await;
    let mut door = within("the landlord's door", connect_when_ready(&vault.ipc, "door")).await;
    let (_, vault_key_hex) = within("the vault's identity", door.get_node_identity())
        .await
        .expect("the door says who the vault is");
    let (operator_key, credential) =
        within("minting the credential", operator_credential(&vault, &vault_key_hex)).await;
    let (_desk, mut landlord) = within("the landlord's desktop", a_desktop("landlord", "lee")).await;
    within("enrolling the credential", landlord.operator_enrol("lee", &credential))
        .await
        .expect("the desktop keeps the credential");
    match within("the pools, from the desktop", landlord.as_operator("lee", "kotton", OperatorVerb::Pools))
        .await
        .expect("the desktop's daemon answers")
    {
        UserResponse::VaultTenants { .. } => {}
        other => panic!("the credential had no standing before its revocation: {other:?}"),
    }

    // A connection under the credential, held open across the revocation.
    let vault_pub: [u8; 32] = hex::decode(&vault_key_hex).unwrap().try_into().unwrap();
    let op_addr: SocketAddr = format!("127.0.0.1:{}", vault.op_port).parse().unwrap();
    let offer = kotton_net::transport::quic::tls::CertOffer {
        admission: vec![],
        claim: None,
    };
    let conn = match within(
        "dialling as the credential",
        nat_connect(&operator_key, &offer, vault_pub, Some(op_addr), &NatConfig::default(), None),
    )
    .await
    {
        NatResult::Direct(c) | NatResult::Punched(c) => c,
        other => panic!("the credential's key is admitted at the handshake: {other:?}"),
    };
    let channel = QuicPeerChannel::new(conn);
    let tenants = serde_json::to_vec(&UserRequest::Tenants).unwrap();
    let ask = |channel: &QuicPeerChannel| {
        let tenants = tenants.clone();
        let channel = channel.clone();
        async move {
            let raw = channel.request(&tenants).await.expect("the vault answers on the open connection");
            serde_json::from_slice::<UserResponse>(&raw).unwrap()
        }
    };
    assert!(
        matches!(within("before", ask(&channel)).await, UserResponse::VaultTenants { .. }),
        "the open connection has the operator's standing"
    );

    within("revoking at the host", revoke_at_the_door(&vault)).await;

    // The next frame on the same connection.
    match within("the next frame", ask(&channel)).await {
        UserResponse::Error { message } => {
            assert!(message.contains("not this vault's operator"), "{message}")
        }
        other => panic!("the revoked credential kept its standing on an open connection: {other:?}"),
    }
    // A fresh dial: the key left the allowlist.
    let fresh = within(
        "a fresh dial as the revoked credential",
        try_ask_the_vault_with(
            &operator_key,
            &offer,
            &VaultIdentity {
                did: String::new(),
                pubkey_hex: vault_key_hex.clone(),
                op_addr,
            },
            tenants.clone(),
        ),
    )
    .await;
    assert!(fresh.is_err(), "a revoked credential completed a handshake: {fresh:?}");
    // And the desktop that holds it is refused.
    match within(
        "the desktop after the revocation",
        landlord.as_operator("lee", "kotton", OperatorVerb::Pools),
    )
    .await
    .expect("the desktop's daemon answers")
    {
        UserResponse::Error { .. } => {}
        other => panic!("the desktop kept its standing after the revocation: {other:?}"),
    }
}

/// **A vault has operators, not an operator**
/// (`TASK-a-device-has-operators-not-an-operator`). Two people each mint their
/// own credential for the same vault and each is enrolled at its door; the
/// second does not replace the first. Each invites a person from their own
/// desktop, and the vault keeps each invite under the key that said it — Lee's
/// under Lee's, Nia's under Nia's; Nia's quota and drop are kept under hers
/// too. Then Lee's credential alone is revoked at
/// the door: Lee's desktop is refused its next act, and Nia's still stands.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn two_operators_each_invite_a_person_and_the_vault_keeps_which_key_did_which() {
    use kotton_wire::ipc::OperatorVerb;

    init_crypto();
    // An invite meets at the vault's relay.
    let (_relay, relay_addr) = within("starting the relay", crate::common::relay::spawn()).await;
    let vault = within(
        "starting the vault at the relay",
        spawn_vault_at(&relay_addr, "vault"),
    )
    .await;
    let mut door = within("the landlord's door", connect_when_ready(&vault.ipc, "door")).await;
    let (_, vault_key_hex) = within("the vault's identity", door.get_node_identity())
        .await
        .expect("the door says who the vault is");
    let (lee_key, lee_credential) = within(
        "minting Lee's credential",
        operator_credential(&vault, &vault_key_hex),
    )
    .await;
    let (nia_key, nia_credential) = within(
        "minting Nia's credential",
        operator_credential(&vault, &vault_key_hex),
    )
    .await;
    let keys = kotton_peer::daemon::db::operator_keys(
        &kotton_device::db::open_machine_db(vault.base_path.join("system").join("agent.db"))
            .await
            .expect("the vault's machine db"),
    )
    .await
    .expect("the operator keys");
    assert_eq!(keys.len(), 3, "enrolling Nia's key kept Lee's, beside the operator the vault was created for");
    for key in [&lee_key, &nia_key] {
        assert!(keys.contains(&key.verifying_key().to_bytes()), "{keys:?}");
    }

    let (_lee_desk, mut lee) = within("Lee's desktop", a_desktop("lee-desk", "lee")).await;
    let (_nia_desk, mut nia) = within("Nia's desktop", a_desktop("nia-desk", "nia")).await;
    within("Lee enrols", lee.operator_enrol("lee", &lee_credential)).await.expect("Lee's desktop keeps it");
    within("Nia enrols", nia.operator_enrol("nia", &nia_credential)).await.expect("Nia's desktop keeps it");

    let invite = |pool: &str| OperatorVerb::Invite {
        pool: pool.into(),
        quota: None,
        ttl_seconds: 120,
    };
    for (who, client, pool) in [("lee", &mut lee, "sam"), ("nia", &mut nia, "ana")] {
        match within("an invite from a desktop", client.as_operator(who, "kotton", invite(pool)))
            .await
            .expect("the desktop's daemon answers")
        {
            UserResponse::PairAdvertising { .. } => {}
            other => panic!("{who}'s desktop minted no invite for {pool}: {other:?}"),
        }
    }

    let acts = vault.vault.operator_acts().await.expect("the vault's record of its operators");
    let invites: Vec<([u8; 32], String)> = acts
        .iter()
        .filter(|a| a.verb == "DeviceInvite" && a.ok)
        .map(|a| (a.public_key, a.pool.clone()))
        .collect();
    assert_eq!(
        invites,
        vec![
            (lee_key.verifying_key().to_bytes(), "sam".to_string()),
            (nia_key.verifying_key().to_bytes(), "ana".to_string()),
        ],
        "each invite is kept under the key that said it: {acts:?}"
    );

    // Nia sets sam's number and then drops that pool; each is kept under her key.
    const SPACE: u64 = 10 * 1024 * 1024;
    for verb in [
        OperatorVerb::SetQuota {
            pool: "sam".into(),
            quota: SPACE,
        },
        OperatorVerb::Drop { pool: "sam".into() },
    ] {
        let answer = within("Nia's act", nia.as_operator("nia", "kotton", verb.clone()))
            .await
            .expect("the desktop's daemon answers");
        assert!(!matches!(answer, UserResponse::Error { .. }), "{verb:?} was refused: {answer:?}");
    }
    let acts = vault.vault.operator_acts().await.expect("the vault's record");
    let nia_pub = nia_key.verifying_key().to_bytes();
    for (verb, pool) in [("SetQuota", "sam"), ("DropTenant", "sam")] {
        assert!(
            acts.iter().any(|a| a.public_key == nia_pub && a.verb == verb && a.pool == pool && a.ok),
            "{verb} of {pool} is kept under Nia's key: {acts:?}"
        );
    }

    // Lee's credential, and only Lee's, revoked at the door.
    within("revoking Lee's credential", revoke_one_at_the_door(&vault, &lee_key)).await;
    match within("Lee after the revocation", lee.as_operator("lee", "kotton", OperatorVerb::Pools))
        .await
        .expect("the desktop's daemon answers")
    {
        UserResponse::Error { .. } => {}
        other => panic!("Lee kept a standing the door revoked: {other:?}"),
    }
    match within("Nia after Lee's revocation", nia.as_operator("nia", "kotton", OperatorVerb::Pools))
        .await
        .expect("the desktop's daemon answers")
    {
        UserResponse::VaultTenants { .. } => {}
        other => panic!("revoking Lee's key took Nia's standing: {other:?}"),
    }
    let after = vault.vault.operator_acts().await.expect("the vault's record");
    assert!(
        after
            .iter()
            .filter(|a| a.public_key == lee_key.verifying_key().to_bytes())
            .all(|a| a.verb == "DeviceInvite"),
        "nothing of Lee's reached a verb after the revocation: {after:?}"
    );
}

/// **A drop from the desktop leaves the desktop its standing**
/// (`TASK-the-landlords-verbs-reach-the-desktop-over-the-wire`). Dropping one
/// pool rebuilds the vault's handshake allowlist from its rows
/// (`reproject_allowlist`), and the operator's key is no tenant's row: it is
/// kept only because the rebuild reads `operator_key` too. So the landlord's
/// desktop drops a tenant over the wire, and then — on a fresh dial, twice:
/// through its own daemon, and by the credential's key directly — lists the
/// pools and is answered, the dropped one gone. A rebuild that forgot the
/// operator would refuse both dials at the handshake.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_desktop_that_drops_a_pool_keeps_its_standing_across_the_rebuild_the_drop_makes() {
    use kotton_wire::ipc::OperatorVerb;

    init_crypto();
    let vault = within("starting the vault", spawn_vault("vault")).await;

    // A tenant, paired with the vault, so the drop has a real row to take
    // out of the allowlist.
    let bob_device = within("starting bob's device", spawn_device("bob")).await;
    let mut bob = within("bob's client", connect_when_ready(&bob_device.ipc, "bob")).await;
    within("bob's identity", bob.create_user("bob", crate::common::TEST_PASSPHRASE))
        .await
        .expect("create_user");
    let (_bob, bob_vault) = within(
        "enrolling bob",
        enrol_vault_from(bob, "bob's laptop", &vault, "bob", "vault"),
    )
    .await;

    let (operator_key, credential) =
        within("minting the credential", operator_credential(&vault, &bob_vault.pubkey_hex)).await;
    let (_desk, mut landlord) = within("the landlord's desktop", a_desktop("landlord", "lee")).await;
    within("enrolling the credential", landlord.operator_enrol("lee", &credential))
        .await
        .expect("the desktop keeps the credential");

    // The landlord drops bob from the desktop.
    match within(
        "dropping bob from the desktop",
        landlord.as_operator("lee", "kotton", OperatorVerb::Drop { pool: "bob".into() }),
    )
    .await
    .expect("the desktop's daemon answers")
    {
        UserResponse::TenantDropped { tenant } => assert_eq!(tenant.user_id, "bob"),
        other => panic!("the desktop dropped no pool: {other:?}"),
    }
    let left: Vec<String> = tenants_at_the_door(&vault.ipc).await.into_iter().map(|t| t.user_id).collect();
    assert!(!left.contains(&"bob".to_string()), "bob was dropped: {left:?}");

    // A fresh dial from the desktop's daemon — `say` dials per verb — is
    // admitted and answered.
    match within("the pools after the drop", landlord.as_operator("lee", "kotton", OperatorVerb::Pools))
        .await
        .expect("the desktop's daemon answers")
    {
        UserResponse::VaultTenants { tenants } => assert!(
            tenants.iter().all(|t| t.user_id != "bob"),
            "the dropped pool is listed: {tenants:?}"
        ),
        other => panic!("the drop's rebuild took the desktop's standing: {other:?}"),
    }
    // And the credential's key, dialling the vault itself on a connection of
    // its own, completes the handshake and is answered as the operator.
    let tenants = serde_json::to_vec(&UserRequest::Tenants).unwrap();
    let no_offer = kotton_net::transport::quic::tls::CertOffer {
        admission: vec![],
        claim: None,
    };
    match within(
        "a fresh dial as the credential after the drop",
        try_ask_the_vault_with(&operator_key, &no_offer, &bob_vault, tenants),
    )
    .await
    {
        Ok(UserResponse::VaultTenants { .. }) => {}
        other => panic!("the drop's rebuild left the operator's key out of the allowlist: {other:?}"),
    }
}

/// What the landlord's door answers for `VaultRequest::Tenants` — what
/// `kvaultd tenants` prints.
pub(crate) async fn tenants_at_the_door(ipc: &IpcEndpoint) -> Vec<kotton_wire::ipc::VaultTenant> {
    let mut door = kotton_ipc::IpcClient::<VaultRequest, UserResponse>::connect(ipc.clone())
        .await
        .expect("the landlord reaches the door");
    match door.send(&VaultRequest::Tenants).await.expect("the door answers") {
        UserResponse::VaultTenants { tenants } => tenants,
        other => panic!("the door did not list its tenants: {other:?}"),
    }
}

/// Every file under a tenant's directory with its bytes, and — on a bucket —
/// every object under their prefix with its bytes: what "untouched" is
/// compared against.
fn holdings(
    base: &std::path::Path,
    user: &str,
    bucket: Option<&crate::common::s3::S3Server>,
) -> std::collections::BTreeMap<String, Vec<u8>> {
    let mut out = std::collections::BTreeMap::new();
    // Everything under `users/<user>/`, walked as a tree from that one
    // directory, so a neighbour whose name starts with `user` is never read.
    let mut pending = vec![base.join("users").join(user)];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                out.insert(path.display().to_string(), std::fs::read(&path).unwrap());
            }
        }
    }
    if let Some(bucket) = bucket {
        for key in bucket.keys() {
            if key.starts_with(&format!("vault-1/{user}/")) {
                out.insert(format!("s3:{key}"), std::fs::read(bucket.bucket_dir().join(&key)).unwrap());
            }
        }
    }
    out
}

/// A landlord drops one of two tenants (`TASK-a-landlord-can-only-drop-every-tenant-at-once`).
/// The survivor is `alicex`, whose name starts with the dropped `alice`'s, so
/// a drop that took a prefix rather than a name — `users/alice*`, a bucket
/// prefix without its trailing `/` — takes the neighbour too, and fails here:
/// the dropped one's pool, chain, sealed recovery copy, pairing and quota go —
/// their device is refused, their phrase recovers nothing here, and the door no
/// longer lists them — and the other's bytes, chain and copy are byte for byte
/// what they were, their pairing still admits them, their number stands, and
/// their phrase still recovers everything.
async fn a_landlord_drops_one_of_two_tenants(
    vault: RunningVault,
    bucket: Option<&crate::common::s3::S3Server>,
) {
    // Two numbers that differ, and room for what a push leaves. A push to a
    // vault packs first (RFC-0070 M3), and each commit is its own fixed-size
    // pack: the note's and the record log's are two, 32 MiB with superblocks
    // on top. These were 32 and 48 MiB while a manual push still sent loose
    // objects (`TASK-a-manual-sync-to-a-vault-sends-loose-objects-without-packing-first`).
    const ALICE: u64 = 64 * 1024 * 1024;
    const ALICEX: u64 = 96 * 1024 * 1024;
    let (_, a) = within("setting alice's quota", set_quota_at_the_door(&vault.ipc, "alice", ALICE)).await;
    let (_, b) = within("setting alicex's quota", set_quota_at_the_door(&vault.ipc, "alicex", ALICEX)).await;
    assert_eq!((a, b), (Some(ALICE), Some(ALICEX)));

    // Two tenants, each on their own device — named apart, because two that
    // share a name unpair each other at a vault today
    // (`TASK-two-tenants-whose-devices-share-a-name-unpair-each-other-at-a-vault`).
    let alice_device = within("starting alice's device", spawn_device("alice")).await;
    let mut alice = within("alice's client", connect_when_ready(&alice_device.ipc, "alice")).await;
    let alice_phrase = within("alice's things", a_person_with_things(&mut alice, "alice", b"alice's note")).await;
    let (mut alice, alice_vault) = within(
        "enrolling alice",
        enrol_vault_from(alice, "alice's laptop", &vault, "alice", "vault"),
    )
    .await;
    let alicex_device = within("starting alicex's device", spawn_device("alicex")).await;
    let mut alicex = within("alicex's client", connect_when_ready(&alicex_device.ipc, "alicex")).await;
    let alicex_phrase = within("alicex's things", a_person_with_things(&mut alicex, "alicex", b"alicex's note")).await;
    let (mut alicex, alicex_vault) = within(
        "enrolling alicex",
        enrol_vault_from(alicex, "alicex's laptop", &vault, "alicex", "vault"),
    )
    .await;
    for (client, user) in [(&mut alice, "alice"), (&mut alicex, "alicex")] {
        let pushed = within(
            "a push",
            client.sync_mount(user, "local", "vault", Some(SyncDirection::Push)),
        )
        .await
        .expect("push");
        assert!(pushed.pushed >= 1, "{user} pushed");
    }

    // What the door lists: two names, three numbers each, no device named.
    let listed = within("listing the tenants", tenants_at_the_door(&vault.ipc)).await;
    let names: Vec<&str> = listed.iter().map(|t| t.user_id.as_str()).collect();
    assert_eq!(names, ["alice", "alicex"]);
    for (t, quota) in listed.iter().zip([ALICE, ALICEX]) {
        assert!(t.held > 0, "{} holds what was pushed", t.user_id);
        assert_eq!(t.quota, Some(quota), "{}'s own number", t.user_id);
        assert_eq!(t.devices, 1, "{} has one device paired", t.user_id);
    }
    let alicex_listed = listed[1].clone();
    let alice_before = holdings(&vault.base_path, "alice", bucket);
    assert!(
        alice_before.keys().any(|k| k.ends_with("kel.json")) && alice_before.keys().any(|k| k.ends_with("recovery.json")),
        "alice's chain and sealed copy are on the vault: {:?}",
        alice_before.keys()
    );
    let alicex_before = holdings(&vault.base_path, "alicex", bucket);
    assert!(alicex_before.keys().any(|k| k.ends_with("kel.json")));
    assert!(alicex_before.keys().any(|k| k.ends_with("recovery.json")));
    if bucket.is_some() {
        assert!(alicex_before.keys().any(|k| k.starts_with("s3:")), "alicex's packs are in the bucket");
        assert!(alice_before.keys().any(|k| k.starts_with("s3:")), "and so are alice's");
    }

    // A phrase-only device of alice's is admitted at the handshake on a
    // recovery claim before the drop — the control for the refusal after it.
    let seed = kotton_crypto::try_mnemonic_to_seed32(&alice_phrase).expect("alice's phrase");
    let claim_offer = |rung: u64, device: &ed25519_dalek::SigningKey| {
        use kotton_net::transport::quic::tls::{CertOffer, RecoveryClaim};
        let reserve = ed25519_dalek::SigningKey::from_bytes(&kotton_crypto::kdf::derive_kel_recovery_key(&seed, rung));
        CertOffer::claim(RecoveryClaim::sign(&reserve, &device.verifying_key().to_bytes()))
    };
    let fetch = serde_json::to_vec(&UserRequest::RecoveryFetch { user_id: "alice".into() }).unwrap();
    let before_key = ed25519_dalek::SigningKey::from_bytes(&[77u8; 32]);
    let mut rung = None;
    for r in 0..4 {
        if let Ok(UserResponse::RecoveryMaterial { .. }) = within(
            "alice's claim before the drop",
            try_ask_the_vault_with(&before_key, &claim_offer(r, &before_key), &alice_vault, fetch.clone()),
        )
        .await
        {
            rung = Some(r);
            break;
        }
    }
    let rung = rung.expect("before the drop, alice's phrase is admitted on a claim and fetches her copy");

    // The landlord drops alice.
    let mut door = kotton_ipc::IpcClient::<VaultRequest, UserResponse>::connect(vault.ipc.clone())
        .await
        .expect("the landlord reaches the door");
    let dropped = match within(
        "dropping alice",
        door.send(&VaultRequest::DropTenant {
            user_id: "alice".into(),
        }),
    )
    .await
    .expect("the door answers")
    {
        UserResponse::TenantDropped { tenant } => tenant,
        other => panic!("the door did not drop alice: {other:?}"),
    };
    assert_eq!(dropped, listed[0], "the answer is alice's readout as it stood");

    // Alice is gone from this vault: listed nowhere, no pool, no directory,
    // no object, no number of her own.
    let after = within("listing after the drop", tenants_at_the_door(&vault.ipc)).await;
    assert_eq!(
        after,
        vec![alicex_listed.clone()],
        "the door lists alicex alone, as they were — a row of alice's that survived would list her"
    );
    assert!(!vault.vault.pools().ids().contains(&"alice".to_string()), "alice's pool is not resident");
    assert_eq!(vault.vault.pools().count(), 1);
    assert_eq!(
        holdings(&vault.base_path, "alice", bucket),
        Default::default(),
        "nothing of alice's is on the disk or the shelf"
    );
    assert_eq!(vault.vault.meter().quota("alice"), None, "alice's number went with her");
    let mut door = within("the door again", connect_when_ready(&vault.ipc, "door")).await;
    let (held, quota) = within("alice's capacity", door.vault_capacity("alice")).await.expect("capacity");
    assert_eq!((held, quota), (0, None), "the vault holds nothing for the name");

    // Her device is refused — at the handshake, its key off the allowlist —
    // and her own push does not land.
    let asked = serde_json::to_vec(&UserRequest::VaultCapacity { user_id: "alice".into() }).unwrap();
    match within("alice's device asks", try_ask_the_vault_as(&alice_device, &alice_vault, asked)).await {
        Err(_) => {}
        Ok(UserResponse::Error { message }) if message.contains("not paired") => {}
        Ok(other) => panic!("alice's device still reaches a pool here: {other:?}"),
    }
    within("alice writes", alice.write_file("alice", "after.txt", b"after the drop"))
        .await
        .expect("write locally");
    let pushed = within_for(
        WHOLE,
        "alice's push after the drop",
        alice.sync_mount("alice", "local", "vault", Some(SyncDirection::Push)),
    )
    .await;
    assert!(
        pushed.as_ref().map_or(true, |r| r.pushed == 0),
        "nothing of alice's lands after the drop: {pushed:?}"
    );

    // Her phrase is a stranger at the handshake itself — the vault forgot her
    // identity's recovery authorities — not a device admitted on a claim and
    // then refused per request. Nothing is left pending for it either.
    let after_key = ed25519_dalek::SigningKey::from_bytes(&[78u8; 32]);
    let refused = within(
        "alice's claim after the drop",
        try_ask_the_vault_with(&after_key, &claim_offer(rung, &after_key), &alice_vault, fetch.clone()),
    )
    .await;
    assert!(
        refused.is_err(),
        "the handshake refuses a claim on a dropped tenant's identity: {refused:?}"
    );
    assert_eq!(
        vault.vault.runtime().admission().admitted(&after_key.verifying_key().to_bytes()),
        None,
        "no admission was granted for the dropped identity"
    );

    // Her phrase recovers nothing here: the chain and the sealed copy are what
    // a phrase-only device is admitted against, and both are gone.
    let cold = within("alice's cold device", spawn_device("alice cold")).await;
    let mut cold_client = within("alice's cold client", connect_when_ready(&cold.ipc, "alice cold")).await;
    within(
        "alice's phrase on a cold device",
        cold_client.login_with_recovery_key(&alice_phrase, Some("alice".to_string()), None),
    )
    .await
    .expect("the phrase claims the identity locally");
    within_for(
        WHOLE,
        "alice's recovery",
        cold_client.recover("alice", &alice_phrase, crate::common::TEST_PASSPHRASE, &alice_vault.line()),
    )
    .await
    .expect_err("a dropped tenant's phrase recovers nothing from this vault");

    // Alicex keeps everything: his chain, his sealed copy and his packs are byte
    // for byte what they were ...
    assert_eq!(
        holdings(&vault.base_path, "alicex", bucket),
        alicex_before,
        "alicex's chain, sealed copy and packs are untouched"
    );
    assert_eq!(vault.vault.meter().quota("alicex"), Some(ALICEX), "alicex's number stands");
    // ... his pairing admits him and his number is his ...
    let own = serde_json::to_vec(&UserRequest::VaultCapacity { user_id: "alicex".into() }).unwrap();
    match within("alicex asks for their own", ask_the_vault_as(&alicex_device, &alicex_vault, own)).await {
        UserResponse::VaultCapacityResult { held, quota } => {
            assert_eq!((held, quota), (alicex_listed.held, Some(ALICEX)))
        }
        other => panic!("alicex's device lost its pool: {other:?}"),
    }
    within("alicex writes", alicex.write_file("alicex", "after.txt", b"alicex after the drop"))
        .await
        .expect("write");
    let pushed = within(
        "alicex's push after the drop",
        alicex.sync_mount("alicex", "local", "vault", Some(SyncDirection::Push)),
    )
    .await
    .expect("alicex still writes");
    assert!(pushed.pushed >= 1);
    // ... and his phrase still recovers everything from here.
    let (_recovered_device, mut recovered) = within_for(WHOLE, "alicex's recovery", recover_from(&alicex_phrase, "alicex", &alicex_vault)).await;
    assert_eq!(
        within("alicex's note", recovered.read_file("alicex", "notes.txt")).await.expect("file").as_slice(),
        b"alicex's note"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_landlord_drops_one_of_two_tenants_and_the_other_keeps_everything() {
    init_crypto();
    let vault = within("starting the vault", spawn_vault("vault")).await;
    a_landlord_drops_one_of_two_tenants(vault, None).await;
}

/// The same drop with the pools on a bucket (RFC-0084 V5), where the objects
/// go only through the shelf: nothing under alice's prefix is left, and every
/// object under alicex's is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_landlord_drops_one_of_two_tenants_on_a_bucket_and_the_other_keeps_everything() {
    init_crypto();
    let bucket = crate::common::s3::serve("kotton").await;
    let vault = within("starting the vault", spawn_vault_on("vault", bucket.shelves(Some("vault-1")))).await;
    a_landlord_drops_one_of_two_tenants(vault, Some(&bucket)).await;
}

/// The number the landlord set survives the vault: set at the door of one
/// vault, close it, start another on the same directory and the same keys,
/// and the door reads the number back — for a pool not yet admitted, as an
/// invite's `--quota` leaves one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pools_quota_survives_a_restart_of_the_vault() {
    init_crypto();
    let base = tempfile::tempdir().expect("vault base");
    let secrets: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    crate::common::create_vault(base.path(), secrets.as_ref()).await;
    let start = |ipc: IpcEndpoint| {
        let base = base.path().to_owned();
        let secrets = Arc::clone(&secrets);
        async move {
            let vault = Arc::new(
                Vault::new_with_shelves(base, ipc.clone(), secrets, kvaultd::shelf::local())
                    .await
                    .expect("vault"),
            );
            let task = tokio::spawn(Arc::clone(&vault).run());
            wait_for_daemon(&ipc, "vault").await;
            (vault, task)
        }
    };

    let ipc = unique_ipc();
    let (first, task) = within("starting the first vault", start(ipc.clone())).await;
    let (_, set) = within("setting alice's quota", set_quota_at_the_door(&ipc, "alice", 4096)).await;
    assert_eq!(set, Some(4096));
    task.abort();
    within("closing the first vault", first.shutdown()).await;
    drop(first);

    let ipc = unique_ipc();
    let (second, _task) = within("starting the second vault", start(ipc.clone())).await;
    let mut door = within("the second vault's door", connect_when_ready(&ipc, "door")).await;
    let (_, quota) = within("alice's capacity after the restart", door.vault_capacity("alice"))
        .await
        .expect("capacity");
    assert_eq!(quota, Some(4096), "the number survived the restart");
    let (_, other) = within("a pool with no number", door.vault_capacity("carol"))
        .await
        .expect("capacity");
    assert_eq!(other, second.meter().default_quota(), "a pool with no number reads the default");
}

/// One vault process keeps for two people (V6). Each pairs it from their own
/// device, each pushes, and each recovers their own from the phrase — and
/// nothing of one is visible in the other's pool.
#[tokio::test]
async fn two_people_keep_at_one_vault_and_each_recovers_their_own() {
    init_crypto();
    let vault = spawn_vault("vault").await;
    let mut phrases = Vec::new();
    let mut identities = Vec::new();
    for (user, note) in [("alice", b"alice's note".as_slice()), ("bob", b"bob's note".as_slice())] {
        let device = spawn_device(user).await;
        let mut client = connect_when_ready(&device.ipc, user).await;
        let phrase = a_person_with_things(&mut client, user, note).await;
        let (mut client, identity) = enrol_vault(client, &vault, user, "vault").await;
        let pushed = client
            .sync_mount(user, "local", "vault", Some(SyncDirection::Push))
            .await
            .expect("push");
        assert!(pushed.pushed >= 1);
        phrases.push(phrase);
        identities.push(identity);
    }
    assert_eq!(vault.vault.pools().count(), 2, "two pools in one process");

    for (i, (user, note)) in [("alice", b"alice's note".as_slice()), ("bob", b"bob's note".as_slice())]
        .into_iter()
        .enumerate()
    {
        let (_cold_device, mut cold) = recover_from(&phrases[i], user, &identities[i]).await;
        assert_eq!(cold.read_file(user, "notes.txt").await.expect("file").as_slice(), note);
    }
}

/// The exit (V7), which is Paper No. 4's gate: a person enrols at one
/// landlord's vault, moves to another's, and the first is destroyed. No device
/// re-pairs, the identity does not change, and the first landlord was never
/// asked. A phrase-only device then recovers everything from the second.
#[tokio::test]
async fn a_person_moves_vaults_and_the_first_landlord_is_never_asked() {
    init_crypto();
    let vault_a = spawn_vault("vault A").await;
    let vault_b = spawn_vault("vault B").await;

    let phrase;
    let identity_b;
    {
        let device = spawn_device("device").await;
        let mut client = connect_when_ready(&device.ipc, "client").await;
        phrase = a_person_with_things(&mut client, "alice", NOTE).await;

        // Life at landlord A.
        let (client, _identity_a) = enrol_vault(client, &vault_a, "alice", "vault-a").await;
        let mut client = client;
        let pushed = client
            .sync_mount("alice", "local", "vault-a", Some(SyncDirection::Push))
            .await
            .expect("push to A");
        assert!(pushed.pushed >= 1);

        // The move: admit B, push, forget A. A is not consulted.
        let (mut client, id_b) = enrol_vault(client, &vault_b, "alice", "vault-b").await;
        identity_b = id_b;
        let pushed = client
            .sync_mount("alice", "local", "vault-b", Some(SyncDirection::Push))
            .await
            .expect("push to B");
        assert!(pushed.pushed >= 1);
        client
            .remote_remove("alice", "vault-a")
            .await
            .expect("forget A as a remote");
        client
            .node_revoke("alice", "vault-a")
            .await
            .expect("drop A from the paired set");
        // The device is lost here too.
    }

    // Landlord A is destroyed: process gone, disk gone.
    let a_path = vault_a.base_path.clone();
    let RunningVault {
        task, _base, vault, ..
    } = vault_a;
    task.abort();
    let _ = task.await;
    vault.shutdown().await;
    drop(vault);
    drop(_base);
    assert!(!a_path.exists(), "nothing of A survives");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let (_cold_device, mut cold) = recover_from(&phrase, "alice", &identity_b).await;
    assert_eq!(cold.read_file("alice", "notes.txt").await.expect("file").as_slice(), NOTE);
    let recs = cold
        .record_query("alice", "com.test.notes", vec![], None, None)
        .await
        .expect("records");
    assert_eq!(recs.len(), 1, "the record came with the file");
    // B kept for one pool, and its door says so.
    let mut door = connect_when_ready(&vault_b.ipc, "door B").await;
    let (held, _) = door.vault_capacity("alice").await.expect("capacity");
    assert!(held > 0);
}

/// **The ceremony carries the vault's peer port.**
/// (`TASK-admitting-a-vault-records-the-wrong-port-for-it`)
///
/// A vault is admitted, and nothing else is said. The address the admitting
/// device records must be the one its `HoldDoors` hand-off will dial — the
/// vault's peer listener — and not the bootstrap socket the ceremony happened
/// to arrive on, which is torn down when the ceremony ends.
///
/// Measured red on 2026-09-12 against the code before this landed: the port
/// recorded was the enrolment listener's, and every harness in the tree hid it
/// by calling `peer_add` with the right address immediately afterwards.
#[tokio::test]
async fn admitting_a_vault_records_the_port_its_peers_dial() {
    init_crypto();
    let vault = spawn_vault("vault").await;
    let device = spawn_device("device E").await;
    let mut client = connect_when_ready(&device.ipc, "client E").await;
    client
        .create_user("alice", crate::common::TEST_PASSPHRASE)
        .await
        .expect("create_user");
    let client_v = connect_when_ready(&vault.ipc, "vault door").await;
    let (mut client, _client_v, node) =
        enroll_streamed(client, client_v, "alice", "vault", Posture::BlindStorage).await;
    assert_eq!(node.id, "vault");

    let nodes = client.list_nodes("alice").await.expect("node list");
    let recorded = nodes
        .iter()
        .find(|n| n.id == "vault")
        .expect("the vault is among this device's paired nodes");
    let addr = *recorded
        .addresses
        .first()
        .expect("the ceremony recorded an address for the vault");
    assert_eq!(
        addr.port(),
        vault.op_port,
        "the admitting device recorded {addr}, not the vault's peer listener on port {}",
        vault.op_port
    );
}

/// **Nothing listens** (`DEC-0068`).
///
/// The vault mints an invite at its door — in the one code grammar: its key,
/// three words, and the relay it reserves at by key and hint — and waits at the
/// relay. The person's device, which has no relay yet, admits the invite: it
/// holds the relay to the invite's key, meets the vault through it, and runs
/// the same ceremony with the words as the PAKE password. **Admitting does not
/// set its relay**: the last frame offers it, and the device stands there only
/// on the yes — here the terminal's, `relay set <line>`
/// (`TASK-an-invite-is-the-codes-other-clause-and-its-relay-is-offered`,
/// Done-when (3)). No
/// bootstrap port is bound on either side, so the vault is recorded with **no
/// address** and its relay, and it is reached afterwards the way it is reached
/// for everything else: through the relay. The push at the end is that reach.
#[tokio::test]
async fn an_invite_admits_a_vault_through_the_relay_with_nothing_listening() {
    init_crypto();
    let (_relay, relay_addr) = crate::common::relay::spawn().await;
    let relay_url = format!("http://{relay_addr}");
    let vault = spawn_vault_at(&relay_addr, "vault").await;
    let device = spawn_device("device E").await;
    let mut client = connect_when_ready(&device.ipc, "client E").await;
    a_person_with_things(&mut client, "alice", NOTE).await;

    // What the relay holds before anyone is paired: the gauge this waits on
    // afterwards, off the relay's own `/metrics`.
    let reservations_before = crate::common::relay::reservations(&relay_addr).await;

    // The landlord mints the invite. Its first frame is the invite itself.
    let door = connect_when_ready(&vault.ipc, "vault door").await;
    let mut rx_v = door
        .device_invite_stream("alice", 120, Some("vault"))
        .await
        .expect("device_invite_stream");
    let invite = match rx_v.recv().await {
        Some(UserResponse::PairAdvertising { code, .. }) => code.expose().to_string(),
        other => panic!("the first frame is the invite, got {other:?}"),
    };
    let relay_id = crate::common::relay::key_of(&relay_addr).await;
    match kotton_wire::line::InviteCode::parse(&invite) {
        Ok(kotton_wire::line::InviteCode::Vault { words, relay_key, relay_hint, .. }) => {
            assert_eq!(relay_hint, relay_url, "the invite names the vault's relay: {invite}");
            assert_eq!(relay_key, relay_id, "by the key it proves: {invite}");
            assert_eq!(words.split('-').count(), 3, "and the words: {invite}");
        }
        other => panic!("the invite is a vault's, in the grammar: {other:?}"),
    }

    // The vault's side: confirm on sight, as `kvaultd invite` does.
    let vault_ipc = vault.ipc.clone();
    let vault_side = tokio::spawn(async move {
        let mut node = None;
        while let Some(frame) = rx_v.recv().await {
            match frame {
                UserResponse::PairShowCode { token, .. } => {
                    let confirm = connect_when_ready(&vault_ipc, "vault confirm").await;
                    confirm.pair_confirm_code("alice", token.expose(), true).await.expect("vault confirm");
                }
                UserResponse::PairingComplete { node: n, .. } => {
                    node = Some(n);
                    break;
                }
                UserResponse::PairFailed { reason } => panic!("the vault's ceremony failed: {reason}"),
                _ => {}
            }
        }
        node.expect("the vault completed the ceremony")
    });

    // The person's device admits the invite. It had no relay, and admitting
    // does not give it one: the last frame offers the vault's.
    let mut rx_d = client
        .device_admit_stream("alice", &invite, 60, Posture::BlindStorage)
        .await
        .expect("device_admit_stream");
    let mut vault_as_recorded = None;
    let mut offered = None;
    while let Some(frame) = rx_d.recv().await {
        match frame {
            UserResponse::PairShowCode { token, .. } => {
                client.pair_confirm_code("alice", token.expose(), true).await.expect("device confirm");
            }
            UserResponse::PairingComplete { node, relay_offer, .. } => {
                vault_as_recorded = Some(node);
                offered = relay_offer;
                break;
            }
            UserResponse::PairFailed { reason } => panic!("the device's ceremony failed: {reason}"),
            _ => {}
        }
    }
    let vault_node = vault_as_recorded.expect("the device completed the ceremony");
    let device_node = vault_side.await.expect("vault task");

    // What each side recorded: the other's proven key, no address for a vault
    // that announced only a port over a relay, and the relay to reach it at.
    assert_eq!(vault_node.id, "vault");
    // The only address a vault can be recorded at is the one its **peer
    // listener** bound, announced inside the channel: under the socket sandbox
    // that listener binds loopback and is announced concretely, so the device
    // has a direct path; on a wide bind it announces an unspecified IP the
    // relayed circuit cannot complete, so nothing is recorded and the relay is
    // the path. Either way no bootstrap socket existed to be recorded — the
    // defect the listening transport had to be taught not to record.
    let op_addr: SocketAddr = format!("127.0.0.1:{}", vault.op_port).parse().unwrap();
    assert!(
        vault_node.addresses.is_empty() || vault_node.addresses == vec![op_addr],
        "the vault is recorded at its peer listener or nowhere, never at an enrolment socket: {:?}",
        vault_node.addresses
    );
    assert_eq!(vault_node.relay_url.as_deref(), Some(relay_url.as_str()));
    assert_eq!(
        device_node.relay_url, None,
        "the device had no relay, took none from the invite, and announced none"
    );
    // Offered, by the relay's line — its key and the address it was met at —
    // and not taken.
    let offered = offered.expect("a device with no relay is offered the vault's");
    assert_eq!(
        offered,
        kotton_wire::line::InstanceLine { kind: kotton_wire::ipc::OperatedService::Relay, hint: relay_url.clone(), key: relay_id }
            .to_text()
    );
    assert_eq!(
        client.node_rendezvous_status().await.expect("relay status").url,
        None,
        "admitting set the device's relay"
    );
    // The yes, as the terminal says it: `relay set <the line>`.
    client.relay_stand("alice", &offered).await.expect("the device stands at the relay it was offered");
    assert_eq!(
        client.node_rendezvous_status().await.expect("relay status").url.as_deref(),
        Some(relay_url.as_str()),
        "the yes stood the device at the relay it was offered"
    );
    let nodes = client.list_nodes("alice").await.expect("node list");
    let recorded = nodes.iter().find(|n| n.id == "vault").expect("the vault is paired");
    assert_eq!(recorded.relay_url.as_deref(), Some(relay_url.as_str()));

    // And the vault is reachable: the person pushes everything through the
    // relay, and the landlord's meter shows bytes. Reachable *once the vault
    // has reserved for the new pair* — its registrar reconciles on a one-second
    // interval, and a dial in the gap gets an honest 404 from the relay, which
    // the listening transport never showed because the direct address answered.
    // The relay's gauge is the instrument for that, so wait on it, not on time.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let now = crate::common::relay::reservations(&relay_addr).await;
        if now >= reservations_before + 4 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the pair never reserved at the relay: {now} held, {reservations_before} before"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let remote_added = client
        .remote_add(
            "alice",
            "vault",
            RemoteBackend::Kotton {
                peer_did: vault_node.device_did.to_string(),
                label: "vault".to_string(),
            },
            None,
        )
        .await;
    if let Err(e) = remote_added {
        let now = crate::common::relay::reservations(&relay_addr).await;
        panic!(
            "remote_add vault through the relay: {e} (relay held {reservations_before} reservations before pairing, {now} now)"
        );
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let pushed = loop {
        match client.sync_mount("alice", "local", "vault", Some(SyncDirection::Push)).await {
            Ok(r) if r.pushed >= 1 => break r,
            Ok(_) | Err(_) if std::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Ok(r) => panic!("pushed nothing through the relay: {r:?}"),
            Err(e) => panic!("could not reach the vault through its relay: {e}"),
        }
    };
    assert!(pushed.pushed >= 1);
    let mut door = connect_when_ready(&vault.ipc, "door").await;
    let (held, _quota) = door.vault_capacity("alice").await.expect("capacity");
    assert!(held > 0, "the vault holds what was pushed through the relay: {held}");
}

/// The vault's side of one relayed admit: mint an invite for `pool` and
/// confirm on sight, as `kvaultd invite <pool>` does. Returns the invite, the
/// task that completes the vault's half, and the digits its `sas=` line prints
/// once the device dials — what the landlord reads to the person.
async fn an_invite_for(
    vault: &RunningVault,
    pool: &str,
) -> (String, tokio::task::JoinHandle<()>, tokio::sync::watch::Receiver<Option<u32>>) {
    let door = connect_when_ready(&vault.ipc, "vault door").await;
    let mut rx_v = door
        .device_invite_stream(pool, 120, Some("vault"))
        .await
        .expect("device_invite_stream");
    let invite = match within("the vault's invite", rx_v.recv()).await {
        Some(UserResponse::PairAdvertising { code, .. }) => code.expose().to_string(),
        other => panic!("the first frame is the invite, got {other:?}"),
    };
    let vault_ipc = vault.ipc.clone();
    let pool = pool.to_string();
    let (print_sas, printed) = tokio::sync::watch::channel(None);
    let vault_side = tokio::spawn(async move {
        while let Some(frame) = rx_v.recv().await {
            match frame {
                UserResponse::PairShowCode { token, sas, .. } => {
                    // The `sas=` line: what the landlord reads to the person.
                    print_sas.send_replace(Some(sas));
                    let confirm = connect_when_ready(&vault_ipc, "vault confirm").await;
                    confirm.pair_confirm_code(&pool, token.expose(), true).await.expect("vault confirm");
                }
                UserResponse::PairingComplete { .. } => return,
                UserResponse::PairFailed { reason } => panic!("the vault's ceremony failed: {reason}"),
                _ => {}
            }
        }
        panic!("the vault's ceremony ended without completing");
    });
    (invite, vault_side, printed)
}

/// The same invite, naming `vault_key` for the vault or `relay_key` for its
/// relay in place of what the vault minted: a forged code, or one cut and
/// pasted from two.
fn the_invite_naming(invite: &str, vault_key: Option<[u8; 32]>, relay_key: Option<[u8; 32]>) -> String {
    use kotton_wire::line::InviteCode;
    match InviteCode::parse(invite).expect("a vault's invite in the grammar") {
        InviteCode::Vault { key, words, relay_key: relay, relay_hint, invited } => InviteCode::Vault {
            key: vault_key.unwrap_or(key),
            words,
            relay_key: relay_key.unwrap_or(relay),
            relay_hint,
            invited,
        }
        .to_text(),
        other => panic!("a vault's invite, not {other:?}"),
    }
}

/// **A code whose vault key is not the key the vault answering proves is
/// refused, and nothing is handed over**
/// (`TASK-an-invite-is-the-codes-other-clause-and-its-relay-is-offered`,
/// Done-when (2) and (5)). The words and the relay are the vault's own, so the
/// ceremony meets it; the vault proves its key inside the channel, and the
/// admitting device — holding the vault to the key the code names — refuses it
/// there, before it says anything about itself. No node is recorded, and the
/// vault pairs nobody.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_code_whose_vault_key_is_not_the_one_answering_is_refused_and_handed_nothing() {
    init_crypto();
    let (_relay, relay_addr) = crate::common::relay::spawn().await;
    let vault = spawn_vault_at(&relay_addr, "vault").await;
    let device = spawn_device("device E").await;
    let mut client = connect_when_ready(&device.ipc, "client E").await;
    a_person_with_things(&mut client, "alice", NOTE).await;

    let (invite, vault_side, shown) = an_invite_for(&vault, "alice").await;
    let named = [7u8; 32];
    let said = the_admit_as(&mut client, "alice", &the_invite_naming(&invite, Some(named), None), Shown::AtTheHost(shown)).await;
    vault_side.abort();
    match said {
        UserResponse::PairFailed { reason } => {
            assert!(reason.contains("is not the vault the invite names"), "{reason}");
            assert!(reason.contains(&hex::encode(named)), "the refusal names the key the code named: {reason}");
            assert!(reason.contains("nothing was handed over"), "{reason}");
        }
        other => panic!("a vault that is not the one the code names was admitted: {other:?}"),
    }
    let nodes = within("the device's paired nodes", client.list_nodes("alice")).await.expect("node list");
    assert!(nodes.is_empty(), "the device recorded a vault it refused: {nodes:?}");
    assert!(
        tenants_at_the_door(&vault.ipc).await.iter().all(|t| t.user_id != "alice" || t.devices == 0),
        "the vault paired the device that refused it"
    );
}

/// **A code whose relay key is not the key the relay at its address proves is
/// refused before the dial** (Done-when (2)). The admitting device asks the
/// relay who it is first, and refuses: nothing is dialled at it, so the vault's
/// one-time reservation is still there — the same invite, as the vault minted
/// it, admits afterwards. A dial would have spent it: a ceremony handle admits
/// exactly one party.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_code_whose_relay_key_is_not_the_relays_is_refused_before_the_dial() {
    init_crypto();
    let (_relay, relay_addr) = crate::common::relay::spawn().await;
    let vault = spawn_vault_at(&relay_addr, "vault").await;
    let device = spawn_device("device E").await;
    let mut client = connect_when_ready(&device.ipc, "client E").await;
    a_person_with_things(&mut client, "alice", NOTE).await;

    let (invite, vault_side, shown) = an_invite_for(&vault, "alice").await;
    let said = the_admit_as(&mut client, "alice", &the_invite_naming(&invite, None, Some([9u8; 32])), Shown::AtTheHost(shown.clone())).await;
    match said {
        UserResponse::PairFailed { reason } => {
            assert!(reason.contains("did not prove the key the invite names"), "{reason}");
            assert!(reason.contains("nothing was handed over"), "{reason}");
        }
        other => panic!("a relay that is not the one the code names was dialled: {other:?}"),
    }
    assert!(
        within("the device's paired nodes", client.list_nodes("alice")).await.expect("node list").is_empty(),
        "the device recorded a vault behind a relay it refused"
    );
    // The invite as minted: the reservation was not spent by the refused admit.
    match the_admit_as(&mut client, "alice", &invite, Shown::AtTheHost(shown)).await {
        UserResponse::PairingComplete { node, .. } => assert_eq!(node.id, "vault"),
        other => panic!("the refused admit spent the vault's reservation: {other:?}"),
    }
    within("the vault's half", vault_side).await.expect("vault task");
}

/// **A relay's invite, minted by its operator and admitted at a friend's
/// door, stands the friend's device at that relay holding the invited key**
/// (`TASK-an-invite-is-the-codes-other-clause-and-its-relay-is-offered`,
/// Done-when (1) and (4)). `relay invite` prints the relay's key, its address
/// and the *invited* key the operator keeps, in the one grammar; under *only my
/// devices* it is refused, since it would admit nobody. Pasted at the friend's
/// door it is `joining.admit`, which holds the relay to the code's key — a
/// forged key is refused and nothing changes — and then stands the device
/// there with the invited key kept and presented, which the relay's rule reads.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_relays_invite_stands_a_friend_there_holding_the_invited_key() {
    use kotton_app::daemon::apps::OccupantHost;
    use kotton_wire::ipc::OperatorVerb;
    use kotton_wire::rendezvous::AdmissionRule;
    init_crypto();
    let bx = a_box().await;
    let mut desk = within("the operator's desktop", crate::common::relay::env_on(&bx.relay_addr)).await;
    within("the operator's things", a_person_with_things(&mut desk.client, "lee", NOTE)).await;
    bx.enrol_on(&mut desk.client, "lee").await;

    // Under *only my devices* an invite would admit nobody, and is refused.
    assert_eq!(
        rule_said(&mut desk.client, "lee", OperatorVerb::SetRule { rule: AdmissionRule::OnlyMyDevices }).await,
        AdmissionRule::OnlyMyDevices
    );
    match within_for(WHOLE, "relay invite kotton", desk.client.as_operator("lee", "kotton", OperatorVerb::RelayInvite)).await {
        Ok(UserResponse::Error { message }) => assert!(message.contains("people_i_invite"), "{message}"),
        other => panic!("an invite to a relay that admits only its operator's devices was minted: {other:?}"),
    }
    assert_eq!(
        rule_said(&mut desk.client, "lee", OperatorVerb::SetRule { rule: AdmissionRule::PeopleIInvite }).await,
        AdmissionRule::PeopleIInvite
    );
    let invite = match within_for(WHOLE, "relay invite kotton", desk.client.as_operator("lee", "kotton", OperatorVerb::RelayInvite))
        .await
        .expect("the desktop's daemon answers")
    {
        UserResponse::RelayInvite { invite } => invite.expose().to_string(),
        other => panic!("no relay invite was minted: {other:?}"),
    };
    let invited = desk.runtime.reachability().relay_keys().offer_for("lee", &bx.relay_id).expect("the operator offers invited");
    assert_eq!(
        kotton_wire::line::InviteCode::parse(&invite).expect("in the grammar"),
        kotton_wire::line::InviteCode::Relay { key: bx.relay_id, hint: bx.relay_url.clone(), invited: invited.to_bytes() },
        "the invite names the relay by its key, its address, and the invited key"
    );
    assert!(refused_by_the_rule(&a_push_at(&bx.relay_url, None).await), "the relay reads a key now");

    // The friend, on no network, pastes it at the door.
    let mut friend = within("the friend's desktop", crate::common::relay::env_without()).await;
    within("the friend's things", a_person_with_things(&mut friend.client, "sam", NOTE)).await;

    // A code naming another key for the relay is refused, and nothing changes.
    let forged = match kotton_wire::line::InviteCode::parse(&invite).unwrap() {
        kotton_wire::line::InviteCode::Relay { hint, invited, .. } => {
            kotton_wire::line::InviteCode::Relay { key: [9u8; 32], hint, invited }.to_text()
        }
        other => panic!("{other:?}"),
    };
    let refused = within("standing at a forged relay", friend.client.relay_stand("sam", &forged))
        .await
        .expect_err("a relay that does not prove the code's key was stood at");
    assert!(refused.to_string().contains("did not prove the key its code names"), "{refused}");
    assert_eq!(friend.runtime.reachability().nat().relay_url, "", "a refused code changed the device's relay");

    let host = friend.daemon.occupant_host();
    within("the friend's door taking the relay's invite", OccupantHost::join_admit(&host, invite.clone()))
        .await
        .expect("the door takes a relay's invite");
    let paired = within_for(WHOLE, "waiting for the relay in the readout", relay_in_the_readout(&friend.daemon))
        .await
        .expect("the relay's invite must leave the network in the list");
    assert_eq!(paired, bx.relay_addr, "{paired}");
    let nat = friend.runtime.reachability().nat();
    assert_eq!(nat.relay_key.as_deref(), Some(hex::encode(bx.relay_id).as_str()), "held to the key the invite named");
    let presented = friend
        .runtime
        .reachability()
        .relay_keys()
        .present_for("sam", &bx.relay_id)
        .expect("the friend holds the invited key at the relay");
    assert_eq!(presented.to_text(), invited.to_text(), "the invited key, and no other");
    assert_eq!(friend.runtime.reachability().present_at_own_relay().map(|k| k.to_text()), Some(invited.to_text()));
    assert!(a_push_at(&bx.relay_url, Some(presented)).await.is_ok(), "the relay's rule reads the key the friend holds");
    within("letting go of the join", OccupantHost::join_cancel(&host)).await.expect("cancel is idempotent");
}

/// Where the six digits a device's admit asks for are shown: to the person who
/// minted the invite, who reads them to the person admitting it. The admit is
/// only as good as this — the digits are the whole of the security — so the
/// helper that drives an admit types what was shown here, and nothing else.
pub(crate) enum Shown<'a> {
    /// The vault's own `sas=` line, at the host that minted the invite
    /// (`kvaultd invite`, [`an_invite_for`], [`vault_mints_an_invite`]).
    AtTheHost(tokio::sync::watch::Receiver<Option<u32>>),
    /// The desktop that minted it over the operator channel (`vault invite
    /// <v> <pool>`), as `user`, under its credential for `vault`.
    AtTheDesktop {
        client: &'a mut kotton::KottonClient,
        user: &'a str,
        vault: &'a str,
        pool: &'a str,
    },
}

impl Shown<'_> {
    /// The six digits, once they are shown — `None` when nothing shows them
    /// within [`STEP`], and then the person admitting has nothing to type.
    async fn read(&mut self) -> Option<u32> {
        match self {
            Shown::AtTheHost(printed) => {
                let shown = tokio::time::timeout(STEP, printed.wait_for(Option::is_some)).await.ok()?.ok()?;
                *shown
            }
            Shown::AtTheDesktop { client, user, vault, pool } => {
                the_digits_the_desktop_shows(client, user, vault, pool).await
            }
        }
    }
}

/// The six digits the desktop shows its person for the ceremony an invite it
/// minted for `pool` is waiting in: `vault digits <v> <pool>`, asked — as the
/// landlord asks it once the person says their device is asking — until it
/// shows one set, or [`STEP`] passes. Two sets would be two invites under one
/// name both dialled, which this test never mints, so it fails on them.
async fn the_digits_the_desktop_shows(
    client: &mut kotton::KottonClient,
    user: &str,
    vault: &str,
    pool: &str,
) -> Option<u32> {
    use kotton_wire::ipc::OperatorVerb;
    let deadline = std::time::Instant::now() + STEP;
    while std::time::Instant::now() < deadline {
        match within("vault digits", client.as_operator(user, vault, OperatorVerb::Digits { pool: pool.to_string() }))
            .await
            .expect("the desktop's daemon answers")
        {
            UserResponse::InviteDigits { digits } => match digits.as_slice() {
                [] => tokio::time::sleep(Duration::from_millis(200)).await,
                [one] => return Some(*one),
                several => panic!("the desktop shows {} sets of digits for one invite: {several:?}", several.len()),
            },
            other => panic!("the desktop did not say the digits: {other:?}"),
        }
    }
    None
}

/// The device's side: `drive enrol <invite> --blind` as `user`, typing the
/// digits `shown` says were shown — the comparison the shell's prompt makes
/// (`client/shell`'s `prompt_code_match`): the typed digits confirm only when
/// they are the ones this device derived. Returns the frame the admit ended
/// on — `PairingComplete` or `PairFailed` — which is what the shell prints.
async fn the_admit_as(client: &mut kotton::KottonClient, user: &str, invite: &str, mut shown: Shown<'_>) -> UserResponse {
    let mut rx_d = client
        .device_admit_stream(user, invite, 60, Posture::BlindStorage)
        .await
        .expect("device_admit_stream");
    while let Some(frame) = within_for(WHOLE, "the device's admit", rx_d.recv()).await {
        match frame {
            UserResponse::PairShowCode { token, sas, .. } => {
                let typed = shown.read().await;
                client.pair_confirm_code(user, token.expose(), typed == Some(sas)).await.expect("device confirm");
            }
            done @ (UserResponse::PairingComplete { .. } | UserResponse::PairFailed { .. }) => return done,
            _ => {}
        }
    }
    panic!("the admit ended with no last frame");
}

/// **A friend invited from the desktop types the six digits the desktop shows.**
/// The landlord mints the invite at their desktop, under the
/// vault's operator credential, as `vault invite <v> <name>` does; the friend
/// says `drive enrol <invite>` at their own `kotton`, a process of its own,
/// and is asked for six digits. Those digits are the whole of the security, so
/// they must have been shown to the landlord, who reads them out: the test
/// takes them from the landlord's desktop and nowhere else, types them at the
/// friend's prompt, and the admit completes with them — the friend is added to
/// the vault and the vault keeps for them.
///
/// The friend's side runs on pipes rather than a terminal
/// ([`crate::common::cli::Cli::spawn_on_pipes`]): the digits do not exist until
/// the ceremony meets the vault, and the prompt reads them as a line from
/// stdin, which a pipe types into exactly as a terminal does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_friend_invited_from_the_desktop_types_the_digits_the_desktop_shows() {
    use kotton_wire::ipc::OperatorVerb;
    use std::io::{Read as _, Write as _};
    init_crypto();
    let bx = a_box().await;
    let mut desk = within("the landlord's desktop", crate::common::relay::env_on(&bx.relay_addr)).await;
    within("the landlord's things", a_person_with_things(&mut desk.client, "lee", NOTE)).await;
    bx.enrol_on(&mut desk.client, "lee").await;

    // `vault invite kotton sam`, at the landlord's desktop.
    let invite = match within_for(
        WHOLE,
        "vault invite kotton sam",
        desk.client.as_operator("lee", "kotton", OperatorVerb::Invite { pool: "sam".into(), quota: None, ttl_seconds: 120 }),
    )
    .await
    .expect("the desktop's daemon answers")
    {
        UserResponse::PairAdvertising { code, .. } => code.expose().to_string(),
        other => panic!("no invite: {other:?}"),
    };

    // The friend, on a desktop of their own and on no network, at its CLI.
    let mut friend = within("the friend's desktop", crate::common::TestEnv::spawn_cli_reachable()).await;
    within("the friend's things", a_person_with_things(&mut friend.client, "sam", NOTE)).await;
    let cli = crate::common::cli::Cli::for_env(&friend);
    cli.seed_session("sam", friend.client.session_token.as_deref().expect("create_user bound a session"));
    let mut admit = cli.spawn_on_pipes(&["drive", "--user", "sam", "enrol", &invite]);
    let said = Arc::new(std::sync::Mutex::new(String::new()));
    let pumps: Vec<_> = [
        Box::new(admit.stdout.take().expect("stdout")) as Box<dyn std::io::Read + Send>,
        Box::new(admit.stderr.take().expect("stderr")),
    ]
    .into_iter()
    .map(|mut out| {
        let said = Arc::clone(&said);
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n @ 1..) = out.read(&mut buf) {
                said.lock().unwrap().push_str(&String::from_utf8_lossy(&buf[..n]));
            }
        })
    })
    .collect();

    // The landlord reads the digits where their desktop shows them, and the
    // friend types what they are read.
    let shown = Shown::AtTheDesktop { client: &mut desk.client, user: "lee", vault: "kotton", pool: "sam" }
        .read()
        .await;
    let mut stdin = admit.stdin.take().expect("stdin");
    writeln!(stdin, "{}", shown.map(|d| format!("{d:06}")).unwrap_or_default()).expect("type at the friend's prompt");
    drop(stdin);
    let exited = within_for(
        WHOLE,
        "the friend's admit to end",
        tokio::task::spawn_blocking(move || admit.wait()),
    )
    .await
    .expect("the wait")
    .expect("the friend's admit exits");
    for pump in pumps {
        pump.join().expect("the output is read");
    }
    let said = said.lock().unwrap().clone();
    assert!(
        shown.is_some(),
        "the friend was asked for six digits the landlord's desktop never showed\n--- the friend's terminal ---\n{said}"
    );
    assert!(exited.success(), "the friend's admit, typing the digits the desktop showed, failed\n--- the friend's terminal ---\n{said}");
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while !tenants_at_the_door(&bx.vault.ipc).await.iter().any(|t| t.user_id == "sam" && t.devices >= 1) {
        assert!(std::time::Instant::now() < deadline, "the vault keeps nobody as sam after the admit\n{said}");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    // The vault keeps the digits only while the ceremony waits, and its watch
    // ends where the ceremony's stream ends, not at a frame it names (#140):
    // so the desktop showing none now is the invite's stream having ended
    // after its result.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        match within("vault digits", desk.client.as_operator("lee", "kotton", OperatorVerb::Digits { pool: "sam".into() }))
            .await
            .expect("the desktop's daemon answers")
        {
            UserResponse::InviteDigits { digits } if digits.is_empty() => break,
            UserResponse::InviteDigits { digits } => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the vault still shows {digits:?} after its ceremony completed: the invite's stream did not end"
                );
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            other => panic!("the desktop did not say the digits: {other:?}"),
        }
    }
}

/// A device whose user is `alice` admits a vault under an invite the landlord
/// minted for `sam` (`TASK-a-vault-invite-names-a-tenant-the-device-does-not-sync-as`).
/// The admit itself says so — naming both, and what to type — rather than the
/// first sync, where the refusal named only the device's key and its user.
/// Then the landlord invites again under `alice`, the device admits that, and
/// it syncs as it always has.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_admit_under_an_invite_for_another_name_says_so_and_a_matching_one_syncs() {
    init_crypto();
    let (_relay, relay_addr) = crate::common::relay::spawn().await;
    let vault = spawn_vault_at(&relay_addr, "vault").await;
    let device = spawn_device("device E").await;
    let mut client = connect_when_ready(&device.ipc, "client E").await;
    a_person_with_things(&mut client, "alice", NOTE).await;

    // The invite names `sam`; the device's user is `alice`.
    let (invite, vault_side, shown) = an_invite_for(&vault, "sam").await;
    let said = the_admit_as(&mut client, "alice", &invite, Shown::AtTheHost(shown)).await;
    within("the vault's half", vault_side).await.expect("vault task");
    match said {
        UserResponse::PairFailed { reason } => {
            assert!(
                reason.contains("tenant `sam`") && reason.contains("as `alice`"),
                "the admit names the pool the vault holds and the name this device asked as: {reason}"
            );
            assert!(
                reason.contains("kvaultd invite alice"),
                "the admit says what to type at the host: {reason}"
            );
            // The vault's rule is read before the vault is recorded, so a
            // refused admit leaves no row beside the failure it reports (#157).
            let nodes = within("the device's paired nodes", client.list_nodes("alice")).await.expect("node list");
            assert!(nodes.is_empty(), "a refused admit recorded the vault: {nodes:?}");
        }
        UserResponse::PairingComplete { node, .. } => {
            // Today's shape: the admit completes, and the first sync is where
            // the vault refuses, naming the key and `alice` and not `sam`.
            client
                .remote_add(
                    "alice",
                    "vault",
                    RemoteBackend::Kotton {
                        peer_did: node.device_did.to_string(),
                        label: "vault".to_string(),
                    },
                    None,
                )
                .await
                .expect("remote_add vault");
            let first = within_for(
                WHOLE,
                "the first sync",
                client.sync_mount("alice", "local", "vault", Some(SyncDirection::Push)),
            )
            .await;
            panic!("the admit completed without naming the mismatch; the first sync said: {first:?}");
        }
        other => panic!("the admit ended on {other:?}"),
    }

    // The landlord invites again under the device's user, as the admit said.
    let (invite, vault_side, shown) = an_invite_for(&vault, "alice").await;
    let said = the_admit_as(&mut client, "alice", &invite, Shown::AtTheHost(shown)).await;
    within("the vault's half", vault_side).await.expect("vault task");
    let node = match said {
        UserResponse::PairingComplete { node, .. } => node,
        other => panic!("a matching admit completes: {other:?}"),
    };
    client
        .remote_add(
            "alice",
            "vault",
            RemoteBackend::Kotton {
                peer_did: node.device_did.to_string(),
                label: "vault".to_string(),
            },
            None,
        )
        .await
        .expect("remote_add vault");
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        match client.sync_mount("alice", "local", "vault", Some(SyncDirection::Push)).await {
            Ok(r) if r.pushed >= 1 => break,
            Ok(_) | Err(_) if std::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Ok(r) => panic!("pushed nothing: {r:?}"),
            Err(e) => panic!("a matching admit syncs: {e}"),
        }
    }
    let mut door = connect_when_ready(&vault.ipc, "door").await;
    let (held, _) = door.vault_capacity("alice").await.expect("capacity");
    assert!(held > 0, "the vault holds alice's bytes: {held}");
}


// ── The desktop completes the key it minted from the line (RFC-0084 V21, V22) ──

/// Who an in-process vault was told to stand at, and the relay keys it holds:
/// `None` when it stands nowhere and holds none.
fn told_to(vault: &RunningVault, relay: &[u8; 32]) -> (String, bool) {
    let nat = vault.vault.runtime().reachability().nat();
    (nat.relay_url, vault.vault.runtime().reachability().relay_keys().present_at(relay).is_some())
}

/// **A stand-in at the line's address receives no reach set**
/// (`TASK-the-desktop-completes-the-key-it-minted-from-the-line-the-service-prints`,
/// Done-when (2); RFC-0084 V21). The desktop holds an instance to the key its
/// line names before it keeps anything: a relay at its proof, a vault at the
/// operator dial pinned to that key. At a relay's address a relay under
/// another key is refused, and nothing is kept. At a vault's address a vault
/// under another key — one that admits this desktop's key, as anyone may make
/// one do, since an operator key is public — is refused, nothing is kept, and
/// it is told nothing: no relay, and not the relay's *mine* key. Then the
/// real vault's line completes the same minted key, and that vault is told
/// where to stand, with the keys — so the stand-in's nothing is the guard's.
///
/// Through `enrol` as the shell sends it, with no name
/// (`TASK-enrol-takes-the-lines-an-instance-printed-and-a-vaults-ends-on-an-offer`,
/// Done-when (6): red when a stand-in's key is taken): each stand-in is said
/// as dialled and its key not matched, and the key minted for its instance
/// still waits after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_stand_in_at_the_address_receives_no_reach_set() {
    use kotton_wire::ipc::{OperatedService, OperatorVerb};

    init_crypto();
    let _base = OwnBaseDir::take();
    let mut desk = within("the operator's desktop", crate::common::relay::env_without()).await;
    within("the operator's identity", desk.client.create_user("lee", crate::common::TEST_PASSPHRASE))
        .await
        .expect("create_user");

    // The relay: a line naming another key at its address completes nothing.
    let relay_public = within("mint relay gate", desk.client.operator_mint("lee", OperatedService::Relay, Some("gate"), None))
        .await
        .expect("the desktop mints the relay's key");
    let (_relay, relay_addr) = within("the relay, created for it", crate::common::relay::spawn_with_operator(&relay_public)).await;
    let relay_url = format!("http://{relay_addr}");
    let relay_id = within("the relay's key", crate::common::relay::key_of(&relay_addr)).await;
    let came = enrol_lines(&mut desk.client, "lee", &[&relay_line(&relay_url, &[0x42; 32])]).await;
    let (line, why) = refused_line(&came);
    assert!(why.contains("not the relay this device knows") && why.contains("nothing is kept"), "{why}");
    assert_eq!((line.dialled, line.reached, line.matched), (true, Some(true), Some(false)), "reached, and its key did not match: {line:?}");
    match within("the relay's rule, with nothing kept", desk.client.as_operator("lee", "gate", OperatorVerb::ReadRule)).await.expect("answers") {
        UserResponse::Error { message } => assert!(message.contains("holds no operator credential for the relay 'gate'"), "{message}"),
        other => panic!("a credential was kept for a stand-in relay: {other:?}"),
    }
    assert_eq!(waiting_for(&mut desk.client, "lee", OperatedService::Relay).await, vec!["gate".to_string()], "the stand-in took the key");
    let came = enrol_lines(&mut desk.client, "lee", &[&relay_line(&relay_url, &relay_id)]).await;
    assert!(matches!(&came[0].came_to, kotton_wire::ipc::LineCame::Kept { name, .. } if name == "gate"), "{came:?}");
    assert_eq!((came[0].reached, came[0].matched), (Some(true), Some(true)));

    // The vault: the line names the real vault's key; a stand-in is at its address.
    let vault_public = within("mint vault kotton", desk.client.operator_mint("lee", OperatedService::Vault, Some("kotton"), None))
        .await
        .expect("the desktop mints the vault's key");
    let vault = within("the vault, created for it", spawn_vault("vault")).await;
    let stand_in = within("a stand-in that admits the same key", spawn_vault("stand-in")).await;
    admit_public_at_the_door(&vault, &vault_public).await;
    admit_public_at_the_door(&stand_in, &vault_public).await;
    let mut door = within("the vault's door", connect_when_ready(&vault.ipc, "door")).await;
    let (_, vault_key_hex) = within("the vault's identity", door.get_node_identity()).await.expect("the door says who the vault is");
    let at_the_stand_in = kotton_wire::line::InstanceLine {
        kind: OperatedService::Vault,
        hint: format!("127.0.0.1:{}", stand_in.op_port),
        key: hex::decode(&vault_key_hex).unwrap().try_into().unwrap(),
    }
    .to_text();
    let came = enrol_lines(&mut desk.client, "lee", &[&at_the_stand_in]).await;
    let (line, said) = refused_line(&came);
    assert!(said.contains("did not answer under the key its line names") && said.contains("nothing was told to it"), "{said}");
    assert!(line.dialled && line.matched != Some(true), "{line:?}");
    assert_eq!(told_to(&stand_in, &relay_id), (String::new(), false), "the stand-in was handed a reach set");
    match within("the vault's people, with nothing kept", desk.client.as_operator("lee", "kotton", OperatorVerb::Pools)).await.expect("answers") {
        UserResponse::Error { message } => assert!(message.contains("holds no operator credential for the vault 'kotton'"), "{message}"),
        other => panic!("a credential was kept for a stand-in vault: {other:?}"),
    }
    assert_eq!(waiting_for(&mut desk.client, "lee", OperatedService::Vault).await, vec!["kotton".to_string()], "the stand-in took the key");

    // The vault's own line: kept, and told where to stand, with the keys.
    let came = enrol_lines(&mut desk.client, "lee", &[&vault_line(&vault, &vault_key_hex)]).await;
    match &came[0].came_to {
        kotton_wire::ipc::LineCame::Kept { name, unstood, .. } => {
            assert_eq!(name, "kotton");
            assert!(unstood.is_none(), "the vault was not told where to stand: {unstood:?}");
        }
        other => panic!("the vault's own line did not complete the key still waiting: {other:?}"),
    }
    assert_eq!(told_to(&vault, &relay_id), (relay_url.clone(), true), "the vault was not told its reach set");
    assert_eq!(told_to(&stand_in, &relay_id), (String::new(), false), "the stand-in was handed a reach set after all");
}

/// **A key already kept completes no second service** (Done-when (3);
/// RFC-0084 V22). One minted key, enrolled at two vaults — the slip V22 is
/// about: the two are joined, to anyone who sees both, as one operator's. The
/// first vault's line completes it. The second's, pasted to `enrol` with no
/// name as the shell sends it, finds no key of its kind waiting; the desktop
/// operates one vault, so the refusal says what this may be — that vault's
/// command run on a second host, one key now operating two instances — and
/// names the remedy: a key of its own for it, enrolled there, and the reused
/// one revoked there, each in the command its guide types. The credential kept
/// is untouched. The same at two relays. Then the remedy, followed: a new key,
/// minted and enrolled at the second vault, completes from that vault's line,
/// with no name — the one key waiting.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_key_already_kept_completes_no_second_service() {
    use kotton_wire::ipc::{LineCame, OperatedService, OperatorVerb};

    init_crypto();
    let _base = OwnBaseDir::take();
    let mut desk = within("the operator's desktop", crate::common::relay::env_without()).await;
    within("the operator's identity", desk.client.create_user("lee", crate::common::TEST_PASSPHRASE))
        .await
        .expect("create_user");

    let public = within("mint vault kotton", desk.client.operator_mint("lee", OperatedService::Vault, Some("kotton"), None))
        .await
        .expect("the desktop mints the vault's key");
    let first = within("the first vault", spawn_vault("first")).await;
    let second = within("the second vault, created for the same key", spawn_vault("second")).await;
    let mut lines = Vec::new();
    for v in [&first, &second] {
        admit_public_at_the_door(v, &public).await;
        let mut door = within("the vault's door", connect_when_ready(&v.ipc, "door")).await;
        let (_, key) = within("the vault's identity", door.get_node_identity()).await.expect("who the vault is");
        lines.push(vault_line(v, &key));
    }
    let came = enrol_lines(&mut desk.client, "lee", &[&lines[0]]).await;
    assert!(matches!(&came[0].came_to, LineCame::Kept { name, .. } if name == "kotton"), "the first vault completes the key: {came:?}");
    let came = enrol_lines(&mut desk.client, "lee", &[&lines[1]]).await;
    let (line, said) = refused_line(&came);
    assert!(!line.dialled, "nothing waits, so nothing is dialled: {line:?}");
    for words in [
        "minted no key waiting for a vault",
        "the command printed for the vault 'kotton' you operate",
        "one key now operates two instances",
        "`mint vault <a new name>`",
        "`kvaultd operator enrol <the new key>`",
        &format!("`kvaultd operator revoke {public}`"),
        "then `enrol <this line>`",
    ] {
        assert!(said.contains(words), "the refusal does not say {words:?}: {said}");
    }
    assert!(
        matches!(
            within_for(WHOLE, "the kept vault's people", desk.client.as_operator("lee", "kotton", OperatorVerb::Pools)).await.expect("answers"),
            UserResponse::VaultTenants { .. }
        ),
        "the credential kept for the first vault was disturbed"
    );

    // The same at two relays.
    let relay_public = within("mint relay gate", desk.client.operator_mint("lee", OperatedService::Relay, Some("gate"), None))
        .await
        .expect("the desktop mints the relay's key");
    let (_r1, r1) = within("the first relay", crate::common::relay::spawn_with_operator(&relay_public)).await;
    let (_r2, r2) = within("the second relay, for the same key", crate::common::relay::spawn_with_operator(&relay_public)).await;
    let r1_line = relay_line(&format!("http://{r1}"), &crate::common::relay::key_of(&r1).await);
    let r2_line = relay_line(&format!("http://{r2}"), &crate::common::relay::key_of(&r2).await);
    let came = enrol_lines(&mut desk.client, "lee", &[&r1_line]).await;
    assert!(matches!(&came[0].came_to, LineCame::Kept { name, .. } if name == "gate"), "the first relay completes the key: {came:?}");
    let came = enrol_lines(&mut desk.client, "lee", &[&r2_line]).await;
    let (_, said) = refused_line(&came);
    assert!(said.contains("the command printed for the relay 'gate' you operate"), "{said}");
    assert!(said.contains(&format!("operator revoke {relay_public}`")) && said.contains("`mint relay <a new name>`"), "{said}");

    // The remedy, followed at the second vault: a key of its own, completed with no name.
    let own = within("mint vault attic", desk.client.operator_mint("lee", OperatedService::Vault, Some("attic"), None))
        .await
        .expect("a new key");
    admit_public_at_the_door(&second, &own).await;
    let came = enrol_lines(&mut desk.client, "lee", &[&lines[1]]).await;
    assert!(matches!(&came[0].came_to, LineCame::Kept { name, .. } if name == "attic"), "the second vault completes under a key of its own: {came:?}");
    // …and the reused key revoked there, at its door (`kvaultd operator revoke <key>`).
    let mut door = kotton_ipc::IpcClient::<VaultRequest, UserResponse>::connect(second.ipc.clone()).await.expect("the second vault's door");
    match door.send(&VaultRequest::OperatorRevoke { key: public.clone() }).await.expect("the door answers") {
        UserResponse::Ok => {}
        other => panic!("the second vault did not revoke the reused key: {other:?}"),
    }
}

/// `line` typed at the REPL, through the registry the REPL dispatches on, with
/// `answers` given in advance to whatever it asks in place.
async fn at_the_repl(repl: &mut kotton_shell::ShellState, line: &str, answers: &[&str]) -> kotton_shell::CommandOutput {
    repl.asking = kotton_shell::Asking::Given(answers.iter().map(|a| a.to_string()).collect());
    let words: Vec<String> = line.split_whitespace().map(str::to_string).collect();
    let executor = kotton_cli::bridge::repl_executor();
    within_for(WHOLE, line, executor.registry().execute(&words[0], &words[1..], repl))
        .await
        .unwrap_or_else(|e| panic!("`{line}`: {e:#}"))
}

/// The value of `field` in each record a command said, in order.
fn said_as(out: &kotton_shell::CommandOutput, field: &str) -> Vec<String> {
    out.out
        .iter()
        .filter_map(|o| match o {
            kotton_shell::out::Out::Record(rows) => rows.iter().find(|(k, _)| k == field).map(|(_, v)| v.clone()),
            _ => None,
        })
        .collect()
}

/// **`enrol` at the REPL completes each vault by the key it was created for,
/// asks which only between two keys of a kind, and asks nothing else: a vault
/// is where things are kept** (`TASK-enrol-takes-the-lines-an-instance-printed-and-a-vaults-ends-on-an-offer`,
/// Done-when (1), (2), (6); #57).
///
/// Two vault keys are minted, `home` and `attic`, and each vault is created
/// for its own. `enrol <attic's line>` takes no name, so with two waiting it
/// asks which. Answered wrong — `home` — the vault at attic's address refuses
/// home's key: red when a line is matched to the wrong mint; nothing is kept
/// and both keys still wait. Answered `attic`, it is kept under the mint's
/// name, said by its three readouts, and nothing more is asked — an answer
/// given beyond *which* is left unread. The enrol goes on to keep `lee`'s
/// things there unasked, and the vault, standing at no relay here, cannot meet
/// the invite: that is said with why and the `vault invite --me` that takes it
/// up, the enrol exits 1 — a vault is where things are kept, and this one
/// keeps nothing yet — and nothing is written: no tenant, no node. (Keeping at a vault that
/// stands at a relay is `headless::a_headless_desktop_operates_…`.) Then
/// `enrol <home's line>` asks nothing at all — one key waits — with nobody to
/// answer, and says the same of home, naming it, since there are two. With two
/// held, `vault people` is refused listing both, and `vault people attic` is
/// answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn enrol_at_the_repl_asks_which_between_two_vault_keys_and_nothing_else() {
    use kotton_wire::ipc::{OperatedService, OperatorVerb};

    init_crypto();
    let _base = OwnBaseDir::take();
    let mut desk = within("the operator's desktop", crate::common::relay::env_without()).await;
    within("the operator's identity", desk.client.create_user("lee", crate::common::TEST_PASSPHRASE))
        .await
        .expect("create_user");
    let token = desk.client.session_token.clone().expect("create_user binds a session");
    let mut client = kotton::KottonClient::connect_to(desk.endpoint.clone()).await.expect("connect");
    client.authenticate(&token).await.expect("authenticate as the REPL's identity");
    let mut repl = kotton_shell::ShellState::new("lee".to_string(), Arc::new(tokio::sync::Mutex::new(client)));

    for name in ["home", "attic"] {
        let minted = at_the_repl(&mut repl, &format!("mint vault {name}"), &[]).await;
        assert!(matches!(minted.exit_code, kotton_shell::ExitCode::Success), "{:?}", minted.out);
    }
    let keys = within("mint", desk.client.operator_mints("lee")).await.expect("the keys waiting");
    let key_of = |name: &str| keys.iter().find(|m| m.name == name).map(|m| m.key.clone()).expect("minted");
    let mut lines = Vec::new();
    for name in ["home", "attic"] {
        let vault = within("a vault, created for its own key", spawn_vault(name)).await;
        admit_public_at_the_door(&vault, &key_of(name)).await;
        let mut door = within("the vault's door", connect_when_ready(&vault.ipc, "door")).await;
        let (_, key) = within("the vault's identity", door.get_node_identity()).await.expect("who the vault is");
        lines.push((vault_line(&vault, &key), vault));
    }
    let (home, attic) = (&lines[0].0, &lines[1].0);

    // Two keys wait for a vault: asked which. The wrong one is refused by the vault.
    let wrong = at_the_repl(&mut repl, &format!("enrol {attic}"), &["home"]).await;
    assert!(!matches!(wrong.exit_code, kotton_shell::ExitCode::Success), "{:?}", wrong.out);
    assert!(said_as(&wrong, "enrolled").is_empty(), "attic's vault was kept under home's key: {:?}", wrong.out);
    assert!(said_as(&wrong, "not enrolled")[0].contains("it was not created for that key"), "{:?}", wrong.out);
    assert_eq!(said_as(&wrong, "reached from here"), vec!["yes".to_string()], "{:?}", wrong.out);
    assert_eq!(said_as(&wrong, "its key"), vec!["did not match".to_string()], "{:?}", wrong.out);
    assert_eq!(waiting_for(&mut desk.client, "lee", OperatedService::Vault).await, vec!["home".to_string(), "attic".to_string()]);
    match within("home's people, nothing kept", desk.client.as_operator("lee", "home", OperatorVerb::Pools)).await.expect("answers") {
        UserResponse::Error { message } => assert!(message.contains("holds no operator credential for the vault 'home'"), "{message}"),
        other => panic!("a credential was kept under the wrong mint: {other:?}"),
    }

    // Answered right: kept under the mint's name, said by its readouts, and nothing else asked.
    let kept = at_the_repl(&mut repl, &format!("enrol {attic}"), &["attic", "n"]).await;
    assert!(
        matches!(kept.exit_code, kotton_shell::ExitCode::Code(1)),
        "a vault's enrol that keeps nothing exited {:?}: {:?}",
        kept.exit_code,
        kept.out
    );
    assert_eq!(
        repl.asking,
        kotton_shell::Asking::Given(["n".to_string()].into()),
        "which was asked once, and nothing after it: {:?}",
        kept.out
    );
    assert!(said_as(&kept, "names")[0].starts_with("a vault at 127.0.0.1:"), "{:?}", kept.out);
    assert_eq!(said_as(&kept, "reached from here"), vec!["yes".to_string()]);
    assert_eq!(said_as(&kept, "its key"), vec!["matched".to_string()]);
    assert!(said_as(&kept, "enrolled")[0].contains("you operate the vault 'attic'"), "{:?}", kept.out);
    match within("attic's people", desk.client.as_operator("lee", "attic", OperatorVerb::Pools)).await.expect("answers") {
        UserResponse::VaultTenants { tenants } => assert!(tenants.is_empty(), "a vault at no relay wrote a tenant: {tenants:?}"),
        other => panic!("attic's credential was not kept: {other:?}"),
    }
    assert!(not_kept(&kept).contains("stands at no relay"), "{:?}", kept.out);
    let nodes = within("the desktop's nodes", desk.client.list_nodes("lee")).await.expect("nodes");
    assert!(nodes.is_empty(), "a keep that could not meet paired the vault: {nodes:?}");
    assert_eq!(waiting_for(&mut desk.client, "lee", OperatedService::Vault).await, vec!["home".to_string()]);

    // One key waits: nothing is asked, with nobody to answer, and the keep at home is said the same, by name.
    let one = at_the_repl(&mut repl, &format!("enrol {home}"), &[]).await;
    assert!(
        matches!(one.exit_code, kotton_shell::ExitCode::Code(1)),
        "a vault's enrol that keeps nothing exited {:?}: {:?}",
        one.exit_code,
        one.out
    );
    assert!(said_as(&one, "enrolled")[0].contains("you operate the vault 'home'"), "{:?}", one.out);
    assert!(not_kept(&one).contains("stands at no relay"), "{:?}", one.out);
    assert!(
        one.out.iter().any(|o| matches!(o, kotton_shell::out::Out::Fail { try_: Some(t), .. } if t == "`vault invite home --me`")),
        "the keep that could not meet does not name home's `vault invite --me`: {:?}",
        one.out
    );
    assert!(waiting_for(&mut desk.client, "lee", OperatedService::Vault).await.is_empty());

    // Two vaults held: a verb that names none is refused in one line listing
    // both and the named form, and is said to neither; one that names one is
    // said to it.
    let nameless = at_the_repl(&mut repl, "vault people", &[]).await;
    assert!(!matches!(nameless.exit_code, kotton_shell::ExitCode::Success), "{:?}", nameless.out);
    match nameless.out.as_slice() {
        [kotton_shell::out::Out::Fail { what, .. }] => {
            assert!(what.contains("attic, home") && what.contains("`vault people <v>`") && !what.contains('\n'), "{what}")
        }
        other => panic!("`vault people` with two vaults held was not refused in one line: {other:?}"),
    }
    let named = at_the_repl(&mut repl, "vault people attic", &[]).await;
    assert!(matches!(named.exit_code, kotton_shell::ExitCode::Success), "{:?}", named.out);
}

/// A relay and a vault each minted at `repl` with no name and created for its
/// key, neither enrolled yet: the relay, its address, its key, the vault, and
/// the two lines `enrol` takes. With `stood`, the vault stands at the relay in
/// process already, outside anything this desktop told it
/// (`common::relay::stand_at`).
async fn a_relay_and_a_vault_not_enrolled(
    desk: &mut crate::common::TestEnv,
    repl: &mut kotton_shell::ShellState,
    stood: bool,
) -> (crate::common::relay::Relay, RunningVault, String, String) {
    for kind in ["relay", "vault"] {
        let minted = at_the_repl(repl, &format!("mint {kind}"), &[]).await;
        assert!(matches!(minted.exit_code, kotton_shell::ExitCode::Success), "mint {kind}: {:?}", minted.out);
    }
    let keys = within("mint", desk.client.operator_mints("lee")).await.expect("the keys waiting");
    let key_of = |name: &str| keys.iter().find(|m| m.name == name).map(|m| m.key.clone()).expect("minted");
    let (relay, relay_addr) = within("the relay", crate::common::relay::spawn_with_operator(&key_of("relay"))).await;
    let relay_id = within("the relay's key", crate::common::relay::key_of(&relay_addr)).await;
    let vault = within("the vault", spawn_vault("vault")).await;
    if stood {
        crate::common::relay::stand_at(&vault.vault, &relay_addr).await;
    }
    admit_public_at_the_door(&vault, &key_of("vault")).await;
    let mut door = within("the vault's door", connect_when_ready(&vault.ipc, "door")).await;
    let (_, vault_key_hex) = within("the vault's identity", door.get_node_identity()).await.expect("who the vault is");
    let (relay_text, vault_text) = (relay_line(&format!("http://{relay_addr}"), &relay_id), vault_line(&vault, &vault_key_hex));
    (relay, vault, relay_text, vault_text)
}

/// **A relay's `enrol` keeps the person's things at the vault that could not
/// keep yet** (#102). A vault enrolled while this desktop operates no relay
/// stands nowhere, so its keep has nowhere to meet: said not kept, exit 1,
/// no tenant written. The relay's line, enrolled after, tells the vault to
/// stand there — its readout names it — and then runs the keep the vault's
/// own enrol runs, `vault invite --me`, unasked (an answer given is left
/// unread), with this device standing at that relay. The vault then holds
/// `lee` as a tenant, is `lee`'s one drive, and the enrol exits 0.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_relays_enrol_keeps_your_things_at_the_vault_that_could_not_keep_yet() {
    init_crypto();
    let _base = OwnBaseDir::take();
    let mut desk = within("the operator's desktop", crate::common::relay::env_without()).await;
    within("the operator's identity", desk.client.create_user("lee", crate::common::TEST_PASSPHRASE))
        .await
        .expect("create_user");
    let mut repl = a_repl(&mut desk, "lee").await;
    let (_relay, vault, relay_text, vault_text) = a_relay_and_a_vault_not_enrolled(&mut desk, &mut repl, false).await;

    // The vault first, with no relay held: kept, and its keep cannot meet.
    let first = at_the_repl(&mut repl, &format!("enrol {vault_text}"), &[]).await;
    assert!(matches!(first.exit_code, kotton_shell::ExitCode::Code(1)), "{:?}: {:?}", first.exit_code, first.out);
    assert!(said_as(&first, "enrolled")[0].contains("you operate the vault"), "{:?}", first.out);
    assert!(not_kept(&first).contains("stands at no relay"), "{:?}", first.out);
    assert!(tenants_at_the_door(&vault.ipc).await.is_empty(), "a vault at no relay wrote a tenant");

    // Then the relay's line: the vault stands there, and the keep is taken up, asking nothing.
    let then = at_the_repl(&mut repl, &format!("enrol {relay_text}"), &["y"]).await;
    assert!(
        matches!(then.exit_code, kotton_shell::ExitCode::Success),
        "the relay's enrol that kept at the vault exited {:?}: {:?}",
        then.exit_code,
        then.out
    );
    assert_eq!(repl.asking, kotton_shell::Asking::Given(["y".to_string()].into()), "the enrol asked something: {:?}", then.out);
    assert!(said_as(&then, "enrolled")[0].contains("you operate the relay"), "{:?}", then.out);
    assert_eq!(said_as(&then, "told to stand here"), vec!["the vault 'vault'".to_string()], "{:?}", then.out);
    assert!(
        !then.out.iter().any(|o| matches!(o, kotton_shell::out::Out::Fail { .. })),
        "the relay's enrol said something failed: {:?}",
        then.out
    );
    assert!(
        then.out.iter().any(
            |o| matches!(o, kotton_shell::out::Out::Confirm { action, .. } if action.starts_with("this device stands at your relay too"))
        ),
        "the keep did not stand this device at the relay: {:?}",
        then.out
    );
    let tenants = tenants_at_the_door(&vault.ipc).await;
    assert!(tenants.iter().any(|t| t.user_id == "lee" && t.devices == 1), "the vault does not hold lee as a tenant: {tenants:?}");
    let (_, drives) = within("a sync asked for", desk.client.sync_drives("lee")).await.expect("the sync asked for");
    assert_eq!(drives, 1, "the vault is not lee's one drive");
}

/// **A vault that keeps the person's things already is not invited again by a
/// relay's `enrol`** (#102). The vault stands at the relay in process, outside
/// anything this desktop told it, so its own enrol's keep meets: `lee` is its
/// tenant, and this desktop's record still says the vault was told nothing.
/// The relay's enrol then tells it to stand there — its readout names it —
/// and the vault answers the keep's invite that it keeps for `lee` already
/// (#108): nothing minted, no ceremony, one device of `lee`'s paired there,
/// the keep said done and not failed, and the enrol exits 0.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_relays_enrol_does_not_invite_again_a_vault_that_keeps_your_things() {
    init_crypto();
    let _base = OwnBaseDir::take();
    let mut desk = within("the operator's desktop", crate::common::relay::env_without()).await;
    within("the operator's identity", desk.client.create_user("lee", crate::common::TEST_PASSPHRASE))
        .await
        .expect("create_user");
    let mut repl = a_repl(&mut desk, "lee").await;
    let (_relay, vault, relay_text, vault_text) = a_relay_and_a_vault_not_enrolled(&mut desk, &mut repl, true).await;

    let first = at_the_repl(&mut repl, &format!("enrol {vault_text}"), &[]).await;
    assert!(matches!(first.exit_code, kotton_shell::ExitCode::Success), "{:?}: {:?}", first.exit_code, first.out);
    let kept = tenants_at_the_door(&vault.ipc).await;
    assert!(kept.iter().any(|t| t.user_id == "lee" && t.devices == 1), "the vault's own enrol did not keep: {kept:?}");

    let then = at_the_repl(&mut repl, &format!("enrol {relay_text}"), &[]).await;
    assert!(matches!(then.exit_code, kotton_shell::ExitCode::Success), "{:?}: {:?}", then.exit_code, then.out);
    assert_eq!(said_as(&then, "told to stand here"), vec!["the vault 'vault'".to_string()], "{:?}", then.out);
    assert!(
        !then.out.iter().any(|o| matches!(o, kotton_shell::out::Out::Fail { .. } | kotton_shell::out::Out::Confirm { .. })),
        "the relay's enrol invited a vault that keeps lee's things already: {:?}",
        then.out
    );
    assert!(said_kept_already(&then, "vault"), "the keep the vault had done was not said: {:?}", then.out);
    assert_eq!(tenants_at_the_door(&vault.ipc).await, kept, "the vault's people changed");
    let nodes = within("the desktop's nodes", desk.client.list_nodes("lee")).await.expect("nodes");
    assert_eq!(nodes.len(), 1, "the vault was paired again: {nodes:?}");
}

/// **Whom a vault keeps for is the vault's to say** (#108). As above, the
/// vault's own enrol keeps `lee` there while this desktop's record says the
/// vault was told nothing; then `lee`'s only device there is withdrawn, under
/// `lee`'s identity, as `device revoke` withdraws one. Its people now list
/// `lee` with no device and no bytes, and the vault still keeps for the name.
/// A guess from the people list called that not kept, and the relay's enrol
/// invited, was refused "already keeps", said a not-kept `Fail` naming a
/// `vault invite --me` refused the same way, and exited 1. The vault's answer
/// is typed now: the keep is said done, nothing fails, nothing is minted, and
/// the enrol exits 0. `vault invite --me` typed after it reads the same word
/// the same way, and `vault invite lee` — an invite for someone new under the
/// kept name — is refused in the vault's words, exit 1.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_relays_enrol_takes_the_vaults_word_that_it_keeps_a_person_with_no_device_there() {
    use ed25519_dalek::Signer as _;
    use kotton_wire::ipc::{TenantDeviceAct, TenantDeviceChange};
    init_crypto();
    let _base = OwnBaseDir::take();
    let mut desk = within("the operator's desktop", crate::common::relay::env_without()).await;
    within("the operator's identity", desk.client.create_user("lee", crate::common::TEST_PASSPHRASE))
        .await
        .expect("create_user");
    let mut repl = a_repl(&mut desk, "lee").await;
    let (_relay, vault, relay_text, vault_text) = a_relay_and_a_vault_not_enrolled(&mut desk, &mut repl, true).await;

    let first = at_the_repl(&mut repl, &format!("enrol {vault_text}"), &[]).await;
    assert!(matches!(first.exit_code, kotton_shell::ExitCode::Success), "{:?}: {:?}", first.exit_code, first.out);
    let kept = tenants_at_the_door(&vault.ipc).await;
    assert!(kept.iter().any(|t| t.user_id == "lee" && t.devices == 1), "the vault's own enrol did not keep: {kept:?}");

    // lee's only device there — this desktop — withdrawn, signed under lee's identity.
    let (desk_did, desk_key_hex) = within("the desktop's identity", desk.client.get_node_identity()).await.expect("who the desktop is");
    let said_at_ms = u64::try_from(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis()).unwrap();
    let change = TenantDeviceChange {
        act: TenantDeviceAct::Withdraw,
        device_did: desk_did,
        public_key: hex::decode(&desk_key_hex).unwrap().try_into().unwrap(),
        said_at_ms,
    };
    let secrets = desk.runtime.secrets();
    let identity = kotton_peer::daemon::nodes::load_signing_key("lee", secrets).expect("lee's identity is held here");
    let signature = identity.sign(&change.signed_bytes("lee")).to_bytes().to_vec();
    let device_key = kotton_peer::daemon::nodes::load_device_operational_key(secrets).expect("the desktop's key");
    let request = serde_json::to_vec(&UserRequest::TenantDevice { user_id: "lee".into(), change, signature }).unwrap();
    let offer = kotton_net::transport::quic::tls::CertOffer { admission: vec![], claim: None };
    let withdrawn = try_ask_the_vault_with(&device_key, &offer, &identity_of(&vault).await, request).await;
    assert!(matches!(withdrawn, Ok(UserResponse::Ok)), "the withdrawal was not taken: {withdrawn:?}");
    let left = tenants_at_the_door(&vault.ipc).await;
    assert!(
        left.iter().any(|t| t.user_id == "lee" && t.devices == 0 && t.held == 0),
        "lee is not listed with no device and no bytes: {left:?}"
    );

    let then = at_the_repl(&mut repl, &format!("enrol {relay_text}"), &[]).await;
    assert!(
        matches!(then.exit_code, kotton_shell::ExitCode::Success),
        "the relay's enrol at a vault that keeps lee exited {:?}: {:?}",
        then.exit_code,
        then.out
    );
    assert_eq!(said_as(&then, "told to stand here"), vec!["the vault 'vault'".to_string()], "{:?}", then.out);
    assert!(
        !then.out.iter().any(|o| matches!(o, kotton_shell::out::Out::Fail { .. })),
        "the relay's enrol said something failed: {:?}",
        then.out
    );
    assert!(said_kept_already(&then, "vault"), "the keep the vault had done was not said: {:?}", then.out);
    assert_eq!(tenants_at_the_door(&vault.ipc).await, left, "the vault's people changed");

    // `vault invite --me` typed by hand reads the same word as done: said,
    // nothing failed, exit 0, nothing minted.
    let me = at_the_repl(&mut repl, "vault invite --me", &[]).await;
    assert!(
        matches!(me.exit_code, kotton_shell::ExitCode::Success),
        "`vault invite --me` at a vault that keeps lee exited {:?}: {:?}",
        me.exit_code,
        me.out
    );
    assert!(!me.out.iter().any(|o| matches!(o, kotton_shell::out::Out::Fail { .. })), "{:?}", me.out);
    assert!(said_kept_already(&me, "vault"), "`vault invite --me` did not say the keep done: {:?}", me.out);
    assert_eq!(tenants_at_the_door(&vault.ipc).await, left, "the vault's people changed");

    // An invite for someone new under the kept name is the refusal it is:
    // one failure, in the vault's words, exit 1, nothing minted.
    let named = at_the_repl(&mut repl, "vault invite lee", &[]).await;
    assert!(matches!(named.exit_code, kotton_shell::ExitCode::Code(1)), "{:?}: {:?}", named.exit_code, named.out);
    let why = failed_with(&named);
    assert!(
        why.starts_with("vault: this vault already keeps for 'lee' — an invite admits someone new"),
        "`vault invite lee` was not refused as kept: {why}"
    );
    assert_eq!(tenants_at_the_door(&vault.ipc).await, left, "the vault's people changed");
}

/// Whether an `enrol` said that the vault `vault` keeps this person's things
/// already (#108).
fn said_kept_already(out: &kotton_shell::CommandOutput, vault: &str) -> bool {
    let said = format!("your things are kept at the vault '{vault}' already");
    out.out.iter().any(|o| matches!(o, kotton_shell::out::Out::Note(n) if n.starts_with(&said)))
}

/// What an `enrol` said of a vault that does not keep this person's things,
/// panicking when it said nothing of the kind.
fn not_kept(out: &kotton_shell::CommandOutput) -> String {
    out.out
        .iter()
        .find_map(|o| match o {
            kotton_shell::out::Out::Fail { what, .. } => what.strip_prefix("your things are not kept at the vault: ").map(str::to_string),
            _ => None,
        })
        .unwrap_or_else(|| panic!("the enrol did not say the vault keeps nothing: {:?}", out.out))
}

/// The one line a command failed with, panicking when it did not fail in one.
fn failed_with(out: &kotton_shell::CommandOutput) -> String {
    assert!(!matches!(out.exit_code, kotton_shell::ExitCode::Success), "it did not fail: {:?}", out.out);
    match out.out.as_slice() {
        [kotton_shell::out::Out::Fail { what, .. }] => what.clone(),
        other => panic!("not one failure: {other:?}"),
    }
}

/// A REPL acting as `user` on `desk`, as `enrol_at_the_repl_asks_which_…` builds one.
async fn a_repl(desk: &mut crate::common::TestEnv, user: &str) -> kotton_shell::ShellState {
    let token = desk.client.session_token.clone().expect("create_user binds a session");
    let mut client = kotton::KottonClient::connect_to(desk.endpoint.clone()).await.expect("connect");
    client.authenticate(&token).await.expect("authenticate as the REPL's identity");
    kotton_shell::ShellState::new(user.to_string(), Arc::new(tokio::sync::Mutex::new(client)))
}

/// `mint relay` and `mint vault` at `repl`, nameless, then a relay and a vault
/// each created for its key, and `enrol` with both lines: the relay, its key,
/// the vault and its key, as a person who runs one of each stands after
/// `docs/use/run-a-vault.md`.
async fn a_host_enrolled(
    desk: &mut crate::common::TestEnv,
    repl: &mut kotton_shell::ShellState,
) -> (crate::common::relay::Relay, [u8; 32], RunningVault, String, String) {
    use kotton_wire::ipc::LineCame;
    for kind in ["relay", "vault"] {
        let minted = at_the_repl(repl, &format!("mint {kind}"), &[]).await;
        assert!(matches!(minted.exit_code, kotton_shell::ExitCode::Success), "mint {kind}: {:?}", minted.out);
    }
    let keys = within("mint", desk.client.operator_mints("lee")).await.expect("the keys waiting");
    let key_of = |name: &str| keys.iter().find(|m| m.name == name).map(|m| m.key.clone()).expect("minted");
    let (relay_public, vault_public) = (key_of("relay"), key_of("vault"));
    let (relay, relay_addr) = within("the relay", crate::common::relay::spawn_with_operator(&relay_public)).await;
    let relay_id = within("the relay's key", crate::common::relay::key_of(&relay_addr)).await;
    let vault = within("the vault", spawn_vault("vault")).await;
    admit_public_at_the_door(&vault, &vault_public).await;
    let mut door = within("the vault's door", connect_when_ready(&vault.ipc, "door")).await;
    let (_, vault_key_hex) = within("the vault's identity", door.get_node_identity()).await.expect("who the vault is");
    let came = enrol_lines(
        &mut desk.client,
        "lee",
        &[&relay_line(&format!("http://{relay_addr}"), &relay_id), &vault_line(&vault, &vault_key_hex)],
    )
    .await;
    for c in &came {
        assert!(matches!(&c.came_to, LineCame::Kept { unstood: None, .. }), "each line is kept, the vault standing at the relay: {came:?}");
    }
    (relay, relay_id, vault, relay_public, vault_public)
}

/// **A credential whose instance is gone is forgotten, and its name minted
/// again** (#82). A person runs one relay and one vault, minted with no name
/// and enrolled; the host is started over — both instances destroyed. Minting
/// under the kept name is refused while the credential is kept. `vault forget`
/// and `relay forget`, nameless with one of each held, dial each instance,
/// which does not answer, and forget it: the held set is empty, and the relay's
/// keys are no longer held in the keyring as its operator's. `mint relay` and
/// `mint vault` then succeed under the same names, and a new host's relay and
/// vault enrol as the first did — the vault standing at the one relay held,
/// never asked to choose between a dead relay and the new one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn an_instance_destroyed_is_forgotten_and_its_name_minted_again() {
    use kotton_wire::ipc::OperatedService;

    init_crypto();
    let _base = OwnBaseDir::take();
    let mut desk = within("the operator's desktop", crate::common::relay::env_without()).await;
    within("the operator's identity", desk.client.create_user("lee", crate::common::TEST_PASSPHRASE))
        .await
        .expect("create_user");
    let mut repl = a_repl(&mut desk, "lee").await;
    let (relay, relay_id, vault, _, _) = a_host_enrolled(&mut desk, &mut repl).await;
    let keys = desk.runtime.reachability().relay_keys();
    assert!(keys.present_at(&relay_id).is_some(), "the relay's keys are held as its operator's");

    // The host is started over: the relay's process and the vault's, and their state.
    drop(relay);
    let RunningVault { task, _base: vault_base, vault, .. } = vault;
    task.abort();
    let _ = task.await;
    vault.shutdown().await;
    drop(vault);
    drop(vault_base);

    let refused = within("mint vault, kept", desk.client.operator_mint("lee", OperatedService::Vault, None, None))
        .await
        .expect_err("a second key under a name kept");
    assert!(refused.to_string().contains("you already hold a vault called vault"), "{refused}");

    for kind in ["vault", "relay"] {
        let forgot = at_the_repl(&mut repl, &format!("{kind} forget"), &[]).await;
        assert!(matches!(forgot.exit_code, kotton_shell::ExitCode::Success), "{kind} forget: {:?}", forgot.out);
        let answered = said_as(&forgot, "answered");
        assert!(answered.len() == 1 && answered[0].starts_with("no"), "{kind} forget: {:?}", forgot.out);
    }
    for service in [OperatedService::Vault, OperatedService::Relay] {
        let held = within("the instances held", desk.client.operator_held("lee", service)).await.expect("held");
        assert!(held.is_empty(), "a forgotten {} is still held: {held:?}", service.word());
    }
    assert!(keys.present_at(&relay_id).is_none(), "the forgotten relay's keys are still presented");
    assert!(keys.at("lee", &relay_id).operated_at.is_none(), "the forgotten relay's address is still read as own");

    // The same names, minted again, and a new host enrolled as the first was.
    let (_relay, _, _vault, _, _) = a_host_enrolled(&mut desk, &mut repl).await;
}

/// **An instance that still stands the key is not forgotten** (#82). With a
/// relay and a vault running and enrolled, `vault forget` and `relay forget`
/// are refused, saying it is still running and the revoke there with the key in
/// it, and nothing is forgotten. Once the vault revokes the key at its own
/// terminal, `vault forget` forgets it, saying the vault answered — read from
/// the vault refusing the key at its handshake — and once the relay revokes it
/// at its terminal, `relay forget` does too, saying the relay did not answer
/// and printing the revoke: its *not an operator of this relay* is an unsigned
/// 403 that a proxy in front of it could give as well.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn an_instance_still_running_under_its_key_is_not_forgotten() {
    use kotton_wire::ipc::OperatedService;

    init_crypto();
    let _base = OwnBaseDir::take();
    let mut desk = within("the operator's desktop", crate::common::relay::env_without()).await;
    within("the operator's identity", desk.client.create_user("lee", crate::common::TEST_PASSPHRASE))
        .await
        .expect("create_user");
    let mut repl = a_repl(&mut desk, "lee").await;
    let (relay, _, vault, relay_public, vault_public) = a_host_enrolled(&mut desk, &mut repl).await;

    let refused = failed_with(&at_the_repl(&mut repl, "vault forget", &[]).await);
    for words in ["still running", "destroy it first", &format!("`kvaultd operator revoke {vault_public}`")] {
        assert!(refused.contains(words), "the refusal does not say {words:?}: {refused}");
    }
    let refused = failed_with(&at_the_repl(&mut repl, "relay forget", &[]).await);
    for words in ["still running", &format!("operator revoke {relay_public}`")] {
        assert!(refused.contains(words), "the refusal does not say {words:?}: {refused}");
    }
    for service in [OperatedService::Vault, OperatedService::Relay] {
        let held = within("the instances held", desk.client.operator_held("lee", service)).await.expect("held");
        assert_eq!(held, vec![service.word().to_string()], "a refused forget forgot the {}", service.word());
    }

    // Revoked at the vault's terminal: the vault answers, and no longer stands the key.
    let mut door = kotton_ipc::IpcClient::<VaultRequest, UserResponse>::connect(vault.ipc.clone()).await.expect("the vault's door");
    match door.send(&VaultRequest::OperatorRevoke { key: vault_public.clone() }).await.expect("the door answers") {
        UserResponse::Ok => {}
        other => panic!("the vault did not revoke the key: {other:?}"),
    }
    let forgot = at_the_repl(&mut repl, "vault forget", &[]).await;
    assert!(matches!(forgot.exit_code, kotton_shell::ExitCode::Success), "{:?}", forgot.out);
    let answered = said_as(&forgot, "answered");
    assert!(answered.len() == 1 && answered[0].starts_with("yes"), "{:?}", forgot.out);
    let held = within("the vaults held", desk.client.operator_held("lee", OperatedService::Vault)).await.expect("held");
    assert!(held.is_empty(), "{held:?}");

    // Revoked at the relay's terminal: it proves its key, and its operator door
    // refuses this one with a 403 — an unsigned answer a proxy could give as
    // well, so the relay is never said to have answered, and the revoke is said.
    relay.operator_revoke(&relay_public);
    let forgot = at_the_repl(&mut repl, "relay forget", &[]).await;
    assert!(matches!(forgot.exit_code, kotton_shell::ExitCode::Success), "{:?}", forgot.out);
    let answered = said_as(&forgot, "answered");
    assert!(
        answered.len() == 1 && answered[0].starts_with("no") && answered[0].contains(&format!("operator revoke {relay_public}`")),
        "{:?}",
        forgot.out
    );
    let held = within("the relays held", desk.client.operator_held("lee", OperatedService::Relay)).await.expect("held");
    assert!(held.is_empty(), "{held:?}");
}

// ── Settings › Networking: the three doors, driven from the shell's world ──────

/// A `KOTTON_BASE_DIR` of this test's own, restored on drop.
///
/// The occupant host resolves *which person this device is for* through
/// `device_users::load(self.base)`, which now reads `device/users.json`
/// relative to the daemon's own base rather than the process-global
/// `kotton_common::base_dir()`
/// (`TASK-the-device-user-registry-is-read-from-a-process-global-base`, closed).
/// This isolation predates that fix — a suite where every daemon shared one
/// process-global file accumulated every user every test ever created, so
/// `the_only_user()` answered `SeveralIdentities` and no occupant verb worked
/// at all — and is kept because `DeviceDaemon::new()` and anything a test
/// spawns as a subprocess still resolve `KOTTON_BASE_DIR` the old way; `#[serial]`
/// is what the mock-runner tests isolate theirs with too.
struct OwnBaseDir {
    _dir: tempfile::TempDir,
    previous: Option<std::ffi::OsString>,
}

impl OwnBaseDir {
    fn take() -> Self {
        let dir = tempfile::tempdir().expect("a base dir of this test's own");
        let previous = std::env::var_os("KOTTON_BASE_DIR");
        std::env::set_var("KOTTON_BASE_DIR", dir.path());
        Self { _dir: dir, previous }
    }
}

impl Drop for OwnBaseDir {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(v) => std::env::set_var("KOTTON_BASE_DIR", v),
            None => std::env::remove_var("KOTTON_BASE_DIR"),
        }
    }
}

/// Wait for the shell's readout to say a relay is paired, and return its name.
///
/// Polled, and **only in the test**: the flows push their steps at
/// `on-message`, and what a person's screen does with them is the shell's
/// business. What a test can do is ask the readout the same question the pane
/// asks on its next render, which is exactly the clause under measurement —
/// *the new network is in the list by name*.
///
/// Each read is inside `within`, for the reason `confirm_when_the_digits_arrive`
/// gives: the iteration cap does not bound one read that never returns.
pub(crate) async fn relay_in_the_readout(daemon: &Arc<kuserd::DeviceDaemon>) -> Option<String> {
    use kotton_app::daemon::apps::OccupantHost;
    for _ in 0..100 {
        let host = daemon.occupant_host();
        if let Ok(Some(relay)) =
            within("reading the relay while waiting for it", OccupantHost::paired_relay(&host)).await
        {
            return Some(relay.name);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}

/// Wait for the shell's readout to list a vault, and return every row it lists.
///
/// Polled for the reason [`relay_in_the_readout`] is, and bounded twice as it
/// is. The rows come back whole once one is there, so the caller asserts the
/// set rather than the first thing that turned up.
///
/// **What this reads is `network::enrolled_vaults`** — the verb the pane calls
/// — and nothing under it: not the node roster and not the membership set. A
/// vault that is paired and recorded and missing from this list is the defect
/// `TASK-an-admitted-vault-is-not-in-the-remote-set-so-the-readout-shows-no-vault`
/// was filed for, and this is where it would show.
async fn vaults_in_the_readout(
    daemon: &Arc<kuserd::DeviceDaemon>,
) -> Vec<kotton_wire::runner::RunnerVault> {
    use kotton_app::daemon::apps::OccupantHost;
    let mut last = Vec::new();
    for _ in 0..100 {
        let host = daemon.occupant_host();
        last = within("reading the enrolled vaults", OccupantHost::enrolled_vaults(&host))
            .await
            .expect("the readout answers");
        if !last.is_empty() {
            return last;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    last
}

/// The one row an admitted vault must read as: named by the word it was
/// enrolled under, and met through the relay the invite named.
fn assert_the_vault_is_listed(vaults: &[kotton_wire::runner::RunnerVault], relay_addr: &str) {
    assert_eq!(
        vaults.len(),
        1,
        "one vault was admitted, so the readout lists exactly one: {vaults:?}"
    );
    assert_eq!(
        vaults[0].label.as_deref(),
        Some("vault"),
        "the row is named by the word the vault was enrolled under: {vaults:?}"
    );
    assert_eq!(
        vaults[0].through.as_deref(),
        Some(relay_addr),
        "the row names the relay the vault was met through: {vaults:?}"
    );
}

/// Type the six digits the vault printed, as soon as there are six digits to
/// answer.
///
/// `join_confirm` refuses while nothing is waiting on a comparison, so this
/// **is** the assertion that the ceremony reached the compare step: the first
/// call is expected to be refused in those words, and the loop succeeds only
/// once a `PairShowCode` frame has arrived and the daemon has taken its token.
/// Nothing else in this process can make it succeed.
///
/// **What is typed is the vault's SAS, read off the vault's side** — its
/// `sas=` line, which is what a person reads — grouped the way a person types
/// it. The desktop is the issuer and is never shown the digits (RFC-0076), so
/// there is nowhere else they could come from: a join that completes here is
/// one whose typed digits the daemon compared and found equal
/// (`TASK-the-desktop-asks-whether-the-six-digits-match-where-the-person-must-type-them`).
///
/// Two bounds, because a loop's iteration cap bounds how many times it asks
/// and not how long one ask takes: each call is inside `within` as well.
async fn confirm_when_the_digits_arrive(
    daemon: &Arc<kuserd::DeviceDaemon>,
    printed: &tokio::sync::watch::Receiver<Option<u32>>,
) -> bool {
    use kotton_app::daemon::apps::OccupantHost;
    for _ in 0..600 {
        // Copied out before any await: a `watch` borrow is a read lock.
        let seen = *printed.borrow();
        let Some(sas) = seen else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let typed = format!("{:03} {:03}", sas / 1000, sas % 1000);
        let host = daemon.occupant_host();
        match within("typing the digits", OccupantHost::join_confirm(&host, typed)).await {
            Ok(()) => return true,
            Err(why) => assert!(
                why.contains("no digits to compare"),
                "the only reason to refuse a comparison before the digits is that there are \
                 none, got: {why}"
            ),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

/// How long any one step of these three tests may take before it counts as
/// wedged.
///
/// **Every await in them is bounded, and that is a rule rather than a
/// precaution.** A test that hangs reports *nothing at all* — no panic, no
/// name, no line — and a suite with one in it is a gate nobody can read. These
/// three drive two daemons, a vault, a relay process and a ceremony from one
/// test, so a step that stops is the failure mode to expect; what matters is
/// that it says which step. A bound here fires only while the runtime's timer
/// is being driven, which is the other half of why the tests are
/// multi-threaded.
const STEP: Duration = Duration::from_secs(45);

/// Await `what`, or fail naming it.
///
/// Used on every await in the three joining tests. `STEP` is generous for work
/// that takes milliseconds when it works, so a red here is a wedge and never a
/// slow machine.
async fn within<F: std::future::Future>(what: &str, f: F) -> F::Output {
    within_for(STEP, what, f).await
}

/// How long one of the composite waits — the digits, the readout, the vault's
/// invite — may take as a whole. Each is bounded inside as well; this bounds
/// it at the call site, so *every await is bounded* is checked by reading the
/// test and not by reading the helper.
const WHOLE: Duration = Duration::from_secs(120);

/// Await `what` for at most `limit`, or fail naming it.
async fn within_for<F: std::future::Future>(limit: Duration, what: &str, f: F) -> F::Output {
    match tokio::time::timeout(limit, f).await {
        Ok(v) => v,
        Err(_) => panic!("{what} did not finish within {}s — it is wedged", limit.as_secs()),
    }
}

/// Wait for a ceremony half to finish, or fail naming whose it was.
async fn finished(task: tokio::task::JoinHandle<()>, whose: &str) {
    match tokio::time::timeout(STEP, task).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => panic!("{whose} of the ceremony panicked: {e}"),
        Err(_) => panic!("{whose} of the ceremony never finished within {}s", STEP.as_secs()),
    }
}

/// How long an invite stays good for in these tests.
///
/// Short on purpose. A generous TTL does not make a ceremony more likely to
/// succeed; it makes a ceremony that is never going to succeed sit on the relay
/// until the harness gives up, which is the difference between a red with a
/// name and a run that reports nothing.
const INVITE_TTL_SECONDS: u64 = 60;

/// Run the vault's half of an invite: mint it, and confirm on sight.
///
/// What `kvaultd invite` does, and what `DEC-0069` step 10 prints. Returns the
/// invite string, the task holding the vault's side of the ceremony, and the
/// six digits the vault prints on its `sas=` line once both ends meet — what
/// a person reads off the host and types at the desktop.
///
/// **The task's own recv is bounded too.** It is spawned, so a deadline placed
/// on the `JoinHandle` alone would leave the task itself parked on a channel
/// forever, holding the vault's reservation at the relay — which is what the
/// *next* test in the file then meets.
async fn vault_mints_an_invite(
    ipc: &IpcEndpoint,
    user: &str,
    label: &str,
) -> (
    String,
    tokio::task::JoinHandle<()>,
    tokio::sync::watch::Receiver<Option<u32>>,
) {
    let door = within("connecting to the vault's door", connect_when_ready(ipc, "vault door")).await;
    let mut rx = within(
        "asking the vault for an invite",
        door.device_invite_stream(user, INVITE_TTL_SECONDS, Some(label)),
    )
    .await
    .expect("device_invite_stream");
    let invite = match within("the vault minting its invite", rx.recv()).await {
        Some(UserResponse::PairAdvertising { code, .. }) => code.expose().to_string(),
        other => panic!("the first frame is the invite, got {other:?}"),
    };
    let ipc = ipc.clone();
    let user = user.to_owned();
    let (print_sas, printed) = tokio::sync::watch::channel(None);
    let task = tokio::spawn(async move {
        loop {
            let frame = match tokio::time::timeout(STEP, rx.recv()).await {
                Ok(Some(frame)) => frame,
                // The stream ended without a terminal frame. Nothing left to
                // wait for, and the test's own assertions say what is missing.
                Ok(None) => break,
                Err(_) => panic!(
                    "the vault's side heard nothing for {}s — the ceremony is wedged",
                    STEP.as_secs()
                ),
            };
            match frame {
                UserResponse::PairShowCode { token, sas, .. } => {
                    // The `sas=` line: what the person at the desktop reads.
                    print_sas.send_replace(Some(sas));
                    let confirm = within(
                        "the vault opening a connection to confirm on",
                        connect_when_ready(&ipc, "vault confirm"),
                    )
                    .await;
                    within(
                        "the vault confirming the digits on sight",
                        confirm.pair_confirm_code(&user, token.expose(), true),
                    )
                    .await
                    .expect("vault confirm");
                }
                UserResponse::PairingComplete { .. } => break,
                UserResponse::PairFailed { reason } => {
                    panic!("the vault's side of the ceremony failed: {reason}")
                }
                _ => {}
            }
        }
    });
    (invite, task, printed)
}

/// **Join… from the shell's world** — one invite, end to end, read back
/// through the readout.
///
/// A person on no network at all pastes one invite into *Join…*. That is
/// `joining.admit`, which is `UserRequest::DeviceAdmit` under the blind
/// posture — the request `kotton drive enrol <invite> --blind` already sends.
/// It admits the vault through the relay the invite names, held to that
/// relay's key; and because this device had none, the relay is offered, and
/// taken on the door's yes (`joining.take-relay`) — never by the admit.
///
/// **The six digits are load-bearing here.** `join_confirm` refuses until a
/// `PairShowCode` frame has arrived and the daemon has taken its token, so a
/// ceremony that never showed the digits cannot be confirmed and this test
/// cannot pass.
///
/// **Multi-threaded on purpose**, for the reason `cli_identity.rs`'s recovery
/// test is. These three call `OccupantHost` **directly**, so every task the
/// daemon spawns to serve them — the ceremony, the relay dial, the push at
/// `on-message` — lands on *this* runtime rather than the daemon's own. Then
/// `TestEnv::drop` blocks this thread waiting for `daemon.shutdown()`. On the
/// default current-thread runtime the thread it blocks is the only one that
/// could finish what `shutdown()` is waiting on, so the suite stops with the
/// test already passed and nothing to report. Measured 2026-09-22 with `gdb`:
/// the test body at its closing brace, `TestEnv::drop` in `JoinHandle::join`,
/// and the daemon's worker parked with nothing to poll — and 4 hangs in 6
/// alone on the current-thread runtime, against 0 in 8 on this one. A bounded
/// await cannot catch it, because the runtime's timer is not being driven.
/// The harness half is `TASK-a-test-env-teardown-waits-forever-on-work-parked-on-the-tests-own-runtime`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn the_desktop_joins_a_network_with_one_invite_from_the_shells_world() {
    use kotton_app::daemon::apps::OccupantHost;
    init_crypto();
    let _base = OwnBaseDir::take();
    let (_relay, relay_addr) = within("starting the relay", crate::common::relay::spawn()).await;
    let relay_url = format!("http://{relay_addr}");
    let vault = within(
        "starting the vault",
        spawn_vault_at(&relay_addr, "vault"),
    )
    .await;

    // A desktop on **no** network: this is what makes the door *Join…*.
    let mut env = within("starting the desktop daemon", crate::common::relay::env_without()).await;
    within(
        "making the person and their things",
        a_person_with_things(&mut env.client, "alice", NOTE),
    )
    .await;
    {
        let host = env.daemon.occupant_host();
        assert!(
            within("reading the relay before anything is paired", OccupantHost::paired_relay(&host))
                .await
                .expect("the readout answers")
                .is_none(),
            "this desktop is supposed to start on no network"
        );
    }

    let (invite, vault_side, printed) = within_for(
        WHOLE,
        "the vault minting an invite",
        vault_mints_an_invite(&vault.ipc, "alice", "vault"),
    )
    .await;
    assert!(
        invite.starts_with("kotton-invite:vault:") && invite.ends_with(&format!("@{relay_url}")),
        "the invite names the relay and the words: {invite}"
    );
    {
        let host = env.daemon.occupant_host();
        within("the shell's world taking the invite", OccupantHost::join_admit(&host, invite))
            .await
            .expect("the shell's world takes the invite");
    }
    assert!(
        within_for(WHOLE, "waiting for the digits", confirm_when_the_digits_arrive(&env.daemon, &printed))
            .await,
        "the join never showed six digits to compare"
    );
    finished(vault_side, "the vault's side").await;

    // The join does not stand this device at the relay the invite named: it is
    // offered, in the joined frame, and taken only on the door's yes
    // (`TASK-an-invite-is-the-codes-other-clause-and-its-relay-is-offered`).
    {
        let host = env.daemon.occupant_host();
        assert!(
            within("reading the relay after the join", OccupantHost::paired_relay(&host))
                .await
                .expect("the readout answers")
                .is_none(),
            "admitting the invite stood this device at its relay without a yes"
        );
        // The offer is kept when the joined frame is, a moment after the
        // vault's side ends; the yes waits for it, as a person reads it.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            match within("the door's yes to the offered relay", OccupantHost::join_take_relay(&host)).await {
                Ok(()) => break,
                Err(why) if std::time::Instant::now() < deadline && why.contains("nothing this window admitted") => {
                    tokio::time::sleep(Duration::from_millis(200)).await
                }
                Err(why) => panic!("the relay the join offered was not taken on the yes: {why}"),
            }
        }
        assert!(
            within("a second yes", OccupantHost::join_take_relay(&host)).await.is_err(),
            "the offer is spent by the yes"
        );
    }

    // The relay the invite named is now this device's, by the name the pane
    // draws it under — the readout's own `relay_name`, address without scheme.
    let paired = within_for(WHOLE, "waiting for the relay in the readout", relay_in_the_readout(&env.daemon))
        .await
        .expect("the yes must leave the network in the list");
    assert_eq!(paired, relay_addr, "the row is named after the relay: {paired}");

    // And the vault the invite named is this person's now, in the list the pane
    // draws, recorded against the relay it was met at (RFC-0083 R5). This read
    // came back empty until 2026-09-23 — the readout listed the remote set,
    // which admission never wrote
    // (`TASK-an-admitted-vault-is-not-in-the-remote-set-so-the-readout-shows-no-vault`).
    let vaults = within_for(WHOLE, "waiting for the vault in the readout", vaults_in_the_readout(&env.daemon))
        .await;
    assert_the_vault_is_listed(&vaults, &relay_addr);
    let nodes = within("reading the node roster", env.client.list_nodes("alice"))
        .await
        .expect("node list");
    let vault_row = nodes
        .iter()
        .find(|n| n.id == "vault")
        .expect("the vault the invite named is paired now");
    assert_eq!(
        vault_row.relay_url.as_deref().map(|u| u.trim_start_matches("http://")),
        Some(relay_addr.as_str()),
        "the vault records the relay it reserves at: {vault_row:?}"
    );
    let host = env.daemon.occupant_host();

    // Let go of the join before the daemon is torn down — what closing the
    // sheet does, and what leaves nothing of this flow still holding a pool
    // connection when `TestEnv::drop` waits for them all to come back.
    within("letting go of the join", OccupantHost::join_cancel(&host))
        .await
        .expect("cancel is idempotent");
}

/// **Enrol… from the shell's world** — an invite admitted through the relay
/// this device already has.
///
/// The other of the two invite doors, and what separates it from *Join…* is a
/// precondition rather than a verb: this device is already on a network, so the
/// pane's *Enrol…* is open (`NetworkCard::can_enrol`) and the same
/// `joining.admit` runs. The relay does not move — a person enrolling a vault
/// is adding to the network they are on, not leaving it — which is the half of
/// `DEC-0068` that a single-request door has to be shown not to break.
///
/// **Multi-threaded on purpose**, for the reason `cli_identity.rs`'s recovery
/// test is. These three call `OccupantHost` **directly**, so every task the
/// daemon spawns to serve them — the ceremony, the relay dial, the push at
/// `on-message` — lands on *this* runtime rather than the daemon's own. Then
/// `TestEnv::drop` blocks this thread waiting for `daemon.shutdown()`. On the
/// default current-thread runtime the thread it blocks is the only one that
/// could finish what `shutdown()` is waiting on, so the suite stops with the
/// test already passed and nothing to report. Measured 2026-09-22 with `gdb`:
/// the test body at its closing brace, `TestEnv::drop` in `JoinHandle::join`,
/// and the daemon's worker parked with nothing to poll — and 4 hangs in 6
/// alone on the current-thread runtime, against 0 in 8 on this one. A bounded
/// await cannot catch it, because the runtime's timer is not being driven.
/// The harness half is `TASK-a-test-env-teardown-waits-forever-on-work-parked-on-the-tests-own-runtime`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn enrolling_a_vault_goes_through_the_relay_already_paired() {
    use kotton_app::daemon::apps::OccupantHost;
    init_crypto();
    let _base = OwnBaseDir::take();
    let (_relay, relay_addr) = within("starting the relay", crate::common::relay::spawn()).await;
    let vault = within(
        "starting the vault",
        spawn_vault_at(&relay_addr, "vault"),
    )
    .await;

    let mut env = within("starting the desktop daemon", crate::common::relay::env_without()).await;
    within(
        "making the person and their things",
        a_person_with_things(&mut env.client, "alice", NOTE),
    )
    .await;

    // The relay this device already has, before any vault — set at the
    // terminal (`config relay set`, `RendezvousSet`). *Pair…* is deleted
    // (`TASK-settings-has-one-door-and-it-takes-a-code`), and so is the
    // shell's `pair-relay`, with the claim's sheet.
    within(
        "the terminal setting the relay",
        env.client.node_rendezvous_set(Some(&format!("http://{relay_addr}"))),
    )
    .await
    .expect("the relay is set");
    assert_eq!(
        within_for(WHOLE, "waiting for the relay in the readout", relay_in_the_readout(&env.daemon))
            .await
            .as_deref(),
        Some(relay_addr.as_str()),
        "Enrol… is shut until a relay is paired, so this is its precondition"
    );

    // *Enrol…* — the same verb, with a relay in hand.
    let (invite, vault_side, printed) = within_for(
        WHOLE,
        "the vault minting an invite",
        vault_mints_an_invite(&vault.ipc, "alice", "vault"),
    )
    .await;
    {
        let host = env.daemon.occupant_host();
        within("the shell's world taking the invite", OccupantHost::join_admit(&host, invite))
            .await
            .expect("the shell's world takes the invite");
    }
    assert!(
        within_for(WHOLE, "waiting for the digits", confirm_when_the_digits_arrive(&env.daemon, &printed))
            .await,
        "the enrolment never showed six digits to compare"
    );
    finished(vault_side, "the vault's side").await;

    let host = env.daemon.occupant_host();
    let relay = within("reading the relay after enrolling", OccupantHost::paired_relay(&host))
        .await
        .expect("the readout answers")
        .expect("still on a relay");
    assert_eq!(
        relay.name, relay_addr,
        "enrolling through the relay you already have must not move you to another"
    );
    // The vault's side finishing is not the admit finishing: this device
    // records the vault only once the vault has said it keeps for it (#157),
    // a dial after the ceremony. So the roster is read until the admit has
    // written it, bounded like every step here: a vault never recorded is
    // this step wedged.
    within_for(WHOLE, "waiting for the vault among this device's paired nodes", async {
        loop {
            let nodes = within("reading the node roster", env.client.list_nodes("alice"))
                .await
                .expect("node list");
            if nodes.iter().any(|n| n.id == "vault") {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    // And in the list the pane draws, with nothing typed after the digits.
    let vaults = within_for(WHOLE, "waiting for the vault in the readout", vaults_in_the_readout(&env.daemon))
        .await;
    assert_the_vault_is_listed(&vaults, &relay_addr);
    within("letting go of the join", OccupantHost::join_cancel(&host))
        .await
        .expect("cancel is idempotent");
}

/// **`kotton drive enrol <invite> --blind`** — the terminal's door, read back
/// through the pane's readout with nothing typed in between.
///
/// The request is the CLI's own: `device_admit_stream` under the blind posture
/// is what `client/shell`'s `drive enrol` sends, through the same client
/// library, to the same handler Settings' *Join…* and *Enrol…* call. The
/// assertion is on `network::enrolled_vaults` — the verb the Networking pane
/// calls — and there is no `remote add`, no `sync` and no other command between
/// the digits and the read. Both were once needed for the vault to appear,
/// because the readout listed the remote set and only a sync writes one
/// (`TASK-an-admitted-vault-is-not-in-the-remote-set-so-the-readout-shows-no-vault`).
///
/// **What makes it green is the membership record admission writes.** Take the
/// `record_own_device_member` call out of `finalize_enrolled_node` and the
/// vault is paired, on the roster, and in no list — which is this test going
/// red, measured 2026-09-23.
///
/// Multi-threaded and `#[serial]`, and every await bounded, for the reasons the
/// *Join…* test above gives: it reads through `OccupantHost` directly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_vault_admitted_at_the_terminal_is_in_the_readout_with_nothing_more_typed() {
    init_crypto();
    let _base = OwnBaseDir::take();
    let (_relay, relay_addr) = within("starting the relay", crate::common::relay::spawn()).await;
    let vault = within(
        "starting the vault",
        spawn_vault_at(&relay_addr, "vault"),
    )
    .await;

    let mut env = within("starting the desktop daemon", crate::common::relay::env_without()).await;
    within(
        "making the person and their things",
        a_person_with_things(&mut env.client, "alice", NOTE),
    )
    .await;
    {
        use kotton_app::daemon::apps::OccupantHost;
        let host = env.daemon.occupant_host();
        assert!(
            within("reading the vaults before any is admitted", OccupantHost::enrolled_vaults(&host))
                .await
                .expect("the readout answers")
                .is_empty(),
            "this person is supposed to start with no vault"
        );
    }

    // The terminal answers from the frame it is sent, as `kotton drive enrol`
    // does; the vault's printed digits are not needed here.
    let (invite, vault_side, _printed) = within_for(
        WHOLE,
        "the vault minting an invite",
        vault_mints_an_invite(&vault.ipc, "alice", "vault"),
    )
    .await;

    // What `kotton drive enrol <invite> --blind` sends, and what it does with
    // the frames: confirm the digits, stop at the end.
    let mut rx = within(
        "sending the terminal's admit",
        env.client
            .device_admit_stream("alice", &invite, INVITE_TTL_SECONDS, Posture::BlindStorage),
    )
    .await
    .expect("device_admit_stream");
    let mut admitted = None;
    while let Some(frame) = within("the next frame of the admit", rx.recv()).await {
        match frame {
            UserResponse::PairShowCode { token, .. } => {
                within(
                    "confirming the digits at the terminal",
                    env.client.pair_confirm_code("alice", token.expose(), true),
                )
                .await
                .expect("device confirm");
            }
            UserResponse::PairingComplete { node, .. } => {
                admitted = Some(node);
                break;
            }
            UserResponse::PairFailed { reason } => panic!("the terminal's admit failed: {reason}"),
            _ => {}
        }
    }
    let admitted = admitted.expect("the terminal's admit completed");
    assert_eq!(admitted.id, "vault");
    finished(vault_side, "the vault's side").await;

    // Nothing else typed. The pane's read, and the vault is in it.
    let vaults = within_for(WHOLE, "waiting for the vault in the readout", vaults_in_the_readout(&env.daemon))
        .await;
    assert_the_vault_is_listed(&vaults, &relay_addr);
}

/// The vault as a device dials it: its key and its peer port, on loopback.
async fn dialled(vault: &RunningVault) -> VaultIdentity {
    let mut door = within("the landlord's door", connect_when_ready(&vault.ipc, "door")).await;
    let (_, pubkey_hex) = within("the vault's identity", door.get_node_identity()).await.expect("the door says who the vault is");
    VaultIdentity { did: String::new(), pubkey_hex, op_addr: format!("127.0.0.1:{}", vault.op_port).parse().unwrap() }
}

/// **A vault and a relay created for a key each admit that key and refuse
/// every other** (RFC-0084 V18, V19): the vault at its handshake, where the key
/// it was created for completes one and is answered as its operator; the relay
/// at `/operator`, where it reads the rule and another key is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_service_started_with_its_operators_key_admits_that_key_and_no_other() {
    init_crypto();
    let offer = kotton_net::transport::quic::tls::CertOffer::default();
    let tenants = serde_json::to_vec(&UserRequest::Tenants).unwrap();
    let stranger = ed25519_dalek::SigningKey::from_bytes(&rand::random());

    let vault = within("starting the vault", spawn_vault("vault")).await;
    let id = dialled(&vault).await;
    match within("the vault's operator", try_ask_the_vault_with(&vault.creator, &offer, &id, tenants.clone())).await {
        Ok(UserResponse::VaultTenants { .. }) => {}
        other => panic!("the key the vault was created for was not answered as its operator: {other:?}"),
    }
    // Refused at the handshake: no answer at all. A refusal by standing would
    // be an answer — an `Error` frame — and the connection would have been
    // admitted; under QUIC the client learns of the server's refusal of its
    // certificate as the connection lost before any answer.
    let refused = within("a stranger at the vault", try_ask_the_vault_with(&stranger, &offer, &id, tenants)).await;
    assert!(refused.is_err(), "a key the vault was not created for was answered: {refused:?}");

    let operator = ed25519_dalek::SigningKey::from_bytes(&rand::random());
    let state = tempfile::tempdir().expect("a relay state directory");
    crate::common::relay::create_at(state.path(), &hex::encode(operator.verifying_key().to_bytes()));
    let (mut relay, addr, _) = crate::common::relay::relay_at(state.path(), "127.0.0.1:0", "").await;
    let url = format!("http://{addr}");
    let read = kotton_wire::rendezvous::RelayOperatorRequest::ReadRule;
    let ours = kotton_net::rendezvous::say_as_operator(&url, &operator, &read).await;
    let theirs = kotton_net::rendezvous::say_as_operator(&url, &stranger, &read).await;
    let _ = relay.kill();
    let _ = relay.wait();
    assert!(
        matches!(ours, Ok(kotton_wire::rendezvous::RelayOperatorResponse::Rule { .. })),
        "the key the relay was created for was not its operator: {ours:?}"
    );
    assert!(
        matches!(theirs, Err(kotton_net::rendezvous::RendezvousError::HttpError { status: 403, .. })),
        "a key the relay was not created for was answered: {theirs:?}"
    );
}

/// **A stranger's handshake is refused at a vault, and no claim is ever open**
/// (RFC-0084 V17, V19) — the inverse of the deleted
/// `an_unclaimed_vault_admits_a_stranger_to_the_claim_and_nothing_else`. A
/// key the vault has never seen, offering nothing — no key events, no
/// recovery claim, the very certificate the claim's verifier arm let through —
/// completes no handshake: when the vault has just started, once an operator is
/// enrolled at its door, and once that operator is revoked again. There is no
/// moment of the vault's life at which its peer port is anything but the
/// allowlist.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_strangers_handshake_is_refused_at_a_vault_and_no_claim_is_ever_open() {
    init_crypto();
    let offer = kotton_net::transport::quic::tls::CertOffer::default();
    let tenants = serde_json::to_vec(&UserRequest::Tenants).unwrap();
    let vault = within("starting the vault", spawn_vault("vault")).await;
    let id = dialled(&vault).await;
    let refused_at_the_handshake = |when: &'static str| {
        let (offer, id, tenants) = (offer.clone(), &id, tenants.clone());
        async move {
            let stranger = ed25519_dalek::SigningKey::from_bytes(&rand::random());
            let got = within(when, try_ask_the_vault_with(&stranger, &offer, id, tenants)).await;
            // No answer at all, not a refusal by standing: an answer, even an
            // `Error`, would mean the handshake admitted it.
            assert!(got.is_err(), "{when}: a stranger was answered: {got:?}");
        }
    };
    refused_at_the_handshake("just started").await;
    let second = ed25519_dalek::SigningKey::from_bytes(&rand::random());
    admit_at_the_door(&vault, &second).await;
    refused_at_the_handshake("an operator enrolled at the door").await;
    revoke_one_at_the_door(&vault, &second).await;
    refused_at_the_handshake("that operator revoked").await;
}
