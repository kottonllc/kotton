// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — a model is content the person owns (RFC-0085
//! *The model as content*, `DEC-0073`).
//!
//! RFC-0085's first Done criterion is one sentence with three clauses, and each
//! of them is a separate test here because they fail for different reasons:
//!
//! | Clause | Test |
//! |---|---|
//! | *"a sealed object and a manifest record in the store"* | `a_model_added_from_a_file_is_a_sealed_object_and_a_manifest_record` |
//! | *"appears on a second paired device after sync"* | `an_installed_model_reaches_a_second_paired_device` |
//! | *"is recovered from the phrase after both are lost"* | `a_model_comes_back_from_the_phrase_after_every_device_is_lost` |
//!
//! The last two are deliberately built out of the same daemons and the same
//! sync and recovery calls as `enroll_threshold_sign`'s file and record tests.
//! That is the claim being made: a model rides the paths the store already has,
//! and if it needed a path of its own the two tests would not look alike.
//!
//! The fixture weights are a few kilobytes of nothing. **A real model does not
//! fit**: the store seals at most 256 MiB in one object and every model RFC-0085
//! is about is larger. That is measured where the ceiling is —
//! `a_model_sized_object_is_refused_by_its_declared_size` in `kuserd`'s
//! `files_tests` — and `TASK-a-model-is-larger-than-the-store-will-seal` carries
//! it.

use std::net::SocketAddr;
use std::sync::Arc;

use kotton::{Licence, ModelFormat, ModelKind, ModelManifest, SyncDirection};
use kotton_schemas::membership::Posture;
use kotton_secret::MemorySecrets;
use kotton_sys::secret::SecretsStore;
use kotton_wire::remote::RemoteBackend;
use kuserd::DeviceDaemon;

use crate::common::{
    connect_when_ready, enroll_streamed, init_crypto, unique_ipc, wait_for_daemon, TestEnv,
};

const USER: &str = "alice";
const MODEL_NSID: &str = "sh.kotton.model";

fn free_port() -> u16 {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind :0 for port probe");
    s.local_addr().expect("local_addr").port()
}

/// Weights, as far as this unit is concerned: bytes with a hash.
///
/// No backend parses them — `StubBackend` is still what runs, and choosing a
/// real one is RFC-0085's next step. What is under test is that the bytes are
/// sealed, named by their hash, and come back.
fn weights(seed: u8) -> Vec<u8> {
    (0..4096u32).map(|i| (i as u8) ^ seed).collect()
}

fn manifest_for(name: &str, kind: ModelKind, body: &[u8]) -> ModelManifest {
    ModelManifest {
        name: name.to_string(),
        version: "1".to_string(),
        weights: blake3::hash(body).to_hex().to_string(),
        format: ModelFormat::Gguf,
        kind,
        parameters: 1_000_000_000,
        quantisation: "Q4_K_M".to_string(),
        size: body.len() as u64,
        context_window: 4096,
        template: "{question}".to_string(),
        licence: Licence {
            spdx: "Apache-2.0".to_string(),
            text_hash: "00".repeat(32),
        },
        publisher: None,
    }
}

/// Send the weights through their own door, then install — `kotton model add`.
///
/// The weights go from a file on disk through `Model::add`, which is what the
/// CLI calls: `ModelWeights` chunks the daemon streams into its own object for
/// the manifest's hash, then `ModelAdd`. Nothing here names a path, because
/// nothing the caller could name reaches the weights
/// (`TASK-a-models-weights-are-the-daemons-and-no-files-grant-reaches-them`).
async fn install(
    client: &mut kotton::KottonClient,
    user: &str,
    manifest: &ModelManifest,
    body: &[u8],
) -> std::io::Result<(String, bool)> {
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("weights.gguf");
    std::fs::write(&file, body)?;
    client.model(user).add(&file, manifest).await
}

/// The path the weights rested at in the person's tree until 2026-09-24 —
/// kept here only to assert nothing of the model's is there now.
fn old_tree_path(manifest: &ModelManifest) -> String {
    format!("/models/{}.weights", manifest.weights)
}

/// Whether the daemon holds weights that verify against `manifest`: `ModelAdd`
/// re-hashes the object at the manifest's key and refuses unless it is those
/// bytes, so a second `add` of an installed manifest succeeding is the daemon
/// saying the weights are there, byte for byte (hash and length).
async fn weights_verify(client: &mut kotton::KottonClient, manifest: &ModelManifest) -> bool {
    client.model_add(USER, manifest).await.is_ok()
}

// ── Clause 1: a sealed object and a manifest record ──────────────────────────

/// A model added from a file is a sealed object and a manifest record in the
/// store — and `ls` reads both back as one thing.
#[tokio::test]
async fn a_model_added_from_a_file_is_a_sealed_object_and_a_manifest_record() {
    let mut env = TestEnv::spawn().await;
    env.client
        .create_user(USER, crate::common::TEST_PASSPHRASE)
        .await
        .expect("create_user");

    let body = weights(0x11);
    let manifest = manifest_for("gemma-fixture", ModelKind::Chat, &body);
    let (id, active) = install(&mut env.client, USER, &manifest, &body)
        .await
        .expect("install");

    assert_eq!(id, manifest.weights, "a model's identity is its weights hash");
    assert!(active, "the first model of a kind is the one that answers");

    // The object: the daemon's, verifying against the manifest — and not a
    // file in the person's tree.
    assert!(
        weights_verify(&mut env.client, &manifest).await,
        "the weights the manifest names are in the store"
    );
    assert!(
        env.client.read_file(USER, &old_tree_path(&manifest)).await.is_err(),
        "the weights are a file in the person's tree"
    );
    let tree = env.client.list_files(USER, "/").await.expect("the tree lists");
    assert!(
        tree.iter().all(|p| !p.trim_start_matches('/').starts_with("models")),
        "installing a model put something in the person's tree: {tree:?}"
    );

    // The record: the manifest, unchanged, plus the host's two fields.
    let records = env
        .client
        .record_query(USER, MODEL_NSID, vec![], None, None)
        .await
        .expect("record_query");
    assert_eq!(records.len(), 1, "one manifest record");
    let back: ModelManifest =
        serde_json::from_value(records[0].clone()).expect("the record body is a manifest");
    assert_eq!(back, manifest, "the manifest is what gets stored, unchanged");
    assert_eq!(records[0]["active"], serde_json::json!(true));

    // And the two together are what `ls` shows.
    let listed = env.client.model_list(USER).await.expect("model_list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].manifest, manifest);
    assert!(listed[0].active);
}

/// A manifest that names weights the store does not hold, or holds other bytes
/// for, installs nothing.
///
/// `DEC-0073` says the weights are *"verified against that hash before it is
/// sealed"*, and that check is the store's own: `write_file` refuses any
/// reassembly whose BLAKE3 is not the declared `content_hash`
/// (`a_hash_mismatch_is_refused_and_stores_nothing`, in `kuserd`'s
/// `files_tests`). What is checked here is the half that gate cannot see,
/// because the caller declares both the path and the hash: that the object
/// *at the model's path* is the one the manifest names.
#[tokio::test]
async fn weights_that_are_not_what_the_manifest_names_install_nothing() {
    let mut env = TestEnv::spawn().await;
    env.client
        .create_user(USER, crate::common::TEST_PASSPHRASE)
        .await
        .expect("create_user");

    let body = weights(0x22);
    let manifest = manifest_for("honest", ModelKind::Chat, &body);

    // Nothing at the path at all.
    let err = env
        .client
        .model_add(USER, &manifest)
        .await
        .expect_err("a manifest naming weights the store has not got installs nothing");
    assert!(
        err.to_string().contains("not in the store"),
        "the refusal must name what is missing: {err}"
    );

    // Bytes at the old path in the person's tree — what a bare `kotton fs
    // write`, or an app holding `files.write` on `/`, can put there. That is an
    // ordinary file of theirs now, and `ModelAdd` never reads it.
    let other = weights(0x23);
    env.client
        .write_file(USER, &old_tree_path(&manifest), &other)
        .await
        .expect("the person's tree takes a file of theirs");
    let err = env
        .client
        .model_add(USER, &manifest)
        .await
        .expect_err("a file in the person's tree is not a model's weights");
    assert!(err.to_string().contains("not in the store"), "{err}");

    // Other bytes through the weights' own door, declared as the manifest's
    // hash: refused on the way in, so nothing is at the key.
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("liar.gguf");
    std::fs::write(&file, &other).expect("write");
    let err = env
        .client
        .seal_model_weights(USER, &file, &manifest.weights)
        .await
        .expect_err("weights that are not their declared hash are refused");
    assert!(
        err.to_string().contains(&blake3::hash(&other).to_hex().to_string()),
        "the refusal must say what actually arrived: {err}"
    );
    let err = env
        .client
        .model_add(USER, &manifest)
        .await
        .expect_err("a refused stream leaves nothing to install");
    assert!(err.to_string().contains("not in the store"), "{err}");
    assert!(
        env.client.model_list(USER).await.expect("model_list").is_empty(),
        "a refused install leaves no model behind"
    );
}

// ── `DEC-0073`: one model per kind answers, and the person chooses ───────────

/// One model per kind is active, the first one answers because nothing else
/// can, and a second install does not take the choice away from the person.
#[tokio::test]
async fn one_model_per_kind_answers_and_installing_another_does_not_move_it() {
    let mut env = TestEnv::spawn().await;
    env.client
        .create_user(USER, crate::common::TEST_PASSPHRASE)
        .await
        .expect("create_user");

    let first_body = weights(0x31);
    let first = manifest_for("first-chat", ModelKind::Chat, &first_body);
    let (_, active) = install(&mut env.client, USER, &first, &first_body)
        .await
        .expect("install first");
    assert!(active);

    let second_body = weights(0x32);
    let second = manifest_for("second-chat", ModelKind::Chat, &second_body);
    let (_, active) = install(&mut env.client, USER, &second, &second_body)
        .await
        .expect("install second");
    assert!(
        !active,
        "installing a second model must not silently change which one answers"
    );

    // An embed model is a different kind, so it answers for its own kind at once.
    let embed_body = weights(0x33);
    let embed = manifest_for("first-embed", ModelKind::Embed, &embed_body);
    let (_, active) = install(&mut env.client, USER, &embed, &embed_body)
        .await
        .expect("install embed");
    assert!(active, "one model per *kind*, not one model");

    let listed = env.client.model_list(USER).await.expect("model_list");
    assert_eq!(listed.len(), 3);
    assert_eq!(
        listed.iter().filter(|m| m.active).count(),
        2,
        "exactly one chat and one embed answer"
    );

    // The person moves it.
    env.client
        .model_use(USER, "second-chat", false)
        .await
        .expect("model_use");
    let listed = env.client.model_list(USER).await.expect("model_list");
    let active: Vec<&str> = listed
        .iter()
        .filter(|m| m.active)
        .map(|m| m.manifest.name.as_str())
        .collect();
    assert_eq!(active.len(), 2, "still one per kind after the switch");
    assert!(active.contains(&"second-chat"), "the person's choice took: {active:?}");
    assert!(!active.contains(&"first-chat"));
    assert!(active.contains(&"first-embed"), "the embed choice was not disturbed");
}

/// Changing the active *embed* model is not the same act as changing the chat
/// model, and the surface does not let them look alike.
///
/// RFC-0085, *The index*: changing the embedding model *"invalidates the chunks
/// it produced"*, and its manifest *"is what makes two devices' indexes
/// comparable"*. There is no index yet — that is the next step — so what is held
/// here is the shape of the act: it is refused until the person says yes, and
/// the refusal says what it would cost.
#[tokio::test]
async fn changing_the_active_embed_model_is_refused_until_the_person_says_yes() {
    let mut env = TestEnv::spawn().await;
    env.client
        .create_user(USER, crate::common::TEST_PASSPHRASE)
        .await
        .expect("create_user");

    let first_body = weights(0x41);
    let first = manifest_for("first-embed", ModelKind::Embed, &first_body);
    install(&mut env.client, USER, &first, &first_body)
        .await
        .expect("install first embed");
    let second_body = weights(0x42);
    let second = manifest_for("second-embed", ModelKind::Embed, &second_body);
    install(&mut env.client, USER, &second, &second_body)
        .await
        .expect("install second embed");

    let err = env
        .client
        .model_use(USER, "second-embed", false)
        .await
        .expect_err("changing the embedding model must not be a quiet act");
    let why = err.to_string();
    assert!(why.contains("index"), "the refusal must say what it costs: {why}");
    assert!(why.contains("rebuild-index"), "and how to say yes: {why}");

    // Unchanged until the person says so.
    let listed = env.client.model_list(USER).await.expect("model_list");
    assert!(
        listed.iter().any(|m| m.active && m.manifest.name == "first-embed"),
        "the refused switch changed nothing"
    );

    // A chat model in the same store switches with no ceremony, which is the
    // contrast this rule exists to make.
    let chat_body = weights(0x43);
    let chat = manifest_for("a-chat", ModelKind::Chat, &chat_body);
    install(&mut env.client, USER, &chat, &chat_body)
        .await
        .expect("install chat");
    env.client
        .model_use(USER, "a-chat", false)
        .await
        .expect("a chat model moves without a flag");

    env.client
        .model_use(USER, "second-embed", true)
        .await
        .expect("and the embed model moves once the person has said yes");
    let listed = env.client.model_list(USER).await.expect("model_list");
    assert!(listed.iter().any(|m| m.active && m.manifest.name == "second-embed"));
    assert_eq!(
        listed
            .iter()
            .filter(|m| m.active && m.manifest.kind == ModelKind::Embed)
            .count(),
        1,
        "still exactly one embed model answers"
    );
}

/// `rm` takes both halves: the manifest record and the sealed weights.
#[tokio::test]
async fn removing_a_model_takes_the_record_and_the_weights_together() {
    let mut env = TestEnv::spawn().await;
    env.client
        .create_user(USER, crate::common::TEST_PASSPHRASE)
        .await
        .expect("create_user");

    let body = weights(0x51);
    let manifest = manifest_for("leaving", ModelKind::Chat, &body);
    install(&mut env.client, USER, &manifest, &body)
        .await
        .expect("install");

    env.client
        .model_remove(USER, "leaving")
        .await
        .expect("model_remove by name");

    assert!(
        env.client.model_list(USER).await.expect("model_list").is_empty(),
        "the manifest record is gone"
    );
    assert!(
        !weights_verify(&mut env.client, &manifest).await,
        "and so are the weights — the store is paid by the byte"
    );
    assert!(
        env.client.model_list(USER).await.expect("model_list").is_empty(),
        "the failed re-add above left no model behind"
    );
}

// ── Clause 2: it appears on a second paired device after sync ────────────────

/// A model installed on one device reaches another device of the same identity
/// — both halves of it, the manifest record and the sealed weights.
///
/// Built out of the same calls as `enroll_threshold_sign`'s file and record
/// tests, on purpose: a model is content, so the sync it gets is the sync
/// everything else gets, and nothing in the model surface is a sync path.
#[tokio::test]
async fn an_installed_model_reaches_a_second_paired_device() {
    init_crypto();

    // E holds the model; N joins the identity and pulls.
    let base_e = tempfile::tempdir().expect("base_e");
    let ipc_e = unique_ipc();
    let secrets_e: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    let daemon_e = DeviceDaemon::new_with_base_and_secrets(
        base_e.path().to_owned(),
        ipc_e.clone(),
        Arc::clone(&secrets_e),
    )
    .await
    .expect("daemon E");

    let base_n = tempfile::tempdir().expect("base_n");
    let ipc_n = unique_ipc();
    let secrets_n: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    let daemon_n = DeviceDaemon::new_with_base_and_secrets(
        base_n.path().to_owned(),
        ipc_n.clone(),
        Arc::clone(&secrets_n),
    )
    .await
    .expect("daemon N");

    let _task_e = tokio::spawn(async move { std::sync::Arc::new(daemon_e).run().await });
    let _task_n = tokio::spawn(async move { std::sync::Arc::new(daemon_n).run().await });
    wait_for_daemon(&ipc_e, "daemon E").await;
    wait_for_daemon(&ipc_n, "daemon N").await;

    let mut client_e = connect_when_ready(&ipc_e, "client_e").await;
    let client_n = connect_when_ready(&ipc_n, "client_n").await;

    client_e
        .create_user(USER, crate::common::TEST_PASSPHRASE)
        .await
        .expect("create_user E");
    // E keeps the person's things on a drive, enrolled before N joins so the
    // join introduces N to it: N receives E's model by way of the drive.
    let (client_e, _drive) = crate::drive_sync::a_drive_for(client_e, "device-e", USER).await;

    let (mut client_e, mut client_n, _node_n) = enroll_streamed(
        client_e,
        client_n,
        USER,
        "device-n",
        Posture::Full,
    )
    .await;

    // The model, installed on E.
    let body = weights(0x71);
    let manifest = manifest_for("travels", ModelKind::Chat, &body);
    install(&mut client_e, USER, &manifest, &body)
        .await
        .expect("install on E");

    // E syncs to the drive — its records logged into the packs it sends — and
    // N takes everything from there.
    client_e
        .sync_mount(USER, "local", "vault", Some(SyncDirection::Push))
        .await
        .expect("E pushes to the drive");
    client_n
        .sync_mount(USER, "local", "vault", Some(SyncDirection::Pull))
        .await
        .expect("N pulls from the drive");

    // The criterion: the model is on N, both halves of it.
    let listed = client_n.model_list(USER).await.expect("model_list on N");
    assert_eq!(listed.len(), 1, "the manifest record reached the second device");
    assert_eq!(listed[0].manifest, manifest);
    assert!(
        listed[0].active,
        "and so did which model answers — the choice travels with the model"
    );

    // The weights: the daemon on N re-hashes its own object for the manifest
    // and finds the same bytes, opened with the delivered key.
    assert!(
        weights_verify(&mut client_n, &manifest).await,
        "the weights reached the second device"
    );

}

// ── Clause 3: it is recovered from the phrase after both are lost ────────────

/// Every device is lost, and the model comes back from the phrase.
///
/// The same arrangement as
/// `enroll_threshold_sign::a_user_who_loses_every_device_recovers_everything_from_the_phrase`:
/// a blind node that holds ciphertext it cannot read, a phrase, and a cold
/// device. A model is in that "everything" because it is a record and a sealed
/// object, and for no other reason.
#[tokio::test]
async fn a_model_comes_back_from_the_phrase_after_every_device_is_lost() {
    init_crypto();

    let body = weights(0x81);
    let manifest = manifest_for("survives", ModelKind::Chat, &body);

    // B = the blind node. It outlives every device the person has.
    let base_b = tempfile::tempdir().expect("base_b");
    let ipc_b = unique_ipc();
    let secrets_b: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    let daemon_b = Arc::new(
        DeviceDaemon::new_with_base_and_secrets(
            base_b.path().to_owned(),
            ipc_b.clone(),
            Arc::clone(&secrets_b),
        )
        .await
        .expect("daemon B"),
    );
    let op_port_b = free_port();
    daemon_b
        .start_peer_listener_background(op_port_b)
        .await
        .expect("start B operational listener");
    let daemon_b =
        Arc::try_unwrap(daemon_b).unwrap_or_else(|_| panic!("sole arc owner for daemon_b"));
    let _task_b = tokio::spawn(async move { std::sync::Arc::new(daemon_b).run().await });
    wait_for_daemon(&ipc_b, "daemon B").await;

    let recovery_phrase;
    let did_b_dev;
    let pubkey_b_hex;
    {
        let base_e = tempfile::tempdir().expect("base_e");
        let ipc_e = unique_ipc();
        let secrets_e: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
        let daemon_e = DeviceDaemon::new_with_base_and_secrets(
            base_e.path().to_owned(),
            ipc_e.clone(),
            Arc::clone(&secrets_e),
        )
        .await
        .expect("daemon E");
        let _task_e = tokio::spawn(async move { std::sync::Arc::new(daemon_e).run().await });
        wait_for_daemon(&ipc_e, "daemon E").await;

        let mut client_e = connect_when_ready(&ipc_e, "client_e").await;
        let client_b = connect_when_ready(&ipc_b, "client_b").await;

        client_e
            .create_user(USER, crate::common::TEST_PASSPHRASE)
            .await
            .expect("create_user E");
        recovery_phrase = client_e
            .add_recovery_phrase(USER)
            .await
            .expect("add_recovery_phrase");

        let (mut client_e, _client_b, node_b) = enroll_streamed(
            client_e,
            client_b,
            USER,
            "blind-vps",
            Posture::BlindStorage,
        )
        .await;
        did_b_dev = node_b.device_did.to_string();
        pubkey_b_hex = hex::encode(node_b.public_key);

        install(&mut client_e, USER, &manifest, &body)
            .await
            .expect("install on E");

        client_e
            .remote_add(
                USER,
                "blind-vps",
                RemoteBackend::Kotton {
                    peer_did: did_b_dev.clone(),
                    label: "blind-vps".to_string(),
                },
                None,
            )
            .await
            .expect("remote_add B on E");
        let pushed = client_e
            .sync_mount(USER, "local", "blind-vps", Some(SyncDirection::Push))
            .await
            .expect("push everything to the blind node");
        assert!(
            pushed.pushed >= 1,
            "the blind node must actually hold something to recover from"
        );

        // `base_e` drops here: the disk, the keychain, the records. Nothing of
        // the person's only device survives but the phrase.
    }
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let base_c = tempfile::tempdir().expect("base_c");
    let ipc_c = unique_ipc();
    let secrets_c: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    let daemon_c = DeviceDaemon::new_with_base_and_secrets(
        base_c.path().to_owned(),
        ipc_c.clone(),
        Arc::clone(&secrets_c),
    )
    .await
    .expect("daemon C");
    let _task_c = tokio::spawn(async move { std::sync::Arc::new(daemon_c).run().await });
    wait_for_daemon(&ipc_c, "daemon C").await;

    let mut client_c = connect_when_ready(&ipc_c, "client_c").await;
    client_c
        .login_with_recovery_key(&recovery_phrase, Some(USER.to_string()), None)
        .await
        .expect("the phrase alone claims the identity on a cold device");

    let b_op_addr: SocketAddr = format!("127.0.0.1:{op_port_b}").parse().unwrap();
    // B's line, as the recovery card prints it: `Recover` adds B as the node
    // `vault`, and records it as the person's drive once the phrase proves.
    let b_line = kotton_wire::line::InstanceLine {
        kind: kotton_wire::ipc::OperatedService::Vault,
        hint: b_op_addr.to_string(),
        key: hex::decode(&pubkey_b_hex).expect("B's key is hex").try_into().expect("B's key is 32 bytes"),
    }
    .to_text();
    client_c
        .recover(USER, &recovery_phrase, crate::common::TEST_PASSPHRASE, &b_line)
        .await
        .expect("recover from the phrase and the blind node alone");
    client_c
        .remote_add(
            USER,
            "blind-vps",
            RemoteBackend::Kotton {
                peer_did: did_b_dev.clone(),
                label: "vault".to_string(),
            },
            None,
        )
        .await
        .expect("remote_add B on C");
    client_c
        .sync_mount(USER, "local", "blind-vps", Some(SyncDirection::Pull))
        .await
        .expect("pull the whole of it back from the blind node");

    // The criterion.
    let listed = client_c.model_list(USER).await.expect("model_list on C");
    assert_eq!(
        listed.len(),
        1,
        "the model's manifest came back from the phrase"
    );
    assert_eq!(listed[0].manifest, manifest);
    assert!(
        weights_verify(&mut client_c, &manifest).await,
        "and so did the weights it names"
    );
}
