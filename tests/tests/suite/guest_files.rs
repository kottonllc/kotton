// SPDX-License-Identifier: AGPL-3.0-or-later
//! A file an app writes rests in the sealed store, and nowhere else.
//!
//! `TASK-a-file-an-app-writes-rests-in-the-clear-in-the-sealed-stores-own-directory`:
//! `users/<uid>/data` is the sealed store's backing directory, and it was also
//! the tree every `files` handle wrote into with `tokio::fs` — so a note a
//! person saved in the editor rested there in plaintext under its own name,
//! the store's listing failed on it (`encrypted blob too short`), its packing
//! pass stopped on it, and a sync to a device holding the keys would have
//! carried it verbatim.
//!
//! The fix is that the store serves the `files` world: the runner asks the
//! daemon for every read and write, the daemon answers from the person's loaded
//! `UserStore` after checking the path against the instance's grant, and the
//! runner's kernel profile no longer names the directory at all. These tests
//! drive that whole path the way a person's editor does — a real daemon's
//! launch, the real confined `kotton-runner`, a real component
//! (`tests/fixtures/files-probe`) — and then look at the store and at the disk.
//!
//! **A stale runner makes these meaningless**, as it did for the roots probe
//! (`TASK-a-real-runner-test-runs-whatever-runner-was-last-built`): run
//! `cargo build --bin kotton-runner` first, or the old runner writes the file
//! in the clear and the grep below says so.

use crate::common::{InstallApprovingAll as _, TestEnv, TEST_PASSPHRASE};
use std::path::{Path, PathBuf};

/// What the probe writes, and the string searched for on disk. The same
/// constant as `NOTE_BODY` in `tests/fixtures/files-probe/src/lib.rs`.
const NOTE_BODY: &str = "PLAINTEXT-MARKER-4f1c9a: a note an app wrote through files.write";
/// The marker alone — the part no sealed byte can contain by accident.
const MARKER: &[u8] = b"PLAINTEXT-MARKER-4f1c9a";

/// A daemon with a person on it, the probe installed with read and write on
/// their whole tree, and the probe's id.
pub(crate) async fn a_person_with_the_probe_installed() -> (TestEnv, String) {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/files-probe");
    let manifest = std::fs::read_to_string(fixture.join("manifest.toml")).expect("manifest");
    let wasm_path = fixture.join("app.wasm");
    let wasm = std::fs::read(&wasm_path).unwrap_or_else(|e| {
        panic!(
            "the files probe is not built, so this test cannot run it.\n  \
             missing: {} ({e})\n  fix:     cargo xtask build-apps",
            wasm_path.display()
        )
    });

    let mut env = TestEnv::spawn_with_real_runner().await;
    env.client
        .create_user("owner", TEST_PASSPHRASE)
        .await
        .expect("create_user (authenticates the connection)");
    let (app_id, _, _) = env
        .client
        .app_install_approving_all("owner", manifest, wasm)
        .await
        .expect("install, approving files.read and files.write on /");
    (env, app_id)
}

/// Launch the probe and read back what it painted.
async fn launch(env: &mut TestEnv, app_id: &str) -> serde_json::Value {
    launch_with(env, app_id, vec![]).await
}

/// Launch the probe with arguments — what it does with each is in its own
/// module comment — and read back what it painted.
pub(crate) async fn launch_with(
    env: &mut TestEnv,
    app_id: &str,
    args: Vec<(String, String)>,
) -> serde_json::Value {
    let patches = match env.client.app_launch(app_id, args).await {
        Ok(launched) => launched.patches,
        Err(e) => panic!("the probe did not launch: {e}"),
    };
    let patch = patches.first().expect("the probe paints its report as the launch's patch");
    let report: serde_json::Value =
        serde_json::from_slice(&patch[1..]).expect("the probe paints raw JSON (format version 0x00)");
    eprintln!("files probe report: {report}");
    report
}

/// Every regular file under `dir`, at any depth.
fn every_file(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for entry in rd.flatten() {
            let path = entry.path();
            match entry.file_type() {
                Ok(t) if t.is_dir() => stack.push(path),
                Ok(t) if t.is_file() => out.push(path),
                _ => {}
            }
        }
    }
    out
}

/// Assert no file under `dir` is named for the probe's files or holds the
/// marker the probe wrote, and say how many files were searched.
fn assert_nothing_in_the_clear(dir: &Path, when: &str) -> usize {
    let files = every_file(dir);
    for file in &files {
        let name = file.file_name().and_then(|n| n.to_str()).unwrap_or("");
        assert!(
            !["probe-note.md", "inner.md", "folder"].contains(&name),
            "{when}: a file the app wrote rests under its own name: {}",
            file.display()
        );
        let bytes = std::fs::read(file).unwrap_or_default();
        assert!(
            !bytes.windows(MARKER.len()).any(|w| w == MARKER),
            "{when}: the app's plaintext rests on disk in {}",
            file.display()
        );
    }
    files.len()
}

/// **A file an app writes through `files.write` is in the store: listed,
/// packed, and read back through it — and the app reads it back through the
/// packed store too.**
///
/// The record's condition, as one test. The probe writes a note on the handle
/// its grant on `/` minted and a second file one folder down. Then the
/// person's own `local` mount lists both (the listing that failed on a guest's
/// file with *encrypted blob too short*), the packing pass runs to completion
/// (the pass that stopped on it), the note reads back through the store over
/// IPC, and a second launch of the probe — a fresh instance after the pack —
/// reads it back through its own handle.
#[tokio::test]
async fn a_file_an_app_writes_rests_sealed_and_packs_and_reads_back() {
    let (mut env, app_id) = a_person_with_the_probe_installed().await;

    let first = launch(&mut env, &app_id).await;
    assert_eq!(first["handles"], 1, "{first}");
    assert_eq!(first["writable"], true, "{first}");
    assert!(first["read_before"].as_str().unwrap_or("").starts_with("err"), "{first}");
    assert_eq!(first["write"], "ok", "the write through files.write failed: {first}");
    assert_eq!(first["write_inner"], "ok", "{first}");
    assert_eq!(first["read_after"], format!("ok: {NOTE_BODY}"), "{first}");
    assert_eq!(first["read_inner"], "ok: one folder down", "{first}");
    let listing = first["listing"].as_array().expect("a listing");
    assert!(
        listing.iter().any(|e| e["name"] == "probe-note.md"
            && e["is_dir"] == false
            && e["size"] == NOTE_BODY.len() as u64),
        "the guest's own listing lacks the note: {first}"
    );
    assert!(
        listing.iter().any(|e| e["name"] == "folder" && e["is_dir"] == true),
        "the guest's own listing lacks the folder: {first}"
    );

    // ── The store sees what the app wrote ────────────────────────────────────
    let store = env.users.get("owner").expect("the person's store is loaded");
    let listed = store.list_files("/").await.expect(
        "the person's local mount lists — a plaintext file in its directory made this fail",
    );
    assert!(listed.contains(&"probe-note.md".to_string()), "{listed:?}");
    assert!(listed.contains(&"folder/inner.md".to_string()), "{listed:?}");
    let children = store.list_children("/").await.expect("children");
    assert!(children.iter().any(|c| c.name == "probe-note.md" && !c.is_dir), "{children:?}");
    assert!(children.iter().any(|c| c.name == "folder" && c.is_dir), "{children:?}");

    // ── The packing pass runs over it ────────────────────────────────────────
    let local = store.get_remote("local").expect("the local mount");
    let packed = kotton_store::runtime::pack_mount(&*local, "local")
        .await
        .expect("the packing pass completes — a guest's file stopped it before")
        .expect("an unlocked person's mount packs");
    eprintln!("packed: {packed:?}");
    assert!(
        kotton_store::runtime::pack_mount(&*local, "local").await.is_ok(),
        "a second pass over the packed store runs too"
    );

    // ── And it reads back through the store ──────────────────────────────────
    assert_eq!(
        store.read_file("/probe-note.md").await.expect("read through the store"),
        NOTE_BODY.as_bytes()
    );
    assert_eq!(
        env.client.read_file("owner", "/probe-note.md").await.expect("read over IPC"),
        NOTE_BODY.as_bytes(),
        "what an app wrote is what `kotton fs read` reads"
    );

    // ── And through the app, from the packed store ───────────────────────────
    let second = launch(&mut env, &app_id).await;
    assert_eq!(
        second["read_before"],
        format!("ok: {NOTE_BODY}"),
        "a fresh instance did not read the note back from the packed store: {second}"
    );
    assert!(second.get("write").is_none(), "the probe wrote again: {second}");
    assert_eq!(second["read_inner"], "ok: one folder down", "{second}");
}

/// **No byte an app writes rests in the clear under the person's directory.**
///
/// The grep the record asks for: after the probe has written its note, every
/// file under `users/owner/` is read and searched for the note's marker, and
/// for the names the probe gave its files. Before the fix both were there —
/// `data/probe-note.md`, holding the note verbatim. Searched twice: with the
/// objects loose, and again after the packing pass has moved them into packs.
/// The count of files searched is asserted non-zero so an empty directory
/// cannot pass for a sealed one.
#[tokio::test]
async fn no_byte_an_app_writes_rests_in_the_clear_under_the_persons_directory() {
    let (mut env, app_id) = a_person_with_the_probe_installed().await;

    let report = launch(&mut env, &app_id).await;
    assert_eq!(report["write"], "ok", "the probe's write failed, so there is nothing to look for: {report}");

    let person = env.base_dir.join("users").join("owner");
    let data = person.join("data");
    let loose = assert_nothing_in_the_clear(&person, "loose");
    assert!(
        every_file(&data).len() >= 2,
        "the store's directory holds fewer objects than the app wrote files, so the \
         search proves nothing: {loose} files under {}",
        person.display()
    );

    let store = env.users.get("owner").expect("the person's store is loaded");
    kotton_store::runtime::pack_mount(&*store.get_remote("local").expect("local"), "local")
        .await
        .expect("the packing pass completes")
        .expect("an unlocked mount packs");
    assert_nothing_in_the_clear(&person, "packed");

    // The control: the marker really is what the app wrote, so a search that
    // finds nothing found nothing because nothing is there.
    assert_eq!(
        store.read_file("/probe-note.md").await.expect("read through the store"),
        NOTE_BODY.as_bytes()
    );
}

/// The names the probe's listing of its first handle's root holds.
fn listed_names(report: &serde_json::Value) -> Vec<String> {
    let mut names: Vec<String> = report["listing"]
        .as_array()
        .unwrap_or_else(|| panic!("the probe listed nothing: {report}"))
        .iter()
        .map(|e| e["name"].as_str().expect("a name").to_string())
        .collect();
    names.sort();
    names
}

/// An own device, as the pairing ceremony would write it for `did`.
fn own_device(did: &str, label: &str) -> kotton_schemas::membership::Member {
    use kotton_schemas::membership::{Ceremony, Member, Posture, Role};
    Member {
        did: did.to_string(),
        public_key: [7u8; 32],
        role: Role::OwnDevice,
        admitted_by: Ceremony::DeviceEnroll,
        added_at: "2026-09-24T00:00:00Z".to_string(),
        posture: Some(Posture::Full),
        label: Some(label.to_string()),
        reach: None,
    }
}

/// **An app granted the person's whole tree cannot write a member into the
/// daemon's membership set** — the assessor's probe of 2026-09-24, kept.
///
/// That day the probe wrote `network/members/did:key:z6MkForgedByAnApp` with
/// an own-device, `posture: full` record through the handle a `files.write`
/// grant on `/` minted — the grant the shell holds — and `list_members`
/// returned it with `in_paired_key_allowlist() == true`, which is the set the
/// peer mTLS allowlist and `paired_nodes` are projected from. The person's
/// tree is rooted in the store beside the daemon's records now, not over
/// them. So the same write is an ordinary file in the person's own tree: it
/// lands, it reads back to the app that wrote it, and the membership set does
/// not see it.
#[tokio::test]
async fn an_app_granted_the_whole_tree_cannot_forge_a_member() {
    use kotton_peer::membership::Membership as _;
    const FORGED: &str = "did:key:z6MkForgedByAnApp";

    let (mut env, app_id) = a_person_with_the_probe_installed().await;
    let store = env.users.get("owner").expect("the person's store is loaded");
    let before = store.list_members().await.expect("the membership set lists");
    assert!(before.iter().all(|m| m.did != FORGED), "{before:?}");

    let body = serde_json::to_string(&own_device(FORGED, "forged by an app")).expect("json");
    let report = launch_with(
        &mut env,
        &app_id,
        vec![
            ("write".to_string(), format!("network/members/{FORGED}")),
            ("body".to_string(), body.clone()),
        ],
    )
    .await;
    // The write is the app's to make — in the person's own tree, where it is
    // an ordinary file of theirs named like a record.
    assert_eq!(report["arg_write"], "ok", "{report}");
    assert_eq!(report["arg_read"], format!("ok: {body}"), "{report}");

    let members = store.list_members().await.expect("the membership set lists");
    assert!(
        members.iter().all(|m| m.did != FORGED),
        "an app wrote a member the daemon reads as its own: {members:?}"
    );
    assert!(
        !members.iter().any(|m| m.did == FORGED && m.in_paired_key_allowlist()),
        "an app's write reached the paired-key allowlist: {members:?}"
    );
    assert!(
        store.read_member(FORGED).await.expect("a lookup").is_none(),
        "the forged member reads back from the daemon's records"
    );
}

/// **A grant on `/` reaches every file of the person's and no record of the
/// daemon's** — and the shell's Files view, which is that grant's listing,
/// shows neither `network/` nor `messages/`.
///
/// Both kinds of thing are in the store: files written the way `kotton fs
/// write` writes them, and a member and a read mark written the way the
/// daemon's own domain code writes them. The probe lists its handle's root,
/// then reads the member record by the path it used to have, and gets nothing
/// either way. That the Files view's delete cannot reach a member either — it
/// unpaired devices on the branch the assessor refused — is proved at the
/// store by `a_path_in_the_persons_tree_cannot_name_a_daemon_record`, which
/// holds every verb, delete included, to the rooted key.
#[tokio::test]
async fn a_grant_on_the_whole_tree_reaches_every_file_and_no_daemon_record() {
    use kotton_peer::membership::Membership as _;
    const REAL: &str = "did:key:z6MkTheirOtherLaptop";

    let (mut env, app_id) = a_person_with_the_probe_installed().await;
    env.client.write_file("owner", "/top.md", b"a file of theirs").await.expect("write");
    env.client
        .write_file("owner", "/notes/a.md", b"another, one folder down")
        .await
        .expect("write");
    let store = env.users.get("owner").expect("the person's store is loaded");
    store
        .write_member(&own_device(REAL, "their other laptop"))
        .await
        .expect("the daemon writes a member");
    store
        .write_daemon_object("/messages/read/did:key:z6MkSarah", b"{\"read_up_to\":1}")
        .await
        .expect("the daemon writes a read mark");

    let listed = launch_with(&mut env, &app_id, vec![("list".to_string(), String::new())]).await;
    assert_eq!(
        listed_names(&listed),
        vec!["notes".to_string(), "top.md".to_string()],
        "the Files view of the whole tree is not exactly the person's files: {listed}"
    );

    let read = launch_with(
        &mut env,
        &app_id,
        vec![("read".to_string(), format!("network/members/{REAL}"))],
    )
    .await;
    assert!(
        read["arg_read"].as_str().unwrap_or("").starts_with("err"),
        "an app read the daemon's member record: {read}"
    );

    let top = launch_with(&mut env, &app_id, vec![("read".to_string(), "top.md".to_string())]).await;
    assert_eq!(top["arg_read"], "ok: a file of theirs", "{top}");
    let inner =
        launch_with(&mut env, &app_id, vec![("read".to_string(), "notes/a.md".to_string())]).await;
    assert_eq!(inner["arg_read"], "ok: another, one folder down", "{inner}");

    let members = store.list_members().await.expect("the membership set lists");
    assert!(
        members.iter().any(|m| m.did == REAL && m.in_paired_key_allowlist()),
        "the daemon's own member is gone: {members:?}"
    );
    assert_eq!(
        store
            .read_daemon_object("/messages/read/did:key:z6MkSarah")
            .await
            .expect("the read mark is still there"),
        b"{\"read_up_to\":1}"
    );
}

/// **A grant on `/` cannot list or read the person's name**
/// (`TASK-a-persons-name-travels-with-their-identity`).
///
/// The name is one of the daemon's records in the person's store, written by
/// `kuserd::own_name::write` — the writer the welcome and Settings both reach —
/// at a key outside the person's tree. The probe holds `files.read` and
/// `files.write` on `/`, the shell's grant: its listing of the root shows the
/// person's one file and no `identity/`, and a read of the name's key by its
/// own spelling, with and without the leading slash, is refused. The record is
/// still there afterwards, so the refusals are the grant's and not an absence.
#[tokio::test]
async fn a_grant_on_the_whole_tree_cannot_list_or_read_the_persons_name() {
    let (mut env, app_id) = a_person_with_the_probe_installed().await;
    env.client.write_file("owner", "/top.md", b"a file of theirs").await.expect("write");
    let store = env.users.get("owner").expect("the person's store is loaded");
    kuserd::own_name::write(&store, "Austin").await.expect("the daemon keeps the name");

    let listed = launch_with(&mut env, &app_id, vec![("list".to_string(), String::new())]).await;
    assert_eq!(
        listed_names(&listed),
        vec!["top.md".to_string()],
        "the whole tree's listing shows the name's key: {listed}"
    );

    let key = kuserd::own_name::NAME_PATH;
    for spelling in [key.trim_start_matches('/'), key] {
        let read = launch_with(&mut env, &app_id, vec![("read".to_string(), spelling.to_string())]).await;
        assert!(
            read["arg_read"].as_str().unwrap_or("").starts_with("err"),
            "an app read the person's name at {spelling}: {read}"
        );
        assert!(
            !read.to_string().contains("Austin"),
            "the name reached an app through {spelling}: {read}"
        );
    }

    assert_eq!(
        kuserd::own_name::read(&store).await.expect("the record reads"),
        Some(kuserd::own_name::NameRecord { name: Some("Austin".to_string()) }),
        "the name is still kept, so the refusals were the grant's"
    );
}

/// **A launch on a file the person picked hands the app that file, found in
/// the store** — the powerbox hand-off, through a real daemon and a real
/// runner.
///
/// `hand_over_picked_file` asks the person's tree whether the path names a
/// file before it mints a grant on it; until this test only a unit test with
/// a seeded double held that lookup, and no suite test launched with a picked
/// path at all. Here the file is written the way `kotton fs write` writes it,
/// the launch carries its path as the occupant's would, and the app reads it
/// through the one handle the mint shaped — by its own name, which is all the
/// hand-off tells it.
#[tokio::test]
async fn an_app_launched_on_a_picked_file_reads_it_from_the_store() {
    let (mut env, app_id) = a_person_with_the_probe_installed().await;
    env.client
        .write_file("owner", "/notes/picked.md", b"the file the person chose")
        .await
        .expect("write");

    let report = launch_with(
        &mut env,
        &app_id,
        vec![("path".to_string(), "/notes/picked.md".to_string())],
    )
    .await;
    assert_eq!(
        report["picked_name"], "picked.md",
        "the hand-off did not rewrite the path to the file's own name: {report}"
    );
    assert_eq!(
        report["picked"], "ok: the file the person chose",
        "the app could not read the file it was handed: {report}"
    );
}

/// **An app granted the whole tree cannot name, list, read or overwrite a
/// model's weights** —
/// `TASK-a-models-weights-are-the-daemons-and-no-files-grant-reaches-them`.
///
/// A model is installed the way `kotton model add` installs one: the weights
/// through their own chunked door, then the manifest. The probe, holding
/// `files.read` and `files.write` on `/`, then lists its root and sees no
/// `models/`; reads the weights by the path they rested at until 2026-09-24
/// and gets nothing; and writes other bytes there — which lands, as an
/// ordinary file of the person's, and changes nothing about the model:
/// `ModelAdd` re-hashes the daemon's object and still finds the installed
/// weights, and the daemon's object is still those bytes.
#[tokio::test]
async fn an_app_granted_the_whole_tree_cannot_reach_a_models_weights() {
    use kotton::{Licence, ModelFormat, ModelKind, ModelManifest};

    let (mut env, app_id) = a_person_with_the_probe_installed().await;
    let body: Vec<u8> = (0..4096u32).map(|i| (i as u8) ^ 0x5a).collect();
    let hash = blake3::hash(&body).to_hex().to_string();
    let manifest = ModelManifest {
        name: "the-persons-model".to_string(),
        version: "1".to_string(),
        weights: hash.clone(),
        format: ModelFormat::Gguf,
        kind: ModelKind::Chat,
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
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("weights.gguf");
    std::fs::write(&file, &body).expect("write the weights file");
    env.client
        .model("owner")
        .add(&file, &manifest)
        .await
        .expect("kotton model add installs the model");
    env.client.write_file("owner", "/top.md", b"a file of theirs").await.expect("write");

    // List: the whole tree is the person's files, and no `models/`.
    let listed = launch_with(&mut env, &app_id, vec![("list".to_string(), String::new())]).await;
    assert_eq!(
        listed_names(&listed),
        vec!["top.md".to_string()],
        "an app granted `/` lists something of the model's: {listed}"
    );

    // Read, by the path the weights used to have.
    let old_path = format!("models/{hash}.weights");
    let read = launch_with(&mut env, &app_id, vec![("read".to_string(), old_path.clone())]).await;
    assert!(
        read["arg_read"].as_str().unwrap_or("").starts_with("err"),
        "an app read the model's weights: {read}"
    );

    // Overwrite: the write lands, as a file of the person's, and the model
    // does not see it.
    let forged = "weights an app would have a model run";
    let wrote = launch_with(
        &mut env,
        &app_id,
        vec![
            ("write".to_string(), old_path.clone()),
            ("body".to_string(), forged.to_string()),
        ],
    )
    .await;
    assert_eq!(wrote["arg_write"], "ok", "{wrote}");
    assert_eq!(wrote["arg_read"], format!("ok: {forged}"), "{wrote}");

    let store = env.users.get("owner").expect("the person's store is loaded");
    assert_eq!(
        store.read_file(&format!("/{old_path}")).await.expect("the app's file"),
        forged.as_bytes(),
        "the app's write is an ordinary file in the person's tree"
    );
    assert_eq!(
        store
            .read_daemon_object(&old_path)
            .await
            .expect("the daemon's object for the model"),
        body,
        "an app's write reached the model's weights"
    );
    env.client
        .model_add("owner", &manifest)
        .await
        .expect("the installed weights still verify: `ModelAdd` never read the app's file");

    // And the person's own listing and removal still work.
    let models = env.client.model_list("owner").await.expect("kotton model ls");
    assert_eq!(models.len(), 1, "{models:?}");
    env.client
        .model_remove("owner", "the-persons-model")
        .await
        .expect("kotton model rm");
    assert!(env.client.model_list("owner").await.expect("ls").is_empty());
    assert!(
        store.read_daemon_object(&old_path).await.is_err(),
        "removing the model left its weights"
    );
    assert_eq!(
        store.read_file(&format!("/{old_path}")).await.expect("still theirs"),
        forged.as_bytes(),
        "removing a model deleted a file of the person's"
    );
}
