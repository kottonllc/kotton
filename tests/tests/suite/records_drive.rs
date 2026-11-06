// SPDX-License-Identifier: AGPL-3.0-or-later
//! A record put on one device is read on another by way of `personal`, and the vault that
//! keeps it can read none of it (kotton #38).
//!
//! Two of alice's devices and two vaults she enrolled from the first before the second
//! joined, so both devices reach both. Her first drive, `personal`, is one drive at the vault
//! enrolled first (kotton #124). Device A keeps it whole; device B keeps it on demand. Every
//! line is typed at the REPL's registry, the one parser `kotton record …` runs too, and every
//! pass is a bare `sync`: no remote is named and no wall-clock sleep is taken, since each step
//! waits on the pass or the answer it reads.
//!
//! What a vault holds is read off its disk, every file under its directory, path and bytes
//! alike: no record's fields, id or schema NSID are among them, before the move and after it,
//! at the vault `personal` left and at the one it went to.

use crate::common::{connect_when_ready, enroll_streamed_as, init_crypto};
use crate::drive_sync::{personal_tree, sealed_in, trees_at};
use crate::vault::{enrol_vault_from, spawn_device, spawn_vault, RunningDevice, RunningVault};
use kotton_schemas::membership::Posture;
use kotton_shell::{ExitCode, ShellState};
use kotton_wire::ipc::{PinValue, FIRST_DRIVE_NAME};

/// The user `drive_sync`'s helpers read.
const USER: &str = "alice";
/// The schema the records are of, cited by name. Not a core schema: a core NSID is in every
/// daemon's own database (the machine database's table definitions name `sh.kotton.notes`),
/// a vault's included, so finding it there says nothing of alice. This one is known only to
/// her two devices, each of which registers it, so it is a needle only her records carry.
const NOTES: &str = "com.example.recordsdrive.diary";

/// [`NOTES`] registered on a device of alice's, as `schema register` does.
async fn knows_the_schema(client: &mut kotton::KottonClient) {
    use kotton_schemas::field::{FieldType, SchemaField};
    let schema = kotton_schemas::definition::SchemaDefinition::new(
        kotton_schemas::nsid::Nsid::new(NOTES).unwrap(),
        1,
        vec![SchemaField::required("title", FieldType::String), SchemaField::required("body", FieldType::String)],
    );
    client.schema_register(USER, &serde_json::to_string(&schema).unwrap()).await.expect("schema register");
}

/// What a line typed at a device's REPL answered: its exit, the payload it printed on stdout,
/// and everything it said, as a person reads it.
struct Said {
    exit: ExitCode,
    data: String,
    text: String,
}

/// `words`, typed at the REPL of `device` as the person whose session `token` is. Each line
/// is written to the test's output, as the transcript.
async fn typed(device: &RunningDevice, who: &str, token: &str, words: &[&str]) -> Said {
    let mut client = kotton::KottonClient::connect_to(device.ipc.clone()).await.expect("a REPL connection");
    client.authenticate(token).await.expect("the REPL's identity");
    let mut state = ShellState::new(USER.to_string(), std::sync::Arc::new(tokio::sync::Mutex::new(client)));
    let words: Vec<String> = words.iter().map(|w| w.to_string()).collect();
    let out = kotton_cli::bridge::repl_executor()
        .registry()
        .execute(&words[0], &words[1..], &mut state)
        .await
        .unwrap_or_else(|e| panic!("{who}$ {}: {e}", words.join(" ")));
    let data: String = out
        .out
        .iter()
        .filter_map(|o| if let kotton_shell::out::Out::Data(d) = o { Some(d.as_str()) } else { None })
        .collect::<Vec<_>>()
        .join("\n");
    let mut text: String = out.out.iter().map(kotton_shell::out::render_shape).collect::<Vec<_>>().join("\n");
    for stream in [&out.stdout, &out.stderr].into_iter().flatten() {
        text.push('\n');
        text.push_str(stream);
    }
    eprintln!("{who}$ {}\n{text}\n", words.join(" "));
    Said { exit: out.exit_code, data, text }
}

/// One of alice's devices, at its REPL.
struct At<'a> {
    device: &'a RunningDevice,
    who: &'static str,
    token: String,
}

impl At<'_> {
    async fn line(&self, words: &[&str]) -> Said {
        typed(self.device, self.who, &self.token, words).await
    }

    /// A line that must be done: exit 0.
    async fn done(&self, words: &[&str]) -> Said {
        let said = self.line(words).await;
        assert_eq!(said.exit, ExitCode::Success, "{}$ {}: {}", self.who, words.join(" "), said.text);
        said
    }

    /// A bare `sync`.
    async fn sync(&self) {
        self.done(&["sync"]).await;
    }

    /// `record put --schema NOTES <body>`, and the id it printed.
    async fn put(&self, body: serde_json::Value) -> String {
        let id = self.done(&["record", "put", "--schema", NOTES, &body.to_string()]).await.data;
        assert!(!id.is_empty() && !id.contains(char::is_whitespace), "{} put printed no id: {id:?}", self.who);
        id
    }

    /// `record get --schema NOTES <id>`, as the JSON it printed.
    async fn get(&self, id: &str) -> serde_json::Value {
        let said = self.done(&["record", "get", "--schema", NOTES, id]).await;
        serde_json::from_str(&said.data).unwrap_or_else(|e| panic!("{} get printed no JSON: {e}: {}", self.who, said.text))
    }

    /// `record get` of an id no record has here: exit 1, and no payload.
    async fn get_is_missing(&self, id: &str) {
        let said = self.line(&["record", "get", "--schema", NOTES, id]).await;
        assert_eq!(said.exit, ExitCode::Code(1), "{} read a record it should not have: {}", self.who, said.text);
        assert!(said.data.is_empty(), "{}: a missing record printed a payload: {}", self.who, said.data);
    }

    /// The ids `record list --schema NOTES --json` answered, sorted.
    async fn listed(&self) -> Vec<String> {
        let said = self.done(&["record", "list", "--schema", NOTES, "--json"]).await;
        let rows: Vec<serde_json::Value> = serde_json::from_str(&said.data).expect("list --json is a JSON array");
        let mut ids: Vec<String> = rows.iter().map(|r| r["_id"].as_str().expect("a row's id").to_string()).collect();
        ids.sort();
        ids
    }
}

/// A note whose body carries `marker`, a string nothing else in the test writes.
fn note(marker: &str) -> serde_json::Value {
    serde_json::json!({ "title": "a note", "body": marker })
}

/// Every needle any file under `vault`'s directory holds, in its bytes or in its path. Each
/// needle is looked for as it is written and, for a record's id, as the sixteen bytes of the
/// UUID it spells, so a binary copy of the id is found too. Returns, with the findings, how
/// many files and bytes were read, so a scan that read nothing cannot pass.
fn readable_at(vault: &RunningVault, needles: &[&str]) -> (Vec<String>, usize, usize) {
    let mut forms: Vec<(String, Vec<u8>)> = Vec::new();
    for n in needles {
        forms.push((n.to_string(), n.as_bytes().to_vec()));
        let hex: String = n.chars().filter(|c| *c != '-').collect();
        if hex.len() == 32 {
            if let Ok(raw) = hex::decode(&hex) {
                forms.push((format!("{n} (as bytes)"), raw));
            }
        }
    }
    let (mut found, mut files, mut bytes) = (Vec::new(), 0usize, 0usize);
    let mut pending = vec![vault.base_path.clone()];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            let Ok(held) = std::fs::read(&path) else { continue };
            files += 1;
            bytes += held.len();
            let name = path.to_string_lossy().into_owned();
            for (said, form) in &forms {
                if held.windows(form.len()).any(|w| w == form.as_slice()) || name.as_bytes().windows(form.len()).any(|w| w == form.as_slice()) {
                    found.push(format!("{said} in {name}"));
                }
            }
        }
    }
    (found, files, bytes)
}

/// Neither vault holds any of `needles` where its disk can be read.
fn neither_vault_reads(vaults: &[&RunningVault], needles: &[&str]) {
    for vault in vaults {
        let (found, files, bytes) = readable_at(vault, needles);
        assert!(files > 0 && bytes > 0, "the scan of {} read nothing", vault.base_path.display());
        assert!(found.is_empty(), "a vault can read a record: {found:?}");
    }
}

/// **A record put on one device is read on another by way of `personal`, and still after
/// `personal` moves; a missing id exits 1; and neither vault can read any record's fields,
/// id or schema** (kotton #38's done-when).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_record_put_on_one_device_is_read_on_another_by_way_of_personal_wherever_it_lives() {
    init_crypto();
    let vault = spawn_vault("vault").await;
    let vault_2 = spawn_vault("vault 2").await;
    let a = spawn_device("device A").await;
    let mut client_a = connect_when_ready(&a.ipc, "client A").await;
    client_a.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user on A");
    let (client_a, first) = enrol_vault_from(client_a, "device-a", &vault, USER, "vault").await;
    let (client_a, second) = enrol_vault_from(client_a, "device-a", &vault_2, USER, "vault-2").await;
    let b = spawn_device("device B").await;
    let client_b = connect_when_ready(&b.ipc, "client B").await;
    let (client_a, client_b, _node_b) =
        enroll_streamed_as(client_a, client_b, USER, "device-a", "device-b", Posture::Full).await;
    let on_a = At { device: &a, who: "A", token: client_a.session_token.clone().expect("A's session") };
    let on_b = At { device: &b, who: "B", token: client_b.session_token.clone().expect("B's session") };

    // A keeps personal whole, as the device that made it does; B, which learns personal
    // from the vaults' listings at its first pass, keeps it on demand.
    on_a.sync().await;
    on_b.sync().await;
    on_b.done(&["pin", FIRST_DRIVE_NAME, "on-demand"]).await;
    let (mut client_a, mut client_b) = (client_a, client_b);
    knows_the_schema(&mut client_a).await;
    knows_the_schema(&mut client_b).await;
    for (who, client, want) in [("A", &mut client_a, PinValue::Whole), ("B", &mut client_b, PinValue::OnDemand)] {
        let status = client.status(USER).await.unwrap_or_else(|e| panic!("{who}'s status: {e}"));
        let held = status.drives.iter().find(|d| d.name == FIRST_DRIVE_NAME).expect("personal in status");
        assert_eq!(held.keeps, Some(want), "{who} keeps personal otherwise: {status:?}");
    }

    // personal is one drive, at the vault enrolled first.
    let at_first = personal_tree(&a, &first.pubkey_hex).await;
    assert_eq!(personal_tree(&b, &first.pubkey_hex).await, at_first, "B and A record personal apart");

    // Put on A, read on B after a sync on each.
    let one = on_a.put(note("records-drive-marker-one")).await;
    on_b.get_is_missing(&one).await;
    on_a.sync().await;
    on_b.sync().await;
    assert_eq!(on_b.get(&one).await["body"], "records-drive-marker-one", "B read another record");
    assert_eq!(on_b.listed().await, std::slice::from_ref(&one), "B's list");
    assert!(!sealed_in(&vault, &at_first).await.is_empty(), "personal at the first vault holds nothing");

    // A missing id exits 1, on either device, for `get` and for `rm`.
    let nobody = "00000000-0000-4000-8000-000000000000";
    on_a.get_is_missing(nobody).await;
    on_b.get_is_missing(nobody).await;
    let rm = on_b.line(&["record", "rm", "--schema", NOTES, nobody]).await;
    assert_eq!(rm.exit, ExitCode::Code(1), "B removed a record nobody put: {}", rm.text);

    // A second record, put on A and synced to the first vault; then personal moves.
    let two = on_a.put(note("records-drive-marker-two")).await;
    on_a.sync().await;
    on_a.done(&["drive", "move", FIRST_DRIVE_NAME, "--to", "vault-2"]).await;
    let at_second = personal_tree(&a, &second.pubkey_hex).await;
    assert!(!trees_at(&vault).contains(&at_first), "the first vault still keeps the tree personal left");

    // B follows it there at its next sync and reads, from there, what A put before the move.
    on_b.sync().await;
    assert_eq!(personal_tree(&b, &second.pubkey_hex).await, at_second, "B does not follow personal to the second vault");
    assert_eq!(on_b.get(&two).await["body"], "records-drive-marker-two", "B did not read the record the move carried");
    assert_eq!(on_b.get(&one).await["body"], "records-drive-marker-one", "B lost a record it had read");

    // After the move, each verb the other way: B puts and removes, A reads and lists.
    let three = on_b.put(note("records-drive-marker-three")).await;
    on_b.done(&["record", "rm", "--schema", NOTES, &one]).await;
    on_b.get_is_missing(&one).await;
    on_b.sync().await;
    on_a.sync().await;
    assert_eq!(on_a.get(&three).await["body"], "records-drive-marker-three", "A did not read B's record");
    on_a.get_is_missing(&one).await;
    let rm = on_a.line(&["record", "rm", "--schema", NOTES, &one]).await;
    assert_eq!(rm.exit, ExitCode::Code(1), "A removed again a record B removed: {}", rm.text);
    let mut want = vec![two.clone(), three.clone()];
    want.sort();
    assert_eq!(on_a.listed().await, want, "A's list after the move");
    assert_eq!(on_b.listed().await, want, "B's list after the move");
    assert!(!sealed_in(&vault_2, &at_second).await.is_empty(), "personal at the second vault holds nothing");

    // Neither vault reads a byte of any record: its fields, its id, or its schema's NSID.
    neither_vault_reads(
        &[&vault, &vault_2],
        &[
            "records-drive-marker-one",
            "records-drive-marker-two",
            "records-drive-marker-three",
            &one,
            &two,
            &three,
            NOTES,
        ],
    );
}
