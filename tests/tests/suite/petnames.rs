// SPDX-License-Identifier: AGPL-3.0-or-later
//! A grant shows who stands behind the name (kotton #471): a schema is named by the key that
//! publishes it, and a grant prompt says who stands behind a schema or an app only by the
//! person's own name for the key, a petname, or by its absence. A petname given on one device
//! is a record in Personal, so it is on the person's other devices after a bare `sync` on
//! each, and the prompt there names the publisher by it.

use crate::common::{connect_when_ready, enroll_streamed_as, init_crypto};
use crate::vault::{enrol_vault_from, spawn_device, spawn_vault};
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use kotton_schemas::membership::Posture;
use kotton_schemas::Publisher;
use kotton_shell::grant_prompt::DIFFERS;
use kotton_shell::{Asking, ExitCode, ShellState};
use kotton_sys::ipc::IpcEndpoint;

/// The user `drive_sync`'s helpers read.
const USER: &str = "alice";

/// What a line typed at a REPL answered: its exit and all it said.
struct Said {
    exit: ExitCode,
    text: String,
}

/// `words`, typed at the REPL of the daemon at `door` as the session `token`, with `answers`
/// given to whatever the line asks in place; none left is nobody there to ask.
async fn typed(door: &IpcEndpoint, who: &str, token: &str, words: &[&str], answers: &[&str]) -> Said {
    let mut client = kotton::KottonClient::connect_to(door.clone()).await.expect("a REPL connection");
    client.authenticate(token).await.expect("the REPL's identity");
    let mut state = ShellState::new(USER.to_string(), std::sync::Arc::new(tokio::sync::Mutex::new(client)));
    state.asking = Asking::Given(answers.iter().map(|a| a.to_string()).collect());
    let words: Vec<String> = words.iter().map(|w| w.to_string()).collect();
    let out = kotton_cli::bridge::repl_executor()
        .registry()
        .execute(&words[0], &words[1..], &mut state)
        .await
        .unwrap_or_else(|e| panic!("{who}$ {}: {e}", words.join(" ")));
    let mut text: String = out.out.iter().map(kotton_shell::out::render_shape).collect::<Vec<_>>().join("\n");
    for stream in [&out.stdout, &out.stderr].into_iter().flatten() {
        text.push('\n');
        text.push_str(stream);
    }
    eprintln!("{who}$ {}\n{text}\n", words.join(" "));
    Said { exit: out.exit_code, text }
}

/// An app's directory, as `app sideload` reads one: `manifest.toml` asking `reads` and
/// `writes`, and an `app.wasm` of `wasm`, signed by `signer` when there is one. The preview
/// hashes the bytes and checks the signature; it runs nothing, so they need not be a module.
fn an_app(dir: &std::path::Path, name: &str, signer: Option<&SigningKey>, reads: &[String], writes: &[String]) -> String {
    let wasm = format!("not a module: {name}").into_bytes();
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("app.wasm"), &wasm).unwrap();
    let list = |ids: &[String]| ids.iter().map(|i| format!("\"{i}\"")).collect::<Vec<_>>().join(", ");
    let mut manifest = format!(
        "[app]\nid = \"com.example.{}\"\nname = \"{name}\"\nversion = \"1.0.0\"\n\n[capabilities]\n\
         \"schema.read\" = [{}]\n\"schema.write\" = [{}]\n",
        name.to_lowercase(),
        list(reads),
        list(writes)
    );
    if let Some(key) = signer {
        let did = publisher_of(key);
        let signature = key.sign(blake3::hash(&wasm).as_bytes());
        let b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
        manifest.push_str(&format!("\n[publisher]\ndid = \"{did}\"\nsignature = \"{b64}\"\n"));
    }
    std::fs::write(dir.join("manifest.toml"), manifest).unwrap();
    dir.to_str().unwrap().to_string()
}

fn publisher_of(key: &SigningKey) -> Publisher {
    Publisher::from_ed25519_public_key(&key.verifying_key().to_bytes())
}

/// **A petname given on device A is on device B after a bare `sync` on each, and a grant
/// prompt on B names the publisher by it; a prompt for a schema whose publisher the person
/// has not named says so** (kotton #471's done-when). The first meeting with the bank's key
/// is on A, at the sideload's prompt, where the person names it; on B the same prompt names
/// it with nothing asked. An app signed by a key nobody named, asking for a schema of another
/// such key, reads "from a publisher you have not named" for both, and the line saying the two
/// publishers differ; an app with no `[publisher]` block is "from an app nobody signed".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_petname_given_on_one_device_names_the_publisher_in_a_prompt_on_another() {
    init_crypto();
    let vault = spawn_vault("vault").await;
    let a = spawn_device("device A").await;
    let mut client_a = connect_when_ready(&a.ipc, "client A").await;
    client_a.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user on A");
    let (client_a, _first) = enrol_vault_from(client_a, "device-a", &vault, USER, "vault").await;
    let b = spawn_device("device B").await;
    let client_b = connect_when_ready(&b.ipc, "client B").await;
    let (client_a, client_b, _node_b) =
        enroll_streamed_as(client_a, client_b, USER, "device-a", "device-b", Posture::Full).await;
    let token_a = client_a.session_token.clone().expect("A's session");
    let token_b = client_b.session_token.clone().expect("B's session");
    let on_a = |words: Vec<String>, answers: &'static [&'static str]| {
        let (door, token) = (a.ipc.clone(), token_a.clone());
        async move { typed(&door, "A", &token, &words.iter().map(String::as_str).collect::<Vec<_>>(), answers).await }
    };
    let on_b = |words: Vec<String>| {
        let (door, token) = (b.ipc.clone(), token_b.clone());
        async move { typed(&door, "B", &token, &words.iter().map(String::as_str).collect::<Vec<_>>(), &[]).await }
    };
    let line = |w: &[&str]| w.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let done = |said: Said| {
        assert_eq!(said.exit, ExitCode::Success, "{}", said.text);
        said
    };

    let apps = tempfile::tempdir().unwrap();
    let bank = SigningKey::from_bytes(&[7u8; 32]);
    let statement = format!("{}/statement", publisher_of(&bank));
    let notes = kotton_common::namespace::NSID_NOTES.to_string();
    let ledger = an_app(&apps.path().join("ledger"), "Ledger", Some(&bank), std::slice::from_ref(&statement), &[notes]);

    done(on_a(line(&["sync"]), &[]).await);
    done(on_b(line(&["sync"])).await);

    // B first, before A names the key: not named, and nothing asked of nobody.
    let before = done(on_b(line(&["app", "sideload", &ledger])).await);
    assert!(before.text.contains("Ledger 1.0.0 (com.example.ledger) from a publisher you have not named"), "{}", before.text);
    assert!(before.text.contains("read your statement records from a publisher you have not named"), "{}", before.text);

    // The first meeting, on A: the person names the bank's key at the prompt, and the prompt
    // then says that name.
    let met = done(on_a(line(&["app", "sideload", &ledger]), &["My Bank"]).await);
    assert!(met.text.contains("Ledger 1.0.0 (com.example.ledger) from My Bank"), "{}", met.text);
    assert!(met.text.contains("read your statement records from My Bank"), "{}", met.text);
    assert!(met.text.contains("write your notes records from kotton"), "{}", met.text);
    assert!(met.text.contains(DIFFERS), "the two publishers differ, and nothing said so: {}", met.text);
    assert!(met.text.contains("Nothing has been installed."), "{}", met.text);

    done(on_a(line(&["sync"]), &[]).await);
    done(on_b(line(&["sync"])).await);

    // B, after a bare sync on each: the name the person gave on A, with nothing asked.
    let after = done(on_b(line(&["app", "sideload", &ledger])).await);
    assert!(after.text.contains("Ledger 1.0.0 (com.example.ledger) from My Bank"), "{}", after.text);
    assert!(after.text.contains("read your statement records from My Bank"), "{}", after.text);
    // The short form resolves by it too: to the bank's identity, which B does not know.
    let listed = on_b(line(&["record", "list", "--schema", "My Bank/statement"])).await;
    assert!(!listed.text.contains("no key has the name") && listed.text.contains(&statement), "{}", listed.text);

    // A publisher the person has not named, for the app and for its schema, and an app nobody
    // signed.
    let stranger = SigningKey::from_bytes(&[9u8; 32]);
    let other = SigningKey::from_bytes(&[11u8; 32]);
    let theirs = format!("{}/ledger.entry", publisher_of(&other));
    let odd = an_app(&apps.path().join("odd"), "Odd", Some(&stranger), std::slice::from_ref(&theirs), &[]);
    let unnamed = done(on_b(line(&["app", "sideload", &odd])).await);
    assert!(unnamed.text.contains("Odd 1.0.0 (com.example.odd) from a publisher you have not named"), "{}", unnamed.text);
    assert!(unnamed.text.contains("read your ledger.entry records from a publisher you have not named"), "{}", unnamed.text);
    assert!(unnamed.text.contains(DIFFERS), "{}", unnamed.text);
    assert!(!unnamed.text.contains(&publisher_of(&other).to_string()), "a key was shown as who: {}", unnamed.text);
    let bare = an_app(&apps.path().join("bare"), "Bare", None, &[statement], &[]);
    let unsigned = done(on_b(line(&["app", "sideload", &bare])).await);
    assert!(unsigned.text.contains("Bare 1.0.0 (com.example.bare) from an app nobody signed"), "{}", unsigned.text);
    assert!(unsigned.text.contains("read your statement records from My Bank"), "{}", unsigned.text);
}
