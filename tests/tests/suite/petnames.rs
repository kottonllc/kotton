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
use kotton_shell::grant_prompt::{DIFFERS, DIFFERS_UNSIGNED, NOT_HELD};
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

/// `<key's did>/<name>`'s definition, signed by `key`, as `schema register` takes it.
fn a_signed_schema(key: &SigningKey, name: &str) -> String {
    use kotton_schemas::{FieldType, SchemaDefinition, SchemaField, SchemaId};
    let id = SchemaId::parse(format!("{}/{name}", publisher_of(key))).unwrap();
    let mut def = SchemaDefinition::new(id, 1, vec![SchemaField::required("amount", FieldType::String)])
        .with_description("A bank statement line.");
    kotton_crypto::schema_signature::sign(&mut def, key).unwrap();
    serde_json::to_string(&def).unwrap()
}

/// The device's line saying who signed an app's code, for a key the person calls `name`.
fn signed_by(name: &str) -> String {
    format!("This app's code is signed by a publisher you call \"{name}\".")
}

/// The device's line for a held schema whose publisher the person calls `name`.
fn reads_from(name: &str) -> String {
    format!("  read your records of a schema published by a publisher you call \"{name}\"")
}

/// **A petname given on device A is on device B after a bare `sync` on each, and a grant
/// prompt on B names the publisher by it; a prompt for a schema whose publisher the person
/// has not named says so** (kotton #471's done-when). The device's own lines come first: who
/// signed the app's code, by the person's name for the key, and that what the app asks for is
/// signed by no one; the app's words follow, quoted. The first meeting with the bank's key is
/// on A, after the prompt is shown, where the person names it; on B the same prompt names it
/// with nothing asked. A schema neither device holds is attributed to no one, even when it
/// cites the named bank's key; an app nobody signed asking for the bank's schema has its own
/// line saying the two differ. A name given to a second key is said to be taken, with the key,
/// kept on an explicit yes, and from then on shown as shared, with the key each line is.
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
    let (mut client_a, mut client_b, _node_b) =
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

    // The bank publishes `statement`, and both devices hold its signed definition.
    let apps = tempfile::tempdir().unwrap();
    let bank = SigningKey::from_bytes(&[7u8; 32]);
    let bank_key = publisher_of(&bank).to_string();
    let definition = a_signed_schema(&bank, "statement");
    client_a.schema_register(USER, &definition).await.expect("A holds the bank's statement");
    client_b.schema_register(USER, &definition).await.expect("B holds the bank's statement");
    let statement = format!("{bank_key}/statement");
    let notes = kotton_common::namespace::NSID_NOTES.to_string();
    let ledger = an_app(&apps.path().join("ledger"), "Ledger", Some(&bank), std::slice::from_ref(&statement), &[notes]);

    done(on_a(line(&["sync"]), &[]).await);
    done(on_b(line(&["sync"])).await);

    // B first, before A names the key: not named, with the key, and nothing asked of nobody.
    let before = done(on_b(line(&["app", "sideload", &ledger])).await);
    let unnamed_bank = format!("This app's code is signed by a publisher you have not named ({bank_key}).");
    assert!(before.text.trim_start().starts_with(&unnamed_bank), "the device's line is not first: {}", before.text);
    assert!(before.text.contains(kotton_shell::grant_prompt::ASKS_UNSIGNED), "{}", before.text);
    assert!(
        before.text.contains(&format!("  read your records of a schema published by a publisher you have not named ({bank_key})")),
        "{}",
        before.text
    );
    assert!(before.text.contains("  | the app's name: \"Ledger\""), "{}", before.text);
    assert!(before.text.contains("  | its publisher's name for it: \"statement\""), "{}", before.text);
    assert!(!before.text.contains("Name:") && !before.text.contains("Name it now"), "{}", before.text);

    // The first meeting, on A: the prompt is shown, then the person names the bank's key, and
    // the prompt then says that name.
    let met = done(on_a(line(&["app", "sideload", &ledger]), &["My Bank"]).await);
    let shown = met.text.find(&unnamed_bank).expect("the prompt, shown before the question");
    let asked = met.text.find("Name it now").expect("the question");
    assert!(shown < asked, "the name was asked for before the prompt was shown: {}", met.text);
    let after_naming = &met.text[asked..];
    assert!(after_naming.contains(&signed_by("My Bank")), "{}", met.text);
    assert!(after_naming.contains(&reads_from("My Bank")), "{}", met.text);
    assert!(
        after_naming.contains("  write your records of a schema published by a publisher you call \"kotton\""),
        "{}",
        met.text
    );
    assert!(after_naming.contains(DIFFERS), "the two publishers differ, and nothing said so: {}", met.text);
    assert!(met.text.contains("Nothing has been installed."), "{}", met.text);

    done(on_a(line(&["sync"]), &[]).await);
    done(on_b(line(&["sync"])).await);

    // B, after a bare sync on each: the name the person gave on A, with nothing asked.
    let after = done(on_b(line(&["app", "sideload", &ledger])).await);
    assert!(after.text.trim_start().starts_with(&signed_by("My Bank")), "{}", after.text);
    assert!(after.text.contains(&reads_from("My Bank")), "{}", after.text);
    // The short form resolves by it too: to the bank's identity.
    let listed = on_b(line(&["record", "list", "--schema", "My Bank/statement"])).await;
    assert!(!listed.text.contains("no key has the name"), "{}", listed.text);

    // A publisher the person has not named, for the app, and a schema no device holds: the
    // schema is attributed to no one, and no line says the publishers differ.
    let stranger = SigningKey::from_bytes(&[9u8; 32]);
    let other = SigningKey::from_bytes(&[11u8; 32]);
    let theirs = format!("{}/ledger.entry", publisher_of(&other));
    let odd = an_app(&apps.path().join("odd"), "Odd", Some(&stranger), std::slice::from_ref(&theirs), &[]);
    let unnamed = done(on_b(line(&["app", "sideload", &odd])).await);
    assert!(
        unnamed.text.trim_start().starts_with(&format!("This app's code is signed by a publisher you have not named ({}).", publisher_of(&stranger))),
        "{}",
        unnamed.text
    );
    assert!(unnamed.text.contains(&format!("  read your records of {NOT_HELD}")), "{}", unnamed.text);
    assert!(!unnamed.text.contains(DIFFERS), "{}", unnamed.text);

    // **A manifest citing the named bank's key with a name of its own, which no device holds,
    // prints no publisher's name on that line.**
    let forged = format!("{bank_key}/approved-by-my-bank");
    let approved = an_app(&apps.path().join("approved"), "Approved", Some(&stranger), std::slice::from_ref(&forged), &[]);
    let cited = done(on_b(line(&["app", "sideload", &approved])).await);
    let ask: Vec<&str> = cited.text.lines().skip_while(|l| !l.starts_with("It asks to:")).skip(1).take(3).collect();
    assert_eq!(ask[0], format!("  read your records of {NOT_HELD}"), "{}", cited.text);
    assert_eq!(ask[1], "  | the app's name for it: \"approved-by-my-bank\"", "{}", cited.text);
    assert!(ask.iter().all(|l| !l.contains("My Bank") && !l.contains("you call")), "{}", cited.text);

    // An app nobody signed, asking for the bank's schema: said so first, and a line of its own
    // says the app's code is not the schema's publisher's.
    let bare = an_app(&apps.path().join("bare"), "Bare", None, std::slice::from_ref(&statement), &[]);
    let unsigned = done(on_b(line(&["app", "sideload", &bare])).await);
    assert!(unsigned.text.trim_start().starts_with("This is an app nobody signed: no key signed its code."), "{}", unsigned.text);
    assert!(unsigned.text.contains(&reads_from("My Bank")), "{}", unsigned.text);
    assert!(unsigned.text.contains(DIFFERS_UNSIGNED), "{}", unsigned.text);

    // **The offer with a name already taken**: a second key named "my bank" is told the name
    // is the bank key's, shown that key, and asked again; an explicit yes keeps it.
    let imposter = SigningKey::from_bytes(&[13u8; 32]);
    let imposter_key = publisher_of(&imposter).to_string();
    let lookalike = an_app(&apps.path().join("lookalike"), "Lookalike", Some(&imposter), &[], &[]);
    let taken = done(on_a(line(&["app", "sideload", &lookalike]), &["my bank", "yes"]).await);
    let told = taken.text.find("You already gave the name \"my bank\" to another key:");
    let told = told.unwrap_or_else(|| panic!("a name already taken was not said to be: {}", taken.text));
    assert!(taken.text[told..].contains(&format!("\n  {bank_key}\n")), "the key was not shown: {}", taken.text);
    assert!(taken.text.contains("Type yes"), "{}", taken.text);
    // **Two keys with one name in the prompt**: each line says the name is shared, and which
    // key it is.
    let shared = format!("a publisher you call \"my bank\" (a name you gave 2 keys; this is {imposter_key})");
    assert!(taken.text.contains(&format!("This app's code is signed by {shared}.")), "{}", taken.text);
    let again = done(on_a(line(&["app", "sideload", &ledger]), &[]).await);
    let bank_shared = format!("a publisher you call \"My Bank\" (a name you gave 2 keys; this is {bank_key})");
    assert!(again.text.trim_start().starts_with(&format!("This app's code is signed by {bank_shared}.")), "{}", again.text);
    assert!(again.text.contains(&format!("  read your records of a schema published by {bank_shared}")), "{}", again.text);

    // A name already taken, answered with another: the other is the name.
    let third = SigningKey::from_bytes(&[17u8; 32]);
    let third_app = an_app(&apps.path().join("third"), "Third", Some(&third), &[], &[]);
    let renamed = done(on_a(line(&["app", "sideload", &third_app]), &["My Bank", "Third Bank"]).await);
    assert!(renamed.text.contains("You already gave the name \"My Bank\" to other keys:"), "{}", renamed.text);
    assert!(renamed.text.contains(&signed_by("Third Bank")), "{}", renamed.text);
}
