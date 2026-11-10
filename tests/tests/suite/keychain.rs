// SPDX-License-Identifier: AGPL-3.0-or-later
//! The keychain is records (kotton #449): a secret set on one device is read on another after
//! a bare `sync`, the vault that keeps `personal` reads none of it, and at the terminal the
//! value is never a word of the line, is read hidden or from stdin, and is printed by `get`
//! alone.

use crate::common::cli::{said, Cli};
use crate::common::{connect_when_ready, enroll_streamed_as, init_crypto, TestEnv};
use crate::drive_sync::personal_tree;
use crate::records_drive::the_vault_keeping_it_reads_none_of;
use crate::vault::{enrol_vault_from, spawn_device, spawn_vault};
use kotton_schemas::membership::Posture;
use kotton_shell::{Asking, ExitCode, ShellState};
use kotton_sys::ipc::IpcEndpoint;
use std::io::Write as _;

/// The user `drive_sync`'s helpers read.
const USER: &str = "alice";

/// What a line typed at a REPL answered: its exit, its stdout payload, and all it said.
struct Said {
    exit: ExitCode,
    data: String,
    text: String,
}

/// `words`, typed at the REPL of the daemon at `door` as the session `token`, with `answers`
/// given to whatever the line asks in place (the value `secret set` reads).
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

/// **A secret set on one device is read on the second after a bare `sync` on each, and the
/// vault that keeps `personal` holds none of its value's bytes or its label** (kotton #449's
/// done-when).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_secret_set_on_one_device_is_read_on_another_and_the_vault_reads_none_of_it() {
    const LABEL: &str = "keychain-label-5c1e";
    const VALUE: &str = "keychain-value-9b27d4e1f0a3";
    init_crypto();
    let vault = spawn_vault("vault").await;
    let a = spawn_device("device A").await;
    let mut client_a = connect_when_ready(&a.ipc, "client A").await;
    client_a.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user on A");
    let (client_a, first) = enrol_vault_from(client_a, "device-a", &vault, USER, "vault").await;
    let b = spawn_device("device B").await;
    let client_b = connect_when_ready(&b.ipc, "client B").await;
    let (client_a, client_b, _node_b) =
        enroll_streamed_as(client_a, client_b, USER, "device-a", "device-b", Posture::Full).await;
    let token_a = client_a.session_token.clone().expect("A's session");
    let token_b = client_b.session_token.clone().expect("B's session");
    let on_a = |words: &'static [&'static str], answers: &'static [&'static str]| {
        let (door, token) = (a.ipc.clone(), token_a.clone());
        async move { typed(&door, "A", &token, words, answers).await }
    };
    let on_b = |words: &'static [&'static str]| {
        let (door, token) = (b.ipc.clone(), token_b.clone());
        async move { typed(&door, "B", &token, words, &[]).await }
    };
    let done = |said: Said| {
        assert_eq!(said.exit, ExitCode::Success, "{}", said.text);
        said
    };

    done(on_a(&["sync"], &[]).await);
    done(on_b(&["sync"]).await);

    let set = done(on_a(&["secret", "set", LABEL], &[VALUE]).await);
    assert!(!set.text.contains(VALUE), "set said the value: {}", set.text);
    let missing = on_b(&["secret", "get", LABEL]).await;
    assert_eq!(missing.exit, ExitCode::Code(1), "B read a secret before any sync: {}", missing.text);
    assert!(missing.data.is_empty());

    done(on_a(&["sync"], &[]).await);
    done(on_b(&["sync"]).await);

    let got = done(on_b(&["secret", "get", LABEL]).await);
    assert_eq!(got.data, VALUE, "B read another value");
    let listed = done(on_b(&["secret", "list"]).await);
    assert!(listed.text.contains(LABEL) && listed.text.contains("password"), "{}", listed.text);
    assert!(!listed.text.contains(VALUE), "list printed a value: {}", listed.text);

    let at_first = personal_tree(&a, &first.pubkey_hex).await;
    the_vault_keeping_it_reads_none_of(&vault, &at_first, &[VALUE, LABEL]).await;
}

/// A daemon the `kotton` binary can reach, `USER` on it, and a CLI holding their session.
async fn a_terminal() -> (TestEnv, Cli) {
    let mut env = TestEnv::spawn_cli_reachable().await;
    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let cli = Cli::for_env(&env);
    cli.seed_session(USER, env.client.session_token.as_deref().expect("alice logged in"));
    (env, cli)
}

/// **At the terminal the value is never a word of the line.** `kotton secret set` reads it
/// from stdin when stdin is no terminal, and at a hidden prompt, asked twice, when it is one,
/// where what is typed is not echoed; neither prints it. `get` prints the value alone, one
/// line on stdout. A value on the line is refused, exit 2, without being said back. `generate`
/// keeps a value it does not print, which `get` then reads; `rm` removes it.
#[tokio::test]
async fn at_the_terminal_a_value_is_read_hidden_or_from_stdin_and_printed_by_get_alone() {
    const PIPED: &str = "piped-value-3e8a1c77";
    const TYPED: &str = "typed-value-d45f0b19";
    let (env, cli) = a_terminal().await;

    let mut child = cli.spawn_on_pipes(&["secret", "--user", USER, "set", "bank", "--note", "the bank"]);
    child.stdin.take().expect("stdin").write_all(format!("{PIPED}\n").as_bytes()).expect("write the value");
    let set = child.wait_with_output().expect("secret set");
    assert!(set.status.success(), "{}", said(&set));
    assert!(!said(&set).contains(PIPED), "set printed the value: {}", said(&set));

    let got = cli.run(&["secret", "--user", USER, "get", "bank"]);
    assert!(got.status.success(), "{}", said(&got));
    assert_eq!(String::from_utf8_lossy(&got.stdout), format!("{PIPED}\n"), "{}", said(&got));

    let typed = cli.run_on_a_terminal(&["secret", "--user", USER, "set", "mail", "--kind", "token"], &[TYPED, TYPED]);
    assert!(typed.ok, "{typed}");
    assert!(!typed.transcript.contains(TYPED), "the value was echoed: {typed}");
    let got = cli.run(&["secret", "--user", USER, "get", "mail"]);
    assert_eq!(String::from_utf8_lossy(&got.stdout), format!("{TYPED}\n"), "{}", said(&got));

    let refused = cli.run(&["secret", "--user", USER, "set", "bank", "hunter2"]);
    assert_eq!(refused.status.code(), Some(2), "{}", said(&refused));
    assert!(!said(&refused).contains("hunter2"), "the refusal said the value: {}", said(&refused));
    let still = cli.run(&["secret", "--user", USER, "get", "bank"]);
    assert_eq!(String::from_utf8_lossy(&still.stdout), format!("{PIPED}\n"), "a refused line changed it");

    let listed = cli.run(&["secret", "--user", USER, "list"]);
    assert!(listed.status.success(), "{}", said(&listed));
    let shown = said(&listed);
    assert!(shown.contains("bank") && shown.contains("the bank") && shown.contains("mail") && shown.contains("token"), "{shown}");
    assert!(!shown.contains(PIPED) && !shown.contains(TYPED), "list printed a value: {shown}");

    let generated = cli.run(&["secret", "--user", USER, "generate", "wifi", "--length", "24"]);
    assert!(generated.status.success(), "{}", said(&generated));
    let value = cli.run(&["secret", "--user", USER, "get", "wifi"]);
    let value = String::from_utf8_lossy(&value.stdout).trim_end_matches('\n').to_string();
    assert_eq!(value.chars().count(), 24, "{value:?}");
    assert!(!said(&generated).contains(&value), "generate printed its value: {}", said(&generated));
    let again = cli.run(&["secret", "--user", USER, "generate", "wifi"]);
    assert_eq!(again.status.code(), Some(1), "generate replaced a secret: {}", said(&again));

    let rm = cli.run(&["secret", "--user", USER, "rm", "wifi"]);
    assert!(rm.status.success(), "{}", said(&rm));
    let gone = cli.run(&["secret", "--user", USER, "get", "wifi"]);
    assert_eq!(gone.status.code(), Some(1), "{}", said(&gone));
    assert!(gone.stdout.is_empty(), "{}", said(&gone));
    drop(env);
}

/// **One label is one secret.** `set` on a label kept writes that record again under its id:
/// the value is the new one, the note it had is kept, and `list` names the label once.
#[tokio::test]
async fn set_on_a_label_kept_replaces_its_value_and_keeps_its_note() {
    let (mut env, cli) = a_terminal().await;
    for (value, extra) in [("first-value-11", &["--note", "kept note"][..]), ("second-value-22", &[][..])] {
        let mut args = vec!["secret", "--user", USER, "set", "bank"];
        args.extend_from_slice(extra);
        let mut child = cli.spawn_on_pipes(&args);
        child.stdin.take().expect("stdin").write_all(format!("{value}\n").as_bytes()).expect("write");
        let set = child.wait_with_output().expect("secret set");
        assert!(set.status.success(), "{}", said(&set));
    }
    let got = cli.run(&["secret", "--user", USER, "get", "bank"]);
    assert_eq!(String::from_utf8_lossy(&got.stdout), "second-value-22\n", "{}", said(&got));
    let listed = said(&cli.run(&["secret", "--user", USER, "list"]));
    assert_eq!(listed.matches("bank").count(), 1, "{listed}");
    assert!(listed.contains("kept note"), "{listed}");
    let rows = env
        .client
        .record_query_in(USER, Some(kotton_wire::ipc::PERSONAL_ROOT), None, kotton_common::namespace::NSID_SECRET, vec![], None, None)
        .await
        .expect("the person's own query");
    assert_eq!(rows.len(), 1, "two records under one label: {rows:?}");
    drop(env);
}
