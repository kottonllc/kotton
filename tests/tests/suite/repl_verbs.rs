// SPDX-License-Identifier: AGPL-3.0-or-later
//! The REPL reaches the verbs `kotton` has, or says which door to use.
//!
//! `TASK-the-repl-reaches-only-five-of-the-kotton-verbs-so-recovery-needs-a-second-terminal`.
//! On 2026-09-28 the owner, living in the REPL on a headless machine, typed
//! `id add-recovery` three times and was answered with the REPL's own `id` usage
//! line: the verb existed only as `kotton id add-recovery <name>`, in a second
//! terminal.
//!
//! For the things a person meets:
//!
//! - the verb runs **through the REPL's registry** — the table the REPL itself
//!   dispatches on — as the REPL's identity, and hands back the phrase and the card;
//! - at a real terminal, the phrase appears **once**, and no recovery phrase lands in
//!   the REPL's history file;
//! - `id rotate` runs in the REPL at a real terminal, asks for the phrase and the
//!   passphrase at hidden prompts, and leaves neither in the history file, and the
//!   same REPL goes on reading the person's data under the new key. `id recover` at
//!   the REPL is `cli_identity`'s, beside the card it recovers from;
//! - `id recover` on a device that kept its sealed copy asks for a new passphrase at
//!   the same hidden prompt before it begins, and ends sealed under it; with no
//!   passphrase chosen it refuses before anything changes.

use std::sync::Arc;

use kotton::KottonClient;
use kotton_shell::out::Out;
use kotton_shell::{ExitCode, ShellState};
use tokio::sync::Mutex;

use crate::common::cli::Cli;
use crate::common::{TestEnv, TEST_PASSPHRASE};

const USER: &str = "alice";

/// The line in `text` that is a 24-word phrase, if exactly one is.
fn phrase_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| {
            let words: Vec<&str> = l.split_whitespace().collect();
            words.len() == 24 && words.iter().all(|w| w.chars().all(|c| c.is_ascii_lowercase()))
        })
        .map(str::to_string)
        .collect()
}

/// **The defect, as a test.** Red before this branch: the REPL's `id` answered
/// `add-recovery` with `usage: id list | id use <name> | id lock` and exit 1.
#[tokio::test]
async fn id_add_recovery_runs_through_the_repls_registry_and_hands_back_the_card() {
    let mut env = TestEnv::spawn().await;
    env.client.create_user(USER, TEST_PASSPHRASE).await.expect("create_user");
    let token = env.client.session_token.clone().expect("create_user binds a session");

    // The REPL's own connection: a client of its own, authenticated as its identity,
    // which is what `establish_session` builds.
    let mut client = KottonClient::connect_to(env.endpoint.clone()).await.expect("connect");
    client.authenticate(&token).await.expect("authenticate as the REPL's identity");
    let mut state = ShellState::new(USER.to_string(), Arc::new(Mutex::new(client)));

    // The registry the REPL dispatches on, as the REPL builds it.
    let executor = kotton_cli::bridge::repl_executor();
    let out = executor
        .registry()
        .execute("id", &["add-recovery".to_string()], &mut state)
        .await
        .expect("id add-recovery");

    assert!(
        matches!(out.exit_code, ExitCode::Success),
        "the REPL refused `id add-recovery`: {:?}",
        out.stderr
    );

    // The phrase is a security display, not a payload: never on `stdout`, which is
    // the channel a pipe consumes and `>` writes into a file that syncs.
    assert!(out.stdout.is_none(), "the phrase went out on stdout: {:?}", out.stdout);

    let reveals: Vec<&str> = out
        .out
        .iter()
        .filter_map(|o| match o {
            Out::Reveal(r) => Some(r.as_str()),
            _ => None,
        })
        .collect();
    let phrases: Vec<&&str> = reveals.iter().filter(|r| r.split_whitespace().count() == 24).collect();
    assert_eq!(phrases.len(), 1, "expected the phrase exactly once, got {reveals:?}");

    // The card. This identity has admitted no node, so there is nowhere a new device
    // could ask — and the card must say so, and say what to do, rather than print
    // nothing and leave the person holding a phrase with nothing to prove it to.
    let text: String = out
        .out
        .iter()
        .map(|o| match o {
            Out::Note(t) | Out::Hint(t) | Out::Reveal(t) | Out::Data(t) => t.clone(),
            Out::Warn { what, consequence } => format!("{what} {consequence}"),
            other => format!("{other:?}"),
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        text.contains("No node has a copy of your sealed keys") && text.contains("device admit"),
        "no card after the phrase:\n{text}"
    );
}

/// At a real terminal, in the REPL entered by bare `kotton`: the phrase prints once,
/// and after `id login` the REPL's history holds no phrase.
///
/// `id login` claims a name before a shell runs as it, so the REPL answers it by
/// naming the one-shot form; the answer below is consumed as a *command*, and none
/// is left over as an unasked prompt. `id rotate` and `id recover`, which the REPL
/// answers, are typed at their hidden prompts in the tests that drive them.
#[tokio::test]
async fn the_repl_prints_the_phrase_once_and_keeps_none_in_its_history() {
    let mut env = TestEnv::spawn_cli_reachable().await;
    env.client.create_user(USER, TEST_PASSPHRASE).await.expect("create_user");
    let token = env.client.session_token.clone().expect("create_user binds a session");
    let cli = Cli::for_env(&env);
    cli.seed_session(USER, &token);

    // Bare `kotton` enters as the active identity; `id use` is how a person sets it.
    let used = cli.run(&["id", "use", USER]);
    assert!(used.status.success(), "{}", crate::common::cli::said(&used));

    let session = cli.run_on_a_terminal(
        &[],
        &["id add-recovery", "id login alice", "exit"],
    );
    assert!(session.ok, "the REPL did not exit cleanly.\n{session}");

    let printed = phrase_lines(&session.transcript);
    assert_eq!(printed.len(), 1, "the phrase should print exactly once.\n{session}");
    let phrase = &printed[0];

    assert!(
        session.transcript.contains("kotton id login alice"),
        "the REPL did not name the one-shot form `kotton id login alice`.\n{session}"
    );

    // `<base>/users/<user>/history` — `history_file` in `client/shell/src/shell.rs`,
    // over `kotton_common::user_config_dir`. Asserted to exist, so a wrong path
    // fails here instead of passing on a file that was never written.
    let history_path = env.base_dir.join("users").join(USER).join("history");
    let history = std::fs::read_to_string(&history_path)
        .unwrap_or_else(|e| panic!("no REPL history at {}: {e}\n{session}", history_path.display()));
    assert!(history.contains("id login alice"), "history missed the verbs:\n{history}");
    assert!(!history.contains(phrase.as_str()), "the phrase is in the REPL's history:\n{history}");
    assert!(phrase_lines(&history).is_empty(), "a phrase-shaped line is in the history:\n{history}");
}

/// **`id rotate` runs in the REPL, asks for both secrets at hidden prompts, and
/// keeps neither in the history file.**
///
/// Red before the shell answered it: the REPL refused `id rotate` with a line
/// naming `kotton id rotate alice`, the phrase typed next was read by the line
/// editor as a command, and the history file kept it.
///
/// **Hidden** is checked at the terminal itself: the pty's transcript is everything
/// the terminal showed, including whatever it echoed of what was typed, and neither
/// secret is in it. A prompt that read a visible line would echo both there while
/// still keeping them out of the history file.
///
/// Rotation is checked where it happens — the stored identity key changed — and the
/// same REPL then goes on, on the session it already had: a rotation replaces the
/// identity key and leaves the session and the data key alone, so nothing has to be
/// re-established. `id add-recovery`, the next command, appends a key-log event
/// signed with the key in custody, and the whole log replays to the new key — so
/// the command after a rotation signed with the new key, not the retired one. And
/// the REPL reads a file it wrote before the rotation.
#[tokio::test]
async fn id_rotate_at_the_repl_asks_at_hidden_prompts_and_keeps_neither_secret_in_its_history() {
    use kotton_common::crypto::kdf_labels;

    const NOTE: &str = "written before the key rotated";

    let mut env = TestEnv::spawn_cli_reachable().await;
    env.client.create_user(USER, TEST_PASSPHRASE).await.expect("create_user");
    let phrase = env.client.add_recovery_phrase(USER).await.expect("a recovery phrase");
    env.client.write_file(USER, "notes.txt", NOTE.as_bytes()).await.expect("write a file");
    let token = env.client.session_token.clone().expect("create_user binds a session");
    let cli = Cli::for_env(&env);
    cli.seed_session(USER, &token);
    let used = cli.run(&["id", "use", USER]);
    assert!(used.status.success(), "{}", crate::common::cli::said(&used));

    let events = |env: &TestEnv| {
        kotton_identity::kel_store::load_chain(&env.base_dir, USER).expect("the key log").len()
    };
    let key = |env: &TestEnv| {
        env.runtime
            .secrets()
            .get_secret(&kdf_labels::identity_signing_key(USER))
            .expect("custody answers")
            .expect("an identity key")
    };
    let (events_before, key_before) = (events(&env), key(&env));

    // The phrase and the passphrase are answers to the two hidden prompts; were
    // either read as a REPL line instead, it would be one answer short at `exit`
    // and the run would not end cleanly.
    let session = cli.run_on_a_terminal(
        &[],
        &["id rotate", &phrase, TEST_PASSPHRASE, "id add-recovery", "cat notes.txt", "exit"],
    );
    assert!(session.ok, "the REPL did not exit cleanly.\n{session}");
    assert!(
        !session.transcript.contains(phrase.as_str()),
        "the terminal showed the phrase: it was not read at a hidden prompt.\n{session}"
    );
    assert!(
        !session.transcript.contains(TEST_PASSPHRASE),
        "the terminal showed the passphrase: it was not read at a hidden prompt.\n{session}"
    );

    // The rotation, then the add-recovery event the next command signed.
    assert_eq!(events(&env), events_before + 2, "the rotation and the next event were not both appended.\n{session}");
    let key_after = key(&env);
    assert_ne!(key_after, key_before, "the stored identity key did not change.\n{session}");
    let public_of = |hex_key: &str| {
        let bytes: [u8; 32] = hex::decode(hex_key).expect("hex").try_into().expect("32 bytes");
        ed25519_dalek::SigningKey::from_bytes(&bytes).verifying_key().to_bytes()
    };
    let replayed = kotton_identity::kel_store::resolve_current_key_for(&env.base_dir, USER, false)
        .unwrap_or_else(|e| panic!("the key log does not replay after the next command signed it: {e:#}\n{session}"))
        .expect("a key log");
    assert_eq!(replayed, public_of(&key_after), "the key log does not resolve to the new key.\n{session}");
    assert_ne!(replayed, public_of(&key_before), "the key log still resolves to the retired key.\n{session}");
    assert!(
        session.transcript.contains(NOTE),
        "the REPL could not read its own file after the rotation, on the session it had.\n{session}"
    );

    let history_path = env.base_dir.join("users").join(USER).join("history");
    let history = std::fs::read_to_string(&history_path)
        .unwrap_or_else(|e| panic!("no REPL history at {}: {e}\n{session}", history_path.display()));
    assert!(history.contains("id rotate"), "history missed the verb:\n{history}");
    assert!(!history.contains(phrase.as_str()), "the phrase is in the REPL's history:\n{history}");
    assert!(phrase_lines(&history).is_empty(), "a phrase-shaped line is in the history:\n{history}");
    assert!(!history.contains(TEST_PASSPHRASE), "the passphrase is in the REPL's history:\n{history}");
}

/// **`id recover` on a device that kept its sealed copy asks for a new passphrase at
/// the hidden prompt, and ends with the device sealed under it.**
///
/// The device holds the copy of alice's keys sealed under her passphrase, which
/// creation wrote. After the phrase, the REPL asks for a new passphrase and asks
/// again to confirm, as `kotton id create` does, at the same hidden prompt, before
/// anything is sent; the recovery replaces the key that copy seals and the copy
/// with it, sealed under the new passphrase in the same act. The pty's
/// transcript holds neither secret and says, in one line, that the copy under the
/// old passphrase is replaced; the copy on disk opens under the new passphrase to
/// this device's key and not under the old one; the history file holds neither.
#[tokio::test]
async fn id_recover_where_a_sealed_copy_was_kept_asks_for_a_new_passphrase_at_a_hidden_prompt() {
    use kotton_identity::provisioning::open_vault_under;

    /// Five distinct wordlist words, above the bar a passphrase is held to.
    const NEW_PASSPHRASE: &str = "abandon-ability-able-about-above";

    let mut env = TestEnv::spawn_cli_reachable().await;
    env.client.create_user(USER, TEST_PASSPHRASE).await.expect("create_user");
    let phrase = env.client.add_recovery_phrase(USER).await.expect("a recovery phrase");
    let token = env.client.session_token.clone().expect("create_user binds a session");
    let cli = Cli::for_env(&env);
    cli.seed_session(USER, &token);
    let used = cli.run(&["id", "use", USER]);
    assert!(used.status.success(), "{}", crate::common::cli::said(&used));
    assert!(
        open_vault_under(env.runtime.as_ref(), USER, TEST_PASSPHRASE).is_ok(),
        "the premise: this device keeps a copy sealed under the old passphrase"
    );

    // The phrase, the new passphrase and its confirmation answer the three hidden
    // prompts; were any read as a REPL line instead, the run would be an answer
    // short at `exit` and would not end cleanly.
    let session = cli.run_on_a_terminal(
        &[],
        &["id recover", &phrase, NEW_PASSPHRASE, NEW_PASSPHRASE, "exit"],
    );
    assert!(session.ok, "the REPL did not exit cleanly.\n{session}");
    assert!(
        !session.transcript.contains(phrase.as_str()),
        "the terminal showed the phrase: it was not read at a hidden prompt.\n{session}"
    );
    assert!(
        !session.transcript.contains(NEW_PASSPHRASE),
        "the terminal showed the new passphrase: it was not read at a hidden prompt.\n{session}"
    );
    assert!(
        session.transcript.contains("The copy sealed under your old passphrase is replaced."),
        "the transcript does not say the old copy is replaced.\n{session}"
    );

    let sealed = open_vault_under(env.runtime.as_ref(), USER, NEW_PASSPHRASE)
        .unwrap_or_else(|e| panic!("the copy on disk does not open under the new passphrase: {e:#}\n{session}"));
    let installed = kotton_identity::kel_store::resolve_current_key_for(&env.base_dir, USER, false)
        .expect("the key log replays")
        .expect("a key log");
    assert_eq!(
        ed25519_dalek::SigningKey::from_bytes(&sealed.identity_key).verifying_key().to_bytes(),
        installed,
        "the new copy seals a key other than the one the recovery installed.\n{session}"
    );
    assert!(
        open_vault_under(env.runtime.as_ref(), USER, TEST_PASSPHRASE).is_err(),
        "the old passphrase still opens a copy on this device.\n{session}"
    );

    let history_path = env.base_dir.join("users").join(USER).join("history");
    let history = std::fs::read_to_string(&history_path)
        .unwrap_or_else(|e| panic!("no REPL history at {}: {e}\n{session}", history_path.display()));
    assert!(history.contains("id recover"), "history missed the verb:\n{history}");
    assert!(!history.contains(phrase.as_str()), "the phrase is in the REPL's history:\n{history}");
    assert!(!history.contains(NEW_PASSPHRASE), "the new passphrase is in the REPL's history:\n{history}");
}

/// **`id recover` refuses before anything happens when no passphrase is chosen.**
/// The phrase and the passphrase are both read before `Recover` is sent, so a
/// passphrase nobody is here to give, or one not confirmed, refuses with the key
/// log and the sealed copy as they were: there is no recovered device waiting for
/// a passphrase.
#[tokio::test]
async fn id_recover_refuses_before_anything_when_no_passphrase_is_chosen() {
    let mut env = TestEnv::spawn().await;
    env.client.create_user(USER, TEST_PASSPHRASE).await.expect("create_user");
    let phrase = env.client.add_recovery_phrase(USER).await.expect("a recovery phrase");
    let token = env.client.session_token.clone().expect("create_user binds a session");
    let mut client = KottonClient::connect_to(env.endpoint.clone()).await.expect("connect");
    client.authenticate(&token).await.expect("authenticate as the REPL's identity");
    let mut state = ShellState::new(USER.to_string(), Arc::new(Mutex::new(client)));
    let sealed = env.base_dir.join("users").join(USER).join(kotton_identity::provisioning::VAULT_FILE);
    let events = || kotton_identity::kel_store::load_chain(&env.base_dir, USER).expect("the key log").len();
    let (events_before, copy_before) = (events(), std::fs::read(&sealed).expect("the sealed copy"));
    let executor = kotton_cli::bridge::repl_executor();

    for (answers, refusal) in [
        (vec![phrase.clone()], "kotton id recover alice"),
        (vec![phrase.clone(), "abandon-ability-able-about-above".to_string(), "something else".to_string()], "did not match"),
    ] {
        state.asking = kotton_shell::Asking::Given(answers.into());
        let out = executor
            .registry()
            .execute("id", &["recover".to_string()], &mut state)
            .await
            .unwrap_or_else(|e| panic!("id recover: {e:#}"));
        assert!(matches!(out.exit_code, ExitCode::Code(1)), "`id recover` did not exit 1: {:?}", out.exit_code);
        let said = out.stderr.clone().unwrap_or_default();
        assert!(said.contains(refusal), "the refusal does not say `{refusal}`: {said}");
        assert!(
            !out.out.iter().any(|o| matches!(o, Out::Reveal(_))),
            "a suggested passphrase nobody took was printed: {:?}",
            out.out
        );
    }
    assert_eq!(events(), events_before, "a refused recovery changed the key log");
    assert_eq!(std::fs::read(&sealed).expect("the sealed copy"), copy_before, "a refused recovery changed the sealed copy");
}

/// **With nobody at a terminal, `id rotate` and `id recover` ask nothing and say
/// where to run them.** A secret is never read from stdin: under a pipe, the next
/// line is the script's, and taking it for a phrase would act on it. Each verb is
/// run through the REPL's registry with nobody to answer, is refused with the
/// command to run at a terminal, and the key log is left as it was.
#[tokio::test]
async fn with_nobody_at_a_terminal_rotate_and_recover_ask_nothing_and_name_the_terminal_form() {
    let mut env = TestEnv::spawn().await;
    env.client.create_user(USER, TEST_PASSPHRASE).await.expect("create_user");
    env.client.add_recovery_phrase(USER).await.expect("a recovery phrase");
    let token = env.client.session_token.clone().expect("create_user binds a session");
    let mut client = KottonClient::connect_to(env.endpoint.clone()).await.expect("connect");
    client.authenticate(&token).await.expect("authenticate as the REPL's identity");
    let mut state = ShellState::new(USER.to_string(), Arc::new(Mutex::new(client)));
    let events = || kotton_identity::kel_store::load_chain(&env.base_dir, USER).expect("the key log").len();
    let before = events();

    let executor = kotton_cli::bridge::repl_executor();
    for verb in ["rotate", "recover"] {
        state.asking = kotton_shell::Asking::Nobody;
        let out = executor
            .registry()
            .execute("id", &[verb.to_string()], &mut state)
            .await
            .unwrap_or_else(|e| panic!("id {verb}: {e:#}"));
        assert!(!matches!(out.exit_code, ExitCode::Success), "`id {verb}` ran with nobody to ask");
        let said = out.stderr.unwrap_or_default();
        assert!(
            said.contains(&format!("kotton id {verb} {USER}")) && said.contains("terminal"),
            "`id {verb}` did not name the command to run at a terminal: {said}"
        );
    }
    assert_eq!(events(), before, "a refused verb changed the key log");
}
