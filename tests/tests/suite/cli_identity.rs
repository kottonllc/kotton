// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `id` subcommands, run as separate `kotton` processes.
//!
//! ## What this suite is for
//!
//! Not the daemon — `user_lifecycle` covers that, through a library client, and
//! covered it correctly while six of the eleven `id` subcommands were broken.
//! This is for what the library path structurally cannot see: **a fresh process
//! with a fresh connection, finding the daemon and its session for itself.**
//!
//! `TASK-six-id-subcommands-connected-without-a-session` is the defect. It lived
//! for months behind a green suite, and it was found by a person typing a command.
//! That is the loop this file closes. See `common/cli.rs` for what the child gets
//! and what is deliberately not faked.

use crate::common::cli::{said, Cli};
use crate::common::{TestEnv, TEST_PASSPHRASE};

const USER: &str = "alice";

/// The passphrase a recovered device is sealed under: five distinct wordlist words,
/// above the bar a passphrase is held to.
const NEW_PASSPHRASE: &str = "abandon-ability-able-about-above";

/// Words that prove nothing: the first BIP-39 test vector, a phrase of the list that
/// is no authority for anyone.
const NOT_THEIRS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                          abandon abandon abandon abandon abandon abandon abandon abandon \
                          abandon abandon abandon abandon abandon abandon abandon art";

/// Create `USER` on a CLI-reachable daemon and give a child process the session a
/// person would have after `id create` or `id unlock`.
async fn ready() -> (TestEnv, Cli) {
    let mut env = TestEnv::spawn_cli_reachable().await;
    env.client
        .create_user(USER, TEST_PASSPHRASE)
        .await
        .expect("create_user");
    let token = env
        .client
        .session_token
        .clone()
        .expect("create_user binds a session token to the client");
    let cli = Cli::for_env(&env);
    cli.seed_session(USER, &token);
    (env, cli)
}

/// **The defect, end to end.**
///
/// Red before 2026-09-11: `IdCommand::execute` opened `KottonClient::connect()`,
/// which never authenticates, so the daemon refused `AddRecoveryPhrase` with
/// `NoActiveSession` and the CLI exited non-zero. This is the assertion the whole
/// file exists for, and note what it is *not*: it does not check any wording. It
/// checks that the command a person runs, from a process, works.
#[tokio::test]
async fn add_recovery_from_a_fresh_process_succeeds() {
    let (_env, cli) = ready().await;

    let out = cli.run(&["id", "add-recovery", USER]);
    assert!(out.status.success(), "`kotton id add-recovery` failed.\n{}", said(&out));

    // A phrase came back, which is the point of the command. Twenty-four words,
    // printed once; asserting the count rather than the words keeps this a test of
    // behaviour and not of copy.
    let stdout = String::from_utf8_lossy(&out.stdout);
    let longest = stdout
        .lines()
        .map(|l| l.split_whitespace().count())
        .max()
        .unwrap_or(0);
    assert_eq!(longest, 24, "no 24-word phrase in the output.\n{}", said(&out));
}

/// The other five that were broken the same way, each from its own process.
///
/// `rm` is last because it removes the user. `rotate` and `bind-device` prompt for a
/// secret after connecting, so with no terminal they fail — but they must fail
/// *there*, having authenticated, rather than being refused at the daemon.
/// `set-passphrase` prompts too. `recover` asks for everything before it connects
/// and opens its own session by the words, so with no terminal it fails before
/// reaching the daemon at all. So what this asserts for those four is the thing
/// that was wrong: that the failure is never the daemon refusing an
/// unauthenticated connection.
#[tokio::test]
async fn the_session_scoped_subcommands_reach_the_daemon() {
    let (_env, cli) = ready().await;

    for args in [
        vec!["id", "rotate", USER],
        vec!["id", "recover", USER],
        vec!["id", "set-passphrase", USER],
        vec!["id", "bind-device", USER],
    ] {
        let out = cli.run(&args);
        let text = said(&out);
        assert!(
            !text.contains("unexpected response"),
            "`kotton {}` still swallows the daemon's answer.\n{text}",
            args.join(" ")
        );
        assert!(
            !text.contains("no authenticated session"),
            "`kotton {}` connected without a session.\n{text}",
            args.join(" ")
        );
    }

    // `rm --force` takes no secret at all, so it runs to completion.
    let out = cli.run(&["id", "rm", USER, "--force"]);
    assert!(out.status.success(), "`kotton id rm --force` failed.\n{}", said(&out));

    let out = cli.run(&["id", "list"]);
    let listed = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(!listed.contains(USER), "`id rm` left the identity behind.\n{listed}");
}

/// A command that needs no session still needs no session.
///
/// The fix routes six subcommands through `connect_as`, which prompts when there
/// is nothing cached. Routing the other five through it too would have made
/// `id list` — the command a person runs *to find out who they could log in as* —
/// demand a login first. This is the test that would go red if somebody "fixed"
/// the bug by authenticating everything.
#[tokio::test]
async fn a_session_less_subcommand_needs_no_session() {
    let mut env = TestEnv::spawn_cli_reachable().await;
    env.client.create_user(USER, TEST_PASSPHRASE).await.expect("create_user");
    let cli = Cli::for_env(&env);
    // Deliberately no `seed_session`.

    let out = cli.run(&["id", "list"]);
    assert!(out.status.success(), "`kotton id list` needed a session.\n{}", said(&out));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains(USER),
        "`id list` did not list the identity.\n{}",
        said(&out)
    );
}

/// When a command *does* need a session and there is none, the failure has to be
/// actionable — and it has to not hang.
///
/// This is the second half of the same defect. The daemon answered
/// `NoActiveSession`, naming the remedy, and the client discarded it at one of 119
/// identical `_` arms, so a person read `"unexpected response"` and had to go
/// source-diving. Asserting the *absence* of that string is a test of copy, which
/// is usually the wrong thing — it earns its place here because that exact string
/// is the defect, and because the positive half (it names a next step) is what a
/// person actually needs.
#[tokio::test]
async fn a_command_with_no_session_says_what_to_do() {
    let mut env = TestEnv::spawn_cli_reachable().await;
    env.client.create_user(USER, TEST_PASSPHRASE).await.expect("create_user");
    let cli = Cli::for_env(&env);
    // No `seed_session`, and the child has no terminal: exactly a script, a CI
    // job, or an agent.

    let out = cli.run(&["id", "add-recovery", USER]);
    let text = said(&out);
    assert!(!out.status.success(), "expected a refusal with no session.\n{text}");
    assert!(
        !text.contains("unexpected response"),
        "the daemon's answer was discarded — this is the defect.\n{text}"
    );
    assert!(
        text.contains("kotton login") || text.contains("terminal"),
        "the failure names no next step, so a person cannot act on it.\n{text}"
    );
}

/// The harness derives the session cache's path a second time, and this is what
/// keeps the two derivations honest.
///
/// `common::cli::session_file` mirrors `sessions_dir`, which has no form that takes
/// an environment, so there are two copies of one rule — and a second copy is only
/// safe while something compares them. The daemon's socket was the other copy until
/// `discoverable_socket` began asking `daemon_socket_path_in` for it
/// (`TASK-two-harnesses-still-derive-a-daemons-door-by-a-copy-of-the-rule`); there is
/// no second copy of that rule left here to compare.
///
/// Serial, because it sets process-wide environment variables to put this process
/// in the child's shoes.
#[test]
#[cfg(unix)]
#[serial_test::serial]
fn the_session_cache_derivation_matches_the_products() {
    let base = tempfile::tempdir().expect("tempdir");

    let saved = std::env::var("KOTTON_BASE_DIR").ok();

    // The one variable `Cli::run` gives the child that `sessions_dir` reads.
    std::env::set_var("KOTTON_BASE_DIR", base.path());

    let sessions = kotton_common::sessions_dir().expect("sessions_dir");

    match saved {
        Some(v) => std::env::set_var("KOTTON_BASE_DIR", v),
        None => std::env::remove_var("KOTTON_BASE_DIR"),
    }

    assert_eq!(
        sessions, crate::common::cli::session_file(base.path(), "alice").parent().unwrap(),
        "the harness and the product disagree about where the session cache is, so \
         `seed_session` would write a token the child never reads — and every test \
         above would pass or fail for the wrong reason"
    );
}

/// **The identity ceremony, as a sequence of separate processes, through a real
/// terminal.**
///
/// `TASK-no-test-walks-the-cli-the-way-a-person-does` left this half open: `id
/// create` reads its passphrase through `rpassword`, which opens `/dev/tty`, so
/// no test in the repository had ever run it. The seam is a terminal rather than
/// an environment variable holding a passphrase — see `Cli::run_on_a_terminal`
/// for why that distinction is not a preference.
///
/// Each command is its own process with its own connection, which is the
/// boundary every defect this suite exists for sits on.
#[tokio::test]
async fn the_ceremony_runs_as_separate_processes_at_a_terminal() {
    let env = TestEnv::spawn_cli_reachable().await;
    let cli = Cli::for_env(&env);

    // `id create` asks for a passphrase and then asks again to confirm. Two
    // answers, because that is what a person types.
    let created = cli.run_on_a_terminal(
        &["id", "create", USER],
        &[TEST_PASSPHRASE, TEST_PASSPHRASE],
    );
    assert!(created.ok, "`kotton id create` failed at a terminal.\n{created}");

    // The session `id create` cached is the one the next process finds; nothing
    // here writes it. That is the whole point of running these separately.
    let out = cli.run(&["id", "add-recovery", USER]);
    assert!(
        out.status.success(),
        "`id add-recovery` did not find the session `id create` left.\n{}",
        said(&out)
    );

    let out = cli.run(&["id", "list"]);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains(USER),
        "`id list` does not know the identity `id create` made.\n{}",
        said(&out)
    );
}

/// **The M1 demonstration, in one command.**
///
/// A person sets up recovery, writes down what the product told them to write
/// down — the twenty-four words and the vault's line — and loses everything. A
/// wiped device is given *only that printout* — no fixture value, no address only
/// the harness knew — and `kotton id recover` with no name asks for the name, the
/// words, the line and a passphrase, and ends with the identity and the person's
/// things on the machine. Before that, the same command given words that prove
/// nothing is refused and leaves the machine holding nothing, so the recovery
/// that follows starts from a machine as clean as it was.
///
/// The only channel between the two halves is the text `kotton id add-recovery`
/// printed, read the way a person reads it off paper.
///
/// **What is driven through the library, and why.** Setting up the person's side
/// — creating the identity, admitting the vault, writing a file — is library work
/// here. The vault joins by the ceremony a device enrols one by, driven through the
/// library on both sides with the six digits confirmed for them. The rest is
/// arrange rather than assert. Everything on the *recovering* side is a separate
/// `kotton` process, because that side is the claim.
///
/// **Multi-threaded on purpose.** `Cli::run` blocks until the child exits, and the
/// daemons this test runs are in *this* process. On the default current-thread
/// runtime that block freezes their accept loops, so the vault stops answering for
/// as long as `kotton` is running — and the first thing the child makes the daemon
/// do is dial it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wiped_device_given_only_the_words_and_the_line_recovers_in_one_command() {
    recover_from_the_card(None, Door::OneShot).await;
}

/// **The REPL's `id recover`, the piece, on a wiped device: it records the vault as
/// the person's drive, and the REPL's history keeps no phrase.**
///
/// The pieces `kotton id recover` runs are kept, and this drives them by hand:
/// `kotton id login` claims the name, and a bare `kotton` enters the REPL as the
/// claimed identity, where `id recover` is typed and asks for the words, the line
/// and a passphrase, as the one-shot does. No `peer add` comes first: the REPL
/// sends the same `Recover`, with the line, and the daemon adds the vault and
/// records it as the person's drive once the words prove (#80; #76, which this
/// door used to miss). The phrase is asked at a hidden prompt, read from the
/// terminal and never by the line editor, and the terminal never shows it.
///
/// The same REPL then pulls from the vault and reads the person's file back, on the
/// session it entered with — opened on the claim, which held no data key. Recovery
/// is what puts the keys back, and the daemon tells the connection that ran it so,
/// so a REPL that stayed as it was would refuse the read; this one reads.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wiped_device_recovers_in_the_repl_and_its_history_keeps_no_phrase() {
    recover_from_the_card(None, Door::Repl).await;
}

/// Where the recovering device recovers.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Door {
    /// `kotton id recover`, its own process, the whole of it.
    OneShot,
    /// The claim by hand, and `id recover` inside the REPL a bare `kotton` enters.
    Repl,
    /// `kotton id recover` on the device that set recovery up, which still holds the
    /// identity and pairs the vault.
    Held,
    /// `kotton id recover` on a device that pairs the vault for the name already, added
    /// by address and key alone (`kotton peer add`) under a claim since removed: a
    /// row that says nothing of what the node keeps.
    AddedByHand,
}

/// **`kotton id recover` makes the vault a drive on a device where it was added by
/// hand, and only once the phrase proves.** The person claimed the name, added the
/// line's vault with a plain `kotton peer add` — a row with no posture, and no drive —
/// and removed the claim, which leaves the row. Words that prove nothing are refused
/// and leave it so. The words then recover, and the vault, already paired, is
/// recorded as the person's drive — the record enrolling the vault writes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_vault_added_by_hand_becomes_a_drive_when_the_words_recover_and_not_before() {
    recover_from_the_card(None, Door::AddedByHand).await;
}

/// The drives `daemon` records for `name`: each one's vault key (hex), tenancy, the
/// node it is reached through, and that node's posture.
async fn drives_of(daemon: &kuserd::DeviceDaemon, name: &str) -> Vec<(String, String, String, Option<String>)> {
    daemon
        .drives(name)
        .await
        .expect("read the drive record")
        .into_iter()
        .map(|d| (hex::encode(d.vault_key), d.tenancy, d.node.id, d.node.posture))
        .collect()
}

/// The one drive a recovery from `line` records for `name`, reached through `label`.
fn the_lines_drive(line: &str, name: &str, label: &str) -> Vec<(String, String, String, Option<String>)> {
    let key = kotton_wire::line::InstanceLine::parse(line).expect("the card's line parses").key;
    vec![(hex::encode(key), name.to_string(), label.to_string(), Some("blind-storage".to_string()))]
}

/// **A device that already acts as someone else recovers in one command, and the
/// vault lands in the identity being recovered.**
///
/// The device holds `bob`, made active by `id use` as a person makes it. `kotton id
/// recover <name>` claims the name, adds the vault the line names to *that* name,
/// recovers it, and makes it the identity the device acts as; `bob` is not handed
/// the vault.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_acting_as_another_identity_recovers_in_one_command() {
    recover_from_the_card(Some("bob"), Door::OneShot).await;
}

/// **A device that still holds the identity recovers it in one command, and words
/// that prove nothing take back nothing that was there.**
///
/// The device is the one that set recovery up: it holds `alice`, her log, her keys,
/// a cached session and the vault, paired under the line's key and address. `kotton
/// id recover`, given the name, the words and the line, proves the words against the
/// log this device holds, finds the vault already paired where the line says and
/// adds nothing, recovers, and ends with the device acting as `alice` and her note
/// read back. Before that, the same command given words that prove nothing is
/// refused, and `alice` is still held, still listed, still has her session and still
/// reads her note: a refusal takes back only what the command wrote, and on this
/// device it wrote nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_that_holds_the_identity_recovers_it_and_a_refusal_takes_back_nothing() {
    recover_from_the_card(None, Door::Held).await;
}

/// The person's side, the card, and a new device given only the card. `someone_else`
/// is an identity the new device already holds and acts as before the recovery;
/// `None` is a device that has never held one.
async fn recover_from_the_card(someone_else: Option<&str>, door: Door) {
    use crate::common::connect_when_ready;

    const NOTE: &[u8] = b"the whole of what alice owns";

    // ── The person's side ────────────────────────────────────────────────────
    let (env, cli) = ready().await;

    // A vault that keeps and cannot read, admitted by the ceremony a device enrols
    // one by, on a second connection carrying the session the CLI uses.
    let vault = crate::vault::spawn_vault("the vault").await;
    let token = env.client.session_token.clone().expect("create_user bound a session");
    let mut alice = connect_when_ready(&env.endpoint, "alice's device").await;
    alice.authenticate(&token).await.expect("present the session");
    let (mut alice, _vault_identity) = crate::vault::enrol_vault(alice, &vault, USER, "vault").await;

    alice.write_file(USER, "notes.txt", NOTE).await.expect("write a file");
    let out = cli.run(&["sync", "--user", USER, "vault"]);
    assert!(out.status.success(), "`kotton sync vault` failed.\n{}", said(&out));
    let synced = said(&out);
    let pushed: u64 = synced
        .lines()
        .find_map(|l| l.trim().strip_prefix("pushed"))
        .and_then(|rest| rest.trim().trim_start_matches(':').trim().parse().ok())
        .unwrap_or_else(|| panic!("`sync` did not report a pushed count.\n{synced}"));
    assert!(pushed >= 1, "nothing was pushed, so there is nothing to recover.\n{synced}");

    // ── The one moment the product tells the person anything ─────────────────
    let out = cli.run(&["id", "add-recovery", USER]);
    assert!(out.status.success(), "`kotton id add-recovery` failed.\n{}", said(&out));
    // The words and the line are payloads, on stdout; the messages — the name among
    // them — go where the shell's messages go, which off a terminal is stderr. Read
    // both, the way a person reads a terminal.
    let printout = String::from_utf8_lossy(&out.stdout).to_string();
    let heard = said(&out);
    let phrase = twenty_four_words(&printout)
        .unwrap_or_else(|| panic!("no 24-word phrase in the printout.\n{heard}"));
    let line = the_vaults_line(&printout).unwrap_or_else(|| {
        panic!("`add-recovery` printed no vault's line, so a wiped device is told the words and not where to use them.\n{heard}")
    });
    assert!(
        !heard.lines().any(|l| l.trim().starts_with("kotton ")),
        "the card spells a command line to type; the line is the card.\n{heard}"
    );
    // The name, as the card says it. The fixture's `USER` is not used past this
    // point on the new device.
    let name = the_name_on_the_card(&heard)
        .unwrap_or_else(|| panic!("the card does not say whose recovery it is.\n{heard}"));

    if door == Door::Held {
        recover_where_it_is_held(&env, &cli, &name, &phrase, &line, NOTE).await;
        return;
    }

    // Everything of the person's is gone. From here on, the only things that cross
    // are the name, the words and the line — all read out of the text above.
    drop(alice);
    drop(env);

    // ── A device that has never held this identity ───────────────────────────
    let mut fresh = TestEnv::spawn_cli_reachable().await;
    let new_cli = Cli::for_env(&fresh);
    if let Some(other) = someone_else {
        fresh
            .client
            .create_user(other, TEST_PASSPHRASE)
            .await
            .expect("create the identity the device already holds");
        let token = fresh.client.session_token.clone().expect("create_user bound a session");
        new_cli.seed_session(other, &token);
        let out = new_cli.run(&["id", "use", other]);
        assert!(out.status.success(), "`kotton id use {other}` failed.\n{}", said(&out));
    }

    match door {
        Door::OneShot => {
            // Words that prove nothing are refused, and the machine holds nothing of
            // the name — so the recovery that follows runs on it as found.
            if someone_else.is_none() {
                let refused = new_cli.run_on_a_terminal(
                    &["id", "recover"],
                    &[&name, NOT_THEIRS, &line, NEW_PASSPHRASE, NEW_PASSPHRASE],
                );
                assert!(!refused.ok, "words that prove nothing recovered.\n{refused}");
                assert!(
                    refused.transcript.contains(&format!("nothing of '{name}' is left on this machine")),
                    "the refusal does not say the machine was left as it was.\n{refused}"
                );
                let out = new_cli.run(&["id", "list"]);
                assert!(
                    out.status.success() && !said(&out).contains(&name),
                    "a refused recovery left '{name}' on the machine.\n{}",
                    said(&out)
                );
                // The session the claim cached is taken back with the claim.
                let cached = crate::common::cli::session_file(&fresh.base_dir, &name);
                assert!(
                    !cached.exists(),
                    "a refused recovery left the claim's session cached at {}",
                    cached.display()
                );
                assert!(drives_of(&fresh.daemon, &name).await.is_empty(), "a refused recovery recorded a drive");
            }

            // The recovery: the name unless given, the words, the line, then a
            // passphrase and its confirmation, all asked before anything is sent.
            let (name, phrase, line) = (name.as_str(), phrase.as_str(), line.as_str());
            let (args, answers): (Vec<&str>, Vec<&str>) = match someone_else {
                None => (vec!["id", "recover"], vec![name, phrase, line, NEW_PASSPHRASE, NEW_PASSPHRASE]),
                Some(_) => (vec!["id", "recover", name], vec![phrase, line, NEW_PASSPHRASE, NEW_PASSPHRASE]),
            };
            let recovered = new_cli.run_on_a_terminal(&args, &answers);
            assert!(recovered.ok, "recovery failed on a device given only the printout.\n{recovered}");
            assert!(
                !recovered.transcript.contains(phrase) && !recovered.transcript.contains(NEW_PASSPHRASE),
                "the terminal showed the words or the passphrase: they were not read at a hidden prompt.\n{recovered}"
            );
            assert!(
                recovered.transcript.contains(&format!("'{name}' is yours on this machine again")),
                "the recovery did not end on the line that says so.\n{recovered}"
            );
            // The identity this machine acts as is the one recovered.
            let out = new_cli.run(&["whoami"]);
            assert!(
                String::from_utf8_lossy(&out.stdout).contains(&format!("you are acting as: {name}")),
                "the recovered identity is not the one this machine acts as.\n{}",
                said(&out)
            );
            // The vault the line names is the person's drive here, as `id recover`
            // added it.
            assert_eq!(
                drives_of(&fresh.daemon, name).await,
                the_lines_drive(line, name, "vault"),
                "`kotton id recover` did not record the line's vault as the person's drive"
            );
        }
        Door::AddedByHand => {
            assert!(someone_else.is_none(), "the by-hand door is driven on a device that held no identity");
            // The claim, then the line's vault by address and key alone.
            let login = new_cli.run_on_a_terminal(&["id", "login", &name], &[&phrase]);
            assert!(login.ok, "`kotton id login` refused the phrase on a fresh device.\n{login}");
            let parsed = kotton_wire::line::InstanceLine::parse(&line).expect("the card's line parses");
            let did = kotton_crypto::DidKeyMethod::from_public_key_bytes(&parsed.key)
                .expect("the line's key")
                .to_string();
            let key = hex::encode(parsed.key);
            // Under a label of the person's own, `home`, so the drive below is seen to
            // be reached through this row and not through one the recovery added.
            let out = new_cli.run(&["peer", "--user", &name, "add", "home", &did, &key, &parsed.hint]);
            assert!(out.status.success(), "`kotton peer add` of the line's vault failed.\n{}", said(&out));
            assert!(drives_of(&fresh.daemon, &name).await.is_empty(), "a plain `peer add` recorded a drive");
            // The claim goes; the name's node rows stay (`id recover`'s module doc), so
            // the vault is paired here, by hand, when the recovery begins. The claim
            // must go before the one-shot runs: `kotton id recover` after a by-hand
            // `id login` refuses the right words at its own claim (#78, open).
            let out = new_cli.run(&["id", "rm", &name, "--force"]);
            assert!(out.status.success(), "`kotton id rm --force` failed.\n{}", said(&out));

            // Words that prove nothing: refused, and the vault is still no drive.
            let refused = new_cli.run_on_a_terminal(
                &["id", "recover", &name],
                &[NOT_THEIRS, &line, NEW_PASSPHRASE, NEW_PASSPHRASE],
            );
            assert!(!refused.ok, "words that prove nothing recovered.\n{refused}");
            assert!(
                drives_of(&fresh.daemon, &name).await.is_empty(),
                "a refused recovery made the vault a drive.\n{refused}"
            );

            // The words: the vault, already paired, becomes the person's drive.
            let recovered = new_cli.run_on_a_terminal(
                &["id", "recover", &name],
                &[&phrase, &line, NEW_PASSPHRASE, NEW_PASSPHRASE],
            );
            assert!(recovered.ok, "recovery failed on a device that added its vault by hand.\n{recovered}");
            assert_eq!(
                drives_of(&fresh.daemon, &name).await,
                the_lines_drive(&line, &name, "home"),
                "`kotton id recover` did not record the vault paired by hand as the person's drive"
            );
        }
        Door::Repl => {
            assert!(someone_else.is_none(), "the REPL door is driven on a device that held no identity");
            // The claim, by hand; nothing else. The vault is the REPL's `id recover`'s
            // to add, from the line.
            let login = new_cli.run_on_a_terminal(&["id", "login", &name], &[&phrase]);
            assert!(login.ok, "`kotton id login` refused the phrase on a fresh device.\n{login}");
            assert!(drives_of(&fresh.daemon, &name).await.is_empty(), "the claim recorded a drive");

            let typed = "id recover".to_string();
            let session = new_cli.run_on_a_terminal(
                &[],
                &[&typed, &phrase, &line, NEW_PASSPHRASE, NEW_PASSPHRASE, "sync --pull vault", "cat notes.txt", "exit"],
            );
            assert!(session.ok, "the REPL did not exit cleanly.\n{session}");
            // The vault the line names is the person's drive here, as the one-shot
            // records it: the REPL's door no longer leaves it a row with no posture.
            assert_eq!(
                drives_of(&fresh.daemon, &name).await,
                the_lines_drive(&line, &name, "vault"),
                "the REPL's `id recover` did not record the line's vault as the person's drive.\n{session}"
            );
            assert!(
                !session.transcript.contains(phrase.as_str()) && !session.transcript.contains(NEW_PASSPHRASE),
                "the terminal showed the phrase or the passphrase.\n{session}"
            );
            assert!(
                session.transcript.contains(std::str::from_utf8(NOTE).expect("the note is text")),
                "the REPL did not read the person's file back on the session it recovered on.\n{session}"
            );
            let history_path = fresh.base_dir.join("users").join(&name).join("history");
            let history = std::fs::read_to_string(&history_path).unwrap_or_else(|e| {
                panic!("no REPL history at {}: {e}\n{session}", history_path.display())
            });
            assert!(history.contains(&typed), "history missed the verb:\n{history}");
            assert!(!history.contains(phrase.as_str()), "the phrase is in the REPL's history:\n{history}");
            assert!(!history.contains(NEW_PASSPHRASE), "the passphrase is in the REPL's history:\n{history}");
            assert!(
                twenty_four_words(&history).is_none(),
                "a phrase-shaped line is in the REPL's history:\n{history}"
            );
        }
        Door::Held => unreachable!("the held door recovers before the person's device is dropped"),
    }

    // And what came back is the person's data, not merely a successful exit. For the
    // one command no further sync is typed: it synced. The read is the library's, on
    // the session the recovery cached, so this stands on what the processes above
    // produced and nothing else.
    let token = std::fs::read_to_string(crate::common::cli::session_file(&fresh.base_dir, &name))
        .expect("the recovery cached a session on the recovered device");
    let mut cold = connect_when_ready(&fresh.endpoint, "the recovered device").await;
    cold.authenticate(token.trim()).await.expect("present that session");
    let got = cold.read_file(&name, "notes.txt").await.expect("read the file back");
    assert_eq!(got.as_slice(), NOTE, "the file came back changed");

    // And the identity the device already held was not handed the vault.
    if let Some(other) = someone_else {
        let out = new_cli.run(&["peer", "--user", other, "list"]);
        assert!(out.status.success(), "`kotton peer --user {other} list` failed.\n{}", said(&out));
        assert!(
            !said(&out).contains("vault"),
            "the recovery added the vault to `{other}`'s peers.\n{}",
            said(&out)
        );
    }
    drop(vault);
}

/// **`kotton device reset` starts this device fresh, and refuses until it is told
/// twice.** `TASK-a-device-has-no-verb-to-start-fresh`, `DEC-0069` §6.
///
/// The one `device` subcommand that is not the REPL's, so this is the only place
/// it can be tested the way it is used: as a process, against a base directory,
/// with **no daemon running** — which is both the state it is built for and the
/// state it insists on.
///
/// ## What this test can and cannot see
///
/// It sees the directory half: the listing names every identity found on disk,
/// the refusal without `--yes` leaves the tree untouched, and `--yes` removes it.
///
/// It **cannot** see the keychain half. A base directory under the system temp
/// dir is a throwaway root, so `secrets_for_base_dir` hands back an in-process
/// store on purpose (`core/secret/src/provider/mod.rs` — 250 permanent Windows
/// credentials were left behind before that rule existed). The purge therefore
/// runs against a store that persists nothing. What holds that half is
/// `every_device_label_is_purged` in `core/identity`, which loads the labels into
/// a store and checks they are gone; a process test that claimed to cover it
/// would be an instrument reporting on something it cannot perceive.
#[tokio::test]
async fn device_reset_lists_what_it_will_delete_and_refuses_until_told_twice() {
    let tmp = tempfile::tempdir().expect("a base dir to reset");
    let base = tmp.path();
    for id in ["alice", "bob"] {
        std::fs::create_dir_all(base.join("users").join(id)).expect("create an identity dir");
        std::fs::write(base.join("users").join(id).join("config.toml"), b"x=1")
            .expect("something inside it");
    }
    std::fs::create_dir_all(base.join("system")).expect("create system dir");
    std::fs::write(base.join("system").join("users.json"), b"{}").expect("write the registry");

    let cli = Cli::for_base(base);

    // Refuses, and says what it would take with it.
    let out = cli.run(&["device", "reset"]);
    assert!(
        !out.status.success(),
        "`device reset` without --yes must refuse.\n{}",
        said(&out)
    );
    let listing = String::from_utf8_lossy(&out.stdout).to_string();
    for id in ["alice", "bob"] {
        assert!(
            listing.contains(id),
            "the listing does not name the identity `{id}` it would delete.\n{}",
            said(&out)
        );
    }
    assert!(
        base.join("users").join("alice").exists(),
        "a refused reset deleted something.\n{}",
        said(&out)
    );

    // Told twice, it goes.
    let out = cli.run(&["device", "reset", "--yes"]);
    assert!(out.status.success(), "`device reset --yes` failed.\n{}", said(&out));
    assert!(
        !base.exists(),
        "the base directory survived `device reset --yes`.\n{}",
        said(&out)
    );
}

/// A base directory that is not there is not an error.
///
/// The second run of a reset, and the first run on a machine that has never
/// started Kotton, are the same state — and neither is a failure. A non-zero exit
/// here would make `device reset --yes` unusable in a script that does not
/// already know the answer.
#[tokio::test]
async fn device_reset_on_a_device_with_nothing_on_it_succeeds() {
    let tmp = tempfile::tempdir().expect("a parent for the missing base dir");
    let base = tmp.path().join("never-used");
    let cli = Cli::for_base(&base);

    let out = cli.run(&["device", "reset", "--yes"]);
    assert!(
        out.status.success(),
        "resetting a device with no Kotton directory must succeed.\n{}",
        said(&out)
    );
}

/// `kotton id recover` on the device that set recovery up, which still holds `name`,
/// her session and the vault the line names. Words that prove nothing first, then
/// the words. See `a_device_that_holds_the_identity_recovers_it_and_a_refusal_takes_back_nothing`.
async fn recover_where_it_is_held(env: &TestEnv, cli: &Cli, name: &str, phrase: &str, line: &str, note: &[u8]) {
    use crate::common::connect_when_ready;

    let cached = crate::common::cli::session_file(&env.base_dir, name);
    let reads_the_note = |why: &'static str| async move {
        let token = std::fs::read_to_string(crate::common::cli::session_file(&env.base_dir, name))
            .unwrap_or_else(|e| panic!("{why}: no session is cached for '{name}': {e}"));
        let mut conn = connect_when_ready(&env.endpoint, "the device that holds the identity").await;
        conn.authenticate(token.trim()).await.unwrap_or_else(|e| panic!("{why}: the cached session: {e}"));
        let got = conn.read_file(name, "notes.txt").await.unwrap_or_else(|e| panic!("{why}: read the note: {e}"));
        assert_eq!(got.as_slice(), note, "{why}: the note came back changed");
    };

    // The line is read again here with nothing made: `peer show` prints it first.
    let out = cli.run(&["peer", "--user", name, "show", "vault"]);
    assert!(
        out.status.success() && said(&out).contains(line),
        "`kotton peer --user {name} show vault` does not print the card's line.\nthe line: {line}\n{}",
        said(&out)
    );

    // Words that prove nothing, checked against the log this device holds.
    let refused = cli.run_on_a_terminal(&["id", "recover", name], &[NOT_THEIRS, line, NEW_PASSPHRASE, NEW_PASSPHRASE]);
    assert!(!refused.ok, "words that prove nothing recovered a held identity.\n{refused}");
    let out = cli.run(&["id", "list"]);
    assert!(
        out.status.success() && said(&out).contains(name),
        "a refused recovery took '{name}' off a device that held it.\n{}",
        said(&out)
    );
    assert!(cached.exists(), "a refused recovery took back the session '{name}' had before it.\n{refused}");
    reads_the_note("after the refusal").await;
    // The vault this device enrolled is its drive, and a refusal leaves it so.
    assert_eq!(drives_of(&env.daemon, name).await, the_lines_drive(line, name, "vault"), "after the refusal");

    // The words.
    let recovered = cli.run_on_a_terminal(&["id", "recover"], &[name, phrase, line, NEW_PASSPHRASE, NEW_PASSPHRASE]);
    assert!(recovered.ok, "recovery failed on the device that holds the identity.\n{recovered}");
    assert!(
        !recovered.transcript.contains(phrase) && !recovered.transcript.contains(NEW_PASSPHRASE),
        "the terminal showed the words or the passphrase.\n{recovered}"
    );
    assert!(
        recovered.transcript.contains(&format!("'{name}' is yours on this machine again")),
        "the recovery did not end on the line that says so.\n{recovered}"
    );
    let out = cli.run(&["whoami"]);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains(&format!("you are acting as: {name}")),
        "the recovered identity is not the one this device acts as.\n{}",
        said(&out)
    );
    // The vault was paired where the line says, so nothing was added beside it.
    let out = cli.run(&["peer", "--user", name, "list"]);
    assert!(
        out.status.success() && !said(&out).contains("vault-"),
        "the recovery paired the vault a second time.\n{}",
        said(&out)
    );
    assert_eq!(drives_of(&env.daemon, name).await, the_lines_drive(line, name, "vault"), "after the recovery");
    reads_the_note("after the recovery").await;
}


/// The 24 words, read off the printout the way a person reads them off a card.
fn twenty_four_words(printout: &str) -> Option<String> {
    printout
        .lines()
        .map(str::trim)
        .find(|l| l.split_whitespace().count() == 24)
        .map(str::to_string)
}

/// The vault's line on the printout, `kotton-instance:vault:<key>@<address>`, read
/// the way a person reads it off paper — parsed rather than taken from a fixture,
/// because *the printout is the only thing that crosses*.
fn the_vaults_line(printout: &str) -> Option<String> {
    printout
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("kotton-instance:vault:"))
        .map(str::to_string)
}

/// The name the card says recovery was set up for: `… set up for '<name>'.`
fn the_name_on_the_card(printout: &str) -> Option<String> {
    let at = printout.find("set up for '")? + "set up for '".len();
    let name = &printout[at..];
    Some(name[..name.find('\'')?].to_string())
}
