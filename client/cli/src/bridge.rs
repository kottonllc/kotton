// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bridge: run a REPL shell verb from the standalone `kotton` CLI (terminal UX
//! Pillar 4 — one command, two doors).
//!
//! The shared verbs (`sync`, `peer`, `issuer`, …) are implemented **once**, in
//! `client/shell/src/commands/`, and the REPL runs them. This bridge lets the
//! standalone `kotton <verb>` run the *same* command: it captures the verb's raw
//! args, hands them to the identical `07_shell` command the REPL uses, and renders
//! the result through the same Pillar-3 renderer. Drift between `kotton <verb>` and
//! the REPL `<verb>` is structurally impossible — there is only one implementation.

use kotton::KottonClient;
use kotton_shell::{out, CommandOutput, ExitCode, ShellExecutor, ShellState};
use std::io;
use std::sync::Arc;
use tokio::sync::Mutex;

/// The executor the REPL runs on: every shell verb, plus a refusal naming the one-shot
/// form for each `kotton` verb the shell does not run.
///
/// The verbs are read out of the clap tree rather than listed, so a verb added to
/// `Commands` is accounted for in the REPL without anyone remembering to
/// (`TASK-the-repl-reaches-only-five-of-the-kotton-verbs-so-recovery-needs-a-second-terminal`).
pub fn repl_executor() -> ShellExecutor {
    use clap::CommandFactory;
    let verbs: Vec<String> = crate::Cli::command()
        .get_subcommands()
        .flat_map(|c| {
            std::iter::once(c.get_name().to_string())
                .chain(c.get_all_aliases().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .collect();
    ShellExecutor::with_one_shots(verbs)
}

/// Run shell verb `name` with `args` as the resolved identity, render its output,
/// and exit with its code. `user` is an explicit `--user`; it falls back to
/// `KOTTON_USER` (which the active identity populated at startup), else fails with
/// guidance.
///
/// A line the verb runs without a session (`Command::execute_without_session`) runs
/// first, with no connection made and no identity required: it is handed the one
/// named, if one was, and connects for itself if it asks the daemon anything. That is
/// how `kotton id join <name>` reaches the daemon on a device with no identity yet.
pub async fn run_verb(
    user: Option<String>,
    name: &str,
    args: Vec<String>,
    json: bool,
) -> io::Result<()> {
    let executor = ShellExecutor::new();
    let (args, json) = json_word(&executor, name, args, json);
    let named = named_user(user);
    if let Some(output) = executor
        .registry()
        .execute_without_session(name, &args, named.as_deref())
        .await
    {
        finish(output.map_err(io::Error::other)?, json, None);
    }

    let user_id = named.ok_or_else(no_active_identity)?;

    let client = KottonClient::connect_as(&user_id)
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;
    let actor = user_id.clone();
    let client = Arc::new(Mutex::new(client));
    let mut state = ShellState::new(user_id, Arc::clone(&client));

    let output = executor
        .registry()
        .execute(name, &args, &mut state)
        .await
        .map_err(io::Error::other)?;
    finish(output, json, Some(&actor));
}

/// A verb that reads `--json` among its own words is handed the word for a
/// `kotton --json <verb> …`, and its output is then rendered as it says (its JSON
/// is a payload); any other verb keeps the flag, and its shapes are serialized.
/// One parser reads `--json` for such a verb, whichever door it was typed at.
fn json_word(executor: &ShellExecutor, name: &str, mut args: Vec<String>, json: bool) -> (Vec<String>, bool) {
    if json && executor.registry().answers_json(name) {
        if !args.iter().any(|a| a == "--json") {
            args.push("--json".to_string());
        }
        return (args, false);
    }
    (args, json)
}

/// Render a verb's output and exit with its code.
fn finish(output: CommandOutput, json: bool, actor: Option<&str>) -> ! {
    // Same rendering path as the REPL: Pillar-3 shapes through the renderer, legacy
    // string stdout/stderr direct. Under `--json`, shapes serialize instead. The
    // actor trailer echoes who acted (a CLI one-shot has no persistent prompt).
    if !output.out.is_empty() {
        if json {
            out::render_json(&output.out);
        } else {
            out::render(&output.out, actor);
        }
    }
    if let Some(s) = &output.stdout {
        println!("{s}");
    }
    if let Some(e) = &output.stderr {
        eprintln!("error: {e}");
    }

    let code = match output.exit_code {
        ExitCode::Success | ExitCode::Exit => 0,
        ExitCode::Code(c) => c,
    };
    std::process::exit(code);
}

/// The identity a verb was told to act as: explicit `--user` → `KOTTON_USER` → the active
/// identity.
///
/// **The active identity was missing from this chain**, while the refusal told the user to
/// set it with `kotton id use <name>` and the `--user` doc comment promised it as the default.
/// So `id use` wrote a file nothing read, and every command that omitted `--user` failed with
/// advice that could not work. Found 2026-08-26 on the fresh-machine path.
///
/// `None` is not yet a refusal: a line that runs without a session may need no
/// identity, or bring its own. [`no_active_identity`] is the refusal for one that does.
fn named_user(explicit: Option<String>) -> Option<String> {
    explicit
        .filter(|u| !u.is_empty())
        .or_else(|| std::env::var("KOTTON_USER").ok().filter(|u| !u.is_empty()))
        .or_else(crate::active_identity::get)
}

/// Why a verb that acts as somebody could not find out who.
fn no_active_identity() -> io::Error {
    io::Error::other(
        "no active identity — run `kotton id use <name>`, pass --user <name>, \
         or set KOTTON_USER",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn names(c: &clap::Command) -> Vec<String> {
        std::iter::once(c.get_name().to_string())
            .chain(c.get_all_aliases().map(str::to_string))
            .collect()
    }

    /// **The gate the record names.** Every subcommand of the clap tree is either
    /// answered inside the REPL under the same words, or refused there by a line
    /// naming the one-shot form. A verb added to one table has never had to account
    /// for the other; now it cannot compile past this without doing so.
    #[test]
    fn every_kotton_verb_is_answered_in_the_repl_or_refused_there_by_name() {
        let executor = repl_executor();
        let registry = executor.registry();
        let cli = crate::Cli::command();
        for verb in cli.get_subcommands() {
            for name in names(verb) {
                assert!(
                    registry.has_command(&name) || registry.is_one_shot(&name),
                    "`kotton {name}` is neither a REPL verb nor refused there by name"
                );
            }
        }
    }

    /// Every subcommand the tree gives both a `--user` and raw words — the `run_verb`
    /// variants, read out of the tree rather than listed — takes `--user`
    /// wherever it is typed, or refuses the line. Never the third thing: parsed, with
    /// the name passed through to the verb as two more words, and the verb run as the
    /// active identity instead of the one named. `trailing_var_arg` did exactly that
    /// to every word after the verb's first, so `kotton peer add <4> --user bob` acted
    /// as whoever was active and said nothing
    /// (`TASK-a-trailing-user-flag-is-swallowed-and-the-verb-acts-as-someone-else`).
    #[test]
    fn a_user_flag_after_the_verb_word_binds_or_is_refused_never_discarded() {
        let cli = crate::Cli::command();
        let mut walked = Vec::new();
        for verb in cli.get_subcommands() {
            let takes_user = verb
                .get_arguments()
                .any(|a| a.get_id() == "user" && a.get_long() == Some("user"));
            // Raw words: a positional that takes `--x` as a value. That is what swallows
            // the flag, with or without `trailing_var_arg`, so it is what the walk keys on.
            let takes_raw_words = verb
                .get_positionals()
                .any(|p| p.is_allow_hyphen_values_set());
            if !(takes_user && takes_raw_words) {
                continue;
            }
            let name = verb.get_name();
            walked.push(name.to_string());
            // The last line is the form that has always bound, and must go on binding:
            // a refusal is only an answer where binding is not possible.
            let lines: [(&[&str], bool); 5] = [
                (&["list", "--user", "bob"], true),
                (&["list", "--user=bob"], true),
                (&["add", "a", "b", "c", "d", "--user", "bob"], true),
                (&["add", "a", "--user", "bob", "b", "--as", "c"], true),
                (&["--user", "bob", "add", "a"], false),
            ];
            for (line, may_refuse) in lines {
                let argv: Vec<&str> = ["kotton", name].iter().chain(line).copied().collect();
                let m = match crate::Cli::command().try_get_matches_from(&argv) {
                    Ok(m) => m,
                    // Refused: the person is told, which is the other honest answer — but
                    // only if what they are told is about the flag they typed.
                    Err(e) if may_refuse => {
                        let said = e.to_string();
                        assert!(
                            said.contains("`--user` goes before"),
                            "`{}` was refused, but not for `--user`: {said}",
                            argv.join(" ")
                        );
                        continue;
                    }
                    Err(e) => panic!("`{}` refused: {e}", argv.join(" ")),
                };
                let (_, sub) = m.subcommand().expect("the verb parsed as a subcommand");
                assert_eq!(
                    sub.get_one::<String>("user").map(String::as_str),
                    Some("bob"),
                    "`{}` parsed, and the named identity was discarded",
                    argv.join(" ")
                );
                let words: Vec<&str> = verb
                    .get_positionals()
                    .flat_map(|p| sub.get_raw(p.get_id().as_str()).into_iter().flatten())
                    .filter_map(|w| w.to_str())
                    .collect();
                assert!(
                    !words.iter().any(|w| w.starts_with("--user") || *w == "bob"),
                    "`{}` passed the flag through to the verb as words: {words:?}",
                    argv.join(" ")
                );
            }
        }
        for verb in ["app", "peer", "device", "sync", "drive", "pin", "issuer", "cp", "cat", "keep", "mint", "enrol", "relay", "vault"] {
            assert!(
                walked.iter().any(|w| w == verb),
                "the walk did not reach `kotton {verb}`: {walked:?}"
            );
        }
    }

    /// `kotton --json drive list` hands `drive` the word its own parser reads, as the
    /// REPL's `drive list --json` does; a verb that reads no such word keeps the flag.
    #[test]
    fn a_json_flag_before_a_noun_that_reads_it_is_handed_to_the_noun() {
        let executor = ShellExecutor::new();
        let words = |w: &[&str]| w.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(json_word(&executor, "drive", words(&["list"]), true), (words(&["list", "--json"]), false));
        assert_eq!(json_word(&executor, "pin", words(&["list", "--json"]), true), (words(&["list", "--json"]), false));
        assert_eq!(json_word(&executor, "issuer", words(&["list"]), true), (words(&["list"]), true));
        assert_eq!(json_word(&executor, "drive", words(&["list"]), false), (words(&["list"]), false));
    }

    /// The verbs' own flags still reach them untouched, before and after the first
    /// word — binding `--user` must not cost `--push`, `-n` or `--as` their pass-through.
    #[test]
    fn a_verbs_own_flags_still_pass_through_to_it() {
        for (line, want) in [
            (&["sync", "--no-wait"][..], &["--no-wait"][..]),
            (&["sync", "now", "-n"], &["now", "-n"]),
            (&["drive", "list", "--json"], &["list", "--json"]),
            (&["pin", "personal:/photos", "whole"], &["personal:/photos", "whole"]),
            (
                &["device", "add", "--as", "laptop", "--blind"],
                &["add", "--as", "laptop", "--blind"],
            ),
            (&["device", "reset", "--yes"], &["reset", "--yes"]),
            (
                &["peer", "add", "a", "--pin", "b"],
                &["add", "a", "--pin", "b"],
            ),
            (
                &["mint", "relay", "--rule", "anyone", "--rev", "r"],
                &["relay", "--rule", "anyone", "--rev", "r"],
            ),
            (&["vault", "invite", "--me"], &["invite", "--me"]),
            (&["drive", "move", "photos", "--to", "office"], &["move", "photos", "--to", "office"]),
            (&["cp", "host:photo.jpg", "/photos/"], &["host:photo.jpg", "/photos/"]),
            (&["keep", "../Photos", "as", "/photos"], &["../Photos", "as", "/photos"]),
        ] {
            let argv: Vec<&str> = std::iter::once("kotton")
                .chain(line.iter().copied())
                .collect();
            let m = crate::Cli::command()
                .try_get_matches_from(&argv)
                .unwrap_or_else(|e| panic!("`{}` refused: {e}", argv.join(" ")));
            let (_, sub) = m.subcommand().expect("subcommand");
            let words: Vec<&str> = sub
                .get_many::<String>("args")
                .into_iter()
                .flatten()
                .map(String::as_str)
                .collect();
            assert_eq!(words, want, "`{}`", argv.join(" "));
            assert_eq!(sub.get_one::<String>("user"), None);
        }
    }

    /// **A shared verb's `--help` ends on the shell verb's own help.** Every subcommand the
    /// tree hands to `run_verb` — a `--user` and raw words, read out of the tree as the walk
    /// above reads it — is a verb the shell registers under the same name, and its help ends on
    /// that verb's `help_text`, so `kotton mint --help` says the words `mint` takes rather than
    /// only that it takes some. A pass-through verb added without its help fails here.
    #[test]
    fn a_shared_verbs_help_ends_on_the_shell_verbs_own() {
        let registry = ShellExecutor::new().registry();
        let docs = registry.command_docs();
        let mut seen = Vec::new();
        for verb in crate::Cli::command().get_subcommands() {
            let takes_user = verb.get_arguments().any(|a| a.get_id() == "user");
            let takes_raw_words = verb.get_positionals().any(|p| p.is_allow_hyphen_values_set());
            if !(takes_user && takes_raw_words) {
                continue;
            }
            let name = verb.get_name();
            let (_, help) = docs
                .iter()
                .find(|(n, _)| n == name)
                .unwrap_or_else(|| panic!("`kotton {name}` passes through to no shell verb of that name"));
            assert_eq!(
                verb.get_after_help().map(|h| h.to_string()).as_deref(),
                Some(help.as_str()),
                "`kotton {name} --help` does not end on the shell's `{name}` help"
            );
            seen.push(name.to_string());
        }
        for verb in ["mint", "enrol", "cp", "cat", "keep", "relay", "vault", "sync", "drive", "pin"] {
            assert!(seen.iter().any(|s| s == verb), "`kotton {verb}` is not a pass-through: {seen:?}");
        }
    }

    /// **A noun that declares retired verbs says nothing of them in its clap `about` or its
    /// arguments' help**: its `--help` ends on the shell's page, whose `RETIRED:` block is
    /// generated from the table, and a hand-written sentence beside it is a second account
    /// that drifted once (`device`'s about said a gone word still ran). Read as
    /// `verb-check`'s sweep reads the reference: the noun and the word, or the bare word
    /// opening a backticked span, since the noun is the page's subject.
    #[test]
    fn a_nouns_clap_help_says_nothing_of_its_retired_verbs() {
        let registry = ShellExecutor::new().registry();
        let mut held = 0;
        for verb in crate::Cli::command().get_subcommands() {
            let name = verb.get_name();
            let retired: Vec<&str> = registry
                .verbs_of(name)
                .iter()
                .filter(|v| !matches!(v.is, kotton_shell::VerbIs::Current) && !v.word.starts_with('<'))
                .map(|v| v.word)
                .collect();
            if retired.is_empty() {
                continue;
            }
            held += 1;
            let mut texts: Vec<String> = [verb.get_about(), verb.get_long_about()].into_iter().flatten().map(|t| t.to_string()).collect();
            texts.extend(verb.get_arguments().flat_map(|a| [a.get_help(), a.get_long_help()]).flatten().map(|t| t.to_string()));
            for text in &texts {
                let lower = text.to_lowercase();
                for word in &retired {
                    for needle in [format!("{name} {word}"), format!("`{word}")] {
                        let said = lower.match_indices(&needle).any(|(at, m)| {
                            !lower[at + m.len()..].starts_with(|c: char| c.is_alphanumeric() || c == '-' || c == '_')
                        });
                        assert!(!said, "`kotton {name} --help` says `{needle}` in a hand-written line: {text}");
                    }
                }
            }
        }
        assert!(held >= 2, "`sync` and `device` declare retired verbs; held {held}");
    }

    /// **The one command the recovery card names parses, and it needs no name.** The
    /// card is the words and each vault's line, and names one command to give them to,
    /// `kotton id recover`, in backticks; it spells none of the pieces that command
    /// runs. Run through the real tree, the command parses with no name, which it then
    /// asks for, and with the name the card says.
    #[test]
    fn the_one_command_the_recovery_card_names_parses_with_or_without_a_name() {
        let node = kotton_wire::peer::PairedNode {
            id: "blind-vps".to_string(),
            device_did: kotton_wire::did::Did::new("key", "z6MktGLn5v9bCrdxWgRojExample"),
            public_key: [7; 32],
            paired_at: 0,
            addresses: vec!["203.0.113.9:7710".parse().expect("a socket address")],
            relay_url: None,
            posture: None,
        };
        let card = kotton_shell::commands::recovery_card("sam", "the phrase", &[node]);
        let text: Vec<String> = card
            .iter()
            .filter_map(|o| match o {
                out::Out::Note(t) | out::Out::Hint(t) | out::Out::Reveal(t) => Some(t.trim().to_string()),
                _ => None,
            })
            .collect();
        assert!(
            !text.iter().any(|t| t.starts_with("kotton ")),
            "the card spells a command line to type: {text:#?}"
        );
        let named: Vec<&str> = text
            .iter()
            .flat_map(|t| t.split('`').skip(1).step_by(2))
            .filter(|c| c.starts_with("kotton "))
            .collect();
        assert_eq!(named, vec!["kotton id recover"], "{text:#?}");
        for argv in [vec!["kotton", "id", "recover"], vec!["kotton", "id", "recover", "sam"]] {
            let m = crate::Cli::command()
                .try_get_matches_from(&argv)
                .unwrap_or_else(|e| panic!("`{}` does not parse: {e}", argv.join(" ")));
            let (_, id) = m.subcommand().expect("a verb");
            let (sub, recover) = id.subcommand().expect("an `id` subcommand");
            assert_eq!(sub, "recover");
            assert_eq!(recover.get_one::<String>("username").map(String::as_str), argv.get(3).copied());
        }
    }

    /// The same, one level down, for the verb the REPL shares by name: every
    /// `kotton id` subcommand has an answer in the REPL's `id`
    /// (`kotton_shell::commands::id_answer`, the table its `execute` dispatches on).
    #[test]
    fn every_id_subcommand_is_answered_in_the_repl_or_refused_there_by_name() {
        let cli = crate::Cli::command();
        let id = cli.find_subcommand("id").expect("`kotton id` exists");
        let mut seen = 0;
        for sub in id.get_subcommands() {
            for name in names(sub) {
                assert!(
                    kotton_shell::commands::id_answer(&name).is_some(),
                    "`kotton id {name}` has no answer in the REPL's `id`"
                );
                seen += 1;
            }
        }
        assert!(
            seen >= 12,
            "walked only {seen} `id` names — the walk is not reaching the tree"
        );
        // `login` claims the name before any shell runs as it, so it stays the
        // one-shot's. `rotate` and `recover` are answered in the shell too, for the
        // identity it runs as: each asks for its secret at the hidden prompt
        // (`kotton_shell::secret`), never through the line editor. `kotton id
        // rotate` runs the shell's here; `kotton id recover` asks at the same prompt
        // and sends the same `Recover` request among its pieces.
        assert!(matches!(
            kotton_shell::commands::id_answer("login"),
            Some(kotton_shell::commands::IdAnswer::OneShot { .. })
        ));
        for sub in ["add-recovery", "rotate", "recover"] {
            assert_eq!(
                kotton_shell::commands::id_answer(sub),
                Some(kotton_shell::commands::IdAnswer::Here),
                "`id {sub}`"
            );
        }
    }
}
