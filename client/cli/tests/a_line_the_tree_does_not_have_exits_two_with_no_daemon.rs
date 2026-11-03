// SPDX-License-Identifier: AGPL-3.0-or-later
//! The clap door answers a line `device`, `drive`, `pin` or `sync` does not have with exit 2 and the
//! verb to type instead, and asks no daemon for it: the noun's one parser refuses the line
//! before the door connects (`Command::execute_without_session`), so a usage line is a
//! usage line whether or not a daemon runs, as the command-tree decision fixes 2 for usage.
//!
//! The binary runs with an environment of only the variables named here, so it can reach
//! no daemon, no session and no active identity of the machine it runs on; `--user nobody`
//! names an identity nothing here holds.
//!
//! `device` is here for two kinds of word: `device admit`, which the command-tree decision's
//! table retires for `drive enrol`, and a word `device` never had (`admitx`), both of which
//! needed a daemon to be refused (exit 1 with "connect"). The rest of `device` is not the
//! tree's yet, but `device add`'s words are parsed before any session (`parse_add`).

use std::process::{Command, Output};

fn kotton(dir: &std::path::Path, args: &[&str]) -> Output {
    let home = dir.join("home");
    std::fs::create_dir_all(&home).unwrap();
    Command::new(env!("CARGO_BIN_EXE_kotton"))
        .args(args)
        .current_dir(dir)
        .env_clear()
        .env("HOME", &home)
        .env("KOTTON_BASE_DIR", dir.join("base"))
        .output()
        .unwrap()
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("kotton-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Each line, and what its refusal must name: the replacement for a retired word, the
/// usage for a word the noun never had.
const REFUSED: &[(&[&str], &str)] = &[
    (&["sync", "--user", "nobody", "add", "foo"], "pin <drive> whole|on-demand|default"),
    (&["sync", "--user", "nobody", "list"], "pin list"),
    (&["sync", "--user", "nobody", "remove", "foo"], "pin <drive>"),
    (&["sync", "--user", "nobody", "--node", "x"], "`sync` syncs this device's drives"),
    (&["sync", "--user", "nobody", "--push", "r"], "`sync` syncs this device's drives"),
    (&["sync", "--user", "nobody", "vault"], "`sync` syncs this device's drives"),
    (&["drive", "--user", "nobody", "frob"], "usage: drive create <name>"),
    (&["drive", "--user", "nobody", "move", "photos"], "usage: drive create <name>"),
    (&["drive", "--user", "nobody", "enrol", "--blind"], "usage: drive enrol <invite>"),
    (&["drive", "--user", "nobody", "enrol", "CODE", "extra"], "usage: drive enrol <invite>"),
    (&["drive", "--user", "nobody", "enrol", "CODE", "--frob"], "usage: drive enrol <invite>"),
    (&["drive", "--user", "nobody", "enrol", "CODE", "--blind", "--cosigner"], "usage: drive enrol <invite>"),
    (&["drive", "--user", "nobody", "enrol", "-x"], "usage: drive enrol <invite>"),
    (&["device", "--user", "nobody", "admit", "--blind"], "drive enrol <invite>"),
    (&["device", "--user", "nobody", "admit", "CODE"], "drive enrol <invite>"),
    (&["device", "--user", "nobody", "admit", "CODE", "extra"], "drive enrol <invite>"),
    (&["device", "--user", "nobody", "admitx"], "usage: device add [--as NAME] [--blind|--cosigner]"),
    (&["device", "--user", "nobody", "add", "--blind", "--cosigner"], "usage: device add [--as NAME] [--blind|--cosigner]"),
    (&["device", "--user", "nobody", "add", "--blind", "--blind"], "usage: device add [--as NAME] [--blind|--cosigner]"),
    (&["pin", "--user", "nobody", "personal", "sometimes"], "usage: pin default"),
    (&["pin", "--user", "nobody", "frob"], "usage: pin default"),
];

#[test]
fn a_retired_word_or_an_unknown_verb_exits_two_naming_what_to_type_with_no_daemon() {
    let dir = scratch("refused");
    for (args, names) in REFUSED {
        let out = kotton(&dir, args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let line = format!("kotton {}", args.join(" "));
        assert_eq!(out.status.code(), Some(2), "`{line}` did not exit 2:\nstderr: {stderr}");
        assert!(stderr.contains(names), "`{line}` did not name `{names}` on stderr:\n{stderr}");
        assert!(!stderr.contains("connect"), "`{line}` tried a daemon before refusing:\n{stderr}");
        assert!(out.stdout.is_empty(), "`{line}` wrote its refusal to stdout:\n{}", String::from_utf8_lossy(&out.stdout));
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `kotton --json <noun> …` hands the noun the word (`bridge::json_word`), so the noun's own
/// parser is what reads it: `--json` on a line that is not a `list` or a `show` is refused
/// by that parser, exit 2, naming where `--json` belongs, before any daemon is asked.
/// Without the hand-off the flag would serialize shapes and the parser would never see it.
#[test]
fn a_json_flag_before_the_noun_reaches_the_nouns_own_parser() {
    let dir = scratch("json-word");
    for (args, names) in [
        (&["--json", "drive", "--user", "nobody", "create", "photos"][..], "`--json` is for `drive list` and `drive show`"),
        (&["--json", "pin", "--user", "nobody", "personal", "whole"][..], "`--json` is for `pin list`"),
    ] {
        let out = kotton(&dir, args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let line = format!("kotton {}", args.join(" "));
        assert_eq!(out.status.code(), Some(2), "`{line}` did not exit 2:\nstderr: {stderr}");
        assert!(stderr.contains(names), "`{line}` was not refused by the noun's parser:\n{stderr}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A line that parses still needs the daemon, and is not answered here: with none, it fails
/// as a refusal (exit 1), never as usage.
#[test]
fn a_line_that_parses_goes_on_to_the_daemon() {
    let dir = scratch("parses");
    let out = kotton(&dir, &["drive", "--user", "nobody", "list"]);
    assert_eq!(out.status.code(), Some(1), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The `--word`s of a line, in order of first appearance, each once.
fn flags(line: &str) -> Vec<&str> {
    let mut seen = Vec::new();
    for w in line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-')).filter(|w| w.starts_with("--")) {
        if !seen.contains(&w) {
            seen.push(w);
        }
    }
    seen.sort_unstable();
    seen
}

/// `kotton device --help`'s argument help and the usage line `device` refuses a word with are
/// two doors to one grammar (kotton #326): each renders the shell's grammar with its own
/// prefix (kotton #361), and the help adds only `reset`'s own word, `--yes`, since `reset` is
/// the CLI's and the shell does not run it. Read from outside, as a person reads them: the
/// flags each names are the same list.
#[test]
fn the_device_help_names_the_words_the_usage_line_names() {
    let dir = scratch("device-help");
    let help = kotton(&dir, &["device", "--help"]);
    assert_eq!(help.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&help.stderr));
    let help = String::from_utf8_lossy(&help.stdout).into_owned();
    let args_help = help.lines().find(|l| l.trim_start().starts_with("[ARGS]...")).unwrap_or_else(|| panic!("no argument help:\n{help}"));
    let refused = kotton(&dir, &["device", "--user", "nobody", "admitx"]);
    assert_eq!(refused.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&refused.stderr).into_owned();
    let usage = stderr
        .lines()
        .find_map(|l| l.split_once("usage: ").map(|(_, rest)| rest))
        .unwrap_or_else(|| panic!("no usage line:\n{stderr}"));
    // The usage line ends on an aside naming the CLI's `reset`; the grammar is what precedes it.
    let grammar = usage.split("   (").next().unwrap();

    let help_flags: Vec<&str> = flags(args_help).into_iter().filter(|w| *w != "--yes").collect();
    assert_eq!(
        help_flags,
        flags(grammar),
        "`kotton device --help` names {help_flags:?}; the usage line names {:?}\nhelp: {args_help}\nusage: {usage}",
        flags(grammar)
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `kotton device --help`'s argument help reads like its siblings' (`kotton peer`, `kotton
/// app`): `Arguments to the verb:`, then each alternative after the verb word, never starting
/// with `device` again, since clap prints `kotton device` before it and `kotton device device
/// add` is no line anyone runs (kotton #361).
#[test]
fn the_device_help_names_its_alternatives_after_the_verb_word() {
    let dir = scratch("device-help-form");
    let help = kotton(&dir, &["device", "--help"]);
    assert_eq!(help.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&help.stderr));
    let help = String::from_utf8_lossy(&help.stdout).into_owned();
    let args_help = help.lines().find(|l| l.trim_start().starts_with("[ARGS]...")).unwrap_or_else(|| panic!("no argument help:\n{help}"));
    let (_, alternatives) = args_help.split_once(": ").unwrap_or_else(|| panic!("no alternatives:\nhelp: {args_help}"));
    let led: Vec<&str> = alternatives
        .split(" | ")
        .map(|a| a.trim_matches('`'))
        .filter(|a| a.split_whitespace().next() == Some("device"))
        .collect();
    assert!(led.is_empty(), "alternatives that begin with the verb word: {led:?}\nhelp: {args_help}");
    assert!(
        args_help.contains("Arguments to the verb: "),
        "the help does not read `Arguments to the verb:` as its siblings do:\nhelp: {args_help}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
