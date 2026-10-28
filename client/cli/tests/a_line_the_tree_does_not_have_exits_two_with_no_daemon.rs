// SPDX-License-Identifier: AGPL-3.0-or-later
//! The clap door answers a line `drive`, `pin` or `sync` does not have with exit 2 and the
//! verb to type instead, and asks no daemon for it: the noun's one parser refuses the line
//! before the door connects (`Command::execute_without_session`), so a usage line is a
//! usage line whether or not a daemon runs, as the command-tree decision fixes 2 for usage.
//!
//! The binary runs with an environment of only the variables named here, so it can reach
//! no daemon, no session and no active identity of the machine it runs on; `--user nobody`
//! names an identity nothing here holds.

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
