// SPDX-License-Identifier: AGPL-3.0-or-later
//! The release gate's two entry points, run as the binary a person runs, on a machine where
//! systemd's own settings parser is not: `release-server` refuses, saying so, before it
//! reads, fetches or builds anything
//! (`TASK-the-settings-differential-is-not-green-where-systemds-parser-is-absent`); and
//! `release-server-test`, which compares nothing with the parser, does not ask for it
//! (`TASK-the-release-gates-parser-presence-refusals-guard-what-the-differentials-run-now-proves`).
//!
//! The parser is made absent through the one seam the finder reads from the process: `PATH`,
//! set to an empty directory, so no `python3` is found. Each run is in a scratch directory of
//! its own, so an entry point whose refusal were removed would act on nothing of the checkout's.
//! The refusal's sentence is asserted, not only the exit: without it `release-server` still
//! fails here, on a commit it cannot read, and an exit alone would read that as the gate
//! holding. `release-server-test` fails here too, on an archive not there, and that is
//! asserted as its failure and the parser's absence from it.
//!
//! And where the parser is, the third: `release-server` runs the settings differential's four
//! tests itself and names no archive unless each reported `ok` — run on a checkout of its own
//! whose four tests are stand-ins, one `#[ignore]`d
//! (`TASK-the-release-gate-requires-systemds-parser-and-does-not-run-the-differential`).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The corpus the differential tests share, for its one rule about a machine: a test that
/// needs systemd's parser fails where it is absent, unless the run declares
/// `KOTTON_NO_SYSTEMD_PARSER` — and then xtask's build script, which `include!`s the same
/// source the relay's and the vault's do, compiles it `#[ignore]`d, and the corpus's own guard
/// fails where the parser is present after all.
#[path = "../../infra/relay/tests/common/settings_corpus.rs"]
mod corpus;

fn scratch(name: &str) -> (PathBuf, PathBuf) {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let empty = dir.join("empty-path");
    std::fs::create_dir_all(&empty).unwrap();
    (dir, empty)
}

fn xtask(dir: &PathBuf, empty_path: &PathBuf, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(args)
        .current_dir(dir)
        .env("PATH", empty_path)
        // The release gate does not read the developer's declaration; set it, to show that.
        .env("KOTTON_NO_SYSTEMD_PARSER", "1")
        .output()
        .unwrap()
}

fn said(out: &Output) -> String {
    format!(
        "exit {:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

const REFUSAL: &str = "systemd's own settings parser is not on this machine (no python3 on PATH)";

/// **`release-server` refuses first, and builds nothing.**
#[test]
fn release_server_refuses_where_systemds_parser_is_absent() {
    let (dir, empty) = scratch("release-server-no-parser");
    let out = xtask(&dir, &empty, &["release-server", "relay", "--not-a-release", "--no-build"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    assert!(stderr.contains(&format!("release-server: {REFUSAL}")), "{}", said(&out));
    assert!(stderr.contains("KOTTON_NO_SYSTEMD_PARSER does not change that"), "{}", said(&out));
    assert!(stderr.contains("nothing was built."), "{}", said(&out));
    assert!(!dir.join("out").exists(), "release-server wrote under its directory before refusing");
    let _ = std::fs::remove_dir_all(&dir);
}

/// **`release-server-test` does not ask for systemd's parser, because it compares nothing.**
///
/// It installs an archive and starts its binary; nothing in that reads a settings file with
/// systemd's parser, so a machine without the parser tests an archive as any other does. Run
/// here with no parser, it goes past where the refusal stood and fails on the archive that is
/// not there, saying that and nothing about the parser
/// (`TASK-the-release-gates-parser-presence-refusals-guard-what-the-differentials-run-now-proves`).
#[test]
fn release_server_test_does_not_ask_for_systemds_parser() {
    let (dir, empty) = scratch("release-server-test-no-parser");
    let archive = "kotton-relay-0123456789ab-linux-x86_64.tar.gz";
    let out = xtask(&dir, &empty, &["release-server-test", archive]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    assert!(stderr.contains(&format!("release-server-test: FAIL — {archive}")), "{}", said(&out));
    assert!(stderr.contains(&format!("cannot read {archive}")), "{}", said(&out));
    assert!(!stderr.contains("systemd's own settings parser"), "{}", said(&out));
    let _ = std::fs::remove_dir_all(&dir);
}

/// The four tests `release-server` runs, by the file and crate it runs each pair from.
const RELAY_PAIR: [&str; 2] = [
    "the_installer_reads_what_systemds_own_parser_reads",
    "generated_settings_the_installer_accepts_are_read_the_same_by_systemds_parser",
];
const VAULT_PAIR: [&str; 2] = [
    "kvaultd_reads_the_fixed_forms_the_installer_accepts_as_the_installer_and_systemd_do",
    "kvaultd_reads_the_generated_forms_the_installer_accepts_as_the_installer_and_systemd_do",
];

fn run(dir: &Path, program: &str, args: &[&str]) {
    let out = Command::new(program).args(args).current_dir(dir).output().unwrap();
    assert!(out.status.success(), "{program} {args:?}: {}", said(&out));
}

fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// A stand-in test file holding `names`, each passing only where the declaration is absent
/// from its environment — so a pass is also the release having cleared it — and `ignored`
/// carrying `#[ignore]`.
fn stand_ins(names: &[&str], ignored: Option<&str>) -> String {
    names
        .iter()
        .map(|n| {
            format!(
                "#[test]{}\nfn {n}() {{ assert!(std::env::var_os(\"KOTTON_NO_SYSTEMD_PARSER\").is_none(), \"run under the declaration\"); }}\n",
                if ignored == Some(*n) { "\n#[ignore = \"a stand-in that compared nothing\"]" } else { "" }
            )
        })
        .collect()
}

/// A checkout of its own, outside this repository so no `.cargo/config.toml` of ours reaches
/// it: a workspace with a `kvaultd` package and, beside it, `infra/relay` as its own
/// workspace, as the tree has them, each with the differential's test file under its real
/// name holding stand-ins for its pair. Committed, with lockfiles, so the tree is clean.
fn checkout(dir: &Path, ignored: Option<&str>) {
    write(&dir.join(".gitignore"), "out/\ntarget/\n");
    write(&dir.join("Cargo.toml"), "[workspace]\nmembers = [\"core/kvaultd\"]\nresolver = \"2\"\n");
    write(&dir.join("core/kvaultd/Cargo.toml"), "[package]\nname = \"kvaultd\"\nversion = \"0.0.0\"\nedition = \"2021\"\n");
    write(&dir.join("core/kvaultd/src/main.rs"), "fn main() {}\n");
    write(&dir.join("infra/relay/Cargo.toml"), "[package]\nname = \"kotton-relay\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[workspace]\n");
    write(&dir.join("infra/relay/src/main.rs"), "fn main() {}\n");
    stand_in_files(dir, ignored);
    run(dir, "cargo", &["generate-lockfile", "--offline"]);
    run(dir, "cargo", &["generate-lockfile", "--offline", "--manifest-path", "infra/relay/Cargo.toml"]);
    run(dir, "git", &["init", "--quiet", "--initial-branch", "main"]);
    commit(dir);
}

fn stand_in_files(dir: &Path, ignored: Option<&str>) {
    write(&dir.join("infra/relay/tests/an_install_tells_the_relay_its_address.rs"), &stand_ins(&RELAY_PAIR, ignored));
    write(
        &dir.join("core/kvaultd/tests/the_vault_reads_its_settings_as_the_installer_and_systemd_do.rs"),
        &stand_ins(&VAULT_PAIR, ignored),
    );
}

fn commit(dir: &Path) {
    run(dir, "git", &["add", "--all"]);
    run(dir, "git", &["-c", "user.name=t", "-c", "user.email=t@t", "commit", "--quiet", "-m", "stand-ins"]);
}

/// `release-server relay --not-a-release --no-build` in `dir`, with the declaration set, as a
/// developer's shell on a machine without the parser would have it.
fn release(dir: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["release-server", "relay", "--not-a-release", "--no-build"])
        .current_dir(dir)
        .env("KOTTON_NO_SYSTEMD_PARSER", "1")
        .env_remove("CARGO_TARGET_DIR")
        .output()
        .unwrap()
}

/// **`release-server` names no archive unless the differential's four tests compared.**
///
/// One of the four reports `ignored` — the verdict a test gives under the declaration, or
/// under a `--cfg` nobody meant — and the release refuses, naming it, before it builds or
/// packs anything. Then, the control: the same checkout with all four passing gets past the
/// differential and stops where `--no-build` with no binary stops, at the pack, so the
/// refusal above was the differential's and not the stand-in checkout's.
#[test]
#[cfg_attr(kotton_no_systemd_parser, ignore = "KOTTON_NO_SYSTEMD_PARSER is set: this machine declares it has no systemd parser to compare with")]
fn release_server_names_no_archive_unless_the_settings_differential_compared() {
    // The verb refuses first where the parser is absent; past that is what this holds.
    if corpus::systemds_parser_for("release_server_names_no_archive_unless_the_settings_differential_compared").is_none() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let skipped = RELAY_PAIR[1];
    checkout(dir, Some(skipped));

    let out = release(dir);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    assert!(stderr.contains("release-server: the settings differential did not compare against systemd's parser"), "{}", said(&out));
    assert!(stderr.contains(&format!("{skipped}: ignored")), "{}", said(&out));
    assert!(stderr.contains("nothing was built."), "{}", said(&out));
    let dist = dir.join("out/dist");
    let named: Vec<_> = std::fs::read_dir(&dist).into_iter().flatten().flatten().map(|e| e.path()).collect();
    assert!(named.is_empty(), "release-server wrote {named:?} before refusing");

    stand_in_files(dir, None);
    commit(dir);
    let out = release(dir);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("did not compare"), "{}", said(&out));
    for name in RELAY_PAIR.iter().chain(&VAULT_PAIR) {
        assert!(stdout.contains(&format!("{name} ... ok")), "{name}: {}", said(&out));
    }
    assert!(stdout.contains("release-server: the settings differential compared against systemd's parser"), "{}", said(&out));
    assert!(stderr.contains("build it: cargo xtask release-server relay (without --no-build)"), "{}", said(&out));
}
