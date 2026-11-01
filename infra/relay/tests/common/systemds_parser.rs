// SPDX-License-Identifier: AGPL-3.0-or-later
//! Where systemd's own settings parser is on this machine: `libsystemd-shared-*.so`, whose
//! `load_env_file` is what `EnvironmentFile=` calls, and the `python3` the differential
//! tests call it through with `ctypes`
//! (`TASK-the-settings-differential-is-not-green-where-systemds-parser-is-absent`).
//!
//! One finder for every reader of the question: the relay's and the vault's differential
//! tests (through `settings_corpus.rs`), and `xtask`'s release gate and `doctor`, which
//! compile this file by `#[path]`. It names nothing but `std`, which is what lets it be
//! compiled in all three crates; xtask's test of every `#[path]`-shared file
//! (`xtask/src/std_only.rs`, kotton #306) holds that, where a name all three link would
//! compile and go unseen.
//!
//! **A run that cannot reach the parser is not a pass.** A differential test that finds it
//! missing fails naming what is missing, unless [`SKIP_VAR`] is set — by a developer, on a
//! machine that cannot have the library — and then it is compiled ignored, by name. The release
//! gate does not read [`SKIP_VAR`] at all: a release is cut only where the parser is.
//!
//! **Why here, under a test directory, when `xtask` includes it.** It answers the question
//! the differential corpus beside it asks, and both test crates already reach that corpus by
//! `#[path]`; `xtask` compiles it for the one reason it compiles `kvaultd`'s settings reader —
//! a second copy would be a second finder held to the first by nothing. The places that would
//! not invert the include are worse: under `xtask/` the product's tests would reach into the
//! tooling, and `infra/release/` holds what an archive ships.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// Set (to anything but empty) on a machine that cannot have `libsystemd-shared` or `python3`.
/// Read at build time by `systemd_parser_cfg.rs` beside this file, which the relay's, the
/// vault's and xtask's build scripts each `include!`, and under which they compile the tests
/// that need the parser `#[ignore]`d with a reason, so libtest counts them ignored by name;
/// and at run time here. It cannot hide a parser that is present: under it,
/// `kotton_no_systemd_parser_is_declared_only_where_systemds_parser_is_absent` fails where
/// [`find`] succeeds.
pub const SKIP_VAR: &str = "KOTTON_NO_SYSTEMD_PARSER";

/// The directories a distribution puts `libsystemd-shared-*.so` in: Debian and Ubuntu's
/// multiarch one, then the plain and the lib64 ones.
pub const LIBRARY_DIRS: [&str; 3] = ["/usr/lib/x86_64-linux-gnu/systemd", "/usr/lib/systemd", "/usr/lib64/systemd"];

/// systemd's parser, found: the library and the interpreter that calls into it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemdsParser {
    pub library: PathBuf,
    pub python: PathBuf,
}

/// The newest `libsystemd-shared-*.so` in `dirs`, by name, as the tests have always taken it.
pub fn library_in(dirs: &[&Path]) -> Option<PathBuf> {
    let mut found: Vec<PathBuf> = dirs
        .iter()
        .filter_map(|d| std::fs::read_dir(d).ok())
        .flatten()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("libsystemd-shared-") && n.ends_with(".so"))
        })
        .collect();
    found.sort();
    found.pop()
}

/// `python3` on `path` (a `PATH` value), as a spawn of `python3` would find it.
pub fn python_on(path: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    std::env::split_paths(path?).map(|d| d.join("python3")).find(|p| p.is_file())
}

/// systemd's parser in `dirs` and on `path`, or a sentence naming each half that is missing.
pub fn find_in(dirs: &[&Path], path: Option<&std::ffi::OsStr>) -> Result<SystemdsParser, String> {
    let library = library_in(dirs);
    let python = python_on(path);
    match (library, python) {
        (Some(library), Some(python)) => Ok(SystemdsParser { library, python }),
        (library, python) => {
            let mut missing = Vec::new();
            if library.is_none() {
                let shown: Vec<String> = dirs.iter().map(|d| d.display().to_string()).collect();
                missing.push(format!("no libsystemd-shared-*.so in {}", shown.join(", ")));
            }
            if python.is_none() {
                missing.push("no python3 on PATH".to_string());
            }
            Err(missing.join(", and "))
        }
    }
}

/// systemd's parser on this machine, or what is missing.
pub fn find() -> Result<SystemdsParser, String> {
    let dirs: Vec<&Path> = LIBRARY_DIRS.iter().map(Path::new).collect();
    find_in(&dirs, std::env::var_os("PATH").as_deref())
}

/// Whether this run says it knows the parser cannot be here.
pub fn skip_declared() -> bool {
    std::env::var_os(SKIP_VAR).is_some_and(|v| !v.is_empty())
}

/// What a differential test does with what [`find`] said: compare against the parser
/// (`Ok(Some)`), report itself skipped because the run declared it (`Ok(None)`, with the
/// line to print), or fail naming what is missing (`Err`).
pub fn for_test(test: &str, found: Result<SystemdsParser, String>, declared: bool) -> Result<Result<SystemdsParser, String>, String> {
    match found {
        Ok(parser) => Ok(Ok(parser)),
        Err(missing) if declared => Ok(Err(format!(
            "SKIPPED {test}: {missing}; {SKIP_VAR} is set, so nothing was compared with systemd's parser on this machine"
        ))),
        Err(missing) => Err(format!(
            "{test}: systemd's parser is not on this machine ({missing}), so nothing would be compared with it. \
             Install it (`cargo xtask doctor` names the packages), or, on a machine that cannot have it, \
             set {SKIP_VAR}=1, under which the build compiles this test ignored, by name"
        )),
    }
}
