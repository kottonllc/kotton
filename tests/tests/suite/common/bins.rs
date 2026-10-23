// SPDX-License-Identifier: AGPL-3.0-or-later
//! The binaries the suite runs as processes, and the one check of all of them.
//!
//! **No suite test returns green on an input that is not there**: a test that cannot run
//! says so and fails, by name, beside whatever else is missing, with the command that
//! makes it, because a skip prints to a stream nobody reads and reports as a pass. Every
//! input is one this tree builds: no guest app, no wasm component, no binary from a tree
//! that is not here.
//!
//! Each is bin-only, so none can be a dev-dependency of this package, and Cargo has no
//! way on stable to say "this test needs that binary" (artifact dependencies are
//! nightly). So `cargo test -p kotton-integration-tests` builds none of them:
//! `tests/build.rs` emits where cargo puts them, and the suite checks they are there.
//!
//! **One check, of every binary, the first time any test asks for one.** A check that
//! names only the binary its own test needs makes a narrow run discover the missing
//! ones a failure at a time: build the one named, run again, meet the next. So the
//! first call to [`require`] looks at every binary in [`ALL`], once for the process,
//! and a test whose binary is missing fails naming *all* the missing ones with the
//! command that builds them together. A test whose binary is present runs as it would
//! have: the check widens what a failure says, never what fails.
//!
//! `just test_suite <names>` builds every one of them and then runs the named tests.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// A binary the suite runs as a process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bin {
    /// The CLI, which `cli_identity` and its neighbours run as a person does.
    Kotton,
    /// The fixture runner every `TestEnv` launches apps in.
    MockRunner,
    /// The daemon `two_node_transfer` spawns.
    Kuserd,
    /// The vault `headless` installs with the self-host adapter.
    Kvaultd,
    /// The relay — its own workspace, built into its own target directory.
    Relay,
}

/// Every binary the suite runs, in the order a failure lists them.
pub const ALL: [Bin; 5] = [Bin::Kotton, Bin::MockRunner, Bin::Kuserd, Bin::Kvaultd, Bin::Relay];

impl Bin {
    /// Cargo's name for it: what `--bin` takes.
    pub fn name(self) -> &'static str {
        match self {
            Bin::Kotton => "kotton",
            Bin::MockRunner => "kotton-mock-runner",
            Bin::Kuserd => "kuserd",
            Bin::Kvaultd => "kvaultd",
            Bin::Relay => "kotton-relay",
        }
    }

    /// The variable that names another binary in its place, where the suite reads one.
    fn named_by(self) -> Option<&'static str> {
        match self {
            Bin::Kvaultd => Some("KOTTON_VAULT_BIN"),
            Bin::Relay => Some("KOTTON_RELAY_BIN"),
            _ => None,
        }
    }

    /// Where the suite runs it from, and whether a variable said so.
    fn locate(self) -> (PathBuf, Option<&'static str>) {
        if let Some(var) = self.named_by() {
            if let Ok(p) = std::env::var(var) {
                return (PathBuf::from(p), Some(var));
            }
        }
        let path = match self {
            Bin::Kotton => PathBuf::from(env!("KOTTON_BIN")),
            Bin::MockRunner => PathBuf::from(env!("MOCK_RUNNER_BIN")),
            Bin::Kuserd => PathBuf::from(env!("KUSERD_BIN")),
            Bin::Kvaultd => PathBuf::from(env!("KVAULTD_BIN")),
            Bin::Relay => relay_built_at(),
        };
        (path, None)
    }
}

/// Where the relay's own build leaves it.
///
/// The relay is its own workspace, so it builds into its own `out/relay` — handed to
/// cargo as `--target-dir` by the `Justfile` and by `cargo xtask build-relay`
/// (`xtask/src/out.rs`), because cargo reads `build.target-dir` from where it is *run*,
/// not from the manifest it is given. `CARGO_TARGET_DIR` wins when exported, as it does
/// for every build, and a relative value is resolved against the repository root, where
/// the recipes run. It is the relay's own directory, never the workspace's, so a binary
/// built into a shared directory by another checkout is never the one a test runs.
fn relay_built_at() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().expect("tests/ has a parent");
    let name = if cfg!(windows) { "kotton-relay.exe" } else { "kotton-relay" };
    let target = match std::env::var("CARGO_TARGET_DIR") {
        Ok(d) if !d.is_empty() => root.join(d),
        _ => root.join("out/relay"),
    };
    target.join("debug").join(name)
}

/// One binary, as the check found it.
struct Found {
    bin: Bin,
    path: PathBuf,
    named_by: Option<&'static str>,
    present: bool,
}

/// Every binary, looked at once for the process.
fn survey() -> &'static [Found] {
    static SURVEY: OnceLock<Vec<Found>> = OnceLock::new();
    SURVEY.get_or_init(|| {
        ALL.iter()
            .map(|&bin| {
                let (path, named_by) = bin.locate();
                Found { bin, present: path.exists(), path, named_by }
            })
            .collect()
    })
}

/// The path to `bin`, or a failure naming every binary the suite runs that is not built,
/// with the commands that build them together.
pub fn require(bin: Bin) -> &'static Path {
    let all = survey();
    let found = all.iter().find(|f| f.bin == bin).expect("every binary is surveyed");
    assert!(found.present, "{}", missing_report(bin, all));
    &found.path
}

/// What a test whose binary is missing says: all of them, and how to build them.
fn missing_report(needed: Bin, all: &[Found]) -> String {
    let missing: Vec<&Found> = all.iter().filter(|f| !f.present).collect();
    let width = missing.iter().map(|f| f.bin.name().len()).max().unwrap_or(0);
    let mut s = format!(
        "{} is not built, so this test cannot use it.\n\
         The suite runs {} binaries as processes, and {} of them {} not built:\n",
        needed.name(),
        all.len(),
        missing.len(),
        if missing.len() == 1 { "is" } else { "are" },
    );
    for f in &missing {
        let _ = write!(s, "  {:width$}  {}", f.bin.name(), f.path.display());
        if let Some(var) = f.named_by {
            let _ = write!(s, "  (named by {var})");
        }
        if f.bin == needed {
            s.push_str("  <- this test");
        }
        s.push('\n');
    }

    let workspace: Vec<&str> = missing
        .iter()
        .filter(|f| f.bin != Bin::Relay && f.named_by.is_none())
        .map(|f| f.bin.name())
        .collect();
    let relay = missing.iter().any(|f| f.bin == Bin::Relay && f.named_by.is_none());
    s.push_str("Build them together:\n");
    if !workspace.is_empty() {
        let bins: Vec<String> = workspace.iter().map(|b| format!("--bin {b}")).collect();
        let _ = writeln!(s, "  cargo build {}", bins.join(" "));
    }
    if relay {
        s.push_str("  cargo xtask build-relay    (the relay is its own workspace)\n");
    }
    for f in missing.iter().filter(|f| f.named_by.is_some()) {
        let var = f.named_by.expect("filtered on it");
        let _ = writeln!(s, "  {var} names a file that is not there: build it, or unset {var}");
    }
    s.push_str(
        "or build every input the suite needs and run the tests you name: \
         just test_suite <name>...\n\
         (each is bin-only, so none can be a dev-dependency of this package — see tests/build.rs)",
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(bin: Bin, present: bool, named_by: Option<&'static str>) -> Found {
        Found {
            bin,
            path: PathBuf::from(format!("/t/debug/{}", bin.name())),
            named_by,
            present,
        }
    }

    /// A narrow run meets every missing binary in its first failure, and one line builds
    /// the workspace's together.
    #[test]
    fn a_missing_binary_names_every_missing_one_and_the_line_that_builds_them() {
        let all: Vec<Found> = ALL
            .iter()
            .map(|&b| found(b, !matches!(b, Bin::MockRunner | Bin::Kvaultd | Bin::Kuserd), None))
            .collect();
        let report = missing_report(Bin::Kvaultd, &all);
        assert!(report.starts_with("kvaultd is not built"), "{report}");
        assert!(report.contains("The suite runs 5 binaries as processes, and 3 of them are not built"), "{report}");
        for name in ["kotton-mock-runner", "kuserd", "kvaultd"] {
            assert!(report.contains(&format!("/t/debug/{name}")), "{name} unlisted:\n{report}");
        }
        assert!(
            report.contains("  cargo build --bin kotton-mock-runner --bin kuserd --bin kvaultd\n"),
            "{report}"
        );
        assert!(report.contains("/t/debug/kvaultd  <- this test\n"), "{report}");
        assert!(!report.contains("build-relay"), "the relay is built:\n{report}");
        assert!(!report.contains("/t/debug/kotton\n"), "the CLI is built:\n{report}");
    }

    /// The relay is built by its own command, and a binary a variable names is not
    /// something `cargo build` makes, so neither goes on the workspace's line.
    #[test]
    fn the_relay_and_a_named_binary_say_their_own_fix() {
        let all: Vec<Found> = ALL
            .iter()
            .map(|&b| match b {
                Bin::Relay => found(b, false, None),
                Bin::Kvaultd => found(b, false, Some("KOTTON_VAULT_BIN")),
                _ => found(b, true, None),
            })
            .collect();
        let report = missing_report(Bin::Relay, &all);
        assert!(!report.contains("cargo build --bin"), "{report}");
        assert!(report.contains("cargo xtask build-relay"), "{report}");
        assert!(report.contains("(named by KOTTON_VAULT_BIN)"), "{report}");
        assert!(report.contains("KOTTON_VAULT_BIN names a file that is not there"), "{report}");
    }
}
