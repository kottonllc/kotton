// SPDX-License-Identifier: AGPL-3.0-or-later
//! The binaries the suite runs as processes, and the one check of all of them.
//!
//! The same check also covers the built inputs that are not binaries, the three guest
//! apps' `app.wasm` ([`require_shell_wasm`], [`require_apps_bundled`]): a test that drives
//! the real shell needs it as a test that spawns the runner needs the runner, and it fails
//! the same way — by name,
//! beside whatever else is missing, with the command that makes it. **No suite test
//! returns green on an input that is not there**: a test that cannot run says so and
//! fails, because a skip prints to a stream nobody reads and reports as a pass.
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
//! `just test_suite <names>` builds every one of them, the apps included, and then runs the
//! named tests.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// A binary the suite runs as a process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bin {
    /// The CLI, which `cli_identity` and its neighbours run as a person does.
    Kotton,
    /// The fixture runner most `TestEnv`s launch apps in.
    MockRunner,
    /// The real runner, for `confinement` and `runner_confinement`.
    Runner,
    /// The daemon `two_node_transfer` spawns.
    Kuserd,
    /// The gateway `gateway_bind` and enrolment start.
    Khttpd,
    /// The inference sidecar `inference_sidecar` supervises.
    Kinferd,
    /// The vault `headless` installs with the self-host adapter.
    Kvaultd,
    /// The relay — its own workspace, built into its own target directory.
    Relay,
}

/// What the check looks for: a binary the suite runs, or the shell's `app.wasm`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Input {
    Bin(Bin),
    /// A guest app's `app.wasm`, which `cargo xtask build-apps` makes. It is a component
    /// the tests load, not a process they run, and `kuserd` embeds all three when it
    /// compiles (`core/kuserd/build.rs`).
    App(App),
}

/// The bundled guest apps, the three `core/kuserd/build.rs` requires before `kuserd`
/// embeds any of them. That list is the other half of this one: a fourth there is a
/// fourth here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum App {
    Shell,
    Editor,
    Records,
}

/// Every app `kuserd` embeds, in the order a failure lists them.
const APPS: [App; 3] = [App::Shell, App::Editor, App::Records];

impl App {
    fn name(self) -> &'static str {
        match self {
            App::Shell => "the shell's app.wasm",
            App::Editor => "the editor's app.wasm",
            App::Records => "the records app's app.wasm",
        }
    }

    /// Where `cargo xtask build-apps` leaves it, under the repository root.
    fn built_at(self) -> PathBuf {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().expect("tests/ has a parent");
        let dir = match self {
            App::Shell => "kotton-shell",
            App::Editor => "kotton-editor",
            App::Records => "kotton-records",
        };
        root.join("guest/apps").join(dir).join("app.wasm")
    }
}

impl Input {
    /// What a failure calls it.
    fn name(self) -> &'static str {
        match self {
            Input::Bin(b) => b.name(),
            Input::App(a) => a.name(),
        }
    }
}

/// Every binary the suite runs, in the order a failure lists them.
pub const ALL: [Bin; 8] = [
    Bin::Kotton,
    Bin::MockRunner,
    Bin::Runner,
    Bin::Kuserd,
    Bin::Khttpd,
    Bin::Kinferd,
    Bin::Kvaultd,
    Bin::Relay,
];

impl Bin {
    /// Cargo's name for it: what `--bin` takes.
    pub fn name(self) -> &'static str {
        match self {
            Bin::Kotton => "kotton",
            Bin::MockRunner => "kotton-mock-runner",
            Bin::Runner => "kotton-runner",
            Bin::Kuserd => "kuserd",
            Bin::Khttpd => "khttpd",
            Bin::Kinferd => "kinferd",
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
            Bin::Runner => PathBuf::from(env!("KOTTON_RUNNER_BIN")),
            Bin::Kuserd => PathBuf::from(env!("KUSERD_BIN")),
            Bin::Khttpd => PathBuf::from(env!("KHTTPD_BIN")),
            Bin::Kinferd => PathBuf::from(env!("KINFERD_BIN")),
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

/// One input, as the check found it.
struct Found {
    input: Input,
    path: PathBuf,
    named_by: Option<&'static str>,
    present: bool,
}

/// Every input, looked at once for the process.
fn survey() -> &'static [Found] {
    static SURVEY: OnceLock<Vec<Found>> = OnceLock::new();
    SURVEY.get_or_init(|| {
        let bins = ALL.iter().map(|&bin| {
            let (path, named_by) = bin.locate();
            Found { input: Input::Bin(bin), present: path.exists(), path, named_by }
        });
        let apps = APPS.iter().map(|&app| {
            let path = app.built_at();
            Found { input: Input::App(app), present: path.exists(), path, named_by: None }
        });
        bins.chain(apps).collect()
    })
}

/// The path to `input`, or a failure naming every input the suite needs that is not built,
/// with the commands that build them together.
fn require_input(input: Input) -> &'static Path {
    let all = survey();
    let found = all.iter().find(|f| f.input == input).expect("every input is surveyed");
    assert!(found.present, "{}", missing_report(input, all));
    &found.path
}

/// The path to `bin`, or a failure naming every binary the suite runs that is not built,
/// with the commands that build them together.
pub fn require(bin: Bin) -> &'static Path {
    require_input(Input::Bin(bin))
}

/// The path to the shell's `app.wasm`, or the same failure [`require`] gives, which
/// names it beside anything else that is also missing: the other apps, the binaries.
pub fn require_shell_wasm() -> &'static Path {
    require_input(Input::App(App::Shell))
}

/// The apps are bundled in the `kuserd` this suite links, or a failure that says why not.
///
/// `kuserd` embeds the guest apps only if **all three** exist when *it* compiles
/// (`core/kuserd/build.rs`), so a suite built before `cargo xtask build-apps` ran links a
/// daemon that installs no shell, however present the files are now. `bundled` is what
/// the test observed of that daemon. A file that is missing is named first, with any
/// other input that is, so the cause that can be fixed is the one reported.
pub fn require_apps_bundled(bundled: bool) {
    let all = survey();
    if let Some(app) = APPS.iter().find(|&&a| !all.iter().any(|f| f.input == Input::App(a) && f.present)) {
        require_input(Input::App(*app));
    }
    assert!(
        bundled,
        "the guest apps are built, but the kuserd this suite links was compiled before they \
         were, so a new identity receives no shell and this test has nothing to launch.\n\
         kuserd embeds the apps only when all three exist as it compiles (core/kuserd/build.rs):\n  \
         cargo test -p kotton-integration-tests --test suite    (rebuilds kuserd, which watches the files)"
    );
}

/// What a test whose input is missing says: all of them, and how to build them.
fn missing_report(needed: Input, all: &[Found]) -> String {
    let missing: Vec<&Found> = all.iter().filter(|f| !f.present).collect();
    let width = missing.iter().map(|f| f.input.name().len()).max().unwrap_or(0);
    let binaries = all.iter().filter(|f| matches!(f.input, Input::Bin(_))).count();
    let apps_total = all.len() - binaries;
    let mut s = format!(
        "{} is not built, so this test cannot use it.\n\
         The suite needs {} built inputs, {binaries} binaries it runs as processes and the \
         {apps_total} guest apps' app.wasm, and {} of them {} not built:\n",
        needed.name(),
        all.len(),
        missing.len(),
        if missing.len() == 1 { "is" } else { "are" },
    );
    for f in &missing {
        let _ = write!(s, "  {:width$}  {}", f.input.name(), f.path.display());
        if let Some(var) = f.named_by {
            let _ = write!(s, "  (named by {var})");
        }
        if f.input == needed {
            s.push_str("  <- this test");
        }
        s.push('\n');
    }

    let workspace: Vec<&str> = missing
        .iter()
        .filter_map(|f| match f.input {
            Input::Bin(b) if b != Bin::Relay && f.named_by.is_none() => Some(b.name()),
            _ => None,
        })
        .collect();
    let relay =
        missing.iter().any(|f| f.input == Input::Bin(Bin::Relay) && f.named_by.is_none());
    let apps = missing.iter().any(|f| matches!(f.input, Input::App(_)));
    s.push_str("Build them together:\n");
    if apps {
        // First: `kuserd` embeds the component when it compiles, so it is built after.
        s.push_str("  cargo xtask build-apps    (before the cargo build below: kuserd embeds the apps)\n");
    }
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
            input: Input::Bin(bin),
            path: PathBuf::from(format!("/t/debug/{}", bin.name())),
            named_by,
            present,
        }
    }

    /// The three apps' components, present or not, beside the binaries.
    fn apps(shell: bool, editor: bool, records: bool) -> Vec<Found> {
        [(App::Shell, shell, "kotton-shell"), (App::Editor, editor, "kotton-editor"), (App::Records, records, "kotton-records")]
            .into_iter()
            .map(|(app, present, dir)| Found {
                input: Input::App(app),
                path: PathBuf::from(format!("/t/guest/apps/{dir}/app.wasm")),
                named_by: None,
                present,
            })
            .collect()
    }

    /// A narrow run meets every missing binary in its first failure, and one line builds
    /// the workspace's together.
    #[test]
    fn a_missing_binary_names_every_missing_one_and_the_line_that_builds_them() {
        let mut all: Vec<Found> = ALL
            .iter()
            .map(|&b| found(b, !matches!(b, Bin::MockRunner | Bin::Kvaultd | Bin::Kuserd), None))
            .collect();
        all.extend(apps(true, true, true));
        let report = missing_report(Input::Bin(Bin::Kvaultd), &all);
        assert!(report.starts_with("kvaultd is not built"), "{report}");
        assert!(report.contains("11 built inputs, 8 binaries it runs as processes and the 3 guest apps"), "{report}");
        assert!(report.contains("and 3 of them are not built"), "{report}");
        assert!(!report.contains("build-apps"), "the apps are built:\n{report}");
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
        let mut all: Vec<Found> = ALL
            .iter()
            .map(|&b| match b {
                Bin::Relay => found(b, false, None),
                Bin::Kvaultd => found(b, false, Some("KOTTON_VAULT_BIN")),
                _ => found(b, true, None),
            })
            .collect();
        all.extend(apps(true, true, true));
        let report = missing_report(Input::Bin(Bin::Relay), &all);
        assert!(!report.contains("cargo build --bin"), "{report}");
        assert!(report.contains("cargo xtask build-relay"), "{report}");
        assert!(report.contains("(named by KOTTON_VAULT_BIN)"), "{report}");
        assert!(report.contains("KOTTON_VAULT_BIN names a file that is not there"), "{report}");
    }

    /// A test that needs the shell and finds it missing is told so by name, beside the
    /// runner and the editor it also lacks, with the command that builds them before the
    /// one that builds the daemon that embeds them. The records app is built and unlisted.
    #[test]
    fn a_missing_app_is_named_beside_a_missing_binary_and_built_first() {
        let mut all: Vec<Found> =
            ALL.iter().map(|&b| found(b, b != Bin::Runner, None)).collect();
        all.extend(apps(false, false, true));
        let report = missing_report(Input::App(App::Shell), &all);
        assert!(report.starts_with("the shell's app.wasm is not built"), "{report}");
        assert!(report.contains("and 3 of them are not built"), "{report}");
        assert!(report.contains("/t/guest/apps/kotton-shell/app.wasm  <- this test\n"), "{report}");
        assert!(report.contains("/t/guest/apps/kotton-editor/app.wasm\n"), "{report}");
        assert!(!report.contains("kotton-records"), "the records app is built:\n{report}");
        assert!(report.contains("/t/debug/kotton-runner\n"), "{report}");
        let apps = report.find("cargo xtask build-apps").expect(&report);
        let bins = report.find("cargo build --bin kotton-runner").expect(&report);
        assert!(apps < bins, "the daemon embeds the apps, so they are built first:\n{report}");
    }
}
