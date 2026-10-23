// SPDX-License-Identifier: AGPL-3.0-or-later
//! Where build output lives, and how a tool finds it.
//!
//! **One directory, `out/`, at the repository root, holds every build output** — the
//! workspace's target (`out/target`), xtask's own (`out/xtask`), each guest app's wasm
//! target (`out/guest/<app>`), the relay's (`out/relay`), bindwatch's (`out/bindwatch`),
//! the merge gate's (`out/merge`), the release builds' (`out/release`) and the release
//! archives (`out/dist`). `.cargo/config.toml` sets the first with `build.target-dir` and
//! the second with the `xtask` alias; this module hands cargo the rest. `just clean`
//! deletes `out/` and nothing else
//! (`TASK-build-outputs-live-under-out-and-the-tooling-reads-where-cargo-put-them`).
//!
//! **A tool never composes a path from a layout it assumed.** Until 2026-09-26 six trees
//! lived in six places, and four tools composed the default one — `build-apps` from
//! `<app>/logic/target`, the suite from `infra/relay/target`, `release` and
//! `release-server` from `target/` — so exporting `CARGO_TARGET_DIR`, which
//! the parallel-work guide recommended, turned each of them into a wrong red (36 measured
//! on 2026-09-15; `TASK-two-builds-break-under-a-shared-target-directory`). So:
//!
//! - the workspace's target is whatever `cargo metadata` says it is ([`workspace_target`]),
//!   which is `build.target-dir` or `CARGO_TARGET_DIR`, whichever cargo chose;
//! - a separate workspace's target is the one this module *tells* cargo with
//!   `--target-dir`, so it is known by construction;
//! - and what a build produced is read from the build's own JSON messages
//!   ([`build_artifacts`]) wherever the tool ran the build.
//!
//! **Which builds may follow an exported `CARGO_TARGET_DIR` is a decision, and the caller
//! names it** (decision 0014, `docs/design/decisions/`). Cargo keys a workspace's own crates
//! by their path relative to the workspace root, so checkouts that build into one target
//! share one freshness record per crate, and a build there can be another tree's. A
//! developer's convenience build — `build-apps`, `build-relay`, bindwatch — asks
//! [`own_target`], which follows the variable, because a warm shared cache is the point of
//! exporting it. A build whose output ships or gates — what `release` and `release-server`
//! pack and test, and what `merge` checks — asks [`private_target`], which is `out/<what>`
//! in this checkout whatever the environment says.
//!
//! The repository root is asked of git ([`root`]), never baked in by `env!`: a baked root
//! is the directory xtask was *compiled* in, which a carried-over `out/xtask` makes a dead
//! path (`TASK-constitution-check-resolves-its-files-against-where-xtask-was-built`).

use std::path::{Path, PathBuf};
use std::process::Command;

/// The directory every build output lives under, relative to the repository root.
pub const OUT: &str = "out";

/// The repository this command runs in — asked of git, so it is the checkout being
/// checked and not the one xtask happened to be built in.
///
/// `git rev-parse --show-toplevel`, or `.` where git cannot say: every check is run from the
/// workspace root, where the two agree.
pub fn root() -> PathBuf {
    let root = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| PathBuf::from(String::from_utf8_lossy(&o.stdout).trim()))
        .unwrap_or_else(|| PathBuf::from("."));
    std::fs::canonicalize(&root).unwrap_or(root)
}

/// `CARGO_TARGET_DIR`, absolute, when a person or a fleet has exported it.
///
/// Resolved against the repository root when relative, because a relative value is
/// legitimate and a path handed to a test that runs somewhere else is not
/// (`TASK-the-gates-were-written-for-one-checkout`, the fifth defect).
pub fn exported_target() -> Option<PathBuf> {
    match std::env::var_os("CARGO_TARGET_DIR") {
        Some(d) if !d.is_empty() => {
            let d = PathBuf::from(d);
            Some(if d.is_absolute() { d } else { root().join(d) })
        }
        _ => None,
    }
}

/// The main workspace's target directory, as cargo reports it.
///
/// `cargo metadata` run at the repository root, so the root's `.cargo/config.toml` is the
/// one cargo reads — its `build.target-dir`, or `CARGO_TARGET_DIR` over it.
pub fn workspace_target() -> PathBuf {
    let root = root();
    let out = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps", "--offline"])
        .current_dir(&root)
        .output();
    let parsed = out
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| serde_json::from_slice::<serde_json::Value>(&o.stdout).ok())
        .and_then(|v| v.get("target_directory")?.as_str().map(PathBuf::from));
    parsed.unwrap_or_else(|| {
        eprintln!(
            "xtask: `cargo metadata` did not say where the workspace builds; run from a \
             checkout where `cargo metadata --no-deps` succeeds"
        );
        std::process::exit(1);
    })
}

/// The target directory for a **developer's convenience build** of a workspace of its own —
/// a guest app for `build-apps`, the relay for `build-relay`, bindwatch — named `sub`
/// under `out/`, **or `CARGO_TARGET_DIR` when that is exported**: such a build follows the
/// variable, so a fleet that shares a warm cache shares it here too. Never for an output that
/// ships or gates; that is [`private_target`] (decision 0014).
///
/// Callers pass this to cargo as `--target-dir`, which is what makes it true: cargo
/// discovers configuration from the directory it is *run* in, not the manifest it is
/// handed, so `build.target-dir` cannot give a second workspace a directory of its own.
pub fn own_target(sub: &str) -> PathBuf {
    exported_target().unwrap_or_else(|| private_target(sub))
}

/// The target directory for a **build whose output ships or gates**, named `sub` under this
/// checkout's `out/`, **whatever `CARGO_TARGET_DIR` says**: what `release` and
/// `release-server` build, test and pack, and what `merge` checks.
///
/// Only this checkout writes here, so every source newer than its last build was written
/// after that build and cargo rebuilds it; in a target other checkouts build into, cargo's
/// record of a crate can be another tree's, and the artifact with it (decision 0014).
/// Handed to cargo as `--target-dir`, which wins over the variable.
pub fn private_target(sub: &str) -> PathBuf {
    private_target_in(&root(), sub)
}

/// [`private_target`] under the checkout at `root`, for a caller that has been handed the
/// root rather than standing in it.
pub fn private_target_in(root: &Path, sub: &str) -> PathBuf {
    root.join(OUT).join(sub)
}

/// xtask's own target, where the alias builds it. Never `CARGO_TARGET_DIR`: the xtask
/// binary lands unhashed, and a shared directory served one checkout another's xtask
/// (measured 2026-09-15). The alias passes `--target-dir out/xtask`, which a flag wins
/// over the variable.
pub fn xtask_target() -> PathBuf {
    root().join(OUT).join("xtask")
}

/// Where release archives are written.
pub fn dist() -> PathBuf {
    root().join(OUT).join("dist")
}

/// Every file a build produced, read from cargo's own messages.
///
/// Adds `--message-format=json-render-diagnostics` to `cmd` (which must be a
/// `cargo build`), so diagnostics still reach the terminal as text and stdout carries
/// one JSON object per line. Returns `None` when the build failed.
pub fn build_artifacts(cmd: &mut Command) -> Option<Vec<PathBuf>> {
    cmd.arg("--message-format=json-render-diagnostics");
    let out = cmd
        .stderr(std::process::Stdio::inherit())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(artifacts_in(&String::from_utf8_lossy(&out.stdout)))
}

/// The artifact paths in a stream of cargo JSON messages: each `compiler-artifact`'s
/// `filenames`, and its `executable` when it has one.
fn artifacts_in(stream: &str) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for line in stream.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if v.get("reason").and_then(|r| r.as_str()) != Some("compiler-artifact") {
            continue;
        }
        for f in v
            .get("filenames")
            .and_then(|f| f.as_array())
            .into_iter()
            .flatten()
            .filter_map(|f| f.as_str())
        {
            found.push(PathBuf::from(f));
        }
        if let Some(e) = v.get("executable").and_then(|e| e.as_str()) {
            found.push(PathBuf::from(e));
        }
    }
    found.dedup();
    found
}

/// The artifact among `built` whose file name is `name`.
pub fn named<'a>(built: &'a [PathBuf], name: &str) -> Option<&'a Path> {
    built
        .iter()
        .find(|p| p.file_name().is_some_and(|n| n == name))
        .map(PathBuf::as_path)
}

/// What `cargo xtask out` answers, for its usage line and its refusal.
const OUT_USAGE: &str = "cargo xtask out [target|xtask|dist|root|relay|bindwatch|guest/<app>\
     |merge|release|release/workspace|release/relay]";

/// `cargo xtask out [what]` — print where that output lives, so a script or a recipe asks
/// rather than composes. Each private target is asked of the module that builds there.
pub fn run(args: &[String]) {
    let what = args.first().map(String::as_str).unwrap_or("target");
    let path = match what {
        "target" => workspace_target(),
        "xtask" => xtask_target(),
        "dist" => dist(),
        "root" => root().join(OUT),
        // A developer's convenience builds: `CARGO_TARGET_DIR` when it is exported.
        s if s == "relay" || s == "bindwatch" || s.starts_with("guest/") => own_target(s),
        // The gate's and the release's: this checkout's own, whatever the environment says.
        "merge" => crate::merge::own_target(&root()),
        "release" => crate::release::target(),
        "release/workspace" => crate::release::workspace_target(),
        "release/relay" => crate::release_server::target_of(&crate::release_server::RELAY),
        other => {
            eprintln!("usage: {OUT_USAGE} — `{other}` is none of those");
            std::process::exit(2);
        }
    };
    println!("{}", path.display());
}

/// Running a test under an exported `CARGO_TARGET_DIR`, for the tests that hold a build that
/// ships or gates to a target of its own whatever the variable says.
#[cfg(test)]
pub(crate) mod exported {
    use std::path::Path;
    use std::process::Command;

    /// Set in the child, so the test it runs knows it is the child.
    const CHILD: &str = "XTASK_TEST_UNDER_AN_EXPORTED_TARGET";

    /// Run `body` in a process with `CARGO_TARGET_DIR` exported to a fresh directory outside
    /// the checkout, handing it that directory: this test binary again, running only `test`
    /// (`concat!(module_path!(), "::<name>")`), with the variable in its environment from its
    /// first instruction.
    ///
    /// Not `set_var` in this process: libtest runs every test on a thread of one process and
    /// several of them run cargo, which reads the variable, so setting it here would reach
    /// builds that never asked for it.
    pub(crate) fn run(test: &str, body: impl FnOnce(&Path)) {
        if std::env::var_os(CHILD).is_some() {
            let dir = super::exported_target().expect("the parent exported CARGO_TARGET_DIR");
            return body(&dir);
        }
        let tmp = tempfile::tempdir().expect("a directory for CARGO_TARGET_DIR");
        let dir = std::fs::canonicalize(tmp.path()).unwrap();
        assert!(!dir.starts_with(super::root()), "{} is inside the checkout", dir.display());
        // libtest names a test by its path below the crate: `release::tests::<name>`.
        let name = test.split_once("::").map_or(test, |(_, t)| t);
        let out = Command::new(std::env::current_exe().unwrap())
            .args([name, "--exact", "--test-threads=1"])
            .env(CHILD, "1")
            .env("CARGO_TARGET_DIR", &dir)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        // `1 passed` as well as success: a filter that matched nothing would also exit 0.
        assert!(
            out.status.success() && stdout.contains("test result: ok. 1 passed"),
            "{name}, run with CARGO_TARGET_DIR={}:\n{stdout}\n{}",
            dir.display(),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// The claim each of those tests makes of a target: under this checkout's own `out/`, and
    /// neither the exported directory nor inside it.
    pub(crate) fn assert_private(what: &str, target: &Path, exported: &Path) {
        let out = super::root().join(super::OUT);
        assert!(
            target.starts_with(&out),
            "{what} builds in {}, which is not under {}",
            target.display(),
            out.display()
        );
        assert!(
            !target.starts_with(exported),
            "{what} builds in {}, under the exported CARGO_TARGET_DIR {}",
            target.display(),
            exported.display()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The path cargo printed is the path returned — including an executable, which is
    /// how a `bin` target's location is reported, and nothing from a message that is not
    /// an artifact.
    #[test]
    fn artifacts_are_read_from_cargo_messages() {
        let stream = r#"{"reason":"compiler-message","message":{"rendered":"warning"}}
{"reason":"compiler-artifact","target":{"kind":["cdylib"]},"filenames":["/x/out/guest/a/wasm32-wasip2/release/a.wasm"],"executable":null}
{"reason":"compiler-artifact","target":{"kind":["bin"]},"filenames":["/x/out/relay/debug/kotton-relay"],"executable":"/x/out/relay/debug/kotton-relay"}
{"reason":"build-finished","success":true}"#;
        let got = artifacts_in(stream);
        assert_eq!(
            got,
            vec![
                PathBuf::from("/x/out/guest/a/wasm32-wasip2/release/a.wasm"),
                PathBuf::from("/x/out/relay/debug/kotton-relay"),
            ]
        );
        assert_eq!(
            named(&got, "a.wasm"),
            Some(Path::new("/x/out/guest/a/wasm32-wasip2/release/a.wasm"))
        );
    }

    /// **The two kinds of target, under an exported `CARGO_TARGET_DIR`:** a convenience
    /// build's is the exported directory, and a build that ships or gates has
    /// `out/<what>` in this checkout, whatever the variable says.
    #[test]
    fn a_private_target_is_the_checkouts_own_where_a_convenience_target_follows_the_variable() {
        exported::run(
            concat!(module_path!(), "::a_private_target_is_the_checkouts_own_where_a_convenience_target_follows_the_variable"),
            |dir| {
                assert_eq!(own_target("relay"), dir, "a convenience build follows the variable");
                let private = private_target("release/relay");
                assert_eq!(private, root().join("out").join("release").join("relay"));
                exported::assert_private("private_target", &private, dir);
            },
        );
    }

    /// The workspace target is what cargo says: under `out/` in this checkout unless
    /// `CARGO_TARGET_DIR` is exported, and never the default `target/`.
    #[test]
    fn the_workspace_target_is_asked_of_cargo() {
        let t = workspace_target();
        match exported_target() {
            Some(e) => assert_eq!(t, e),
            None => assert_eq!(t, root().join("out").join("target")),
        }
    }

    /// **The arrangement a fleet uses, end to end:** `CARGO_TARGET_DIR` exported to a
    /// directory outside the checkout, and the relay build, the mock runner build and one
    /// suite module — `relay_presence::`, which spawns the relay through `common::relay`
    /// from the path `build.rs` located — all succeed under it, with their output landing
    /// there and not under `out/`. Every one of these failed under a shared target on
    /// 2026-09-15 (`TASK-two-builds-break-under-a-shared-target-directory`).
    ///
    /// The module is `relay_presence::`, one case, rather than `vault::`: the question is
    /// where the build lands and whether the suite finds the relay there, which one case
    /// answers, and two `vault::` cases wedge when the module runs whole
    /// (kottonllc/kotton#31), which would fail this for a reason that is not its own.
    ///
    /// Ignored because it is a cold build of the suite into a fresh directory — most of
    /// an hour and about 10 GB on four cores. Run it with
    /// `cargo test -p xtask --target-dir out/xtask -- --ignored --nocapture
    /// a_target_directory_outside_the_checkout`; `KOTTON_OUT_TEST_DIR` names the
    /// directory to use instead of a fresh temporary one.
    #[test]
    #[ignore = "cold-builds the suite into a directory outside the checkout"]
    fn a_target_directory_outside_the_checkout_builds_and_runs_the_suite() {
        let root = root();
        let temp;
        let dir = match std::env::var_os("KOTTON_OUT_TEST_DIR") {
            Some(d) => PathBuf::from(d),
            None => {
                temp = tempfile::tempdir().expect("a directory outside the checkout");
                temp.path().to_path_buf()
            }
        };
        let dir = std::fs::canonicalize(&dir).unwrap_or(dir);
        assert!(!dir.starts_with(&root), "{} is inside the checkout", dir.display());

        let step = |what: &str, args: &[&str]| {
            eprintln!("\n== {what}: cargo {} (CARGO_TARGET_DIR={})", args.join(" "), dir.display());
            let status = Command::new("cargo")
                .args(args)
                .current_dir(&root)
                .env("CARGO_TARGET_DIR", &dir)
                .status()
                .expect("run cargo");
            assert!(status.success(), "{what} failed under CARGO_TARGET_DIR={}", dir.display());
        };
        step("the relay build", &["xtask", "build-relay"]);
        step("the suite's runner", &["build", "--bin", "kotton-mock-runner"]);
        step(
            "one suite module",
            &["test", "-p", "kotton-integration-tests", "--test", "suite", "--", "relay_presence::"],
        );

        // And the output is where the variable said, which is the whole claim.
        for built in [
            dir.join("debug/kotton-relay"),
            dir.join("debug/kotton-mock-runner"),
        ] {
            assert!(built.is_file(), "{} was not built there", built.display());
        }
    }
}
