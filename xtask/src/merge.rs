// SPDX-License-Identifier: AGPL-3.0-or-later
//! `merge`: a branch reaches `main` through one recipe, and the recipe builds the tree `main`
//! would carry before it carries it.
//!
//! ## Why this exists
//!
//! `main` once did not compile. Each side of that merge compiled on its own; the merged tree
//! was never built, and the merge was a hand-typed `git merge --no-ff` followed by
//! `git push origin main`, so nothing stood between a tree nobody built and `main`. It nearly
//! happened again with no textual conflict at all: each side added one `None` to the same
//! call, and git kept one of the two.
//!
//! ## What it does, in order
//!
//! 1. **Refuses unless it stands on a clean `main`** that origin has (after a fetch) — a
//!    merge made anywhere else is not the one that gets pushed.
//! 2. **Refuses unless the branch is current with `main`**: every commit on `main` is already
//!    in the branch. That is what makes the merged tree *the branch's own tree*: a `--no-ff` merge of a
//!    branch that contains `main` produces exactly the tip's tree, so whatever the branch's
//!    executive gated is what lands. A branch that is behind is a merged tree nobody gated.
//! 3. **Runs `signoff-check` at the tip**, the branch checked out
//!    detached, with the xtask that runs this recipe — `main`'s gate, not the branch's, so a
//!    branch does not judge itself by a check it rewrote.
//! 4. **Merges `--no-ff --no-commit`, and builds the merged tree**: `cargo check --workspace
//!    --all-targets --locked`, which covers xtask (a workspace member), and the relay's own
//!    workspace when the tree has one. A failure aborts the merge: nothing was committed, so
//!    there is nothing to undo. Both build in the merge's own target, `out/merge/` under
//!    this checkout, whatever `CARGO_TARGET_DIR` says: see below.
//! 5. **Commits as the owner**, with one trailer block naming every step above with its real
//!    exit — a check marked as measured against `main` ends `@<the origin/main it measured>` —
//!    then `Assisted-by: Claude Code`, and last the owner's own `Signed-off-by:` (name and
//!    address from `signoff_check::PEOPLE`), because a commit authored as a person is
//!    certified by that person (CONTRIBUTING.md, "Every commit is signed off": a merge commit is a commit). A check or
//!    build that could not start, or was killed, is
//!    refused as not run, never as a tree that fails.
//! 6. **Pushes `main`**, and if the push is refused (someone else merged first), takes the
//!    merge commit back off the local `main` so the next attempt starts from origin's.
//!
//! ## What it is not
//!
//! It is not a lock on the remote. A person can still type `git merge` and `git push`; this
//! makes the built merge the one-command path. The seam back toward a merge that *cannot* reach `main` unbuilt is a
//! check on the receiving side, which needs a forge setting or a server this repository does
//! not run.
//!
//! It does not build the guest apps (`wasm32-wasip2`, `cargo xtask build-apps`) or run tests.
//! `cargo check` is the floor that would have stopped `96eb0b9`, cheap on a warm cache; the
//! branch's own `just test` is the bar, and step 2 is what makes that run describe this tree.
//! That run builds wherever its contributor pointed it, a shared target included, so it
//! describes this tree only as far as the touch rule reaches. The check here is the exit that
//! counts for the merged workspace and the relay compiling, and for nothing else: a test's
//! exit and a guest crate's build stand on the branch's run and the assessor's
//! (docs/design/decisions/0018).
//!
//! ## Why the builds have a target of their own
//!
//! Cargo decides a crate is up to date by comparing its sources' modification times with
//! the record of its last build, and it names a workspace's own crates by their path
//! *relative to the workspace root*. So two checkouts of this repository building into one
//! target directory (an exported `CARGO_TARGET_DIR` that several checkouts build into, as a
//! fleet of parallel agents does) share one record per crate: a build of another tree,
//! finished after this merge wrote its files, makes the merged tree's sources look older
//! than an artifact that was never built from them, and the check compiles nothing and exits
//! 0. The gate would pass a tree nobody built, which is the one thing it exists to stop.
//!
//! So each build is handed `--target-dir` (which wins over the variable) under
//! `out/merge/`, a directory only this checkout's merges build in. There, every file whose
//! content differs from what was last checked was written by git after that check, so its
//! time is newer and cargo rebuilds it. The cost is one cold check of each workspace the
//! first time, and the disk it holds; after that a merge rechecks what changed since the
//! last merge. Touching the files the merge changed, in the shared target, was the cheaper
//! option and is not sound: a crate the merge did not change can still have been built from
//! another checkout's different content, and the touched crates would be checked against it.
//!
//! Usage: `cargo xtask merge <branch> -m "<message>" [--no-fetch] [--no-push]`

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The branch merges land on, and the remote they are pushed to.
const MAIN: &str = "main";
const REMOTE: &str = "origin";
const ORIGIN_MAIN: &str = "refs/remotes/origin/main";

/// Trailer keys the recipe writes itself, so a message carrying one would end with two blocks.
const OWN_TRAILERS: &[&str] = &["Gates:", "Assisted-by:", "Signed-off-by:"];

/// One command the recipe runs and whose exit it reports.
#[derive(Clone, Debug)]
pub(crate) struct Step {
    /// How the step is named in the `Gates:` trailer.
    pub label: String,
    pub program: OsString,
    pub args: Vec<String>,
    /// The trailer clause ends `@<sha>`: the `origin/main` it was measured against.
    pub at_main: bool,
}

impl Step {
    fn new(label: &str, program: impl Into<OsString>, args: &[&str]) -> Step {
        Step {
            label: label.to_string(),
            program: program.into(),
            args: args.iter().map(|a| a.to_string()).collect(),
            at_main: false,
        }
    }

    /// Run it in `dir`, output through to the person watching: its exit code, or why there is
    /// none. A step that could not be started, or was killed by a signal, said nothing about
    /// the tree, and is kept apart from one that exited non-zero.
    fn run(&self, dir: &Path) -> Result<i32, String> {
        println!("merge: running {}", self.label);
        let status = Command::new(&self.program)
            .args(&self.args)
            .current_dir(dir)
            .status()
            .map_err(|e| format!("could not be started: {e}"))?;
        status.code().ok_or_else(|| format!("ended with no exit code ({status})"))
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Options {
    pub fetch: bool,
    pub push: bool,
}

/// Why a merge was not made. Every variant leaves `main` where it was, locally and on origin.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    NotOnMain(String),
    Dirty(String),
    NoSuchBranch(String),
    Message(String),
    /// Local `main` and origin's disagree in a way a fast-forward does not settle.
    MainDiverged(String),
    NothingToMerge,
    /// `main` has commits the branch does not.
    Behind(usize),
    CheckFailed { step: String, code: i32 },
    Conflict,
    BuildFailed { step: String, code: i32 },
    /// A check or a build that did not run to an exit: it could not be started, or it was
    /// killed. It says nothing about the tree, so it is not reported as a tree that fails.
    NotRun { step: String, why: String },
    PushRejected,
    Git(String),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::NotOnMain(on) => write!(
                f,
                "this checkout is on `{on}`, not `{MAIN}`. A merge is made on the main it is \
                 pushed from: `git checkout {MAIN}`, then run this again"
            ),
            Refusal::Dirty(st) => write!(
                f,
                "the working tree is not clean, and the merge would carry it:\n{st}"
            ),
            Refusal::NoSuchBranch(b) => write!(f, "`{b}` does not name a commit here"),
            Refusal::Message(why) => write!(f, "{why}"),
            Refusal::MainDiverged(why) => write!(f, "{why}"),
            Refusal::NothingToMerge => write!(f, "`{MAIN}` already contains the branch"),
            Refusal::Behind(n) => write!(
                f,
                "the branch is {n} commit(s) behind `{MAIN}`, so the tree this would merge is \
                 one nobody built. On the branch: `git merge origin/main`, re-gate, push, and \
                 run this again"
            ),
            Refusal::CheckFailed { step, code } => write!(
                f,
                "`{step}` exited {code} at the branch's tip. Nothing was merged"
            ),
            Refusal::Conflict => write!(f, "the merge conflicts; it was aborted"),
            Refusal::BuildFailed { step, code } => write!(
                f,
                "the merged tree does not build: `{step}` exited {code}. The merge was aborted \
                 and `{MAIN}` is unchanged. Merge origin/main into the branch, build it there, \
                 and fix it on the branch"
            ),
            Refusal::NotRun { step, why } => write!(
                f,
                "`{step}` did not run to an exit — it {why} — so nothing is known about the \
                 tree. Nothing was merged and `{MAIN}` is unchanged; run it again where it can run"
            ),
            Refusal::PushRejected => write!(
                f,
                "origin refused the push — someone merged first. The merge was taken back off \
                 the local `{MAIN}`; merge origin/main into the branch, re-gate, and run this again"
            ),
            Refusal::Git(why) => write!(f, "{why}"),
        }
    }
}

/// What a made merge was.
#[derive(Debug)]
pub(crate) struct Merged {
    pub commit: String,
    pub onto: String,
    pub gates: String,
    pub pushed: bool,
}

/// `git` in `dir`: stdout trimmed on success, stderr on failure.
fn git(dir: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .map_err(|e| format!("git {}: {e}", args.join(" ")))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim_end().to_string())
    } else {
        Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

fn git_ok(dir: &Path, args: &[&str]) -> bool {
    git(dir, args).is_ok()
}

fn count(dir: &Path, range: &str) -> Result<usize, Refusal> {
    git(dir, &["rev-list", "--count", range])
        .map_err(Refusal::Git)?
        .trim()
        .parse()
        .map_err(|e| Refusal::Git(format!("rev-list --count {range}: {e}")))
}

/// The cargo that is running this, or `cargo` from the path.
fn cargo() -> OsString {
    std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into())
}

/// The merge's own target directory under the checkout at `root`, `out/merge`: a private
/// target (`out::private_target_in`), never `CARGO_TARGET_DIR`, which other checkouts may
/// build into (the module's "Why the builds have a target of their own", and decision 0014).
pub(crate) fn own_target(root: &Path) -> PathBuf {
    crate::out::private_target_in(root, "merge")
}

/// Under the merge's target, the directory each workspace's check builds in.
const WORKSPACE: &str = "workspace";
const RELAY: &str = "relay";

/// The build caches the gate leaves under the checkout at `root`, one per workspace it
/// checks: what `reclaim` prunes alongside `out/target` and `out/xtask`.
pub(crate) fn caches(root: &Path) -> Vec<PathBuf> {
    let target = own_target(root);
    vec![target.join(WORKSPACE), target.join(RELAY)]
}

/// The builds the merged tree in `dir` must pass: the workspace, and every workspace of its
/// own that `just lint` reaches with cargo and the workspace does not — today, the relay.
/// Each builds in a directory of its own under `target`, handed to cargo as `--target-dir`
/// so an exported `CARGO_TARGET_DIR` cannot choose it.
pub(crate) fn builds(dir: &Path, target: &Path) -> Vec<Step> {
    let mut steps = Vec::new();
    if dir.join("Cargo.toml").is_file() {
        let target = target.join(WORKSPACE);
        let target = target.to_string_lossy();
        steps.push(Step::new(
            "cargo check --workspace --all-targets --locked",
            cargo(),
            &["check", "--workspace", "--all-targets", "--locked", "--target-dir", &target],
        ));
    }
    if dir.join("infra/relay/Cargo.toml").is_file() {
        let target = target.join(RELAY);
        let target = target.to_string_lossy();
        steps.push(Step::new(
            "cargo check --manifest-path infra/relay/Cargo.toml --all-targets --locked",
            cargo(),
            &[
                "check",
                "--manifest-path",
                "infra/relay/Cargo.toml",
                "--all-targets",
                "--locked",
                "--target-dir",
                &target,
            ],
        ));
    }
    steps
}

/// The check run at the branch's tip: the certificate check, with this xtask binary.
fn tip_checks() -> Vec<Step> {
    let me: OsString = std::env::current_exe()
        .map(PathBuf::into_os_string)
        .unwrap_or_else(|_| "xtask".into());
    vec![Step::new("signoff-check", me, &["signoff-check"])]
}

/// Make the merge, or say why not. `checks` run at the tip; `builds` is asked for the merged
/// tree's builds once the merge is in the working tree.
pub(crate) fn merge(
    dir: &Path,
    branch: &str,
    message: &str,
    opts: Options,
    checks: &[Step],
    builds: impl Fn(&Path) -> Vec<Step>,
) -> Result<Merged, Refusal> {
    // 1. A clean `main`, the one origin has.
    let on = git(dir, &["symbolic-ref", "--quiet", "--short", "HEAD"])
        .unwrap_or_else(|_| "a detached HEAD".to_string());
    if on != MAIN {
        return Err(Refusal::NotOnMain(on));
    }
    let status = git(dir, &["status", "--porcelain"]).map_err(Refusal::Git)?;
    if !status.is_empty() {
        return Err(Refusal::Dirty(status));
    }
    if message.trim().is_empty() {
        return Err(Refusal::Message(
            "a merge says what and why: pass -m \"Merge: …\"".to_string(),
        ));
    }
    if let Some(line) = message
        .lines()
        .find(|l| OWN_TRAILERS.iter().any(|t| l.trim_start().starts_with(t)))
    {
        return Err(Refusal::Message(format!(
            "the message carries `{}`; the recipe writes the trailer block itself, from what it ran",
            line.trim()
        )));
    }
    let tip = git(dir, &["rev-parse", "--verify", "--quiet", &format!("{branch}^{{commit}}")])
        .map_err(|_| Refusal::NoSuchBranch(branch.to_string()))?;

    if opts.fetch {
        git(dir, &["fetch", "--quiet", REMOTE, &format!("+refs/heads/{MAIN}:{ORIGIN_MAIN}")])
            .map_err(Refusal::Git)?;
    }
    if git_ok(dir, &["rev-parse", "--verify", "--quiet", ORIGIN_MAIN]) {
        let ahead = count(dir, &format!("{ORIGIN_MAIN}..{MAIN}"))?;
        let behind = count(dir, &format!("{MAIN}..{ORIGIN_MAIN}"))?;
        if ahead > 0 && opts.push {
            return Err(Refusal::MainDiverged(format!(
                "the local `{MAIN}` carries {ahead} commit(s) origin does not; pushing would \
                 publish them unreviewed. Push or drop them first"
            )));
        }
        if behind > 0 {
            if ahead > 0 {
                return Err(Refusal::MainDiverged(format!(
                    "the local `{MAIN}` and origin's have diverged ({ahead} ahead, {behind} behind)"
                )));
            }
            git(dir, &["merge", "--quiet", "--ff-only", ORIGIN_MAIN]).map_err(Refusal::Git)?;
        }
    } else if opts.push {
        return Err(Refusal::Git(format!(
            "no `{ORIGIN_MAIN}` here, so there is nothing to push onto"
        )));
    }
    let onto = git(dir, &["rev-parse", "HEAD"]).map_err(Refusal::Git)?;
    // A check marked `at_main` measures against `origin/main`, never the local `main`, so that
    // is the sha its clause names. With a push they are the same commit; with
    // `--no-push` and a local `main` ahead of origin's they are not, and stamping the first
    // parent would claim a measurement that was not made. Step 2 below holds the branch to
    // the local `main` itself.
    let measured = git(dir, &["rev-parse", "--verify", "--quiet", ORIGIN_MAIN]).ok();
    let measured = measured.as_deref().map(|m| &m[..m.len().min(8)]);

    // 2. Current with `main`.
    if git_ok(dir, &["merge-base", "--is-ancestor", &tip, &onto]) {
        return Err(Refusal::NothingToMerge);
    }
    let behind = count(dir, &format!("{tip}..{onto}"))?;
    if behind > 0 {
        return Err(Refusal::Behind(behind));
    }

    // 3. The checks, at the tip.
    let mut gates: Vec<String> = Vec::new();
    if !checks.is_empty() {
        git(dir, &["checkout", "--quiet", "--detach", &tip]).map_err(Refusal::Git)?;
        let mut failed = None;
        for step in checks {
            match step.run(dir) {
                Ok(code) => {
                    gates.push(clause(step, code, measured));
                    if code != 0 {
                        failed = Some(Refusal::CheckFailed { step: step.label.clone(), code });
                        break;
                    }
                }
                Err(why) => {
                    failed = Some(Refusal::NotRun { step: step.label.clone(), why });
                    break;
                }
            }
        }
        git(dir, &["checkout", "--quiet", MAIN]).map_err(Refusal::Git)?;
        if let Some(refusal) = failed {
            return Err(refusal);
        }
    }

    // 4. Merge without committing, and build what is in the working tree.
    if git(dir, &["merge", "--quiet", "--no-ff", "--no-commit", &tip]).is_err() {
        let _ = git(dir, &["merge", "--abort"]);
        return Err(Refusal::Conflict);
    }
    let mut build_gates = Vec::new();
    for step in builds(dir) {
        let ran = step.run(dir);
        if ran != Ok(0) {
            git(dir, &["merge", "--abort"]).map_err(Refusal::Git)?;
            return Err(match ran {
                Ok(code) => Refusal::BuildFailed { step: step.label, code },
                Err(why) => Refusal::NotRun { step: step.label, why },
            });
        }
        build_gates.push(clause(&step, 0, measured));
    }
    // The builds first in the trailer: they are about this tree, the checks about the branch.
    build_gates.extend(gates);
    let gates = build_gates.join("; ");

    // 5. Commit as the owner, with one trailer block.
    let (name, email) = crate::signoff_check::PEOPLE[0];
    let full = format!(
        "{}\n\nGates: {gates}\nAssisted-by: Claude Code\nSigned-off-by: {name} <{email}>\n",
        message.trim_end()
    );
    let committed = Command::new("git")
        .current_dir(dir)
        .args(["commit", "--quiet", "--cleanup=verbatim", "-m", &full])
        .env("GIT_AUTHOR_NAME", name)
        .env("GIT_AUTHOR_EMAIL", email)
        .env("GIT_COMMITTER_NAME", name)
        .env("GIT_COMMITTER_EMAIL", email)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !committed {
        let _ = git(dir, &["merge", "--abort"]);
        return Err(Refusal::Git("the merge commit could not be written; aborted".to_string()));
    }
    let commit = git(dir, &["rev-parse", "HEAD"]).map_err(Refusal::Git)?;

    // 6. Push, or take the merge back off the local `main`.
    if opts.push && git(dir, &["push", "--quiet", REMOTE, MAIN]).is_err() {
        git(dir, &["reset", "--quiet", "--keep", &onto]).map_err(Refusal::Git)?;
        return Err(Refusal::PushRejected);
    }
    Ok(Merged { commit, onto, gates, pushed: opts.push })
}

/// `<label> <exit>`, and for a step measured against `origin/main`, ` @<the sha it measured>`
/// — or `(no origin/main)` when there was none to measure against.
fn clause(step: &Step, code: i32, measured: Option<&str>) -> String {
    match (step.at_main, measured) {
        (false, _) => format!("{} {code}", step.label),
        (true, Some(sha)) => format!("{} {code} @{sha}", step.label),
        (true, None) => format!("{} {code} (no origin/main)", step.label),
    }
}

/// `cargo xtask merge <branch> -m "<message>" [--no-fetch] [--no-push]`
pub fn run(args: &[String]) {
    let mut branch = None;
    let mut message = None;
    let mut opts = Options { fetch: true, push: true };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-m" | "--message" => message = it.next().cloned(),
            "--no-fetch" => opts.fetch = false,
            "--no-push" => opts.push = false,
            s if s.starts_with('-') => usage(&format!("unknown flag `{s}`")),
            s if branch.is_none() => branch = Some(s.to_string()),
            s => usage(&format!("one branch per merge; `{s}` is a second")),
        }
    }
    let Some(branch) = branch else { usage("name the branch to merge") };
    let Some(message) = message else { usage("a merge says what and why: -m \"Merge: …\"") };

    let root = crate::out::root();
    let target = own_target(&root);
    match merge(&root, &branch, &message, opts, &tip_checks(), |d| builds(d, &target)) {
        Ok(m) => {
            println!(
                "merge: {} onto {}{}\n  Gates: {}",
                &m.commit[..m.commit.len().min(8)],
                &m.onto[..m.onto.len().min(8)],
                if m.pushed { ", pushed to origin/main" } else { ", not pushed (--no-push)" },
                m.gates
            );
        }
        Err(r) => {
            eprintln!("merge: REFUSED — {r}");
            std::process::exit(1);
        }
    }
}

fn usage(why: &str) -> ! {
    eprintln!(
        "merge: {why}\n\nusage: cargo xtask merge <branch> -m \"<message>\" [--no-fetch] [--no-push]"
    );
    std::process::exit(2);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// A bare origin and a clone of it, both in one temporary directory, the clone holding a
    /// tiny cargo workspace on `main`, and the fixture's own target directory beside them.
    ///
    /// Every fixture's crate is `twosides` at the root of its workspace, so in one shared
    /// target directory every fixture would share one cargo record: a parallel test's build
    /// of a tree that compiles, finished after this one's merge was written, read as this
    /// merged tree's, and the check that must fail compiled nothing and passed. Each fixture
    /// building in its own `target` is what keeps the merged tree the one checked.
    struct Fixture {
        _tmp: tempfile::TempDir,
        origin: PathBuf,
        clone: PathBuf,
        target: PathBuf,
    }

    fn g(dir: &Path, args: &[&str]) -> String {
        git(dir, args).unwrap_or_else(|e| panic!("{e}"))
    }

    fn write(dir: &Path, path: &str, body: &str) {
        let p = dir.join(path);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    }

    fn commit_all(dir: &Path, msg: &str) {
        g(dir, &["add", "-A"]);
        g(dir, &["commit", "--quiet", "-m", msg]);
    }

    /// `cargo check` on whatever the clone has checked out, in the fixture's own target:
    /// does this tree compile on its own?
    fn compiles(fx: &Fixture) -> bool {
        builds(&fx.clone, &fx.target)
            .iter()
            .all(|s| s.run(&fx.clone) == Ok(0))
    }

    impl Fixture {
        /// `main` holds `f(a)` and one caller of it.
        fn new() -> Fixture {
            let tmp = tempfile::tempdir().unwrap();
            let origin = tmp.path().join("origin.git");
            let clone = tmp.path().join("clone");
            let target = tmp.path().join("target");
            g(tmp.path(), &["init", "--quiet", "--bare", "-b", MAIN, origin.to_str().unwrap()]);
            g(tmp.path(), &["init", "--quiet", "-b", MAIN, clone.to_str().unwrap()]);
            for (k, v) in [
                ("user.name", "Fixture"),
                ("user.email", "fixture@example.invalid"),
                ("commit.gpgsign", "false"),
            ] {
                g(&clone, &["config", k, v]);
            }
            // No hook of this machine's runs in the fixture.
            let hooks = tmp.path().join("no-hooks");
            fs::create_dir_all(&hooks).unwrap();
            g(&clone, &["config", "core.hooksPath", hooks.to_str().unwrap()]);
            g(&clone, &["remote", "add", REMOTE, origin.to_str().unwrap()]);
            write(
                &clone,
                "Cargo.toml",
                "[package]\nname = \"twosides\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n",
            );
            write(&clone, ".gitignore", "/target\n");
            write(&clone, "src/lib.rs", "pub mod f;\npub mod one;\n");
            write(&clone, "src/f.rs", "pub fn f(a: u32) -> u32 {\n    a\n}\n");
            write(&clone, "src/one.rs", "pub fn one() -> u32 {\n    crate::f::f(1)\n}\n");
            // The lockfile this cargo writes, so `--locked` holds whatever its version.
            let locked = Command::new(cargo())
                .args(["generate-lockfile", "--offline"])
                .current_dir(&clone)
                .status()
                .unwrap();
            assert!(locked.success(), "cargo generate-lockfile");
            commit_all(&clone, "base");
            g(&clone, &["push", "--quiet", REMOTE, MAIN]);
            Fixture { _tmp: tmp, origin, clone, target }
        }

        /// `main` gives `f` a second argument and updates its one caller. Compiles.
        fn main_adds_an_argument(&self) {
            write(&self.clone, "src/f.rs", "pub fn f(a: u32, b: u32) -> u32 {\n    a + b\n}\n");
            write(&self.clone, "src/one.rs", "pub fn one() -> u32 {\n    crate::f::f(1, 0)\n}\n");
            commit_all(&self.clone, "main: f takes two");
            g(&self.clone, &["push", "--quiet", REMOTE, MAIN]);
        }

        /// A branch cut from the base adds a second caller of the one-argument `f`. Compiles
        /// on its own, and touches no line `main_adds_an_argument` does.
        fn branch_adds_a_caller(&self, base: &str) {
            g(&self.clone, &["checkout", "--quiet", "-b", "side", base]);
            write(&self.clone, "src/lib.rs", "pub mod f;\npub mod one;\npub mod two;\n");
            write(&self.clone, "src/two.rs", "pub fn two() -> u32 {\n    crate::f::f(2)\n}\n");
            commit_all(&self.clone, "side: a second caller");
        }

        fn head(&self, rev: &str) -> String {
            g(&self.clone, &["rev-parse", rev])
        }

        fn origin_main(&self) -> String {
            g(&self.origin, &["rev-parse", MAIN])
        }

        fn merge(&self, checks: &[Step]) -> Result<Merged, Refusal> {
            merge(
                &self.clone,
                "side",
                "Merge: side",
                Options { fetch: true, push: true },
                checks,
                |d| builds(d, &self.target),
            )
        }
    }

    /// The defect this recipe exists for, reproduced: two sides that each compile, merged
    /// cleanly by git into a tree that does not, are stopped before `main` moves.
    #[test]
    fn a_merge_whose_sides_compile_apart_and_not_together_is_refused() {
        let fx = Fixture::new();
        let base = fx.head("HEAD");
        fx.main_adds_an_argument();
        assert!(compiles(&fx), "main compiles on its own");
        fx.branch_adds_a_caller(&base);
        assert!(compiles(&fx), "the branch compiles on its own");
        // The branch is brought current, as the procedure asks; git merges it with no
        // conflict, and nobody builds it.
        g(&fx.clone, &["merge", "--quiet", "--no-edit", MAIN]);
        g(&fx.clone, &["checkout", "--quiet", MAIN]);
        let main_before = fx.head(MAIN);

        let refused = fx.merge(&[]).expect_err("an unbuildable merge must be refused");
        assert!(
            matches!(refused, Refusal::BuildFailed { .. }),
            "refused for the build, not something else: {refused:?}"
        );
        assert_eq!(fx.head(MAIN), main_before, "the local main did not move");
        assert_eq!(fx.origin_main(), main_before, "origin's main did not move");
        assert!(
            g(&fx.clone, &["status", "--porcelain"]).is_empty(),
            "the merge was aborted, not left half-made"
        );
        assert!(!fx.clone.join(".git/MERGE_HEAD").exists());
    }

    /// Every build the gate runs names its target with `--target-dir`, which wins over an
    /// exported `CARGO_TARGET_DIR`, and each workspace gets a directory of its own under the
    /// merge's: the gate's target is chosen by the recipe, never inherited from the shell.
    #[test]
    fn every_gate_build_names_a_target_of_its_own_under_the_merges() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "Cargo.toml", "[workspace]\n");
        write(tmp.path(), "infra/relay/Cargo.toml", "[workspace]\n");
        let root = tmp.path().join("checkout");
        let target = own_target(&root);
        assert_eq!(target, root.join("out").join("merge"));

        let steps = builds(tmp.path(), &target);
        assert_eq!(steps.len(), 2, "the workspace and the relay: {steps:?}");
        let mut dirs = Vec::new();
        for step in &steps {
            let at = step.args.iter().position(|a| a == "--target-dir");
            let dir = at.and_then(|i| step.args.get(i + 1)).map(PathBuf::from);
            let dir = dir.unwrap_or_else(|| panic!("`{}` names no --target-dir", step.label));
            assert!(dir.starts_with(&target), "`{}` builds in {}", step.label, dir.display());
            assert!(!step.label.contains("--target-dir"), "the Gates label is unchanged");
            dirs.push(dir);
        }
        assert_ne!(dirs[0], dirs[1], "the two workspaces do not share a target");
        assert_eq!(dirs, caches(&root), "what the gate builds in is what reclaim prunes");
    }

    /// Under an exported `CARGO_TARGET_DIR`, the gate in this checkout still builds under its
    /// own `out/merge`, and every build it runs names a directory there, not the exported one.
    #[test]
    fn the_gate_builds_in_its_own_target_under_an_exported_cargo_target_dir() {
        crate::out::exported::run(
            concat!(module_path!(), "::the_gate_builds_in_its_own_target_under_an_exported_cargo_target_dir"),
            |exported| {
                let root = crate::out::root();
                let target = own_target(&root);
                crate::out::exported::assert_private("merge", &target, exported);
                let tmp = tempfile::tempdir().unwrap();
                write(tmp.path(), "Cargo.toml", "[workspace]\n");
                write(tmp.path(), "infra/relay/Cargo.toml", "[workspace]\n");
                let steps = builds(tmp.path(), &target);
                assert_eq!(steps.len(), 2, "the workspace and the relay: {steps:?}");
                for step in &steps {
                    let at = step.args.iter().position(|a| a == "--target-dir");
                    let dir = at.and_then(|i| step.args.get(i + 1)).map(PathBuf::from);
                    let dir = dir.unwrap_or_else(|| panic!("`{}` names no --target-dir", step.label));
                    crate::out::exported::assert_private(&step.label, &dir, exported);
                }
            },
        );
    }

    /// A branch that has not merged `main` is refused before anything is merged or built:
    /// the tree it would land is one nobody gated.
    #[test]
    fn a_branch_behind_main_is_refused_before_it_is_merged() {
        let fx = Fixture::new();
        let base = fx.head("HEAD");
        fx.main_adds_an_argument();
        fx.branch_adds_a_caller(&base);
        g(&fx.clone, &["checkout", "--quiet", MAIN]);
        let main_before = fx.head(MAIN);

        assert_eq!(fx.merge(&[]).unwrap_err(), Refusal::Behind(1));
        assert_eq!(fx.head(MAIN), main_before);
        assert_eq!(fx.origin_main(), main_before);
    }

    /// The same two sides, with the branch's caller fixed after it merged `main`: merged,
    /// committed as the owner with one trailer block, and pushed. The tip check runs at the
    /// tip — `git diff --quiet <tip>` exits 0 only when the working tree is the tip's.
    #[test]
    fn a_current_branch_that_builds_is_merged_as_the_owner_and_pushed() {
        let fx = Fixture::new();
        let base = fx.head("HEAD");
        fx.main_adds_an_argument();
        fx.branch_adds_a_caller(&base);
        g(&fx.clone, &["merge", "--quiet", "--no-edit", MAIN]);
        write(&fx.clone, "src/two.rs", "pub fn two() -> u32 {\n    crate::f::f(2, 0)\n}\n");
        commit_all(&fx.clone, "side: the second caller passes two");
        let tip = fx.head("HEAD");
        g(&fx.clone, &["checkout", "--quiet", MAIN]);
        let main_before = fx.head(MAIN);

        let mut at_tip = Step::new("at-the-tip", "git", &["diff", "--quiet", &tip]);
        at_tip.at_main = true;
        let m = fx.merge(&[at_tip]).expect("a current branch that builds is merged");

        assert_eq!(fx.origin_main(), m.commit, "pushed");
        assert_eq!(fx.head(MAIN), m.commit);
        assert_eq!(fx.head("HEAD^1"), main_before, "first parent is the main it was made onto");
        assert_eq!(fx.head("HEAD^2"), tip, "second parent is the branch's tip");
        let (name, email) = crate::signoff_check::PEOPLE[0];
        let who = g(&fx.clone, &["log", "-1", "--format=%an <%ae>|%cn <%ce>"]);
        assert_eq!(who, format!("{name} <{email}>|{name} <{email}>"));
        let body = g(&fx.clone, &["log", "-1", "--format=%B"]);
        let short = &main_before[..8];
        assert!(
            body.trim_end().ends_with(&format!(
                "\n\nGates: cargo check --workspace --all-targets --locked 0; at-the-tip 0 @{short}\n\
                 Assisted-by: Claude Code\n\
                 Signed-off-by: {name} <{email}>"
            )),
            "one trailer block naming every step and its exit:\n{body}"
        );
        // `signoff-check` over the range holding only the merge the gate made passes.
        let (n, found) = crate::signoff_check::check(&fx.clone, &[&main_before, &tip])
            .expect("the range reads");
        assert_eq!((n, found.len()), (1, 0), "{found:#?}");
    }

    /// A tip check that fails stops the merge before it is made, and leaves the checkout on
    /// `main`, where it was.
    #[test]
    fn a_failing_tip_check_refuses_and_returns_to_main() {
        let fx = Fixture::new();
        let base = fx.head("HEAD");
        fx.branch_adds_a_caller(&base);
        g(&fx.clone, &["checkout", "--quiet", MAIN]);
        let main_before = fx.head(MAIN);

        let failing = Step::new("a-check", "git", &["rev-parse", "--verify", "--quiet", "no-such-ref"]);
        let refused = fx.merge(&[failing]).unwrap_err();
        assert!(matches!(refused, Refusal::CheckFailed { ref step, .. } if step == "a-check"));
        assert_eq!(g(&fx.clone, &["symbolic-ref", "--short", "HEAD"]), MAIN);
        assert_eq!(fx.head(MAIN), main_before);
        assert_eq!(fx.origin_main(), main_before);
    }

    /// A tip check that cannot be started has measured nothing, so it is refused as not run:
    /// never skipped, never read as a pass. The merge is not made and the checkout is back on
    /// `main`.
    #[test]
    fn a_tip_check_that_cannot_start_is_refused_as_not_run() {
        let fx = Fixture::new();
        let main_before = current_branch(&fx);
        let missing = fx.clone.join("no-such-done-check");
        let r = fx.merge(&[Step::new("a-check", missing, &["--enforce"])]);
        assert!(
            matches!(r, Err(Refusal::NotRun { ref step, .. }) if step == "a-check"),
            "{r:?}"
        );
        untouched(&fx, &main_before);
    }

    /// The same for a tip check killed by a signal: it ended without an exit, so without a
    /// verdict on the branch.
    #[cfg(unix)]
    #[test]
    fn a_tip_check_killed_by_a_signal_is_refused_as_not_run() {
        let fx = Fixture::new();
        let main_before = current_branch(&fx);
        let r = fx.merge(&[Step::new("a-check", "sh", &["-c", "kill -9 $$"])]);
        assert!(
            matches!(r, Err(Refusal::NotRun { ref step, .. }) if step == "a-check"),
            "{r:?}"
        );
        untouched(&fx, &main_before);
    }

    /// The recipe writes the trailer block; a message that brings its own is refused rather
    /// than ending with two.
    #[test]
    fn a_message_carrying_a_trailer_is_refused() {
        let fx = Fixture::new();
        let base = fx.head("HEAD");
        fx.branch_adds_a_caller(&base);
        g(&fx.clone, &["checkout", "--quiet", MAIN]);
        for trailer in ["Assisted-by: Claude Code", "Signed-off-by: A <a@example.invalid>"] {
            let r = merge(
                &fx.clone,
                "side",
                &format!("Merge: side\n\n{trailer}"),
                Options { fetch: false, push: false },
                &[],
                |_| Vec::new(),
            );
            assert!(matches!(r, Err(Refusal::Message(_))), "{trailer}: {r:?}");
        }
    }

    /// A branch brought current with `main` and buildable: the common start of the tests below.
    fn current_branch(fx: &Fixture) -> String {
        let base = fx.head("HEAD");
        fx.branch_adds_a_caller(&base);
        g(&fx.clone, &["checkout", "--quiet", MAIN]);
        fx.head(MAIN)
    }

    /// Everything a refused merge must leave as it was.
    fn untouched(fx: &Fixture, main_before: &str) {
        assert_eq!(g(&fx.clone, &["symbolic-ref", "--short", "HEAD"]), MAIN);
        assert_eq!(fx.head(MAIN), main_before, "the local main did not move");
        assert_eq!(fx.origin_main(), main_before, "origin's main did not move");
        assert!(
            g(&fx.clone, &["status", "--porcelain"]).is_empty(),
            "the working tree is main's, clean"
        );
        assert!(!fx.clone.join(".git/MERGE_HEAD").exists(), "no merge is left in progress");
    }

    /// Origin refuses every push: the merge is made and built, and then taken back off the
    /// local `main`, so the next attempt starts from origin's and not from a merge nobody has.
    #[cfg(unix)]
    #[test]
    fn a_push_origin_refuses_takes_the_merge_back_off_main() {
        use std::os::unix::fs::PermissionsExt;
        let fx = Fixture::new();
        let main_before = current_branch(&fx);
        let hook = fx.origin.join("hooks/pre-receive");
        fs::create_dir_all(hook.parent().unwrap()).unwrap();
        fs::write(&hook, "#!/bin/sh\necho refused by the fixture >&2\nexit 1\n").unwrap();
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();

        assert_eq!(fx.merge(&[]).unwrap_err(), Refusal::PushRejected);
        untouched(&fx, &main_before);
    }

    /// A build that cannot be started says nothing about the tree: it is refused as not run,
    /// never as a tree that does not build, and the merge is aborted all the same.
    #[test]
    fn a_build_that_cannot_start_is_refused_as_not_run_and_aborted() {
        let fx = Fixture::new();
        let main_before = current_branch(&fx);
        let missing = fx.clone.join("no-such-cargo");
        let r = merge(
            &fx.clone,
            "side",
            "Merge: side",
            Options { fetch: true, push: true },
            &[],
            |_| vec![Step::new("a-build", missing.clone(), &["check"])],
        );
        assert!(
            matches!(r, Err(Refusal::NotRun { ref step, .. }) if step == "a-build"),
            "{r:?}"
        );
        untouched(&fx, &main_before);
    }

    /// The same for a build killed by a signal: no exit code, so no verdict on the tree.
    #[cfg(unix)]
    #[test]
    fn a_build_killed_by_a_signal_is_refused_as_not_run_and_aborted() {
        let fx = Fixture::new();
        let main_before = current_branch(&fx);
        let r = merge(
            &fx.clone,
            "side",
            "Merge: side",
            Options { fetch: true, push: true },
            &[],
            |_| vec![Step::new("a-build", "sh", &["-c", "kill -9 $$"])],
        );
        assert!(matches!(r, Err(Refusal::NotRun { .. })), "{r:?}");
        untouched(&fx, &main_before);
    }

    /// With `--no-push` the local `main` may be ahead of origin's — the shared-machine path. The
    /// done-check clause then names the `origin/main` done-check measured, not the first parent
    /// it did not measure against.
    #[test]
    fn with_no_push_and_main_ahead_the_trailer_names_the_main_done_check_measured() {
        let fx = Fixture::new();
        let base = fx.head("HEAD");
        write(&fx.clone, "NOTES", "a local merge not pushed yet\n");
        commit_all(&fx.clone, "main: a local commit origin does not have");
        let local_main = fx.head(MAIN);
        let origin = fx.origin_main();
        assert_ne!(local_main, origin);
        fx.branch_adds_a_caller(&base);
        g(&fx.clone, &["merge", "--quiet", "--no-edit", MAIN]);
        g(&fx.clone, &["checkout", "--quiet", MAIN]);

        let mut measured = Step::new("measured", "git", &["rev-parse", "--quiet", "HEAD"]);
        measured.at_main = true;
        let m = merge(
            &fx.clone,
            "side",
            "Merge: side",
            Options { fetch: true, push: false },
            &[measured],
            |d| builds(d, &fx.target),
        )
        .expect("merged locally");
        assert_eq!(m.onto, local_main, "made onto the local main");
        assert_eq!(fx.origin_main(), origin, "not pushed");
        let body = g(&fx.clone, &["log", "-1", "--format=%B"]);
        assert!(body.contains(&format!("measured 0 @{}", &origin[..8])), "{body}");
        assert!(!body.contains(&format!("@{}", &local_main[..8])), "{body}");
    }
}
