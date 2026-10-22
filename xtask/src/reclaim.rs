// SPDX-License-Identifier: AGPL-3.0-or-later
//! `reclaim`: the disk prune the build loop runs, written once instead of by hand.
//!
//! ## Why this exists
//!
//! The parallel-work guide described a prune in prose, and every agent that
//! needed it wrote it again in a shell loop — measured 2026-09-22, free space fell under 2 GB
//! four times in one night on a container with one checkout and one agent, and each time the
//! prune was typed fresh. A rule every reader re-implements is a rule with as many versions as
//! readers. This is the one version; the prose now says to run it
//! (`TASK-every-package-selection-rebuilds-the-shared-crates-under-a-different-feature-set`).
//!
//! ## What it removes, and only from where
//!
//! It works inside this checkout's large build caches — the workspace's target as cargo
//! reports it (`out/target`, or `$CARGO_TARGET_DIR`), xtask's `out/xtask`, the merge
//! gate's two under `out/merge` (`merge::caches`), and the release builds' under
//! `out/release` — the workspace's, the relay's and each bundled app's (`release::caches`) —
//! and nowhere else; a cache that does not exist is skipped. The guest apps'
//! `out/guest/*`, the relay's `out/relay`, `/opt` and every other directory are not
//! reachable from those roots, so they are untouched by construction rather than by a list
//! of exclusions somebody has to keep complete. It never runs `cargo clean`; `just clean` is
//! the recipe that deletes all of `out/`.
//!
//! 1. `incremental/` directories — unused under `CARGO_INCREMENTAL=0`.
//! 2. Anything whose name contains `.tmp` — a compiler's scratch left by a killed build.
//! 3. In every `deps/` directory, extensionless test binaries (`<name>-<16 hex>`): all but the
//!    newest per name.
//! 4. In every `deps/` directory, library artifacts (`lib<crate>-<16 hex>.rlib`/`.rmeta`): per
//!    crate, all but the newest **two** compiled libraries and the newest **two** check-only
//!    metadata files, with the `.d` dep-info of what is removed.
//! 5. In every `build/` directory, a crate's build-script directories
//!    (`<crate>-<16 hex>`): per crate, all but the newest two that hold a compiled build
//!    script and the newest two that hold a script's output.
//!
//! ## Why "per crate" means name *and* source, and why builds and checks are counted apart
//!
//! The prose rule counted `lib<crate>-*` by file name and kept two. Two things are wrong with
//! that, and both make the prune delete what the next gate needs, which is a rebuild wearing a
//! cleanup's clothes:
//!
//! - **Two versions of one crate share a file name.** `hashbrown` 0.15, 0.16 and 0.17 are all
//!   `libhashbrown-*.rlib`; keeping two of three deletes a version something links, every time.
//!   The version is read from the artifact's `.d` file, whose first source path names the
//!   package directory (`…/hashbrown-0.16.1/src/lib.rs`).
//! - **A check is not a build.** `cargo clippy` writes `.rmeta` alone, under its own hash, and
//!   a crate used by a build script *and* by the code has a host build and a target build. So
//!   "one per profile in flight" is two compiled libraries and, separately, two check-only
//!   metadata files.
//!
//! ## Safe while a build may be live
//!
//! Cargo holds an exclusive lock on `<target>/<profile>/.cargo-lock` for as long as it builds
//! there. This takes the same lock, without waiting, on every profile directory before it
//! plans anything in it; one it cannot lock has a build running in it and is left entirely
//! alone, and the report says so. While this holds a lock a build that starts waits for it
//! ("Blocking waiting for file lock"), for the second or two the removal takes. On top of
//! that, nothing modified in the last ten minutes is touched anywhere.
//!
//! The lock is not decoration. The first version relied on the ten minutes alone and, run
//! beside a build on 2026-09-22, deleted `libheck-e40ebeb2….rlib` from under it: a crate
//! compiled days earlier and reused fresh keeps its old modification time, so "newest two by
//! time" ranked it below a stale copy built that morning, and the build failed with *extern
//! location for heck does not exist*. Age says when a file was written, not when it was last
//! read, and only the lock says whether anything is reading.
//!
//! What remains of that is a cost, not a breakage: after a feature set changes — a dependency
//! edit, a regenerated `tools/workspace-hack` — a stale copy can be newer than one still in
//! use, and the prune removes the one in use. The next build compiles that crate again. It
//! never fails. Measured the day it was written: 144 of the 1,092 rlibs one gate pass had just
//! used. The fix is to rank by cargo's own unit graph rather than by age
//! (`TASK-just-reclaim-ranks-copies-by-age-and-a-crate-reused-fresh-looks-stale`). `tools/workspace-hack` is what makes this rare: with one feature set for every
//! test build, the copies a crate legitimately has are its host build, its target build and
//! the check `clippy` makes, and stale ones only appear when the feature set moves.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::worktrees::human;

/// Nothing younger than this is touched — a live build writes newer files than this.
pub const MIN_AGE: Duration = Duration::from_secs(10 * 60);

/// How many compiled copies of one crate to keep, and separately how many check-only ones.
const KEEP_PER_CRATE: usize = 2;

#[derive(Default)]
struct Tally {
    files: u64,
    bytes: u64,
}

impl Tally {
    fn add(&mut self, bytes: u64) {
        self.files += 1;
        self.bytes += bytes;
    }
}

/// What a prune would remove, by category — computed before anything is deleted, so a
/// `--dry-run` and a real run print the same plan.
#[derive(Default)]
pub struct Plan {
    /// (category, path, bytes)
    pub removals: Vec<(&'static str, PathBuf, u64)>,
}

pub fn run(args: &[String]) {
    let dry_run = args.iter().any(|a| a == "--dry-run");
    let roots = roots();
    let now = SystemTime::now();

    let mut before_total = 0u64;
    let mut plan = Plan::default();
    // Held until the removals are done: a build that starts meanwhile waits for us.
    let mut held: Vec<File> = Vec::new();
    let mut busy: Vec<PathBuf> = Vec::new();
    for root in &roots {
        if !root.is_dir() {
            continue;
        }
        let (locks, running) = lock_build_dirs(root);
        held.extend(locks);
        busy.extend(running);
        before_total += tree_size(root);
        plan_root(root, now, MIN_AGE, &mut plan);
    }
    skip_busy(&mut plan, &busy);

    let mut by_cat: BTreeMap<&'static str, Tally> = BTreeMap::new();
    let mut failures = 0usize;
    for (cat, path, bytes) in &plan.removals {
        if !dry_run {
            let res = if path.is_dir() {
                fs::remove_dir_all(path)
            } else {
                fs::remove_file(path)
            };
            if let Err(e) = res {
                // Gone already is fine: a concurrent build or prune got there first.
                if e.kind() != std::io::ErrorKind::NotFound {
                    eprintln!("reclaim: could not remove {}: {e}", path.display());
                    failures += 1;
                    continue;
                }
            }
        }
        by_cat.entry(cat).or_default().add(*bytes);
    }

    let verb = if dry_run { "would free" } else { "freed" };
    let names: Vec<String> = roots.iter().map(|r| r.display().to_string()).collect();
    println!(
        "reclaim: {} (nothing younger than 10 minutes)",
        names.join(", ")
    );
    let mut freed = 0u64;
    for (cat, t) in &by_cat {
        println!(
            "  {verb} {:>10}  {:>6} entries  {cat}",
            human(t.bytes),
            t.files
        );
        freed += t.bytes;
    }
    if by_cat.is_empty() {
        println!("  nothing to reclaim");
    }
    for dir in &busy {
        println!(
            "  left alone  {}: a build is running there (cargo holds its lock); run again after it",
            dir.display()
        );
    }
    drop(held);
    println!(
        "reclaim: {verb} {} of {} — the caches weigh {} now.",
        human(freed),
        human(before_total),
        human(before_total.saturating_sub(if dry_run { 0 } else { freed })),
    );
    if failures > 0 {
        eprintln!("reclaim: {failures} removal(s) failed; see above.");
        std::process::exit(1);
    }
}

/// Take cargo's own build lock on every profile directory under `root` without waiting.
/// Returns the locks taken, which the caller holds, and the directories a build holds.
fn lock_build_dirs(root: &Path) -> (Vec<File>, Vec<PathBuf>) {
    let mut held = Vec::new();
    let mut busy = Vec::new();
    // `<root>/<profile>` and `<root>/<triple>/<profile>` — where cargo puts `.cargo-lock`.
    let mut dirs = vec![];
    for e in fs::read_dir(root).into_iter().flatten().flatten() {
        let p = e.path();
        if p.is_dir() {
            dirs.push(p.clone());
            for e2 in fs::read_dir(&p).into_iter().flatten().flatten() {
                if e2.path().is_dir() {
                    dirs.push(e2.path());
                }
            }
        }
    }
    for dir in dirs {
        let lock = dir.join(".cargo-lock");
        if !lock.is_file() {
            continue;
        }
        match File::options().read(true).write(true).open(&lock) {
            Ok(f) => match f.try_lock() {
                Ok(()) => held.push(f),
                Err(_) => busy.push(dir),
            },
            // Cannot even open it: treat as busy rather than guess.
            Err(_) => busy.push(dir),
        }
    }
    (held, busy)
}

/// Drop every planned removal inside a directory a build is running in.
fn skip_busy(plan: &mut Plan, busy: &[PathBuf]) {
    plan.removals
        .retain(|(_, p, _)| !busy.iter().any(|b| p.starts_with(b)));
}

/// This checkout's build caches, and nothing else: where cargo says the workspace builds,
/// where the alias builds xtask (`out.rs`), where the merge gate checks each workspace
/// (`merge::caches`) and where the release builds (`release::caches`), each asked of the
/// module that builds there.
fn roots() -> Vec<PathBuf> {
    let root = crate::out::root();
    let mut roots = vec![crate::out::workspace_target(), crate::out::xtask_target()];
    roots.extend(crate::merge::caches(&root));
    roots.extend(crate::release::caches(&root));
    roots
}

/// Plan every removal under one cache root. Pure apart from reading the directory, so the
/// tests can hold it to the rules on a tree they built.
pub fn plan_root(root: &Path, now: SystemTime, min_age: Duration, plan: &mut Plan) {
    let old = |p: &Path| newest_mtime(p).is_some_and(|t| age(now, t) >= min_age);

    // 1 and 2: incremental directories and `.tmp` scratch, anywhere under the root.
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let path = e.path();
            let Ok(ft) = e.file_type() else { continue };
            let name = e.file_name().to_string_lossy().into_owned();
            if ft.is_dir() && name == "incremental" {
                if old(&path) {
                    plan.removals
                        .push(("incremental/", path.clone(), tree_size(&path)));
                }
                continue;
            }
            if name.contains(".tmp") {
                if old(&path) {
                    let bytes = if ft.is_dir() {
                        tree_size(&path)
                    } else {
                        file_len(&path)
                    };
                    plan.removals.push(("*.tmp*", path.clone(), bytes));
                }
                continue;
            }
            if ft.is_dir() && !ft.is_symlink() {
                if name == "deps" {
                    plan_deps(&path, now, min_age, plan);
                } else if name == "build" {
                    plan_build(&path, now, min_age, plan);
                } else {
                    stack.push(path);
                }
            }
        }
    }
}

struct Artifact {
    path: PathBuf,
    mtime: SystemTime,
    bytes: u64,
}

/// One compiled unit in `deps/`: every file sharing a `<stem>-<hash>`.
#[derive(Default)]
struct Unit {
    files: Vec<Artifact>,
    has_rlib: bool,
}

impl Unit {
    fn newest(&self) -> SystemTime {
        self.files
            .iter()
            .map(|a| a.mtime)
            .max()
            .unwrap_or(SystemTime::UNIX_EPOCH)
    }
}

fn plan_deps(deps: &Path, now: SystemTime, min_age: Duration, plan: &mut Plan) {
    let Ok(entries) = fs::read_dir(deps) else {
        return;
    };
    // (crate, hash) -> library unit; name -> [(hash, binary)]
    let mut libs: HashMap<(String, String), Unit> = HashMap::new();
    let mut bins: HashMap<String, Vec<Artifact>> = HashMap::new();
    for e in entries.flatten() {
        let Ok(ft) = e.file_type() else { continue };
        if !ft.is_file() {
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        let path = e.path();
        let Ok(meta) = e.metadata() else { continue };
        if name.contains(".tmp") {
            if meta.modified().is_ok_and(|t| age(now, t) >= min_age) {
                plan.removals.push(("*.tmp*", path, meta.len()));
            }
            continue;
        }
        let art = Artifact {
            path: path.clone(),
            mtime: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            bytes: meta.len(),
        };
        if let Some((stem, ext)) = name.rsplit_once('.') {
            if ext != "rlib" && ext != "rmeta" {
                continue;
            }
            let Some(rest) = stem.strip_prefix("lib") else {
                continue;
            };
            let Some((krate, hash)) = split_hash(rest) else {
                continue;
            };
            let unit = libs
                .entry((krate.to_string(), hash.to_string()))
                .or_default();
            unit.has_rlib |= ext == "rlib";
            unit.files.push(art);
        } else if let Some((bin, _hash)) = split_hash(&name) {
            bins.entry(bin.to_string()).or_default().push(art);
        }
    }

    // 3: test binaries, newest per name.
    for (_, mut arts) in bins {
        arts.sort_by_key(|a| std::cmp::Reverse(a.mtime));
        for a in arts.into_iter().skip(1) {
            if age(now, a.mtime) >= min_age {
                plan.removals.push(("older test binaries", a.path, a.bytes));
            }
        }
    }

    // 4: libraries, newest two per (crate, source, kind).
    let mut groups: HashMap<(String, String, bool), Vec<(String, Unit)>> = HashMap::new();
    for ((krate, hash), unit) in libs {
        let source = source_of(deps, &krate, &hash).unwrap_or_default();
        groups
            .entry((krate, source, unit.has_rlib))
            .or_default()
            .push((hash, unit));
    }
    for ((krate, _, has_rlib), mut units) in groups {
        units.sort_by_key(|(_, u)| std::cmp::Reverse(u.newest()));
        for (hash, unit) in units.into_iter().skip(KEEP_PER_CRATE) {
            if age(now, unit.newest()) < min_age {
                continue;
            }
            let cat = if has_rlib {
                "older .rlib/.rmeta copies"
            } else {
                "older check-only .rmeta copies"
            };
            for a in unit.files {
                plan.removals.push((cat, a.path, a.bytes));
            }
            let d = deps.join(format!("{krate}-{hash}.d"));
            if d.is_file() {
                plan.removals.push((cat, d.clone(), file_len(&d)));
            }
        }
    }
}

/// Build-script directories: `<crate>-<hash>` holding either the compiled script
/// (`build-script-build*`) or what running it produced (`out/`, `output`). A crate built for
/// the host and for the target, or checked, has one of each per variant, so the two kinds
/// are counted apart and the newest two of each kept — the same rule as the libraries.
fn plan_build(build: &Path, now: SystemTime, min_age: Duration, plan: &mut Plan) {
    let Ok(entries) = fs::read_dir(build) else {
        return;
    };
    let mut groups: HashMap<(String, bool), Vec<(SystemTime, PathBuf)>> = HashMap::new();
    for e in entries.flatten() {
        let path = e.path();
        if !path.is_dir() {
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        let Some((krate, _)) = split_hash(&name) else {
            continue;
        };
        let compiled = fs::read_dir(&path)
            .into_iter()
            .flatten()
            .flatten()
            .any(|f| {
                f.file_name()
                    .to_string_lossy()
                    .starts_with("build-script-build")
            });
        let Some(t) = newest_mtime(&path) else {
            continue;
        };
        groups
            .entry((krate.to_string(), compiled))
            .or_default()
            .push((t, path));
    }
    for (_, mut dirs) in groups {
        dirs.sort_by_key(|d| std::cmp::Reverse(d.0));
        for (t, path) in dirs.into_iter().skip(KEEP_PER_CRATE) {
            if age(now, t) >= min_age {
                let bytes = tree_size(&path);
                plan.removals.push(("older build-script dirs", path, bytes));
            }
        }
    }
}

/// `name-0123456789abcdef` → (`name`, hash). Cargo's hashes are 16 lowercase hex digits.
fn split_hash(s: &str) -> Option<(&str, &str)> {
    let (name, hash) = s.rsplit_once('-')?;
    (hash.len() == 16 && hash.bytes().all(|b| b.is_ascii_hexdigit()) && !name.is_empty())
        .then_some((name, hash))
}

/// The package directory an artifact was compiled from, read from its `.d` file: the first
/// source path after the colon, up to `/src/` (or the crate root's directory). Two versions
/// of one crate differ here and nowhere in the artifact's file name.
fn source_of(deps: &Path, krate: &str, hash: &str) -> Option<String> {
    let text = fs::read_to_string(deps.join(format!("{krate}-{hash}.d"))).ok()?;
    let line = text.lines().find(|l| l.contains(": "))?;
    let first = line.split_once(": ")?.1.split_whitespace().next()?;
    let first = first.replace('\\', "/");
    Some(match first.find("/src/") {
        Some(i) => first[..i].to_string(),
        None => first
            .rsplit_once('/')
            .map(|(d, _)| d.to_string())
            .unwrap_or(first),
    })
}

fn age(now: SystemTime, t: SystemTime) -> Duration {
    now.duration_since(t).unwrap_or(Duration::ZERO)
}

fn file_len(p: &Path) -> u64 {
    fs::symlink_metadata(p).map(|m| m.len()).unwrap_or(0)
}

/// The newest modification time of any file under `p` — or of `p` itself when it is a file,
/// or a directory holding none. A directory a live build is writing into is young even when
/// the directory entry itself is old; the directories' own times are not read, because
/// creating an entry is what moves them and that is not a build writing.
fn newest_mtime(p: &Path) -> Option<SystemTime> {
    let meta = fs::symlink_metadata(p).ok()?;
    if !meta.is_dir() {
        return meta.modified().ok();
    }
    let newest = fs::read_dir(p)
        .ok()?
        .flatten()
        .filter_map(|e| newest_mtime(&e.path()))
        .max();
    newest.or_else(|| meta.modified().ok())
}

/// Recursive size, never following symlinks — the same rule `worktrees` uses.
fn tree_size(p: &Path) -> u64 {
    let Ok(meta) = fs::symlink_metadata(p) else {
        return 0;
    };
    if !meta.is_dir() {
        return meta.len();
    }
    let Ok(entries) = fs::read_dir(p) else {
        return 0;
    };
    entries.flatten().map(|e| tree_size(&e.path())).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    const HOUR: Duration = Duration::from_secs(3600);

    /// Write `name` under `dir`, `ago` old.
    fn put(dir: &Path, name: &str, ago: Duration, body: &str) {
        let p = dir.join(name);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        let mut f = File::create(&p).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        f.set_modified(SystemTime::now() - ago).unwrap();
    }

    fn removed(plan: &Plan) -> Vec<String> {
        let mut v: Vec<String> = plan
            .removals
            .iter()
            .map(|(_, p, _)| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    fn dep_info(krate: &str, hash: &str, src: &str) -> (String, String) {
        (
            format!("{krate}-{hash}.d"),
            format!("/t/deps/lib{krate}-{hash}.rlib: {src}/src/lib.rs {src}/src/a.rs\n"),
        )
    }

    fn plan_for(root: &Path) -> Plan {
        let mut plan = Plan::default();
        plan_root(root, SystemTime::now(), MIN_AGE, &mut plan);
        plan
    }

    /// The roots are every build cache this checkout's tools build in: the workspace's and
    /// xtask's, and each one `merge::caches` and `release::caches` name, asked of those
    /// modules rather than listed here.
    #[test]
    fn the_roots_are_every_cache_the_gate_and_the_release_build_in() {
        let roots = roots();
        let root = crate::out::root();
        assert!(roots.contains(&crate::out::workspace_target()));
        assert!(roots.contains(&crate::out::xtask_target()));
        for cache in crate::merge::caches(&root).into_iter().chain(crate::release::caches(&root)) {
            assert!(roots.contains(&cache), "reclaim does not reach {}", cache.display());
        }
    }

    #[test]
    fn keeps_the_newest_two_libraries_of_a_crate_and_removes_the_rest_with_their_dep_info() {
        let t = tempfile::tempdir().unwrap();
        let deps = t.path().join("debug/deps");
        for (i, h) in ["000000000000000a", "000000000000000b", "000000000000000c"]
            .iter()
            .enumerate()
        {
            let ago = HOUR * (3 - i as u32);
            put(&deps, &format!("liburl-{h}.rlib"), ago, "x");
            put(&deps, &format!("liburl-{h}.rmeta"), ago, "x");
            let (d, body) = dep_info("url", h, "/reg/url-2.5.8");
            put(&deps, &d, ago, &body);
        }
        assert_eq!(
            removed(&plan_for(t.path())),
            [
                "liburl-000000000000000a.rlib",
                "liburl-000000000000000a.rmeta",
                "url-000000000000000a.d"
            ]
        );
    }

    #[test]
    fn two_versions_of_one_crate_are_two_crates() {
        // `hashbrown` 0.15 and 0.16 share a file name; the prose rule deleted one of them
        // on every prune and the next build compiled it again.
        let t = tempfile::tempdir().unwrap();
        let deps = t.path().join("debug/deps");
        for (h, src) in [
            ("00000000000000a1", "/reg/hashbrown-0.15.5"),
            ("00000000000000a2", "/reg/hashbrown-0.15.5"),
            ("00000000000000b1", "/reg/hashbrown-0.16.1"),
            ("00000000000000b2", "/reg/hashbrown-0.16.1"),
        ] {
            put(&deps, &format!("libhashbrown-{h}.rlib"), HOUR, "x");
            let (d, body) = dep_info("hashbrown", h, src);
            put(&deps, &d, HOUR, &body);
        }
        assert!(removed(&plan_for(t.path())).is_empty());
    }

    #[test]
    fn a_check_only_rmeta_is_counted_apart_from_compiled_libraries() {
        // clippy's `.rmeta` has its own hash; it is not a third copy of the build.
        let t = tempfile::tempdir().unwrap();
        let deps = t.path().join("debug/deps");
        for h in ["000000000000000a", "000000000000000b"] {
            put(&deps, &format!("libserde-{h}.rlib"), HOUR * 2, "x");
            put(&deps, &format!("libserde-{h}.rmeta"), HOUR * 2, "x");
        }
        put(&deps, "libserde-000000000000000c.rmeta", HOUR, "x");
        assert!(removed(&plan_for(t.path())).is_empty());
    }

    /// Set in the process [`alone`] starts, which runs only the one test that asked.
    const ALONE: &str = "XTASK_RECLAIM_TEST_ALONE";

    /// Run `body` in a process of its own: this test binary again, running only `test`.
    ///
    /// For a test whose premise is who holds a file lock. Cargo's lock, and the one `File::lock`
    /// takes, belongs to the open file description, and every process another test spawns is
    /// forked with a copy of each descriptor this process has open until its exec closes them;
    /// so in the shared binary a lock this test drops can still be held, for that window, by a
    /// child it never made. Alone, nothing else in the process forks, and the test holds and
    /// releases exactly what it says.
    fn alone(test: &str, body: impl FnOnce()) {
        if std::env::var_os(ALONE).is_some() {
            return body();
        }
        // libtest names a test by its path below the crate: `reclaim::tests::<name>`.
        let module = module_path!()
            .split_once("::")
            .map_or(module_path!(), |(_, m)| m);
        let name = format!("{module}::{test}");
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([name.as_str(), "--exact", "--test-threads=1"])
            .env(ALONE, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        // `1 passed` as well as success: a filter that matched nothing would also exit 0.
        assert!(
            out.status.success() && stdout.contains("test result: ok. 1 passed"),
            "{name}, run alone:\n{stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn a_profile_directory_a_build_holds_is_left_entirely_alone() {
        alone(
            "a_profile_directory_a_build_holds_is_left_entirely_alone",
            a_profile_directory_a_build_holds_is_left_entirely_alone_body,
        );
    }

    fn a_profile_directory_a_build_holds_is_left_entirely_alone_body() {
        // The failure this exists for: a pruned rlib a live build was about to link.
        let t = tempfile::tempdir().unwrap();
        let deps = t.path().join("debug/deps");
        for h in ["000000000000000a", "000000000000000b", "000000000000000c"] {
            put(&deps, &format!("libheck-{h}.rlib"), HOUR, "x");
        }
        put(t.path(), "debug/.cargo-lock", HOUR, "");
        put(
            t.path(),
            "release/deps/suite-000000000000000a",
            HOUR * 2,
            "old",
        );
        put(t.path(), "release/deps/suite-000000000000000b", HOUR, "new");
        put(t.path(), "release/.cargo-lock", HOUR, "");

        // A build holds `debug`; nothing holds `release`.
        let build = File::options()
            .read(true)
            .write(true)
            .open(t.path().join("debug/.cargo-lock"))
            .unwrap();
        build.lock().unwrap();

        let (held, busy) = lock_build_dirs(t.path());
        assert_eq!(busy, vec![t.path().join("debug")]);
        let mut plan = plan_for(t.path());
        skip_busy(&mut plan, &busy);
        assert_eq!(removed(&plan), ["suite-000000000000000a"]);

        // And while this holds `release`, a build there would wait.
        let other = File::options()
            .read(true)
            .write(true)
            .open(t.path().join("release/.cargo-lock"))
            .unwrap();
        assert!(other.try_lock().is_err());
        drop(held);
        assert!(other.try_lock().is_ok());
    }

    #[test]
    fn keeps_the_newest_two_build_script_dirs_of_each_kind() {
        let t = tempfile::tempdir().unwrap();
        let b = t.path().join("debug/build");
        for (i, (compiled, ran)) in [
            ("00000000000000a1", "00000000000000b1"),
            ("00000000000000a2", "00000000000000b2"),
            ("00000000000000a3", "00000000000000b3"),
        ]
        .iter()
        .enumerate()
        {
            let ago = HOUR * (3 - i as u32);
            put(&b, &format!("ring-{compiled}/build-script-build"), ago, "x");
            put(&b, &format!("ring-{ran}/out/lib.a"), ago, "x");
        }
        // Two kinds, three of each: the oldest of each goes.
        assert_eq!(
            removed(&plan_for(t.path())),
            ["ring-00000000000000a1", "ring-00000000000000b1"]
        );
    }

    #[test]
    fn keeps_the_newest_test_binary_per_name() {
        let t = tempfile::tempdir().unwrap();
        let deps = t.path().join("debug/deps");
        put(&deps, "suite-000000000000000a", HOUR * 2, "old");
        put(&deps, "suite-000000000000000b", HOUR, "new");
        assert_eq!(removed(&plan_for(t.path())), ["suite-000000000000000a"]);
    }

    #[test]
    fn touches_nothing_younger_than_ten_minutes() {
        let t = tempfile::tempdir().unwrap();
        let deps = t.path().join("debug/deps");
        let young = Duration::from_secs(60);
        put(&deps, "suite-000000000000000a", young * 2, "old");
        put(&deps, "suite-000000000000000b", young, "new");
        for h in ["000000000000000a", "000000000000000b", "000000000000000c"] {
            put(&deps, &format!("libtokio-{h}.rlib"), young, "x");
        }
        put(
            t.path(),
            "debug/incremental/kuserd-1/s-abc/dep-graph.bin",
            young,
            "x",
        );
        put(&deps, "libfoo-000000000000000a.rlib.tmp", young, "x");
        assert!(removed(&plan_for(t.path())).is_empty());
    }

    #[test]
    fn an_incremental_directory_a_build_is_writing_into_is_left_alone() {
        // The directory entry is old; a file inside it is not.
        let t = tempfile::tempdir().unwrap();
        put(t.path(), "debug/incremental/old/s-1/a.bin", HOUR, "x");
        put(
            t.path(),
            "debug/incremental/old/s-2/b.bin",
            Duration::from_secs(5),
            "x",
        );
        assert!(removed(&plan_for(t.path())).is_empty());
        let t2 = tempfile::tempdir().unwrap();
        put(t2.path(), "debug/incremental/old/s-1/a.bin", HOUR, "x");
        assert_eq!(removed(&plan_for(t2.path())), ["incremental"]);
    }

    #[test]
    fn removes_old_tmp_scratch_and_leaves_everything_it_does_not_name() {
        let t = tempfile::tempdir().unwrap();
        let deps = t.path().join("debug/deps");
        put(&deps, "libfoo-000000000000000a.rlib.tmp", HOUR, "x");
        put(&deps, "kuserd-000000000000000a.d", HOUR, "x");
        put(t.path(), "debug/kuserd", HOUR, "binary");
        put(
            t.path(),
            "debug/build/ring-000000000000000a/output",
            HOUR,
            "x",
        );
        assert_eq!(
            removed(&plan_for(t.path())),
            ["libfoo-000000000000000a.rlib.tmp"]
        );
    }
}
