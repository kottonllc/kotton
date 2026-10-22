// SPDX-License-Identifier: AGPL-3.0-or-later
//! `worktrees`: what the parallel-work convention is costing, and what of it is reclaimable.
//!
//! ## Why this exists
//!
//! `AGENTS.md` requires a worktree per unit of work, and requires removing it after the
//! merge — *"Each carries its own `target/` — tens of GB that nothing reclaims
//! automatically."* The requirement is right and the cost is real: reported 2026-08-23,
//! hundreds of gigabytes across worktrees and four cold rebuilds in one day.
//!
//! The rule has never had tooling, which is the same shape as every other finding this
//! week — a cost written down, and nothing that makes acting on it cheaper than ignoring
//! it. Removal is currently a thing you must remember, from the primary checkout, about a
//! directory you are not standing in. This makes it a thing you can see.
//!
//! ## What it will and will not do
//!
//! It **reports** by default and exits 0. `--prune` is the only destructive path, and it
//! removes a worktree only when every one of these holds:
//!
//! - it is not the primary checkout, and not the one you are standing in;
//! - it has a branch (a detached worktree is somebody's investigation);
//! - that branch is an ancestor of `main`, so removal discards no commit.
//!
//! The last is the whole safety argument: a merged branch's commits are on `main`, and the
//! branch itself outlives the directory, so nothing is lost. Anything failing a condition
//! is listed with the reason and left alone.
//!
//! This deliberately does not delete `out/` inside a live worktree. That is somebody's
//! warm cache, and reclaiming it converts their next build into the twenty-minute cold one
//! this record set is trying to eliminate.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A worktree's build output, relative to it: `out/`, where every output has lived since
/// 2026-09-26, and the two trees that held them before, which a worktree cut earlier still
/// carries and nothing else would ever name again
/// (`TASK-build-outputs-live-under-out-and-the-tooling-reads-where-cargo-put-them`).
const BUILD_OUTPUT: &[&str] = &["out", "target", "target-xtask"];

struct Worktree {
    path: PathBuf,
    branch: Option<String>,
    is_primary: bool,
    is_current: bool,
    merged: bool,
    last_commit: String,
    author: String,
    agent: Option<String>,
    target_bytes: u64,
}

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim_end().to_string())
}

/// Recursive size, in Rust rather than `du`, because this repository is developed on
/// Windows as much as on Unix and `du` is not there.
///
/// Symlinks are counted by their own size, never followed: a followed link out of
/// `target/` would attribute somebody else's tree to this worktree, and `target/` is full
/// of them.
fn dir_size(p: &Path) -> u64 {
    let Ok(entries) = fs::read_dir(p) else {
        return 0;
    };
    let mut total = 0;
    for e in entries.flatten() {
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_symlink() {
            total += e.metadata().map(|m| m.len()).unwrap_or(0);
        } else if ft.is_dir() {
            total += dir_size(&e.path());
        } else {
            total += e.metadata().map(|m| m.len()).unwrap_or(0);
        }
    }
    total
}

pub(crate) fn human(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

fn collect(measure: bool) -> Vec<Worktree> {
    let porcelain = git(&["worktree", "list", "--porcelain"]).unwrap_or_default();
    let cwd = std::env::current_dir().unwrap_or_default();
    let mut out: Vec<Worktree> = Vec::new();
    let mut cur: Option<(PathBuf, Option<String>)> = None;

    let flush = |cur: &mut Option<(PathBuf, Option<String>)>, out: &mut Vec<Worktree>| {
        let Some((path, branch)) = cur.take() else {
            return;
        };
        let is_primary = out.is_empty(); // `git worktree list` prints the primary first
        let is_current = cwd.starts_with(&path);
        // Ancestry, not `git branch --merged`: the question is whether removal loses a
        // commit, and that is exactly "is this branch reachable from main".
        let merged = branch.as_deref().is_some_and(|b| {
            ["main", "origin/main"].iter().any(|m| {
                Command::new("git")
                    .args(["merge-base", "--is-ancestor", b, m])
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false)
            })
        });
        let last_commit = branch
            .as_deref()
            .and_then(|b| git(&["log", "-1", "--format=%ar", b]))
            .unwrap_or_else(|| "—".into());
        // Who last committed here. The best attribution available for a worktree nobody
        // claimed: when 394 GB has to be traced to an owner, a name beats a directory.
        // Weak by construction while every agent commits under one identity — see the
        // per-worktree `user.name` note in the report footer.
        // The durable name its agent gave itself, if any. Read by running git inside
        // that worktree, which is what resolves its per-worktree config.
        let agent = Command::new("git")
            .args([
                "-C",
                &path.to_string_lossy(),
                "config",
                "--get",
                "kotton.agent",
            ])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|a| !a.is_empty());
        let author = branch
            .as_deref()
            .and_then(|b| git(&["log", "-1", "--format=%an", b]))
            .filter(|a| !a.is_empty())
            .unwrap_or_else(|| "—".into());
        let target_bytes = if measure {
            BUILD_OUTPUT.iter().map(|d| dir_size(&path.join(d))).sum()
        } else {
            0
        };
        out.push(Worktree {
            path,
            branch,
            is_primary,
            is_current,
            merged,
            last_commit,
            author,
            agent,
            target_bytes,
        });
    };

    for line in porcelain.lines() {
        if let Some(p) = line.strip_prefix("worktree ") {
            flush(&mut cur, &mut out);
            cur = Some((PathBuf::from(p), None));
        } else if let Some(b) = line.strip_prefix("branch refs/heads/") {
            if let Some(c) = cur.as_mut() {
                c.1 = Some(b.to_string());
            }
        }
    }
    flush(&mut cur, &mut out);
    out
}

/// Why this worktree may not be removed, or `None` if it may.
fn blocker(w: &Worktree) -> Option<&'static str> {
    if w.is_primary {
        return Some("primary checkout");
    }
    if w.is_current {
        return Some("you are standing in it");
    }
    if w.branch.is_none() {
        return Some("detached — no branch to fall back on");
    }
    if !w.merged {
        return Some("branch not merged into main");
    }
    None
}

/// One worktree past this is worth saying out loud, unprompted.
const LOUD: u64 = 50 * 1024 * 1024 * 1024;
/// And the sum past this, whatever any single one holds.
const LOUD_TOTAL: u64 = 150 * 1024 * 1024 * 1024;

/// Delete a worktree's build output (`out/`, and the older trees if it still has them),
/// returning what it freed.
///
/// `rm -rf` rather than `cargo clean`: when the disk is already full, loading a manifest
/// and resolving a workspace can itself fail, and the two do the same thing to the same
/// directory. Losing a build cache costs one rebuild; a blocked machine costs everybody.
fn reclaim(w: &Worktree) -> Result<u64, String> {
    for d in BUILD_OUTPUT {
        let dir = w.path.join(d);
        if dir.exists() {
            fs::remove_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
    }
    Ok(w.target_bytes)
}

pub fn run(args: &[String]) {
    let prune = args.iter().any(|a| a == "--prune");
    let clean = args.iter().any(|a| a == "--clean");
    let only = args
        .iter()
        .position(|a| a == "--only")
        .and_then(|i| args.get(i + 1))
        .cloned();
    let measure = !args.iter().any(|a| a == "--fast");

    let mut list = collect(measure);
    list.sort_by_key(|w| std::cmp::Reverse(w.target_bytes));
    if list.is_empty() {
        println!("worktrees: none registered.");
        return;
    }

    if clean {
        // Never the one you are standing in: that is your warm cache and your current
        // build, and reclaiming it turns this into the cold rebuild it exists to prevent.
        let targets: Vec<&Worktree> = list
            .iter()
            .filter(|w| !w.is_current)
            .filter(|w| {
                only.as_deref()
                    .is_none_or(|o| w.path.to_string_lossy().contains(o))
            })
            .filter(|w| w.target_bytes > 0)
            .collect();
        if targets.is_empty() {
            println!("worktrees: nothing to reclaim (the current worktree is never cleaned).");
            return;
        }
        let mut freed = 0u64;
        for w in targets {
            match reclaim(w) {
                Ok(n) => {
                    freed += n;
                    println!("reclaimed {:>9}  {}", human(n), w.path.display());
                }
                Err(e) => eprintln!("could not reclaim {}: {e}", w.path.display()),
            }
        }
        println!(
            "\nfreed {}. Those worktrees will cold-build next time.",
            human(freed)
        );
        return;
    }

    println!("{} worktree(s), largest first\n", list.len());
    let mut reclaimable = 0u64;
    let mut total = 0u64;
    let mut removable: Vec<&Worktree> = Vec::new();

    for w in &list {
        total += w.target_bytes;
        let name = w
            .path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| w.path.display().to_string());
        let size = if measure {
            human(w.target_bytes)
        } else {
            "—".into()
        };
        let state = match blocker(w) {
            None => {
                reclaimable += w.target_bytes;
                removable.push(w);
                "MERGED — removable"
            }
            Some(reason) => reason,
        };
        println!(
            "  {name:<28} {:<36} out {size:>9}",
            w.branch.clone().unwrap_or_else(|| "(detached)".into())
        );
        println!(
            "  {:<28} {state} · last commit {} by {}\n  {:<28} agent: {}\n",
            "",
            w.last_commit,
            w.author,
            "",
            w.agent
                .clone()
                .unwrap_or_else(|| "unnamed".into())
        );
    }

    if measure {
        println!("out/ across all worktrees: {}", human(total));
        println!(
            "reclaimable by removing merged worktrees: {}",
            human(reclaimable)
        );

        // The named gap: nothing warned as it grew. Reported 2026-08-23, a single
        // worktree reached **394 GB** — and the symptom was not a disk-full error but a
        // failed fetch, permission oddities and slow builds. A number nobody is shown
        // until it is fatal is a number nobody has.
        for w in list.iter().filter(|w| w.target_bytes > LOUD) {
            let name = w
                .path
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| w.path.display().to_string());
            println!(
                "\n  !! {name} is holding {} of build artifacts.\n     \
                 A worktree reused across branches accumulates them for every branch it \n     \
                 has held. `cargo clean` in it, or remove it if its branch is merged.",
                human(w.target_bytes)
            );
        }
        if total > LOUD_TOTAL {
            println!(
                "\n  !! {} total. A full disk here does not announce itself — it surfaces as \n     \
                 a failed fetch, permission oddities, or builds that are mysteriously slow.",
                human(total)
            );
        }
    }

    if measure && total > 0 {
        println!(
            "\nTo reclaim without losing a branch: `just worktrees --clean` deletes out/ \n\
             from every worktree except the one you are in (`--only <name>` for just one).\n\
             Nothing is lost but build caches."
        );
    }
    if removable.is_empty() {
        println!("\nNothing to remove.");
        return;
    }
    if !prune {
        println!(
            "\n{} worktree(s) are merged and removable. Re-run with `--prune` to remove them.\n\
             A merged branch can still be somebody's live work: ask first, and stop background \n\
             tasks in a worktree before removing it.",
            removable.len()
        );
        return;
    }

    for w in removable {
        let path = w.path.display().to_string();
        match Command::new("git")
            .args(["worktree", "remove", &path])
            .output()
        {
            Ok(o) if o.status.success() => println!("removed {path}"),
            Ok(o) => {
                let err = String::from_utf8_lossy(&o.stderr);
                eprintln!("could not remove {path}: {}", err.trim());
                // The documented failure: an indexer or a backgrounded build still holds
                // handles inside the directory. Deregistering succeeds and the directory
                // is left behind, so say what finishes the job rather than leaving a
                // half-removed worktree with no explanation.
                eprintln!(
                    "  handles are probably still open (rust-analyzer, a backgrounded \
                     `just test`).\n  Stop them, then: rm -rf {path} && git worktree prune"
                );
            }
            Err(e) => eprintln!("could not run git worktree remove: {e}"),
        }
    }
}
