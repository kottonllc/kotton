// SPDX-License-Identifier: AGPL-3.0-or-later
//! `ship-check`: every binary an archive packs links only the system's crates, and crates.io.
//!
//! This repository is the system, as kotton-protocol's repository plan names it: the user
//! daemon, the device daemon, the QUIC acceptor, the sync watcher, and the crates they share. It was cut out of
//! the reference (`kotton-ahead`), which held everything, and the cut is only as good as what
//! the binaries link: one path dependency on a crate that belongs elsewhere links it back in,
//! and nothing in the build says so. This check says so.
//!
//! ## What it reads
//!
//! For every binary each archive packs — the system's ([`crate::release::BINS`]) and each
//! server's, read from [`license_check::ARCHIVES`], the one statement of what an archive
//! carries code from — `cargo tree --edges normal` over its package, for the target the
//! archive is built for (every target, for the system, which is built on each platform for
//! itself). Every crate in that closure is judged by where it comes from ([`judge`]):
//!
//! - **a path crate in this repository** must be on [`SYSTEM_CRATES`], the allow-list: the
//!   system's own crates, and the crates the CLI, the relay and the vault are built from while
//!   they are still here. On [`NOT_THE_SYSTEMS`] instead, it is a **finding**: printed, with
//!   the crates it is a dependency of and the cut, tracked in kottonllc/kotton#18, and not refused, because
//!   today's binaries link it and the cut is work of its own. On neither, it is refused: a new
//!   crate is judged before it ships.
//! - **a path crate outside this repository**, or **a crate from git or any registry but
//!   crates.io**, is refused: that is how a crate of the reference comes back.
//! - **a crate from crates.io** is admitted — the dependencies the system's crates declare,
//!   which `license-check` holds to their licences — unless it carries the name of a crate of
//!   this repository's, or a `kotton` name, which here means one arrived from somewhere else.
//!
//! And both lists are held to the closures: an entry no packed binary reaches is a failure,
//! so a cut that lands deletes its entry rather than leaving it to admit the crate back.
//!
//! ## What it does not refuse yet
//!
//! [`NOT_THE_SYSTEMS`] is the list of cuts still owed. While it is not empty, the closures are
//! larger than the system; the check makes that visible on every `just lint` and refuses only
//! what would make it larger.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::license_check::{Part, ARCHIVES};

/// The allow-list: every crate of this repository a packed binary may link.
///
/// The system's daemons and the crates they share, and — while they are built here — the CLI's
/// (`kotton-cli`, the client and operator libraries, the shell, the record-file parser), the
/// relay's and the vault's.
pub(crate) const SYSTEM_CRATES: &[&str] = &[
    // The system's binaries.
    "kuserd",
    "kdeviced",
    "kquicd",
    "ksyncd",
    // Mechanism, carrier and primitives the daemons share.
    "kotton-common",
    // The version every binary reports, derived once from the tags.
    "kotton-version",
    "kotton-sys",
    "kotton-pair",
    "kotton-proc",
    "kotton-context",
    "kotton-wire",
    "kotton-schemas",
    "kotton-crypto",
    "kotton-net",
    "kotton-fs",
    "kotton-diag",
    "kotton-ipc",
    // Domains, and enforcement.
    "kotton-identity",
    "kotton-peer",
    "kotton-record",
    "kotton-sealed",
    "kotton-store",
    "kotton-sync",
    "kotton-secret",
    "kotton-device",
    "kotton-session",
    // The CLI, here until it has a repository of its own (`kotton-cli` in kotton-protocol's
    // repository plan).
    "kotton-cli",
    "kotton",
    "kotton-operator",
    "kotton-shell",
    "kotton-record-file",
    // The relay and the vault, here until each has a repository of its own.
    "kotton-relay",
    "kvaultd",
];

/// A crate of this repository that a packed binary links and that is not the system's: a cut
/// still owed.
pub(crate) struct NotTheSystems {
    pub(crate) name: &'static str,
    /// Where kotton-protocol's repository plan puts it, or that it does not.
    pub(crate) belongs: &'static str,
    /// The cut, one of the seven kottonllc/kotton#18 tracks.
    pub(crate) cut: &'static str,
}

/// The findings: crates here today, linked into what ships, that kotton-protocol's repository
/// plan does not make the system's. Reported on every run and refused by none, until each cut lands and deletes its
/// entry.
pub(crate) const NOT_THE_SYSTEMS: &[NotTheSystems] = &[
    NotTheSystems {
        name: "kotton-app",
        belongs: "the app surface is kotton-protocol's; running a guest is the sandbox host's, a process of its own that holds no keys",
        cut: "kuserd links kotton-app: move the app host out of the user daemon into the sandbox host",
    },
    NotTheSystems {
        name: "kotton-surface",
        belongs: "windows are the compositor's (kotton-compositor)",
        cut: "kuserd links kotton-surface: cut the window registry from the user daemon",
    },
    NotTheSystems {
        name: "kotton-msg",
        belongs: "kotton-protocol's repository plan names no repository for messaging",
        cut: "kuserd links kotton-msg: place messaging in a repository, then cut it from the user daemon",
    },
    NotTheSystems {
        name: "kotton-org",
        belongs: "kotton-protocol's repository plan names no repository for orgs",
        cut: "kuserd and kotton-peer link kotton-org: place orgs in a repository, then cut them from the system",
    },
    NotTheSystems {
        name: "kotton-outbound",
        belongs: "mediated outbound HTTP for confined extensions, which goes with the sandbox host",
        cut: "kotton-app links kotton-outbound: it leaves the system with the app host",
    },
    NotTheSystems {
        name: "kotton-infer",
        belongs: "the inference runtime is kotton-infer's",
        cut: "kuserd alone links kotton-infer, directly, for the inference channel's frames: it leaves when the daemon reaches inference over the protocol, through a sandbox host that spawns it (kottonllc/kotton#16, kottonllc/kotton#27); the wire, the device crate and the client name a model by kotton-schemas' manifest, so no other binary links it, the vault and the relay among them",
    },
    NotTheSystems {
        name: "kotton-grant",
        belongs: "kotton-protocol's repository plan does not place it; what any side must verify is kotton-protocol's",
        cut: "kotton-record, kotton-app and kuserd link kotton-grant: decide whether grants are the protocol's or the system's, then cut or admit",
    },
];

/// What one closure says, judged.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct Judged {
    /// Why a crate may not be linked, one line each.
    pub(crate) refused: Vec<String>,
    /// Each crate of [`NOT_THE_SYSTEMS`] reached, with the crates it is a direct dependency
    /// of: where its cut is made.
    pub(crate) owed: BTreeMap<String, BTreeSet<String>>,
    /// Each crate of [`SYSTEM_CRATES`] reached.
    pub(crate) system: BTreeSet<String>,
}

/// One line of `cargo tree --prefix depth -f {p}`: its depth, its name, and where it is from
/// — `None` for crates.io, else the parenthesised source cargo prints (a path, a git URL, a
/// registry).
fn parse(line: &str) -> Option<(usize, &str, Option<&str>)> {
    let digits = line.find(|c: char| !c.is_ascii_digit())?;
    let depth = line[..digits].parse().ok()?;
    let rest = &line[digits..];
    let name = rest.split_whitespace().next()?;
    let source = rest
        .match_indices(" (")
        .filter_map(|(i, _)| rest[i + 2..].split_once(')').map(|(g, _)| g))
        .find(|g| !matches!(*g, "*" | "proc-macro" | "build"));
    Some((depth, name, source))
}

/// Judge one closure, `tree` as `cargo tree --edges normal --prefix depth -f {p}` prints it,
/// against this repository at `repo`. `what` names the binary in what is printed.
pub(crate) fn judge(tree: &str, repo: &Path, what: &str) -> Judged {
    let ours = |n: &str| SYSTEM_CRATES.contains(&n);
    let owed = |n: &str| NOT_THE_SYSTEMS.iter().any(|c| c.name == n);
    let mut judged = Judged::default();
    // The crate at each depth on the path to this line, so a line's parent is known.
    let mut path: Vec<String> = Vec::new();
    for line in tree.lines().filter(|l| !l.trim().is_empty()) {
        let Some((depth, name, source)) = parse(line) else {
            judged.refused.push(format!("{what}: cannot read `cargo tree` line {line:?}"));
            continue;
        };
        path.truncate(depth);
        let parent = path.last().cloned();
        path.push(name.to_string());
        match source {
            Some(s) if Path::new(s).is_absolute() => {
                if !Path::new(s).starts_with(repo) {
                    judged.refused.push(format!("{what} links {name} from {s}, outside this repository"));
                } else if ours(name) {
                    judged.system.insert(name.to_string());
                } else if owed(name) {
                    let through = judged.owed.entry(name.to_string()).or_default();
                    through.extend(parent);
                } else {
                    judged.refused.push(format!(
                        "{what} links {name} ({s}), a crate of this repository ship-check has not judged: \
                         add it to SYSTEM_CRATES in xtask/src/ship_check.rs if it is the system's, or cut it"
                    ));
                }
            }
            Some(s) => judged.refused.push(format!("{what} links {name} from {s}, which is neither this repository nor crates.io")),
            None if ours(name) || owed(name) || name.starts_with("kotton") => judged.refused.push(format!(
                "{what} links {name} from crates.io, a name of this repository's: it arrived from somewhere else"
            )),
            None => {}
        }
    }
    judged
}

/// The packages of `workspace`, as `cargo metadata --no-deps` describes them.
fn packages(repo: &Path, workspace: &str) -> Result<Vec<serde_json::Value>, String> {
    let out = Command::new("cargo")
        .args(["metadata", "--locked", "--no-deps", "--format-version", "1", "--manifest-path"])
        .arg(repo.join(workspace).join("Cargo.toml"))
        .current_dir(repo)
        .output()
        .map_err(|e| format!("cannot run cargo metadata: {e}"))?;
    if !out.status.success() {
        return Err(format!("cargo metadata for {workspace} failed:\n{}", String::from_utf8_lossy(&out.stderr)));
    }
    let meta: serde_json::Value =
        serde_json::from_slice(&out.stdout).map_err(|e| format!("cargo metadata for {workspace}: {e}"))?;
    Ok(meta["packages"].as_array().cloned().unwrap_or_default())
}

/// The package of `workspace` with a `[[bin]]` named `root`, or else the package named `root`.
fn package_of(repo: &Path, workspace: &str, root: &str) -> Result<String, String> {
    let packages = packages(repo, workspace)?;
    // A binary's name first: the CLI's binary is `kotton`, and so is the client library's
    // package, which is not what the archive packs.
    let has_bin = |p: &&serde_json::Value| {
        p["targets"].as_array().is_some_and(|ts| {
            ts.iter().any(|t| t["name"] == root && t["kind"].as_array().is_some_and(|k| k.iter().any(|k| k == "bin")))
        })
    };
    packages
        .iter()
        .find(has_bin)
        .or_else(|| packages.iter().find(|p| p["name"] == root))
        .and_then(|p| p["name"].as_str().map(str::to_string))
        .ok_or_else(|| format!("{workspace} has no package or binary named {root}"))
}

/// The closure of `package` in `part`'s workspace, as [`judge`] reads it.
fn tree(repo: &Path, part: &Part, package: &str) -> Result<String, String> {
    let out = Command::new("cargo")
        .args(["tree", "--locked", "--manifest-path"])
        .arg(repo.join(part.workspace).join("Cargo.toml"))
        .args(["-p", package, "--edges", "normal", "--target", part.target.unwrap_or("all")])
        .args(["--prefix", "depth", "-f", "{p}"])
        .current_dir(repo)
        .output()
        .map_err(|e| format!("cannot run cargo tree: {e}"))?;
    if !out.status.success() {
        return Err(format!("cargo tree -p {package} failed:\n{}", String::from_utf8_lossy(&out.stderr)));
    }
    let tree = String::from_utf8_lossy(&out.stdout).into_owned();
    if tree.trim().is_empty() {
        return Err(format!("cargo tree -p {package} listed nothing, which cannot be true: the check would be vacuous"));
    }
    Ok(tree)
}

pub(crate) fn ship_check(repo: &Path) {
    let repo: PathBuf = repo.canonicalize().unwrap_or_else(|_| repo.to_path_buf());
    let mut refused = Vec::new();
    let mut reached_system = BTreeSet::new();
    // Each owed crate: the binaries that link it, and the system crates it enters through.
    let mut owed: BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)> = BTreeMap::new();
    for archive in ARCHIVES {
        for part in archive.parts {
            for root in part.roots {
                let what = format!("{root} ({})", archive.name);
                let judged = package_of(&repo, part.workspace, root)
                    .and_then(|package| tree(&repo, part, &package))
                    .map(|t| judge(&t, &repo, &what));
                let judged = match judged {
                    Ok(j) => j,
                    Err(e) => {
                        refused.push(format!("{what}: {e}"));
                        continue;
                    }
                };
                println!(
                    "ship-check: {what} links {} of the system's crates{}",
                    judged.system.len(),
                    if judged.owed.is_empty() {
                        String::new()
                    } else {
                        format!(", and {} that are not: {}", judged.owed.len(), judged.owed.keys().cloned().collect::<Vec<_>>().join(", "))
                    }
                );
                refused.extend(judged.refused);
                reached_system.extend(judged.system);
                for (name, through) in judged.owed {
                    let entry = owed.entry(name).or_default();
                    entry.0.insert(root.to_string());
                    entry.1.extend(through);
                }
            }
        }
    }
    for name in SYSTEM_CRATES {
        if !reached_system.contains(*name) {
            refused.push(format!("SYSTEM_CRATES names {name}, which no packed binary links: delete the entry"));
        }
    }
    for c in NOT_THE_SYSTEMS {
        if !owed.contains_key(c.name) {
            refused.push(format!("NOT_THE_SYSTEMS names {}, which no packed binary links: the cut landed, delete the entry", c.name));
        }
    }

    if !owed.is_empty() {
        println!("\nship-check: findings, not refused yet — crates linked into what ships that are not the system's:");
        for c in NOT_THE_SYSTEMS {
            let Some((bins, through)) = owed.get(c.name) else { continue };
            println!("  {}: linked into {}; a dependency of {}", c.name, join(bins), join(through));
            println!("    {}", c.belongs);
            println!("    cut (kottonllc/kotton#18): {}", c.cut);
        }
    }
    println!("\nship-check: the daemon still starts by name, and the archive does not carry:");
    for (name, why) in crate::release::STARTED_BUT_NOT_BUILT_HERE {
        println!("  {name}: {why}");
    }

    if refused.is_empty() {
        println!("\nship-check: OK — every packed binary links only the system's crates, crates.io, and the findings above");
    } else {
        eprintln!("\nship-check: FAILED");
        for r in &refused {
            eprintln!("  {r}");
        }
        std::process::exit(1);
    }
}

fn join(s: &BTreeSet<String>) -> String {
    s.iter().cloned().collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPO: &str = "/r";

    fn judged(tree: &str) -> Judged {
        judge(tree, Path::new(REPO), "kuserd (system)")
    }

    /// A closure of the system's own crates and crates.io's passes, deduplicated lines and
    /// proc-macros included.
    #[test]
    fn the_systems_crates_and_crates_io_pass() {
        let j = judged(
            "0kuserd v0.1.0 (/r/core/kuserd)\n\
             1kotton-ipc v0.1.0 (/r/core/ipc)\n\
             2async-trait v0.1.92 (proc-macro)\n\
             2kotton-common v0.1.0 (/r/core/common) (*)\n\
             1serde v1.0.0\n",
        );
        assert_eq!(j.refused, Vec::<String>::new());
        assert!(j.owed.is_empty());
        assert_eq!(j.system, ["kotton-common", "kotton-ipc", "kuserd"].map(String::from).into());
    }

    /// A crate on NOT_THE_SYSTEMS is a finding, not a refusal, and names the system crate it
    /// enters through — the edge its cut removes.
    #[test]
    fn a_crate_not_the_systems_is_a_finding_naming_where_it_enters() {
        let j = judged(
            "0kuserd v0.1.0 (/r/core/kuserd)\n\
             1kotton-wire v0.1.0 (/r/core/wire)\n\
             2kotton-schemas v0.1.0 (/r/core/schemas)\n\
             1kotton-infer v0.1.0 (/r/core/infer)\n\
             2serde v1.0.0\n\
             1kotton-app v0.1.0 (/r/core/app)\n\
             2kotton-outbound v0.1.0 (/r/core/outbound)\n",
        );
        assert_eq!(j.refused, Vec::<String>::new());
        assert_eq!(j.owed["kotton-infer"], ["kuserd".to_string()].into());
        // The protocol's crates under it are the system's, and no finding.
        assert!(j.system.contains("kotton-schemas") && !j.owed.contains_key("kotton-wire"));
        assert_eq!(j.owed["kotton-app"], ["kuserd".to_string()].into());
        // Reached through another finding: it goes when that one does.
        assert_eq!(j.owed["kotton-outbound"], ["kotton-app".to_string()].into());
    }

    /// Everything else of this repository's, anything from outside it, and anything from git
    /// or another registry is refused, each naming the crate; so is a crates.io crate that
    /// carries this repository's name.
    #[test]
    fn a_crate_from_anywhere_else_is_refused_by_name() {
        for (line, why) in [
            ("1kotton-kuid v0.1.0 (/r/core/kuid)\n", "has not judged"),
            ("1kotton-runtime v0.1.0 (/elsewhere/kotton-ahead/core/runtime)\n", "outside this repository"),
            ("1kotton-shell-logic v0.1.0 (https://github.com/kottonllc/kotton-ahead#0123abcd)\n", "neither this repository nor crates.io"),
            ("1left-pad v1.0.0 (registry `other`)\n", "neither this repository nor crates.io"),
            ("1kotton-wire v9.0.0\n", "from crates.io"),
            ("1kotton-anything v1.0.0\n", "from crates.io"),
        ] {
            let j = judged(&format!("0kuserd v0.1.0 (/r/core/kuserd)\n{line}"));
            assert_eq!(j.refused.len(), 1, "{line}: {:?}", j.refused);
            let name = line[1..].split_whitespace().next().unwrap();
            assert!(j.refused[0].contains(name) && j.refused[0].contains(why), "{line}: {}", j.refused[0]);
        }
    }

    /// The two lists are disjoint, and each names a package of this repository — the
    /// workspace or the relay's — so neither can admit a name nothing here builds.
    #[test]
    fn the_lists_are_disjoint_and_name_this_repositorys_packages() {
        let repo = crate::out::root();
        for c in NOT_THE_SYSTEMS {
            assert!(!SYSTEM_CRATES.contains(&c.name), "{} is on both lists", c.name);
        }
        for name in SYSTEM_CRATES.iter().copied().chain(NOT_THE_SYSTEMS.iter().map(|c| c.name)) {
            let found = [".", "infra/relay"]
                .iter()
                .any(|ws| packages(&repo, ws).unwrap().iter().any(|p| p["name"] == name));
            assert!(found, "{name} is not a package of this repository");
        }
    }

    /// The check reads every binary each archive packs: the system's are exactly
    /// `release::BINS`, and the servers' are each server's binary.
    #[test]
    fn the_closures_read_are_every_archives_binaries() {
        let roots: Vec<&str> = ARCHIVES.iter().flat_map(|a| a.parts.iter().flat_map(|p| p.roots.iter().copied())).collect();
        let mut want: Vec<&str> = crate::release::BINS.to_vec();
        want.extend(crate::release_server::SERVERS.iter().map(|s| s.binary));
        assert_eq!(roots, want);
    }
}
