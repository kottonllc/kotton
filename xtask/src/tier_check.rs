// SPDX-License-Identifier: AGPL-3.0-or-later
//! `tier-check`'s rows: one for each repository of kotton-protocol's repository plan that this
//! tree holds a part of, each over the paths that part has today, each saying which rows it may
//! path-depend on, and each with an owed list of the edges that break it today.
//!
//! ## Why rows
//!
//! kotton-protocol's repository plan says that until a part is cut, this tree is laid out as
//! the plan: one top-level directory for each repository a part of it becomes, and a check that
//! holds each directory to the directories its repository may link. An edge the plan does not allow is on that
//! directory's owed list, by name, or the check fails; the lists are printed on every run, and
//! one only shrinks. A part is cut when its list is empty.
//!
//! The rows come before the directories. A row is a set of paths, so it is laid over the tree as
//! it is, and a later move changes a row's paths and nothing in its list: every list is printed
//! from the first run, and none waits on a path being free.
//!
//! ## What it reads
//!
//! Every `Cargo.toml` under the roots the rows lie in (`core/`, `client/`, `infra/`), parsed as
//! TOML: the package's name, and every `path` dependency in `[dependencies]`,
//! `[dev-dependencies]`, `[build-dependencies]` and their `[target.'…']` forms. A dev-dependency
//! is an edge: the rule reads manifests, and a crate cut into another repository takes its tests
//! with it. Nothing is built.
//!
//! A `path` under `[workspace.dependencies]`, in the root manifest or in a row's manifest that
//! declares a workspace, is refused: a crate that inherits it writes no path of its own, so the
//! edge would be in no manifest read here. And a dependency that is not a dev-dependency, from a
//! row's crate into a root that is no row, is refused: it ships what it links, and nothing under
//! that root is read. A row's dev-dependencies into those roots (`tools/workspace-hack`, for most
//! crates) are on no list; each row prints how many it does not count.
//!
//! Each edge is judged by the row of each end. Inside one row, or into a row the first may link,
//! it is admitted. Otherwise it is on the first row's owed list, by crate name, or it is refused,
//! naming both crates.
//!
//! ## What holds the lists
//!
//! The lists are [`OWED_FILE`], a data file rather than a table in this source, because the
//! check reads the same file at the merge base with `origin/main` and compares the two: an
//! entry that is not on its row's list there is refused, so a list only shrinks and the gate,
//! not review, holds that. A row absent at the merge base arrives with its list, and the run
//! says which rows arrive. An entry is also refused when no manifest has its edge (an
//! untangling that lands deletes its entry), when the edge is one its row may link, or when it
//! is filed under a row its crate is not in.
//!
//! ## What no list may owe
//!
//! The regions of [`crate::tree::REGIONS`] are in dependency order: `core/` acts on a
//! principal's authority, and `client/` only asks. A crate under `core/` that path-depends on
//! one under `client/` is refused whatever the lists say. Cargo permits that edge and nothing
//! else here would catch it; it is authority moving somewhere it was not granted, which is not
//! a debt to be paid later.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use toml::{Table, Value};

/// A repository of kotton-protocol's repository plan that this tree holds a part of, over
/// today's paths.
pub(crate) struct Row {
    /// The row's name, as the owed list files it.
    pub(crate) name: &'static str,
    /// What its part becomes: the repository it is cut into, or that it stays.
    pub(crate) becomes: &'static str,
    /// The directories it is today. A directory belongs to the row whose path is the longest
    /// prefix of it, by component, so `core` is the rest of `core/`.
    pub(crate) paths: &'static [&'static str],
    /// The rows it may path-depend on. A row's own crates are always admitted.
    pub(crate) may_link: &'static [&'static str],
}

/// The rows. Each `may_link` is the repository plan's: the CLI is built from the protocol and
/// the client library alone; the client library and the relay from the protocol; the vault from the
/// protocol and its own crates; the system and the device-owner tool, which the repository plan
/// makes the system's, from the protocol and the system.
pub(crate) const ROWS: &[Row] = &[
    Row {
        name: "protocol",
        becomes: "becomes kotton-protocol's crates",
        paths: &[
            "core/wire",
            "core/schemas",
            "core/pair",
            "core/handshake",
            "core/ed25519",
            "core/common",
        ],
        may_link: &["protocol"],
    },
    Row {
        name: "relay",
        becomes: "becomes kotton-relay",
        paths: &["infra/relay"],
        may_link: &["protocol"],
    },
    Row {
        name: "cli",
        becomes: "becomes kotton-cli",
        paths: &["client/cli", "client/shell"],
        may_link: &["protocol", "client library", "cli"],
    },
    Row {
        name: "client library",
        becomes: "becomes kotton-protocol's client library",
        paths: &["client/kotton-client", "client/record-file"],
        may_link: &["protocol", "client library"],
    },
    Row {
        name: "vault",
        becomes: "becomes kotton-vault",
        paths: &["core/kvaultd"],
        may_link: &["protocol", "vault"],
    },
    Row {
        name: "operator",
        becomes: "stays in kotton: the device-owner tool",
        paths: &["client/kotton-operator"],
        may_link: &["protocol", "system", "operator"],
    },
    Row {
        name: "system",
        becomes: "stays in kotton: the system",
        paths: &["core"],
        may_link: &["protocol", "system"],
    },
];

/// The code roots that are no row: nothing in them ships. `tools/` holds test instruments
/// (`tools/workspace-hack` among them, which crates dev-depend on), `xtask/` the gates and
/// `tests/` the integration suite. A row's crate may dev-depend on them and on nothing else
/// there ([`read_tree`]).
pub(crate) const NOT_ROWS: &[&str] = &["tools", "xtask", "tests"];

/// The one feature set every test build shares: most crates dev-depend on it, and it is no row.
const WORKSPACE_HACK: &str = "tools/workspace-hack";

/// The owed lists, repo-relative.
pub(crate) const OWED_FILE: &str = "xtask/tier-owed.toml";

/// The branch the lists may only shrink against.
const MAIN_REF: &str = "origin/main";

/// Each row's owed list: row, then the crate the edge is from, then the crates it is to.
pub(crate) type Owed = BTreeMap<String, BTreeMap<String, BTreeSet<String>>>;

/// A crate of a row.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Crate {
    pub(crate) name: String,
    pub(crate) dir: String,
    pub(crate) row: &'static str,
}

/// One path dependency between two crates of rows.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Edge {
    pub(crate) from: String,
    pub(crate) from_dir: String,
    pub(crate) to: String,
    pub(crate) to_dir: String,
}

/// What the owed lists were at the merge base with `origin/main`.
#[derive(Debug, PartialEq)]
pub(crate) enum Base {
    /// The lists at that commit.
    At { commit: String, owed: Owed },
    /// [`OWED_FILE`] is not in that commit: every row arrives.
    Absent { commit: String },
    /// The merge base or the file could not be read, and why. Growth cannot be judged, so the
    /// gate fails rather than reading it as no growth.
    Unknown(String),
}

/// What a run found.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct Judged {
    pub(crate) refused: Vec<String>,
    /// The rows absent at the merge base, which arrive with their lists.
    pub(crate) arriving: Vec<&'static str>,
}

fn row_named(name: &str) -> Option<&'static Row> {
    ROWS.iter().find(|r| r.name == name)
}

/// The row a repo-relative directory is in: the row whose path is its longest prefix.
pub(crate) fn row_of(dir: &str) -> Option<&'static Row> {
    let parts: Vec<&str> = dir.split('/').collect();
    let mut best: Option<(&'static Row, usize)> = None;
    for row in ROWS {
        for p in row.paths {
            let pp: Vec<&str> = p.split('/').collect();
            if parts.len() >= pp.len()
                && parts[..pp.len()] == pp[..]
                && best.is_none_or(|(_, n)| pp.len() > n)
            {
                best = Some((row, pp.len()));
            }
        }
    }
    best.map(|(r, _)| r)
}

/// The top-level directories the rows lie in, in order.
pub(crate) fn row_roots() -> Vec<&'static str> {
    let mut roots: Vec<&'static str> = Vec::new();
    for row in ROWS {
        for p in row.paths {
            let top = p.split('/').next().unwrap_or(p);
            if !roots.contains(&top) {
                roots.push(top);
            }
        }
    }
    roots
}

/// Parse [`OWED_FILE`]: a table per row, each key a crate, each value the crates it owes.
pub(crate) fn parse_owed(text: &str) -> Result<Owed, String> {
    let table: Table = text
        .parse()
        .map_err(|e| format!("{OWED_FILE} is not TOML: {e}"))?;
    let mut owed = Owed::new();
    for (row, entries) in table {
        let Value::Table(entries) = entries else {
            return Err(format!("{OWED_FILE}: `{row}` is not a table of a row's owed edges"));
        };
        let mut list = BTreeMap::new();
        for (from, tos) in entries {
            let Value::Array(tos) = tos else {
                return Err(format!("{OWED_FILE}: [{row}] `{from}` is not a list of crate names"));
            };
            let mut set = BTreeSet::new();
            for to in tos {
                let Value::String(to) = to else {
                    return Err(format!("{OWED_FILE}: [{row}] `{from}` holds a value that is not a crate name"));
                };
                if !set.insert(to.clone()) {
                    return Err(format!("{OWED_FILE}: [{row}] `{from}` names `{to}` twice"));
                }
            }
            list.insert(from, set);
        }
        owed.insert(row, list);
    }
    Ok(owed)
}

/// Every `Cargo.toml` under `dir`, depth-first, skipping build output and hidden directories.
fn manifests_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if path.is_dir() {
                if name.starts_with('.') || name == "target" || name.starts_with("target-") {
                    continue;
                }
                stack.push(path);
            } else if name == "Cargo.toml" {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

const DEPENDENCY_TABLES: &[&str] = &[
    "dependencies",
    "dev-dependencies",
    "build-dependencies",
    "dev_dependencies",
    "build_dependencies",
];

/// The `path` of every dependency a parsed manifest declares, target-specific tables included,
/// and whether it is a dev-dependency.
fn dependency_paths(manifest: &Table) -> Vec<(String, bool)> {
    let mut tables: Vec<(&Table, bool)> = Vec::new();
    let is_dev = |t: &str| t.starts_with("dev");
    for t in DEPENDENCY_TABLES {
        if let Some(Value::Table(deps)) = manifest.get(*t) {
            tables.push((deps, is_dev(t)));
        }
    }
    if let Some(Value::Table(targets)) = manifest.get("target") {
        for spec in targets.values() {
            let Value::Table(spec) = spec else { continue };
            for t in DEPENDENCY_TABLES {
                if let Some(Value::Table(deps)) = spec.get(*t) {
                    tables.push((deps, is_dev(t)));
                }
            }
        }
    }
    let mut out = Vec::new();
    for (deps, dev) in tables {
        for dep in deps.values() {
            if let Some(Value::String(p)) = dep.as_table().and_then(|d| d.get("path")) {
                out.push((p.clone(), dev));
            }
        }
    }
    out
}

/// Every `path` under a manifest's `[workspace.dependencies]`, refused. A crate that inherits
/// one (`{ workspace = true }`) declares no `path` of its own, so the edge would be in no
/// manifest this check reads; with no `path` there, the edge cannot be written that way.
fn workspace_paths(manifest: &Table, at: &str) -> Vec<String> {
    let Some(Value::Table(deps)) = manifest
        .get("workspace")
        .and_then(Value::as_table)
        .and_then(|w| w.get("dependencies"))
    else {
        return Vec::new();
    };
    deps.iter()
        .filter_map(|(key, dep)| {
            let path = dep.as_table()?.get("path")?.as_str()?;
            Some(format!(
                "{at} names `{key}` by path (`{path}`) under [workspace.dependencies]: a crate \
                 that inherits it declares no path of its own, so tier-check would not read the \
                 edge. Write the path in each crate's own manifest"
            ))
        })
        .collect()
}

/// What [`read_tree`] read.
#[derive(Debug, Default)]
pub(crate) struct Tree {
    pub(crate) crates: Vec<Crate>,
    pub(crate) edges: BTreeSet<Edge>,
    /// The dev-dependencies of each row's crates into a root that is no row, which no list
    /// counts: row, then the directory depended on, then the crates that depend on it.
    pub(crate) uncounted: BTreeMap<&'static str, BTreeMap<String, BTreeSet<String>>>,
    pub(crate) refused: Vec<String>,
}

fn package_name(manifest: &Table) -> Option<String> {
    manifest
        .get("package")?
        .as_table()?
        .get("name")?
        .as_str()
        .map(str::to_string)
}

fn parse_manifest(path: &Path) -> Result<Table, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    text.parse::<Table>()
        .map_err(|e| format!("{}: not TOML: {e}", path.display()))
}

/// The crates of every row under `root`, and the path dependencies between them. A manifest
/// that cannot be read, a package in no row, or a path that names no package is refused: a
/// reader that skips what it cannot read reports OK over less than the tree. So is a `path`
/// under `[workspace.dependencies]`, in the root manifest or in a row's, and a dependency that
/// is not a dev-dependency from a row's crate into a root that is no row: it ships what it
/// links, and nothing reads what that is.
pub(crate) fn read_tree(root: &Path) -> Tree {
    let mut t = Tree::default();
    let (crates, edges, refused) = (&mut t.crates, &mut t.edges, &mut t.refused);
    let uncounted = &mut t.uncounted;
    let root_manifest = root.join("Cargo.toml");
    if root_manifest.exists() {
        match parse_manifest(&root_manifest) {
            Ok(m) => refused.extend(workspace_paths(&m, "Cargo.toml")),
            Err(e) => refused.push(e),
        }
    }
    let rel = |p: &Path| -> String {
        let s = p.strip_prefix(root).unwrap_or(p).to_string_lossy().replace('\\', "/");
        crate::normalise_path(&s)
    };
    for top in row_roots() {
        for manifest_path in manifests_under(&root.join(top)) {
            let manifest = match parse_manifest(&manifest_path) {
                Ok(m) => m,
                Err(e) => {
                    refused.push(e);
                    continue;
                }
            };
            let dir_path = manifest_path.parent().unwrap_or(root);
            let dir = rel(dir_path);
            refused.extend(workspace_paths(&manifest, &format!("{dir}/Cargo.toml")));
            let Some(name) = package_name(&manifest) else {
                continue;
            };
            let Some(row) = row_of(&dir) else {
                refused.push(format!(
                    "{name} ({dir}) is in no row: name it in a row of xtask/src/tier_check.rs, \
                     by the repository of kotton-protocol's repository plan it becomes"
                ));
                continue;
            };
            crates.push(Crate { name: name.clone(), dir: dir.clone(), row: row.name });
            for (dep, dev) in dependency_paths(&manifest) {
                let to_dir = crate::normalise_path(&format!("{dir}/{dep}"));
                if row_of(&to_dir).is_none() {
                    let top = to_dir.split('/').next().unwrap_or("");
                    if !NOT_ROWS.contains(&top) {
                        continue;
                    }
                    if dev {
                        uncounted
                            .entry(row.name)
                            .or_default()
                            .entry(to_dir)
                            .or_default()
                            .insert(name.clone());
                    } else {
                        refused.push(format!(
                            "{name} ({dir}, row `{}`) depends on {to_dir}, under `{top}/`, which \
                             is no row: a dependency that is not a dev-dependency ships what it \
                             links, and tier-check reads nothing under `{top}/`. Move the crate \
                             into a row, or drop the dependency",
                            row.name
                        ));
                    }
                    continue;
                }
                let to = parse_manifest(&root.join(&to_dir).join("Cargo.toml"))
                    .ok()
                    .and_then(|m| package_name(&m));
                let Some(to) = to else {
                    refused.push(format!(
                        "{name} ({dir}) path-depends on {to_dir}, which holds no package tier-check \
                         can read"
                    ));
                    continue;
                };
                edges.insert(Edge { from: name.clone(), from_dir: dir.clone(), to, to_dir });
            }
        }
    }
    t
}

/// The index of the region of [`crate::tree::REGIONS`] a directory is in, if any.
fn region_index(dir: &str) -> Option<usize> {
    let top = dir.split('/').next()?;
    crate::tree::REGIONS.iter().position(|r| *r == top)
}

/// Whether an edge from `from_dir` to `to_dir` runs against the regions' order, which no list
/// may owe.
fn against_regions(from_dir: &str, to_dir: &str) -> bool {
    matches!((region_index(from_dir), region_index(to_dir)), (Some(f), Some(t)) if f < t)
}

fn admitted(from: &Row, to: &Row) -> bool {
    from.name == to.name || from.may_link.contains(&to.name)
}

/// Judge the edges against the rows, the owed lists against the edges, and the lists against
/// the merge base.
pub(crate) fn judge(crates: &[Crate], edges: &BTreeSet<Edge>, owed: &Owed, base: &Base) -> Judged {
    let mut j = Judged::default();
    let row_of_crate: BTreeMap<&str, &Crate> = crates.iter().map(|c| (c.name.as_str(), c)).collect();

    for row in ROWS {
        if !owed.contains_key(row.name) {
            j.refused.push(format!(
                "row `{}` has no list in {OWED_FILE}: give it one, empty if it owes nothing",
                row.name
            ));
        }
    }
    for name in owed.keys() {
        if row_named(name).is_none() {
            j.refused.push(format!("{OWED_FILE} lists `[{name}]`, which is not a row"));
        }
    }

    let is_owed = |row: &str, from: &str, to: &str| {
        owed.get(row)
            .and_then(|l| l.get(from))
            .is_some_and(|tos| tos.contains(to))
    };

    // Every edge.
    for e in edges {
        let (Some(fr), Some(tr)) = (row_of(&e.from_dir), row_of(&e.to_dir)) else {
            continue;
        };
        if against_regions(&e.from_dir, &e.to_dir) {
            j.refused.push(format!(
                "{} ({}, row `{}`) links {} ({}, row `{}`): a crate under `{}/` never \
                 path-depends on one under `{}/`, and no owed list may hold it",
                e.from,
                e.from_dir,
                fr.name,
                e.to,
                e.to_dir,
                tr.name,
                e.from_dir.split('/').next().unwrap_or(""),
                e.to_dir.split('/').next().unwrap_or("")
            ));
            continue;
        }
        if admitted(fr, tr) || is_owed(fr.name, &e.from, &e.to) {
            continue;
        }
        j.refused.push(format!(
            "{} ({}, row `{}`) links {} ({}, row `{}`), and `{}` may link: {}. The edge is on \
             no owed list: remove it, or, if it is in a row absent at the merge base, list it there",
            e.from,
            e.from_dir,
            fr.name,
            e.to,
            e.to_dir,
            tr.name,
            fr.name,
            fr.may_link.join(", ")
        ));
    }

    // Every entry.
    for (row_name, list) in owed {
        let Some(row) = row_named(row_name) else { continue };
        for (from, tos) in list {
            for to in tos {
                let entry = format!("{from} -> {to} (row `{row_name}`)");
                let Some(fc) = row_of_crate.get(from.as_str()) else {
                    j.refused.push(format!("the owed entry {entry} names {from}, which is no crate of any row"));
                    continue;
                };
                if fc.row != row.name {
                    j.refused.push(format!(
                        "the owed entry {entry} is filed under `{row_name}`, and {from} is in row `{}`",
                        fc.row
                    ));
                    continue;
                }
                let Some(tc) = row_of_crate.get(to.as_str()) else {
                    j.refused.push(format!("the owed entry {entry} names {to}, which is no crate of any row"));
                    continue;
                };
                let in_a_manifest = edges.iter().any(|e| e.from == *from && e.to == *to);
                if !in_a_manifest {
                    j.refused.push(format!(
                        "the owed entry {entry} is in no manifest: {from} no longer path-depends \
                         on {to}, so delete the entry from {OWED_FILE}"
                    ));
                    continue;
                }
                if let Some(tr) = row_named(tc.row) {
                    if admitted(row, tr) {
                        j.refused.push(format!(
                            "the owed entry {entry} is not owed: `{row_name}` may link `{}`, so \
                             delete the entry from {OWED_FILE}",
                            tr.name
                        ));
                        continue;
                    }
                }
            }
        }
    }

    // The lists against the merge base.
    match base {
        Base::Unknown(why) => j.refused.push(format!(
            "the owed lists cannot be compared with the merge base with {MAIN_REF}, so whether \
             one grew cannot be judged: {why}"
        )),
        Base::Absent { .. } => {
            j.arriving = ROWS.iter().map(|r| r.name).filter(|n| owed.contains_key(*n)).collect();
        }
        Base::At { commit, owed: at } => {
            for (row_name, list) in owed {
                let Some(row) = row_named(row_name) else { continue };
                let Some(at_list) = at.get(row_name) else {
                    j.arriving.push(row.name);
                    continue;
                };
                for (from, tos) in list {
                    for to in tos {
                        let was = at_list.get(from).is_some_and(|t| t.contains(to));
                        if !was {
                            j.refused.push(format!(
                                "the owed entry {from} -> {to} (row `{row_name}`) is not on the \
                                 list at the merge base with {MAIN_REF} ({}): an owed list only \
                                 shrinks",
                                short(commit)
                            ));
                        }
                    }
                }
            }
        }
    }
    j
}

fn short(commit: &str) -> &str {
    &commit[..commit.len().min(12)]
}

fn git(root: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .map_err(|e| format!("git {}: {e}", args.join(" ")))?;
    if !out.status.success() {
        return Err(format!(
            "git {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// The owed lists at the merge base of `HEAD` with `origin/main`, read from git objects.
pub(crate) fn base_owed(root: &Path) -> Base {
    let commit = match git(root, &["merge-base", MAIN_REF, "HEAD"]) {
        Ok(c) => c.trim().to_string(),
        Err(e) => return Base::Unknown(e),
    };
    match git(root, &["ls-tree", "--name-only", &commit, "--", OWED_FILE]) {
        Ok(listed) if listed.trim().is_empty() => return Base::Absent { commit },
        Ok(_) => {}
        Err(e) => return Base::Unknown(e),
    }
    let text = match git(root, &["show", &format!("{commit}:{OWED_FILE}")]) {
        Ok(t) => t,
        Err(e) => return Base::Unknown(e),
    };
    match parse_owed(&text) {
        Ok(owed) => Base::At { commit, owed },
        Err(e) => Base::Unknown(format!("at {}: {e}", short(&commit))),
    }
}

/// Print every row, its paths, what it may link and its owed list with a count, and return
/// what is refused. The lists are printed on every run, refused or not.
pub(crate) fn rows_check(root: &Path) -> Vec<String> {
    let mut refused = Vec::new();
    for row in ROWS {
        for p in row.paths {
            if !root.join(p).is_dir() {
                refused.push(format!(
                    "row `{}` names `{p}`, which is not a directory here, so it reads nothing: \
                     repoint ROWS in xtask/src/tier_check.rs",
                    row.name
                ));
            }
        }
    }
    let owed = match std::fs::read_to_string(root.join(OWED_FILE))
        .map_err(|e| format!("{OWED_FILE}: {e}"))
        .and_then(|t| parse_owed(&t))
    {
        Ok(o) => o,
        Err(e) => {
            refused.push(e);
            return refused;
        }
    };
    let rowed = row_roots();
    for r in crate::tree::CODE_ROOTS {
        if rowed.contains(r) == NOT_ROWS.contains(r) {
            refused.push(format!(
                "code root `{r}/` must be either a row's or named in NOT_ROWS, and not both \
                 (xtask/src/tier_check.rs)"
            ));
        }
    }
    let tree = read_tree(root);
    refused.extend(tree.refused.iter().cloned());
    let base = base_owed(root);
    let judged = judge(&tree.crates, &tree.edges, &owed, &base);

    println!("tier-check: one row for each repository of kotton-protocol's repository plan this tree holds a part of, over today's paths");
    for row in ROWS {
        let list = owed.get(row.name);
        let count: usize = list.map(|l| l.values().map(BTreeSet::len).sum()).unwrap_or(0);
        let paths = if row.name == "system" {
            "core/ (the rest of it)".to_string()
        } else {
            row.paths.join(", ")
        };
        println!("\n  {}: {}", row.name, row.becomes);
        println!("    paths: {paths}");
        println!("    may link: {}", row.may_link.join(", "));
        println!("    owed ({count}):");
        for (from, tos) in list.into_iter().flatten() {
            for to in tos {
                println!("      {from} -> {to}");
            }
        }
        let none = BTreeMap::new();
        let uncounted = tree.uncounted.get(row.name).unwrap_or(&none);
        let hack = uncounted.get(WORKSPACE_HACK).map(BTreeSet::len).unwrap_or(0);
        println!(
            "    not counted: dev-dependencies on {WORKSPACE_HACK}, which is no row ({hack} of \
             this row's crates)"
        );
        for (to_dir, froms) in uncounted.iter().filter(|(d, _)| d.as_str() != WORKSPACE_HACK) {
            println!(
                "    not counted: dev-dependencies on {to_dir}, which is no row ({} of this row's crates)",
                froms.len()
            );
        }
    }
    match &base {
        Base::At { commit, .. } | Base::Absent { commit } if !judged.arriving.is_empty() => println!(
            "\ntier-check: rows absent at the merge base with {MAIN_REF} ({}), arriving with their \
             lists: {}",
            short(commit),
            judged.arriving.join(", ")
        ),
        Base::At { commit, .. } => println!(
            "\ntier-check: every list is compared with the merge base with {MAIN_REF} ({})",
            short(commit)
        ),
        _ => {}
    }
    refused.extend(judged.refused);
    refused
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tree of manifests in a temp directory: `(dir, name, path deps)`.
    fn fixture(crates: &[(&str, &str, &[&str])]) -> tempfile::TempDir {
        let t = tempfile::tempdir().expect("a temp dir");
        for (dir, name, deps) in crates {
            let mut text = format!("[package]\nname = \"{name}\"\n\n[dependencies]\n");
            for d in *deps {
                let to = d.rsplit('/').next().unwrap_or(d);
                let up = "../".repeat(dir.split('/').count());
                text.push_str(&format!("{to} = {{ path = \"{up}{d}\" }}\n"));
            }
            let p = t.path().join(dir);
            std::fs::create_dir_all(&p).unwrap();
            std::fs::write(p.join("Cargo.toml"), text).unwrap();
        }
        t
    }

    /// A small tree with one owed edge: the shell links the system's crypto crate.
    fn tree() -> tempfile::TempDir {
        fixture(&[
            ("core/wire", "kotton-wire", &[]),
            ("core/crypto", "kotton-crypto", &["core/wire"]),
            ("core/fs", "kotton-fs", &[]),
            ("infra/relay", "kotton-relay", &["core/wire"]),
            ("client/shell", "kotton-shell", &["core/wire", "core/crypto"]),
            ("tools/workspace-hack", "workspace-hack", &[]),
        ])
    }

    const OWED: &str = "[protocol]\n[relay]\n[cli]\nkotton-shell = [\"kotton-crypto\"]\n\
                        [\"client library\"]\n[vault]\n[operator]\n[system]\n";

    fn run(t: &tempfile::TempDir, owed: &str, base: &Base) -> Judged {
        let tree = read_tree(t.path());
        assert!(tree.refused.is_empty(), "{:?}", tree.refused);
        judge(&tree.crates, &tree.edges, &parse_owed(owed).unwrap(), base)
    }

    fn at(owed: &str) -> Base {
        Base::At { commit: "0123456789abcdef".into(), owed: parse_owed(owed).unwrap() }
    }

    fn add_dep(t: &tempfile::TempDir, dir: &str, line: &str) {
        let p = t.path().join(dir).join("Cargo.toml");
        let mut text = std::fs::read_to_string(&p).unwrap();
        text.push_str(line);
        std::fs::write(p, text).unwrap();
    }

    #[test]
    fn the_tree_as_listed_passes() {
        let j = run(&tree(), OWED, &at(OWED));
        assert_eq!(j, Judged::default());
    }

    /// Item 2: an edge out of its row that no list owes is refused, naming both crates.
    #[test]
    fn an_edge_on_no_list_is_refused_naming_both_crates() {
        let t = tree();
        add_dep(&t, "infra/relay", "kotton-crypto = { path = \"../../core/crypto\" }\n");
        let j = run(&t, OWED, &at(OWED));
        assert_eq!(j.refused.len(), 1, "{:?}", j.refused);
        assert!(j.refused[0].contains("kotton-relay") && j.refused[0].contains("kotton-crypto"));
        assert!(j.refused[0].contains("on no owed list"));
    }

    /// A dev-dependency is an edge, and so is a target-specific one.
    #[test]
    fn a_dev_or_target_dependency_is_an_edge() {
        for table in ["[dev-dependencies]", "[target.'cfg(unix)'.build-dependencies]"] {
            let t = tree();
            add_dep(&t, "infra/relay", &format!("{table}\nkotton-fs = {{ path = \"../../core/fs\" }}\n"));
            let j = run(&t, OWED, &at(OWED));
            assert_eq!(j.refused.len(), 1, "{table}: {:?}", j.refused);
            assert!(j.refused[0].contains("kotton-relay") && j.refused[0].contains("kotton-fs"));
        }
    }

    /// Item 3: an entry no manifest has is refused, so an untangling that lands deletes it.
    #[test]
    fn an_entry_no_manifest_has_is_refused() {
        let t = fixture(&[
            ("core/wire", "kotton-wire", &[]),
            ("core/crypto", "kotton-crypto", &[]),
            ("client/shell", "kotton-shell", &["core/wire"]),
        ]);
        let j = run(&t, OWED, &at(OWED));
        assert_eq!(j.refused.len(), 1, "{:?}", j.refused);
        assert!(j.refused[0].contains("kotton-shell -> kotton-crypto"));
        assert!(j.refused[0].contains("in no manifest"));
    }

    /// Item 4: a list cannot grow against the merge base; a row absent there arrives with its
    /// list.
    #[test]
    fn a_list_cannot_grow_and_an_absent_row_arrives() {
        let t = tree();
        add_dep(&t, "infra/relay", "kotton-crypto = { path = \"../../core/crypto\" }\n");
        let grown = OWED.replace("[relay]\n", "[relay]\nkotton-relay = [\"kotton-crypto\"]\n");
        let j = run(&t, &grown, &at(OWED));
        assert_eq!(j.refused.len(), 1, "{:?}", j.refused);
        assert!(j.refused[0].contains("kotton-relay -> kotton-crypto"));
        assert!(j.refused[0].contains("not on the list at the merge base with origin/main"));

        // The same list, with the relay's row absent at the merge base: it arrives.
        let without_relay = OWED.replace("[relay]\n", "");
        let j = run(&t, &grown, &at(&without_relay));
        assert_eq!(j.refused, Vec::<String>::new());
        assert_eq!(j.arriving, vec!["relay"]);

        // No list at the merge base: every row arrives.
        let j = run(&t, &grown, &Base::Absent { commit: "0123".into() });
        assert!(j.refused.is_empty(), "{:?}", j.refused);
        assert_eq!(j.arriving.len(), ROWS.len());

        // A merge base that cannot be read fails rather than reading as no growth.
        let j = run(&t, &grown, &Base::Unknown("no origin/main".into()));
        assert_eq!(j.refused.len(), 1, "{:?}", j.refused);
        assert!(j.refused[0].contains("cannot be judged"));
    }

    /// Item 5: removing an entry whose edge remains is refused.
    #[test]
    fn removing_an_entry_whose_edge_remains_is_refused() {
        let shrunk = OWED.replace("kotton-shell = [\"kotton-crypto\"]\n", "");
        let j = run(&tree(), &shrunk, &at(OWED));
        assert_eq!(j.refused.len(), 1, "{:?}", j.refused);
        assert!(j.refused[0].contains("kotton-shell") && j.refused[0].contains("kotton-crypto"));
    }

    /// No list may owe an edge from `core/` into `client/`.
    #[test]
    fn no_list_owes_the_system_linking_a_client() {
        let t = tree();
        add_dep(&t, "core/fs", "kotton-shell = { path = \"../../client/shell\" }\n");
        let owed = OWED.replace("[system]\n", "[system]\nkotton-fs = [\"kotton-shell\"]\n");
        let j = run(&t, &owed, &Base::Absent { commit: "0123".into() });
        assert_eq!(j.refused.len(), 1, "{:?}", j.refused);
        assert!(j.refused[0].contains("kotton-fs") && j.refused[0].contains("no owed list may hold it"));
    }

    /// An entry that is not owed, or is filed under the wrong row, or a row with no list, is
    /// refused: the lists say what is true.
    #[test]
    fn the_lists_are_held_to_the_rows() {
        let t = tree();
        let allowed = OWED.replace("[relay]\n", "[relay]\nkotton-relay = [\"kotton-wire\"]\n");
        let j = run(&t, &allowed, &Base::Absent { commit: "0".into() });
        assert!(j.refused.iter().any(|r| r.contains("is not owed")), "{:?}", j.refused);

        let misfiled = OWED
            .replace("kotton-shell = [\"kotton-crypto\"]\n", "")
            .replace("[vault]\n", "[vault]\nkotton-shell = [\"kotton-crypto\"]\n");
        let j = run(&t, &misfiled, &Base::Absent { commit: "0".into() });
        assert!(j.refused.iter().any(|r| r.contains("filed under `vault`")), "{:?}", j.refused);

        let rowless = OWED.replace("[operator]\n", "");
        let j = run(&t, &rowless, &at(OWED));
        assert!(j.refused.iter().any(|r| r.contains("row `operator` has no list")), "{:?}", j.refused);
    }

    /// Ground of the first review: a `path` under `[workspace.dependencies]` is refused, in the
    /// root manifest and in a row's manifest that declares a workspace, because the crate that
    /// inherits it writes no path of its own.
    #[test]
    fn a_path_under_workspace_dependencies_is_refused() {
        let t = tree();
        std::fs::write(
            t.path().join("Cargo.toml"),
            "[workspace]\nmembers = []\n\n[workspace.dependencies]\nserde = \"1\"\n",
        )
        .unwrap();
        add_dep(&t, "client/shell", "kotton-fs = { workspace = true }\n");
        assert!(read_tree(t.path()).refused.is_empty(), "a version under the table is not a path");

        std::fs::write(
            t.path().join("Cargo.toml"),
            "[workspace]\nmembers = []\n\n[workspace.dependencies]\nkotton-fs = { path = \"core/fs\" }\n",
        )
        .unwrap();
        let refused = read_tree(t.path()).refused;
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(refused[0].starts_with("Cargo.toml names `kotton-fs` by path"), "{refused:?}");

        let t = tree();
        add_dep(&t, "infra/relay", "[workspace.dependencies.kotton-fs]\npath = \"../../core/fs\"\n");
        let refused = read_tree(t.path()).refused;
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(refused[0].starts_with("infra/relay/Cargo.toml names `kotton-fs` by path"), "{refused:?}");
    }

    /// Ground of the second review: a dependency from a row's crate into a root that is no row
    /// is refused unless it is a dev-dependency, which is counted aside and printed.
    #[test]
    fn a_shipped_dependency_into_a_root_that_is_no_row_is_refused() {
        let t = tree();
        add_dep(&t, "infra/relay", "bridge = { path = \"../../tools/bridge\" }\n");
        let refused = read_tree(t.path()).refused;
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(refused[0].contains("kotton-relay") && refused[0].contains("tools/bridge"), "{refused:?}");

        let t = tree();
        add_dep(&t, "infra/relay", "[build-dependencies]\nbridge = { path = \"../../tests/bridge\" }\n");
        assert_eq!(read_tree(t.path()).refused.len(), 1);

        let t = tree();
        add_dep(&t, "infra/relay", "[dev-dependencies]\nworkspace-hack = { path = \"../../tools/workspace-hack\" }\n");
        add_dep(&t, "client/shell", "[target.'cfg(unix)'.dev-dependencies]\nworkspace-hack = { path = \"../../tools/workspace-hack\" }\n");
        let tree = read_tree(t.path());
        assert!(tree.refused.is_empty(), "{:?}", tree.refused);
        assert_eq!(tree.uncounted["relay"][WORKSPACE_HACK].len(), 1);
        assert_eq!(tree.uncounted["cli"][WORKSPACE_HACK].len(), 1);
    }

    /// A crate under a row's root that no row names is refused, not skipped.
    #[test]
    fn a_crate_in_no_row_is_refused() {
        let t = fixture(&[("client/newthing", "kotton-new", &[])]);
        let refused = read_tree(t.path()).refused;
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(refused[0].contains("kotton-new") && refused[0].contains("in no row"));
    }

    /// The merge base's lists are read from git objects, and a file absent there means every
    /// row arrives.
    #[test]
    fn the_merge_base_is_read_from_git() {
        let r = crate::git_fixture::Repo::new();
        r.write("README", "x\n");
        let first = r.commit("first");
        r.git(&["update-ref", "refs/remotes/origin/main", &first]);
        assert_eq!(base_owed(r.path()), Base::Absent { commit: first.clone() });

        r.write(OWED_FILE, OWED);
        let second = r.commit("lists");
        r.git(&["update-ref", "refs/remotes/origin/main", &second]);
        r.write(OWED_FILE, &OWED.replace("kotton-shell = [\"kotton-crypto\"]\n", ""));
        r.commit("shrink on a branch");
        assert_eq!(base_owed(r.path()), Base::At { commit: second, owed: parse_owed(OWED).unwrap() });
    }

    #[test]
    fn a_directory_is_in_the_row_of_its_longest_path() {
        assert_eq!(row_of("core/wire").map(|r| r.name), Some("protocol"));
        assert_eq!(row_of("core/kvaultd").map(|r| r.name), Some("vault"));
        assert_eq!(row_of("core/crypto").map(|r| r.name), Some("system"));
        assert_eq!(row_of("core/wirex").map(|r| r.name), Some("system"));
        assert_eq!(row_of("client/shell").map(|r| r.name), Some("cli"));
        assert!(row_of("client/elsewhere").is_none());
        assert!(row_of("tools/workspace-hack").is_none());
    }

    /// Every `may_link` names a row, and none runs against the regions' order.
    #[test]
    fn what_a_row_may_link_is_rows_in_order() {
        for row in ROWS {
            for l in row.may_link {
                let to = row_named(l).unwrap_or_else(|| panic!("`{}` may link `{l}`, which is not a row", row.name));
                for f in row.paths {
                    for t in to.paths {
                        assert!(!against_regions(f, t), "`{}` may link `{l}`, against the regions", row.name);
                    }
                }
            }
        }
    }

    /// The tree as it is passes, every crate under the rows' roots is in a row, and every list
    /// in the file names an edge a manifest has. The merge base is not read here.
    #[test]
    fn the_tree_as_it_is_is_in_the_rows() {
        let root = crate::out::root();
        let tree = read_tree(&root);
        assert!(tree.refused.is_empty(), "{:?}", tree.refused);
        let owed = parse_owed(&std::fs::read_to_string(root.join(OWED_FILE)).unwrap()).unwrap();
        let j = judge(&tree.crates, &tree.edges, &owed, &Base::Absent { commit: String::new() });
        assert!(j.refused.is_empty(), "{:?}", j.refused);
    }
}
