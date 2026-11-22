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
//! with it. Nothing is built. The walk passes over hidden, `target` and `target-*` directories,
//! which hold build output and tool state; so that it passes over no manifest, git is asked for
//! every `Cargo.toml` it tracks under those roots, and one the walk did not read is refused. Git
//! failing to answer is refused too: the run cannot then say it read every manifest. A manifest
//! that names no package is passed over only when it is virtual (no `[package]`, no dependency
//! table of its own); `[project]`, which cargo reads as `[package]` before the 2024 edition, is
//! refused wherever it is.
//!
//! What it cannot place it refuses, naming the crate and the path. Every dependency `path` ends
//! at a directory whose manifest this run read as a row's crate, or is a dev-dependency into a
//! root that is no row; anything else is refused: a path that leaves the repository, even to
//! come back, one into a directory in no row, one into a hidden, `target` or `target-*`
//! directory (whose manifests are not read), and a normal or build dependency into a root that
//! is no row, which ships what it links. A `path` under `[workspace.dependencies]`, `[patch]` or
//! `[replace]` in any manifest read (cargo honours the last two in whichever manifest roots a
//! workspace, declared or not) is refused: each puts an edge or a crate where no manifest read
//! here says so. The `.cargo/` config of a directory that declares a workspace may hold only the
//! top-level keys of [`CONFIG_KEYS`]; any other is refused, naming the file and the key. Each of
//! `paths`, `[patch]`, `[source]` (`directory`, `local-registry`), `[registries]` and
//! `[path-bases]` can make a directory of this checkout a package's source where no manifest
//! read here says so, and a key cargo adds later may; `include` loads files not read here. A
//! crate whose `package.workspace` names no workspace read here is refused. A row's
//! dev-dependencies into a root that is no row (`tools/workspace-hack`, for most crates) are on
//! no list; each row prints how many it does not count.
//!
//! Each edge is judged by the row of each end. Inside one row, or into a row the first may link,
//! it is admitted. Otherwise it is on the first row's owed list, by crate name, or it is refused,
//! naming both crates.
//!
//! ## What holds the lists
//!
//! The lists are [`OWED_FILE`], a data file rather than a table in this source, because the
//! check reads the same file at the merge base with `origin/main` and compares the two: an
//! entry whose edge no list there holds is refused, so a list only shrinks and the gate, not
//! review, holds that. The comparison is by the edge an entry holds, not by the name of the row
//! it is filed under: a row renamed reads at the merge base as the edges its crates owed there,
//! and an entry that follows its crate into another row keeps its floor. Lists arrive only
//! when the merge base has no [`OWED_FILE`], and the run then says so. An entry is also
//! refused when no manifest has its edge (an
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
    /// The rows whose lists arrive because the merge base has no [`OWED_FILE`].
    pub(crate) arriving: Vec<&'static str>,
}

fn row_named_in<'a>(rows: &'a [Row], name: &str) -> Option<&'a Row> {
    rows.iter().find(|r| r.name == name)
}

/// The row a repo-relative directory is in: the row whose path is its longest prefix.
pub(crate) fn row_of(dir: &str) -> Option<&'static Row> {
    row_in(ROWS, dir)
}

/// [`row_of`] over `rows`.
fn row_in<'a>(rows: &'a [Row], dir: &str) -> Option<&'a Row> {
    let parts: Vec<&str> = dir.split('/').collect();
    let mut best: Option<(&'a Row, usize)> = None;
    for row in rows {
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

/// Every `Cargo.toml` under `dir`, depth-first, skipping hidden, `target` and `target-*`
/// directories. [`read_tree`] refuses a manifest git tracks that this passed over.
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

/// Why the manifest at `at` cannot be read as a crate or passed over as a virtual one. A
/// `[project]` table is refused in any manifest: cargo still reads it as the package before the
/// 2024 edition, and [`package_name`] reads `[package]` only. A manifest that names no package
/// passes only when it is virtual: no `[package]`, and no dependency table of its own, at the
/// top level or under `[target.'…']`. Anything else is a crate whose dependencies no rule reads.
fn shape_refusals(manifest: &Table, at: &str) -> Vec<String> {
    if manifest.contains_key("project") {
        return vec![format!(
            "{at} names its package under [project]: cargo reads that table as [package] before \
             the 2024 edition, and tier-check reads [package] only, so nothing judges what that \
             crate links. Rename it [package]"
        )];
    }
    if package_name(manifest).is_some() {
        return Vec::new();
    }
    let mut found: Vec<String> = Vec::new();
    if manifest.contains_key("package") {
        found.push("[package] with no name".to_string());
    }
    for t in DEPENDENCY_TABLES {
        if manifest.contains_key(*t) {
            found.push(format!("[{t}]"));
        }
    }
    if let Some(Value::Table(targets)) = manifest.get("target") {
        for (spec, tables) in targets {
            let Value::Table(tables) = tables else { continue };
            for t in DEPENDENCY_TABLES {
                if tables.contains_key(*t) {
                    found.push(format!("[target.'{spec}'.{t}]"));
                }
            }
        }
    }
    if found.is_empty() {
        return Vec::new();
    }
    vec![format!(
        "{at} names no package and is not a virtual manifest: it has {}, so it is a crate whose \
         dependencies tier-check does not read. Name it under [package], or drop {}",
        found.join(", "),
        if found.len() == 1 { "it" } else { "them" }
    )]
}

fn parse_manifest(path: &Path) -> Result<Table, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    text.parse::<Table>()
        .map_err(|e| format!("{}: not TOML: {e}", path.display()))
}

/// Resolve a dependency `path` written in the manifest in repo-relative `dir` to the
/// repo-relative directory it names. `None` when it is absolute or climbs above the repository
/// at any point, even to come back: where it lands then depends on what the checkout is named,
/// which nothing here reads.
fn resolve(dir: &str, path: &str) -> Option<String> {
    let path = path.replace('\\', "/");
    if path.starts_with('/') || path.as_bytes().get(1) == Some(&b':') {
        return None;
    }
    let mut parts: Vec<&str> = Vec::new();
    for segment in dir.split('/').chain(path.split('/')) {
        match segment {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            s => parts.push(s),
        }
    }
    Some(parts.join("/"))
}

/// Every `path` under a manifest's `[patch.*]` or `[replace]`, or a config file's `[patch.*]`,
/// refused. A patch puts another crate where a dependency was, and that crate is not placed by
/// any row, so what it links would be read by nothing.
fn patch_paths(manifest: &Table, at: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut refuse = |key: &str, path: &str, table: &str| {
        out.push(format!(
            "{at} names `{key}` by path (`{path}`) under [{table}]: the crate it puts in a \
             dependency's place is in no manifest tier-check reads as a row's, so nothing reads \
             what it links. Drop it"
        ));
    };
    if let Some(Value::Table(sources)) = manifest.get("patch") {
        for (source, deps) in sources {
            for (key, dep) in deps.as_table().into_iter().flatten() {
                if let Some(path) = dep.as_table().and_then(|d| d.get("path")).and_then(Value::as_str) {
                    refuse(key, path, &format!("patch.{source}"));
                }
            }
        }
    }
    if let Some(Value::Table(deps)) = manifest.get("replace") {
        for (key, dep) in deps {
            if let Some(path) = dep.as_table().and_then(|d| d.get("path")).and_then(Value::as_str) {
                refuse(key, path, "replace");
            }
        }
    }
    out
}

/// The top-level keys a `.cargo/` config file [`config_refusals`] reads may hold: the four the
/// tree's config holds today. None of them, as tier-check admits it, makes a directory of this
/// checkout a package's source: an `[alias]` is a command line cargo expands in place, and the
/// pinned cargo applies `--config` written in one, in a string or a list, joined as
/// `--config=…` or after the subcommand, as if it were written in this file (shown by a run,
/// pull request #678), so an alias holding `--config` is refused ([`alias_refusals`]). A key
/// not here is refused unread, whatever it holds, so a key that does, and one cargo adds later,
/// is refused without being named in this source.
const CONFIG_KEYS: &[&str] = &["build", "alias", "target", "env"];

/// What a workspace declared in repo-relative `dir` is held to beyond its manifest: each of its
/// `.cargo/` config files may hold only the top-level keys of [`CONFIG_KEYS`], and any other is
/// refused, naming the file and the key. `include`, `paths` and `[patch]` keep lines of their
/// own, saying what each does: `include` loads files that are not read here, `paths` and a
/// `[patch]` path each put a crate in a dependency's place, and an alias holding `--config`
/// sets config this file does not show. A config file that cannot be read is refused.
fn config_refusals(root: &Path, dir: &str) -> Vec<String> {
    let mut out = Vec::new();
    for name in [".cargo/config.toml", ".cargo/config"] {
        let at = if dir.is_empty() { name.to_string() } else { format!("{dir}/{name}") };
        let file = root.join(&at);
        if !file.is_file() {
            continue;
        }
        let config = match parse_manifest(&file) {
            Ok(c) => c,
            Err(e) => {
                out.push(e);
                continue;
            }
        };
        if config.contains_key("include") {
            out.push(format!(
                "{at} has `include`: cargo loads the config files it names and honours `paths` \
                 and [patch] in them, and tier-check does not read the files it names, so a \
                 path they hold would be read by nothing. Drop it, and write what it held in \
                 {at}"
            ));
        }
        let before_paths = out.len();
        if let Some(paths) = config.get("paths") {
            let named: Vec<String> = match paths.as_array() {
                Some(a) => a.iter().map(|p| p.as_str().map_or_else(|| format!("{p:?}"), str::to_string)).collect(),
                None => vec![format!("{paths:?}")],
            };
            for p in named {
                out.push(format!(
                    "{at} names `{p}` under `paths`: a path override puts a crate in a \
                     dependency's place that is in no manifest tier-check reads as a row's, so \
                     nothing reads what it links. Drop it"
                ));
            }
        }
        let paths_named = out.len() > before_paths;
        let patched = patch_paths(&config, &at);
        let patch_named = !patched.is_empty();
        out.extend(patched);
        // A key on the list passes; `include`, `paths` and `[patch]` pass here only where a
        // line above already refused them, so each refused key gets one line.
        for key in config.keys() {
            let answered = match key.as_str() {
                "include" => true,
                "paths" => paths_named,
                "patch" => patch_named,
                k => CONFIG_KEYS.contains(&k),
            };
            if !answered {
                out.push(format!(
                    "{at} has `{key}`, which is not a config key tier-check admits (it admits \
                     {}): a key it does not admit may make a directory of this checkout a \
                     package's source, which no manifest it reads would say. Drop it",
                    CONFIG_KEYS.iter().map(|k| format!("`{k}`")).collect::<Vec<_>>().join(", ")
                ));
            }
        }
        if let Some(Value::Table(aliases)) = config.get("alias") {
            out.extend(alias_refusals(aliases, &at));
        }
    }
    out
}

/// Every alias under a config file's `[alias]` that holds `--config`, refused, naming the file
/// and the alias. Cargo splits a string alias on whitespace and takes a list alias element by
/// element, and applies a `--config` it finds there wherever it stands, so the token is looked
/// for in every whitespace-separated word of the value, in either form, alone or as
/// `--config=…`.
fn alias_refusals(aliases: &Table, at: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (name, value) in aliases {
        let words: Vec<&str> = match value {
            Value::String(s) => s.split_whitespace().collect(),
            Value::Array(a) => a.iter().filter_map(Value::as_str).flat_map(str::split_whitespace).collect(),
            _ => Vec::new(),
        };
        if let Some(word) = words.iter().find(|w| **w == "--config" || w.starts_with("--config=")) {
            out.push(format!(
                "{at} has alias `{name}` holding `{word}`: cargo applies config given in an alias \
                 as if it were written in {at}, so it may set a key tier-check refuses, which \
                 this file would not show. Drop `--config` from the alias"
            ));
        }
    }
    out
}

/// The manifests git tracks under the rows' roots, repo-relative, or why git could not list
/// them. [`read_tree`] refuses each one its walk did not read, and refuses the run when git
/// cannot be asked.
pub(crate) type Tracked = Result<Vec<String>, String>;

/// Every `Cargo.toml` git tracks under the rows' roots in the checkout at `root`.
pub(crate) fn tracked_manifests(root: &Path) -> Tracked {
    let mut args = vec!["ls-files", "-z", "--cached", "--"];
    let roots = row_roots();
    args.extend(roots.iter().copied());
    let listed = git(root, &args)?;
    Ok(listed
        .split('\0')
        .filter(|f| *f == "Cargo.toml" || f.ends_with("/Cargo.toml"))
        .map(str::to_string)
        .collect())
}

fn declares_workspace(manifest: &Table) -> bool {
    matches!(manifest.get("workspace"), Some(Value::Table(_)))
}

/// The crates of every row under `root`, and the path dependencies between them. A reader that
/// skips what it cannot read reports OK over less than the tree, so what it cannot place is
/// refused, not skipped:
///
/// - a manifest that cannot be read, or a package in no row;
/// - a `[project]` table in any manifest read, and a manifest read that names no package and
///   is not virtual: one with `[package]`, or a dependency table at the top level or under
///   `[target.'…']` ([`shape_refusals`]);
/// - a manifest git tracks under the rows' roots that the walk did not read (one under a
///   hidden, `target` or `target-*` directory, or one missing from the working tree), and the
///   run itself when git cannot list them ([`Tracked`]);
/// - a dependency `path` that does not end at a directory whose manifest this run read as a
///   row's crate, unless it is a dev-dependency into a root named in [`NOT_ROWS`]. That refuses
///   a path that leaves the repository (even to come back), one into a directory under no row
///   and no such root, one into a hidden, `target` or `target-*` directory (whose manifests are
///   not read),
///   and a normal or build dependency into a root that is no row, which ships what it links;
/// - a `path` under `[workspace.dependencies]`, `[patch]` or `[replace]` in the root manifest
///   or any manifest the walk read, and `paths`, a `[patch]` path or `include` in the `.cargo/`
///   config of a directory that declares a workspace;
/// - a crate whose `package.workspace` names no workspace this run read.
pub(crate) fn read_tree(root: &Path, tracked: &Tracked) -> Tree {
    let mut t = Tree::default();
    let (crates, edges, refused) = (&mut t.crates, &mut t.edges, &mut t.refused);
    let uncounted = &mut t.uncounted;
    // The directories that declare a workspace this run read, repo-relative ("" is the root).
    let mut workspaces: BTreeSet<String> = BTreeSet::new();
    let root_manifest = root.join("Cargo.toml");
    if root_manifest.exists() {
        match parse_manifest(&root_manifest) {
            Ok(m) => {
                refused.extend(shape_refusals(&m, "Cargo.toml"));
                refused.extend(workspace_paths(&m, "Cargo.toml"));
                refused.extend(patch_paths(&m, "Cargo.toml"));
                refused.extend(config_refusals(root, ""));
                if declares_workspace(&m) {
                    workspaces.insert(String::new());
                }
            }
            Err(e) => refused.push(e),
        }
    }
    let rel = |p: &Path| -> String {
        let s = p.strip_prefix(root).unwrap_or(p).to_string_lossy().replace('\\', "/");
        crate::normalise_path(&s)
    };
    // First every manifest, so a dependency is placed against everything this run read.
    let mut read: Vec<(String, String, &'static Row, Table)> = Vec::new();
    let mut walked: BTreeSet<String> = BTreeSet::new();
    for top in row_roots() {
        for manifest_path in manifests_under(&root.join(top)) {
            walked.insert(rel(&manifest_path));
            let manifest = match parse_manifest(&manifest_path) {
                Ok(m) => m,
                Err(e) => {
                    refused.push(e);
                    continue;
                }
            };
            let dir_path = manifest_path.parent().unwrap_or(root);
            let dir = rel(dir_path);
            let at = format!("{dir}/Cargo.toml");
            refused.extend(shape_refusals(&manifest, &at));
            refused.extend(workspace_paths(&manifest, &at));
            refused.extend(patch_paths(&manifest, &at));
            if declares_workspace(&manifest) {
                refused.extend(config_refusals(root, &dir));
                workspaces.insert(dir.clone());
            }
            // No name: virtual, or refused above by [`shape_refusals`].
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
            read.push((name, dir, row, manifest));
        }
    }
    match tracked {
        Ok(files) => {
            for f in files.iter().map(|f| crate::normalise_path(&f.replace('\\', "/"))) {
                if walked.contains(&f) {
                    continue;
                }
                let skipped_dir = f
                    .split('/')
                    .rev()
                    .skip(1)
                    .any(|d| d.starts_with('.') || d == "target" || d.starts_with("target-"));
                let absent = matches!(
                    std::fs::symlink_metadata(root.join(&f)),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound
                );
                let why = if skipped_dir {
                    ": it reads no manifest under a hidden, `target` or `target-*` directory. Move \
                     the crate to a directory of its own in a row"
                } else if absent {
                    ": it is not in the working tree. Restore it, or stage its deletion"
                } else {
                    ""
                };
                refused.push(format!(
                    "{f} is tracked by git under a row's root, and tier-check did not read it, so \
                     nothing judges what that crate links{why}"
                ));
            }
        }
        Err(e) => refused.push(format!(
            "the manifests git tracks under {} cannot be listed, so whether this run read every \
             one cannot be judged: {e}",
            row_roots().iter().map(|r| format!("{r}/")).collect::<Vec<_>>().join(", ")
        )),
    }
    let by_dir: BTreeMap<&str, &str> = read.iter().map(|(n, d, _, _)| (d.as_str(), n.as_str())).collect();
    for (name, dir, row, manifest) in &read {
        let workspace = manifest
            .get("package")
            .and_then(Value::as_table)
            .and_then(|p| p.get("workspace"))
            .and_then(Value::as_str);
        if let Some(ws) = workspace {
            if !resolve(dir, ws).is_some_and(|w| workspaces.contains(&w)) {
                refused.push(format!(
                    "{name} ({dir}, row `{}`) names its workspace at `{ws}`, which is no workspace \
                     tier-check read: it reads [workspace.dependencies], [patch] and [replace] only \
                     in the root manifest and in a row's that declares a workspace",
                    row.name
                ));
            }
        }
        for (dep, dev) in dependency_paths(manifest) {
            let Some(to_dir) = resolve(dir, &dep) else {
                refused.push(format!(
                    "{name} ({dir}, row `{}`) depends on `{dep}`, which leaves the repository: \
                     tier-check places only a path that stays inside it, so nothing reads what \
                     that crate links. Write the path from {dir} without climbing above the \
                     repository",
                    row.name
                ));
                continue;
            };
            if let Some(to) = by_dir.get(to_dir.as_str()) {
                edges.insert(Edge {
                    from: name.clone(),
                    from_dir: dir.clone(),
                    to: (*to).to_string(),
                    to_dir,
                });
                continue;
            }
            let top = to_dir.split('/').next().unwrap_or("").to_string();
            let shown = if to_dir.is_empty() { "the repository root".to_string() } else { to_dir.clone() };
            if NOT_ROWS.contains(&top.as_str()) {
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
            } else if row_of(&to_dir).is_some() {
                refused.push(format!(
                    "{name} ({dir}, row `{}`) path-depends on {shown}, which is no crate \
                     tier-check read as a row's, so nothing reads what that crate links. Where \
                     tier-check refused {shown}/Cargo.toml, that refusal gives the cause",
                    row.name
                ));
            } else {
                refused.push(format!(
                    "{name} ({dir}, row `{}`) depends on {shown}, which is in no row and under \
                     no root named in NOT_ROWS: tier-check reads nothing there, so nothing reads \
                     what that crate links. Move the crate into a row",
                    row.name
                ));
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

/// Judge the edges against `rows`, the owed lists against the edges, and the lists against the
/// merge base. The merge base's lists are read by the edges they hold, not by the rows they are
/// filed under: an entry is compared with every list there, so a row renamed, or a crate moved
/// from one row to another, keeps the floor its edges had.
pub(crate) fn judge(rows: &[Row], crates: &[Crate], edges: &BTreeSet<Edge>, owed: &Owed, base: &Base) -> Judged {
    let mut j = Judged::default();
    let row_of_crate: BTreeMap<&str, &Crate> = crates.iter().map(|c| (c.name.as_str(), c)).collect();
    // Whether a list at the merge base holds the edge, under any row.
    let owed_at_base = |from: &str, to: &str| match base {
        Base::At { owed: at, .. } => at
            .values()
            .any(|l| l.get(from).is_some_and(|tos| tos.contains(to))),
        _ => false,
    };

    for row in rows {
        if !owed.contains_key(row.name) {
            j.refused.push(format!(
                "row `{}` has no list in {OWED_FILE}: give it one, empty if it owes nothing",
                row.name
            ));
        }
    }
    for name in owed.keys() {
        if row_named_in(rows, name).is_none() {
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
        let (Some(fr), Some(tr)) = (row_in(rows, &e.from_dir), row_in(rows, &e.to_dir)) else {
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
        let remedy = match base {
            Base::At { .. } if owed_at_base(&e.from, &e.to) => format!(
                "a list at the merge base with {MAIN_REF} holds it, so file it under `{}`",
                fr.name
            ),
            Base::At { .. } => format!(
                "no list at the merge base with {MAIN_REF} holds it, and an owed list only \
                 shrinks, so remove it"
            ),
            Base::Absent { .. } => format!(
                "remove it, or list it under `{}`: the merge base with {MAIN_REF} has no lists, \
                 so every list arrives",
                fr.name
            ),
            Base::Unknown(_) => "remove it".to_string(),
        };
        j.refused.push(format!(
            "{} ({}, row `{}`) links {} ({}, row `{}`), and `{}` may link: {}. The edge is on \
             no owed list: {remedy}",
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
        let Some(row) = row_named_in(rows, row_name) else { continue };
        for (from, tos) in list {
            for to in tos {
                let entry = format!("{from} -> {to} (row `{row_name}`)");
                let Some(fc) = row_of_crate.get(from.as_str()) else {
                    j.refused.push(format!("the owed entry {entry} names {from}, which is no crate of any row"));
                    continue;
                };
                let from_row = row_in(rows, &fc.dir).map_or("no row", |r| r.name);
                if from_row != row.name {
                    j.refused.push(format!(
                        "the owed entry {entry} is filed under `{row_name}`, and {from} is in row `{from_row}`"
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
                if let Some(tr) = row_in(rows, &tc.dir) {
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
            j.arriving = rows.iter().map(|r| r.name).filter(|n| owed.contains_key(*n)).collect();
        }
        Base::At { commit, .. } => {
            for (row_name, list) in owed {
                if row_named_in(rows, row_name).is_none() {
                    continue;
                }
                for (from, tos) in list {
                    for to in tos {
                        if !owed_at_base(from, to) {
                            j.refused.push(format!(
                                "the owed entry {from} -> {to} (row `{row_name}`) is on no list \
                                 at the merge base with {MAIN_REF} ({}): an owed list only \
                                 shrinks, and is read there by the edges it holds, not by its \
                                 row's name, so a row renamed or added owes no edge the lists \
                                 there did not",
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
    let tree = read_tree(root, &tracked_manifests(root));
    refused.extend(tree.refused.iter().cloned());
    let base = base_owed(root);
    let judged = judge(ROWS, &tree.crates, &tree.edges, &owed, &base);

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
        Base::Absent { commit } => println!(
            "\ntier-check: the merge base with {MAIN_REF} ({}) has no {OWED_FILE}, so every list \
             arrives: {}",
            short(commit),
            judged.arriving.join(", ")
        ),
        Base::At { commit, .. } => println!(
            "\ntier-check: every list is compared with the merge base with {MAIN_REF} ({}) by \
             the edges it holds, under any row",
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

    /// Every `Cargo.toml` under the rows' roots in a fixture, hidden and `target` directories
    /// included: what git would list had every file been added.
    fn every_manifest(root: &Path) -> Vec<String> {
        let mut out = Vec::new();
        let mut stack: Vec<PathBuf> = row_roots().iter().map(|r| root.join(r)).collect();
        while let Some(d) = stack.pop() {
            for entry in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if entry.file_name() == "Cargo.toml" {
                    out.push(path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/"));
                }
            }
        }
        out
    }

    /// [`read_tree`] over a fixture, every manifest in it tracked.
    fn read(t: &tempfile::TempDir) -> Tree {
        read_tree(t.path(), &Ok(every_manifest(t.path())))
    }

    fn run(t: &tempfile::TempDir, owed: &str, base: &Base) -> Judged {
        let tree = read(t);
        assert!(tree.refused.is_empty(), "{:?}", tree.refused);
        judge(ROWS, &tree.crates, &tree.edges, &parse_owed(owed).unwrap(), base)
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

    /// Item 4: a list cannot grow against the merge base, whatever its row is called there;
    /// lists arrive only when the merge base has none.
    #[test]
    fn a_list_cannot_grow_and_lists_arrive_only_where_the_merge_base_has_none() {
        let t = tree();
        add_dep(&t, "infra/relay", "kotton-crypto = { path = \"../../core/crypto\" }\n");
        let grown = OWED.replace("[relay]\n", "[relay]\nkotton-relay = [\"kotton-crypto\"]\n");
        let j = run(&t, &grown, &at(OWED));
        assert_eq!(j.refused.len(), 1, "{:?}", j.refused);
        assert!(j.refused[0].contains("kotton-relay -> kotton-crypto"));
        assert!(j.refused[0].contains("on no list at the merge base with origin/main"));

        // The same list, with the relay's row absent at the merge base: the edge is still on
        // no list there, so it is refused, and nothing arrives.
        let without_relay = OWED.replace("[relay]\n", "");
        let j = run(&t, &grown, &at(&without_relay));
        assert_eq!(j.refused.len(), 1, "{:?}", j.refused);
        assert!(j.refused[0].contains("kotton-relay -> kotton-crypto"));
        assert!(j.arriving.is_empty(), "{:?}", j.arriving);

        // No list at the merge base: every row arrives.
        let j = run(&t, &grown, &Base::Absent { commit: "0123".into() });
        assert!(j.refused.is_empty(), "{:?}", j.refused);
        assert_eq!(j.arriving.len(), ROWS.len());

        // A merge base that cannot be read fails rather than reading as no growth.
        let j = run(&t, &grown, &Base::Unknown("no origin/main".into()));
        assert_eq!(j.refused.len(), 1, "{:?}", j.refused);
        assert!(j.refused[0].contains("cannot be judged"));
    }

    /// The rows, with `old` called `new`. No `may_link` names the rows renamed here.
    fn renamed(old: &str, new: &'static str) -> Vec<Row> {
        ROWS.iter()
            .map(|r| Row {
                name: if r.name == old { new } else { r.name },
                becomes: r.becomes,
                paths: r.paths,
                may_link: r.may_link,
            })
            .collect()
    }

    /// A row renamed is compared with the merge base by the edges its list holds, not by its
    /// name: renamed alone it passes, and renamed with its list grown by one it is refused.
    #[test]
    fn a_renamed_row_keeps_the_floor_its_edges_had() {
        let rows = renamed("relay", "relay server");
        assert!(rows.iter().all(|r| !r.may_link.contains(&"relay")));
        let renamed_list = OWED.replace("[relay]\n", "[\"relay server\"]\n");

        let t = tree();
        let tree = read(&t);
        let j = judge(&rows, &tree.crates, &tree.edges, &parse_owed(&renamed_list).unwrap(), &at(OWED));
        assert_eq!(j, Judged::default());

        add_dep(&t, "infra/relay", "kotton-crypto = { path = \"../../core/crypto\" }\n");
        let tree = read(&t);
        assert!(tree.refused.is_empty(), "{:?}", tree.refused);
        let grown = renamed_list.replace(
            "[\"relay server\"]\n",
            "[\"relay server\"]\nkotton-relay = [\"kotton-crypto\"]\n",
        );
        let j = judge(&rows, &tree.crates, &tree.edges, &parse_owed(&grown).unwrap(), &at(OWED));
        assert_eq!(j.refused.len(), 1, "{:?}", j.refused);
        assert!(
            j.refused[0].starts_with(
                "the owed entry kotton-relay -> kotton-crypto (row `relay server`) is on no list at \
                 the merge base with origin/main (0123456789ab)"
            ),
            "{}",
            j.refused[0]
        );
        assert!(j.arriving.is_empty(), "{:?}", j.arriving);
    }

    /// An entry follows its crate into another row and keeps its floor there; left behind, it
    /// is refused as filed under the wrong row, and dropped, the refusal of its edge says which
    /// row to file it under.
    #[test]
    fn an_entry_keeps_its_floor_when_its_crate_changes_rows() {
        let rows: Vec<Row> = ROWS
            .iter()
            .map(|r| Row {
                name: r.name,
                becomes: r.becomes,
                paths: match r.name {
                    "cli" => &["client/cli"],
                    "client library" => &["client/kotton-client", "client/record-file", "client/shell"],
                    _ => r.paths,
                },
                may_link: r.may_link,
            })
            .collect();
        let t = tree();
        let tree = read(&t);
        let judged = |owed: &str| judge(&rows, &tree.crates, &tree.edges, &parse_owed(owed).unwrap(), &at(OWED));

        let followed = OWED
            .replace("kotton-shell = [\"kotton-crypto\"]\n", "")
            .replace("[\"client library\"]\n", "[\"client library\"]\nkotton-shell = [\"kotton-crypto\"]\n");
        assert_eq!(judged(&followed), Judged::default());

        let j = judged(OWED);
        assert_eq!(j.refused.len(), 2, "{:?}", j.refused);
        assert!(j.refused.iter().any(|r| r.contains("filed under `cli`, and kotton-shell is in row `client library`")), "{:?}", j.refused);
        assert!(
            j.refused.iter().any(|r| r.ends_with(
                "a list at the merge base with origin/main holds it, so file it under `client library`"
            )),
            "{:?}",
            j.refused
        );

        // An edge no list at the merge base holds is not to be filed anywhere.
        let none = OWED.replace("kotton-shell = [\"kotton-crypto\"]\n", "");
        let j = judge(&rows, &tree.crates, &tree.edges, &parse_owed(&none).unwrap(), &at(&none));
        assert_eq!(j.refused.len(), 1, "{:?}", j.refused);
        assert!(
            j.refused[0].ends_with("no list at the merge base with origin/main holds it, and an owed list only shrinks, so remove it"),
            "{}",
            j.refused[0]
        );
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
        assert!(read(&t).refused.is_empty(), "a version under the table is not a path");

        std::fs::write(
            t.path().join("Cargo.toml"),
            "[workspace]\nmembers = []\n\n[workspace.dependencies]\nkotton-fs = { path = \"core/fs\" }\n",
        )
        .unwrap();
        let refused = read(&t).refused;
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(refused[0].starts_with("Cargo.toml names `kotton-fs` by path"), "{refused:?}");

        let t = tree();
        add_dep(&t, "infra/relay", "[workspace.dependencies.kotton-fs]\npath = \"../../core/fs\"\n");
        let refused = read(&t).refused;
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(refused[0].starts_with("infra/relay/Cargo.toml names `kotton-fs` by path"), "{refused:?}");
    }

    /// Ground of the second review: a dependency from a row's crate into a root that is no row
    /// is refused unless it is a dev-dependency, which is counted aside and printed.
    #[test]
    fn a_shipped_dependency_into_a_root_that_is_no_row_is_refused() {
        let t = tree();
        add_dep(&t, "infra/relay", "bridge = { path = \"../../tools/bridge\" }\n");
        let refused = read(&t).refused;
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(refused[0].contains("kotton-relay") && refused[0].contains("tools/bridge"), "{refused:?}");

        let t = tree();
        add_dep(&t, "infra/relay", "[build-dependencies]\nbridge = { path = \"../../tests/bridge\" }\n");
        assert_eq!(read(&t).refused.len(), 1);

        let t = tree();
        add_dep(&t, "infra/relay", "[dev-dependencies]\nworkspace-hack = { path = \"../../tools/workspace-hack\" }\n");
        add_dep(&t, "client/shell", "[target.'cfg(unix)'.dev-dependencies]\nworkspace-hack = { path = \"../../tools/workspace-hack\" }\n");
        let tree = read(&t);
        assert!(tree.refused.is_empty(), "{:?}", tree.refused);
        assert_eq!(tree.uncounted["relay"][WORKSPACE_HACK].len(), 1);
        assert_eq!(tree.uncounted["cli"][WORKSPACE_HACK].len(), 1);
    }

    /// A crate under a row's root that no row names is refused, not skipped.
    #[test]
    fn a_crate_in_no_row_is_refused() {
        let t = fixture(&[("client/newthing", "kotton-new", &[])]);
        let refused = read(&t).refused;
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(refused[0].contains("kotton-new") && refused[0].contains("in no row"));
    }

    /// What one change to [`tree`] makes [`read_tree`] refuse: exactly one line.
    fn refused_once(t: &tempfile::TempDir) -> String {
        let refused = read(t).refused;
        assert_eq!(refused.len(), 1, "{refused:?}");
        refused[0].clone()
    }

    fn write(t: &tempfile::TempDir, file: &str, text: &str) {
        let p = t.path().join(file);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }

    /// A path that leaves the repository is refused, absolute or relative.
    #[test]
    fn a_path_outside_the_repository_is_refused() {
        for path in ["../../../elsewhere", "/opt/elsewhere"] {
            let t = tree();
            add_dep(&t, "infra/relay", &format!("elsewhere = {{ path = \"{path}\" }}\n"));
            let r = refused_once(&t);
            assert!(
                r.starts_with(&format!("kotton-relay (infra/relay, row `relay`) depends on `{path}`, which leaves the repository")),
                "{r}"
            );
        }
    }

    /// A path that climbs out of the repository and back in is refused, though on disk it
    /// lands on a crate of a row.
    #[test]
    fn a_path_that_climbs_out_and_returns_is_refused() {
        let t = tree();
        let name = t.path().file_name().unwrap().to_string_lossy().to_string();
        let path = format!("../../../{name}/core/fs");
        add_dep(&t, "client/shell", &format!("kotton-fs = {{ path = \"{path}\" }}\n"));
        assert!(t.path().join("client/shell").join(&path).join("Cargo.toml").is_file());
        let r = refused_once(&t);
        assert!(
            r.starts_with(&format!("kotton-shell (client/shell, row `cli`) depends on `{path}`, which leaves the repository")),
            "{r}"
        );
    }

    /// A path into a hidden top-level directory is in no row and under no root named in
    /// `NOT_ROWS`, and is refused, a dev-dependency too.
    #[test]
    fn a_path_into_a_hidden_top_level_directory_is_refused() {
        for table in ["", "[dev-dependencies]\n"] {
            let t = tree();
            write(&t, ".hidden/bridge/Cargo.toml", "[package]\nname = \"bridge\"\n");
            add_dep(&t, "infra/relay", &format!("{table}bridge = {{ path = \"../../.hidden/bridge\" }}\n"));
            let r = refused_once(&t);
            assert!(
                r.starts_with("kotton-relay (infra/relay, row `relay`) depends on .hidden/bridge, which is in no row and under no root named in NOT_ROWS"),
                "{table}: {r}"
            );
        }
    }

    /// A crate under a hidden, `target` or `target-*` directory inside a row is never read, so
    /// an edge into it is refused rather than admitted as same-row, and the manifest itself is
    /// refused as tracked and unread.
    #[test]
    fn a_crate_under_a_hidden_or_target_directory_in_a_row_is_refused() {
        for under in [".vendored/bridge", "target/bridge", "target-x/bridge"] {
            let t = tree();
            write(
                &t,
                &format!("infra/relay/{under}/Cargo.toml"),
                "[package]\nname = \"bridge\"\n\n[dependencies]\nkotton-crypto = { path = \"../../../../core/crypto\" }\n",
            );
            add_dep(&t, "infra/relay", &format!("bridge = {{ path = \"{under}\" }}\n"));
            let mut refused = read(&t).refused;
            refused.sort();
            assert_eq!(refused.len(), 2, "{under}: {refused:?}");
            assert!(
                refused[0].starts_with(&format!("infra/relay/{under}/Cargo.toml is tracked by git under a row's root, and tier-check did not read it")),
                "{under}: {refused:?}"
            );
            assert_eq!(
                refused[1],
                format!(
                    "kotton-relay (infra/relay, row `relay`) path-depends on infra/relay/{under}, which \
                     is no crate tier-check read as a row's, so nothing reads what that crate links. \
                     Where tier-check refused infra/relay/{under}/Cargo.toml, that refusal gives the \
                     cause"
                ),
                "{under}"
            );
        }
    }

    /// A `path` under `[patch]` is refused in the root manifest, in a row's that declares a
    /// workspace, and in one that declares none (cargo honours it where such a manifest roots a
    /// workspace, as a crate under the root's `exclude` does); a patch that names no path is not.
    #[test]
    fn a_path_under_patch_is_refused() {
        let t = tree();
        write(&t, "Cargo.toml", "[workspace]\nmembers = []\n\n[patch.crates-io]\nserde = { git = \"https://example.invalid/serde\" }\n");
        assert!(read(&t).refused.is_empty(), "a patch with no path");

        write(&t, "Cargo.toml", "[workspace]\nmembers = []\n\n[patch.crates-io]\nserde = { path = \"core/fs\" }\n");
        let r = refused_once(&t);
        assert!(r.starts_with("Cargo.toml names `serde` by path (`core/fs`) under [patch.crates-io]"), "{r}");

        let t = tree();
        add_dep(&t, "infra/relay", "[workspace]\n\n[patch.crates-io.serde]\npath = \"../../core/fs\"\n");
        let r = refused_once(&t);
        assert!(r.starts_with("infra/relay/Cargo.toml names `serde` by path (`../../core/fs`) under [patch.crates-io]"), "{r}");

        let t = tree();
        add_dep(&t, "core/fs", "[patch.crates-io]\nserde = { path = \"../wire\" }\n");
        let r = refused_once(&t);
        assert!(r.starts_with("core/fs/Cargo.toml names `serde` by path (`../wire`) under [patch.crates-io]"), "{r}");
    }

    /// A `path` under `[replace]` is refused where a workspace is declared and where none is.
    #[test]
    fn a_path_under_replace_is_refused() {
        let t = tree();
        write(&t, "Cargo.toml", "[workspace]\nmembers = []\n\n[replace]\n\"serde:1.0.0\" = { path = \"core/fs\" }\n");
        let r = refused_once(&t);
        assert!(r.starts_with("Cargo.toml names `serde:1.0.0` by path (`core/fs`) under [replace]"), "{r}");

        let t = tree();
        add_dep(&t, "infra/relay", "[workspace]\n\n[replace]\n\"serde:1.0.0\" = { path = \"../../core/fs\" }\n");
        let r = refused_once(&t);
        assert!(r.starts_with("infra/relay/Cargo.toml names `serde:1.0.0` by path"), "{r}");

        let t = tree();
        add_dep(&t, "core/fs", "[replace]\n\"serde:1.0.0\" = { path = \"../wire\" }\n");
        let r = refused_once(&t);
        assert!(r.starts_with("core/fs/Cargo.toml names `serde:1.0.0` by path (`../wire`) under [replace]"), "{r}");
    }

    /// A manifest git tracks under a row's root that the walk passed over is refused, with
    /// what it depends on or without; one git does not track is git's to refuse first.
    #[test]
    fn a_tracked_manifest_the_walk_passed_over_is_refused() {
        for under in ["infra/relay/.vendor/bridge", "infra/relay/target-vendor/bridge", "core/target/bridge"] {
            let t = tree();
            write(
                &t,
                &format!("{under}/Cargo.toml"),
                "[package]\nname = \"bridge\"\n\n[dependencies]\nkotton-shell = { path = \"../../../../client/shell\" }\n",
            );
            let r = refused_once(&t);
            assert!(
                r.starts_with(&format!("{under}/Cargo.toml is tracked by git under a row's root, and tier-check did not read it")),
                "{under}: {r}"
            );
        }
    }

    /// The same, read from a real repository: git's index is what is held, so a manifest is
    /// refused once it is added, and the tree passes once it is gone.
    #[test]
    fn the_tracked_manifests_are_read_from_git() {
        let r = crate::git_fixture::Repo::new();
        r.write("core/wire/Cargo.toml", "[package]\nname = \"kotton-wire\"\n");
        r.write("tools/x/Cargo.toml", "[package]\nname = \"x\"\n");
        r.commit("first");
        let tracked = tracked_manifests(r.path());
        assert_eq!(tracked, Ok(vec!["core/wire/Cargo.toml".to_string()]));
        assert!(read_tree(r.path(), &tracked).refused.is_empty());

        r.write("core/.vendor/bridge/Cargo.toml", "[package]\nname = \"bridge\"\n");
        assert!(read_tree(r.path(), &tracked_manifests(r.path())).refused.is_empty(), "untracked");
        r.git(&["add", "core/.vendor/bridge/Cargo.toml"]);
        let refused = read_tree(r.path(), &tracked_manifests(r.path())).refused;
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(refused[0].starts_with("core/.vendor/bridge/Cargo.toml is tracked by git"), "{refused:?}");
    }

    /// A tracked manifest missing from the working tree is refused with that as its reason, not
    /// a hidden or `target` directory; one under such a directory is given that reason.
    #[test]
    fn a_tracked_manifest_missing_from_the_working_tree_is_refused_as_missing() {
        let t = tree();
        let mut tracked = every_manifest(t.path());
        tracked.push("core/gone/Cargo.toml".into());
        tracked.push("core/.vendor/gone/Cargo.toml".into());
        let mut refused = read_tree(t.path(), &Ok(tracked)).refused;
        refused.sort();
        assert_eq!(
            refused,
            vec![
                "core/.vendor/gone/Cargo.toml is tracked by git under a row's root, and tier-check \
                 did not read it, so nothing judges what that crate links: it reads no manifest \
                 under a hidden, `target` or `target-*` directory. Move the crate to a directory \
                 of its own in a row"
                    .to_string(),
                "core/gone/Cargo.toml is tracked by git under a row's root, and tier-check did not \
                 read it, so nothing judges what that crate links: it is not in the working tree. \
                 Restore it, or stage its deletion"
                    .to_string(),
            ]
        );
    }

    /// `[project]` is refused in a row's manifest and in the root's, with `[package]` beside it
    /// or without.
    #[test]
    fn a_package_under_project_is_refused() {
        let t = tree();
        write(&t, "core/fs/Cargo.toml", "[project]\nname = \"kotton-fs\"\n\n[dependencies]\nkotton-shell = { path = \"../../client/shell\" }\n");
        let r = refused_once(&t);
        assert!(r.starts_with("core/fs/Cargo.toml names its package under [project]: cargo reads"), "{r}");

        let t = tree();
        write(&t, "core/fs/Cargo.toml", "[package]\nname = \"kotton-fs\"\n\n[project]\nname = \"kotton-fs\"\n");
        let r = refused_once(&t);
        assert!(r.starts_with("core/fs/Cargo.toml names its package under [project]"), "{r}");

        let t = tree();
        write(&t, "Cargo.toml", "[workspace]\nmembers = []\n\n[project]\nname = \"root\"\n");
        let r = refused_once(&t);
        assert!(r.starts_with("Cargo.toml names its package under [project]"), "{r}");
    }

    /// A manifest that names no package passes only when it is virtual: no `[package]` and no
    /// dependency table, at the top level or under `[target.'…']`, empty or not.
    #[test]
    fn a_manifest_with_no_name_passes_only_when_virtual() {
        for virtual_ in ["[workspace]\nmembers = []\n", "", "[target.'cfg(unix)']\n"] {
            let t = tree();
            write(&t, "core/virt/Cargo.toml", virtual_);
            assert!(read(&t).refused.is_empty(), "{virtual_:?}: {:?}", read(&t).refused);
        }
        let prefix = "core/virt/Cargo.toml names no package and is not a virtual manifest: it has";
        for (text, found) in [
            ("[dependencies]\nx = { path = \"../wire\" }\n", "[dependencies]"),
            ("[dev-dependencies]\n", "[dev-dependencies]"),
            ("[build_dependencies]\nx = { path = \"../wire\" }\n", "[build_dependencies]"),
            ("[target.'cfg(unix)'.dependencies]\nx = { path = \"../wire\" }\n", "[target.'cfg(unix)'.dependencies]"),
            ("[package]\nversion = \"0.1.0\"\n", "[package] with no name"),
            (
                "[workspace]\n\n[dependencies]\nx = { path = \"../wire\" }\n\n[target.'cfg(unix)'.dev-dependencies]\n",
                "[dependencies], [target.'cfg(unix)'.dev-dependencies]",
            ),
        ] {
            let t = tree();
            write(&t, "core/virt/Cargo.toml", text);
            let r = refused_once(&t);
            assert!(r.starts_with(&format!("{prefix} {found}, so it is a crate")), "{text:?}: {r}");
        }

        let t = tree();
        write(&t, "Cargo.toml", "[workspace]\nmembers = []\n\n[dependencies]\nx = { path = \"core/wire\" }\n");
        let r = refused_once(&t);
        assert!(r.starts_with("Cargo.toml names no package and is not a virtual manifest: it has [dependencies]"), "{r}");
    }

    /// When git cannot list the tracked manifests, the run is refused: it cannot say it read
    /// every one.
    #[test]
    fn git_failing_to_list_the_manifests_is_refused() {
        let t = tree();
        let refused = read_tree(t.path(), &Err("git ls-files: not a git repository".into())).refused;
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(
            refused[0].starts_with("the manifests git tracks under core/, infra/, client/ cannot be listed")
                && refused[0].ends_with("not a git repository"),
            "{refused:?}"
        );
    }

    /// A path that resolves to the repository root is refused, naming the root.
    #[test]
    fn a_path_to_the_repository_root_names_the_root() {
        let t = tree();
        add_dep(&t, "infra/relay", "root = { path = \"../..\" }\n");
        let r = refused_once(&t);
        assert!(
            r.starts_with("kotton-relay (infra/relay, row `relay`) depends on the repository root, which is in no row"),
            "{r}"
        );
    }

    /// `paths`, and a `[patch]` path, in a workspace's `.cargo/` config are refused; a config
    /// with neither is not.
    #[test]
    fn config_paths_are_refused() {
        let t = tree();
        write(&t, "Cargo.toml", "[workspace]\nmembers = []\n");
        write(&t, ".cargo/config.toml", "[build]\ntarget-dir = \"out/target\"\n");
        assert!(read(&t).refused.is_empty(), "a config with no paths");

        write(&t, ".cargo/config.toml", "paths = [\"core/fs\"]\n");
        let r = refused_once(&t);
        assert!(r.starts_with(".cargo/config.toml names `core/fs` under `paths`"), "{r}");

        write(&t, ".cargo/config.toml", "[patch.crates-io]\nserde = { path = \"core/fs\" }\n");
        let r = refused_once(&t);
        assert!(r.starts_with(".cargo/config.toml names `serde` by path (`core/fs`) under [patch.crates-io]"), "{r}");

        let t = tree();
        add_dep(&t, "infra/relay", "[workspace]\n");
        write(&t, "infra/relay/.cargo/config", "paths = [\"../../core/fs\"]\n");
        let r = refused_once(&t);
        assert!(r.starts_with("infra/relay/.cargo/config names `../../core/fs` under `paths`"), "{r}");
    }

    /// `include` in a workspace's `.cargo/` config is refused, naming the file, in each form
    /// cargo accepts and whether or not the file it names exists: the files it names are not
    /// read, and cargo honours `paths` and `[patch]` there.
    #[test]
    fn config_include_is_refused() {
        for (file, text) in [
            (".cargo/config.toml", "include = [\"extra.toml\"]\n"),
            (".cargo/config.toml", "include = \"extra.toml\"\n"),
            (".cargo/config.toml", "include = [{ path = \"extra.toml\", optional = true }]\n"),
            (".cargo/config", "include = []\n"),
        ] {
            for exists in [false, true] {
                let t = tree();
                write(&t, "Cargo.toml", "[workspace]\nmembers = []\n");
                write(&t, file, text);
                if exists {
                    write(&t, ".cargo/extra.toml", "[build]\ntarget-dir = \"out/target\"\n");
                }
                let r = refused_once(&t);
                assert!(r.starts_with(&format!("{file} has `include`: cargo loads the config files it names")), "{text:?}: {r}");
            }
        }

        let t = tree();
        add_dep(&t, "infra/relay", "[workspace]\n");
        write(&t, "infra/relay/.cargo/config.toml", "include = [\"extra.toml\"]\n");
        let r = refused_once(&t);
        assert!(r.starts_with("infra/relay/.cargo/config.toml has `include`"), "{r}");
    }

    /// A workspace's `.cargo/` config may hold only the top-level keys of `CONFIG_KEYS`: the
    /// four together pass, and any other key is refused once, naming the file and the key,
    /// whatever it holds. `paths` and `[patch]` that name no path are refused by the list.
    #[test]
    fn config_keys_off_the_list_are_refused() {
        let t = tree();
        write(&t, "Cargo.toml", "[workspace]\nmembers = []\n");
        write(
            &t,
            ".cargo/config.toml",
            "[build]\ntarget-dir = \"out/target\"\n[alias]\nx = \"run\"\n\
             [target.x86_64-pc-windows-msvc]\nlinker = \"rust-lld.exe\"\n[env]\nA = \"1\"\n",
        );
        assert!(read(&t).refused.is_empty(), "the four admitted keys");

        for (file, text, key) in [
            (".cargo/config.toml", "[source.vendored]\ndirectory = \"vendor\"\n[source.crates-io]\nreplace-with = \"vendored\"\n", "source"),
            (".cargo/config.toml", "[source.local]\nlocal-registry = \"core\"\n", "source"),
            (".cargo/config.toml", "[registries.local]\nindex = \"file:///tmp/x\"\n", "registries"),
            (".cargo/config.toml", "[path-bases]\nhere = \"core\"\n", "path-bases"),
            (".cargo/config.toml", "[net]\noffline = true\n", "net"),
            (".cargo/config", "[unstable]\n", "unstable"),
            (".cargo/config.toml", "paths = []\n", "paths"),
            (".cargo/config.toml", "[patch.crates-io]\nserde = { git = \"https://example.com/serde\" }\n", "patch"),
        ] {
            let t = tree();
            write(&t, "Cargo.toml", "[workspace]\nmembers = []\n");
            write(&t, file, text);
            let r = refused_once(&t);
            assert!(
                r.starts_with(&format!("{file} has `{key}`, which is not a config key tier-check admits")),
                "{text:?}: {r}"
            );
        }

        let t = tree();
        add_dep(&t, "infra/relay", "[workspace]\n");
        write(&t, "infra/relay/.cargo/config.toml", "[source.v]\ndirectory = \"v\"\n");
        let r = refused_once(&t);
        assert!(r.starts_with("infra/relay/.cargo/config.toml has `source`"), "{r}");
    }

    /// An `[alias]` that holds `--config` is refused once, naming the file and the alias, in
    /// every form the pinned cargo applies: a string, a list, joined with `=`, and after the
    /// subcommand. An alias without it passes, and the tree's three aliases pass.
    #[test]
    fn an_alias_holding_config_is_refused() {
        let t = tree();
        write(&t, "Cargo.toml", "[workspace]\nmembers = []\n");
        write(
            &t,
            ".cargo/config.toml",
            "[alias]\nxtask = \"run --manifest-path xtask/Cargo.toml --target-dir out/xtask --\"\n\
             dash = \"run -q --manifest-path xtask/Cargo.toml --target-dir out/xtask -- dash\"\n\
             xtask-docs = \"run --manifest-path xtask/Cargo.toml --target-dir out/xtask --features cli-docs --\"\n\
             l = [\"build\", \"--configure-nothing\"]\n",
        );
        assert!(read(&t).refused.is_empty(), "aliases without `--config`");

        for (file, alias, word) in [
            (".cargo/config.toml", "p = \"--config paths=['core/fs'] build\"", "--config"),
            (".cargo/config.toml", "p = [\"--config\", \"paths=['core/fs']\", \"build\"]", "--config"),
            (".cargo/config.toml", "p = \"--config=patch.crates-io.serde.path='core/fs' build\"", "--config=patch.crates-io.serde.path='core/fs'"),
            (".cargo/config.toml", "p = [\"--config=paths=['core/fs']\", \"build\"]", "--config=paths=['core/fs']"),
            (".cargo/config.toml", "p = \"build --config paths=['core/fs']\"", "--config"),
            (".cargo/config", "p = [\"build\", \"--config\", \"paths=['core/fs']\"]", "--config"),
        ] {
            let t = tree();
            write(&t, "Cargo.toml", "[workspace]\nmembers = []\n");
            write(&t, file, &format!("[alias]\n{alias}\n"));
            let r = refused_once(&t);
            assert!(r.starts_with(&format!("{file} has alias `p` holding `{word}`: cargo applies config")), "{alias}: {r}");
        }

        let t = tree();
        add_dep(&t, "infra/relay", "[workspace]\n");
        write(&t, "infra/relay/.cargo/config.toml", "[alias]\nq = \"--config build.target-dir='x' build\"\n");
        let r = refused_once(&t);
        assert!(r.starts_with("infra/relay/.cargo/config.toml has alias `q` holding `--config`"), "{r}");
    }

    /// A crate whose `package.workspace` names no workspace this run read is refused; one that
    /// names a read workspace is not.
    #[test]
    fn a_workspace_outside_the_rows_is_refused() {
        let t = tree();
        write(&t, "Cargo.toml", "[workspace]\nmembers = []\n");
        write(&t, "core/fs/Cargo.toml", "[package]\nname = \"kotton-fs\"\nworkspace = \"../..\"\n");
        assert!(read(&t).refused.is_empty(), "the root's workspace");

        write(&t, "core/fs/Cargo.toml", "[package]\nname = \"kotton-fs\"\nworkspace = \"../../../elsewhere\"\n");
        let r = refused_once(&t);
        assert!(r.starts_with("kotton-fs (core/fs, row `system`) names its workspace at `../../../elsewhere`, which is no workspace tier-check read"), "{r}");
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
                let to = row_named_in(ROWS, l).unwrap_or_else(|| panic!("`{}` may link `{l}`, which is not a row", row.name));
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
        let tree = read_tree(&root, &tracked_manifests(&root));
        assert!(tree.refused.is_empty(), "{:?}", tree.refused);
        let owed = parse_owed(&std::fs::read_to_string(root.join(OWED_FILE)).unwrap()).unwrap();
        let j = judge(ROWS, &tree.crates, &tree.edges, &owed, &Base::Absent { commit: String::new() });
        assert!(j.refused.is_empty(), "{:?}", j.refused);
    }
}
