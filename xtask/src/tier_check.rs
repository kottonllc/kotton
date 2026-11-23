// SPDX-License-Identifier: AGPL-3.0-or-later
//! `tier-check`'s rows: one for each repository of kotton-protocol's repository plan that this
//! tree holds a part of, each over the paths that part has today, each saying which rows it may
//! path-depend on, and each with an owed list of the edges that break it today.
//!
//! Its tests run with the rest of xtask's in `just lint` (`cargo test -p xtask --locked`), so
//! `lint.yml` runs them on every pull request, on Linux; `windows.yml` compiles them and does
//! not run them.
//!
//! ## Why rows
//!
//! kotton-protocol's repository plan says that until a part is cut, this tree is laid out as
//! the plan: one top-level directory for each repository a part of it becomes, and a check that
//! holds each directory to the directories its repository may link. An edge the plan does not
//! allow is on that directory's owed list, by name, or the check fails; the lists are printed on
//! every run, and one only shrinks. A part is cut when its list is empty.
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
//! The reader is held to cargo: every path edge `cargo metadata --no-deps` reports between
//! crates of rows, in the root workspace and the relay's, is one it finds, and every crate it
//! reads is a member of one of the two (`tier_check_cargo_tests`), so a form of dependency it
//! does not know is a red test the day it is written.
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
//! and an entry that follows its crate into another row keeps its floor. A merge base with no
//! [`OWED_FILE`] is refused, as one whose lists cannot be read is: whether a list grew cannot be
//! judged there, and the remedy is to merge `origin/main` into the branch. An entry is also
//! refused when no manifest has its edge (an untangling that lands deletes its entry), when the
//! edge is one its row may link, or when it is filed under a row its crate is not in.
//!
//! ## What holds the rows
//!
//! The rows, and the code roots that are no row, are [`ROWS_FILE`], data for the same reason:
//! the check reads it at the merge base with `origin/main` as well and compares the two, so the
//! gate, not review, holds what the rows admit. A row here is matched with the row of the same
//! name there or, where its name is new, with the row there that has the same paths and whose
//! name is gone (a rename). Against the merge base, the check refuses:
//!
//! - a `may_link` that gains a row: a name in it whose row is matched with no row the matched
//!   row's `may_link` names there;
//! - a root added to `not_rows`;
//! - a crate that changes rows (its directory is in a row here that is not matched with the row
//!   its directory is in there), where the change admits an edge between it and another crate
//!   that the rows there did not admit, or takes such an edge out of the refusal no list may
//!   waive, whether or not a manifest has the edge yet. A path that leaves a row, a path a row
//!   gains from another's, and a row added over another row's paths each change the rows of the
//!   crates under them;
//! - a matched row marked `acting` or `asking` there that is marked otherwise here;
//! - a row that arrives: a row here matched with no row there. A row added, and a row renamed
//!   whose paths change with its name, each arrive.
//!
//! Each of these is a widening, and is accepted only where [`WIDENINGS_FILE`] at the merge base
//! names it: so a widening lands in two pull requests, each read and merged through the loop,
//! the first recording it and the second making it and deleting the record, and an entry whose
//! widening the tree already has is refused. A pull request has `origin/main` merged into it
//! before it lands, and then its merge base is main's tip: a record counts only while main's tip
//! holds it. An entry names rows the tree has (a row that arrives excepted), so splitting a row
//! whose crates link each other takes three: the first records the new row; the second adds it
//! over a placeholder path, a directory that holds a tracked file and no crate, and records the
//! moves of the crates and the `may_link` gains the split needs; the third makes them and
//! deletes the records. Nothing accepts the one refusal more: an edge a list at the merge base
//! owes, which a manifest here has, is refused when the rows here admit it, however they came
//! to. An entry leaves the lists only when its crate is untangled, which is when no manifest
//! here has its edge, from that crate to that crate by package name; a crate moved into its
//! dependency's row, or a row's paths grown over it, or a row added over them, is not
//! untangled. So a crate re-homed into its dependency's row while the edge is owed has no route
//! but untangling: no record accepts it, and its directory and the rows stay as the merge base
//! has them until no manifest has the edge.
//!
//! A merge base with no [`ROWS_FILE`] is refused, as one whose rows cannot be read is: there is
//! nothing there to compare the rows with, so whether they widened cannot be judged. The
//! remedy is to merge `origin/main` into the branch, so that the merge base is main's tip.
//!
//! ## The invariant
//!
//! The lists taken together only shrink; a row's list may receive an entry that follows its
//! crate. Taken together: an entry is compared with every list at the merge base by the edge it
//! holds, under any row, so it may leave one row's list only for the list of the row its crate
//! is in; and the rows, compared with theirs at the merge base, do not admit an edge those lists
//! owe while a manifest has it, so no entry leaves the lists by the rows changing under it.
//!
//! ## What no list may owe
//!
//! Every row is marked, in [`ROWS_FILE`], `acting`, `asking` or `neither`, and a row with no
//! mark, or with another word, is refused when the file is read. The system's and the vault's
//! rows act on a principal's authority, and the protocol's is what every other row is built
//! from, so the three are `acting`, and an acting row may link only acting rows; the CLI's, the
//! client library's and the device-owner tool's rows only ask, and are `asking`; the relay's is
//! `neither`. A crate of an acting row that path-depends on a crate of an asking row is refused
//! whatever the lists say and whatever directory holds either crate: the rule is [`never`],
//! derived from the marks of the rows of each end before any list is read, so a crate that
//! leaves `client/` takes it along, and a row added later that only asks is held by it from its
//! mark. Cargo permits that edge and nothing else here would catch it; it is authority moving
//! somewhere it was not granted, which is not a debt to be paid later. An exception is written
//! only where the repository plan's table names a caller of the device-owner tool, and it names
//! none, so no acting row links it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use toml::{Table, Value};

/// How a row is marked: what the refusal no list may waive ([`never`]) is derived from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Mark {
    /// It acts on a principal's authority, or is what such a row is built from.
    Acting,
    /// It only asks.
    Asking,
    /// Neither.
    Neither,
}

impl Mark {
    fn word(self) -> &'static str {
        match self {
            Mark::Acting => "acting",
            Mark::Asking => "asking",
            Mark::Neither => "neither",
        }
    }

    fn from_word(word: &str) -> Option<Mark> {
        [Mark::Acting, Mark::Asking, Mark::Neither].into_iter().find(|m| m.word() == word)
    }
}

/// A repository of kotton-protocol's repository plan that this tree holds a part of, over
/// today's paths.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Row {
    /// The row's name, as the owed list files it.
    pub(crate) name: String,
    /// What its part becomes: the repository it is cut into, or that it stays.
    pub(crate) becomes: String,
    /// Whether it acts, asks or neither.
    pub(crate) mark: Mark,
    /// The directories it is today. A directory belongs to the row whose path is the longest
    /// prefix of it, by component, so `core` is the rest of `core/`.
    pub(crate) paths: Vec<String>,
    /// The rows it may path-depend on. A row's own crates are always admitted.
    pub(crate) may_link: Vec<String>,
}

/// The rows and the code roots that are no row: [`ROWS_FILE`], read.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Rows {
    pub(crate) rows: Vec<Row>,
    /// The code roots that are no row: nothing in them ships. A row's crate may dev-depend on
    /// them and on nothing else there ([`read_tree`]).
    pub(crate) not_rows: Vec<String>,
}

impl Rows {
    pub(crate) fn named(&self, name: &str) -> Option<&Row> {
        self.rows.iter().find(|r| r.name == name)
    }

    /// The row a repo-relative directory is in: the row whose path is its longest prefix.
    pub(crate) fn row_of(&self, dir: &str) -> Option<&Row> {
        row_in(self, dir)
    }

    /// The top-level directories the rows lie in, in order.
    pub(crate) fn roots(&self) -> Vec<&str> {
        let mut roots: Vec<&str> = Vec::new();
        for row in &self.rows {
            for p in &row.paths {
                let top = p.split('/').next().unwrap_or(p);
                if !roots.contains(&top) {
                    roots.push(top);
                }
            }
        }
        roots
    }

    fn is_not_row(&self, root: &str) -> bool {
        self.not_rows.iter().any(|r| r == root)
    }
}

/// The rows and the roots that are no row, repo-relative.
pub(crate) const ROWS_FILE: &str = "xtask/tier-rows.toml";

/// The widenings of the rows recorded and not yet made, repo-relative.
pub(crate) const WIDENINGS_FILE: &str = "xtask/tier-widenings.toml";

/// The rows of the tree this binary was built in, read from its [`ROWS_FILE`], for the tests
/// of the tree as it is. A test of what the check refuses runs over rows of its own.
#[cfg(test)]
pub(crate) fn live_rows() -> Rows {
    let root = crate::out::root();
    let text = std::fs::read_to_string(root.join(ROWS_FILE)).unwrap_or_else(|e| panic!("{ROWS_FILE}: {e}"));
    parse_rows(&text).unwrap_or_else(|e| panic!("{e}"))
}

fn strings(v: Option<&Value>, at: &str, key: &str) -> Result<Vec<String>, String> {
    let Some(Value::Array(a)) = v else {
        return Err(format!("{ROWS_FILE}: {at} has no `{key}` list"));
    };
    let mut out: Vec<String> = Vec::new();
    for x in a {
        let Value::String(s) = x else {
            return Err(format!("{ROWS_FILE}: {at} `{key}` holds a value that is not a string"));
        };
        if out.contains(s) {
            return Err(format!("{ROWS_FILE}: {at} `{key}` names `{s}` twice"));
        }
        out.push(s.clone());
    }
    Ok(out)
}

/// Parse [`ROWS_FILE`]: `not_rows`, then a `[[row]]` per row with `name`, `becomes`, `mark`,
/// `paths` and `may_link`, and nothing else; then [`held_together`].
pub(crate) fn parse_rows(text: &str) -> Result<Rows, String> {
    let table: Table = text
        .parse()
        .map_err(|e| format!("{ROWS_FILE} is not TOML: {e}"))?;
    for key in table.keys() {
        if key != "not_rows" && key != "row" {
            return Err(format!("{ROWS_FILE} has `{key}`, which is neither `not_rows` nor `row`"));
        }
    }
    let not_rows = strings(table.get("not_rows"), "the file", "not_rows")?;
    let Some(Value::Array(entries)) = table.get("row") else {
        return Err(format!("{ROWS_FILE} has no [[row]]"));
    };
    let mut rows = Vec::new();
    for (i, entry) in entries.iter().enumerate() {
        let Value::Table(entry) = entry else {
            return Err(format!("{ROWS_FILE}: row {} is not a table", i + 1));
        };
        let Some(Value::String(name)) = entry.get("name") else {
            return Err(format!("{ROWS_FILE}: row {} has no `name`", i + 1));
        };
        let at = format!("row `{name}`");
        for key in entry.keys() {
            if !["name", "becomes", "mark", "paths", "may_link"].contains(&key.as_str()) {
                return Err(format!("{ROWS_FILE}: {at} has `{key}`, which is no field of a row"));
            }
        }
        let Some(Value::String(becomes)) = entry.get("becomes") else {
            return Err(format!("{ROWS_FILE}: {at} has no `becomes`"));
        };
        let mark = match entry.get("mark") {
            Some(Value::String(w)) => Mark::from_word(w).ok_or_else(|| {
                format!("{ROWS_FILE}: {at} is marked `{w}`, which is not `acting`, `asking` or `neither`")
            })?,
            _ => {
                return Err(format!(
                    "{ROWS_FILE}: {at} has no mark: mark it `acting`, `asking` or `neither`, so \
                     what no list may owe is derived for it"
                ))
            }
        };
        rows.push(Row {
            name: name.clone(),
            becomes: becomes.clone(),
            mark,
            paths: strings(entry.get("paths"), &at, "paths")?,
            may_link: strings(entry.get("may_link"), &at, "may_link")?,
        });
    }
    let rows = Rows { rows, not_rows };
    held_together(&rows).map_err(|e| format!("{ROWS_FILE}: {e}"))?;
    Ok(rows)
}

/// What a table of rows is held to wherever it is read: every row is named once and has a path;
/// no path is two rows'; every `may_link` names a row; and an acting row may link only acting
/// rows, so what it is built from is held by the refusal it is held by.
fn held_together(rows: &Rows) -> Result<(), String> {
    let mut names = BTreeSet::new();
    let mut paths: BTreeMap<&str, &str> = BTreeMap::new();
    for row in &rows.rows {
        if !names.insert(row.name.as_str()) {
            return Err(format!("row `{}` is named twice", row.name));
        }
        if row.paths.is_empty() {
            return Err(format!("row `{}` has no path", row.name));
        }
        for p in &row.paths {
            if let Some(other) = paths.insert(p.as_str(), row.name.as_str()) {
                return Err(format!("`{p}` is a path of row `{other}` and of row `{}`", row.name));
            }
        }
    }
    for row in &rows.rows {
        for l in &row.may_link {
            let Some(to) = rows.named(l) else {
                return Err(format!("row `{}` may link `{l}`, which is not a row", row.name));
            };
            if row.mark == Mark::Acting && to.mark != Mark::Acting {
                return Err(format!(
                    "row `{}` is marked `acting` and may link `{l}`, which is marked `{}`: an \
                     acting row may link only acting rows",
                    row.name,
                    to.mark.word()
                ));
            }
        }
    }
    Ok(())
}

/// One widening of the rows, as [`WIDENINGS_FILE`] records it and as the comparison with the
/// merge base finds it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Widening {
    /// Row `row`'s `may_link` gains row `gains`.
    MayLink { row: String, gains: String },
    /// Crate `krate` moves from row `from` to row `to`.
    Moves { krate: String, from: String, to: String },
    /// Row `row`, marked `acting` or `asking` at the merge base, is marked `mark`.
    Mark { row: String, mark: Mark },
    /// `not_rows` gains `root`.
    NotRow { root: String },
    /// Row `row` arrives: it is matched with no row at the merge base.
    Arrives { row: String },
}

impl std::fmt::Display for Widening {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Widening::MayLink { row, gains } => write!(f, "row = \"{row}\", gains = \"{gains}\""),
            Widening::Moves { krate, from, to } => write!(f, "crate = \"{krate}\", from = \"{from}\", to = \"{to}\""),
            Widening::Mark { row, mark } => write!(f, "row = \"{row}\", mark = \"{}\"", mark.word()),
            Widening::NotRow { root } => write!(f, "not_row = \"{root}\""),
            Widening::Arrives { row } => write!(f, "row = \"{row}\""),
        }
    }
}

/// Parse [`WIDENINGS_FILE`]: a `[[widen]]` per widening, each one of the five shapes of
/// [`Widening`] with a `why` that is not empty, and nothing else.
pub(crate) fn parse_widenings(text: &str) -> Result<Vec<Widening>, String> {
    let table: Table = text
        .parse()
        .map_err(|e| format!("{WIDENINGS_FILE} is not TOML: {e}"))?;
    for key in table.keys() {
        if key != "widen" {
            return Err(format!("{WIDENINGS_FILE} has `{key}`, which is not `widen`"));
        }
    }
    let entries = match table.get("widen") {
        None => return Ok(Vec::new()),
        Some(Value::Array(a)) => a,
        Some(_) => return Err(format!("{WIDENINGS_FILE}: `widen` is not a list of [[widen]] tables")),
    };
    let mut out = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        let at = format!("{WIDENINGS_FILE}: widening {}", i + 1);
        let Value::Table(e) = e else {
            return Err(format!("{at} is not a table"));
        };
        let s = |k: &str| e.get(k).and_then(Value::as_str).map(str::to_string);
        if s("why").is_none_or(|w| w.trim().is_empty()) {
            return Err(format!("{at} has no `why`: say what a reader holds it to"));
        }
        let mut keys: Vec<&str> = e.keys().map(String::as_str).filter(|k| *k != "why").collect();
        keys.sort_unstable();
        let w = match (keys.as_slice(), s("row"), s("gains"), s("crate"), s("from"), s("to"), s("mark"), s("not_row")) {
            (["gains", "row"], Some(row), Some(gains), ..) => Widening::MayLink { row, gains },
            (["crate", "from", "to"], _, _, Some(krate), Some(from), Some(to), ..) => Widening::Moves { krate, from, to },
            (["mark", "row"], Some(row), .., Some(mark), _) => Widening::Mark {
                row,
                mark: Mark::from_word(&mark).ok_or_else(|| format!("{at} names the mark `{mark}`"))?,
            },
            (["not_row"], .., Some(root)) => Widening::NotRow { root },
            (["row"], Some(row), ..) => Widening::Arrives { row },
            _ => {
                return Err(format!(
                    "{at} has {keys:?}: a widening is `row` and `gains`, `crate`, `from` and `to`, \
                     `row` and `mark`, `not_row`, or `row` alone, each a string, with `why`"
                ))
            }
        };
        if out.contains(&w) {
            return Err(format!("{at} records {w} twice"));
        }
        out.push(w);
    }
    Ok(out)
}

/// The branch the lists may only shrink against.
const MAIN_REF: &str = "origin/main";

/// The one feature set every test build shares: most crates dev-depend on it, and it is no row.
const WORKSPACE_HACK: &str = "tools/workspace-hack";

/// The owed lists, repo-relative.
pub(crate) const OWED_FILE: &str = "xtask/tier-owed.toml";

/// Each row's owed list: row, then the crate the edge is from, then the crates it is to.
pub(crate) type Owed = BTreeMap<String, BTreeMap<String, BTreeSet<String>>>;

/// A crate of a row.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Crate {
    pub(crate) name: String,
    pub(crate) dir: String,
    pub(crate) row: String,
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
    /// The merge base could not be read, or has no [`OWED_FILE`], or the file there could not be
    /// read, and why. Growth cannot be judged, so the gate fails rather than reading it as no
    /// growth.
    Unknown(String),
}

/// What the rows were at the merge base with `origin/main`.
#[derive(Debug, PartialEq)]
pub(crate) enum BaseRows {
    /// [`ROWS_FILE`] and [`WIDENINGS_FILE`] at that commit (no widening where the second is
    /// absent).
    At { commit: String, rows: Rows, widenings: Vec<Widening> },
    /// The merge base could not be read, or has no [`ROWS_FILE`], or a file there could not be
    /// read, and why: the gate fails rather than reading it as no change.
    Unknown(String),
}

/// What a run found.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct Judged {
    pub(crate) refused: Vec<String>,
}

/// The row of `dir` in `rows`: the row whose path is its longest prefix, by component.
fn row_in<'a>(rows: &'a Rows, dir: &str) -> Option<&'a Row> {
    let parts: Vec<&str> = dir.split('/').collect();
    let mut best: Option<(&'a Row, usize)> = None;
    for row in &rows.rows {
        for p in &row.paths {
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
pub(crate) fn manifests_under(dir: &Path) -> Vec<PathBuf> {
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
    pub(crate) uncounted: BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
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

pub(crate) fn parse_manifest(path: &Path) -> Result<Table, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    text.parse::<Table>()
        .map_err(|e| format!("{}: not TOML: {e}", path.display()))
}

/// Resolve a dependency `path` written in the manifest in repo-relative `dir` to the
/// repo-relative directory it names. `None` when it is absolute or climbs above the repository
/// at any point, even to come back: where it lands then depends on what the checkout is named,
/// which nothing here reads.
pub(crate) fn resolve(dir: &str, path: &str) -> Option<String> {
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

/// Every `Cargo.toml` git tracks under the roots of `rows` in the checkout at `root`.
pub(crate) fn tracked_manifests(root: &Path, rows: &Rows) -> Tracked {
    let mut args = vec!["ls-files", "-z", "--cached", "--"];
    let roots = rows.roots();
    args.extend(roots.iter().copied());
    let listed = git(root, &args)?;
    Ok(listed
        .split('\0')
        .filter(|f| *f == "Cargo.toml" || f.ends_with("/Cargo.toml"))
        .map(str::to_string)
        .collect())
}

pub(crate) fn declares_workspace(manifest: &Table) -> bool {
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
///   row's crate, unless it is a dev-dependency into a root `not_rows` names. That refuses
///   a path that leaves the repository (even to come back), one into a directory under no row
///   and no such root, one into a hidden, `target` or `target-*` directory (whose manifests are
///   not read),
///   and a normal or build dependency into a root that is no row, which ships what it links;
/// - a `path` under `[workspace.dependencies]`, `[patch]` or `[replace]` in the root manifest
///   or any manifest the walk read, and `paths`, a `[patch]` path or `include` in the `.cargo/`
///   config of a directory that declares a workspace;
/// - a crate whose `package.workspace` names no workspace this run read.
pub(crate) fn read_tree(root: &Path, rows: &Rows, tracked: &Tracked) -> Tree {
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
    let mut read: Vec<(String, String, &Row, Table)> = Vec::new();
    let mut walked: BTreeSet<String> = BTreeSet::new();
    for top in rows.roots() {
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
            let Some(row) = rows.row_of(&dir) else {
                refused.push(format!(
                    "{name} ({dir}) is in no row: name it in a row of {ROWS_FILE}, by the \
                     repository of kotton-protocol's repository plan it becomes"
                ));
                continue;
            };
            crates.push(Crate { name: name.clone(), dir: dir.clone(), row: row.name.clone() });
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
            rows.roots().iter().map(|r| format!("{r}/")).collect::<Vec<_>>().join(", ")
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
            if rows.is_not_row(&top) {
                if dev {
                    uncounted
                        .entry(row.name.clone())
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
            } else if rows.row_of(&to_dir).is_some() {
                refused.push(format!(
                    "{name} ({dir}, row `{}`) path-depends on {shown}, which is no crate \
                     tier-check read as a row's, so nothing reads what that crate links. Where \
                     tier-check refused {shown}/Cargo.toml, that refusal gives the cause",
                    row.name
                ));
            } else {
                refused.push(format!(
                    "{name} ({dir}, row `{}`) depends on {shown}, which is in no row and under \
                     no root `not_rows` names ({ROWS_FILE}): tier-check reads nothing there, so \
                     nothing reads what that crate links. Move the crate into a row",
                    row.name
                ));
            }
        }
    }
    t
}

fn admitted(from: &Row, to: &Row) -> bool {
    from.name == to.name || from.may_link.contains(&to.name)
}

/// Whether `from` never links `to`, which no list may owe: an acting row never path-depends on
/// an asking row. Derived from the marks alone, so every row is held by it from its mark.
pub(crate) fn never(from: &Row, to: &Row) -> bool {
    from.mark == Mark::Acting && to.mark == Mark::Asking
}

/// Whether a list at the merge base holds the edge, under any row.
fn owed_at(base: &Base, from: &str, to: &str) -> bool {
    match base {
        Base::At { owed, .. } => owed
            .values()
            .any(|l| l.get(from).is_some_and(|tos| tos.contains(to))),
        _ => false,
    }
}

/// Judge the edges against `rows`, the owed lists against the edges, and the lists against the
/// merge base. The merge base's lists are read by the edges they hold, not by the rows they are
/// filed under: an entry is compared with every list there, so a row renamed, or a crate moved
/// from one row to another, keeps the floor its edges had. An edge a list there holds that the
/// rows here admit is refused while a manifest has it: its entry leaves the lists only when its
/// crate is untangled.
pub(crate) fn judge(rows: &Rows, crates: &[Crate], edges: &BTreeSet<Edge>, owed: &Owed, base: &Base) -> Judged {
    let mut j = Judged::default();
    let row_of_crate: BTreeMap<&str, &Crate> = crates.iter().map(|c| (c.name.as_str(), c)).collect();
    let owed_at_base = |from: &str, to: &str| owed_at(base, from, to);

    for row in &rows.rows {
        if !owed.contains_key(&row.name) {
            j.refused.push(format!(
                "row `{}` has no list in {OWED_FILE}: give it one, empty if it owes nothing",
                row.name
            ));
        }
    }
    for name in owed.keys() {
        if rows.named(name).is_none() {
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
        let (Some(fr), Some(tr)) = (rows.row_of(&e.from_dir), rows.row_of(&e.to_dir)) else {
            continue;
        };
        if never(fr, tr) {
            j.refused.push(format!(
                "{} ({}, row `{}`) links {} ({}, row `{}`): row `{}` never path-depends on row \
                 `{}`, whatever directory holds either crate, and no owed list may hold it",
                e.from, e.from_dir, fr.name, e.to, e.to_dir, tr.name, fr.name, tr.name
            ));
            continue;
        }
        if admitted(fr, tr) {
            if let (true, Base::At { commit, .. }) = (owed_at_base(&e.from, &e.to), base) {
                j.refused.push(format!(
                    "{} ({}, row `{}`) links {} ({}, row `{}`), which a list at the merge base \
                     with {MAIN_REF} ({}) owes, and the rows here admit it: an owed entry leaves \
                     the lists only when its crate is untangled, when no manifest has the edge, \
                     and a row's paths or `may_link` changing under it does not untangle it. \
                     Untangle {} from {}, or put the rows, and the directories of both crates, \
                     back as they were there",
                    e.from,
                    e.from_dir,
                    fr.name,
                    e.to,
                    e.to_dir,
                    tr.name,
                    short(commit),
                    e.from,
                    e.to
                ));
            }
            continue;
        }
        if is_owed(&fr.name, &e.from, &e.to) {
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
        let Some(row) = rows.named(row_name) else { continue };
        for (from, tos) in list {
            for to in tos {
                let entry = format!("{from} -> {to} (row `{row_name}`)");
                let Some(fc) = row_of_crate.get(from.as_str()) else {
                    j.refused.push(format!("the owed entry {entry} names {from}, which is no crate of any row"));
                    continue;
                };
                let from_row = rows.row_of(&fc.dir).map_or("no row", |r| r.name.as_str());
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
                if let Some(tr) = rows.row_of(&tc.dir) {
                    // An edge a list at the merge base owes is refused above, as the edge.
                    if admitted(row, tr) && !owed_at_base(from, to) {
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
             one grew cannot be judged: {why}. Fetch, and merge {MAIN_REF} into the branch, so \
             the merge base is main's tip"
        )),
        Base::At { commit, .. } => {
            for (row_name, list) in owed {
                if rows.named(row_name).is_none() {
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

/// The row at the merge base matched with `row`, a row of `here`: the row of the same name
/// there or, where no row there has its name, the row there with the same paths whose name no
/// row here has (a rename).
fn matched<'a>(row: &Row, here: &Rows, there: &'a Rows) -> Option<&'a Row> {
    if let Some(b) = there.named(&row.name) {
        return Some(b);
    }
    let paths: BTreeSet<&String> = row.paths.iter().collect();
    there
        .rows
        .iter()
        .find(|b| here.named(&b.name).is_none() && b.paths.iter().collect::<BTreeSet<_>>() == paths)
}

/// Why an entry of [`WIDENINGS_FILE`] here is refused, if it is: each names a widening this tree
/// has not made yet, of rows and crates it has (a row that arrives excepted), and one that can
/// be made: a `may_link` gain of an acting row names an acting row, or a row `all`, the file's
/// entries, record becoming `acting`.
fn entry_refusal(w: &Widening, all: &[Widening], here: &Rows, crates: &[Crate]) -> Option<String> {
    let made = || {
        Some(format!(
            "{WIDENINGS_FILE} records `{w}`, which this tree has made: an entry is consumed by \
             the change that makes it, so delete it there"
        ))
    };
    let no_row = |r: &str| Some(format!("{WIDENINGS_FILE} records `{w}`, and `{r}` is no row of {ROWS_FILE}"));
    match w {
        Widening::MayLink { row, gains } => {
            let Some(r) = here.named(row) else { return no_row(row) };
            let Some(g) = here.named(gains) else { return no_row(gains) };
            if r.may_link.contains(gains) {
                return made();
            }
            let g_acts = g.mark == Mark::Acting || all.contains(&Widening::Mark { row: gains.clone(), mark: Mark::Acting });
            if r.mark == Mark::Acting && !g_acts {
                return Some(format!(
                    "{WIDENINGS_FILE} records `{w}`, and row `{row}` is marked `acting` and row \
                     `{gains}` `{}`: an acting row may link only acting rows, so it cannot be \
                     made. Mark `{gains}` `acting` first, or record that with it, or delete it",
                    g.mark.word()
                ));
            }
        }
        Widening::Moves { krate, from, to } => {
            if here.named(from).is_none() {
                return no_row(from);
            }
            if here.named(to).is_none() {
                return no_row(to);
            }
            let Some(c) = crates.iter().find(|c| c.name == *krate) else {
                return Some(format!("{WIDENINGS_FILE} records `{w}`, and `{krate}` is no crate of a row"));
            };
            if c.row == *to {
                return made();
            }
            if c.row != *from {
                return Some(format!(
                    "{WIDENINGS_FILE} records `{w}`, and {krate} is in row `{}`, not `{from}`",
                    c.row
                ));
            }
        }
        Widening::Mark { row, mark } => {
            let Some(r) = here.named(row) else { return no_row(row) };
            if r.mark == *mark {
                return made();
            }
        }
        Widening::NotRow { root } => {
            if here.is_not_row(root) {
                return made();
            }
        }
        Widening::Arrives { row } => {
            if here.named(row).is_some() {
                return made();
            }
        }
    }
    None
}

/// Judge the rows against the rows at the merge base: a row that arrives, a `may_link` that
/// gains a row, a root added to `not_rows`, a mark changed from `acting` or `asking`, and a crate
/// that changes rows where that admits an edge the rows there did not or takes one out of
/// [`never`], each refused unless [`WIDENINGS_FILE`] at the merge base records it; and every
/// entry of `widenings`, the file here, held to name a widening not yet made. An edge a list at
/// the merge base owes is [`judge`]'s to refuse, and is not named again here.
pub(crate) fn judge_rows(
    here: &Rows,
    widenings: &[Widening],
    base: &BaseRows,
    crates: &[Crate],
    edges: &BTreeSet<Edge>,
    owed_base: &Base,
) -> Vec<String> {
    let mut refused: Vec<String> = widenings
        .iter()
        .filter_map(|w| entry_refusal(w, widenings, here, crates))
        .collect();
    let (commit, there, recorded): (&str, &Rows, &[Widening]) = match base {
        BaseRows::Unknown(why) => {
            refused.push(format!(
                "the rows cannot be compared with the merge base with {MAIN_REF}, so whether they \
                 widened cannot be judged: {why}. Fetch, and merge {MAIN_REF} into the branch, so \
                 the merge base is main's tip"
            ));
            return refused;
        }
        BaseRows::At { commit, rows, widenings } => (commit, rows, widenings),
    };
    let at = format!("the merge base with {MAIN_REF} ({})", short(commit));
    let mut widened = |w: Widening, what: String| {
        if !recorded.contains(&w) {
            refused.push(format!(
                "{what}. A widening lands only where {WIDENINGS_FILE} at {at} records it: record \
                 `{w}` there, with `why`, in a pull request of its own, and make it in one after"
            ));
        }
    };

    for h in &here.rows {
        let Some(b) = matched(h, here, there) else {
            widened(
                Widening::Arrives { row: h.name.clone() },
                format!(
                    "row `{}` arrives: at {at} no row has its name, and none whose name is gone has \
                     its paths. A row arrives only as a widening",
                    h.name
                ),
            );
            continue;
        };
        for l in &h.may_link {
            if *l == h.name {
                continue;
            }
            let gained = here
                .named(l)
                .and_then(|lr| matched(lr, here, there))
                .is_none_or(|lb| lb.name != b.name && !b.may_link.contains(&lb.name));
            if gained {
                widened(
                    Widening::MayLink { row: h.name.clone(), gains: l.clone() },
                    format!(
                        "row `{}` may link `{l}`, and at {at} row `{}` may link only {}: a \
                         `may_link` does not gain a row",
                        h.name,
                        b.name,
                        b.may_link.join(", ")
                    ),
                );
            }
        }
        if b.mark != Mark::Neither && h.mark != b.mark {
            widened(
                Widening::Mark { row: h.name.clone(), mark: h.mark },
                format!(
                    "row `{}` is marked `{}`, and at {at} row `{}` is marked `{}`: a row's mark \
                     holds the refusal no list may waive, and one marked `acting` or `asking` \
                     keeps it",
                    h.name,
                    h.mark.word(),
                    b.name,
                    b.mark.word()
                ),
            );
        }
    }

    for r in &here.not_rows {
        if !there.is_not_row(r) {
            widened(
                Widening::NotRow { root: r.clone() },
                format!(
                    "`not_rows` names `{r}`, and at {at} it does not: tier-check reads nothing \
                     under a root that is no row, and `not_rows` does not gain one"
                ),
            );
        }
    }

    // Every crate whose directory is in a row there and in an unmatched row here.
    let placed: Vec<(&Crate, &Row, &Row)> = crates
        .iter()
        .filter_map(|c| Some((c, here.row_of(&c.dir)?, there.row_of(&c.dir)?)))
        .collect();
    for &(c, h, b) in &placed {
        if matched(h, here, there).is_some_and(|m| m.name == b.name) {
            continue;
        }
        let mut what: Vec<String> = Vec::new();
        for &(o, oh, ob) in &placed {
            if o.name == c.name {
                continue;
            }
            for (from, to, fh, th, fb, tb) in [(c, o, h, oh, b, ob), (o, c, oh, h, ob, b)] {
                let refused_as_owed = owed_at(owed_base, &from.name, &to.name)
                    && edges.iter().any(|e| e.from == from.name && e.to == to.name);
                if refused_as_owed {
                    continue;
                }
                if admitted(fh, th) && !admitted(fb, tb) {
                    what.push(format!("{} -> {} is admitted, and was not", from.name, to.name));
                } else if never(fb, tb) && !never(fh, th) {
                    what.push(format!(
                        "{} -> {} leaves the refusal no list may waive",
                        from.name, to.name
                    ));
                }
            }
        }
        if !what.is_empty() {
            widened(
                Widening::Moves { krate: c.name.clone(), from: b.name.clone(), to: h.name.clone() },
                format!(
                    "{} ({}) is in row `{}`, and at {at} it is in row `{}`: a crate changes rows \
                     only where that admits no edge the rows there did not, and takes none out of \
                     the refusal no list may waive, and here {}",
                    c.name,
                    c.dir,
                    h.name,
                    b.name,
                    what.join("; ")
                ),
            );
        }
    }
    refused
}

fn short(commit: &str) -> &str {
    &commit[..commit.len().min(12)]
}

pub(crate) fn git(root: &Path, args: &[&str]) -> Result<String, String> {
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

/// The merge base of `HEAD` with `origin/main`.
fn merge_base(root: &Path) -> Result<String, String> {
    git(root, &["merge-base", MAIN_REF, "HEAD"]).map(|c| c.trim().to_string())
}

/// `file` at `commit`, read from git objects, or `None` when that commit has no such file.
fn file_at(root: &Path, commit: &str, file: &str) -> Result<Option<String>, String> {
    if git(root, &["ls-tree", "--name-only", commit, "--", file])?.trim().is_empty() {
        return Ok(None);
    }
    git(root, &["show", &format!("{commit}:{file}")]).map(Some)
}

/// The owed lists at the merge base of `HEAD` with `origin/main`, read from git objects.
pub(crate) fn base_owed(root: &Path) -> Base {
    let commit = match merge_base(root) {
        Ok(c) => c,
        Err(e) => return Base::Unknown(e),
    };
    let text = match file_at(root, &commit, OWED_FILE) {
        Ok(Some(t)) => t,
        Ok(None) => return Base::Unknown(format!("{} has no {OWED_FILE}", short(&commit))),
        Err(e) => return Base::Unknown(e),
    };
    match parse_owed(&text) {
        Ok(owed) => Base::At { commit, owed },
        Err(e) => Base::Unknown(format!("at {}: {e}", short(&commit))),
    }
}

/// The rows at the merge base of `HEAD` with `origin/main`, read from git objects: its
/// [`ROWS_FILE`] and [`WIDENINGS_FILE`]. A merge base with no [`ROWS_FILE`] is `Unknown`.
pub(crate) fn base_rows(root: &Path) -> BaseRows {
    let commit = match merge_base(root) {
        Ok(c) => c,
        Err(e) => return BaseRows::Unknown(e),
    };
    let unknown = |e: String| BaseRows::Unknown(format!("at {}: {e}", short(&commit)));
    match file_at(root, &commit, ROWS_FILE) {
        Err(e) => BaseRows::Unknown(e),
        Ok(Some(text)) => {
            let rows = match parse_rows(&text) {
                Ok(r) => r,
                Err(e) => return unknown(e),
            };
            let widenings = match file_at(root, &commit, WIDENINGS_FILE) {
                Err(e) => return BaseRows::Unknown(e),
                Ok(None) => Vec::new(),
                Ok(Some(t)) => match parse_widenings(&t) {
                    Ok(w) => w,
                    Err(e) => return unknown(e),
                },
            };
            BaseRows::At { commit, rows, widenings }
        }
        Ok(None) => BaseRows::Unknown(format!("{} has no {ROWS_FILE}", short(&commit))),
    }
}

fn read_file(root: &Path, file: &str) -> Result<String, String> {
    std::fs::read_to_string(root.join(file)).map_err(|e| format!("{file}: {e}"))
}

/// Print every row, its mark, its paths, what it may link and its owed list with a count, and
/// return what is refused. The lists are printed on every run, refused or not.
pub(crate) fn rows_check(root: &Path) -> Vec<String> {
    let mut refused = Vec::new();
    let rows = match read_file(root, ROWS_FILE).and_then(|t| parse_rows(&t)) {
        Ok(r) => r,
        Err(e) => {
            refused.push(e);
            return refused;
        }
    };
    for row in &rows.rows {
        for p in &row.paths {
            if !root.join(p).is_dir() {
                refused.push(format!(
                    "row `{}` names `{p}`, which is not a directory here, so it reads nothing: \
                     repoint it in {ROWS_FILE}",
                    row.name
                ));
            }
        }
    }
    let owed = match read_file(root, OWED_FILE).and_then(|t| parse_owed(&t)) {
        Ok(o) => o,
        Err(e) => {
            refused.push(e);
            return refused;
        }
    };
    let widenings = match read_file(root, WIDENINGS_FILE).and_then(|t| parse_widenings(&t)) {
        Ok(w) => w,
        Err(e) => {
            refused.push(e);
            return refused;
        }
    };
    let rowed = rows.roots();
    for r in crate::tree::CODE_ROOTS {
        if rowed.contains(r) == rows.is_not_row(r) {
            refused.push(format!(
                "code root `{r}/` must be either a row's or named in `not_rows`, and not both \
                 ({ROWS_FILE})"
            ));
        }
    }
    let tree = read_tree(root, &rows, &tracked_manifests(root, &rows));
    refused.extend(tree.refused.iter().cloned());
    let base = base_owed(root);
    let judged = judge(&rows, &tree.crates, &tree.edges, &owed, &base);
    let base_r = base_rows(root);
    let rows_refused = judge_rows(&rows, &widenings, &base_r, &tree.crates, &tree.edges, &base);

    println!("tier-check: one row for each repository of kotton-protocol's repository plan this tree holds a part of, over today's paths");
    for row in &rows.rows {
        let list = owed.get(&row.name);
        let count: usize = list.map(|l| l.values().map(BTreeSet::len).sum()).unwrap_or(0);
        let paths = if row.name == "system" {
            "core/ (the rest of it)".to_string()
        } else {
            row.paths.join(", ")
        };
        println!("\n  {}: {}", row.name, row.becomes);
        println!("    mark: {}", row.mark.word());
        println!("    paths: {paths}");
        println!("    may link: {}", row.may_link.join(", "));
        println!("    owed ({count}):");
        for (from, tos) in list.into_iter().flatten() {
            for to in tos {
                println!("      {from} -> {to}");
            }
        }
        let none = BTreeMap::new();
        let uncounted = tree.uncounted.get(&row.name).unwrap_or(&none);
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
    println!("\n  not rows: {}", rows.not_rows.join(", "));
    if let Base::At { commit, .. } = &base {
        println!(
            "\ntier-check: every list is compared with the merge base with {MAIN_REF} ({}) by \
             the edges it holds, under any row",
            short(commit)
        );
    }
    if let BaseRows::At { commit, widenings: w, .. } = &base_r {
        println!(
            "tier-check: every row is compared with {ROWS_FILE} at the merge base with \
             {MAIN_REF} ({}), which records {} widening(s) in {WIDENINGS_FILE}",
            short(commit),
            w.len()
        );
    }
    for w in &widenings {
        println!("tier-check: recorded, not yet made ({WIDENINGS_FILE}): {w}");
    }
    refused.extend(judged.refused);
    refused.extend(rows_refused);
    refused
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rows these tests run over: their own, written here and not read from [`ROWS_FILE`],
    /// so that an edit of that file the gate accepts needs no edit of a test. They are shaped as
    /// the repository plan's rows, over the directories of [`tree`] and a few more.
    const ROWS: &str = r#"not_rows = ["tools", "xtask", "tests"]

[[row]]
name = "protocol"
becomes = "a fixture's protocol"
mark = "acting"
paths = ["core/wire", "core/common"]
may_link = ["protocol"]

[[row]]
name = "relay"
becomes = "a fixture's relay"
mark = "neither"
paths = ["infra/relay"]
may_link = ["protocol"]

[[row]]
name = "cli"
becomes = "a fixture's CLI"
mark = "asking"
paths = ["client/cli", "client/shell"]
may_link = ["protocol", "client library", "cli"]

[[row]]
name = "client library"
becomes = "a fixture's client library"
mark = "asking"
paths = ["client/kotton-client"]
may_link = ["protocol", "client library"]

[[row]]
name = "vault"
becomes = "a fixture's vault"
mark = "acting"
paths = ["core/kvaultd"]
may_link = ["protocol", "vault"]

[[row]]
name = "operator"
becomes = "a fixture's device-owner tool"
mark = "asking"
paths = ["client/kotton-operator"]
may_link = ["protocol", "system", "operator"]

[[row]]
name = "system"
becomes = "a fixture's system"
mark = "acting"
paths = ["core"]
may_link = ["protocol", "system"]
"#;

    /// [`ROWS`], read.
    fn rows() -> Rows {
        parse_rows(ROWS).unwrap_or_else(|e| panic!("{e}"))
    }

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
        let mut stack: Vec<PathBuf> = rows().roots().iter().map(|r| root.join(r)).collect();
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
        read_tree(t.path(), &rows(), &Ok(every_manifest(t.path())))
    }

    fn run(t: &tempfile::TempDir, owed: &str, base: &Base) -> Judged {
        let tree = read(t);
        assert!(tree.refused.is_empty(), "{:?}", tree.refused);
        judge(&rows(), &tree.crates, &tree.edges, &parse_owed(owed).unwrap(), base)
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

    /// A list cannot grow against the merge base, whatever its row is called there, and a
    /// merge base whose lists cannot be read is refused.
    #[test]
    fn a_list_cannot_grow_and_a_merge_base_without_lists_is_refused() {
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

        // A merge base that cannot be read, or has no lists, fails rather than reading as no
        // growth, and names the remedy.
        let j = run(&t, &grown, &Base::Unknown("no origin/main".into()));
        assert_eq!(j.refused.len(), 1, "{:?}", j.refused);
        assert_eq!(
            j.refused[0],
            "the owed lists cannot be compared with the merge base with origin/main, so whether one \
             grew cannot be judged: no origin/main. Fetch, and merge origin/main into the branch, so \
             the merge base is main's tip"
        );
    }

    /// The rows, with `old` called `new`. No `may_link` names the rows renamed here.
    fn renamed(old: &str, new: &str) -> Rows {
        let mut rows = rows();
        for r in &mut rows.rows {
            if r.name == old {
                r.name = new.to_string();
            }
        }
        rows
    }

    /// The rows, with the paths of each row `paths` names replaced.
    fn repathed(paths: &[(&str, &[&str])]) -> Rows {
        let mut rows = rows();
        for r in &mut rows.rows {
            if let Some((_, p)) = paths.iter().find(|(n, _)| *n == r.name) {
                r.paths = p.iter().map(|s| s.to_string()).collect();
            }
        }
        rows
    }

    /// A row renamed is compared with the merge base by the edges its list holds, not by its
    /// name: renamed alone it passes, and renamed with its list grown by one it is refused.
    #[test]
    fn a_renamed_row_keeps_the_floor_its_edges_had() {
        let rows = renamed("relay", "relay server");
        assert!(rows.rows.iter().all(|r| !r.may_link.iter().any(|l| l == "relay")));
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
    }

    /// An entry follows its crate into another row and keeps its floor there; left behind, it
    /// is refused as filed under the wrong row, and dropped, the refusal of its edge says which
    /// row to file it under.
    #[test]
    fn an_entry_keeps_its_floor_when_its_crate_changes_rows() {
        let rows = repathed(&[
            ("cli", &["client/cli"]),
            ("client library", &["client/kotton-client", "client/shell"]),
        ]);
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

    /// No list may owe the system linking the CLI, read from the manifests.
    #[test]
    fn no_list_owes_the_system_linking_a_client() {
        let t = tree();
        add_dep(&t, "core/fs", "kotton-shell = { path = \"../../client/shell\" }\n");
        let owed = OWED.replace("[system]\n", "[system]\nkotton-fs = [\"kotton-shell\"]\n");
        let j = run(&t, &owed, &at(&owed));
        assert_eq!(j.refused.len(), 1, "{:?}", j.refused);
        assert!(j.refused[0].contains("kotton-fs") && j.refused[0].contains("no owed list may hold it"));
    }

    /// No list may owe a crate of the protocol's, the vault's or the system's row linking a crate
    /// of the CLI's, the client library's or the operator's, whatever directory holds it: here
    /// the CLI's crate and the operator's lie outside `client/`, each edge is on its row's list
    /// and on that list at the merge base, and every edge is refused all the same.
    #[test]
    fn no_list_owes_a_row_that_acts_linking_one_that_only_asks_wherever_it_lies() {
        let rows = repathed(&[("cli", &["cli"]), ("operator", &["operator"])]);
        let crate_of = |name: &str, dir: &str| {
            let row = rows.row_of(dir).unwrap_or_else(|| panic!("{dir} is in no row")).name.clone();
            Crate { name: name.into(), dir: dir.into(), row }
        };
        let from = [crate_of("kotton-wire", "core/wire"), crate_of("kvaultd", "core/kvaultd"), crate_of("kotton-fs", "core/fs")];
        let to = [
            crate_of("kotton-cli", "cli"),
            crate_of("kotton", "client/kotton-client"),
            crate_of("kotton-operator", "operator"),
        ];
        assert_eq!(from.iter().map(|c| c.row.as_str()).collect::<Vec<_>>(), ["protocol", "vault", "system"]);
        assert_eq!(to.iter().map(|c| c.row.as_str()).collect::<Vec<_>>(), ["cli", "client library", "operator"]);

        let mut edges = BTreeSet::new();
        let mut owed: Owed = rows.rows.iter().map(|r| (r.name.to_string(), BTreeMap::new())).collect();
        for f in &from {
            for t in &to {
                edges.insert(Edge { from: f.name.clone(), from_dir: f.dir.clone(), to: t.name.clone(), to_dir: t.dir.clone() });
                owed.get_mut(&f.row).unwrap().entry(f.name.clone()).or_default().insert(t.name.clone());
            }
        }
        let crates: Vec<Crate> = from.iter().chain(&to).cloned().collect();
        for base in [Base::At { commit: "0123".into(), owed: owed.clone() }] {
            let j = judge(&rows, &crates, &edges, &owed, &base);
            assert_eq!(j.refused.len(), from.len() * to.len(), "{base:?}: {:?}", j.refused);
            for f in &from {
                for t in &to {
                    let head = format!(
                        "{} ({}, row `{}`) links {} ({}, row `{}`): row `{}` never path-depends on row `{}`",
                        f.name, f.dir, f.row, t.name, t.dir, t.row, f.row, t.row
                    );
                    assert!(
                        j.refused.iter().any(|r| r.starts_with(&head) && r.ends_with("no owed list may hold it")),
                        "{base:?}: {head}: {:?}",
                        j.refused
                    );
                }
            }
        }
    }

    /// An entry that is not owed, or is filed under the wrong row, or a row with no list, is
    /// refused: the lists say what is true.
    #[test]
    fn the_lists_are_held_to_the_rows() {
        let t = tree();
        let allowed = OWED.replace("[relay]\n", "[relay]\nkotton-relay = [\"kotton-wire\"]\n");
        let j = run(&t, &allowed, &at(OWED));
        assert!(j.refused.iter().any(|r| r.contains("is not owed")), "{:?}", j.refused);

        let misfiled = OWED
            .replace("kotton-shell = [\"kotton-crypto\"]\n", "")
            .replace("[vault]\n", "[vault]\nkotton-shell = [\"kotton-crypto\"]\n");
        let j = run(&t, &misfiled, &at(OWED));
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

    /// A path into a hidden top-level directory is in no row and under no root `not_rows`
    /// names, and is refused, a dev-dependency too.
    #[test]
    fn a_path_into_a_hidden_top_level_directory_is_refused() {
        for table in ["", "[dev-dependencies]\n"] {
            let t = tree();
            write(&t, ".hidden/bridge/Cargo.toml", "[package]\nname = \"bridge\"\n");
            add_dep(&t, "infra/relay", &format!("{table}bridge = {{ path = \"../../.hidden/bridge\" }}\n"));
            let r = refused_once(&t);
            assert!(
                r.starts_with("kotton-relay (infra/relay, row `relay`) depends on .hidden/bridge, which is in no row and under no root `not_rows` names"),
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
        let tracked = tracked_manifests(r.path(), &rows());
        assert_eq!(tracked, Ok(vec!["core/wire/Cargo.toml".to_string()]));
        assert!(read_tree(r.path(), &rows(), &tracked).refused.is_empty());

        r.write("core/.vendor/bridge/Cargo.toml", "[package]\nname = \"bridge\"\n");
        assert!(read_tree(r.path(), &rows(), &tracked_manifests(r.path(), &rows())).refused.is_empty(), "untracked");
        r.git(&["add", "core/.vendor/bridge/Cargo.toml"]);
        let refused = read_tree(r.path(), &rows(), &tracked_manifests(r.path(), &rows())).refused;
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
        let mut refused = read_tree(t.path(), &rows(), &Ok(tracked)).refused;
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
        let refused = read_tree(t.path(), &rows(), &Err("git ls-files: not a git repository".into())).refused;
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

    /// The merge base's lists are read from git objects, and a merge base with no lists file is
    /// refused, naming the remedy.
    #[test]
    fn the_merge_base_is_read_from_git() {
        let r = crate::git_fixture::Repo::new();
        r.write("README", "x\n");
        let first = r.commit("first");
        r.git(&["update-ref", "refs/remotes/origin/main", &first]);
        let base = base_owed(r.path());
        assert_eq!(base, Base::Unknown(format!("{} has no xtask/tier-owed.toml", short(&first))));
        let j = run(&tree(), OWED, &base);
        assert_eq!(j.refused.len(), 1, "{:?}", j.refused);
        assert!(
            j.refused[0].ends_with(&format!(
                "cannot be judged: {} has no xtask/tier-owed.toml. Fetch, and merge origin/main into \
                 the branch, so the merge base is main's tip",
                short(&first)
            )),
            "{}",
            j.refused[0]
        );

        r.write(OWED_FILE, OWED);
        let second = r.commit("lists");
        r.git(&["update-ref", "refs/remotes/origin/main", &second]);
        r.write(OWED_FILE, &OWED.replace("kotton-shell = [\"kotton-crypto\"]\n", ""));
        r.commit("shrink on a branch");
        assert_eq!(base_owed(r.path()), Base::At { commit: second, owed: parse_owed(OWED).unwrap() });
    }

    fn base_at(rows: Rows, widenings: Vec<Widening>) -> BaseRows {
        BaseRows::At { commit: "0123456789abcdef".into(), rows, widenings }
    }

    /// [`judge_rows`] over [`tree`] read by `here`, against `base`, the lists at the merge base
    /// being [`OWED`].
    fn judged_rows(here: &Rows, widenings: &[Widening], base: &BaseRows) -> Vec<String> {
        held_together(here).unwrap();
        let t = tree();
        let tree = read_tree(t.path(), here, &Ok(every_manifest(t.path())));
        assert!(tree.refused.is_empty(), "{:?}", tree.refused);
        judge_rows(here, widenings, base, &tree.crates, &tree.edges, &at(OWED))
    }

    fn row_mut<'a>(rows: &'a mut Rows, name: &str) -> &'a mut Row {
        rows.rows.iter_mut().find(|r| r.name == name).unwrap()
    }

    const AT: &str = "at the merge base with origin/main (0123456789ab)";

    /// Every row is marked: a row with no mark, or with a word that is no mark, is refused when
    /// the file is read, and so is an acting row that may link a row that is not acting.
    #[test]
    fn every_row_is_marked() {
        let text = ROWS;
        assert!(parse_rows(text).is_ok());
        let cli = "name = \"cli\"\nbecomes = \"a fixture's CLI\"\nmark = \"asking\"\n";
        assert!(text.contains(cli));

        let unmarked = text.replace(cli, "name = \"cli\"\nbecomes = \"a fixture's CLI\"\n");
        let e = parse_rows(&unmarked).unwrap_err();
        assert!(e.starts_with("xtask/tier-rows.toml: row `cli` has no mark"), "{e}");

        let misnamed = text.replace(cli, "name = \"cli\"\nbecomes = \"a fixture's CLI\"\nmark = \"asks\"\n");
        let e = parse_rows(&misnamed).unwrap_err();
        assert!(e.contains("row `cli` is marked `asks`, which is not"), "{e}");

        let vault = "may_link = [\"protocol\", \"vault\"]";
        assert!(text.contains(vault));
        let e = parse_rows(&text.replace(vault, "may_link = [\"protocol\", \"vault\", \"relay\"]")).unwrap_err();
        assert!(e.contains("row `vault` is marked `acting` and may link `relay`, which is marked `neither`"), "{e}");
    }

    /// The refusal no list may waive, derived from the marks, is an acting row linking an asking
    /// row and nothing else: over [`ROWS`], each of the protocol's, the vault's and the system's
    /// rows never links the CLI's, the client library's or the operator's, and no other pair is
    /// refused.
    #[test]
    fn the_marks_refuse_an_acting_row_linking_an_asking_row_and_nothing_else() {
        let rows = rows();
        let mut derived = BTreeSet::new();
        for a in &rows.rows {
            for b in &rows.rows {
                if never(a, b) {
                    derived.insert((a.name.as_str(), b.name.as_str()));
                }
            }
        }
        let mut written = BTreeSet::new();
        for a in ["protocol", "vault", "system"] {
            for b in ["cli", "client library", "operator"] {
                written.insert((a, b));
            }
        }
        assert_eq!(derived, written);
    }

    /// A row's `may_link` that gains a row is refused against the rows file at the merge base;
    /// recorded at the merge base it is accepted, and the record, kept here, is refused as made.
    /// Recorded only here, it is refused.
    #[test]
    fn a_may_link_that_gains_a_row_is_refused() {
        let mut here = rows();
        row_mut(&mut here, "cli").may_link.push("relay".into());
        let w = Widening::MayLink { row: "cli".into(), gains: "relay".into() };
        let r = judged_rows(&here, &[], &base_at(rows(), vec![]));
        assert_eq!(r.len(), 1, "{r:?}");
        assert!(
            r[0].starts_with(&format!(
                "row `cli` may link `relay`, and {AT} row `cli` may link only protocol, client library, cli: a `may_link` does not gain a row. A widening lands only where xtask/tier-widenings.toml {AT} records it"
            )),
            "{}",
            r[0]
        );
        assert_eq!(judged_rows(&here, &[], &base_at(rows(), vec![w.clone()])), Vec::<String>::new());
        let r = judged_rows(&here, std::slice::from_ref(&w), &base_at(rows(), vec![w.clone()]));
        assert_eq!(r.len(), 1, "{r:?}");
        assert!(r[0].contains("which this tree has made"), "{r:?}");
        let r = judged_rows(&here, std::slice::from_ref(&w), &base_at(rows(), vec![]));
        assert!(r.iter().any(|l| l.contains("a `may_link` does not gain a row")), "{r:?}");
        // Recorded and not yet made: pending.
        assert_eq!(judged_rows(&rows(), &[w], &base_at(rows(), vec![])), Vec::<String>::new());
    }

    /// A path that leaves a row for one that admits an edge a list at the merge base owes is
    /// refused, with its entry kept or deleted, whichever end's crate moves; once no manifest has
    /// the edge (the crate untangled), the entry goes and nothing is refused.
    #[test]
    fn a_path_that_leaves_a_row_for_one_that_admits_an_owed_edge_is_refused() {
        let shrunk = OWED.replace("kotton-shell = [\"kotton-crypto\"]\n", "");
        for (here, to_row) in [
            (repathed(&[("protocol", &["core/wire", "core/common", "core/crypto"])]), "protocol"),
            (repathed(&[("cli", &["client/cli"]), ("system", &["core", "client/shell"])]), "system"),
        ] {
            held_together(&here).unwrap();
            let shell_row = if to_row == "system" { "system" } else { "cli" };
            for owed in [OWED.to_string(), shrunk.clone()] {
                let t = tree();
                let tree = read_tree(t.path(), &here, &Ok(every_manifest(t.path())));
                let mut j = judge(&here, &tree.crates, &tree.edges, &parse_owed(&owed).unwrap(), &at(OWED));
                // Kept under `cli` while the crate is in `system`, the entry is also misfiled.
                j.refused.retain(|r| !r.contains("is filed under"));
                assert_eq!(j.refused.len(), 1, "{to_row}: {:?}", j.refused);
                let crypto_row = if to_row == "protocol" { "protocol" } else { "system" };
                assert!(
                    j.refused[0].starts_with(&format!(
                        "kotton-shell (client/shell, row `{shell_row}`) links kotton-crypto (core/crypto, row `{crypto_row}`), which a list {AT} owes, and the rows here admit it: an owed entry leaves the lists only when its crate is untangled"
                    )),
                    "{}",
                    j.refused[0]
                );
            }
            let t = fixture(&[
                ("core/wire", "kotton-wire", &[]),
                ("core/crypto", "kotton-crypto", &["core/wire"]),
                ("core/fs", "kotton-fs", &[]),
                ("infra/relay", "kotton-relay", &["core/wire"]),
                ("client/shell", "kotton-shell", &["core/wire"]),
            ]);
            let tree = read_tree(t.path(), &here, &Ok(every_manifest(t.path())));
            let j = judge(&here, &tree.crates, &tree.edges, &parse_owed(&OWED.replace("kotton-shell = [\"kotton-crypto\"]\n", "")).unwrap(), &at(OWED));
            assert_eq!(j, Judged::default(), "{to_row}: untangled");
        }
    }

    /// A row added over another row's paths that admits an edge a list at the merge base owes
    /// is refused, though the entry is gone; and the crates it takes are refused as moved.
    #[test]
    fn a_row_added_over_another_rows_paths_that_admits_an_owed_edge_is_refused() {
        let mut here = repathed(&[("cli", &["client/cli"])]);
        here.rows.push(Row {
            name: "tangle".into(),
            becomes: "becomes nothing".into(),
            mark: Mark::Neither,
            paths: vec!["client/shell".into(), "core/crypto".into()],
            may_link: vec!["protocol".into()],
        });
        held_together(&here).unwrap();
        let owed = OWED.replace("kotton-shell = [\"kotton-crypto\"]\n", "") + "[tangle]\n";
        let t = tree();
        let tree = read_tree(t.path(), &here, &Ok(every_manifest(t.path())));
        let j = judge(&here, &tree.crates, &tree.edges, &parse_owed(&owed).unwrap(), &at(OWED));
        assert_eq!(j.refused.len(), 1, "{:?}", j.refused);
        assert!(
            j.refused[0].starts_with(&format!(
                "kotton-shell (client/shell, row `tangle`) links kotton-crypto (core/crypto, row `tangle`), which a list {AT} owes"
            )),
            "{}",
            j.refused[0]
        );
        let r = judge_rows(&here, &[], &base_at(rows(), vec![]), &tree.crates, &tree.edges, &at(OWED));
        assert!(r.iter().any(|l| l.starts_with(&format!("kotton-crypto (core/crypto) is in row `tangle`, and {AT} it is in row `system`"))), "{r:?}");
    }

    /// A crate that changes rows where that admits an edge the rows at the merge base did not
    /// is refused, though no manifest has the edge, and so is one that leaves the refusal no
    /// list may waive; recorded at the merge base, the move is accepted.
    #[test]
    fn a_crate_that_changes_rows_where_that_admits_more_is_refused() {
        let here = repathed(&[("protocol", &["core/wire", "core/common", "core/fs"])]);
        let r = judged_rows(&here, &[], &base_at(rows(), vec![]));
        assert_eq!(r.len(), 1, "{r:?}");
        assert!(r[0].starts_with(&format!("kotton-fs (core/fs) is in row `protocol`, and {AT} it is in row `system`")), "{}", r[0]);
        assert!(r[0].contains("kotton-relay -> kotton-fs is admitted, and was not"), "{}", r[0]);
        let w = Widening::Moves { krate: "kotton-fs".into(), from: "system".into(), to: "protocol".into() };
        assert_eq!(judged_rows(&here, &[], &base_at(rows(), vec![w])), Vec::<String>::new());

        let here = repathed(&[("cli", &["client/cli"]), ("relay", &["infra/relay", "client/shell"])]);
        let r = judged_rows(&here, &[], &base_at(rows(), vec![]));
        assert_eq!(r.len(), 1, "{r:?}");
        assert!(r[0].contains("kotton-fs -> kotton-shell leaves the refusal no list may waive"), "{}", r[0]);
    }

    /// A root added to `not_rows` is refused, and accepted where the merge base records it.
    #[test]
    fn a_root_added_to_not_rows_is_refused() {
        let mut here = rows();
        here.not_rows.push("docs".into());
        let r = judged_rows(&here, &[], &base_at(rows(), vec![]));
        assert_eq!(r.len(), 1, "{r:?}");
        assert!(r[0].starts_with(&format!("`not_rows` names `docs`, and {AT} it does not")), "{}", r[0]);
        let w = Widening::NotRow { root: "docs".into() };
        assert_eq!(judged_rows(&here, &[], &base_at(rows(), vec![w])), Vec::<String>::new());
    }

    /// A row marked `acting` or `asking` at the merge base keeps its mark; one marked `neither`
    /// may take either.
    #[test]
    fn a_mark_that_changes_from_acting_or_asking_is_refused() {
        for (row, mark) in [("cli", Mark::Neither), ("system", Mark::Neither)] {
            let mut here = rows();
            row_mut(&mut here, row).mark = mark;
            if row == "system" {
                // An acting row may link only acting rows.
                row_mut(&mut here, "protocol").mark = Mark::Acting;
            }
            let r = judge_rows(&here, &[], &base_at(rows(), vec![]), &[], &BTreeSet::new(), &at(OWED));
            assert_eq!(r.len(), 1, "{row}: {r:?}");
            assert!(r[0].starts_with(&format!("row `{row}` is marked `neither`, and {AT} row `{row}` is marked")), "{}", r[0]);
            let w = Widening::Mark { row: row.into(), mark };
            assert_eq!(judge_rows(&here, &[], &base_at(rows(), vec![w]), &[], &BTreeSet::new(), &at(OWED)), Vec::<String>::new());
        }
        let mut here = rows();
        row_mut(&mut here, "relay").mark = Mark::Acting;
        held_together(&here).unwrap();
        assert_eq!(judge_rows(&here, &[], &base_at(rows(), vec![]), &[], &BTreeSet::new(), &at(OWED)), Vec::<String>::new());
    }

    /// A row renamed, with every `may_link` that names it, widens nothing.
    #[test]
    fn a_renamed_row_is_no_widening() {
        let mut here = renamed("protocol", "proto");
        for r in &mut here.rows {
            for l in &mut r.may_link {
                if l == "protocol" {
                    *l = "proto".into();
                }
            }
        }
        assert_eq!(judged_rows(&here, &[], &base_at(rows(), vec![])), Vec::<String>::new());
    }

    /// Rows that cannot be read at the merge base are refused rather than read as no change, and
    /// the refusal names the remedy.
    #[test]
    fn rows_the_merge_base_cannot_give_are_refused() {
        let mut here = rows();
        here.not_rows.push("docs".into());
        let r = judged_rows(&here, &[], &BaseRows::Unknown("no origin/main".into()));
        assert_eq!(r.len(), 1, "{r:?}");
        assert!(
            r[0].starts_with("the rows cannot be compared with the merge base")
                && r[0].ends_with("no origin/main. Fetch, and merge origin/main into the branch, so the merge base is main's tip"),
            "{r:?}"
        );
    }

    /// The widenings file: each entry one of five shapes with a `why`, and each held to name a
    /// widening this tree has not made, of rows and crates it has, that can be made.
    #[test]
    fn the_widenings_are_read_and_held_pending() {
        let text = "[[widen]]\nrow = \"cli\"\ngains = \"relay\"\nwhy = \"a\"\n\
                    [[widen]]\ncrate = \"kotton-fs\"\nfrom = \"system\"\nto = \"protocol\"\nwhy = \"b\"\n\
                    [[widen]]\nrow = \"cli\"\nmark = \"neither\"\nwhy = \"c\"\n\
                    [[widen]]\nnot_row = \"docs\"\nwhy = \"d\"\n\
                    [[widen]]\nrow = \"wallet\"\nwhy = \"e\"\n";
        let w = parse_widenings(text).unwrap();
        assert_eq!(
            w,
            vec![
                Widening::MayLink { row: "cli".into(), gains: "relay".into() },
                Widening::Moves { krate: "kotton-fs".into(), from: "system".into(), to: "protocol".into() },
                Widening::Mark { row: "cli".into(), mark: Mark::Neither },
                Widening::NotRow { root: "docs".into() },
                Widening::Arrives { row: "wallet".into() },
            ]
        );
        assert!(parse_widenings("[[widen]]\nrow = \"wallet\"\n").unwrap_err().contains("has no `why`"));
        assert_eq!(judged_rows(&rows(), &w, &base_at(rows(), vec![])), Vec::<String>::new());
        assert!(parse_widenings("[[widen]]\nnot_row = \"docs\"\n").unwrap_err().contains("has no `why`"));
        assert!(parse_widenings("[[widen]]\nnot_row = \"docs\"\nrow = \"cli\"\nwhy = \"x\"\n").unwrap_err().contains("a widening is"));

        for (entry, says) in [
            (Widening::MayLink { row: "cli".into(), gains: "protocol".into() }, "which this tree has made"),
            (Widening::MayLink { row: "cli".into(), gains: "nowhere".into() }, "`nowhere` is no row"),
            (Widening::Moves { krate: "kotton-fs".into(), from: "relay".into(), to: "protocol".into() }, "kotton-fs is in row `system`, not `relay`"),
            (Widening::Moves { krate: "kotton-fs".into(), from: "protocol".into(), to: "system".into() }, "which this tree has made"),
            (Widening::Moves { krate: "kotton-none".into(), from: "system".into(), to: "protocol".into() }, "`kotton-none` is no crate"),
            (Widening::Mark { row: "cli".into(), mark: Mark::Asking }, "which this tree has made"),
            (Widening::NotRow { root: "tools".into() }, "which this tree has made"),
            (Widening::Arrives { row: "cli".into() }, "which this tree has made"),
            (
                Widening::MayLink { row: "vault".into(), gains: "relay".into() },
                "row `vault` is marked `acting` and row `relay` `neither`: an acting row may link only acting rows, so it cannot be made",
            ),
            (
                Widening::MayLink { row: "system".into(), gains: "cli".into() },
                "row `system` is marked `acting` and row `cli` `asking`: an acting row may link only acting rows, so it cannot be made",
            ),
        ] {
            let r = judged_rows(&rows(), std::slice::from_ref(&entry), &base_at(rows(), vec![]));
            assert_eq!(r.len(), 1, "{entry}: {r:?}");
            assert!(r[0].contains(says), "{entry}: {}", r[0]);
        }
        // An acting row's gain recorded with the row it names becoming acting can be made.
        let both = [
            Widening::MayLink { row: "vault".into(), gains: "relay".into() },
            Widening::Mark { row: "relay".into(), mark: Mark::Acting },
        ];
        assert_eq!(judged_rows(&rows(), &both, &base_at(rows(), vec![])), Vec::<String>::new());
    }

    /// A row that arrives, matched with no row at the merge base, is refused; recorded at the
    /// merge base it is accepted, and the record, kept here, is refused as made. A row renamed
    /// whose paths change with its name arrives.
    #[test]
    fn a_row_that_arrives_is_refused() {
        let mut here = rows();
        here.rows.push(Row {
            name: "wallet".into(),
            becomes: "becomes nothing".into(),
            mark: Mark::Asking,
            paths: vec!["client/wallet".into()],
            may_link: vec!["protocol".into(), "wallet".into()],
        });
        let w = Widening::Arrives { row: "wallet".into() };
        let r = judged_rows(&here, &[], &base_at(rows(), vec![]));
        assert_eq!(r.len(), 1, "{r:?}");
        assert!(
            r[0].starts_with(&format!(
                "row `wallet` arrives: {AT} no row has its name, and none whose name is gone has its paths. A row arrives only as a widening. A widening lands only where xtask/tier-widenings.toml {AT} records it: record `row = \"wallet\"` there"
            )),
            "{}",
            r[0]
        );
        assert_eq!(judged_rows(&here, &[], &base_at(rows(), vec![w.clone()])), Vec::<String>::new());
        let r = judged_rows(&here, std::slice::from_ref(&w), &base_at(rows(), vec![w.clone()]));
        assert_eq!(r.len(), 1, "{r:?}");
        assert!(r[0].contains("which this tree has made"), "{r:?}");
        // Recorded and not yet made: pending.
        assert_eq!(judged_rows(&rows(), std::slice::from_ref(&w), &base_at(rows(), vec![])), Vec::<String>::new());

        let mut here = renamed("vault", "keep");
        let keep = row_mut(&mut here, "keep");
        keep.may_link = vec!["protocol".into(), "keep".into()];
        keep.paths.push("core/keep".into());
        let r = judged_rows(&here, &[], &base_at(rows(), vec![]));
        assert_eq!(r.len(), 1, "{r:?}");
        assert!(r[0].starts_with("row `keep` arrives"), "{}", r[0]);
        let w = Widening::Arrives { row: "keep".into() };
        assert_eq!(judged_rows(&here, &[], &base_at(rows(), vec![w])), Vec::<String>::new());
    }

    /// The rows at the merge base are read from git objects: the rows file and the widenings
    /// there. A merge base with no rows file is refused, naming the remedy, whatever else it
    /// holds, and so is one whose rows file cannot be read.
    #[test]
    fn the_rows_at_the_merge_base_are_read_from_git() {
        let r = crate::git_fixture::Repo::new();
        let land = |message: &str| {
            let c = r.commit(message);
            r.git(&["update-ref", "refs/remotes/origin/main", &c]);
            c
        };
        r.write("README", "x\n");
        r.write(OWED_FILE, OWED);
        let c = land("first");
        let base = base_rows(r.path());
        assert_eq!(base, BaseRows::Unknown(format!("{} has no xtask/tier-rows.toml", short(&c))));
        let refused = judged_rows(&rows(), &[], &base);
        assert_eq!(
            refused,
            vec![format!(
                "the rows cannot be compared with the merge base with origin/main, so whether they \
                 widened cannot be judged: {} has no xtask/tier-rows.toml. Fetch, and merge \
                 origin/main into the branch, so the merge base is main's tip",
                short(&c)
            )]
        );

        r.write(ROWS_FILE, &ROWS.replacen("paths =", "path =", 1));
        land("a rows file that cannot be read");
        assert!(matches!(base_rows(r.path()), BaseRows::Unknown(e) if e.contains("has `path`")), "{:?}", base_rows(r.path()));

        r.write(ROWS_FILE, ROWS);
        let c = land("the rows file");
        assert_eq!(base_rows(r.path()), BaseRows::At { commit: c, rows: rows(), widenings: vec![] });

        r.write(WIDENINGS_FILE, "[[widen]]\nnot_row = \"docs\"\nwhy = \"x\"\n");
        let c = land("a widening");
        r.write(WIDENINGS_FILE, "");
        r.commit("consumed on a branch");
        assert_eq!(
            base_rows(r.path()),
            BaseRows::At { commit: c, rows: rows(), widenings: vec![Widening::NotRow { root: "docs".into() }] }
        );
    }

    #[test]
    fn a_directory_is_in_the_row_of_its_longest_path() {
        let rows = rows();
        let row_of = |d: &str| rows.row_of(d).map(|r| r.name.clone());
        assert_eq!(row_of("core/wire").as_deref(), Some("protocol"));
        assert_eq!(row_of("core/kvaultd").as_deref(), Some("vault"));
        assert_eq!(row_of("core/crypto").as_deref(), Some("system"));
        assert_eq!(row_of("core/wirex").as_deref(), Some("system"));
        assert_eq!(row_of("client/shell").as_deref(), Some("cli"));
        assert!(row_of("client/elsewhere").is_none());
        assert!(row_of("tools/workspace-hack").is_none());
    }

    /// Every `may_link` names a row, and no row may link a row it never links.
    #[test]
    fn what_a_row_may_link_is_rows_it_does_not_never_link() {
        let rows = rows();
        for row in &rows.rows {
            for l in &row.may_link {
                let to = rows.named(l).unwrap_or_else(|| panic!("`{}` names `{l}`, which is not a row", row.name));
                assert!(!never(row, to), "`{}` may link `{l}`, which it never links", row.name);
            }
        }
    }

    /// The tree as it is passes, every crate under the rows' roots is in a row, every list in
    /// the file names an edge a manifest has, and every widening recorded is one not yet made.
    /// The merge base is not read here: the files are compared with themselves.
    #[test]
    fn the_tree_as_it_is_is_in_the_rows() {
        let root = crate::out::root();
        let rows = live_rows();
        let tree = read_tree(&root, &rows, &tracked_manifests(&root, &rows));
        assert!(tree.refused.is_empty(), "{:?}", tree.refused);
        let owed = parse_owed(&std::fs::read_to_string(root.join(OWED_FILE)).unwrap()).unwrap();
        let base = Base::At { commit: String::new(), owed: owed.clone() };
        let j = judge(&rows, &tree.crates, &tree.edges, &owed, &base);
        assert!(j.refused.is_empty(), "{:?}", j.refused);
        let widenings = parse_widenings(&std::fs::read_to_string(root.join(WIDENINGS_FILE)).unwrap()).unwrap();
        let base_r = BaseRows::At { commit: String::new(), rows: rows.clone(), widenings: vec![] };
        let none = judge_rows(&rows, &widenings, &base_r, &tree.crates, &tree.edges, &base);
        assert!(none.is_empty(), "{none:?}");
    }

    /// The tests run over rows of their own, so an edit of [`ROWS_FILE`] that the gate accepts
    /// needs no edit of this source: no line of it holds what a row of that file `becomes`,
    /// which a copy of the file, or a test pinned to it, would.
    #[test]
    fn an_edit_of_the_rows_file_needs_no_edit_of_this_source() {
        let source = include_str!("tier_check.rs");
        for row in &live_rows().rows {
            let becomes = format!("\"{}\"", row.becomes);
            assert!(
                !source.contains(&becomes),
                "this source holds {becomes}, what row `{}` becomes in {ROWS_FILE}: a test that \
                 needs rows runs over [`ROWS`], not over that file",
                row.name
            );
        }
    }
}
