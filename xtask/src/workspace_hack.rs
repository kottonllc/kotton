// SPDX-License-Identifier: AGPL-3.0-or-later
//! `workspace-hack` / `workspace-hack-check`: one feature set for every test build.
//!
//! ## Why this exists
//!
//! Cargo unifies features over the packages a command *selects*. `cargo test -p kotton-store`
//! and `cargo test -p kuserd` therefore compile `url`, `sqlx-core` and `tokio` with different
//! features, under different hashes — and so every crate above them, `kuserd` included, again.
//! Measured 2026-09-22 on one checkout with one agent: `target/debug/deps` at 13 GB, `liburl`
//! eleven times, `kuserd` seven, because every gate the loop runs selects differently
//! (`TASK-every-package-selection-rebuilds-the-shared-crates-under-a-different-feature-set`).
//! Nothing was stale. Each copy was the correct build of its selection, which is why pruning
//! them only bought a night.
//!
//! ## The shape
//!
//! `tools/workspace-hack` is a crate with no code whose dependencies name every package that
//! would otherwise resolve differently under different selections, with the union of the
//! features the whole workspace turns on. Every workspace member **dev**-depends on it. Any
//! test build selects at least one member, that member's dev-dependencies are active, and so
//! every test build — any `-p`, `clippy --all-targets`, the integration suite — resolves each
//! shared package to one feature set. That is `cargo hakari`'s shape with three differences,
//! each a property this repository holds that hakari's model would break:
//!
//! 1. **A dev-dependency, not a dependency.** hakari's hack is a normal dependency, so a test
//!    feature (`tokio/test-util`) and a member's test double (`kotton-secret/test-utils`,
//!    `kotton-ipc/test-utils`) would reach every shipped binary. `kinferd`'s dev-dependency
//!    comment says it: *"it is a dev-dependency so nothing that ships can reach it"*. A
//!    dev-dependency is never in a shipped build's graph, and `infer-check` and `vault-check`,
//!    which read `-e normal` closures as reach, see nothing new.
//! 2. **Members' own test features are in it.** hakari only unifies third-party packages. Here
//!    the variation that cost most was a member's: `kotton-store/test-support` on in some
//!    selections and off in others, which re-hashes everything above the store. A
//!    dev-dependency may form a cycle, so the hack can name members; a normal one could not.
//! 3. **The renderer stack is not in it.** `kuid-desktop` and `kuid-gpu` pull wgpu, vello and
//!    blitz; forcing those on every member would make `cargo test -p kotton-store` compile a
//!    GPU stack. A package only [`LEAVES`] reach is left to their own feature sets, and the
//!    generator prints the list. The features the renderer turns on in *shared* packages are
//!    in the union, so `cargo test -p kuid --features kuid-desktop` shares every crate it has
//!    in common with the rest of the loop.
//!
//! One more thing hakari does that is needed here too: cargo builds a host dependency with
//! the target profile's debuginfo when the same package is also a target dependency, so a
//! package's *side* differs by selection as well as its features. A package the workspace
//! uses on both sides is named on both.
//!
//! ## Keeping it true
//!
//! `cargo xtask workspace-hack` regenerates it from scratch — every member resolved alone on
//! Linux, Windows and macOS, iterated until nothing new varies — and adds the dev-dependency to
//! any member without one. `cargo xtask workspace-hack-check`, in `just lint`, holds the
//! property rather than the file: on this machine's platform, every member resolved alone must
//! give every shared package the features the whole workspace gives it. A dependency change
//! that breaks that fails lint and names the command that fixes it.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;

/// The crate's package name and where it lives.
pub const HACK: &str = "workspace-hack";
pub const HACK_DIR: &str = "tools/workspace-hack";

/// The platforms the generator unifies. A package that exists on one of them only is named
/// under that triple, so the hack never forces a Linux crate on a Windows build.
const PLATFORMS: &[&str] = &[
    "x86_64-unknown-linux-gnu",
    "x86_64-pc-windows-msvc",
    "aarch64-apple-darwin",
];

/// Members whose own closure is the renderer stack. A package only these reach is not
/// unified, so the GPU and layout crates are never forced on a member that does not draw.
pub const LEAVES: &[&str] = &["kuid", "kotton-css-support"];

/// The reference resolution: the whole workspace with every feature the loop's gates turn
/// on. `kuid-desktop` and `kuid-gpu` enable features in shared packages (`rustix`,
/// `hashbrown`, `num-traits`), and unless the union carries them, the kuid gate compiles its
/// own copy of everything above those.
const REF_FEATURES: &str = "kuid/kuid-desktop,kuid/kuid-gpu";

/// A package on one side of the build. `host` is a build script's or proc-macro's world.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Key {
    pub name: String,
    pub version: String,
    /// `Some(path)` for a path package (a workspace member), `None` for crates.io.
    pub path: Option<String>,
    pub host: bool,
}

impl Key {
    fn flipped(&self) -> Key {
        Key {
            host: !self.host,
            ..self.clone()
        }
    }
}

/// What one `cargo tree` resolved: each package-side and the feature sets it was built with.
pub type Resolution = BTreeMap<Key, BTreeSet<String>>;

/// Parse `cargo tree --charset ascii -e normal,build,dev -f '{p} [{f}]'`.
///
/// Side is read from the tree's shape: anything under a `[build-dependencies]` marker, and
/// anything under a proc-macro, is host. A `(*)` line repeats a node already printed and is
/// the same package-side, so it is recorded again harmlessly.
pub fn parse_tree(out: &str) -> Result<Resolution, String> {
    let mut res = Resolution::new();
    // (depth, host) of the path from the root to the current line.
    let mut stack: Vec<(usize, bool)> = Vec::new();
    // child depth -> whether the section marker above it is `[build-dependencies]`
    let mut section: BTreeMap<usize, bool> = BTreeMap::new();
    for raw in out.lines() {
        let body_at = raw
            .char_indices()
            .find(|(_, c)| !matches!(c, '|' | '`' | '-' | ' '))
            .map(|(i, _)| i);
        let Some(body_at) = body_at else { continue };
        let depth = raw[..body_at].chars().count() / 4;
        let body = raw[body_at..].trim_end();
        if body.starts_with('[') && body.ends_with(']') {
            section.insert(depth + 1, body == "[build-dependencies]");
            continue;
        }
        section.retain(|d, _| *d <= depth);
        while stack.last().is_some_and(|(d, _)| *d >= depth) {
            stack.pop();
        }
        let body = body.strip_suffix(" (*)").unwrap_or(body);
        let Some(open) = body.rfind(" [") else {
            return Err(format!("unparsed cargo tree line: {raw}"));
        };
        let feats = body[open + 2..].trim_end_matches(']').to_string();
        let mut head = &body[..open];
        let proc_macro = head.ends_with(" (proc-macro)");
        if proc_macro {
            head = &head[..head.len() - " (proc-macro)".len()];
        }
        let (name_ver, source) = match head.find(" (") {
            Some(i) => (&head[..i], Some(head[i + 2..].trim_end_matches(')'))),
            None => (head, None),
        };
        let Some((name, ver)) = name_ver.split_once(" v") else {
            return Err(format!("unparsed cargo tree line: {raw}"));
        };
        if let Some(src) = source {
            if src.contains("://") {
                return Err(format!(
                    "`{name}` comes from `{src}`; only crates.io and path packages can be named \
                     in the workspace-hack"
                ));
            }
        }
        let parent_host = stack.last().is_some_and(|(_, h)| *h);
        let host = parent_host || proc_macro || section.get(&depth).copied().unwrap_or(false);
        let key = Key {
            name: name.to_string(),
            version: ver.to_string(),
            path: source.map(|s| s.replace('\\', "/")),
            host,
        };
        res.entry(key).or_default().insert(feats);
        stack.push((depth, host));
    }
    Ok(res)
}

fn cargo_tree(select: &[&str], target: Option<&str>) -> Result<Resolution, String> {
    let mut cmd = Command::new("cargo");
    cmd.args([
        "tree",
        "--charset",
        "ascii",
        "-e",
        "normal,build,dev",
        "-f",
        "{p} [{f}]",
    ])
    .args(select);
    if let Some(t) = target {
        cmd.args(["--target", t]);
    }
    let out = cmd
        .output()
        .map_err(|e| format!("could not run cargo tree: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "`cargo tree {}` failed:\n{}",
            select.join(" "),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    parse_tree(&String::from_utf8_lossy(&out.stdout))
}

/// A workspace member: its package name and its directory relative to the repository root.
#[derive(Clone, Debug)]
pub struct Member {
    pub name: String,
    pub dir: String,
}

/// Every member, read from the root manifest's `members` list and each member's `[package]`.
pub fn members(root: &Path) -> Result<Vec<Member>, String> {
    let ws = fs::read_to_string(root.join("Cargo.toml")).map_err(|e| format!("Cargo.toml: {e}"))?;
    let start = ws
        .find("members = [")
        .ok_or("no `members = [` in Cargo.toml")?;
    let block = &ws[start..];
    let block = &block[..block.find(']').ok_or("unterminated members list")?];
    let mut out = Vec::new();
    for line in block.lines() {
        let t = line.trim();
        let Some(rest) = t.strip_prefix('"') else {
            continue;
        };
        let Some(dir) = rest.split('"').next() else {
            continue;
        };
        let manifest = root.join(dir).join("Cargo.toml");
        let text =
            fs::read_to_string(&manifest).map_err(|e| format!("{}: {e}", manifest.display()))?;
        let name = package_name(&text).ok_or_else(|| format!("{dir}: no [package] name"))?;
        out.push(Member {
            name,
            dir: dir.to_string(),
        });
    }
    Ok(out)
}

fn package_name(manifest: &str) -> Option<String> {
    let mut in_package = false;
    for line in manifest.lines() {
        // A manifest saved on Windows may open with a byte-order mark.
        let t = line.trim().trim_start_matches('\u{feff}');
        if t.starts_with('[') {
            in_package = t == "[package]";
            continue;
        }
        if in_package {
            if let Some(v) = t.strip_prefix("name") {
                let v = v.trim_start();
                if let Some(v) = v.strip_prefix('=') {
                    return Some(v.trim().trim_matches('"').to_string());
                }
            }
        }
    }
    None
}

/// `../..` from a member directory to the repository root, then the hack.
fn hack_path_from(dir: &str) -> String {
    let up = dir.split('/').filter(|s| !s.is_empty()).count();
    let mut p = "../".repeat(up);
    p.push_str(HACK_DIR);
    p
}

/// Whether a manifest dev-depends on the hack, in its plain `[dev-dependencies]` table.
pub fn has_dev_dep(manifest: &str) -> bool {
    let mut in_dev = false;
    for line in manifest.lines() {
        // A manifest saved on Windows may open with a byte-order mark.
        let t = line.trim().trim_start_matches('\u{feff}');
        if t.starts_with('[') {
            in_dev = t == "[dev-dependencies]";
            continue;
        }
        if in_dev && (t.starts_with(&format!("{HACK} ")) || t.starts_with(&format!("{HACK}="))) {
            return true;
        }
    }
    false
}

/// Add the dev-dependency line to a manifest that lacks it; `None` if it already has it.
pub fn with_dev_dep(manifest: &str, dir: &str) -> Option<String> {
    if has_dev_dep(manifest) {
        return None;
    }
    let line = format!("{HACK} = {{ path = \"{}\" }}", hack_path_from(dir));
    let mut out = String::new();
    let mut done = false;
    for l in manifest.lines() {
        out.push_str(l);
        out.push('\n');
        if !done && l.trim() == "[dev-dependencies]" {
            out.push_str(&line);
            out.push('\n');
            done = true;
        }
    }
    if !done {
        let trimmed = out.trim_end().to_string();
        out = format!("{trimmed}\n\n[dev-dependencies]\n{line}\n");
    }
    Some(out)
}

/// Resolve every member alone, and the whole workspace, on one platform.
fn resolve_all(
    members: &[Member],
    target: Option<&str>,
) -> Result<(Resolution, Vec<(String, Resolution)>), String> {
    let reference = cargo_tree(&["--workspace", "--features", REF_FEATURES], target)?;
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(2, 8);
    let todo: Vec<&Member> = members.iter().filter(|m| m.name != HACK).collect();
    let mut per: Vec<(String, Resolution)> = Vec::new();
    for chunk in todo.chunks(threads) {
        let results: Vec<Result<(String, Resolution), String>> = std::thread::scope(|s| {
            let handles: Vec<_> = chunk
                .iter()
                .map(|m| {
                    s.spawn(move || {
                        cargo_tree(&["-p", &m.name], target).map(|r| (m.name.clone(), r))
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| {
                    h.join()
                        .unwrap_or_else(|_| Err("cargo tree thread panicked".into()))
                })
                .collect()
        });
        for r in results {
            per.push(r?);
        }
    }
    Ok((reference, per))
}

/// Package-sides only [`LEAVES`] reach: the renderer stack, left to its own feature sets.
fn leaf_only(per: &[(String, Resolution)]) -> BTreeSet<Key> {
    let mut owners: BTreeMap<&Key, BTreeSet<&str>> = BTreeMap::new();
    for (m, r) in per {
        for k in r.keys() {
            owners.entry(k).or_default().insert(m.as_str());
        }
    }
    owners
        .into_iter()
        .filter(|(_, o)| o.iter().all(|m| LEAVES.contains(m)))
        .map(|(k, _)| k.clone())
        .collect()
}

/// One way a member's own resolution differs from the workspace's.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Divergence {
    pub member: String,
    /// The package-side to name in the hack.
    pub key: Key,
    pub why: String,
}

/// Every package-side a member resolves differently from the whole workspace — the list the
/// generator adds and the check refuses.
pub fn divergences(
    reference: &Resolution,
    per: &[(String, Resolution)],
    leaf_only: &BTreeSet<Key>,
) -> Vec<Divergence> {
    let skip =
        |k: &Key| k.name == HACK || LEAVES.contains(&k.name.as_str()) || leaf_only.contains(k);
    let mut out = Vec::new();
    for (m, r) in per {
        for (k, fs) in r {
            if skip(k) {
                continue;
            }
            if reference.get(k) != Some(fs) {
                out.push(Divergence {
                    member: m.clone(),
                    key: k.clone(),
                    why: format!(
                        "features [{}], where the workspace has [{}]",
                        join(fs),
                        reference.get(k).map(join).unwrap_or_default()
                    ),
                });
            }
            // Cargo builds a host dependency with the target profile's debuginfo when the
            // same package is also a target dependency, so which side a package sits on
            // changes its hash as surely as a feature does.
            let flip = k.flipped();
            if reference.contains_key(&flip) && !r.contains_key(&flip) && !skip(&flip) {
                for key in [k.clone(), flip] {
                    out.push(Divergence {
                        member: m.clone(),
                        key,
                        why: format!(
                            "this build has it only on the {} side; the workspace has it as a \
                             build dependency and in the code",
                            if k.host { "host" } else { "target" }
                        ),
                    });
                }
            }
        }
    }
    out.sort();
    out
}

fn join(s: &BTreeSet<String>) -> String {
    s.iter().cloned().collect::<Vec<_>>().join(" | ")
}

/// What the hack names: per (section, platform) → key → features.
type Entries = BTreeMap<(bool, Option<&'static str>), BTreeMap<Key, String>>;

/// Render the hack's manifest. Deterministic, so a regeneration that finds nothing new
/// writes the same bytes.
pub fn render(
    entries: &BTreeMap<Key, BTreeMap<&'static str, String>>,
    members: &[Member],
) -> String {
    // A package named twice (two versions) is keyed by version everywhere, so no two tables
    // call one crate by different names.
    let mut versions: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for k in entries.keys() {
        versions.entry(&k.name).or_default().insert(&k.version);
    }
    let mut sections: Entries = BTreeMap::new();
    for (k, per_platform) in entries {
        let feats: BTreeSet<&String> = per_platform.values().collect();
        if per_platform.len() == PLATFORMS.len() && feats.len() == 1 {
            sections
                .entry((k.host, None))
                .or_default()
                .insert(k.clone(), per_platform[PLATFORMS[0]].clone());
        } else {
            for (t, f) in per_platform {
                sections
                    .entry((k.host, Some(t)))
                    .or_default()
                    .insert(k.clone(), f.clone());
            }
        }
    }
    let dir_of: BTreeMap<&str, &str> = members
        .iter()
        .map(|m| (m.name.as_str(), m.dir.as_str()))
        .collect();
    let mut out = HEADER.replace("{license}", crate::license_check::boundary_license(HACK_DIR));
    for ((host, platform), deps) in &sections {
        let table = if *host {
            "build-dependencies"
        } else {
            "dependencies"
        };
        match platform {
            None => out.push_str(&format!("\n[{table}]\n")),
            Some(t) => out.push_str(&format!("\n[target.{t}.{table}]\n")),
        }
        for (k, feats) in deps {
            let versioned = versions.get(k.name.as_str()).is_some_and(|v| v.len() > 1);
            let dep_key = if versioned {
                format!("{}-v{}", k.name, k.version.replace(['.', '+'], "_"))
            } else {
                k.name.clone()
            };
            let list: Vec<String> = feats
                .split(',')
                .filter(|f| !f.is_empty())
                .map(|f| format!("\"{f}\""))
                .collect();
            let source = match &k.path {
                Some(_) => format!(
                    "path = \"../../{}\"",
                    dir_of.get(k.name.as_str()).copied().unwrap_or("?")
                ),
                None => format!("version = \"{}\"", k.version),
            };
            let package = if versioned {
                format!("package = \"{}\", ", k.name)
            } else {
                String::new()
            };
            out.push_str(&format!(
                "{dep_key} = {{ {package}{source}, default-features = false, features = [{}] }}\n",
                list.join(", ")
            ));
        }
    }
    out
}

const HEADER: &str = "\
# GENERATED by `cargo xtask workspace-hack` — do not edit; regenerate.
#
# One feature set for every test build. Every workspace member dev-depends on this crate,
# so any `cargo test -p …`, `cargo clippy --all-targets` or suite run resolves each package
# named here to the features the whole workspace turns on, and compiles it once rather
# than once per selection. Why a dev-dependency, why members' test features are here, and
# why the renderer stack is not: `xtask/src/workspace_hack.rs`.
# It is `exclude`d from the workspace on purpose: a member is a root of every build at the
# root, and its test features would reach shipped binaries.
# `cargo xtask workspace-hack-check` (in `just lint`) holds the property.

[package]
name = \"workspace-hack\"
version = \"0.1.0\"
edition = \"2021\"
license = \"{license}\"
publish = false
# A build script so that the `[build-dependencies]` below take part in resolution: that is
# how the host side of a build (build scripts, proc-macros) is unified too.
build = \"build.rs\"

[lib]
path = \"lib.rs\"
";

const LIB_RS: &str = "\
//! No code. This crate exists for its dependency list: see `Cargo.toml` beside it and
//! `xtask/src/workspace_hack.rs`.
";

const BUILD_RS: &str = "\
// Present so that the `[build-dependencies]` in `Cargo.toml` are resolved. It does nothing.
fn main() {}
";

/// `cargo xtask workspace-hack`: regenerate from scratch.
pub fn generate(root: &Path) {
    if let Err(e) = generate_inner(root) {
        eprintln!("workspace-hack: {e}");
        std::process::exit(1);
    }
}

fn generate_inner(root: &Path) -> Result<(), String> {
    let dir = root.join(HACK_DIR);
    fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    // Each opens with the SPDX line `license-check` will require of it, asked of the same
    // code that requires it — as the manifest's `license` line is, in `render` — so this
    // generator never keeps its own copy of the id.
    for (name, body) in [("lib.rs", LIB_RS), ("build.rs", BUILD_RS)] {
        let rel = format!("{HACK_DIR}/{name}");
        let id = crate::license_check::file_license(root, &rel)?;
        write(&dir.join(name), &format!("// SPDX-License-Identifier: {id}\n{body}"))?;
    }
    // From scratch: an entry that is no longer needed is only found by starting empty.
    write(&dir.join("Cargo.toml"), &render(&BTreeMap::new(), &[]))?;
    let members = members(root)?;
    if let Some(problem) = membership_problem(root) {
        return Err(problem);
    }
    let mut added = 0;
    for m in members.iter().filter(|m| m.name != HACK) {
        let p = root.join(&m.dir).join("Cargo.toml");
        let text = fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        if let Some(new) = with_dev_dep(&text, &m.dir) {
            write(&p, &new)?;
            added += 1;
        }
    }
    if added > 0 {
        println!("workspace-hack: added the dev-dependency to {added} member(s)");
    }

    let mut entries: BTreeMap<Key, BTreeMap<&'static str, String>> = BTreeMap::new();
    let mut leaves: BTreeMap<&'static str, BTreeSet<Key>> = BTreeMap::new();
    for round in 1..=8 {
        let mut new = 0;
        for t in PLATFORMS {
            let (reference, per) = resolve_all(&members, Some(t))?;
            let leaf = leaves.entry(t).or_insert_with(|| leaf_only(&per));
            for d in divergences(&reference, &per, leaf) {
                let feats = reference
                    .get(&d.key)
                    .ok_or("divergent key not in the workspace")?;
                if feats.len() != 1 {
                    return Err(format!(
                        "{} {} resolves to {} feature sets across the workspace on {t}",
                        d.key.name,
                        d.key.version,
                        feats.len()
                    ));
                }
                let f = feats.iter().next().cloned().unwrap_or_default();
                if entries.entry(d.key).or_default().insert(t, f).is_none() {
                    new += 1;
                }
            }
        }
        write(&dir.join("Cargo.toml"), &render(&entries, &members))?;
        println!("workspace-hack: round {round}, {new} new package-platform entries");
        if new == 0 {
            let leaf: BTreeSet<String> = leaves
                .values()
                .flatten()
                .map(|k| format!("{} {}", k.name, k.version))
                .collect();
            println!(
                "workspace-hack: {} package-sides named; {} renderer-only packages left to {} \
                 (see LEAVES).",
                entries.len(),
                leaf.len(),
                LEAVES.join(" and ")
            );
            return Ok(());
        }
    }
    Err("no fixpoint after 8 rounds; something enables features in a cycle".into())
}

fn write(p: &Path, text: &str) -> Result<(), String> {
    if fs::read_to_string(p).ok().as_deref() == Some(text) {
        return Ok(());
    }
    fs::write(p, text).map_err(|e| format!("{}: {e}", p.display()))
}

/// Strip `//` comments and whitespace — what a source file *does*.
fn code_of(src: &str) -> String {
    src.lines()
        .map(|l| l.split("//").next().unwrap_or(""))
        .collect::<String>()
        .split_whitespace()
        .collect()
}

/// The hack must be outside the workspace: listed under `exclude`, and never selected by a
/// build at the root.
///
/// This is the property the dev-dependency shape rests on. A workspace member is a root of
/// `cargo build --bin kuserd` — every Justfile build is written that way — so a hack that
/// was a member would switch its test features on in the binaries a person is handed, which
/// is exactly what hakari's shape does and this one exists not to. And a path dependency
/// inside the workspace directory *becomes* a member unless `exclude` names it; nested under
/// a member's directory, `exclude` cannot name it at all (cargo reads the member entry as a
/// prefix), which is why it lives in `tools/` and not beside the code that writes it.
fn membership_problem(root: &Path) -> Option<String> {
    let ws = fs::read_to_string(root.join("Cargo.toml")).unwrap_or_default();
    let excluded = ws
        .find("exclude = [")
        .map(|i| &ws[i..])
        .and_then(|b| b.find(']').map(|j| &b[..j]))
        .is_some_and(|b| b.contains(&format!("\"{HACK_DIR}\"")));
    if !excluded {
        return Some(format!(
            "`{HACK_DIR}` is not in the workspace's `exclude`, so cargo makes it a member and a \
             root build switches its test features on in shipped binaries"
        ));
    }
    let out = Command::new("cargo")
        .args([
            "tree",
            "--workspace",
            "-e",
            "normal",
            "--depth",
            "0",
            "--prefix",
            "none",
            "-f",
            "{p}",
        ])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let roots = String::from_utf8_lossy(&o.stdout);
            roots
                .lines()
                .any(|l| l.starts_with(&format!("{HACK} ")))
                .then(|| format!("`{HACK}` is a root of `cargo build --workspace`; it must not be"))
        }
        Ok(o) => Some(format!(
            "`cargo tree --workspace` failed: {}",
            String::from_utf8_lossy(&o.stderr)
        )),
        Err(e) => Some(format!("could not run cargo tree: {e}")),
    }
}

fn host_triple() -> Result<String, String> {
    let out = Command::new("rustc")
        .arg("-vV")
        .output()
        .map_err(|e| format!("could not run rustc: {e}"))?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("host: "))
        .map(|h| h.trim().to_string())
        .ok_or_else(|| "`rustc -vV` printed no host triple".to_string())
}

/// `cargo xtask workspace-hack-check`.
pub fn check(root: &Path) {
    let mut problems: Vec<String> = Vec::new();
    let members = match members(root) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("workspace-hack-check: {e}");
            std::process::exit(1);
        }
    };
    if let Some(problem) = membership_problem(root) {
        problems.push(problem);
    }
    for m in members.iter().filter(|m| m.name != HACK) {
        let text = fs::read_to_string(root.join(&m.dir).join("Cargo.toml")).unwrap_or_default();
        if !has_dev_dep(&text) {
            problems.push(format!(
                "{} does not dev-depend on {HACK}, so `cargo test -p {}` resolves on its own",
                m.dir, m.name
            ));
        }
    }
    // It holds no code, so nothing can reach anything through it.
    let dir = root.join(HACK_DIR);
    if !code_of(&fs::read_to_string(dir.join("lib.rs")).unwrap_or_default()).is_empty() {
        problems.push(format!("{HACK_DIR}/lib.rs has code; it must hold none"));
    }
    if code_of(&fs::read_to_string(dir.join("build.rs")).unwrap_or_default()) != "fnmain(){}" {
        problems.push(format!(
            "{HACK_DIR}/build.rs must be `fn main() {{}}` and nothing else"
        ));
    }

    // The host triple named explicitly: without `--target`, `cargo tree` shows a package used
    // by a build script and by the code as one node, and the side it prints it under depends
    // on which path it met first.
    let host = match host_triple() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("workspace-hack-check: {e}");
            std::process::exit(1);
        }
    };
    let (reference, per) = match resolve_all(&members, Some(host.as_str())) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("workspace-hack-check: {e}");
            std::process::exit(1);
        }
    };
    let leaf = leaf_only(&per);
    let found = divergences(&reference, &per, &leaf);
    let shared: BTreeSet<&Key> = per
        .iter()
        .flat_map(|(_, r)| r.keys())
        .filter(|k| !leaf.contains(k) && k.name != HACK)
        .collect();
    for d in found.iter().take(20) {
        problems.push(format!(
            "`cargo test -p {}` resolves {} {} ({}) differently: {}",
            d.member,
            d.key.name,
            d.key.version,
            if d.key.host { "host" } else { "target" },
            d.why
        ));
    }
    if found.len() > 20 {
        problems.push(format!("… and {} more", found.len() - 20));
    }

    if problems.is_empty() {
        println!(
            "workspace-hack-check: OK — {} members, each resolved alone, give all {} shared \
             package-sides the workspace's features: one build of each for every test \
             selection. {} renderer-only package-sides are left to {}.",
            per.len(),
            shared.len(),
            leaf.len(),
            LEAVES.join(" and ")
        );
        return;
    }
    eprintln!("workspace-hack-check: {} problem(s):", problems.len());
    for p in &problems {
        eprintln!("  x {p}");
    }
    eprintln!(
        "\nA test selection that resolves a shared package differently compiles it — and \
         everything above it — again, under a new hash. Regenerate with \
         `cargo xtask workspace-hack` and commit what it writes."
    );
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    const TREE: &str = "\
kotton-store v0.1.0 (/r/core/store) []
|-- aes-kw v0.2.1 []
|   `-- cipher v0.4.4 [zeroize]
|       |-- generic-array v0.14.7 [more_lengths]
|       |   `-- typenum v1.20.1 [const-generics]
|       |   [build-dependencies]
|       |   `-- version_check v0.9.5 []
|       `-- zeroize v1.9.0 [alloc,default,derive,zeroize_derive]
|           `-- zeroize_derive v1.5.0 (proc-macro) []
|               `-- syn v2.0.119 [full]
|                   `-- unicode-ident v1.0.24 []
|-- unicode-ident v1.0.24 []
[dev-dependencies]
`-- tempfile v3.27.0 [default]
    `-- generic-array v0.14.7 [more_lengths] (*)
";

    fn key(name: &str, host: bool) -> Key {
        let r = parse_tree(TREE).unwrap();
        r.keys()
            .find(|k| k.name == name && k.host == host)
            .cloned()
            .unwrap()
    }

    #[test]
    fn a_build_dependency_and_everything_under_a_proc_macro_is_host() {
        let r = parse_tree(TREE).unwrap();
        let host: BTreeSet<&str> = r
            .keys()
            .filter(|k| k.host)
            .map(|k| k.name.as_str())
            .collect();
        assert_eq!(
            host,
            ["syn", "unicode-ident", "version_check", "zeroize_derive"]
                .into_iter()
                .collect()
        );
        // The marker covers the children after it and nothing that follows at its own level.
        assert!(!key("zeroize", false).host);
        // The same package on both sides is two keys.
        assert!(r.contains_key(&key("unicode-ident", false)));
        assert!(r.contains_key(&key("unicode-ident", true)));
    }

    #[test]
    fn a_path_package_carries_its_path_and_features_are_read_exactly() {
        let r = parse_tree(TREE).unwrap();
        let store = key("kotton-store", false);
        assert_eq!(store.path.as_deref(), Some("/r/core/store"));
        assert_eq!(
            r[&key("zeroize", false)],
            ["alloc,default,derive,zeroize_derive".to_string()].into()
        );
        assert!(key("tempfile", false).path.is_none());
    }

    #[test]
    fn a_member_that_builds_a_package_with_fewer_features_diverges() {
        let reference = parse_tree(TREE).unwrap();
        let narrower = parse_tree(&TREE.replace(
            "zeroize v1.9.0 [alloc,default,derive,zeroize_derive]",
            "zeroize v1.9.0 [alloc]",
        ))
        .unwrap();
        let d = divergences(&reference, &[("m".into(), narrower)], &BTreeSet::new());
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].key.name, "zeroize");
    }

    #[test]
    fn a_member_that_has_a_package_on_one_side_only_diverges_on_both() {
        // Cargo gives a host dependency the target's debuginfo when the package is on both
        // sides, so the side is part of the hash.
        let reference = parse_tree(TREE).unwrap();
        let one_side = parse_tree(&TREE.replace("|-- unicode-ident v1.0.24 []\n", "")).unwrap();
        let d = divergences(&reference, &[("m".into(), one_side)], &BTreeSet::new());
        let named: BTreeSet<(String, bool)> =
            d.iter().map(|d| (d.key.name.clone(), d.key.host)).collect();
        assert_eq!(
            named,
            [
                ("unicode-ident".to_string(), false),
                ("unicode-ident".to_string(), true)
            ]
            .into()
        );
    }

    #[test]
    fn the_renderer_stack_is_never_forced_on_other_members() {
        let reference = parse_tree(TREE).unwrap();
        let mut kuid = parse_tree(TREE).unwrap();
        let vello = Key {
            name: "vello_cpu".into(),
            version: "0.1.0".into(),
            path: None,
            host: false,
        };
        kuid.insert(vello.clone(), ["std".to_string()].into());
        let per = vec![
            ("kuid".to_string(), kuid),
            ("kotton-store".to_string(), reference.clone()),
        ];
        let leaf = leaf_only(&per);
        assert!(leaf.contains(&vello));
        let mut wider = reference.clone();
        wider.insert(vello, ["multithreading,std".to_string()].into());
        assert!(divergences(&wider, &per, &leaf).is_empty());
    }

    #[test]
    fn the_dev_dependency_goes_into_an_existing_table_or_a_new_one() {
        let with = with_dev_dep(
            "[package]\nname = \"a\"\n\n[dev-dependencies]\ntempfile = \"3\"\n",
            "core/store",
        )
        .unwrap();
        assert!(with.contains("[dev-dependencies]\nworkspace-hack = { path = \"../../tools/workspace-hack\" }\ntempfile"));
        assert!(has_dev_dep(&with));
        assert!(with_dev_dep(&with, "core/store").is_none());
        let without = with_dev_dep(
            "[package]\nname = \"a\"\n\n[lints]\nworkspace = true\n",
            "tests",
        )
        .unwrap();
        assert!(without.ends_with(
            "[dev-dependencies]\nworkspace-hack = { path = \"../tools/workspace-hack\" }\n"
        ));
        // A normal dependency on it is not what the check asks for.
        assert!(!has_dev_dep(
            "[dependencies]\nworkspace-hack = { path = \"x\" }\n"
        ));
    }

    #[test]
    fn two_versions_of_one_crate_are_keyed_by_version_in_every_table() {
        let k = |v: &str, host| Key {
            name: "hashbrown".into(),
            version: v.into(),
            path: None,
            host,
        };
        let mut e: BTreeMap<Key, BTreeMap<&'static str, String>> = BTreeMap::new();
        for t in PLATFORMS {
            e.entry(k("0.16.1", false))
                .or_default()
                .insert(t, "default".into());
        }
        e.entry(k("0.17.1", true))
            .or_default()
            .insert(PLATFORMS[0], "raw".into());
        let out = render(&e, &[]);
        assert!(out.contains("[dependencies]\nhashbrown-v0_16_1 = { package = \"hashbrown\", version = \"0.16.1\", default-features = false, features = [\"default\"] }"));
        assert!(out.contains("[target.x86_64-unknown-linux-gnu.build-dependencies]\nhashbrown-v0_17_1 = { package = \"hashbrown\", version = \"0.17.1\""));
    }

    #[test]
    fn the_hack_may_hold_no_code() {
        assert!(code_of(LIB_RS).is_empty());
        assert_eq!(code_of(BUILD_RS), "fnmain(){}");
        assert!(!code_of("pub use tokio::net;\n").is_empty());
    }
}
