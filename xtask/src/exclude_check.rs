// SPDX-License-Identifier: AGPL-3.0-or-later
//! `exclude-check`: every `[workspace] exclude` entry names a crate's directory in the tree.
//!
//! ## Why this exists
//!
//! Cargo reads an `exclude` entry as a path prefix: a manifest under it is kept out of the
//! workspace, and an entry under which there is no manifest keeps nothing out and is accepted
//! all the same. `cargo metadata` and `cargo check` exit 0 over an entry that names nothing,
//! so once the crate it excluded leaves the tree, the entry stays, and the list says the tree
//! holds a crate it does not. Nothing in cargo can say so; this does.
//!
//! ## What it holds
//!
//! For the root manifest, and every other manifest under [`crate::tree::CODE_ROOTS`] that
//! declares a `[workspace]` (found by the walk `tier-check` uses), each `exclude` entry is a
//! string that, resolved from that manifest's directory, names a directory inside the
//! repository that holds a `Cargo.toml` of its own, on disk and tracked by git. Refused, each
//! with the entry, the manifest and the remedy:
//!
//! - an entry that names nothing in the tree;
//! - an entry that names a file;
//! - an entry that names a directory with no `Cargo.toml` directly in it, even when a manifest
//!   lies further down: an entry names the crate it excludes, not a parent of it;
//! - an entry whose `Cargo.toml` git does not track, which a checkout of this tree would not
//!   hold;
//! - a glob: cargo takes globs in `members` only and reads an `exclude` entry as a plain path,
//!   so `crates/*` names a directory called `*`, which is no crate's;
//! - an absolute entry, or one that climbs out of the repository, whose meaning depends on
//!   where the checkout is;
//! - an entry that resolves to its own manifest's directory (`.`, or an empty string): a
//!   workspace does not exclude itself, so the entry names no excluded crate;
//! - an entry holding a backslash, which cargo on Unix reads as part of one path component,
//!   not as a separator, so it names a directory other than the one it seems to;
//! - an `exclude` that is not a list of strings, and a workspace manifest that cannot be read.
//!
//! The run itself is refused when git cannot list what it tracks: a check that cannot tell
//! does not report OK.

use std::collections::BTreeSet;
use std::path::Path;

use toml::Value;

use crate::tier_check::{declares_workspace, git, manifests_under, parse_manifest, resolve};

/// What [`check`] read and what it refused.
#[derive(Debug, Default)]
pub(crate) struct Report {
    /// Repo-relative path of each workspace manifest read, the root's first.
    pub(crate) manifests: Vec<String>,
    /// How many `exclude` entries those manifests hold.
    pub(crate) entries: usize,
    pub(crate) refused: Vec<String>,
}

/// `path` relative to `root`, with `/` between its parts whatever the platform.
fn rel(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

/// Every `Cargo.toml` git tracks in the checkout at `root`, repo-relative.
fn tracked(root: &Path) -> Result<BTreeSet<String>, String> {
    let listed = git(root, &["ls-files", "-z", "--cached"])?;
    Ok(listed
        .split('\0')
        .filter(|f| *f == "Cargo.toml" || f.ends_with("/Cargo.toml"))
        .map(str::to_string)
        .collect())
}

/// The workspace manifests under `root`: the root's own, then every manifest under a code
/// root that declares a `[workspace]`. A manifest under a code root that cannot be read is
/// refused here, not skipped.
fn workspace_manifests(root: &Path, refused: &mut Vec<String>) -> Vec<(String, toml::Table)> {
    let mut out = Vec::new();
    match parse_manifest(&root.join("Cargo.toml")) {
        Ok(m) if declares_workspace(&m) => out.push(("Cargo.toml".to_string(), m)),
        Ok(_) => refused.push(
            "Cargo.toml declares no [workspace]: exclude-check reads the workspace roots from \
             the repository's root manifest, and this one is not one. Run it from the \
             repository's root"
                .to_string(),
        ),
        Err(e) => refused.push(format!("{e}: exclude-check cannot read the root manifest")),
    }
    for r in crate::tree::CODE_ROOTS {
        for path in manifests_under(&root.join(r)) {
            let at = rel(root, &path);
            match parse_manifest(&path) {
                Ok(m) if declares_workspace(&m) => out.push((at, m)),
                Ok(_) => {}
                Err(e) => refused.push(format!(
                    "{e}: exclude-check cannot tell whether it declares a [workspace]"
                )),
            }
        }
    }
    out
}

/// Why the entry `entry` of the `exclude` in `at` (a manifest in repo-relative `dir`) names no
/// crate's directory, or `None` when it names one.
fn entry_refusal(root: &Path, tracked: &BTreeSet<String>, at: &str, dir: &str, entry: &str) -> Option<String> {
    let head = format!("{at}: [workspace] exclude names `{entry}`");
    if entry.contains(['*', '?', '[']) {
        return Some(format!(
            "{head}, a glob. Cargo takes globs in `members` only and reads an exclude entry as \
             a plain path, so this names no directory and excludes nothing. Name each excluded \
             crate's directory instead"
        ));
    }
    if entry.contains('\\') {
        return Some(format!(
            "{head}, which holds a backslash: cargo on Unix reads it as part of one path \
             component, not a separator, so the entry names a directory other than the one it \
             seems to. Write it with `/` between its parts"
        ));
    }
    let Some(target) = resolve(dir, entry) else {
        return Some(format!(
            "{head}, which is absolute or climbs out of the repository, so what it names \
             depends on where the checkout is. Name the excluded crate's directory relative to \
             {at}, inside the repository"
        ));
    };
    if target == dir {
        return Some(format!(
            "{head}, which resolves to {at}'s own directory: a workspace does not exclude \
             itself, so the entry names no excluded crate. Name the excluded crate's directory, \
             or delete the entry"
        ));
    }
    let on_disk = root.join(&target);
    let manifest = format!("{target}/Cargo.toml");
    if !on_disk.exists() {
        return Some(format!(
            "{head}, which names nothing in the tree: cargo accepts an exclude entry that names \
             nothing, so the list says the tree holds a crate it does not. Delete the entry, or \
             put back the crate it excludes"
        ));
    }
    if !on_disk.is_dir() {
        return Some(format!(
            "{head}, which is a file, not a directory: cargo excludes a crate by its directory. \
             Name the directory that holds the excluded crate's Cargo.toml, or delete the entry"
        ));
    }
    if !on_disk.join("Cargo.toml").is_file() {
        return Some(format!(
            "{head}, a directory that holds no Cargo.toml: an entry names the crate it \
             excludes. Name the directory that holds the excluded crate's Cargo.toml, or \
             delete the entry"
        ));
    }
    if !tracked.contains(&manifest) {
        return Some(format!(
            "{head}, whose {manifest} git does not track, so a checkout of this tree would not \
             hold the crate it excludes. Commit the crate, or delete the entry"
        ));
    }
    None
}

/// Every workspace manifest's `exclude` in the checkout at `root`, read and judged.
pub(crate) fn check(root: &Path) -> Report {
    let mut report = Report::default();
    let tracked = match tracked(root) {
        Ok(t) => t,
        Err(e) => {
            report.refused.push(format!(
                "{e}: exclude-check cannot tell which manifests the tree holds"
            ));
            return report;
        }
    };
    for (at, manifest) in workspace_manifests(root, &mut report.refused) {
        let dir = at.strip_suffix("Cargo.toml").unwrap_or("").trim_end_matches('/').to_string();
        let exclude = manifest
            .get("workspace")
            .and_then(Value::as_table)
            .and_then(|w| w.get("exclude"));
        report.manifests.push(at.clone());
        let Some(exclude) = exclude else { continue };
        let Value::Array(entries) = exclude else {
            report.refused.push(format!(
                "{at}: [workspace] exclude is not a list: cargo reads it as a list of paths. \
                 Write it as one"
            ));
            continue;
        };
        for entry in entries {
            report.entries += 1;
            let Value::String(entry) = entry else {
                report.refused.push(format!(
                    "{at}: [workspace] exclude holds a value of type {}, not a path: cargo \
                     reads the list as paths. Write it as the excluded crate's directory, or \
                     delete it",
                    entry.type_str()
                ));
                continue;
            };
            if let Some(r) = entry_refusal(root, &tracked, &at, &dir, entry) {
                report.refused.push(r);
            }
        }
    }
    report
}

pub fn run(root: &Path) {
    let report = check(root);
    if report.refused.is_empty() {
        println!(
            "exclude-check: OK: {} exclude entr(ies) across {} workspace manifest(s) ({}), each \
             naming a directory that holds a tracked Cargo.toml.",
            report.entries,
            report.manifests.len(),
            report.manifests.join(", ")
        );
        return;
    }
    eprintln!(
        "exclude-check: {} refused, each an exclude entry that names no crate's directory or a \
         manifest the check cannot read:\n",
        report.refused.len()
    );
    for r in &report.refused {
        eprintln!("  {r}\n");
    }
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git_fixture::Repo;

    const CRATE: &str = "[package]\nname = \"a\"\nversion = \"0.1.0\"\n";

    /// A repository whose root manifest excludes `entries`, holding a committed crate at
    /// `tools/kept`, a directory with no manifest at `tools/empty` (it holds one file), a file
    /// at `tools/file`, and a crate one level down at `tools/parent/child`.
    fn repo(entries: &[&str]) -> Repo {
        let r = Repo::new();
        let list = entries
            .iter()
            .map(|e| format!("{e:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        r.write(
            "Cargo.toml",
            &format!("[workspace]\nmembers = []\nexclude = [{list}]\n"),
        );
        r.write("tools/kept/Cargo.toml", CRATE);
        r.write("tools/empty/README.md", "no crate here\n");
        r.write("tools/file", "a file\n");
        r.write("tools/parent/child/Cargo.toml", CRATE);
        r.commit("tree");
        r
    }

    fn refused(r: &Repo) -> Vec<String> {
        check(r.path()).refused
    }

    #[test]
    fn an_entry_naming_a_directory_with_a_manifest_passes() {
        let r = repo(&["tools/kept"]);
        let report = check(r.path());
        assert!(report.refused.is_empty(), "{:?}", report.refused);
        assert_eq!(report.manifests, vec!["Cargo.toml".to_string()]);
        assert_eq!(report.entries, 1);
    }

    #[test]
    fn an_entry_naming_nothing_is_refused_with_the_entry_the_manifest_and_the_remedy() {
        let r = repo(&["tools/kept", "tools/gone"]);
        let got = refused(&r);
        assert_eq!(got.len(), 1, "{got:?}");
        let m = &got[0];
        assert!(m.starts_with("Cargo.toml: [workspace] exclude names `tools/gone`"), "{m}");
        assert!(m.contains("names nothing in the tree"), "{m}");
        assert!(m.contains("Delete the entry, or put back the crate it excludes"), "{m}");
    }

    #[test]
    fn an_entry_naming_a_directory_without_a_manifest_is_refused() {
        let r = repo(&["tools/empty"]);
        let got = refused(&r);
        assert_eq!(got.len(), 1, "{got:?}");
        let m = &got[0];
        assert!(m.starts_with("Cargo.toml: [workspace] exclude names `tools/empty`"), "{m}");
        assert!(m.contains("a directory that holds no Cargo.toml"), "{m}");
        assert!(m.contains("Name the directory that holds the excluded crate's Cargo.toml, or delete the entry"), "{m}");
    }

    /// A parent of a crate is refused too: the entry names the crate it excludes.
    #[test]
    fn an_entry_naming_a_parent_of_a_crate_is_refused() {
        let r = repo(&["tools/parent"]);
        let got = refused(&r);
        assert_eq!(got.len(), 1, "{got:?}");
        let m = &got[0];
        assert!(m.starts_with("Cargo.toml: [workspace] exclude names `tools/parent`, a directory that holds no Cargo.toml"), "{m}");
        assert!(m.contains("Name the directory that holds the excluded crate's Cargo.toml, or delete the entry"), "{m}");
    }

    #[test]
    fn an_entry_naming_a_file_is_refused() {
        let r = repo(&["tools/file"]);
        let got = refused(&r);
        assert_eq!(got.len(), 1, "{got:?}");
        let m = &got[0];
        assert!(m.starts_with("Cargo.toml: [workspace] exclude names `tools/file`"), "{m}");
        assert!(m.contains("which is a file, not a directory"), "{m}");
        assert!(m.contains("Name the directory that holds the excluded crate's Cargo.toml, or delete the entry"), "{m}");
    }

    /// Cargo reads an exclude entry as a plain path, so a glob names no directory, even one
    /// whose pattern would match a crate.
    #[test]
    fn a_glob_is_refused_as_naming_no_directory() {
        for glob in ["tools/*", "tools/kep?", "tools/[k]ept"] {
            let r = repo(&[glob]);
            let got = refused(&r);
            assert_eq!(got.len(), 1, "{glob}: {got:?}");
            let m = &got[0];
            assert!(m.starts_with(&format!("Cargo.toml: [workspace] exclude names `{glob}`, a glob")), "{m}");
            assert!(m.contains("reads an exclude entry as a plain path, so this names no directory"), "{m}");
            assert!(m.contains("Name each excluded crate's directory instead"), "{m}");
        }
    }

    #[test]
    fn an_entry_leaving_the_repository_is_refused() {
        for entry in ["../elsewhere", "/abs/crate", "tools/../../out"] {
            let r = repo(&[entry]);
            let got = refused(&r);
            assert_eq!(got.len(), 1, "{entry}: {got:?}");
            let m = &got[0];
            assert!(m.starts_with(&format!("Cargo.toml: [workspace] exclude names `{entry}`, which is absolute or climbs out of the repository")), "{m}");
            assert!(m.contains("Name the excluded crate's directory relative to Cargo.toml, inside the repository"), "{m}");
        }
    }

    /// A crate on disk that git does not track would not be in a checkout of the tree.
    #[test]
    fn an_entry_whose_manifest_is_untracked_is_refused() {
        let r = repo(&["tools/local"]);
        r.write("tools/local/Cargo.toml", CRATE);
        let got = refused(&r);
        assert_eq!(got.len(), 1, "{got:?}");
        let m = &got[0];
        assert!(m.starts_with("Cargo.toml: [workspace] exclude names `tools/local`"), "{m}");
        assert!(m.contains("whose tools/local/Cargo.toml git does not track"), "{m}");
        assert!(m.contains("Commit the crate, or delete the entry"), "{m}");
    }

    #[test]
    fn an_exclude_that_is_not_a_list_of_paths_is_refused() {
        let r = Repo::new();
        r.write("Cargo.toml", "[workspace]\nexclude = \"tools/kept\"\n");
        r.write("tools/kept/Cargo.toml", CRATE);
        r.commit("tree");
        let got = refused(&r);
        assert_eq!(got.len(), 1, "{got:?}");
        let m = &got[0];
        assert!(m.starts_with("Cargo.toml: [workspace] exclude is not a list"), "{m}");
        assert!(m.ends_with("Write it as one"), "{m}");

        r.write("Cargo.toml", "[workspace]\nexclude = [\"tools/kept\", 7]\n");
        let got = refused(&r);
        assert_eq!(got.len(), 1, "{got:?}");
        let m = &got[0];
        assert!(m.starts_with("Cargo.toml: [workspace] exclude holds a value of type integer, not a path"), "{m}");
        assert!(m.contains("Write it as the excluded crate's directory, or delete it"), "{m}");
    }

    /// Every workspace root under the code roots is read, and its entries resolve from its own
    /// directory, not the repository's.
    #[test]
    fn a_workspace_root_under_a_code_root_is_held_too() {
        let r = repo(&["tools/kept"]);
        r.write(
            "infra/relay/Cargo.toml",
            "[package]\nname = \"relay\"\nversion = \"0.1.0\"\n\n[workspace]\nexclude = [\"vendored\", \"gone\"]\n",
        );
        r.write("infra/relay/vendored/Cargo.toml", CRATE);
        r.commit("relay");
        let report = check(r.path());
        assert_eq!(
            report.manifests,
            vec!["Cargo.toml".to_string(), "infra/relay/Cargo.toml".to_string()]
        );
        assert_eq!(report.entries, 3);
        assert_eq!(report.refused.len(), 1, "{:?}", report.refused);
        assert!(
            report.refused[0].starts_with("infra/relay/Cargo.toml: [workspace] exclude names `gone`, which names nothing in the tree"),
            "{}",
            report.refused[0]
        );
    }

    /// The mutation the check is for: a tree that passes, then the same tree with a stale
    /// entry re-added, which turns it red.
    #[test]
    fn re_adding_a_stale_entry_turns_the_check_red() {
        let r = repo(&["tools/kept"]);
        assert!(refused(&r).is_empty());
        r.write(
            "Cargo.toml",
            "[workspace]\nmembers = []\nexclude = [\"tools/kept\", \"tools/floor-bench\"]\n",
        );
        let got = refused(&r);
        assert_eq!(got.len(), 1, "{got:?}");
        assert!(got[0].contains("exclude names `tools/floor-bench`, which names nothing in the tree"), "{}", got[0]);
    }

    #[test]
    fn a_root_manifest_without_a_workspace_is_refused() {
        let r = Repo::new();
        r.write("Cargo.toml", CRATE);
        r.commit("tree");
        let got = refused(&r);
        assert_eq!(got.len(), 1, "{got:?}");
        let m = &got[0];
        assert!(m.starts_with("Cargo.toml declares no [workspace]"), "{m}");
        assert!(m.contains("Run it from the repository's root"), "{m}");
    }

    /// A root manifest that cannot be read (here a directory where the file would be) is
    /// refused, not taken as a tree with nothing to check.
    #[test]
    fn a_root_manifest_that_cannot_be_read_is_refused() {
        let r = Repo::new();
        r.write("Cargo.toml/README.md", "a directory, not a manifest\n");
        r.commit("tree");
        let report = check(r.path());
        assert!(report.manifests.is_empty(), "{:?}", report.manifests);
        assert_eq!(report.refused.len(), 1, "{:?}", report.refused);
        let m = &report.refused[0];
        assert!(m.contains("Cargo.toml"), "{m}");
        assert!(m.ends_with(": exclude-check cannot read the root manifest"), "{m}");
    }

    /// A manifest under a code root that is not TOML might declare a workspace; it is refused,
    /// not skipped.
    #[test]
    fn a_manifest_under_a_code_root_that_is_not_toml_is_refused() {
        let r = repo(&["tools/kept"]);
        r.write("tools/broken/Cargo.toml", "[workspace\nexclude = [\n");
        r.commit("broken");
        let got = refused(&r);
        assert_eq!(got.len(), 1, "{got:?}");
        let m = &got[0];
        assert!(m.contains("Cargo.toml: not TOML"), "{m}");
        assert!(m.contains("broken"), "{m}");
        assert!(m.ends_with("exclude-check cannot tell whether it declares a [workspace]"), "{m}");
    }

    /// Outside a git repository nothing says which manifests are tracked, and the run is
    /// refused rather than reported OK.
    #[test]
    fn a_tree_git_cannot_list_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "[workspace]\nexclude = []\n").unwrap();
        let report = check(dir.path());
        assert!(report.manifests.is_empty(), "{:?}", report.manifests);
        assert_eq!(report.refused.len(), 1, "{:?}", report.refused);
        let m = &report.refused[0];
        assert!(m.starts_with("git ls-files -z --cached"), "{m}");
        assert!(m.ends_with(": exclude-check cannot tell which manifests the tree holds"), "{m}");
    }

    /// An entry that resolves to its own manifest's directory names no excluded crate, from the
    /// root and from a workspace root further down.
    #[test]
    fn an_entry_naming_its_own_manifests_directory_is_refused() {
        for entry in [".", "", "tools/.."] {
            let r = repo(&[entry]);
            let got = refused(&r);
            assert_eq!(got.len(), 1, "{entry:?}: {got:?}");
            let m = &got[0];
            assert!(m.starts_with(&format!("Cargo.toml: [workspace] exclude names `{entry}`, which resolves to Cargo.toml's own directory")), "{m}");
            assert!(m.contains("Name the excluded crate's directory, or delete the entry"), "{m}");
        }
        let r = repo(&["tools/kept"]);
        r.write(
            "infra/relay/Cargo.toml",
            "[package]\nname = \"relay\"\nversion = \"0.1.0\"\n\n[workspace]\nexclude = [\".\"]\n",
        );
        r.commit("relay");
        let got = refused(&r);
        assert_eq!(got.len(), 1, "{got:?}");
        assert!(got[0].starts_with("infra/relay/Cargo.toml: [workspace] exclude names `.`, which resolves to infra/relay/Cargo.toml's own directory"), "{}", got[0]);
    }

    /// Cargo on Unix reads a backslash as part of one component, so `tools\kept` is not
    /// `tools/kept`, even where `tools/kept` is a crate.
    #[test]
    fn an_entry_holding_a_backslash_is_refused() {
        let r = repo(&["tools\\kept"]);
        let got = refused(&r);
        assert_eq!(got.len(), 1, "{got:?}");
        let m = &got[0];
        assert!(m.starts_with("Cargo.toml: [workspace] exclude names `tools\\kept`, which holds a backslash"), "{m}");
        assert!(m.ends_with("Write it with `/` between its parts"), "{m}");
    }
}
