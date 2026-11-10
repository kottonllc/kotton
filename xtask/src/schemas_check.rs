// SPDX-License-Identifier: AGPL-3.0-or-later
//! `schemas-check`: the core set this tree compiles in is the protocol's.
//!
//! A schema is named by the key that publishes it (kotton-protocol's decision of that title),
//! and Kotton's core set is the files under the protocol's `schemas/kotton/`, published under
//! the release key. The reference holds a copy of each under `core/schemas/schemas/kotton/`,
//! compiled into `kotton_schemas::CoreSchema`. This check holds the copy to the original:
//! when a checkout of kotton-protocol is at hand (`$KOTTON_PROTOCOL_DIR`, or
//! `../kotton-protocol` beside this one, as verb-check reads it), every file here equals the
//! file of the same name there, byte for byte, but for the files named in
//! [`NOT_YET_PUBLISHED`]. That list is where a new core schema this tree holds first
//! waits for the protocol to take it, and a name on it that the protocol does have is a
//! finding too, since the list would then be stale. The other way too: a file the protocol
//! publishes under `schemas/kotton/` that this tree lacks is a finding, since the core set
//! would then be short of the protocol's. Without a checkout, the check says so and passes:
//! the tree is held to its own copy, as verb-check is to its pinned words.

use std::path::{Path, PathBuf};

/// The files under `core/schemas/schemas/kotton/` that the protocol does not publish yet: a
/// new core schema this tree holds first, waiting to join `schemas/kotton/` in the protocol by
/// a pull request there. Empty while the protocol publishes the whole core set. A name comes
/// off this list in the commit that finds it published.
pub const NOT_YET_PUBLISHED: &[&str] = &[
    // The person's own name for a key, read by a grant prompt: kotton-protocol's branch
    // `schemas/a-petname-is-a-record-no-app-can-write` (kotton #471).
    "petname.json",
];

/// Where the tree's copy of the core set is.
const OURS: &str = "core/schemas/schemas/kotton";

/// kotton-protocol's checkout, if there is one: `$KOTTON_PROTOCOL_DIR`, or beside this one.
pub fn protocol_dir(root: &Path) -> Option<PathBuf> {
    let dir = std::env::var_os("KOTTON_PROTOCOL_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("..").join("kotton-protocol"));
    dir.join("schemas").join("kotton").is_dir().then_some(dir)
}

/// The findings, against the protocol's `schemas/kotton/` at `theirs`.
pub fn findings(ours: &Path, theirs: &Path) -> Vec<String> {
    findings_excepting(ours, theirs, NOT_YET_PUBLISHED)
}

/// The findings, with `not_yet_published` standing for [`NOT_YET_PUBLISHED`].
fn findings_excepting(ours: &Path, theirs: &Path, not_yet_published: &[&str]) -> Vec<String> {
    let mut found = Vec::new();
    let mut names: Vec<String> = match std::fs::read_dir(ours) {
        Ok(entries) => entries
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.ends_with(".json"))
            .collect(),
        Err(e) => return vec![format!("{}: cannot be read: {e}", ours.display())],
    };
    names.sort();
    if names.is_empty() {
        found.push(format!("{}: holds no schema file", ours.display()));
    }
    for name in &names {
        let mine = ours.join(name);
        let published = theirs.join(name);
        let listed = not_yet_published.contains(&name.as_str());
        match (std::fs::read(&published), listed) {
            (Ok(their_bytes), false) => {
                let my_bytes = std::fs::read(&mine).unwrap_or_default();
                if my_bytes != their_bytes {
                    found.push(format!(
                        "{}: is not the protocol's {} byte for byte; the protocol's file is the authority, so copy it here",
                        mine.display(),
                        published.display()
                    ));
                }
            }
            (Ok(_), true) => found.push(format!(
                "{name}: the protocol publishes it at {}, so it comes off NOT_YET_PUBLISHED in xtask/src/schemas_check.rs",
                published.display()
            )),
            (Err(_), true) => {}
            (Err(_), false) => found.push(format!(
                "{}: the protocol has no {name} under schemas/kotton/, and it is not named in NOT_YET_PUBLISHED (xtask/src/schemas_check.rs)",
                mine.display()
            )),
        }
    }
    for listed in not_yet_published {
        if !names.iter().any(|n| n == listed) {
            found.push(format!("{listed}: named in NOT_YET_PUBLISHED and not under {}", ours.display()));
        }
    }
    let mut published: Vec<String> = match std::fs::read_dir(theirs) {
        Ok(entries) => entries
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.ends_with(".json"))
            .collect(),
        Err(e) => {
            found.push(format!("{}: cannot be read: {e}", theirs.display()));
            Vec::new()
        }
    };
    published.sort();
    for name in published.iter().filter(|n| !names.contains(n)) {
        found.push(format!(
            "{name}: the protocol publishes it at {}, and {} has no copy; the core set is the protocol's, so copy it here",
            theirs.join(name).display(),
            ours.display()
        ));
    }
    found
}

pub fn run(root: &Path) {
    let ours = root.join(OURS);
    let Some(protocol) = protocol_dir(root) else {
        println!(
            "schemas-check: no kotton-protocol checkout (set KOTTON_PROTOCOL_DIR, or check it out beside this one); \
             the core set is held to the tree's own copy under {OURS}, {} of which the protocol does not publish yet.",
            NOT_YET_PUBLISHED.len()
        );
        return;
    };
    let theirs = protocol.join("schemas").join("kotton");
    let found = findings(&ours, &theirs);
    if found.is_empty() {
        println!(
            "schemas-check: OK — every file under {OURS} is the protocol's at {}, byte for byte, or one of the {} not yet published there.",
            theirs.display(),
            NOT_YET_PUBLISHED.len()
        );
        return;
    }
    eprintln!("schemas-check: {} finding(s):\n", found.len());
    for f in &found {
        eprintln!("  {f}");
    }
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (path, text) in files {
            let p = dir.path().join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }
        dir
    }

    /// The list names files that exist here, each once, sorted.
    #[test]
    fn the_list_is_sorted_and_names_files_in_the_tree() {
        let ours = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(OURS);
        let mut sorted = NOT_YET_PUBLISHED.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted, NOT_YET_PUBLISHED, "sorted, none twice");
        for name in NOT_YET_PUBLISHED {
            assert!(ours.join(name).is_file(), "{name} is listed and not in {OURS}");
        }
    }

    /// Equal is fine, listed-and-unpublished is fine, and each other case is a finding by name.
    /// The list is the fixture's own, so the cases hold whatever [`NOT_YET_PUBLISHED`] names.
    #[test]
    fn each_case_is_named() {
        let dir = tree(&[
            ("ours/secret.json", "{\"a\":1}\n"),
            ("theirs/secret.json", "{\"a\":1}\n"),
            ("ours/keeps-whole.json", "{\"a\":1}\n"),
            ("theirs/keeps-whole.json", "{\"a\":2}\n"),
            ("ours/unlisted.json", "{}"),
            ("ours/waiting.json", "{}"),
            ("ours/stale.json", "{}"),
            ("theirs/stale.json", "{}"),
        ]);
        let listed = ["listed-absent.json", "stale.json", "waiting.json"];
        let found = findings_excepting(&dir.path().join("ours"), &dir.path().join("theirs"), &listed);
        let text = found.join("\n");
        assert!(text.contains("keeps-whole.json") && text.contains("byte for byte"), "{text}");
        assert!(text.contains("unlisted.json") && text.contains("not named in NOT_YET_PUBLISHED"), "{text}");
        assert!(text.contains("stale.json") && text.contains("comes off NOT_YET_PUBLISHED"), "{text}");
        assert!(text.contains("listed-absent.json: named in NOT_YET_PUBLISHED and not under"), "{text}");
        assert!(!text.contains("secret.json"), "{text}");
        assert!(!text.contains("waiting.json"), "{text}");
        assert_eq!(found.len(), 4, "{found:#?}");
    }

    /// With the list empty, a file here that the protocol lacks is a finding, by name.
    #[test]
    fn an_unpublished_file_is_named_while_the_list_is_empty() {
        let dir = tree(&[("ours/secret.json", "{}"), ("theirs/secret.json", "{}"), ("ours/new-here.json", "{}")]);
        let found = findings_excepting(&dir.path().join("ours"), &dir.path().join("theirs"), &[]);
        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(found[0].contains("new-here.json") && found[0].contains("not named in NOT_YET_PUBLISHED"), "{}", found[0]);
    }

    /// A file the protocol publishes that the tree lacks is a finding, by name.
    #[test]
    fn a_file_the_protocol_publishes_and_the_tree_lacks_is_named() {
        let dir = tree(&[
            ("ours/secret.json", "{}"),
            ("theirs/secret.json", "{}"),
            ("theirs/new-in-the-protocol.json", "{}"),
            ("theirs/README.md", "not a schema"),
        ]);
        let found = findings(&dir.path().join("ours"), &dir.path().join("theirs"));
        let missing: Vec<&String> = found.iter().filter(|f| f.contains("has no copy")).collect();
        assert_eq!(missing.len(), 1, "{found:#?}");
        assert!(missing[0].starts_with("new-in-the-protocol.json:"), "{}", missing[0]);
    }

    /// The tree's own copy, against the protocol's checkout when there is one.
    #[test]
    fn the_trees_copy_is_the_protocols() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let Some(protocol) = protocol_dir(&root) else { return };
        let found = findings(&root.join(OURS), &protocol.join("schemas").join("kotton"));
        assert!(found.is_empty(), "{found:#?}");
    }
}
