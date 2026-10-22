// SPDX-License-Identifier: AGPL-3.0-or-later
//! **The scaffold is a crate the tree compiles.** `guest/examples/hello` is built by
//! `cargo xtask build-apps`; this holds every file `kotton app new hello` writes to that
//! directory's file of the same name, byte for byte, the SDK's entry aside, and holds the
//! directory to those files and the build's own outputs.
//!
//! Here and not in the shell because the fixture is this tree's: a release of the shell ships
//! without `guest/`, so the shell's tests read nothing of it. The shell says what it writes,
//! `kotton_shell::scaffold_files`; its own tests hold `app new` to that, and this holds the
//! fixture to it.

use std::path::{Path, PathBuf};

/// The fixture's SDK entry, which is the one line `scaffold_files` is handed rather than
/// writes: in-tree, by path, so `cargo xtask build-apps` builds it with the tree.
const SDK_IN_TREE: &str = "\
# The SDK, by path, so `cargo xtask build-apps` builds this crate with the tree.
# `kotton app new` writes the SDK's repository here instead, and its test holds
# every other byte of this directory to what it writes.
kotton-app = { path = \"../../sdk/kotton-app\", features = [\"dioxus\"] }";

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../guest/examples/hello")
}

/// The files under `dir`, as paths relative to it, but what a build leaves: the lockfile it
/// writes, `target/`, and the `app.wasm` `build-apps` copies out.
fn files_under(dir: &Path) -> Vec<String> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).expect("readable directory") {
            let path = entry.expect("readable entry").path();
            let rel = path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
            if matches!(rel.as_str(), "Cargo.lock" | "app.wasm" | "target") {
                continue;
            }
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                out.push(rel);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

#[test]
fn the_scaffold_is_the_fixture_build_apps_compiles() {
    let dir = fixture();
    let written = kotton_shell::scaffold_files("hello", SDK_IN_TREE);
    for (path, contents) in &written {
        let kept = std::fs::read_to_string(dir.join(path))
            .unwrap_or_else(|e| panic!("guest/examples/hello/{path}: {e}"));
        assert_eq!(&kept, contents, "guest/examples/hello/{path} is what `app new hello` writes");
    }
    let mut names: Vec<String> = written.iter().map(|(p, _)| p.to_string()).collect();
    names.sort();
    assert_eq!(files_under(&dir), names, "the fixture holds the scaffold's files and no others");
}

/// The command's own entry and the fixture's are the one line in which the two differ: the
/// scaffold with the repository's entry, that entry swapped for the fixture's, is the
/// fixture's `Cargo.toml`.
#[test]
fn the_scaffold_and_the_fixture_differ_in_the_sdks_entry_alone() {
    let (_, cargo) = kotton_shell::scaffold_files("hello", kotton_shell::SDK_FROM_REPOSITORY)
        .into_iter()
        .find(|(p, _)| *p == "Cargo.toml")
        .expect("the scaffold writes a Cargo.toml");
    let fixture = std::fs::read_to_string(fixture().join("Cargo.toml")).unwrap();
    assert_eq!(cargo.replace(kotton_shell::SDK_FROM_REPOSITORY, SDK_IN_TREE), fixture);
}
