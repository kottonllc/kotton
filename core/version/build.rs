// SPDX-License-Identifier: AGPL-3.0-or-later
//! Sets `KOTTON_VERSION`, the version every binary reports, once for all of them.
//!
//! `src/git.rs` asks git about the commit being built (`git describe --tags --long`, then
//! every tag on the commit that names), and `src/derive.rs` turns the answer into the form
//! kotton-protocol's `VERSIONING.md` describes; each file says its half of the rule and holds
//! its tests. A tag whose version disagrees with the workspace's fails the build here, with the
//! reason. When git cannot answer, the build still succeeds, reporting no tag known.
//!
//! Re-run when the commit or the tags move: `HEAD`, the branch it names, `packed-refs` and
//! `refs/tags`. Only paths that exist are named, since cargo re-runs on every build for one
//! that does not.

#[path = "src/derive.rs"]
mod derive;
#[path = "src/git.rs"]
mod git;

use std::path::Path;

fn fail(reason: &str) -> ! {
    eprintln!("kotton-version: {reason}");
    std::process::exit(1)
}

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=src/derive.rs");
    println!("cargo::rerun-if-changed=src/git.rs");
    // `core/version` → the workspace root.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("core/version has no grandparent");
    // This crate's version is the workspace's (`version.workspace = true`).
    let workspace = semver::Version::parse(env!("CARGO_PKG_VERSION"))
        .unwrap_or_else(|e| fail(&format!("the workspace's version is not semver: {e}")));
    let source = git::source(root, &mut |p| {
        println!("cargo::rerun-if-changed={}", p.display());
    })
    .unwrap_or_else(|e| fail(&e));
    let version = derive::reported(&source, &workspace).unwrap_or_else(|e| fail(&e));
    println!("cargo::rustc-env=KOTTON_VERSION={version}");
}
