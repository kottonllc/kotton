// SPDX-License-Identifier: AGPL-3.0-or-later
//! Sets `KOTTON_VERSION`, the version every binary reports, once for all of them.
//!
//! `src/git.rs` asks git about the commit being built (`git describe --tags --long`, then
//! every tag on the commit that names), and `src/derive.rs` turns the answer into the form
//! kotton-protocol's `VERSIONING.md` describes; each file says its half of the rule and holds
//! its tests. A tag whose version disagrees with the workspace's fails the build here, with the
//! reason. When git cannot answer, the build still succeeds, reporting no tag known.
//!
//! It re-runs when the commit or the tags move. The paths it watches, and why each one, are
//! listed in `src/git.rs`: `HEAD`, `refs/heads` and `refs/tags` as directories, and
//! `packed-refs`. A tree with no `.git` of its own watches where `.git` would be, so the script
//! re-runs on every build until a repository appears.

#[path = "src/derive.rs"]
mod derive;
#[path = "src/git.rs"]
mod git;

use std::path::Path;

fn fail(reason: &str) -> ! {
    eprintln!("kotton-version: {reason}");
    std::process::exit(1)
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| fail(&format!("cargo did not set `{name}`")))
}

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=src/derive.rs");
    println!("cargo::rerun-if-changed=src/git.rs");
    // The tree this build is for: `.cargo/config.toml` sets it to the checkout's own path.
    // Cargo gives this crate the same hash in every tree, so trees at different paths share
    // one cached run in a shared target directory. A different path makes that run stale.
    // `src/git.rs` says why each watched path is there, and why this one is needed too.
    println!("cargo::rerun-if-env-changed=KOTTON_VERSION_TREE");
    // Read when the script runs, never with `env!`: a build-script binary compiled in one tree
    // is reused by every other, and would otherwise ask git about the first.
    let manifest = env("CARGO_MANIFEST_DIR");
    // `core/version` → the workspace root.
    let root = Path::new(&manifest)
        .parent()
        .and_then(Path::parent)
        .expect("core/version has no grandparent");
    // This crate's version is the workspace's (`version.workspace = true`).
    let workspace = semver::Version::parse(&env("CARGO_PKG_VERSION"))
        .unwrap_or_else(|e| fail(&format!("the workspace's version is not semver: {e}")));
    let source = git::source(root, &mut |p| {
        println!("cargo::rerun-if-changed={}", p.display());
    })
    .unwrap_or_else(|e| fail(&e));
    let version = derive::reported(&source, &workspace).unwrap_or_else(|e| fail(&e));
    println!("cargo::rustc-env=KOTTON_VERSION={version}");
}
