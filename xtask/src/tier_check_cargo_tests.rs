// SPDX-License-Identifier: AGPL-3.0-or-later
//! `tier-check`'s reader, held to cargo. The reader parses manifests itself, so a form of
//! dependency cargo accepts and the reader does not know would be an edge cargo links and the
//! gate never judges. Here the path edges the reader finds between crates of rows are compared
//! with the path dependencies `cargo metadata --no-deps` reports for the root workspace and for
//! the relay's, and any edge cargo has that the reader does not fails the test, on the day the
//! form is first written.
//!
//! `cargo metadata --no-deps` resolves no registry and builds nothing; it is run offline, with
//! `CARGO_TARGET_DIR` pointed at a directory that does not exist, and the test fails if cargo
//! made it.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

use crate::tier_check::{live_rows, read_tree, tracked_manifests, Rows};

/// The workspaces cargo is asked about, by manifest, repo-relative: the root's and the relay's.
const WORKSPACES: &[&str] = &["Cargo.toml", "infra/relay/Cargo.toml"];

/// One path edge as `(from crate, from dir, to crate, to dir)`, dirs repo-relative.
type PathEdge = (String, String, String, String);

/// Repo-relative form of an absolute path cargo reported, or `None` outside the repository.
fn relative(root: &Path, p: &str) -> Option<String> {
    let rel = Path::new(p).strip_prefix(root).ok()?;
    Some(crate::normalise_path(&rel.to_string_lossy().replace('\\', "/")))
}

/// What cargo reports for the workspace at `manifest`: the directory of each member package,
/// and every path dependency whose two ends are both in rows.
fn cargo_edges(root: &Path, rows: &Rows, manifest: &str, target: &Path) -> (BTreeSet<String>, BTreeSet<PathEdge>) {
    let out = Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1", "--no-deps", "--offline", "--manifest-path"])
        .arg(root.join(manifest))
        .current_dir(root)
        .env("CARGO_TARGET_DIR", target)
        .output()
        .expect("cargo runs");
    assert!(
        out.status.success(),
        "`cargo metadata --no-deps` failed for {manifest}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let meta: serde_json::Value = serde_json::from_slice(&out.stdout).expect("cargo metadata is JSON");
    let mut members = BTreeSet::new();
    let mut edges = BTreeSet::new();
    for pkg in meta["packages"].as_array().expect("cargo metadata lists packages") {
        let name = pkg["name"].as_str().expect("a package has a name").to_string();
        let manifest_path = pkg["manifest_path"].as_str().expect("a package has a manifest");
        let from_dir = relative(root, manifest_path)
            .and_then(|m| m.strip_suffix("Cargo.toml").map(|d| d.trim_end_matches('/').to_string()))
            .unwrap_or_else(|| panic!("{name}'s manifest {manifest_path} is not under {}", root.display()));
        members.insert(from_dir.clone());
        if rows.row_of(&from_dir).is_none() {
            continue;
        }
        for dep in pkg["dependencies"].as_array().expect("a package lists its dependencies") {
            let Some(path) = dep["path"].as_str() else { continue };
            let Some(to_dir) = relative(root, path) else { continue };
            if rows.row_of(&to_dir).is_none() {
                continue;
            }
            let to = dep["name"].as_str().expect("a dependency has a name").to_string();
            edges.insert((name.clone(), from_dir.clone(), to, to_dir));
        }
    }
    (members, edges)
}

/// Every path edge cargo reports between crates of rows, in either workspace, is one the reader
/// found; every crate the reader read is a member of one of the two workspaces, so no crate's
/// edges go uncompared; and cargo built nothing.
#[test]
fn every_path_edge_cargo_reports_is_one_tier_check_reads() {
    let root = crate::out::root();
    let rows = live_rows();
    let tree = read_tree(&root, &rows, &tracked_manifests(&root, &rows));
    let read: BTreeSet<PathEdge> = tree
        .edges
        .iter()
        .map(|e| (e.from.clone(), e.from_dir.clone(), e.to.clone(), e.to_dir.clone()))
        .collect();

    let scratch = tempfile::tempdir().expect("a temp dir");
    let target = scratch.path().join("target");
    let mut members = BTreeSet::new();
    let mut missed = Vec::new();
    for manifest in WORKSPACES {
        let (m, cargo) = cargo_edges(&root, &rows, manifest, &target);
        assert!(
            !cargo.is_empty(),
            "cargo reports no path edge between crates of rows in {manifest}: the comparison would \
             hold nothing"
        );
        members.extend(m);
        for (from, from_dir, to, to_dir) in cargo.difference(&read) {
            missed.push(format!(
                "{from} ({from_dir}) -> {to} ({to_dir}), in the workspace of {manifest}: cargo links \
                 it and tier-check's reader does not find it, so the gate does not judge it. Teach \
                 xtask/src/tier_check.rs the form that manifest writes it in, or refuse the form"
            ));
        }
    }
    assert!(missed.is_empty(), "{}", missed.join("\n"));

    let outside: Vec<String> = tree
        .crates
        .iter()
        .filter(|c| !members.contains(&c.dir))
        .map(|c| format!("{} ({})", c.name, c.dir))
        .collect();
    assert!(
        outside.is_empty(),
        "tier-check reads these crates, and no workspace cargo is asked about here ({}) has them \
         as members, so their edges are compared with nothing: {}",
        WORKSPACES.join(", "),
        outside.join(", ")
    );

    assert!(
        !target.exists(),
        "`cargo metadata --no-deps` wrote {}: the comparison is to build nothing",
        target.display()
    );
}
