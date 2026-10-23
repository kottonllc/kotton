// SPDX-License-Identifier: AGPL-3.0-or-later
//! **The newest release this desktop knows**, for `mint relay` and `mint vault`
//! to name the archive the host runs
//! (`TASK-mint-prints-the-hosts-install-command-and-is-verb-first`). `mint host` reads
//! nothing here: a host clones the distribution (`kottonllc/kotton-dist`), whose release tags
//! are not this repository's, so its line names a visible `<tag>`.
//!
//! A release is a pushed `v*` tag, and `.github/workflows/release.yml` builds both server
//! archives from the tagged commit and names each by its first 12 hex
//! (`kotton-relay-<rev>-linux-x86_64.tar.gz`). So the newest release a desktop built from a
//! checkout knows is the newest `v*` tag reachable from the commit it was built from, and its
//! revision is that tag's commit, cut the same way: the workflow and this script read one
//! fact by one rule, and cannot disagree about it.
//!
//! Sets `KOTTON_RELEASE_REV` to those 12 hex, or to nothing when no such tag is known — a
//! build outside a checkout, a clone without tags, before the first tag, or a tag named with
//! anything but letters, digits, `.`, `-`, `+` and `_`. Nothing is guessed: an empty revision is printed as a visible `<rev>` with a line
//! saying to put the release's there, and `--rev` names one's own build's. Always set, so a
//! variable of that name in the builder's environment never stands in for it. Never fails the
//! build.
//!
//! Re-run when a tag is made or moved (`refs/tags`, `packed-refs` in the repository's common
//! directory), not on every commit: a commit past the newest tag leaves the newest release
//! where it was.

use std::path::Path;
use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// The newest release's revision.
fn newest_release() -> Option<String> {
    let tag = git(&["describe", "--tags", "--abbrev=0", "--match", "v*", "HEAD"])?;
    if !tag.bytes().all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b)) {
        return None;
    }
    let sha = git(&["rev-parse", "--verify", "--quiet", &format!("{tag}^{{commit}}")])?;
    let rev = sha.get(..12)?;
    rev.bytes().all(|b| b.is_ascii_hexdigit()).then(|| rev.to_ascii_lowercase())
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if let Some(common) = git(&["rev-parse", "--path-format=absolute", "--git-common-dir"]) {
        for watched in ["refs/tags", "packed-refs"] {
            let path = Path::new(&common).join(watched);
            if path.exists() {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }
    let rev = newest_release().unwrap_or_default();
    println!("cargo:rustc-env=KOTTON_RELEASE_REV={rev}");
}
