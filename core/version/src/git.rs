// SPDX-License-Identifier: AGPL-3.0-or-later
//! What git says about the commit a checkout holds, for `src/derive.rs` to derive from.
//!
//! The build script includes this file and runs it on the workspace root; the tests below run
//! it on repositories they make, so what `git describe` picks and what this derives from are
//! shown on real tags, lightweight and annotated, rather than assumed.
//!
//! Git is asked only about `root` itself: a source tree with no `.git` of its own, unpacked
//! inside some other repository, would otherwise report that repository's tags. When git cannot
//! answer, the answer is no tag known.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::derive::{parse_describe, Source};

fn git(root: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        // A hook or a wrapper that exported these would point git at another repository.
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// What git says about the commit `root` holds. `watch` is handed every file whose change
/// would change the answer and that exists now: `HEAD`, the branch it names, `packed-refs` and
/// `refs/tags`.
pub fn source(root: &Path, watch: &mut dyn FnMut(PathBuf)) -> Result<Source, String> {
    let unknown = Source::Untagged { commit: None };
    let Some(top) = git(root, &["rev-parse", "--show-toplevel"]) else {
        return Ok(unknown);
    };
    let same = match (Path::new(&top).canonicalize(), root.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    };
    if !same {
        return Ok(unknown);
    }
    let mut seen = |p: PathBuf| {
        if p.exists() {
            watch(p);
        }
    };
    if let Some(dir) = git(root, &["rev-parse", "--path-format=absolute", "--git-dir"]) {
        seen(Path::new(&dir).join("HEAD"));
    }
    if let Some(common) = git(root, &["rev-parse", "--path-format=absolute", "--git-common-dir"]) {
        let common = Path::new(&common);
        if let Some(branch) = git(root, &["symbolic-ref", "-q", "HEAD"]) {
            seen(common.join(branch));
        }
        seen(common.join("packed-refs"));
        seen(common.join("refs/tags"));
    }
    let Some(commit) = git(root, &["rev-parse", "--verify", "--quiet", "--short=12", "HEAD"])
    else {
        return Ok(unknown);
    };
    let Some(described) = git(
        root,
        &["describe", "--tags", "--long", "--abbrev=12", "--match", "v[0-9]*", "HEAD"],
    ) else {
        return Ok(Source::Untagged {
            commit: Some(commit),
        });
    };
    let (tag, ahead, _) = parse_describe(&described)?;
    // Every tag on the commit `describe` reached, not only the one it named: where a candidate
    // was promoted, the release is the one derived from.
    let tagged = git(root, &["rev-parse", "--verify", "--quiet", &format!("{tag}^{{commit}}")])
        .ok_or_else(|| format!("tag `{tag}` names no commit"))?;
    let tags = git(root, &["tag", "--list", "v[0-9]*", "--points-at", &tagged])
        .map(|t| t.lines().map(str::to_string).collect())
        .unwrap_or_else(|| vec![tag]);
    Ok(Source::Tagged {
        tags,
        ahead,
        commit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::reported;

    /// A repository of `commits` empty commits, in a directory of its own.
    fn repo(commits: usize) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        run(dir.path(), &["init", "-q", "-b", "main"]);
        for i in 0..commits {
            run(dir.path(), &["commit", "-q", "--allow-empty", "-m", &format!("c{i}")]);
        }
        dir
    }

    fn run(root: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"])
            .args(["-c", "tag.gpgsign=false", "-c", "core.hooksPath=/dev/null"])
            .args(args)
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?}");
    }

    fn head(root: &Path) -> String {
        git(root, &["rev-parse", "--short=12", "HEAD"]).unwrap()
    }

    fn says(root: &Path) -> String {
        let s = source(root, &mut |_| {}).unwrap();
        reported(&s, &semver::Version::parse("0.1.0").unwrap())
            .unwrap()
            .to_string()
    }

    #[test]
    fn on_a_snapshot_tag_the_tags_version() {
        let r = repo(2);
        run(r.path(), &["tag", "v0.1.0-dev.1"]);
        assert_eq!(says(r.path()), format!("0.1.0-dev.1+{}", head(r.path())));
    }

    #[test]
    fn three_past_an_annotated_snapshot() {
        let r = repo(1);
        run(r.path(), &["tag", "-a", "-m", "snapshot", "v0.1.0-dev.1"]);
        for i in 0..3 {
            run(r.path(), &["commit", "-q", "--allow-empty", "-m", &format!("d{i}")]);
        }
        assert_eq!(says(r.path()), format!("0.1.0-dev.1.3+{}", head(r.path())));
    }

    #[test]
    fn twelve_past_a_release() {
        let r = repo(1);
        run(r.path(), &["tag", "v0.1.0"]);
        for i in 0..12 {
            run(r.path(), &["commit", "-q", "--allow-empty", "-m", &format!("d{i}")]);
        }
        assert_eq!(says(r.path()), format!("0.1.1-dev.0.12+{}", head(r.path())));
    }

    /// Whichever of the two `git describe` names, the release is derived from.
    #[test]
    fn a_promoted_candidate_derives_from_the_release() {
        for annotate in ["v0.1.0-rc.1", "v0.1.0"] {
            let r = repo(1);
            for tag in ["v0.1.0-rc.1", "v0.1.0"] {
                if tag == annotate {
                    run(r.path(), &["tag", "-a", "-m", tag, tag]);
                } else {
                    run(r.path(), &["tag", tag]);
                }
            }
            assert_eq!(says(r.path()), format!("0.1.0+{}", head(r.path())));
            run(r.path(), &["commit", "-q", "--allow-empty", "-m", "past"]);
            assert_eq!(says(r.path()), format!("0.1.1-dev.0.1+{}", head(r.path())));
        }
    }

    #[test]
    fn a_tag_that_disagrees_with_the_workspace_fails() {
        let r = repo(1);
        run(r.path(), &["tag", "v0.2.0-dev.1"]);
        let s = source(r.path(), &mut |_| {}).unwrap();
        assert!(reported(&s, &semver::Version::parse("0.1.0").unwrap()).is_err());
    }

    #[test]
    fn a_checkout_with_no_tags_names_its_commit() {
        let r = repo(2);
        assert_eq!(says(r.path()), format!("0.1.0-dev.0+{}", head(r.path())));
    }

    #[test]
    fn a_tree_with_no_repository_of_its_own_is_unknown() {
        // Not a repository at all.
        let bare = tempfile::tempdir().unwrap();
        assert_eq!(says(bare.path()), "0.1.0-dev.0+unknown");
        // A directory inside some other repository, as a tarball unpacked in one: that
        // repository's tags are not this tree's.
        let outer = repo(1);
        run(outer.path(), &["tag", "v9.9.9"]);
        let inner = outer.path().join("unpacked");
        std::fs::create_dir(&inner).unwrap();
        assert_eq!(says(&inner), "0.1.0-dev.0+unknown");
    }

    #[test]
    fn what_is_watched_exists() {
        let r = repo(1);
        run(r.path(), &["tag", "v0.1.0"]);
        let mut watched = Vec::new();
        source(r.path(), &mut |p| watched.push(p)).unwrap();
        assert!(watched.iter().any(|p| p.ends_with("HEAD")), "{watched:?}");
        assert!(watched.iter().any(|p| p.ends_with("refs/tags")), "{watched:?}");
        assert!(watched.iter().all(|p| p.exists()), "{watched:?}");
    }
}
