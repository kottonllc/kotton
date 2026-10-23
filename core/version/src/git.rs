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
//!
//! ## What is watched, and why each path
//!
//! The build script hands each path below to cargo as `rerun-if-changed`. Cargo re-runs the
//! script when a watched path is missing, or when the newest modification time of the path,
//! and of everything under it when it is a directory, directory entries included, is newer
//! than the last run. So a file written, rewritten or deleted under a watched directory is
//! seen. Every path is chosen so that whatever moves the answer moves one of them:
//!
//! - **`<git-dir>/HEAD`**: a checkout, or a commit on a detached `HEAD`, rewrites it. In a
//!   worktree this is the worktree's own `HEAD`.
//! - **`<common>/refs/heads`, as a directory**: a commit on a branch writes that branch's
//!   loose ref under it. Naming the branch's file instead is not enough. Once `git pack-refs`
//!   has run (auto-gc runs it), the branch is in `packed-refs` and has no loose file. The next
//!   commit then writes a new loose file that nothing named, and neither `HEAD` nor
//!   `packed-refs` changes.
//! - **`<common>/refs/tags`, as a directory**: a tag made, moved or deleted while it is loose.
//! - **`<common>/packed-refs`**, when it exists: packing, and deleting or moving a packed tag
//!   or branch, rewrite it. When it does not exist yet, the `git pack-refs` that creates it
//!   also deletes loose refs, which the two directories see.
//! - **`<common>/refs`**, in place of either directory that does not exist yet: creating
//!   `refs/tags` for the first tag changes `refs`. Watching a missing directory would instead
//!   re-run the script on every build.
//! - **`<common>/reftable`**, when the repository uses that ref backend.
//! - **`<root>/.git`, when git gives no answer for `root`**: there is no repository, or it is
//!   not this tree's, or git is not installed. This path is watched whether or not it exists.
//!   A tree with no `.git` therefore re-runs the script on every build, which is cheap and
//!   only happens in such a tree. Without this, a build of the tree before its `.git` appeared
//!   (moved back, cloned into place, the same path in a shared target directory) would keep
//!   reporting `+unknown` on every later build, even on a tag.

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

/// No repository of `root`'s own: watch where its `.git` would be, present or not.
fn unknown(root: &Path, watch: &mut dyn FnMut(PathBuf)) -> Result<Source, String> {
    watch(root.join(".git"));
    Ok(Source::Untagged { commit: None })
}

/// What git says about the commit `root` holds. `watch` is handed every path whose change
/// would change the answer, as the module says.
pub fn source(root: &Path, watch: &mut dyn FnMut(PathBuf)) -> Result<Source, String> {
    let Some(top) = git(root, &["rev-parse", "--show-toplevel"]) else {
        return unknown(root, watch);
    };
    let same = match (Path::new(&top).canonicalize(), root.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    };
    if !same {
        return unknown(root, watch);
    }
    let (Some(dir), Some(common)) = (
        git(root, &["rev-parse", "--path-format=absolute", "--git-dir"]),
        git(
            root,
            &["rev-parse", "--path-format=absolute", "--git-common-dir"],
        ),
    ) else {
        return unknown(root, watch);
    };
    let common = Path::new(&common);
    watch(Path::new(&dir).join("HEAD"));
    let mut refs_watched = false;
    for sub in ["refs/heads", "refs/tags"] {
        let path = common.join(sub);
        if path.is_dir() {
            watch(path);
        } else if !refs_watched {
            watch(common.join("refs"));
            refs_watched = true;
        }
    }
    for file in ["packed-refs", "reftable"] {
        let path = common.join(file);
        if path.exists() {
            watch(path);
        }
    }
    let Some(commit) = git(
        root,
        &["rev-parse", "--verify", "--quiet", "--short=12", "HEAD"],
    ) else {
        // A repository with no commit yet: the first one writes under `refs/heads`.
        return Ok(Source::Untagged { commit: None });
    };
    let Some(described) = git(
        root,
        &[
            "describe",
            "--tags",
            "--long",
            "--abbrev=12",
            "--match",
            "v[0-9]*",
            "HEAD",
        ],
    ) else {
        return Ok(Source::Untagged {
            commit: Some(commit),
        });
    };
    let (tag, ahead, _) = parse_describe(&described)?;
    // Every tag on the commit `describe` reached, not only the one it named: where a candidate
    // was promoted, the release is the one derived from.
    let tagged = git(
        root,
        &[
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("{tag}^{{commit}}"),
        ],
    )
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
            run(
                dir.path(),
                &["commit", "-q", "--allow-empty", "-m", &format!("c{i}")],
            );
        }
        dir
    }

    fn run(root: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(root)
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "-c",
                "commit.gpgsign=false",
            ])
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
            run(
                r.path(),
                &["commit", "-q", "--allow-empty", "-m", &format!("d{i}")],
            );
        }
        assert_eq!(says(r.path()), format!("0.1.0-dev.1.3+{}", head(r.path())));
    }

    #[test]
    fn twelve_past_a_release() {
        let r = repo(1);
        run(r.path(), &["tag", "v0.1.0"]);
        for i in 0..12 {
            run(
                r.path(),
                &["commit", "-q", "--allow-empty", "-m", &format!("d{i}")],
            );
        }
        assert_eq!(says(r.path()), format!("0.1.1-dev.0.12+{}", head(r.path())));
    }

    /// Whichever of the two `git describe` names, the release is derived from. Annotating one
    /// tag makes `describe` prefer it, so each run asserts which tag `describe` named.
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
            let described = git(
                r.path(),
                &["describe", "--tags", "--long", "--match", "v[0-9]*"],
            )
            .unwrap();
            assert_eq!(
                parse_describe(&described).unwrap().0,
                annotate,
                "{described}"
            );
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

    /// When a watched path last changed, as cargo reads it: the newest modification time of
    /// the path and of everything under it, directory entries included, or `None` when it is
    /// missing (which cargo always counts as changed).
    fn stamp(path: &Path) -> Option<std::time::SystemTime> {
        let meta = std::fs::metadata(path).ok()?;
        let mut newest = meta.modified().ok()?;
        if meta.is_dir() {
            for entry in std::fs::read_dir(path).ok()?.flatten() {
                if let Some(t) = stamp(&entry.path()) {
                    newest = newest.max(t);
                }
            }
        }
        Some(newest)
    }

    /// The paths `source` watches on `root`, each with its stamp now.
    fn watched(root: &Path) -> Vec<(PathBuf, Option<std::time::SystemTime>)> {
        let mut paths = Vec::new();
        source(root, &mut |p| paths.push(p)).unwrap();
        paths
            .into_iter()
            .map(|p| {
                let t = stamp(&p);
                (p, t)
            })
            .collect()
    }

    /// Whether cargo would re-run the build script: a watched path missing, or changed.
    fn rerun(before: &[(PathBuf, Option<std::time::SystemTime>)]) -> bool {
        before.iter().any(|(p, t)| t.is_none() || stamp(p) != *t)
    }

    fn commit(root: &Path, message: &str) {
        // Past the file system's timestamp resolution, so a write is a newer stamp.
        std::thread::sleep(std::time::Duration::from_millis(20));
        run(root, &["commit", "-q", "--allow-empty", "-m", message]);
    }

    /// After `git pack-refs` the branch has no loose ref, and the next commit writes one that
    /// no file named before it existed. HEAD and packed-refs are untouched. The build script
    /// must still re-run, and the version must move.
    #[test]
    fn a_commit_on_a_packed_branch_moves_the_version_and_reruns() {
        let r = repo(1);
        run(r.path(), &["tag", "v0.1.0-dev.1"]);
        commit(r.path(), "one");
        run(r.path(), &["pack-refs", "--all", "--prune"]);
        let common = r.path().join(".git");
        assert!(
            !common.join("refs/heads/main").exists(),
            "the branch is packed"
        );
        let before = says(r.path());
        let stamps = watched(r.path());
        assert!(!rerun(&stamps), "nothing moved yet: {stamps:?}");
        commit(r.path(), "two");
        assert!(
            common.join("refs/heads/main").exists(),
            "the commit wrote a loose ref"
        );
        assert!(
            rerun(&stamps),
            "a commit on a packed branch was not seen: {stamps:?}"
        );
        let after = says(r.path());
        assert_ne!(before, after);
        assert_eq!(after, format!("0.1.0-dev.1.2+{}", head(r.path())));
    }

    /// A commit on a branch, a new tag, and a deleted tag each make the build script re-run.
    #[test]
    fn a_commit_or_a_tag_reruns() {
        let r = repo(1);
        let stamps = watched(r.path());
        commit(r.path(), "a");
        assert!(rerun(&stamps), "a commit on a loose branch");

        let stamps = watched(r.path());
        std::thread::sleep(std::time::Duration::from_millis(20));
        run(r.path(), &["tag", "v0.1.0-dev.1"]);
        assert!(rerun(&stamps), "the first tag");
        assert_eq!(says(r.path()), format!("0.1.0-dev.1+{}", head(r.path())));

        let stamps = watched(r.path());
        std::thread::sleep(std::time::Duration::from_millis(20));
        run(r.path(), &["tag", "-d", "v0.1.0-dev.1"]);
        assert!(rerun(&stamps), "a deleted tag");
        assert_eq!(says(r.path()), format!("0.1.0-dev.0+{}", head(r.path())));
    }

    /// A tree with no repository of its own watches where its `.git` would be. That path is
    /// missing, so cargo re-runs the script on every build, and the build after a `.git`
    /// appears reads it.
    #[test]
    fn a_tree_with_no_repository_reruns_until_one_appears() {
        let dir = tempfile::tempdir().unwrap();
        let tree = dir.path().join("tree");
        std::fs::create_dir(&tree).unwrap();
        let stamps = watched(&tree);
        assert_eq!(stamps, vec![(tree.join(".git"), None)]);
        assert!(rerun(&stamps), "a missing `.git` re-runs every build");
        // `.git` appears (moved back, cloned into place): the next run reads it.
        run(&tree, &["init", "-q", "-b", "main"]);
        run(&tree, &["commit", "-q", "--allow-empty", "-m", "c"]);
        run(&tree, &["tag", "v0.1.0"]);
        assert_eq!(says(&tree), format!("0.1.0+{}", head(&tree)));
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
        assert_eq!(watched(&inner), vec![(inner.join(".git"), None)]);
    }

    #[test]
    fn what_is_watched_exists() {
        let r = repo(1);
        run(r.path(), &["tag", "v0.1.0"]);
        let mut watched = Vec::new();
        source(r.path(), &mut |p| watched.push(p)).unwrap();
        assert!(watched.iter().any(|p| p.ends_with("HEAD")), "{watched:?}");
        assert!(
            watched.iter().any(|p| p.ends_with("refs/tags")),
            "{watched:?}"
        );
        assert!(
            watched.iter().any(|p| p.ends_with("refs/heads")),
            "{watched:?}"
        );
        assert!(watched.iter().all(|p| p.exists()), "{watched:?}");
    }
}
