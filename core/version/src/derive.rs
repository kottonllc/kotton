// SPDX-License-Identifier: AGPL-3.0-or-later
//! The derivation: from what git says about the commit being built, the version a binary
//! reports, by kotton-protocol's `VERSIONING.md` ("What a binary says").
//!
//! The build script includes this file and runs git; the tests below run it on the examples
//! that page states and order the results with `semver`, the crate cargo orders versions with,
//! so the page and this code cannot drift without a test failing.
//!
//! - **On a tag**: the tag's version, the commit after `+`. A tag whose version disagrees with
//!   the workspace's is refused, with the reason, and the build fails. A tag agrees when the
//!   workspace (`[workspace.package] version`) names either the tag's own version or the
//!   release it is a pre-release of. `0.1.0` agrees with `v0.1.0-dev.1`, `v0.1.0-rc.2` and
//!   `v0.1.0`. A workspace that names a pre-release itself, such as `0.1.0-dev.1`, agrees
//!   only with that exact tag. It refuses `v0.1.0`, because a release tagged while the
//!   manifest still names a snapshot means the manifest was not moved. VERSIONING does not
//!   say which; this is the stricter reading.
//! - **Past a release**: the next patch's zeroth snapshot plus the count past it,
//!   `v0.1.0` and 12 commits is `0.1.1-dev.0.12+<commit>`.
//! - **Past a snapshot or a candidate**: that tag's word and number plus the count,
//!   `v0.1.0-dev.1` and 3 commits is `0.1.0-dev.1.3+<commit>`.
//! - **No tag known** (a clone without tags, history before the first, a source tree with no
//!   `.git`): the page does not say. What is reported is the workspace's version's zeroth
//!   snapshot, `0.1.0-dev.0+<commit>`, or `+unknown` when there is no commit to name. It is
//!   a version no tag has (`N` counts from 1), it sorts below every tag of that version, and it
//!   claims nothing the build cannot show.
//!
//! Where one commit carries several tags, the one of highest precedence is the one derived
//! from, whatever `git describe` picked.

use semver::{BuildMetadata, Prerelease, Version};

/// What git says about the commit being built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// The nearest tagged commit: every `v*` tag on it, how many commits the build is past it,
    /// and the build's own commit, abbreviated.
    Tagged {
        tags: Vec<String>,
        ahead: u64,
        commit: String,
    },
    /// No tag is reachable, or there is no repository to ask: the commit, when one is known.
    Untagged { commit: Option<String> },
}

/// The version a tag names, if the tag is one of the forms `VERSIONING.md` admits:
/// `vX.Y.Z`, `vX.Y.Z-dev.N` or `vX.Y.Z-rc.N`, `N` from 1, and nothing after `+`.
pub fn tag_version(tag: &str) -> Result<Version, String> {
    let bare = tag
        .strip_prefix('v')
        .ok_or_else(|| format!("tag `{tag}` does not start with `v`"))?;
    let version = Version::parse(bare).map_err(|e| format!("tag `{tag}` is not a version: {e}"))?;
    if !version.build.is_empty() {
        return Err(format!(
            "tag `{tag}` carries build metadata; a tag is `vX.Y.Z`, `vX.Y.Z-dev.N` or `vX.Y.Z-rc.N`"
        ));
    }
    if !version.pre.is_empty() {
        let mut parts = version.pre.as_str().split('.');
        let ok = matches!(
            (parts.next(), parts.next(), parts.next()),
            (Some("dev" | "rc"), Some(n), None)
                if !n.starts_with('0') && n.parse::<u64>().is_ok_and(|n| n >= 1)
        );
        if !ok {
            return Err(format!(
                "tag `{tag}` has the pre-release `{}`; the two that exist are `dev.N` and `rc.N`, N from 1",
                version.pre
            ));
        }
    }
    Ok(version)
}

/// Of the tags on one commit, the one of highest precedence. Every one of them must be a form
/// `VERSIONING.md` admits: a `v` tag that is not is a broken promise, and is named rather than
/// stepped over.
pub fn highest(tags: &[String]) -> Result<(String, Version), String> {
    let mut best: Option<(String, Version)> = None;
    for tag in tags {
        let v = tag_version(tag)?;
        if best.as_ref().is_none_or(|(_, b)| v > *b) {
            best = Some((tag.clone(), v));
        }
    }
    best.ok_or_else(|| "no tag to derive from".to_string())
}

/// `git describe --tags --long` output, `<tag>-<count>-g<commit>`, split into its three parts.
/// The tag itself may hold `-`, so this reads from the right.
pub fn parse_describe(out: &str) -> Result<(String, u64, String), String> {
    let mut parts = out.trim().rsplitn(3, '-');
    let (Some(g), Some(n), Some(tag)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(format!(
            "`git describe` said `{out}`, not `<tag>-<count>-g<commit>`"
        ));
    };
    let commit = g
        .strip_prefix('g')
        .ok_or_else(|| format!("`git describe` said `{out}`: no `g` before the commit"))?;
    let ahead = n
        .parse::<u64>()
        .map_err(|_| format!("`git describe` said `{out}`: `{n}` is not a count"))?;
    Ok((tag.to_string(), ahead, commit.to_string()))
}

fn metadata(commit: Option<&str>) -> Result<BuildMetadata, String> {
    let text = match commit {
        Some(c) if !c.is_empty() && c.bytes().all(|b| b.is_ascii_hexdigit()) => {
            c.to_ascii_lowercase()
        }
        Some(c) => return Err(format!("`{c}` is not a commit")),
        None => "unknown".to_string(),
    };
    BuildMetadata::new(&text).map_err(|e| format!("`{text}` as build metadata: {e}"))
}

fn pre(text: &str) -> Prerelease {
    Prerelease::new(text).expect("a pre-release of words and numbers is valid")
}

/// The version a binary reports, from what git says and the workspace's version.
pub fn reported(source: &Source, workspace: &Version) -> Result<Version, String> {
    match source {
        Source::Untagged { commit } => Ok(Version {
            major: workspace.major,
            minor: workspace.minor,
            patch: workspace.patch,
            pre: pre("dev.0"),
            build: metadata(commit.as_deref())?,
        }),
        Source::Tagged {
            tags,
            ahead,
            commit,
        } => {
            let (tag, version) = highest(tags)?;
            let build = metadata(Some(commit))?;
            if *ahead == 0 {
                agrees(&tag, &version, workspace)?;
                return Ok(Version { build, ..version });
            }
            Ok(if version.pre.is_empty() {
                Version {
                    major: version.major,
                    minor: version.minor,
                    patch: version.patch + 1,
                    pre: pre(&format!("dev.0.{ahead}")),
                    build,
                }
            } else {
                Version {
                    pre: pre(&format!("{}.{ahead}", version.pre)),
                    build,
                    ..version
                }
            })
        }
    }
}

/// A tag agrees with the workspace when the workspace names the tag's version, or the release
/// a snapshot or candidate of it is for: `v0.1.0-dev.1` and `v0.1.0` both agree with `0.1.0`.
fn agrees(tag: &str, version: &Version, workspace: &Version) -> Result<(), String> {
    let core = |v: &Version| (v.major, v.minor, v.patch);
    let same = core(version) == core(workspace)
        && (workspace.pre.is_empty() || workspace.pre == version.pre);
    if same {
        Ok(())
    } else {
        Err(format!(
            "tag `{tag}` names {version}, and the workspace's version (`[workspace.package] \
             version` in the root Cargo.toml) is {workspace}. A binary built here would say one \
             and its manifest the other: set the workspace's version to {}.{}.{} in the commit \
             the tag names, or tag the version it says.",
            version.major, version.minor, version.patch
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    fn tagged(tags: &[&str], ahead: u64, commit: &str) -> Source {
        Source::Tagged {
            tags: tags.iter().map(|t| t.to_string()).collect(),
            ahead,
            commit: commit.to_string(),
        }
    }

    fn says(source: &Source, workspace: &str) -> String {
        reported(source, &v(workspace)).unwrap().to_string()
    }

    // The three cases `VERSIONING.md` gives, each from the `git describe` line it names.

    #[test]
    fn on_a_tag_the_tags_version_with_the_commit() {
        let (tag, ahead, commit) = parse_describe("v0.1.0-dev.1-0-gabc1234").unwrap();
        assert_eq!((tag.as_str(), ahead), ("v0.1.0-dev.1", 0));
        let s = tagged(&[&tag], ahead, &commit);
        assert_eq!(says(&s, "0.1.0"), "0.1.0-dev.1+abc1234");
        assert_eq!(
            says(&tagged(&["v0.1.0"], 0, "abc1234"), "0.1.0"),
            "0.1.0+abc1234"
        );
    }

    #[test]
    fn after_a_release_the_next_patchs_zeroth_snapshot_and_the_count() {
        let (tag, ahead, commit) = parse_describe("v0.1.0-12-gabc1234").unwrap();
        assert_eq!(
            says(&tagged(&[&tag], ahead, &commit), "0.1.0"),
            "0.1.1-dev.0.12+abc1234"
        );
    }

    #[test]
    fn after_a_snapshot_its_word_and_number_and_the_count() {
        let (tag, ahead, commit) = parse_describe("v0.1.0-dev.1-3-gdef5678").unwrap();
        assert_eq!(tag, "v0.1.0-dev.1");
        assert_eq!(
            says(&tagged(&[&tag], ahead, &commit), "0.1.0"),
            "0.1.0-dev.1.3+def5678"
        );
        // A candidate is derived the same way.
        assert_eq!(
            says(&tagged(&["v0.1.0-rc.2"], 5, "def5678"), "0.1.0"),
            "0.1.0-rc.2.5+def5678"
        );
    }

    #[test]
    fn past_a_tag_the_workspaces_version_is_not_read() {
        // After `v0.1.0` the workspace may already say what it works toward.
        assert_eq!(
            says(&tagged(&["v0.1.0"], 12, "abc1234"), "0.2.0"),
            "0.1.1-dev.0.12+abc1234"
        );
    }

    #[test]
    fn a_tag_that_disagrees_with_the_workspace_fails_with_the_reason() {
        let e = reported(&tagged(&["v0.2.0-dev.1"], 0, "abc1234"), &v("0.1.0")).unwrap_err();
        assert!(e.contains("v0.2.0-dev.1") && e.contains("0.1.0"), "{e}");
        assert!(e.contains("[workspace.package] version"), "{e}");
        // A workspace that names a pre-release agrees only with that pre-release.
        assert!(reported(&tagged(&["v0.1.0"], 0, "abc1234"), &v("0.1.0-dev.1")).is_err());
        assert_eq!(
            says(&tagged(&["v0.1.0-dev.1"], 0, "abc1234"), "0.1.0-dev.1"),
            "0.1.0-dev.1+abc1234"
        );
    }

    #[test]
    fn a_commit_carrying_a_candidate_and_its_release_derives_from_the_release() {
        // Whatever `git describe` named, in either order.
        for tags in [["v0.1.0-rc.1", "v0.1.0"], ["v0.1.0", "v0.1.0-rc.1"]] {
            assert_eq!(says(&tagged(&tags, 0, "abc1234"), "0.1.0"), "0.1.0+abc1234");
            assert_eq!(
                says(&tagged(&tags, 12, "abc1234"), "0.1.0"),
                "0.1.1-dev.0.12+abc1234"
            );
        }
    }

    #[test]
    fn no_tag_known_is_the_workspaces_zeroth_snapshot() {
        let commit = Source::Untagged {
            commit: Some("abc1234".into()),
        };
        assert_eq!(says(&commit, "0.1.0"), "0.1.0-dev.0+abc1234");
        let none = Source::Untagged { commit: None };
        assert_eq!(says(&none, "0.1.0"), "0.1.0-dev.0+unknown");
        // Below the first snapshot, and so below every tag of that version.
        assert!(v(&says(&none, "0.1.0")) < v("0.1.0-dev.1"));
    }

    #[test]
    fn only_the_forms_versioning_admits_are_tags() {
        for good in ["v0.1.0", "v0.1.0-dev.1", "v0.1.0-rc.12", "v1.2.3"] {
            assert!(tag_version(good).is_ok(), "{good}");
        }
        for bad in [
            "0.1.0",
            "v0.1",
            "v0.1.0-beta.1",
            "v0.1.0-dev.0",
            "v0.1.0-dev.01",
            "v0.1.0-dev",
            "v0.1.0-dev.1.3",
            "v0.1.0+abc",
        ] {
            assert!(tag_version(bad).is_err(), "{bad}");
        }
        // One bad tag on the commit is named, not stepped over.
        assert!(reported(
            &tagged(&["v0.1.0", "v0.1.0-beta"], 0, "abc1234"),
            &v("0.1.0")
        )
        .is_err());
    }

    /// The order `VERSIONING.md` states, by the crate cargo orders versions with: every
    /// derived form sorts after the tag it is derived from and before any tag that could
    /// follow it, and none has a tag's precedence.
    #[test]
    fn the_order_versioning_states_is_the_order_semver_gives() {
        let order = [
            "0.1.0",
            "0.1.1-dev.0.12",
            "0.1.1-dev.1",
            "0.1.1-dev.1.3",
            "0.1.1-dev.2",
            "0.1.1-rc.1",
            "0.1.1-rc.1.3",
            "0.1.1-rc.2",
            "0.1.1",
        ];
        for pair in order.windows(2) {
            assert!(v(pair[0]) < v(pair[1]), "{} < {}", pair[0], pair[1]);
        }
        // And the derivation gives exactly the derived ones, from the tags before them.
        let derived = |tag: &str, ahead| {
            let mut out = reported(&tagged(&[tag], ahead, "abc1234"), &v("0.1.1")).unwrap();
            out.build = BuildMetadata::EMPTY;
            out.to_string()
        };
        assert_eq!(derived("v0.1.0", 12), order[1]);
        assert_eq!(derived("v0.1.1-dev.1", 3), order[3]);
        assert_eq!(derived("v0.1.1-rc.1", 3), order[6]);
        // Build metadata never orders: two commits' builds of one derivation are equal in
        // precedence.
        assert_eq!(
            v("0.1.1-dev.1.3+abc1234").cmp_precedence(&v("0.1.1-dev.1.3+def5678")),
            std::cmp::Ordering::Equal
        );
    }

    #[test]
    fn a_describe_line_that_is_not_one_is_refused() {
        for bad in ["v0.1.0", "v0.1.0-x-gabc", "v0.1.0-3-abc1234"] {
            assert!(parse_describe(bad).is_err(), "{bad}");
        }
    }
}
