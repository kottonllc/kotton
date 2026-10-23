// SPDX-License-Identifier: AGPL-3.0-or-later
//! The version this build of Kotton reports, in the form kotton-protocol's `VERSIONING.md`
//! describes: a tag's version with the commit after `+`, or, off a tag, the version derived
//! from the nearest one (`0.1.1-dev.0.12+<commit>` twelve commits past `v0.1.0`).
//!
//! Every binary that says what version it is says [`VERSION`], so there is one derivation and
//! one answer. The build script sets it; `src/derive.rs` holds the rule and `src/git.rs` what
//! git is asked, each with its tests.
//! Nothing here reads `CARGO_PKG_VERSION` for a binary: a crate's own manifest version is not
//! what a build is.

/// The version this build reports. Valid semver, always with build metadata: the commit, or
/// `unknown` when the source had no repository to ask.
pub const VERSION: &str = env!("KOTTON_VERSION");

#[cfg(test)]
mod derive;
#[cfg(test)]
mod git;

#[cfg(test)]
mod tests {
    #[test]
    fn the_version_this_build_reports_is_semver_with_build_metadata() {
        let v = semver::Version::parse(super::VERSION).unwrap();
        assert!(!v.build.is_empty(), "{}", super::VERSION);
    }
}
