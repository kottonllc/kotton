// SPDX-License-Identifier: AGPL-3.0-or-later
//! Replaying the sealed history log into state.
//!
//! Segments are facts; this is what turns them back into "what does the tree
//! look like now". It is deliberately a **pure function** over a set of
//! segments — no storage, no IO, no clock — so the reconciliation rules can be
//! tested exhaustively without a store, and so the same rules apply whether the
//! segments came off a local pack, a peer, or a blind bucket.
//!
//! # What makes this different from comparing two listings
//!
//! Object replication today unions two key listings and moves whatever differs.
//! That cannot express a delete — an absence is indistinguishable from "not
//! copied yet" — and it cannot tell a concurrent edit from a sequential one,
//! because a timestamp answers *when* and never *whether the writer had seen
//! the other change*.
//!
//! Entries carry a `parent`: the version of that path the writer held when it
//! wrote. So:
//!
//! - **Sequential** — B's parent is A's version. B saw A. B wins, no conflict.
//! - **Concurrent** — A and B claim the *same* parent. Neither saw the other.
//!   That is a conflict as a matter of fact, not a guess about clocks.
//!
//! Time is still used, but only to pick which concurrent version is shown
//! first. It never decides *whether* a conflict happened, and the losing
//! version is retained rather than overwritten.

use crate::history::{Entry, Segment};
use std::collections::{BTreeMap, BTreeSet};

/// One version of one path, as some writer recorded it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    /// Content digest, or `None` when this version is a deletion.
    pub digest: Option<String>,
    /// True (unpadded) size; zero for a deletion.
    pub size: u64,
    /// DID of the writer that recorded it.
    pub writer: String,
    /// Wall-clock seconds the writer stamped.
    pub at: u64,
    /// The version this writer held when it wrote — `None` means it believed
    /// the path did not exist.
    pub parent: Option<String>,
}

impl Version {
    /// Whether this version deletes the path.
    pub fn is_delete(&self) -> bool {
        self.digest.is_none()
    }

    /// Deterministic ordering for concurrent versions: newest wins, and the
    /// writer DID breaks a tie so every device picks the same one without
    /// coordinating.
    fn beats(&self, other: &Self) -> bool {
        (self.at, &self.writer) > (other.at, &other.writer)
    }
}

/// The result of replaying a set of segments.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplayState {
    /// path → the version currently shown. Deletions are present here as
    /// versions with no digest, because "deleted" is a fact the log records and
    /// not an absence to be inferred.
    pub current: BTreeMap<String, Version>,
    /// path → the versions that lost a concurrent write and were **kept**.
    ///
    /// Non-empty means a real conflict: two writers who had not seen each
    /// other. Nothing here has been discarded — retaining the loser is the
    /// invariant that separates this from the LWW-on-mtime path it replaces.
    pub conflicts: BTreeMap<String, Vec<Version>>,
    /// Opaque record payloads, in the order encountered, for the record layer
    /// to interpret. This module deliberately does not look inside them.
    pub records: Vec<Vec<u8>>,
    /// Segment digests named as parents by some segment but never supplied.
    ///
    /// A non-empty set means the replay is over a **partial** view: it still
    /// converges, but a reader that cares should fetch these before trusting
    /// the result. Detecting this is the whole reason segments carry `parents`.
    pub missing_segments: BTreeSet<String>,
}

impl ReplayState {
    /// Paths whose current version is a live file, with their digests.
    pub fn live(&self) -> impl Iterator<Item = (&str, &Version)> {
        self.current
            .iter()
            .filter(|(_, v)| !v.is_delete())
            .map(|(p, v)| (p.as_str(), v))
    }

    /// Whether any path ended with a retained losing version.
    pub fn has_conflicts(&self) -> bool {
        !self.conflicts.is_empty()
    }
}

/// Replay `segments` into state.
///
/// `available` names the digests of the segments supplied, so `parents`
/// pointing outside the set can be reported as missing. Order does not matter —
/// reconciliation is by causal parent and then by timestamp, never by the order
/// segments happen to arrive in, which is what lets a device pull them in any
/// order from any source.
pub fn replay(segments: &[(String, Segment)]) -> ReplayState {
    let available: BTreeSet<&str> = segments.iter().map(|(d, _)| d.as_str()).collect();
    let mut state = ReplayState::default();

    for (_, seg) in segments {
        // A snapshot's parents are what it *subsumed*, so their absence is
        // collection working as designed rather than a gap to report.
        if seg.snapshot {
            continue;
        }
        for parent in &seg.parents {
            if !available.contains(parent.as_str()) {
                state.missing_segments.insert(parent.clone());
            }
        }
    }

    // Gather every version claimed for every path, then reconcile per path.
    // Two passes rather than one so the outcome cannot depend on the order
    // segments were handed in.
    let mut by_path: BTreeMap<String, Vec<Version>> = BTreeMap::new();
    for (_, seg) in segments {
        for entry in &seg.entries {
            match entry {
                Entry::ObjectWrite {
                    path,
                    digest,
                    size,
                    parent,
                    at,
                    ..
                } => by_path.entry(path.clone()).or_default().push(Version {
                    digest: Some(digest.clone()),
                    size: *size,
                    writer: seg.writer.clone(),
                    at: *at,
                    parent: parent.clone(),
                }),
                Entry::ObjectDelete { path, parent, at } => {
                    by_path.entry(path.clone()).or_default().push(Version {
                        digest: None,
                        size: 0,
                        writer: seg.writer.clone(),
                        at: *at,
                        parent: parent.clone(),
                    })
                }
                Entry::Record { payload, .. } => state.records.push(payload.clone()),
            }
        }
    }

    for (path, versions) in by_path {
        // A version that some other version claims as its parent has been
        // superseded — its writer was seen. What remains are the heads: the
        // versions nobody built on.
        let superseded: BTreeSet<&str> = versions
            .iter()
            .filter_map(|v| v.parent.as_deref())
            .collect();
        let mut heads: Vec<Version> = versions
            .iter()
            .filter(|v| match &v.digest {
                // A write is superseded when something names its content as a
                // parent. Deletes are never named as a parent (a writer that
                // saw a delete records `None`), so they are heads unless a
                // later write supersedes them by other means.
                Some(d) => !superseded.contains(d.as_str()),
                None => true,
            })
            .cloned()
            .collect();

        if heads.is_empty() {
            // Every version was superseded by another — possible only with a
            // cycle, which a monotonic log cannot produce honestly. Fall back
            // to the whole set rather than dropping the path.
            heads = versions.clone();
        }

        // Deterministic: the winner is the same on every device.
        heads.sort_by(|a, b| (b.at, &b.writer).cmp(&(a.at, &a.writer)));
        let winner = heads[0].clone();
        let losers: Vec<Version> = heads[1..].to_vec();

        debug_assert!(losers.iter().all(|l| winner.beats(l)));
        state.current.insert(path.clone(), winner);
        if !losers.is_empty() {
            state.conflicts.insert(path, losers);
        }
    }

    state
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(writer: &str, seq: u64, entries: Vec<Entry>) -> (String, Segment) {
        let mut s = Segment::new(writer, seq);
        s.entries = entries;
        (format!("{writer}:{seq}"), s)
    }

    fn write(path: &str, digest: &str, parent: Option<&str>, at: u64) -> Entry {
        Entry::ObjectWrite {
            path: path.into(),
            digest: digest.into(),
            size: 1,
            parent: parent.map(Into::into),
            at,
            written_from: parent.map(Into::into),
        }
    }

    fn delete(path: &str, parent: Option<&str>, at: u64) -> Entry {
        Entry::ObjectDelete {
            path: path.into(),
            parent: parent.map(Into::into),
            at,
        }
    }

    #[test]
    fn a_single_write_becomes_the_current_version() {
        let s = replay(&[seg("did:a", 1, vec![write("notes/a.md", "d1", None, 10)])]);
        assert_eq!(s.current["notes/a.md"].digest.as_deref(), Some("d1"));
        assert!(!s.has_conflicts());
    }

    /// The sequential case: B saw A, so B simply wins and nothing is a
    /// conflict — even though two writers touched the same path.
    #[test]
    fn a_write_that_saw_its_predecessor_is_not_a_conflict() {
        let s = replay(&[
            seg("did:a", 1, vec![write("f", "d1", None, 10)]),
            seg("did:b", 1, vec![write("f", "d2", Some("d1"), 20)]),
        ]);
        assert_eq!(s.current["f"].digest.as_deref(), Some("d2"));
        assert!(!s.has_conflicts(), "sequential edits must not conflict");
    }

    /// The concurrent case: both claim the same parent, so neither saw the
    /// other. That is a conflict as a fact, and the loser is kept.
    #[test]
    fn concurrent_writes_conflict_and_the_loser_is_retained() {
        let s = replay(&[
            seg("did:a", 1, vec![write("f", "base", None, 5)]),
            seg("did:a", 2, vec![write("f", "mine", Some("base"), 10)]),
            seg("did:b", 1, vec![write("f", "theirs", Some("base"), 20)]),
        ]);
        assert_eq!(s.current["f"].digest.as_deref(), Some("theirs"));
        let kept = &s.conflicts["f"];
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].digest.as_deref(), Some("mine"));
    }

    /// Ordering of the input must not change the outcome — segments arrive in
    /// whatever order a pull happens to produce.
    #[test]
    fn the_result_does_not_depend_on_segment_order() {
        let a = seg("did:a", 1, vec![write("f", "base", None, 5)]);
        let b = seg("did:a", 2, vec![write("f", "mine", Some("base"), 10)]);
        let c = seg("did:b", 1, vec![write("f", "theirs", Some("base"), 20)]);
        let forward = replay(&[a.clone(), b.clone(), c.clone()]);
        let backward = replay(&[c, b, a]);
        assert_eq!(forward, backward);
    }

    /// A tie on the clock still resolves the same way everywhere, because the
    /// writer DID breaks it.
    #[test]
    fn a_timestamp_tie_is_broken_deterministically() {
        let s = replay(&[
            seg("did:aaa", 1, vec![write("f", "x", None, 10)]),
            seg("did:zzz", 1, vec![write("f", "y", None, 10)]),
        ]);
        assert_eq!(s.current["f"].writer, "did:zzz");
        assert_eq!(s.conflicts["f"][0].writer, "did:aaa");
    }

    /// The defect this whole mechanism exists to fix: a delete is a recorded
    /// fact, so it survives replay instead of being re-inferred as "missing
    /// and therefore copy it back".
    #[test]
    fn a_delete_survives_replay_and_does_not_resurrect() {
        let s = replay(&[
            seg("did:a", 1, vec![write("gone", "d1", None, 10)]),
            seg("did:a", 2, vec![delete("gone", Some("d1"), 20)]),
        ]);
        let v = &s.current["gone"];
        assert!(v.is_delete());
        assert_eq!(s.live().count(), 0);
    }

    /// Delete on one device, edit on another, neither having seen the other.
    /// Both are heads; the newer shows, and the other is kept rather than lost.
    #[test]
    fn a_delete_concurrent_with_a_write_is_a_conflict() {
        let s = replay(&[
            seg("did:a", 1, vec![write("f", "base", None, 5)]),
            seg("did:a", 2, vec![delete("f", Some("base"), 10)]),
            seg("did:b", 1, vec![write("f", "edited", Some("base"), 20)]),
        ]);
        assert_eq!(s.current["f"].digest.as_deref(), Some("edited"));
        assert!(s.conflicts["f"][0].is_delete());
    }

    #[test]
    fn parents_outside_the_supplied_set_are_reported_missing() {
        let mut s = Segment::new("did:a", 2);
        s.parents = vec!["not-here".into()];
        s.entries = vec![write("f", "d", None, 10)];
        let out = replay(&[("did:a:2".into(), s)]);
        assert!(out.missing_segments.contains("not-here"));
        // It still converges — a partial view is usable, just flagged.
        assert_eq!(out.current["f"].digest.as_deref(), Some("d"));
    }

    #[test]
    fn record_payloads_pass_through_uninterpreted() {
        let s = replay(&[seg(
            "did:a",
            1,
            vec![Entry::Record {
                payload: b"row".to_vec(),
                at: 1,
            }],
        )]);
        assert_eq!(s.records, vec![b"row".to_vec()]);
        assert!(s.current.is_empty());
    }

    #[test]
    fn independent_paths_do_not_interfere() {
        let s = replay(&[seg(
            "did:a",
            1,
            vec![write("a", "d1", None, 10), write("b", "d2", None, 11)],
        )]);
        assert_eq!(s.live().count(), 2);
        assert!(!s.has_conflicts());
    }
}
