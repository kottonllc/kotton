// SPDX-License-Identifier: AGPL-3.0-or-later
//! `recovery-set-check`: an event's carried recovery set is read through one function.
//!
//! ## Why this exists
//!
//! A key event carries the set of recovery authorities its commitment is the root of
//! (`KelEvent::recovery_set`, in `core/wire`). What an event committed is read from its
//! commitment, which its digest covers, so a carried set is the event's authorities
//! only where it makes that commitment. `kotton_crypto::kel_verify::committed_set` is that rule:
//! it returns the set only where it is not empty and its root is the event's commitment. The
//! field stays public, because `core/wire` holds no hash and so cannot make the comparison
//! itself; this check is what makes the function the only reader rather than one reader among
//! any number.
//!
//! ## What it checks
//!
//! Over every `.rs` file under the workspace root (but `target/`, `out/`, `node_modules/` and
//! `.git/`), outside files under a `tests` or `benches` directory and outside `#[cfg(test)] mod`
//! blocks, with comments and string contents blanked first:
//!
//! 1. **Every read of the field is inside [`READER`].** A read is `.recovery_set` that is not
//!    the left side of a plain `=`. An assignment is a write, which may be anywhere an event is
//!    built; so is a field written in a struct literal (`recovery_set: …`), which has no `.`.
//! 2. **The field is defined in [`DEFINED_IN`] and nowhere else.** A definition is
//!    `pub recovery_set:` or `pub(…) recovery_set:`.
//! 3. **[`READER`] exists and reads the field**, so a check that finds the function gone or
//!    moved fails rather than passing over nothing.
//!
//! ## What a text check cannot see
//!
//! It reads text. It does not see a read by destructuring (`let KelEvent { recovery_set, .. }
//! = e`), a private field of that name defined in another struct, a read composed by a macro
//! from pieces, or a `.` and the name on different lines. It reads a `#[cfg(test)] fn` outside
//! a module as code, which errs toward refusing. Those are the residual, stated here rather
//! than implied away.

use std::path::Path;

use crate::docs_present_check::test_modules;
use crate::relay_address_check::{blank, functions};
use crate::user_database_check::{rel, walk};

/// The field.
const FIELD: &str = "recovery_set";

/// The one reader of the field: (file, function).
const READER: (&str, &str) = ("core/crypto/src/provider/kel_verify.rs", "committed_set");

/// The file that defines the field.
const DEFINED_IN: &str = "core/wire/src/kel.rs";

pub fn run(root: &Path) {
    let mut paths = Vec::new();
    walk(root, &mut paths);
    paths.sort();
    let mut files = Vec::new();
    for path in paths.iter().filter(|p| p.extension().is_some_and(|e| e == "rs")) {
        let Ok(src) = std::fs::read_to_string(path) else {
            eprintln!("recovery-set-check: could not read {}", path.display());
            std::process::exit(1);
        };
        files.push((rel(root, path), src));
    }
    if files.is_empty() {
        eprintln!(
            "recovery-set-check: found no .rs file. Run from the workspace root: a check that \
             inspects nothing reports success."
        );
        std::process::exit(1);
    }
    let found = findings(&files);
    if found.is_empty() {
        println!(
            "recovery-set-check: OK: {} file(s), and `{FIELD}` is read in `{}` ({}) alone, \
             outside tests.",
            files.len(),
            READER.1,
            READER.0
        );
        return;
    }
    for f in &found {
        eprintln!("recovery-set-check: {f}");
    }
    eprintln!(
        "\nAn event's carried recovery set is its authorities only where it makes the event's \
         commitment, and `kotton_crypto::kel_verify::committed_set` is that rule. Read the set \
         through it: `committed_set(event)` returns the set where it makes the commitment and \
         nothing otherwise."
    );
    std::process::exit(1);
}

/// Whether `path` is a test or bench target's file rather than a crate's own source.
fn is_test_file(path: &str) -> bool {
    path.split('/').any(|c| c == "tests" || c == "benches")
}

/// Every finding over `files`, as (repo-relative path, contents), already worded.
fn findings(files: &[(String, String)]) -> Vec<String> {
    let mut out = Vec::new();
    let mut reader_reads = 0usize;
    for (path, src) in files {
        if is_test_file(path) {
            continue;
        }
        let code = blank(src);
        let b = code.as_bytes();
        let tests = test_modules(src);
        let fns = functions(b);
        let line_of = |at: usize| 1 + b[..at].iter().filter(|&&c| c == b'\n').count();
        let enclosing = |at: usize| {
            fns.iter()
                .filter(|(_, s, e)| *s <= at && at < *e)
                .max_by_key(|(_, s, _)| *s)
                .map(|f| f.0.as_str())
        };
        let text_of = |line: usize| src.lines().nth(line - 1).unwrap_or("").trim().to_string();
        let mut from = 0;
        while let Some(at) = word(b, FIELD.as_bytes(), from) {
            from = at + FIELD.len();
            let line = line_of(at);
            if tests.iter().any(|&(a, z)| (a..=z).contains(&line)) {
                continue;
            }
            let before = (0..at).rev().find(|&j| !b[j].is_ascii_whitespace());
            let after = (from..b.len()).find(|&j| !b[j].is_ascii_whitespace());
            let next = |k: usize| b.get(k).copied();
            if before.is_some_and(|j| b[j] == b'.') {
                let assigned = after.is_some_and(|k| next(k) == Some(b'=') && next(k + 1) != Some(b'='));
                if assigned {
                    continue;
                }
                let func = enclosing(at);
                if (path.as_str(), func) == (READER.0, Some(READER.1)) {
                    reader_reads += 1;
                    continue;
                }
                out.push(format!(
                    "{path}:{line} in `{}` reads `{FIELD}` outside `{}`: {}",
                    func.unwrap_or("<item>"),
                    READER.1,
                    text_of(line)
                ));
                continue;
            }
            let is_field_type = after.is_some_and(|k| next(k) == Some(b':') && next(k + 1) != Some(b':'));
            if is_field_type && path != DEFINED_IN && visibility_before(b, at) {
                out.push(format!(
                    "{path}:{line} defines a `{FIELD}` field outside {DEFINED_IN}: {}",
                    text_of(line)
                ));
            }
        }
    }
    if reader_reads == 0 {
        out.push(format!(
            "found no read of `{FIELD}` in `{}` in {}: the reader moved or is gone, and a check \
             that finds no reader holds nothing. Point READER in xtask/src/recovery_set_check.rs \
             at it.",
            READER.1, READER.0
        ));
    }
    out
}

/// The offset of the next `needle` at or after `from` that is a whole word.
fn word(b: &[u8], needle: &[u8], mut from: usize) -> Option<usize> {
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    while from + needle.len() <= b.len() {
        let p = b[from..].windows(needle.len()).position(|w| w == needle)? + from;
        let left = p == 0 || !ident(b[p - 1]);
        let right = b.get(p + needle.len()).is_none_or(|&c| !ident(c));
        if left && right {
            return Some(p);
        }
        from = p + 1;
    }
    None
}

/// Whether the word before offset `at` is a visibility: `pub`, or `pub(…)`.
fn visibility_before(b: &[u8], at: usize) -> bool {
    let mut j = at;
    while j > 0 && b[j - 1].is_ascii_whitespace() {
        j -= 1;
    }
    if j > 0 && b[j - 1] == b')' {
        match (0..j).rev().find(|&k| b[k] == b'(') {
            Some(open) => j = open,
            None => return false,
        }
        while j > 0 && b[j - 1].is_ascii_whitespace() {
            j -= 1;
        }
    }
    j >= 3 && &b[j - 3..j] == b"pub" && (j == 3 || !(b[j - 4].is_ascii_alphanumeric() || b[j - 4] == b'_'))
}

#[cfg(test)]
mod tests {
    use super::{findings, READER};

    /// The reader, as it is in the tree, so every fixture below has one.
    const THE_READER: &str = "pub fn committed_set(event: &KelEvent) -> Option<&[[u8; 32]]> {\n    \
        let set = event.recovery_set.as_slice();\n    \
        (!set.is_empty() && recovery_root(set) == event.recovery_commitment).then_some(set)\n}\n";

    fn tree(extra: &[(&str, &str)]) -> Vec<(String, String)> {
        let mut files = vec![(READER.0.to_string(), THE_READER.to_string())];
        files.extend(extra.iter().map(|(p, s)| (p.to_string(), s.to_string())));
        files
    }

    /// The tree as it stands passes: the field is read in the function and nowhere else.
    #[test]
    fn the_tree_as_merged_passes() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let mut paths = Vec::new();
        crate::user_database_check::walk(root, &mut paths);
        let files: Vec<(String, String)> = paths
            .iter()
            .filter(|p| p.extension().is_some_and(|e| e == "rs"))
            .map(|p| (crate::user_database_check::rel(root, p), std::fs::read_to_string(p).unwrap()))
            .collect();
        assert!(files.iter().any(|(p, _)| p == READER.0), "the walk reads the reader's file");
        let found = findings(&files);
        assert!(found.is_empty(), "{found:#?}");
    }

    /// A read of the field added in `core/net` is refused, and names its file, line and
    /// function.
    #[test]
    fn a_read_added_in_core_net_is_refused() {
        let src = "pub fn learn(chain: &[KelEvent]) {\n    for e in chain {\n        for m in &e.recovery_set {\n            index(m);\n        }\n    }\n}\n";
        let found = findings(&tree(&[("core/net/src/provider/transport/quic/tls.rs", src)]));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].starts_with("core/net/src/provider/transport/quic/tls.rs:3 in `learn`"), "{found:?}");
    }

    /// Each shape a reader would take to read the field itself again is refused: an index
    /// over every event's set, a growth check against the predecessor's, the last set that is
    /// not empty, and a command starting from the tip's.
    #[test]
    fn each_reader_reading_the_field_again_is_refused() {
        let shapes = [
            ("core/net/src/provider/transport/quic/tls.rs", "fn learn_chain(&self) {\n    for member in &e.recovery_set {}\n}\n"),
            (READER.0, "fn check(prev: &KelEvent) {\n    if !prev.recovery_set.iter().all(|m| n.contains(m)) {}\n}\n"),
            (READER.0, "fn tip_commits_recovery_key(chain: &[KelEvent]) {\n    let s = chain.iter().rev().map(|e| &e.recovery_set).find(|s| !s.is_empty());\n}\n"),
            ("core/device/src/users/commands.rs", "async fn add_recovery_phrase() {\n    let mut set = prev.recovery_set.clone();\n}\n"),
            ("core/device/src/users/commands.rs", "async fn rotate_identity_to_key() {\n    let p = recovery_proof(&prev.recovery_set, &reserve);\n}\n"),
        ];
        for (path, src) in shapes {
            let mut files = tree(&[]);
            if path == READER.0 {
                files[0].1.push_str(src);
            } else {
                files.push((path.to_string(), src.to_string()));
            }
            let found = findings(&files);
            assert_eq!(found.len(), 1, "{path}: {src}: {found:?}");
        }
    }

    /// Writes, test code, comments, strings and other words pass: a struct literal's field, an
    /// assignment, a read inside a `#[cfg(test)] mod` or under `tests/`, a comment or string
    /// naming the field, and a name that only contains it.
    #[test]
    fn writes_tests_comments_and_other_words_pass() {
        let src = "// reads `e.recovery_set` in prose\n\
                   fn build() -> KelEvent {\n    \
                   let mut e = KelEvent { recovery_set: set.to_vec(), ..x };\n    \
                   e.recovery_set = vec![];\n    \
                   let m = \"e.recovery_set\";\n    \
                   load_recovery_set(base);\n    \
                   e\n}\n\n\
                   #[cfg(test)]\nmod tests {\n    fn t() { assert!(tip.recovery_set.is_empty()); }\n}\n";
        let found = findings(&tree(&[
            ("core/device/src/users/commands.rs", src),
            ("tests/tests/suite/x.rs", "fn t() { tip.recovery_set.len(); }\n"),
        ]));
        assert!(found.is_empty(), "{found:?}");
    }

    /// The field is defined in `core/wire` and nowhere else; a comparison (`==`) is a read.
    #[test]
    fn a_definition_elsewhere_and_a_comparison_are_refused() {
        let def = "pub struct Other {\n    pub(crate) recovery_set: Vec<[u8; 32]>,\n}\n";
        let found = findings(&tree(&[
            ("core/wire/src/kel.rs", "pub struct KelEvent {\n    pub recovery_set: Vec<[u8; 32]>,\n}\n"),
            ("core/peer/src/x.rs", def),
            ("core/peer/src/y.rs", "fn f() { if a.recovery_set == b {} }\n"),
        ]));
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(found[0].contains("defines a `recovery_set` field"), "{found:?}");
        assert!(found[1].contains("reads `recovery_set`"), "{found:?}");
    }

    /// A tree whose reader is gone fails rather than passing over nothing.
    #[test]
    fn a_tree_with_no_reader_fails() {
        let found = findings(&[(READER.0.to_string(), "fn committed_set() {}\n".to_string())]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("the reader moved or is gone"), "{found:?}");
    }
}
