// SPDX-License-Identifier: AGPL-3.0-or-later
//! The files xtask compiles from another crate's source, and the test that holds each to
//! naming nothing but `std` (kotton #306).
//!
//! xtask compiles three readers from their owners' source by `#[path]` rather than linking
//! the owner: kotton-wire's reader of a recorded surface (`wire_check::recorded_surface`),
//! `kvaultd`'s reader of its settings file (`release_server::settings`) and the finder of
//! systemd's parser (`release_server::systemds_parser`). A dependency on the owner would
//! build its whole closure into every `cargo xtask`; what lets one source compile in both
//! crates is that it names nothing but `std`.
//!
//! **What held that claim before this file was the build, and only half of it.** A
//! `use crate::…` in a shared file fails xtask's build. A name both crates already link —
//! `serde_json`, which xtask and kotton-wire both depend on — compiles on both sides, and
//! the claim rots silently: the next change to xtask's dependencies, or to the owner's, is
//! what breaks, far from the line that caused it. So [`foreign_roots`] reads each file as
//! text and finds every path that starts anywhere but `std`, `core`, `alloc`, `super` or
//! `self`: each `use` (and `extern crate`), and each path written in code — after a
//! leading `::`, with or without whitespace around the `::`, in an attribute or a type —
//! since `serde_json::to_string(..)` in a function body is the same dependency as the
//! `use`.
//!
//! **What a shared file pulls in is the same claim.** A shared file that compiles another
//! file into itself — `#[path = "…"] mod x;` (any spacing, or under `cfg_attr`) or
//! `include!("…")` — makes that file shared too, so [`check`] follows each into the file it
//! names and holds it the same way. An out-of-line `mod x;` with no `#[path]` is refused:
//! where it loads from depends on where the file sits in the crate compiling it, so it is
//! not one source compiled twice.
//!
//! **Held conservatively, by name.** A lowercase first segment of a path is held as a
//! crate's name unless it is one of the roots above or a primitive type (`u8::MAX`). A
//! `mod serde_json {}` or `use std::{io as serde_json}` in the file does not exempt the
//! name: which item a name resolves to depends on the scope it is written in, and this is
//! a text check, so a shared file writes its paths from `std` rather than through an alias
//! or a local module.
//!
//! **A test, not a guard in the build.** The build cannot say this: it resolves names
//! against whatever the compiling crate links, and both crates link more than `std`. The
//! check is over the source text, before any crate's dependencies are in the picture, so
//! it runs once in `cargo test -p xtask` and needs no compile of the owners.
//!
//! **The list cannot miss an include.** [`STD_ONLY`] is the one list; the includes are in
//! `wire_check.rs` and `release_server.rs`, each beside the module that uses it, and
//! `the_list_is_every_include_from_outside_xtask` holds the list to every `#[path]` and
//! `include!` under `xtask/src` that names a file outside `xtask/`, so a fourth one that is
//! not listed fails rather than going unread.
//!
//! **Out of scope: xtask's integration tests.** `xtask/tests/release_server_gate.rs`
//! compiles `infra/relay/tests/common/settings_corpus.rs` by `#[path]`. It is a test
//! target, not the `cargo xtask` binary: it builds with dev-dependencies and only under
//! `cargo test`, so a crate it names reaches no `cargo xtask` run, and that file makes no
//! claim to name only `std`. The scan reads `xtask/src` only, for that reason.

use std::path::{Path, PathBuf};

/// Every file xtask compiles from another crate's source, from the repository root. Each
/// names nothing but `std` (see the module doc); `the_list_is_every_include_from_outside_xtask`
/// holds this list to the attributes themselves.
pub(crate) const STD_ONLY: &[&str] = &[
    // `wire_check::recorded_surface`: the one reader of a recorded wire surface.
    "core/wire/src/recorded_surface.rs",
    // `release_server::settings`: `kvaultd`'s reader of `vault.env`.
    "core/kvaultd/src/settings.rs",
    // `release_server::systemds_parser`: where systemd's own settings parser is.
    "infra/relay/tests/common/systemds_parser.rs",
];

/// The roots a path in a shared file may start from: the standard library, and the file's
/// own modules.
const ROOTS: &[&str] = &["std", "core", "alloc", "super", "self"];

/// Primitive types, whose associated items (`u8::MAX`, `str::from_utf8`) are written as a
/// lowercase path and name no crate.
const PRIMITIVES: &[&str] = &[
    "bool", "char", "str", "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32",
    "i64", "i128", "isize", "f32", "f64",
];

/// Keywords that can stand before a path (`return ::x::y()`, `as serde::X`, `impl
/// serde::X`): a word among these before `::` is not the path's first segment.
const KEYWORDS: &[&str] = &[
    "as", "break", "const", "continue", "dyn", "else", "enum", "extern", "fn", "for", "if",
    "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return",
    "static", "struct", "trait", "type", "unsafe", "use", "where", "while", "async", "await",
];

/// What a file compiles into itself, by the 1-based line it is written on.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Include {
    /// `#[path = "…"]`, in any spacing or under `cfg_attr`: the file it names.
    Path(String),
    /// `include!("…")`: the file it names.
    Macro(String),
    /// An out-of-line `mod name;` with no `#[path]` before it.
    Unpathed(String),
    /// A `path =` or `include!` whose argument is not a plain string literal.
    Opaque,
}

/// Every path in `source` that starts from a name other than [`ROOTS`]: its 1-based line and
/// the name, in file order. Empty for a file that names nothing but `std`.
///
/// Comments and string and char literals are read past, so a doc that names
/// `kvaultd::settings` is not a dependency. A `use` or `extern crate` is held by its root
/// (each root of a `{…}` group at the top). A path in code is held by the segment after a
/// leading `::`, or by its first segment when that is lowercase — a crate's name, never a
/// type's — and not a primitive. Whitespace between a segment and `::` does not end a path.
pub(crate) fn foreign_roots(source: &str) -> Vec<(usize, String)> {
    let code = code_only(source);
    let line_of = |at: usize| code[..at].iter().filter(|&&c| c == '\n').count() + 1;
    let mut found = Vec::new();
    // The `use` items, read once by root and then skipped by the path scan, whose `{a::b}`
    // groups are not path starts.
    let mut items: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    while i < code.len() {
        let Some((word, end)) = word_at(&code, i) else {
            i += 1;
            continue;
        };
        let item = word == "use"
            || (word == "extern" && word_at(&code, skip_space(&code, end)).is_some_and(|(w, _)| w == "crate"));
        if !item {
            i = end;
            continue;
        }
        let stop = code[end..].iter().position(|&c| c == ';').map_or(code.len(), |p| end + p);
        let text: String = code[end..stop].iter().collect();
        let text = text.trim().strip_prefix("crate ").map_or(text.trim(), str::trim);
        for root in tree_roots(text).into_iter().filter(|r| !ROOTS.contains(&r.as_str())) {
            found.push((line_of(i), root));
        }
        items.push((i, stop));
        i = stop;
    }
    let in_item = |at: usize| items.iter().any(|&(s, e)| (s..e).contains(&at));
    let mut i = 0;
    while i + 1 < code.len() {
        if code[i] != ':' || code[i + 1] != ':' {
            i += 1;
            continue;
        }
        let colons = i;
        i += 2;
        if in_item(colons) {
            continue;
        }
        let after = skip_space(&code, i);
        if code.get(after) == Some(&'<') {
            continue; // turbofish: generic arguments, not a path segment
        }
        match segment_before(&code, colons) {
            Before::Continues => {}
            Before::Leading => {
                if let Some((root, _)) = word_at(&code, after) {
                    if !ROOTS.contains(&root.as_str()) {
                        found.push((line_of(after), root));
                    }
                }
            }
            Before::First(at, word) => {
                let crate_like = word.starts_with(|c: char| c.is_ascii_lowercase() || c == '_');
                if crate_like && !ROOTS.contains(&word.as_str()) && !PRIMITIVES.contains(&word.as_str()) {
                    found.push((line_of(at), word));
                }
            }
        }
    }
    found.sort();
    found
}

/// What stands before a `::`.
enum Before {
    /// Nothing that can be a segment: the `::` begins a path (`::serde`, `(::x`, `= ::x`).
    Leading,
    /// A word that is the path's first segment, and where it starts.
    First(usize, String),
    /// The `::` is mid-path: after another segment, a `>` or a method's `.`.
    Continues,
}

fn segment_before(code: &[char], colons: usize) -> Before {
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    let Some(j) = (0..colons).rev().find(|&j| !code[j].is_whitespace()) else {
        return Before::Leading;
    };
    if code[j] == '>' {
        return Before::Continues;
    }
    if !ident(code[j]) {
        return Before::Leading;
    }
    let start = (0..=j).rev().take_while(|&k| ident(code[k])).last().unwrap_or(j);
    let word: String = code[start..=j].iter().collect();
    if KEYWORDS.contains(&word.as_str()) {
        return Before::Leading;
    }
    match (0..start).rev().find(|&k| !code[k].is_whitespace()) {
        Some(k) if code[k] == ':' && k > 0 && code[k - 1] == ':' => Before::Continues,
        Some(k) if matches!(code[k], '.' | '$' | '\'') => Before::Continues,
        _ => Before::First(start, word),
    }
}

/// Every file `source` compiles into itself, and every out-of-line `mod` it leaves to the
/// compiling crate to find, by line.
pub(crate) fn included_files(source: &str) -> Vec<(usize, Include)> {
    let code = code_only(source);
    let raw: Vec<char> = source.chars().collect();
    let line_of = |at: usize| code[..at].iter().filter(|&&c| c == '\n').count() + 1;
    // The literal whose opening quote is at `at` in the source, when there is one.
    let literal = |at: usize| {
        (raw.get(at) == Some(&'"')).then(|| {
            let end = (at + 1..raw.len()).find(|&k| raw[k] == '"').unwrap_or(raw.len());
            raw[at + 1..end].iter().collect::<String>()
        })
    };
    // Each attribute `#[…]` or `#![…]`: where it starts and ends, and whether it says `path =`.
    let mut attrs: Vec<(usize, usize)> = Vec::new();
    let mut found = Vec::new();
    let mut i = 0;
    while i < code.len() {
        if code[i] == '#' {
            let open = skip_space(&code, i + 1 + usize::from(code.get(i + 1) == Some(&'!')));
            if code.get(open) == Some(&'[') {
                let mut depth = 0;
                let close = (open..code.len())
                    .find(|&k| {
                        depth += i32::from(code[k] == '[') - i32::from(code[k] == ']');
                        depth == 0
                    })
                    .unwrap_or(code.len());
                attrs.push((i, close));
                let mut k = open;
                while k < close {
                    match word_at(&code, k) {
                        Some((w, end)) if w == "path" => {
                            let eq = skip_space(&code, end);
                            if code.get(eq) == Some(&'=') {
                                // The literal is blank in `code`; find its quote in the source.
                                let at = skip_space(&raw, eq + 1);
                                let what = literal(at).map_or(Include::Opaque, Include::Path);
                                found.push((line_of(k), what));
                            }
                            k = end;
                        }
                        Some((_, end)) => k = end,
                        None => k += 1,
                    }
                }
                i = close;
                continue;
            }
        }
        i += 1;
    }
    let mut i = 0;
    while i < code.len() {
        let Some((word, end)) = word_at(&code, i) else {
            i += 1;
            continue;
        };
        if word == "include" && code.get(skip_space(&code, end)) == Some(&'!') {
            let paren = skip_space(&code, skip_space(&code, end) + 1);
            if code.get(paren) == Some(&'(') {
                let at = skip_space(&raw, paren + 1);
                found.push((line_of(i), literal(at).map_or(Include::Opaque, Include::Macro)));
            }
        } else if word == "mod" {
            let name_at = skip_space(&code, end);
            if let Some((name, name_end)) = word_at(&code, name_at) {
                if code.get(skip_space(&code, name_end)) == Some(&';') && !path_attr_before(&code, &attrs, i) {
                    found.push((line_of(i), Include::Unpathed(name)));
                }
            }
        }
        i = end;
    }
    found.sort_by_key(|(line, _)| *line);
    found
}

/// Whether the item whose keyword is at `at` carries a `path =` attribute: one of the
/// attributes directly before it, past any visibility.
fn path_attr_before(code: &[char], attrs: &[(usize, usize)], at: usize) -> bool {
    let mut j = at;
    loop {
        let Some(k) = (0..j).rev().find(|&k| !code[k].is_whitespace()) else {
            return false;
        };
        if let Some(&(start, _)) = attrs.iter().find(|&&(_, end)| end == k) {
            let text: String = code[start..=k].iter().collect();
            if text.split(|c: char| !(c.is_alphanumeric() || c == '_')).any(|w| w == "path") {
                return true;
            }
            j = start;
        } else if code[k] == ')' {
            // `pub(crate)`: step past the group and the `pub` before it.
            j = (0..k).rev().find(|&m| code[m] == '(').unwrap_or(0);
        } else if word_ending_at(code, k).as_deref() == Some("pub") {
            j = k + 1 - 3;
        } else {
            return false;
        }
    }
}

fn word_ending_at(code: &[char], end: usize) -> Option<String> {
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    let start = (0..=end).rev().take_while(|&k| ident(code[k])).last()?;
    Some(code[start..=end].iter().collect())
}

/// Every finding for `file` and each file it compiles into itself, followed to the end: a
/// path from outside `std`, an out-of-line `mod` with no `#[path]`, an include whose
/// argument cannot be read, or a file that cannot be read. Empty when all of it names
/// nothing but `std`.
pub(crate) fn check(file: &Path) -> Vec<String> {
    let mut findings = Vec::new();
    let mut seen: Vec<PathBuf> = Vec::new();
    let mut next = vec![file.to_path_buf()];
    while let Some(file) = next.pop() {
        if seen.contains(&file) {
            continue;
        }
        seen.push(file.clone());
        let shown = file.display();
        let text = match std::fs::read_to_string(&file) {
            Ok(t) => t,
            Err(e) => {
                findings.push(format!("{shown}: cannot be read, so it cannot be held: {e}"));
                continue;
            }
        };
        for (line, root) in foreign_roots(&text) {
            findings.push(format!("{shown}:{line}: names `{root}`, which is not `std`"));
        }
        let dir = file.parent().unwrap_or(Path::new("."));
        for (line, include) in included_files(&text) {
            match include {
                Include::Path(p) | Include::Macro(p) => next.push(dir.join(p)),
                Include::Unpathed(name) => findings.push(format!(
                    "{shown}:{line}: `mod {name};` has no `#[path]`, so where it loads from \
                     depends on the crate compiling this file; give it a `#[path]` or write it inline"
                )),
                Include::Opaque => findings.push(format!(
                    "{shown}:{line}: a `path =` or `include!` that is not a plain string, so the \
                     file it names cannot be held"
                )),
            }
        }
    }
    findings
}

/// `source` with every comment and every string and char literal's characters replaced by
/// spaces, newlines kept, so positions and line numbers are the source's.
fn code_only(source: &str) -> Vec<char> {
    let s: Vec<char> = source.chars().collect();
    let mut out = s.clone();
    let blank = |out: &mut Vec<char>, from: usize, to: usize| {
        for c in &mut out[from..to.min(s.len())] {
            if *c != '\n' {
                *c = ' ';
            }
        }
    };
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    let mut i = 0;
    while i < s.len() {
        let rest = &s[i..];
        if rest.starts_with(&['/', '/']) {
            let end = rest.iter().position(|&c| c == '\n').map_or(s.len(), |p| i + p);
            blank(&mut out, i, end);
            i = end;
        } else if rest.starts_with(&['/', '*']) {
            let (mut depth, mut j) = (1, i + 2);
            while j < s.len() && depth > 0 {
                if s[j..].starts_with(&['/', '*']) {
                    (depth, j) = (depth + 1, j + 2);
                } else if s[j..].starts_with(&['*', '/']) {
                    (depth, j) = (depth - 1, j + 2);
                } else {
                    j += 1;
                }
            }
            blank(&mut out, i, j);
            i = j;
        } else if s[i] == 'r'
            && (i == 0 || !ident(s[i - 1]) || (s[i - 1] == 'b' && (i == 1 || !ident(s[i - 2]))))
            && rest[1..].iter().position(|&c| c != '#').is_some_and(|p| rest[1 + p] == '"')
        {
            let hashes = rest[1..].iter().take_while(|&&c| c == '#').count();
            let body = i + 2 + hashes;
            let mut close = vec!['"'];
            close.extend(std::iter::repeat_n('#', hashes));
            let end = (body..s.len()).find(|&j| s[j..].starts_with(&close)).map_or(s.len(), |j| j + close.len());
            blank(&mut out, i + 1, end);
            i = end;
        } else if s[i] == '"' {
            let mut j = i + 1;
            while j < s.len() && s[j] != '"' {
                j += if s[j] == '\\' { 2 } else { 1 };
            }
            blank(&mut out, i, j + 1);
            i = j + 1;
        } else if s[i] == '\'' && rest.get(1) == Some(&'\\') {
            let end = (i + 3..s.len()).find(|&j| s[j] == '\'').map_or(s.len(), |j| j + 1);
            blank(&mut out, i, end);
            i = end;
        } else if s[i] == '\'' && rest.get(2) == Some(&'\'') {
            blank(&mut out, i, i + 3);
            i += 3;
        } else {
            i += 1;
        }
    }
    out
}

/// The identifier that starts at `at`, and where it ends, when one does: not the tail of a
/// longer one.
fn word_at(code: &[char], at: usize) -> Option<(String, usize)> {
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    if at >= code.len() || !(code[at].is_alphabetic() || code[at] == '_') || (at > 0 && ident(code[at - 1])) {
        return None;
    }
    let end = (at..code.len()).find(|&j| !ident(code[j])).unwrap_or(code.len());
    Some((code[at..end].iter().collect(), end))
}

fn skip_space(code: &[char], at: usize) -> usize {
    (at..code.len()).find(|&j| !code[j].is_whitespace()).unwrap_or(code.len())
}

/// The roots of a use tree: `std::a::{b, c}` has `std`; `::serde_json::Value` has
/// `serde_json`; `{std::fs, serde::Serialize}` has both.
fn tree_roots(tree: &str) -> Vec<String> {
    let tree = tree.trim().trim_start_matches("::").trim_start();
    if let Some(group) = tree.strip_prefix('{') {
        let group = group.strip_suffix('}').unwrap_or(group);
        let (mut depth, mut from, mut roots) = (0, 0, Vec::new());
        for (j, c) in group.char_indices() {
            match c {
                '{' => depth += 1,
                '}' => depth -= 1,
                ',' if depth == 0 => {
                    roots.extend(tree_roots(&group[from..j]));
                    from = j + 1;
                }
                _ => {}
            }
        }
        roots.extend(tree_roots(&group[from..]));
        return roots;
    }
    let root: String = tree.chars().take_while(|&c| c.is_alphanumeric() || c == '_').collect();
    if root.is_empty() { Vec::new() } else { vec![root] }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn repo() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).parent().expect("xtask has a parent").to_path_buf()
    }

    /// Each file xtask compiles from another crate, and every file it compiles into itself,
    /// names nothing but `std`, read from the tree.
    #[test]
    fn every_file_xtask_compiles_by_path_names_only_std() {
        for file in STD_ONLY {
            let findings = check(&repo().join(file));
            assert!(
                findings.is_empty(),
                "{file} is compiled into xtask by `#[path]` and must name nothing but `std`, \
                 `core`, `alloc`, `super` or `self`:\n{}",
                findings.join("\n")
            );
        }
    }

    /// The list is every `#[path]` and `include!` under `xtask/src` that names a file
    /// outside `xtask/`, resolved from the file it is in: one that is not listed would go
    /// unread, and a listed file nothing includes would be held for no reason. Reads
    /// `xtask/src` only: `xtask/tests/` is out of scope (see the module doc).
    #[test]
    fn the_list_is_every_include_from_outside_xtask() {
        let root = repo().canonicalize().unwrap();
        let mut included = BTreeSet::new();
        let mut dirs = vec![root.join("xtask/src")];
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    dirs.push(path);
                    continue;
                }
                if path.extension().is_none_or(|e| e != "rs") {
                    continue;
                }
                for (_, include) in included_files(&std::fs::read_to_string(&path).unwrap()) {
                    let target = match include {
                        Include::Path(t) | Include::Macro(t) => t,
                        Include::Unpathed(_) => continue,
                        Include::Opaque => panic!("{}: an include that is not a plain string", path.display()),
                    };
                    let file = dir.join(&target).canonicalize().unwrap_or_else(|e| panic!("{target}: {e}"));
                    let rel = file.strip_prefix(&root).expect("an include inside the repository");
                    if !rel.starts_with("xtask") {
                        included.insert(rel.to_string_lossy().replace('\\', "/"));
                    }
                }
            }
        }
        let listed: BTreeSet<String> = STD_ONLY.iter().map(|s| s.to_string()).collect();
        assert_eq!(included, listed, "the includes from outside xtask/ (left) are not `STD_ONLY` (right)");
    }

    /// Every spelling of a `path` attribute is read, and nothing that only looks like one.
    #[test]
    fn every_spelling_of_a_path_attribute_is_read() {
        let src = r##"//! Not one: #[path = "doc.rs"] mod doc;
#[path="tight.rs"]
mod tight;
#[ path = "spaced.rs" ]
pub(crate) mod spaced;
#[cfg_attr(unix, path = "cfg.rs")]
mod cfg;
#[doc = "x"]
#[path = r"raw.rs"]
mod raw;
fn f() -> String { let path = "p"; format!("{path}{x}", x = path) }
include ! ( "inc.rs" );
const S: &str = "#[path = \"string.rs\"]";
mod inline { }
mod bare;
"##;
        assert_eq!(
            included_files(src),
            [
                (2, Include::Path("tight.rs".into())),
                (4, Include::Path("spaced.rs".into())),
                (6, Include::Path("cfg.rs".into())),
                (9, Include::Opaque),
                (12, Include::Macro("inc.rs".into())),
                (15, Include::Unpathed("bare".into())),
            ]
        );
    }

    /// A planted `use serde_json` in a scratch copy of each listed file is found, by line:
    /// the import both crates link, which compiles on both sides and so is the one the
    /// build cannot catch.
    #[test]
    fn a_planted_use_serde_json_in_a_scratch_copy_is_found() {
        let scratch = tempfile::tempdir().unwrap();
        for file in STD_ONLY {
            let text = std::fs::read_to_string(repo().join(file)).unwrap();
            let copy = scratch.path().join(Path::new(file).file_name().unwrap());
            std::fs::write(&copy, format!("{text}\nuse serde_json::Value;\n")).unwrap();
            let planted = std::fs::read_to_string(&copy).unwrap();
            let line = planted.lines().count();
            assert_eq!(foreign_roots(&planted), [(line, "serde_json".to_string())], "{file}");
            assert_eq!(
                check(&copy),
                [format!("{}:{line}: names `serde_json`, which is not `std`", copy.display())],
                "{file}"
            );
        }
    }

    /// What a shared file compiles into itself is held as the file is: a `#[path]` module
    /// and an `include!` are followed into the files they name, and an out-of-line `mod`
    /// with no `#[path]` is refused.
    #[test]
    fn what_a_shared_file_pulls_in_is_held_too() {
        let scratch = tempfile::tempdir().unwrap();
        let dir = scratch.path();
        let put = |name: &str, text: &str| std::fs::write(dir.join(name), text).unwrap();
        put("a.rs", "#[path = \"b.rs\"]\nmod b;\ninclude!(\"c.rs\");\nmod d;\n#[path = \"gone.rs\"]\nmod gone;\n");
        put("b.rs", "use serde_json::Value;\n#[path = \"a.rs\"]\nmod again;\n");
        put("c.rs", "fn f() { serde::x(); }\n");
        let findings = check(&dir.join("a.rs")).join("\n");
        for want in [
            "b.rs:1: names `serde_json`",
            "c.rs:1: names `serde`",
            "a.rs:4: `mod d;` has no `#[path]`",
            "gone.rs: cannot be read",
        ] {
            assert!(findings.contains(want), "{want} not in:\n{findings}");
        }
        assert_eq!(findings.lines().count(), 4, "{findings}");
    }

    /// Every spelling of a dependency is found: a leading `::`, a group, `crate`, `extern
    /// crate`, a `use` in a body, and a path written in code, an attribute, a type or a
    /// qualified path — with whitespace before `::` or not, and past a lifetime, a label or
    /// a char literal of a quote.
    #[test]
    fn every_spelling_of_a_crate_outside_std_is_found() {
        let found = |src: &str| foreign_roots(src).into_iter().map(|(_, r)| r).collect::<Vec<_>>();
        assert_eq!(found("use ::serde_json::Value;"), ["serde_json"]);
        assert_eq!(found("use {std::fs, serde::Serialize};"), ["serde"]);
        assert_eq!(found("pub(crate) use crate::wire::X;"), ["crate"]);
        assert_eq!(found("extern crate serde_json;"), ["serde_json"]);
        assert_eq!(found("fn f() { use serde_json::Value; }"), ["serde_json"]);
        assert_eq!(found("fn f() { serde_json::json!(1); }"), ["serde_json"]);
        assert_eq!(found("fn f() -> String { ::serde_json::to_string(&1).unwrap() }"), ["serde_json"]);
        assert_eq!(found("fn f() -> String { :: serde_json :: to_string(&1).unwrap() }"), ["serde_json"]);
        assert_eq!(found("#[derive(::serde::Serialize)] struct S;"), ["serde"]);
        assert_eq!(found("#[derive(serde::Serialize)]\nstruct S;"), ["serde"]);
        assert_eq!(found("fn f() { let _ = serde_json ::to_string(&1); }"), ["serde_json"]);
        assert_eq!(found("fn f(x: ::serde_json::Value, _: [::serde::X; 1]) {}"), ["serde", "serde_json"]);
        assert_eq!(found("fn f() -> u8 { return ::serde::x(); }"), ["serde"]);
        assert_eq!(found("fn f(_: Vec<serde_json::Value>) {}"), ["serde_json"]);
        assert_eq!(found("fn f() { <u8 as serde::Serialize>::serialize; }"), ["serde"]);
        assert_eq!(found("impl serde::Serialize for S {}"), ["serde"]);
        assert_eq!(found("fn f<'a>(x: &'a str) -> &'a str { x }\nfn g() { serde_json::x(); }"), ["serde_json"]);
        assert_eq!(found("const Q: u8 = b'\"'; fn g() { serde_json::x(); }"), ["serde_json"]);
        assert_eq!(found("fn g() { 'a: loop { break 'a; } serde_json::x(); }"), ["serde_json"]);
        assert_eq!(foreign_roots("\n\nfn f() { let _ = kvaultd::settings::x(); }"), [(3, "kvaultd".to_string())]);
    }

    /// A local module or a `std` alias named like a crate does not exempt the name: the
    /// check is by name, so a shared file writes its paths from `std` (see the module doc).
    #[test]
    fn a_local_name_does_not_exempt_a_path_from_being_held() {
        let found = |src: &str| foreign_roots(src).into_iter().map(|(_, r)| r).collect::<Vec<_>>();
        assert_eq!(found("mod serde_json {}\nfn f() { serde_json::x(); }"), ["serde_json"]);
        assert_eq!(found("use std::{io as serde_json};\nfn f() { serde_json::x(); }"), ["serde_json"]);
        assert_eq!(found("use std::path;\nfn f() { path::Path::new(\"\"); }"), ["path"]);
    }

    /// What names only `std` reads clean: the standard library and the file's own modules
    /// by any spelling, primitives, turbofish, methods, and a crate's name inside a
    /// comment, a doc, a string or past a char literal of a quote.
    #[test]
    fn what_names_only_std_is_not_held() {
        let src = r##"//! Read by `kvaultd::settings::env_file_pairs`.
use std::path::{self, Path};
use std::{fs, io::Read};
/* serde_json::Value, /* nested */ still a comment */
fn f(s: &str) -> usize {
    let q = '"'; let e = '\''; let _ = (q, e);
    let _ = "serde_json::to_string"; let _ = r#"serde::x "quoted""#;
    let _ = std::path::PathBuf::new(); let _ = ::std::fs::read("x");
    let _: Vec<u8> = s.bytes().collect::<Vec<_>>();
    let _ = Vec::<u8>::new(); let _ = <u8 as std::str::FromStr>::from_str("1");
    let _ = core::mem::size_of::<u8>() + alloc_free(s);
    u8::MAX as usize + str::len(s) + std :: cmp :: max(1, 2)
}
fn alloc_free(_: &str) -> usize { 0 }
mod tests { use super::*; fn g() { let _ = self::super::f(""); let _ = super::alloc_free; } }
"##;
        assert_eq!(foreign_roots(src), []);
        assert_eq!(included_files(src), []);
    }
}
