// SPDX-License-Identifier: AGPL-3.0-or-later
//! The files xtask compiles by `#[path]` from another crate's source, and the test that holds
//! each to naming nothing but `std` (kotton #306).
//!
//! xtask compiles three readers from their owners' source rather than linking the owner:
//! kotton-wire's reader of a recorded surface (`wire_check::recorded_surface`), `kvaultd`'s
//! reader of its settings file (`release_server::settings`) and the finder of systemd's
//! parser (`release_server::systemds_parser`). A dependency on the owner would build its
//! whole closure into every `cargo xtask`; what lets one source compile in both crates is
//! that it names nothing but `std`.
//!
//! **What held that claim before this file was the build, and only half of it.** A
//! `use crate::…` in a shared file fails xtask's build. A name both crates already link —
//! `serde_json`, which xtask and kotton-wire both depend on — compiles on both sides, and
//! the claim rots silently: the next change to xtask's dependencies, or to the owner's, is
//! what breaks, far from the line that caused it. So [`foreign_roots`] reads each file as
//! text and finds every path that starts anywhere but `std`, `core`, `alloc`, `super` or
//! `self`: each `use` (and `extern crate`), and each path written inline in code, since
//! `serde_json::to_string(..)` in a function body is the same dependency as the `use`.
//!
//! **A test, not a guard in the build.** The build cannot say this: it resolves names
//! against whatever the compiling crate links, and both crates link more than `std`. The
//! check is over the source text, before any crate's dependencies are in the picture, so
//! it runs once in `cargo test -p xtask` and needs no compile of the owners.
//!
//! **The list cannot miss an include.** [`STD_ONLY`] is the one list; the includes are in
//! `wire_check.rs` and `release_server.rs`, each beside the module that uses it, and a test
//! here holds the list to every `#[path]` attribute under `xtask/src`, so a fourth include
//! that is not listed fails rather than going unread.

/// Every file xtask compiles by `#[path]` from another crate's source, from the repository
/// root. Each names nothing but `std` (see the module doc); the test
/// `the_list_is_every_path_include_in_xtask` holds this list to the attributes themselves.
#[cfg(test)]
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

/// Every path in `source` that starts from a name other than [`ROOTS`]: its 1-based line and
/// the name, in file order. Empty for a file that names nothing but `std`.
///
/// Comments and string and char literals are read past, so a doc that names
/// `kvaultd::settings` is not a dependency. A `use` or `extern crate` is held by its root
/// (each root of a `{…}` group at the top). A path written in code is held by its first
/// segment when that segment is lowercase — a crate's name, never a type's — and is not a
/// primitive, a `mod` the file declares, or a name a `std` import brought in
/// (`use std::path; path::Path`).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn foreign_roots(source: &str) -> Vec<(usize, String)> {
    let code = code_only(source);
    let line_of = |at: usize| code[..at].iter().filter(|&&c| c == '\n').count() + 1;
    let mut found = Vec::new();
    let mut local: Vec<String> = Vec::new();
    // Byte ranges (in chars) of the `use` items, read once by root and then skipped by the
    // inline scan, whose `{a::b}` groups are not path starts.
    let mut items: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    while i < code.len() {
        let Some((word, end)) = word_at(&code, i) else {
            i += 1;
            continue;
        };
        match word.as_str() {
            "use" | "extern" if word == "use" || word_at(&code, skip_space(&code, end)).is_some_and(|(w, _)| w == "crate") => {
                let stop = code[end..].iter().position(|&c| c == ';').map_or(code.len(), |p| end + p);
                let item: String = code[end..stop].iter().collect();
                let item = item.trim().strip_prefix("crate ").map_or(item.trim(), str::trim);
                let roots = tree_roots(item);
                if roots.iter().all(|r| ROOTS.contains(&r.as_str())) {
                    local.extend(idents(item));
                }
                for root in roots.into_iter().filter(|r| !ROOTS.contains(&r.as_str())) {
                    found.push((line_of(i), root));
                }
                items.push((i, stop));
                i = stop;
            }
            "mod" => {
                if let Some((name, _)) = word_at(&code, skip_space(&code, end)) {
                    local.push(name);
                }
                i = end;
            }
            _ => i = end,
        }
    }
    let mut i = 0;
    while i < code.len() {
        if let Some(&(_, stop)) = items.iter().find(|&&(s, _)| s == i) {
            i = stop;
            continue;
        }
        let Some((word, end)) = word_at(&code, i) else {
            i += 1;
            continue;
        };
        let after_dot = i > 0 && matches!(code[i - 1], '.' | ':');
        let path = code.get(end..end + 2) == Some(&[':', ':'][..]) && code.get(end + 2) != Some(&'<');
        let crate_like = word.starts_with(|c: char| c.is_ascii_lowercase() || c == '_');
        if path
            && crate_like
            && !after_dot
            && !ROOTS.contains(&word.as_str())
            && !PRIMITIVES.contains(&word.as_str())
            && !local.contains(&word)
        {
            found.push((line_of(i), word));
        }
        i = end;
    }
    found.sort();
    found
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

/// Every identifier in a use tree: the names it may bring into scope.
fn idents(tree: &str) -> Vec<String> {
    tree.split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    fn repo() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).parent().expect("xtask has a parent").to_path_buf()
    }

    /// Each file xtask compiles by `#[path]` names nothing but `std`, read from the tree.
    #[test]
    fn every_file_xtask_compiles_by_path_names_only_std() {
        for file in STD_ONLY {
            let text = std::fs::read_to_string(repo().join(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
            let found = foreign_roots(&text);
            assert!(
                found.is_empty(),
                "{file} is compiled into xtask by `#[path]` and must name nothing but `std`, \
                 `core`, `alloc`, `super` or `self`; it names {found:?} (line, root)"
            );
        }
    }

    /// The list is every `#[path]` include under `xtask/src`, resolved from the file it is
    /// in: an include that is not listed would go unread, and a listed file nothing
    /// includes would be held for no reason.
    #[test]
    fn the_list_is_every_path_include_in_xtask() {
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
                for line in std::fs::read_to_string(&path).unwrap().lines() {
                    let Some(rest) = line.trim().strip_prefix("#[path = \"") else { continue };
                    let target = &rest[..rest.find('"').expect("a closed path attribute")];
                    let file = dir.join(target).canonicalize().unwrap_or_else(|e| panic!("{target}: {e}"));
                    let rel = file.strip_prefix(&root).expect("an include inside the repository");
                    included.insert(rel.to_string_lossy().replace('\\', "/"));
                }
            }
        }
        let listed: BTreeSet<String> = STD_ONLY.iter().map(|s| s.to_string()).collect();
        assert_eq!(included, listed, "the `#[path]` includes under xtask/src (left) are not `STD_ONLY` (right)");
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
        }
    }

    /// Every spelling of a dependency is found: a leading `::`, a group, `crate`, `extern
    /// crate`, and a path written inline in code or an attribute.
    #[test]
    fn every_spelling_of_a_crate_outside_std_is_found() {
        let found = |src: &str| foreign_roots(src).into_iter().map(|(_, r)| r).collect::<Vec<_>>();
        assert_eq!(found("use ::serde_json::Value;"), ["serde_json"]);
        assert_eq!(found("use {std::fs, serde::Serialize};"), ["serde"]);
        assert_eq!(found("pub(crate) use crate::wire::X;"), ["crate"]);
        assert_eq!(found("extern crate serde_json;"), ["serde_json"]);
        assert_eq!(found("fn f() -> String { serde_json::json!(null).to_string() }"), ["serde_json"]);
        assert_eq!(found("#[derive(serde::Serialize)]\nstruct S;"), ["serde"]);
        assert_eq!(foreign_roots("\n\nfn f() { let _ = kvaultd::settings::x(); }"), [(3, "kvaultd".to_string())]);
    }

    /// What names only `std` reads clean: the standard library and the file's own modules
    /// by any spelling, primitives, turbofish, a module a `std` import brought in, and a
    /// crate's name inside a comment, a doc, a string or past a char literal of a quote.
    #[test]
    fn what_names_only_std_is_not_held() {
        let src = r##"//! Read by `kvaultd::settings::env_file_pairs`.
use std::path::{self, Path};
use std::{fs, io::Read};
/* serde_json::Value, /* nested */ still a comment */
fn f(s: &str) -> usize {
    let q = '"'; let e = '\''; let _ = (q, e);
    let _ = "serde_json::to_string"; let _ = r#"serde::x "quoted""#;
    let _ = path::PathBuf::new(); let _ = fs::read("x");
    let _: Vec<u8> = s.bytes().collect::<Vec<_>>();
    let _ = core::mem::size_of::<u8>() + alloc_free(s);
    u8::MAX as usize + str::len(s) + std::cmp::max(1, 2)
}
fn alloc_free(_: &str) -> usize { 0 }
mod tests { use super::*; fn g() { let _ = self::super::f(""); let _ = tests::h; } fn h() {} }
"##;
        assert_eq!(foreign_roots(src), []);
    }
}
