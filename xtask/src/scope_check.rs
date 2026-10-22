// SPDX-License-Identifier: AGPL-3.0-or-later
//! `scope-check`: a declared scope names verbs that exist on the channel.
//!
//! ## What a scope is
//!
//! `UserRequest::Authenticate { scope }` lets a caller declare the verbs it
//! intends to use. `kuserd` holds the list as an allow-list and answers anything
//! outside it with `UserResponse::NotInScope`. It is *self*-limitation — the
//! ceiling is still the connection's trust origin, so a scope can only ever
//! subtract — which is exactly why nothing else catches a wrong one: asking for
//! too little is silent until the message a caller actually needed is refused,
//! and asking for something that does not exist is silent forever.
//!
//! ## The failure this is pointed at
//!
//! Measured 2026-08-25. `kuid` declared eight verbs. Four of them —
//! `SurfaceOpen`, `SurfaceCommit`, `SurfaceClose`, `SurfaceResize` — are
//! `KuidRequest` variants that RFC-0082 moved to channel 3 on 2026-08-23, so
//! they cannot be named on the user channel at all. They were not rejected; they
//! were compared against arriving variant names and never matched anything.
//!
//! **A scope is a list of strings, so a name with no referent reads exactly like
//! a name with one.** That is the class this check closes, and it is the half a
//! test cannot hold: the caller's own test can only assert about the names the
//! caller already believes in.
//!
//! ## What this check cannot see
//!
//! The omission direction — a verb a caller *sends* and does not declare, which
//! is the half that had `kuid` never tearing down a dismissed app's runner. That
//! needs the caller's `send` sites, which are values rather than names, so it
//! belongs beside them: `core/kuid/src/main.rs`'s `scope_tests` is the pair to
//! this file. Neither is sufficient alone and this doc says so rather than
//! leaving the gap to be discovered.
//!
//! It also assumes every declared scope is a **user-channel** scope. That is
//! true because `Authenticate` is a `UserRequest` and no other channel has a
//! scope concept — if one grows one, this check is wrong and must learn the
//! channel a const belongs to rather than assuming.

use std::path::{Path, PathBuf};

/// Where the channel's variant names come from.
const REQUEST_SRC: &str = "core/wire/src/ipc/request.rs";
const REQUEST_ENUM: &str = "UserRequest";

/// Directories that may declare a scope.
use crate::tree::CODE_ROOTS as ROOTS;

/// The convention this check reads: a declared scope is a `const …_SCOPE:
/// &[&str]`.
///
/// Stated here rather than inferred, because a check that guesses at a shape is
/// a check that goes quiet when someone writes the same list a different way.
/// `gates.md` carries the same sentence for a reader who never opens this file.
const SUFFIX: &str = "_SCOPE";

pub fn scope_check() {
    let Ok(src) = std::fs::read_to_string(Path::new(REQUEST_SRC)) else {
        eprintln!("scope-check: could not read {REQUEST_SRC}. Run from the workspace root.");
        std::process::exit(1);
    };
    let variants = crate::wire_check::parse_enum_public(&src, REQUEST_ENUM);
    if variants.is_empty() {
        eprintln!(
            "scope-check: parsed no variants out of `{REQUEST_ENUM}` in {REQUEST_SRC}, which \
             cannot be true. Either the enum moved or the parser is broken, and in both cases \
             this check would pass every scope by knowing no verbs at all."
        );
        std::process::exit(1);
    }
    let known: Vec<String> = variants.into_iter().map(|v| v.name).collect();

    let mut files = Vec::new();
    for root in ROOTS {
        collect_rs(Path::new(root), &mut files);
    }
    if files.is_empty() {
        eprintln!(
            "scope-check: found no Rust sources under {ROOTS:?}. Run from the workspace root — \
             this check has not looked at anything."
        );
        std::process::exit(1);
    }

    let mut declarations = 0usize;
    let mut entries = 0usize;
    let mut bad: Vec<(String, String, String)> = Vec::new(); // const, entry, file

    for path in &files {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for (name, names) in scopes_in(&text) {
            declarations += 1;
            for entry in names {
                entries += 1;
                if !known.contains(&entry) {
                    bad.push((name.clone(), entry, display(path)));
                }
            }
        }
    }

    if declarations == 0 {
        eprintln!(
            "scope-check: found no `const …{SUFFIX}: &[&str]` declaration anywhere under \
             {ROOTS:?}. Either every caller stopped declaring a scope — which would mean every \
             connection asks for the whole channel — or this check no longer recognises how one \
             is written. Both are findings; neither is a pass."
        );
        std::process::exit(1);
    }

    if bad.is_empty() {
        println!(
            "scope-check: OK — {entries} scope {} across {declarations} declaration{} name live \
             `{REQUEST_ENUM}` variants.",
            if entries == 1 { "entry" } else { "entries" },
            if declarations == 1 { "" } else { "s" },
        );
        return;
    }

    eprintln!("scope-check: a declared scope names a verb this channel does not have.\n");
    for (name, entry, file) in &bad {
        eprintln!("  {file}: {name} declares \"{entry}\" — no such `{REQUEST_ENUM}` variant");
    }
    eprintln!(
        "\nA scope entry is matched against `variant_name()` on each arriving request, so an \
         entry that names nothing is never compared to anything: it neither grants nor refuses, \
         and it reads to the next person as authority this caller holds. The usual cause is a \
         variant that moved to another channel and left its scope entry behind.\n\nRemove it, \
         or correct it to the verb the caller actually sends."
    );
    std::process::exit(1);
}

/// Every `const …_SCOPE: &[&str] = &[ … ];` in one file, as (const name, entries).
///
/// Brace-blind and line-based, which is safe here only because the shape is
/// fixed: the declaration ends at the first `];`. A scope built by a function
/// rather than declared as a const is invisible to this, and `gates.md` states
/// the convention so that stays a choice rather than an accident.
fn scopes_in(text: &str) -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        let t = line.trim();
        if t.starts_with("//") {
            continue;
        }
        let Some(rest) = t.strip_prefix("const ") else {
            continue;
        };
        let Some((name, tail)) = rest.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if !name.ends_with(SUFFIX) || !tail.contains("&[&str]") {
            continue;
        }
        let mut body = tail.to_string();
        while !body.contains("];") {
            match lines.next() {
                Some(next) => {
                    body.push('\n');
                    body.push_str(next);
                }
                None => break,
            }
        }
        out.push((name.to_string(), string_literals(&body)));
    }
    out
}

/// The `"…"` literals in a declaration body.
///
/// No escape handling: a variant name is an identifier, so a scope entry that
/// needed an escape would already be naming something that cannot exist.
fn string_literals(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        if c != '"' {
            continue;
        }
        let mut lit = String::new();
        for c in chars.by_ref() {
            if c == '"' {
                break;
            }
            lit.push(c);
        }
        out.push(lit);
    }
    out
}

fn display(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            let name = p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            if name == "target" || name == ".git" {
                continue;
            }
            collect_rs(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}
