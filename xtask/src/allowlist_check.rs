// SPDX-License-Identifier: AGPL-3.0-or-later
//! `allowlist-check`: the allowlist's element is the key type.
//!
//! The live allowlist a peer handshake consults is a set of `kotton_ed25519::VerifyingKey`,
//! whose one constructor, `VerifyingKey::from_bytes`, is the Ed25519 rule for a key. So no
//! insert of raw bytes into it compiles: a key is put on it only once the rule admitted its
//! bytes, at every insert alike. The compiler holds each insert to the set's declared type;
//! this check holds the declaration, which is the one thing the compiler takes as given.
//!
//! `ed25519-check` holds the signature checks; this holds what a set of keys is made of.
//!
//! ## What it checks
//!
//! Over every `.rs` file under the code roots (`tree::CODE_ROOTS`), tests included, reading
//! each line without its whitespace and skipping comment lines:
//!
//! 1. **The declarations** ([`DECLARATIONS`]): the field each holder of the live set keeps it
//!    in is declared as `RwLock<HashSet<E>>` with `E` the key type, in every place the file
//!    spells that name with that type, and at least once. The three holders are the device's
//!    reachability state, which makes the set and hands it out, the TLS verifier, and the
//!    door; every set a handshake reads is one of these fields, and every handle to it is
//!    tied to their type by the compiler. A declaration that moved or was renamed is a
//!    finding too, so the list says what the tree holds.
//! 2. **No live set of byte arrays**: no `RwLock<HashSet<[u8; N]>>` is declared anywhere
//!    under the code roots, so a second allowlist of bytes cannot be added beside the typed
//!    one.
//! 3. **`VerifyingKey` is the rule's** in each file of [`DECLARATIONS`]: the file imports it
//!    from `kotton_crypto::ed25519` or `kotton_ed25519`, or spells it in full, and imports no
//!    `ed25519_dalek::VerifyingKey`.
//!
//! ## What it does not read
//!
//! It reads text, line by line: a declaration split across lines, a type alias that hides
//! the set, or a set behind another lock is outside rule 2. Rule 1 does not depend on that
//! reach: a holder's field is the type the compiler ties every handle to.

use std::path::Path;

use crate::user_database_check::{rel, walk};

/// Each holder of the live allowlist, by file and the name it keeps the set under.
pub(crate) const DECLARATIONS: &[(&str, &str)] = &[
    // Where the set is made and every handle to it handed out.
    ("core/peer/src/reachability.rs", "paired_keys"),
    // What the TLS verifier reads at every handshake.
    ("core/net/src/provider/transport/quic/tls.rs", "allowed_keys"),
    // What a door reads at every connection.
    ("core/net/src/provider/transport/admits.rs", "keys"),
];

/// The key type, as a declaration may spell it.
const KEY_TYPE: &[&str] = &["VerifyingKey", "kotton_crypto::ed25519::VerifyingKey", "kotton_ed25519::VerifyingKey"];

/// The imports that make `VerifyingKey` the rule's type in a file.
const KEY_IMPORTS: &[&str] = &["usekotton_crypto::ed25519::", "usekotton_ed25519::"];

/// This file, whose tests spell what it refuses.
const THIS: &str = "xtask/src/allowlist_check.rs";

pub fn run(root: &Path) {
    let (count, found) = findings(root);
    if count == 0 {
        eprintln!("allowlist-check: read no `.rs` file under the code roots. Run from the workspace root.");
        std::process::exit(1);
    }
    if found.is_empty() {
        println!("{}", ok_line(count));
        return;
    }
    for f in &found {
        eprintln!("allowlist-check: {f}");
    }
    eprintln!("{}", failure_footer());
    std::process::exit(1);
}

/// The line printed when the tree holds the rule.
fn ok_line(count: usize) -> String {
    let holders: Vec<String> = DECLARATIONS.iter().map(|(f, n)| format!("{f} ({n})")).collect();
    format!(
        "allowlist-check: OK: {count} source file(s); the allowlist's element is kotton_ed25519::VerifyingKey \
         in each of its holders, {}, and no live set of byte arrays is declared.",
        holders.join(", ")
    )
}

/// The text printed after the findings when the tree breaks the rule.
fn failure_footer() -> String {
    "\nThe allowlist holds keys, not bytes: its element is kotton_ed25519::VerifyingKey, whose one \
     constructor is the Ed25519 rule, so nothing is put on it but through VerifyingKey::from_bytes. \
     Declare the set as HashSet<VerifyingKey> and construct each key where its bytes are read."
        .to_string()
}

/// What the tree breaks of the rule, and how many source files it read.
fn findings(root: &Path) -> (usize, Vec<String>) {
    let mut files = Vec::new();
    for r in crate::tree::CODE_ROOTS {
        walk(&root.join(r), &mut files);
    }
    files.sort();
    let sources: Vec<(String, String)> = files
        .iter()
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .filter_map(|p| std::fs::read_to_string(p).ok().map(|text| (rel(root, p), text)))
        .collect();
    (sources.len(), check(&sources, DECLARATIONS))
}

/// The three rules over `sources`, each a (relative path, contents) pair.
fn check(sources: &[(String, String)], declarations: &[(&str, &str)]) -> Vec<String> {
    let mut out = Vec::new();
    for (file, src) in sources {
        if file == THIS {
            continue;
        }
        for (i, line) in code_lines(src) {
            for element in live_sets(&line) {
                if element.starts_with("[u8;") {
                    out.push(format!(
                        "{file}:{i}: declares a live set of byte arrays (`RwLock<HashSet<{element}>>`); the allowlist's element is the key type"
                    ));
                }
            }
        }
    }
    for (file, name) in declarations {
        let Some((_, src)) = sources.iter().find(|(f, _)| f == file) else {
            out.push(format!("{file}: not found; it holds the allowlist as `{name}`"));
            continue;
        };
        let mut declared = 0;
        for (i, line) in code_lines(src) {
            for element in named_sets(&line, name) {
                declared += 1;
                if !KEY_TYPE.contains(&element.as_str()) {
                    out.push(format!(
                        "{file}:{i}: `{name}` is a set of `{element}`; the allowlist's element is kotton_ed25519::VerifyingKey"
                    ));
                }
            }
        }
        if declared == 0 {
            out.push(format!("{file}: declares no `{name}: Arc<RwLock<HashSet<..>>>`; the allowlist is held there"));
        }
        let lines: Vec<String> = code_lines(src).into_iter().map(|(_, l)| l).collect();
        let imports_rule = lines.iter().any(|l| KEY_IMPORTS.iter().any(|p| l.starts_with(p)) && l.contains("VerifyingKey"));
        let spells_rule = lines.iter().any(|l| l.contains(KEY_TYPE[1]) || l.contains(KEY_TYPE[2]));
        if !imports_rule && !spells_rule {
            out.push(format!("{file}: does not take `VerifyingKey` from kotton_crypto::ed25519 or kotton_ed25519"));
        }
        if lines.iter().any(|l| l.starts_with("useed25519_dalek::") && l.contains("VerifyingKey")) {
            out.push(format!("{file}: imports ed25519_dalek's `VerifyingKey`, which is not the rule's"));
        }
    }
    out
}

/// Each line of `src` but comment lines, numbered from 1 and without its whitespace.
fn code_lines(src: &str) -> Vec<(usize, String)> {
    src.lines()
        .enumerate()
        .filter(|(_, l)| !l.trim_start().starts_with("//"))
        .map(|(i, l)| (i + 1, l.chars().filter(|c| !c.is_whitespace()).collect()))
        .collect()
}

/// The element of each `RwLock<HashSet<E>>` in a line read without its whitespace, with the
/// standard library's paths allowed before either name.
fn live_sets(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(at) = rest.find("RwLock<") {
        let after = rest[at + "RwLock<".len()..].trim_start_matches("std::collections::");
        if let Some(inner) = after.strip_prefix("HashSet<") {
            if let Some(element) = until_close(inner) {
                out.push(element.to_string());
            }
        }
        rest = &rest[at + "RwLock<".len()..];
    }
    out
}

/// The element of each `name: Arc<RwLock<HashSet<E>>>` in a line read without its
/// whitespace, where `name` is the whole name and not the end of a longer one.
fn named_sets(line: &str, name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let needle = format!("{name}:");
    let mut from = 0;
    while let Some(at) = line[from..].find(&needle) {
        let start = from + at;
        from = start + needle.len();
        let whole = start == 0 || !line[..start].ends_with(|c: char| c.is_alphanumeric() || c == '_');
        // `name::` is a path, not a declaration.
        if !whole || line[from..].starts_with(':') {
            continue;
        }
        let ty = &line[from..];
        let ty = ty.trim_start_matches('&').trim_start_matches("std::sync::");
        let ty = ty.strip_prefix("Arc<").unwrap_or(ty).trim_start_matches("std::sync::");
        if !ty.starts_with("RwLock<") {
            continue;
        }
        out.extend(live_sets(ty).into_iter().take(1));
    }
    out
}

/// The text before the `>` that closes an open `<`, counting nested ones.
fn until_close(s: &str) -> Option<&str> {
    let mut depth = 0usize;
    for (i, c) in s.char_indices() {
        match c {
            '<' => depth += 1,
            '>' if depth == 0 => return Some(&s[..i]),
            '>' => depth -= 1,
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const REACH: &str = "core/peer/src/reachability.rs";

    /// A holder as the tree declares it: the key type, imported from the rule's crate.
    const TYPED: &str = "use kotton_crypto::ed25519::VerifyingKey;\n\
                         use std::collections::HashSet;\n\
                         pub struct Reachability {\n    \
                             paired_keys: Arc<RwLock<HashSet<VerifyingKey>>>,\n\
                         }\n\
                         pub fn paired_keys(&self) -> Arc<RwLock<HashSet<VerifyingKey>>> {\n    \
                             Arc::clone(&self.paired_keys)\n\
                         }\n";

    fn one(file: &str, src: &str) -> Vec<(String, String)> {
        vec![(file.to_string(), src.to_string())]
    }

    fn reach_only() -> &'static [(&'static str, &'static str)] {
        &[(REACH, "paired_keys")]
    }

    #[test]
    fn the_allowlist_declared_as_keys_passes() {
        assert!(check(&one(REACH, TYPED), reach_only()).is_empty());
        let spelled = TYPED
            .replace("use kotton_crypto::ed25519::VerifyingKey;\n", "")
            .replace("HashSet<VerifyingKey>", "std::collections::HashSet<kotton_ed25519::VerifyingKey>");
        assert!(check(&one(REACH, &spelled), reach_only()).is_empty(), "{spelled}");
    }

    /// The finding the gate refuses: the allowlist declared as a set of byte arrays, which an
    /// insert of raw bytes compiles against.
    #[test]
    fn the_allowlist_declared_as_a_set_of_byte_arrays_is_a_finding() {
        let bytes = TYPED.replace("HashSet<VerifyingKey>", "HashSet<[u8; 32]>");
        let found = check(&one(REACH, &bytes), reach_only());
        assert!(
            found.iter().any(|f| f.contains("`paired_keys` is a set of `[u8;32]`")),
            "{found:?}"
        );
        assert!(found.iter().any(|f| f.contains("declares a live set of byte arrays")), "{found:?}");
        // The field alone, with the accessor still typed, is refused as surely.
        let field = TYPED.replacen("HashSet<VerifyingKey>", "HashSet<[u8; 32]>", 1);
        let found = check(&one(REACH, &field), reach_only());
        assert!(found.iter().any(|f| f.starts_with(&format!("{REACH}:4:"))), "{found:?}");
    }

    #[test]
    fn a_second_live_set_of_bytes_anywhere_is_a_finding() {
        let mut sources = one(REACH, TYPED);
        sources.push((
            "core/net/src/x.rs".into(),
            "fn verifier(allowed: Arc<std::sync::RwLock<std::collections::HashSet<[u8; 32]>>>) {}\n".into(),
        ));
        let found = check(&sources, reach_only());
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].starts_with("core/net/src/x.rs:1:"), "{found:?}");
        // A comment that names one is not a declaration.
        let mut commented = one(REACH, TYPED);
        commented.push(("core/net/src/x.rs".into(), "// RwLock<HashSet<[u8; 32]>>\n".into()));
        assert!(check(&commented, reach_only()).is_empty());
    }

    #[test]
    fn a_holder_that_moved_or_names_another_key_type_is_a_finding() {
        let renamed = TYPED.replace("paired_keys", "allowed");
        let found = check(&one(REACH, &renamed), reach_only());
        assert!(found.iter().any(|f| f.contains("declares no `paired_keys")), "{found:?}");
        assert_eq!(check(&[], reach_only()).len(), 1, "a holder whose file is gone is a finding");

        let dalek = TYPED.replace("use kotton_crypto::ed25519::VerifyingKey;", "use ed25519_dalek::VerifyingKey;");
        let found = check(&one(REACH, &dalek), reach_only());
        assert_eq!(found.len(), 2, "{found:?}");
    }

    /// A longer name ending in the holder's, or a path through it, is not its declaration.
    #[test]
    fn only_the_whole_name_is_read_as_the_declaration() {
        assert!(named_sets("allowed_keys:Arc<RwLock<HashSet<[u8;32]>>>,", "keys").is_empty());
        assert_eq!(named_sets("keys:Arc<RwLock<HashSet<VerifyingKey>>>,", "keys"), ["VerifyingKey"]);
        assert_eq!(named_sets("paired_keys:&std::sync::RwLock<HashSet<VerifyingKey>>,", "paired_keys"), ["VerifyingKey"]);
        assert!(named_sets("keys::of(x)", "keys").is_empty());
    }

    #[test]
    fn the_printed_text_names_no_record() {
        for text in [ok_line(1), failure_footer()] {
            assert!(!text.contains('#'), "{text}");
        }
    }

    /// The tree as it stands holds the rule, so the gate fails on a change and not on main.
    #[test]
    fn the_tree_holds_the_rule() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().expect("the workspace root");
        let (count, found) = findings(root);
        assert!(count > 0, "read no source file");
        assert!(found.is_empty(), "{found:#?}");
    }
}
