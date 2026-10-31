// SPDX-License-Identifier: AGPL-3.0-or-later
//! `device-add-check`: no line of code under `core/` spells a `device add` flag by hand.
//!
//! ## Why this exists
//!
//! `kotton_schemas::membership` holds the one vocabulary of `device add`: `device_add_word`, a
//! total map from every posture to its words (none, a flag, or a flag and a value). The
//! shell's `parse_add` and usage line walk it over every posture, and so do the daemon's hints
//! that name a `device add` (`adds_instead`, `core/device/src/users/pairing.rs`, read by the
//! invite's refusal and by the vault's refusal in `handle_device_join`).
//! A hint that spelled `device add --cosigner` by hand would print a command the shell might
//! no longer parse, and a test can only catch that after it is written. This holds that, in
//! the text it reads, it is not written.
//!
//! ## What it checks
//!
//! Over every `.rs` file under `core/`, outside its `#[cfg(test)] mod` blocks (test inputs are
//! lines typed at a parser, not hints a person is told to type) and its comment lines (which
//! may name the command they describe), each occurrence of `device add --` anywhere on a line,
//! inside a string literal or not, is a site. There are none, and the check allows none: an
//! exception would be argued for in its own change, which would bring its allowance with it.
//!
//! ## What a text check cannot see
//!
//! It reads text, one line at a time. It does not see a flag composed so that the words never
//! sit together: `format!("device add {}", "--cosigner")`, `concat!`, or a flag held in a
//! constant of its own and interpolated. It does not see a literal split across lines with a
//! `\` continuation between `device add` and its flag. It skips any line that starts with
//! `//`, which is a comment almost always and a string literal's continuation line almost
//! never. It reads a `#[cfg(test)] fn` outside a module, and a `#[doc = "..."]`, as code. And
//! it reads `core/` only: the shell's help text, its `--browser` error context, and prose
//! under `infra/` and the shell's comments are outside it. Those are the residual, stated here
//! rather than implied away.

use std::path::Path;

use crate::docs_present_check::test_modules;
use crate::user_database_check::{rel, walk};

/// What is searched for, anywhere on a line: a `device add` with a flag.
const NEEDLE: &str = "device add --";

pub fn run(root: &Path) {
    let mut files = Vec::new();
    walk(&root.join("core"), &mut files);
    files.sort();
    let mut read = Vec::new();
    for path in files.iter().filter(|p| p.extension().is_some_and(|e| e == "rs")) {
        let Ok(src) = std::fs::read_to_string(path) else {
            eprintln!("device-add-check: could not read {}", path.display());
            std::process::exit(1);
        };
        read.push((rel(root, path), src));
    }
    if read.is_empty() {
        eprintln!(
            "device-add-check: found no .rs file under core/. Run from the workspace root: a \
             check that inspects nothing reports success."
        );
        std::process::exit(1);
    }
    let sites = findings(&read);
    if sites.is_empty() {
        println!(
            "device-add-check: OK: {} file(s) under core/, and no `device add --` outside tests \
             and comments.",
            read.len()
        );
        return;
    }
    for (file, line, text) in &sites {
        eprintln!("device-add-check: {file}:{line}: spells a `device add` flag by hand: {}", text.trim());
    }
    eprintln!(
        "\nA `device add` hint takes its words from device_add_word (kotton-schemas), through \
         `adds_instead` (core/device/src/users/pairing.rs)."
    );
    std::process::exit(1);
}

/// A line that spells a `device add` flag by hand: (file, 1-based line, text).
type Site = (String, usize, String);

/// The sites of [`NEEDLE`] outside test modules and comments, one per line that holds any.
fn findings(files: &[(String, String)]) -> Vec<Site> {
    let mut sites = Vec::new();
    for (file, src) in files {
        let tests = test_modules(src);
        for (i, text) in src.lines().enumerate() {
            let line = i + 1;
            let comment = text.trim_start().starts_with("//");
            if comment || !text.contains(NEEDLE) || tests.iter().any(|&(a, b)| (a..=b).contains(&line)) {
                continue;
            }
            sites.push((file.clone(), line, text.to_string()));
        }
    }
    sites
}

#[cfg(test)]
mod tests {
    use super::findings;

    const PAIRING: &str = "core/device/src/users/pairing.rs";

    fn one(file: &str, src: &str) -> Vec<(String, String)> {
        vec![(file.to_string(), src.to_string())]
    }

    /// A line built from the constants, a test module's inputs and a comment pass.
    #[test]
    fn composed_lines_test_inputs_and_comments_pass() {
        let src = "/// names `\"device add --` in prose\nfn f() {\n    let g = format!(\"device add {GATEWAY} <code>\");\n}\n\n#[cfg(test)]\nmod t {\n    \
                   fn x() { p(\"device add --blind --cosigner\"); }\n}\n";
        let sites = findings(&one(PAIRING, src));
        assert!(sites.is_empty(), "{sites:?}");
    }

    /// A hand-spelled flag is a finding in any file, the gateway's word included.
    #[test]
    fn a_hand_spelled_flag_or_gateway_is_a_finding() {
        let src = "fn f() {\n    let g = \"device add --gateway <code>\";\n    let c = \"device add --cosigner\";\n}\n";
        let sites = findings(&one(PAIRING, src));
        assert_eq!(sites.iter().map(|u| u.1).collect::<Vec<_>>(), vec![2, 3]);

        let elsewhere = "fn f() { \"device add --blind\"; }\n";
        let sites = findings(&one("core/kuserd/src/x.rs", elsewhere));
        assert_eq!(sites.len(), 1, "{sites:?}");

        // Two on one line are one finding, the line.
        let twice = "fn f() { (\"device add --blind\", \"device add --cosigner\"); }\n";
        assert_eq!(findings(&one(PAIRING, twice)).len(), 1);
    }

    /// A flag spelled inside a sentence, on a string's continuation line, is a site.
    #[test]
    fn a_flag_inside_a_sentence_is_a_finding() {
        let src = "fn f() {\n    let r = \"so \\\n        enrol it blind (`device add --blind`)\";\n}\n";
        let sites = findings(&one(PAIRING, src));
        assert_eq!(sites.iter().map(|u| u.1).collect::<Vec<_>>(), vec![3], "{sites:?}");
    }
}
