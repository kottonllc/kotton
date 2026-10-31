// SPDX-License-Identifier: AGPL-3.0-or-later
//! `device-add-check`: no line of code under `core/` spells a `device add` flag by hand.
//!
//! ## Why this exists
//!
//! `kotton_schemas::membership` holds the one vocabulary of `device add`'s flags:
//! `DEVICE_ADD_POSTURE_FLAGS` for the posture flags and `DEVICE_ADD_GATEWAY_FLAG` for the
//! gateway's word. The shell's `parse_add` and usage line read them, and the daemon's hints
//! that name a `device add` (`adds_instead`, `core/device/src/users/pairing.rs`, read by the
//! invite's refusal and by the vault's refusal in `handle_device_join`) walk them by posture.
//! A hint that spelled `device add --cosigner` by hand would print a command the shell might
//! no longer parse, and a test can only catch that after it is written. This holds that, in
//! the text it reads, it is not written.
//!
//! ## What it checks
//!
//! Over every `.rs` file under `core/`, outside its `#[cfg(test)] mod` blocks (test inputs are
//! lines typed at a parser, not hints a person is told to type) and its comment lines (which
//! may name the command they describe), each occurrence of `device add --` anywhere on a line,
//! inside a string literal or not, is a site. There must be none: [`ALLOWED`] is empty, and an
//! entry in it would be an exception argued for in its own change. An allowed site going
//! missing also fails, since then the allowance is stale and says so.
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

/// The sites allowed to spell a `device add` flag by hand, as (file, the literal on its line).
/// None: every flag, the gateway's included, is a constant of `kotton_schemas::membership`.
const ALLOWED: &[(&str, &str)] = &[];

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
    let (unallowed, missing) = findings(&read, ALLOWED);
    if unallowed.is_empty() && missing.is_empty() {
        println!(
            "device-add-check: OK: {} file(s) under core/, and no `device add --` outside tests \
             and comments.",
            read.len()
        );
        return;
    }
    for (file, line, text) in &unallowed {
        eprintln!("device-add-check: {file}:{line}: spells a `device add` flag by hand: {}", text.trim());
    }
    for (file, literal) in &missing {
        eprintln!("device-add-check: {file}: the allowed site {literal} is gone; update ALLOWED.");
    }
    eprintln!(
        "\nA `device add` hint takes its flag from DEVICE_ADD_POSTURE_FLAGS or \
         DEVICE_ADD_GATEWAY_FLAG (kotton-schemas), through `adds_instead` \
         (core/device/src/users/pairing.rs); the allowance, empty, is \
         xtask/src/device_add_check.rs::ALLOWED."
    );
    std::process::exit(1);
}

/// A line that spells a `device add` flag by hand: (file, 1-based line, text).
type Site = (String, usize, String);

/// The sites of [`NEEDLE`] outside test modules and comments that are not in `allowed`
/// ([`ALLOWED`] when run), one per line that holds any; and the allowed sites that were not
/// found. An allowed line is allowed only when its literal is the line's one site.
fn findings<'a>(
    files: &[(String, String)],
    allowed: &[(&'a str, &'a str)],
) -> (Vec<Site>, Vec<(&'a str, &'a str)>) {
    let mut unallowed = Vec::new();
    let mut seen = vec![false; allowed.len()];
    for (file, src) in files {
        let tests = test_modules(src);
        for (i, text) in src.lines().enumerate() {
            let line = i + 1;
            let comment = text.trim_start().starts_with("//");
            let sites = text.matches(NEEDLE).count();
            if comment || sites == 0 || tests.iter().any(|&(a, b)| (a..=b).contains(&line)) {
                continue;
            }
            match allowed.iter().position(|(f, lit)| f == file && text.contains(lit)) {
                Some(k) if sites == 1 && !seen[k] => seen[k] = true,
                _ => unallowed.push((file.clone(), line, text.to_string())),
            }
        }
    }
    let missing = allowed.iter().zip(seen).filter(|(_, s)| !s).map(|(a, _)| *a).collect();
    (unallowed, missing)
}

#[cfg(test)]
mod tests {
    use super::{findings, ALLOWED};

    const PAIRING: &str = "core/device/src/users/pairing.rs";

    fn one(file: &str, src: &str) -> Vec<(String, String)> {
        vec![(file.to_string(), src.to_string())]
    }

    /// A line built from the constants, a test module's inputs and a comment pass.
    #[test]
    fn composed_lines_test_inputs_and_comments_pass() {
        let src = "/// names `\"device add --` in prose\nfn f() {\n    let g = format!(\"device add {GATEWAY} <code>\");\n}\n\n#[cfg(test)]\nmod t {\n    \
                   fn x() { p(\"device add --blind --cosigner\"); }\n}\n";
        let (unallowed, missing) = findings(&one(PAIRING, src), ALLOWED);
        assert!(unallowed.is_empty(), "{unallowed:?}");
        assert!(missing.is_empty(), "{missing:?}");
    }

    /// A hand-spelled flag is a finding in any file, the gateway's word included.
    #[test]
    fn a_hand_spelled_flag_or_gateway_is_a_finding() {
        let src = "fn f() {\n    let g = \"device add --gateway <code>\";\n    let c = \"device add --cosigner\";\n}\n";
        let (unallowed, _) = findings(&one(PAIRING, src), ALLOWED);
        assert_eq!(unallowed.iter().map(|u| u.1).collect::<Vec<_>>(), vec![2, 3]);

        let elsewhere = "fn f() { \"device add --blind\"; }\n";
        let (unallowed, missing) = findings(&one("core/kuserd/src/x.rs", elsewhere), ALLOWED);
        assert_eq!(unallowed.len(), 1, "{unallowed:?}");
        assert!(missing.is_empty());
    }

    /// A flag spelled inside a sentence, on a string's continuation line, is a site.
    #[test]
    fn a_flag_inside_a_sentence_is_a_finding() {
        let src = "fn f() {\n    let r = \"so \\\n        enrol it blind (`device add --blind`)\";\n}\n";
        let (unallowed, _) = findings(&one(PAIRING, src), ALLOWED);
        assert_eq!(unallowed.iter().map(|u| u.1).collect::<Vec<_>>(), vec![3], "{unallowed:?}");
    }

    /// The allowance mechanism, for an entry argued into it: an allowed literal alone on its
    /// line passes; a second site beside it, or the literal twice, is a finding; and an
    /// allowed site gone missing is a finding, since the allowance is stale.
    #[test]
    fn an_allowance_holds_only_its_one_literal_and_goes_stale_when_missing() {
        let allowed: &[(&str, &str)] = &[(PAIRING, "\"device add --x <v>\"")];
        let (unallowed, missing) = findings(&one(PAIRING, "fn f() { \"device add --x <v>\"; }\n"), allowed);
        assert!(unallowed.is_empty() && missing.is_empty(), "{unallowed:?} {missing:?}");

        let beside = "fn f() { (\"device add --x <v>\", \"device add --cosigner\"); }\n";
        let (unallowed, missing) = findings(&one(PAIRING, beside), allowed);
        assert_eq!(unallowed.len(), 1, "{unallowed:?}");
        assert_eq!(missing.len(), 1, "the only line holding it was not allowed");

        let twice = "fn f() {\n    \"device add --x <v>\";\n    \"device add --x <v>\";\n}\n";
        let (unallowed, _) = findings(&one(PAIRING, twice), allowed);
        assert_eq!(unallowed.len(), 1, "{unallowed:?}");

        let (unallowed, missing) = findings(&one(PAIRING, "fn f() {}\n"), allowed);
        assert!(unallowed.is_empty());
        assert_eq!(missing.len(), 1);
    }
}
