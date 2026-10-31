// SPDX-License-Identifier: AGPL-3.0-or-later
//! `device-add-check`: no line of code under `core/` spells a `device add` flag by hand, but
//! the gateway's.
//!
//! ## Why this exists
//!
//! `kotton_schemas::membership::DEVICE_ADD_POSTURE_FLAGS` is the one vocabulary of `device
//! add`'s posture flags: the shell's `parse_add` reads it, and the daemon's hints that name a
//! `device add` with a posture flag (`device_add_flag`, `core/device/src/users/pairing.rs`,
//! read by `adds_instead` and by the vault's refusal in `handle_device_join`) look the flag up
//! in it by posture. A hint that spelled `device add --cosigner` by hand would print a command
//! the shell might no longer parse, and a test can only catch that after it is written. This
//! holds that, in the text it reads, it is not written.
//!
//! ## What it checks
//!
//! Over every `.rs` file under `core/`, outside its `#[cfg(test)] mod` blocks (test inputs are
//! lines typed at a parser, not hints a person is told to type) and its comment lines (which
//! may name the command they describe), each occurrence of `device add --` anywhere on a line,
//! inside a string literal or not, is a site. The sites must be exactly [`ALLOWED`]: one, the
//! gateway's arm, whose `--gateway <code>` is a word with a value the table does not carry, and
//! that line must hold no second site. Any other site fails; so does the allowed one going
//! missing, since then the allowance is stale and says so.
//!
//! ## What a text check cannot see
//!
//! It reads text, one line at a time. It does not see a flag composed so that the words never
//! sit together: `format!("device add {}", "--cosigner")`, `concat!`, or a flag held in a
//! constant of its own and interpolated. It does not see a literal split across lines with a
//! `\` continuation between `device add` and its flag. It skips any line that starts with
//! `//`, which is a comment almost always and a string literal's continuation line almost
//! never. And it reads `core/` only: the shell's usage line (held instead by
//! `the_usage_line_names_exactly_the_tables_posture_flags`), the shell's error contexts, and
//! prose under `infra/` and the shell's comments are outside it. Those are the residual,
//! stated here rather than implied away.

use std::path::Path;

use crate::docs_present_check::test_modules;
use crate::user_database_check::{rel, walk};

/// What is searched for, anywhere on a line: a `device add` with a flag.
const NEEDLE: &str = "device add --";

/// The one site allowed to spell a `device add` flag by hand, as (file, the literal on its
/// line): `--gateway <code>` is not a posture flag of the table but a word with a value.
const ALLOWED: &[(&str, &str)] =
    &[("core/device/src/users/pairing.rs", "\"device add --gateway <code>\"")];

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
    let (unallowed, missing) = findings(&read);
    if unallowed.is_empty() && missing.is_empty() {
        println!(
            "device-add-check: OK: {} file(s) under core/, and the one `device add --` outside \
             tests and comments is the gateway's arm.",
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
        "\nA `device add` hint takes its posture flag from DEVICE_ADD_POSTURE_FLAGS \
         (kotton-schemas), looked up by posture, through `device_add_flag` \
         (core/device/src/users/pairing.rs); the allowance is \
         xtask/src/device_add_check.rs::ALLOWED."
    );
    std::process::exit(1);
}

/// A line that spells a `device add` flag by hand: (file, 1-based line, text).
type Site = (String, usize, String);

/// The sites of [`NEEDLE`] outside test modules and comments that are not [`ALLOWED`], one
/// per line that holds any; and the allowed sites that were not found. An allowed line is
/// allowed only when its literal is the line's one site.
fn findings(files: &[(String, String)]) -> (Vec<Site>, Vec<(&'static str, &'static str)>) {
    let mut unallowed = Vec::new();
    let mut seen = vec![false; ALLOWED.len()];
    for (file, src) in files {
        let tests = test_modules(src);
        for (i, text) in src.lines().enumerate() {
            let line = i + 1;
            let comment = text.trim_start().starts_with("//");
            let sites = text.matches(NEEDLE).count();
            if comment || sites == 0 || tests.iter().any(|&(a, b)| (a..=b).contains(&line)) {
                continue;
            }
            let allowed = ALLOWED.iter().position(|(f, lit)| f == file && text.contains(lit));
            match allowed {
                Some(k) if sites == 1 && !seen[k] => seen[k] = true,
                _ => unallowed.push((file.clone(), line, text.to_string())),
            }
        }
    }
    let missing = ALLOWED.iter().zip(seen).filter(|(_, s)| !s).map(|(a, _)| *a).collect();
    (unallowed, missing)
}

#[cfg(test)]
mod tests {
    use super::findings;

    const PAIRING: &str = "core/device/src/users/pairing.rs";

    fn one(file: &str, src: &str) -> Vec<(String, String)> {
        vec![(file.to_string(), src.to_string())]
    }

    /// The gateway's arm alone is clean; a test module's inputs and a comment are not read.
    #[test]
    fn the_gateway_arm_alone_and_test_inputs_pass() {
        let src = "/// names `\"device add --` in prose\nfn f() {\n    let g = \"device add --gateway <code>\";\n}\n\n#[cfg(test)]\nmod t {\n    \
                   fn x() { p(\"device add --blind --cosigner\"); }\n}\n";
        let (unallowed, missing) = findings(&one(PAIRING, src));
        assert!(unallowed.is_empty(), "{unallowed:?}");
        assert!(missing.is_empty(), "{missing:?}");
    }

    /// A hand-spelled flag is a finding, in the allowed file or any other, and so is the
    /// gateway's literal a second time.
    #[test]
    fn a_hand_spelled_flag_or_a_second_gateway_is_a_finding() {
        let src = "fn f() {\n    let g = \"device add --gateway <code>\";\n    let c = \"device add --cosigner\";\n}\n";
        let (unallowed, _) = findings(&one(PAIRING, src));
        assert_eq!(unallowed.iter().map(|u| u.1).collect::<Vec<_>>(), vec![3]);

        let twice = "fn f() {\n    \"device add --gateway <code>\";\n    \"device add --gateway <code>\";\n}\n";
        let (unallowed, _) = findings(&one(PAIRING, twice));
        assert_eq!(unallowed.len(), 1, "{unallowed:?}");

        let elsewhere = "fn f() { \"device add --blind\"; }\n";
        let mut files = one(PAIRING, "fn f() { \"device add --gateway <code>\"; }\n");
        files.extend(one("core/kuserd/src/x.rs", elsewhere));
        let (unallowed, missing) = findings(&files);
        assert_eq!(unallowed.len(), 1, "{unallowed:?}");
        assert!(missing.is_empty());
    }

    /// A flag spelled inside a sentence, on a string's continuation line, is a site; and a
    /// second site on the allowed line makes that line a finding.
    #[test]
    fn a_flag_inside_a_sentence_or_beside_the_allowed_literal_is_a_finding() {
        let src = "fn f() {\n    \"device add --gateway <code>\";\n    let r = \"so \\\n        enrol it blind (`device add --blind`)\";\n}\n";
        let (unallowed, missing) = findings(&one(PAIRING, src));
        assert_eq!(unallowed.iter().map(|u| u.1).collect::<Vec<_>>(), vec![4], "{unallowed:?}");
        assert!(missing.is_empty());

        let beside = "fn f() { (\"device add --gateway <code>\", \"device add --cosigner\"); }\n";
        let (unallowed, missing) = findings(&one(PAIRING, beside));
        assert_eq!(unallowed.len(), 1, "{unallowed:?}");
        assert_eq!(missing.len(), 1, "the only line holding it was not allowed");
    }

    /// The allowed site going missing is a finding: the allowance is stale.
    #[test]
    fn a_missing_allowed_site_is_a_finding() {
        let (unallowed, missing) = findings(&one(PAIRING, "fn f() {}\n"));
        assert!(unallowed.is_empty());
        assert_eq!(missing.len(), 1);
    }
}
