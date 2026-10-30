// SPDX-License-Identifier: AGPL-3.0-or-later
//! `device-add-check`: a `device add` hint under `core/` takes its posture flag from the table.
//!
//! ## Why this exists
//!
//! `kotton_schemas::membership::DEVICE_ADD_POSTURE_FLAGS` is the one vocabulary of `device
//! add`'s posture flags: the shell's `parse_add` reads it, and the hint the daemon prints when
//! an invite refuses a posture (`adds_instead`, `core/device/src/users/pairing.rs`) looks its
//! flag up in it by posture. A hint that spelled `"device add --cosigner"` by hand would print
//! a command the shell might no longer parse, and a test can only catch that after it is
//! written. This holds that it is not written.
//!
//! ## What it checks
//!
//! Over every `.rs` file under `core/`, outside its `#[cfg(test)] mod` blocks (test inputs are
//! lines typed at a parser, not hints a person is told to type) and its comment lines (which
//! may name the literal they describe), the lines that hold the
//! literal `"device add --` are exactly [`ALLOWED`]: one, the gateway's, whose `--gateway
//! <code>` is a word with a value the table does not carry. A second site fails; so does the
//! allowed one going missing, since then the allowance is stale and says so.

use std::path::Path;

use crate::docs_present_check::test_modules;
use crate::user_database_check::{rel, walk};

/// What is searched for: a string literal that starts a `device add` with a flag.
const NEEDLE: &str = "\"device add --";

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
            "device-add-check: OK: {} file(s) under core/, and the one `\"device add --` literal \
             outside tests is the gateway's.",
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
         (kotton-schemas), looked up by posture, as `adds_instead` does; the allowance is \
         xtask/src/device_add_check.rs::ALLOWED."
    );
    std::process::exit(1);
}

/// A line that spells a `device add` flag by hand: (file, 1-based line, text).
type Site = (String, usize, String);

/// The lines outside test modules and comments that hold [`NEEDLE`] and are not [`ALLOWED`];
/// and the allowed sites that were not found.
fn findings(files: &[(String, String)]) -> (Vec<Site>, Vec<(&'static str, &'static str)>) {
    let mut unallowed = Vec::new();
    let mut seen = vec![false; ALLOWED.len()];
    for (file, src) in files {
        let tests = test_modules(src);
        for (i, text) in src.lines().enumerate() {
            let line = i + 1;
            let comment = text.trim_start().starts_with("//");
            if comment || !text.contains(NEEDLE) || tests.iter().any(|&(a, b)| (a..=b).contains(&line)) {
                continue;
            }
            match ALLOWED.iter().position(|(f, lit)| f == file && text.contains(lit)) {
                Some(k) if !seen[k] => seen[k] = true,
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

    /// The allowed site going missing is a finding: the allowance is stale.
    #[test]
    fn a_missing_allowed_site_is_a_finding() {
        let (unallowed, missing) = findings(&one(PAIRING, "fn f() {}\n"));
        assert!(unallowed.is_empty());
        assert_eq!(missing.len(), 1);
    }
}
