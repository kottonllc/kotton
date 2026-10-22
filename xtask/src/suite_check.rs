// SPDX-License-Identifier: AGPL-3.0-or-later
//! `suite-check`: every test file in the suite is declared, so none runs silently.
//!
//! ## Why this exists
//!
//! The integration tests were 42 files directly under `tests/tests/`, which Cargo
//! compiles as 42 separate crates — 42 links of the whole workspace, 8 GB of
//! executables, and a relink of all of them whenever a low crate changed. They are
//! now one binary: `tests/tests/suite/main.rs` with a `mod` line each.
//!
//! That trade has one sharp edge. A file directly under `tests/` is *automatically*
//! a test target — forget nothing and it still runs. A file in `suite/` with no
//! `mod` line is **not compiled at all**: no error, no warning, and the suite
//! reports success having never built it. Deleting a test by forgetting to mention
//! it is exactly the failure the consolidation could introduce, so this refuses it.
//!
//! The inverse is checked too: a `mod` line naming a file that no longer exists
//! fails the build already, so it needs nothing here.

use std::collections::HashSet;
use std::path::Path;

const SUITE: &str = "tests/tests/suite";
const MAIN: &str = "tests/tests/suite/main.rs";

pub fn suite_check() {
    let Ok(main) = std::fs::read_to_string(Path::new(MAIN)) else {
        eprintln!("suite-check: could not read {MAIN}. Run from the workspace root.");
        std::process::exit(1);
    };

    let declared: HashSet<String> = main
        .lines()
        .filter_map(|l| {
            let t = l.trim();
            t.strip_prefix("mod ")
                .and_then(|r| r.strip_suffix(';'))
                .map(|n| n.trim().to_string())
        })
        .collect();

    if declared.is_empty() {
        eprintln!(
            "suite-check: {MAIN} declares no modules. Either the suite moved or the parser \
             is broken — and a check that inspects nothing reports success."
        );
        std::process::exit(1);
    }

    let Ok(entries) = std::fs::read_dir(Path::new(SUITE)) else {
        eprintln!("suite-check: could not read {SUITE}.");
        std::process::exit(1);
    };

    let mut orphans: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for e in entries.flatten() {
        let path = e.path();
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if stem == "main" {
            continue;
        }
        checked += 1;
        if !declared.contains(stem) {
            orphans.push(stem.to_string());
        }
    }

    if orphans.is_empty() {
        println!("suite-check: OK — all {checked} suite file(s) are declared in main.rs.");
        return;
    }

    orphans.sort();
    eprintln!(
        "suite-check: {} test file(s) in {SUITE} are not declared in main.rs and are \
         therefore not compiled or run:\n",
        orphans.len()
    );
    for o in &orphans {
        eprintln!("  {o}");
    }
    eprintln!(
        "\nAdd `mod {};` to {MAIN}. A file directly under tests/ used to be picked up \
         automatically; inside the suite it has to be named, and an unnamed one disappears \
         without an error.",
        orphans[0]
    );
    std::process::exit(1);
}
