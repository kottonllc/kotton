// SPDX-License-Identifier: AGPL-3.0-or-later
//! `residency-check`: `device` may name a user's store; it may not enumerate one.
//!
//! ## The concession this guards
//!
//! `core/device` gained a dependency on `core/store` on 2026-08-24. Before it, a method
//! that took or returned a `UserStore` could not be written in `device` at all, so 44 of
//! them lived in `kuserd` as an extension trait and three more files had no home. Adding
//! the edge moved 3,910 lines to the crate that owns `DeviceRuntime`.
//!
//! RFC-0080 step 6 had removed the user registry from `DeviceRuntime` deliberately: "the
//! machine type can no longer enumerate users or resolve one to a runtime." That step is
//! about **holding**, not **naming** — and the edge only restores naming. The narrower
//! constraint that replaces it:
//!
//! > `device` may name a user's store; it may not enumerate or resolve one.
//!
//! Which was, until this check, a sentence in a module doc. The Invariant Director role
//! is explicit that this is not enough: "if it matters, it is a check; if it cannot be a
//! check yet, say so in the record and name what would make it one."
//!
//! ## What it checks, and what it cannot
//!
//! Two mechanical things:
//!
//! 1. **The `Residency` trait's shape.** It exists so a pairing ceremony can make a user
//!    resident mid-flight. Two methods — `insert` and `get` — and an enumeration method
//!    added here would hand `device` the registry back one call at a time.
//! 2. **No collection of user stores held in `device`.** A field of
//!    `HashMap<_, Arc<UserStore>>` *is* the registry, whatever it is called. Local
//!    bindings are exempt: the first run of this check flagged a test that builds one
//!    on purpose, to assert residency does not survive a process.
//!
//! It cannot check intent, and it is syntactic: a determined author can defeat it with a
//! type alias. That is stated rather than hidden — the check exists to make the
//! constraint visible and to fail an *accidental* widening, which is the realistic way
//! this gets lost.

use std::path::Path;

/// The trait that lends residency to a ceremony, and the only shape it may have.
const TRAIT_FILE: &str = "core/device/src/users/residency.rs";
/// Exactly these, in any order. Adding one is the widening this refuses.
const ALLOWED_METHODS: &[&str] = &["insert", "get"];
/// Where a registry would hide if one grew back.
const DEVICE_SRC: &str = "core/device/src";

pub fn residency_check() {
    let Ok(src) = std::fs::read_to_string(Path::new(TRAIT_FILE)) else {
        eprintln!(
            "residency-check: could not read {TRAIT_FILE}.\n\n\
             Either this is not the workspace root, or the trait moved. If it moved, this \
             check must move with it — a residency seam nobody is checking is the state \
             this check exists to prevent."
        );
        std::process::exit(1);
    };

    // Method names declared in the trait body: `fn <name>(`.
    let mut found: Vec<String> = Vec::new();
    let mut in_trait = false;
    for line in src.lines() {
        let t = line.trim();
        if t.starts_with("pub trait Residency") {
            in_trait = true;
            continue;
        }
        if in_trait && t == "}" {
            break;
        }
        if in_trait {
            if let Some(rest) = t
                .strip_prefix("fn ")
                .or_else(|| t.strip_prefix("async fn "))
            {
                if let Some(name) = rest.split('(').next() {
                    found.push(name.trim().to_string());
                }
            }
        }
    }

    if found.is_empty() {
        eprintln!(
            "residency-check: found no methods on `Residency` in {TRAIT_FILE}.\n\n\
             The trait was renamed, or the parser no longer matches it. Either way this \
             check is inspecting nothing and would report success — which is worse than \
             the widening it looks for."
        );
        std::process::exit(1);
    }

    let mut extra: Vec<&String> = found
        .iter()
        .filter(|m| !ALLOWED_METHODS.contains(&m.as_str()))
        .collect();
    extra.sort();

    if !extra.is_empty() {
        eprintln!(
            "residency-check: `Residency` gained {} method(s) beyond insert/get:\n",
            extra.len()
        );
        for m in &extra {
            eprintln!("  {m}");
        }
        eprintln!(
            "\n`device` may name a user's store; it may not enumerate or resolve one. A \
             method that lists, counts or iterates users hands the registry back one call \
             at a time. If this is deliberate, it is a decision under docs/design/decisions/ \
             and the owner's call, not a check edit."
        );
        std::process::exit(1);
    }

    // A registry by any other name: a keyed collection of user stores inside `device`.
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    collect_rs(Path::new(DEVICE_SRC), &mut files);
    if files.is_empty() {
        eprintln!(
            "residency-check: found no .rs files under {DEVICE_SRC}. Run from the workspace root."
        );
        std::process::exit(1);
    }
    let mut holders: Vec<String> = Vec::new();
    for f in &files {
        let Ok(text) = std::fs::read_to_string(f) else {
            continue;
        };
        for (i, line) in text.lines().enumerate() {
            let l = line.trim();
            if l.starts_with("//") || l.starts_with("#[") {
                continue;
            }
            // A `let` binding is not a registry. The first run of this check flagged a
            // test that builds a local map precisely to assert residency does *not*
            // survive a process — the right thing for that test to do, and not a field
            // on any type. What this looks for is something `device` *holds*.
            if l.starts_with("let ") || l.starts_with("let mut ") {
                continue;
            }
            let keyed = l.contains("HashMap<") || l.contains("BTreeMap<");
            if keyed && l.contains("UserStore") {
                holders.push(format!("{}:{}", f.display(), i + 1));
            }
        }
    }

    if !holders.is_empty() {
        eprintln!(
            "residency-check: {} place(s) in `device` hold a keyed collection of user stores:\n",
            holders.len()
        );
        for h in &holders {
            eprintln!("  {h}");
        }
        eprintln!(
            "\nThat is the residency map, whatever it is called, and it belongs to the \
             daemon. `device` is lent one user at a time through \
             `Residency`."
        );
        std::process::exit(1);
    }

    println!(
        "residency-check: OK — `Residency` lends {} method(s) and `device` holds no user registry.",
        found.len()
    );
}

fn collect_rs(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_rs(&p, out);
        } else if p.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(p);
        }
    }
}
