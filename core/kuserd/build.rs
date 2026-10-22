// SPDX-License-Identifier: AGPL-3.0-or-later
//! Two jobs, both about what this binary carries rather than what it does.
//!
//! **Windows version metadata** (ProductName / CompanyName / FileDescription) so the OS
//! firewall dialog, Task Manager and file properties identify this binary as Kotton rather
//! than a bare path. No-op off Windows. Never fails the build: if no resource compiler is
//! available the metadata is simply dropped (emitted as a cargo warning), so the .exe still
//! builds unsigned-but-named.
//!
//! **Whether the bundled guest apps are present to embed.** `src/bundled.rs` embeds the
//! shell, editor and records components with `include_bytes!`, which needs the files to exist when
//! this crate compiles. They are produced by `cargo xtask build-apps`, which `just
//! desktop::build` runs first and a bare `cargo build` does not — so their absence is an
//! ordinary state, not an error, and it must not break a build that was never going to run
//! a desktop.
//!
//! So this checks, and sets `bundled_apps_present` when all of them are there. A build without
//! them gets a warning naming the command that makes them, and a daemon that installs no
//! apps — which is exactly what it did before any of this existed.

use std::path::Path;

/// The components `src/bundled.rs` embeds, relative to the workspace root.
const APPS: [&str; 3] = [
    "guest/apps/kotton-shell/app.wasm",
    "guest/apps/kotton-editor/app.wasm",
    "guest/apps/kotton-records/app.wasm",
];

fn main() {
    println!("cargo::rustc-check-cfg=cfg(bundled_apps_present)");

    // `core/kuserd` → the workspace root.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("core/kuserd has no grandparent");

    let mut missing = Vec::new();
    for rel in APPS {
        let p = root.join(rel);
        // Declared whether or not it exists: cargo then re-runs this script when one
        // appears, so building the apps after the daemon still embeds them rather than
        // leaving a cached "absent" behind.
        println!("cargo::rerun-if-changed={}", p.display());
        if !p.is_file() {
            missing.push(rel);
        }
    }

    if missing.is_empty() {
        println!("cargo::rustc-cfg=bundled_apps_present");
    } else {
        println!(
            "cargo::warning=kuserd: no guest apps embedded ({} missing). A new identity will \
             have no shell and no editor. Run `cargo xtask build-apps` and rebuild; \
             `just desktop::build` does both in order.",
            missing.join(", ")
        );
    }

    #[cfg(windows)]
    {
        let mut res = winresource::WindowsResource::new();
        res.set("ProductName", "Kotton");
        res.set("CompanyName", "Kotton LLC");
        res.set("FileDescription", "Kotton User Daemon");
        res.set("LegalCopyright", "\u{a9} Kotton LLC");
        if let Err(e) = res.compile() {
            println!("cargo::warning=Kotton version resource skipped: {e}");
        }
    }
}
