// SPDX-License-Identifier: AGPL-3.0-or-later
//! The files xtask compiles from another crate's source, and the test that holds each to
//! naming nothing but `std` (kotton #306).
//!
//! xtask compiles three readers from their owners' source by `#[path]` rather than linking
//! the owner: kotton-wire's reader of a recorded surface (`wire_check::recorded_surface`),
//! `kvaultd`'s reader of its settings file (`release_server::settings`) and the finder of
//! systemd's parser (`release_server::systemds_parser`). A dependency on the owner would
//! build its whole closure into every `cargo xtask`; what lets one source compile in both
//! crates is that it names nothing but `std`.
//!
//! **What held that claim before this file was the build, and only half of it.** A
//! `use crate::…` in a shared file fails xtask's build. A name both crates already link —
//! `serde_json`, which xtask and kotton-wire both depend on — compiles on both sides, and
//! the claim rots silently: the next change to xtask's dependencies, or to the owner's, is
//! what breaks, far from the line that caused it.
//!
//! **The compiler is asked.** "Names nothing but `std`" is a property of name resolution,
//! and rustc is the one reader that resolves names exactly. [`compile_alone`] compiles a
//! shared file as a crate of its own, in place, with no `--extern` and an empty library
//! path, so the only crates it can reach are `std`, `core` and `alloc`. Any other root —
//! however it is spelled, through a macro, a raw identifier, a nested `#[path]` module or
//! an `include!`, or past a local item of the same name in the value namespace — fails to
//! resolve, and the compiler's own message is the finding. Each file is compiled twice:
//! once as a library, and once with `--test`, so the `#[cfg(test)]` module xtask's tests
//! compile in is held too. Lints are capped, so only an error fails.
//!
//! **What this holds is exactly what rustc resolves, and so it does not hold:**
//! - code under a `cfg` the host's test build does not enable (`#[cfg(windows)]` on Linux,
//!   a feature): it is not compiled, so it names nothing here;
//! - the body of a `macro_rules!` the file never expands: rustc resolves a macro's paths
//!   where it is expanded, and so does xtask's build;
//! - a path through `crate::` or `$crate` to an item the file itself declares: compiled
//!   alone the file is its own crate root, so that resolves here, and in xtask it names
//!   xtask's root and fails xtask's build — the half of the claim the build already held.
//!   A top-level `super::`, which would make the file not a crate root, fails here, as it
//!   should: it reaches outside the file.
//!
//! **A test, not a guard in the build, and no new dependency.** The build cannot say this:
//! it resolves names against whatever the compiling crate links, and both crates link more
//! than `std`. The test runs the toolchain's own `rustc` (`$RUSTC`, as cargo sets it, or
//! `rustc`), so it needs no crate, and no build but `cargo test -p xtask` pays for it.
//!
//! **The list cannot miss an include.** [`STD_ONLY`] is the one list; the includes are in
//! `wire_check.rs` and `release_server.rs`, each beside the module that uses it, and
//! `the_list_is_every_file_xtask_compiles_from_outside_xtask` holds the list to the source
//! files rustc itself recorded as compiled into this test binary (its dep-info), so a
//! fourth include that is not listed fails rather than going unread.
//!
//! **Out of scope: xtask's integration tests.** `xtask/tests/release_server_gate.rs`
//! compiles `infra/relay/tests/common/settings_corpus.rs` by `#[path]`. It is a test
//! target, not the `cargo xtask` binary: it builds with dev-dependencies and only under
//! `cargo test`, so a crate it names reaches no `cargo xtask` run, and that file makes no
//! claim to name only `std`. Its sources are not in this binary's dep-info, so the list
//! test does not see it.

use std::path::Path;
use std::process::Command;

/// Every file xtask compiles from another crate's source, from the repository root. Each
/// names nothing but `std` (see the module doc);
/// `the_list_is_every_file_xtask_compiles_from_outside_xtask` holds this list to what rustc
/// compiled.
pub(crate) const STD_ONLY: &[&str] = &[
    // `wire_check::recorded_surface`: the one reader of a recorded wire surface.
    "core/wire/src/recorded_surface.rs",
    // `release_server::settings`: `kvaultd`'s reader of `vault.env`.
    "core/kvaultd/src/settings.rs",
    // `release_server::systemds_parser`: where systemd's own settings parser is.
    "infra/relay/tests/common/systemds_parser.rs",
];

/// The edition the owners and xtask all compile these files under.
const EDITION: &str = "2021";

/// Compile `file` as a crate of its own, with no crate but `std`, `core` and `alloc` in
/// reach — as a library, or with `--test` as its test harness — writing only metadata, into
/// `out`. `Err` carries the compiler's own messages.
pub(crate) fn compile_alone(file: &Path, test: bool, out: &Path) -> Result<(), String> {
    let empty = out.join("empty-library-path");
    std::fs::create_dir_all(&empty).map_err(|e| format!("{}: {e}", empty.display()))?;
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let mut c = Command::new(&rustc);
    c.args(["--edition", EDITION, "--emit=metadata", "--cap-lints", "allow", "--crate-name", "shared_file"])
        .arg("--out-dir")
        .arg(out)
        .arg("-L")
        .arg(&empty);
    if test {
        c.arg("--test");
    } else {
        c.args(["--crate-type", "lib"]);
    }
    let run = c.arg(file).output().map_err(|e| format!("{}: cannot run: {e}", rustc.to_string_lossy()))?;
    if run.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&run.stderr).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    fn repo() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).parent().expect("xtask has a parent").to_path_buf()
    }

    /// Each file xtask compiles from another crate compiles alone, as a library and as its
    /// tests, with nothing but `std` in reach.
    #[test]
    fn every_file_xtask_compiles_by_path_names_only_std() {
        let out = tempfile::tempdir().unwrap();
        for file in STD_ONLY {
            for test in [false, true] {
                if let Err(e) = compile_alone(&repo().join(file), test, out.path()) {
                    panic!(
                        "{file} is compiled into xtask by `#[path]` and must name nothing but \
                         `std`; compiled alone{} it does not:\n{e}",
                        if test { " with --test" } else { "" }
                    );
                }
            }
        }
    }

    /// The list is every Rust source outside `xtask/` that rustc recorded as compiled into
    /// this test binary (the dep-info cargo keeps beside it): a file compiled in and not
    /// listed would go unheld, and a listed file nothing compiles in would be held for no
    /// reason. `xtask/tests/` is a different binary and out of scope (see the module doc).
    #[test]
    fn the_list_is_every_file_xtask_compiles_from_outside_xtask() {
        let exe = std::env::current_exe().unwrap();
        let info = exe.with_extension("d");
        let text = std::fs::read_to_string(&info)
            .unwrap_or_else(|e| panic!("{}: the dep-info cargo writes beside a test binary: {e}", info.display()));
        let root = repo().canonicalize().unwrap();
        let first = text.lines().next().unwrap_or_default();
        let (_, deps) = first.split_once(": ").unwrap_or_else(|| panic!("{}: no `target: deps` line", info.display()));
        let mut compiled = BTreeSet::new();
        for dep in deps.replace("\\ ", "\u{0}").split(' ').filter(|d| !d.is_empty()) {
            let dep = dep.replace('\u{0}', " ");
            if !dep.ends_with(".rs") {
                continue;
            }
            let file = root.join(&dep).canonicalize().unwrap_or_else(|e| panic!("{dep}: {e}"));
            let Ok(rel) = file.strip_prefix(&root) else { continue };
            if !rel.starts_with("xtask") {
                compiled.insert(rel.to_string_lossy().replace('\\', "/"));
            }
        }
        let listed: BTreeSet<String> = STD_ONLY.iter().map(|s| s.to_string()).collect();
        assert_eq!(compiled, listed, "the sources from outside xtask/ in {} (left) are not `STD_ONLY` (right)", info.display());
    }

    /// Compile `files` (name, text) written into a scratch directory, the first as the crate
    /// root, and return the compiler's messages, as library and as tests.
    fn alone(files: &[(&str, &str)]) -> (Result<(), String>, Result<(), String>) {
        let dir = tempfile::tempdir().unwrap();
        for (name, text) in files {
            let path = dir.path().join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        let root = dir.path().join(files[0].0);
        let out = dir.path().join("out");
        (compile_alone(&root, false, &out), compile_alone(&root, true, &out))
    }

    /// A planted `use serde_json` in a scratch copy of each listed file — the import both
    /// crates link, which the build cannot catch — fails, and the compiler names it.
    #[test]
    fn a_planted_use_serde_json_in_a_scratch_copy_is_found() {
        for file in STD_ONLY {
            let text = std::fs::read_to_string(repo().join(file)).unwrap();
            let planted = format!("{text}\n#[allow(unused_imports)]\nuse serde_json::Value;\n");
            let (lib, _) = alone(&[("planted.rs", &planted)]);
            let e = lib.expect_err(file);
            assert!(e.contains("serde_json"), "{file}:\n{e}");
        }
    }

    /// Every spelling of a crate outside `std` that the earlier text readers missed fails:
    /// a leading `::` after `->`, `=>`, a comparison or `1 << 2` inside a macro, a raw
    /// identifier, a value-namespace item of the crate's name, a `std` alias or a module of
    /// that name in another module, a `$crate` path, a nested `#[path]` module (under an
    /// inline module) or an `include!`, a `cfg_attr` path, and a `use` only the tests see.
    #[test]
    fn every_spelling_of_a_crate_outside_std_fails() {
        let cases: &[(&[(&str, &str)], &str)] = &[
            (&[("a.rs", "pub fn f() -> String { ::serde_json::to_string(&1).unwrap() }")], "serde_json"),
            (&[("a.rs", "pub fn f() -> ::serde_json::Value { todo!() }")], "serde_json"),
            (&[("a.rs", "pub fn f(x: u8) { match x { _ => ::serde_json::x(), } }")], "serde_json"),
            (&[("a.rs", "pub fn f(x: u8) -> bool { x > ::serde_json::N }")], "serde_json"),
            (&[("a.rs", "macro_rules! m { () => {{ let a = 1 << 2; a > ::serde_json::N }} }\npub fn f() -> bool { m!() }")], "serde_json"),
            (&[("a.rs", "pub fn f() { r#serde_json::x(); }")], "serde_json"),
            (&[("a.rs", "#[allow(dead_code)] fn serde_json() {}\npub fn f() -> String { serde_json::to_string(&1).unwrap() }")], "serde_json"),
            (&[("a.rs", "mod a { #[allow(unused_imports)] use std::io as serde_json; }\npub fn f() { serde_json::x(); }")], "serde_json"),
            (&[("a.rs", "mod a { pub mod serde_json {} }\nmod b { pub fn f() { serde_json::x(); } }")], "serde_json"),
            (&[("a.rs", "macro_rules! m { () => { $crate::missing::x() } }\npub fn f() { m!() }")], "missing"),
            (&[("a.rs", "#[derive(serde::Serialize)] pub struct S;")], "serde"),
            (&[("a.rs", "pub fn f<T>() where T: serde::Serialize {}")], "serde"),
            (&[("a.rs", "mod inner { #[path = \"e.rs\"] mod e; }"), ("inner/e.rs", "pub fn f() { serde_json::x(); }"), ("e.rs", "")], "serde_json"),
            (&[("a.rs", "include!(\"c.rs\");"), ("c.rs", "pub fn f() { serde::x(); }")], "serde"),
            (&[("a.rs", "#[cfg_attr(all(), path = \"p.rs\")] mod p;"), ("p.rs", "pub fn f() { serde::x(); }")], "serde"),
            (&[("a.rs", "pub mod b;"), ("b.rs", "pub fn f() { serde::x(); }")], "serde"),
        ];
        for (files, needle) in cases {
            let (lib, test) = alone(files);
            for (how, result) in [("lib", &lib), ("test", &test)] {
                match result {
                    Err(e) => assert!(e.contains(needle), "{files:?} as {how} failed, not on `{needle}`:\n{e}"),
                    Ok(()) => panic!("{files:?} compiled alone as {how}"),
                }
            }
        }
        let (lib, test) = alone(&[("a.rs", "#[cfg(test)]\nmod tests { #[allow(unused_imports)] use serde_json::Value; }")]);
        assert!(lib.is_ok(), "{lib:?}");
        assert!(test.as_ref().is_err_and(|e| e.contains("serde_json")), "a `use` only the tests compile is held by `--test`: {test:?}");
    }

    /// What names only `std` compiles alone: the standard library and the file's own
    /// modules by any spelling, a local module or `std` alias used where it is in scope,
    /// prelude names, turbofish, qualified paths, lint tools, and crate names in comments
    /// and strings.
    #[test]
    fn what_names_only_std_compiles_alone() {
        let src = r##"//! Read by `kvaultd::settings::env_file_pairs`.
use std::path::{self, Path};
use std::{fs, io as sio};
/* serde_json::Value, /* nested */ still a comment */
#[allow(clippy::too_many_lines)]
pub fn f(s: &str) -> usize {
    let _ = "serde_json::to_string"; let _ = r#"serde::x "quoted""#;
    let _ = path::PathBuf::new(); let _ = ::std::fs::read("x"); let _ = sio::stdin();
    let _: Vec<u8> = s.bytes().collect::<Vec<_>>();
    let _ = Vec::<u8>::new(); let _ = <u8 as std::str::FromStr>::from_str("1");
    let _ = <Vec<u8>>::new(); let _ = Option::<u8>::None; let _ = local::x();
    let _ = 1 << 2 > ::core::cmp::max(1, 0);
    u8::MAX as usize + Path::new("").as_os_str().len() + fs::metadata("").map_or(0, |_| 0)
}
mod local { pub fn x() {} }
#[cfg(test)]
mod tests { use super::*; #[test] fn g() { let _ = self::super::f(""); } }
"##;
        let (lib, test) = alone(&[("a.rs", src)]);
        assert!(lib.is_ok() && test.is_ok(), "lib: {lib:?}\ntest: {test:?}");
    }
}
