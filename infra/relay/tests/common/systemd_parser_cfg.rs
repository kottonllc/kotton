// SPDX-License-Identifier: AGPL-3.0-or-later
// The build-time half of `KOTTON_NO_SYSTEMD_PARSER`, the one source of it, `include!`d by the
// build script of each crate whose tests need systemd's own settings parser: the relay
// (`infra/relay/build.rs`), the vault (`core/kvaultd/build.rs`) and xtask (`xtask/build.rs`,
// for `release_server_gate`). Where a developer declares the variable — a machine that cannot have
// the parser — this sets the `kotton_no_systemd_parser` cfg, under which those tests are
// `#[ignore]`d with a reason, so libtest's own verdict counts them ignored, by name, rather
// than passed. Undeclared, a missing parser fails them at run time. The run-time half, and why
// both live under this directory, is `systemds_parser.rs` beside it
// (`TASK-the-settings-differential-is-not-green-where-systemds-parser-is-absent`,
// `TASK-the-release-gate-requires-systemds-parser-and-does-not-run-the-differential`).
//
// Plain comments, not `//!`: an `include!`d file's items land inside the build script, where
// an inner attribute or doc is not allowed.
//
// `shared` is this file's path as the including build script names it — relative to that
// build script, which is at its package's root, so it is also the path cargo resolves a
// `rerun-if-changed` against. Both files are watched, and the variable: a build script that
// watches a file which does not exist is rerun on every build
// (the assessor's refusal of a3fa73c04, which pointed xtask at the relay's `build.rs`).
fn declare_systemd_parser_cfg(shared: &str) {
    println!("cargo::rustc-check-cfg=cfg(kotton_no_systemd_parser)");
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed={shared}");
    println!("cargo::rerun-if-env-changed=KOTTON_NO_SYSTEMD_PARSER");
    if std::env::var_os("KOTTON_NO_SYSTEMD_PARSER").is_some_and(|v| !v.is_empty()) {
        println!("cargo::rustc-cfg=kotton_no_systemd_parser");
    }
}
