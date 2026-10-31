// SPDX-License-Identifier: AGPL-3.0-or-later
//! `cargo xtask` â€” internal code-generation and maintenance tasks.
//!
//! Usage: `cargo xtask <subcommand>`; with no subcommand, or an unknown one, it prints every
//! subcommand and what it does. `just lint` runs the checks among them.

// With `cli-docs` on, a rustc warning in the gated code is an error. `cargo xtask-docs`, which
// `just lint` already runs, builds that code under plain rustc, where a warning would print and
// be ignored; this makes it fatal there at no extra compile. Rustc warnings only, not clippy lints.
#![cfg_attr(feature = "cli-docs", deny(warnings))]

mod seed;

#[cfg(feature = "cli-docs")]
use kotton_cli::Cli;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

// Windows-only: raw FFI for suppressing the spurious STATUS_CONTROL_C_EXIT
// error when the user Ctrl-Cs the dev daemon.  No extra crate needed.
#[cfg(windows)]
extern "system" {
    fn SetConsoleCtrlHandler(
        handler_routine: Option<unsafe extern "system" fn(u32) -> i32>,
        add: i32,
    ) -> i32;
}

#[cfg(windows)]
unsafe extern "system" fn noop_ctrl_handler(_ctrl_type: u32) -> i32 {
    1 // TRUE â€” signal handled; don't terminate xtask
}

#[cfg(test)]
mod compose_file_tests;
mod claim_check;
mod request_domains;
mod windows_check;
/// Today as `YYYY-MM-DD`, computed rather than shelled out so it works on Windows.
///
/// Howard Hinnant's civil-from-days, which is exact for the whole proleptic Gregorian
/// range and needs no crate — this binary is deliberately dependency-light
/// (TASK-xtask-drags-in-the-whole-workspace).
pub fn today() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let z = (secs / 86_400) as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

mod doctor;
mod merge;
mod port_check;
mod tree;
mod caller_check;
mod relay_address_check;
mod device_add_check;
mod channel_check;
mod config_key_check;
mod infer_check;
mod license_check;
mod out;
mod reclaim;
mod rg;
mod release;
mod release_server;
mod remote_request;
mod residency_check;
mod scope_check;
mod suite_check;
mod wire_check;
mod actions_check;
#[cfg(test)]
mod git_fixture;
mod docs_present_check;
mod host_word_check;
mod signoff_check;
mod workspace_hack;
mod worktrees;
mod user_database_check;
mod wx_check;
mod ship_check;
#[cfg_attr(not(feature = "cli-docs"), allow(dead_code))]
mod verb_check;
#[cfg_attr(not(feature = "cli-docs"), allow(dead_code))]
mod retired_words;
#[cfg(any(test, feature = "cli-docs"))]
mod verb_tables;
fn main() {
    let mut args = std::env::args().skip(1); // skip binary name
    // The checkout this runs in, asked of git — never `env!("CARGO_MANIFEST_DIR")`, which
    // is the directory xtask was *compiled* in and outlives it
    // (`TASK-constitution-check-resolves-its-files-against-where-xtask-was-built`).
    let workspace_root = &out::root();

    match args.next().as_deref() {
        Some("seed") => {
            let rest: Vec<String> = args.collect();
            seed::run(workspace_root, &rest);
        }
        #[cfg(feature = "cli-docs")]
        Some("gen-docs") => {
            gen_docs();
        }
        #[cfg(feature = "cli-docs")]
        Some("verb-check") => {
            let rest: Vec<String> = args.collect();
            verb_check_run(workspace_root, &rest);
        }
        #[cfg(not(feature = "cli-docs"))]
        Some(cmd @ ("gen-docs" | "docs-check" | "verb-check")) => {
            eprintln!(
                "`{cmd}` walks the real CLI and shell command trees, so it needs the \
                 `cli-docs` feature.\n\nRun `cargo xtask-docs {cmd}` — or `just lint`, \
                 which already does."
            );
            std::process::exit(2);
        }
        Some("gen-types") => {
            gen_types();
        }
        Some("windows-check") => {
            windows_check::run();
        }
        Some("stage-shell") => {
            // Staging on its own, for a caller that has already built and only
            // wants the shell placed where its daemon will look.
            stage_system_shell(&staging_base(
                std::env::var("KOTTON_BASE_DIR").ok().as_deref(),
            ));
        }
        Some("build-apps") => {
            let force = std::env::args().any(|a| a == "--force");
            build_apps(force, guest_target);
        }
        Some("build-relay") => {
            let rest: Vec<String> = args.collect();
            build_relay(&rest);
        }
        // The build a friend installs, and its install test
        // (`TASK-a-friend-cannot-install-kotton-without-a-toolchain`).
        Some("release") => {
            let rest: Vec<String> = args.collect();
            release::release(workspace_root, &rest);
        }
        Some("release-test") => {
            let rest: Vec<String> = args.collect();
            release::release_test(&rest);
        }
        // The relay and the vault, each one archive a host installs under systemd,
        // and its install test (DEC-0085).
        Some("release-server") => {
            let rest: Vec<String> = args.collect();
            release_server::release_server(workspace_root, &rest);
        }
        Some("release-server-test") => {
            let rest: Vec<String> = args.collect();
            release_server::release_server_test(&rest);
        }
        Some("run::headless") => {
            // Headless entry is identity-first — you're identified by your key, not
            // a username. There is no named path: the REPL always onboards (enter
            // your key, or create a new identity).
            run(None, workspace_root, Profile::Headless);
        }
        Some("run::first-run") => {
            first_run(workspace_root);
        }
        Some("run::desktop") => {
            // Optional, and an empty string is the same as absent — `just` passes a
            // defaulted parameter as `""` rather than omitting it. With no user the
            // window onboards (`DEC-0077`); with one it opens that existing identity.
            let user = args.next().filter(|u| !u.is_empty());
            run(user.as_deref(), workspace_root, Profile::Desktop);
        }
        Some("demo::sync") => {
            demo_sync(workspace_root);
        }
        Some("constitution-check") => {
            constitution_check();
        }
        Some("doctor") => {
            let rest: Vec<String> = std::env::args().skip(2).collect();
            doctor::run(&rest);
        }
        Some("tier-check") => {
            tier_check();
        }
        Some("blindness-check") => {
            blindness_check();
        }
        Some("vault-check") => {
            vault_check();
        }
        Some("infer-check") => {
            infer_check::infer_check();
        }
        Some("wx-check") => {
            wx_check::wx_check();
        }
        // Every binary an archive packs links only the system's crates and crates.io (#1).
        Some("ship-check") => {
            ship_check::ship_check(workspace_root);
        }
        Some("bind-check") => {
            // Everything after the subcommand goes to `cargo test`, so
            // `bind-check -- -p kuid --features ...` narrows the run.
            let rest: Vec<String> = args.by_ref().skip_while(|a| a == "--").collect();
            bind_check(&rest);
        }
        Some("key-reach-check") => {
            key_reach_check();
        }
        Some("link-check") => {
            link_check();
        }
        #[cfg(feature = "cli-docs")]
        Some("docs-check") => {
            docs_check();
        }
        Some("claim-check") => {
            let rest: Vec<String> = args.collect();
            claim_check::run(&rest);
        }
        Some("facts-check") => {
            facts_check();
        }
        Some("docs-present-check") => docs_present_check::run(workspace_root),
        Some("host-word-check") => host_word_check::run(workspace_root),
        Some("actions-check") => {
            let rest: Vec<String> = args.collect();
            actions_check::run(&rest);
        }
        Some("signoff-check") => {
            signoff_check::run(workspace_root);
        }
        Some("worktrees") => {
            let rest: Vec<String> = args.collect();
            worktrees::run(&rest);
        }
        Some("out") => {
            let rest: Vec<String> = args.collect();
            out::run(&rest);
        }
        Some("reclaim") => {
            let rest: Vec<String> = args.collect();
            reclaim::run(&rest);
        }
        Some("workspace-hack") => workspace_hack::generate(workspace_root),
        Some("workspace-hack-check") => workspace_hack::check(workspace_root),
        // A branch reaches `main` through one recipe that builds the merged tree first
        // (TASK-a-merge-reached-main-without-being-built).
        Some("merge") => {
            let rest: Vec<String> = args.collect();
            merge::run(&rest);
        }
        Some("port-check") => {
            port_check::run();
        }
        // Every dependency's license is one Kotton may ship under, every crate and source
        // file says Kotton's, and every archive's notices can be made
        // (TASK-a-release-carries-its-third-party-notices-and-every-dependency-has-a-known-license).
        Some("license-check") => license_check::run(workspace_root),
        Some("third-party-notices") => {
            let rest: Vec<String> = args.collect();
            license_check::print(workspace_root, &rest);
        }
        Some("request-domains") => {
            request_domains::run();
        }
        Some("channel-check") => {
            channel_check::channel_check();
        }
        Some("scope-check") => {
            scope_check::scope_check();
        }
        Some("caller-check") => {
            caller_check::caller_check();
        }
        // A relay's address is compared by `same_relay_address` and nowhere else
        // (TASK-a-relay-address-is-compared-in-one-place).
        Some("relay-address-check") => relay_address_check::run(workspace_root),
        // No code under core/ spells `device add --`.
        Some("device-add-check") => device_add_check::run(workspace_root),
        Some("residency-check") => {
            residency_check::residency_check();
        }
        Some("config-key-check") => {
            config_key_check::run();
        }
        Some("suite-check") => {
            suite_check::suite_check();
        }
        Some("remote-request") => {
            remote_request::run(true);
        }
        Some("remote-request-check") => {
            remote_request::run(false);
        }
        Some("wire-check") => {
            wire_check::wire_check(false);
        }
        Some("wire-surface") => {
            wire_check::wire_check(true);
        }
        other => {
            eprintln!(
                "Unknown subcommand: {}\n\nAvailable:\n  gen-docs                                                   Re-generate docs/cli/reference.md (cargo xtask-docs)\n  gen-types                                                  Re-generate the TypeScript type surface from ts-rs annotations\n  build-apps [--force]                                       Compile bundled WASM apps for wasm32-wasip2\n  build-relay [cargo args]                                   Build kotton-relay into out/relay (or CARGO_TARGET_DIR) and print the binary's path\n  out [what]                                                 Print where a build output lives: target, xtask, relay, dist, bindwatch, guest/<app>, merge, release[/workspace|/relay]\n  release [--allow-dirty] [--no-build]                       Build the system's daemons and the CLI --release, pack them as one archive under out/dist/, and install-test it — prefer `just release::desktop`\n  release-test <archive>                                     Install an archive into a clean directory, run `kotton --help`, start it, and run `kotton id create` from it\n  release-server relay|vault|host [--not-a-release] [--no-build]  Build the relay or the vault for Linux, or both as the host's archive, pack it with its systemd units and SHA256SUMS under out/dist/, install-test it, and print its sha256\n  release-server-test <archive> [--relay <archive>]          Install a server or host archive into a clean root, start it there, and read /health or its first log line\n  run::headless                                              Run headless (kuserd + REPL). Assumes built — prefer `just headless::run`\n  run::desktop [user]                                        Run with the kuid display server; no user means the window onboards — prefer `just desktop::run`\n  run::first-run                                             Wipe .kotton.firstrun and start the daemon there with no user — prefer `just desktop::first-run`\n  demo::sync                                                 Two-node encrypted file transfer demo (QUIC mTLS)\n  doctor [--tier T]                                          Check this checkout has what it needs (lint | test | build | desktop | server)\n  constitution-check                                         Check the code against the principles it inspects: II, III and IV\n  tier-check                                                 Check core/ crate deps obey the region and platform-seam rules\n  blindness-check                                            Check terminal storage backends hold no key material\n  vault-check                                                Check the vault names none of the crates that carry plaintext verbs, inference, the apps or the display\n  infer-check                                                Check core/infer links and names no socket\n  wx-check                                                   Check a server whose unit says MemoryDenyWriteExecute=yes links no code-emitting crate\n  ship-check                                                 Check every binary an archive packs links only the system's crates and crates.io, and print the cuts still owed\n  bind-check [-- args]                                       Run the tests and fail if any binds a non-loopback socket (Linux)\n  key-reach-check                                            Check only entitled crates can name SealingKeys\n  residency-check                                            Check `device` may name a user store but not enumerate one\n  scope-check                                                Check a declared IPC scope names verbs the channel has\n  channel-check                                              Check one acceptor serves one request type\n  caller-check                                               Check no request is accepted without being told who sent it\n  relay-address-check                                        Check a relay's address is compared in one place\n  device-add-check                                           Check no code under core/ spells `device add --` (tests, comments skipped)\n  config-key-check                                           Check every device-config key read is also written\n  request-domains                                            Check every UserRequest variant has a domain\n  wire-check                                                 Check the request, peer-request, vault-peer-request, relay-operator, operator-verb and response wire surfaces match their recordings in core/wire, and each peer verb records its door twin's block\n  wire-surface                                               Re-record those surfaces after a deliberate wire change, then print (exit 0) any peer verb whose block no longer matches its door twin's\n  remote-request[-check]                                     Re-generate, or check, RemoteRequest from required_trust()'s Remote arms\n  windows-check                                              Check no Unix-only path is compiled on Windows too\n  suite-check                                                Check every integration test file is compiled into the suite\n  port-check                                                 Check the relay and the vault compose onto one machine\n  license-check                                              Check every dependency's licence, every crate's and file's own, and LICENSE's table\n  third-party-notices                                        Print an archive's THIRD-PARTY-NOTICES\n  link-check                                                 Check relative Markdown links in docs/ and the root docs, and that none holds a merge-conflict marker\n  docs-check                                                 Check docs/cli/reference.md matches `gen-docs` output (cargo xtask-docs)\n  verb-check [--pinned]                                      Check the clap tree and the REPL's registry are the command-tree decision's, one tree for drive, pin and sync, and that no line a person reads names a retired verb (cargo xtask-docs)\n  docs-present-check                                         Check no page under docs/ or at the root, no line xtask prints and no Rust comment under the trees host-word-check reads (but the files not yet swept) names a record or narrates a date, and no file beside the pages names a record\n  claim-check [page…]                                        Check every `kotton` command README.md (and each page named) gives is one the binary has, and every script it runs is in the tree\n  host-word-check                                            Check the copy a person reads says host, instance, relay or vault\n  facts-check                                                Check repo paths named in CLAUDE.md, README.md and CONTRIBUTING.md exist\n  actions-check                                              Check every GitHub workflow is the release on a pushed tag or the pull-request lint, on Linux\n  signoff-check                                              Check no commit since origin/main is made as an agent and each is certified by a person\n  workspace-hack[-check]                                     Re-generate, or check, the one feature set every test build shares\n  merge <branch> -m <msg> [--no-fetch] [--no-push]           Merge a branch current with main into main, build the merged tree, run signoff-check at the tip, commit as the owner and push\n  worktrees [--prune]                                        Report each worktree's branch, age and out/ size; remove merged ones\n  reclaim [--dry-run]                                        Reclaim disk from this checkout's build caches\n  seed                                                       Populate a running daemon with a plausible household, through the real CLI",
                other.unwrap_or("<none>")
            );
            std::process::exit(1);
        }
    }
}

/// Build `kotton-relay`, a workspace of its own, into `out/relay` — or `CARGO_TARGET_DIR`
/// when that is exported — and print the path cargo reported for the binary.
///
/// One command for every recipe that builds the relay, so the directory is stated once
/// (`out::own_target`) and read back by the suite's `relay_bin`, rather than each recipe
/// passing its own `--target-dir` or, as before 2026-09-26, none — which left the binary
/// in `infra/relay/target` for the harness to look for by composing that path. Extra
/// arguments go to `cargo build` (`--release`, `--bin …`). A developer's convenience build,
/// so it follows the variable; the relay a release packs is built by `release-server` in a
/// target of its own (decision 0014).
fn build_relay(extra: &[String]) {
    let built = out::build_artifacts(
        Command::new("cargo")
            .args(["build", "--manifest-path", "infra/relay/Cargo.toml", "--bin", "kotton-relay"])
            .args(extra)
            .arg("--target-dir")
            .arg(out::own_target("relay"))
            .current_dir(out::root()),
    )
    .unwrap_or_else(|| {
        eprintln!("build-relay: cargo build failed");
        std::process::exit(1);
    });
    let name = format!("kotton-relay{}", std::env::consts::EXE_SUFFIX);
    let bin = out::named(&built, &name).unwrap_or_else(|| {
        eprintln!("build-relay: cargo built the relay and reported no {name}");
        std::process::exit(1);
    });
    println!("{}", bin.display());
}

/// Every guest app and example `build_apps` builds, as
/// (app-dir, cargo-package-name, cdylib-filename-stem, manifest-subpath).
///
/// Rust/WASM logic lives in a `logic/` subdirectory of each app. The entries after the
/// bundled apps are examples rather than apps, each with its reason beside it.
const GUEST_APPS: [(&str, &str, &str, &str); 5] = [
    (
        "guest/apps/kotton-shell",
        "kotton-shell-logic",
        "kotton_shell_logic",
        "logic",
    ),
    (
        "guest/apps/kotton-editor",
        "kotton-editor-logic",
        "kotton_editor_logic",
        "logic",
    ),
    // The project's records, as an app (RFC-0088 phase two): a third
    // bundled guest in `world app`, reading one schema through `schema.kept`.
    (
        "guest/apps/kotton-records",
        "kotton-records-logic",
        "kotton_records_logic",
        "logic",
    ),
    // What `kotton app new hello` writes, the SDK's dependency line aside; building it here
    // holds the scaffold to the SDK.
    ("guest/examples/hello", "hello", "hello", "."),
    // The worked example an author copies once `hello` is not enough. Its `Cargo.toml` says
    // the gate compiles it; building it here is what makes that true, so a change to the SDK
    // that breaks the example an author starts from fails here, not in their checkout.
    ("guest/examples/notes", "notes", "notes", "."),
];

/// The triple every guest app is built for.
const GUEST_TRIPLE: &str = "wasm32-wasip2";

/// The name each guest app's target is named for: its directory's last component.
fn guest_app_name(dir: &'static str) -> &'static str {
    dir.rsplit('/').next().expect("an app directory has a name")
}

/// Where a `build_apps` build of the guest app `app` into `target_dir` leaves its component:
/// `<target_dir>/wasm32-wasip2/release/<lib>.wasm`, the path cargo reports for a target
/// directory it was handed, which `build_apps` holds it to. `None` for an app it does not
/// build.
pub(crate) fn guest_wasm(target_dir: &Path, app: &str) -> Option<PathBuf> {
    let (_, _, lib, _) = GUEST_APPS.iter().find(|(dir, ..)| guest_app_name(dir) == app)?;
    Some(target_dir.join(GUEST_TRIPLE).join("release").join(format!("{lib}.wasm")))
}

/// Where `build-apps` builds the guest app `app`: a developer's convenience build,
/// so `out/guest/<app>`, or `CARGO_TARGET_DIR` when that is exported (`out::own_target`).
/// `release` builds no guest app and packs none: the system's archive carries the daemons and
/// the CLI alone (`release::BINS`).
fn guest_target(app: &str) -> PathBuf {
    out::own_target(&format!("guest/{app}"))
}

/// Build every guest app and test fixture for `wasm32-wasip2`, each into `target_of(<app>)`,
/// and copy each component to `<app dir>/app.wasm`, where `kuserd`'s build embeds it from when
/// it is there. The caller names the target; [`guest_target`] is the only one passed, since
/// `release` calls none of this.
pub(crate) fn build_apps(force: bool, target_of: fn(&str) -> PathBuf) {
    const TARGET: &str = GUEST_TRIPLE;
    // Paths are the checkout's, whatever directory this was run from.
    let root = out::root();

    // Ensure the wasm32-wasip2 target is installed.
    let status = Command::new("rustup")
        .args(["target", "add", TARGET])
        .status()
        .expect("failed to run rustup");
    if !status.success() {
        eprintln!("Failed to add {TARGET} via rustup. Install rustup and retry.");
        std::process::exit(1);
    }


    for (app_dir, package, lib_name, subpath) in &GUEST_APPS {
        // Each app is its own workspace with its own Cargo.lock, and builds into the target
        // the caller named for it. Cargo reads configuration from where it is run, not from
        // the manifest it is handed, so this is passed rather than configured.
        let app = Path::new(app_dir)
            .file_name()
            .expect("an app directory has a name")
            .to_string_lossy();
        let target_dir = target_of(&app);

        // --force: wipe the wasm32-wasip2 target dir so Cargo does a clean rebuild.
        // Useful when the WIT file changed but Cargo's fingerprint didn't catch it.
        if force {
            let wasm_dir = target_dir.join(TARGET);
            if wasm_dir.exists() {
                println!("[force] removing {}", wasm_dir.display());
                fs::remove_dir_all(&wasm_dir).unwrap_or_else(|e| {
                    eprintln!("Warning: could not remove {}: {e}", wasm_dir.display())
                });
            }
        }
        println!("Building {package} for {TARGET}…");

        // App crates are excluded from the workspace (they target wasm32-wasip2).
        // Use --manifest-path so cargo treats each as a standalone crate.
        let manifest = root.join(format!("{app_dir}/{subpath}/Cargo.toml"));
        let built = out::build_artifacts(
            Command::new("cargo")
                .args(["build", "--target", TARGET, "--release", "--manifest-path"])
                .arg(&manifest)
                .arg("--target-dir")
                .arg(&target_dir)
                .current_dir(&root),
        )
        .unwrap_or_else(|| {
            eprintln!("cargo build failed for {package}");
            std::process::exit(1);
        });

        // The wasm is where cargo said it put it. This used to be composed from
        // `<app>/logic/target/…`, and panicked the first day a worktree exported
        // `CARGO_TARGET_DIR` (`TASK-two-builds-break-under-a-shared-target-directory`).
        let wasm_name = format!("{lib_name}.wasm");
        let wasm_src = out::named(&built, &wasm_name).unwrap_or_else(|| {
            eprintln!("cargo built {package} and reported no {wasm_name}");
            std::process::exit(1);
        });
        // The release packs the shell from `guest_wasm`, so where cargo said it put the
        // component is held to that path, here, where it can be asked.
        let expected = guest_wasm(&target_dir, &app);
        let same = expected.as_deref().and_then(|p| fs::canonicalize(p).ok())
            == fs::canonicalize(wasm_src).ok();
        if expected.is_none() || !same {
            eprintln!(
                "cargo put {package}'s component at {}, and the release reads it from {}",
                wasm_src.display(),
                expected.map_or_else(|| "nowhere".to_string(), |p| p.display().to_string())
            );
            std::process::exit(1);
        }
        let wasm_dst = root.join(format!("{app_dir}/app.wasm"));
        fs::copy(wasm_src, &wasm_dst).unwrap_or_else(|e| {
            panic!("Failed to copy {} → {}: {e}", wasm_src.display(), wasm_dst.display())
        });
        println!("  → {app_dir}/app.wasm");
    }

    println!("\nAll apps compiled.");
}

/// Copy the built shell into `<base>/system/shell/`, where a daemon with no
/// resident user looks for something to draw.
///
/// A fresh machine has no user, so no per-user app registry, so nothing to
/// resolve the `shell` role against — `app_launch_system_shell` reads this fixed
/// device-scoped path instead. Something has to put the shell there. In a
/// packaged Kotton that is the installer; here it is this.
///
/// Staging rather than embedding in the daemon binary: the wasm is a guest
/// artifact built by a different toolchain for a different target, and
/// `include_bytes!` would make `cargo build -p kuserd` fail on a checkout that
/// has not run `build-apps` yet. The tradeoff is that the file can be missing at
/// runtime, which `app_launch_system_shell` reports by name rather than by
/// drawing nothing.
/// The base dir the daemon this command is about to start will read.
///
/// `kotton_common::paths::base_dir()` is the same resolver `kuserd` uses, so
/// `KOTTON_BASE_DIR` and the platform default are honoured identically. Staging
/// against a *guess* is what the first draft did — it hardcoded `.kotton.dev`,
/// which is right for `just dev` and wrong for `run::desktop`, where kuserd
/// takes the platform default and would have found nothing to draw.
fn staging_base(explicit: Option<&str>) -> PathBuf {
    match explicit {
        Some(dir) => PathBuf::from(dir),
        None => kotton_common::paths::base_dir()
            .unwrap_or_else(|e| panic!("cannot resolve the Kotton base dir: {e}")),
    }
}

/// Whether `run` stages the shell before the daemon starts — the whole staging
/// decision, as a function of the run rather than of what the run happens to reach.
///
/// **Every desktop run stages, with a user named or without one** (the owner, 2026-09-21,
/// on `TASK-the-desktop-stages-the-shell-on-every-run-and-the-window-owns-the-credential`).
/// The staged copy is the body the designated shell runs from on *every* path — the
/// welcome, the lock screen, and the relaunch as a user, which `designated_shell_body`
/// in `core/app/src/daemon/apps.rs` resolves to it. There is one body of the shell, so a
/// run that skipped staging ran whatever the previous run left behind and no rebuild
/// reached the desk.
///
/// `user` is a parameter and is not read, deliberately: this answer used to depend on it,
/// on two reasons that are both gone. A named user does **not** have a shell of their own
/// — the registry row carries the designation, not a second body. And the guard that
/// withheld staging from a named run was not keeping bodies apart either; it was holding a
/// second door shut, because with nothing staged the pre-identity launch failed, and that
/// failure is what stopped a screen appearing while the terminal separately asked for a
/// passphrase. The terminal no longer asks on any desktop path (`DEC-0077`: the window
/// owns the credential), so there is nothing left for a guard to hold.
///
/// Headless stages nothing: it has no window, and its surface is the terminal.
fn should_stage_shell(desktop: bool, _user: Option<&str>) -> bool {
    desktop
}

fn stage_system_shell(base: &Path) {
    let dst = base.join("system").join("shell");
    if let Err(e) = fs::create_dir_all(&dst) {
        eprintln!("Warning: could not create {}: {e}", dst.display());
        return;
    }
    for (src, name) in [
        ("guest/apps/kotton-shell/app.wasm", "app.wasm"),
        ("guest/apps/kotton-shell/manifest.toml", "manifest.toml"),
    ] {
        if let Err(e) = fs::copy(src, dst.join(name)) {
            eprintln!("Warning: could not stage {src}: {e}");
            return;
        }
    }
    println!("  → {} (the shell every path runs)", dst.display());
}

/// Run profile — selects whether the GUI shell (kuid + the WASM apps) is part of the
/// run. The matching binaries are produced by `just <profile>::build`.
#[derive(Clone, Copy)]
enum Profile {
    /// Core daemons + CLI + the WASM sandbox runner (compute) — no GPU/display server.
    Headless,
    /// Headless + the kuid display server and the GUI shell app (requires Python 3).
    Desktop,
}

impl Profile {
    fn is_desktop(self) -> bool {
        matches!(self, Profile::Desktop)
    }
}

/// Run Kotton for `user`: stage the shell (desktop), spawn kuserd, and hand over to the
/// surface — the window on the desktop, the REPL headless. kuserd supervises kuid for the
/// desktop GUI. Assumes the binaries are already built (the `just <profile>::run` recipe
/// depends on `<profile>::build`).
///
/// It creates no identity and opens none: a name is checked here and unlocked in the
/// window (`DEC-0077`). Every run stages the shell on the desktop, so the body the
/// designated shell runs from is the build this recipe just made — `should_stage_shell`.
fn run(user: Option<&str>, workspace_root: &Path, profile: Profile) {
    use std::io::BufRead;
    use std::process::Stdio;

    let desktop = profile.is_desktop();

    // 0. Kill leftover daemons so their binaries aren't locked when cargo overwrites
    // them (Windows denies writes to a running .exe).
    for name in &["kuserd", "kuid", "kdeviced"] {
        kill_by_name(name);
    }

    // Binaries (and, on desktop, the WASM apps) are produced by the
    // `just <profile>::build` step the `run` recipe depends on — `run` only
    // orchestrates: stage, spawn, hand over to the surface.

    // Stage the shell before kuserd starts — on **every** desktop run, with a user named
    // or without one. `run` sets no KOTTON_BASE_DIR, so this resolves the platform
    // default: the same answer kuserd will get.
    //
    // The staged copy is the body the designated shell runs from on every path — the
    // welcome, the lock screen, and the relaunch as a user (`designated_shell_body`
    // resolves the designation to it; `TASK-the-drawn-ground-shows-for-a-second-and-the-
    // relaunched-desk-is-flat`). A named user does not have a shell of their own, so the
    // build this recipe just made is the body every path runs, and a rebuild reaches the
    // desk. `should_stage_shell` carries the reasoning and is what the tests drive.
    if should_stage_shell(desktop, user) {
        stage_system_shell(&staging_base(
            std::env::var("KOTTON_BASE_DIR").ok().as_deref(),
        ));
    }

    // 1. Spawn kuserd.
    let kuserd_bin = bin_path("kuserd");
    let runner_bin = bin_path("kotton-runner");
    // **`info`, matching `first-run`.** This defaulted to `warn` while `run::first-run`
    // defaulted to `info`, so the same daemon logged differently depending on which recipe
    // started it — and the quieter one is the recipe a person uses every day.
    //
    // That cost three rounds of debugging a window that would not draw, on 2026-09-17: the
    // terminal says `[run] daemon log: …`, the person opens it, and finds four lines,
    // because every line that would have said what happened — which shell launched, which
    // surface opened, what the compositor did — is `INFO`. A log a person is pointed at,
    // filtered to hide the events they were sent to read, is worse than no log: it looks
    // like an answer.
    let rust_log = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    let mut kuserd_cmd = Command::new(&kuserd_bin);
    kuserd_cmd
        .current_dir(workspace_root)
        .env("RUST_LOG", &rust_log)
        .env("KOTTON_RUNNER", &runner_bin)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    prefer_x11(&mut kuserd_cmd);
    let mut kuserd = kuserd_cmd.spawn().unwrap_or_else(|e| {
        eprintln!("[run] failed to spawn kuserd: {e}");
        std::process::exit(1);
    });
    let kuserd_pid = kuserd.id();

    // 2. The daemon's output goes to a file, not the terminal. The terminal is where
    // the person is asked for a passphrase and shown six digits; three WARN lines from
    // the compositor landing on top of a hidden prompt was the owner's first run
    // (2026-09-17). What still reaches the terminal is what a person must not miss —
    // a panic, or an ERROR — one line each, and the path of the rest, once.
    let log_path = staging_base(std::env::var("KOTTON_BASE_DIR").ok().as_deref())
        .join("logs")
        .join("kuserd.log");
    let log = open_daemon_log(&log_path);
    println!("[run] daemon log: {}", log_path.display());
    let k_out = kuserd.stdout.take().unwrap();
    let k_err = kuserd.stderr.take().unwrap();
    for reader in [
        Box::new(k_out) as Box<dyn std::io::Read + Send>,
        Box::new(k_err) as Box<dyn std::io::Read + Send>,
    ] {
        let log = std::sync::Arc::clone(&log);
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(reader)
                .lines()
                .map_while(Result::ok)
            {
                if let Ok(mut f) = log.lock() {
                    if let Some(f) = f.as_mut() {
                        use std::io::Write;
                        let _ = writeln!(f, "{line}");
                    }
                }
                if line.contains("panicked at") || line.contains(" ERROR ") {
                    eprintln!("[kuserd] {line}");
                }
                // **The two lifecycle facts the person needs, out of the daemon's own
                // log** (`TASK-quit-kotton-stops-the-daemon-and-closing-the-window-does-not`).
                //
                // This recipe waits on the daemon and nothing else, so it cannot see the
                // window at all; what it can see is what the daemon says. `kuserd` logs
                // one of these two sentences when `kuid` leaves — which of them depends
                // on which gesture the person made, and the daemon is the only process
                // that knows both halves. See `kuid_left_the_window_up` in
                // `core/kuserd/src/agent/mod.rs`.
                //
                // Matched against the constants rather than against a literal, so a
                // reworded log line is a compile error's worth of join and not a
                // sentence that quietly stops printing
                // (`the_recipe_reads_the_lines_the_daemon_writes`).
                if let Some(said) = the_daemon_said_something_the_person_needs(&line) {
                    println!("[run] {said}");
                }
            }
        });
    }

    // 3. Poll IPC socket (the shared resolver — `kotton_common::paths`).
    println!("[run] waiting for daemon…");
    if !poll_ipc_ready(&kuserd_door_here(), 30) {
        eprintln!("[run] daemon did not become ready within 30 s. The end of its log:");
        if let Ok(text) = fs::read_to_string(&log_path) {
            let lines: Vec<&str> = text.lines().collect();
            for l in lines.iter().rev().take(40).rev() {
                eprintln!("  {l}");
            }
        }
        kill_pid(kuserd_pid);
        let _ = kuserd.wait();
        std::process::exit(1);
    }
    println!("[run] daemon ready");

    let kotton_bin = bin_path("kotton");

    // 4. A named identity must already exist. **This recipe does not create one, and it
    // no longer opens one either** — naming one is checked here and unlocked in the
    // window. With NO user there is nothing to check: the window (desktop) or the REPL
    // (headless) onboards identity-first.
    if let Some(user) = user {
        //
        // It used to: `kotton id create <user>`, which opens the terminal device and blocks
        // on a hidden passphrase prompt — while the window, four hundred lines above, was
        // showing the pre-identity welcome screen offering the same act. Two doors to one
        // thing, neither aware of the other, and answering the wrong one left the run
        // blocked forever on a prompt nobody was going to answer (`DEC-0077`).
        //
        // A username here means *open this identity*, never *create it*. Naming a new one
        // stays a CLI act, which is also what `occupant_host` already intends: the window
        // creates exactly one identity and does not name it, because a guest that could
        // mint arbitrarily-named users would be a naming authority.
        if !user_exists(&kotton_bin, workspace_root, user) {
            eprintln!(
                "[run] there is no identity '{user}' on this device.\n\
                 \n\
                 Create one and name it:      cargo run --bin kotton -- id create {user}\n\
                 Or let the window do it:     just desktop::run        (no user)\n\
                 \n\
                 The window's welcome flow creates a single identity called 'owner'. To have\n\
                 one under another name, create it first with the command above, then run\n\
                 `just desktop::run {user}`."
            );
            kill_pid(kuserd_pid);
            let _ = kuserd.wait();
            std::process::exit(1);
        }
    }

    // 5. **On the desktop the terminal stays out of it, named user or not.** kuserd stays
    // up and supervises kuid, which opens the window; this waits on the daemon and Ctrl-C
    // stops both.
    //
    // There is no authenticate step above this line and no terminal surface below it,
    // because every terminal door here is a credential prompt: `kotton login <user>` asked
    // outright, and `kotton repl <user>` asks through `connect_as`, which prompts for the
    // PIN or recovery key whenever the cached session is missing or stale — a daemon
    // restart, which is the first thing this recipe does. `DEC-0077` rules that the window
    // owns the credential on every `desktop::*` path, so the step is deleted rather than
    // held behind a condition: two doors to one act is what that decision closed, and a
    // door that is merely shut is still a door. The window shows the welcome flow with
    // nobody named, and the lock screen — or the chooser, once several identities are
    // registered — with a name.
    //
    // 6. Windows: suppress STATUS_CONTROL_C_EXIT in this process, so that Ctrl-C reaches
    // the children (kuserd, or the REPL) and this one survives long enough to clean up.
    // It sits above the desktop's return on purpose: on the desktop, Ctrl-C ends kuserd,
    // the wait below returns, and kuid is killed by name — none of which happens if the
    // event kills xtask first.
    #[cfg(windows)]
    unsafe {
        SetConsoleCtrlHandler(Some(noop_ctrl_handler), 1);
    }

    // Headless is untouched: the terminal is its window, so the REPL below is its surface
    // and onboarding in it is the only door there is.
    if desktop {
        match user {
            Some(user) => println!("[run] the window has '{user}' — unlock there. Ctrl-C to stop."),
            None => println!(
                "[run] the window is onboarding — create your identity there. Ctrl-C to stop."
            ),
        }
        // Where the tray is, said once, because on Windows 11 it is usually not where a
        // person looks first (`TASK-the-tray-icon-is-a-dark-square-on-a-dark-tray`). The
        // owner's report was *"I'm not seeing anything in the windows tray area"* with
        // an icon that was invisible **and** parked under the chevron; the mark is fixed
        // in `kuid`, and this is the half of it that is a sentence.
        println!("[run] {TRAY_NOTE}");
        // **Unchanged, and deliberately so.** The wait is on the daemon, which is the
        // long-running process; the window is a client of it. Closing the window does
        // not end this wait — the log-reader thread above prints why, and the daemon
        // keeps replicating. *Quit Kotton* ends the daemon, and that is what ends this.
        let _ = kuserd.wait();
        kill_by_name("kuid");
        return;
    }

    // 7. Headless: drop into the REPL, which is this profile's whole surface. Ctrl-C exits.
    println!("[run] entering REPL — Ctrl-C or 'exit' to stop");
    let mut repl_cmd = Command::new(&kotton_bin);
    repl_cmd.current_dir(workspace_root);
    match user {
        // `run::headless` names nobody today (headless is identity-first — you are
        // identified by your key), so this arm is here for the contract rather than for a
        // caller: a named headless run opens that identity in its own terminal, which is
        // the surface there. The desktop, where the window owns the credential, took its
        // own branch above and never reaches this.
        Some(user) => {
            repl_cmd.args(["repl", user]);
        }
        None => {
            repl_cmd.arg("repl");
        }
    }
    let repl_status = repl_cmd.status().unwrap_or_else(|e| {
        eprintln!("[run] failed to launch REPL: {e}");
        kill_pid(kuserd_pid);
        let _ = kuserd.wait();
        std::process::exit(1);
    });
    if !repl_status.success() {
        eprintln!("[run] REPL exited with error");
    }

    // 8. REPL exited — stop kuserd.
    kill_pid(kuserd_pid);
    let _ = kuserd.wait();
    eprintln!("[run] stopped");
}

/// Boot a machine nobody has ever logged into, and watch it draw.
///
/// `run::desktop` runs against whatever this machine already has — an identity or none —
/// so bare it is *this machine with nobody logged in*, which is not the same thing. This wipes
/// `.kotton.firstrun/` in the checkout to nothing, stages the shell there, and starts the
/// daemon against it with no user at all — the path a real machine takes out of the box,
/// where the shell comes from `system/shell/` because there is no per-user registry to
/// resolve it in. Re-running wipes again, so first run stays first.
///
/// Lived in `just/desktop.just` as PowerShell until 2026-09-17, so it ran on one of
/// the three platforms the README names. The keychain entries this install makes are
/// scoped to its base directory (`OsSecrets::for_base_dir`), which is what lets
/// `kotton device reset --yes` under the same variables wipe only this one.
fn first_run(workspace_root: &Path) {
    const BASE: &str = ".kotton.firstrun";
    const IPC: &str = "kuserd-firstrun";

    for name in &["kuserd", "kuid", "kdeviced"] {
        kill_by_name(name);
    }
    let base = workspace_root.join(BASE);
    if base.exists() {
        if let Err(e) = fs::remove_dir_all(&base) {
            eprintln!("[first-run] could not wipe {}: {e}", base.display());
            std::process::exit(1);
        }
    }
    fs::create_dir_all(&base).expect("failed to create the first-run base dir");
    stage_system_shell(&base);

    let runner_bin = bin_path("kotton-runner");
    let rust_log = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    println!(
        "[first-run] a machine that has never had Kotton on it: {}",
        base.display()
    );
    println!("[first-run] to reach it from another terminal:");
    println!("[first-run]   KOTTON_BASE_DIR={BASE} KUSERD_IPC_NAME={IPC} kotton …");
    println!("[first-run] Ctrl-C stops it; running this again wipes it.");
    let mut cmd = Command::new(bin_path("kuserd"));
    cmd.current_dir(workspace_root)
        .env("KOTTON_BASE_DIR", BASE)
        .env("KUSERD_IPC_NAME", IPC)
        .env("KOTTON_RUNNER", &runner_bin)
        .env("RUST_LOG", &rust_log);
    prefer_x11(&mut cmd);
    let child = cmd.spawn();
    match child {
        Ok(mut c) => {
            #[cfg(windows)]
            // SAFETY: standard Win32 call; the function pointer is valid for the
            // lifetime of this process. Ctrl-C reaches the daemon, and this
            // process waits for it instead of dying first.
            unsafe {
                SetConsoleCtrlHandler(Some(noop_ctrl_handler), 1);
            }
            let _ = c.wait();
            eprintln!("[first-run] stopped");
        }
        Err(e) => {
            eprintln!("[first-run] failed to spawn kuserd: {e}");
            std::process::exit(1);
        }
    }
}

/// On Linux, when a session offers both a Wayland and an X11 display, the window the
/// daemon starts takes X11. **A concession, with its seam.** kuid's windowing is a
/// pre-release winit, and its Wayland backend ended on a broken pipe the moment the
/// window was focused under WSLg's Weston (2026-09-17,
/// `TASK-the-window-dies-on-focus-under-wslg`); through Xwayland the same window took
/// focus and input. Every earlier Linux run was X11, and the doctor's own
/// window-manager row asks an X11 display. So X11 is the path that is known to work,
/// and it is what a person gets unless they ask: `KUID_WAYLAND=1` keeps `WAYLAND_DISPLAY`
/// for the child, which is the seam back, and the record above names what closes it.
/// A session with no X11 display is left alone — there is nothing to fall back to.
fn prefer_x11(cmd: &mut Command) {
    if !cfg!(target_os = "linux") {
        return;
    }
    let both =
        std::env::var_os("WAYLAND_DISPLAY").is_some() && std::env::var_os("DISPLAY").is_some();
    if both && std::env::var_os("KUID_WAYLAND").is_none() {
        cmd.env_remove("WAYLAND_DISPLAY");
        println!("[run] the window runs on X11 here; KUID_WAYLAND=1 asks for Wayland instead");
    }
}

/// Where the tray lives, in the one sentence a person on Windows 11 needs.
///
/// `TASK-the-tray-icon-is-a-dark-square-on-a-dark-tray`. Windows parks a new
/// application's icon in the *hidden icons* overflow until the person promotes it, so
/// even a correctly drawn mark is somewhere they have to be told about once.
const TRAY_NOTE: &str = "the tray icon is in the notification area (on Windows 11 it may \
                         be under the ^ overflow until you drag it out)";

/// **What the person is told when the window goes away**, and it is one of two sentences.
///
/// `TASK-quit-kotton-stops-the-daemon-and-closing-the-window-does-not`. The recipe's wait
/// is on the daemon, so the window's fate reaches it only through the daemon's log. Both
/// sentences are owned by `kotton_common` and written by `kuserd`; this reads them back.
///
/// A free function over a line, rather than an `if` inside the reader thread, because it
/// is the whole of the join between two processes' words and
/// [`the_recipe_reads_the_lines_the_daemon_writes`] can then hold it to the constants
/// themselves.
fn the_daemon_said_something_the_person_needs(line: &str) -> Option<String> {
    if line.contains(kotton_common::KUID_LEFT_LINE) {
        // The record's sentence, in full. The daemon logs the fact; the recipe is where
        // the person is told what to do about it, because *Ctrl-C* is a fact about this
        // terminal rather than about the daemon.
        return Some(format!(
            "{} — Quit Kotton from the tray, or Ctrl-C, stops it",
            kotton_common::KUID_LEFT_LINE
        ));
    }
    if line.contains(kotton_common::DAEMON_QUIT_LINE) {
        return Some(kotton_common::DAEMON_QUIT_LINE.to_string());
    }
    None
}

/// The file a spawned daemon's output is written to, truncated on each run so it is
/// this run's log and not every run's. If it cannot be opened the daemon still runs;
/// the lines are simply not kept, and the terminal was told where they would have been.
fn open_daemon_log(path: &Path) -> std::sync::Arc<std::sync::Mutex<Option<fs::File>>> {
    let file = path
        .parent()
        .map(|d| fs::create_dir_all(d).is_ok())
        .unwrap_or(false)
        .then(|| fs::File::create(path).ok())
        .flatten();
    if file.is_none() {
        eprintln!(
            "[run] could not open {} — the daemon's output will not be kept",
            path.display()
        );
    }
    std::sync::Arc::new(std::sync::Mutex::new(file))
}

/// Return `true` if an identity named `user` already exists on this device.
fn user_exists(kotton_bin: &Path, workspace_root: &Path, user: &str) -> bool {
    Command::new(kotton_bin)
        .args(["id", "list"])
        .current_dir(workspace_root)
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .any(|l| l.contains(user))
        })
        .unwrap_or(false)
}

/// Two-node encrypted file transfer demo.
///
/// Spins up two isolated `kuserd` processes (A and B), each in their own base
/// directory under `.kotton.demo/`, exchanges their identities via the IPC
/// protocol, writes a file on A, syncs it to B over a real QUIC mTLS
/// connection, and prints the received content.
///
/// Runs on every platform without any shell prerequisites.
fn demo_sync(workspace_root: &Path) {
    use std::process::Stdio;

    // ── 0. Build required binaries ────────────────────────────────────────────
    // Kill any running binaries first so cargo can overwrite them on Windows.
    for name in &["kuserd", "kotton"] {
        kill_by_name(name);
    }
    println!("[demo] building kuserd + kotton …");
    run_step(
        Command::new("cargo")
            .args(["build", "-p", "kuserd", "-p", "kotton-cli"])
            .current_dir(workspace_root),
        "build demo binaries",
    );

    // ── 1. Clean up previous demo state ──────────────────────────────────────
    let demo_dir = workspace_root.join(".kotton.demo");
    if demo_dir.exists() {
        fs::remove_dir_all(&demo_dir).expect("clean .kotton.demo");
    }
    fs::create_dir_all(demo_dir.join("a")).expect("create .kotton.demo/a");
    fs::create_dir_all(demo_dir.join("b")).expect("create .kotton.demo/b");

    // ── 2. Pick free UDP ports for the two QUIC listeners ────────────────────
    let port_a = free_port();
    let port_b = free_port();

    // ── 3. Unique IPC names ───────────────────────────────────────────────────
    let ipc_a = "kotton-demo-a";
    let ipc_b = "kotton-demo-b";

    let kuserd_bin = bin_path("kuserd");
    let kotton_bin = bin_path("kotton");

    // ── 4. Spawn daemon A ─────────────────────────────────────────────────────
    println!("[demo] starting node A (QUIC port {port_a}) …");
    let base_a = workspace_root.join(".kotton.demo/a");
    let mut proc_a = Command::new(&kuserd_bin)
        .current_dir(workspace_root)
        .env("KOTTON_BASE_DIR", &base_a)
        .env("KUSERD_IPC_NAME", ipc_a)
        .env("KOTTON_PEER_LISTEN_PORT", port_a.to_string())
        .env(
            "RUST_LOG",
            "kotton_device::runtime::network=debug,kotton_store::runtime::user::sync=debug,warn",
        )
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|e| {
            eprintln!("[demo] failed to spawn kuserd A: {e}");
            std::process::exit(1);
        });

    // ── 5. Spawn daemon B ─────────────────────────────────────────────────────
    println!("[demo] starting node B (QUIC port {port_b}) …");
    let base_b = workspace_root.join(".kotton.demo/b");
    let mut proc_b = Command::new(&kuserd_bin)
        .current_dir(workspace_root)
        .env("KOTTON_BASE_DIR", &base_b)
        .env("KUSERD_IPC_NAME", ipc_b)
        .env("KOTTON_PEER_LISTEN_PORT", port_b.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| {
            eprintln!("[demo] failed to spawn kuserd B: {e}");
            std::process::exit(1);
        });

    // Helper: kill both on early exit.
    let cleanup = |proc_a: &mut std::process::Child, proc_b: &mut std::process::Child| {
        let _ = proc_a.kill();
        let _ = proc_b.kill();
        let _ = proc_a.wait();
        let _ = proc_b.wait();
    };

    macro_rules! bail {
        ($msg:expr) => {{
            eprintln!("[demo] {}", $msg);
            cleanup(&mut proc_a, &mut proc_b);
            std::process::exit(1);
        }};
    }

    // ── 6. Wait for both daemons to be ready ──────────────────────────────────
    println!("[demo] waiting for daemon A …");
    if !poll_ipc_ready(&isolated_kuserd_door(ipc_a, &base_a), 30) {
        bail!("daemon A did not become ready");
    }
    println!("[demo] waiting for daemon B …");
    if !poll_ipc_ready(&isolated_kuserd_door(ipc_b, &base_b), 30) {
        bail!("daemon B did not become ready");
    }

    // Helper: run `kotton` against a specific daemon.
    let run_kotton = |ipc: &str, base: &Path, args: &[&str]| -> std::process::Output {
        Command::new(&kotton_bin)
            .args(args)
            .current_dir(workspace_root)
            .env("KUSERD_IPC_NAME", ipc)
            .env("KOTTON_BASE_DIR", base)
            .output()
            .unwrap_or_else(|e| panic!("failed to run kotton: {e}"))
    };

    // ── 7. Create user "demo" on both nodes ───────────────────────────────────
    println!("[demo] creating user 'demo' on both nodes …");
    let out = run_kotton(ipc_a, &base_a, &["id", "add", "demo"]);
    if !out.status.success() {
        bail!(format!(
            "user add on A failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let out = run_kotton(ipc_b, &base_b, &["id", "add", "demo"]);
    if !out.status.success() {
        bail!(format!(
            "user add on B failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    // ── 7b. Authenticate both users ─────────────────────────────────────────
    println!("[demo] authenticating 'demo' on both nodes …");
    let out = run_kotton(ipc_a, &base_a, &["login", "demo"]);
    if !out.status.success() {
        bail!(format!(
            "login on A failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let out = run_kotton(ipc_b, &base_b, &["login", "demo"]);
    if !out.status.success() {
        bail!(format!(
            "login on B failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    // ── 8. Read identities ────────────────────────────────────────────────────
    println!("[demo] reading node identities …");
    let out_a = run_kotton(ipc_a, &base_a, &["node", "identity"]);
    let out_b = run_kotton(ipc_b, &base_b, &["node", "identity"]);
    if !out_a.status.success() {
        bail!(format!(
            "node identity on A failed: {}",
            String::from_utf8_lossy(&out_a.stderr)
        ));
    }
    if !out_b.status.success() {
        bail!(format!(
            "node identity on B failed: {}",
            String::from_utf8_lossy(&out_b.stderr)
        ));
    }

    let parse_identity = |output: &[u8]| -> (String, String) {
        let s = String::from_utf8_lossy(output);
        let did = s
            .lines()
            .find(|l| l.starts_with("DID:"))
            .map(|l| l.trim_start_matches("DID:").trim().to_string())
            .unwrap_or_default();
        let pubkey = s
            .lines()
            .find(|l| l.starts_with("pubkey:"))
            .map(|l| l.trim_start_matches("pubkey:").trim().to_string())
            .unwrap_or_default();
        (did, pubkey)
    };

    let (did_a, pubkey_a) = parse_identity(&out_a.stdout);
    let (did_b, pubkey_b) = parse_identity(&out_b.stdout);

    if did_a.is_empty() || pubkey_a.is_empty() {
        bail!("could not parse identity from node A");
    }
    if did_b.is_empty() || pubkey_b.is_empty() {
        bail!("could not parse identity from node B");
    }

    println!("[demo] node A DID: {did_a}");
    println!("[demo] node B DID: {did_b}");

    // ── 9. Cross-register peers ───────────────────────────────────────────────
    println!("[demo] registering nodes as peers of each other …");
    let addr_b = format!("127.0.0.1:{port_b}");
    let addr_a = format!("127.0.0.1:{port_a}");

    let out = run_kotton(
        ipc_a,
        &base_a,
        &[
            "node",
            "add",
            "node-b",
            "--peer-did",
            &did_b,
            "--pubkey-hex",
            &pubkey_b,
            "--peer-addr",
            &addr_b,
            "--user",
            "demo",
        ],
    );
    if !out.status.success() {
        bail!(format!(
            "node add (A->B) failed:\n  stdout: {}\n  stderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    let out = run_kotton(
        ipc_b,
        &base_b,
        &[
            "node",
            "add",
            "node-a",
            "--peer-did",
            &did_a,
            "--pubkey-hex",
            &pubkey_a,
            "--peer-addr",
            &addr_a,
            "--user",
            "demo",
        ],
    );
    if !out.status.success() {
        bail!(format!(
            "node add (B->A) failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    // ── 10. Write a file on A ─────────────────────────────────────────────────
    println!("[demo] writing file on node A ...");
    let file_content = "hello from node A";
    let out = run_kotton(
        ipc_a,
        &base_a,
        &[
            "vfs",
            "write",
            "local",
            "/demo.txt",
            file_content,
            "--user",
            "demo",
        ],
    );
    if !out.status.success() {
        bail!(format!(
            "vfs write failed:\n  stdout: {}\n  stderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    // ── 11. Configure sync rule on A: push /demo.txt to node-b ───────────────
    println!("[demo] configuring sync rule on A -> node-b ...");
    let out = run_kotton(
        ipc_a,
        &base_a,
        &[
            "sync",
            "add",
            "/demo.txt",
            "--to",
            "node-b",
            "--user",
            "demo",
        ],
    );
    if !out.status.success() {
        bail!(format!(
            "sync add failed:\n  stdout: {}\n  stderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    // ── 12. Trigger sync on A and wait for completion ─────────────────────────
    println!("[demo] syncing A -> B over QUIC mTLS (waiting for completion) ...");
    let out = run_kotton(ipc_a, &base_a, &["sync", "now", "--user", "demo"]);
    if !out.status.success() {
        bail!(format!(
            "sync now failed:\n  stdout: {}\n  stderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    println!(
        "[demo] sync result: {}",
        String::from_utf8_lossy(&out.stdout).trim()
    );

    // ── 13. Read the file on B — sync now blocked until complete ──────────────
    println!("[demo] reading file on node B ...");
    let out = run_kotton(
        ipc_b,
        &base_b,
        &["vfs", "read", "local", "/demo.txt", "--user", "demo"],
    );
    if !out.status.success() {
        bail!(format!(
            "vfs read on B failed:\n  stdout: {}\n  stderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let received = String::from_utf8_lossy(&out.stdout).to_string();

    cleanup(&mut proc_a, &mut proc_b);

    println!();
    println!("=== DEMO SUCCESS ===");
    println!("  Node A: {did_a}");
    println!("  Node B: {did_b}");
    println!();
    println!("  Written on A:  {file_content}");
    println!("  Read on B:     {}", received.trim());
    println!();
    if received.trim() != file_content {
        eprintln!("WARNING: content mismatch (sync may be async — re-run to confirm)");
        std::process::exit(1);
    }
    println!("File transferred A -> B over QUIC mTLS.");
}

/// Bind a UDP socket on :0 and return the OS-assigned port.
fn free_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .expect("bind :0 for port probe")
        .local_addr()
        .expect("local_addr")
        .port()
}

/// `kuserd`'s door as a recipe waits on it: the socket path on unix, the pipe name on
/// Windows.
#[cfg(unix)]
type Door = std::path::PathBuf;
#[cfg(windows)]
type Door = String;

/// The door of a `kuserd` started with this process's environment, as `run` starts it:
/// `kotton_common::kuserd_door`, so a `KUSERD_IPC_NAME` exported here is the door
/// waited on, as it is the door the daemon binds.
fn kuserd_door_here() -> Door {
    #[cfg(unix)]
    {
        kotton_common::kuserd_door().expect("resolve kuserd's door")
    }
    #[cfg(windows)]
    {
        kotton_common::kuserd_ipc_name()
    }
}

/// The door of a `kuserd` started with this process's environment plus
/// `KOTTON_BASE_DIR=base_dir` and `KUSERD_IPC_NAME=ipc_name`, as the demo starts each
/// node: `kuserd_door_in` over that environment. Until 2026-09-28 this set and restored
/// the two variables on this process so the process-env rule would answer for another
/// environment, which is what the `_in` form exists to replace
/// (`TASK-a-suite-test-and-xtasks-poller-still-derive-kuserds-door-by-a-copy-of-the-rule`).
fn isolated_kuserd_door(ipc_name: &str, base_dir: &Path) -> Door {
    #[cfg(unix)]
    {
        let base = base_dir.to_string_lossy().into_owned();
        let env = |key: &str| match key {
            "KOTTON_BASE_DIR" => Some(base.clone()),
            "KUSERD_IPC_NAME" => Some(ipc_name.to_string()),
            _ => std::env::var(key).ok(),
        };
        kotton_common::paths::kuserd_door_in(&env).expect("resolve kuserd's door")
    }
    #[cfg(windows)]
    {
        let _ = base_dir;
        ipc_name.to_string()
    }
}

/// Poll a `kuserd` door until it becomes connectable.
/// Returns true if ready within `timeout_secs`, false on timeout.
fn poll_ipc_ready(door: &Door, timeout_secs: u64) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    while std::time::Instant::now() < deadline {
        if ipc_connectable(door) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    false
}

/// Check if the kuserd IPC endpoint is connectable.
#[cfg(windows)]
fn ipc_connectable(ipc_name: &str) -> bool {
    let path = kotton_common::paths::pipe_path(ipc_name);
    match std::fs::OpenOptions::new().read(true).open(&path) {
        Ok(_) => true,
        // ERROR_PIPE_BUSY (231): pipe exists but all instances are busy — daemon is up.
        Err(e) => e.raw_os_error() == Some(231),
    }
}

#[cfg(unix)]
fn ipc_connectable(door: &std::path::Path) -> bool {
    std::os::unix::net::UnixStream::connect(door).is_ok()
}

/// Return the path to a debug binary, in the target directory cargo reports.
fn bin_path(name: &str) -> std::path::PathBuf {
    let target = out::workspace_target();
    if cfg!(windows) {
        target.join(format!("debug/{name}.exe"))
    } else {
        target.join(format!("debug/{name}"))
    }
}

/// Run a command and exit with an error if it fails.
fn run_step(cmd: &mut Command, label: &str) {
    let status = cmd
        .status()
        .unwrap_or_else(|e| panic!("failed to spawn {label}: {e}"));
    if !status.success() {
        eprintln!("[xtask] {label} failed");
        std::process::exit(1);
    }
}

/// Send SIGTERM (Unix) or TerminateProcess (Windows) to a process by PID.
/// Kill all processes with the given executable name (best-effort, silent on failure).
#[cfg(windows)]
fn kill_by_name(name: &str) {
    let _ = Command::new("taskkill")
        .args(["/IM", &format!("{name}.exe"), "/F"])
        .output();
}

#[cfg(not(windows))]
fn kill_by_name(name: &str) {
    let _ = Command::new("pkill").args(["-x", name]).output();
}

fn kill_pid(pid: u32) {
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F"])
            .output();
    }
    #[cfg(not(windows))]
    {
        let _ = Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .output();
    }
}

fn gen_types() {
    // Resolve the workspace root relative to the xtask crate's manifest directory.
    // The export dir must be absolute so that the test can write to it regardless
    // of the cargo working directory.
    let workspace_root = &out::root();
    let export_dir = workspace_root
        .join("packages/types/src")
        .canonicalize()
        .unwrap_or_else(|_| workspace_root.join("packages/types/src"));

    println!("Exporting TS types to {}", export_dir.display());

    let status = Command::new("cargo")
        .args([
            "test",
            "-p",
            "kotton-wire",
            "--features",
            "ts-types",
            "--",
            "ts_export::export_ts_bindings",
        ])
        .env("TS_RS_EXPORT_DIR", &export_dir)
        .current_dir(workspace_root)
        .status()
        .expect("failed to run cargo test");

    if !status.success() {
        eprintln!("gen-types failed");
        std::process::exit(1);
    }
    println!("Done. Re-export via packages/types/src/index.ts");
}

/// Path of the generated CLI reference, relative to the workspace root.
#[cfg(feature = "cli-docs")]
const CLI_REFERENCE_PATH: &str = "docs/cli/reference.md";
/// Build the CLI reference Markdown. Pure — `gen-docs` writes it, `docs-check`
/// compares it against what is committed.
#[cfg(feature = "cli-docs")]
fn cli_reference_markdown() -> String {
    use clap::CommandFactory;
    // A shared verb's help ends on the shell verb's own (`after_help`), written for a
    // terminal: aligned columns and `<placeholders>`, which Markdown runs together and takes
    // for tags. Here it is a text block, as the terminal prints it.
    // `mut_subcommand` moves the verb it touches to the end, so every verb is passed through
    // it, in order, and the order the tree declares is the order the reference keeps.
    let mut cli = Cli::command();
    let verbs: Vec<String> = cli.get_subcommands().map(|c| c.get_name().to_string()).collect();
    for name in verbs {
        cli = cli.mut_subcommand(name, |c| match c.get_after_help().map(|h| h.to_string()) {
            Some(help) => c.after_help(format!("```text\n{help}\n```")),
            None => c,
        });
    }
    // clap-markdown walks the full command tree and emits a single Markdown doc.
    let markdown = clap_markdown::help_markdown_command(&cli);

    // Prepend a short header so the file is self-explanatory on GitHub and in
    // a future Starlight site without any frontmatter required.
    format!(
        "<!-- Generated by `cargo xtask gen-docs`. Do not edit by hand. -->\n\
         <!-- Re-generate: `just gen::docs` -->\n\n\
         {}",
        markdown
    )
}

#[cfg(feature = "cli-docs")]
fn gen_docs() {
    let out_path = Path::new(CLI_REFERENCE_PATH);
    fs::create_dir_all(out_path.parent().expect("CLI_REFERENCE_PATH has a parent"))
        .expect("failed to create docs/cli/");
    fs::write(out_path, cli_reference_markdown()).expect("failed to write reference.md");

    println!("Wrote {}", out_path.display());
}

// ── Constitution compliance checks ───────────────────────────────────────────────

/// Source files the constitution-check *reads* to verify an invariant, relative
/// to the workspace root. Kept as named constants so the checker and the
/// `inspected_files_exist` self-test share one source of truth: if one of these
/// is renamed, both the runtime check (via `read_required`) and the test fail,
/// instead of the check silently going vacuous (audit finding H8).
const ARTICLE_II_KDEVICED: &str = "core/kdeviced/src/system.rs";
const ARTICLE_IV_CAPABILITY: &str = "core/schemas/src/capability.rs";

/// One inspection constitution-check runs, and the principle it stands for.
struct Inspection {
    /// The principle's number, as Kotton's principles number it.
    principle: &'static str,
    /// What the inspection holds, in a phrase.
    holds: &'static str,
    run: fn(&Path, &mut Vec<String>),
}

/// Every inspection constitution-check runs, each paired with the principle it stands for.
///
/// This is the only list: the check runs exactly these. The reference also holds this list to
/// the principles page's table of what is enforced; this tree holds no such page, so that
/// comparison is not made here, and the inspections whose subject is absent from this tree —
/// Principle VIII's, which read the sandbox in `core/wasm` and the apps under `guest/` — are
/// not run here.
const INSPECTIONS: [Inspection; 5] = [
    Inspection {
        principle: "II",
        holds: "no device-daemon handler takes a GrantEnvelope as authentication",
        run: grant_envelope_is_not_authentication,
    },
    Inspection {
        principle: "II",
        holds: "only Ping, Challenge and Authenticate are served before the authentication gate",
        run: only_the_handshake_skips_authentication,
    },
    Inspection {
        principle: "III",
        holds: "no SQL in the workspace creates a table named for users, accounts, logins or \
                credentials, or a column whose name holds password, passwd, passphrase, pw_hash, \
                pin_hash, secret_hash, token_hash, email or phone, but the two columns the check \
                names with their reasons",
        run: user_database_check::no_account_table,
    },
    Inspection {
        principle: "III",
        holds: "no type in core/ or the relay has a field whose name holds password, passwd, \
                passphrase, pw_hash, pin_hash, secret_hash, token_hash, email or phone, but the \
                fields the check names with their reasons, and a type named for an account has a \
                did field",
        run: user_database_check::no_account_record,
    },
    Inspection {
        principle: "IV",
        holds: "CapabilityTarget has no admin, root or system variant",
        run: no_privileged_capability_target,
    },
];

/// Checks the code against the principles [`INSPECTIONS`] stand for.
///
/// Every inspection runs, and a file one reads that is missing is a failure of the gate rather
/// than a pass (`read_required`). The "Article" numbers in its messages are the principles'
/// numbers.
///
/// This is fast: it inspects source files without compiling. Run locally with
/// `cargo xtask constitution-check`; `just lint` runs it on every pull request.
fn constitution_check() {
    let mut violations: Vec<String> = Vec::new();

    // Resolve inspected paths against the repository the command is *run in* — asked of git —
    // not the process CWD and not the directory xtask was compiled in.
    let root = &out::root();

    for inspection in &INSPECTIONS {
        (inspection.run)(root, &mut violations);
    }

    let mut held: Vec<&str> = INSPECTIONS.iter().map(|i| i.principle).collect();
    held.dedup();

    // ── Report ────────────────────────────────────────────────────────────────
    if violations.is_empty() {
        println!(
            "constitution-check: OK, {} principles ({}) held by {} inspections.",
            held.len(),
            held.join(", "),
            INSPECTIONS.len(),
        );
    } else {
        eprintln!("PRINCIPLE VIOLATIONS ({}):", violations.len());
        for v in &violations {
            eprintln!("  \u{2717} {v}");
        }
        eprintln!("\nThe inspections and the principle each stands for:");
        for i in &INSPECTIONS {
            eprintln!("  {:<5} {}", i.principle, i.holds);
        }
        eprintln!(
            "\nA violation must be fixed, or the principle amended in the open by a pull \
             request, before this check will pass."
        );
        std::process::exit(1);
    }
}

/// Reads an inspected file, or records that the gate itself is broken.
///
/// Reading an inspected file must never *silently skip* its check. A moved or
/// deleted path is exactly how the Article II and VIII checks passed
/// vacuously for months (audit finding H8): `if let Ok(src) = read(..)` turns
/// a missing file into "no violations found". Treat a missing required file as
/// a failure of the gate itself so a rename screams at PR time instead of
/// quietly disabling enforcement. The `inspected_files_exist` self-test is the
/// second guard.
fn read_required(root: &Path, rel: &str, violations: &mut Vec<String>) -> Option<String> {
    match fs::read_to_string(root.join(rel)) {
        Ok(src) => Some(src),
        Err(e) => {
            violations.push(format!(
                "constitution-check is BROKEN: cannot read `{rel}` ({e}). The \
                 invariant it guards is now unverified — repoint or retire this \
                 check rather than let it pass vacuously."
            ));
            None
        }
    }
}

/// Article IV: `CapabilityTarget` has no privileged admin variant.
///
/// Access is explicit and revocable, with no privileged tier for first-party
/// software. Every app, first-party or third-party, receives capabilities from
/// the same `CapabilityTarget` enum. No variant named Admin, Root, System,
/// Coordinator, or similar may exist: that would create a privileged tier
/// unavailable to third-party apps.
fn no_privileged_capability_target(root: &Path, violations: &mut Vec<String>) {
    let capability_target_file = ARTICLE_IV_CAPABILITY;
    if let Some(src) = read_required(root, capability_target_file, violations) {
        // Find the CapabilityTarget enum block (up to the closing brace).
        if let Some(start) = src.find("enum CapabilityTarget") {
            let enum_body: String = src[start..]
                .chars()
                .scan(0i32, |depth, c| {
                    if c == '{' {
                        *depth += 1;
                    } else if c == '}' {
                        *depth -= 1;
                        if *depth == 0 {
                            return None; // stop after closing brace
                        }
                    }
                    Some(c)
                })
                .collect();
            let forbidden = [
                "Admin",
                "Root",
                "System",
                "Coordinator",
                "Privileged",
                "Sudo",
            ];
            // Tokenise into identifiers so a forbidden name matches only as a
            // whole variant name, never as a substring of a larger identifier
            // (the previous `.contains()` claimed a word boundary but did not).
            let idents: std::collections::HashSet<&str> = enum_body
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .filter(|s| !s.is_empty())
                .collect();
            for variant in &forbidden {
                if idents.contains(variant) {
                    violations.push(format!(
                        "Article IV: `CapabilityTarget` in {capability_target_file} \
                         contains a `{variant}` variant. \
                         This creates a privileged capability tier, and Article IV \
                         allows none for first-party software. Only `Schema` and `Vfs` \
                         variants are permitted."
                    ));
                }
            }
        } else {
            // Failing to locate the enum is itself a broken check, not a pass.
            violations.push(format!(
                "constitution-check is BROKEN: could not locate `enum CapabilityTarget` \
                 in {capability_target_file} — Article IV is unverified. Repoint the check."
            ));
        }
    }
}

/// Article II: kdeviced handlers must not accept a `GrantEnvelope` as authentication.
///
/// Device-layer commands (kdeviced / kctl) must authenticate via
/// challenge-response against the sudoers DID set — proof of key possession.
/// A GrantEnvelope accepted as authentication would allow capability grants
/// to substitute for key ownership, undermining the node as root-of-trust.
fn grant_envelope_is_not_authentication(root: &Path, violations: &mut Vec<String>) {
    let kdeviced_handler = ARTICLE_II_KDEVICED;
    if let Some(src) = read_required(root, kdeviced_handler, violations) {
        // Detect fn signatures (lines containing "fn " + "GrantEnvelope").
        // A GrantEnvelope parameter in a handler function is the violation;
        // use as a type reference elsewhere (match arms, etc.) is fine.
        for (lineno, line) in src.lines().enumerate() {
            let trimmed = line.trim();
            if (trimmed.starts_with("fn ")
                || trimmed.starts_with("pub fn ")
                || trimmed.starts_with("async fn ")
                || trimmed.starts_with("pub async fn "))
                && trimmed.contains("GrantEnvelope")
            {
                violations.push(format!(
                    "Article II: {kdeviced_handler} line {}: \
                         handler `{}` accepts a `GrantEnvelope` parameter. \
                         kdeviced handlers must authenticate via challenge-response, \
                         not via GrantEnvelope.",
                    lineno + 1,
                    trimmed.split('(').next().unwrap_or(trimmed)
                ));
            }
        }
    }
}

/// Article II: only Ping, Challenge and Authenticate may skip authentication.
///
/// The rule above catches one way of substituting something for proof of key
/// possession. It cannot see the simpler failure: a verb served *before* the
/// auth gate, which skips authentication altogether. That gap is not
/// hypothetical — a bearer-token design for `GetDeviceOperationalKey` was
/// drafted, would have passed this check, and was caught by reading Article II
/// rather than by running the gate (2026-08-17).
///
/// So the unauthenticated section is pinned by name. Adding a verb there is a
/// constitutional change and must be argued as one; adding a verb anywhere
/// else needs no permission from this check, because everything else sits
/// behind the gate by construction.
fn only_the_handshake_skips_authentication(root: &Path, violations: &mut Vec<String>) {
    if let Some(src) = read_required(root, ARTICLE_II_KDEVICED, violations) {
        const UNAUTH_START: &str = "── Unauthenticated";
        const UNAUTH_END: &str = "── Authenticated";
        const ALLOWED_UNAUTHENTICATED: [&str; 3] = ["Ping", "Challenge", "Authenticate"];

        let start = src.lines().position(|l| l.contains(UNAUTH_START));
        let end = src.lines().position(|l| l.contains(UNAUTH_END));

        match (start, end) {
            (Some(start), Some(end)) if start < end => {
                // Match-arm heads only: `DeviceRequest::Verb` at the start of a
                // trimmed line, which is how every arm in this section is
                // written. A mention inside an arm body does not open a hole.
                let mut served: Vec<String> = Vec::new();
                for line in src.lines().take(end).skip(start) {
                    let trimmed = line.trim();
                    let Some(rest) = trimmed.strip_prefix("DeviceRequest::") else {
                        continue;
                    };
                    let verb: String = rest
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    if !verb.is_empty() && !served.contains(&verb) {
                        served.push(verb);
                    }
                }

                for verb in &served {
                    if !ALLOWED_UNAUTHENTICATED.contains(&verb.as_str()) {
                        violations.push(format!(
                            "Article II: {ARTICLE_II_KDEVICED}: `DeviceRequest::{verb}` is served before the authentication gate. Device-layer commands authenticate by challenge-response, proof of key possession; only {ALLOWED_UNAUTHENTICATED:?} may skip it."
                        ));
                    }
                }

                // A section that stopped containing the arms it guards means the
                // markers drifted, not that the rule is kept.
                for expected in ALLOWED_UNAUTHENTICATED {
                    if !served.iter().any(|v| v == expected) {
                        violations.push(format!(
                            "constitution-check is BROKEN: {ARTICLE_II_KDEVICED}: expected `DeviceRequest::{expected}` in the unauthenticated section and did not find it — the section markers have moved. Repoint the check."
                        ));
                    }
                }
            }
            _ => violations.push(format!(
                "constitution-check is BROKEN: {ARTICLE_II_KDEVICED}: could not locate the unauthenticated-section markers — Article II's authentication gate is unverified. Repoint the check."
            )),
        }
    }
}

// ── Tier discipline checks ────────────────────────────────────────────────────

/// Check the one dependency rule Cargo cannot express.
///
/// Kotton used to carry an eleven-tier rule enforced here. It is gone, for two
/// reasons found while implementing RFC-0059.
///
/// **Cargo already covers most of it.** A tier violation is low-depends-on-high,
/// but a higher tier almost always already depends on the lower one — so the
/// violating edge closes a cycle and Cargo refuses it before this check runs.
/// The rule only ever bit between tiers with no existing downward edge, which
/// is a small set.
///
/// **And the broad check was not doing its job.** It read 16 of 121 path
/// dependencies for an unknown length of time without anyone noticing, which is
/// itself evidence nothing relied on it.
///
/// What remains is the rule that matters and that Cargo genuinely cannot state:
///
/// > `common` and `sys` may not depend on anything else in `core/`.
///
/// That is the platform seam. If `sys` acquired a dependency on the wire
/// protocol, a bare-metal port would need the wire protocol — the exact
/// foreclosure the seam exists to prevent, and not a cycle, so Cargo permits it.
/// Rust enforces its own version structurally: `core` cannot depend on `std`.
/// The four regions, and which regions a crate in each may path-depend on.
///
/// A region is neither a tier nor a domain. A domain says *what capability area* —
/// `store`, `grant`, `surface` — and RFC-0054 owns that vocabulary. A region says
/// *on whose authority this acts*, at directory granularity, and directory
/// granularity is the whole point: it is what a check can read.
///
/// Until 2026-08-25 this axis existed only as comments in the workspace
/// `Cargo.toml` (`# consumers — no authority of their own; they ask`, sitting above
/// `core/shell` and `core/cli`) and as one sentence of prose in
/// `.github/copilot-instructions.md` (*"`sdk/` crates may depend on `core/` crates
/// but not vice versa"*). Both were correct. Neither was read by anything.
///
/// **The rule that bites is the reverse edge.** "`client/` may depend on `core/`"
/// forbids nothing — it is already true. The `core` row is the one that does work:
/// it forbids `core/store` from depending on `client/cli`, which Cargo permits and
/// nothing else here would have caught.
///
/// The reference has two more regions, `system/` (the trusted-path occupant, held to a crate
/// list) and `guest/` (the confined apps). This tree holds neither, so neither has a row: a
/// rule over a region that is absent reads nothing. A region added here is a top-level
/// directory holding Rust, which `tree`'s tests refuse until it is named.
const REGIONS: &[(&str, &[&str])] = &[
    ("core", &["core"]),
    ("client", &["core", "client"]),
];

/// Every `Cargo.toml` under `root`, depth-first, skipping `target/`.
fn manifests_under(root: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                stack.push(path);
            } else if path.file_name().is_some_and(|n| n == "Cargo.toml") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// Normalise a repo-relative directory path for comparison.
fn as_repo_path(p: &Path) -> String {
    normalise_path(&p.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/"))
}

/// Check that no crate path-depends across a region boundary it may not cross.
fn region_check(violations: &mut Vec<String>) {
    for (region, allowed) in REGIONS {
        let root = Path::new(region);
        if !root.exists() {
            violations.push(format!(
                "tier-check: the region `{region}/` is not a directory here, so its rule reads \
                 nothing. Repoint REGIONS in xtask/src/main.rs."
            ));
            continue;
        }
        for manifest in manifests_under(root) {
            let Ok(content) = std::fs::read_to_string(&manifest) else {
                continue;
            };
            let Some(dir) = manifest.parent() else {
                continue;
            };
            let from = as_repo_path(dir);
            for dep in regex_find_paths(&content) {
                let to = as_repo_path(&dir.join(&dep));
                let Some(to_region) = to.split('/').next() else {
                    continue;
                };
                // Only edges landing inside a region are this rule's business; a
                // crates.io dependency or a path into `tests/` is not.
                if !crate::tree::REGIONS.contains(&to_region) {
                    continue;
                }
                if !allowed.contains(&to_region) {
                    violations.push(format!(
                        "{from} depends on {to} — crossing a region boundary. `{region}/` may \
                         depend on: {}",
                        allowed.join(", ")
                    ));
                }
            }
        }
    }
}

fn tier_check() {
    let core_dir = Path::new("core");
    if !core_dir.exists() {
        eprintln!("tier-check: could not find core/ directory. Run from workspace root.");
        std::process::exit(1);
    }

    // `common` depends on nothing in core/. `sys` may depend on `common` only.
    let sealed: [(&str, &[&str]); 2] = [("common", &[]), ("sys", &["common"])];

    let mut violations: Vec<String> = Vec::new();

    for (crate_name, allowed) in sealed {
        let manifest = core_dir.join(crate_name).join("Cargo.toml");
        let Ok(content) = std::fs::read_to_string(&manifest) else {
            eprintln!("tier-check: core/{crate_name}/Cargo.toml not found");
            std::process::exit(1);
        };
        for dep in regex_find_paths(&content) {
            // Only intra-core dependencies are constrained; a crates.io dep or a
            // path outside core/ is not this rule's business.
            let resolved = normalise_path(
                &core_dir
                    .join(crate_name)
                    .join(&dep)
                    .to_string_lossy()
                    .replace(std::path::MAIN_SEPARATOR, "/"),
            );
            let Some(rest) = resolved.strip_prefix("core/") else {
                continue;
            };
            let target = rest.split('/').next().unwrap_or(rest);
            if target == crate_name || allowed.contains(&target) {
                continue;
            }
            violations.push(format!(
                "core/{crate_name} depends on core/{target} — the platform seam must not                  reach upward. Allowed: {allowed:?}"
            ));
        }
    }

    region_check(&mut violations);

    if violations.is_empty() {
        println!(
            "tier-check: OK — common and sys hold the platform seam, and no crate \
             path-depends across a region boundary it may not cross."
        );
    } else {
        eprintln!("SEAM VIOLATIONS ({}):", violations.len());
        for v in &violations {
            eprintln!("  x {v}");
        }
        eprintln!(
            "\nThe platform seam: a bare-metal port substitutes core/sys \
             implementations, and a dependency reaching upward from the seam takes the \
             rest of the system with it.\n\
             \nThe region boundary (docs/design/processes.md, *Crates*): core/ acts on a \
             principal's authority, client/ only asks, system/ holds a handed channel and \
             nothing else, and guest/ is confined. An edge the wrong way across one of \
             those is not a layering preference — it is authority moving somewhere it was not granted."
        );
        std::process::exit(1);
    }
}

// ── Key reach ─────────────────────────────────────────────────────────────────

/// Check that the type naming the sealing keys stays inside the crates entitled to it.
///
/// RFC-0062's invariant 2 is that no type may reach more authority than the crate it
/// lives in names. Mechanising that in full is unresolved, but its most important case
/// is checkable today: `SealingKeys` — the content key and the path-blinding key —
/// lives in `kotton-context`, and only two crates have any business naming it.
///
/// The check has two halves, because either one alone is defeated by the other:
///
/// 1. **The dependency edge.** A crate that does not depend on `core/context` cannot
///    name the type at all. That is absence rather than a rule, which is the whole
///    point — `kotton-app` cannot reach user data because the items are not there.
/// 2. **Re-exports.** `05_runtime/src/user/mod.rs` re-exported `SealingKeys` and
///    thereby handed the type to everything depending on `kotton-runtime` — `kuserd`,
///    `cli` — while the dependency graph still looked clean. A `pub use` punches a hole
///    straight through the first half, so both are checked together.
///
/// The allowlist does **not** shrink on its own, which an earlier version of this comment
/// claimed. When `05_runtime` stops existing its entry stops *matching* — the permission
/// goes inert while still reading as granted, and nothing says so. Silent inertness is the
/// failure mode this repo names as "a gate you cannot see fail is not a gate," so the third
/// half below makes it loud: an allowlist entry naming no crate is an error that asks to be
/// deleted. The allowlist then shrinks because the build stops until someone shrinks it.
///
/// Run locally: `cargo xtask key-reach-check`
fn key_reach_check() {
    /// Crates permitted to depend on `core/context`.
    ///
    /// Every entry must name a crate that exists — see the staleness check below.
    /// **Exactly one crate**, as of 2026-08-22. `core/05_runtime` left this list
    /// the day it stopped existing, and it did not leave quietly: the staleness
    /// rule below failed the build until someone deleted the entry. That is the
    /// mechanical form of RFC-0080's invariant — no type can reach the content key
    /// except through a crate naming the user's authority.
    const ALLOWED: &[&str] = &["core/store"];
    /// Where the sealing keys are defined; exempt from the re-export rule by definition.
    const HOME: &str = "core/context";
    /// The type that names the keys.
    const KEY_TYPE: &str = "SealingKeys";

    let roots = ["core", "client", "guest", "system", "infra"];
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    for root in roots {
        let dir = Path::new(root);
        if dir.exists() {
            collect_files(dir, &mut files);
        }
    }
    if files.is_empty() {
        eprintln!("key-reach-check: found no files under {roots:?}. Run from workspace root.");
        std::process::exit(1);
    }

    let mut dependents: Vec<String> = Vec::new();
    let mut reexports: Vec<String> = Vec::new();
    let mut crate_dirs: Vec<String> = Vec::new();

    for file in &files {
        let rel = file
            .to_string_lossy()
            .replace(std::path::MAIN_SEPARATOR, "/");
        let Ok(content) = std::fs::read_to_string(file) else {
            continue;
        };

        if rel.ends_with("/Cargo.toml") {
            let crate_dir = rel.trim_end_matches("/Cargo.toml").to_string();
            crate_dirs.push(crate_dir.clone());
            if crate_dir == HOME {
                continue;
            }
            for dep in regex_find_paths(&content) {
                let resolved = normalise_path(&format!("{crate_dir}/{dep}"));
                if resolved == HOME {
                    dependents.push(crate_dir.clone());
                }
            }
        } else if rel.ends_with(".rs") && !rel.starts_with(&format!("{HOME}/")) {
            // A glob re-export leaks the type without ever naming it.
            for (n, line) in content.lines().enumerate() {
                let t = line.trim();
                if !t.starts_with("pub use") {
                    continue;
                }
                if t.contains(KEY_TYPE) || t.contains("kotton_context::*") {
                    reexports.push(format!("{rel}:{}  {t}", n + 1));
                }
            }
        }
    }

    // A check that finds nothing is not a passing check — it is a broken one. The
    // dependency edge is known to exist today, so zero dependents means the manifest
    // scan stopped working, not that the property improved.
    if dependents.is_empty() {
        eprintln!(
            "key-reach-check: found no crate depending on {HOME}, which cannot be true \
             while {HOME} has any consumer. The manifest scan is broken and this check \
             is silently vacuous. Fix the rule."
        );
        std::process::exit(1);
    }

    // A permission for a crate that no longer exists reads as granted and enforces
    // nothing. Left alone it would outlive the migration that made it pointless, so
    // the entry has to be removed by whoever removed the crate — and the only way to
    // make that happen is to stop the build until they do.
    let stale_entries: Vec<&&str> = ALLOWED
        .iter()
        .filter(|a| !crate_dirs.iter().any(|c| c == *a))
        .collect();
    if !stale_entries.is_empty() {
        eprintln!(
            "key-reach-check: allowlist entr{} for {} name{} no crate. The permission is \
             inert but still reads as granted. Delete {} from ALLOWED in xtask.",
            if stale_entries.len() == 1 { "y" } else { "ies" },
            stale_entries
                .iter()
                .map(|s| **s)
                .collect::<Vec<_>>()
                .join(", "),
            if stale_entries.len() == 1 { "s" } else { "" },
            if stale_entries.len() == 1 {
                "it"
            } else {
                "them"
            },
        );
        std::process::exit(1);
    }

    dependents.sort();
    dependents.dedup();
    let violations: Vec<&String> = dependents
        .iter()
        .filter(|d| !ALLOWED.contains(&d.as_str()))
        .collect();

    if violations.is_empty() && reexports.is_empty() {
        println!(
            "key-reach-check: OK — {} crate(s) can name {KEY_TYPE} ({}), none re-export it.",
            dependents.len(),
            dependents.join(", ")
        );
        return;
    }

    eprintln!("KEY REACH VIOLATIONS:");
    for v in &violations {
        eprintln!("  x {v} depends on {HOME}, so it can name {KEY_TYPE}. Allowed: {ALLOWED:?}");
    }
    for r in &reexports {
        eprintln!("  x {r}");
    }
    eprintln!(
        "\nKey material is reached through `UserContext::sealing_keys()`, never as a field. A crate \
         that can name {KEY_TYPE} can reach the user's content key; a `pub use` extends \
         that reach to everything downstream without changing the dependency graph."
    );
    std::process::exit(1);
}

/// Collect every file under `dir`, skipping build output and version control.
fn collect_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == "target" || name == ".git" || name == "node_modules" {
                continue;
            }
            collect_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

// ── Provider blindness ────────────────────────────────────────────────────────

/// Run the test suite and fail if it opens a socket that faces the network.
///
/// `KOTTON_PAIR_LOCAL_ONLY=1` means *this run opens nothing off this machine* — the
/// `Justfile` sets it for the whole suite so a Windows or macOS run raises no OS firewall
/// dialog, which is a GUI prompt a background run sits blocked on. That claim went four
/// months being false, across two separate sockets found by hand, because no gate could
/// see a socket.
///
/// This is that gate. It runs `cargo test` with `tools/bindwatch` interposed on `bind(2)`
/// (see that crate's docs for why interception beats a source scan and beats sampling
/// `/proc/net`), then reports every non-loopback address the run bound and who bound it.
///
/// Recording rather than blocking is deliberate: the suite runs to completion and every
/// violation is reported at once, instead of the first one cascading into unrelated
/// failures.
///
/// Linux-only, by way of `LD_PRELOAD`. Windows and macOS are the platforms that actually
/// raise the dialog, so the gate is a stand-in for them rather than a check of them — it
/// says so on those platforms rather than printing a pass it did not earn. Giving it a
/// second back end (`DYLD_INSERT_LIBRARIES`, or a Detours-style hook) is the seam left open.
///
/// Run locally: `cargo xtask bind-check [-- <cargo test args>]`
fn bind_check(cargo_args: &[String]) {
    /// The suite's own precondition — set here too so the gate measures what `just test`
    /// runs, not a laxer variant of it.
    const LOCAL_ONLY: (&str, &str) = ("KOTTON_PAIR_LOCAL_ONLY", "1");

    let run_tests = |extra: &[(&str, &str)]| -> bool {
        let mut cmd = Command::new("cargo");
        cmd.arg("test")
            .args(cargo_args)
            .env(LOCAL_ONLY.0, LOCAL_ONLY.1);
        for (k, v) in extra {
            cmd.env(k, v);
        }
        cmd.status().map(|s| s.success()).unwrap_or_else(|e| {
            eprintln!("bind-check: could not run cargo test: {e}");
            std::process::exit(1);
        })
    };

    // Compile first, as its own step, so a build failure can be *named* as one.
    //
    // Folded together, it could not be: `cargo test` exits non-zero whether the suite
    // failed or never compiled, and this printed "tests failed (sockets were clean)"
    // over three consecutive runs in which no test executed. Zero sockets is also what
    // a build failure produces, so the reassuring half of that sentence was true and
    // meant nothing — the exact "silence read as success" this gate exists to prevent,
    // in the gate. Unarmed, too: nothing is measured during the build, so the process
    // count below now counts test processes rather than rustc invocations.
    let compiled = {
        let mut cmd = Command::new("cargo");
        cmd.arg("test")
            .arg("--no-run")
            .args(cargo_args)
            .env(LOCAL_ONLY.0, LOCAL_ONLY.1);
        cmd.status().map(|s| s.success()).unwrap_or_else(|e| {
            eprintln!("bind-check: could not run cargo test --no-run: {e}");
            std::process::exit(1);
        })
    };
    if !compiled {
        eprintln!(
            "bind-check: COMPILATION FAILED — no test ran, so no socket was observed. \
             This is not a clean run and not a test failure; the compiler error is above."
        );
        std::process::exit(1);
    }

    if !cfg!(target_os = "linux") {
        // The build already succeeded above, so a failure here is the suite's.
        // Say what was and was not checked. A gate that quietly does nothing off its home
        // platform is how a claim rots while the output still reads green.
        println!(
            "bind-check: running tests without socket observation — the bind(2) shim is \
             LD_PRELOAD, so it is Linux-only. Sockets are unchecked on this platform."
        );
        std::process::exit(if run_tests(&[]) { 0 } else { 1 });
    }

    // Build the shim. It is outside the workspace, so this is its own cargo invocation and
    // its own target dir; release because it sits in front of every bind in the suite.
    let manifest = Path::new("tools/bindwatch/Cargo.toml");
    if !manifest.exists() {
        eprintln!(
            "bind-check: {} not found. Run from workspace root.",
            manifest.display()
        );
        std::process::exit(1);
    }
    // bindwatch is a workspace of its own, so it builds into `out/bindwatch` (or
    // `CARGO_TARGET_DIR`: a convenience build, decision 0014), and the shim is where cargo
    // said it put it.
    let built = out::build_artifacts(
        Command::new("cargo")
            .args(["build", "--release", "--quiet", "--manifest-path"])
            .arg(manifest)
            .arg("--target-dir")
            .arg(out::own_target("bindwatch")),
    )
    .unwrap_or_else(|| {
        eprintln!("bind-check: failed to build tools/bindwatch.");
        std::process::exit(1);
    });
    let shim = out::named(&built, "libbindwatch.so")
        .map(Path::to_path_buf)
        .unwrap_or_else(|| {
            eprintln!("bind-check: built the shim and cargo reported no libbindwatch.so");
            std::process::exit(1);
        });

    // In this checkout's own `out/`, so `just clean` takes it, and **never** under
    // `CARGO_TARGET_DIR`: a cache other checkouts share would give two concurrent
    // bind-checks one log, and each run deletes it first, so one agent's run could erase
    // the other's recorded binds and pass it. Absolute because test binaries do not all
    // share this process's working directory.
    let log = out::root().join(out::OUT).join("bindwatch.log");
    let _ = fs::remove_file(&log);
    if let Some(parent) = log.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let tests_passed = run_tests(&[
        ("LD_PRELOAD", &shim.to_string_lossy()),
        ("BINDWATCH_LOG", &log.to_string_lossy()),
    ]);

    // Absent file means no process ever wrote a line — including the load marker — which is
    // the "measured nothing" case, not a clean run.
    let recorded = fs::read_to_string(&log).unwrap_or_default();
    let mut processes = 0usize;
    let mut violations: Vec<(String, String)> = Vec::new();
    for line in recorded.lines() {
        let mut f = line.split('\t');
        match (f.next(), f.next(), f.next(), f.next()) {
            (Some("PROC"), Some(_), Some(_), _) => processes += 1,
            (Some("BIND"), Some(who), Some(_), Some(addr)) => {
                violations.push((who.to_string(), addr.to_string()))
            }
            _ => {}
        }
    }

    // The instrument reporting its own absence. Without this, a statically linked test
    // binary or a dropped LD_PRELOAD would print a pass over an unmeasured run — the same
    // failure `read_required` guards against in the constitution-check, and the same one
    // that let `ss` returning nothing read as a clean suite on 2026-08-21.
    if processes == 0 {
        eprintln!(
            "bind-check: the bindwatch shim never loaded — no process announced itself in \
             {}. Nothing was measured, so this is a broken gate rather than a clean run. \
             Check that the test binaries are dynamically linked and that LD_PRELOAD \
             survives to them.",
            log.display()
        );
        std::process::exit(1);
    }

    violations.sort();
    violations.dedup();

    if violations.is_empty() {
        println!(
            "bind-check: OK — {processes} process(es) observed, no socket bound off this \
             machine."
        );
        if !tests_passed {
            eprintln!(
                "bind-check: the suite compiled and ran, and tests failed. Sockets were \
                 clean — that is a real finding here, unlike on a run that never built."
            );
            std::process::exit(1);
        }
        return;
    }

    eprintln!("NETWORK-FACING SOCKETS ({}):", violations.len());
    for (who, addr) in &violations {
        eprintln!("  x {who} bound {addr}");
    }
    eprintln!(
        "\n{processes} process(es) observed. `KOTTON_PAIR_LOCAL_ONLY=1` promises this run \
         opens nothing off this machine; each address above breaks that promise and is what \
         raises the firewall dialog on Windows and macOS.\n\n\
         Bind loopback instead. `kotton_peer::scope` owns the switch and lists what honours \
         it — inbound listeners take `scope::inbound_bind_ip()`, and an outbound socket \
         derives its bind from the destination via `kotton_net::provider::transport::bind`. \
         A socket in a primitive-tier crate cannot reach `scope`, which is a domain's \
         (docs/design/processes.md, *Crates*): gate it at the \
         domain-tier caller that constructs it, as `kotton_device::network` does for mDNS. A \
         test that genuinely needs the network — real multicast, a real interface — is \
         `#[ignore]`d and run with `-- --include-ignored`."
    );
    std::process::exit(1);
}

/// The vault is the binary in which the apps, the sandbox, the display, inference
/// and every plaintext verb do not exist (RFC-0084 V1). This holds the dependency half of
/// that sentence: `core/kvaultd/Cargo.toml` names none of the crates that carry
/// them, and its transitive closure, as cargo resolves it for every vault target,
/// does not either. Both halves refuse.
fn vault_check() {
    // `kotton-infer`: a vault keeps sealed packs it cannot open, so it has no plaintext for a
    // model to read; the wire names a model by `kotton-schemas`' manifest, not the runtime's.
    const FORBIDDEN: &[&str] = &["kotton-app", "kotton-surface", "kotton-msg", "kotton-wasm", "kotton-infer"];
    let manifest = Path::new("core/kvaultd/Cargo.toml");
    let Ok(text) = fs::read_to_string(manifest) else {
        eprintln!(
            "vault-check: {} not found. Run from workspace root.",
            manifest.display()
        );
        std::process::exit(1);
    };
    let mut direct: Vec<&str> = Vec::new();
    for line in text.lines() {
        let name = line.split('=').next().unwrap_or("").trim();
        if FORBIDDEN.contains(&name) {
            direct.push(name);
        }
    }
    if !direct.is_empty() {
        eprintln!("vault-check: core/kvaultd depends directly on {direct:?} — a vault links none of these.");
        std::process::exit(1);
    }
    // The transitive closure, as cargo resolves it. Enforced since 2026-09-05,
    // when `device`'s edge to `app` and `surface` (RFC-0080's migration) was
    // cut: a vault links none of these through anything. Read by `wx-check`'s
    // reader, which refuses a tree cargo could not give: until 2026-09-28 this
    // gate ran its own `cargo tree`, never read its exit, and printed OK over the
    // empty closure a broken manifest leaves
    // (TASK-vault-check-reports-ok-when-cargo-tree-fails).
    let tree = wx_check::closure(Path::new("."), &release_server::VAULT, VAULT_TARGETS, VAULT_EDGES);
    match vault_reaches(FORBIDDEN, tree) {
        Err(why) => {
            eprintln!("vault-check: nothing was measured — {why}
A closure nobody read is not a clean one.");
            std::process::exit(1);
        }
        Ok(transitive) if transitive.is_empty() => println!(
            "vault-check: OK — kvaultd links none of {FORBIDDEN:?}, directly or transitively, for any target."
        ),
        Ok(transitive) => {
            eprintln!(
                "vault-check: kvaultd reaches {transitive:?} transitively — a vault links none of these \
                 through anything. `cargo tree -p kvaultd -e {VAULT_EDGES} --target {VAULT_TARGETS} -i <crate>` \
                 shows the path."
            );
            std::process::exit(1);
        }
    }
}

/// The targets `vault-check` reads the closure for: every one. The released vault is
/// [`release_server::TARGET`], and a vault run from a checkout is the host's; `all` holds
/// both, and gives one answer whichever machine runs the gate (the host-only read it
/// replaced did not).
const VAULT_TARGETS: &str = "all";

/// The edges `vault-check` reads: normal dependencies, proc-macros included. `wx-check` drops
/// proc-macros because it asks what runs in the process; this asks what a vault is built
/// from, and a forbidden crate reached through a proc-macro is still reached.
const VAULT_EDGES: &str = "normal";

/// The forbidden crates named on any line of a `--prefix none` closure, or why there is no
/// closure to read — which is never a pass.
fn vault_reaches<'a>(forbidden: &[&'a str], closure: Result<String, String>) -> Result<Vec<&'a str>, String> {
    let tree = closure?;
    Ok(forbidden
        .iter()
        .copied()
        .filter(|name| tree.lines().any(|l| l.split_whitespace().next() == Some(name)))
        .collect())
}

/// Check that terminal storage backends hold no key material.
///
/// Kotton's hosted-infrastructure claim is that whoever runs the storage sees
/// ciphertext and blinded keys, never plaintext. That property is not a promise in
/// a document — it is the *order of the stack*. `build_local_store` assembles
///
/// ```text
/// Packed( Blinded( Encrypted( LocalObjectStorage(fs) ) ) )
/// ```
///
/// so the backend is innermost and every sealing layer sits above it. The backend
/// receives a blinded key and a ciphertext value, which is exactly what makes a
/// third party able to hold the bytes without being trusted with them.
///
/// Today that holds by construction: of the modules under
/// `core/store/src/provider/`, precisely the decorators name key material and the
/// backends name none. Nothing enforced it. This does.
///
/// A module is a **terminal backend** if it implements `ObjectStorage` and holds no
/// inner store to delegate to. That is the layer a third party would write — an S3
/// or IPFS backend — and the one place a key must never appear. A decorator has an
/// `inner`, and holding keys is its whole job, so decorators are not the subject.
///
/// The rule is shape-based rather than an allowlist so that a new `s3.rs` is covered
/// the day it is added, not the day someone remembers to list it. Both remote
/// backends are stubs today (`instantiate_remotes` declines them), so this check
/// exists to be true *before* the case it guards arrives.
///
/// Run locally: `cargo xtask blindness-check`
fn blindness_check() {
    let dir = Path::new("core/store/src/provider");
    if !dir.exists() {
        eprintln!(
            "blindness-check: {} not found. Run from workspace root.",
            dir.display()
        );
        std::process::exit(1);
    }

    // Names that mean "this code can open user data". `[u8; 32]` is the raw shape
    // every key in the system takes; the rest are the specific keys by name.
    const KEY_TOKENS: &[&str] = &["[u8; 32]", "cek", "path_key", "k_log", "k_pack", "kek"];

    let mut backends: Vec<String> = Vec::new();
    let mut violations: Vec<String> = Vec::new();

    let Ok(entries) = std::fs::read_dir(dir) else {
        eprintln!("blindness-check: could not read {}", dir.display());
        std::process::exit(1);
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let name = path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        if name == "mod" {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };

        // Comments describe the invariant constantly, so scanning them would flag
        // every file that explains itself. Only code counts.
        let code: String = content
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");

        if !code.contains("ObjectStorage for") {
            continue; // not a store module — a manifest, a chunker, a contract
        }
        if code.lines().any(|l| l.trim_start().starts_with("inner:")) {
            continue; // a decorator; sealing is its purpose
        }

        backends.push(name.clone());
        for token in KEY_TOKENS {
            if code.contains(token) {
                violations.push(format!(
                    "core/store/src/provider/{name}.rs is a terminal backend and names \
                     `{token}` — a backend is the layer a third party runs, and it must \
                     see only ciphertext and blinded keys"
                ));
            }
        }
    }

    // A check that finds nothing to check is not passing, it is broken. If the trait
    // is renamed or the directory moves, this is the line that says so rather than
    // printing OK over an empty set.
    if backends.is_empty() {
        eprintln!(
            "blindness-check: found no terminal backends under {}. The detection rule \
             (implements `ObjectStorage`, holds no `inner`) no longer matches the code, \
             so this check is silently vacuous. Fix the rule.",
            dir.display()
        );
        std::process::exit(1);
    }

    if violations.is_empty() {
        backends.sort();
        println!(
            "blindness-check: OK — {} terminal backend(s) hold no key material ({}).",
            backends.len(),
            backends.join(", ")
        );
    } else {
        eprintln!("BLINDNESS VIOLATIONS ({}):", violations.len());
        for v in &violations {
            eprintln!("  x {v}");
        }
        eprintln!(
            "\nA terminal storage backend holds no key material: it is the layer a host runs, \
             and a host holding the store and no key learns its volume and its pattern of \
             access and nothing else (docs/design/store.md, *What a host learns*). Sealing \
             belongs in a decorator above the backend, never in the backend itself — that \
             ordering is what lets storage be run by someone the user has not trusted."
        );
        std::process::exit(1);
    }
}

/// Extract all `path = \"...\"` values from a Cargo.toml string.
fn regex_find_paths(content: &str) -> Vec<String> {
    let mut paths = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        // `path = "..."` appears in two forms, and only matching the first
        // meant this check read 16 of 121 dependencies and passed on the rest:
        //
        //   [dependencies.foo]          foo = { path = "../bar" }
        //   path = "../bar"             ^ inline — the form this repo uses
        //
        // So scan for the key anywhere on the line, not only at its start.
        let mut rest = trimmed;
        while let Some(idx) = rest.find("path") {
            let after = &rest[idx + "path".len()..];
            // Require `path` to be a key: preceded by a delimiter, followed by `=`.
            let before_ok = idx == 0 || {
                let c = rest.as_bytes()[idx - 1];
                c == b'{' || c == b',' || c.is_ascii_whitespace()
            };
            let after_trimmed = after.trim_start();
            if before_ok && after_trimmed.starts_with('=') {
                let value = after_trimmed[1..].trim_start();
                if let Some(end_quote) = value.strip_prefix('"').and_then(|v| v.find('"')) {
                    let s = &value[1..=end_quote];
                    // Skip binary entry points (`src/bin/*.rs` in [[bin]] sections).
                    if !s.ends_with(".rs") {
                        paths.push(s.to_string());
                    }
                }
            }
            rest = &rest[idx + "path".len()..];
        }
    }
    paths
}

/// Every Markdown link to a `.md` file appearing in a Rust **doc comment**,
/// reported as `path:line  ->  target`.
///
/// (The link syntax is deliberately not written out here: this function is what
/// rejects it, so spelling it in prose would make the checker fail on its own
/// documentation. That has now happened five times in this codebase with
/// grep-shaped rules — text near a criterion is part of what it measures.)
///
/// Only lines whose trimmed form starts with `//!` or `///` are considered, which
/// is what separates a real doc link from a string literal that happens to contain
/// one — `xtask`'s own fixture for [`extract_relative_links`] is exactly that, and
/// a coarser scan would flag the checker's test data as a defect in the checker.
fn rust_doc_md_links() -> Vec<String> {
    let mut out = Vec::new();
    let mut rs_files: Vec<PathBuf> = Vec::new();
    for root in ["core", "client", "guest", "system", "infra", "xtask"] {
        let root = Path::new(root);
        if root.exists() {
            collect_rust(root, &mut rs_files);
        }
    }
    for file in &rs_files {
        let Ok(content) = std::fs::read_to_string(file) else {
            continue;
        };
        for (i, line) in content.lines().enumerate() {
            let t = line.trim_start();
            if !(t.starts_with("//!") || t.starts_with("///")) {
                continue;
            }
            // Two link forms, and the second was missed until 2026-08-21: inline
            // `[text](url)`, which `extract_relative_links` finds, and
            // **reference-style** `[label]: url` on its own line, which it does
            // not. Three doc comments were still pointing into the deleted
            // `rfcs/` tree in that second form, invisible to this check for a
            // day. A gate that knows one spelling of a thing gates one spelling.
            let mut targets: Vec<String> = extract_relative_links(line)
                .into_iter()
                .map(|(_, t)| t)
                .collect();
            if let Some(rest) = t
                .trim_start_matches("//!")
                .trim_start_matches("///")
                .trim()
                .strip_prefix('[')
            {
                if let Some((_, url)) = rest.split_once("]: ") {
                    targets.push(url.trim().to_string());
                }
            }
            for target in targets {
                if target.split('#').next().unwrap_or(&target).ends_with(".md") {
                    out.push(format!(
                        "{}:{}  ->  {}",
                        file.display().to_string().replace('\\', "/"),
                        i + 1,
                        target
                    ));
                }
            }
        }
    }
    out
}

/// Every `.rs` file under `dir`, skipping build output.
fn collect_rust(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            collect_rust(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn link_check() {
    // Every directory a reader is sent into, recursively: here, `docs/`, which holds the
    // generated CLI reference.
    let roots = [Path::new("docs")];
    // The root's Markdown is files, not a directory, so a root-walk cannot reach them.
    // Listed rather than globbed, so adding one is a deliberate act of putting it under the
    // gate.
    const ROOT_DOCS: [&str; 5] = ["CLAUDE.md", "CONTRIBUTING.md", "DCO.md", "README.md", "SECURITY.md"];
    let mut md_files: Vec<PathBuf> = Vec::new();
    for root in roots {
        if !root.exists() {
            eprintln!(
                "link-check: could not find {}/ directory. Run from workspace root.",
                root.display()
            );
            std::process::exit(1);
        }
        collect_markdown(root, &mut md_files);
    }
    for doc in ROOT_DOCS {
        let path = Path::new(doc);
        if !path.exists() {
            eprintln!("link-check: could not find {doc}. Run from workspace root.");
            std::process::exit(1);
        }
        md_files.push(path.to_path_buf());
    }

    let mut broken: Vec<String> = Vec::new();
    // A merge that conflicts in a document can be staged with its markers still in it. This
    // walk already reads every Markdown file in the graph, so the markers are read here
    // rather than by a second walk.
    let mut conflicts: Vec<String> = Vec::new();
    for file in &md_files {
        let Ok(content) = std::fs::read_to_string(file) else {
            continue;
        };
        for (line_no, marker) in conflict_markers(&content) {
            conflicts.push(format!(
                "{}:{}  {}",
                file.display().to_string().replace('\\', "/"),
                line_no,
                marker,
            ));
        }
        let dir = file.parent().unwrap_or(Path::new("."));
        for (line_no, target) in extract_relative_links(&content) {
            // Resolve relative to the linking file's directory; drop any #anchor.
            let path_part = target.split('#').next().unwrap_or(&target);
            if path_part.is_empty() {
                continue; // pure in-page anchor
            }
            // Only guard the documentation graph: links to other Markdown docs. Links
            // from a planning doc into source code (`.rs`, `src/…`, a crate dir) are
            // informational and rot with refactors — coupling doc CI to code layout is
            // the wrong tradeoff, so they're out of scope.
            if !path_part.to_ascii_lowercase().ends_with(".md") {
                continue;
            }
            if !dir.join(path_part).exists() {
                broken.push(format!(
                    "{}:{}  ->  {}",
                    file.display().to_string().replace('\\', "/"),
                    line_no,
                    target,
                ));
            }
        }
    }

    // Rust doc comments are checked by a different rule, and a stricter one: they may not
    // carry a relative link to a Markdown file at all, because they never worked. Rustdoc
    // resolves a doc-comment link against the generated HTML, not the source tree, so a
    // relative path to a `.md` is a 404 in `cargo doc` however correct it looks here.
    if !conflicts.is_empty() {
        eprintln!(
            "link-check: {} merge-conflict marker(s) in the documentation graph:\n",
            conflicts.len()
        );
        for c in &conflicts {
            eprintln!("  {c}");
        }
        eprintln!(
            "\nA marker left in a document splits a section in two and keeps both sides of a \
             disagreement as if both were true. Resolve the conflict; to show one on purpose, \
             put it in a fenced code block."
        );
        std::process::exit(1);
    }

    let rs_offenders = rust_doc_md_links();
    if !rs_offenders.is_empty() {
        eprintln!(
            "link-check: {} Markdown link(s) in Rust doc comments:\n",
            rs_offenders.len()
        );
        for o in &rs_offenders {
            eprintln!("  {o}");
        }
        eprintln!(
            "\nRustdoc resolves these against the generated HTML, not the source tree, so a \
             relative path here is a 404 in `cargo doc` however correct it looks in the \
             repository. Say what it says in words instead, or name the page as a path in backticks."
        );
        std::process::exit(1);
    }

    if broken.is_empty() {
        println!(
            "link-check: OK — every relative link in docs/ and the root docs resolves and none holds a merge-conflict marker ({} files scanned), and no Rust doc comment links to one by path.",
            md_files.len()
        );
    } else {
        eprintln!(
            "link-check: {} broken relative link(s) in the documentation graph:\n",
            broken.len()
        );
        for b in &broken {
            eprintln!("  {b}");
        }
        eprintln!(
            "\nFix the target or the path. (http/https/mailto/tel, absolute, and #anchor \
             links are ignored.)"
        );
        std::process::exit(1);
    }
}

/// Check that the generated CLI reference matches what `gen-docs` would write.
///
/// `docs/cli/reference.md` carries a "Do not edit by hand" header, and this is what makes it
/// true: the reference is generated from the command tree, and `claim-check` holds the
/// commands `README.md` gives to it, so a reference that drifted from the binary would let a
/// page name a verb the binary lacks.
///
/// It compares in memory and never writes — a check that repairs the tree would go green on a
/// dirty working copy and hide the very drift it exists to catch.
///
/// Comparison is line-ending agnostic: a Windows checkout with `core.autocrlf` holds the file
/// as CRLF while the generator emits LF, and a byte comparison would fail there however fresh
/// the file.
#[cfg(feature = "cli-docs")]
fn docs_check() {
    let want = cli_reference_markdown();
    match fs::read_to_string(CLI_REFERENCE_PATH) {
        Ok(have) if have.replace("\r\n", "\n") == want.replace("\r\n", "\n") => {
            println!("docs-check: OK — {CLI_REFERENCE_PATH} matches the command tree.");
        }
        _ => {
            eprintln!(
                "docs-check: {CLI_REFERENCE_PATH} is out of date or missing.\n\nRun `cargo \
                 xtask-docs gen-docs` and commit the result. The file is generated from the \
                 CLI's command tree — edit the commands, not the Markdown."
            );
            std::process::exit(1);
        }
    }
}

/// `verb-check`: read both trees, and hold them to the command-tree decision ([`verb_check`]). `--pinned`
/// prints the words of the RFC this tree holds, read from kotton-protocol's checkout.
#[cfg(feature = "cli-docs")]
fn verb_check_run(root: &Path, args: &[String]) {
    use clap::CommandFactory;
    use kotton_cli::shell::ShellExecutor;
    use verb_check::{table_of, Trees};

    if args.iter().any(|a| a == "--pinned") {
        match verb_check::protocol_rfc(root) {
            Some((text, at)) => {
                eprintln!("read {}", at.display());
                println!("{}", verb_check::Rfc::parse(&text).held().to_rust());
                return;
            }
            None => {
                eprintln!("verb-check --pinned: no kotton-protocol checkout to read (set KOTTON_PROTOCOL_DIR)");
                std::process::exit(2);
            }
        }
    }
    let repl = kotton_cli::bridge::repl_executor().registry();
    let door = ShellExecutor::new().registry();
    let mut trees = Trees::default();
    for c in Cli::command().get_subcommands() {
        // A door to the shell verb of its name: a `--user` and raw words, which
        // `bridge::run_verb` hands to the registry. Any other subcommand parses its own.
        let takes_user = c.get_arguments().any(|a| a.get_id() == "user");
        let raw = c.get_positionals().any(|p| p.is_allow_hyphen_values_set());
        let is_door = takes_user && raw && door.has_command(c.get_name());
        for name in std::iter::once(c.get_name()).chain(c.get_all_aliases()) {
            trees.clap.insert(name.to_string(), is_door);
            if is_door {
                let t = table_of(&door, c.get_name());
                if !t.is_empty() {
                    trees.clap_tables.insert(name.to_string(), t);
                }
            }
        }
    }
    trees.repl_tables = verb_check::tables_of(&repl);
    trees.repl.extend(repl.command_names());
    let (rfc, rfc_found) = verb_check::the_rfc(root);
    // First: the fixture the unit tests read is the registry's tables, so they test what ships.
    let mut found: Vec<String> = verb_tables::drift(&trees.repl_tables).into_iter().collect();
    found.extend(rfc_found);
    found.extend(verb_check::findings(&rfc, &trees));
    // The tables' other direction: what they retired, no line a person reads still teaches.
    let retired = match retired_words::retired(&trees.repl_tables) {
        Ok(retired) => {
            found.extend(retired_words::findings(root, &retired));
            retired
        }
        Err(unsaid) => {
            found.push(format!(
                "the retired-words sweep did not run: it has nothing to tell a person to type for {}, each named above",
                unsaid.iter().map(|w| format!("`{w}`")).collect::<Vec<_>>().join(", ")
            ));
            Vec::new()
        }
    };
    if found.is_empty() {
        println!(
            "verb-check: OK — {} clap names and {} REPL names have a place in the command-tree decision; {} are one tree, held to its verbs.",
            trees.clap.len(),
            trees.repl.len(),
            verb_check::HELD.join(", ")
        );
        println!(
            "  no line a person reads names a retired word ({}) but to point to what replaced it",
            retired.iter().map(|r| format!("`{}`", r.was())).collect::<Vec<_>>().join(", ")
        );
        for (path, word, _, why) in retired_words::STILL_RUNS {
            println!("  still runs: `{word}` in {path} — {why}");
        }
        for (noun, verb, why) in verb_check::DEFERRED {
            println!("  deferred: `{noun} {verb}` — {why}");
        }
        for (name, why) in verb_check::UNPLACED {
            println!("  unplaced: `{name}` — {why}");
        }
    } else {
        eprintln!("verb-check: {} finding(s):\n", found.len());
        for f in &found {
            eprintln!("  \u{2717} {f}");
        }
        eprintln!("\nA verb's name or meaning changes only by editing the command-tree decision; the tree follows it.");
        std::process::exit(1);
    }
}

// ── The board ────────────────────────────────────────────────────────────────

/// Check that repo paths named in the orientation docs actually exist.
///
/// The orientation docs are the pages a contributor and an agent are told to read first:
/// here `CLAUDE.md`, `CONTRIBUTING.md` and `README.md`. A stale path in a file everyone is
/// told to trust is worse than a stale path in a file nobody reads.
///
/// This checks **existence, not accuracy**: that a path named in prose is a real path.
/// Whether the description beside it is true stays a human's job.
///
/// Only backtick-quoted tokens that look like repo paths are considered — a token
/// containing `/` (or a known top-level directory name) that does not look like a URL,
/// a crate name with `::`, a glob, or a shell command.
fn facts_check() {
    // What agents and contributors are told to trust: a path one of these names that does
    // not exist is a door into nothing.
    const SOURCES: [&str; 3] = ["CLAUDE.md", "CONTRIBUTING.md", "README.md"];

    let mut missing: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for src in SOURCES {
        let Ok(content) = fs::read_to_string(src) else {
            eprintln!("facts-check: could not read {src}. Run from workspace root.");
            std::process::exit(1);
        };

        for (line_no, line) in content.lines().enumerate() {
            for token in backticked_tokens(line) {
                let Some(path) = repo_path_candidate(&token) else {
                    continue;
                };
                checked += 1;
                if !Path::new(&path).exists() {
                    missing.push(format!("{}:{}  ->  {}", src, line_no + 1, token));
                }
            }
        }
    }

    if missing.is_empty() {
        println!("facts-check: OK — {checked} repo path(s) named in the orientation docs exist.");
    } else {
        eprintln!(
            "facts-check: {} path(s) named in the orientation docs do not exist:\n",
            missing.len()
        );
        for m in &missing {
            eprintln!("  {m}");
        }
        eprintln!(
            "\nRename or remove the reference. These files are what agents are told to trust, \
             so a path that moved without them is a defect and not a cosmetic lag."
        );
        std::process::exit(1);
    }
}

/// Extract the contents of every `` `backtick` `` span on a line.
fn backticked_tokens(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(open) = rest.find('`') {
        rest = &rest[open + 1..];
        let Some(close) = rest.find('`') else { break };
        let token = &rest[..close];
        if !token.is_empty() {
            out.push(token.to_string());
        }
        rest = &rest[close + 1..];
    }
    out
}

/// Decide whether a backticked token is a repo path this check should verify.
///
/// Deliberately conservative: it is better to skip a real path than to fail the gate on a
/// shell snippet. Requires a `/`, and rejects anything carrying URL, glob, command, or
/// Rust-path syntax.
/// Top-level source directories of the repo, read from the tree once per run.
///
/// `target/` is excluded: it is build output, so a doc naming `target/debug/…` describes
/// something that exists only after a build and must not decide whether the gate passes.
/// Hidden directories need no exclusion — a token starting with `.` is already rejected.
fn known_roots() -> &'static [String] {
    static ROOTS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    ROOTS.get_or_init(|| {
        let Ok(entries) = std::fs::read_dir(".") else {
            eprintln!("facts-check: could not read the repository root. Run from workspace root.");
            std::process::exit(1);
        };
        entries
            .flatten()
            .filter(|e| e.path().is_dir())
            .filter_map(|e| e.file_name().into_string().ok())
            // `out/` is where every build output lives: a doc naming `out/target/…`
            // describes a path a fresh clone does not have, exactly as `target/` did.
            .filter(|n| !n.starts_with('.') && n != "target" && n != out::OUT)
            .collect()
    })
}

fn repo_path_candidate(token: &str) -> Option<String> {
    let t = token.trim();
    if !t.contains('/') || t.len() < 3 {
        return None;
    }
    let rejects = [
        "://", "::", "*", "?", " ", "$", "{", "<", "|", "\\", "..", "@",
    ];
    if rejects.iter().any(|r| t.contains(r)) {
        return None;
    }
    // Absolute / platform paths and socket names are not repo-relative.
    if t.starts_with('/') || t.starts_with('.') {
        return None;
    }
    // Only trust tokens rooted at a real top-level directory of this repo.
    //
    // Read from the tree rather than a hand-kept list: a token under a root this check does
    // not recognise is skipped silently, so a stale list turns every path under a new root
    // into an unchecked one and the check goes green while saying nothing.
    let root = t.split('/').next()?;
    if !known_roots().iter().any(|r| r == root) {
        return None;
    }
    Some(t.trim_end_matches('/').to_string())
}

/// Recursively collect `*.md` files under `dir`, skipping `archive/` subtrees.
///
/// Archived docs are frozen history — their links pointed at a tree that has since
/// moved, and we deliberately do not maintain them. The lint guards the **live**
/// planning tree, so a stale archive can't make it permanently red (which would
/// train everyone to ignore it).
fn collect_markdown(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "archive") {
                continue;
            }
            collect_markdown(&path, out);
        } else if path.extension().is_some_and(|e| e == "md") {
            out.push(path);
        }
    }
}

/// The lines of a Markdown text that are outside every fenced block, with their 0-based
/// index; a fence's own opening and closing lines are not returned.
pub(crate) fn unfenced(text: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    // The open fence's character and length. As in CommonMark, only a run of the same
    // character at least as long, with nothing after it, closes it.
    let mut fence: Option<(char, usize)> = None;
    for (i, line) in text.lines().enumerate() {
        let t = line.trim_start();
        let run = |c: char| t.chars().take_while(|&x| x == c).count();
        match fence {
            Some((c, n)) if run(c) >= n && t.trim_start_matches(c).trim().is_empty() => {
                fence = None;
                continue;
            }
            Some(_) => continue,
            None => {
                fence = ['`', '~'].into_iter().map(|c| (c, run(c))).find(|&(_, n)| n >= 3);
                if fence.is_some() {
                    continue;
                }
            }
        }
        out.push((i, line));
    }
    out
}

/// The merge-conflict markers in a Markdown file, as `(1-based line, which marker)`.
///
/// A marker is the shape git writes, at the start of the line: `<<<<<<< ` or `>>>>>>> `
/// followed by a name, or a line that is exactly `=======`. Fenced blocks are skipped by the
/// fence reading [`unfenced`] gives, so a document can show a conflict on purpose.
///
/// Seven `=` directly under a text line is a setext heading underline and is not a marker.
/// That rule also passes the separator of a conflict whose "ours" side ends in text — which
/// costs nothing, because the `<<<<<<<` and `>>>>>>>` lines around it are findings anyway.
fn conflict_markers(content: &str) -> Vec<(usize, &'static str)> {
    const OURS: &str = "<<<<<<< ";
    const THEIRS: &str = ">>>>>>> ";
    const SEPARATOR: &str = "=======";
    let is_marker = |l: &str| l.starts_with(OURS) || l.starts_with(THEIRS) || l == SEPARATOR;
    let mut out = Vec::new();
    // The line directly above, when it was outside a fence: `None` after a fence line.
    let mut above: Option<(usize, &str)> = None;
    for (i, raw) in unfenced(content) {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let under_text = above.is_some_and(|(j, a)| {
            j + 1 == i && !a.trim().is_empty() && !is_marker(a)
        });
        if line.starts_with(OURS) {
            out.push((i + 1, "<<<<<<<"));
        } else if line.starts_with(THEIRS) {
            out.push((i + 1, ">>>>>>>"));
        } else if line == SEPARATOR && !under_text {
            out.push((i + 1, "======="));
        }
        above = Some((i, line));
    }
    out
}

/// Extract inline-Markdown link targets (`](target)`) that are repo-relative paths,
/// returning `(line_number, target)`. Reads the URL up to the first `)` and drops an
/// optional `"title"` suffix; skips external, protocol-relative, absolute, and
/// in-page-anchor links via [`is_relative_link`].
fn extract_relative_links(content: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let mut idx = 0;
        while let Some(pos) = line[idx..].find("](") {
            let start = idx + pos + 2;
            let Some(end_rel) = line[start..].find(')') else {
                break;
            };
            let raw = &line[start..start + end_rel];
            // Strip an optional title: `url "title"`.
            let url = raw.split_whitespace().next().unwrap_or("").trim();
            if is_relative_link(url) {
                out.push((i + 1, url.to_string()));
            }
            idx = start + end_rel + 1;
        }
    }
    out
}

/// True for a repo-relative link target — i.e. one `link-check` should resolve on
/// disk. False for empty, in-page anchors, external schemes, protocol-relative, and
/// absolute paths.
fn is_relative_link(url: &str) -> bool {
    if url.is_empty() || url.starts_with('#') || url.starts_with('/') {
        return false;
    }
    !["http://", "https://", "mailto:", "tel:", "//"]
        .iter()
        .any(|scheme| url.starts_with(scheme))
}

/// Collapse `..` and `.` segments in a path string for comparison.
/// This is a simple string-level normalisation, not a filesystem canonicalise.
fn normalise_path(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    parts.join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The dependency-rule table and `tree::REGIONS` must name the same set. They are
    /// separate types — one carries the rules, the other is just the names — and two lists of
    /// the same thing is exactly the shape `tree` exists to stop. So they are checked against
    /// each other rather than merged into a type that would make the rules awkward to read.
    #[test]
    fn the_region_rules_cover_every_region() {
        let ruled: Vec<&str> = REGIONS.iter().map(|(r, _)| *r).collect();
        for r in crate::tree::REGIONS {
            assert!(
                ruled.contains(r),
                "region `{r}` has no dependency rule in tier-check"
            );
        }
        for r in &ruled {
            assert!(
                crate::tree::REGIONS.contains(r),
                "tier-check rules `{r}`, which is not a region"
            );
        }
    }

    /// A closure cargo could not give is carried to the gate as the reason, never read as an
    /// empty tree — the false OK of `TASK-vault-check-reports-ok-when-cargo-tree-fails`.
    #[test]
    fn vault_check_measures_nothing_when_there_is_no_closure() {
        let why = "`cargo tree -p kvaultd` failed:\nerror: key with no value, expected `=`".to_string();
        assert_eq!(vault_reaches(&["kotton-app"], Err(why.clone())), Err(why));
    }

    #[test]
    fn vault_check_names_a_forbidden_crate_by_its_first_word_only() {
        let tree = "kvaultd v0.1.0 (/k/core/kvaultd)\nkotton-app v0.1.0 (/k/core/app)\n\
                    kotton-app-model v0.1.0 (/k/core/app-model)\nserde v1.0.0 (*)\nkotton-msg v0.1.0 (*)";
        assert_eq!(
            vault_reaches(&["kotton-app", "kotton-surface", "kotton-msg"], Ok(tree.to_string())),
            Ok(vec!["kotton-app", "kotton-msg"])
        );
        assert_eq!(vault_reaches(&["kotton-surface"], Ok(tree.to_string())), Ok(vec![]));
    }

    /// The merge of 2026-09-28 that staged a record with its markers in it: every record gate
    /// exited 0 on it (TASK-no-record-gate-catches-a-conflict-marker-in-a-record).
    #[test]
    fn a_conflict_left_in_a_record_is_a_finding_on_its_marker_lines() {
        let md = "# A record\n\n**Built:** x\n\n<<<<<<< HEAD\nours\n\n=======\ntheirs\n>>>>>>> claude/gate-main\n";
        let lines: Vec<usize> = conflict_markers(md).iter().map(|(n, _)| *n).collect();
        assert_eq!(lines, vec![5, 8, 10], "{:?}", conflict_markers(md));
    }

    /// (a) A `=======` with no text line directly above it is the separator — here the "ours"
    /// side is empty, so it sits right under the `<<<<<<<` line, and at the head of a file.
    #[test]
    fn a_separator_not_under_a_text_line_is_a_marker() {
        let md = "<<<<<<< HEAD\n=======\ntheirs\n>>>>>>> b\n";
        let lines: Vec<usize> = conflict_markers(md).iter().map(|(n, _)| *n).collect();
        assert_eq!(lines, vec![1, 2, 4]);
        let lines: Vec<usize> = conflict_markers("=======\n").iter().map(|(n, _)| *n).collect();
        assert_eq!(lines, vec![1]);
    }

    /// (b) Seven `=` directly under a text line underline a setext heading, and are not a marker.
    #[test]
    fn a_setext_underline_of_seven_is_not_a_marker() {
        let md = "Heading\n=======\n\nBody text.\n";
        assert_eq!(conflict_markers(md), vec![]);
    }

    /// A fence showing a conflict on purpose is a quotation of one, not one — and the fence
    /// is read by the same rule `measured_grep` reads it, so a longer fence holds a shorter.
    #[test]
    fn a_conflict_shown_inside_a_fence_is_not_a_finding() {
        let md = "Git writes this:\n\n````text\n<<<<<<< HEAD\n```\n=======\n>>>>>>> b\n````\n\nAfter.\n";
        assert_eq!(conflict_markers(md), vec![]);
        // A fence never closed hides everything after it, as CommonMark reads it.
        let unclosed = "```\n<<<<<<< HEAD\n";
        assert_eq!(conflict_markers(unclosed), vec![]);
        // After the fence closes, a marker is read again.
        let after = "```\nx\n```\n<<<<<<< HEAD\n";
        let lines: Vec<usize> = conflict_markers(after).iter().map(|(n, _)| *n).collect();
        assert_eq!(lines, vec![4]);
    }

    /// Only the exact shapes: a longer run of `=`, a marker with no space, or one indented,
    /// is not what git writes.
    #[test]
    fn only_the_shapes_git_writes_are_markers() {
        let md = "\n========\n\n<<<<<<<HEAD\n\n >>>>>>> b\n\n=======  \n";
        assert_eq!(conflict_markers(md), vec![]);
    }

    #[test]
    fn link_check_extracts_only_relative_links() {
        let md = "See [the map](../README.md) and [the store](../design/store.md#sec).\n\
                  External [site](https://example.com), [mail](mailto:a@b.c), anchor [x](#top),\n\
                  absolute [y](/etc/hosts), titled [z](./z.md \"a title\").";
        let links = extract_relative_links(md);
        let targets: Vec<&str> = links.iter().map(|(_, t)| t.as_str()).collect();
        assert_eq!(
            targets,
            vec![
                "../README.md",
                "../design/store.md#sec",
                "./z.md"
            ],
            "only repo-relative links (with optional #anchor / title) should be extracted"
        );
        // Line numbers are 1-based and correct.
        assert_eq!(links[0].0, 1);
        assert_eq!(links[2].0, 3);
    }

    #[test]
    fn is_relative_link_classifies_correctly() {
        for yes in ["../a.md", "./a.md", "a/b.md", "a.md#x"] {
            assert!(is_relative_link(yes), "{yes} should be relative");
        }
        for no in [
            "",
            "#top",
            "/abs",
            "https://x.y",
            "http://x",
            "mailto:a@b",
            "//host/x",
        ] {
            assert!(!is_relative_link(no), "{no} should not be relative");
        }
    }

    /// The constitution-check's whole value is being load-bearing in CI. Its
    /// most dangerous failure mode (H8) is a *silent* one: an inspected source
    /// file gets renamed, the read fails, and the check reports "all passed"
    /// while verifying nothing. `read_required` makes that fail at check time;
    /// this test makes it fail even faster — in `cargo test` — so a rename is
    /// caught in the same PR that makes it.
    #[test]
    fn inspected_files_exist() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask crate has a parent workspace dir");
        for rel in [
            ARTICLE_II_KDEVICED,
            ARTICLE_IV_CAPABILITY,
        ] {
            assert!(
                root.join(rel).exists(),
                "constitution-check inspects `{rel}`, but it does not exist. \
                 Repoint the check in constitution_check() and update the constant, \
                 or the invariant it guards will pass vacuously."
            );
        }
    }
}

#[cfg(test)]
mod staging_decision_tests {
    use super::{should_stage_shell, the_daemon_said_something_the_person_needs, TRAY_NOTE};

    /// **The decision this unit exists to change.** `just desktop::run` stages the build
    /// it just made, with a user named and without one, because there is one body of the
    /// shell and every path runs it — the welcome, the lock screen, and the relaunch as a
    /// user. The run that skipped staging is why a rebuild stopped at the lock screen and
    /// the desk stayed on whatever the last no-user run left in `system/shell/`.
    #[test]
    fn the_desktop_stages_the_shell_on_every_run() {
        assert!(
            should_stage_shell(true, None),
            "the desktop with nobody named must stage: the welcome screen has no registry to resolve a shell in"
        );
        assert!(
            should_stage_shell(true, Some("austin")),
            "the desktop with a user named must stage too: the name selects an identity, it does not bring a shell of its own"
        );
    }

    /// Headless has no window to draw a shell in, so it stages nothing and nothing about
    /// this change reaches it — its surface is the terminal, and that is untouched.
    #[test]
    fn headless_stages_nothing_with_a_user_or_without() {
        assert!(!should_stage_shell(false, None));
        assert!(!should_stage_shell(false, Some("austin")));
    }

    /// **The recipe reads the lines the daemon writes** — and it is one join, not two
    /// sentences that happen to match today.
    ///
    /// `TASK-quit-kotton-stops-the-daemon-and-closing-the-window-does-not`. The recipe
    /// waits on the daemon and cannot see the window; the only way it learns the window
    /// closed is by reading `kuserd`'s log. That is a string comparison between two
    /// crates, and the failure mode of a string comparison between two crates is that
    /// somebody rewords one side and the line silently stops printing, with nothing red.
    ///
    /// So both sentences live in `kotton_common`, `kuserd` logs them and this reads
    /// them, and the test asserts the matcher answers to the constants rather than to a
    /// literal copied out of them. A real log line is used, prefix and all, because the
    /// matcher sees `tracing`'s formatting and not the bare message.
    #[test]
    fn the_recipe_reads_the_lines_the_daemon_writes() {
        let as_logged = |msg: &str| format!("2026-09-22T00:00:00Z  INFO kuserd: {msg}");

        let closed =
            the_daemon_said_something_the_person_needs(&as_logged(kotton_common::KUID_LEFT_LINE))
                .expect("the recipe did not recognise the window closing");
        assert!(
            closed.contains(kotton_common::KUID_LEFT_LINE),
            "the recipe reworded the daemon's own sentence: {closed}"
        );
        assert!(
            closed.contains("Quit Kotton from the tray, or Ctrl-C, stops it"),
            "the person is told the daemon is still running and not how to stop it: {closed}"
        );

        let quit =
            the_daemon_said_something_the_person_needs(&as_logged(kotton_common::DAEMON_QUIT_LINE))
                .expect("the recipe did not recognise the daemon stopping");
        assert!(quit.contains(kotton_common::DAEMON_QUIT_LINE));

        // And it stays quiet about everything else. The daemon logs hundreds of lines a
        // run; a matcher that fired on any of them would bury the one that matters.
        for ordinary in [
            "System daemon listening on UnixSocket(\"/run/user/1000/kuserd\")",
            "kuid exited cleanly; stopping supervision",
            "shutdown complete",
        ] {
            assert!(
                the_daemon_said_something_the_person_needs(&as_logged(ordinary)).is_none(),
                "the recipe spoke up about an ordinary log line: {ordinary}"
            );
        }
    }

    /// The tray note says where to look, including the place Windows 11 hides it.
    ///
    /// `TASK-the-tray-icon-is-a-dark-square-on-a-dark-tray` asks for this sentence by
    /// name; without the chevron half it is advice to look where the owner already
    /// looked.
    #[test]
    fn the_recipe_says_where_the_tray_icon_is() {
        assert!(TRAY_NOTE.contains("notification area"));
        assert!(
            TRAY_NOTE.contains('^'),
            "the overflow is where it actually is: {TRAY_NOTE}"
        );
    }
}
