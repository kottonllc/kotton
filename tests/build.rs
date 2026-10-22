// SPDX-License-Identifier: AGPL-3.0-or-later
//! Build script for the `kotton-integration-tests` package.
//!
//! Emits `MOCK_RUNNER_BIN` so tests can locate the `kotton-mock-runner`
//! binary without hard-coding a target directory path.
//!
//! **The binary is not guaranteed to exist.** This file used to say it was,
//! "because `kotton-mock-runner` is listed as a dev-dependency" — and
//! `tests/Cargo.toml`, ten lines of its own comment, says the opposite and is
//! right: a bin-only crate cannot be a Cargo library dep, so nothing here pulls
//! it into this package's unit graph.
//!
//! What follows, measured 2026-09-03 by deleting the binary and running the
//! suite: `cargo test -p kotton-integration-tests` does **not** build it, and
//! the tests that spawn it fail with `No such file or directory`. Only a
//! workspace-wide build or test does, because then it is built as a member.
//!
//! Cargo has no way to express "this test needs that binary" on stable —
//! artifact dependencies are the feature for it and they are nightly-only. So
//! the paths are emitted here and checked together, the first time a test asks for
//! one, so a failure names every binary that is missing. See `common::bins`.

fn main() {
    let manifest_dir =
        std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));

    // Walk up to the workspace root (one level above `tests/`).
    let workspace_root = manifest_dir
        .parent()
        .expect("tests/ must have a parent directory");

    // **Asked of cargo, not composed.** Where this workspace builds is
    // `build.target-dir` in `.cargo/config.toml` (`out/target`) unless
    // `CARGO_TARGET_DIR` is exported, and `cargo metadata` is the one answer that
    // knows both. This read the variable and fell back to `<root>/target` — the
    // default layout — which stopped being true the day the config key moved it
    // (TASK-build-outputs-live-under-out-and-the-tooling-reads-where-cargo-put-them).
    //
    // Before that it took a relative `CARGO_TARGET_DIR` verbatim, baking a path the
    // test then resolved from `tests/`: 253 tests failed on 2026-09-16 reporting a
    // binary missing that sat exactly where it was built. `cargo metadata` reports an
    // absolute path, so that cannot come back.
    let target_dir = cargo_target_dir(workspace_root);
    println!("cargo:rerun-if-env-changed=CARGO_TARGET_DIR");

    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());

    #[cfg(windows)]
    let binary = target_dir.join(&profile).join("kotton-mock-runner.exe");
    #[cfg(not(windows))]
    let binary = target_dir.join(&profile).join("kotton-mock-runner");

    println!("cargo:rustc-env=MOCK_RUNNER_BIN={}", binary.display());
    println!("cargo:rerun-if-changed=fixtures/mock-runner/src/main.rs");

    // Same for `kuserd`: emitted as a path, built only by a workspace build.
    // `two_node_transfer` spawns it and fails the same way when it is absent.
    #[cfg(windows)]
    let kuserd = target_dir.join(&profile).join("kuserd.exe");
    #[cfg(not(windows))]
    let kuserd = target_dir.join(&profile).join("kuserd");

    println!("cargo:rustc-env=KUSERD_BIN={}", kuserd.display());

    // And `khttpd`, so `gateway_bind` can start a real gateway and read back the
    // address it actually bound. Neither daemon is a dev-dependency (binary-only
    // crates cannot be), so the Justfile builds both before the suite runs.
    #[cfg(windows)]
    let khttpd = target_dir.join(&profile).join("khttpd.exe");
    #[cfg(not(windows))]
    let khttpd = target_dir.join(&profile).join("khttpd");

    println!("cargo:rustc-env=KHTTPD_BIN={}", khttpd.display());

    // And `kinferd`, so `inference_sidecar` can run the real supervisor against
    // the real process and prove the handed pipe carries a generation
    // (RFC-0085). Same bargain as the three above: emitted as a path, built only
    // by a workspace build or by `just test`, checked at the point of use.
    #[cfg(windows)]
    let kinferd = target_dir.join(&profile).join("kinferd.exe");
    #[cfg(not(windows))]
    let kinferd = target_dir.join(&profile).join("kinferd");

    println!("cargo:rustc-env=KINFERD_BIN={}", kinferd.display());

    // And the real `kotton-runner`, so `confinement` can prove a denial through
    // the process the daemon actually spawns rather than through the mock.
    #[cfg(windows)]
    let runner = target_dir.join(&profile).join("kotton-runner.exe");
    #[cfg(not(windows))]
    let runner = target_dir.join(&profile).join("kotton-runner");

    println!("cargo:rustc-env=KOTTON_RUNNER_BIN={}", runner.display());

    // And the `kotton` CLI itself, so a test can run a subcommand the way a
    // person does: as its own process, with its own connection, discovering the
    // daemon through the environment.
    //
    // Nothing did until 2026-09-11, and six `id` subcommands were broken the
    // whole time — see `TASK-six-id-subcommands-connected-without-a-session`.
    // The suite exercised the *library* path, where a session is already bound
    // to the connection `create_user` minted it on, and that path was green.
    #[cfg(windows)]
    let kotton = target_dir.join(&profile).join("kotton.exe");
    #[cfg(not(windows))]
    let kotton = target_dir.join(&profile).join("kotton");

    println!("cargo:rustc-env=KOTTON_BIN={}", kotton.display());

    // And `kvaultd`, which `headless` installs with the self-host adapter and starts as
    // its unit does. Emitted here like the rest, so every binary the suite runs is found
    // by the one answer `cargo metadata` gives and checked together (`common::bins`).
    #[cfg(windows)]
    let kvaultd = target_dir.join(&profile).join("kvaultd.exe");
    #[cfg(not(windows))]
    let kvaultd = target_dir.join(&profile).join("kvaultd");

    println!("cargo:rustc-env=KVAULTD_BIN={}", kvaultd.display());
}

/// The workspace's target directory, as `cargo metadata` reports it.
///
/// Run from the workspace root so the root's `.cargo/config.toml` is the one read, with
/// the `cargo` that is running this build. `--no-deps --offline` resolves nothing and
/// takes no lock the build holds. Read with a string scan rather than a JSON parser so
/// the build script depends on nothing: the one field is a JSON string, and the only
/// escapes a path can carry in it are `\\` and `\"`.
fn cargo_target_dir(workspace_root: &std::path::Path) -> std::path::PathBuf {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let out = std::process::Command::new(cargo)
        .args(["metadata", "--format-version", "1", "--no-deps", "--offline"])
        .current_dir(workspace_root)
        .output()
        .expect("run `cargo metadata` to learn the target directory");
    assert!(
        out.status.success(),
        "`cargo metadata` failed, so the suite cannot learn where its binaries are built:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    let key = "\"target_directory\":\"";
    let start = text.find(key).expect("`cargo metadata` names a target_directory") + key.len();
    let mut dir = String::new();
    let mut chars = text[start..].chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => break,
            '\\' => dir.push(chars.next().expect("a JSON escape is complete")),
            c => dir.push(c),
        }
    }
    std::path::PathBuf::from(dir)
}
