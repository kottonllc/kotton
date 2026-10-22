// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton config paths` prints the door the client connects to
//! (`TASK-config-paths-prints-a-socket-nothing-binds`).
//!
//! The binary is run with an environment of only the variables named here, and
//! its `socket:` line is held equal to `kuserd_door_in` over that same
//! environment — the function `KottonClient::connect` asks. Until 2026-09-28 the
//! line was `/tmp/<name>.sock`, joined by hand, and no daemon bound there.
#![cfg(unix)]

use std::process::Command;

/// The `socket:` line `kotton config paths` prints under `env`, and nothing else set.
fn printed_socket(env: &[(&str, &str)]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_kotton"))
        .args(["config", "paths"])
        .env_clear()
        .envs(env.iter().copied())
        .output()
        .unwrap();
    assert!(out.status.success(), "config paths failed: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8(out.stdout).unwrap();
    stdout
        .lines()
        .find_map(|l| l.trim_start().strip_prefix("socket:"))
        .unwrap_or_else(|| panic!("no socket line in:\n{stdout}"))
        .trim()
        .to_string()
}

/// The door a client under `env` connects to.
fn door(env: &[(&str, &str)]) -> String {
    let lookup = |k: &str| env.iter().find(|(key, _)| *key == k).map(|(_, v)| v.to_string());
    kotton_common::paths::kuserd_door_in(&lookup).unwrap().display().to_string()
}

#[test]
fn the_socket_line_is_the_door_under_each_tier_and_the_fallback() {
    let long = format!("/tmp/{}", "b".repeat(120));
    let cases: &[&[(&str, &str)]] = &[
        // Tier 3: base_dir/run.
        &[("KOTTON_BASE_DIR", "/tmp/kotton-config-paths-test")],
        // A base dir long enough that tier 3 overflows `sun_path`: the door moves
        // to `/tmp/kotton-<hash>/`.
        &[("KOTTON_BASE_DIR", &long)],
        // Tier 2, and a name other than the default.
        &[
            ("KOTTON_BASE_DIR", "/tmp/kotton-config-paths-test"),
            ("TMPDIR", "/tmp/kotton-config-paths-tmpdir"),
            ("KUSERD_IPC_NAME", "kuserd-dev"),
        ],
    ];
    for env in cases {
        assert_eq!(printed_socket(env), door(env), "under {env:?}");
    }
    let fallback = door(&[("KOTTON_BASE_DIR", &long)]);
    assert!(
        fallback.starts_with("/tmp/kotton-") && !fallback.starts_with(&long),
        "the long case did not exercise the sun_path fallback: {fallback}"
    );
}
