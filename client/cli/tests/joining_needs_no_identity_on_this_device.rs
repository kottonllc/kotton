// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton id join <name>` is reached on a device with no identity: the join is how one
//! arrives, so the door runs it without resolving an identity or presenting a session
//! (`Command::execute_without_session`), and the first thing it needs is the daemon.
//!
//! The binary runs with an environment of only the variables named here, so it can reach
//! no daemon, no session and no active identity of the machine it runs on. The whole
//! ceremony, with a daemon on each side, is the suite's `device_add_join`.

use std::process::{Command, Output};

fn kotton(dir: &std::path::Path, args: &[&str]) -> Output {
    let home = dir.join("home");
    std::fs::create_dir_all(&home).unwrap();
    Command::new(env!("CARGO_BIN_EXE_kotton"))
        .args(args)
        .env_clear()
        .env("HOME", &home)
        .env("KOTTON_BASE_DIR", dir.join("base"))
        .env("NO_COLOR", "1")
        .output()
        .unwrap()
}

fn said(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn a_join_on_a_device_with_no_identity_goes_to_the_daemon_and_not_to_a_refusal() {
    let dir = std::env::temp_dir().join(format!("kotton-id-join-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // Named: it goes looking for the daemon, which is not running here, and says so.
    let joined = kotton(&dir, &["id", "join", "alice", "a-code"]);
    let text = said(&joined);
    assert!(!joined.status.success(), "{text}");
    assert!(text.contains("could not reach the daemon"), "{text}");
    assert!(!text.contains("no active identity"), "the join asked for an identity first: {text}");

    // The shell's verb at the terminal, with nobody named: it says how to name one.
    let unnamed = kotton(&dir, &["device", "join", "a-code"]);
    let text = said(&unnamed);
    assert!(!unnamed.status.success(), "{text}");
    assert!(text.contains("kotton id join <name>"), "{text}");

    std::fs::remove_dir_all(&dir).unwrap();
}
