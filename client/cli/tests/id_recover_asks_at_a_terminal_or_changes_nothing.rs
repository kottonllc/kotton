// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton id recover` asks for the words at a hidden prompt, and with no terminal to
//! ask at it says so and changes nothing: it asks before it connects, so it reaches no
//! daemon and writes nothing under its base directory.
//!
//! The binary runs with an environment of only the variables named here and a null
//! stdin, which is what a script or a pipe gives it. What it does at a terminal is held
//! by `commands::recover`'s tests, which answer its questions in advance, and by the
//! suite, which drives it on a real terminal against a daemon and a vault.

use std::process::{Command, Stdio};

#[test]
fn id_recover_with_no_terminal_says_where_to_run_it_and_writes_nothing() {
    let dir = std::env::temp_dir().join(format!("kotton-id-recover-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let home = dir.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let base = dir.join("base");

    for args in [&["id", "recover"][..], &["id", "recover", "sam"][..]] {
        let out = Command::new(env!("CARGO_BIN_EXE_kotton"))
            .args(args)
            .current_dir(&dir)
            .env_clear()
            .env("HOME", &home)
            .env("KOTTON_BASE_DIR", &base)
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let said = format!(
            "stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!out.status.success(), "`kotton {}` succeeded with nobody to ask.\n{said}", args.join(" "));
        assert!(
            said.contains("run `kotton id recover` at a terminal") && said.contains("nothing was changed"),
            "`kotton {}` did not say where to run it.\n{said}",
            args.join(" ")
        );
        assert!(!base.exists(), "`kotton {}` wrote under its base directory.\n{said}", args.join(" "));
    }

    std::fs::remove_dir_all(&dir).unwrap();
}
