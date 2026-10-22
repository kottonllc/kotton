// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton app new` writes an app with no daemon running: an author's first command asks
//! the daemon nothing, so the door runs it without connecting
//! (`Command::execute_without_session`).
//!
//! The binary runs with an environment of only the variables named here, so it can reach
//! no daemon, no session and no active identity of the machine it runs on.

use std::process::Command;

#[test]
fn app_new_writes_the_scaffold_with_no_daemon_and_no_identity() {
    let dir = std::env::temp_dir().join(format!("kotton-app-new-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let home = dir.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_kotton"))
        .args(["app", "new", "hello"])
        .current_dir(dir.as_path())
        .env_clear()
        .env("HOME", &home)
        .env("KOTTON_BASE_DIR", dir.as_path().join("base"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "`kotton app new hello` failed with no daemon:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // Each file is the shell's scaffold, byte for byte, the SDK reached by its repository.
    // That the scaffold is a crate the tree compiles is held where its fixture is
    // (`guest/examples/hello`, by xtask's `the_scaffold_is_the_fixture_build_apps_compiles`).
    let app = dir.as_path().join("hello");
    for (file, contents) in kotton_shell::scaffold_files("hello", kotton_shell::SDK_FROM_REPOSITORY) {
        assert_eq!(std::fs::read_to_string(app.join(file)).unwrap(), contents, "{file} is the scaffold's");
    }
    let cargo = std::fs::read_to_string(app.join("Cargo.toml")).unwrap();
    assert!(cargo.contains("git = \"https://github.com/kottonllc/kotton\""), "{cargo}");
    let mut written: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(&app).unwrap() {
        written.push(entry.unwrap().file_name().to_string_lossy().into_owned());
    }
    written.sort();
    assert_eq!(written, ["Cargo.toml", "manifest.toml", "src"], "three files, no web half");

    std::fs::remove_dir_all(&dir).unwrap();
}
