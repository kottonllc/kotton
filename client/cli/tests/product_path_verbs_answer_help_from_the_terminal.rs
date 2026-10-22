// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton mint`, `kotton enrol`, `kotton cp`, `kotton cat`, `kotton keep`, `kotton relay` and `kotton vault` are
//! verbs of the terminal: each hands its words to the shell verb of the same name
//! (`bridge::run_verb`), and its `--help` ends on that verb's own help, so the page that says
//! `kotton mint relay` names a command the binary has and documents.
//!
//! The binary runs with an environment of only the variables named here, so it can reach no
//! daemon, no session and no active identity of the machine it runs on: help is answered
//! before any of them is asked for. No test under this crate starts a daemon, so what the
//! verbs do against one is held by the shell's own tests of the verbs, which the terminal
//! runs unchanged.

use std::process::Command;

#[test]
fn each_product_path_verb_answers_help_with_the_shell_verbs_own() {
    let dir = std::env::temp_dir().join(format!("kotton-verb-help-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let home = dir.join("home");
    std::fs::create_dir_all(&home).unwrap();

    let executor = kotton_shell::ShellExecutor::new();
    let docs = executor.command_docs();
    for verb in ["mint", "enrol", "cp", "cat", "keep", "relay", "vault"] {
        let out = Command::new(env!("CARGO_BIN_EXE_kotton"))
            .args([verb, "--help"])
            .current_dir(&dir)
            .env_clear()
            .env("HOME", &home)
            .env("KOTTON_BASE_DIR", dir.join("base"))
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "`kotton {verb} --help` failed:\nstdout: {stdout}\nstderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let (_, help) = docs
            .iter()
            .find(|(name, _)| name == verb)
            .unwrap_or_else(|| panic!("the shell registers no `{verb}`"));
        assert!(
            stdout.contains(help),
            "`kotton {verb} --help` does not say the shell's `{verb}` help.\nwant: {help}\ngot: {stdout}"
        );
        assert!(
            stdout.contains(&format!("Usage: kotton {verb} [OPTIONS] [ARGS]...")),
            "`kotton {verb} --help` is not the terminal verb's: {stdout}"
        );
        assert!(stdout.contains("--user <USER>"), "`kotton {verb} --help` names no --user: {stdout}");
    }

    std::fs::remove_dir_all(&dir).unwrap();
}
