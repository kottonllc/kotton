// SPDX-License-Identifier: AGPL-3.0-or-later
//! `vault.env` has three readers: `install-server.sh`, systemd's `EnvironmentFile=`, and
//! `kvaultd` itself (`kvaultd::settings::env_file_pairs`, which `take_installed_env` runs
//! before every verb but `serve`, and through which `create` reads its address). The relay's
//! install test holds the first two to each other over the shared corpus; this holds the
//! third to both, over the same corpus — the fixed forms and the twenty generated seeds
//! (`TASK-the-vaults-own-reader-of-its-settings-reads-the-plain-form-the-installer-admits`).
//!
//! For every file the installer accepts, `kvaultd`'s reader must take it too and give each
//! of the five values the installer reads as the installer's `setting` does, and as
//! systemd's `load_env_file` does. Without that library or `python3` each test fails, naming
//! which is missing — unless the run sets `KOTTON_NO_SYSTEMD_PARSER`, and then both are
//! compiled `#[ignore]`d with that reason (the crate's build script), so libtest counts them
//! ignored by name, and two tests of their own hold the `kvaultd` column to the installer's
//! (`TASK-the-settings-differential-is-not-green-where-systemds-parser-is-absent`).
#![cfg(target_os = "linux")]

use std::io::Write as _;
use std::path::{Path, PathBuf};

#[path = "../../../infra/relay/tests/common/settings_corpus.rs"]
mod corpus;
use corpus::*;

const KEYS: [&str; 5] = ["KOTTON_RELAY_ADVERTISE", "KOTTON_RELAY_BIND", "KOTTON_RELAY_STATE_DIR", "KOTTON_PUBLIC_ADDR", "KOTTON_BASE_DIR"];

/// `kvaultd`'s reading of each key, the last assignment winning as it does when
/// `take_installed_env` sets them in order; `Err` naming why where it refuses the file.
fn vaults_reading(file: &Path) -> Result<Vec<String>, String> {
    let pairs = kvaultd::settings::env_file_pairs(&std::fs::read(file).unwrap())?;
    Ok(KEYS
        .iter()
        .map(|key| pairs.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v.clone()).unwrap_or_default())
        .collect())
}

/// `systemd_for` names the test whose systemd column is compared; `None` compares kvaultd's
/// column with the installer's alone, which is what the declared-absent run's own tests do.
fn compare(systemd_for: Option<&str>, label: &str, names: &[String], files: &[PathBuf]) {
    let ours = installers_verdicts(files, &KEYS);
    // Missing, the systemd column fails the test, naming what is missing.
    let systemd = systemd_for.and_then(systemds_parser_for).map(|parser| systemds_reading(&parser, files, &KEYS));
    match &systemd {
        Some((lib, _)) => {
            let _ = std::io::stderr().write_all(format!("{label}: compared against {lib} and kvaultd's reader\n").as_bytes());
        }
        None => {
            let _ = std::io::stderr().write_all(format!("{label}: kvaultd's reader compared with the installer's only\n").as_bytes());
        }
    }
    let mut differ = Vec::new();
    let mut accepted = 0;
    for (i, verdict) in ours.iter().enumerate() {
        let Some(values) = verdict else { continue };
        accepted += 1;
        let name = &names[i];
        match vaults_reading(&files[i]) {
            Err(why) => differ.push(format!("{name}: the installer accepts it and kvaultd's reader refuses it: {why}")),
            Ok(vault) => {
                for (k, key) in KEYS.iter().enumerate() {
                    if vault[k] != values[k] {
                        differ.push(format!("{name}: {key} — installer {:?}, kvaultd {:?}", values[k], vault[k]));
                    }
                }
            }
        }
        if let Some((_, readings)) = &systemd {
            let (r, ref theirs) = readings[i];
            if r < 0 {
                differ.push(format!("{name}: the installer accepts it and systemd's parser fails it ({r})"));
            } else {
                for (k, key) in KEYS.iter().enumerate() {
                    let t = theirs[k].clone().unwrap_or_default();
                    if t != values[k] {
                        differ.push(format!("{name}: {key} — installer {:?}, systemd {t:?}", values[k]));
                    }
                }
            }
        }
    }
    let _ = std::io::stderr().write_all(format!("{label}: the installer accepted {accepted} of {}\n", files.len()).as_bytes());
    assert!(differ.is_empty(), "{label}: {} disagreement(s):\n{}", differ.len(), differ.iter().take(12).cloned().collect::<Vec<_>>().join("\n"));
}

fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The fixed forms: every accepted and refused form of the corpus, and the vault's own file.
fn fixed_forms(dir: &Path) -> (Vec<String>, Vec<PathBuf>) {
    let mut names = Vec::new();
    let mut files = Vec::new();
    for (n, (name, bytes)) in accepted_forms().into_iter().enumerate() {
        let f = dir.join(format!("accepted-{n}.env"));
        std::fs::write(&f, bytes).unwrap();
        names.push(name.to_string());
        files.push(f);
    }
    for (n, (from, to, _)) in refused_forms().into_iter().enumerate() {
        let f = dir.join(format!("refused-{n}.env"));
        std::fs::write(&f, replaced(shipped().as_bytes(), from.as_bytes(), to)).unwrap();
        names.push(format!("{:?}", String::from_utf8_lossy(to)));
        files.push(f);
    }
    // The vault's own shipped settings, and its address quoted, as the relay's are above.
    let vault = std::fs::read_to_string(repo().join("infra/vault/vault.env")).unwrap();
    for (name, text) in [
        ("vault.env as shipped", vault.clone()),
        ("vault address double-quoted", vault.replace("KOTTON_PUBLIC_ADDR=\n", "KOTTON_PUBLIC_ADDR=\"192.0.2.7\"\n")),
        ("vault base directory single-quoted", vault.replace("KOTTON_BASE_DIR=/var/lib/kotton-vault\n", "KOTTON_BASE_DIR='/var/lib/elsewhere'\n")),
    ] {
        let f = dir.join(format!("vault-{}.env", files.len()));
        std::fs::write(&f, text).unwrap();
        names.push(name.to_string());
        files.push(f);
    }
    (names, files)
}

/// The generated forms: the twenty seeds' files.
fn generated_forms(dir: &Path) -> (Vec<String>, Vec<PathBuf>) {
    let mut names = Vec::new();
    let mut files = Vec::new();
    for seed in SEEDS {
        for (n, text) in generated_files(seed, 600).into_iter().enumerate() {
            let f = dir.join(format!("seed-{seed}-{n}.env"));
            std::fs::write(&f, &text).unwrap();
            names.push(format!("seed {seed} file {n}"));
            files.push(f);
        }
    }
    (names, files)
}

/// **The fixed forms: every one the installer accepts, kvaultd's reader reads alike.**
#[test]
#[cfg_attr(kotton_no_systemd_parser, ignore = "KOTTON_NO_SYSTEMD_PARSER is set: this machine declares it has no systemd parser to compare with")]
fn kvaultd_reads_the_fixed_forms_the_installer_accepts_as_the_installer_and_systemd_do() {
    let dir = scratch("vault-fixed");
    let (names, files) = fixed_forms(&dir);
    compare(
        Some("kvaultd_reads_the_fixed_forms_the_installer_accepts_as_the_installer_and_systemd_do"),
        "kvaultd_reads_the_fixed_forms",
        &names,
        &files,
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// **The generated forms: the twenty seeds, read alike by all three.**
#[test]
#[cfg_attr(kotton_no_systemd_parser, ignore = "KOTTON_NO_SYSTEMD_PARSER is set: this machine declares it has no systemd parser to compare with")]
fn kvaultd_reads_the_generated_forms_the_installer_accepts_as_the_installer_and_systemd_do() {
    let dir = scratch("vault-generated");
    let (names, files) = generated_forms(&dir);
    compare(
        Some("kvaultd_reads_the_generated_forms_the_installer_accepts_as_the_installer_and_systemd_do"),
        &format!("kvaultd_reads_the_generated_forms (seeds {SEEDS:?})"),
        &names,
        &files,
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// **Declared absent, kvaultd's column is still held to the installer's** — on the fixed
/// forms, in a test of its own, so the two above are counted ignored and this one passed.
#[cfg(kotton_no_systemd_parser)]
#[test]
fn kvaultd_reads_the_fixed_forms_the_installer_accepts_as_the_installer_does() {
    let dir = scratch("vault-fixed-installer-only");
    let (names, files) = fixed_forms(&dir);
    compare(None, "kvaultd_reads_the_fixed_forms (installer only)", &names, &files);
    let _ = std::fs::remove_dir_all(&dir);
}

/// **And on the generated forms.**
#[cfg(kotton_no_systemd_parser)]
#[test]
fn kvaultd_reads_the_generated_forms_the_installer_accepts_as_the_installer_does() {
    let dir = scratch("vault-generated-installer-only");
    let (names, files) = generated_forms(&dir);
    compare(None, &format!("kvaultd_reads_the_generated_forms (installer only, seeds {SEEDS:?})"), &names, &files);
    let _ = std::fs::remove_dir_all(&dir);
}
