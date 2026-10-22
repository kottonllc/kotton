// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton device reset --yes` under `KOTTON_SECRETS=file` leaves no base
//! directory behind.
//!
//! The reset removes the directory and then deletes this install's secret
//! entries. Under the file store those entries were `system/secrets.json`,
//! inside the directory, and a delete that wrote recreated `system/` with an
//! empty store and its lock — after the command had printed that the
//! directory was gone. Red on e99e03317.
//!
//! The binary is run with an environment of only the variables named here.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// A directory of this test's own, outside every other run's. Not a
/// `tempfile` one: the crate has no such dependency, and the name is all a
/// directory needs to be this run's.
fn scratch_root() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("kotton-device-reset-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    root
}

/// Every path under `dir`, for a failure message.
fn listing(dir: &Path) -> Vec<PathBuf> {
    let mut found = vec![dir.to_path_buf()];
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            found.extend(listing(&entry.path()));
        }
    }
    found
}

#[test]
fn a_reset_under_a_file_store_leaves_no_base_directory() {
    let root = scratch_root();
    let base = root.join("base");
    // The child's temp directory, beside the base rather than above it: a base
    // under the temp directory is a throwaway root, which gets an in-process
    // store and would never reach the file this test is about. This is also
    // where the daemon probe looks for a door, and nothing listens here.
    let tmp = root.join("tmp");
    std::fs::create_dir_all(&tmp).unwrap();
    assert!(!base.starts_with(&tmp), "the base is under the child's temp directory: {}", base.display());

    // An install as the file store leaves one: a device key in the store, and
    // one identity's directory.
    std::fs::create_dir_all(base.join("system")).unwrap();
    std::fs::create_dir_all(base.join("users").join("alice")).unwrap();
    std::fs::write(
        base.join("system").join("secrets.json"),
        br#"{"kotton:device_operational_key": "hex"}"#,
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_kotton"))
        .args(["device", "reset", "--yes"])
        .env_clear()
        .env("KOTTON_BASE_DIR", &base)
        .env("KOTTON_SECRETS", "file")
        .env("TMPDIR", &tmp)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let present = base.exists().then(|| listing(&base));
    let _ = std::fs::remove_dir_all(&root);

    assert!(out.status.success(), "reset failed ({}):\n{stdout}\n{stderr}", out.status);
    assert!(
        stdout.contains(&format!("Reset. {} is gone, with its secrets.", base.display())),
        "reset did not say the directory is gone:\n{stdout}"
    );
    assert_eq!(present, None, "the reset said the directory is gone and left it there");
}
