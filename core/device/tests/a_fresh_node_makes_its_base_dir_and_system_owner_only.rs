// SPDX-License-Identifier: AGPL-3.0-or-later
//! A fresh node's base dir and its `system/` are made `0700`, whichever store
//! makes them first.
//!
//! **One test in this file, and it must stay one.** It sets the process's umask
//! to `022` — the usual one, under which `create_dir_all` makes `0755` — and a
//! umask is the whole process's: a second test here, on another thread, would
//! race it. An integration test file is its own process, so this is the one
//! place the umask can be set without reaching any other test.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

fn mode_of(path: &Path) -> u32 {
    std::fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}

#[test]
fn a_fresh_node_makes_its_base_dir_and_system_owner_only() {
    rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o022));
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let root = tempfile::tempdir().unwrap();
    let mut wrong = Vec::new();
    for first in ["the device db", "the record store", "the secrets store"] {
        let base = root.path().join(first.replace(' ', "-")).join("base");
        assert!(!base.exists());
        match first {
            "the device db" => rt.block_on(async {
                // The machine db it imports from, kept outside the base dir so
                // the device db is what makes the base dir and `system/`.
                let agent = kotton_device::db::open_machine_db(root.path().join("elsewhere").join("agent.db")).await.unwrap();
                kotton_device::db::open_device_db(&base, &agent).await.unwrap().close().await;
            }),
            "the record store" => rt.block_on(async {
                kotton_record::open_sqlite(&base.join("system").join("agent.db")).await.unwrap().close().await;
            }),
            _ => {
                use kotton_sys::secret::SecretsStore as _;
                kotton_secret::FileSecrets::for_base_dir(&base).unwrap().set_secret("k", "v").unwrap();
            }
        }
        for dir in [base.clone(), base.join("system")] {
            let mode = mode_of(&dir);
            if mode != 0o700 {
                wrong.push(format!("{first} first: {} is {mode:04o}", dir.display()));
            }
        }
    }
    assert!(wrong.is_empty(), "made wider than 0700 under umask 022:\n{}", wrong.join("\n"));
}
