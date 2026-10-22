// SPDX-License-Identifier: AGPL-3.0-or-later
//! The device registry's writers make a fresh node's base dir, its `system/`
//! and a user's directory `0700`.
//!
//! **One test in this file, and it must stay one**, for the reason
//! `a_fresh_node_makes_its_base_dir_and_system_owner_only.rs` gives: it sets the
//! process's umask to `022`, and a umask is the whole process's.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

fn mode_of(path: &Path) -> u32 {
    std::fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}

#[test]
fn save_users_on_a_fresh_base_makes_base_and_system_owner_only() {
    use kotton_device::registry;
    rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o022));
    let root = tempfile::tempdir().unwrap();
    let mut wrong = Vec::new();
    let mut expect = |first: &str, dirs: Vec<std::path::PathBuf>| {
        for dir in dirs {
            let mode = mode_of(&dir);
            if mode != 0o700 {
                wrong.push(format!("{first} first: {} is {mode:04o}", dir.display()));
            }
        }
    };

    let base = root.path().join("users-registry").join("base");
    registry::save_users(&base.join("system"), &registry::UsersRegistry::default()).unwrap();
    expect("save_users", vec![base.clone(), base.join("system")]);

    let base = root.path().join("device-routing").join("base");
    registry::save_device_routing(&base.join("system"), &registry::DeviceRouting::default()).unwrap();
    expect("save_device_routing", vec![base.clone(), base.join("system")]);

    let base = root.path().join("user-directory").join("base");
    let user = registry::create_user_directory(&base, "alice").unwrap();
    expect("create_user_directory", vec![base.clone(), base.join("users"), user]);

    assert!(wrong.is_empty(), "made wider than 0700 under umask 022:\n{}", wrong.join("\n"));
}
