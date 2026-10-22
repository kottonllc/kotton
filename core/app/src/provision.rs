// SPDX-License-Identifier: AGPL-3.0-or-later
//! Laying down a user's app directory before anything is installed into it.

use anyhow::{Context, Result};
use std::path::Path;

/// Create `<base_dir>/apps`, owner-only.
///
/// Called when a user is created, **before** any app exists. The ordering is
/// the point: a directory created on first install would spend the interval
/// between `mkdir` and `chmod` readable, and the first install is exactly when
/// something worth reading arrives. Creating it empty and locked means there is
/// no such interval.
///
/// This came from `UserRuntime::new` on 2026-08-21 (RFC-0080). It sat there
/// under a comment saying apps were "the runtime's business, and `data/` is the
/// store's" — which was right about `data/` and wrong about the other half: an
/// app directory is the app domain's, and the runtime was merely where user
/// creation happened to run.
///
/// The permissions are Unix-only. On Windows the directory inherits the
/// user-profile ACL, which is already owner-scoped.
pub fn apps_dir(base_dir: &Path) -> Result<()> {
    let apps_dir = base_dir.join("apps");
    kotton_common::fs::create_dir_all_owner_only(&apps_dir)
        .with_context(|| format!("Failed to create apps directory {apps_dir:?}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&apps_dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("Failed to set permissions on {apps_dir:?}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_directory_is_created_and_re_creating_is_not_an_error() {
        let temp = tempfile::tempdir().unwrap();
        apps_dir(temp.path()).unwrap();
        assert!(temp.path().join("apps").is_dir());
        // Idempotent: user creation can be retried after a partial failure.
        apps_dir(temp.path()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn the_directory_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let temp = tempfile::tempdir().unwrap();
        apps_dir(temp.path()).unwrap();
        let mode = std::fs::metadata(temp.path().join("apps"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
    }
}
