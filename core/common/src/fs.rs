// SPDX-License-Identifier: AGPL-3.0-or-later
//! Filesystem operations whose *failure mode* is the interesting part.
//!
//! Two functions, each here rather than beside its callers because it would
//! otherwise be written once per caller.
//!
//! [`remove_dir_all_retrying`]: `logout_user` removes one identity's
//! directory, `kotton device reset` removes the whole base directory, and both
//! meet the same wall on Windows — a file handle an in-flight task has not let
//! go of yet, which surfaces as a bare `Access is denied` naming the *directory*
//! and nothing inside it. The retry and the naming are the hard-won part. A
//! second copy of them would be a second thing to get right, and the one that
//! lags is the one that produces the undiagnosable failure.
//!
//! [`create_dir_all_owner_only`]: several components each made a node's base dir
//! and `system/` with `create_dir_all`, `0755` under the usual umask, and the
//! one that came first decided the mode. One maker is the fix.

use std::path::{Path, PathBuf};

/// A directory that would not go, and what was still holding it.
#[derive(Debug)]
pub struct HeldOpen {
    /// The last error `remove_dir_all` returned.
    pub source: std::io::Error,
    /// The files that refused to be deleted individually, by path.
    ///
    /// Empty means every file went and the *directory* itself is what refused —
    /// on Windows, usually a handle on the directory rather than on its
    /// contents.
    pub held: Vec<PathBuf>,
}

impl std::fmt::Display for HeldOpen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.source)?;
        if !self.held.is_empty() {
            write!(f, " (still held open: {:?})", self.held)?;
        }
        Ok(())
    }
}

impl std::error::Error for HeldOpen {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Remove `path` and everything under it, retrying briefly, and on failure
/// reporting **which files** refused rather than only that the directory did.
///
/// A no-op when `path` does not exist, so a caller need not check first.
///
/// ## Why it retries
///
/// A background task that took a handle just before the caller evicted its
/// cache releases it within milliseconds, and Windows holds the lock for
/// exactly that long. Twenty attempts at 50 ms is a second of patience for a
/// wait that is normally one tick — cheap, and the alternative is a delete that
/// fails for a reason that has already stopped being true.
///
/// ## Why it names the files
///
/// *"The directory is locked"* is undiagnosable without knowing which file, and
/// the diagnosis is destructive on purpose: the walk deletes every file it
/// **can**, so what it reports is the true remainder and the caller is left as
/// close to done as the machine allows. A probe that left the tree untouched
/// would be tidier and would make the next attempt no more likely to succeed.
pub fn remove_dir_all_retrying(path: &Path) -> Result<(), HeldOpen> {
    if !path.exists() {
        return Ok(());
    }

    let mut last_err = None;
    for _ in 0..20 {
        match std::fs::remove_dir_all(path) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last_err = Some(e);
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    }

    // Unwrap-free: the loop runs at least once, so `last_err` is `Some` on every
    // path that reaches here.
    let Some(source) = last_err else {
        return Ok(());
    };

    let mut held: Vec<PathBuf> = Vec::new();
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    stack.push(p);
                } else if std::fs::remove_file(&p).is_err() {
                    held.push(p);
                }
            }
        }
    }

    // The walk may have freed the last of it — a handle released while we were
    // reading the tree. Try once more before reporting a failure that has
    // stopped being true.
    if held.is_empty() && std::fs::remove_dir_all(path).is_ok() {
        return Ok(());
    }

    Err(HeldOpen { source, held })
}

/// `path` spelled so that a stat of it reads its **last component's own entry**:
/// its components rejoined, which drops a trailing separator (and any `.`
/// between components). `symlink_metadata("link/")` — and an `O_NOFOLLOW` open
/// of it — reports the symlink's *target*, because a trailing separator makes
/// the kernel resolve the last component; `std::path::absolute` keeps the slash
/// and `KOTTON_BASE_DIR` arrives as typed, so `link/` would pass a check that
/// refuses `link`. Every check of "is this entry a symlink" stats this instead
/// (the Fable reviewer's refusal of `80b8458da`, on
/// `TASK-kvaultd-create-chmods-any-existing-directory-it-is-pointed-at`).
pub fn own_entry(path: &Path) -> PathBuf {
    path.components().collect()
}

/// Make `path` owner-only (`0o700`), and every missing directory above it the
/// same way, **by the mode `mkdir(2)` is given** — which the process umask can
/// only narrow, so there is no moment at which it is wider and nothing to
/// re-check. Returns whether this call made `path` itself.
///
/// **It changes the mode of nothing that exists.** A directory already there —
/// `path` or any parent — is left exactly as it is, whatever its mode, and
/// `path`'s own entry is read without following a symlink: a symlink there,
/// dangling or not, is "already there" and `false` comes back. A caller that
/// must know what it is using checks it then; `kvaultd`'s state directory does
/// (`kvaultd::instance::own_state_dir`).
///
/// The one maker of a node's base dir, its `system/`, a user's `users/<id>`
/// and a daemon's state directory
/// (`TASK-the-base-dir-and-system-are-said-to-be-0700-and-nothing-makes-them-so`):
/// every writer that may make one of them — itself or as a missing parent of
/// what it writes — makes it here, so which comes first on a fresh node decides
/// nothing. That record's Implementation status lists every site, and the one
/// other `DirBuilder` that can reach the base dir, the socket bind's (also
/// `0700`). The leaf is made without
/// `recursive`, so a directory that appears between the read and the `mkdir`
/// is reported as found (`false`), never as made.
pub fn create_dir_all_owner_only(path: &Path) -> std::io::Result<bool> {
    let path = &own_entry(path);
    match std::fs::symlink_metadata(path) {
        Ok(_) => return Ok(false),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        create_dir_all_owner_only(parent)?;
    }
    #[cfg(unix)]
    let made = {
        use std::os::unix::fs::DirBuilderExt as _;
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder
    };
    #[cfg(not(unix))]
    let made = std::fs::DirBuilder::new();
    match made.create(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch path nobody else is using. Named per test **and** per process,
    /// because this crate has no dev-dependencies (it is the bottom of the tier
    /// order and `tier-check` keeps it there), so there is no `tempfile` here and
    /// a fixed name under the system temp dir is shared with every other run on
    /// the machine.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kotton-fs-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// A missing tree is made `0700` from the top, and an existing directory —
    /// `0755` here — is left as it is and reported as found, not made.
    #[cfg(unix)]
    #[test]
    fn an_owner_only_tree_is_made_and_an_existing_directory_keeps_its_mode() {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = |p: &Path| std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777;
        let root = scratch("owner-only");
        let leaf = root.join("a").join("b");
        assert!(create_dir_all_owner_only(&leaf).unwrap(), "the leaf was made");
        for d in [&root, &root.join("a"), &leaf] {
            assert_eq!(mode(d), 0o700, "{}", d.display());
        }
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(!create_dir_all_owner_only(&leaf).unwrap(), "an existing directory was reported made");
        assert_eq!(mode(&leaf), 0o755, "an existing directory's mode was changed");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `link/` is read as `link`: the helper stats the symlink's own entry, not
    /// its target, however the leaf is spelled, and so reports it as found and
    /// leaves the target's mode alone.
    #[cfg(unix)]
    #[test]
    fn a_slashed_symlink_is_read_as_its_own_entry() {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(own_entry(Path::new("/a/b/")), PathBuf::from("/a/b"));
        assert_eq!(own_entry(Path::new("a/./b//")), PathBuf::from("a/b"));
        let root = scratch("slashed");
        let real = root.join("real");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755)).unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let slashed = PathBuf::from(format!("{}/", link.display()));
        assert!(std::fs::symlink_metadata(&slashed).unwrap().is_dir(), "the kernel resolves `link/`");
        assert!(std::fs::symlink_metadata(own_entry(&slashed)).unwrap().file_type().is_symlink());
        assert!(!create_dir_all_owner_only(&slashed).unwrap(), "a symlink reported as made");
        assert_eq!(std::fs::metadata(&real).unwrap().permissions().mode() & 0o7777, 0o755);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_path_that_does_not_exist_is_already_removed() {
        let dir = scratch("absent");
        assert!(!dir.exists());
        assert!(remove_dir_all_retrying(&dir).is_ok());
    }

    #[test]
    fn a_populated_tree_goes_entirely() {
        let root = scratch("populated");
        std::fs::create_dir_all(root.join("a").join("b")).expect("create nested dirs");
        std::fs::write(root.join("top.txt"), b"x").expect("write top file");
        std::fs::write(root.join("a").join("b").join("deep.txt"), b"y").expect("write deep file");

        remove_dir_all_retrying(&root).expect("remove the tree");
        assert!(!root.exists(), "the tree is gone");
    }
}
