// SPDX-License-Identifier: AGPL-3.0-or-later
//! What an installed Kotton finds beside its own daemon.
//!
//! A checkout runs the daemon out of `target/<profile>/`, and `cargo xtask` puts
//! everything else where the daemon will look: the runner by `KOTTON_RUNNER`, the
//! shell by copying it into `<base>/system/shell/` before the daemon starts. An
//! installed Kotton has no xtask. What it has is one directory, laid out by
//! `cargo xtask pack`, so a friend can install Kotton without a toolchain:
//!
//! ```text
//! <prefix>/bin/kuserd            this process
//! <prefix>/bin/kotton-runner     found by `resolve_runner`, beside it
//! <prefix>/bin/kuid, ksyncd, …   found by `sidecar_bin`, beside it
//! <prefix>/share/kotton/shell/   staged here, by `stage_the_shell_that_shipped`
//! ```
//!
//! So the daemon locates what shipped with it relative to its own executable —
//! the rule its sidecars already followed — and nothing about the machine it was
//! built on survives into the one it runs on.
//!
//! **Why the daemon stages, rather than an install script.** Staging needs the
//! base directory, and the base directory is `kotton_common::paths::base_dir()`:
//! `KOTTON_BASE_DIR`, else a per-platform default. A script that re-derived it
//! would be a second copy of that rule with nothing holding the two together, and
//! a launcher that *set* `KOTTON_BASE_DIR` to be sure would change which keychain
//! names the install uses (`OsSecrets::for_base_dir` scopes them when the variable
//! is set), so the `kotton` a person then types, without the variable, would look
//! for keys under other names. The daemon is the one process that already holds
//! the answer.
//!
//! **Why every start, not first start.** The staged copy is the body every path
//! runs the shell from (`designated_shell_body`), so a copy staged once would be
//! the body from the first version a person installed, forever: the drawn ground
//! would show for a second and the relaunched desk would be flat.
//! A checkout has no `share/` beside `target/debug/`, so there this does nothing
//! and the xtask staging it already had stays the only one.

use std::io;
use std::path::{Path, PathBuf};

/// The files a shipped shell is made of, in the order they are copied.
///
/// The same two `xtask::stage_system_shell` copies out of a checkout.
const SHELL_FILES: [&str; 2] = ["app.wasm", "manifest.toml"];

/// Where an installed layout keeps the shell, given the directory the daemon
/// runs from: `<prefix>/share/kotton/shell` for a daemon at `<prefix>/bin/`.
pub fn shipped_shell_dir(exe_dir: &Path) -> Option<PathBuf> {
    exe_dir
        .parent()
        .map(|prefix| prefix.join("share").join("kotton").join("shell"))
}

/// Copy the shell that shipped beside this daemon into `<base>/system/shell/`.
///
/// Returns the directory it staged into, or `None` when there is no shipped shell
/// beside `exe_dir` — a checkout, or a headless install that carries none — and
/// nothing was touched. A shipped shell that is only half there (one of its two
/// files missing) is an error rather than `None`: that is a broken install, and
/// staging half of it would draw the previous version's manifest over this
/// version's code.
///
/// Each file is written beside its destination and renamed over it, so neither
/// file is ever half-written. The *pair* is not replaced atomically — between the
/// two renames the new `app.wasm` sits beside the old `manifest.toml` — and that
/// is safe only because of when this runs: `kuserd`'s `main` calls it before the
/// daemon is built, so no launch of this base's shell can be in flight. A caller
/// that staged while a daemon served this base would need the pair swapped as one
/// directory.
pub fn stage_the_shell_that_shipped(exe_dir: &Path, base: &Path) -> io::Result<Option<PathBuf>> {
    let Some(src) = shipped_shell_dir(exe_dir) else {
        return Ok(None);
    };
    let present: Vec<bool> = SHELL_FILES.iter().map(|f| src.join(f).is_file()).collect();
    if present.iter().all(|p| !p) {
        return Ok(None);
    }
    if !present.iter().all(|p| *p) {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "{} holds part of a shell ({} of {}): this install is incomplete",
                src.display(),
                present.iter().filter(|p| **p).count(),
                SHELL_FILES.len()
            ),
        ));
    }
    let dst = kotton_app::daemon::apps::system_shell_dir(base);
    kotton_common::fs::create_dir_all_owner_only(&dst)?;
    for name in SHELL_FILES {
        let partial = dst.join(format!(".{name}.staging"));
        std::fs::copy(src.join(name), &partial)?;
        std::fs::rename(&partial, dst.join(name))?;
    }
    Ok(Some(dst))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn installed(prefix: &Path, wasm: &[u8]) -> PathBuf {
        let bin = prefix.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let shell = prefix.join("share/kotton/shell");
        std::fs::create_dir_all(&shell).unwrap();
        std::fs::write(shell.join("app.wasm"), wasm).unwrap();
        std::fs::write(shell.join("manifest.toml"), b"[app]\n").unwrap();
        bin
    }

    /// The installed layout: the daemon at `bin/`, the shell at
    /// `share/kotton/shell/`, and the body reaches `<base>/system/shell/`.
    #[test]
    fn an_installed_daemon_stages_the_shell_it_shipped_with() {
        let prefix = tempfile::tempdir().unwrap();
        let base = tempfile::tempdir().unwrap();
        let bin = installed(prefix.path(), b"version two");

        let staged = stage_the_shell_that_shipped(&bin, base.path()).unwrap();
        let dir = staged.expect("an installed layout stages");
        assert_eq!(dir, kotton_app::daemon::apps::system_shell_dir(base.path()));
        assert_eq!(std::fs::read(dir.join("app.wasm")).unwrap(), b"version two");
        assert!(dir.join("manifest.toml").is_file());
        // Nothing half-written is left behind.
        let names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 2, "{names:?}");
    }

    /// Every start, so an upgrade reaches the desk: a body staged by an earlier
    /// version is replaced by the one beside the daemon now running.
    #[test]
    fn a_newer_install_replaces_what_an_older_one_staged() {
        let prefix = tempfile::tempdir().unwrap();
        let base = tempfile::tempdir().unwrap();
        let bin = installed(prefix.path(), b"version one");
        stage_the_shell_that_shipped(&bin, base.path()).unwrap();
        installed(prefix.path(), b"version two");

        let dir = stage_the_shell_that_shipped(&bin, base.path())
            .unwrap()
            .unwrap();
        assert_eq!(std::fs::read(dir.join("app.wasm")).unwrap(), b"version two");
    }

    /// A checkout: `target/debug/` has no `share/` beside it, and whatever xtask
    /// staged is left exactly as it was.
    #[test]
    fn a_checkout_stages_nothing_and_leaves_what_xtask_staged() {
        let checkout = tempfile::tempdir().unwrap();
        let bin = checkout.path().join("target/debug");
        std::fs::create_dir_all(&bin).unwrap();
        let base = tempfile::tempdir().unwrap();
        let dst = kotton_app::daemon::apps::system_shell_dir(base.path());
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(dst.join("app.wasm"), b"from xtask").unwrap();

        assert!(stage_the_shell_that_shipped(&bin, base.path())
            .unwrap()
            .is_none());
        assert_eq!(std::fs::read(dst.join("app.wasm")).unwrap(), b"from xtask");
    }

    /// Half a shell is a broken install and says so; it does not stage the half.
    #[test]
    fn half_a_shipped_shell_is_refused_and_nothing_is_staged() {
        let prefix = tempfile::tempdir().unwrap();
        let base = tempfile::tempdir().unwrap();
        let bin = installed(prefix.path(), b"x");
        std::fs::remove_file(prefix.path().join("share/kotton/shell/manifest.toml")).unwrap();

        let err = stage_the_shell_that_shipped(&bin, base.path()).unwrap_err();
        assert!(err.to_string().contains("incomplete"), "{err}");
        assert!(!kotton_app::daemon::apps::system_shell_dir(base.path()).exists());
    }
}
