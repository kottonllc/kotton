// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bundled first-party WASM component apps.
//!
//! What a newly opened user database is given: the shell that draws the screen, the
//! editor the shell hands a file to, and the project's records. [`auto_install_bundled_apps`] installs these on every
//! user-database open, so an identity created through *any* door — the CLI, the window's
//! welcome flow, a future installer — has them, and one created before this existed gets
//! them the next time its database opens in this daemon's life: a boot, for an identity with
//! no lock policy, or an unlock, for one that was locked at boot
//! (`custody_window::rekey_resident_store`): an app bundled after an identity
//! was made reaches it.
//!
//! [`auto_install_bundled_apps`]: crate::agent
//!
//! # Why this list is not empty
//!
//! An identity is born with the apps it needs, whoever creates it, and this list is where
//! that happens. Sideloaded by one recipe instead — inside an `if !user_exists(…)` branch
//! that never runs again — an identity created anywhere else would get neither app and no
//! re-run would repair it: a file browser with no controls and `apps.launch failed … app
//! not found: sh.kotton.editor`, both correct reports of a half-provisioned machine.
//!
//! # Who may fill it
//!
//! Today: whoever compiles the binary. That is an unchangeable default installed by a
//! mechanism no third party can use, which is the shape platforms are litigated over and
//! the opposite of this project's refusal of lock-in. A boot configuration may replace
//! this list, under one invariant — it may **propose** an app and
//! a role, and may never **grant** a capability that was not consented to or vouched for.
//! This function is that seam: when the configuration path lands, it answers from a file,
//! and nothing above it changes.
//!
//! # Build order
//!
//! `include_bytes!` needs the components to exist when this crate compiles. `cargo xtask
//! build-apps` makes them and `just desktop::build` runs it first; a bare `cargo build`
//! does not. So `build.rs` looks for them and sets `bundled_apps_present`, and a build
//! without them warns and bundles nothing rather than failing — a checkout that is never
//! going to open a window should still compile the daemon.

/// A bundled first-party app ready for installation.
pub struct BundledApp {
    /// TOML manifest source (same format as `AppManifest::from_toml`).
    pub manifest_toml: &'static str,
    /// WASM binary bytes.
    pub wasm_bytes: &'static [u8],
}

/// What a new identity receives.
///
/// The shell needs no role assignment here: `user_db.rs` seeds `shell → sh.kotton.shell`
/// on the open path with `INSERT OR IGNORE`, so the default yields to a person's own
/// designation rather than overwriting it. The editor holds no role at all — the shell
/// launches it by nsid through `apps.launch`.
#[cfg(bundled_apps_present)]
pub fn bundled_apps() -> Vec<BundledApp> {
    vec![
        BundledApp {
            manifest_toml: include_str!("../../../guest/apps/kotton-shell/manifest.toml"),
            wasm_bytes: include_bytes!("../../../guest/apps/kotton-shell/app.wasm"),
        },
        BundledApp {
            manifest_toml: include_str!("../../../guest/apps/kotton-editor/manifest.toml"),
            wasm_bytes: include_bytes!("../../../guest/apps/kotton-editor/app.wasm"),
        },
        // The project's records. Its whole grant is
        // `schema.read` on one extension schema, so on an identity with no
        // project root it reads nothing and says so; the dock carries it as a
        // guest tile, and it is installed here rather than left for a person to
        // sideload because an identity is born with the apps it needs.
        BundledApp {
            manifest_toml: include_str!("../../../guest/apps/kotton-records/manifest.toml"),
            wasm_bytes: include_bytes!("../../../guest/apps/kotton-records/app.wasm"),
        },
    ]
}

/// The components were not built when this binary was. `build.rs` has already said so, and
/// named the command that makes them.
#[cfg(not(bundled_apps_present))]
pub fn bundled_apps() -> Vec<BundledApp> {
    vec![]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The apps a new identity receives are the three the desktop's dock launches, and
    /// their manifests parse.
    ///
    /// Guards the failure this list was empty for: a bundled entry whose manifest does not
    /// parse is skipped by `auto_install_bundled_apps` with one line on stderr, so a typo
    /// here would reproduce exactly the silent half-provisioned machine — a shell that
    /// never launches and a `WARN` nobody sees.
    #[cfg(bundled_apps_present)]
    #[test]
    fn a_new_identity_receives_the_shell_the_editor_and_the_records() {
        let apps = bundled_apps();
        let ids: Vec<String> = apps
            .iter()
            .map(|a| {
                kotton_schemas::AppManifest::from_toml(a.manifest_toml)
                    .expect("a bundled manifest must parse")
                    .app
                    .id
                    .as_str()
                    .to_owned()
            })
            .collect();
        assert_eq!(ids, vec!["sh.kotton.shell", "sh.kotton.editor", "sh.kotton.records"]);
        for app in &apps {
            assert!(
                app.wasm_bytes.starts_with(b"\0asm"),
                "a bundled app must be a wasm module"
            );
        }
    }

    /// Without the components the list is empty rather than wrong.
    ///
    /// `build.rs` has already warned and named `cargo xtask build-apps`; the daemon then
    /// behaves as it did before this list was filled. What must never happen is a build
    /// that embeds something else and calls it the shell.
    #[cfg(not(bundled_apps_present))]
    #[test]
    fn without_the_components_nothing_is_bundled() {
        assert!(bundled_apps().is_empty());
    }
}
