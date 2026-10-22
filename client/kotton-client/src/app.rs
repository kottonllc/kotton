// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `app` domain — installing, launching and addressing WASM guests.
//!
//! Reached through [`KottonClient::app`], which binds the user once:
//!
//! ```no_run
//! # async fn example(client: &mut kotton::KottonClient) -> std::io::Result<()> {
//! let mut app = client.app("did:key:…");
//! for installed in app.list().await? {
//!     let _ = installed;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! The domain name is RFC-0054's;
//! grouping the verbs under it is RFC-0055.

use std::io;

use kotton_schemas::CapabilityGrant;

use super::{InstalledApp, KottonClient, UserRequest, UserResponse};

/// What an installed app asked for, and what it holds.
///
/// `approved` is `None` when no approval was ever recorded — an install from
/// before the consent gate — which is not the same as an empty list, where the
/// user was asked and declined everything.
#[derive(Debug, Clone)]
pub struct AppGrants {
    pub app_id: String,
    pub name: String,
    pub requested: Vec<CapabilityGrant>,
    pub requested_display: Vec<String>,
    pub approved: Option<Vec<CapabilityGrant>>,
    pub approved_display: Vec<String>,
    pub envelopes: Vec<kotton_wire::ipc::AppGrantEnvelope>,
}

/// What an app package is asking for, before anything is installed.
///
/// The client-side shape of [`UserResponse::AppInstallPreview`]. `requested` and
/// `requested_display` are the same grants in the same order — the structured
/// values to echo back as `approved`, and the strings to show a human — so a
/// consent prompt cannot display one thing and approve another.
#[derive(Debug, Clone)]
pub struct AppInstallPreview {
    pub app_id: String,
    pub name: String,
    pub version: String,
    /// BLAKE3 of the WASM bytes, hex.
    pub wasm_hash: String,
    pub requested: Vec<CapabilityGrant>,
    pub requested_display: Vec<String>,
    /// The VFS resources the app declared, each bindable to a path the user
    /// chooses. Pass the ones they changed to `app_install`'s `bindings`.
    pub shapes: Vec<kotton_schemas::CapabilityShape>,
    /// Whether the publisher DID signature verified. `false` means unsigned or
    /// self-published — say so in the prompt.
    pub publisher_verified: bool,
}
use crate::extensions::InstallOutcome;
use kotton_wire::ipc::InstalledExtension;

/// The result of launching a WASM app.
///
/// Contains element tree patches committed by the app's `surface::commit` calls
/// during `on_launch`.
#[derive(Debug, Clone)]
pub struct AppLaunchOutput {
    /// Element tree patches committed via `surface::commit` during `on_launch`.
    /// Format version 0x00 = raw JSON message (transitional). May be empty.
    pub patches: Vec<Vec<u8>>,
}

/// The `app` domain, bound to one user.
///
/// Borrows the client, so it costs nothing to construct and cannot outlive the
/// connection it speaks over.
pub struct App<'a> {
    client: &'a mut KottonClient,
    user_id: String,
}

impl KottonClient {
    /// Enter the `app` domain for a user.
    ///
    /// Only [`App::install`] names the user on the wire; the rest carry no
    /// `user_id` and the daemon takes the user from the authenticated session
    /// (`agent/dispatch.rs`). The bound user still governs — it is simply not
    /// restated per request. See the note in [`crate::Record`]: the asymmetry is
    /// the protocol's, and the protocol split is where it is resolved.
    pub fn app(&mut self, user_id: &str) -> App<'_> {
        App {
            client: self,
            user_id: user_id.to_string(),
        }
    }
}

impl App<'_> {
    /// Every installed app. See [`KottonClient::app_list`].
    pub async fn list(&mut self) -> io::Result<Vec<InstalledApp>> {
        self.client.app_list().await
    }

    /// Launch an app. See [`KottonClient::app_launch`].
    pub async fn launch(
        &mut self,
        app_id: &str,
        launch_args: Vec<(String, String)>,
    ) -> io::Result<AppLaunchOutput> {
        self.client.app_launch(app_id, launch_args).await
    }

    /// Send a message to a running app. See [`KottonClient::app_message`].
    pub async fn message(&mut self, app_id: &str, msg: String) -> io::Result<Vec<Vec<u8>>> {
        self.client.app_message(app_id, msg).await
    }

    /// Install an app from a manifest and its WASM. See [`KottonClient::app_install`].
    pub async fn install(
        &mut self,
        manifest_toml: String,
        wasm_bytes: Vec<u8>,
        approved: Vec<CapabilityGrant>,
        bindings: Vec<(String, String)>,
    ) -> io::Result<(String, String, Vec<String>)> {
        let u = self.user_id.clone();
        self.client
            .app_install(&u, manifest_toml, wasm_bytes, approved, bindings)
            .await
    }

    /// Ask what an app wants, before installing it. See
    /// [`KottonClient::app_install_preview`].
    pub async fn install_preview(
        &mut self,
        manifest_toml: String,
        wasm_bytes: Vec<u8>,
    ) -> io::Result<AppInstallPreview> {
        let u = self.user_id.clone();
        self.client
            .app_install_preview(&u, manifest_toml, wasm_bytes)
            .await
    }

    /// Remove an installed app. See [`KottonClient::app_uninstall`].
    pub async fn uninstall(&mut self, app_id: &str) -> io::Result<()> {
        self.client.app_uninstall(app_id).await
    }

    /// Verify an app's signature and bundle. See [`KottonClient::app_verify`].
    pub async fn verify(&mut self, app_id: &str) -> io::Result<(String, String, bool)> {
        self.client.app_verify(app_id).await
    }

    /// Register a bundle on disk. See [`KottonClient::app_register_bundle`].
    #[allow(clippy::too_many_arguments)]
    pub async fn register_bundle(
        &mut self,
        app_id: &str,
        name: &str,
        version: &str,
        capabilities_json: &str,
        bundle_path: &str,
        dev: bool,
    ) -> io::Result<()> {
        self.client
            .app_register_bundle(app_id, name, version, capabilities_json, bundle_path, dev)
            .await
    }

    /// Where an app's bundle lives. See [`KottonClient::app_get_bundle_path`].
    pub async fn bundle_path(&mut self, app_id: &str) -> io::Result<Option<String>> {
        self.client.app_get_bundle_path(app_id).await
    }

    /// Which app fills a role. See [`KottonClient::app_get_role`].
    pub async fn get_role(&mut self, role: &str) -> io::Result<Option<String>> {
        self.client.app_get_role(role).await
    }

    /// Assign an app to a role. See [`KottonClient::app_set_role`].
    pub async fn set_role(&mut self, role: &str, app_id: &str) -> io::Result<()> {
        self.client.app_set_role(role, app_id).await
    }

    // -- Extensions -----------------------------------------------------------
    //
    // An extension is an app that extends the shell rather than opening a
    // window. Same confinement, same grants, same install path -- so it is this
    // domain rather than one of its own, which is what RFC-0054 means by naming
    // capabilities rather than form factors.

    /// Install an extension. See [`KottonClient::extension_install`].
    pub async fn install_extension(
        &mut self,
        manifest_toml: String,
        wasm_bytes: Vec<u8>,
    ) -> io::Result<InstallOutcome> {
        let u = self.user_id.clone();
        self.client.extension_install(&u, manifest_toml, wasm_bytes).await
    }

    /// Every installed extension. See [`KottonClient::extension_list`].
    pub async fn extensions(&mut self) -> io::Result<Vec<InstalledExtension>> {
        let u = self.user_id.clone();
        self.client.extension_list(&u).await
    }

    /// Remove an extension. See [`KottonClient::extension_remove`].
    pub async fn remove_extension(&mut self, extension_id: &str) -> io::Result<String> {
        let u = self.user_id.clone();
        self.client.extension_remove(&u, extension_id).await
    }
}

impl KottonClient {
    // -- App management ------------------------------------------------------

    /// List all installed WASM apps on this device.
    pub async fn app_list(&mut self) -> io::Result<Vec<InstalledApp>> {
        match self.client.send(&UserRequest::AppList).await? {
            UserResponse::AppList { apps } => Ok(apps),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Launch an installed WASM app with optional key/value arguments.
    ///
    /// `launch_args` is forwarded directly to the app's `on-launch` export.
    /// Conventional keys: `"record_url"` (deep link), `"path"` (VFS file).
    /// Pass an empty vec for a default launch.
    ///
    /// Returns the surface patches the app committed during `on-launch`, as
    /// `UserResponse::AppLaunched` carries them.
    pub async fn app_launch(
        &mut self,
        app_id: &str,
        launch_args: Vec<(String, String)>,
    ) -> io::Result<AppLaunchOutput> {
        let request = UserRequest::AppLaunch {
            app_id: app_id.to_string(),
            launch_args,
        };
        match self.client.send(&request).await? {
            UserResponse::AppLaunched { patches, .. } => Ok(AppLaunchOutput { patches }),
            UserResponse::AppNotFound { app_id } => {
                Err(io::Error::other(format!("app not found: {app_id}")))
            }
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Deliver a message to an app's `on-message` export.
    ///
    /// Returns surface patches committed by the app during the handler.
    pub async fn app_message(&mut self, app_id: &str, msg: String) -> io::Result<Vec<Vec<u8>>> {
        let request = UserRequest::AppMessage {
            app_id: app_id.to_string(),
            msg,
        };
        match self.client.send(&request).await? {
            UserResponse::AppMessageDelivered { patches } => Ok(patches),
            UserResponse::AppNotFound { app_id } => {
                Err(io::Error::other(format!("app not found: {app_id}")))
            }
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Install a WASM app from a TOML manifest and compiled WASM bytes.
    ///
    /// `user_id` identifies the user on whose behalf the app is installed.
    /// The daemon signs a `GrantEnvelope` over `approved` — the set a human was
    /// shown and agreed to — and refuses any grant the manifest did not request.
    ///
    /// Get the set to show them from [`KottonClient::app_install_preview`]; pass
    /// an empty vec to install with no capabilities at all.
    ///
    /// Returns `(app_id, name, capabilities)` from the daemon's parsed manifest.
    pub async fn app_install(
        &mut self,
        user_id: &str,
        manifest_toml: String,
        wasm_bytes: Vec<u8>,
        approved: Vec<CapabilityGrant>,
        bindings: Vec<(String, String)>,
    ) -> io::Result<(String, String, Vec<String>)> {
        let request = UserRequest::AppInstall {
            user_id: user_id.to_string(),
            manifest_toml,
            wasm_bytes,
            approved,
            bindings,
        };
        match self.client.send(&request).await? {
            UserResponse::AppInstalled {
                app_id,
                name,
                capabilities,
            } => Ok((app_id, name, capabilities)),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            // This site is where the cost was first measured: a bare "unexpected
            // response" cost three debug cycles here when the answer was
            // `NoActiveSession`. It was fixed here alone, and the other 118 arms
            // charged the next person the same thing — which is why the naming now
            // lives in `protocol::unexpected` and every arm reads it.
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Ask what an app package wants, without installing it or minting anything.
    ///
    /// The first half of the consent ceremony: show what comes back to a human,
    /// then pass the subset they approved to [`KottonClient::app_install`].
    ///
    /// Returns the parsed identity plus `(grants, display strings)` in matching
    /// order, and whether the publisher signature verified.
    pub async fn app_install_preview(
        &mut self,
        user_id: &str,
        manifest_toml: String,
        wasm_bytes: Vec<u8>,
    ) -> io::Result<AppInstallPreview> {
        let request = UserRequest::AppInstallPreview {
            user_id: user_id.to_string(),
            manifest_toml,
            wasm_bytes,
        };
        match self.client.send(&request).await? {
            UserResponse::AppInstallPreview {
                app_id,
                name,
                version,
                wasm_hash,
                requested,
                requested_display,
                shapes,
                publisher_verified,
            } => Ok(AppInstallPreview {
                app_id,
                name,
                version,
                wasm_hash,
                requested,
                requested_display,
                shapes,
                publisher_verified,
            }),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// What an installed app asked for, and what it holds.
    ///
    /// Read-only. Use it to show a user which of their data an app can reach —
    /// and, in tests, to assert what the consent ceremony actually recorded.
    pub async fn app_grants(&mut self, app_id: &str) -> io::Result<AppGrants> {
        let request = UserRequest::AppGrants {
            app_id: app_id.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::AppGrants {
                app_id,
                name,
                requested,
                requested_display,
                approved,
                approved_display,
                envelopes,
            } => Ok(AppGrants {
                app_id,
                name,
                requested,
                requested_display,
                approved,
                approved_display,
                envelopes,
            }),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Uninstall an app by ID, removing its WASM file and all handler registrations.
    pub async fn app_uninstall(&mut self, app_id: &str) -> io::Result<()> {
        let request = UserRequest::AppUninstall {
            app_id: app_id.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::AppUninstalled => Ok(()),
            UserResponse::AppNotFound { app_id } => {
                Err(io::Error::other(format!("app not found: {app_id}")))
            }
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Re-hash the installed WASM binary and compare against the stored hash.
    ///
    /// Returns `(stored_hash, computed_hash, matches)`.
    pub async fn app_verify(
        &mut self,
        app_id: &str,
    ) -> io::Result<(String, String, bool)> {
        let request = UserRequest::AppVerify {
            app_id: app_id.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::AppVerifyResult {
                stored_hash,
                computed_hash,
                matches,
                ..
            } => Ok((stored_hash, computed_hash, matches)),
            UserResponse::AppNotFound { app_id } => {
                Err(io::Error::other(format!("app not found: {app_id}")))
            }
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Register a pre-built web bundle as an installed app.
    ///
    /// `bundle_path` must be an absolute path to a `dist/` directory that exists
    /// on disk. The daemon stores the path — it does not copy any files.
    ///
    /// `dev` should be `true` when registering a live build-output directory
    /// for active development (shows a `(dev)` badge in `app list`).
    pub async fn app_register_bundle(
        &mut self,
        app_id: &str,
        name: &str,
        version: &str,
        capabilities_json: &str,
        bundle_path: &str,
        dev: bool,
    ) -> io::Result<()> {
        let request = UserRequest::AppRegisterBundle {
            app_id: app_id.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            capabilities_json: capabilities_json.to_string(),
            bundle_path: bundle_path.to_string(),
            dev,
        };
        match self.client.send(&request).await? {
            UserResponse::AppBundleRegistered { .. } => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Return the bundle path for an installed app.
    ///
    /// Returns `None` if the app has no web bundle (WASM-only), or if the
    /// app is not installed at all.
    pub async fn app_get_bundle_path(&mut self, app_id: &str) -> io::Result<Option<String>> {
        let request = UserRequest::AppGetBundlePath {
            app_id: app_id.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::AppBundlePath { bundle_path, .. } => Ok(bundle_path),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Return the app ID registered for a named system role (e.g. `"shell"`).
    ///
    /// Returns `None` if no app has been assigned to the role.
    pub async fn app_get_role(&mut self, role: &str) -> io::Result<Option<String>> {
        let request = UserRequest::AppGetRole {
            role: role.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::AppRole { app_id, .. } => Ok(Some(app_id)),
            UserResponse::AppNotFound { .. } => Ok(None),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Assign an app to a named system role.
    ///
    /// Fails if the app does not have the required capabilities for the role.
    pub async fn app_set_role(&mut self, role: &str, app_id: &str) -> io::Result<()> {
        let request = UserRequest::AppSetRole {
            role: role.to_string(),
            app_id: app_id.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::AppRoleSet { .. } => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }
}
