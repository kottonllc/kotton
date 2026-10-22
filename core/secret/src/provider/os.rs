// SPDX-License-Identifier: AGPL-3.0-or-later
//! OS keychain secrets provider
//!
//! Platform-specific implementations:
//! - Windows: Windows Credential Manager
//! - macOS: Keychain
//! - Linux: Secret Service API
//!
//! ## Scoping (why the service name varies)
//!
//! Keychain entry *names* (`kotton:master_secret:<user>`, …) carry no base
//! directory, and one of them (`kotton:device_operational_key`) carries no
//! discriminator at all — so before scoping, a dev daemon run with
//! `KOTTON_BASE_DIR=.kotton.dev` read and wrote the **production** entries:
//! same users collided, and the dev device announced to relays under the
//! production device's operational identity.
//!
//! The scope lives in the keyring **service**: the default install keeps the
//! legacy service `"Kotton"` — no migration, existing entries keep working —
//! and any non-default base dir gets `"Kotton@<absolute path>"`, so isolated
//! installs (dev, CI, sideloads) have isolated secrets, visibly labeled in the
//! platform's credential UI. The keychain remains defense-in-depth, never the
//! trust boundary; scoping prevents accidents, not attacks.

use keyring::Entry;
use kotton_sys::secret::{SecretsError, SecretsResult, SecretsStore};
use std::path::Path;

/// The legacy service name, and the one the default install stays on.
const DEFAULT_SERVICE: &str = "Kotton";

/// Production implementation using the OS keyring.
pub struct OsSecrets {
    /// Keyring service the entries live under. `"Kotton"` for the default
    /// install; `"Kotton@<base dir>"` for an isolated one.
    service: String,
}

impl OsSecrets {
    /// The store for `base_dir`'s install: the legacy unscoped service when it
    /// is the platform default, a per-directory scope otherwise.
    pub fn for_base_dir(base_dir: &Path) -> Self {
        Self {
            service: service_for_base_dir(base_dir),
        }
    }

    /// The legacy unscoped store. Prefer [`for_base_dir`](Self::for_base_dir)
    /// wherever the base directory is known.
    pub fn unscoped() -> Self {
        Self {
            service: DEFAULT_SERVICE.to_string(),
        }
    }
}

impl Default for OsSecrets {
    fn default() -> Self {
        Self::unscoped()
    }
}

/// The keyring service for an install rooted at `base_dir`.
///
/// Pure so it is testable without touching a real keychain. Paths are
/// absolutized (a relative `KOTTON_BASE_DIR=.kotton.dev` names a different
/// directory from each working directory, and its secrets should follow the
/// directory, not the string); comparison with the platform default is on the
/// absolutized forms.
fn service_for_base_dir(base_dir: &Path) -> String {
    let absolute = |p: &Path| {
        std::fs::canonicalize(p)
            .or_else(|_| std::env::current_dir().map(|cwd| cwd.join(p)))
            .unwrap_or_else(|_| p.to_path_buf())
    };

    let base = absolute(base_dir);
    let is_default = kotton_common::default_base_dir()
        .map(|d| absolute(&d) == base)
        .unwrap_or(false);

    if is_default {
        DEFAULT_SERVICE.to_string()
    } else {
        format!("{DEFAULT_SERVICE}@{}", base.display())
    }
}

impl SecretsStore for OsSecrets {
    fn get_secret(&self, key: &str) -> SecretsResult<Option<String>> {
        let entry =
            Entry::new(&self.service, key).map_err(|e| SecretsError::Storage(e.to_string()))?;
        match entry.get_password() {
            Ok(p) => Ok(Some(p)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(convert_error(e)),
        }
    }

    fn set_secret(&self, key: &str, value: &str) -> SecretsResult<()> {
        let entry =
            Entry::new(&self.service, key).map_err(|e| SecretsError::Storage(e.to_string()))?;
        entry.set_password(value).map_err(convert_error)
    }

    fn delete_secret(&self, key: &str) -> SecretsResult<()> {
        let entry =
            Entry::new(&self.service, key).map_err(|e| SecretsError::Storage(e.to_string()))?;
        entry.delete_password().map_err(convert_error)
    }
}

/// Convert a `keyring::Error` from an actual store operation (as opposed to
/// `Entry::new`, which never touches the kernel).
///
/// On Linux, `add_key`/`keyctl` refusing this process (`EPERM`) is its own
/// [`SecretsError::KeyringRefused`] rather than a generic [`SecretsError::Storage`] —
/// downcasting the boxed platform-failure source to `linux_keyutils::KeyError`
/// is what tells "the keyring said no" apart from every other platform
/// failure `keyring::Error::PlatformFailure` also carries.
fn convert_error(err: keyring::Error) -> SecretsError {
    #[cfg(target_os = "linux")]
    if let keyring::Error::PlatformFailure(ref source) = err {
        if let Some(linux_keyutils::KeyError::PermissionDenied) =
            source.downcast_ref::<linux_keyutils::KeyError>()
        {
            return SecretsError::KeyringRefused;
        }
    }
    SecretsError::Storage(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default install keeps the legacy service — no migration, ever:
    /// renaming it would orphan every existing user's secrets.
    #[test]
    fn the_default_base_dir_keeps_the_legacy_service() {
        if let Ok(default) = kotton_common::default_base_dir() {
            assert_eq!(service_for_base_dir(&default), DEFAULT_SERVICE);
        }
    }

    /// An isolated install gets an isolated, visibly-labeled service.
    #[test]
    fn a_dev_base_dir_gets_its_own_service() {
        let temp = std::env::temp_dir().join("kotton-secret-scope-test");
        let service = service_for_base_dir(&temp);
        assert_ne!(service, DEFAULT_SERVICE);
        assert!(
            service.starts_with("Kotton@"),
            "the scope is visible in the credential UI: {service}"
        );
    }

    /// Two different isolated installs never share a service — the collision
    /// this scoping exists to prevent.
    #[test]
    fn two_isolated_installs_do_not_share_a_service() {
        let a = std::env::temp_dir().join("kotton-a");
        let b = std::env::temp_dir().join("kotton-b");
        assert_ne!(service_for_base_dir(&a), service_for_base_dir(&b));
    }

    /// `convert_error` is the one place that turns a `keyring::Error` into
    /// [`SecretsError::KeyringRefused`], and it must do it for exactly the
    /// cause `add_key`/`keyctl` being refused takes — never the generic
    /// case, so the friendly message never claims a cause that was not the
    /// real one.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_permission_denied_platform_failure_becomes_keyring_refused() {
        let err =
            keyring::Error::PlatformFailure(Box::new(linux_keyutils::KeyError::PermissionDenied));
        assert!(matches!(convert_error(err), SecretsError::KeyringRefused));
    }

    /// A different `linux_keyutils::KeyError` inside the same `PlatformFailure`
    /// variant is a real platform failure that is not a refused keyring — it
    /// must not be folded into the message meant for one specific cause.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_different_platform_failure_stays_generic() {
        let err =
            keyring::Error::PlatformFailure(Box::new(linux_keyutils::KeyError::QuotaExceeded));
        assert!(matches!(convert_error(err), SecretsError::Storage(_)));
    }

    /// A `keyring::Error` that never touches a platform-failure source at all
    /// is untouched by the downcast and stays generic too.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_non_platform_failure_error_stays_generic() {
        let err = keyring::Error::NoStorageAccess(Box::new(std::io::Error::other("locked")));
        assert!(matches!(convert_error(err), SecretsError::Storage(_)));
    }
}
