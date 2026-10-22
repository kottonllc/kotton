// SPDX-License-Identifier: AGPL-3.0-or-later
//! Secrets provider for managing cryptographic keys
//!
//! This crate provides implementations of SecretsStore trait:
//! - OsSecrets: OS keychain (Windows Credential Manager, macOS Keychain, Linux Secret Service)
//! - MemorySecrets: In-memory storage for testing

pub mod file;
pub mod memory;
pub mod os;
pub mod sealed_custody;
pub mod secure_enclave_binding;
pub mod tpm_binding;
#[cfg(any(test, feature = "test-utils"))]
pub mod counting_binding;

pub use file::FileSecrets;
pub use os::OsSecrets;
pub use sealed_custody::SealedCustody;
pub use secure_enclave_binding::SecureEnclaveBinding;
pub use tpm_binding::TpmBinding;
#[cfg(any(test, feature = "test-utils"))]
pub use counting_binding::CountingBinding;

/// The device-binding backend for the platform this was built for.
///
/// One name so callers above tier 03 do not carry `cfg` for a decision that is
/// entirely a property of the machine. On a platform with neither backend this
/// resolves to the TPM type, whose non-Windows stub reports unavailable and
/// errors on use — which is the correct behaviour (no binding is possible) with
/// no third type to maintain.
#[cfg(target_os = "macos")]
pub type PlatformBinding = SecureEnclaveBinding;
#[cfg(not(target_os = "macos"))]
pub type PlatformBinding = TpmBinding;

pub use memory::MemorySecrets;

/// The secrets store for a Kotton runtime rooted at `base_dir`.
///
/// A real install gets the OS keychain. A **throwaway root** — a base directory
/// under the system temp dir — gets an in-process store that persists nothing.
///
/// ## Why this rule exists
///
/// `OsSecrets` namespaces by base dir, so a runtime rooted at a temp directory
/// writes entries under a service name unique to that directory. The entries are
/// scoped correctly and are also **permanent**: the temp directory is deleted,
/// the credentials are not. Every spawned test daemon left a handful behind for
/// good, and on 2026-08-17 the Windows credential store reached its ceiling and
/// began refusing writes — which surfaces as a daemon that will not start, with
/// `Windows error code 8`, nowhere near the code that caused it. 250 stale
/// entries were cleared by hand.
///
/// The rule is deliberately **structural rather than a flag**. An env var or a
/// test-harness opt-in is something the next test to spawn a daemon can forget,
/// and this failure is invisible until the store is full — the worst possible
/// combination of "easy to miss" and "hard to diagnose". A root under the system
/// temp dir is not a real install, and treating it as one is what caused this.
///
/// The cost is honest and small: a throwaway-rooted daemon loses its secrets if
/// the *process* restarts. Its data directory is equally throwaway, so there is
/// nothing for those secrets to have unlocked.
///
/// An error when the chosen store is there and cannot be read (a `file`
/// store's `secrets.json` that does not parse): never an empty store, which a
/// caller would mint a new key into ([`FileSecrets::at`]).
pub fn secrets_for_base_dir(
    base_dir: &std::path::Path,
) -> kotton_sys::secret::SecretsResult<std::sync::Arc<dyn kotton_sys::secret::SecretsStore + Send + Sync>> {
    SecretsProvider::for_base_dir(base_dir).open(base_dir)
}

/// Which store [`secrets_for_base_dir`] gives a runtime rooted at a base
/// directory — decided once, by [`Self::for_base_dir`], so a caller that must
/// know (a service's `create`, which keeps a key the start must find) asks the
/// same rule the store is opened by and records the answer rather than
/// deriving it again later from a path's spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretsProvider {
    /// An in-process store: a throwaway root. Nothing outlives the process.
    Memory,
    /// `KOTTON_SECRETS=file`: a `0600` file under the base directory's `system/`.
    File,
    /// The OS keychain, scoped to the base directory.
    Keychain,
}

impl SecretsProvider {
    /// The provider for `base_dir`: the rule [`secrets_for_base_dir`] states.
    pub fn for_base_dir(base_dir: &std::path::Path) -> Self {
        if is_throwaway_root(base_dir) {
            Self::Memory
        } else if std::env::var("KOTTON_SECRETS").as_deref() == Ok("file") {
            Self::File
        } else {
            Self::Keychain
        }
    }

    /// Whether what this provider keeps outlives the process.
    pub fn outlives_the_process(self) -> bool {
        self != Self::Memory
    }

    /// Its name, as a record of it is written and read.
    pub fn name(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::File => "file",
            Self::Keychain => "keychain",
        }
    }

    /// The store, for `base_dir`. An error when the store is there and cannot
    /// be read — a `file` store's `secrets.json` that does not parse — rather
    /// than an empty store a caller would mint a key into (see `FileSecrets::at`).
    pub fn open(
        self,
        base_dir: &std::path::Path,
    ) -> kotton_sys::secret::SecretsResult<std::sync::Arc<dyn kotton_sys::secret::SecretsStore + Send + Sync>> {
        Ok(match self {
            Self::Memory => {
                tracing::info!(
                    base_dir = %base_dir.display(),
                    "secrets: throwaway root — using an in-process store, nothing reaches the OS keychain"
                );
                std::sync::Arc::new(MemorySecrets::new())
            }
            // A machine with no keychain — a rented vault, a gateway host, a node in a
            // container — says so explicitly. Never a fallback: see `file.rs`.
            Self::File => {
                tracing::info!(
                    base_dir = %base_dir.display(),
                    "secrets: KOTTON_SECRETS=file — a 0600 file under system/, chosen for a machine with no keychain"
                );
                std::sync::Arc::new(FileSecrets::for_base_dir(base_dir)?)
            }
            Self::Keychain => std::sync::Arc::new(OsSecrets::for_base_dir(base_dir)),
        })
    }
}

/// Whether `base_dir` sits under the system temp directory.
///
/// Normalized on both sides before comparing, because the same directory
/// arrives in several spellings and a mismatch here fails **open** — it silently
/// restores the keychain writes this exists to prevent, with no error anywhere.
/// The spellings that actually bite:
///
/// - `canonicalize` adds Windows' `\\?\` verbatim prefix; `temp_dir()` has no
///   such prefix, so a canonical path never `starts_with` a plain one.
/// - `canonicalize` fails outright on a path that does not exist yet, dropping
///   silently back to the raw form for one side only.
/// - Windows paths are case-insensitive, and 8.3 short names (`RUNNER~1`) may
///   survive on one side.
///
/// Each of those turns the check into a no-op rather than an error, which is why
/// this is defensive out of proportion to its size.
fn is_throwaway_root(base_dir: &std::path::Path) -> bool {
    fn normalize(p: &std::path::Path) -> String {
        let resolved = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        let s = resolved.to_string_lossy().replace(r"\\?\", "");
        let s = s.trim_end_matches(['\\', '/']).to_string();
        if cfg!(windows) {
            s.to_lowercase()
        } else {
            s
        }
    }

    let base = normalize(base_dir);
    let temp = normalize(&std::env::temp_dir());
    // Path-separator boundary, so `/tmpfoo` is not read as being under `/tmp`.
    base == temp
        || base.starts_with(&format!("{temp}{}", std::path::MAIN_SEPARATOR))
        || base.starts_with(&format!("{temp}/"))
}

#[cfg(test)]
mod secrets_selection_tests {
    use super::*;

    /// A temp-rooted runtime must not reach the OS keychain. Pinned because the
    /// failure it prevents is invisible until a machine-wide store fills up.
    #[test]
    fn a_temp_root_gets_an_in_process_store() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            is_throwaway_root(dir.path()),
            "a tempfile::tempdir() root must be recognised as throwaway"
        );
    }

    /// And a real install still gets the keychain — the rule must not be so
    /// broad that it disables the OS store generally.
    #[test]
    fn an_ordinary_root_is_not_throwaway() {
        let cwd = std::env::current_dir().unwrap();
        assert!(
            !is_throwaway_root(&cwd),
            "the working directory is a real root, not a throwaway one"
        );
    }

    /// A path that does not exist yet must still be recognised. `canonicalize`
    /// fails on a missing path, and the fallback used to leave the two sides in
    /// different spellings — which fails *open*, quietly restoring keychain
    /// writes. A base dir the daemon has not created yet is the ordinary case.
    #[test]
    fn a_not_yet_created_temp_root_is_still_throwaway() {
        let missing = std::env::temp_dir().join("kotton-does-not-exist-yet-12345");
        assert!(
            !missing.exists(),
            "precondition: the probe path must not exist"
        );
        assert!(
            is_throwaway_root(&missing),
            "a temp path must be recognised before it is created, not only after"
        );
    }

    /// The boundary is a path separator, so a sibling whose name merely starts
    /// with the temp dir's is not swept in.
    #[test]
    fn a_sibling_sharing_the_prefix_is_not_throwaway() {
        let temp = std::env::temp_dir();
        let sibling = std::path::PathBuf::from(format!(
            "{}-not-actually-temp",
            temp.to_string_lossy().trim_end_matches(['\\', '/'])
        ));
        assert!(
            !is_throwaway_root(&sibling),
            "prefix matching must respect the separator boundary"
        );
    }
}
