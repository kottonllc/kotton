// SPDX-License-Identifier: AGPL-3.0-or-later
//! Platform secrets storage abstraction
//!
//! Defines the SecretsStore trait for secure credential storage.
//! Implementations are provided in the `kotton_secret` crate.
//!
//! # Architecture
//!
//! - `SecretsStore` trait: Platform-agnostic secret storage interface
//! - `prefix_key`: Adds "Kotton:" namespace prefix to keys
//!
//! # Implementations
//!
//! See `kotton_secret` for concrete providers:
//! - `OsSecrets`: OS keychain (Windows Credential Manager, macOS Keychain, Linux Secret Service)
//! - `MemorySecrets`: In-memory storage for testing

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SecretsError {
    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Secret not found: {0}")]
    NotFound(String),

    /// On Linux, the kernel keyring refused this process — `add_key` or
    /// `keyctl` returned `EPERM`, which in practice means a seccomp profile
    /// (Docker's default among them) denies those syscalls to this process.
    ///
    /// Its own variant, rather than folding into [`Self::Storage`]'s opaque
    /// string, exists so a caller that wants to tell a person something they
    /// can act on does not have to parse one back out
    /// (`TASK-the-daemon-dies-opaquely-where-the-kernel-keyring-is-refused`).
    /// Carries no key material and no path — naming the keyring and the
    /// remedy is the whole content.
    #[error(
        "the kernel keyring refused this process (add_key/keyctl denied) — \
         run without seccomp confinement, or allow add_key and keyctl in the \
         sandbox's seccomp profile, then start again"
    )]
    KeyringRefused,
}

pub type SecretsResult<T> = Result<T, SecretsError>;

/// Trait for storing and retrieving secrets
///
/// Abstracts OS-specific secure storage mechanisms. See `kotton_secret`
/// for concrete implementations.
pub trait SecretsStore: Send + Sync {
    fn get_secret(&self, key: &str) -> SecretsResult<Option<String>>;
    fn set_secret(&self, key: &str, value: &str) -> SecretsResult<()>;
    fn delete_secret(&self, key: &str) -> SecretsResult<()>;
}

/// Add the "Kotton:" namespace prefix to a key
///
/// Services build their own key structure, this just ensures the Kotton namespace.
pub fn prefix_key(key: &str) -> String {
    format!("Kotton:{}", key)
}

// ── Attempt limiting (RFC-0053) ───────────────────────────────────────────────

/// Whether this platform can count failed unlock attempts **where an attacker
/// cannot reach the counter**.
///
/// This is the single fact RFC-0053's credential-strength rule turns on, and it
/// is deliberately not the question "does this OS have a TPM". A counter in a
/// file is reset by anyone holding the disk, and an attacker who copies the
/// sealed vault and guesses offline never encounters *any* counter of ours.
/// Only a limiter inside a TPM or a secure enclave converts a short PIN into
/// something defensible — which is why a six-digit phone PIN is strong and a
/// six-digit desktop PIN is not, on hardware that is otherwise comparable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptLimiting {
    /// Nothing outside Kotton's own software bounds the guess rate. The daily
    /// credential must carry real entropy on its own.
    None,
    /// A TPM or secure enclave counts failures and throttles or wipes.
    Hardware,
}

/// What limits guessing on this device, for a vault with **no** hardware
/// binding — the answer at first run, before anything is bound.
///
/// The credential-strength rule follows the rate limiter rather than the
/// platform name, and the limiter is a property of a *binding*, not of a
/// machine: a TPM counts nothing for a key it holds without an auth policy.
/// So the general form is [`attempt_limiting_for`], which asks the binding a
/// vault is sealed against; this is that with no binding, and it answers
/// [`AttemptLimiting::None`].
pub fn attempt_limiting() -> AttemptLimiting {
    attempt_limiting_for(None)
}

/// What limits guessing for a vault sealed against `binding`.
///
/// Reads [`DeviceBinding::counts_attempts`] — the one fact the credential
/// bar turns on, asked of the thing that would do the counting. `None` is a
/// vault with no binding, and nothing counts for it.
pub fn attempt_limiting_for(binding: Option<&dyn DeviceBinding>) -> AttemptLimiting {
    match binding {
        Some(b) if b.counts_attempts() => AttemptLimiting::Hardware,
        _ => AttemptLimiting::None,
    }
}

/// Where a device-binding secret comes from (RFC-0053 step 8, RFC-0056
/// `HardwareCustody`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyBackend {
    /// Nothing binds the vault to this machine.
    None,
    /// TPM 2.0 via the CNG Platform Crypto Provider (Windows).
    WindowsTpm,
    /// The Secure Enclave (macOS).
    AppleSecureEnclave,
}

impl CustodyBackend {
    /// Whether this backend binds the vault to this physical device.
    pub fn binds_device(&self) -> bool {
        !matches!(self, Self::None)
    }
}

/// A non-exportable device secret the at-rest vault can be bound to.
///
/// Implementations live in `kotton_secret`. The contract is narrow on
/// purpose: a stable 32 bytes this device can reproduce and another cannot. What
/// makes it trustworthy is that it never leaves the hardware that derives it —
/// which is why the trait yields a *derived* secret rather than a key.
pub trait DeviceBinding: Send + Sync {
    fn backend(&self) -> CustodyBackend;

    /// The stable binding secret for this device.
    ///
    /// `credential` is the daily credential the vault is sealed under. A binding
    /// whose key carries an auth policy needs it — the hardware will not decrypt
    /// without it, and a wrong one is what the hardware counts — and a binding
    /// without one ignores it. Threading it through the trait rather than a
    /// side channel is what keeps "the credential reaches the chip" a fact of
    /// the signature.
    fn binding_secret(&self, credential: Option<&str>) -> SecretsResult<[u8; 32]>;

    /// Whether the hardware behind this binding counts failed attempts somewhere
    /// an attacker cannot reach — the only property that makes a short PIN
    /// defensible (RFC-0053, DEC-0046).
    ///
    /// **Deliberately separate from binding.** Binding removes the *offline*
    /// attack: the file is useless elsewhere, so guessing must happen on the
    /// machine. That is valuable on its own and is *not* attempt counting — an
    /// attacker holding the device still grinds locally at hardware speed unless
    /// the hardware itself refuses. Only the second relaxes the credential bar.
    ///
    /// A property of the **instance**, not the platform: the same TPM counts for
    /// a key created with an auth value and for nothing else. Required, not
    /// defaulted, so a new backend has to say which it is rather than inherit
    /// a `false` nobody wrote.
    fn counts_attempts(&self) -> bool;

    /// Whether opening this binding needs the daily credential — its key
    /// carries an auth policy. Readable without the credential, from the stored
    /// form, which is how a daemon learns a vault's limiting before anyone
    /// types. A credential change must replace such a binding, since the key
    /// is tied to the credential it was made with.
    fn requires_credential(&self) -> bool;

    /// Release whatever this binding holds in hardware once it is replaced —
    /// a per-binding key, where the backend keys per binding. Best-effort; a
    /// backend with nothing of its own does nothing.
    fn discard(&self) {}
}

/// The backend available on this machine.
///
/// [`CustodyBackend::None`] today. The TPM and Secure Enclave backends are the
/// next slice of RFC-0053 step 8; this returns `None` until one of them is
/// implemented *and* verified on its platform, because a binding that cannot be
/// reproduced is indistinguishable from a lost vault.
///
/// A deliberate non-choice: Kotton does **not** stand in a keychain-held random
/// secret here. It would bind the vault to the machine, but it would also make a
/// wiped keychain unrecoverable-by-credential — strictly worse than the hardware
/// it imitates, and it would break the RFC-0039 promise that a PIN recovers from
/// keychain loss.
pub fn active_custody_backend() -> CustodyBackend {
    CustodyBackend::None
}
