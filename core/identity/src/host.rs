// SPDX-License-Identifier: AGPL-3.0-or-later
//! What provisioning a user on a device needs from the device.
//!
//! Creating a user, logging one in, rotating their identity, and sealing their
//! roots under a PIN all need a handful of facts about the machine they happen
//! on. Until 2026-08-22 the code that does this took a whole `DeviceRuntime` to
//! get them, which is why it could not leave `05_runtime` (RFC-0080).
//!
//! ## Six capabilities, named
//!
//! The point is what is *absent*. A `DeviceRuntime` carries transports, an
//! event bus, a window registry, sealed custody, the schema registry, every
//! resident user's routing entry. Provisioning needs none of that, and a
//! parameter that hands it over anyway is a reach nobody chose — the same
//! argument [`crate`]'s sibling traits in the daemon make.
//!
//! Two of the six are narrower than the thing they came from, deliberately:
//!
//! - [`ProvisioningHost::principal`] replaces `config()`. Every call site read
//!   exactly one field off that config, so the trait names the field.
//! - [`ProvisioningHost::adopt_root`] replaces `custody()`. One call site, one
//!   operation. Handing over the custody handle would have offered every
//!   credential-gated operation to code that wanted one of them.
//!
//! That is the distinction RFC-0080 draws between the withdrawn `UserHandle`
//! trait and the `MemberStore` inversion: **a trait that relocates a reach is
//! not worth having; one that shrinks it is.**

use anyhow::Result;
use kotton_sys::secret::{DeviceBinding, SecretsStore};
use std::path::Path;

/// The machine, as user provisioning sees it.
pub trait ProvisioningHost: Send + Sync {
    /// Where this device keeps its users — `users/<id>/` hangs off here.
    fn base_dir(&self) -> &Path;

    /// The platform keychain. Provisioning writes a user's roots into it and
    /// reads them back to re-derive keys.
    fn secrets(&self) -> &(dyn SecretsStore + Send + Sync);

    /// The stable per-machine fingerprint, recorded on the device entry a newly
    /// created or newly bound user gets.
    fn device_fingerprint(&self) -> &str;

    /// The DID this machine signs as, used to scope a user's key labels.
    fn device_did(&self) -> &str;

    /// The shelves this node's mounts rest on (RFC-0084 V5): a directory
    /// through the host filesystem on a device, a bucket on a rented vault.
    /// The node's configuration, decided once; provisioning builds every
    /// store over it and names no backend of its own.
    fn shelves(&self) -> &dyn kotton_sys::store::Shelves;

    /// The single principal this daemon serves, if it was started for one.
    ///
    /// `None` means a multi-user daemon. `Some(p)` is a refusal to provision
    /// anyone else — the check that keeps a single-user daemon single-user.
    fn principal(&self) -> Option<&str>;

    // ── The routing table ────────────────────────────────────────────────
    //
    // Creating a user, removing one, and restoring the set at startup each
    // change which user an incoming device fingerprint belongs to. The table is
    // the machine's; provisioning is what makes an entry true.

    /// Record that `device_fingerprint` belongs to `user_id`.
    fn register_device(&self, device_fingerprint: String, user_id: String);

    /// Drop every route pointing at `user_id`, as part of removing them.
    fn unregister_user_devices(&self, user_id: &str);

    /// Replace the whole table, used once at startup from the persisted file.
    fn restore_device_routes(&self, routes: std::collections::HashMap<String, String>);

    /// Take custody of a root secret, returning whether anything moved.
    ///
    /// Sealing a root under this device's custody is what lets the plaintext
    /// copy be purged from platform storage afterwards.
    fn adopt_root(&self, label: &str) -> Result<bool>;

    // ── The hardware binding ─────────────────────────────────────────────
    //
    // Which hardware this machine binds a vault to is the machine's fact, and
    // it is the seam a test stands a counting double in — the only way to
    // prove the credential ladder (bar flips, a PIN seals, the hardware
    // refuses) on a machine with no TPM. The defaults are the platform's
    // binding; nothing above this trait names it.

    /// Reopen a stored binding.
    fn binding_from_stored(&self, stored: Vec<u8>) -> Box<dyn DeviceBinding> {
        Box::new(kotton_secret::PlatformBinding::from_sealed(stored))
    }

    /// Create a binding for a vault sealed under `credential`, with an auth
    /// policy on the key where the platform can put one, and without where it
    /// cannot. Returns the binding and the bytes to store.
    fn create_binding(&self, credential: &str) -> Result<(Box<dyn DeviceBinding>, Vec<u8>)> {
        let (b, stored) = if kotton_secret::PlatformBinding::supports_credential_policy() {
            kotton_secret::PlatformBinding::create_with_credential(credential)
        } else {
            kotton_secret::PlatformBinding::create()
        }
        .map_err(|e| anyhow::anyhow!("could not create a hardware binding on this device: {e}"))?;
        Ok((Box::new(b), stored))
    }

    /// Whether this machine has a usable hardware-backed key store at all.
    fn binding_available(&self) -> bool {
        kotton_secret::PlatformBinding::is_available()
    }
}
