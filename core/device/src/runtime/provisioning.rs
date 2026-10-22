// SPDX-License-Identifier: AGPL-3.0-or-later
//! This machine, presented as [`ProvisioningHost`].
//!
//! `kotton-identity` states what provisioning a user needs from a device; this
//! says that a `DeviceRuntime` can supply it. The impl lives here rather than in
//! `identity` because `identity` must not know this type exists — it sits far
//! below the machine, and a domain that named the runtime could not be depended
//! on by it.
//!
//! Every method is one line. That is the shape to expect from a well-drawn host
//! trait: if satisfying it took work, the trait would be asking for the wrong
//! things.

use kotton_identity::ProvisioningHost;
use kotton_sys::secret::SecretsStore;
use std::path::Path;

impl ProvisioningHost for crate::runtime::DeviceRuntime {
    fn base_dir(&self) -> &Path {
        crate::runtime::DeviceRuntime::base_dir(self)
    }

    fn secrets(&self) -> &(dyn SecretsStore + Send + Sync) {
        crate::runtime::DeviceRuntime::secrets(self)
    }

    fn device_fingerprint(&self) -> &str {
        crate::runtime::DeviceRuntime::device_fingerprint(self)
    }

    fn device_did(&self) -> &str {
        crate::runtime::DeviceRuntime::device_did(self)
    }

    fn shelves(&self) -> &dyn kotton_sys::store::Shelves {
        crate::runtime::DeviceRuntime::shelves(self)
    }

    fn principal(&self) -> Option<&str> {
        self.config().principal.as_deref()
    }

    fn register_device(&self, device_fingerprint: String, user_id: String) {
        crate::runtime::DeviceRuntime::register_device(self, device_fingerprint, user_id)
    }

    fn unregister_user_devices(&self, user_id: &str) {
        crate::runtime::DeviceRuntime::unregister_user_devices(self, user_id)
    }

    fn restore_device_routes(&self, routes: std::collections::HashMap<String, String>) {
        crate::runtime::DeviceRuntime::restore_device_routes(self, routes)
    }

    fn adopt_root(&self, label: &str) -> anyhow::Result<bool> {
        Ok(self.custody().adopt_root(label)?)
    }
}
