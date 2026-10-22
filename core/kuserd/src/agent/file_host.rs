// SPDX-License-Identifier: AGPL-3.0-or-later
//! The daemon's implementation of [`FileHost`].
//!
//! Four capabilities, and the shape of the keychain pair is the interesting
//! part. The handlers used to hold `&DeviceRuntime` and call `.secrets()`,
//! which gave them the whole keychain — every identity signing key, every
//! operational CEK — to do two things: pin a mount's key domain, and hold a
//! remote's credentials.
//!
//! So the trait names those two things instead. The label construction
//! (`kdf_labels::sealed_mount_domain`, the `remote.{user}.{name}` prefix) lives
//! here rather than in the handler, which means a handler cannot ask for a
//! secret this type did not decide to expose. That is a narrower reach, not a
//! relocated one — the distinction between a `UserHandle` trait that hands a
//! domain the user and the `MemberStore` inversion, which hands it only what
//! it asks.
//!
//! Stays in `kuserd` when `files.rs` becomes `core/fs`: the trait travels with
//! the domain, the implementation stays with whoever can satisfy it.
use kotton_common::crypto::kdf_labels;
use kotton_device::users::files::FileHost;
use kotton_device::users::DeviceUsers as _;
use kotton_device::DeviceRuntime;
use kotton_diag::service::EventBus;
use kotton_store::runtime::user::UserStore;
use kotton_sys::secret::prefix_key;
use kotton_sys::store::SyncableStore;
use std::io;
use std::sync::Arc;

/// The machine, presented as the four things the file handlers need.
pub struct DaemonFileHost<'a> {
    pub runtime: &'a DeviceRuntime,
    /// The host's live per-user resources — which users are resident, and which
    /// record stores are open. The daemon's own bookkeeping, and the reason
    /// `user_store` can be answered here and not in the domain.
    ///
    /// One seam rather than the two locator types it used to name, for the same
    /// reason the sync engine stopped naming them: this file is the daemon's side
    /// of the boundary, and `sync_mount_with_records` is on the domain's.
    pub resources: &'a dyn kotton_sync::SyncHost,
}

/// Where a remote's credentials live in the keychain.
///
/// Built here so the handler never names a keychain label — it asks for a
/// remote's credentials, and this decides what that means.
fn credentials_key(user_id: &str, name: &str) -> String {
    prefix_key(&format!("remote.{user_id}.{name}"))
}

#[async_trait::async_trait]
impl FileHost for DaemonFileHost<'_> {
    fn events(&self) -> &Arc<EventBus> {
        self.runtime.event_bus()
    }

    fn mount_domain(&self, user_id: &str, mount: &str) -> io::Result<Option<String>> {
        self.runtime
            .secrets()
            .get_secret(&kdf_labels::sealed_mount_domain(user_id, mount))
            .map_err(io::Error::other)
    }

    fn pin_mount_domain(&self, user_id: &str, mount: &str, domain: &str) -> io::Result<()> {
        self.runtime
            .secrets()
            .set_secret(&kdf_labels::sealed_mount_domain(user_id, mount), domain)
            .map_err(io::Error::other)
    }

    fn cek_domain_id(&self, user_id: &str, store: Option<&UserStore>) -> Option<String> {
        self.runtime.user_cek_domain_id(user_id, store)
    }

    fn set_remote_credentials(&self, user_id: &str, name: &str, value: &str) -> io::Result<()> {
        self.runtime
            .secrets()
            .set_secret(&credentials_key(user_id, name), value)
            .map_err(io::Error::other)
    }

    /// Absence is not an error: a remote may never have had credentials, and
    /// removing one that does not exist is the same outcome either way.
    fn forget_remote_credentials(&self, user_id: &str, name: &str) {
        let _ = self
            .runtime
            .secrets()
            .delete_secret(&credentials_key(user_id, name));
    }

    fn user_store(&self, user_id: &str) -> Option<Arc<UserStore>> {
        self.resources.user_store(user_id)
    }

    async fn sync_mount(
        &self,
        user_id: &str,
        mount: &str,
        remote: &str,
        direction: Option<kotton_wire::ipc::SyncDirection>,
    ) -> anyhow::Result<kotton_wire::remote::SyncResult> {
        kotton_sync::engine::sync_mount_with_records(
            self.runtime,
            self.resources,
            user_id,
            mount,
            remote,
            direction,
        )
        .await
    }

    async fn open_peer_storage(
        &self,
        node: kotton_wire::peer::PairedNode,
        user_id: &str,
        store: Option<&UserStore>,
    ) -> anyhow::Result<Arc<dyn SyncableStore>> {
        self.runtime.open_peer_storage(node, user_id, store).await
    }
}

/// Build a host for one dispatch arm.
pub fn file_host<'a>(
    runtime: &'a DeviceRuntime,
    resources: &'a dyn kotton_sync::SyncHost,
) -> DaemonFileHost<'a> {
    DaemonFileHost { runtime, resources }
}
