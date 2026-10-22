// SPDX-License-Identifier: AGPL-3.0-or-later
//! The vault, presented as the few things the sealed file handlers need.
//!
//! The same seam the full daemon implements, answered by a keeper: it can name
//! the domain a mount was pinned to and pin one, it can find a pool, and that is
//! all. Everything a device does that a vault does not — hold a remote's
//! credentials, replicate a mount, dial a peer — is answered with a refusal
//! rather than left unimplemented, so a handler that reaches for it gets a
//! sentence instead of a panic.

use crate::residency::Pools;
use kotton_common::crypto::kdf_labels;
use kotton_device::users::files::FileHost;
use kotton_device::users::residency::Residency as _;
use kotton_device::users::DeviceUsers as _;
use kotton_device::DeviceRuntime;
use kotton_diag::service::EventBus;
use kotton_store::runtime::user::UserStore;
use kotton_sys::store::SyncableStore;
use std::io;
use std::sync::Arc;

pub struct VaultHost<'a> {
    pub runtime: &'a DeviceRuntime,
    pub pools: &'a Pools,
}

#[async_trait::async_trait]
impl FileHost for VaultHost<'_> {
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
        // A vault holds no key, so the answer is the pinned domain or nothing;
        // the runtime's own reading of the store says exactly that.
        self.runtime.user_cek_domain_id(user_id, store)
    }

    fn set_remote_credentials(&self, _user_id: &str, _name: &str, _value: &str) -> io::Result<()> {
        Err(io::Error::other("a vault holds no remote; its devices do"))
    }

    fn forget_remote_credentials(&self, _user_id: &str, _name: &str) {}

    fn user_store(&self, user_id: &str) -> Option<Arc<UserStore>> {
        self.pools.get(user_id)
    }

    async fn sync_mount(
        &self,
        _user_id: &str,
        _mount: &str,
        _remote: &str,
        _direction: Option<kotton_wire::ipc::SyncDirection>,
    ) -> anyhow::Result<kotton_wire::remote::SyncResult> {
        anyhow::bail!("a vault does not replicate; the devices that can read do")
    }

    async fn open_peer_storage(
        &self,
        _node: kotton_wire::peer::PairedNode,
        _user_id: &str,
        _store: Option<&UserStore>,
    ) -> anyhow::Result<Arc<dyn SyncableStore>> {
        anyhow::bail!("a vault dials no peer; it is dialled")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotton_device::config::RuntimeConfig;
    use kotton_device::users::files::write_sealed;
    use kotton_sys::secret::{SecretsError, SecretsResult, SecretsStore};
    use kotton_wire::ipc::UserResponse;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    /// A secrets store whose reads can be made to fail — a locked keychain, a
    /// file the disk will not give back — and which records every key it is
    /// asked to write.
    struct UnreadableWhenLocked {
        inner: kotton_secret::MemorySecrets,
        locked: AtomicBool,
        written: Mutex<Vec<String>>,
    }

    impl UnreadableWhenLocked {
        fn new() -> Self {
            Self { inner: kotton_secret::MemorySecrets::new(), locked: AtomicBool::new(false), written: Mutex::new(Vec::new()) }
        }
    }

    impl SecretsStore for UnreadableWhenLocked {
        fn get_secret(&self, key: &str) -> SecretsResult<Option<String>> {
            if self.locked.load(Ordering::SeqCst) {
                return Err(SecretsError::Storage("the store could not be read".into()));
            }
            self.inner.get_secret(key)
        }
        fn set_secret(&self, key: &str, value: &str) -> SecretsResult<()> {
            self.written.lock().unwrap().push(key.to_string());
            self.inner.set_secret(key, value)
        }
        fn delete_secret(&self, key: &str) -> SecretsResult<()> {
            self.inner.delete_secret(key)
        }
    }

    async fn write(host: &VaultHost<'_>, path: &str, domain: &str) -> UserResponse {
        let blob = format!("sealed under {domain}").into_bytes();
        let hash = blake3::hash(&blob).to_hex().to_string();
        write_sealed(host, "alice".into(), "local".into(), path.into(), blob.clone(), domain.into(), 0, blob.len() as u64, hash, None)
            .await
            .unwrap()
    }

    /// A pin the store cannot read is not *no pin*: the write is refused naming
    /// the mount, nothing is pinned, and once the store reads again the mount
    /// still answers to the domain its first write pinned.
    #[tokio::test]
    async fn a_pin_the_store_cannot_read_refuses_the_write_and_pins_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = Arc::new(UnreadableWhenLocked::new());
        let runtime = DeviceRuntime::new_with_secrets(dir.path().join("vault"), RuntimeConfig::default(), secrets.clone())
            .await
            .unwrap();
        // A vault's pool: no key, so the pin is the only domain the mount has.
        let pool = UserStore::create(
            "alice",
            "did:key:zAlice",
            dir.path().join("alice"),
            kotton_store::runtime::UserKeys::new(None),
            &kotton_store::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();
        let pools = Pools::new();
        pools.insert("alice".into(), Arc::new(pool));
        let host = VaultHost { runtime: &runtime, pools: &pools };

        let first = write(&host, "a/first", "aaaa").await;
        assert!(matches!(first, UserResponse::Ok), "the first write pins the mount: {first:?}");

        secrets.written.lock().unwrap().clear();
        secrets.locked.store(true, Ordering::SeqCst);
        match write(&host, "a/second", "bbbb").await {
            UserResponse::Error { message } => assert!(message.contains("local"), "the refusal names the mount: {message}"),
            other => panic!("a write whose pin could not be read was not refused: {other:?}"),
        }
        assert!(secrets.written.lock().unwrap().is_empty(), "a pin was written: {:?}", secrets.written.lock().unwrap());

        secrets.locked.store(false, Ordering::SeqCst);
        match write(&host, "a/third", "bbbb").await {
            UserResponse::SealedDomainMismatch { expected, got } => {
                assert_eq!((expected.as_str(), got.as_str()), ("aaaa", "bbbb"));
            }
            other => panic!("the mount no longer answers to its first pin: {other:?}"),
        }
    }
}
