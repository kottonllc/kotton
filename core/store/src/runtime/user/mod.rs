// SPDX-License-Identifier: AGPL-3.0-or-later
//! A user's stores: the mounts, the mount table, and the key material they seal
//! under.
//!
//! ## Why this is a type
//!
//! A user's store and a user's device list share no state. The filesystem and
//! mount half touches **three fields** (`remotes`, `config`, `ctx`) and four
//! helpers, and the device list touches only itself; a `save()` writing
//! `devices.json` and `config.toml` in one call would be **two unrelated files,
//! no shared state**, which is what a bundled seam looks like from the inside.
//! So the store is a type of its own, and the device list is `peer`'s.
//!
//! ## Why it is in `core/store`
//!
//! A gate decides that rather than taste. `key-reach-check` entitles only a few
//! crates to name `SealingKeys`, `core/store` among them, and a user's VFS seals
//! and unseals, so wherever it lives must be entitled. `store` owns the router,
//! the mount table, the leaf keys, the maintenance passes and the sealed-stack
//! builder. Putting it in `fs` instead would mean entitling another crate to
//! the user's keys, which is a security-model change dressed as a layout
//! preference.
//!
//! ## On the key material
//!
//! [`kotton_context::UserContext`] is deliberately **not `Clone`** — it holds
//! raw key bytes. So this type *takes* the field rather than copying it, and
//! the number of places the user's CEK lives is unchanged by this split. That
//! was the constraint that decided the shape: a design where both halves held a
//! context would have been one more copy of the key, which is not a layout
//! question.

pub mod files;
pub mod storage;
pub mod sync;

use anyhow::Result;
use super::{router, save_config, UserConfig, UserKeys};
use crate::LocalObjectStorage;
use kotton_sys::store::{ObjectStorage, SyncableStore};
use std::collections::HashMap;
use std::sync::Arc;

/// The user's mounts and the table that routes paths across them.
pub struct UserStore {
    /// The user's persisted configuration, including each remote's backend.
    pub(crate) config: std::sync::RwLock<UserConfig>,
    /// Live remote handles (e.g. "local", "s3-backup"), keyed by mount name.
    ///
    /// Interior mutability so adding a mount needs only `&self` — see the note
    /// this moved from: `&mut` was obtainable only through `Arc::get_mut`, which
    /// made `remote add` fail whenever anyone else held a handle, and
    /// `sync_mount` is a method on this type so a long sync holds one by
    /// construction.
    pub(crate) remotes: std::sync::RwLock<HashMap<String, Arc<dyn SyncableStore>>>,
    /// Cached path router, built lazily from `storage-mounts.toml`.
    pub(crate) mount_router: std::sync::RwLock<Option<Arc<router::UserStorageRouter>>>,
    /// Everything the user's domains act upon: id, DID, base dir, and the key
    /// material. Moved rather than cloned — see the module note.
    pub(crate) ctx: kotton_context::UserContext,
}

impl UserStore {
    pub fn new(
        config: UserConfig,
        remotes: HashMap<String, Arc<dyn SyncableStore>>,
        ctx: kotton_context::UserContext,
    ) -> Self {
        Self {
            config: std::sync::RwLock::new(config),
            remotes: std::sync::RwLock::new(remotes),
            mount_router: std::sync::RwLock::new(None),
            ctx,
        }
    }

    /// Build a brand-new user's stores: the `data/` directory and the one
    /// "local" mount, born Blinded.
    ///
    /// **The shelves are a parameter for the reason this whole crate is:** they
    /// decide where objects land — a directory through some filesystem, a
    /// bucket — and this domain must not choose a host OS, nor a landlord's
    /// bucket. `std::fs` still creates the directory, which is a
    /// weaker thing — owning a directory is not the same as choosing what
    /// objects are written through.
    ///
    /// A new user has no pre-blinding objects, so the mount is born Blinded with
    /// no fallback. Fallback where it is not needed would let an unmigrated
    /// object hide.
    pub fn create(
        user_id: &str,
        did: &str,
        base_dir: std::path::PathBuf,
        keys: UserKeys,
        shelves: &dyn kotton_sys::store::Shelves,
    ) -> Result<Self> {
        use anyhow::Context as _;
        let UserKeys { cek, path_key, log } = keys;

        let data_dir = base_dir.join("data");
        kotton_common::fs::create_dir_all_owner_only(&data_dir)
            .with_context(|| format!("Failed to create data directory {data_dir:?}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("Failed to set permissions on {data_dir:?}"))?;
        }

        let local = crate::stack::build_sealed_store(
            crate::stack::ArcStore(shelves.open(user_id, "local", &data_dir)),
            cek,
            path_key,
            log.as_ref(),
            kotton_wire::remote::KeyFormat::Blinded,
        );

        let mut remotes: HashMap<String, Arc<dyn SyncableStore>> = HashMap::new();
        remotes.insert("local".to_string(), local);

        let mut remote_configs = HashMap::new();
        remote_configs.insert(
            "local".to_string(),
            kotton_wire::remote::RemoteConfig {
                backend: kotton_wire::remote::RemoteBackend::Local { path: data_dir },
                cache_dir: None,
                key_format: kotton_wire::remote::KeyFormat::Blinded,
            },
        );

        let config = UserConfig {
            remotes: remote_configs,
            ..Default::default()
        };
        let ctx = kotton_context::UserContext::new(user_id, did, base_dir)
            .with_keys(cek, path_key)
            .with_log(log);

        Ok(Self::new(config, remotes, ctx))
    }

    /// Reopen an existing user's stores from disk.
    ///
    /// The counterpart to [`Self::create`]: a store constructor sitting beside
    /// the store's other constructor. It loads no device list, which is `peer`'s
    /// and shares no state with any of this.
    ///
    /// **The shelves are a parameter for the same reason they are in `create`:**
    /// instantiating remotes decides what objects are written through, and this
    /// domain must not choose a host OS.
    pub async fn load(
        user_id: &str,
        did: &str,
        base_dir: std::path::PathBuf,
        keys: UserKeys,
        shelves: &dyn kotton_sys::store::Shelves,
    ) -> Result<Self> {
        let UserKeys { cek, path_key, log } = keys;
        let config = super::load_config(&base_dir)?;
        let remotes =
            super::instantiate_remotes(&config, user_id, shelves, cek, path_key, log.as_ref())
                .await?;
        let ctx = kotton_context::UserContext::new(user_id, did, base_dir)
            .with_keys(cek, path_key)
            .with_log(log);
        Ok(Self::new(config, remotes, ctx))
    }

    /// The key material this user's objects seal under, when this node holds it.
    ///
    /// `pub` because the split put a crate boundary between this and the runtime
    /// that builds stores for it. Both crates are already entitled to name
    /// `SealingKeys` (`key-reach-check`), so this widens no reach — it makes an
    /// existing one crossable.
    pub fn sealing_keys(&self) -> Option<kotton_context::SealingKeys<'_>> {
        self.ctx.sealing_keys()
    }

    /// Seal a drive's name under this person's key, bound to the `tree` a
    /// vault keeps the drive under, for the vault to keep and hand back to
    /// every device of theirs (`kotton_wire::ipc::TenantDrive`). The vault
    /// cannot open it; a sealed name moved to another tree does not open there,
    /// so a vault cannot pass one drive's name off as another's.
    ///
    /// `finished` is false for the tree a `drive move` is still filling: its
    /// name is sealed in a domain of its own, so every device that opens it
    /// reads an unfinished move and not a second drive of that name, and only
    /// the device that verified the copy seals it finished
    /// (`kotton_device::users::drive_verbs`).
    ///
    /// Refused on a store with no keys: a node that holds none names nothing.
    pub fn seal_drive_name(&self, tree: &str, name: &str, finished: bool) -> Result<Vec<u8>> {
        let keys = self
            .sealing_keys()
            .ok_or_else(|| anyhow::anyhow!("this node holds no keys for {}, so it cannot name a drive", self.user_id()))?;
        crate::provider::seal_envelope(keys.cek, &drive_name_aad(tree, finished), name.as_bytes())
            .map_err(|e| anyhow::anyhow!("sealing a drive's name: {e}"))
    }

    /// Open a drive's name [`Self::seal_drive_name`] sealed for `tree`, and
    /// whether it was sealed finished.
    pub fn open_drive_name(&self, tree: &str, sealed: &[u8]) -> Result<(String, bool)> {
        let keys = self
            .sealing_keys()
            .ok_or_else(|| anyhow::anyhow!("this node holds no keys for {}, so it cannot read a drive's name", self.user_id()))?;
        let (name, finished) = match crate::provider::open_envelope(keys.cek, &drive_name_aad(tree, true), sealed) {
            Ok(name) => (name, true),
            Err(_) => (
                crate::provider::open_envelope(keys.cek, &drive_name_aad(tree, false), sealed).map_err(|e| {
                    anyhow::anyhow!("the name sealed for drive tree '{tree}' does not open under this person's key: {e}")
                })?,
                false,
            ),
        };
        let name = String::from_utf8(name).map_err(|_| anyhow::anyhow!("the name sealed for drive tree '{tree}' is not text"))?;
        Ok((name, finished))
    }

    /// This user's DID.
    pub fn did(&self) -> &str {
        self.ctx.did()
    }

    /// This user's base directory.
    pub fn base_dir(&self) -> &std::path::Path {
        self.ctx.base_dir()
    }

    /// This user's id.
    pub fn user_id(&self) -> &str {
        self.ctx.user_id()
    }

    /// Whether this user has sync enabled.
    ///
    /// A named question rather than a `pub` field: the config sits behind a lock
    /// so that adding a mount needs only `&self`, and handing out the lock would
    /// let a caller hold it across an await — the shape the interior mutability
    /// exists to prevent.
    pub fn sync_enabled(&self) -> bool {
        self.config.read().unwrap().sync_enabled
    }

    /// Each mount resting on this node's own shelves: its name, and the path
    /// its configuration names. For what must reach the raw backend beneath a
    /// mount rather than the sealed stack over it — a vault dropping a tenant
    /// opens each through its `Shelves` and deletes what it finds there, which
    /// on a bucket is the only way the objects go.
    pub fn shelf_mounts(&self) -> Vec<(String, std::path::PathBuf)> {
        self.config
            .read()
            .unwrap()
            .remotes
            .iter()
            .filter_map(|(name, remote)| match &remote.backend {
                kotton_wire::remote::RemoteBackend::Local { path } => Some((name.clone(), path.clone())),
                _ => None,
            })
            .collect()
    }

    /// The vaults this device has already enrolled, as roots may target them.
    ///
    /// See [`crate::runtime::roots::enrolled_targets`] for why the handle is
    /// read out of the remote set rather than minted.
    pub fn enrolled_targets(&self) -> Vec<crate::runtime::roots::Target> {
        crate::runtime::roots::enrolled_targets(&self.config.read().unwrap())
    }

    /// This person's roots, migrating on first run.
    ///
    /// `own_aid` is the person's AID and arrives from the caller:
    /// this domain seals and places bytes, it does not replay a KEL, and a store
    /// that derived an identity would be a second identity authority. The daemon
    /// reads it from the chain it already reads for grant verification.
    ///
    /// On first run the existing tree becomes *Personal* and the vaults above
    /// become its targets — in place, with nothing re-encrypted.
    ///
    /// **Refused on a store with no keys**, which is the sealed index's whole
    /// point: the meaning half — every root's name and its members' AIDs — is
    /// sealed under this person's own keys, so a node that holds none of them
    /// can route their bytes (`RoutingIndex`) and cannot name a root. That is a
    /// blind posture doing exactly what it says, not a store that
    /// failed to configure one.
    /// `binding` is this device's **no-auth-policy** device binding, where it
    /// has one. It is not the person's key and it opens nothing of theirs: it
    /// seals the routing half — the addresses a cold daemon reads — to this
    /// machine, so that a copy of that file opens nowhere else. A caller with
    /// none passes `None` and the half is written in the clear, with its first
    /// line saying so.
    pub fn roots(
        &self,
        own_aid: &str,
        binding: Option<&dyn kotton_sys::secret::DeviceBinding>,
    ) -> Result<crate::runtime::roots::RootSet> {
        let keys = self.sealing_keys().ok_or_else(|| {
            anyhow::anyhow!(
                "this node holds no keys for {}, so it cannot name their roots",
                self.user_id()
            )
        })?;
        crate::runtime::roots::RootSet::open(
            self.base_dir(),
            own_aid,
            &self.enrolled_targets(),
            keys,
            binding,
        )
    }

    /// Persist `config.toml`.
    ///
    /// Half of what `UserRuntime::save` used to do in one call. The other half
    /// wrote `devices.json`, which shares no state with this — the two were
    /// bundled, not coupled.
    pub fn save_config(&self) -> Result<()> {
        save_config(self.base_dir(), &self.config.read().unwrap())?;
        Ok(())
    }

    /// The door a path in the person's tree goes through: which store it lands
    /// in, honouring `storage-mounts.toml`, and how that store is addressed.
    ///
    /// **One path, one key, whichever mount holds it.**
    /// The path is canonicalised once, here, and both the routing and the key
    /// are read from that one string: routing on the path as the caller spelled
    /// it let `\photos\a.jpg` go to the local store while the key it named was
    /// the one `/photos/a.jpg` names on the `/photos` mount, so one file had two
    /// homes by spelling. Then the handle the door gives out applies
    /// [`files::PERSON_TREE_ROOT`] once — to a mount that holds keys, which is
    /// every mount but a peer, the same key the store's own backend would get —
    /// and to a peer, which is a door onto the person's tree of its own, not at
    /// all: it is handed the person's path and roots it on its side.
    ///
    /// Routing happens on the caller's path, *before* [`to_object_key`] blinds
    /// it — a blinded key could never match a `/photos` prefix.
    ///
    /// Falls back to the local store when no mount matches, so a node with no
    /// mounts configured behaves exactly as it did before routing was wired.
    ///
    /// [`to_object_key`]: kotton_schemas::to_object_key
    pub(crate) fn person_door(&self, path: &str) -> PersonDoor {
        let router = {
            let cached = self.mount_router.read().unwrap();
            cached.clone()
        };
        let router = match router {
            Some(r) => r,
            None => {
                let built = Arc::new(self.build_mount_router());
                *self.mount_router.write().unwrap() = Some(Arc::clone(&built));
                built
            }
        };
        let canonical = format!("/{}", kotton_schemas::to_object_key(path));
        let (storage, addressing) = router.resolve_door(std::path::Path::new(&canonical));
        PersonDoor { storage, addressing }
    }

    /// How the remote called `name` is addressed from the person's tree: a
    /// paired peer by the person's path, every other backend by key. See
    /// [`router::Addressing`].
    pub(crate) fn addressing_of(&self, name: &str) -> router::Addressing {
        match self.config.read().unwrap().remotes.get(name).map(|c| &c.backend) {
            Some(kotton_wire::remote::RemoteBackend::Kotton { .. }) => router::Addressing::Names,
            _ => router::Addressing::Keys,
        }
    }

    /// Drop the cached router so the next resolve re-reads `storage-mounts.toml`.
    pub fn invalidate_mount_router(&self) {
        *self.mount_router.write().unwrap() = None;
    }

    /// Build a `UserStorageRouter` from the current remote set and
    /// `storage-mounts.toml` in the user's config directory.
    ///
    /// Mounts whose `remote` name is not present in `self.remotes` are skipped
    /// with a warning — the router degrades gracefully to the local fallback.
    pub fn build_mount_router(&self) -> router::UserStorageRouter {
        use crate::runtime::StorageMountsFile;
        use router::UserStorageRouter;

        let remotes = self.remotes.read().unwrap();
        let local = remotes
            .get("local")
            .cloned()
            .expect("UserStore invariant: 'local' remote must always exist");

        let mut router = UserStorageRouter::new(local);

        match StorageMountsFile::load(self.base_dir()) {
            Ok(mounts_file) => {
                for entry in &mounts_file.mounts {
                    match remotes.get(&entry.remote) {
                        Some(backend) => {
                            router.add_mount_addressed(
                                entry.path.clone(),
                                backend.clone(),
                                self.addressing_of(&entry.remote),
                            );
                        }
                        None => {
                            tracing::warn!(
                                path = %entry.path,
                                remote = %entry.remote,
                                "storage-mounts.toml references unknown remote; skipping"
                            );
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to load storage-mounts.toml: {e}; using local-only routing");
            }
        }

        router
    }

    /// Read the RAW on-disk bytes of a `local` object, **bypassing the encryption
    /// layer**.
    ///
    /// The `"local"` remote is an [`EncryptedObjectStorage`] whose `get()` decrypts
    /// and returns plaintext. Guest-DEK re-wrapping needs the raw on-disk
    /// blob — `[wrapped_dek:40][nonce:12][ciphertext]` — to lift the per-object
    /// wrapped-DEK header, so it must read the underlying [`LocalObjectStorage`]
    /// directly. Returns `None` if the path is absent or unreadable.
    /// **The filesystem is a parameter.** Naming `OsFilesystem` here would
    /// bring a host-OS reference into a domain that must not have one — a single
    /// constructor inside 8,000 lines that otherwise take a filesystem — and
    /// would make this crate depend on `kotton-fs`.
    pub async fn read_raw_local_object<F: kotton_sys::fs::Filesystem + 'static>(
        &self,
        path: &str,
        filesystem: F,
    ) -> Option<Vec<u8>> {
        let key = path.trim_start_matches('/');
        let raw = LocalObjectStorage::new(self.base_dir().join("data"), filesystem);
        raw.get(std::path::Path::new(key))
            .await
            .ok()
            .map(|b| b.to_vec())
    }
}

/// What a drive's sealed name is bound to: its own domain — one for a
/// finished drive, another for a move's unfinished tree — then the tree.
fn drive_name_aad(tree: &str, finished: bool) -> Vec<u8> {
    let mut aad = if finished { b"kotton/drive-name/v1\0".to_vec() } else { b"kotton/drive-name-unfinished/v1\0".to_vec() };
    aad.extend_from_slice(tree.as_bytes());
    aad
}

/// Where one path in the person's tree lands, as [`UserStore::person_door`]
/// resolved it.
pub(crate) struct PersonDoor {
    storage: Arc<dyn ObjectStorage>,
    addressing: router::Addressing,
}

impl PersonDoor {
    /// A handle on this door that takes the person's paths: rooted at
    /// [`files::PERSON_TREE_ROOT`] where the store holds keys, and handing the
    /// path on unrooted where the store is a naming door of its own.
    pub(crate) fn fs(&self) -> crate::Fs<'_> {
        match self.addressing {
            router::Addressing::Keys => {
                crate::Fs::rooted(self.storage.as_ref(), files::PERSON_TREE_ROOT)
            }
            router::Addressing::Names => crate::Fs::naming(self.storage.as_ref()),
        }
    }

    /// The store itself, for the verbs `Fs` does not carry.
    pub(crate) fn storage(&self) -> &dyn ObjectStorage {
        self.storage.as_ref()
    }

    /// Whether this door holds keys or is handed the person's path.
    pub(crate) fn addressing(&self) -> router::Addressing {
        self.addressing
    }
}
