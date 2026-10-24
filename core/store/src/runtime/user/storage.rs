// SPDX-License-Identifier: AGPL-3.0-or-later
//! Remote storage management for UserRuntime
//!
//! Handles adding, removing, and instantiating storage backends using provider abstractions.

pub use crate::runtime::{StorageMountEntry, StorageMountsFile};

use super::UserStore;
use kotton_wire::remote::{RemoteBackend, RemoteConfig};
use anyhow::{Context as _, Result};
use kotton_sys::store::SyncableStore;
use kotton_wire::remote::KeyFormat;
use std::sync::Arc;

impl UserStore {
    /// Add a remote storage backend
    ///
    /// User-chosen remote name allows multiple backends of the same type
    /// with different configurations (e.g., "s3-work", "s3-personal", "ipfs-archive").
    ///
    /// ## Arguments
    /// * `name` - User-chosen remote name (cannot be "local", which is reserved)
    /// * `storage` - ObjectStorage implementation
    /// * `remote_config` - Backend configuration (no secrets — those go in the keychain)
    ///
    /// ## Errors
    /// - Returns error if remote name already exists
    /// - Returns error if trying to use reserved name "local"
    pub fn add_remote(
        &self,
        name: String,
        storage: Arc<dyn SyncableStore>,
        remote_config: RemoteConfig,
    ) -> Result<()> {
        // Reject reserved remote name
        if name == "local" {
            anyhow::bail!(
                "Remote name 'local' is reserved for auto-created local filesystem storage. \
                 Choose a different name."
            );
        }

        // One critical section for the check and the insert, so two concurrent
        // adds of the same name cannot both pass the check and the second
        // silently replace the first.
        {
            let mut remotes = self.remotes.write().unwrap();
            if remotes.contains_key(&name) {
                anyhow::bail!("Remote '{}' already exists", name);
            }
            remotes.insert(name.clone(), storage);
            self.config.write().unwrap().remotes.insert(name, remote_config);
        }
        self.save_config()?;
        Ok(())
    }

    /// Remove a remote storage backend
    ///
    /// ## Errors
    /// - Cannot remove "local" remote (reserved)
    /// - Cannot remove the last remote (UserRuntime requires persistent storage)
    /// - Returns error if remote doesn't exist
    pub fn remove_remote(&self, name: &str) -> Result<()> {
        // Cannot remove reserved "local" remote
        if name == "local" {
            anyhow::bail!(
                "Cannot remove 'local' remote. \
                 This is the auto-created local filesystem storage."
            );
        }

        {
            let mut remotes = self.remotes.write().unwrap();
            if remotes.len() <= 1 {
                anyhow::bail!(
                    "Cannot remove last remote. \
                     A user requires at least one persistent storage backend."
                );
            }

            if remotes.remove(name).is_none() {
                anyhow::bail!("Remote '{}' not found", name);
            }

            self.config.write().unwrap().remotes.remove(name);
        }
        self.save_config()?;
        Ok(())
    }

    /// List all remote names
    pub fn list_remotes(&self) -> Vec<String> {
        self.remotes.read().unwrap().keys().cloned().collect()
    }

    /// Get a remote storage backend by name
    pub fn get_remote(&self, name: &str) -> Option<Arc<dyn SyncableStore>> {
        self.remotes.read().unwrap().get(name).cloned()
    }

    /// The DID of the paired peer the remote called `name` reaches, or `None` for
    /// a remote that is not a peer (a directory, a bucket) or no remote at all.
    ///
    /// Read from the remote's own configuration, the one place a remote records
    /// who is on the other end — so whatever pushes through a remote can ask what
    /// that peer may hold without being told a second time by whoever began the
    /// push.
    pub fn peer_of(&self, name: &str) -> Option<String> {
        match &self.config.read().unwrap().remotes.get(name)?.backend {
            RemoteBackend::Kotton { peer_did, .. } => Some(peer_did.clone()),
            _ => None,
        }
    }

    /// Migrate any local mount still in the `Plain` key scheme to blinded keys,
    /// then record it as `Blinded`.
    ///
    /// Runs once, at startup, for a store created before keys were blinded. A node with no
    /// path key (a blind storage node, or a dev store with no keys) blinds nothing and
    /// its mounts stay `Plain` — the guard here, not an accident. The migration
    /// itself is resumable and idempotent, so an interrupted startup simply
    /// re-runs it next time.
    pub async fn migrate_pending_mounts(&self) -> Result<()> {
        if self.ctx.sealing_keys().is_none() {
            return Ok(());
        }
        let pending: Vec<String> = self
            .config
            .read()
            .unwrap()
            .remotes
            .iter()
            .filter(|(_, c)| {
                matches!(c.backend, RemoteBackend::Local { .. })
                    && c.key_format == KeyFormat::Plain
            })
            .map(|(name, _)| name.clone())
            .collect();

        for name in pending {
            // Clone the handle and drop the guard: the migration below awaits,
            // and a lock held across an await blocks every other reader for the
            // length of an I/O operation.
            let store = {
                let remotes = self.remotes.read().unwrap();
                let Some(store) = remotes.get(&name) else {
                    continue;
                };
                Arc::clone(store)
            };
            let moved = store
                .migrate_blinding()
                .await
                .with_context(|| format!("migrate mount '{name}' to blinded keys"))?;
            if let Some(cfg) = self.config.write().unwrap().remotes.get_mut(&name) {
                cfg.key_format = KeyFormat::Blinded;
            }
            tracing::info!(
                mount = %name,
                moved,
                "RFC-0044: migrated mount to blinded keys"
            );
        }
        self.save_config()?;
        Ok(())
    }

    /// Build a filesystem-backed store, stating which key scheme its objects are
    /// currently in.
    ///
    /// `KeyFormat::Plain` means the mount has not been migrated yet, so reads
    /// fall back to plaintext keys while the pass runs. A new mount is
    /// born `Blinded` — it has no legacy objects to fall back to, and enabling
    /// fallback where it is not needed would let an unmigrated object hide.
    /// Build a store over `filesystem`, sealed under this user's keys.
    ///
    /// **The single place a local-backed mount is constructed**, so a new mount
    /// cannot be added in a way that skips encryption at rest. That is not
    /// hypothetical: mounts added at runtime were once bare `LocalObjectStorage`
    /// while startup mounts were sealed, so `kotton remote add --local` wrote
    /// plaintext to disk. Sealed replication surfaced it — a sealed blob copied
    /// into an unsealed mount reads back as the envelope, because there was no
    /// key domain to open it with. The hazard this method exists to prevent is a
    /// caller reaching for `LocalObjectStorage` directly.
    ///
    /// A `None` CEK yields a store that **refuses plaintext content** and serves
    /// only the sealed path ([`crate::SealedOnlyStorage`]) — correct for a node
    /// that holds no data keys by design, and a refusal rather than a silent
    /// plaintext write for one whose key is merely absent.
    ///
    /// **The filesystem is a parameter because this crate must not know a host
    /// OS exists** — that is the boundary `stack::build_local_store` was already
    /// generic for. The layer that knows the host OS is the caller, so the
    /// filesystem is injected there rather than the constraint being quietly
    /// dropped.
    pub fn local_store_with<F: kotton_sys::fs::Filesystem + 'static>(
        &self,
        path: std::path::PathBuf,
        filesystem: F,
        format: KeyFormat,
    ) -> Arc<dyn SyncableStore> {
        let keys = self.ctx.sealing_keys();
        crate::stack::build_local_store(path,
                filesystem,
                keys.map(|k| *k.cek),
                keys.map(|k| *k.path_key),
                self.ctx.log_identity(),
                format,
            )
    }

    /// Keep one more sealed tree on this node's own shelves, as the mount
    /// `name`, resting at `path` — a drive a vault makes for a tenant beside
    /// the tenancy's own tree (`kvaultd::drives`).
    ///
    /// Built as every shelf mount of this store is built at load
    /// ([`crate::runtime::instantiate_remotes`]): the shelf `shelves` opens
    /// for it, under this store's own keys — none on a vault, so the tree
    /// takes sealed bytes and refuses content — and recorded in `config.toml`
    /// as a `Local` mount, so a reload instantiates it again and a tenant's
    /// drop finds it among [`super::UserStore::shelf_mounts`] and clears it.
    /// Refused for a name a mount already carries, `local` among them.
    pub fn add_shelf_tree(
        &self,
        name: &str,
        path: std::path::PathBuf,
        shelves: &dyn kotton_sys::store::Shelves,
    ) -> Result<()> {
        kotton_common::fs::create_dir_all_owner_only(&path)
            .with_context(|| format!("creating the directory for mount '{name}' at {path:?}"))?;
        let keys = self.ctx.sealing_keys();
        let store = crate::stack::build_sealed_store(
            crate::stack::ArcStore(shelves.open(self.user_id(), name, &path)),
            keys.map(|k| *k.cek),
            keys.map(|k| *k.path_key),
            self.ctx.log_identity(),
            KeyFormat::Blinded,
        );
        self.add_remote(
            name.to_string(),
            store,
            RemoteConfig {
                backend: RemoteBackend::Local { path },
                cache_dir: None,
                key_format: KeyFormat::Blinded,
            },
        )
    }
}


// ── Mount maintenance ─────────────────────────────────────────────────────────
//
// These three take the store they act on and nothing else: a function operating
// on one mount that resolved the mount itself could reach every mount the user
// has. Resolving
// *which* store a mount name refers to stays with the caller, who is the one
// already holding the user's runtime.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::UserKeys;

    /// **A drive's name opens only under the person's key, and only for the
    /// tree it was sealed for**; a node with no keys names nothing.
    #[test]
    fn a_drive_name_opens_for_its_own_tree_under_its_own_key() {
        let shelves = crate::LocalShelves(kotton_fs::OsFilesystem);
        let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
        let open = |dir: &tempfile::TempDir, keys| {
            UserStore::create("alice", "did:key:zAlice", dir.path().to_path_buf(), keys, &shelves).unwrap()
        };
        let mine = open(&dirs[0], UserKeys::new(Some([7; 32])));
        let other = open(&dirs[1], UserKeys::new(Some([8; 32])));
        let keyless = open(&dirs[2], UserKeys::keyless());

        let sealed = mine.seal_drive_name("drive-aa", "photos", true).unwrap();
        assert!(!sealed.windows(6).any(|w| w == b"photos"), "the name is sealed");
        assert_eq!(mine.open_drive_name("drive-aa", &sealed).unwrap(), ("photos".to_string(), true));
        assert!(mine.open_drive_name("drive-bb", &sealed).is_err(), "it opened for another tree");
        assert!(other.open_drive_name("drive-aa", &sealed).is_err(), "it opened under another key");
        assert!(keyless.seal_drive_name("drive-aa", "photos", true).is_err(), "a keyless node named a drive");
        // A move's unfinished tree reads as unfinished, and never as the drive.
        let unfinished = mine.seal_drive_name("drive-aa", "photos", false).unwrap();
        assert_eq!(mine.open_drive_name("drive-aa", &unfinished).unwrap(), ("photos".to_string(), false));
        assert!(mine.open_drive_name("drive-bb", &unfinished).is_err(), "an unfinished name opened for another tree");
        assert!(keyless.open_drive_name("drive-aa", &sealed).is_err(), "a keyless node read a drive's name");
    }

    /// **A tree added beside `local` is a mount of its own, kept across a
    /// reload**: what is written to one is not in the other, and the store
    /// reopened from its configuration has both.
    #[tokio::test]
    async fn a_shelf_tree_is_its_own_mount_and_survives_a_reload() {
        let temp = tempfile::tempdir().unwrap();
        let shelves = crate::LocalShelves(kotton_fs::OsFilesystem);
        let store = UserStore::create("alice", "did:key:zAlice", temp.path().to_path_buf(), UserKeys::keyless(), &shelves).unwrap();
        store.save_config().unwrap();
        store.add_shelf_tree("drive-aa", temp.path().join("drives").join("drive-aa"), &shelves).unwrap();
        assert!(store.add_shelf_tree("local", temp.path().join("x"), &shelves).is_err(), "local was replaced");

        store.write_sealed("drive-aa", "x/one", b"sealed one").await.unwrap();
        store.write_sealed("local", "x/two", b"sealed two").await.unwrap();
        let keys = |mount: &'static str| {
            let store = &store;
            async move { store.list_sealed(mount, "").await.unwrap().into_iter().map(|(k, _, _)| k).collect::<Vec<_>>() }
        };
        assert_eq!(keys("drive-aa").await, ["x/one"]);
        assert_eq!(keys("local").await, ["x/two"]);

        let again = UserStore::load("alice", "did:key:zAlice", temp.path().to_path_buf(), UserKeys::keyless(), &shelves)
            .await
            .unwrap();
        assert_eq!(again.read_sealed("drive-aa", "x/one").await.unwrap(), b"sealed one");
        let mut mounts: Vec<String> = again.shelf_mounts().into_iter().map(|(name, _)| name).collect();
        mounts.sort();
        assert_eq!(mounts, ["drive-aa", "local"]);
    }

    #[test]
    fn test_cannot_add_remote_named_local() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = UserStore::create(
            "alice",
            "did:key:z6Mk...",
            temp.path().to_path_buf(),
            UserKeys::keyless(),
            &crate::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();

        // Try to add a remote with reserved name "local"
        let mock_storage = Arc::new(crate::MemoryObjectStorage::new());
        let config = RemoteConfig {
            backend: RemoteBackend::S3 {
                bucket: "test".to_string(),
                region: "us-east-1".to_string(),
                endpoint: None,
            },
            cache_dir: None,
            key_format: kotton_wire::remote::KeyFormat::default(),
        };

        let result = runtime.add_remote("local".to_string(), mock_storage, config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("reserved"));
    }

    #[test]
    fn test_cannot_remove_local_remote() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = UserStore::create(
            "alice",
            "did:key:z6Mk...",
            temp.path().to_path_buf(),
            UserKeys::keyless(),
            &crate::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();

        // Try to remove the "local" remote
        let result = runtime.remove_remote("local");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("local"));
    }

    #[test]
    fn test_user_defined_remote_names() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = UserStore::create(
            "alice",
            "did:key:z6Mk...",
            temp.path().to_path_buf(),
            UserKeys::keyless(),
            &crate::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();

        // Add multiple remotes with user-chosen names
        let s3_work = Arc::new(crate::MemoryObjectStorage::new());
        let s3_personal = Arc::new(crate::MemoryObjectStorage::new());

        runtime
            .add_remote(
                "s3-work".to_string(),
                s3_work,
                RemoteConfig {
                    backend: RemoteBackend::S3 {
                        bucket: "work-bucket".to_string(),
                        region: "us-east-1".to_string(),
                        endpoint: None,
                    },
                    cache_dir: None,
                    key_format: kotton_wire::remote::KeyFormat::default(),
                },
            )
            .unwrap();

        runtime
            .add_remote(
                "s3-personal".to_string(),
                s3_personal,
                RemoteConfig {
                    backend: RemoteBackend::S3 {
                        bucket: "personal-bucket".to_string(),
                        region: "us-east-1".to_string(),
                        endpoint: None,
                    },
                    cache_dir: None,
                    key_format: kotton_wire::remote::KeyFormat::default(),
                },
            )
            .unwrap();

        let remotes = runtime.list_remotes();
        assert_eq!(remotes.len(), 3); // local + s3-work + s3-personal
        assert!(remotes.contains(&"local".to_string()));
        assert!(remotes.contains(&"s3-work".to_string()));
        assert!(remotes.contains(&"s3-personal".to_string()));
    }
}


#[cfg(test)]
mod mounts_tests {
    use super::*;

    #[test]
    fn roundtrip_empty() {
        let dir = tempfile::tempdir().unwrap();
        let f = StorageMountsFile::default();
        f.save(dir.path()).unwrap();
        let loaded = StorageMountsFile::load(dir.path()).unwrap();
        assert!(loaded.mounts.is_empty());
    }

    #[test]
    fn missing_file_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let loaded = StorageMountsFile::load(dir.path()).unwrap();
        assert!(loaded.mounts.is_empty());
    }

    #[test]
    fn roundtrip_with_entries() {
        let dir = tempfile::tempdir().unwrap();
        let mut f = StorageMountsFile::default();
        f.upsert(StorageMountEntry { path: "/archive".into(), remote: "s3-arc".into() });
        f.upsert(StorageMountEntry { path: "/photos".into(),  remote: "s3-media".into() });
        f.save(dir.path()).unwrap();

        let loaded = StorageMountsFile::load(dir.path()).unwrap();
        assert_eq!(loaded.mounts.len(), 2);
        assert_eq!(loaded.mounts[0].path, "/archive");
        assert_eq!(loaded.mounts[1].remote, "s3-media");
    }

    #[test]
    fn upsert_replaces_existing_prefix() {
        let mut f = StorageMountsFile::default();
        f.upsert(StorageMountEntry { path: "/archive".into(), remote: "old".into() });
        f.upsert(StorageMountEntry { path: "/archive".into(), remote: "new".into() });
        assert_eq!(f.mounts.len(), 1);
        assert_eq!(f.mounts[0].remote, "new");
    }

    #[test]
    fn remove_entry() {
        let mut f = StorageMountsFile::default();
        f.upsert(StorageMountEntry { path: "/archive".into(), remote: "s3".into() });
        assert!(f.remove("/archive"));
        assert!(f.mounts.is_empty());
        assert!(!f.remove("/archive")); // idempotent
    }
}

#[cfg(test)]
mod packing_tests {
    use super::UserStore;
    use crate::runtime::pack_mount;
    use crate::runtime::UserKeys;
    use kotton_crypto::derive_cek;
    use crate::pack::PACK_SIZE;
    use crate::runtime::user::sync::Outbound;

    /// A write that lands after the pre-push pack is withheld from a peer that
    /// holds no data keys, not sent loose.
    ///
    /// Ordinary file writes take no mount lock, so nothing stops one landing
    /// between a pass's pack and its transfer. The sequence here is that window,
    /// run in order: a file is written and packed, a second file is written, and
    /// the pass pushes. Under [`Outbound::PacksOnly`] only packs and superblocks
    /// cross, the late file stays in the local mount counted as skipped, and it
    /// is still readable there.
    #[tokio::test]
    async fn a_write_after_the_pack_is_withheld_from_a_peer_that_holds_no_keys() {
        use kotton_wire::ipc::SyncDirection;
        use kotton_wire::remote::{KeyFormat, RemoteBackend, RemoteConfig};
        use std::sync::Arc;

        let temp = tempfile::tempdir().unwrap();
        let rt = UserStore::create(
            "alice",
            "did:key:zAlice",
            temp.path().to_path_buf(),
            UserKeys::new(Some(derive_cek(&[5u8; 32]))),
            &crate::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();
        let vault: Arc<dyn kotton_sys::store::SyncableStore> =
            Arc::new(crate::MemoryObjectStorage::new());
        rt.add_remote(
            "vault".to_string(),
            vault,
            RemoteConfig {
                backend: RemoteBackend::Kotton {
                    peer_did: "did:key:zVault".to_string(),
                    label: "vault".to_string(),
                },
                cache_dir: None,
                key_format: KeyFormat::default(),
            },
        )
        .unwrap();

        rt.write_file("/notes/packed.md", b"in a pack before the push").await.unwrap();
        pack_mount(&*rt.get_remote("local").unwrap(), "local").await.unwrap().unwrap();
        // The write the window lets in: after the pack, before the transfer.
        let late = vec![0x6b; 37_000];
        rt.write_file("/notes/late.bin", &late).await.unwrap();

        let result = rt
            .sync_mount("local", "vault", Some(SyncDirection::Push), Outbound::PacksOnly)
            .await
            .unwrap();
        assert!(result.pushed >= 2, "the pack and its superblock cross: {result:?}");
        for (_, key, bytes) in &result.transfers {
            assert!(
                key.starts_with("_pack/") || key.starts_with("_superblock/"),
                "{key} crossed at {bytes} bytes, and is neither a pack nor a superblock"
            );
        }
        assert!(result.skipped >= 1, "the late file was withheld: {result:?}");
        assert_eq!(rt.read_file("/notes/late.bin").await.unwrap(), late, "and is still here");
    }

    /// Deterministic pseudo-random content, entropic enough for the chunker.
    fn noise(len: usize, seed: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        let mut state = seed;
        while out.len() < len {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            out.extend_from_slice(&state.to_le_bytes());
        }
        out.truncate(len);
        out
    }

    /// Every file under `dir` as (relative path, size).
    fn walk_files(dir: &std::path::Path) -> Vec<(String, u64)> {
        let mut out = Vec::new();
        fn walk(base: &std::path::Path, dir: &std::path::Path, out: &mut Vec<(String, u64)>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(base, &p, out);
                } else if let (Ok(rel), Ok(meta)) = (p.strip_prefix(base), p.metadata()) {
                    out.push((rel.to_string_lossy().replace('\\', "/"), meta.len()));
                }
            }
        }
        walk(dir, dir, &mut out);
        out
    }

    /// The history log end to end: a runtime carrying a log identity produces mounts
    /// that actually append history, and one without produces mounts that do
    /// not. Both are observable through the trait — only a store with a log can
    /// snapshot — so this checks the wiring rather than the internals.
    #[tokio::test]
    async fn a_runtime_with_a_log_identity_builds_mounts_that_append_history() {
        let temp = tempfile::tempdir().unwrap();
        let cek = derive_cek(&[9u8; 32]);
        let rt = UserStore::create(
            "alice",
            "did:key:zAliceUser",
            temp.path().to_path_buf(),
            UserKeys::new(Some(cek)).with_log("did:key:zThisDevice", &[3u8; 32]),
            &crate::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();

        rt.write_file("/notes/a.md", b"hello").await.unwrap();
        pack_mount(&*rt.get_remote("local").unwrap(), "local").await.unwrap().unwrap();

        let out = rt
            .get_remote("local")
            .unwrap()
            .snapshot(0, &[])
            .await
            .unwrap()
            .expect("a mount built with a log identity must be able to snapshot");
        assert_eq!(out.files_captured, 1);
        assert_eq!(out.segments_subsumed, 1, "the pack pass appended a segment");
    }

    /// A node holding the CEK but no `master_secret` — a blind storage node, a
    /// FROST-joined device — packs and reads but appends no history. It could
    /// not open a segment it wrote.
    #[tokio::test]
    async fn a_runtime_without_master_secret_appends_no_history() {
        let temp = tempfile::tempdir().unwrap();
        let cek = derive_cek(&[9u8; 32]);
        let rt = UserStore::create(
            "alice",
            "did:key:zAliceUser",
            temp.path().to_path_buf(),
            UserKeys::new(Some(cek)),
            &crate::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();

        rt.write_file("/notes/a.md", b"hello").await.unwrap();
        pack_mount(&*rt.get_remote("local").unwrap(), "local")
            .await
            .unwrap()
            .expect("it still packs");
        assert!(
            rt.get_remote("local").unwrap().snapshot(0, &[]).await.unwrap().is_none(),
            "a mount with no log identity must not pretend to snapshot"
        );
    }

    /// The pack layer end to end through `UserRuntime`: write through the VFS,
    /// pack the mount, read back through the VFS, and confirm the disk holds
    /// nothing but fixed-size packs and constant-size superblocks — then
    /// reopen cold and read again (the superblock is the entry point, scan
    /// recovery's happy path).
    #[tokio::test]
    async fn a_mount_packs_serves_from_packs_and_reopens() {
        let temp = tempfile::tempdir().unwrap();
        let cek = derive_cek(&[7u8; 32]);
        let rt = UserStore::create(
            "alice",
            "did:key:zAlice",
            temp.path().to_path_buf(),
            UserKeys::new(Some(cek)),
            &crate::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();

        let big = noise(2 * 1024 * 1024, 11);
        rt.write_file("/photos/vacation.jpg", &big)
            .await
            .unwrap();
        rt.write_file("/notes/tiny.md", b"a small note")
            .await
            .unwrap();

        let summary = pack_mount(&*rt.get_remote("local").unwrap(), "local")
            .await
            .unwrap()
            .expect("a local mount with keys must have a pack layer");
        assert_eq!(summary.files_packed, 2);
        assert_eq!(summary.generation, Some(1));

        // The VFS still serves both files.
        assert_eq!(
            rt.read_file("/photos/vacation.jpg").await.unwrap(),
            big
        );
        assert_eq!(
            rt.read_file("/notes/tiny.md").await.unwrap(),
            b"a small note"
        );

        // What rests on disk — what a replica would hold — is only packs of
        // exactly PACK_SIZE and superblocks of one constant size.
        let files = walk_files(&temp.path().join("data"));
        assert!(!files.is_empty());
        let mut superblock_sizes = Vec::new();
        for (path, size) in &files {
            if path.starts_with("_pack/") {
                assert_eq!(
                    *size as usize, PACK_SIZE,
                    "pack {path} is not exactly PACK_SIZE"
                );
            } else if path.starts_with("_superblock/") {
                superblock_sizes.push(*size);
            } else {
                panic!("unexpected file on disk after packing: {path}");
            }
        }
        superblock_sizes.dedup();
        assert_eq!(superblock_sizes.len(), 1, "superblock size must be constant");

        // Cold reopen: a fresh runtime over the same directory reads the
        // packed files with no loose copies left to lean on.
        let rt2 = UserStore::create(
            "alice",
            "did:key:zAlice",
            temp.path().to_path_buf(),
            UserKeys::new(Some(cek)),
            &crate::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();
        assert_eq!(
            rt2.read_file("/photos/vacation.jpg").await.unwrap(),
            big
        );
        assert_eq!(
            rt2.read_file("/notes/tiny.md").await.unwrap(),
            b"a small note"
        );
    }

    /// A keyless node (a blind storage node) has no pack layer — `pack_mount`
    /// reports that honestly instead of pretending to pack.
    #[tokio::test]
    async fn a_keyless_mount_reports_no_pack_layer() {
        let temp = tempfile::tempdir().unwrap();
        let rt = UserStore::create(
            "replica",
            "did:key:zReplica",
            temp.path().to_path_buf(),
            UserKeys::keyless(),
            &crate::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();
        assert_eq!(pack_mount(&*rt.get_remote("local").unwrap(), "local").await.unwrap(), None);
    }

    /// With `reconcile()` wired into `sync_mount`, replay — not the `modified`
    /// comparison — is the authority for a packed
    /// mount, so a **delete propagates** across a sync instead of resurrecting.
    ///
    /// This is the exact case the old last-write-wins path could never handle:
    /// a file deleted on A is, to the timestamp comparison, simply *absent* on
    /// A and *present* on B — `(None, Some(_))` — which pulls it straight back.
    /// A delete is a segment in the log, not an absence, so unioning the two
    /// devices' histories and replaying removes it on B for good.
    ///
    /// Two runtimes share one key domain (same CEK, same `master_secret`, hence
    /// the same `K_log`) — A's device and a joined B — so B can open the
    /// segments A wrote. B pulls A's on-disk store through a local remote,
    /// which is the loopback stand-in for a peer exchange delivering packs.
    #[tokio::test]
    async fn a_delete_propagates_across_sync_instead_of_resurrecting() {
        use crate::stack::build_local_store;
        use kotton_wire::remote::{RemoteBackend, RemoteConfig};
    use crate::runtime::UserKeys;
        use kotton_wire::ipc::SyncDirection;
        use kotton_wire::remote::KeyFormat;
        use std::sync::Arc;

        let cek = derive_cek(&[42u8; 32]);
        let master = [7u8; 32];

        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();

        let rt_a = UserStore::create(
            "alice",
            "did:key:zAlice",
            dir_a.path().to_path_buf(),
            UserKeys::new(Some(cek)).with_log("did:key:zDeviceA", &master),
            &crate::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();
        let rt_b = UserStore::create(
            "alice",
            "did:key:zAlice",
            dir_b.path().to_path_buf(),
            UserKeys::new(Some(cek)).with_log("did:key:zDeviceB", &master),
            &crate::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();

        // B gets a remote pointing at A's data dir — same key domain, so B can
        // open what it pulls. This is the loopback form of "a peer shipped B
        // A's packs."
        let from_a: Arc<dyn super::SyncableStore> = build_local_store(dir_a.path().join("data"),
                kotton_fs::OsFilesystem,
                rt_b.ctx.sealing_keys().map(|k| *k.cek),
                rt_b.ctx.sealing_keys().map(|k| *k.path_key),
                rt_b.ctx.log_identity(),
                KeyFormat::Blinded,
            );
        rt_b.add_remote(
            "from-a".to_string(),
            from_a,
            RemoteConfig {
                backend: RemoteBackend::Local {
                    path: dir_a.path().join("data"),
                },
                cache_dir: None,
                key_format: KeyFormat::Blinded,
            },
        )
        .unwrap();

        // ── A writes and packs, B pulls and reconciles ──────────────────────
        rt_a.write_file("/notes/todo.md", b"buy milk")
            .await
            .unwrap();
        pack_mount(&*rt_a.get_remote("local").unwrap(), "local").await.unwrap().unwrap();

        rt_b
            .sync_mount("local", "from-a", Some(SyncDirection::Pull), Outbound::Everything)
            .await
            .unwrap();
        assert_eq!(
            rt_b.read_file("/notes/todo.md").await.unwrap(),
            b"buy milk",
            "B must see the file A wrote after pulling and reconciling",
        );

        // ── A deletes and packs, B pulls again ──────────────────────────────
        rt_a.delete_file("/notes/todo.md").await.unwrap();
        pack_mount(&*rt_a.get_remote("local").unwrap(), "local").await.unwrap().unwrap();

        rt_b
            .sync_mount("local", "from-a", Some(SyncDirection::Pull), Outbound::Everything)
            .await
            .unwrap();

        // The whole point: the delete propagated. Under per-file LWW this read
        // would still succeed — the file would have been pulled back.
        assert!(
            rt_b.read_file("/notes/todo.md").await.is_err(),
            "the delete on A must propagate to B, not resurrect",
        );
    }

    /// Replication never destroys the only copy.
    ///
    /// Two devices write the *same path* without having seen each other's
    /// write. Both are content the user created; neither corrects the other.
    /// Per-file last-writer-wins on `modified` picks the later timestamp and
    /// `transfer_sealed` overwrites the destination, so the losing version is
    /// gone from both sides — the defect list's words are "with no record it
    /// existed."
    ///
    /// Measured rather than assumed.
    ///
    /// The assertion is the weakest observable form that still means anything:
    /// not that one path holds two values, but that some device the user owns
    /// can still reach each thing they wrote. If every replica converges on the
    /// winner, the loser is not merely superseded — it is unreachable, and that
    /// is the "only copy" replication may not destroy.
    #[tokio::test]
    async fn r3_a_concurrent_write_does_not_destroy_the_losing_version() {
        use crate::stack::build_local_store;
        use kotton_wire::remote::{RemoteBackend, RemoteConfig};
    use crate::runtime::UserKeys;
        use kotton_wire::remote::KeyFormat;
        use std::sync::Arc;

        let cek = derive_cek(&[42u8; 32]);
        let master = [7u8; 32];

        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();

        let rt_a = UserStore::create(
            "alice",
            "did:key:zAlice",
            dir_a.path().to_path_buf(),
            UserKeys::new(Some(cek)).with_log("did:key:zDeviceA", &master),
            &crate::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();
        let rt_b = UserStore::create(
            "alice",
            "did:key:zAlice",
            dir_b.path().to_path_buf(),
            UserKeys::new(Some(cek)).with_log("did:key:zDeviceB", &master),
            &crate::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();

        // Concurrent by construction: each writes from its own empty state, so
        // neither write names the other as its parent.
        const A_WROTE: &[u8] = b"A: call the plumber";
        const B_WROTE: &[u8] = b"B: cancel the plumber";

        rt_a.write_file("/notes/todo.md", A_WROTE).await.unwrap();
        pack_mount(&*rt_a.get_remote("local").unwrap(), "local")
            .await
            .unwrap()
            .unwrap();

        rt_b.write_file("/notes/todo.md", B_WROTE).await.unwrap();
        pack_mount(&*rt_b.get_remote("local").unwrap(), "local")
            .await
            .unwrap()
            .unwrap();

        let from_a: Arc<dyn super::SyncableStore> = build_local_store(dir_a.path().join("data"),
                kotton_fs::OsFilesystem,
                rt_b.ctx.sealing_keys().map(|k| *k.cek),
                rt_b.ctx.sealing_keys().map(|k| *k.path_key),
                rt_b.ctx.log_identity(),
                KeyFormat::Blinded,
            );
        rt_b.add_remote(
            "from-a".to_string(),
            from_a,
            RemoteConfig {
                backend: RemoteBackend::Local {
                    path: dir_a.path().join("data"),
                },
                cache_dir: None,
                key_format: KeyFormat::Blinded,
            },
        )
        .unwrap();

        // Both devices run a pass. Only B syncing would prove nothing: A would
        // still hold its own write because nothing had touched it, and the test
        // would pass for a reason unrelated to keeping the only copy.
        let from_b: Arc<dyn super::SyncableStore> = build_local_store(dir_b.path().join("data"),
                kotton_fs::OsFilesystem,
                rt_a.ctx.sealing_keys().map(|k| *k.cek),
                rt_a.ctx.sealing_keys().map(|k| *k.path_key),
                rt_a.ctx.log_identity(),
                KeyFormat::Blinded,
            );
        rt_a
            .add_remote(
                "from-b".to_string(),
                from_b,
                RemoteConfig {
                    backend: RemoteBackend::Local {
                        path: dir_b.path().join("data"),
                    },
                    cache_dir: None,
                    key_format: KeyFormat::Blinded,
                },
            )
            .unwrap();

        rt_b.sync_mount("local", "from-a", None, Outbound::Everything).await.unwrap();
        rt_a.sync_mount("local", "from-b", None, Outbound::Everything).await.unwrap();

        // One path holds one current value, so keeping the only copy cannot mean "read_file returns
        // both". It means the losing write is still *reachable*: retained by the
        // merge, kept alive through compaction, and nameable by a user who wants
        // it back.
        let on_b = rt_b.read_file("/notes/todo.md").await.unwrap();
        let store = rt_b.get_remote("local").unwrap();

        // Named by its path in the person's tree, which is what `kotton fs
        // conflicts` prints; the store keeps it under the tree's root.
        let retained = rt_b.file_conflicts().await.unwrap();
        let ids = retained
            .iter()
            .find(|(path, _)| path == "notes/todo.md")
            .map(|(_, ids)| ids)
            .expect("the concurrent write must be retained");
        assert_eq!(ids.len(), 1, "one losing version retained");

        let loser = store
            .read_retained(std::path::Path::new("files/notes/todo.md"), &ids[0])
            .await
            .unwrap();

        let both: [&[u8]; 2] = [on_b.as_ref(), loser.as_ref()];
        assert!(
            both.contains(&A_WROTE) && both.contains(&B_WROTE),
            "R3 violated: a concurrent write is unreachable. current {:?}, retained {:?}",
            String::from_utf8_lossy(&on_b),
            String::from_utf8_lossy(&loser),
        );
    }
}

#[cfg(test)]
mod migration_trigger_tests {
    // A trait, used by method syntax: this module calls `.put()` through it, so
    // nothing names it and both clippy and grep read it as unused.
    use kotton_sys::store::ObjectStorage as _;
    use super::*;
    use crate::runtime::UserKeys;
    use kotton_crypto::derive_cek;
    use std::path::Path as StdPath;

    /// A store created before keys were blinded holds objects under plaintext keys and its
    /// config records `Plain`. `migrate_pending_mounts` must rewrite them to
    /// blinded keys, flip the mount to `Blinded`, and leave the object readable.
    #[tokio::test]
    async fn a_plain_mount_migrates_and_flips_to_blinded() {
        let temp = tempfile::tempdir().unwrap();
        let cek = derive_cek(&[9u8; 32]);

        // A live runtime (its "local" mount is Blinded by birth).
        let rt = UserStore::create(
            "alice",
            "did:key:zAlice",
            temp.path().to_path_buf(),
            UserKeys::new(Some(cek)),
            &crate::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();

        // Simulate a pre-blinding object: written under its *plaintext* key,
        // directly into the mount's data dir via a bare encrypting store.
        let data_dir = temp.path().join("data");
        let legacy = crate::EncryptedObjectStorage::new(
            crate::LocalObjectStorage::new(
                data_dir.clone(),
                kotton_fs::OsFilesystem,
            ),
            cek,
        );
        // Under the person's tree root, where `read_file` looks: this test is
        // about the key scheme, and a file at the store's bare root is the
        // other migration (`PERSON_TREE_ROOT`).
        legacy
            .put(StdPath::new("files/notes/legacy.md"), b"from before")
            .await
            .unwrap();

        // Mark the mount Plain, as an old config would have it.
        rt.config
            .write()
            .unwrap()
            .remotes
            .get_mut("local")
            .unwrap()
            .key_format = KeyFormat::Plain;

        rt.migrate_pending_mounts().await.unwrap();

        // The mount is now recorded Blinded…
        assert_eq!(
            rt.config.read().unwrap().remotes.get("local").unwrap().key_format,
            KeyFormat::Blinded
        );
        // …the legacy object reads back through the normal path…
        assert_eq!(
            rt.read_file("/notes/legacy.md").await.unwrap(),
            b"from before"
        );
        // …and no plaintext key survives on disk.
        for entry in walkdir_keys(&data_dir) {
            assert!(
                !entry.contains("notes") && !entry.contains("legacy"),
                "plaintext key survived migration: {entry}"
            );
        }
    }

    /// A node with no path key (a blind storage node) blinds nothing, so its mounts
    /// stay `Plain` — flipping them would be a lie.
    #[tokio::test]
    async fn a_keyless_node_does_not_flip_its_mounts() {
        let temp = tempfile::tempdir().unwrap();
        let rt = UserStore::create(
            "alice",
            "did:key:zAlice",
            temp.path().to_path_buf(),
            UserKeys::keyless(),
            &crate::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();
        rt.config
            .write()
            .unwrap()
            .remotes
            .get_mut("local")
            .unwrap()
            .key_format = KeyFormat::Plain;

        rt.migrate_pending_mounts().await.unwrap();

        assert_eq!(
            rt.config.read().unwrap().remotes.get("local").unwrap().key_format,
            KeyFormat::Plain,
            "a keyless node must not claim its mount is blinded"
        );
    }

    /// Recursively collect the relative file paths under `dir`.
    fn walkdir_keys(dir: &std::path::Path) -> Vec<String> {
        let mut out = Vec::new();
        fn walk(base: &std::path::Path, dir: &std::path::Path, out: &mut Vec<String>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(base, &p, out);
                } else if let Ok(rel) = p.strip_prefix(base) {
                    out.push(rel.to_string_lossy().replace('\\', "/"));
                }
            }
        }
        walk(dir, dir, &mut out);
        out
    }
}
