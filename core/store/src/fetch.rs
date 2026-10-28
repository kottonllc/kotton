// SPDX-License-Identifier: AGPL-3.0-or-later
//! **Fetch on open**: a pack this device does not hold is fetched from where
//! the person's things live when something reads it (kotton #55, pins).
//!
//! A device keeps a drive's index always and its content as its person chose
//! ("a device keeps what its person chose"; on demand "fetches on open").
//! The index names every file and the content packs that hold it
//! (`crate::packed::CONTENT_PACK_PREFIX`); a content pack a device was not
//! told to keep whole is not fetched by a sync pass. When anything reads a
//! file whose content is in such a pack — a person's `cat`, an app, the
//! daemon's own verification of a chunk a new write reuses — the read reaches
//! the shelf, the shelf has no such pack, and this layer asks the
//! [`PackSource`] the host lent the store for it, keeps it, and answers.
//!
//! **Where it sits, and why there.** At the very bottom of the stack, over the
//! shelf, so every layer above reads the pack exactly as if it had always been
//! here: the bytes it fetches are the sealed pack the drive holds, verbatim,
//! and are opened by the same layers that open a pack synced in a pass. It
//! sees only storage keys under `_pack/`; a pack's name says nothing about
//! what is in it, and the source is asked for nothing else — not a path, not a
//! file. What the drive learns is that this device asked for one pack — and,
//! unlike a pass, *when*: a fetch is timed to a read, often a person's, so the
//! drive learns when a device opened something it does not keep, and which
//! pack. That is the cost of keeping on demand, which the protocol's storage
//! model chooses; a device that keeps a drive whole pays none of it.
//!
//! **Offline.** A write on a device that cannot reach a drive fails, not
//! found, when it reuses a chunk whose pack this device does not hold: the
//! commit reads back every chunk the new state depends on, the reused one
//! included (`crate::packed`'s `commit_new_state`), and that read is a fetch
//! with no drive to answer. An overwrite of a file kept on demand, unopened,
//! offline, is that case.
//!
//! **Who lends the source.** The store cannot dial a vault — it does not know
//! one exists — so the daemon that hosts it lends one ([`PackSlot::lend`]),
//! once, for every user it makes resident. Until one is lent, or when the
//! source has no drive that answers, a read of a pack this device does not
//! hold fails as it did before this layer existed: not found.

use async_trait::async_trait;
/// The bytes a [`PackSource`] hands back, named here so a source need not
/// depend on the crate that defines them.
pub use bytes::Bytes;
use kotton_sys::store::{
    ObjectMetadata, ObjectSink, ObjectStorage, ObjectStorageError, ObjectStorageResult,
    SealedObjectAccess, SyncableStore,
};
use std::path::Path;
use std::sync::{Arc, RwLock};

/// Somewhere a store's missing packs can be fetched from: the person's drives,
/// as the host reaches them.
#[async_trait]
pub trait PackSource: Send + Sync {
    /// The sealed pack stored under `key` in `user_id`'s first drive, as the
    /// drive holds it, or `None` when no drive this source reaches has it.
    async fn fetch(&self, user_id: &str, key: &str) -> anyhow::Result<Option<Bytes>>;
}

/// The one place a store's [`PackSource`] is lent: shared by the store and
/// the bottom layer of its `local` mount, so a source lent after the store was
/// built reaches the layer that reads.
#[derive(Clone, Default)]
pub struct PackSlot(Arc<RwLock<Option<Arc<dyn PackSource>>>>);

impl PackSlot {
    /// Lend `source` to every read of this store from now on.
    pub fn lend(&self, source: Arc<dyn PackSource>) {
        *self.0.write().unwrap() = Some(source);
    }

    fn source(&self) -> Option<Arc<dyn PackSource>> {
        self.0.read().unwrap().clone()
    }
}

/// The shelf of a `local` mount, with fetch on open beneath every layer
/// (module doc).
pub struct FetchOnMiss {
    inner: Arc<dyn SyncableStore>,
    user_id: String,
    slot: PackSlot,
}

impl FetchOnMiss {
    pub fn new(inner: Arc<dyn SyncableStore>, user_id: &str, slot: PackSlot) -> Self {
        Self { inner, user_id: user_id.to_string(), slot }
    }

    /// Whether `key` names a pack: the one thing this layer fetches.
    fn is_pack(key: &Path) -> bool {
        let key = key.to_string_lossy();
        key.trim_start_matches('/')
            .strip_prefix(crate::packed::PACK_PREFIX)
            .is_some_and(|rest| rest.starts_with('/'))
    }

    /// `read`, and when it finds no pack here, the pack fetched, kept, and
    /// read again.
    async fn read_or_fetch<T, F, Fut>(&self, key: &Path, read: F) -> ObjectStorageResult<T>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = ObjectStorageResult<T>>,
    {
        match read().await {
            Err(ObjectStorageError::NotFound(missing)) if Self::is_pack(key) => {
                let Some(source) = self.slot.source() else {
                    return Err(ObjectStorageError::NotFound(missing));
                };
                let wanted = key.to_string_lossy().trim_start_matches('/').to_string();
                match source.fetch(&self.user_id, &wanted).await {
                    Ok(Some(blob)) => {
                        self.inner.put_sealed(key, &blob).await?;
                        tracing::debug!(user_id = %self.user_id, pack = %wanted, "fetched a pack on open");
                        read().await
                    }
                    Ok(None) => Err(ObjectStorageError::NotFound(format!(
                        "{missing}: this device does not keep it, and no drive it reached holds it"
                    ))),
                    Err(e) => Err(ObjectStorageError::NotFound(format!(
                        "{missing}: this device does not keep it, and fetching it from a drive failed: {e:#}"
                    ))),
                }
            }
            other => other,
        }
    }
}

#[async_trait]
impl ObjectStorage for FetchOnMiss {
    async fn get(&self, key: &Path) -> ObjectStorageResult<Bytes> {
        self.read_or_fetch(key, || self.inner.get(key)).await
    }
    async fn put(&self, key: &Path, data: &[u8]) -> ObjectStorageResult<()> {
        self.inner.put(key, data).await
    }
    async fn get_range(&self, key: &Path, offset: u64, length: u64) -> ObjectStorageResult<(Bytes, u64)> {
        self.read_or_fetch(key, || self.inner.get_range(key, offset, length)).await
    }
    async fn begin_stream(&self, key: &Path) -> ObjectStorageResult<Option<Box<dyn ObjectSink>>> {
        self.inner.begin_stream(key).await
    }
    async fn delete(&self, key: &Path) -> ObjectStorageResult<()> {
        self.inner.delete(key).await
    }
    async fn list(&self, prefix: &Path) -> ObjectStorageResult<Vec<ObjectMetadata>> {
        self.inner.list(prefix).await
    }
    async fn metadata(&self, key: &Path) -> ObjectStorageResult<ObjectMetadata> {
        self.inner.metadata(key).await
    }
    fn backend_name(&self) -> &str {
        self.inner.backend_name()
    }
}

#[async_trait]
impl SealedObjectAccess for FetchOnMiss {
    async fn get_sealed(&self, key: &Path) -> ObjectStorageResult<Bytes> {
        self.read_or_fetch(key, || self.inner.get_sealed(key)).await
    }
    async fn put_sealed(&self, key: &Path, blob: &[u8]) -> ObjectStorageResult<()> {
        self.inner.put_sealed(key, blob).await
    }
    async fn delete_sealed(&self, key: &Path) -> ObjectStorageResult<()> {
        self.inner.delete_sealed(key).await
    }
    async fn list_sealed(&self, prefix: &Path) -> ObjectStorageResult<Vec<ObjectMetadata>> {
        self.inner.list_sealed(prefix).await
    }
}

/// A node's shelves, with fetch on open beneath the `local` mount — the tree
/// a device keeps of its person's first drive, and the only one a pass keeps
/// less than whole of. Every other mount is the node's shelf as it was.
pub struct FetchingShelves<'a> {
    pub inner: &'a dyn kotton_sys::store::Shelves,
    pub slot: PackSlot,
}

impl kotton_sys::store::Shelves for FetchingShelves<'_> {
    fn open(&self, user_id: &str, mount: &str, path: &Path) -> Arc<dyn SyncableStore> {
        let shelf = self.inner.open(user_id, mount, path);
        if mount == "local" {
            Arc::new(FetchOnMiss::new(shelf, user_id, self.slot.clone()))
        } else {
            shelf
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryObjectStorage;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Drive {
        held: MemoryObjectStorage,
        asked: AtomicUsize,
    }

    #[async_trait]
    impl PackSource for Drive {
        async fn fetch(&self, user_id: &str, key: &str) -> anyhow::Result<Option<Bytes>> {
            assert_eq!(user_id, "alice");
            self.asked.fetch_add(1, Ordering::SeqCst);
            match self.held.get_sealed(Path::new(key)).await {
                Ok(b) => Ok(Some(b)),
                Err(ObjectStorageError::NotFound(_)) => Ok(None),
                Err(e) => Err(e.into()),
            }
        }
    }

    /// **A pack this device does not keep is fetched when read, and kept.**
    /// Before a source is lent the read fails as it always did; once lent, the
    /// pack comes from the drive, verbatim, and the second read is answered
    /// here without asking. Anything that is not a pack is never asked for.
    #[tokio::test]
    async fn a_missing_pack_is_fetched_on_open_and_kept() {
        let held = MemoryObjectStorage::new();
        held.put_sealed(Path::new("_pack/cabc"), b"sealed pack").await.unwrap();
        held.put_sealed(Path::new("files-blinded"), b"not a pack").await.unwrap();
        let drive = Arc::new(Drive { held, asked: AtomicUsize::new(0) });
        let slot = PackSlot::default();
        let here = FetchOnMiss::new(Arc::new(MemoryObjectStorage::new()), "alice", slot.clone());

        assert!(matches!(here.get_sealed(Path::new("_pack/cabc")).await, Err(ObjectStorageError::NotFound(_))));
        slot.lend(drive.clone());
        assert_eq!(here.get(Path::new("_pack/cabc")).await.unwrap().as_ref(), b"sealed pack");
        assert_eq!(here.get_sealed(Path::new("_pack/cabc")).await.unwrap().as_ref(), b"sealed pack");
        assert_eq!(drive.asked.load(Ordering::SeqCst), 1, "a kept pack was fetched again");
        assert!(here.get_sealed(Path::new("files-blinded")).await.is_err(), "a file was fetched");
        match here.get_sealed(Path::new("_pack/gone")).await {
            Err(ObjectStorageError::NotFound(m)) => assert!(m.contains("no drive it reached holds it"), "{m}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(drive.asked.load(Ordering::SeqCst), 2, "only packs are asked for");
    }
}
