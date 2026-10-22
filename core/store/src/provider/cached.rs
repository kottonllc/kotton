// SPDX-License-Identifier: AGPL-3.0-or-later
//! Read-through, write-through cache middleware for ObjectStorage
//!
//! Wraps any `ObjectStorage` backend with a local `LocalObjectStorage` cache.
//! All remote backends (S3, IPFS) should be wrapped with this before being
//! registered as a user remote — it makes small-file VFS access viable.

use async_trait::async_trait;
use bytes::Bytes;
use kotton_sys::store::{
    ObjectMetadata, ObjectStorage, ObjectStorageError, ObjectStorageResult, SealedObjectAccess,
};
use std::path::{Path, PathBuf};

use crate::LocalObjectStorage;

/// Read-through, write-through cache for any `ObjectStorage` backend.
///
/// - **get**: check local cache first; on miss, fetch from inner and write to cache.
/// - **put**: write to inner backend first, then update cache.
/// - **delete**: delete from inner backend, then invalidate cache entry.
/// - **list / metadata**: pass through to inner (metadata not cached).
///
/// Cache invalidation is explicit — no TTL or LRU. Use `cache_dir` to find
/// the cached objects and delete them manually, or call `kotton remote cache
/// clear <name>` (which deletes the cache directory and recreates it empty).
pub struct CachedObjectStorage<T: ObjectStorage> {
    inner: T,
    cache: LocalObjectStorage,
    cache_dir: PathBuf,
}

impl<T: ObjectStorage> CachedObjectStorage<T> {
    /// Create a new caching wrapper.
    ///
    /// * `inner` — the remote backend (S3, IPFS, etc.)
    /// * `cache` — a `LocalObjectStorage` rooted at the cache directory
    /// * `cache_dir` — the root path of the cache (used for `backend_name`)
    pub fn new(inner: T, cache: LocalObjectStorage, cache_dir: PathBuf) -> Self {
        Self {
            inner,
            cache,
            cache_dir,
        }
    }

    /// Return the path of the cache directory (useful for cache-clear operations).
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }
}

#[async_trait]
impl<T: ObjectStorage> ObjectStorage for CachedObjectStorage<T> {
    /// Get an object, checking the local cache first.
    ///
    /// On cache miss: fetch from inner, write to cache, return data.
    /// On cache hit: return cached data immediately.
    async fn get(&self, key: &Path) -> ObjectStorageResult<Bytes> {
        // Cache hit
        match self.cache.get(key).await {
            Ok(data) => return Ok(data),
            Err(ObjectStorageError::NotFound(_)) => {}
            // Propagate unexpected cache errors
            Err(e) => return Err(e),
        }

        // Cache miss — fetch from inner
        let data = self.inner.get(key).await?;

        // Populate cache (best-effort — don't fail the get if cache write fails)
        let _ = self.cache.put(key, &data).await;

        Ok(data)
    }

    /// Put an object — write to inner first, then cache.
    ///
    /// If the inner write fails the cache is not updated.
    async fn put(&self, key: &Path, data: &[u8]) -> ObjectStorageResult<()> {
        self.inner.put(key, data).await?;
        // Best-effort cache update
        let _ = self.cache.put(key, data).await;
        Ok(())
    }

    /// Delete an object from inner and invalidate its cache entry.
    async fn delete(&self, key: &Path) -> ObjectStorageResult<()> {
        self.inner.delete(key).await?;
        // Ignore NotFound in cache — it may not have been cached yet
        match self.cache.delete(key).await {
            Ok(_) | Err(ObjectStorageError::NotFound(_)) => {}
            Err(e) => eprintln!(
                "WARN [CachedObjectStorage]: cache delete failed for {:?}: {e}",
                key
            ),
        }
        Ok(())
    }

    /// List objects — always delegated to inner (lists are not cached).
    async fn list(&self, prefix: &Path) -> ObjectStorageResult<Vec<ObjectMetadata>> {
        self.inner.list(prefix).await
    }

    /// Get metadata — always delegated to inner.
    async fn metadata(&self, key: &Path) -> ObjectStorageResult<ObjectMetadata> {
        self.inner.metadata(key).await
    }

    fn backend_name(&self) -> &str {
        "cached"
    }
}

/// Delegates to the inner backend and **deliberately bypasses the cache**.
///
/// The cache is populated from [`ObjectStorage::get`], so when this wrapper sits
/// outside an encrypting store its entries hold *plaintext* under the same keys.
/// Serving `get_sealed` from that namespace would return plaintext labelled as
/// sealed — the precise confusion sealed replication forbids. Correctness wins over the
/// cache hit; replication reads straight through.
#[async_trait]
impl<T: ObjectStorage + SealedObjectAccess> SealedObjectAccess for CachedObjectStorage<T> {
    async fn get_sealed(&self, key: &Path) -> ObjectStorageResult<Bytes> {
        self.inner.get_sealed(key).await
    }

    async fn put_sealed(&self, key: &Path, blob: &[u8]) -> ObjectStorageResult<()> {
        self.inner.put_sealed(key, blob).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryObjectStorage;
    use kotton_fs::OsFilesystem;
    use tempfile::tempdir;

    fn make_cached(
        inner: MemoryObjectStorage,
        cache_dir: &Path,
    ) -> CachedObjectStorage<MemoryObjectStorage> {
        let local = LocalObjectStorage::new(cache_dir.to_path_buf(), OsFilesystem);
        CachedObjectStorage::new(inner, local, cache_dir.to_path_buf())
    }

    #[tokio::test]
    async fn test_cache_miss_then_hit() {
        let dir = tempdir().unwrap();
        let inner = MemoryObjectStorage::new();
        let key = Path::new("notes/hello.txt");

        inner.put(key, b"hello world").await.unwrap();

        let cached = make_cached(inner, dir.path());

        // First get — cache miss, fetches from inner
        let data = cached.get(key).await.unwrap();
        assert_eq!(&data[..], b"hello world");

        // Second get — should still return correct data (cache hit)
        let data2 = cached.get(key).await.unwrap();
        assert_eq!(&data2[..], b"hello world");
    }

    #[tokio::test]
    async fn test_put_write_through() {
        let dir = tempdir().unwrap();
        // Keep a clone so we can inspect inner independently
        let inner = MemoryObjectStorage::new();
        let inner_clone = inner.clone();
        let key = Path::new("docs/readme.txt");

        let cached = make_cached(inner, dir.path());
        cached.put(key, b"readme content").await.unwrap();

        // Verify inner was written (via independent clone)
        let from_inner = inner_clone.get(key).await.unwrap();
        assert_eq!(&from_inner[..], b"readme content");

        // Verify cache was written (get hits cache — inner content is unchanged)
        let from_cached = cached.get(key).await.unwrap();
        assert_eq!(&from_cached[..], b"readme content");
    }

    #[tokio::test]
    async fn test_delete_invalidates_cache() {
        let dir = tempdir().unwrap();
        let inner = MemoryObjectStorage::new();
        let key = Path::new("tmp/file.txt");

        let cached = make_cached(inner, dir.path());
        cached.put(key, b"data").await.unwrap();

        // Warm the cache
        cached.get(key).await.unwrap();

        // Delete removes from both inner and cache
        cached.delete(key).await.unwrap();

        // Subsequent get should return NotFound (cache miss -> inner miss)
        assert!(matches!(
            cached.get(key).await,
            Err(ObjectStorageError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn test_delete_not_in_cache_is_ok() {
        let dir = tempdir().unwrap();
        let inner = MemoryObjectStorage::new();
        let inner_clone = inner.clone(); // shared reference to the same backing store
        let key = Path::new("uncached.txt");

        // Write directly to inner without going through cached (so cache is cold)
        inner_clone.put(key, b"data").await.unwrap();

        let cached = make_cached(inner, dir.path());

        // Delete should succeed even though the cache entry doesn't exist
        cached.delete(key).await.unwrap();

        // Data gone from inner too
        assert!(matches!(
            inner_clone.get(key).await,
            Err(ObjectStorageError::NotFound(_))
        ));
    }
}
