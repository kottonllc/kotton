// SPDX-License-Identifier: AGPL-3.0-or-later
//! Path-based routing for VFS storage backends.
//!
//! `UserStorageRouter` dispatches `ObjectStorage` operations to the correct
//! backend by longest-prefix matching on the requested path. This enables
//! transparent peer-mounted directories — `/photos` goes to a peer's storage
//! while everything else hits local — without callers knowing about the routing.
//!
//! # Routing rules
//!
//! - The *local* backend is the fallback (effectively prefix `/`).
//! - Each mounted prefix is checked longest-first; the first match wins.
//! - A path matches a prefix if it equals the prefix **or** starts with
//!   `{prefix}/` (i.e., it's a child of the prefix directory).
//!
//! # Example
//!
//! ```rust
//! # use kotton_store::runtime::router::UserStorageRouter;
//! # use kotton_sys::store::{ObjectStorage, ObjectStorageResult, ObjectMetadata};
//! # use bytes::Bytes;
//! # use std::path::Path;
//! # use async_trait::async_trait;
//! # struct Stub;
//! # #[async_trait]
//! # impl ObjectStorage for Stub {
//! #     async fn get(&self, _: &Path) -> ObjectStorageResult<Bytes> { unimplemented!() }
//! #     async fn put(&self, _: &Path, _: &[u8]) -> ObjectStorageResult<()> { unimplemented!() }
//! #     async fn delete(&self, _: &Path) -> ObjectStorageResult<()> { unimplemented!() }
//! #     async fn list(&self, _: &Path) -> ObjectStorageResult<Vec<ObjectMetadata>> { unimplemented!() }
//! #     async fn metadata(&self, _: &Path) -> ObjectStorageResult<ObjectMetadata> { unimplemented!() }
//! #     fn backend_name(&self) -> &str { "stub" }
//! # }
//! // Route /photos/* to peer storage; everything else to local.
//! let local: std::sync::Arc<dyn ObjectStorage> = std::sync::Arc::new(Stub);
//! let peer:  std::sync::Arc<dyn ObjectStorage> = std::sync::Arc::new(Stub);
//! let mut router = UserStorageRouter::new(local);
//! router.add_mount("/photos", peer);
//! ```

use async_trait::async_trait;
use bytes::Bytes;
use kotton_sys::store::{ObjectMetadata, ObjectStorage, ObjectStorageResult};
use std::path::Path;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// UserStorageRouter
// ---------------------------------------------------------------------------

/// Routes VFS paths to the appropriate `ObjectStorage` backend.
///
/// Maintains a list of `(prefix, backend)` pairs sorted by prefix length
/// descending (longest-match-first). The local backend is the fallback and
/// never removed.
pub struct UserStorageRouter {
    /// Fallback local storage backend.
    local: Arc<dyn ObjectStorage>,
    /// Per-mount overrides. Kept sorted longest-first for O(n) longest-match.
    /// `n` is the number of mounts, expected to be small (< 100).
    mounts: Vec<(String, Arc<dyn ObjectStorage>, Addressing)>,
}

/// How a mounted backend is addressed — by the key the person's path names in
/// this store, or by the person's path itself.
///
/// **A mount is a choice of where a key rests, not a second naming**, so
/// almost every backend is [`Addressing::Keys`]: a local
/// directory or an S3 bucket is handed the key the store's own backend would
/// have been, `files/photos/a.jpg`. A **paired peer** is the exception, because
/// it is not a place a key rests — it is a person's door of its own, which
/// takes a path and roots it in *its* store. Handing it the key would root the
/// path twice: `/x` would land at `/files/x` in the peer's tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Addressing {
    /// The backend holds keys: it is given the rooted key.
    Keys,
    /// The backend is another door onto the person's tree: it is given the
    /// person's path, and roots it itself.
    Names,
}

impl UserStorageRouter {
    /// Create a new router with only local storage (no mounts).
    pub fn new(local: Arc<dyn ObjectStorage>) -> Self {
        Self {
            local,
            mounts: Vec::new(),
        }
    }

    /// Resolve a path to the appropriate backend by longest-prefix match.
    ///
    /// Returns the local backend if no mount prefix matches.
    /// As [`Self::resolve`], but returns an owned handle.
    ///
    /// Callers that build a router locally cannot hold the borrowed form past
    /// the router's scope; this hands back the `Arc` the router already holds.
    pub fn resolve_owned(&self, path: &Path) -> Arc<dyn ObjectStorage> {
        self.resolve_door(path).0
    }

    /// As [`Self::resolve_owned`], and how the backend it picks is addressed.
    /// The local fallback is always [`Addressing::Keys`].
    pub fn resolve_door(&self, path: &Path) -> (Arc<dyn ObjectStorage>, Addressing) {
        let path_str = path.to_string_lossy();
        for (prefix, backend, addressing) in &self.mounts {
            if path_matches_prefix(&path_str, prefix) {
                return (Arc::clone(backend), *addressing);
            }
        }
        (Arc::clone(&self.local), Addressing::Keys)
    }

    pub fn resolve(&self, path: &Path) -> &dyn ObjectStorage {
        let path_str = path.to_string_lossy();
        for (prefix, backend, _) in &self.mounts {
            if path_matches_prefix(&path_str, prefix) {
                return backend.as_ref();
            }
        }
        self.local.as_ref()
    }

    /// Register a new mount point.
    ///
    /// If a mount with the same prefix already exists, it is replaced.
    /// The mounts list is re-sorted to maintain longest-match ordering.
    pub fn add_mount(&mut self, prefix: impl Into<String>, storage: Arc<dyn ObjectStorage>) {
        self.add_mount_addressed(prefix, storage, Addressing::Keys);
    }

    /// Register a mount point addressed as `addressing` says. See [`Addressing`].
    pub fn add_mount_addressed(
        &mut self,
        prefix: impl Into<String>,
        storage: Arc<dyn ObjectStorage>,
        addressing: Addressing,
    ) {
        let prefix = normalize_prefix(prefix.into());
        // Remove any existing entry for this prefix
        self.mounts.retain(|(p, _, _)| p != &prefix);
        self.mounts.push((prefix, storage, addressing));
        // Sort by prefix length descending so the first match is always the longest
        self.mounts.sort_by_key(|(p, _, _)| std::cmp::Reverse(p.len()));
    }

    /// Remove a mount point.
    ///
    /// Returns `true` if a mount with the given prefix existed and was removed.
    pub fn remove_mount(&mut self, prefix: &str) -> bool {
        let normalized = normalize_prefix(prefix.to_string());
        let before = self.mounts.len();
        self.mounts.retain(|(p, _, _)| p != &normalized);
        self.mounts.len() < before
    }

    /// Return the list of currently registered mount prefixes.
    pub fn mount_prefixes(&self) -> Vec<&str> {
        self.mounts.iter().map(|(p, _, _)| p.as_str()).collect()
    }
}

// ---------------------------------------------------------------------------
// ObjectStorage impl — delegates to the resolved backend
// ---------------------------------------------------------------------------

#[async_trait]
impl ObjectStorage for UserStorageRouter {
    async fn get(&self, key: &Path) -> ObjectStorageResult<Bytes> {
        self.resolve(key).get(key).await
    }

    async fn put(&self, key: &Path, data: &[u8]) -> ObjectStorageResult<()> {
        self.resolve(key).put(key, data).await
    }

    async fn delete(&self, key: &Path) -> ObjectStorageResult<()> {
        self.resolve(key).delete(key).await
    }

    async fn list(&self, prefix: &Path) -> ObjectStorageResult<Vec<ObjectMetadata>> {
        self.resolve(prefix).list(prefix).await
    }

    async fn metadata(&self, key: &Path) -> ObjectStorageResult<ObjectMetadata> {
        self.resolve(key).metadata(key).await
    }

    async fn exists(&self, key: &Path) -> ObjectStorageResult<bool> {
        self.resolve(key).exists(key).await
    }

    fn backend_name(&self) -> &str {
        "router"
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Normalise a prefix: strip trailing slashes (except for root `/`).
fn normalize_prefix(mut p: String) -> String {
    while p.len() > 1 && p.ends_with('/') {
        p.pop();
    }
    if p.is_empty() {
        p.push('/');
    }
    p
}

/// Returns `true` if `path` is equal to `prefix` or is strictly inside it.
fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    if prefix == "/" {
        return true;
    }
    path == prefix || path.starts_with(&format!("{prefix}/"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use kotton_sys::store::{ObjectStorageError, ObjectStorageResult};
    use std::sync::{Arc, Mutex};

    /// Stub backend that records which method was called and the path string.
    #[derive(Default, Clone)]
    struct TrackingStorage {
        calls: Arc<Mutex<Vec<String>>>,
    }

    impl TrackingStorage {
        fn new() -> Self {
            Self::default()
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }

        fn record(&self, name: &str) {
            self.calls.lock().unwrap().push(name.to_string());
        }
    }

    #[async_trait::async_trait]
    impl ObjectStorage for TrackingStorage {
        async fn get(&self, key: &Path) -> ObjectStorageResult<Bytes> {
            self.record(&format!("get:{}", key.display()));
            Err(ObjectStorageError::NotFound(key.display().to_string()))
        }
        async fn put(&self, key: &Path, _: &[u8]) -> ObjectStorageResult<()> {
            self.record(&format!("put:{}", key.display()));
            Ok(())
        }
        async fn delete(&self, key: &Path) -> ObjectStorageResult<()> {
            self.record(&format!("delete:{}", key.display()));
            Ok(())
        }
        async fn list(&self, prefix: &Path) -> ObjectStorageResult<Vec<ObjectMetadata>> {
            self.record(&format!("list:{}", prefix.display()));
            Ok(vec![])
        }
        async fn metadata(&self, key: &Path) -> ObjectStorageResult<ObjectMetadata> {
            self.record(&format!("metadata:{}", key.display()));
            Err(ObjectStorageError::NotFound(key.display().to_string()))
        }
        async fn exists(&self, key: &Path) -> ObjectStorageResult<bool> {
            self.record(&format!("exists:{}", key.display()));
            Ok(false)
        }
        fn backend_name(&self) -> &str {
            "tracking-stub"
        }
    }

    // -- prefix matching helpers -----------------------------------------------

    #[test]
    fn path_matches_root_always() {
        assert!(path_matches_prefix("/anything", "/"));
        assert!(path_matches_prefix("/", "/"));
    }

    #[test]
    fn path_matches_exact_and_children() {
        assert!(path_matches_prefix("/photos", "/photos"));
        assert!(path_matches_prefix("/photos/2024/img.jpg", "/photos"));
    }

    #[test]
    fn path_does_not_match_sibling_with_shared_prefix() {
        assert!(!path_matches_prefix("/photoshop/file.psd", "/photos"));
    }

    // -- routing ---------------------------------------------------------------

    #[tokio::test]
    async fn no_mounts_routes_to_local() {
        let local = Arc::new(TrackingStorage::new());
        let router = UserStorageRouter::new(local.clone());
        let _ = router.put(Path::new("/notes/a.md"), b"hi").await;
        assert!(!local.calls().is_empty(), "local should be called");
    }

    #[tokio::test]
    async fn mount_intercepts_matching_path() {
        let local = Arc::new(TrackingStorage::new());
        let peer = Arc::new(TrackingStorage::new());
        let mut router = UserStorageRouter::new(local.clone());
        router.add_mount("/photos", peer.clone());

        let _ = router.put(Path::new("/photos/holiday.jpg"), b"").await;
        assert!(
            !peer.calls().is_empty(),
            "peer should be called for /photos/*"
        );
        assert!(local.calls().is_empty(), "local should NOT be called");
    }

    #[tokio::test]
    async fn non_matching_path_falls_through_to_local() {
        let local = Arc::new(TrackingStorage::new());
        let peer = Arc::new(TrackingStorage::new());
        let mut router = UserStorageRouter::new(local.clone());
        router.add_mount("/photos", peer.clone());

        let _ = router.put(Path::new("/documents/report.pdf"), b"").await;
        assert!(
            !local.calls().is_empty(),
            "local should handle /documents/*"
        );
        assert!(peer.calls().is_empty(), "peer should not be invoked");
    }

    #[tokio::test]
    async fn longest_prefix_wins() {
        let local = Arc::new(TrackingStorage::new());
        let peer_photos = Arc::new(TrackingStorage::new());
        let peer_vacation = Arc::new(TrackingStorage::new());

        let mut router = UserStorageRouter::new(local.clone());
        router.add_mount("/photos", peer_photos.clone());
        router.add_mount("/photos/vacation", peer_vacation.clone());

        let _ = router
            .put(Path::new("/photos/vacation/beach.jpg"), b"")
            .await;
        assert!(
            !peer_vacation.calls().is_empty(),
            "/photos/vacation/* should go to peer_vacation"
        );
        assert!(
            peer_photos.calls().is_empty(),
            "/photos should NOT handle this"
        );
        assert!(local.calls().is_empty());
    }

    #[test]
    fn add_mount_replaces_existing_prefix() {
        let local = Arc::new(TrackingStorage::new());
        let peer1 = Arc::new(TrackingStorage::new());
        let peer2 = Arc::new(TrackingStorage::new());
        let mut router = UserStorageRouter::new(local.clone());
        router.add_mount("/photos", peer1.clone());
        router.add_mount("/photos", peer2.clone());
        let prefixes = router.mount_prefixes();
        let count = prefixes.iter().filter(|p| **p == "/photos").count();
        assert_eq!(count, 1, "duplicate prefix should be rejected");
    }

    #[test]
    fn remove_mount_returns_true_on_success() {
        let local = Arc::new(TrackingStorage::new());
        let peer = Arc::new(TrackingStorage::new());
        let mut router = UserStorageRouter::new(local.clone());
        router.add_mount("/photos", peer.clone());
        assert!(router.remove_mount("/photos"));
        assert!(
            !router.remove_mount("/photos"),
            "second remove should return false"
        );
    }

    #[tokio::test]
    async fn after_remove_local_handles_path() {
        let local = Arc::new(TrackingStorage::new());
        let peer = Arc::new(TrackingStorage::new());
        let mut router = UserStorageRouter::new(local.clone());
        router.add_mount("/photos", peer.clone());
        router.remove_mount("/photos");

        let _ = router.put(Path::new("/photos/img.jpg"), b"").await;
        assert!(
            !local.calls().is_empty(),
            "local should handle path after mount removed"
        );
        assert!(peer.calls().is_empty());
    }
}
