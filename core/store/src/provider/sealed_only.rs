// SPDX-License-Identifier: AGPL-3.0-or-later
//! A store for a node that holds no data keys.
//!
//! Some nodes legitimately cannot encrypt: a blind storage node or a cosigner is
//! paired without a content encryption key precisely so it can hold a user's
//! data without being able to read it. What such a node
//! stores is material *already sealed elsewhere*, moved through the sealed
//! replication path, and that continues to work here untouched.
//!
//! What must never happen is the other reading of "no key": a node that *should*
//! hold data keys and does not — a locked session, a keychain entry that is
//! missing. Before this wrapper, both cases produced the same thing, a bare
//! `LocalObjectStorage`, so the second silently wrote **plaintext user data to
//! disk**.
//!
//! That was reachable only past a guard in another crate — kuserd's `NoCek`
//! check rejects file and record operations when the connection has no CEK — so
//! it was not a live disclosure. It was one missed guard away from being one,
//! which is the problem: the safety lived somewhere else. The same divergence
//! has already bitten this codebase once, when mounts added at runtime were bare
//! local stores while startup mounts were sealed and `kotton remote add --local`
//! wrote plaintext.
//!
//! So the storage layer now refuses on its own account. `get` and `put` — the
//! two operations that move content — fail on a keyless store, and the sealed
//! path is forwarded verbatim. Plaintext user data at rest stops being something
//! a guard prevents and becomes something the type cannot express.
//!
//! Deliberately narrow: `metadata`, `delete`, and `exists` are forwarded. They
//! move no content, and replication needs them to decide what to transfer.
//!
//! `list` is not among them, though the same sentence might seem to cover it.
//! Replication reads `list_sealed`, in
//! **storage-key space**, which is still forwarded. The plaintext `list` is the
//! other one: it answers about *logical paths*, and a keyless store has no way to
//! address those. A node holding blinded objects that is asked to list
//! `network/members` would look for that literal prefix, find nothing there
//! because every object lives under a blinded key, and answer **`Ok([])`** —
//! the empty set, not an error.
//!
//! That is the same failure `get` is refused for, one operation over, and worse
//! in practice because it needs no guard to reach and produces no error to
//! notice: a locked node would report that its owner is a member of nothing —
//! no contacts, no devices in the allowlist, no doors for a vault, every step
//! reporting success. So `list` is refused for the reason the module already gives: on a keyless store the
//! answer is not merely unavailable, it is *wrong*.
//!
//! The optional maintenance methods (`pack_loose`, `compact`, `recover_by_scan`,
//! …) are left to their trait defaults, which are inert constants that no
//! filesystem-backed store overrides — so inheriting them is behaviour-identical
//! to forwarding, without the surface.

use async_trait::async_trait;
use bytes::Bytes;
use kotton_sys::store::{
    ObjectMetadata, ObjectStorage, ObjectStorageError, ObjectStorageResult, SealedObjectAccess,
};
use std::path::Path;

/// Wraps a backing store to refuse plaintext content operations.
///
/// See the module docs for why this exists rather than handing back the bare
/// backend.
pub struct SealedOnlyStorage<S> {
    inner: S,
}

impl<S> SealedOnlyStorage<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

fn refused(op: &str, key: &Path) -> ObjectStorageError {
    ObjectStorageError::PermissionDenied(format!(
        "{op} {} requires a content encryption key, and this node holds none — \
         it can store only objects sealed elsewhere. If this is your device, it is locked: \
         unlock it. If it is a blind storage node, use the sealed replication path.",
        key.display()
    ))
}

#[async_trait]
impl<S: ObjectStorage> ObjectStorage for SealedOnlyStorage<S> {
    /// Refused: there is no key to decrypt with, so any bytes returned would be
    /// a sealed envelope masquerading as content.
    async fn get(&self, key: &Path) -> ObjectStorageResult<Bytes> {
        Err(refused("reading", key))
    }

    /// Refused: this is the path that used to write plaintext to disk.
    async fn put(&self, key: &Path, _data: &[u8]) -> ObjectStorageResult<()> {
        Err(refused("writing", key))
    }

    async fn delete(&self, key: &Path) -> ObjectStorageResult<()> {
        self.inner.delete(key).await
    }

    /// Refused: a keyless store cannot address logical paths, so it would answer
    /// about a key space that is not the caller's and report the empty set.
    /// Replication's listing is [`SealedObjectAccess::list_sealed`], which is
    /// forwarded.
    async fn list(&self, prefix: &Path) -> ObjectStorageResult<Vec<ObjectMetadata>> {
        Err(refused("listing", prefix))
    }

    async fn metadata(&self, key: &Path) -> ObjectStorageResult<ObjectMetadata> {
        self.inner.metadata(key).await
    }

    async fn exists(&self, key: &Path) -> ObjectStorageResult<bool> {
        self.inner.exists(key).await
    }

    fn backend_name(&self) -> &str {
        self.inner.backend_name()
    }
}

/// The sealed path is the whole point of a keyless node, so it forwards
/// verbatim.
#[async_trait]
impl<S: ObjectStorage + SealedObjectAccess> SealedObjectAccess for SealedOnlyStorage<S> {
    async fn get_sealed(&self, key: &Path) -> ObjectStorageResult<Bytes> {
        self.inner.get_sealed(key).await
    }

    async fn put_sealed(&self, key: &Path, blob: &[u8]) -> ObjectStorageResult<()> {
        self.inner.put_sealed(key, blob).await
    }

    /// Overridden rather than inherited: the trait default forwards to
    /// `self.delete()`, which would route back through this wrapper. Correct
    /// today because `delete` forwards, but it would break silently the moment
    /// `delete` were tightened, so the sealed path names its own target.
    async fn delete_sealed(&self, key: &Path) -> ObjectStorageResult<()> {
        self.inner.delete_sealed(key).await
    }

    async fn list_sealed(&self, prefix: &Path) -> ObjectStorageResult<Vec<ObjectMetadata>> {
        self.inner.list_sealed(prefix).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryObjectStorage;

    fn store() -> SealedOnlyStorage<MemoryObjectStorage> {
        SealedOnlyStorage::new(MemoryObjectStorage::new())
    }

    /// The invariant this type exists for.
    #[tokio::test]
    async fn plaintext_writes_are_refused() {
        let s = store();
        let err = s
            .put(Path::new("notes/groceries.md"), b"milk, eggs")
            .await
            .expect_err("a keyless store must not accept plaintext");
        assert!(
            matches!(err, ObjectStorageError::PermissionDenied(_)),
            "got {err:?}"
        );
    }

    /// A keyless node cannot decrypt, so returning bytes would hand back an
    /// envelope as though it were content.
    #[tokio::test]
    async fn plaintext_reads_are_refused() {
        let s = store();
        assert!(s.get(Path::new("notes/groceries.md")).await.is_err());
    }

    /// The empty set is a **wrong answer**, not an unavailable one, and that is
    /// why this is refused rather than forwarded.
    ///
    /// A keyless store asked for a logical prefix looks for that literal string.
    /// On a node whose objects are blinded nothing is there, so forwarding
    /// would answer `Ok([])` — indistinguishable from "you are a member of
    /// nothing", which a locked node would tell its owner about their own
    /// contacts, devices and vault doors.
    #[tokio::test]
    async fn plaintext_listing_is_refused_rather_than_answered_empty() {
        let s = store();
        // Something is there, under a key this store cannot address logically.
        s.put_sealed(Path::new("blinded/xyz"), b"sealed").await.unwrap();

        let err = s
            .list(Path::new("network/members"))
            .await
            .expect_err("a keyless store must refuse a logical listing, not answer none");
        assert!(
            matches!(err, ObjectStorageError::PermissionDenied(_)),
            "got {err:?}"
        );

        // And the replication path still sees what it holds.
        assert!(!s.list_sealed(Path::new("")).await.unwrap().is_empty());
    }

    /// The legitimate case keeps working: sealed blobs move through untouched.
    #[tokio::test]
    async fn sealed_objects_round_trip() {
        let s = store();
        let key = Path::new("notes/groceries.md");
        let blob = b"sealed-envelope-bytes";

        s.put_sealed(key, blob).await.unwrap();
        assert_eq!(s.get_sealed(key).await.unwrap().as_ref(), blob);

    }

    /// Refusing content must not break the operations replication needs to
    /// decide what to transfer.
    #[tokio::test]
    async fn metadata_operations_still_work() {
        let s = store();
        let key = Path::new("a.bin");
        s.put_sealed(key, b"xxxx").await.unwrap();

        assert!(s.exists(key).await.unwrap());
        assert_eq!(s.metadata(key).await.unwrap().size, 4);
        s.delete(key).await.unwrap();
        assert!(!s.exists(key).await.unwrap());
    }
}
