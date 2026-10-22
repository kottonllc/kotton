// SPDX-License-Identifier: AGPL-3.0-or-later
//! Assembling a user's sealed storage stack.
//!
//! Every layer this builds — `LocalObjectStorage`, `EncryptedObjectStorage`,
//! `SealedOnlyStorage`, `BlindedObjectStorage`, `PackedObjectStorage` — lives in
//! this crate, so the assembly does too, beside its own parts.
//!
//! The filesystem arrives as a parameter rather than being named here. `core/fs`
//! is a dev-dependency of this crate and deliberately not a real one: naming
//! `OsFilesystem` would bake "there is a host OS" into the storage domain and
//! foreclose the bare-metal path. The caller that
//! knows it is running on an OS is the one that says so.
//!
//! This is the one place key material is *used to construct* rather than merely
//! carried: `store` builds the sealed stack, and every domain above it operates on the result
//! without ever seeing a key. The order is what `cargo xtask blindness-check`
//! defends one layer down — sealing decorators wrap the backend, never the
//! reverse.

use std::sync::Arc;

use kotton_context::LogIdentity;
use kotton_wire::remote::KeyFormat;
use kotton_sys::fs::Filesystem;
use kotton_sys::store::{
    ObjectMetadata, ObjectStorage, ObjectStorageResult, SealedObjectAccess, SyncableStore,
};

use crate::provider::{
    BlindedObjectStorage, EncryptedObjectStorage, LocalObjectStorage, PackedObjectStorage,
    SealedOnlyStorage,
};

/// Build a filesystem-backed store in a user's key domains: sealed under `cek`,
/// keyed under `path_key`, packed under `K_pack`.
///
/// A free function because `UserRuntime::new` needs it before a `UserRuntime`
/// exists. Keeping one implementation is the point — a divergence between
/// startup and runtime mount construction is what would leave `kotton remote
/// add --local` writing plaintext to disk.
pub fn build_local_store<F: Filesystem + 'static>(
    path: std::path::PathBuf,
    filesystem: F,
    cek: Option<[u8; 32]>,
    path_key: Option<[u8; 32]>,
    log: Option<&LogIdentity>,
    format: KeyFormat,
) -> Arc<dyn SyncableStore> {
    build_sealed_store(
        LocalObjectStorage::new(path, filesystem),
        cek,
        path_key,
        log,
        format,
    )
}

/// Build the sealed stack over any shelf: the same layers
/// `build_local_store` puts over a directory, over whatever `backend` is — a
/// bucket, a directory, memory. The stack does not know and the shelf does not
/// get to know; every byte that reaches `backend` is sealed by a layer above
/// it or refused by `SealedOnlyStorage`.
pub fn build_sealed_store<B: SyncableStore + 'static>(
    backend: B,
    cek: Option<[u8; 32]>,
    path_key: Option<[u8; 32]>,
    log: Option<&LogIdentity>,
    format: KeyFormat,
) -> Arc<dyn SyncableStore> {
    let sealed: Arc<dyn SyncableStore> = match cek {
        Some(key) => Arc::new(EncryptedObjectStorage::new(backend, key)),
        // No key means this node cannot encrypt, so it must not accept content.
        // It previously got a bare `LocalObjectStorage`, which wrote plaintext —
        // correct for a blind storage node holding foreign sealed blobs, silently
        // wrong for a node whose key is merely absent. `SealedOnlyStorage`
        // refuses plaintext `get`/`put` and forwards the sealed path, so the two
        // cases stop sharing a behaviour.
        None => Arc::new(SealedOnlyStorage::new(backend)),
    };

    // No path key means no `master_secret` on this node — a blind storage node, or a
    // dev store with no keys at all. Such a node holds only material sealed
    // elsewhere and has nothing of its own to blind or pack; packs a peer
    // pushes rest here as opaque sealed objects.
    let (Some(path_key), Some(cek)) = (path_key, cek) else {
        return sealed;
    };

    let blinded = BlindedObjectStorage::new(ArcStore(sealed), path_key);
    let blinded = match format {
        // Mid-migration reads fall back to plaintext keys; the pack layer is
        // still safe to stack on top, because a packing pass over an
        // unmigrated store fails loudly at enumeration rather than packing
        // around the stragglers.
        KeyFormat::Plain => blinded.with_plaintext_fallback(),
        KeyFormat::Blinded => blinded,
    };
    let packed = PackedObjectStorage::new(
        blinded,
        kotton_crypto::derive_pack_key(&cek),
    );
    // A node with no log identity still packs; it simply appends no history.
    // That is the blind-storage case: it carries segments others
    // wrote and can open none of them.
    Arc::new(match log {
        Some(l) => packed.with_log(l.writer_did.clone(), l.k_log),
        None => packed,
    })
}

/// Lets an already-erased `Arc<dyn SyncableStore>` be wrapped again.
///
/// `BlindedObjectStorage<S>` is generic over a concrete `S`, but the layer below
/// it here is already a trait object — whether the store is encrypted is decided
/// before whether it is blinded. This forwards the traits through the `Arc` so
/// the two decisions stay independent.
pub struct ArcStore(pub Arc<dyn SyncableStore>);

#[async_trait::async_trait]
impl ObjectStorage for ArcStore {
    async fn get(&self, key: &std::path::Path) -> ObjectStorageResult<bytes::Bytes> {
        self.0.get(key).await
    }
    async fn put(&self, key: &std::path::Path, data: &[u8]) -> ObjectStorageResult<()> {
        self.0.put(key, data).await
    }
    // Forwarded, not defaulted: the defaults would re-derive a range and a
    // streaming ingest from *this* wrapper's whole-object view, throwing away
    // whatever the erased store can actually do.
    async fn get_range(
        &self,
        key: &std::path::Path,
        offset: u64,
        length: u64,
    ) -> ObjectStorageResult<(bytes::Bytes, u64)> {
        self.0.get_range(key, offset, length).await
    }
    async fn begin_stream(
        &self,
        key: &std::path::Path,
    ) -> ObjectStorageResult<Option<Box<dyn kotton_sys::store::ObjectSink>>> {
        self.0.begin_stream(key).await
    }
    async fn delete(&self, key: &std::path::Path) -> ObjectStorageResult<()> {
        self.0.delete(key).await
    }
    async fn list(&self, prefix: &std::path::Path) -> ObjectStorageResult<Vec<ObjectMetadata>> {
        self.0.list(prefix).await
    }
    async fn metadata(&self, key: &std::path::Path) -> ObjectStorageResult<ObjectMetadata> {
        self.0.metadata(key).await
    }
    fn backend_name(&self) -> &str {
        self.0.backend_name()
    }
}


#[async_trait::async_trait]
impl SealedObjectAccess for ArcStore {
    async fn get_sealed(&self, key: &std::path::Path) -> ObjectStorageResult<bytes::Bytes> {
        self.0.get_sealed(key).await
    }
    async fn put_sealed(&self, key: &std::path::Path, blob: &[u8]) -> ObjectStorageResult<()> {
        self.0.put_sealed(key, blob).await
    }
    // The defaults would re-derive these from this wrapper's logical view —
    // forward them so the erased store's own storage-space semantics survive.
    async fn delete_sealed(&self, key: &std::path::Path) -> ObjectStorageResult<()> {
        self.0.delete_sealed(key).await
    }
    async fn list_sealed(
        &self,
        prefix: &std::path::Path,
    ) -> ObjectStorageResult<Vec<ObjectMetadata>> {
        self.0.list_sealed(prefix).await
    }
    async fn migrate_blinding(&self) -> ObjectStorageResult<usize> {
        self.0.migrate_blinding().await
    }
    async fn pack_loose(
        &self,
    ) -> ObjectStorageResult<Option<kotton_sys::store::PackSummary>> {
        self.0.pack_loose().await
    }
}
