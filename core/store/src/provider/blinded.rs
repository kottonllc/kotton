// SPDX-License-Identifier: AGPL-3.0-or-later
//! Blinded object keys — the storage layer.
//!
//! Wraps a store so that the key it sees is a blinded derivation of the caller's
//! path, and the path itself travels *inside* the object body. Placed **outside**
//! [`EncryptedObjectStorage`], the path lands inside that layer's AEAD for free:
//!
//! ```text
//! BlindedObjectStorage      caller says  notes/trip.md
//!   └── EncryptedObjectStorage   stores  7bqk…/x2vn…  →  AEAD([path][data])
//!         └── LocalObjectStorage
//! ```
//!
//! That ordering is the whole trick. The alternative — teaching the encrypting
//! layer about paths — would have meant a header format change and a migration
//! of the envelope itself. Prepending the path to the plaintext needs neither:
//! the existing AEAD already covers it, so a replica can neither read the name
//! nor alter it undetected, and `path_aad` now binds the **blinded** key, which
//! keeps the sealed objects' anti-relocation property exactly as it was.
//!
//! # The cost of `list`
//!
//! HMAC does not reverse, so recovering a name means reading the object that
//! carries it. `list` therefore reads every object in the prefix rather than
//! consulting metadata alone — correct, and O(n) reads where it used to be one
//! call.
//!
//! This is a deliberate non-optimisation. The pack layer above this one keeps
//! manifests, and a manifest *is* the index that would fix `list`. Building a
//! separate index here would be work the pack layer makes redundant; doing the simple correct thing and letting the next layer supply
//! the fast path is the cheaper route to the same place.

use async_trait::async_trait;
use bytes::Bytes;
use kotton_sys::store::{
    ObjectMetadata, ObjectStorage, ObjectStorageError, ObjectStorageResult, SealedObjectAccess,
};
use kotton_crypto::path_blind::blind_object_key;
use std::path::Path;

/// Length prefix for the embedded path, in bytes.
const PATH_LEN_BYTES: usize = 2;

/// Wraps `S` so stored keys disclose nothing about the caller's paths.
pub struct BlindedObjectStorage<S: ObjectStorage> {
    inner: S,
    path_key: [u8; 32],
    /// Whether a miss at the blinded key should fall back to the caller's
    /// plaintext key.
    ///
    /// True only while a mount is mid-migration, when some objects have been
    /// rewritten and some have not. Off once the pass completes, so a
    /// fully-migrated store cannot silently keep serving unmigrated objects and
    /// hide an incomplete migration.
    plaintext_fallback: bool,
}

impl<S: ObjectStorage + 'static> BlindedObjectStorage<S> {
    /// Wrap `inner`, blinding keys with `path_key`
    /// (`kotton_crypto::path_blind::derive_path_blind_key`).
    pub fn new(inner: S, path_key: [u8; 32]) -> Self {
        Self {
            inner,
            path_key,
            plaintext_fallback: false,
        }
    }

    /// Serve reads from the caller's plaintext key when the blinded key misses.
    ///
    /// For a mount that is mid-migration only. A fully migrated mount must not
    /// enable this: it would mask an object the pass failed to rewrite, turning
    /// an incomplete migration into a silent one.
    #[must_use]
    pub fn with_plaintext_fallback(mut self) -> Self {
        self.plaintext_fallback = true;
        self
    }

    /// Whether `blob`, stored at `stored_key`, has already been migrated.
    ///
    /// Exact rather than heuristic: an object is migrated exactly when it carries
    /// an embedded path that blinds back to the key it is stored under. A
    /// pre-migration object stored at `notes/a.md` cannot satisfy that, because
    /// its stored key is the path itself rather than the blinding of one — and if
    /// its raw bytes happen to parse as a frame, the recovered path will not
    /// blind to `notes/a.md` either.
    fn is_migrated(&self, stored_key: &str, blob: &[u8]) -> bool {
        match Self::unframe(blob) {
            Ok((path, _)) => blind_object_key(&self.path_key, &path) == stored_key,
            Err(_) => false,
        }
    }

    /// Rewrite every unmigrated object under its blinded key. Returns how many
    /// were moved.
    ///
    /// **Resumable with no cursor.** The remaining set *is* the cursor: an object
    /// is migrated exactly when it lives at its blinded key and not at its
    /// plaintext one, so re-running finds only what is left. There is no progress
    /// record to corrupt, and no state in which a crash leaves the store
    /// disagreeing with a marker about what has been done.
    ///
    /// **Verify before delete**, the same discipline the pack layer keeps for
    /// compaction: the rewritten object is read back and confirmed before the
    /// original is removed. A crash between the write and the delete leaves the
    /// object at both keys, which reads correctly (blinded wins) and re-migrates
    /// harmlessly.
    ///
    /// Objects are decrypted and re-sealed rather than copied, because the
    /// encrypting layer binds the storage key as AEAD AAD (`path_aad`) —
    /// a blob moved to a new key must be re-sealed against it, which is the same
    /// anti-relocation property doing its job.
    pub async fn migrate_from_plaintext(&self) -> ObjectStorageResult<usize> {
        // Migration runs over the *stored* keys, at every depth — see
        // `collect_leaves` on why the walk must recurse.
        //
        // `skip_reserved: false` — pre-migration stored keys are the user's own
        // plaintext paths, where a leading `_` (say `_drafts/x.md`) is a real
        // name that must migrate, not the pack layer's reserved namespace.
        let keys: Vec<String> = self
            .collect_leaves(Path::new(""), false)
            .await?
            .into_iter()
            .map(|m| m.key)
            .collect();
        let mut moved = 0usize;

        for key in keys {
            let blob = self.inner.get(Path::new(&key)).await?;
            if self.is_migrated(&key, &blob) {
                continue;
            }

            let trimmed = key.trim_start_matches('/');
            let blinded = blind_object_key(&self.path_key, trimmed);
            let framed = Self::frame(trimmed, &blob)?;
            self.inner.put(Path::new(&blinded), &framed).await?;

            // Read back before removing the original.
            let check = self.inner.get(Path::new(&blinded)).await?;
            let (recovered, data) = Self::unframe(&check)?;
            if recovered != trimmed || data != blob.as_ref() {
                return Err(ObjectStorageError::BackendError(format!(
                    "migration read-back mismatch for {key}; original left in place"
                )));
            }

            self.inner.delete(Path::new(&key)).await?;
            moved += 1;
        }
        Ok(moved)
    }

    /// Every leaf object under `prefix` in **stored-key space**, recursing
    /// through directory entries.
    ///
    /// The inner store's `list` is one directory level, not a flat recursion (a
    /// filesystem backend returns `is_dir` entries), so every walk of the tree —
    /// listing, migration, and loose enumeration alike — descends through this
    /// helper. Skipping the descent silently dropped everything below the top
    /// level: a "looks done, isn't" failure the flat in-memory test backend
    /// could not surface, and one this file has now grown twice, once per
    /// caller.
    ///
    /// `skip_reserved` skips the `_`-prefixed storage namespace (packs,
    /// superblocks, tombstones — the pack layer's), as `crate::packed::kind`
    /// reads it: every key it does not call a file. Blinded components are base32, so a
    /// stored key starting with `_` can only be reserved — but a
    /// **pre-migration** store's keys are plaintext user paths, where `_` is an
    /// ordinary character, so migration must pass `false`.
    fn collect_leaves<'a>(
        &'a self,
        prefix: &'a Path,
        skip_reserved: bool,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = ObjectStorageResult<Vec<ObjectMetadata>>> + Send + 'a,
        >,
    > {
        Box::pin(async move {
            let mut out = Vec::new();
            for entry in self.inner.list(prefix).await? {
                if skip_reserved && crate::packed::kind(&entry.key) != crate::packed::ObjectKind::File {
                    continue;
                }
                if entry.is_dir {
                    let mut nested = self
                        .collect_leaves(Path::new(&entry.key), skip_reserved)
                        .await?;
                    out.append(&mut nested);
                } else {
                    out.push(entry);
                }
            }
            Ok(out)
        })
    }

    fn blind(&self, key: &Path) -> String {
        let canonical = key.to_string_lossy().replace('\\', "/");
        blind_object_key(&self.path_key, canonical.trim_start_matches('/'))
    }

    /// `[path_len: u16 BE][path][data]`.
    fn frame(path: &str, data: &[u8]) -> ObjectStorageResult<Vec<u8>> {
        let path_bytes = path.as_bytes();
        let len = u16::try_from(path_bytes.len()).map_err(|_| {
            ObjectStorageError::BackendError(format!(
                "path exceeds {} bytes and cannot be embedded: {path}",
                u16::MAX
            ))
        })?;
        let mut out = Vec::with_capacity(PATH_LEN_BYTES + path_bytes.len() + data.len());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(path_bytes);
        out.extend_from_slice(data);
        Ok(out)
    }

    fn unframe(blob: &[u8]) -> ObjectStorageResult<(String, &[u8])> {
        if blob.len() < PATH_LEN_BYTES {
            return Err(ObjectStorageError::BackendError(
                "object too short to carry a path header".into(),
            ));
        }
        let len = u16::from_be_bytes([blob[0], blob[1]]) as usize;
        let end = PATH_LEN_BYTES + len;
        if blob.len() < end {
            return Err(ObjectStorageError::BackendError(
                "object path header is longer than the object".into(),
            ));
        }
        let path = std::str::from_utf8(&blob[PATH_LEN_BYTES..end])
            .map_err(|_| ObjectStorageError::BackendError("object path is not UTF-8".into()))?
            .to_string();
        Ok((path, &blob[end..]))
    }
}

#[async_trait]
impl<S: ObjectStorage + 'static> ObjectStorage for BlindedObjectStorage<S> {
    async fn get(&self, key: &Path) -> ObjectStorageResult<Bytes> {
        let blinded = self.blind(key);
        let blob = match self.inner.get(Path::new(&blinded)).await {
            Ok(b) => b,
            Err(ObjectStorageError::NotFound(_)) if self.plaintext_fallback => {
                // Mid-migration: not yet rewritten, so it still sits under the
                // caller's own key and carries no embedded path.
                let canonical = key.to_string_lossy().replace('\\', "/");
                return self
                    .inner
                    .get(Path::new(canonical.trim_start_matches('/')))
                    .await;
            }
            Err(e) => return Err(e),
        };
        let (stored_path, data) = Self::unframe(&blob)?;

        // Defence in depth. The path is already inside the AEAD and the blinded
        // key is already bound as AAD, so a mismatch here should be unreachable —
        // which is exactly why it is worth failing loudly on. A silent mismatch
        // would mean one of those two bindings has stopped holding.
        let expected = key.to_string_lossy().replace('\\', "/");
        if stored_path != expected.trim_start_matches('/') {
            return Err(ObjectStorageError::BackendError(format!(
                "object at {} carries path {stored_path:?}, expected {expected:?}",
                key.display()
            )));
        }
        Ok(Bytes::copy_from_slice(data))
    }

    async fn put(&self, key: &Path, data: &[u8]) -> ObjectStorageResult<()> {
        let canonical = key.to_string_lossy().replace('\\', "/");
        let canonical = canonical.trim_start_matches('/');
        let framed = Self::frame(canonical, data)?;
        self.inner
            .put(Path::new(&self.blind(key)), &framed)
            .await
    }

    async fn delete(&self, key: &Path) -> ObjectStorageResult<()> {
        self.inner.delete(Path::new(&self.blind(key))).await
    }

    /// Lists by blinding the prefix, then recovering each name from the object
    /// that carries it. See the module docs on why this is O(n) reads.
    async fn list(&self, prefix: &Path) -> ObjectStorageResult<Vec<ObjectMetadata>> {
        let blinded_prefix = self.blind(prefix);
        // Leaves at every depth. A directory carries no object and therefore no
        // embedded path — its contents are reached by descending into it, never
        // by reporting it. (An earlier version skipped `is_dir` entries without
        // descending, which emptied every listing below the top level on
        // filesystem backends; the flat in-memory backend hid it.)
        //
        // `skip_reserved: true` — the `_` storage namespace (packs,
        // superblocks, tombstones) holds storage-layer objects with no path
        // frame; surfacing them in a logical listing would mean trying to open
        // them as sealed user objects. Unreachable for a blinded object: base32
        // components cannot start with `_`.
        let entries = self
            .collect_leaves(Path::new(&blinded_prefix), true)
            .await?;

        let mut out = Vec::with_capacity(entries.len());
        for mut meta in entries {
            // An object deleted between the listing above and this read was
            // deleted during the listing, and is not in it: a listing is what
            // the prefix held at some moment, not a promise each entry still
            // exists. Failing the whole listing on it made every reader of a
            // prefix someone else deletes from — an outbox whose signed-for
            // entries a pickup takes out — fail for a moment, as if locked.
            let blob = match self.inner.get(Path::new(&meta.key)).await {
                Ok(blob) => blob,
                Err(ObjectStorageError::NotFound(_)) => continue,
                Err(e) => return Err(e),
            };
            let (path, data) = Self::unframe(&blob)?;
            meta.size = data.len() as u64;
            meta.key = path;
            out.push(meta);
        }
        Ok(out)
    }

    async fn metadata(&self, key: &Path) -> ObjectStorageResult<ObjectMetadata> {
        let blinded = self.blind(key);
        let mut meta = self.inner.metadata(Path::new(&blinded)).await?;
        // Report the caller's key and a size net of the embedded path, so the
        // blinding is invisible above this layer.
        let canonical = key.to_string_lossy().replace('\\', "/");
        let canonical = canonical.trim_start_matches('/').to_string();
        meta.size = meta
            .size
            .saturating_sub((PATH_LEN_BYTES + canonical.len()) as u64);
        meta.key = canonical;
        Ok(meta)
    }

    fn backend_name(&self) -> &str {
        self.inner.backend_name()
    }
}

/// Sealed access operates in **blinded key space** and passes through untouched.
///
/// Replication moves opaque bytes between nodes and has no use for names: sync
/// compares keys, and blinded keys compare exactly as well as plaintext ones. A
/// peer therefore stores objects under the same blinded keys the origin uses,
/// which is what makes the property survive replication at all.
///
/// It also means replication does **not** pay `list`'s O(n) read cost — sync
/// sees the blinded view directly rather than resolving names it will never use.
#[async_trait]
impl<S: ObjectStorage + SealedObjectAccess + 'static> SealedObjectAccess
    for BlindedObjectStorage<S>
{
    async fn get_sealed(&self, key: &Path) -> ObjectStorageResult<Bytes> {
        self.inner.get_sealed(key).await
    }

    async fn put_sealed(&self, key: &Path, blob: &[u8]) -> ObjectStorageResult<()> {
        self.inner.put_sealed(key, blob).await
    }

    /// Deletes by stored key, bypassing the blinding — the default would blind
    /// an already-blinded (or reserved) key and silently delete nothing.
    async fn delete_sealed(&self, key: &Path) -> ObjectStorageResult<()> {
        self.inner.delete(key).await
    }

    /// Blinded (storage-space) keys, **not** the un-blinded paths
    /// [`ObjectStorage::list`] returns. Replication lists here, so the keys it
    /// then hands to `get_sealed`/`put_sealed` line up — and so only opaque keys
    /// reach a blind storage node.
    async fn list_sealed(&self, prefix: &Path) -> ObjectStorageResult<Vec<ObjectMetadata>> {
        self.inner.list(prefix).await
    }

    async fn migrate_blinding(&self) -> ObjectStorageResult<usize> {
        self.migrate_from_plaintext().await
    }
}

/// Loose enumeration for the packer: every object in the blinded
/// key space, with its logical name recovered from the sealed body.
///
/// Skips the reserved `_` storage namespace (packs, superblocks, tombstones) —
/// those are not loose objects. An object that carries no path frame is an
/// **error**, not a skip: it means the blinding migration has not
/// finished, and packing over it would silently leave it behind forever.
#[async_trait]
impl<S: ObjectStorage + SealedObjectAccess + 'static> crate::packed::LooseObjectSource
    for BlindedObjectStorage<S>
{
    async fn list_loose(&self) -> ObjectStorageResult<Vec<crate::packed::LooseEntry>> {
        let leaves = self.collect_leaves(Path::new(""), true).await?;
        let mut out = Vec::with_capacity(leaves.len());
        for meta in leaves {
            let blob = self.inner.get(Path::new(&meta.key)).await?;
            let (path, data) = Self::unframe(&blob).map_err(|_| {
                ObjectStorageError::BackendError(format!(
                    "object at {} carries no path frame — an unmigrated (RFC-0044) \
                     object; run the blinding migration before packing",
                    meta.key
                ))
            })?;
            out.push(crate::packed::LooseEntry {
                path,
                size: data.len() as u64,
                modified: meta.modified,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packed::LooseObjectSource as _;
    use crate::{EncryptedObjectStorage, MemoryObjectStorage};
    use kotton_crypto::path_blind::derive_path_blind_key;

    fn store() -> BlindedObjectStorage<EncryptedObjectStorage<MemoryObjectStorage>> {
        let inner = EncryptedObjectStorage::new(MemoryObjectStorage::new(), [0x42; 32]);
        BlindedObjectStorage::new(inner, derive_path_blind_key(&[0x11; 32]))
    }

    /// A plain store, so a test can inspect exactly what reaches the disk.
    fn raw() -> (
        BlindedObjectStorage<MemoryObjectStorage>,
        MemoryObjectStorage,
    ) {
        let shared = MemoryObjectStorage::new();
        let key = derive_path_blind_key(&[0x11; 32]);
        (
            BlindedObjectStorage::new(shared.clone(), key),
            shared,
        )
    }

    #[tokio::test]
    async fn round_trips_through_a_blinded_key() {
        let s = store();
        let key = Path::new("family/legal/filing.pdf");
        s.put(key, b"sensitive").await.unwrap();
        assert_eq!(s.get(key).await.unwrap().as_ref(), b"sensitive");
    }

    /// The property blinding exists for: what reaches the backing store carries
    /// no component of the caller's path.
    #[tokio::test]
    async fn the_backing_store_never_sees_the_path() {
        let (s, backing) = raw();
        s.put(Path::new("family/legal/divorce-filing.pdf"), b"x")
            .await
            .unwrap();

        let stored = backing.list(Path::new("")).await.unwrap();
        assert!(!stored.is_empty(), "nothing was stored");
        for entry in stored {
            for part in ["family", "legal", "divorce", "filing", "pdf"] {
                assert!(
                    !entry.key.contains(part),
                    "{part:?} leaked into stored key {}",
                    entry.key
                );
            }
        }
    }

    /// Listing resolves names again, so callers above this layer are unaffected.
    #[tokio::test]
    async fn list_returns_the_callers_paths() {
        let s = store();
        s.put(Path::new("notes/a.md"), b"one").await.unwrap();
        s.put(Path::new("notes/b.md"), b"two").await.unwrap();

        let mut keys: Vec<String> = s
            .list(Path::new("notes"))
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.key)
            .collect();
        keys.sort();
        assert_eq!(keys, vec!["notes/a.md", "notes/b.md"]);
    }

    /// Listing must descend subdirectories on a **filesystem** backend, where
    /// `list` is one directory level and nested paths arrive as `is_dir`
    /// entries. The flat in-memory backend cannot express this shape, and it
    /// hid exactly this failure: nested objects vanishing from every listing
    /// while remaining individually readable at their full path.
    #[tokio::test]
    async fn list_descends_subdirectories_on_a_filesystem_backend() {
        use kotton_fs::OsFilesystem;

        let temp = tempfile::TempDir::new().unwrap();
        let inner = EncryptedObjectStorage::new(
            crate::LocalObjectStorage::new(temp.path().to_path_buf(), OsFilesystem),
            [0x42; 32],
        );
        let s = BlindedObjectStorage::new(inner, derive_path_blind_key(&[0x11; 32]));

        s.put(Path::new("family/notes.txt"), b"flat").await.unwrap();
        s.put(Path::new("family/legal/filing.pdf"), b"nested")
            .await
            .unwrap();

        let listed = |entries: Vec<ObjectMetadata>| {
            let mut keys: Vec<String> = entries.into_iter().map(|m| m.key).collect();
            keys.sort();
            keys
        };

        // Below a prefix whose contents include a subdirectory…
        assert_eq!(
            listed(s.list(Path::new("family")).await.unwrap()),
            vec!["family/legal/filing.pdf", "family/notes.txt"]
        );
        // …and from the root, where *every* entry is a directory.
        assert_eq!(
            listed(s.list(Path::new("")).await.unwrap()),
            vec!["family/legal/filing.pdf", "family/notes.txt"]
        );
    }

    /// An object deleted between the listing and the read that names it is
    /// left out of the listing, not an error that fails the rest: a listing
    /// that races a delete answers with what is still there.
    #[tokio::test]
    async fn an_object_deleted_while_it_is_listed_is_left_out_and_the_rest_are_listed() {
        /// A backing store that deletes the first leaf it lists, as a delete
        /// landing between the listing and the reads after it does.
        struct DeletesWhileListing(MemoryObjectStorage);
        #[async_trait]
        impl ObjectStorage for DeletesWhileListing {
            async fn get(&self, key: &Path) -> ObjectStorageResult<Bytes> {
                self.0.get(key).await
            }
            async fn put(&self, key: &Path, data: &[u8]) -> ObjectStorageResult<()> {
                self.0.put(key, data).await
            }
            async fn delete(&self, key: &Path) -> ObjectStorageResult<()> {
                self.0.delete(key).await
            }
            async fn list(&self, prefix: &Path) -> ObjectStorageResult<Vec<ObjectMetadata>> {
                let listed = self.0.list(prefix).await?;
                if let Some(first) = listed.iter().find(|m| !m.is_dir) {
                    self.0.delete(Path::new(&first.key)).await?;
                }
                Ok(listed)
            }
            async fn metadata(&self, key: &Path) -> ObjectStorageResult<ObjectMetadata> {
                self.0.metadata(key).await
            }
            fn backend_name(&self) -> &str {
                "deletes-while-listing"
            }
        }
        let s = BlindedObjectStorage::new(
            DeletesWhileListing(MemoryObjectStorage::new()),
            derive_path_blind_key(&[0x11; 32]),
        );
        for name in ["a", "b", "c"] {
            s.put(Path::new(&format!("outbox/{name}")), name.as_bytes()).await.unwrap();
        }
        let listed = s.list(Path::new("outbox")).await.expect("a listing that raced a delete");
        assert_eq!(listed.len(), 2, "the two still there: {:?}", listed.iter().map(|m| &m.key).collect::<Vec<_>>());
    }

    /// Listing a prefix must not spill objects from a sibling directory — the
    /// blinded prefix has to line up with the blinded full key.
    #[tokio::test]
    async fn list_is_scoped_to_its_prefix() {
        let s = store();
        s.put(Path::new("notes/a.md"), b"one").await.unwrap();
        s.put(Path::new("other/b.md"), b"two").await.unwrap();

        let keys: Vec<String> = s
            .list(Path::new("notes"))
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.key)
            .collect();
        assert_eq!(keys, vec!["notes/a.md"]);
    }

    /// Reported size is the caller's data, not the framed object — otherwise
    /// every size above this layer would be inflated by the embedded path.
    #[tokio::test]
    async fn metadata_reports_the_callers_size() {
        let s = store();
        let key = Path::new("notes/a.md");
        s.put(key, b"0123456789").await.unwrap();
        assert_eq!(s.metadata(key).await.unwrap().size, 10);
        assert_eq!(s.metadata(key).await.unwrap().key, "notes/a.md");
    }

    #[tokio::test]
    async fn delete_removes_the_blinded_object() {
        let s = store();
        let key = Path::new("notes/a.md");
        s.put(key, b"one").await.unwrap();
        s.delete(key).await.unwrap();
        assert!(s.get(key).await.is_err());
    }

    /// A store in a different path domain cannot address the same objects, so a
    /// replica serving two users learns nothing by comparing their keys.
    #[tokio::test]
    async fn a_different_path_key_cannot_find_the_object() {
        let shared = MemoryObjectStorage::new();
        let mine = BlindedObjectStorage::new(shared.clone(), derive_path_blind_key(&[0x11; 32]));
        let theirs = BlindedObjectStorage::new(shared, derive_path_blind_key(&[0x22; 32]));

        mine.put(Path::new("notes/a.md"), b"one").await.unwrap();
        assert!(theirs.get(Path::new("notes/a.md")).await.is_err());
    }

    // ── migration ────────────────────────────────────────────────────────────

    /// Build a store whose backing already holds pre-migration objects: written
    /// under their plaintext keys, with no embedded path.
    async fn legacy_corpus() -> (
        BlindedObjectStorage<EncryptedObjectStorage<MemoryObjectStorage>>,
        Vec<(&'static str, &'static [u8])>,
    ) {
        let backing = MemoryObjectStorage::new();
        let encrypted = EncryptedObjectStorage::new(backing, [0x42; 32]);
        let corpus: Vec<(&str, &[u8])> = vec![
            ("family/legal/filing.pdf", b"sensitive" as &[u8]),
            ("notes/a.md", b"one"),
            ("notes/b.md", b"two"),
        ];
        for (k, v) in &corpus {
            encrypted.put(Path::new(k), v).await.unwrap();
        }
        let store =
            BlindedObjectStorage::new(encrypted, derive_path_blind_key(&[0x11; 32]))
                .with_plaintext_fallback();
        (store, corpus)
    }

    /// A mount mid-migration must serve both halves — otherwise enabling
    /// blinding would make every unmigrated object disappear.
    #[tokio::test]
    async fn fallback_serves_objects_not_yet_migrated() {
        let (store, corpus) = legacy_corpus().await;
        for (k, v) in &corpus {
            assert_eq!(
                store.get(Path::new(k)).await.unwrap().as_ref(),
                *v,
                "{k} unreadable before migration"
            );
        }
    }

    #[tokio::test]
    async fn migration_moves_every_object_and_content_survives() {
        let (store, corpus) = legacy_corpus().await;
        assert_eq!(store.migrate_from_plaintext().await.unwrap(), corpus.len());

        for (k, v) in &corpus {
            assert_eq!(
                store.get(Path::new(k)).await.unwrap().as_ref(),
                *v,
                "{k} unreadable after migration"
            );
        }
    }

    /// After migrating, nothing at the backing store carries a path component —
    /// the point of the exercise.
    #[tokio::test]
    async fn migration_leaves_no_plaintext_key_behind() {
        let (store, _) = legacy_corpus().await;
        store.migrate_from_plaintext().await.unwrap();

        for entry in store.inner.list(Path::new("")).await.unwrap() {
            for part in ["family", "legal", "filing", "notes", "md", "pdf"] {
                assert!(
                    !entry.key.contains(part),
                    "{part:?} still present in stored key {}",
                    entry.key
                );
            }
        }
    }

    /// Re-running is a no-op. This is what makes the pass resumable without a
    /// cursor: the remaining set is the progress record.
    #[tokio::test]
    async fn migration_is_idempotent() {
        let (store, corpus) = legacy_corpus().await;
        assert_eq!(store.migrate_from_plaintext().await.unwrap(), corpus.len());
        assert_eq!(store.migrate_from_plaintext().await.unwrap(), 0);
        assert_eq!(
            store.get(Path::new("notes/a.md")).await.unwrap().as_ref(),
            b"one"
        );
    }

    /// The crash case: a pass interrupted partway, then resumed, loses nothing.
    ///
    /// Simulated by migrating a corpus, adding more legacy objects, and running
    /// again — the store is then in exactly the mixed state an interruption
    /// leaves behind, and the second pass must reconcile it.
    #[tokio::test]
    async fn an_interrupted_migration_resumes_without_loss() {
        let (store, corpus) = legacy_corpus().await;
        store.migrate_from_plaintext().await.unwrap();

        // More objects arrive in the old scheme, as if the first pass had stopped
        // before reaching them.
        store
            .inner
            .put(Path::new("late/c.md"), b"three")
            .await
            .unwrap();

        assert_eq!(
            store.migrate_from_plaintext().await.unwrap(),
            1,
            "only the unmigrated object should move"
        );

        for (k, v) in &corpus {
            assert_eq!(store.get(Path::new(k)).await.unwrap().as_ref(), *v);
        }
        assert_eq!(
            store.get(Path::new("late/c.md")).await.unwrap().as_ref(),
            b"three"
        );
    }

    /// An object present at *both* keys — the state a crash between write and
    /// delete leaves — resolves to the migrated copy and re-migrates cleanly.
    #[tokio::test]
    async fn an_object_at_both_keys_resolves_to_the_blinded_one() {
        let (store, _) = legacy_corpus().await;
        let key = Path::new("notes/a.md");

        // Write the blinded copy without removing the original.
        let blinded = store.blind(key);
        let framed =
            BlindedObjectStorage::<MemoryObjectStorage>::frame("notes/a.md", b"one").unwrap();
        store.inner.put(Path::new(&blinded), &framed).await.unwrap();

        assert_eq!(store.get(key).await.unwrap().as_ref(), b"one");
        store.migrate_from_plaintext().await.unwrap();
        assert_eq!(store.get(key).await.unwrap().as_ref(), b"one");
    }

    // ── loose enumeration ────────────────────────────────────────────────────

    /// The packer's view: logical names, true sizes, reserved keys excluded.
    #[tokio::test]
    async fn list_loose_recovers_names_and_skips_reserved_keys() {
        let s = store();
        s.put(Path::new("notes/a.md"), b"one").await.unwrap();
        s.put(Path::new("family/legal/filing.pdf"), b"sensitive")
            .await
            .unwrap();
        // A pack and a superblock live alongside the loose objects.
        s.put_sealed(Path::new("_pack/deadbeef"), b"not a loose object")
            .await
            .unwrap();
        s.put_sealed(Path::new("_superblock/000-aa"), b"nor this")
            .await
            .unwrap();

        let mut loose = s.list_loose().await.unwrap();
        loose.sort_by(|a, b| a.path.cmp(&b.path));
        let paths: Vec<&str> = loose.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, vec!["family/legal/filing.pdf", "notes/a.md"]);
        assert_eq!(loose[0].size, 9, "size is the caller's data, not the frame");
    }

    /// An unmigrated object must fail enumeration loudly — packing over it
    /// would strand it forever, invisibly.
    #[tokio::test]
    async fn list_loose_refuses_an_unmigrated_store() {
        let (store, _) = legacy_corpus().await;
        let err = store.list_loose().await.unwrap_err();
        assert!(
            err.to_string().contains("blinding migration"),
            "error must point at the fix: {err}"
        );

        // After migration, enumeration works.
        store.migrate_from_plaintext().await.unwrap();
        assert_eq!(store.list_loose().await.unwrap().len(), 3);
    }

    /// Sealed access works in blinded space, so a replicated blob lands under the
    /// same key on both sides and stays readable.
    #[tokio::test]
    async fn sealed_transfer_preserves_the_blinded_key() {
        let a = store();
        let b = store();
        let key = Path::new("notes/a.md");
        a.put(key, b"payload").await.unwrap();

        // Sync sees blinded keys; replicate one verbatim.
        let blinded = a.blind(key);
        let sealed = a.get_sealed(Path::new(&blinded)).await.unwrap();
        b.put_sealed(Path::new(&blinded), &sealed).await.unwrap();

        assert_eq!(b.get(key).await.unwrap().as_ref(), b"payload");
    }
}
