// SPDX-License-Identifier: AGPL-3.0-or-later
//! Sealed replication — moving ciphertext between stores.
//!
//! These are **not** file operations (RFC-0041). They bind to a store's sealed
//! view, so a pass can move objects between nodes without either side
//! materialising plaintext — which is what lets a node whose posture withholds
//! the data keys hold bytes it cannot open.
//!
//! That is also why this handle addresses a **named store** while
//! `kotton_fs::Fs` does not: replication legitimately says *which* store, and
//! RFC-0058 exempts it for exactly that reason. The invariant it preserves is
//! that anything naming a store sees only ciphertext, and anything seeing
//! plaintext names only paths.

use anyhow::{Context, Result};
use kotton_sys::store::{SealedObjectAccess, StorageKey};
use std::path::Path;

/// One store's sealed view.
///
/// **Every key it is handed is already admitted.** [`read`](Self::read),
/// [`write`](Self::write) and [`list`](Self::list) take a [`StorageKey`],
/// which only `StorageKey::parse` builds, so there is no `&str` door here
/// that rewrites a key into a different one (kotton #275, #320). A `../x`
/// cannot be asked of it: the caller that holds the text is the one that
/// parses it, and is refused there.
///
/// It takes the key a caller admitted:
///
/// ```no_run
/// # async fn f(sealed: kotton_sealed::Sealed<'_>) -> anyhow::Result<()> {
/// let key = kotton_sys::store::StorageKey::parse("x")?;
/// sealed.list(Some(&key)).await?;
/// # Ok(())
/// # }
/// ```
///
/// and not a string, so a `../x` does not compile:
///
/// ```compile_fail
/// # async fn f(sealed: kotton_sealed::Sealed<'_>) -> anyhow::Result<()> {
/// sealed.list(Some("../x")).await?;
/// # Ok(())
/// # }
/// ```
pub struct Sealed<'a> {
    store: &'a dyn SealedObjectAccess,
    /// Retained for error messages: a replication failure is unreadable without
    /// knowing which side it happened on.
    store_name: &'a str,
}

impl<'a> Sealed<'a> {
    pub fn new(store: &'a dyn SealedObjectAccess, store_name: &'a str) -> Self {
        Self { store, store_name }
    }

    /// Read an object exactly as it rests — ciphertext, never opened.
    pub async fn read(&self, key: &StorageKey) -> Result<Vec<u8>> {
        let blob = self
            .store
            .get_sealed(key.as_path())
            .await
            .with_context(|| {
                format!(
                    "Failed to read sealed object '{key}' from store '{}'",
                    self.store_name
                )
            })?;
        Ok(blob.to_vec())
    }

    /// Store bytes verbatim, without sealing them — they already are.
    pub async fn write(&self, key: &StorageKey, blob: &[u8]) -> Result<()> {
        self.store
            .put_sealed(key.as_path(), blob)
            .await
            .with_context(|| {
                format!(
                    "Failed to write sealed object '{key}' to store '{}'",
                    self.store_name
                )
            })
    }

    /// Every object under `prefix` — the store's root when `None` — at any
    /// depth, as `(key, size, modified)`.
    ///
    /// **Leaves only, and the walk happens here.** A filesystem backend lists
    /// one level and reports subdirectories as `is_dir`, but the wire format
    /// carries no `is_dir` — so a remote caller cannot descend, and a version
    /// that filtered directories out without descending them hid every nested
    /// object from a peer. The pull half of sync looked complete while silently
    /// missing everything below the top level.
    ///
    /// Directory-marker keys (trailing `/`) are skipped; they are never
    /// readable objects.
    ///
    /// **A directory is descended only once admitted** (kotton #336). The
    /// keys the walk descends are the ones the store listed, and a listing is
    /// what the store's contents spell: a filesystem store rebuilds each key
    /// from a file's name, decoding `%2F` to `/`, so a directory named
    /// `..%2Fx` is listed as `../x`, and a bucket's keys are whatever was
    /// written to it. Neither is a reason to trust the listing, so each
    /// directory key is parsed into a [`StorageKey`] where the listing enters
    /// the walk, and the store is asked to list only its root or an admitted
    /// key. One that is not canonical is skipped, not a refusal of the whole
    /// listing, as a sync pass skips the keys it refuses: nothing under it is
    /// listed, every canonical object is still returned, and the refusal is
    /// named in the log with the store. It is not counted in the answer:
    /// the wire's `SealedList` has no field to carry a count to the reader.
    ///
    /// A leaf's key is returned as the store spelled it. Nothing here reads
    /// or writes it; every caller that does admits it where this listing
    /// enters it (a sync pass, a drive move), so a second admission here
    /// would be a second guard on the same key.
    pub async fn list(&self, prefix: Option<&StorageKey>) -> Result<Vec<(String, u64, Option<u64>)>> {
        let mut out = Vec::new();
        let mut queue: Vec<Option<StorageKey>> = vec![prefix.cloned()];
        while let Some(dir) = queue.pop() {
            let entries = self
                .store
                .list_sealed(dir.as_ref().map_or(Path::new(""), StorageKey::as_path))
                .await
                .with_context(|| {
                    format!("Failed to list sealed on store '{}'", self.store_name)
                })?;
            for m in entries {
                if m.key.ends_with('/') {
                    continue;
                }
                if m.is_dir {
                    match StorageKey::parse(&m.key) {
                        Ok(key) => queue.push(Some(key)),
                        Err(refused) => tracing::warn!(
                            store = self.store_name,
                            "sealed list: {refused}; the directory is not descended"
                        ),
                    }
                } else {
                    out.push((m.key, m.size, m.modified));
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use bytes::Bytes;
    use futures::executor::block_on;
    use kotton_sys::store::{ObjectMetadata, ObjectStorage, ObjectStorageError, ObjectStorageResult};
    use std::sync::Mutex;

    /// A store that records every key it is asked for, and lists, for a
    /// prefix, the entries it was given for it (nothing otherwise): what the
    /// sealed view hands a store is exactly what these tests read.
    #[derive(Default)]
    struct Asked {
        asked: Mutex<Vec<String>>,
        listing: Vec<(&'static str, Vec<ObjectMetadata>)>,
    }

    impl Asked {
        fn note(&self, key: &Path) -> ObjectStorageResult<()> {
            self.asked.lock().unwrap().push(key.to_string_lossy().into_owned());
            Ok(())
        }
        fn asked(&self) -> Vec<String> {
            self.asked.lock().unwrap().clone()
        }
    }

    fn dir(key: &str) -> ObjectMetadata {
        ObjectMetadata { key: key.into(), is_dir: true, size: 0, modified: None }
    }

    fn leaf(key: &str, size: u64) -> ObjectMetadata {
        ObjectMetadata { key: key.into(), is_dir: false, size, modified: Some(7) }
    }

    #[async_trait]
    impl ObjectStorage for Asked {
        async fn get(&self, key: &Path) -> ObjectStorageResult<Bytes> {
            Err(ObjectStorageError::NotFound(key.display().to_string()))
        }
        async fn put(&self, _: &Path, _: &[u8]) -> ObjectStorageResult<()> {
            unreachable!("the sealed view writes through `put_sealed`")
        }
        async fn delete(&self, _: &Path) -> ObjectStorageResult<()> {
            unreachable!("the sealed view deletes nothing")
        }
        async fn list(&self, _: &Path) -> ObjectStorageResult<Vec<ObjectMetadata>> {
            unreachable!("the sealed view lists through `list_sealed`")
        }
        async fn metadata(&self, key: &Path) -> ObjectStorageResult<ObjectMetadata> {
            Err(ObjectStorageError::NotFound(key.display().to_string()))
        }
        fn backend_name(&self) -> &str {
            "asked"
        }
    }

    #[async_trait]
    impl SealedObjectAccess for Asked {
        async fn get_sealed(&self, key: &Path) -> ObjectStorageResult<Bytes> {
            self.note(key)?;
            Ok(Bytes::new())
        }
        async fn put_sealed(&self, key: &Path, _: &[u8]) -> ObjectStorageResult<()> {
            self.note(key)
        }
        async fn list_sealed(&self, prefix: &Path) -> ObjectStorageResult<Vec<ObjectMetadata>> {
            self.note(prefix)?;
            let prefix = prefix.to_string_lossy();
            Ok(self.listing.iter().find(|(p, _)| *p == prefix).map(|(_, l)| l.clone()).unwrap_or_default())
        }
    }

    /// A store is asked for the key the caller admitted, as it is, and the
    /// root is the empty prefix. `../x` cannot be asked: there is no
    /// `StorageKey` for it to pass (the `compile_fail` example on [`Sealed`]
    /// shows a string is not taken), so the store hears nothing of it.
    #[test]
    fn the_store_is_asked_only_for_admitted_keys() {
        let store = Asked::default();
        let sealed = Sealed::new(&store, "asked");
        let x = StorageKey::parse("x").unwrap();

        block_on(sealed.list(None)).unwrap();
        block_on(sealed.list(Some(&x))).unwrap();
        block_on(sealed.read(&x)).unwrap();
        block_on(sealed.write(&x, b"sealed")).unwrap();
        assert_eq!(store.asked(), ["", "x", "x", "x"]);

        let refused = StorageKey::parse("../x").unwrap_err();
        assert_eq!(refused.to_string(), "storage key \"../x\" refused: a component is `.` or `..`");
        assert_eq!(store.asked().len(), 4, "a refused key reached the store");
    }

    /// **The walk descends only into directory keys it admitted** (kotton
    /// #336). A filesystem store rebuilds each key from a file's name,
    /// decoding `%2F` to `/`, so a directory named `..%2Fx` is listed as
    /// `../x`. The walk refuses it where the listing enters, before it asks
    /// the store for anything under it, and returns everything else: the
    /// root's leaf and the leaf under the canonical directory `a`.
    #[test]
    fn a_listed_directory_that_is_not_canonical_is_not_descended() {
        let store = Asked {
            listing: vec![
                ("", vec![dir("../x"), leaf("top", 3), dir("a")]),
                ("a", vec![leaf("a/b", 5)]),
                ("../x", vec![leaf("../x/served", 6)]),
            ],
            ..Asked::default()
        };
        let listed = block_on(Sealed::new(&store, "asked").list(None)).unwrap();

        assert_eq!(store.asked(), ["", "a"], "the store was asked under a directory key that is not canonical");
        let mut listed: Vec<_> = listed.into_iter().map(|(k, size, _)| (k, size)).collect();
        listed.sort();
        assert_eq!(listed, [("a/b".to_string(), 5), ("top".to_string(), 3)]);
    }
}
