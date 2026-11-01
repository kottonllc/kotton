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
    /// readable objects. The directories the walk descends are the keys the
    /// store itself listed, not a caller's words.
    pub async fn list(&self, prefix: Option<&StorageKey>) -> Result<Vec<(String, u64, Option<u64>)>> {
        let mut out = Vec::new();
        let mut queue: Vec<String> = vec![prefix.map_or_else(String::new, |k| k.as_str().to_string())];
        while let Some(dir) = queue.pop() {
            let entries = self
                .store
                .list_sealed(Path::new(&dir))
                .await
                .with_context(|| {
                    format!("Failed to list sealed on store '{}'", self.store_name)
                })?;
            for m in entries {
                if m.key.ends_with('/') {
                    continue;
                }
                if m.is_dir {
                    queue.push(m.key);
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

    /// A store that answers nothing and records every key it is asked for:
    /// what the sealed view hands a store is exactly what these tests read.
    #[derive(Default)]
    struct Asked(Mutex<Vec<String>>);

    impl Asked {
        fn note(&self, key: &Path) -> ObjectStorageResult<()> {
            self.0.lock().unwrap().push(key.to_string_lossy().into_owned());
            Ok(())
        }
        fn asked(&self) -> Vec<String> {
            self.0.lock().unwrap().clone()
        }
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
            Ok(Vec::new())
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
}
