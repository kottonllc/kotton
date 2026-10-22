// SPDX-License-Identifier: AGPL-3.0-or-later
//! Sealed replication — moving ciphertext between stores.
//!
//! These are **not** file operations (RFC-0041). They bind to a store's sealed
//! view, so a pass can move objects between nodes without either side
//! materialising plaintext — which is what lets a node whose posture withholds
//! the data keys hold bytes it cannot open.
//!
//! That is also why this handle addresses a **named store** while
//! [`kotton_fs::Fs`] does not: replication legitimately says *which* store, and
//! RFC-0058 exempts it for exactly that reason. The invariant it preserves is
//! that anything naming a store sees only ciphertext, and anything seeing
//! plaintext names only paths.

use anyhow::{Context, Result};
use kotton_schemas::to_object_key;
use kotton_sys::store::SealedObjectAccess;
use std::path::Path;

/// One store's sealed view.
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
    pub async fn read(&self, path: &str) -> Result<Vec<u8>> {
        let key = to_object_key(path);
        let blob = self
            .store
            .get_sealed(Path::new(&key))
            .await
            .with_context(|| {
                format!(
                    "Failed to read sealed object '{path}' from store '{}'",
                    self.store_name
                )
            })?;
        Ok(blob.to_vec())
    }

    /// Store bytes verbatim, without sealing them — they already are.
    pub async fn write(&self, path: &str, blob: &[u8]) -> Result<()> {
        let key = to_object_key(path);
        self.store
            .put_sealed(Path::new(&key), blob)
            .await
            .with_context(|| {
                format!(
                    "Failed to write sealed object '{path}' to store '{}'",
                    self.store_name
                )
            })
    }

    /// Every object under a prefix, at any depth, as `(key, size, modified)`.
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
    pub async fn list(&self, prefix: &str) -> Result<Vec<(String, u64, Option<u64>)>> {
        let mut out = Vec::new();
        let mut queue: Vec<String> = vec![to_object_key(prefix)];
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
