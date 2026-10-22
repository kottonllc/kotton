// SPDX-License-Identifier: AGPL-3.0-or-later
//! The quarantine namespace — a fetcher's landing zone (RFC-0049; Sprint 03
//! Phase 3).
//!
//! A fetcher pulls content from the internet and has to put it *somewhere* the
//! user can later promote into their real store. That somewhere cannot be the
//! VFS, for two reasons that point in opposite directions:
//!
//! - **Confidentiality.** A fetcher holds the network. If it could read the
//!   user's files it would be the forbidden corner — read-user-data AND egress
//!   in one domain — and could put anything it read into a URL.
//! - **Integrity.** Even blind, a fetcher that could *write* anywhere in `home/`
//!   would let a hostile server's bytes overwrite the user's data. It could not
//!   steal your notes, but it could destroy them.
//!
//! Quarantine closes both: an extension may **write** into its own namespace and
//! **read back only what it itself wrote**, and can reach nothing else. Getting
//! content out of quarantine and into the user's tree is **promotion**, an act
//! the fetcher holds no capability to perform — it is done by the user, or later
//! by a no-network apply stage (`RFC-0051`).
//!
//! Read-own is enforced structurally rather than by bookkeeping: the namespace
//! is keyed by extension id (`system/extensions/<id>/quarantine/`), so "keys
//! this extension wrote" and "keys under this extension's prefix" are the same
//! set. There is no per-key writer table to get out of sync, and the guest never
//! supplies the id — it comes from the verified install.
//!

use std::path::Path;
use std::sync::Arc;

use kotton_schemas::{CapabilityKind, CapabilitySet, CapabilityTarget};
use kotton_sys::store::{ObjectStorage, ObjectStorageError};
use thiserror::Error;

/// Reserved VFS prefix under which every extension's quarantine lives.
pub const QUARANTINE_ROOT: &str = "system/extensions";

/// Largest single quarantined object.
///
/// Bounds one hostile response; RFC-0048's `RANGE_LEN`, the chunk size the rest
/// of the system moves bytes in. A fetcher needing more must range it into
/// several keys, which keeps any single write bounded.
pub const MAX_OBJECT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum QuarantineError {
    #[error("extension `{0}` holds no quarantine grant")]
    NotGranted(String),
    #[error("quarantine key is invalid: {0}")]
    InvalidKey(String),
    #[error("object exceeds {MAX_OBJECT_BYTES} bytes")]
    TooLarge,
    #[error("not found: {0}")]
    NotFound(String),
    #[error("storage error: {0}")]
    Storage(String),
}

pub type QuarantineResult<T> = Result<T, QuarantineError>;

/// One extension's view of its quarantine namespace.
///
/// Constructed by the host after the extension's grants are checked; every
/// method re-checks the grant, so holding the handle is not itself authority.
pub struct Quarantine {
    extension_id: String,
    grants: CapabilitySet,
    store: Arc<dyn ObjectStorage>,
}

impl Quarantine {
    pub fn new(
        extension_id: impl Into<String>,
        grants: CapabilitySet,
        store: Arc<dyn ObjectStorage>,
    ) -> Self {
        Self {
            extension_id: extension_id.into(),
            grants,
            store,
        }
    }

    fn target(&self) -> CapabilityTarget {
        CapabilityTarget::Quarantine {
            extension_id: self.extension_id.clone(),
        }
    }

    fn check(&self, kind: CapabilityKind) -> QuarantineResult<()> {
        if self.grants.allows(&kind, &self.target()) {
            Ok(())
        } else {
            Err(QuarantineError::NotGranted(self.extension_id.clone()))
        }
    }

    /// This extension's namespace prefix. Read-own falls out of this: the guest
    /// never names a key outside it, so "what I wrote" and "what is under my
    /// prefix" are the same set.
    fn prefix(&self) -> String {
        format!("{QUARANTINE_ROOT}/{}/quarantine/", self.extension_id)
    }

    /// Map a guest-supplied relative key into this extension's namespace.
    ///
    /// The guest's key is untrusted input, so this rejects anything that could
    /// escape the prefix or collide with another extension's namespace, rather
    /// than normalizing it into something valid. Refusing beats repairing: a
    /// fetcher that meant `../other/secret` has no legitimate reading.
    fn resolve(&self, key: &str) -> QuarantineResult<String> {
        if key.is_empty() {
            return Err(QuarantineError::InvalidKey("empty".into()));
        }
        if key.len() > 512 {
            return Err(QuarantineError::InvalidKey("too long".into()));
        }
        if key.starts_with('/') || key.starts_with('\\') {
            return Err(QuarantineError::InvalidKey(format!("not relative: {key}")));
        }
        // `..` in any position, either separator, and backslashes generally —
        // the store is `/`-keyed, so a backslash is either an escape attempt or
        // a Windows path leaking in.
        if key.contains("..") || key.contains('\\') || key.contains('\0') {
            return Err(QuarantineError::InvalidKey(format!(
                "may not contain `..`, `\\`, or NUL: {key}"
            )));
        }
        Ok(format!("{}{}", self.prefix(), key))
    }

    /// Write external content into this extension's quarantine.
    pub async fn write(&self, key: &str, content: &[u8]) -> QuarantineResult<()> {
        self.check(CapabilityKind::Write)?;
        if content.len() > MAX_OBJECT_BYTES {
            return Err(QuarantineError::TooLarge);
        }
        let full = self.resolve(key)?;
        self.store
            .put(Path::new(&full), content)
            .await
            .map_err(|e| QuarantineError::Storage(format!("{e}")))?;
        tracing::debug!(
            extension = %self.extension_id,
            key,
            bytes = content.len(),
            "quarantine write"
        );
        Ok(())
    }

    /// Read back something this extension wrote.
    ///
    /// This is what makes incremental fetch work — cursors, etags, feed
    /// positions — without a single bit flowing from the user's side.
    pub async fn read_own(&self, key: &str) -> QuarantineResult<Vec<u8>> {
        self.check(CapabilityKind::Read)?;
        let full = self.resolve(key)?;
        match self.store.get(Path::new(&full)).await {
            Ok(bytes) => Ok(bytes.to_vec()),
            Err(ObjectStorageError::NotFound(_)) => Err(QuarantineError::NotFound(key.to_string())),
            Err(e) => Err(QuarantineError::Storage(format!("{e}"))),
        }
    }

    /// List this extension's own keys under `prefix`, returned relative to the
    /// namespace so the guest never learns its absolute location.
    pub async fn list_own(&self, prefix: &str) -> QuarantineResult<Vec<String>> {
        self.check(CapabilityKind::Read)?;
        let base = self.prefix();
        let full_prefix = if prefix.is_empty() {
            base.clone()
        } else {
            self.resolve(prefix)?
        };
        let entries = self
            .store
            .list(Path::new(&full_prefix))
            .await
            .map_err(|e| QuarantineError::Storage(format!("{e}")))?;
        Ok(entries
            .into_iter()
            .filter(|e| !e.is_dir)
            .filter_map(|e| e.key.strip_prefix(&base).map(str::to_string))
            .collect())
    }

    /// Absolute key for a quarantined object — for the **host** to resolve when
    /// promoting content into the user's tree. Never handed to the guest.
    pub fn absolute_key(&self, key: &str) -> QuarantineResult<String> {
        self.resolve(key)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use kotton_schemas::CapabilityGrant;
    use kotton_store::MemoryObjectStorage;

    fn grants_for(id: &str) -> CapabilitySet {
        let target = CapabilityTarget::Quarantine {
            extension_id: id.to_string(),
        };
        CapabilitySet::new(vec![
            CapabilityGrant {
                kind: CapabilityKind::Write,
                target: target.clone(),
            },
            CapabilityGrant {
                kind: CapabilityKind::Read,
                target,
            },
        ])
    }

    fn quarantine_for(id: &str, store: Arc<dyn ObjectStorage>) -> Quarantine {
        Quarantine::new(id, grants_for(id), store)
    }

    #[tokio::test]
    async fn a_fetcher_writes_and_reads_back_its_own_content() {
        let store = Arc::new(MemoryObjectStorage::new());
        let q = quarantine_for("sh.kotton.feed-reader", store);

        q.write("feed.xml", b"<rss/>").await.unwrap();
        assert_eq!(q.read_own("feed.xml").await.unwrap(), b"<rss/>");

        // The incremental-fetch pattern: state derived from external data,
        // kept on the fetcher's own side of the wall.
        q.write("state/etag", b"W/\"abc123\"").await.unwrap();
        assert_eq!(q.read_own("state/etag").await.unwrap(), b"W/\"abc123\"");
    }

    #[tokio::test]
    async fn one_extension_cannot_reach_another_extensions_quarantine() {
        let store: Arc<dyn ObjectStorage> = Arc::new(MemoryObjectStorage::new());
        let mine = quarantine_for("sh.kotton.mine", store.clone());
        let theirs = quarantine_for("sh.kotton.theirs", store.clone());

        theirs.write("secret.txt", b"theirs").await.unwrap();

        // Same relative key, different namespace: I get my own miss, not their hit.
        let err = mine.read_own("secret.txt").await.unwrap_err();
        assert!(matches!(err, QuarantineError::NotFound(_)), "got: {err}");

        // And I cannot climb into theirs by naming it.
        for escape in [
            "../sh.kotton.theirs/quarantine/secret.txt",
            "..\\sh.kotton.theirs\\quarantine\\secret.txt",
            "/system/extensions/sh.kotton.theirs/quarantine/secret.txt",
        ] {
            let err = mine.read_own(escape).await.unwrap_err();
            assert!(
                matches!(err, QuarantineError::InvalidKey(_)),
                "`{escape}` must be refused outright, got: {err}"
            );
        }
    }

    /// The integrity half: a fetcher's writes land in quarantine and nowhere
    /// else, so a hostile server's bytes can never overwrite the user's data.
    #[tokio::test]
    async fn writes_cannot_escape_the_namespace() {
        let store: Arc<dyn ObjectStorage> = Arc::new(MemoryObjectStorage::new());
        let q = quarantine_for("sh.kotton.feed-reader", store.clone());

        for escape in [
            "../../../home/notes/todo.md",
            "/home/notes/todo.md",
            "..",
            "a/../../b",
        ] {
            assert!(
                q.write(escape, b"evil").await.is_err(),
                "`{escape}` must not be writable"
            );
        }

        // Everything that did land is under this extension's prefix.
        q.write("ok.txt", b"fine").await.unwrap();
        let all = store.list(Path::new("")).await.unwrap();
        let files: Vec<_> = all.into_iter().filter(|e| !e.is_dir).collect();
        assert!(!files.is_empty(), "the legitimate write should be present");
        for entry in files {
            assert!(
                entry
                    .key
                    .starts_with("system/extensions/sh.kotton.feed-reader/quarantine/"),
                "stray key outside the namespace: {}",
                entry.key
            );
        }
    }

    #[tokio::test]
    async fn without_the_grant_nothing_works() {
        let store = Arc::new(MemoryObjectStorage::new());
        // A handle is not authority: same id, empty grant set.
        let q = Quarantine::new("sh.kotton.feed-reader", CapabilitySet::default(), store);

        assert!(matches!(
            q.write("a.txt", b"x").await.unwrap_err(),
            QuarantineError::NotGranted(_)
        ));
        assert!(matches!(
            q.read_own("a.txt").await.unwrap_err(),
            QuarantineError::NotGranted(_)
        ));
        assert!(matches!(
            q.list_own("").await.unwrap_err(),
            QuarantineError::NotGranted(_)
        ));
    }

    #[tokio::test]
    async fn listing_is_relative_and_scoped() {
        let store: Arc<dyn ObjectStorage> = Arc::new(MemoryObjectStorage::new());
        let mine = quarantine_for("sh.kotton.mine", store.clone());
        let theirs = quarantine_for("sh.kotton.theirs", store.clone());

        mine.write("a.xml", b"1").await.unwrap();
        mine.write("nested/b.xml", b"2").await.unwrap();
        theirs.write("c.xml", b"3").await.unwrap();

        let mut listed = mine.list_own("").await.unwrap();
        listed.sort();
        assert_eq!(listed, vec!["a.xml", "nested/b.xml"]);
        assert!(
            !listed.iter().any(|k| k.contains("system/extensions")),
            "the guest must not learn its absolute location: {listed:?}"
        );
    }

    #[tokio::test]
    async fn an_oversized_object_is_refused() {
        let store = Arc::new(MemoryObjectStorage::new());
        let q = quarantine_for("sh.kotton.feed-reader", store);
        let huge = vec![0u8; MAX_OBJECT_BYTES + 1];
        assert!(matches!(
            q.write("big.bin", &huge).await.unwrap_err(),
            QuarantineError::TooLarge
        ));
    }
}
