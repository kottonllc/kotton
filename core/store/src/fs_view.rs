// SPDX-License-Identifier: AGPL-3.0-or-later
//! `Fs` — a path-addressed view of one already-routed store.
//!
//! It lives here, not in `core/fs`: its only caller is this crate's path verbs,
//! and held in `fs` it would be half of a wrong-way dependency — `store` would
//! have to name `kotton-fs` to read a file, which it must not, *so it cannot
//! name a host OS even by accident.*
//!
//! `core/fs` is the host-filesystem domain: its `provider` module implements
//! `kotton_sys::fs::Filesystem` for a real OS and for memory. A handle over an
//! `ObjectStorage` is not that — it is the store's own surface, spelled in paths
//! rather than keys, and it belongs beside the objects it addresses.

use anyhow::{Context as _, Result};
use kotton_schemas::to_object_key;
use std::path::Path;
use kotton_sys::store::ObjectStorage;

/// The `fs` domain over one store.
///
/// Which store a path resolves to is decided before the handle is built
/// — placement is not this domain's business either.
///
/// **A handle may be rooted** at one key prefix, and then every path it is
/// given resolves beneath that prefix and nothing outside it is addressable
/// through it: the path is canonicalised first (`..` is resolved and cannot
/// climb above the path's own root), and only then is the prefix put in front.
/// A listing through a rooted handle answers in the handle's own paths, with
/// the prefix taken off. This is how a person's own tree is kept apart from the
/// daemon's records in one key space ([`crate::runtime::user::PERSON_TREE_ROOT`]).
pub struct Fs<'a> {
    store: &'a dyn ObjectStorage,
    /// The key prefix every path resolves beneath, without slashes; empty for
    /// the store's whole key space.
    root: &'a str,
    /// The store is another door onto the person's tree (a paired peer), so it
    /// is handed the person's path, canonical and absolute, and roots it itself.
    names: bool,
}

impl<'a> Fs<'a> {
    /// Build a handle over an already-routed store, addressing its whole key
    /// space.
    pub fn new(store: &'a dyn ObjectStorage) -> Self {
        Self { store, root: "", names: false }
    }

    /// Build a handle over an already-routed store that addresses only what
    /// lies beneath `root`.
    pub fn rooted(store: &'a dyn ObjectStorage, root: &'a str) -> Self {
        Self { store, root, names: false }
    }

    /// Build a handle over a store that is **another door onto the person's
    /// tree** — a paired peer — rather than a place keys rest.
    ///
    /// It is handed the person's path, canonicalised by the same rule and
    /// spelled absolute (`/notes/a.md`), and applies its own root: the root is
    /// the naming's, and a door that names is given the name, not the key, so
    /// a peer mount never roots a path twice.
    /// A listing answers in the far door's own paths, which are the person's.
    pub fn naming(store: &'a dyn ObjectStorage) -> Self {
        Self { store, root: "", names: true }
    }

    /// What this handle hands its store for `path`: the stored key it names,
    /// or, through a naming door, the person's canonical path.
    pub(crate) fn key(&self, path: &str) -> String {
        if self.names {
            format!("/{}", to_object_key(path))
        } else {
            rooted_key(self.root, path)
        }
    }

    /// Read a file whole.
    pub async fn read(&self, path: &str) -> Result<Vec<u8>> {
        let key = self.key(path);
        let bytes = self
            .store
            .get(Path::new(&key))
            .await
            .with_context(|| format!("Failed to read file '{path}'"))?;
        Ok(bytes.to_vec())
    }

    /// Read `[offset, offset + length)` of a file, and the file's total size.
    ///
    /// The size comes back with the bytes because the caller fetching a file in
    /// ranges needs to know when it has all of it, and asking separately would
    /// be a second round trip against a file that may have changed between the
    /// two.
    pub async fn read_range(
        &self,
        path: &str,
        offset: u64,
        length: u64,
    ) -> Result<(Vec<u8>, u64)> {
        let key = self.key(path);
        let (bytes, total) = self
            .store
            .get_range(Path::new(&key), offset, length)
            .await
            .with_context(|| format!("Failed to read file '{path}'"))?;
        Ok((bytes.to_vec(), total))
    }

    /// Begin writing a file as a stream, or `None` if this store takes objects
    /// whole only.
    ///
    /// The key is canonicalised here, as it is for every other verb — which is
    /// the reason this is a method rather than the caller reaching for the
    /// store: a streamed file must land at the same key its path would have
    /// resolved to, or it becomes a file nothing can name.
    pub async fn begin_write(
        &self,
        path: &str,
    ) -> Result<Option<Box<dyn kotton_sys::store::ObjectSink>>> {
        let key = self.key(path);
        self.store
            .begin_stream(Path::new(&key))
            .await
            .with_context(|| format!("Failed to begin a streaming write of '{path}'"))
    }

    /// Write a file, creating or overwriting it.
    pub async fn write(&self, path: &str, data: &[u8]) -> Result<()> {
        let key = self.key(path);
        self.store
            .put(Path::new(&key), data)
            .await
            .with_context(|| format!("Failed to write file '{path}'"))?;
        Ok(())
    }

    /// Delete a file.
    pub async fn delete(&self, path: &str) -> Result<()> {
        let key = self.key(path);
        self.store
            .delete(Path::new(&key))
            .await
            .with_context(|| format!("Failed to delete file '{path}'"))?;
        Ok(())
    }

    /// Whether a file exists.
    pub async fn exists(&self, path: &str) -> Result<bool> {
        let key = self.key(path);
        self.store
            .exists(Path::new(&key))
            .await
            .with_context(|| format!("Failed to check existence of '{path}'"))
    }

    /// List entries under a prefix.
    ///
    /// Directory entries carry a trailing `/` so a caller can tell them from
    /// files — the store's metadata says which, and the wire format does not.
    pub async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let key = self.key(prefix);
        let entries = self
            .store
            .list(Path::new(&key))
            .await
            .with_context(|| format!("Failed to list files in '{prefix}'"))?;
        let base = if self.root.is_empty() {
            String::new()
        } else {
            format!("{}/", self.root)
        };
        Ok(entries
            .iter()
            // A naming door answers in the person's paths already; the far
            // side took its own root off.
            .map(|m| (m, if self.names { m.key.trim_start_matches('/') } else { m.key.as_str() }))
            // A rooted handle answers in its own paths. The store's listing is
            // by key prefix, so an entry outside the root cannot be asked for —
            // the filter is what keeps a store that over-answers from leaking
            // one, not a second guard on the way in.
            .filter_map(|(m, key)| key.strip_prefix(base.as_str()).map(|k| (m, k)))
            .map(|(m, key)| {
                // A folder the person made is listed as the folder, with the
                // trailing `/` every directory entry carries, never as an
                // entry of its own.
                if let Some(folder) = key.strip_suffix(FOLDER_ENTRY) {
                    if folder.ends_with('/') {
                        return folder.to_string();
                    }
                }
                if m.is_dir && !key.ends_with('/') {
                    format!("{key}/")
                } else {
                    key.to_string()
                }
            })
            .collect())
    }
}

/// The last segment of the key a folder the person made is kept at: the
/// folder's own `.`, so `/notes/trip` made empty rests at `files/notes/trip/.`.
///
/// **A folder is an object in the store, and this is its name.** The store
/// otherwise keeps files, and a directory is a prefix some file lies under —
/// so without this a folder could not be empty: it would last exactly as long
/// as its last file.
///
/// **No path can name it, so nothing has to refuse one.** Every path a person
/// or an app hands the store is canonicalised by `to_object_key`, which drops
/// a `.` segment wherever it stands; so `notes/trip/.` is read, written and
/// deleted as `notes/trip`, and the key below is reachable only through
/// [`folder_key`]. A reserved *name* — `.folder`, say — would have collided
/// with a person's own file of that name and needed a guard on every write to
/// keep it theirs; a segment canonicalisation cannot produce needs none.
///
/// **What a replica sees is what an empty file in that folder looks like.**
/// The blinded layer HMACs `.` chained through the folder's own blinded key
/// like any other segment, so the marker is one more fixed-length
/// opaque name under an opaque prefix, and no two folders' markers blind alike.
pub(crate) const FOLDER_ENTRY: &str = ".";

/// The stored key a folder made at `dir_key` (already a stored key, from
/// [`Fs::key`]) is kept at. See [`FOLDER_ENTRY`].
pub(crate) fn folder_key(dir_key: &str) -> String {
    let dir = dir_key.trim_end_matches('/');
    if dir.is_empty() {
        FOLDER_ENTRY.to_string()
    } else {
        format!("{dir}/{FOLDER_ENTRY}")
    }
}

/// The stored key `path` names beneath `root` — `to_object_key(path)` with
/// `root/` in front, or `root` itself for the root's own path. `root` empty is
/// the store's whole key space.
///
/// **Canonicalised before it is prefixed**, so no path can name a key outside
/// `root`: `to_object_key` resolves every `..` (and reads `\` as a separator)
/// against the path's own root, where there is nothing above to climb to.
pub(crate) fn rooted_key(root: &str, path: &str) -> String {
    let key = to_object_key(path);
    match (root.is_empty(), key.is_empty()) {
        (true, _) => key,
        (false, true) => root.to_string(),
        (false, false) => format!("{root}/{key}"),
    }
}
