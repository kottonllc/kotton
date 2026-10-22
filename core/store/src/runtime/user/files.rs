// SPDX-License-Identifier: AGPL-3.0-or-later
//! Virtual File System (VFS) operations for UserRuntime
//!
//! Provides file operations that work across remote storage backends using the ObjectStorage abstraction.
//! Files are stored as objects in the underlying storage backend (local, S3, IPFS, etc.).

use super::UserStore;
use anyhow::{anyhow, Result};
use crate::fs_view::rooted_key;
use crate::Fs;
use kotton_sealed::Sealed;

/// The key prefix a person's own tree lives under in their store.
///
/// **Every path a person or an app names is a path in this tree**, and
/// resolves beneath this prefix: `/notes/a.md` is the object `files/notes/a.md`.
/// The daemon keeps its own records — the membership set at
/// `network/members/`, read marks at `messages/read/` — in the same store,
/// sealed and synced the same way, but at keys outside this prefix, and the
/// only verbs that reach them are [`UserStore::write_daemon_object`] and its
/// three siblings, which no person-facing door calls.
///
/// **Why a prefix, and why this direction.** If the person's tree *were* the
/// store's key space, a `files.write` grant on `/` — the one the shell holds —
/// would reach `network/members/`, and an app could write an own-device member
/// record that the daemon then projects into the paired-key allowlist. A
/// refusal of `/network` in the `files` door would have been a check made
/// necessary by the records being reachable; this makes them unreachable. The
/// person's tree moved rather than the daemon's records, because records that
/// fail to be found unpair a person's devices, while files written before the
/// prefix existed are still in the store to be adopted; such a file is outside
/// the person's tree until it is.
pub const PERSON_TREE_ROOT: &str = "files";

/// The stored key a path in the person's tree names.
fn person_key(path: &str) -> String {
    rooted_key(PERSON_TREE_ROOT, path)
}

// Used only by the `test-support` methods below, which address a store directly
// and so must canonicalise the key themselves rather than going through `Fs`.
#[cfg(feature = "test-support")]
use anyhow::Context;
#[cfg(feature = "test-support")]
use std::path::Path;

/// One immediate child of a directory in a person's tree, as
/// [`UserStore::list_children`] answers it.
///
/// A directory is a prefix some file lies under, or a folder the person made
/// ([`UserStore::create_dir`]), which the store keeps as an object of its own
/// so that it can be empty. Either way it has no size and no time of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirChild {
    /// The child's own name — one segment, no slash.
    pub name: String,
    /// Whether the child is a directory.
    pub is_dir: bool,
    /// The file's length in bytes; `0` for a directory.
    pub size: u64,
    /// When the file was last written, seconds since the Unix epoch, where the
    /// store records it; `None` for a directory.
    pub modified: Option<u64>,
}

/// What a path names in a person's tree, as [`UserStore::path_kind`] answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    /// An object is stored at this path.
    File,
    /// At least one object lies beneath this path — a file, or the folder's
    /// own entry when the person made it — or it is the root.
    Dir,
}

/// File metadata for VFS operations (not yet constructed)
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub path: String,
    pub size: u64,
    pub created_at: std::time::SystemTime,
    pub modified_at: std::time::SystemTime,
}

impl UserStore {
    /// Write a file to a specific storage mount
    ///
    /// # Arguments
    /// * `mount_name` - Name of the storage mount (e.g., "local", "s3-backup")
    /// * `path` - File path (e.g., "/documents/note.txt")
    /// * `data` - File contents as bytes
    ///
    /// # Example
    /// ```no_run
    /// # use kotton_store::runtime::user::UserStore;
    /// # async fn example(store: &UserStore) -> anyhow::Result<()> {
    /// store.write_file("/documents/hello.txt", b"Hello, world!").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn write_file(&self, path: &str, data: &[u8]) -> Result<()> {
        self.person_door(path).fs().write(path, data).await
    }

    /// List a mount in **storage-key space** — the opaque stored keys
    /// replication addresses, not the caller's logical paths.
    ///
    /// Returns **leaves only, at every depth**. A filesystem backend lists one
    /// directory level and reports subdirectories as `is_dir` entries, but the
    /// wire format (`SealedListEntry`) carries no `is_dir`, so a remote caller
    /// cannot descend — the walk has to happen here, on the side that can. An
    /// earlier version filtered directory entries out without descending them,
    /// which hid every nested object from a peer's view: the pull half of sync
    /// looked complete while silently missing everything below the top level.
    /// Directory-marker keys (trailing `/`) are skipped — never readable
    /// objects.
    pub async fn list_sealed(
        &self,
        mount_name: &str,
        prefix: &str,
    ) -> Result<Vec<(String, u64, Option<u64>)>> {
        let storage = self
            .get_remote(mount_name)
            .ok_or_else(|| anyhow!("Remote '{mount_name}' not found"))?;
        Sealed::new(storage.as_ref(), mount_name).list(prefix).await
    }

    /// Write plaintext to a **named** store, bypassing path routing.
    ///
    /// **Compiled only under the `test-support` feature.** A production build of
    /// `kuserd` or `kotton-cli` does not contain it, so the invariant below is
    /// not merely a convention they are asked to respect.
    ///
    /// Deliberately absent from the protocol. The invariant the IPC surface
    /// holds is that **anything addressing a store sees only
    /// ciphertext, and anything seeing plaintext addresses only paths** — so
    /// `WriteSealed` names a store and takes a blob, while `WriteFile` takes a
    /// path and no store.
    ///
    /// This grants nothing new: `UserRuntime` already holds every key and every
    /// store. It exists for in-process callers — chiefly tests staging a
    /// two-store scenario — that would otherwise need a protocol verb breaking
    /// that invariant.
    #[cfg(feature = "test-support")]
    pub async fn write_file_to(&self, mount_name: &str, path: &str, data: &[u8]) -> Result<()> {
        let storage = self
            .get_remote(mount_name)
            .ok_or_else(|| anyhow!("Remote '{mount_name}' not found"))?;
        let object_key = person_key(path);
        storage
            .put(Path::new(&object_key), data)
            .await
            .with_context(|| format!("Failed to write '{path}' to store '{mount_name}'"))?;
        Ok(())
    }

    /// Read plaintext from a **named** store. Counterpart to
    /// `write_file_to`; the same reasoning and the same feature gate apply.
    #[cfg(feature = "test-support")]
    pub async fn read_file_from(&self, mount_name: &str, path: &str) -> Result<Vec<u8>> {
        let storage = self
            .get_remote(mount_name)
            .ok_or_else(|| anyhow!("Remote '{mount_name}' not found"))?;
        let object_key = person_key(path);
        let bytes = storage
            .get(Path::new(&object_key))
            .await
            .with_context(|| format!("Failed to read '{path}' from store '{mount_name}'"))?;
        Ok(bytes.to_vec())
    }

    /// Read an object as a **sealed blob** — the bytes as they rest, with no
    /// decryption.
    ///
    /// This is the read half of replication. It addresses the blob by its
    /// storage key as given — the VFS methods add [`PERSON_TREE_ROOT`] to a
    /// person's path first; this one does not — which is what lets the
    /// `path_aad` binding survive a transfer: the same key on the far side still
    /// opens, and a relocated one does not.
    pub async fn read_sealed(&self, mount_name: &str, path: &str) -> Result<Vec<u8>> {
        let storage = self
            .get_remote(mount_name)
            .ok_or_else(|| anyhow!("Remote '{mount_name}' not found"))?;
        Sealed::new(storage.as_ref(), mount_name).read(path).await
    }

    /// Write a **sealed blob** verbatim — no sealing is applied.
    ///
    /// `blob` must be an envelope produced by [`read_sealed`] on a store in the
    /// same key domain. Writing bytes that are not a valid envelope does not
    /// corrupt anything else: the object simply fails to open on read, because
    /// the DEK unwrap and the AEAD open both fail closed.
    ///
    /// [`read_sealed`]: UserRuntime::read_sealed
    pub async fn write_sealed(&self, mount_name: &str, path: &str, blob: &[u8]) -> Result<()> {
        let storage = self
            .get_remote(mount_name)
            .ok_or_else(|| anyhow!("Remote '{mount_name}' not found"))?;
        Sealed::new(storage.as_ref(), mount_name).write(path, blob).await
    }

    /// Read a file from a specific storage mount
    ///
    /// # Arguments
    /// * `mount_name` - Name of the storage mount
    /// * `path` - File path
    ///
    /// # Returns
    /// File contents as bytes
    ///
    /// # Example
    /// ```no_run
    /// # use kotton_store::runtime::user::UserStore;
    /// # async fn example(store: &UserStore) -> anyhow::Result<()> {
    /// let contents = store.read_file("/documents/hello.txt").await?;
    /// println!("{}", String::from_utf8_lossy(&contents));
    /// # Ok(())
    /// # }
    /// ```
    pub async fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        self.person_door(path).fs().read(path).await
    }

    /// Read `[offset, offset + length)` of a file, and the file's total size.
    ///
    /// What a caller reading a large file in ranges should use. `read_file`
    /// returns the whole thing, so serving N ranges through it costs N whole
    /// reads — a quadratic cost, measured on a model larger than the store
    /// would seal. Where the
    /// store keeps a file as packed chunks this reads only the chunks the range
    /// touches; where it does not, it is exactly `read_file` plus a slice,
    /// which is what a single-envelope object permits.
    pub async fn read_file_range(
        &self,
        path: &str,
        offset: u64,
        length: u64,
    ) -> Result<(Vec<u8>, u64)> {
        self.person_door(path).fs().read_range(path, offset, length).await
    }

    /// Begin writing a file as a stream, or `None` from a store that can only
    /// take an object whole.
    ///
    /// `write_file` takes a `&[u8]`, so the largest file it can accept is
    /// bounded by what the caller can hold in memory — the ceiling that stood
    /// between a person and a model of their own. A sink takes the bytes as
    /// they arrive and seals them as they land.
    ///
    /// **Nothing appears at `path` until the sink commits.** That is what lets
    /// the caller hash the stream as it feeds it and refuse at the end without
    /// having published anything, which is where the integrity gate belongs —
    /// with whoever declared the hash.
    pub async fn begin_file_write(
        &self,
        path: &str,
    ) -> Result<Option<Box<dyn kotton_sys::store::ObjectSink>>> {
        self.person_door(path).fs().begin_write(path).await
    }

    /// Delete a file from a specific storage mount
    ///
    /// # Arguments
    /// * `mount_name` - Name of the storage mount
    /// * `path` - File path
    pub async fn delete_file(&self, path: &str) -> Result<()> {
        self.person_door(path).fs().delete(path).await
    }

    /// Check if a file exists in a specific storage mount
    ///
    /// # Arguments
    /// * `mount_name` - Name of the storage mount
    /// * `path` - File path
    pub async fn file_exists(&self, mount_name: &str, path: &str) -> Result<bool> {
        let storage = self
            .get_remote(mount_name)
            .ok_or_else(|| anyhow!("Remote '{mount_name}' not found"))?;
        match self.addressing_of(mount_name) {
            crate::runtime::router::Addressing::Keys => {
                Fs::rooted(storage.as_ref(), PERSON_TREE_ROOT).exists(path).await
            }
            crate::runtime::router::Addressing::Names => {
                Fs::naming(storage.as_ref()).exists(path).await
            }
        }
    }

    /// List all files in a directory (prefix) on a specific storage mount
    ///
    /// # Arguments
    /// * `mount_name` - Name of the storage mount
    /// * `prefix` - Directory path prefix (e.g., "/documents/")
    ///
    /// # Returns
    /// List of object keys matching the prefix
    pub async fn list_files(&self, prefix: &str) -> Result<Vec<String>> {
        self.person_door(prefix).fs().list(prefix).await
    }

    /// The immediate children of `dir` — the shape a file browser draws, and
    /// what an app's `files.list-entries` is answered from.
    ///
    /// **Folded from the store's own listing**, which reports files at every
    /// depth under a prefix (the blinded layer walks leaves; the pack layer
    /// adds what its manifest holds): a file one level down is a child, and
    /// anything deeper names the directory it lies in. A folder the person
    /// made is kept as its own entry beneath it ([`crate::fs_view::FOLDER_ENTRY`]),
    /// which folds the same way — so the folder is listed in its parent while
    /// it is empty, and its own entry is never listed as a child of it.
    ///
    /// **The cost is the listing's, not this fold's.** A packed file is listed
    /// from the sealed manifest; a loose one is opened to read the path it
    /// carries, because its stored key is blinded and names nothing.
    /// The measurement is a test below.
    ///
    /// A backend that lists one level and reports prefixes as `is_dir` (a
    /// routed mount on a plain-keyed store) folds the same way.
    pub async fn list_children(&self, dir: &str) -> Result<Vec<DirChild>> {
        Ok(self.fold_children(dir).await?.0)
    }

    /// [`Self::list_children`], and whether `dir` holds the entry a folder the
    /// person made is kept at — which is not a child, but is what makes an
    /// empty folder a directory rather than nothing.
    async fn fold_children(&self, dir: &str) -> Result<(Vec<DirChild>, bool)> {
        let door = self.person_door(dir);
        let key = door.fs().key(dir);
        let listed = door
            .storage()
            .list(std::path::Path::new(&key))
            .await
            .map_err(|e| anyhow!("Failed to list '{dir}': {e}"))?;
        // Never empty where the store holds keys: the person's own root is
        // `PERSON_TREE_ROOT`, so every row this folds lies beneath it and
        // nothing of the daemon's does. Through a naming door (a peer) the far
        // side answers in the person's own paths, and the root's rows begin at
        // the top.
        let key = key.trim_matches('/');
        let base = if key.is_empty() { String::new() } else { format!("{key}/") };
        let mut children: std::collections::BTreeMap<String, DirChild> =
            std::collections::BTreeMap::new();
        let mut made = false;
        for meta in listed {
            let full = meta.key.trim_start_matches('/').trim_end_matches('/');
            let Some(rest) = full.strip_prefix(base.as_str()) else {
                continue;
            };
            if rest.is_empty() {
                continue;
            }
            if rest == crate::fs_view::FOLDER_ENTRY {
                made = true;
                continue;
            }
            match rest.split_once('/') {
                Some((name, _)) => {
                    children
                        .entry(name.to_string())
                        .or_insert_with(|| DirChild {
                            name: name.to_string(),
                            is_dir: true,
                            size: 0,
                            modified: None,
                        });
                }
                None => {
                    // A file and a directory of one name cannot both exist in
                    // one store key space; the file is the object, so it wins.
                    children.insert(
                        rest.to_string(),
                        DirChild {
                            name: rest.to_string(),
                            is_dir: meta.is_dir,
                            size: if meta.is_dir { 0 } else { meta.size },
                            modified: if meta.is_dir { None } else { meta.modified },
                        },
                    );
                }
            }
        }
        Ok((children.into_values().collect(), made))
    }

    /// Whether `path` names a file, a directory, or nothing in this person's
    /// tree. The root is always a directory, empty or not.
    pub async fn path_kind(&self, path: &str) -> Result<Option<PathKind>> {
        if kotton_schemas::to_object_key(path).is_empty() {
            return Ok(Some(PathKind::Dir));
        }
        let door = self.person_door(path);
        let key = door.fs().key(path);
        // `metadata` rather than `exists`: a filesystem shelf answers for the
        // directory a loose object's blinded key lies in, too, and that is not
        // a file.
        match door.storage().metadata(std::path::Path::new(&key)).await {
            Ok(meta) if !meta.is_dir => return Ok(Some(PathKind::File)),
            Ok(_) | Err(kotton_sys::store::ObjectStorageError::NotFound(_)) => {}
            Err(e) => return Err(anyhow!("Failed to look up '{path}': {e}")),
        }
        let (children, made) = self.fold_children(path).await?;
        Ok((made || !children.is_empty()).then_some(PathKind::Dir))
    }

    /// Make an empty folder at `path` in this person's tree.
    ///
    /// **A folder is an object here, not a side effect of a file.** It is kept
    /// at the folder's own entry ([`crate::fs_view::FOLDER_ENTRY`]), sealed,
    /// blinded and packable like any file, so it is listed while it is empty,
    /// syncs to the person's other devices, and outlives the last file taken
    /// out of it. Missing parents appear with it, as they do for a file.
    ///
    /// `already exists`, in those words, when anything is at `path` — a file,
    /// or a folder, made or implied by what is in it. A person who asked for a
    /// new folder and was told it was made should find a new, empty folder.
    ///
    /// **Through a paired device, refused.** A naming door is handed the
    /// person's path and canonicalises it again on the far side, where the
    /// folder's entry would collapse onto the folder's own name and land as an
    /// empty *file*. The peer wire has no verb for a folder, so a folder cannot
    /// be made on a paired device's mount.
    pub async fn create_dir(&self, path: &str) -> Result<()> {
        if self.path_kind(path).await?.is_some() {
            return Err(anyhow!("already exists"));
        }
        let door = self.person_door(path);
        if door.addressing() == crate::runtime::router::Addressing::Names {
            return Err(anyhow!(
                "'{path}' is on a paired device's mount, which cannot make an empty folder yet"
            ));
        }
        let key = crate::fs_view::folder_key(&door.fs().key(path));
        door.storage()
            .put(std::path::Path::new(&key), &[])
            .await
            .map_err(|e| anyhow!("Failed to make folder '{path}': {e}"))
    }

    /// The conflicts retained in this person's tree, each by
    /// its path in the tree (without the leading `/`, as the store's own
    /// listing spells it) and the versions kept for it.
    ///
    /// **The person's tree only.** A retained version of one of the daemon's
    /// own records is not a file of theirs and has no path in their tree to be
    /// named by; it is not listed here, and `resolve_file_conflict` could not
    /// reach it if it were.
    pub async fn file_conflicts(&self) -> Result<Vec<(String, Vec<String>)>> {
        let local = self.local_mount()?;
        let base = format!("{PERSON_TREE_ROOT}/");
        Ok(local
            .retained_conflicts()
            .await
            .map_err(|e| anyhow!("{e}"))?
            .into_iter()
            .filter_map(|(key, versions)| {
                key.strip_prefix(base.as_str())
                    .map(|path| (path.to_string(), versions))
            })
            .collect())
    }

    /// Settle the conflict on `path` in the person's tree, releasing what was
    /// retained for it; `keep` promotes a retained version.
    pub async fn resolve_file_conflict(&self, path: &str, keep: Option<&str>) -> Result<()> {
        let local = self.local_mount()?;
        local
            .resolve_conflict(std::path::Path::new(&person_key(path)), keep)
            .await
            .map_err(|e| anyhow!("{e}"))
    }

    /// Erase `path` in the person's tree and its entire history (`purge`).
    pub async fn purge_file(&self, path: &str) -> Result<()> {
        let local = self.local_mount()?;
        local
            .purge(std::path::Path::new(&person_key(path)))
            .await
            .map(|_| ())
            .map_err(|e| anyhow!("{e}"))
    }

    /// Turn the **keep versions** switch on `path` in the person's tree on or
    /// off.
    ///
    /// The person-facing door to the mount's `set_keep_versions`, which takes a
    /// store key: this is where a path the person names becomes one, beneath
    /// [`PERSON_TREE_ROOT`], so the switch lands on their file and never on a
    /// key the same spelling would name outside their tree — one of the
    /// daemon's own records.
    pub async fn set_file_keep_versions(&self, path: &str, on: bool) -> Result<()> {
        let local = self.local_mount()?;
        local
            .set_keep_versions(std::path::Path::new(&person_key(path)), on)
            .await
            .map_err(|e| anyhow!("{e}"))
    }

    /// Whether `path` in the person's tree keeps its versions. See
    /// [`Self::set_file_keep_versions`].
    pub async fn file_keeps_versions(&self, path: &str) -> Result<bool> {
        let local = self.local_mount()?;
        local
            .keeps_versions(std::path::Path::new(&person_key(path)))
            .await
            .map_err(|e| anyhow!("{e}"))
    }

    /// The prior versions of `path` in the person's tree, newest first. See
    /// [`Self::set_file_keep_versions`].
    pub async fn file_versions(&self, path: &str) -> Result<Vec<kotton_sys::store::FileVersion>> {
        let local = self.local_mount()?;
        local
            .versions(std::path::Path::new(&person_key(path)))
            .await
            .map_err(|e| anyhow!("{e}"))
    }

    /// The generation at which `path`'s current version in the person's tree
    /// entered the history log of the mount that carries it, or `None` while
    /// it has not — the readout a hand-over to a device of theirs says *sent*
    /// on (*a device of your own*). See
    /// [`SealedObjectAccess::logged`](kotton_sys::store::SealedObjectAccess::logged).
    pub async fn file_logged(&self, path: &str) -> Result<Option<u64>> {
        let local = self.local_mount()?;
        local
            .logged(std::path::Path::new(&person_key(path)))
            .await
            .map_err(|e| anyhow!("{e}"))
    }

    /// Restore a prior version of `path` in the person's tree — a new write of
    /// its old bytes. See [`Self::set_file_keep_versions`].
    pub async fn restore_file_version(&self, path: &str, content_id: &str) -> Result<()> {
        let local = self.local_mount()?;
        local
            .restore_version(std::path::Path::new(&person_key(path)), content_id)
            .await
            .map_err(|e| anyhow!("{e}"))
    }

    /// Write one of **the daemon's own records** — the membership set, a read
    /// mark — at `path` in the store's key space, outside the person's tree.
    ///
    /// Sealed, blinded, packed and synced to the person's other devices exactly
    /// as a file is: it is the same `local` mount. What differs is who can name
    /// it. Every person-facing verb above resolves beneath
    /// [`PERSON_TREE_ROOT`], so no path a person types or an app is granted
    /// reaches a key these four verbs address; only the daemon's own domain
    /// code calls them (`MemberStore` in `kotton-peer`, `ReadMarkStore` in
    /// `kuserd`).
    ///
    /// Always the `local` mount. The person's mount table routes paths in
    /// *their* tree; a record of the daemon's is not one, and a mount of
    /// `/network` the person made for their own files must not carry the
    /// membership set away with it.
    pub async fn write_daemon_object(&self, path: &str, data: &[u8]) -> Result<()> {
        Fs::new(self.local_mount()?.as_ref()).write(path, data).await
    }

    /// Read one of the daemon's own records. See [`Self::write_daemon_object`].
    pub async fn read_daemon_object(&self, path: &str) -> Result<Vec<u8>> {
        Fs::new(self.local_mount()?.as_ref()).read(path).await
    }

    /// Begin writing one of the daemon's own objects as a stream, or `None`
    /// from a store that takes objects whole only — the streaming sibling of
    /// [`Self::write_daemon_object`], as [`Self::begin_file_write`] is of
    /// [`Self::write_file`].
    ///
    /// A model's weights are the daemon's object and gigabytes long, so they cannot go through a verb that takes a `&[u8]`. **Nothing appears
    /// at `path` until the sink commits**, which is what lets the model verb
    /// hash the stream as it lands and commit only at the declared hash.
    pub async fn begin_daemon_object_write(
        &self,
        path: &str,
    ) -> Result<Option<Box<dyn kotton_sys::store::ObjectSink>>> {
        Fs::new(self.local_mount()?.as_ref()).begin_write(path).await
    }

    /// Read `[offset, offset + length)` of one of the daemon's own objects, and
    /// its total size. See [`Self::write_daemon_object`]; what
    /// [`Self::read_file_range`] is to the person's tree, so a caller checking
    /// a multi-gigabyte object never holds it whole.
    pub async fn read_daemon_object_range(
        &self,
        path: &str,
        offset: u64,
        length: u64,
    ) -> Result<(Vec<u8>, u64)> {
        Fs::new(self.local_mount()?.as_ref())
            .read_range(path, offset, length)
            .await
    }

    /// Delete one of the daemon's own records. See [`Self::write_daemon_object`].
    pub async fn delete_daemon_object(&self, path: &str) -> Result<()> {
        Fs::new(self.local_mount()?.as_ref()).delete(path).await
    }

    /// List the daemon's own records under `prefix`, by key. See
    /// [`Self::write_daemon_object`].
    pub async fn list_daemon_objects(&self, prefix: &str) -> Result<Vec<String>> {
        Fs::new(self.local_mount()?.as_ref()).list(prefix).await
    }

    fn local_mount(&self) -> Result<std::sync::Arc<dyn kotton_sys::store::SyncableStore>> {
        self.get_remote("local")
            .ok_or_else(|| anyhow!("no local store for this user"))
    }
}


#[cfg(test)]
mod tests {
    use super::UserStore;
    use crate::runtime::UserKeys;
    // Explicit rather than via `super::*`, which only re-exports it when the
    // `test-support` feature happens to be on.
    use kotton_schemas::to_object_key;
    use crate::MemoryObjectStorage;
    use std::sync::Arc;

    /// Data keys for an **unlocked** node — what a logged-in user's device holds.
    ///
    /// These tests exercise the ordinary VFS path, so they need a key. They used
    /// `UserKeys::keyless()`, which is keyless: before `SealedOnlyStorage` that
    /// silently produced a bare local store, so every assertion below was passing
    /// against **unencrypted** storage while production encrypts. The tests now
    /// fail loudly without a key, which is how the substitution came to light.
    fn unlocked_keys() -> UserKeys {
        UserKeys::new(Some([7u8; 32]))
    }

    #[tokio::test]
    async fn test_write_and_read_file() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = UserStore::create(
            "alice",
            "did:key:z6Mk...",
            temp.path().to_path_buf(),
            unlocked_keys(),
            &crate::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();

        // Write a file
        runtime
            .write_file("/test.txt", b"Hello, world!")
            .await
            .unwrap();

        // Read it back
        let contents = runtime.read_file("/test.txt").await.unwrap();
        assert_eq!(contents, b"Hello, world!");
    }

    #[tokio::test]
    async fn test_file_exists() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = UserStore::create(
            "alice",
            "did:key:z6Mk...",
            temp.path().to_path_buf(),
            unlocked_keys(),
            &crate::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();

        // File doesn't exist yet
        assert!(!runtime.file_exists("local", "/test.txt").await.unwrap());

        // Write file
        runtime
            .write_file("/test.txt", b"test")
            .await
            .unwrap();

        // Now it exists
        assert!(runtime.file_exists("local", "/test.txt").await.unwrap());
    }

    #[tokio::test]
    async fn test_delete_file() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = UserStore::create(
            "alice",
            "did:key:z6Mk...",
            temp.path().to_path_buf(),
            unlocked_keys(),
            &crate::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();

        // Write and verify
        runtime
            .write_file("/test.txt", b"test")
            .await
            .unwrap();
        assert!(runtime.file_exists("local", "/test.txt").await.unwrap());

        // Delete
        runtime.delete_file("/test.txt").await.unwrap();
        assert!(!runtime.file_exists("local", "/test.txt").await.unwrap());
    }

    #[tokio::test]
    async fn test_list_files() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = UserStore::create(
            "alice",
            "did:key:z6Mk...",
            temp.path().to_path_buf(),
            unlocked_keys(),
            &crate::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();

        // Write multiple files
        runtime
            .write_file("/docs/file1.txt", b"one")
            .await
            .unwrap();
        runtime
            .write_file("/docs/file2.txt", b"two")
            .await
            .unwrap();
        runtime
            .write_file("/other/file3.txt", b"three")
            .await
            .unwrap();

        // List files in /docs/
        let files = runtime.list_files("/docs/").await.unwrap();
        assert_eq!(files.len(), 2);
        assert!(files.contains(&"docs/file1.txt".to_string()));
        assert!(files.contains(&"docs/file2.txt".to_string()));
    }

    /// A node with no data keys must **refuse** content, not store it in the clear.
    ///
    /// This is the invariant `SealedOnlyStorage` exists for. A keyless runtime is
    /// either a blind storage node — which moves data over the sealed path, not this
    /// one — or a device whose key is absent because it is locked. Neither may
    /// write a user's bytes to disk unencrypted, and both used to.
    #[tokio::test]
    async fn a_keyless_runtime_refuses_to_write_plaintext() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = UserStore::create(
            "alice",
            "did:key:z6Mk...",
            temp.path().to_path_buf(),
            UserKeys::keyless(),
            &crate::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();

        assert!(
            runtime
                .write_file("/secrets.txt", b"not for disk")
                .await
                .is_err(),
            "a node holding no CEK must refuse content rather than write plaintext"
        );

        // And nothing landed: the refusal is not a partial write.
        assert!(!runtime.file_exists("local", "/secrets.txt").await.unwrap());
    }

    #[tokio::test]
    async fn routes_a_configured_prefix_to_its_mount() {
        use crate::runtime::{StorageMountEntry, StorageMountsFile};

        let temp = tempfile::tempdir().unwrap();
        let runtime = UserStore::create(
            "alice",
            "did:key:z6Mk...",
            temp.path().to_path_buf(),
            unlocked_keys(),
            &crate::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();

        let memory_storage = Arc::new(MemoryObjectStorage::new());
        runtime
            .add_remote(
                "memory".to_string(),
                memory_storage.clone(),
                kotton_wire::remote::RemoteConfig {
                    backend: kotton_wire::remote::RemoteBackend::Local {
                        path: temp.path().join("memory-data"),
                    },
                    cache_dir: None,
                    key_format: kotton_wire::remote::KeyFormat::default(),
                },
            )
            .unwrap();

        // Route `/mem` to the memory remote, the way a user would.
        StorageMountsFile {
            mounts: vec![StorageMountEntry {
                path: "/mem".to_string(),
                remote: "memory".to_string(),
            }],
        }
        .save(temp.path())
        .unwrap();
        runtime.invalidate_mount_router();

        // The caller names a path, never a store.
        runtime.write_file("/mem/test.txt", b"routed!").await.unwrap();
        let contents = runtime.read_file("/mem/test.txt").await.unwrap();
        assert_eq!(contents, b"routed!");

        // A path outside the mount falls back to local, and the two do not mix.
        runtime.write_file("/elsewhere.txt", b"local!").await.unwrap();
        assert_eq!(
            runtime.read_file("/elsewhere.txt").await.unwrap(),
            b"local!"
        );
    }

    /// **A routed mount holds the key the person's door names** — the same key
    /// the store's own backend would, however the path was spelled — never
    /// rooted twice.
    ///
    /// The second backend is a plain in-memory store so the key it is handed
    /// can be read off it directly. `/photos/a.jpg` rests there at
    /// `files/photos/a.jpg`, which is [`super::person_key`] — the one function
    /// that names a key under the root — and at no bare `photos/a.jpg`; a read,
    /// a listing and a `path_kind` through the person's door find it. A second
    /// spelling of a path under the mount, `\photos\b.jpg`, lands on the mount
    /// too: the door routes on the path it keys by, so a spelling cannot send
    /// one file's bytes to the local store while its name points at the mount.
    #[tokio::test]
    async fn a_routed_mount_stores_the_key_the_persons_door_names() {
        use crate::runtime::{StorageMountEntry, StorageMountsFile};
        use kotton_sys::store::ObjectStorage as _;

        let temp = tempfile::tempdir().unwrap();
        let store = UserStore::create(
            "alice",
            "did:key:z6Mk...",
            temp.path().to_path_buf(),
            unlocked_keys(),
            &crate::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();
        let archive = Arc::new(MemoryObjectStorage::new());
        store
            .add_remote(
                "archive".to_string(),
                archive.clone(),
                kotton_wire::remote::RemoteConfig {
                    backend: kotton_wire::remote::RemoteBackend::Local {
                        path: temp.path().join("archive"),
                    },
                    cache_dir: None,
                    key_format: kotton_wire::remote::KeyFormat::default(),
                },
            )
            .unwrap();
        StorageMountsFile {
            mounts: vec![StorageMountEntry {
                path: "/photos".to_string(),
                remote: "archive".to_string(),
            }],
        }
        .save(temp.path())
        .unwrap();
        store.invalidate_mount_router();

        store.write_file("/photos/a.jpg", b"alpha").await.unwrap();
        let key = super::person_key("/photos/a.jpg");
        assert_eq!(key, "files/photos/a.jpg");
        assert_eq!(
            archive.get(std::path::Path::new(&key)).await.unwrap().as_ref(),
            b"alpha",
            "the mount holds the key the store's own backend would"
        );
        assert!(
            archive.get(std::path::Path::new("photos/a.jpg")).await.is_err(),
            "nothing rests at the bare key"
        );
        assert_eq!(store.read_file("/photos/a.jpg").await.unwrap(), b"alpha");

        store.write_file("\\photos\\b.jpg", b"bravo").await.unwrap();
        assert_eq!(
            archive
                .get(std::path::Path::new(&super::person_key("/photos/b.jpg")))
                .await
                .expect("a second spelling of a path under the mount lands on the mount")
                .as_ref(),
            b"bravo"
        );
        assert_eq!(store.read_file("/photos/b.jpg").await.unwrap(), b"bravo");

        let names: Vec<String> = store
            .list_children("/photos")
            .await
            .unwrap()
            .into_iter()
            .map(|c| c.name)
            .collect();
        assert_eq!(names, vec!["a.jpg".to_string(), "b.jpg".to_string()]);
        assert_eq!(store.path_kind("/photos/a.jpg").await.unwrap(), Some(super::PathKind::File));
        assert!(
            !store.list_files("/").await.unwrap().iter().any(|k| k.contains("photos")),
            "the local store holds none of the mount's files"
        );
    }

    /// **A directory listing is one level deep, loose or packed.** The store
    /// lists files at every depth; `list_children` folds that into what a file
    /// browser draws — the files directly inside, and one row per directory
    /// that anything deeper lies in — and the answer does not change when the
    /// packing pass moves the objects out of their loose files.
    #[tokio::test]
    async fn a_directory_lists_its_own_children_before_and_after_packing() {
        use super::{DirChild, PathKind};
        let temp = tempfile::tempdir().unwrap();
        let store = UserStore::create(
            "alice",
            "did:key:z6Mk...",
            temp.path().to_path_buf(),
            unlocked_keys(),
            &crate::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();
        store.write_file("/notes/a.md", b"alpha").await.unwrap();
        store.write_file("/notes/trip/b.md", b"bravo!").await.unwrap();
        store.write_file("/notes/trip/deeper/c.md", b"c").await.unwrap();
        store.write_file("/elsewhere.md", b"not in notes").await.unwrap();

        let shape = |children: Vec<DirChild>| {
            children
                .into_iter()
                .map(|c| (c.name, c.is_dir, c.size))
                .collect::<Vec<_>>()
        };
        let want = vec![
            ("a.md".to_string(), false, 5),
            ("trip".to_string(), true, 0),
        ];
        assert_eq!(shape(store.list_children("/notes").await.unwrap()), want);
        assert_eq!(
            shape(store.list_children("/").await.unwrap()),
            vec![("elsewhere.md".to_string(), false, 12), ("notes".to_string(), true, 0)]
        );
        let a = store
            .list_children("/notes")
            .await
            .unwrap()
            .into_iter()
            .find(|c| c.name == "a.md")
            .unwrap();
        assert!(a.modified.is_some(), "a loose file carries the time it was written");

        crate::runtime::pack_mount(&*store.get_remote("local").unwrap(), "local")
            .await
            .unwrap()
            .expect("an unlocked store packs");
        assert_eq!(
            shape(store.list_children("/notes").await.unwrap()),
            want,
            "packing changed what the directory lists"
        );

        assert_eq!(store.path_kind("/notes/a.md").await.unwrap(), Some(PathKind::File));
        assert_eq!(store.path_kind("/notes/trip").await.unwrap(), Some(PathKind::Dir));
        assert_eq!(store.path_kind("/").await.unwrap(), Some(PathKind::Dir));
        assert_eq!(store.path_kind("/nothing").await.unwrap(), None);
        assert_eq!(store.path_kind("/note").await.unwrap(), None, "a prefix of a name is not a directory");
    }

    /// **A folder the person makes is an object: listed while empty, packed,
    /// and outliving its last file.**
    ///
    /// A store that kept files only would keep a folder exactly as long as
    /// something was in it, and could not make one empty at all.
    #[tokio::test]
    async fn a_folder_the_person_makes_is_listed_empty_and_outlives_its_last_file() {
        use super::{DirChild, PathKind};
        let temp = tempfile::tempdir().unwrap();
        let store = UserStore::create(
            "alice",
            "did:key:z6Mk...",
            temp.path().to_path_buf(),
            unlocked_keys(),
            &crate::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();
        store.write_file("/notes/a.md", b"alpha").await.unwrap();
        store.create_dir("/notes/trip").await.unwrap();

        let shape = |children: Vec<DirChild>| {
            children
                .into_iter()
                .map(|c| (c.name, c.is_dir, c.size))
                .collect::<Vec<_>>()
        };
        let parent = vec![("a.md".to_string(), false, 5), ("trip".to_string(), true, 0)];
        assert_eq!(shape(store.list_children("/notes").await.unwrap()), parent);
        assert!(
            store.list_children("/notes/trip").await.unwrap().is_empty(),
            "a new folder is empty: its own entry is not a child of it"
        );
        assert_eq!(store.path_kind("/notes/trip").await.unwrap(), Some(PathKind::Dir));
        assert!(
            store.list_files("/notes/").await.unwrap().contains(&"notes/trip/".to_string()),
            "the flat listing names the folder as a folder"
        );

        // Missing parents appear with it, as they do for a file.
        store.create_dir("/deep/er/still").await.unwrap();
        assert_eq!(store.path_kind("/deep/er").await.unwrap(), Some(PathKind::Dir));

        // Anything already there refuses: a file, a made folder, an implied one,
        // and the root.
        for taken in ["/notes/a.md", "/notes/trip", "/notes", "/"] {
            let err = store.create_dir(taken).await.unwrap_err().to_string();
            assert_eq!(err, "already exists", "{taken}");
        }

        // A file put in and taken out leaves the folder, still empty.
        store.write_file("/notes/trip/b.md", b"b").await.unwrap();
        store.delete_file("/notes/trip/b.md").await.unwrap();
        assert!(store.list_children("/notes/trip").await.unwrap().is_empty());
        assert_eq!(store.path_kind("/notes/trip").await.unwrap(), Some(PathKind::Dir));

        crate::runtime::pack_mount(&*store.get_remote("local").unwrap(), "local")
            .await
            .unwrap()
            .expect("an unlocked store packs");
        assert_eq!(
            shape(store.list_children("/notes").await.unwrap()),
            parent,
            "packing changed what the folder's parent lists"
        );
        assert!(store.list_children("/notes/trip").await.unwrap().is_empty());
        assert_eq!(store.path_kind("/notes/trip").await.unwrap(), Some(PathKind::Dir));
    }

    /// **No path names the entry a folder is kept at**, so no guard keeps it:
    /// every spelling of it canonicalises onto the folder's own name, which is
    /// not a file, and the entry survives every file verb aimed at it.
    #[tokio::test]
    async fn no_path_reaches_the_entry_a_folder_is_kept_at() {
        use super::PathKind;
        let temp = tempfile::tempdir().unwrap();
        let store = UserStore::create(
            "alice",
            "did:key:z6Mk...",
            temp.path().to_path_buf(),
            unlocked_keys(),
            &crate::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();
        store.create_dir("/trip").await.unwrap();
        for spelling in ["/trip/.", "/trip/./", "trip\\.", "/trip/x/..", "/trip/."] {
            assert!(store.read_file(spelling).await.is_err(), "{spelling} read as a file");
            let _ = store.delete_file(spelling).await;
            assert_eq!(
                store.path_kind("/trip").await.unwrap(),
                Some(PathKind::Dir),
                "a delete of {spelling} took the folder away"
            );
        }
        assert!(store.list_children("/trip").await.unwrap().is_empty());
    }

    /// **The folder's name does not reach the disk.** Its entry is sealed and
    /// blinded like a file, so what rests under the store's own directory
    /// carries no segment of the path the person chose.
    #[tokio::test]
    async fn a_folders_name_rests_nowhere_on_disk() {
        let temp = tempfile::tempdir().unwrap();
        let store = UserStore::create(
            "alice",
            "did:key:z6Mk...",
            temp.path().to_path_buf(),
            unlocked_keys(),
            &crate::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();
        store.create_dir("/Divorce-Filings/Mediator").await.unwrap();
        fn walk(dir: &std::path::Path, out: &mut Vec<String>) {
            for e in std::fs::read_dir(dir).unwrap() {
                let e = e.unwrap();
                out.push(e.file_name().to_string_lossy().into_owned());
                if e.file_type().unwrap().is_dir() {
                    walk(&e.path(), out);
                }
                if e.file_type().unwrap().is_file() {
                    let bytes = std::fs::read(e.path()).unwrap();
                    let text = String::from_utf8_lossy(&bytes);
                    assert!(!text.contains("Divorce") && !text.contains("Mediator"), "{:?}", e.path());
                }
            }
        }
        let mut names = Vec::new();
        walk(temp.path(), &mut names);
        assert!(!names.is_empty(), "nothing rests on disk at all");
        for n in names {
            assert!(!n.contains("Divorce") && !n.contains("Mediator"), "{n} rests on disk");
        }
    }

    /// **What one listing of a hundred files costs, loose and packed** —
    /// measured. A hundred files of the size the "before" run used (the
    /// sandbox's `list-entries` over a plain directory, the same hundred plus
    /// one), listed seven times each way, with every timing printed:
    ///
    /// ```text
    /// cargo test -p kotton-store --lib a_listing_of_a_hundred_files -- --nocapture
    /// ```
    ///
    /// Loose, every object is opened to read the path it carries — its stored
    /// key is blinded and names nothing — so the cost grows with
    /// the bytes under the prefix. Packed, the sealed manifest answers.
    #[tokio::test]
    async fn a_listing_of_a_hundred_files_is_measured_loose_and_packed() {
        let temp = tempfile::tempdir().unwrap();
        let store = UserStore::create(
            "alice",
            "did:key:z6Mk...",
            temp.path().to_path_buf(),
            unlocked_keys(),
            &crate::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();
        for i in 0..100 {
            let body = format!("body {i} ").repeat(40);
            store
                .write_file(&format!("/notes/note-{i:03}.md"), body.as_bytes())
                .await
                .unwrap();
        }
        store.write_file("/notes/ok.txt", b"in-grant").await.unwrap();

        let time = |label: &'static str| {
            let store = &store;
            async move {
                let mut times = Vec::new();
                for _ in 0..7 {
                    let t = std::time::Instant::now();
                    let listed = store.list_children("/notes").await.unwrap();
                    times.push(t.elapsed());
                    assert_eq!(listed.len(), 101);
                }
                eprintln!("{label}: list of 101 entries through the store: {times:?}");
            }
        };
        time("loose").await;
        crate::runtime::pack_mount(&*store.get_remote("local").unwrap(), "local")
            .await
            .unwrap()
            .expect("an unlocked store packs");
        time("packed").await;
    }

    /// **No path in the person's tree names one of the daemon's records** —
    /// the reach half, at the store.
    ///
    /// Without the prefix, an app granted `files.write` on `/` could write
    /// `network/members/did:key:z6MkForgedByAnApp` and the membership set would
    /// read it back as an own device. The person's tree is rooted at
    /// [`super::PERSON_TREE_ROOT`] now, so the same path, and every spelling
    /// that tries to climb out of it, lands in the person's own tree, and the
    /// daemon's listing of its records does not see it.
    #[tokio::test]
    async fn a_path_in_the_persons_tree_cannot_name_a_daemon_record() {
        let temp = tempfile::tempdir().unwrap();
        let store = UserStore::create(
            "alice",
            "did:key:z6Mk...",
            temp.path().to_path_buf(),
            unlocked_keys(),
            &crate::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();
        store
            .write_daemon_object("/network/members/did:key:zReal", b"the daemon's")
            .await
            .unwrap();

        for spelling in [
            "/network/members/did:key:zForged",
            "network/members/did:key:zForged2",
            "/../network/members/did:key:zForged3",
            "/notes/../../network/members/did:key:zForged4",
            "..\\..\\network\\members\\did:key:zForged5",
        ] {
            store.write_file(spelling, b"an app's").await.unwrap();
        }
        assert_eq!(
            store.list_daemon_objects("/network/members/").await.unwrap(),
            vec!["network/members/did:key:zReal".to_string()],
            "a write in the person's tree reached the daemon's records"
        );
        assert!(
            store.read_file("/network/members/did:key:zReal").await.is_err(),
            "a read in the person's tree reached the daemon's record"
        );
        assert_eq!(
            store
                .read_daemon_object("/network/members/did:key:zReal")
                .await
                .unwrap(),
            b"the daemon's"
        );
        assert_eq!(
            store.path_kind("/network/members/did:key:zReal").await.unwrap(),
            None
        );
        // And deleting through the person's tree deletes nothing of the
        // daemon's — the Files view's delete, which unpaired devices.
        assert!(
            store.delete_file("/network/members/did:key:zReal").await.is_err(),
            "there is nothing at that path in the person's tree to delete"
        );
        assert!(store
            .read_daemon_object("/network/members/did:key:zReal")
            .await
            .is_ok());
    }

    /// **A daemon object streamed in lands outside the person's tree, and not
    /// before it commits** — the door a model's weights come through, which no
    /// `files` grant reaches.
    ///
    /// An uncommitted sink leaves nothing at the key; a committed one reads
    /// back whole and in ranges through the daemon's verbs; and every spelling
    /// of the same path in the person's tree — read, list, write, delete —
    /// reaches their own file and never the daemon's object.
    #[tokio::test]
    async fn a_streamed_daemon_object_lands_outside_the_persons_tree() {
        let temp = tempfile::tempdir().unwrap();
        let store = UserStore::create(
            "alice",
            "did:key:z6Mk...",
            temp.path().to_path_buf(),
            unlocked_keys(),
            &crate::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();
        let key = "models/abc.weights";
        let body: Vec<u8> = (0..3_000_000u32).map(|i| (i % 253) as u8).collect();

        // Dropped uncommitted: nothing is there under any name.
        {
            let mut sink = store
                .begin_daemon_object_write(key)
                .await
                .unwrap()
                .expect("the local mount streams");
            sink.push(&body[..1024]).await.unwrap();
        }
        assert!(store.read_daemon_object(key).await.is_err());

        let mut sink = store
            .begin_daemon_object_write(key)
            .await
            .unwrap()
            .expect("the local mount streams");
        for chunk in body.chunks(1 << 20) {
            sink.push(chunk).await.unwrap();
        }
        sink.commit().await.unwrap();

        assert_eq!(store.read_daemon_object(key).await.unwrap(), body);
        let (mid, total) = store
            .read_daemon_object_range(key, 1_000_000, 4096)
            .await
            .unwrap();
        assert_eq!(total, body.len() as u64);
        assert_eq!(mid, &body[1_000_000..1_004_096]);

        // The person's tree does not see it, and cannot touch it.
        assert!(store.read_file("/models/abc.weights").await.is_err());
        assert!(store.list_files("/").await.unwrap().is_empty());
        assert!(store.list_children("/").await.unwrap().is_empty());
        assert!(store.delete_file("/models/abc.weights").await.is_err());
        store
            .write_file("/models/abc.weights", b"a file of the person's")
            .await
            .unwrap();
        assert_eq!(store.read_daemon_object(key).await.unwrap(), body);
        assert_eq!(
            store.read_file("/models/abc.weights").await.unwrap(),
            b"a file of the person's"
        );
    }

    /// **The person's tree lists their files and nothing of the daemon's** —
    /// what the file browser draws at *Personal*, loose and packed.
    #[tokio::test]
    async fn the_persons_tree_lists_no_daemon_record() {
        use super::PathKind;
        let temp = tempfile::tempdir().unwrap();
        let store = UserStore::create(
            "alice",
            "did:key:z6Mk...",
            temp.path().to_path_buf(),
            unlocked_keys(),
            &crate::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();
        store
            .write_daemon_object("/network/members/did:key:zReal", b"{}")
            .await
            .unwrap();
        store
            .write_daemon_object("/messages/read/did:key:zSarah", b"{}")
            .await
            .unwrap();
        store.write_file("/notes/a.md", b"mine").await.unwrap();
        store.write_file("/top.md", b"mine too").await.unwrap();

        for when in ["loose", "packed"] {
            let names: Vec<String> = store
                .list_children("/")
                .await
                .unwrap()
                .into_iter()
                .map(|c| c.name)
                .collect();
            assert_eq!(names, vec!["notes".to_string(), "top.md".to_string()], "{when}");
            let mut all = store.list_files("/").await.unwrap();
            all.sort();
            assert_eq!(all, vec!["notes/a.md".to_string(), "top.md".to_string()], "{when}");
            assert_eq!(store.path_kind("/network").await.unwrap(), None, "{when}");
            assert_eq!(store.path_kind("/messages").await.unwrap(), None, "{when}");
            assert_eq!(store.path_kind("/notes").await.unwrap(), Some(PathKind::Dir), "{when}");
            crate::runtime::pack_mount(&*store.get_remote("local").unwrap(), "local")
                .await
                .unwrap()
                .expect("an unlocked store packs");
        }
        // Both halves are the same mount, sealed and packed by the same pass.
        assert_eq!(
            store.read_daemon_object("/messages/read/did:key:zSarah").await.unwrap(),
            b"{}"
        );
        assert_eq!(store.read_file("/notes/a.md").await.unwrap(), b"mine");
    }

    /// **The versions switch a person flips lands under their tree's root** —
    /// the switch works on store keys. Through `UserStore` the person's `/notes/a.md` is the
    /// object `files/notes/a.md`: the switch, the versions and a restore all
    /// reach it, and the same verbs spelled at a daemon record's key find
    /// nothing of the person's and switch nothing of the daemon's.
    #[tokio::test]
    async fn the_versions_switch_a_person_flips_lands_under_their_trees_root() {
        let temp = tempfile::tempdir().unwrap();
        let store = UserStore::create(
            "alice",
            "did:key:z6Mk...",
            temp.path().to_path_buf(),
            UserKeys::new(Some([7u8; 32])).with_log("did:key:zThisDevice", &[3u8; 32]),
            &crate::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();
        let local = store.get_remote("local").unwrap();
        let pack = || async {
            crate::runtime::pack_mount(&*store.get_remote("local").unwrap(), "local")
                .await
                .unwrap()
                .expect("an unlocked store packs");
        };
        store
            .write_daemon_object("/network/members/did:key:zReal", b"the daemon's")
            .await
            .unwrap();
        store.write_file("/notes/a.md", b"the good draft").await.unwrap();

        store.set_file_keep_versions("/notes/a.md", true).await.unwrap();
        assert!(store.file_keeps_versions("/notes/a.md").await.unwrap());
        assert!(
            local
                .keeps_versions(std::path::Path::new("files/notes/a.md"))
                .await
                .unwrap(),
            "the switch did not land on the object beneath the person's root"
        );
        assert!(
            !local.keeps_versions(std::path::Path::new("notes/a.md")).await.unwrap(),
            "the switch landed on the unrooted key"
        );

        store.write_file("/notes/a.md", b"the bad edit").await.unwrap();
        pack().await;
        let versions = store.file_versions("/notes/a.md").await.unwrap();
        assert!(!versions.is_empty(), "a superseded version was not kept");
        let good = versions
            .iter()
            .find(|v| v.size == b"the good draft".len() as u64)
            .expect("the good draft is among the kept versions")
            .content_id
            .clone();
        store.restore_file_version("/notes/a.md", &good).await.unwrap();
        assert_eq!(store.read_file("/notes/a.md").await.unwrap(), b"the good draft");

        // The daemon's record is not a file of the person's: the switch
        // spelled at its key finds nothing, and the record keeps no versions.
        let daemon_path = "/network/members/did:key:zReal";
        assert!(store.set_file_keep_versions(daemon_path, true).await.is_err());
        assert!(
            !matches!(store.file_keeps_versions(daemon_path).await, Ok(true)),
            "the daemon's record reads as keeping versions through the person's door"
        );
        assert!(
            store
                .file_versions(daemon_path)
                .await
                .map(|v| v.is_empty())
                .unwrap_or(true),
            "the person's door listed versions of the daemon's record"
        );
        assert!(
            store.restore_file_version(daemon_path, &good).await.is_err(),
            "a restore through the person's door wrote at the daemon record's path"
        );
        assert!(!local
            .keeps_versions(std::path::Path::new("network/members/did:key:zReal"))
            .await
            .unwrap());
        assert_eq!(
            store
                .read_daemon_object("/network/members/did:key:zReal")
                .await
                .unwrap(),
            b"the daemon's"
        );
    }

    /// **A hand-over is *sent* when its write is in the log, and not before**
    /// (*a device of your own*; the share sheet reads this).
    ///
    /// A write lands loose: durable, and in no segment, so the readout says
    /// nothing. The packing pass commits it into a segment and the readout
    /// names that segment's generation. A second write to the same path is
    /// loose again — the version the log holds is no longer the current one —
    /// and the next pass names a later generation. A path nobody wrote, and a
    /// store that keeps no history, answer nothing rather than a number.
    #[tokio::test]
    async fn a_write_is_in_the_log_once_a_pass_commits_it_and_not_while_it_is_loose() {
        let temp = tempfile::tempdir().unwrap();
        let store = UserStore::create(
            "alice",
            "did:key:z6Mk...",
            temp.path().to_path_buf(),
            UserKeys::new(Some([7u8; 32])).with_log("did:key:zThisDevice", &[3u8; 32]),
            &crate::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();
        let pack = || async {
            crate::runtime::pack_mount(&*store.get_remote("local").unwrap(), "local")
                .await
                .unwrap()
                .expect("an unlocked store packs");
        };

        store.write_file("/Inbox/photo.jpg", b"the first").await.unwrap();
        assert_eq!(
            store.file_logged("/Inbox/photo.jpg").await.unwrap(),
            None,
            "a loose write read as in the log"
        );
        pack().await;
        let first = store
            .file_logged("/Inbox/photo.jpg")
            .await
            .unwrap()
            .expect("the pass committed the write into a segment");

        store.write_file("/Inbox/photo.jpg", b"the second").await.unwrap();
        assert_eq!(
            store.file_logged("/Inbox/photo.jpg").await.unwrap(),
            None,
            "the log's version read as current while a newer write is loose"
        );
        pack().await;
        let second = store
            .file_logged("/Inbox/photo.jpg")
            .await
            .unwrap()
            .expect("the second pass committed the second write");
        assert!(second > first, "{second} is not after {first}");

        assert_eq!(store.file_logged("/Inbox/nobody.jpg").await.unwrap(), None);

        let bare = tempfile::tempdir().unwrap();
        let unlogged = UserStore::create(
            "bob",
            "did:key:z6Mk...",
            bare.path().to_path_buf(),
            UserKeys::new(Some([7u8; 32])),
            &crate::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();
        unlogged.write_file("/Inbox/photo.jpg", b"the first").await.unwrap();
        crate::runtime::pack_mount(&*unlogged.get_remote("local").unwrap(), "local")
            .await
            .unwrap();
        assert_eq!(
            unlogged.file_logged("/Inbox/photo.jpg").await.unwrap(),
            None,
            "a store that keeps no history named a generation"
        );
    }

    #[test]
    fn test_to_object_key() {
        assert_eq!(to_object_key("/foo/bar"), "foo/bar");
        assert_eq!(to_object_key("foo/bar"), "foo/bar");
        assert_eq!(to_object_key("/foo\\bar"), "foo/bar");
        // Redundant slashes are collapsed by normalization (was: leading-only).
        assert_eq!(to_object_key("///foo///bar"), "foo/bar");
        // `.`/`..` are collapsed so a traversal cannot map to a sibling key (H3).
        assert_eq!(to_object_key("/notes/../../etc/identity"), "etc/identity");
        assert_eq!(to_object_key("/a/./b/../c"), "a/c");
        assert_eq!(to_object_key("/"), "");
    }
}
