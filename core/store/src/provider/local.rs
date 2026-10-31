// SPDX-License-Identifier: AGPL-3.0-or-later
/// Local filesystem-based object storage
///
/// Uses platform::Filesystem to store objects as files on local disk.
/// Bridges object storage semantics to filesystem operations.
use async_trait::async_trait;
use bytes::Bytes;
use kotton_sys::fs::Filesystem;
use kotton_sys::store::{
    ObjectMetadata, ObjectStorage, ObjectStorageError, ObjectStorageResult, SealedObjectAccess,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Local filesystem object storage
pub struct LocalObjectStorage {
    /// Base path for object storage
    base_path: PathBuf,
    /// Platform filesystem implementation
    filesystem: Arc<dyn Filesystem>,
}

impl LocalObjectStorage {
    /// Create new local object storage rooted at base_path
    pub fn new<F: Filesystem + 'static>(base_path: PathBuf, filesystem: F) -> Self {
        Self {
            base_path,
            filesystem: Arc::new(filesystem),
        }
    }

    /// Resolve object key to absolute filesystem path.
    ///
    /// VFS keys are a **logical** namespace: a segment may legally contain bytes
    /// that the host filesystem rejects (e.g. membership records are keyed by DID
    /// — `did:key:z…` — and `:` is illegal in a Windows filename). Each path
    /// segment is therefore percent-encoded for the host (see [`encode_segment`]);
    /// [`list`](Self::list) decodes on the way back, so the logical key is
    /// host-independent. Separators are preserved as directory structure; only
    /// `Normal` components are encoded.
    ///
    /// **A key resolves under the mount root or not at all.** A `..`
    /// component, or a host prefix such as a Windows drive, is refused: it
    /// would name a path outside the root, and no key the store writes has
    /// one. Keys from outside are admitted before they get here: a sync
    /// pass's listings ([`crate::StorageKey`], kotton #265), and a pack id a
    /// manifest or superblock names, at decode ([`crate::packed::PackId`],
    /// kotton #273), so neither reaches this refusal any more.
    ///
    /// What it still stands in for: `UserStore::read_raw_local_object`, which
    /// reads the path a guest re-wrap names on a store of its own, past a
    /// trimmed leading `/` and admitted by nothing else. That is the reach to
    /// close before this refusal can go. Drive move (kotton #274) writes
    /// through a vault's `write_sealed`, which admits, and `Sealed::list`
    /// (kotton #275) collapses `..` before it lists, so neither reaches here
    /// with one; each is a rewrite or a silence to close at its own door.
    ///
    /// A leading `/` and a `.` component name nothing outside the root and
    /// are read past, as the logical paths the VFS hands this store may carry
    /// them.
    fn resolve_key(&self, key: &Path) -> ObjectStorageResult<PathBuf> {
        use std::path::Component;
        let mut path = self.base_path.clone();
        for comp in key.components() {
            match comp {
                Component::Normal(seg) => path.push(encode_segment(&seg.to_string_lossy())),
                Component::ParentDir | Component::Prefix(_) => {
                    return Err(ObjectStorageError::InvalidKey(format!(
                        "{}: names a path outside the mount root",
                        key.display()
                    )))
                }
                Component::CurDir | Component::RootDir => {}
            }
        }
        Ok(path)
    }

    /// Convert filesystem error to object storage error
    fn map_error(e: impl std::error::Error, key: &str) -> ObjectStorageError {
        let err_str = e.to_string().to_lowercase();
        if err_str.contains("not found") || err_str.contains("no such file") {
            ObjectStorageError::NotFound(key.to_string())
        } else if err_str.contains("permission") || err_str.contains("denied") {
            ObjectStorageError::PermissionDenied(e.to_string())
        } else {
            ObjectStorageError::IoError(e.to_string())
        }
    }
}

/// What a put's in-flight copy is named with: `%` followed by a byte that is not
/// a hex digit, which [`encode_segment`] can never produce — it writes every `%`
/// as `%25` — so no key resolves to such a name, and a listing can tell the copy
/// from an object without guessing.
const IN_FLIGHT: &str = "%put-";

/// How old an in-flight copy must be before a listing reaps it, in seconds.
///
/// A put writes its copy and renames it in one call, which never takes a
/// minute, so a copy older than this is one whose put will never finish: the
/// process stopped between the write and the rename. It is clutter, never an
/// object — no listing names it and no key reads it — but it holds a version
/// of the object's bytes, so the next listing of its directory deletes it. A
/// store nobody lists keeps it; that is the limit of reaping at one site.
const IN_FLIGHT_STALE_SECS: i64 = 60;

/// Where a put of `target` writes before renaming over it: the same directory,
/// so the rename is atomic on one filesystem, under a name of fixed length, so
/// a key near the host's name limit does not overflow it.
fn in_flight_beside(target: &Path) -> PathBuf {
    let name = format!("{IN_FLIGHT}{:016x}", rand::random::<u64>());
    match target.parent() {
        Some(dir) => dir.join(name),
        None => PathBuf::from(name),
    }
}

/// Whether a listed host path is a put's in-flight copy rather than an object.
fn is_in_flight(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|n| n.to_string_lossy().starts_with(IN_FLIGHT))
}

/// Bytes unsafe in a path *segment* on a supported host filesystem — Windows is
/// the strict one (`< > : " \ | ? *` and control bytes) — plus `%` itself so the
/// encoding is reversible. Path separators are not in this set: they are handled
/// as directory structure by [`LocalObjectStorage::resolve_key`], never escaped.
fn segment_byte_needs_escape(b: u8) -> bool {
    b < 0x20 || matches!(b, b'%' | b'<' | b'>' | b':' | b'"' | b'\\' | b'|' | b'?' | b'*')
}

fn hex_digit(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'A' + (n - 10)) as char,
    }
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Percent-encode the host-unsafe bytes of one logical path segment so it is a
/// legal host filename. Inverse of [`decode_segment`].
///
/// Note: this escapes the host-illegal *character* set; reserved whole-segment
/// forms (Windows device names like `CON`, trailing dot/space) are out of scope
/// — the logical keys in use (DIDs, structured VFS paths) cannot produce them.
/// Extend here if a future key class can.
fn encode_segment(seg: &str) -> String {
    let mut out = String::with_capacity(seg.len());
    for ch in seg.chars() {
        match u8::try_from(ch as u32) {
            Ok(b) if segment_byte_needs_escape(b) => {
                out.push('%');
                out.push(hex_digit(b >> 4));
                out.push(hex_digit(b & 0x0f));
            }
            _ => out.push(ch),
        }
    }
    out
}

/// Reverse [`encode_segment`]: percent-decode `%XX` escapes in one segment. A `%`
/// not followed by two hex digits is passed through literally.
fn decode_segment(seg: &str) -> String {
    let bytes = seg.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[async_trait]
impl ObjectStorage for LocalObjectStorage {
    async fn get(&self, key: &Path) -> ObjectStorageResult<Bytes> {
        let abs_path = self.resolve_key(key)?;
        let bytes = self
            .filesystem
            .read_file(&abs_path)
            .await
            .map_err(|e| Self::map_error(e, key.to_str().unwrap_or("")))?;
        Ok(bytes)
    }

    async fn put(&self, key: &Path, data: &[u8]) -> ObjectStorageResult<()> {
        let abs_path = self.resolve_key(key)?;

        // Ensure parent directory exists
        if let Some(parent) = abs_path.parent() {
            self.filesystem
                .create_dir_all(parent)
                .await
                .map_err(|e| Self::map_error(e, key.to_str().unwrap_or("")))?;
        }

        // Written beside the object under a name no key resolves to, then
        // renamed over it: a reader racing this put opens the old object or the
        // new one, never a truncated one. `write_file` alone truncates and then
        // writes, and a get in between read a torn object — which failed the
        // whole of a listing the blinded layer took, and left a person who had
        // just learned a contact's new key with no door for anyone.
        let in_flight = in_flight_beside(&abs_path);
        let written = match self.filesystem.write_file(&in_flight, data).await {
            Ok(()) => self.filesystem.move_path(&in_flight, &abs_path).await,
            Err(e) => Err(e),
        };
        if let Err(e) = written {
            // The in-flight copy is this put's litter, so it is this put's to
            // sweep; left behind it would sit beside the object holding bytes
            // nobody's listing will ever name.
            let _ = self.filesystem.delete_file(&in_flight).await;
            return Err(Self::map_error(e, key.to_str().unwrap_or("")));
        }
        Ok(())
    }

    async fn delete(&self, key: &Path) -> ObjectStorageResult<()> {
        let abs_path = self.resolve_key(key)?;
        self.filesystem
            .delete_file(&abs_path)
            .await
            .map_err(|e| Self::map_error(e, key.to_str().unwrap_or("")))?;
        Ok(())
    }

    async fn list(&self, prefix: &Path) -> ObjectStorageResult<Vec<ObjectMetadata>> {
        let abs_path = self.resolve_key(prefix)?;
        let entries = match self.filesystem.list_dir(&abs_path).await {
            Ok(entries) => entries,
            Err(e) => match Self::map_error(e, prefix.to_str().unwrap_or("")) {
                // A non-existent prefix is not an error — it simply has no objects.
                ObjectStorageError::NotFound(_) => return Ok(vec![]),
                other => return Err(other),
            },
        };

        let mut result = Vec::new();
        for metadata in entries {
            // A put still in flight is not an object yet. One left by a put
            // that stopped before its rename is not going to be one, and is
            // swept here (`IN_FLIGHT_STALE_SECS`).
            if is_in_flight(Path::new(&metadata.path)) {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                if now - metadata.modified > IN_FLIGHT_STALE_SECS {
                    let _ = self
                        .filesystem
                        .delete_file(Path::new(&metadata.path))
                        .await;
                }
                continue;
            }
            // Recover the logical key from the host path: strip the mount root,
            // then decode each segment (the inverse of `resolve_key`'s encoding)
            // and rejoin with `/` so the returned key is host-independent and
            // re-resolves identically when fed back to get/read.
            let entry_path = PathBuf::from(&metadata.path);
            let rel = entry_path
                .strip_prefix(&self.base_path)
                .unwrap_or(&entry_path);
            let rel_key = rel
                .components()
                .filter_map(|c| match c {
                    std::path::Component::Normal(s) => Some(decode_segment(&s.to_string_lossy())),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("/");

            result.push(ObjectMetadata {
                key: rel_key,
                is_dir: metadata.is_directory,
                size: metadata.size,
                modified: Some(metadata.modified as u64),
            });
        }

        Ok(result)
    }

    async fn metadata(&self, key: &Path) -> ObjectStorageResult<ObjectMetadata> {
        let abs_path = self.resolve_key(key)?;
        let metadata = self
            .filesystem
            .file_metadata(&abs_path)
            .await
            .map_err(|e| Self::map_error(e, key.to_str().unwrap_or("")))?;

        Ok(ObjectMetadata {
            key: key.to_string_lossy().to_string(),
            is_dir: metadata.is_directory,
            size: metadata.size,
            modified: Some(metadata.modified as u64),
        })
    }

    fn backend_name(&self) -> &str {
        "local"
    }
}

/// Identity — this backend applies no sealing of its own, so the bytes at rest
/// *are* the sealed view.
///
/// When it is the inner store of an [`EncryptedObjectStorage`] those bytes are
/// the encrypted envelope; when it stands alone (an unencrypted store, or a
/// `BlindStorage` that holds only material sealed elsewhere) they are whatever
/// was written. Either way the contract holds: return what rests here, unaltered.
///
/// [`EncryptedObjectStorage`]: crate::EncryptedObjectStorage
#[async_trait]
impl SealedObjectAccess for LocalObjectStorage {
    async fn get_sealed(&self, key: &Path) -> ObjectStorageResult<Bytes> {
        self.get(key).await
    }

    async fn put_sealed(&self, key: &Path, blob: &[u8]) -> ObjectStorageResult<()> {
        self.put(key, blob).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts;
    use kotton_fs::OsFilesystem;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_local_object_storage() {
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalObjectStorage::new(temp_dir.path().to_path_buf(), OsFilesystem);

        // Put object
        let key = Path::new("test/file.txt");
        let data = b"Hello, World!";
        storage.put(key, data).await.unwrap();

        // Get object
        let retrieved = storage.get(key).await.unwrap();
        assert_eq!(&retrieved[..], data);

        // Metadata
        let meta = storage.metadata(key).await.unwrap();
        assert_eq!(meta.size, data.len() as u64);
        assert!(!meta.is_dir);

        // Exists
        assert!(storage.exists(key).await.unwrap());

        // Delete
        storage.delete(key).await.unwrap();
        assert!(!storage.exists(key).await.unwrap());
    }

    /// A put that stopped between its write and its rename leaves an in-flight
    /// copy; the next listing of its directory deletes it once it is older than
    /// [`IN_FLIGHT_STALE_SECS`], and leaves a younger one, which may be a put
    /// still running. Either way the listing names only the object.
    #[tokio::test]
    async fn a_stale_in_flight_copy_is_reaped_by_a_listing_and_a_fresh_one_is_left() {
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalObjectStorage::new(temp_dir.path().to_path_buf(), OsFilesystem);
        storage.put(Path::new("shelf/object"), b"the object").await.unwrap();
        let dir = temp_dir.path().join("shelf");
        let stale = dir.join(format!("{IN_FLIGHT}00000000000000aa"));
        let fresh = dir.join(format!("{IN_FLIGHT}00000000000000bb"));
        std::fs::write(&stale, b"an older version of the object").unwrap();
        std::fs::write(&fresh, b"a put still running").unwrap();
        let old = std::time::SystemTime::now()
            - std::time::Duration::from_secs(IN_FLIGHT_STALE_SECS as u64 * 2);
        std::fs::File::options().write(true).open(&stale).unwrap().set_modified(old).unwrap();

        let keys = |listed: Vec<ObjectMetadata>| listed.into_iter().map(|m| m.key).collect::<Vec<_>>();
        let listed = keys(storage.list(Path::new("shelf/")).await.unwrap());
        assert_eq!(listed, vec!["shelf/object".to_string()], "the listing names the object alone");
        assert!(!stale.exists(), "a copy older than a put ever takes is reaped by one listing");
        assert!(fresh.exists(), "a copy a put may still rename is left alone");
        assert_eq!(
            keys(storage.list(Path::new("shelf/")).await.unwrap()),
            listed,
            "the reap changes nothing a listing names"
        );
    }

    #[tokio::test]
    async fn satisfies_object_storage_contract() {
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalObjectStorage::new(temp_dir.path().to_path_buf(), OsFilesystem);
        contracts::run_all(storage).await;
    }

    /// A key whose segment contains host-illegal characters (`:` is the real
    /// case — membership records are keyed by `did:key:…`, and `:` is reserved on
    /// Windows) must round-trip through put / get / metadata / list / delete. This
    /// is the regression guard for VFS-PATH-PORTABILITY.
    #[tokio::test]
    async fn key_with_host_illegal_chars_round_trips() {
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalObjectStorage::new(temp_dir.path().to_path_buf(), OsFilesystem);

        // A membership-style key plus a sampling of the other reserved chars.
        let key = Path::new("network/members/did:key:zNode2");
        let data = b"member record";
        storage.put(key, data).await.expect("put a colon-bearing key");
        assert_eq!(
            &storage.get(key).await.expect("get it back")[..],
            data,
            "the colon-bearing key reads back identically"
        );
        assert!(storage.exists(key).await.unwrap());

        // list under the parent must return the *logical* key (decoded, '/'-joined),
        // so a caller can feed it straight back into get.
        let listed = storage.list(Path::new("network/members/")).await.unwrap();
        let keys: Vec<&str> = listed.iter().map(|m| m.key.as_str()).collect();
        assert!(
            keys.contains(&"network/members/did:key:zNode2"),
            "list returns the decoded logical key, got {keys:?}"
        );
        let round_tripped = Path::new(keys[0]);
        assert_eq!(
            &storage.get(round_tripped).await.expect("get via listed key")[..],
            data,
            "the key returned by list re-resolves to the same object"
        );

        storage.delete(key).await.unwrap();
        assert!(!storage.exists(key).await.unwrap());
    }

    /// A key that would resolve outside the mount root is refused by every
    /// verb, and nothing is written or read beside the root (kotton #265).
    #[tokio::test]
    async fn a_key_naming_a_path_outside_the_root_is_refused() {
        let outer = TempDir::new().unwrap();
        let root = outer.path().join("mount");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(outer.path().join("beside"), b"outside the root").unwrap();
        let storage = LocalObjectStorage::new(root.clone(), OsFilesystem);
        for key in ["../x", "_pack/../../x", "a/../../x"] {
            let refused = storage.put_sealed(Path::new(key), b"sealed").await;
            assert!(matches!(refused, Err(ObjectStorageError::InvalidKey(_))), "{key}: {refused:?}");
        }
        assert!(!outer.path().join("x").exists(), "a put landed outside the root");
        for refused in [
            storage.get(Path::new("../beside")).await.map(|_| ()),
            storage.metadata(Path::new("../beside")).await.map(|_| ()),
            storage.delete(Path::new("../beside")).await,
            storage.list(Path::new("../")).await.map(|_| ()),
        ] {
            assert!(matches!(refused, Err(ObjectStorageError::InvalidKey(_))), "{refused:?}");
        }
        assert!(outer.path().join("beside").exists(), "a delete reached outside the root");
    }

    #[test]
    fn encode_decode_segment_round_trips_the_reserved_set() {
        for seg in [
            "did:key:zNode2",
            "plain",
            "a<b>c:d\"e\\f|g?h*i",
            "%already%percent",
            "unicode-é-ok",
        ] {
            assert_eq!(decode_segment(&encode_segment(seg)), seg, "round-trip {seg}");
        }
        // The colon is actually escaped (not passed through).
        assert!(encode_segment("a:b").contains("%3A"));
    }
}
