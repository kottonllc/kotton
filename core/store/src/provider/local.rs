// SPDX-License-Identifier: AGPL-3.0-or-later
/// Local filesystem-based object storage
///
/// Uses platform::Filesystem to store objects as files on local disk.
/// Bridges object storage semantics to filesystem operations.
///
/// A key's segments are written to the disk through [`encode_segment`], and a
/// listing reads them back through [`decode_segment`]. The directory can hold
/// names this store never wrote — a put's in-flight copy, or a file put there
/// by hand — and a listing names only a host name in `encode_segment`'s image,
/// so every key it names resolves back to the name it was read from
/// (kotton #349). One gap is open: the filesystem layer hands this store each
/// name as text, converted lossily, so a host name that is not UTF-8 arrives
/// already rewritten (see [`decode_segment`]).
use async_trait::async_trait;
use bytes::Bytes;
use kotton_sys::fs::{Filesystem, FilesystemError};
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
    /// host-independent, and lists only host names this encoding writes, so
    /// a listed key resolves here to the very name it was listed from.
    /// Separators are preserved as directory structure; only `Normal`
    /// components are encoded.
    ///
    /// **A key resolves under the mount root or not at all.** A `..`
    /// component, or a host prefix such as a Windows drive, is refused: it
    /// would name a path outside the root, and no key the store writes has
    /// one. Keys from outside are admitted before they get here: a sync
    /// pass's listings ([`crate::StorageKey`], kotton #265), and a pack id a
    /// manifest or superblock names, at decode ([`crate::packed::PackId`],
    /// kotton #273), so neither reaches this refusal any more.
    ///
    /// What it no longer stands in for: drive move (kotton #274) admits each
    /// key where the source vault's listing enters it and writes through a
    /// vault's `write_sealed`, which admits again, and
    /// `kotton_sealed::Sealed` takes only admitted keys and prefixes
    /// (kotton #275, #320) and admits each directory key a store lists
    /// before it descends into it (kotton #336). `BlindedObjectStorage`'s
    /// walk (`collect_leaves`, behind its `list`, the packer's `list_loose`
    /// and the blinding migration) admits every key the inner store lists,
    /// directory or leaf, before it descends into it or hands it to a read,
    /// write or delete (kotton #357). `kvaultd::meter::Meter::measure`
    /// holds the directories it descends into as admitted keys, parsed where
    /// the listing enters its walk (kotton #352). None of them reaches here
    /// with a key it did not admit.
    ///
    /// The door still relying on this refusal, to close before it can go:
    ///
    /// - The guest re-wrap's raw read (kotton #299):
    ///   `UserStore::read_raw_local_object` reads the path a re-wrap names on
    ///   a store of its own, past a trimmed leading `/`, admitted by nothing
    ///   else.
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

    /// What a failed operation on `key` answers: [`Self::map_error`]'s
    /// answer, except that "not found" is absence only under a root that is
    /// there.
    ///
    /// **A store whose root is gone holds nothing it can name, and says so as
    /// a refusal** (kotton #412). Every key under a missing root is missing
    /// too, so ENOENT alone would answer `NotFound` for every object and an
    /// empty listing for every prefix: a shelf unmounted or its directory
    /// removed from outside would read as a store that holds nothing, and a
    /// device that reads a drive's absence as "not held" may delete what only
    /// that drive keeps. So the one operation that met ENOENT asks whether
    /// the root is there, and only then answers absence. A missing root is an
    /// `IoError` naming it. A read that finds what it asked for never asks; a
    /// write always does ([`Self::root_is_there`]).
    async fn answer(&self, e: ObjectStorageError) -> ObjectStorageError {
        let ObjectStorageError::NotFound(key) = e else {
            return e;
        };
        let root = self.base_path.display();
        match self.filesystem.dir_exists(&self.base_path).await {
            Ok(true) => ObjectStorageError::NotFound(key),
            Ok(false) => ObjectStorageError::IoError(format!(
                "{root}: the store's root is missing, so it cannot say whether it holds '{key}'"
            )),
            Err(why) => ObjectStorageError::IoError(format!(
                "{root}: whether the store's root is there could not be read ({why}), so it cannot \
                 say whether it holds '{key}'"
            )),
        }
    }

    /// Refuse a write under a root that is not there (kotton #415).
    ///
    /// The root is made once, by whoever makes the mount (`UserStore::create`
    /// and `add_shelf_tree`, through `kotton_common::fs::create_dir_all_owner_only`),
    /// and never by a write. A store whose root has gone refuses every read,
    /// listing and delete ([`Self::answer`]); a write that made the root again,
    /// as the next `WriteSealed` of any routine push would, would turn every
    /// later read of what the old root held into a true `NotFound`, and a
    /// device's compaction may then retire a generation only that drive kept.
    /// So a `put` asks whether the root is there before it writes, refuses
    /// naming the root when it is not, and makes only the parents below it.
    async fn root_is_there(&self, key: &Path) -> ObjectStorageResult<()> {
        let root = self.base_path.display();
        let key = key.display();
        match self.filesystem.dir_exists(&self.base_path).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(ObjectStorageError::IoError(format!(
                "{root}: the store's root is missing, so '{key}' is not written under it; a write \
                 makes no root"
            ))),
            Err(why) => Err(ObjectStorageError::IoError(format!(
                "{root}: whether the store's root is there could not be read ({why}), so '{key}' \
                 is not written under it"
            ))),
        }
    }

    /// Convert filesystem error to object storage error.
    ///
    /// **An error is `NotFound` by its variant, never by its words** (kotton
    /// #416). `NotFound` is what `held_generation` reads as "neither", so it
    /// is answered only for a provider that said `FilesystemError::NotFound`;
    /// a failure whose text happens to say "not found" is an `IoError`. The
    /// providers type ENOENT and EACCES at their source (`map_io_error` in
    /// `kotton-fs`), so there is no second rule here.
    fn map_error(e: FilesystemError, key: &str) -> ObjectStorageError {
        match e {
            FilesystemError::NotFound(_) => ObjectStorageError::NotFound(key.to_string()),
            FilesystemError::PermissionDenied(_) => {
                ObjectStorageError::PermissionDenied(e.to_string())
            }
            other => ObjectStorageError::IoError(other.to_string()),
        }
    }
}

/// What a put's in-flight copy is named with: `%` followed by a byte that is not
/// a hex digit, which [`encode_segment`] can never produce — it writes every `%`
/// as `%25` — so no key resolves to such a name. A listing leaves it out by the
/// rule it applies to every name, [`decode_segment`]'s; this prefix only tells
/// it which of the names it leaves out are a put's to reap.
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
/// legal host filename. [`decode_segment`] inverts it on its image, and refuses
/// every name outside it.
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

/// Reverse [`encode_segment`]: the logical segment it encodes to the host name
/// `seg`, or `None` when it encodes none to it.
///
/// `None` is every name `encode_segment` never writes: a `%` not followed by
/// two hex digits (`a%zz`, and a put's in-flight copy, [`IN_FLIGHT`]), an
/// escape in lower case or of a byte it leaves alone (`%3a`, `%41`), an
/// unescaped byte it would escape, or escapes that decode to bytes that are
/// not UTF-8 (`%FF`). Decoded leniently, such a name would give a key that
/// resolves to another name, so a listing would name an object that no verb
/// on its key reaches, and a walk that deletes what it lists would fail on it
/// (kotton #349). The test is exact: a name is decoded only if encoding the
/// result spells it again.
///
/// It is exact on the text it is given, and that text is not always the host
/// name. The filesystem layer lists each name as a `String`, converted
/// lossily, so a host name whose bytes are not UTF-8 (`a\xff`) arrives as
/// `a\u{FFFD}`: inside the image, listed under a key that resolves to a name
/// that is not there, and a walk that deletes it still fails. Closing that
/// wants the filesystem layer to hand names over as the host's bytes; it is
/// the open part of this rule.
fn decode_segment(seg: &str) -> Option<String> {
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
    let decoded = String::from_utf8(out).ok()?;
    (encode_segment(&decoded) == seg).then_some(decoded)
}

#[async_trait]
impl ObjectStorage for LocalObjectStorage {
    async fn get(&self, key: &Path) -> ObjectStorageResult<Bytes> {
        let abs_path = self.resolve_key(key)?;
        match self.filesystem.read_file(&abs_path).await {
            Ok(bytes) => Ok(bytes),
            Err(e) => Err(self.answer(Self::map_error(e, key.to_str().unwrap_or(""))).await),
        }
    }

    async fn put(&self, key: &Path, data: &[u8]) -> ObjectStorageResult<()> {
        let abs_path = self.resolve_key(key)?;

        // The root is there or the write is refused; only the parents below it
        // are made here (kotton #415).
        self.root_is_there(key).await?;
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
        match self.filesystem.delete_file(&abs_path).await {
            Ok(()) => Ok(()),
            Err(e) => Err(self.answer(Self::map_error(e, key.to_str().unwrap_or(""))).await),
        }
    }

    /// The objects and directories directly under `prefix`, each by the key
    /// that resolves back to its host name.
    ///
    /// A listing names what this store wrote and nothing else: a host name is
    /// named only if [`decode_segment`] decodes it, which is only if
    /// [`encode_segment`] writes it. A name outside that image — a put's
    /// in-flight copy, or a file or directory put there by hand, such as
    /// `a%zz` — is not listed, so a caller's walk neither hands it to a verb
    /// under a key that resolves elsewhere nor descends into it (kotton #349).
    /// It stays where it rests; a stale in-flight copy is reaped.
    async fn list(&self, prefix: &Path) -> ObjectStorageResult<Vec<ObjectMetadata>> {
        let abs_path = self.resolve_key(prefix)?;
        let entries = match self.filesystem.list_dir(&abs_path).await {
            Ok(entries) => entries,
            Err(e) => match self.answer(Self::map_error(e, prefix.to_str().unwrap_or(""))).await {
                // A non-existent prefix under a present root is not an error —
                // it simply has no objects.
                ObjectStorageError::NotFound(_) => return Ok(vec![]),
                other => return Err(other),
            },
        };

        let mut result = Vec::new();
        for metadata in entries {
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
                    std::path::Component::Normal(s) => Some(s.to_str().and_then(decode_segment)),
                    _ => None,
                })
                .collect::<Option<Vec<_>>>()
                .map(|segments| segments.join("/"));
            // The one listing rule: a name `encode_segment` never writes is
            // not an object of this store, file or directory, and is not
            // named, so no walk of the listing reaches it by a key that
            // resolves elsewhere or descends into it. A put still in flight
            // is such a name; one left by a put that stopped before its
            // rename never will be an object, and is swept here
            // (`IN_FLIGHT_STALE_SECS`). Any other is left where it rests.
            let Some(rel_key) = rel_key else {
                if is_in_flight(&entry_path) {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    if now - metadata.modified > IN_FLIGHT_STALE_SECS {
                        let _ = self.filesystem.delete_file(&entry_path).await;
                    }
                }
                continue;
            };

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
        let metadata = match self.filesystem.file_metadata(&abs_path).await {
            Ok(metadata) => metadata,
            Err(e) => return Err(self.answer(Self::map_error(e, key.to_str().unwrap_or(""))).await),
        };

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

    /// **A listing names only what resolves back to the host name it was read
    /// from** (kotton #349). Beside objects whose keys `encode_segment`
    /// escapes, the root holds names it never writes: a bare `%` (`a%zz`), an
    /// escape of a byte it leaves alone (`%41`), one in lower case (`%3a`), and
    /// a directory `b%zz` with a file inside. Each would decode to a key that
    /// resolves elsewhere; none is listed, every listed key resolves back
    /// through `resolve_key` to a path on the disk, and the contract's walk
    /// reads every leaf it lists. The planted names stay where they are.
    #[tokio::test]
    async fn a_listing_names_only_keys_that_resolve_back_to_their_host_names() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        let storage = LocalObjectStorage::new(root.to_path_buf(), OsFilesystem);
        storage.put(Path::new("pct/%already"), b"one").await.unwrap();
        storage.put(Path::new("pct/did:key:zNode2"), b"two").await.unwrap();
        let planted = [root.join("a%zz"), root.join("%41"), root.join("pct/%3a"), root.join("b%zz/inner")];
        std::fs::create_dir_all(root.join("b%zz")).unwrap();
        for host in &planted {
            std::fs::write(host, b"planted").unwrap();
        }

        let mut every = Vec::new();
        let mut pending = vec![String::new()];
        while let Some(prefix) = pending.pop() {
            for entry in storage.list(Path::new(&prefix)).await.unwrap() {
                let host = storage.resolve_key(Path::new(&entry.key)).unwrap();
                assert!(host.exists(), "{:?} is listed but resolves to {host:?}, which is not there", entry.key);
                if entry.is_dir {
                    pending.push(entry.key.clone());
                }
                every.push(entry.key);
            }
        }
        every.sort();
        assert_eq!(every, ["pct", "pct/%already", "pct/did:key:zNode2"], "the listing names what the store wrote, and only that");
        contracts::every_listed_key_resolves_back(&storage).await;
        for host in &planted {
            assert!(host.exists(), "a listing removed {host:?}");
        }
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

    /// **A store whose root is gone refuses; it does not answer absence**
    /// (kotton #412). A key missing under a present root is `NotFound`, and a
    /// prefix missing under it lists nothing. Once the root itself is removed
    /// (a shelf unmounted, a directory deleted from outside) every read,
    /// listing and delete is an error naming the root: the store cannot say
    /// what it holds, and "nothing" would read as an answer.
    #[tokio::test]
    async fn a_store_whose_root_is_missing_refuses_rather_than_answering_absence() {
        let outer = TempDir::new().unwrap();
        let root = outer.path().join("shelf");
        std::fs::create_dir_all(&root).unwrap();
        let storage = LocalObjectStorage::new(root.clone(), OsFilesystem);
        storage.put(Path::new("_pack/held"), b"sealed").await.unwrap();
        assert!(matches!(storage.get(Path::new("_pack/absent")).await, Err(ObjectStorageError::NotFound(_))));
        assert!(matches!(storage.get_sealed(Path::new("_pack/absent")).await, Err(ObjectStorageError::NotFound(_))));
        assert!(matches!(storage.delete(Path::new("_pack/absent")).await, Err(ObjectStorageError::NotFound(_))));
        assert!(matches!(storage.metadata(Path::new("_pack/absent")).await, Err(ObjectStorageError::NotFound(_))));
        assert!(storage.list(Path::new("no/such/prefix")).await.unwrap().is_empty());

        std::fs::remove_dir_all(&root).unwrap();
        let named = root.display().to_string();
        for refused in [
            storage.get(Path::new("_pack/held")).await.map(|_| ()),
            storage.get_sealed(Path::new("_pack/held")).await.map(|_| ()),
            storage.metadata(Path::new("_pack/held")).await.map(|_| ()),
            storage.delete(Path::new("_pack/held")).await,
            storage.list(Path::new("")).await.map(|_| ()),
            storage.list(Path::new("_pack")).await.map(|_| ()),
        ] {
            match refused {
                Err(ObjectStorageError::IoError(m)) => assert!(m.contains(&named), "the refusal does not name the root: {m}"),
                other => panic!("a store whose root is gone answered {other:?}"),
            }
        }
    }

    /// **A write does not make a missing root** (kotton #415). Once a shelf's
    /// root is gone, a `put` is refused naming the root, the root is still
    /// not there afterwards, and the next read still refuses rather than
    /// answering absence: a routine push cannot turn "the root is missing"
    /// into "the store holds nothing". Under a present root, a write still
    /// makes the parents below it.
    #[tokio::test]
    async fn a_write_does_not_recreate_a_missing_root() {
        let outer = TempDir::new().unwrap();
        let root = outer.path().join("shelf");
        std::fs::create_dir_all(&root).unwrap();
        let storage = LocalObjectStorage::new(root.clone(), OsFilesystem);
        storage.put(Path::new("_pack/deep/held"), b"sealed").await.unwrap();
        assert_eq!(storage.get(Path::new("_pack/deep/held")).await.unwrap().as_ref(), b"sealed");

        std::fs::remove_dir_all(&root).unwrap();
        let named = root.display().to_string();
        for refused in [
            storage.put(Path::new("_pack/next"), b"sealed").await,
            storage.put_sealed(Path::new("_pack/next"), b"sealed").await,
        ] {
            match refused {
                Err(ObjectStorageError::IoError(m)) => assert!(m.contains(&named), "the refusal does not name the root: {m}"),
                other => panic!("a write under a missing root answered {other:?}"),
            }
        }
        assert!(!root.exists(), "a write made the root");
        match storage.get(Path::new("_pack/deep/held")).await {
            Err(ObjectStorageError::IoError(m)) => assert!(m.contains(&named), "{m}"),
            other => panic!("a read after the refused write answered {other:?}"),
        }
        match storage.get(Path::new("_pack/next")).await {
            Err(ObjectStorageError::IoError(m)) => assert!(m.contains(&named), "{m}"),
            other => panic!("a read of the refused key answered {other:?}"),
        }
    }

    /// **An error is `NotFound` by its variant, not by its words** (kotton
    /// #416). `held_generation` reads `NotFound` as "neither", so a failure
    /// whose text merely says "not found" must not become it.
    #[test]
    fn an_error_is_not_found_by_its_variant_not_by_its_words() {
        use kotton_sys::fs::FilesystemError as E;
        for look_alike in [
            E::IoError("I/O error: volume not found".into()),
            E::IoError("No such file or directory (os error 2)".into()),
            E::InvalidPath("not found".into()),
            E::AlreadyExists("not found".into()),
        ] {
            let mapped = LocalObjectStorage::map_error(look_alike, "k");
            assert!(matches!(mapped, ObjectStorageError::IoError(_)), "{mapped:?}");
        }
        let denied_by_words = E::IoError("permission denied by the volume".into());
        assert!(matches!(
            LocalObjectStorage::map_error(denied_by_words, "k"),
            ObjectStorageError::IoError(_)
        ));
        assert!(matches!(
            LocalObjectStorage::map_error(E::NotFound("/x".into()), "k"),
            ObjectStorageError::NotFound(k) if k == "k"
        ));
        assert!(matches!(
            LocalObjectStorage::map_error(E::PermissionDenied("/x".into()), "k"),
            ObjectStorageError::PermissionDenied(_)
        ));
    }

    /// The typed variant is what the OS provider hands up for ENOENT, on every
    /// operation the store calls, so absence is still absence.
    #[tokio::test]
    async fn a_real_missing_file_through_the_os_provider_is_still_not_found() {
        let dir = TempDir::new().unwrap();
        let storage = LocalObjectStorage::new(dir.path().to_path_buf(), OsFilesystem);
        let key = Path::new("absent/object");
        assert!(matches!(storage.get(key).await, Err(ObjectStorageError::NotFound(_))));
        assert!(matches!(storage.metadata(key).await, Err(ObjectStorageError::NotFound(_))));
        assert!(matches!(storage.delete(key).await, Err(ObjectStorageError::NotFound(_))));
        assert!(storage.list(Path::new("absent")).await.unwrap().is_empty());
    }

    /// EACCES is `PermissionDenied` by variant. Unix only, and skipped when the
    /// process can read past a 000 mode (root).
    #[cfg(unix)]
    #[tokio::test]
    async fn a_real_permission_error_through_the_os_provider_is_still_permission_denied() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let storage = LocalObjectStorage::new(dir.path().to_path_buf(), OsFilesystem);
        storage.put(Path::new("sealed/obj"), b"x").await.unwrap();
        let locked = dir.path().join("sealed");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read_dir(&locked).is_ok() {
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
            eprintln!("skipped: running with privileges that ignore file modes (root)");
            return;
        }
        let got = storage.get(Path::new("sealed/obj")).await;
        let listed = storage.list(Path::new("sealed")).await;
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(got, Err(ObjectStorageError::PermissionDenied(_))), "{got:?}");
        assert!(matches!(listed, Err(ObjectStorageError::PermissionDenied(_))), "{listed:?}");
    }

    /// A root that cannot be looked at is not a root that is missing (kotton
    /// #418): `answer` reaches its error arm and names the failure, instead
    /// of saying the root is missing. A parent that is a regular file gives
    /// ENOTDIR, which needs no permissions, so this asserts as root too.
    /// Unix only: Windows answers that path with `ERROR_PATH_NOT_FOUND`
    /// (`NotFound`), so there the root is reported missing by the OS itself.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_root_that_cannot_be_looked_at_is_not_reported_missing() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("plain");
        std::fs::write(&file, b"x").unwrap();
        let storage = LocalObjectStorage::new(file.join("shelf"), OsFilesystem);
        match storage.answer(ObjectStorageError::NotFound("k".into())).await {
            ObjectStorageError::IoError(m) => {
                assert!(m.contains("could not be read"), "wrong reason: {m}");
                assert!(!m.contains("is missing"), "a failure to look read as missing: {m}");
            }
            other => panic!("answered {other:?}"),
        }
    }

    /// The same through EACCES: the root's parent is mode 000. Unix only;
    /// skipped, and says so, when the process can look past it (root).
    #[cfg(unix)]
    #[tokio::test]
    async fn an_unreadable_root_reaches_answers_error_arm() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let locked = dir.path().join("locked");
        let root = locked.join("shelf");
        std::fs::create_dir_all(&root).unwrap();
        let storage = LocalObjectStorage::new(root.clone(), OsFilesystem);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::metadata(&root).is_ok() {
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
            eprintln!("skipped: running with privileges that ignore file modes (root)");
            return;
        }
        let got = storage.answer(ObjectStorageError::NotFound("k".into())).await;
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        match got {
            ObjectStorageError::IoError(m) => {
                assert!(m.contains("could not be read"), "wrong reason: {m}");
                assert!(!m.contains("is missing"), "{m}");
            }
            other => panic!("answered {other:?}"),
        }
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
            assert_eq!(decode_segment(&encode_segment(seg)).as_deref(), Some(seg), "round-trip {seg}");
        }
        // The colon is actually escaped (not passed through).
        assert!(encode_segment("a:b").contains("%3A"));
        // A name `encode_segment` never writes is decoded to nothing (kotton #349).
        for host in ["a%zz", "%", "a%2", "%3a", "%41", "a:b", "%FF", "%put-00000000000000aa"] {
            assert_eq!(decode_segment(host), None, "{host} is outside the image");
        }
    }
}
