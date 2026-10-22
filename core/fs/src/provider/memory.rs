// SPDX-License-Identifier: AGPL-3.0-or-later
//! In-memory filesystem — the second implementation of [`Filesystem`].
//!
//! Its purpose is the same as [`crate::OsFilesystem`]'s opposite number in
//! `03_providers/ipc`: give tests a filesystem that needs no disk, and give the
//! trait a second implementation so a host assumption cannot enter it unnoticed.
//! See `IDEA-tier-discipline`, Category 0.
//!
//! **It simplifies where the bytes live, never the contract.** `NotFound`,
//! `AlreadyExists`, `DirectoryNotEmpty`, and the create-parents behaviour of
//! `create_dir_all` match the OS implementation, because a double that is more
//! forgiving than the real thing turns an untested path into a falsely-tested
//! one.
//!
//! ## What writing this revealed about `&Path`
//!
//! The trait takes `&Path` and returns `FileMetadata { path: String, .. }`. A
//! store with no disk behind it needs a *key*, so this implementation converts
//! at the boundary via `to_string_lossy`. That is a small, honest cost here —
//! but it is the shape worth watching one tier up: `ObjectStorage` also keys on
//! `&Path`, and its memory, S3, and IPFS implementations have no filesystem
//! behind them at all.

use async_trait::async_trait;
use bytes::Bytes;
use kotton_sys::fs::{FileMetadata, Filesystem, FilesystemError, FilesystemResult};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, Mutex};

/// A [`Filesystem`] held entirely in memory.
///
/// Cloning shares the same contents, so a test can hand a clone to the code
/// under test and still inspect what it wrote.
#[derive(Clone, Default)]
pub struct MemoryFilesystem {
    inner: Arc<Mutex<Tree>>,
}

#[derive(Default)]
struct Tree {
    files: BTreeMap<String, Entry>,
    dirs: BTreeSet<String>,
}

struct Entry {
    data: Vec<u8>,
    created: i64,
    modified: i64,
}

/// Normalize to forward slashes so a test writes the same key on every platform.
fn key(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn parent_of(k: &str) -> Option<String> {
    k.rsplit_once('/').map(|(head, _)| head.to_string())
}

impl MemoryFilesystem {
    pub fn new() -> Self {
        Self::default()
    }

    /// Every file path currently stored, sorted.
    pub fn paths(&self) -> Vec<String> {
        self.inner.lock().unwrap().files.keys().cloned().collect()
    }

    /// Contents of a file, for assertions, without going through the trait.
    pub fn peek(&self, path: &str) -> Option<Vec<u8>> {
        let g = self.inner.lock().unwrap();
        g.files.get(path).map(|e| e.data.clone())
    }

    /// Seed a file, creating parent directories, as a test fixture.
    pub fn seed(&self, path: &str, data: &[u8]) {
        let mut g = self.inner.lock().unwrap();
        let mut cur = parent_of(path);
        while let Some(d) = cur {
            if d.is_empty() {
                break;
            }
            cur = parent_of(&d);
            g.dirs.insert(d);
        }
        g.files.insert(
            path.to_string(),
            Entry {
                data: data.to_vec(),
                created: 0,
                modified: 0,
            },
        );
    }

    fn dir_has_children(g: &Tree, d: &str) -> bool {
        let prefix = format!("{d}/");
        g.files.keys().any(|k| k.starts_with(&prefix))
            || g.dirs.iter().any(|k| k.starts_with(&prefix))
    }
}

#[async_trait]
impl Filesystem for MemoryFilesystem {
    async fn read_file(&self, path: &Path) -> FilesystemResult<Bytes> {
        let k = key(path);
        let g = self.inner.lock().unwrap();
        g.files
            .get(&k)
            .map(|e| Bytes::from(e.data.clone()))
            .ok_or(FilesystemError::NotFound(k))
    }

    async fn write_file(&self, path: &Path, contents: &[u8]) -> FilesystemResult<()> {
        let k = key(path);
        let mut g = self.inner.lock().unwrap();
        let created = g.files.get(&k).map(|e| e.created).unwrap_or(0);
        g.files.insert(
            k,
            Entry {
                data: contents.to_vec(),
                created,
                modified: 0,
            },
        );
        Ok(())
    }

    async fn append_file(&self, path: &Path, contents: &[u8]) -> FilesystemResult<()> {
        let k = key(path);
        let mut g = self.inner.lock().unwrap();
        g.files
            .entry(k)
            .or_insert_with(|| Entry {
                data: Vec::new(),
                created: 0,
                modified: 0,
            })
            .data
            .extend_from_slice(contents);
        Ok(())
    }

    async fn create_file(&self, path: &Path) -> FilesystemResult<()> {
        let k = key(path);
        let mut g = self.inner.lock().unwrap();
        if g.files.contains_key(&k) {
            return Err(FilesystemError::AlreadyExists(k));
        }
        g.files.insert(
            k,
            Entry {
                data: Vec::new(),
                created: 0,
                modified: 0,
            },
        );
        Ok(())
    }

    async fn delete_file(&self, path: &Path) -> FilesystemResult<()> {
        let k = key(path);
        let mut g = self.inner.lock().unwrap();
        g.files
            .remove(&k)
            .map(|_| ())
            .ok_or(FilesystemError::NotFound(k))
    }

    async fn file_exists(&self, path: &Path) -> FilesystemResult<bool> {
        Ok(self.inner.lock().unwrap().files.contains_key(&key(path)))
    }

    async fn file_metadata(&self, path: &Path) -> FilesystemResult<FileMetadata> {
        let k = key(path);
        let g = self.inner.lock().unwrap();
        if let Some(e) = g.files.get(&k) {
            return Ok(FileMetadata {
                path: k,
                size: e.data.len() as u64,
                is_directory: false,
                created: e.created,
                modified: e.modified,
            });
        }
        if g.dirs.contains(&k) {
            return Ok(FileMetadata {
                path: k,
                size: 0,
                is_directory: true,
                created: 0,
                modified: 0,
            });
        }
        Err(FilesystemError::NotFound(k))
    }

    async fn create_dir_all(&self, path: &Path) -> FilesystemResult<()> {
        let k = key(path);
        let mut g = self.inner.lock().unwrap();
        let mut cur = Some(k);
        while let Some(d) = cur {
            if d.is_empty() {
                break;
            }
            cur = parent_of(&d);
            g.dirs.insert(d);
        }
        Ok(())
    }

    async fn delete_dir(&self, path: &Path) -> FilesystemResult<()> {
        let k = key(path);
        let mut g = self.inner.lock().unwrap();
        if !g.dirs.contains(&k) {
            return Err(FilesystemError::NotFound(k));
        }
        if Self::dir_has_children(&g, &k) {
            return Err(FilesystemError::DirectoryNotEmpty(k));
        }
        g.dirs.remove(&k);
        Ok(())
    }

    async fn delete_dir_all(&self, path: &Path) -> FilesystemResult<()> {
        let k = key(path);
        let mut g = self.inner.lock().unwrap();
        if !g.dirs.contains(&k) {
            return Err(FilesystemError::NotFound(k));
        }
        let prefix = format!("{k}/");
        g.files.retain(|p, _| !p.starts_with(&prefix));
        g.dirs.retain(|d| d != &k && !d.starts_with(&prefix));
        Ok(())
    }

    async fn list_dir(&self, path: &Path) -> FilesystemResult<Vec<FileMetadata>> {
        let k = key(path);
        let g = self.inner.lock().unwrap();
        if !g.dirs.contains(&k) {
            return Err(FilesystemError::NotFound(k));
        }
        let prefix = format!("{k}/");
        let mut out = Vec::new();
        for (p, e) in g.files.iter() {
            if let Some(rest) = p.strip_prefix(&prefix) {
                if !rest.contains('/') {
                    out.push(FileMetadata {
                        path: p.clone(),
                        size: e.data.len() as u64,
                        is_directory: false,
                        created: e.created,
                        modified: e.modified,
                    });
                }
            }
        }
        for d in g.dirs.iter() {
            if let Some(rest) = d.strip_prefix(&prefix) {
                if !rest.contains('/') {
                    out.push(FileMetadata {
                        path: d.clone(),
                        size: 0,
                        is_directory: true,
                        created: 0,
                        modified: 0,
                    });
                }
            }
        }
        Ok(out)
    }

    async fn dir_exists(&self, path: &Path) -> FilesystemResult<bool> {
        Ok(self.inner.lock().unwrap().dirs.contains(&key(path)))
    }

    async fn copy_file(&self, src: &Path, dst: &Path) -> FilesystemResult<()> {
        let (s, d) = (key(src), key(dst));
        let mut g = self.inner.lock().unwrap();
        let data = g
            .files
            .get(&s)
            .map(|e| e.data.clone())
            .ok_or(FilesystemError::NotFound(s))?;
        g.files.insert(
            d,
            Entry {
                data,
                created: 0,
                modified: 0,
            },
        );
        Ok(())
    }

    async fn move_path(&self, src: &Path, dst: &Path) -> FilesystemResult<()> {
        let (s, d) = (key(src), key(dst));
        let mut g = self.inner.lock().unwrap();
        let e = g.files.remove(&s).ok_or(FilesystemError::NotFound(s))?;
        g.files.insert(d, e);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> &Path {
        Path::new(s)
    }

    #[tokio::test]
    async fn write_then_read_round_trips() {
        let fs = MemoryFilesystem::new();
        fs.write_file(p("/a/b.txt"), b"hello").await.unwrap();
        assert_eq!(&fs.read_file(p("/a/b.txt")).await.unwrap()[..], b"hello");
    }

    /// The contract, not the mechanism: a missing file is `NotFound`, not empty.
    #[tokio::test]
    async fn missing_file_is_not_found() {
        let fs = MemoryFilesystem::new();
        assert!(matches!(
            fs.read_file(p("/nope")).await,
            Err(FilesystemError::NotFound(_))
        ));
        assert!(!fs.file_exists(p("/nope")).await.unwrap());
    }

    #[tokio::test]
    async fn create_file_refuses_to_clobber() {
        let fs = MemoryFilesystem::new();
        fs.create_file(p("/x")).await.unwrap();
        assert!(matches!(
            fs.create_file(p("/x")).await,
            Err(FilesystemError::AlreadyExists(_))
        ));
    }

    /// A non-empty directory must refuse `delete_dir`, as the OS does.
    #[tokio::test]
    async fn delete_dir_refuses_when_not_empty() {
        let fs = MemoryFilesystem::new();
        fs.create_dir_all(p("/d")).await.unwrap();
        fs.write_file(p("/d/f"), b"x").await.unwrap();
        assert!(matches!(
            fs.delete_dir(p("/d")).await,
            Err(FilesystemError::DirectoryNotEmpty(_))
        ));
        fs.delete_dir_all(p("/d")).await.unwrap();
        assert!(!fs.dir_exists(p("/d")).await.unwrap());
        assert!(!fs.file_exists(p("/d/f")).await.unwrap());
    }

    #[tokio::test]
    async fn create_dir_all_creates_parents() {
        let fs = MemoryFilesystem::new();
        fs.create_dir_all(p("/a/b/c")).await.unwrap();
        assert!(fs.dir_exists(p("/a")).await.unwrap());
        assert!(fs.dir_exists(p("/a/b")).await.unwrap());
        assert!(fs.dir_exists(p("/a/b/c")).await.unwrap());
    }

    /// `list_dir` returns immediate children only — not the whole subtree.
    #[tokio::test]
    async fn list_dir_is_shallow() {
        let fs = MemoryFilesystem::new();
        fs.create_dir_all(p("/d/sub")).await.unwrap();
        fs.write_file(p("/d/one"), b"1").await.unwrap();
        fs.write_file(p("/d/sub/two"), b"2").await.unwrap();
        let names: Vec<String> = fs
            .list_dir(p("/d"))
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.path)
            .collect();
        assert!(names.contains(&"/d/one".to_string()));
        assert!(names.contains(&"/d/sub".to_string()));
        assert!(!names.contains(&"/d/sub/two".to_string()));
    }

    #[tokio::test]
    async fn move_and_copy_behave() {
        let fs = MemoryFilesystem::new();
        fs.write_file(p("/a"), b"v").await.unwrap();
        fs.copy_file(p("/a"), p("/b")).await.unwrap();
        fs.move_path(p("/a"), p("/c")).await.unwrap();
        assert!(!fs.file_exists(p("/a")).await.unwrap());
        assert_eq!(fs.peek("/b").unwrap(), b"v");
        assert_eq!(fs.peek("/c").unwrap(), b"v");
    }

    #[tokio::test]
    async fn append_extends() {
        let fs = MemoryFilesystem::new();
        fs.append_file(p("/log"), b"a").await.unwrap();
        fs.append_file(p("/log"), b"b").await.unwrap();
        assert_eq!(fs.peek("/log").unwrap(), b"ab");
    }
}
