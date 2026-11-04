// SPDX-License-Identifier: AGPL-3.0-or-later
//! OS filesystem implementation using tokio::fs

use async_trait::async_trait;
use bytes::Bytes;
use kotton_sys::fs::{FileMetadata, Filesystem, FilesystemError, FilesystemResult};
use std::path::Path;
use tokio::fs;
use tokio::io::AsyncWriteExt;

/// Standard OS filesystem implementation using tokio::fs
#[derive(Debug, Clone)]
pub struct OsFilesystem;

impl OsFilesystem {
    /// Create a new OS filesystem backend
    pub fn new() -> Self {
        Self
    }
}

impl Default for OsFilesystem {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Filesystem for OsFilesystem {
    async fn read_file(&self, path: &Path) -> FilesystemResult<Bytes> {
        let data = fs::read(path).await.map_err(|e| map_io_error(e, path))?;
        Ok(Bytes::from(data))
    }

    async fn write_file(&self, path: &Path, contents: &[u8]) -> FilesystemResult<()> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| map_io_error(e, parent))?;
        }

        fs::write(path, contents)
            .await
            .map_err(|e| map_io_error(e, path))?;
        Ok(())
    }

    async fn append_file(&self, path: &Path, contents: &[u8]) -> FilesystemResult<()> {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await
            .map_err(|e| map_io_error(e, path))?;

        file.write_all(contents)
            .await
            .map_err(|e| map_io_error(e, path))?;

        file.flush().await.map_err(|e| map_io_error(e, path))?;

        Ok(())
    }

    async fn create_file(&self, path: &Path) -> FilesystemResult<()> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| map_io_error(e, parent))?;
        }

        fs::File::create(path)
            .await
            .map_err(|e| map_io_error(e, path))?;
        Ok(())
    }

    async fn delete_file(&self, path: &Path) -> FilesystemResult<()> {
        fs::remove_file(path)
            .await
            .map_err(|e| map_io_error(e, path))?;
        Ok(())
    }

    async fn file_exists(&self, path: &Path) -> FilesystemResult<bool> {
        match fs::metadata(path).await {
            Ok(metadata) => Ok(metadata.is_file()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(map_io_error(e, path)),
        }
    }

    async fn file_metadata(&self, path: &Path) -> FilesystemResult<FileMetadata> {
        let metadata = fs::metadata(path)
            .await
            .map_err(|e| map_io_error(e, path))?;

        Ok(FileMetadata {
            path: path.to_string_lossy().to_string(),
            size: metadata.len(),
            is_directory: metadata.is_dir(),
            created: metadata
                .created()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
            modified: metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
        })
    }

    async fn create_dir_all(&self, path: &Path) -> FilesystemResult<()> {
        fs::create_dir_all(path)
            .await
            .map_err(|e| map_io_error(e, path))?;
        Ok(())
    }

    async fn delete_dir(&self, path: &Path) -> FilesystemResult<()> {
        fs::remove_dir(path)
            .await
            .map_err(|e| map_io_error(e, path))?;
        Ok(())
    }

    async fn delete_dir_all(&self, path: &Path) -> FilesystemResult<()> {
        fs::remove_dir_all(path)
            .await
            .map_err(|e| map_io_error(e, path))?;
        Ok(())
    }

    async fn list_dir(&self, path: &Path) -> FilesystemResult<Vec<FileMetadata>> {
        let mut entries = Vec::new();
        let mut dir = fs::read_dir(path)
            .await
            .map_err(|e| map_io_error(e, path))?;

        while let Some(entry) = dir.next_entry().await.map_err(|e| map_io_error(e, path))? {
            let metadata = match entry.metadata().await {
                Ok(m) => m,
                // Gone between the directory read and this look at it — deleted,
                // or a file renamed over another. A listing an instant later
                // would not name it either, so it is not named. Answered as an
                // error, the not-found reached the caller as *this directory
                // does not exist*, and an object store listed an empty prefix
                // for a directory full of objects
                // (`TASK-a-contact-who-learned-a-rotated-key-is-sometimes-unreachable-at-the-new-door`).
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(map_io_error(e, &entry.path())),
            };

            entries.push(FileMetadata {
                path: entry.path().to_string_lossy().to_string(),
                size: metadata.len(),
                is_directory: metadata.is_dir(),
                created: metadata
                    .created()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0),
                modified: metadata
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0),
            });
        }

        Ok(entries)
    }

    async fn dir_exists(&self, path: &Path) -> FilesystemResult<bool> {
        match fs::metadata(path).await {
            Ok(metadata) => Ok(metadata.is_dir()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(map_io_error(e, path)),
        }
    }

    async fn copy_file(&self, src: &Path, dst: &Path) -> FilesystemResult<()> {
        // Ensure parent directory exists
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| map_io_error(e, parent))?;
        }

        fs::copy(src, dst).await.map_err(|e| map_io_error(e, src))?;
        Ok(())
    }

    async fn move_path(&self, src: &Path, dst: &Path) -> FilesystemResult<()> {
        // Ensure parent directory exists
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| map_io_error(e, parent))?;
        }

        fs::rename(src, dst)
            .await
            .map_err(|e| map_io_error(e, src))?;
        Ok(())
    }
}

/// Map std::io::Error to FilesystemError with path context
fn map_io_error(error: std::io::Error, path: &Path) -> FilesystemError {
    let path_str = path.to_string_lossy().to_string();
    match error.kind() {
        std::io::ErrorKind::NotFound => FilesystemError::NotFound(path_str),
        std::io::ErrorKind::PermissionDenied => FilesystemError::PermissionDenied(path_str),
        std::io::ErrorKind::AlreadyExists => FilesystemError::AlreadyExists(path_str),
        _ => FilesystemError::IoError(format!("{}: {}", path_str, error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn setup() -> (OsFilesystem, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let fs = OsFilesystem::new();
        (fs, temp_dir)
    }

    #[tokio::test]
    async fn test_file_operations() {
        let (fs, temp_dir) = setup().await;
        let file_path = temp_dir.path().join("test.txt");

        // Create and write
        fs.write_file(&file_path, b"Hello, World!").await.unwrap();
        assert!(fs.file_exists(&file_path).await.unwrap());

        // Read
        let content = fs.read_file(&file_path).await.unwrap();
        assert_eq!(content.as_ref(), b"Hello, World!");

        // Append
        fs.append_file(&file_path, b" More text.").await.unwrap();
        let content = fs.read_file(&file_path).await.unwrap();
        assert_eq!(content.as_ref(), b"Hello, World! More text.");

        // Delete
        fs.delete_file(&file_path).await.unwrap();
        assert!(!fs.file_exists(&file_path).await.unwrap());
    }

    #[tokio::test]
    async fn test_directory_operations() {
        let (fs, temp_dir) = setup().await;
        let dir_path = temp_dir.path().join("subdir");

        // Create directory
        fs.create_dir_all(&dir_path).await.unwrap();
        assert!(fs.dir_exists(&dir_path).await.unwrap());

        // Create file in directory
        let file_path = dir_path.join("file.txt");
        fs.write_file(&file_path, b"test").await.unwrap();

        // List directory
        let entries = fs.list_dir(&dir_path).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].size, 4);

        // Delete directory with contents
        fs.delete_dir_all(&dir_path).await.unwrap();
        assert!(!fs.dir_exists(&dir_path).await.unwrap());
    }

    #[tokio::test]
    async fn test_copy_and_move() {
        let (fs, temp_dir) = setup().await;
        let src = temp_dir.path().join("source.txt");
        let dst = temp_dir.path().join("dest.txt");

        fs.write_file(&src, b"content").await.unwrap();

        // Copy
        fs.copy_file(&src, &dst).await.unwrap();
        assert!(fs.file_exists(&src).await.unwrap());
        assert!(fs.file_exists(&dst).await.unwrap());

        // Move
        let moved = temp_dir.path().join("moved.txt");
        fs.move_path(&dst, &moved).await.unwrap();
        assert!(!fs.file_exists(&dst).await.unwrap());
        assert!(fs.file_exists(&moved).await.unwrap());
    }

    /// A path whose parent is a regular file fails with ENOTDIR, which is a
    /// failure to look, not absence (kotton #418). This needs no permissions,
    /// so it asserts as root too.
    #[tokio::test]
    async fn a_path_under_a_regular_file_is_an_error_not_absence() {
        let (fs, temp_dir) = setup().await;
        let file = temp_dir.path().join("plain");
        fs.write_file(&file, b"x").await.unwrap();
        let under = file.join("child");
        for got in [
            fs.dir_exists(&under).await,
            fs.file_exists(&under).await,
        ] {
            match got {
                Err(FilesystemError::NotFound(p)) => panic!("ENOTDIR read as NotFound: {p}"),
                Err(_) => {}
                Ok(b) => panic!("a failure to look answered Ok({b})"),
            }
        }
    }

    /// An existing path of the other kind is `Ok(false)`, a path that is not
    /// there is `Ok(false)`, and a symlink is followed as `Path::exists` did.
    #[tokio::test]
    async fn exists_answers_false_for_absence_and_for_the_wrong_kind() {
        let (fs, temp_dir) = setup().await;
        let file = temp_dir.path().join("f");
        let dir = temp_dir.path().join("d");
        fs.write_file(&file, b"x").await.unwrap();
        fs.create_dir_all(&dir).await.unwrap();
        assert!(!fs.dir_exists(&file).await.unwrap());
        assert!(!fs.file_exists(&dir).await.unwrap());
        assert!(!fs.dir_exists(&temp_dir.path().join("nope")).await.unwrap());
        assert!(!fs.file_exists(&temp_dir.path().join("nope")).await.unwrap());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn exists_follows_symlinks() {
        let (fs, temp_dir) = setup().await;
        let file = temp_dir.path().join("f");
        let dir = temp_dir.path().join("d");
        fs.write_file(&file, b"x").await.unwrap();
        fs.create_dir_all(&dir).await.unwrap();
        let to_file = temp_dir.path().join("to_file");
        let to_dir = temp_dir.path().join("to_dir");
        let dangling = temp_dir.path().join("dangling");
        std::os::unix::fs::symlink(&file, &to_file).unwrap();
        std::os::unix::fs::symlink(&dir, &to_dir).unwrap();
        std::os::unix::fs::symlink(temp_dir.path().join("gone"), &dangling).unwrap();
        assert!(fs.file_exists(&to_file).await.unwrap());
        assert!(fs.dir_exists(&to_dir).await.unwrap());
        assert!(!fs.file_exists(&to_dir).await.unwrap());
        assert!(!fs.dir_exists(&to_file).await.unwrap());
        assert!(!fs.file_exists(&dangling).await.unwrap());
        assert!(!fs.dir_exists(&dangling).await.unwrap());
    }

    /// EACCES on the way to a path is a failure to look (kotton #418). Unix
    /// only; skipped, and says so, when the process can look past a 000 mode
    /// (root).
    #[cfg(unix)]
    #[tokio::test]
    async fn an_unreadable_parent_is_an_error_not_absence() {
        use std::os::unix::fs::PermissionsExt;
        let (fs, temp_dir) = setup().await;
        let locked = temp_dir.path().join("locked");
        let shelf = locked.join("shelf");
        std::fs::create_dir_all(&shelf).unwrap();
        std::fs::write(shelf.join("f"), b"x").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::metadata(&shelf).is_ok() {
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
            eprintln!("skipped: running with privileges that ignore file modes (root)");
            return;
        }
        let dir = fs.dir_exists(&shelf).await;
        let file = fs.file_exists(&shelf.join("f")).await;
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(dir, Err(FilesystemError::PermissionDenied(_))), "{dir:?}");
        assert!(matches!(file, Err(FilesystemError::PermissionDenied(_))), "{file:?}");
    }
}
