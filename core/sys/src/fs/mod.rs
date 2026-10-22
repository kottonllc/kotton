// SPDX-License-Identifier: AGPL-3.0-or-later
//! Platform filesystem abstraction
//!
//! Provides async filesystem operations with:
//! - File I/O (read, write, append, delete)
//! - Directory operations (create, list, delete)
//! - File metadata queries
//! - Atomic operations where possible

use async_trait::async_trait;
use bytes::Bytes;
use std::path::Path;
use thiserror::Error;

/// Errors that can occur during filesystem operations
#[derive(Debug, Error)]
pub enum FilesystemError {
    /// File or directory not found
    #[error("Not found: {0}")]
    NotFound(String),

    /// Permission denied
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Directory not empty
    #[error("Directory not empty: {0}")]
    DirectoryNotEmpty(String),

    /// Already exists
    #[error("Already exists: {0}")]
    AlreadyExists(String),

    /// I/O operation failed
    #[error("I/O error: {0}")]
    IoError(String),

    /// Invalid path
    #[error("Invalid path: {0}")]
    InvalidPath(String),
}

/// Result type for filesystem operations
pub type FilesystemResult<T> = Result<T, FilesystemError>;

/// Metadata about a file or directory
#[derive(Debug, Clone)]
pub struct FileMetadata {
    /// Path to the file/directory
    pub path: String,
    /// Size in bytes (0 for directories)
    pub size: u64,
    /// Whether this is a directory
    pub is_directory: bool,
    /// Creation timestamp (Unix epoch)
    pub created: i64,
    /// Last modification timestamp (Unix epoch)
    pub modified: i64,
}

/// Abstraction for filesystem operations
///
/// Implementations must handle:
/// - File creation, reading, writing, deletion
/// - Directory creation, listing, deletion
/// - Path normalization (absolute paths, no symlinks)
#[async_trait]
pub trait Filesystem: Send + Sync {
    /// Read entire file contents
    async fn read_file(&self, path: &Path) -> FilesystemResult<Bytes>;

    /// Write entire file contents (creates or overwrites)
    async fn write_file(&self, path: &Path, contents: &[u8]) -> FilesystemResult<()>;

    /// Append to a file
    async fn append_file(&self, path: &Path, contents: &[u8]) -> FilesystemResult<()>;

    /// Create a new empty file
    async fn create_file(&self, path: &Path) -> FilesystemResult<()>;

    /// Delete a file
    async fn delete_file(&self, path: &Path) -> FilesystemResult<()>;

    /// Check if a file exists
    async fn file_exists(&self, path: &Path) -> FilesystemResult<bool>;

    /// Get file metadata
    async fn file_metadata(&self, path: &Path) -> FilesystemResult<FileMetadata>;

    /// Create a directory (and parent directories if needed)
    async fn create_dir_all(&self, path: &Path) -> FilesystemResult<()>;

    /// Delete a directory (must be empty)
    async fn delete_dir(&self, path: &Path) -> FilesystemResult<()>;

    /// Delete a directory and all its contents recursively
    async fn delete_dir_all(&self, path: &Path) -> FilesystemResult<()>;

    /// List directory contents
    async fn list_dir(&self, path: &Path) -> FilesystemResult<Vec<FileMetadata>>;

    /// Check if a directory exists
    async fn dir_exists(&self, path: &Path) -> FilesystemResult<bool>;

    /// Copy a file
    async fn copy_file(&self, src: &Path, dst: &Path) -> FilesystemResult<()>;

    /// Move/rename a file or directory
    async fn move_path(&self, src: &Path, dst: &Path) -> FilesystemResult<()>;
}
