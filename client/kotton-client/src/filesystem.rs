// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `fs` domain — VFS reads, writes, listings and deletes.
//!
//! Reached through [`KottonClient::fs`], which binds the user and mount once:
//!
//! ```no_run
//! # async fn example(client: &mut kotton::KottonClient) -> std::io::Result<()> {
//! let mut fs = client.fs("did:key:…");
//! let data = fs.read("/notes/todo.md").await?;
//! fs.write("/notes/copy.md", &data).await?;
//! # Ok(())
//! # }
//! ```
//!
//! The domain name follows RFC-0054;
//! grouping the verbs under it follows RFC-0055.

use std::io;

use super::{KottonClient, UserRequest, UserResponse};

/// The `fs` domain, bound to one user and mount.
///
/// Borrows the client, so it costs nothing to construct and cannot outlive the
/// connection it speaks over.
pub struct Fs<'a> {
    client: &'a mut KottonClient,
    user_id: String,
}

impl KottonClient {

    /// Paths with a retained losing version, and the content ids kept for each.
    pub async fn list_conflicts(
        &mut self,
        user_id: &str,
    ) -> io::Result<Vec<(String, Vec<String>)>> {
        let request = UserRequest::ListConflicts {
            user_id: user_id.to_owned(),
        };
        match self.client.send(&request).await? {
            UserResponse::ConflictList { conflicts } => Ok(conflicts),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Settle a conflict, optionally promoting one retained version.
    pub async fn resolve_conflict(
        &mut self,
        user_id: &str,
        path: &str,
        keep: Option<&str>,
    ) -> io::Result<()> {
        let request = UserRequest::ResolveConflict {
            user_id: user_id.to_owned(),
            path: path.to_owned(),
            keep: keep.map(str::to_owned),
        };
        match self.client.send(&request).await? {
            UserResponse::Ok => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Erase a path and its entire history. Local-origin only.
    pub async fn purge_file(&mut self, user_id: &str, path: &str) -> io::Result<()> {
        let request = UserRequest::PurgeFile {
            user_id: user_id.to_owned(),
            path: path.to_owned(),
        };
        match self.client.send(&request).await? {
            UserResponse::Ok => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }
    /// Enter the `fs` domain for a user.
    ///
    /// There is no store to name: the node places a path according to the
    /// user's `storage-mounts.toml` (RFC-0058).
    pub fn fs(&mut self, user_id: &str) -> Fs<'_> {
        Fs {
            client: self,
            user_id: user_id.to_string(),
        }
    }
}

impl Fs<'_> {
    /// Write bytes to a file. See [`KottonClient::write_file`].
    pub async fn write(&mut self, path: &str, data: &[u8]) -> io::Result<()> {
        let u = self.user_id.clone();
        self.client.write_file(&u, path, data).await
    }

    /// Read a file whole. See [`KottonClient::read_file`].
    pub async fn read(&mut self, path: &str) -> io::Result<Vec<u8>> {
        let u = self.user_id.clone();
        self.client.read_file(&u, path).await
    }

    /// List paths under a prefix. See [`KottonClient::list_files`].
    pub async fn list(&mut self, prefix: &str) -> io::Result<Vec<String>> {
        let u = self.user_id.clone();
        self.client.list_files(&u, prefix).await
    }

    /// Delete a file. See [`KottonClient::delete_file`].
    pub async fn delete(&mut self, path: &str) -> io::Result<()> {
        let u = self.user_id.clone();
        self.client.delete_file(&u, path).await
    }

    /// Paths holding a version that lost a concurrent write, each with the
    /// content ids retained for it (RFC-0071 R3).
    pub async fn conflicts(&mut self) -> io::Result<Vec<(String, Vec<String>)>> {
        let u = self.user_id.clone();
        self.client.list_conflicts(&u).await
    }

    /// Settle the conflict on `path`. `keep` promotes a retained version;
    /// `None` keeps the current one. Either way the retention is released.
    pub async fn resolve(&mut self, path: &str, keep: Option<&str>) -> io::Result<()> {
        let u = self.user_id.clone();
        self.client.resolve_conflict(&u, path, keep).await
    }

    /// Erase a path **and its entire history**. Unlike `delete`, there is no way
    /// back — and it is refused unless the call is local.
    pub async fn purge(&mut self, path: &str) -> io::Result<()> {
        let u = self.user_id.clone();
        self.client.purge_file(&u, path).await
    }
}

impl KottonClient {
    /// Write bytes to a file in the named user's storage mount.
    ///
    /// A large file exceeds the IPC frame cap, so it is sent as a run of sub-cap
    /// chunks the daemon reassembles (RFC-0048), each tagged with the whole
    /// file's BLAKE3 so a corrupt or interleaved reassembly is refused.
    pub async fn write_file(
        &mut self,
        user_id: &str,
        path: &str,
        data: &[u8],
    ) -> io::Result<()> {
        const CHUNK: usize = 4 * 1024 * 1024;
        let total_size = data.len() as u64;
        let content_hash = blake3::hash(data).to_hex().to_string();

        let mut offset = 0usize;
        loop {
            let end = (offset + CHUNK).min(data.len());
            let request = UserRequest::WriteFile {
                user_id: user_id.to_string(),
                path: path.to_string(),
                data: data[offset..end].to_vec(),
                offset: offset as u64,
                total_size,
                content_hash: content_hash.clone(),
            };
            match self.client.send(&request).await? {
                UserResponse::Ok => {}
                UserResponse::Error { message } => return Err(io::Error::other(message)),
                got => return Err(crate::protocol::unexpected(got)),
            }
            offset = end;
            if offset >= data.len() {
                return Ok(());
            }
        }
    }

    /// Read a file from the named user's storage mount.
    ///
    /// Fetched as a sequence of sub-cap ranges and reassembled (RFC-0048); the
    /// response carries `total_size` so the reader knows when it has the whole
    /// file.
    pub async fn read_file(
        &mut self,
        user_id: &str,
        path: &str,
    ) -> io::Result<Vec<u8>> {
        const RANGE: u32 = 4 * 1024 * 1024;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let request = UserRequest::ReadFile {
                user_id: user_id.to_string(),
                path: path.to_string(),
                offset: out.len() as u64,
                length: RANGE,
            };
            match self.client.send(&request).await? {
                UserResponse::FileData { data, total_size } => {
                    let advanced = !data.is_empty();
                    out.extend_from_slice(&data);
                    if out.len() as u64 >= total_size {
                        return Ok(out);
                    }
                    if !advanced {
                        return Err(io::Error::other("daemon stalled before the file's end"));
                    }
                }
                UserResponse::Error { message } => return Err(io::Error::other(message)),
                got => return Err(crate::protocol::unexpected(got)),
            }
        }
    }

    /// List files in the named user's storage mount under `prefix`.
    pub async fn list_files(
        &mut self,
        user_id: &str,
        prefix: &str,
    ) -> io::Result<Vec<String>> {
        let request = UserRequest::ListFiles {
            user_id: user_id.to_string(),
            prefix: prefix.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::FileList { files } => Ok(files),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Delete a file from the named user's storage mount.
    pub async fn delete_file(&mut self, user_id: &str, path: &str) -> io::Result<()> {
        let request = UserRequest::DeleteFile {
            user_id: user_id.to_string(),
            path: path.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::Ok => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }
}
