// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `store` domain — where a user's data physically rests.
//!
//! Reached through [`KottonClient::store`], which binds the user once:
//!
//! ```no_run
//! # async fn example(client: &mut kotton::KottonClient) -> std::io::Result<()> {
//! let mut store = client.store("did:key:…");
//! let names = store.remotes().await?;
//! # let _ = names;
//! # Ok(())
//! # }
//! ```
//!
//! A remote is a place bytes can live; a mount makes another node's path
//! reachable here. Neither decides *which* store a given path lands in — that
//! follows the user's `storage-mounts.toml` through the router
//! (RFC-0058),
//! which is why no verb in this domain takes a path to place.
//!
//! Everything here addresses a store, so by the standing invariant everything
//! here sees ciphertext. The sealing stack is built below this layer and the
//! keys never reach it.

use std::io;

use super::{KottonClient, MountConfig, RemoteBackend, UserRequest, UserResponse};

/// The `store` domain, bound to one user.
///
/// Borrows the client, so it costs nothing to construct and cannot outlive the
/// connection it speaks over.
pub struct Store<'a> {
    client: &'a mut KottonClient,
    user_id: String,
}

impl KottonClient {
    /// Enter the `store` domain for a user.
    pub fn store(&mut self, user_id: &str) -> Store<'_> {
        Store {
            client: self,
            user_id: user_id.to_string(),
        }
    }
}

impl Store<'_> {
    /// Add a remote. See [`KottonClient::remote_add`].
    pub async fn add_remote(
        &mut self,
        name: &str,
        backend: RemoteBackend,
        credentials: Option<serde_json::Value>,
    ) -> io::Result<String> {
        let u = self.user_id.clone();
        self.client.remote_add(&u, name, backend, credentials).await
    }

    /// Remove a remote. See [`KottonClient::remote_remove`].
    pub async fn remove_remote(&mut self, name: &str) -> io::Result<()> {
        let u = self.user_id.clone();
        self.client.remote_remove(&u, name).await
    }

    /// Every configured remote. See [`KottonClient::remote_list`].
    pub async fn remotes(&mut self) -> io::Result<Vec<String>> {
        let u = self.user_id.clone();
        self.client.remote_list(&u).await
    }

    /// Drop a remote's local cache. See [`KottonClient::remote_cache_clear`].
    pub async fn clear_cache(&mut self, name: &str) -> io::Result<()> {
        let u = self.user_id.clone();
        self.client.remote_cache_clear(&u, name).await
    }

    /// Set a remote's credentials. See [`KottonClient::remote_credentials_set`].
    pub async fn set_credentials(
        &mut self,
        name: &str,
        credentials: serde_json::Value,
    ) -> io::Result<()> {
        let u = self.user_id.clone();
        self.client.remote_credentials_set(&u, name, credentials).await
    }

    /// Make another node's path reachable here. See [`KottonClient::mount`].
    pub async fn mount(
        &mut self,
        node_id: &str,
        remote_path: &str,
        local_path: &str,
        cache_budget_bytes: Option<u64>,
        pins: Vec<String>,
    ) -> io::Result<MountConfig> {
        let u = self.user_id.clone();
        self.client
            .mount(&u, node_id, remote_path, local_path, cache_budget_bytes, pins)
            .await
    }

    /// Every mount. See [`KottonClient::list_mounts`].
    pub async fn mounts(&mut self) -> io::Result<Vec<MountConfig>> {
        let u = self.user_id.clone();
        self.client.list_mounts(&u).await
    }

    /// Reclaim a mount's cached bytes. See [`KottonClient::evict_mount`].
    pub async fn evict(&mut self, node_id: &str, local_path: &str) -> io::Result<u64> {
        let u = self.user_id.clone();
        self.client.evict_mount(&u, node_id, local_path).await
    }

    /// Re-read `storage-mounts.toml`. See [`KottonClient::storage_reload`].
    pub async fn reload(&mut self) -> io::Result<()> {
        let u = self.user_id.clone();
        self.client.storage_reload(&u).await
    }
}

impl KottonClient {
    /// Add a remote storage backend for a user.
    ///
    /// `credentials` is backend-specific JSON (e.g. `{"access_key": "...", "secret_key": "..."}`).
    /// The daemon stores credentials in the OS keychain — they are never written to disk.
    pub async fn remote_add(
        &mut self,
        user_id: &str,
        name: &str,
        backend: RemoteBackend,
        credentials: Option<serde_json::Value>,
    ) -> io::Result<String> {
        let request = UserRequest::RemoteAdd {
            user_id: user_id.to_string(),
            name: name.to_string(),
            backend,
            credentials: credentials.map(kotton_wire::ipc::SecretValue::new),
        };
        match self.client.send(&request).await? {
            UserResponse::RemoteAdded { name } => Ok(name),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Remove a remote storage backend from a user.
    pub async fn remote_remove(&mut self, user_id: &str, name: &str) -> io::Result<()> {
        let request = UserRequest::RemoteRemove {
            user_id: user_id.to_string(),
            name: name.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::Ok => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// List remote names for a user.
    pub async fn remote_list(&mut self, user_id: &str) -> io::Result<Vec<String>> {
        let request = UserRequest::RemoteList {
            user_id: user_id.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::RemoteList { remotes } => Ok(remotes),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Clear the local cache for a remote (no-op until Phase 5).
    pub async fn remote_cache_clear(&mut self, user_id: &str, name: &str) -> io::Result<()> {
        let request = UserRequest::RemoteCacheClear {
            user_id: user_id.to_string(),
            name: name.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::Ok => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Update the stored credentials for an existing remote.
    pub async fn remote_credentials_set(
        &mut self,
        user_id: &str,
        name: &str,
        credentials: serde_json::Value,
    ) -> io::Result<()> {
        let request = UserRequest::RemoteCredentialsSet {
            user_id: user_id.to_string(),
            name: name.to_string(),
            credentials: kotton_wire::ipc::SecretValue::new(credentials),
        };
        match self.client.send(&request).await? {
            UserResponse::Ok => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Mount a path from a paired node into the local VFS.
    pub async fn mount(
        &mut self,
        user_id: &str,
        node_id: &str,
        remote_path: &str,
        local_path: &str,
        cache_budget_bytes: Option<u64>,
        pins: Vec<String>,
    ) -> io::Result<MountConfig> {
        let request = UserRequest::MountPath {
            user_id: user_id.to_string(),
            node_id: node_id.to_string(),
            remote_path: remote_path.to_string(),
            local_path: local_path.to_string(),
            cache_budget_bytes,
            pins,
        };
        match self.client.send(&request).await? {
            UserResponse::Mounted { config } => Ok(config),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// List all peer mounts for `user_id`.
    pub async fn list_mounts(&mut self, user_id: &str) -> io::Result<Vec<MountConfig>> {
        let request = UserRequest::MountList {
            user_id: user_id.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::MountList { mounts } => Ok(mounts),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Evict the local cache for a mount. Returns bytes freed.
    pub async fn evict_mount(
        &mut self,
        user_id: &str,
        node_id: &str,
        local_path: &str,
    ) -> io::Result<u64> {
        let request = UserRequest::MountEvict {
            user_id: user_id.to_string(),
            node_id: node_id.to_string(),
            local_path: local_path.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::MountEvicted { freed_bytes } => Ok(freed_bytes),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Notify the daemon that `storage-mounts.toml` has changed and the
    /// storage router for `user_id` should be rebuilt.
    pub async fn storage_reload(&mut self, user_id: &str) -> io::Result<()> {
        let request = UserRequest::StorageReload {
            user_id: user_id.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::Ok => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }
}
