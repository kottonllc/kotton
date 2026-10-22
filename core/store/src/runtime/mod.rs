// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `store` domain's runtime behaviour.
//!
//! Today: the mount table. `storage-mounts.toml` is what decides where a path
//! lands, so it belongs to the domain that owns placement rather
//! than to a runtime god-struct.
//!
//! It is load-bearing rather than advisory: before the router was wired, this
//! file was read by nothing, and a user who configured `/photos` onto a NAS got
//! local disk.
//!
//! [`roots`] is the layer above all of it: a mount table
//! decides where a *path* lands, and a root decides what a path is *inside* —
//! who may read it, and which vaults it is kept at.
//!
//! [`router`] is the other half: the mount table says where a path *should* go,
//! and the router is what actually dispatches to it. [`config`] is the set of
//! backends those mounts name, [`keys`] the leaf keys their sealed stacks are
//! built from, and [`maintenance`] the passes that run over one mount at a time.

pub mod user;
pub mod roots;
pub mod config;
pub mod keys;
pub mod maintenance;
pub mod private;
pub mod router;

pub use config::{instantiate_remotes, load_config, save_config, UserConfig};
pub use keys::UserKeys;
pub use maintenance::{compact_mount, pack_mount, recover_mount};
pub use roots::{Carried, Kept, Owner, Residency, Root, RootSet, Target};
pub use router::UserStorageRouter;

use anyhow::{Context, Result};

/// A single VFS mount entry deserialized from `storage-mounts.toml`.
///
/// ```toml
/// [[mount]]
/// path   = "/archive"
/// remote = "s3-archive"
/// ```
///
/// `path` is a VFS prefix (must start with `/`).
/// `remote` is the name of a remote registered with `kotton remote add`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct StorageMountEntry {
    /// VFS path prefix, e.g. `"/archive"`.
    pub path: String,
    /// Name of the remote backend to use for this prefix.
    pub remote: String,
}

/// Deserialized contents of `storage-mounts.toml`.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct StorageMountsFile {
    #[serde(default, rename = "mount")]
    pub mounts: Vec<StorageMountEntry>,
}

impl StorageMountsFile {
    /// File name within the user config directory.
    pub const FILE_NAME: &'static str = "storage-mounts.toml";

    /// Read `storage-mounts.toml` from `config_dir`.
    ///
    /// Returns an empty `StorageMountsFile` if the file does not exist — no
    /// mounts configured is a valid initial state.
    pub fn load(config_dir: &std::path::Path) -> Result<Self> {
        let path = config_dir.join(Self::FILE_NAME);
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    /// Write `storage-mounts.toml` to `config_dir`, creating the file if needed.
    pub fn save(&self, config_dir: &std::path::Path) -> Result<()> {
        let path = config_dir.join(Self::FILE_NAME);
        let text = toml::to_string_pretty(self)
            .with_context(|| format!("serializing {}", path.display()))?;
        std::fs::write(&path, text)
            .with_context(|| format!("writing {}", path.display()))
    }

    /// Add or replace a mount entry for `path_prefix`.
    ///
    /// If an entry with the same `path` already exists it is replaced;
    /// otherwise the new entry is appended.
    pub fn upsert(&mut self, entry: StorageMountEntry) {
        if let Some(existing) = self.mounts.iter_mut().find(|m| m.path == entry.path) {
            *existing = entry;
        } else {
            self.mounts.push(entry);
        }
    }

    /// Remove the entry for `path_prefix`, returning `true` if it existed.
    pub fn remove(&mut self, path_prefix: &str) -> bool {
        let before = self.mounts.len();
        self.mounts.retain(|m| m.path != path_prefix);
        self.mounts.len() < before
    }
}
