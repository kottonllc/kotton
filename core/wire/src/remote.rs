// SPDX-License-Identifier: AGPL-3.0-or-later
//! Remote storage backend types
//!
//! `RemoteBackend` and `RemoteConfig` live here — in `wire` — rather than
//! in `05_runtime` because they appear in both the IPC protocol types (used by
//! `06_daemon` and `07_sdk`) and in the runtime's per-user configuration.
//!
//! Placing them in the runtime would force `wire` to depend on `05_runtime`,
//! inverting the layer order. Placing them here lets every layer import from below.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Storage backend variant for a remote mount.
///
/// Serialized with a `"type"` tag so config.toml entries look like:
/// ```toml
/// [remotes.work-s3]
/// type = "s3"
/// bucket = "my-bucket"
/// region = "us-east-1"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RemoteBackend {
    Local {
        path: PathBuf,
    },
    S3 {
        bucket: String,
        region: String,
        endpoint: Option<String>,
    },
    Ipfs {
        gateway: String,
    },
    /// A paired Kotton peer — connected on-demand via the NAT traversal stack.
    ///
    /// `peer_did` must match the `device_did` of a node in the paired-nodes DB.
    /// Connections are established at `remote add` time and not persisted across
    /// daemon restarts (the daemon re-connects on the next `remote add` invocation).
    Kotton {
        /// DID of the target peer device (must be in the paired-nodes table).
        peer_did: String,
        /// Human-readable label for display purposes.
        label: String,
    },
}

/// Remote storage configuration persisted to `config.toml`.
///
/// Contains no secrets — credentials are stored in the OS keychain,
/// keyed by `remote.<user_id>.<remote_name>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteConfig {
    pub backend: RemoteBackend,
    /// Override for the local cache directory for this remote.
    /// Defaults to `<user_dir>/cache/<remote_name>` if `None`.
    pub cache_dir: Option<PathBuf>,
    /// Which key scheme this mount's objects are stored under (RFC-0044).
    #[serde(default)]
    pub key_format: KeyFormat,
}

/// The key scheme a mount's objects are stored under (RFC-0044).
///
/// Per **mount** rather than per user: mounts migrate independently, and a mount
/// added after the migration is born blinded while an older sibling may still be
/// mid-pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyFormat {
    /// Objects are stored under their plaintext paths — the pre-RFC-0044 scheme.
    ///
    /// The default, so a config written before this field existed deserialises
    /// to the scheme its objects are actually in. Defaulting to `Blinded` would
    /// make every existing store unreadable on upgrade.
    #[default]
    Plain,
    /// Objects are stored under blinded keys and every one has been rewritten.
    Blinded,
}

/// Result of a [`sync_mount`] call.
#[derive(Debug, Clone)]
pub struct SyncResult {
    /// Number of objects pushed (local → remote).
    pub pushed: u32,
    /// Number of objects pulled (remote → local).
    pub pulled: u32,
    /// Number of objects skipped (already in sync or excluded by direction).
    pub skipped: u32,
    /// Per-transfer record: `(direction, object_key, bytes_transferred)`.
    pub transfers: Vec<(crate::ipc::SyncDirection, String, u64)>,
}
