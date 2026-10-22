// SPDX-License-Identifier: AGPL-3.0-or-later
//! A user's remote set, as configured and as instantiated.
//!
//! `config.toml` records *which* backends a user has; this module reads it and
//! turns each entry into a live store. Both halves belong to `store` for the
//! same reason the mount table does: they decide where a user's bytes land,
//! which is placement, not runtime orchestration.
//!
//! The filesystem arrives as a parameter, never as a named type. `core/store`
//! keeps `kotton-fs` as a dev-dependency only, so it cannot name `OsFilesystem`
//! even by accident — that is what keeps a bare-metal port a substitution rather
//! than a rewrite, and it is why [`instantiate_remotes`] is generic where the
//! caller is concrete.

use crate::stack::{build_sealed_store, ArcStore};
use anyhow::{anyhow, Context, Result};
use kotton_context::LogIdentity;
use kotton_wire::remote::{RemoteBackend, RemoteConfig};
use kotton_sys::store::{Shelves, SyncableStore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

/// User-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConfig {
    #[serde(default)]
    pub sync_enabled: bool,
    #[serde(default)]
    pub auto_accept_devices: bool,
    /// Remote storage configurations.
    /// Maps remote name -> backend config (no secrets stored here).
    #[serde(default)]
    pub remotes: HashMap<String, RemoteConfig>,
}

impl Default for UserConfig {
    fn default() -> Self {
        Self {
            sync_enabled: true,
            auto_accept_devices: false,
            remotes: HashMap::new(),
        }
    }
}

/// Load user configuration from disk.
///
/// An absent `config.toml` is not an error — it is a user who has configured
/// nothing yet, and the default set is what they get.
pub fn load_config(base_dir: &Path) -> Result<UserConfig> {
    let config_path = base_dir.join("config.toml");
    if config_path.exists() {
        let data = std::fs::read_to_string(&config_path).context("Failed to read config.toml")?;
        toml::from_str(&data).context("Failed to parse config.toml")
    } else {
        Ok(UserConfig::default())
    }
}

/// Save user configuration to disk.
pub fn save_config(base_dir: &Path, config: &UserConfig) -> Result<()> {
    let config_path = base_dir.join("config.toml");
    let toml_str = toml::to_string_pretty(config).context("Failed to serialize config")?;
    std::fs::write(&config_path, toml_str).context("Failed to write config.toml")?;
    Ok(())
}

/// Instantiate remote storage backends from configuration.
///
/// * Local backends are built into the same sealed stack, under the same key
///   domain and `key_format`, as the create path, over whatever shelf the
///   node's `shelves` answers for the mount. That is what makes a *reloaded*
///   or *joined* device's mount blinded rather than only a freshly-created one.
/// * S3 and IPFS backends are not supported in this build and are skipped with
///   a warning rather than failing the load — a user with one unreachable
///   remote should still get the rest.
/// * Kotton peer remotes need a live NAT-traversal session and the daemon's DB
///   pool, so they cannot be re-established at cold start. The user re-adds them
///   over IPC once the daemon is up.
pub async fn instantiate_remotes(
    config: &UserConfig,
    user_id: &str,
    shelves: &dyn Shelves,
    cek: Option<[u8; 32]>,
    path_key: Option<[u8; 32]>,
    log: Option<&LogIdentity>,
) -> Result<HashMap<String, Arc<dyn SyncableStore>>> {
    let mut remotes: HashMap<String, Arc<dyn SyncableStore>> = HashMap::new();

    for (remote_name, remote_config) in &config.remotes {
        match &remote_config.backend {
            RemoteBackend::Local { path } => {
                // The shelf beneath this mount is the node's to choose;
                // the stack over it is the same either way.
                let backend = build_sealed_store(
                    ArcStore(shelves.open(user_id, remote_name, path)),
                    cek,
                    path_key,
                    log,
                    remote_config.key_format,
                );
                remotes.insert(remote_name.clone(), backend);
            }
            RemoteBackend::S3 { .. } => {
                tracing::warn!("Skipping S3 remote '{remote_name}': not supported in this build");
            }
            RemoteBackend::Ipfs { .. } => {
                tracing::warn!("Skipping IPFS remote '{remote_name}': not supported in this build");
            }
            RemoteBackend::Kotton { peer_did, .. } => {
                tracing::warn!(
                    remote = %remote_name,
                    peer = %peer_did,
                    "Skipping Kotton peer remote at startup — peer connections require \
                     a live daemon session. Re-add with `kotton remote add` after the \
                     daemon has fully started."
                );
            }
        }
    }

    // A user with no reachable mount has nowhere to put anything, which is a
    // failure to load rather than an empty success.
    if remotes.is_empty() {
        return Err(anyhow!(
            "This user has no valid storage mounts. \
             Check config.toml and ensure at least one backend is accessible."
        ));
    }

    Ok(remotes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_config_is_the_default_set_rather_than_an_error() {
        let temp = tempfile::tempdir().unwrap();
        let cfg = load_config(temp.path()).unwrap();
        assert!(cfg.sync_enabled);
        assert!(!cfg.auto_accept_devices);
        assert!(cfg.remotes.is_empty());
    }

    #[test]
    fn config_round_trips_through_disk() {
        let temp = tempfile::tempdir().unwrap();
        let cfg = UserConfig {
            auto_accept_devices: true,
            ..Default::default()
        };
        save_config(temp.path(), &cfg).unwrap();

        let back = load_config(temp.path()).unwrap();
        assert!(back.auto_accept_devices);
        assert!(back.sync_enabled);
    }

    #[tokio::test]
    async fn a_config_with_no_reachable_remote_fails_to_instantiate() {
        // Every backend in this set is one this build skips, so the result is
        // empty — and an empty remote set is a load failure, not an empty
        // success, because the user would have nowhere to write.
        let mut cfg = UserConfig::default();
        cfg.remotes.insert(
            "archive".to_string(),
            RemoteConfig {
                backend: RemoteBackend::S3 {
                    bucket: "b".to_string(),
                    region: "us-east-1".to_string(),
                    endpoint: None,
                },
                cache_dir: None,
                key_format: Default::default(),
            },
        );

        // `Ok` here is a map of trait objects, which is not `Debug`, so the
        // failure is matched rather than unwrapped.
        let shelves = crate::LocalShelves(kotton_fs::MemoryFilesystem::new());
        match instantiate_remotes(&cfg, "alice", &shelves, None, None, None).await {
            Ok(_) => panic!("a remote set this build cannot reach must not load"),
            Err(e) => assert!(e.to_string().contains("no valid storage mounts")),
        }
    }
}
