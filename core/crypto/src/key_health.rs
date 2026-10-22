// SPDX-License-Identifier: AGPL-3.0-or-later
//! Key health and algorithm migration.
//!
//! Moved out of `05_runtime` (RFC-0060). Both functions read a user's key
//! material off disk and, for migration, the secrets store — so they take a
//! `base_dir` and a `SecretsStore` rather than a `DeviceRuntime` that also holds
//! every other user's runtime and the device's own identity.
//!
//! Migration exists because the post-quantum answer is not settled. A platform
//! that cannot move algorithms has decided to stay on today's, which is a
//! decision worth making deliberately rather than by omission.

use std::path::Path;
use std::time::SystemTime;

use anyhow::{Context, Result};

// `pin_set` arrives as an argument rather than being probed here. The runtime
// owns the vault filename, and it has already been wrong once: when the file
// moved from `wrapped_seed.json` to `vault.json`, the callers that duplicated
// the check kept reading the old name and reported "no PIN" for every user who
// had one. One place knows the filename.


/// Status of one recovery layer.
#[derive(Debug, Clone)]
pub struct RecoveryLayerStatusResult {
    pub layer: String,
    pub active: bool,
    pub last_tested_at: Option<u64>,
}

/// Full cryptographic health summary for a user.
#[derive(Debug, Clone)]
pub struct KeyHealthResult {
    /// Active signing algorithm, e.g. `"ed25519-v1"`.
    pub root_algorithm: String,
    /// Monotonically increasing key version (1 = original).
    pub key_version: u32,
    /// Unix seconds of most recent explicit rotation; `None` until first rotation.
    pub last_rotated_at: Option<u64>,
    /// Advisory rotation policy in days; `None` if not configured.
    pub rotation_policy_days: Option<u32>,
    /// `true` when `last_rotated_at + rotation_policy_days * 86400 < now`.
    pub rotation_due: bool,
    /// Status of every recovery layer.
    pub recovery_layers: Vec<RecoveryLayerStatusResult>,
}

/// Return the key health summary for a user.
///
/// Reads `identity_v2.json` if present (ML-DSA migration), falls back to
/// `ed25519-v1`.  Reads `onboarding.json` and probes the PIN vault
/// to determine recovery layer status.  No keychain access.
pub fn get_key_health(
    base_dir: &Path,
    user_id: &str,
    pin_set: bool,
) -> Result<KeyHealthResult> {
    let user_dir = base_dir.join("users").join(user_id);

    // -- Active algorithm and key version ------------------------------------
    let identity_v2_path = user_dir.join("identity_v2.json");
    let (root_algorithm, key_version) = if identity_v2_path.exists() {
        let bytes = std::fs::read(&identity_v2_path)
            .with_context(|| format!("reading {}", identity_v2_path.display()))?;
        let val: serde_json::Value = serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing {}", identity_v2_path.display()))?;
        let algo = val
            .get("algorithm")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let ver = val.get("version").and_then(|v| v.as_u64()).unwrap_or(1) as u32;
        (format!("{}-v{}", algo, ver), ver)
    } else {
        ("ed25519-v1".to_string(), 1)
    };

    // -- Rotation metadata ---------------------------------------------------
    // `last_rotated_at` and `rotation_policy_days` are stored in
    // `users/{user_id}/key_health.json` once M24f (key rotation) lands.
    // For now both fields are None.
    let key_health_path = user_dir.join("key_health.json");
    let (last_rotated_at, rotation_policy_days): (Option<u64>, Option<u32>) =
        if key_health_path.exists() {
            let bytes = std::fs::read(&key_health_path)
                .with_context(|| format!("reading {}", key_health_path.display()))?;
            let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
            let rotated = val.get("last_rotated_at").and_then(|v| v.as_u64());
            let policy = val
                .get("rotation_policy_days")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32);
            (rotated, policy)
        } else {
            (None, None)
        };

    let rotation_due = match (last_rotated_at, rotation_policy_days) {
        (Some(rotated), Some(policy_days)) => {
            let now = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            now > rotated + (policy_days as u64) * 86_400
        }
        _ => false,
    };

    // -- Recovery layers -----------------------------------------------------
    let mnemonic_confirmed = {
        let path = user_dir.join("onboarding.json");
        if path.exists() {
            let bytes =
                std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            let val: serde_json::Value =
                serde_json::from_slice(&bytes).unwrap_or(serde_json::json!({}));
            val.get("mnemonic_confirmed")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        } else {
            false
        }
    };

    let recovery_layers = vec![
        RecoveryLayerStatusResult {
            layer: "mnemonic".to_string(),
            active: mnemonic_confirmed,
            last_tested_at: None, // Testing UI comes in a follow-up
        },
        RecoveryLayerStatusResult {
            layer: "pin_wrap".to_string(),
            active: pin_set,
            last_tested_at: None,
        },
        RecoveryLayerStatusResult {
            layer: "escrow".to_string(),
            active: false, // M24h — not yet implemented
            last_tested_at: None,
        },
        RecoveryLayerStatusResult {
            layer: "guardian".to_string(),
            active: false, // M24g — not yet implemented
            last_tested_at: None,
        },
    ];

    Ok(KeyHealthResult {
        root_algorithm,
        key_version,
        last_rotated_at,
        rotation_policy_days,
        rotation_due,
        recovery_layers,
    })
}

