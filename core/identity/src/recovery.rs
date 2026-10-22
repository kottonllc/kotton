// SPDX-License-Identifier: AGPL-3.0-or-later
//! Recovery status, mnemonic confirmation and key rotation.
//!
//! Moved out of `05_runtime` (RFC-0060). Each reads or writes a user's identity
//! material under a base directory; rotation additionally needs the secrets
//! store. None needs a runtime, a device identity, or the registry of running
//! users.
//!
//! Two neighbours looked like they belonged here and do not, both for the same
//! reason — a dependency no field-access measurement could see. `bind_device`
//! calls `set_user_pin`, which needs the custody provider.
//! `rotate_identity_via_mnemonic` reaches `derive_aid_from_mnemonic` and
//! `build_mnemonic_rotation`, a chain still rooted in the runtime. Both follow
//! once that chain moves.

use std::path::Path;

use anyhow::{Context, Result};
// `pin_set` is passed in, not probed. The runtime owns the vault filename and
// has been wrong about it once: when the file moved from `wrapped_seed.json` to
// `vault.json`, every caller that duplicated the check reported "no PIN" for
// users who had one. One place knows the name — the same reason
// `kotton_crypto::key_health` takes it as an argument.


/// Recovery layer coverage for a user.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RecoveryStatus {
    /// User has confirmed their BIP-39 mnemonic by re-entering selected words.
    pub mnemonic_confirmed: bool,
    /// A PIN vault exists — PIN unlock is available.
    pub pin_set: bool,
    /// Managed escrow blob stored on the relay server.
    pub escrow_set: bool,
    /// Number of guardian share recipients configured.
    pub guardian_count: u8,
}

/// Mark that the user has confirmed their recovery mnemonic.
///
/// Writes (or updates) `users/{user_id}/onboarding.json` with
/// `mnemonic_confirmed: true`.  Creates the file if it does not yet exist.
pub async fn confirm_mnemonic(
    base_dir: &Path, user_id: &str) -> Result<()> {
    let path = base_dir
        .join("users")
        .join(user_id)
        .join("onboarding.json");

    let mut obj: serde_json::Map<String, serde_json::Value> = if path.exists() {
        let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_slice(&bytes).unwrap_or_default()
    } else {
        serde_json::Map::new()
    };

    obj.insert("mnemonic_confirmed".to_string(), serde_json::json!(true));

    let bytes = serde_json::to_vec_pretty(&serde_json::Value::Object(obj))
        .context("serialising onboarding.json")?;
    std::fs::write(&path, bytes).with_context(|| format!("writing {}", path.display()))?;

    Ok(())
}

/// Return the recovery layer status for a user.
///
/// Reads `onboarding.json` for the mnemonic-confirmed flag, and probes for
/// the PIN vault to determine whether PIN unlock is available.
pub fn get_recovery_status(
    base_dir: &Path,
    pin_set: bool, user_id: &str) -> Result<RecoveryStatus> {
    let user_dir = base_dir.join("users").join(user_id);

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


    Ok(RecoveryStatus {
        mnemonic_confirmed,
        pin_set,
        escrow_set: false, // M24h — not yet implemented
        guardian_count: 0, // M24g — not yet implemented
    })
}
