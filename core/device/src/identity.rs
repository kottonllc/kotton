// SPDX-License-Identifier: AGPL-3.0-or-later
//! Stable per-device cryptographic identity.
//!
//! On first startup the daemon generates a random Ed25519 keypair, wraps the
//! public key into a `did:key` DID, and writes it to
//! `<base_dir>/device/identity.json`.  Every subsequent startup loads the same
//! fingerprint, so the device identity is stable across restarts and across all
//! users on the same machine.
//!
//! The private key is intentionally *not* persisted — for the current use-case
//! (stable routing fingerprint) only the public key matters.  If signing is
//! needed in a future phase, a separate encrypted key file should be added.

use anyhow::{Context, Result};
use kotton_sys::crypto::KeypairGenerator;
use kotton_crypto::{DidKeyMethod, Ed25519Keypair, ED25519_LIBRARY_TAG};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// On-disk representation of the device identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIdentity {
    /// `did:key:z6Mk…` derived from the device's Ed25519 public key.
    pub fingerprint: String,
    /// Hex-encoded Ed25519 public key (32 bytes).
    pub public_key_hex: String,
    /// ISO-8601 timestamp of when this identity was first created.
    pub created_at: String,
    /// Crate name + version used to generate the keys, e.g. `"ed25519-dalek@2.1.0"`.
    ///
    /// Written at key-generation time.  On startup, the daemon compares this
    /// with [`ED25519_LIBRARY_TAG`] and logs a warning if they differ.
    /// The `determinism_canary` test is the CI gate; this field is an
    /// early-warning complement for already-deployed instances.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crypto_library: Option<String>,
}

/// Load the device identity if it exists, or generate and persist a new one.
///
/// The identity file lives at `<base_dir>/device/identity.json`.
/// This function is called once during `DeviceRuntime::new()`.
pub fn ensure_device_identity(base_dir: &Path) -> Result<DeviceIdentity> {
    let device_dir = base_dir.join("device");
    let identity_path = device_dir.join("identity.json");

    if identity_path.exists() {
        let content = std::fs::read_to_string(&identity_path)
            .with_context(|| format!("Failed to read device identity from {:?}", identity_path))?;
        let identity: DeviceIdentity = serde_json::from_str(&content)
            .with_context(|| format!("Corrupt device identity at {:?}", identity_path))?;

        // Warn if the stored library tag differs from the current build.
        // This is an early-warning; the determinism_canary test is the CI gate.
        if let Some(stored_tag) = &identity.crypto_library {
            if stored_tag != ED25519_LIBRARY_TAG {
                tracing::warn!(
                    stored = %stored_tag,
                    current = %ED25519_LIBRARY_TAG,
                    "Device identity was generated with a different crypto library \
                     version. Run 'cargo test determinism_canary' before serving \
                     user data. If the test fails, follow the M25e upgrade protocol."
                );
            }
        }

        return Ok(identity);
    }

    // First start — generate a fresh identity.
    let keypair_generator = Ed25519Keypair;
    let (_private_key, public_key) = keypair_generator
        .generate()
        .map_err(|e| anyhow::anyhow!("Failed to generate device keypair: {}", e))?;

    let public_key_array: [u8; 32] = public_key
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Generated public key has unexpected length"))?;

    let did = DidKeyMethod::from_public_key_bytes(&public_key_array)
        .map_err(|e| anyhow::anyhow!("Failed to derive device DID: {}", e))?;

    let created_at_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let identity = DeviceIdentity {
        fingerprint: did.to_string(),
        public_key_hex: hex::encode(&public_key),
        created_at: created_at_secs.to_string(),
        crypto_library: Some(ED25519_LIBRARY_TAG.to_string()),
    };

    kotton_common::fs::create_dir_all_owner_only(&device_dir)
        .with_context(|| format!("Failed to create device directory {:?}", device_dir))?;

    let content =
        serde_json::to_string_pretty(&identity).context("Failed to serialize device identity")?;
    std::fs::write(&identity_path, &content)
        .with_context(|| format!("Failed to write device identity to {:?}", identity_path))?;

    tracing::info!(
        fingerprint = %identity.fingerprint,
        "Generated new device identity"
    );

    Ok(identity)
}
