// SPDX-License-Identifier: AGPL-3.0-or-later
//! The machine's registry of the users it serves, and how it routes to them.
//!
//! Two files under `system/`, and the schema of both:
//!
//! - `users.json` — which accounts exist on this machine, their DIDs, and the
//!   component versions their data was written with.
//! - `device_routing.json` — which device fingerprint belongs to which of them.
//!
//! On whose authority? **The machine's.** These are facts about this node: who
//! it serves and where to send an incoming connection. None of it is a user's
//! own data, and none of it can reach any — the invariant this crate keeps.
//!
//! The schema types live with the code that reads and writes them: `UserRecord`
//! sits beside the only file that persists it, not in a shared `types.rs`.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Component version tracking (inspired by iOS/Android/Windows versioning)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentVersion {
    /// Algorithm/implementation name
    pub algorithm: String, // "aes-256-gcm", "hkdf-ed25519", "argon2id-v1", ...

    /// Semver (user-facing): major.minor.patch
    pub version: semver::Version, // 1.2.3

    /// API Level (developer/compatibility): Breaking change counter
    /// Files encrypted with API 1 can be read by API 1 or higher
    pub api_level: u32, // 1, 2, 3...

    /// Build number (support/debug): Exact code version
    /// Format: YYxNNNN (26A5123 = 2026 + A + build 5123)
    pub build: String, // "26A5123"

    /// Security patch date (like Android)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_patch: Option<String>, // a date, "YYYY-MM-DD"

    /// Derivation path (crypto components only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derivation_path: Option<String>, // "m/44'/1234'/0'/1'/0'"

    /// Ordered list of derivation paths to try when recovering from mnemonic
    /// without a stored `ComponentVersions` (e.g. clean device restore).
    ///
    /// When populated, recovery sweeps this list in order. The first path that
    /// produces a known DID wins. The primary `derivation_path` is always tried
    /// first; this list provides fallbacks for previously-deployed defaults that
    /// may exist in the wild.
    ///
    /// Only meaningful for algorithms that sweep a path list during recovery.
    /// Empty for all current users (HKDF has no path to sweep).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recovery_paths: Vec<String>,

    /// BIP-39 word list and word count used for the mnemonic phrase.
    ///
    /// Format: `"bip39-<language>-<word_count>"` (e.g. `"bip39-english-24"`).
    /// Omitted on components where a mnemonic is irrelevant.
    ///
    /// Dispatch hook for Layer 1 of the identity pipeline: when the mnemonic
    /// format changes (different word list, different word count, different
    /// entropy format), this field identifies the old and new formats, enabling
    /// a recovery tool to try known formats without ambiguity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mnemonic_format: Option<String>,

    /// KDF used to stretch the mnemonic into `seed32`.
    ///
    /// Format: `"<algorithm>"` (e.g. `"bip39-pbkdf2-sha512"`).
    /// Omitted on components where a mnemonic is irrelevant.
    ///
    /// Dispatch hook for Layer 2 of the identity pipeline: when the seed
    /// derivation function is replaced (e.g. PBKDF2 → Argon2), this field
    /// identifies which KDF was used, so cross-version recovery code can pick
    /// the right implementation without guessing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mnemonic_kdf: Option<String>,
}

impl ComponentVersion {
    /// Display for users: "aes-256-gcm v1.2.3"
    pub fn user_display(&self) -> String {
        format!("{} v{}", self.algorithm, self.version)
    }

    /// Display for support: "aes-256-gcm v1.2.3 (build 26A5123, API 1)"
    pub fn debug_display(&self) -> String {
        format!(
            "{} v{} (build {}, API {})",
            self.algorithm, self.version, self.build, self.api_level
        )
    }

    /// Check compatibility (Android-style API level check)
    pub fn is_compatible(&self, file_api_level: u32) -> bool {
        self.api_level >= file_api_level
    }
}

/// Component versions for all system components
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentVersions {
    // Crypto components
    pub key_derivation: ComponentVersion,
    pub encryption: ComponentVersion,
    pub signing: ComponentVersion,
    pub hashing: ComponentVersion,

    // Data format components
    pub vfs_format: ComponentVersion,
    pub device_registry: ComponentVersion,
    pub user_config: ComponentVersion,

    /// Passphrase-to-keychain-unlock KDF (Layer C2 of the encryption pipeline).
    ///
    /// Records the algorithm used to derive the keychain-unlock key from the
    /// user's passphrase (e.g. Argon2id parameters).  Dispatch hook: when
    /// Argon2id is superseded, add a new `"argon2id-v2"` case here without
    /// touching any file content.
    pub keychain: ComponentVersion,

    // Protocol components (future)
    pub sync_protocol: ComponentVersion,
    pub pairing_protocol: ComponentVersion,
}

impl Default for ComponentVersions {
    fn default() -> Self {
        let build = option_env!("BUILD_NUMBER").unwrap_or("dev").to_string();

        Self {
            key_derivation: ComponentVersion {
                // Layer 3 of the identity pipeline: seed32 → HKDF-SHA256 → Ed25519 scalar.
                algorithm: "hkdf-ed25519".to_string(),
                version: semver::Version::new(1, 0, 0),
                api_level: 1,
                build: build.clone(),
                security_patch: None,
                // Layer 1: 24-word BIP-39 English mnemonic (256 bits of entropy).
                mnemonic_format: Some("bip39-english-24".to_string()),
                // Layer 2: standard BIP-39 PBKDF2-SHA512, no passphrase.
                mnemonic_kdf: Some("bip39-pbkdf2-sha512".to_string()),
                // No derivation path for HKDF: the label is embedded in the algorithm string.
                derivation_path: None,
                // No recovery paths for HKDF: the label is stable and doesn't change.
                recovery_paths: vec![],
            },
            encryption: ComponentVersion {
                algorithm: "aes-256-gcm".to_string(),
                version: semver::Version::new(1, 0, 0),
                api_level: 1,
                build: build.clone(),
                security_patch: None,
                derivation_path: Some("m/44'/1234'/0'/1'/0'".to_string()),
                recovery_paths: vec![],
                mnemonic_format: None,
                mnemonic_kdf: None,
            },
            signing: ComponentVersion {
                algorithm: "ed25519".to_string(),
                version: semver::Version::new(1, 0, 0),
                api_level: 1,
                build: build.clone(),
                security_patch: None,
                derivation_path: None,
                recovery_paths: vec![],
                mnemonic_format: None,
                mnemonic_kdf: None,
            },
            hashing: ComponentVersion {
                algorithm: "blake3".to_string(),
                version: semver::Version::new(1, 0, 0),
                api_level: 1,
                build: build.clone(),
                security_patch: None,
                derivation_path: None,
                recovery_paths: vec![],
                mnemonic_format: None,
                mnemonic_kdf: None,
            },
            vfs_format: ComponentVersion {
                algorithm: "vfs".to_string(),
                version: semver::Version::new(1, 0, 0),
                api_level: 1,
                build: build.clone(),
                security_patch: None,
                derivation_path: None,
                recovery_paths: vec![],
                mnemonic_format: None,
                mnemonic_kdf: None,
            },
            device_registry: ComponentVersion {
                algorithm: "device-registry".to_string(),
                version: semver::Version::new(1, 0, 0),
                api_level: 1,
                build: build.clone(),
                security_patch: None,
                derivation_path: None,
                recovery_paths: vec![],
                mnemonic_format: None,
                mnemonic_kdf: None,
            },
            user_config: ComponentVersion {
                algorithm: "user-config".to_string(),
                version: semver::Version::new(1, 0, 0),
                api_level: 1,
                build: build.clone(),
                security_patch: None,
                derivation_path: None,
                recovery_paths: vec![],
                mnemonic_format: None,
                mnemonic_kdf: None,
            },
            keychain: ComponentVersion {
                // Layer C2: passphrase → Argon2id → keychain-unlock key.
                // Dispatch hook: when Argon2id parameters change, add "argon2id-v2" here.
                algorithm: "argon2id-v1".to_string(),
                version: semver::Version::new(1, 0, 0),
                api_level: 1,
                build: build.clone(),
                security_patch: None,
                derivation_path: None,
                recovery_paths: vec![],
                mnemonic_format: None,
                mnemonic_kdf: None,
            },
            sync_protocol: ComponentVersion {
                algorithm: "none".to_string(),
                version: semver::Version::new(0, 0, 0),
                api_level: 0,
                build: build.clone(),
                security_patch: None,
                derivation_path: None,
                recovery_paths: vec![],
                mnemonic_format: None,
                mnemonic_kdf: None,
            },
            pairing_protocol: ComponentVersion {
                algorithm: "none".to_string(),
                version: semver::Version::new(0, 0, 0),
                api_level: 0,
                build,
                security_patch: None,
                derivation_path: None,
                recovery_paths: vec![],
                mnemonic_format: None,
                mnemonic_kdf: None,
            },
        }
    }
}

/// User record stored in users.json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRecord {
    pub user_id: String,

    /// The user's primary DID. Always a `did:key:z6Mk...` — self-certifying,
    /// no external dependency, derived from the BIP-39 mnemonic.
    ///
    /// Derived via `HKDF-SHA256(seed32, info="kotton:identity:ed25519:v1")`.
    /// Legacy users used SLIP-10 path `m/44'/1234'/0'/0'/0'`.
    ///
    /// This field must never be changed after the record is created; it is the
    /// stable cryptographic identity for this user.
    pub did: String,

    /// The DID method used for the primary `did` field.
    ///
    /// `"key"` for all current users (`did:key`, self-certifying, no external
    /// dependency).  Future values are TBD — see `decisions.md` for why
    /// no current DID method provides both self-sovereignty and key rotation.
    /// Stored explicitly so resolution code never has to parse `did` to detect method.
    #[serde(default = "default_did_method")]
    pub did_method: String,

    /// Additional DID identifiers that resolve to the same key as `did`.
    ///
    /// Examples:
    /// - `"did:web:kotton.cloud:u:alice"` — a human-readable handle
    /// - `"did:web:alice.example.com:.well-known"` — a self-hosted handle
    ///
    /// The primary `did` is always the canonical identity. Aliases are convenience
    /// pointers only — they can be revoked, changed, or lost without affecting identity.
    /// The DID document at each alias URL must include `alsoKnownAs` pointing back to
    /// the primary `did:key` to prove the binding.
    #[serde(default)]
    pub aliases: Vec<String>,

    pub created_at: SystemTime,
    pub last_active: SystemTime,

    /// Component versions (defaults to current if missing)
    #[serde(default)]
    pub versions: ComponentVersions,
}

fn default_did_method() -> String {
    "key".to_string()
}

/// Users registry (users.json schema)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UsersRegistry {
    pub users: Vec<UserRecord>,
}

/// Device routing table (device_routing.json schema)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeviceRouting {
    pub routes: HashMap<String, String>, // device_fingerprint -> user_id
}

/// Load users registry from ~/.Kotton/system/users.json
pub fn load_users(system_dir: &Path) -> Result<UsersRegistry> {
    let path = system_dir.join("users.json");

    if !path.exists() {
        return Ok(UsersRegistry::default());
    }

    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read users.json from {:?}", path))?;

    let registry: UsersRegistry = serde_json::from_str(&contents)
        .with_context(|| format!("Failed to parse users.json from {:?}", path))?;

    Ok(registry)
}

/// Save users registry to ~/.Kotton/system/users.json
pub fn save_users(system_dir: &Path, registry: &UsersRegistry) -> Result<()> {
    // `system/`, and the base dir above it, owner-only when made here
    // (`kotton_common::fs::create_dir_all_owner_only`).
    kotton_common::fs::create_dir_all_owner_only(system_dir)
        .with_context(|| format!("Failed to create system directory {:?}", system_dir))?;

    let path = system_dir.join("users.json");
    let contents =
        serde_json::to_string_pretty(registry).context("Failed to serialize users registry")?;

    std::fs::write(&path, contents)
        .with_context(|| format!("Failed to write users.json to {:?}", path))?;

    Ok(())
}

/// Load device routing table from ~/.Kotton/system/device_routing.json
pub fn load_device_routing(system_dir: &Path) -> Result<DeviceRouting> {
    let path = system_dir.join("device_routing.json");

    if !path.exists() {
        return Ok(DeviceRouting::default());
    }

    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read device_routing.json from {:?}", path))?;

    let routing: DeviceRouting = serde_json::from_str(&contents)
        .with_context(|| format!("Failed to parse device_routing.json from {:?}", path))?;

    Ok(routing)
}

/// Save device routing table to ~/.Kotton/system/device_routing.json
pub fn save_device_routing(system_dir: &Path, routing: &DeviceRouting) -> Result<()> {
    // `system/`, and the base dir above it, owner-only when made here
    // (`kotton_common::fs::create_dir_all_owner_only`).
    kotton_common::fs::create_dir_all_owner_only(system_dir)
        .with_context(|| format!("Failed to create system directory {:?}", system_dir))?;

    let path = system_dir.join("device_routing.json");
    let contents =
        serde_json::to_string_pretty(routing).context("Failed to serialize device routing")?;

    std::fs::write(&path, contents)
        .with_context(|| format!("Failed to write device_routing.json to {:?}", path))?;

    Ok(())
}

/// Create user directory structure: ~/.Kotton/users/{user_id}/
pub fn create_user_directory(base_dir: &Path, user_id: &str) -> Result<PathBuf> {
    let user_dir = base_dir.join("users").join(user_id);

    // Create main user directory — and `users/` and the base dir above it,
    // owner-only when made here (`kotton_common::fs::create_dir_all_owner_only`).
    kotton_common::fs::create_dir_all_owner_only(&user_dir)
        .with_context(|| format!("Failed to create user directory {:?}", user_dir))?;

    // Create subdirectories
    let keys_dir = user_dir.join("keys");
    let data_dir = user_dir.join("data");

    kotton_common::fs::create_dir_all_owner_only(&keys_dir)
        .with_context(|| format!("Failed to create keys directory {:?}", keys_dir))?;

    kotton_common::fs::create_dir_all_owner_only(&data_dir)
        .with_context(|| format!("Failed to create data directory {:?}", data_dir))?;

    Ok(user_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::ComponentVersions;
    use std::time::SystemTime;
    use tempfile::TempDir;

    #[test]
    fn test_users_registry_roundtrip() {
        let temp = TempDir::new().unwrap();
        let system_dir = temp.path().join("system");

        // Save empty registry
        let registry = UsersRegistry::default();
        save_users(&system_dir, &registry).unwrap();

        // Load it back
        let loaded = load_users(&system_dir).unwrap();
        assert_eq!(loaded.users.len(), 0);

        // Add a user
        let mut registry = loaded;
        registry.users.push(UserRecord {
            user_id: "alice".to_string(),
            did: "did:key:z6Mk...".to_string(),
            did_method: "key".to_string(),
            aliases: vec![],
            created_at: SystemTime::now(),
            last_active: SystemTime::now(),
            versions: ComponentVersions::default(),
        });

        // Save and load again
        save_users(&system_dir, &registry).unwrap();
        let loaded = load_users(&system_dir).unwrap();
        assert_eq!(loaded.users.len(), 1);
        assert_eq!(loaded.users[0].user_id, "alice");
    }

    #[test]
    fn test_device_routing_roundtrip() {
        let temp = TempDir::new().unwrap();
        let system_dir = temp.path().join("system");

        // Save empty routing
        let routing = DeviceRouting::default();
        save_device_routing(&system_dir, &routing).unwrap();

        // Load it back
        let loaded = load_device_routing(&system_dir).unwrap();
        assert_eq!(loaded.routes.len(), 0);

        // Add a route
        let mut routing = loaded;
        routing
            .routes
            .insert("device_abc123".to_string(), "alice".to_string());

        // Save and load again
        save_device_routing(&system_dir, &routing).unwrap();
        let loaded = load_device_routing(&system_dir).unwrap();
        assert_eq!(loaded.routes.len(), 1);
        assert_eq!(
            loaded.routes.get("device_abc123"),
            Some(&"alice".to_string())
        );
    }

    #[test]
    fn test_create_user_directory() {
        let temp = TempDir::new().unwrap();

        let user_dir = create_user_directory(temp.path(), "alice").unwrap();

        // Verify directories exist
        assert!(user_dir.exists());
        assert!(user_dir.join("keys").exists());
        assert!(user_dir.join("data").exists());
    }
}
