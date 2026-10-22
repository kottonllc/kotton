// SPDX-License-Identifier: AGPL-3.0-or-later
//! Runtime configuration types
//!
//! Configuration is capability-based: compose network, storage, and relay
//! capabilities as needed. Preset factory functions provide ergonomic defaults.
//!
//! ## Principles
//!
//! - **No hardcoded values in services** - all config flows from runtime
//! - **Capability composition** - mix and match features freely
//! - **Presets for common scenarios** - full_node, storage_s3, relay_only
//! - **Type-safe** - invalid combinations caught at compile time where possible
//!
//! ## Structure
//!
//! Config types are split into focused modules:
//! - [transport] - TransportConfig, TlsConfig, HttpAuth
//! - [discovery] - DiscoveryMethod
//! - [storage] - StorageConfig
//! - [relay] - RelayConfig
//! - [permissions] - PermissionConfig, PermissionMode
//!
//! ## Example
//!
//! ```rust,no_run
//! use kotton_device::config::RuntimeConfig;
//! use std::path::PathBuf;
//!
//! # fn example() {
//! // A full node: every service this machine can run.
//! let config = RuntimeConfig::full_node(PathBuf::from("/var/lib/Kotton"));
//!
//! // Or compose one: start from the default and switch a service off.
//! let mut config = RuntimeConfig::default();
//! config.relay = None;
//! # }
//! ```
//!
//! *Doctests are compiled, so this example is a compiled check on the type it
//! documents.*

pub mod db;
pub mod ops;
pub mod web_shell_db;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// Re-export all config types
pub use discovery::DiscoveryMethod;
/// Reachability parameters live in the `peer` domain — they configure
/// how this device reaches, and is reached by, the other devices its user owns.
/// Re-exported because they are still persisted as part of [`RuntimeConfig`].
pub use kotton_peer::nat::NatNetworkConfig;
pub use permissions::{PermissionConfig, PermissionMode};
pub use relay::RelayConfig;
pub use storage::{AwsCredentials, StorageConfig};
pub use transport::{HttpAuth, TlsConfig, TransportConfig, TurnServer};

pub mod discovery;
pub mod permissions;
pub mod relay;
pub mod storage;
pub mod transport;

/// Main runtime configuration
///
/// Capabilities are optional - compose as needed for your deployment scenario.
///
/// # Examples
///
/// ```rust
/// use kotton_device::RuntimeConfig;
/// use std::path::PathBuf;
///
/// // Full node with all capabilities
/// let config = RuntimeConfig::full_node(PathBuf::from("/data"));
///
/// // Storage-only node with S3
/// let config = RuntimeConfig::storage_s3(
///     "my-bucket".to_string(),
///     "us-east-1".to_string(),
/// );
///
/// // Custom composition
/// let mut config = RuntimeConfig::default();
/// // config.transports.push(...);
/// // config.relay = Some(RelayConfig::default());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuntimeConfig {
    /// Network transports this device supports
    pub transports: Vec<TransportConfig>,

    /// Discovery mechanisms to find peers
    pub discovery: Vec<DiscoveryMethod>,

    /// Storage backends this device has access to
    pub stores: Vec<StorageConfig>,

    /// Relay capability (forward messages, manage peers)
    pub relay: Option<RelayConfig>,

    /// Permission model
    pub permissions: PermissionConfig,

    /// If `Some(port)`, the QUIC peer-listener is enabled on that port.
    /// Default `None` means the peer-listener is disabled (safe default).
    #[serde(default)]
    pub peer_listen_port: Option<u16>,

    /// NAT traversal configuration.  Empty strings disable individual features.
    #[serde(default)]
    pub nat: NatNetworkConfig,

    /// The one address this host is reached at from outside, when it has one
    /// (`KOTTON_PUBLIC_ADDR`): a host has one public address. A ceremony
    /// that observes no address of its own — one met at a relay — announces
    /// this beside the peer listener's port, so the device that admits this
    /// node records something it can dial. `None` for a device, and for a host
    /// behind a NAT: such a node announces only its port and is reached where
    /// it was seen from, or through its relay.
    #[serde(default)]
    pub public_ip: Option<std::net::IpAddr>,

    /// The one user this process serves — a user DID or user id.
    ///
    /// When set, startup loads **only** this user's runtime and resolves only
    /// this user's keys, and `create_user` refuses any other id: the process
    /// boundary is the principal boundary. `None` is the unsupervised
    /// dev/compat mode, which loads every user the way one daemon always has.
    ///
    /// `#[serde(skip)]` is deliberate: the principal is process identity, not
    /// configuration. It reaches here from the supervisor's `KOTTON_USER_DID`
    /// environment (set by `kdeviced` at spawn), never from a config file a
    /// caller could edit.
    #[serde(skip)]
    pub principal: Option<String>,

    /// Where this machine's supervisor, `kdeviced`, listens — the socket a
    /// person's daemon speaks to under their own operator key.
    ///
    /// `None` is the machine's own (`kdeviced_ipc_name`); a test with a base
    /// directory of its own names its own. Skipped for the principal's reason:
    /// which process supervises this one is not a thing a config file says.
    #[serde(skip)]
    pub kdeviced: Option<kotton_sys::ipc::IpcEndpoint>,
}

impl RuntimeConfig {
    ///
    /// - Network: listening on default port; no discovery (the local network is the
    ///   door's, and the door is opened on purpose)
    /// - Storage: local filesystem at specified path
    /// - Relay: enabled with default limits
    /// - Permissions: permissive (allow all if paired)
    pub fn full_node(data_path: PathBuf) -> Self {
        Self {
            transports: vec![TransportConfig::Tcp {
                listen_addr: "0.0.0.0:7734".parse().unwrap(),
                tls: TlsConfig::default(),
            }],
            // No discovery: the local network is the door's, opened on purpose.
            discovery: vec![],
            stores: vec![StorageConfig::Local { path: data_path }],
            relay: Some(RelayConfig::default()),
            permissions: PermissionConfig::default(),
            peer_listen_port: None,
            nat: NatNetworkConfig::default(),
            public_ip: None,
            principal: None,
            kdeviced: None,
        }
    }

    /// Storage node with S3: no network listening, just serve from S3
    ///
    /// - Network: disabled (no listening socket)
    /// - Storage: S3 bucket
    /// - Relay: disabled
    /// - Permissions: permissive
    pub fn storage_s3(bucket: String, region: String) -> Self {
        Self {
            transports: vec![],
            discovery: vec![],
            stores: vec![StorageConfig::S3 {
                bucket,
                region,
                credentials: None, // Use environment/IAM role
            }],
            relay: None,
            permissions: PermissionConfig::default(),
            peer_listen_port: None,
            nat: NatNetworkConfig::default(),
            public_ip: None,
            principal: None,
            kdeviced: None,
        }
    }

    /// Relay-only node: forward messages, no storage
    ///
    /// - Network: listening; no discovery
    /// - Storage: disabled
    /// - Relay: enabled
    /// - Permissions: permissive
    pub fn relay_only() -> Self {
        Self {
            transports: vec![TransportConfig::Tcp {
                listen_addr: "0.0.0.0:7734".parse().unwrap(),
                tls: TlsConfig::default(),
            }],
            // No discovery: the local network is the door's, opened on purpose.
            discovery: vec![],
            stores: vec![],
            relay: Some(RelayConfig::default()),
            permissions: PermissionConfig::default(),
            peer_listen_port: None,
            nat: NatNetworkConfig::default(),
            public_ip: None,
            principal: None,
            kdeviced: None,
        }
    }

    /// Validate configuration for invalid combinations
    pub fn validate(&self) -> Result<(), String> {
        // Validate all storage backends
        for store in &self.stores {
            store.validate()?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_node_preset() {
        let config = RuntimeConfig::full_node(PathBuf::from("/data"));

        assert_eq!(config.transports.len(), 1);
        assert_eq!(config.stores.len(), 1);
        assert!(matches!(config.stores[0], StorageConfig::Local { .. }));
        assert!(config.relay.is_some());
        assert_eq!(config.permissions.mode, PermissionMode::Permissive);
        assert!(config.discovery.is_empty(), "the local network is the door's");
    }

    #[test]
    fn test_storage_s3_preset() {
        let config = RuntimeConfig::storage_s3("bucket".to_string(), "us-east-1".to_string());

        assert_eq!(config.transports.len(), 0);
        assert_eq!(config.stores.len(), 1);
        assert!(matches!(config.stores[0], StorageConfig::S3 { .. }));
        assert!(config.relay.is_none());
    }

    #[test]
    fn test_relay_only_preset() {
        let config = RuntimeConfig::relay_only();

        assert_eq!(config.transports.len(), 1);
        assert_eq!(config.stores.len(), 0);
        assert!(config.relay.is_some());
        assert!(config.discovery.is_empty(), "the local network is the door's");
    }

    #[test]
    fn test_custom_composition() {
        let config = RuntimeConfig {
            transports: vec![TransportConfig::Tcp {
                listen_addr: "0.0.0.0:7734".parse().unwrap(),
                tls: TlsConfig::default(),
            }],
            discovery: vec![DiscoveryMethod::Manual {
                peers: vec!["192.168.1.10:7734".parse().unwrap()],
            }],
            stores: vec![StorageConfig::S3 {
                bucket: "test".to_string(),
                region: "us-west-2".to_string(),
                credentials: None,
            }],
            relay: None,
            permissions: PermissionConfig::default(),
            peer_listen_port: None,
            nat: NatNetworkConfig::default(),
            public_ip: None,
            principal: None,
            kdeviced: None,
        };

        assert_eq!(config.transports.len(), 1);
        assert_eq!(config.discovery.len(), 1);
        assert_eq!(config.stores.len(), 1);
        assert!(config.relay.is_none());
    }

    #[test]
    fn test_tls_defaults_to_mutual() {
        let tls = TlsConfig::default();
        assert!(tls.require_client_cert);
        assert!(tls.cert_path.is_none()); // Auto-generate
        assert!(tls.key_path.is_none());
    }

    #[test]
    fn test_validation_rejects_empty_s3_bucket() {
        let config = RuntimeConfig {
            transports: vec![],
            discovery: vec![],
            stores: vec![StorageConfig::S3 {
                bucket: "".to_string(),
                region: "us-east-1".to_string(),
                credentials: None,
            }],
            relay: None,
            permissions: PermissionConfig::default(),
            peer_listen_port: None,
            nat: NatNetworkConfig::default(),
            public_ip: None,
            principal: None,
            kdeviced: None,
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_accepts_valid_config() {
        let config = RuntimeConfig::full_node(PathBuf::from("/data"));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_relay_default_limits() {
        let relay = RelayConfig::default();
        assert_eq!(relay.max_peers, 100);
        assert!(relay.bandwidth_limit.is_none());
    }

    #[test]
    fn test_multi_instance_support() {
        // Test that we can configure multiple transports and stores
        let config = RuntimeConfig {
            transports: vec![
                TransportConfig::Tcp {
                    listen_addr: "0.0.0.0:7734".parse().unwrap(),
                    tls: TlsConfig::default(),
                },
                TransportConfig::Quic {
                    listen_addr: "0.0.0.0:7735".parse().unwrap(),
                    ephemeral: true,
                    cert_key_id: None,
                },
                TransportConfig::WebSocket {
                    listen_addr: Some("0.0.0.0:8080".parse().unwrap()),
                    endpoint: None,
                    auth: None,
                },
            ],
            discovery: vec![
                DiscoveryMethod::Manual {
                    peers: vec!["192.168.1.11:7734".parse().unwrap()],
                },
                DiscoveryMethod::Manual {
                    peers: vec!["192.168.1.10:7734".parse().unwrap()],
                },
            ],
            stores: vec![
                StorageConfig::Local {
                    path: PathBuf::from("/data/local"),
                },
                StorageConfig::S3 {
                    bucket: "backup-bucket".to_string(),
                    region: "us-east-1".to_string(),
                    credentials: None,
                },
                StorageConfig::Azure {
                    account: "myaccount".to_string(),
                    container: "mycontainer".to_string(),
                    key: "mykey".to_string(),
                },
            ],
            relay: Some(RelayConfig::default()),
            permissions: PermissionConfig::default(),
            peer_listen_port: None,
            nat: NatNetworkConfig::default(),
            public_ip: None,
            principal: None,
            kdeviced: None,
        };

        assert_eq!(config.transports.len(), 3);
        assert_eq!(config.discovery.len(), 2);
        assert_eq!(config.stores.len(), 3);
        assert!(config.validate().is_ok());
    }
}
