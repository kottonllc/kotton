// SPDX-License-Identifier: AGPL-3.0-or-later
//! Relay capability configuration

use serde::{Deserialize, Serialize};

/// Relay capability configuration
///
/// Controls message forwarding and peer management.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    /// Maximum number of peers to relay for
    pub max_peers: usize,

    /// Optional bandwidth limit in bytes/sec
    pub bandwidth_limit: Option<u64>,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            max_peers: 100,
            bandwidth_limit: None, // Unlimited
        }
    }
}
