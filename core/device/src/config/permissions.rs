// SPDX-License-Identifier: AGPL-3.0-or-later
//! Permission model configuration

use serde::{Deserialize, Serialize};

/// Permission model configuration
///
/// Controls access to capabilities (pairing, messaging, sync).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionConfig {
    /// Permission mode
    pub mode: PermissionMode,
}

impl Default for PermissionConfig {
    fn default() -> Self {
        Self {
            mode: PermissionMode::Permissive,
        }
    }
}

/// Permission modes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PermissionMode {
    /// Allow all operations if device is paired
    Permissive,
    // Future: Fine-grained modes
    // RoleBased { roles: Vec<Role> },
    // DeviceSpecific { rules: Vec<Rule> },
}
