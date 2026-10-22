// SPDX-License-Identifier: AGPL-3.0-or-later
//! Permission checks for DeviceRuntime
//!
//! Permissive mode - all operations allowed
//! Future: RBAC, device-specific rules, resource-level permissions

use crate::runtime::DeviceRuntime;
use kotton_diag::{Event, EventCategory, EventLevel};

impl DeviceRuntime {
    /// Check if device can pair (permission check)
    ///
    /// Permissive mode - always allows pairing
    /// Future: RBAC, device-specific rules
    pub fn can_pair(&self, device_id: &str) -> bool {
        let allowed = true; // Permissive mode

        // Publish authorization event to EventBus
        self.event_bus
            .publish(Event::with_payload(
                EventCategory::Auth,
                EventLevel::Debug,
                format!("Authorization check: can_pair({})", device_id),
                serde_json::json!({
                    "device_id": device_id,
                    "operation": "pair",
                    "result": allowed,
                    "mode": "permissive"
                }),
            ))
            .ok();

        allowed
    }

    /// Check if device can send message to user (permission check)
    ///
    /// Permissive mode - always allows if paired
    /// Future: Fine-grained message permissions
    pub fn can_message(&self, from: &str, to: &str) -> bool {
        // TODO: Check if device is paired with user
        let allowed = true; // Permissive mode

        // Publish authorization event to EventBus
        self.event_bus
            .publish(Event::with_payload(
                EventCategory::Auth,
                EventLevel::Debug,
                format!("Authorization check: can_message({} -> {})", from, to),
                serde_json::json!({
                    "from_device": from,
                    "to_user": to,
                    "operation": "message",
                    "result": allowed,
                    "mode": "permissive"
                }),
            ))
            .ok();

        allowed
    }

    /// Check if device can sync resource (permission check)
    ///
    /// Permissive mode - always allows
    /// Future: Resource-level permissions
    pub fn can_sync(&self, device_id: &str, resource: &str) -> bool {
        let allowed = true; // Permissive mode

        // Publish authorization event to EventBus
        self.event_bus
            .publish(Event::with_payload(
                EventCategory::Auth,
                EventLevel::Debug,
                format!("Authorization check: can_sync({}, {})", device_id, resource),
                serde_json::json!({
                    "device_id": device_id,
                    "resource": resource,
                    "operation": "sync",
                    "result": allowed,
                    "mode": "permissive"
                }),
            ))
            .ok();

        allowed
    }
}

#[cfg(test)]
mod tests {
    use crate::config::RuntimeConfig;
    use crate::runtime::DeviceRuntime;

    #[tokio::test]
    async fn test_permission_checks_are_permissive() {
        let config = RuntimeConfig::default();
        let temp = tempfile::tempdir().unwrap();
        let runtime = DeviceRuntime::new_with_secrets(temp.path().to_path_buf(), config, std::sync::Arc::new(kotton_secret::MemorySecrets::new()))
            .await
            .unwrap();

        // All permission checks should return true in permissive mode
        assert!(runtime.can_pair("test-device"));
        assert!(runtime.can_message("device1", "user1"));
        assert!(runtime.can_sync("device1", "/data/file.txt"));
    }
}
