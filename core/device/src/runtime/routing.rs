// SPDX-License-Identifier: AGPL-3.0-or-later
//! Device and user routing for DeviceRuntime
//!
//! Manages device-to-user mappings and UserRuntime registration.

use crate::runtime::DeviceRuntime;
use kotton_diag::{Event, EventCategory, EventLevel, EventScope};

impl DeviceRuntime {
    /// Register a device-to-user mapping
    ///
    /// Called by UserRuntime when a new device is paired.
    /// Updates the routing table for O(1) connection dispatch.
    pub fn register_device(&self, device_fingerprint: String, user_id: String) {
        let mut routing = self.device_routing.write().unwrap();
        routing.insert(device_fingerprint.clone(), user_id.clone());

        self.event_bus
            .publish(Event::with_payload(
                EventCategory::Auth,
                EventLevel::Info,
                format!("Device registered for user {}", user_id),
                serde_json::json!({
                    "device_fingerprint": device_fingerprint,
                    "user_id": user_id,
                }),
            )
            .in_scope(EventScope::User(user_id.clone())))
            .ok();
    }

    /// Unregister a device (when unpaired)
    pub fn unregister_device(&self, device_fingerprint: &str) {
        let mut routing = self.device_routing.write().unwrap();
        if let Some(user_id) = routing.remove(device_fingerprint) {
            self.event_bus
                .publish(Event::with_payload(
                    EventCategory::Auth,
                    EventLevel::Info,
                    format!("Device unregistered from user {}", user_id),
                    serde_json::json!({
                        "device_fingerprint": device_fingerprint,
                        "user_id": user_id,
                    }),
                )
                .in_scope(EventScope::User(user_id.clone())))
                .ok();
        }
    }

    /// Forget every device routed to `user_id`, on user deletion.
    ///
    /// Separate from [`Self::unregister_device`] because the caller knows the
    /// user, not the fingerprints — asking it to enumerate them first would make
    /// the routing table's internals the caller's problem, which is the shape
    /// this file just finished removing.
    pub fn unregister_user_devices(&self, user_id: &str) {
        self.device_routing
            .write()
            .unwrap()
            .retain(|_fingerprint, uid| uid != user_id);
    }

    /// Replace the in-memory routing table with the persisted one at startup.
    ///
    /// The table is a cache of `device_routing.json`; this is the one path that
    /// treats it as such, and it replaces rather than merges because the file is
    /// the authority at boot.
    pub fn restore_device_routes(&self, routes: std::collections::HashMap<String, String>) {
        *self.device_routing.write().unwrap() = routes;
    }





}

#[cfg(test)]
mod tests {
    use crate::config::RuntimeConfig;
    use crate::runtime::DeviceRuntime;

    /// The DID a node reports for itself decodes to the key it presents. The
    /// routing fingerprint is a different key — one whose private half was
    /// never kept — and it stays what it is: a label scope.
    #[tokio::test]
    async fn the_operational_did_is_the_did_of_the_key_the_node_presents() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = DeviceRuntime::new_with_secrets(
            temp.path().to_path_buf(),
            RuntimeConfig::default(),
            std::sync::Arc::new(kotton_secret::MemorySecrets::new()),
        )
        .await
        .unwrap();

        let did = kotton_wire::did::Did::parse(&runtime.operational_did()).expect("a DID");
        assert_eq!(
            kotton_crypto::DidKeyMethod::to_public_key(&did).expect("did:key").to_bytes(),
            runtime.device_signing_pubkey_bytes()
        );
        assert_ne!(
            runtime.operational_did(),
            runtime.device_did(),
            "the fingerprint names a key nobody holds; it is not the node's identity"
        );
    }

    #[tokio::test]
    async fn test_device_routing() {
        let config = RuntimeConfig::default();
        let temp = tempfile::tempdir().unwrap();
        let runtime = DeviceRuntime::new_with_secrets(temp.path().to_path_buf(), config, std::sync::Arc::new(kotton_secret::MemorySecrets::new()))
            .await
            .unwrap();

        let fingerprint = "sha256:abc123".to_string();
        let user_id = "alice".to_string();

        // Initially, no routing
        assert!(runtime.route_device(&fingerprint).is_none());

        // Register device
        runtime.register_device(fingerprint.clone(), user_id.clone());

        // The table answers with an id — resolving it to a runtime is the
        // daemon's hop, so there is nothing further to assert here.
        assert_eq!(runtime.route_device(&fingerprint), Some(user_id));
    }

    #[tokio::test]
    async fn test_device_unregister() {
        let config = RuntimeConfig::default();
        let temp = tempfile::tempdir().unwrap();
        let runtime = DeviceRuntime::new_with_secrets(temp.path().to_path_buf(), config, std::sync::Arc::new(kotton_secret::MemorySecrets::new()))
            .await
            .unwrap();

        let fingerprint = "sha256:abc123".to_string();
        let user_id = "alice".to_string();

        runtime.register_device(fingerprint.clone(), user_id.clone());
        runtime.unregister_device(&fingerprint);

        assert!(runtime.route_device(&fingerprint).is_none());
    }
}
