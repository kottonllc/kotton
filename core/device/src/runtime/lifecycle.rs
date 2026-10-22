// SPDX-License-Identifier: AGPL-3.0-or-later
//! Runtime lifecycle management (start, shutdown)

use crate::runtime::DeviceRuntime;
use anyhow::Result;
use kotton_diag::{Event, EventCategory, EventLevel};

impl DeviceRuntime {
    /// Start the runtime and all configured services
    pub async fn start(&self) -> Result<()> {
        // Gate check: use a short scope so the lock is released before any await.
        {
            if *self.started.read().unwrap() {
                anyhow::bail!("Runtime already started");
            }
        }

        self.event_bus
            .publish(Event::new(
                EventCategory::System,
                EventLevel::Info,
                "DeviceRuntime starting",
            ))
            .ok(); // Ignore error if no subscribers

        // Instantiate and start all configured transports
        let mut transports_vec = Vec::new();

        for (idx, transport_config) in self.config.transports.iter().enumerate() {
            self.event_bus
                .publish(Event::new(
                    EventCategory::Network,
                    EventLevel::Info,
                    format!("Initializing transport {}: {:?}", idx, transport_config),
                ))
                .ok();

            let instance =
                crate::network::instantiate_transport(transport_config, &self.event_bus)
                    .await?;

            // Note: Listener management deferred to daemon integration
            // Accept loops require Arc<DeviceRuntime> which tests don't provide
            if instance.listener.is_some() {
                self.event_bus
                    .publish(Event::new(
                        EventCategory::Network,
                        EventLevel::Debug,
                        format!(
                            "Listener created for {} (accept loop deferred to daemon)",
                            instance.name
                        ),
                    ))
                    .ok();
            }

            transports_vec.push(instance.transport);
        }

        // Store initialized transports
        *self.transports.write().unwrap() = transports_vec;

        // Instantiate and start all configured discovery mechanisms
        let mut discoveries_vec = Vec::new();

        for (idx, discovery_method) in self.config.discovery.iter().enumerate() {
            self.event_bus
                .publish(Event::new(
                    EventCategory::Network,
                    EventLevel::Info,
                    format!("Initializing discovery {}: {:?}", idx, discovery_method),
                ))
                .ok();

            let discovery =
                crate::network::instantiate_discovery(discovery_method, &self.event_bus)
                    .await?;
            discoveries_vec.push(discovery);
        }

        // Store initialized discoveries
        *self.discoveries.write().unwrap() = discoveries_vec;

        *self.started.write().unwrap() = true;

        self.event_bus
            .publish(Event::new(
                EventCategory::System,
                EventLevel::Info,
                "DeviceRuntime started successfully",
            ))
            .ok();

        Ok(())
    }

    /// Gracefully shutdown the runtime
    pub async fn shutdown(&self) -> Result<()> {
        // Gate check: use a short scope so the lock is released before any await.
        {
            if !*self.started.read().unwrap() {
                anyhow::bail!("Runtime not started");
            }
        }

        self.event_bus
            .publish(Event::new(
                EventCategory::System,
                EventLevel::Info,
                "DeviceRuntime shutting down",
            ))
            .ok();

        // Shut the local-network door first: its keeper would otherwise reopen what
        // the accept-task abort below left behind.
        self.close_local_door().await;
        // And every introduced listener, which the accept-task abort below does not
        // reach: each is its own task.
        self.close_introductions().await;

        // Abort all accept tasks
        let accept_tasks = self.accept_tasks.lock().await;
        for task in accept_tasks.iter() {
            task.abort();
        }
        drop(accept_tasks);

        // Shutting down the resident user runtimes is **the daemon's**, not the
        // machine's: it owns the registry, so it is the only
        // thing that can enumerate them.
        //
        // Shutting a user runtime down beyond what the daemon's teardown does is
        // owed, and not built. It belongs beside the daemon's other teardown,
        // next to `stop_user_log` and the pool eviction, which already run there
        // — not in a loop over a registry this type does not hold.

        *self.started.write().unwrap() = false;

        self.event_bus
            .publish(Event::new(
                EventCategory::System,
                EventLevel::Info,
                "DeviceRuntime shutdown complete",
            ))
            .ok();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::config::RuntimeConfig;
    use crate::runtime::DeviceRuntime;

    #[tokio::test]
    async fn test_start_and_shutdown() {
        let config = RuntimeConfig::default();
        let temp = tempfile::tempdir().unwrap();
        let runtime = DeviceRuntime::new_with_secrets(temp.path().to_path_buf(), config, std::sync::Arc::new(kotton_secret::MemorySecrets::new())).await.unwrap();

        assert!(!runtime.is_started());

        runtime.start().await.unwrap();
        assert!(runtime.is_started());

        runtime.shutdown().await.unwrap();
        assert!(!runtime.is_started());
    }

    #[tokio::test]
    async fn test_cannot_start_twice() {
        let config = RuntimeConfig::default();
        let temp = tempfile::tempdir().unwrap();
        let runtime = DeviceRuntime::new_with_secrets(temp.path().to_path_buf(), config, std::sync::Arc::new(kotton_secret::MemorySecrets::new())).await.unwrap();

        runtime.start().await.unwrap();
        let result = runtime.start().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_cannot_shutdown_before_start() {
        let config = RuntimeConfig::default();
        let temp = tempfile::tempdir().unwrap();
        let runtime = DeviceRuntime::new_with_secrets(temp.path().to_path_buf(), config, std::sync::Arc::new(kotton_secret::MemorySecrets::new())).await.unwrap();

        let result = runtime.shutdown().await;
        assert!(result.is_err());
    }
}
