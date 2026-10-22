// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::service::{Event, EventReceiver, RecvError};
use std::sync::Arc;

/// Trait for external event subscribers
///
/// Subscribers receive events asynchronously and can perform
/// actions like logging to storage, syncing across network,
/// or forwarding to external systems (e.g., MCP).
#[async_trait::async_trait]
pub trait EventSubscriber: Send + Sync {
    /// Handle an incoming event
    ///
    /// Called for each published event. Should be non-blocking
    /// and handle errors internally (logging but not propagating).
    async fn on_event(&self, event: Arc<Event>);

    /// Optional: Get subscriber name for debugging
    fn name(&self) -> &str {
        "EventSubscriber"
    }
}

/// Helper to spawn a task that forwards events to a subscriber
pub fn spawn_subscriber_task(
    subscriber: Arc<dyn EventSubscriber>,
    mut receiver: EventReceiver,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match receiver.recv().await {
                Ok(event) => {
                    subscriber.on_event(event).await;
                }
                Err(RecvError::Lagged(n)) => {
                    eprintln!(
                        "WARN: Event subscriber '{}' lagged by {} events",
                        subscriber.name(),
                        n
                    );
                }
                Err(RecvError::Closed) => {
                    break;
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::{EventBus, EventCategory, EventLevel};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingSubscriber {
        count: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl EventSubscriber for CountingSubscriber {
        async fn on_event(&self, _event: Arc<Event>) {
            self.count.fetch_add(1, Ordering::SeqCst);
        }

        fn name(&self) -> &str {
            "CountingSubscriber"
        }
    }

    #[tokio::test]
    async fn test_subscriber_receives_events() {
        let bus = EventBus::new(100);
        let count = Arc::new(AtomicUsize::new(0));

        let subscriber = Arc::new(CountingSubscriber {
            count: count.clone(),
        });

        let receiver = bus.subscribe();
        let _task = spawn_subscriber_task(subscriber, receiver);

        // Publish some events
        bus.publish(Event::new(EventCategory::VFS, EventLevel::Info, "Event 1"))
            .unwrap();
        bus.publish(Event::new(EventCategory::Auth, EventLevel::Info, "Event 2"))
            .unwrap();
        bus.publish(Event::new(
            EventCategory::Network,
            EventLevel::Info,
            "Event 3",
        ))
        .unwrap();

        // Give the task time to process
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        assert_eq!(count.load(Ordering::SeqCst), 3);
    }
}
