// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::service::Event;
use std::sync::Arc;
use tokio::sync::broadcast;

/// Receiver for events (wraps tokio broadcast::Receiver)
pub struct EventReceiver {
    inner: broadcast::Receiver<Arc<Event>>,
}

impl EventReceiver {
    /// Receive the next event
    pub async fn recv(&mut self) -> Result<Arc<Event>, RecvError> {
        self.inner.recv().await.map_err(|e| match e {
            broadcast::error::RecvError::Closed => RecvError::Closed,
            broadcast::error::RecvError::Lagged(n) => RecvError::Lagged(n),
        })
    }

    /// Try to receive an event without blocking
    pub fn try_recv(&mut self) -> Result<Arc<Event>, TryRecvError> {
        self.inner.try_recv().map_err(|e| match e {
            broadcast::error::TryRecvError::Empty => TryRecvError::Empty,
            broadcast::error::TryRecvError::Closed => TryRecvError::Closed,
            broadcast::error::TryRecvError::Lagged(n) => TryRecvError::Lagged(n),
        })
    }
}

/// Event bus for publish/subscribe event distribution
#[derive(Clone)]
pub struct EventBus {
    sender: broadcast::Sender<Arc<Event>>,
}

impl EventBus {
    /// Create a new event bus with specified capacity
    ///
    /// Capacity determines how many events can be buffered before
    /// slow subscribers start lagging.
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    /// Create a new event bus with default capacity (1024)
    pub fn with_default_capacity() -> Self {
        Self::new(1024)
    }

    /// Publish an event to all subscribers
    pub fn publish(&self, event: Event) -> Result<usize, PublishError> {
        let event = Arc::new(event);
        self.sender
            .send(event)
            .map_err(|_| PublishError::NoSubscribers)
    }

    /// Subscribe to all events
    pub fn subscribe(&self) -> EventReceiver {
        EventReceiver {
            inner: self.sender.subscribe(),
        }
    }

    /// Get the number of active subscribers
    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::with_default_capacity()
    }
}

/// Error publishing an event
#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    #[error("No subscribers")]
    NoSubscribers,
}

/// Error receiving an event
#[derive(Debug, thiserror::Error)]
pub enum RecvError {
    #[error("Event bus closed")]
    Closed,
    #[error("Receiver lagged by {0} events")]
    Lagged(u64),
}

/// Error trying to receive an event
#[derive(Debug, thiserror::Error)]
pub enum TryRecvError {
    #[error("No events available")]
    Empty,
    #[error("Event bus closed")]
    Closed,
    #[error("Receiver lagged by {0} events")]
    Lagged(u64),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::{EventCategory, EventLevel};

    #[tokio::test]
    async fn test_event_bus_creation() {
        let bus = EventBus::new(100);
        assert_eq!(bus.subscriber_count(), 0);
    }

    #[tokio::test]
    async fn test_subscribe() {
        let bus = EventBus::new(100);
        let _receiver = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 1);
    }

    #[tokio::test]
    async fn test_publish_no_subscribers() {
        let bus = EventBus::new(100);
        let event = Event::new(EventCategory::System, EventLevel::Info, "Test");

        // Publishing with no subscribers returns error
        let result = bus.publish(event);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_publish_and_receive() {
        let bus = EventBus::new(100);
        let mut receiver = bus.subscribe();

        let event = Event::new(EventCategory::VFS, EventLevel::Info, "File created");
        let subscribers = bus.publish(event.clone()).unwrap();
        assert_eq!(subscribers, 1);

        let received = receiver.recv().await.unwrap();
        assert_eq!(received.category, EventCategory::VFS);
        assert_eq!(received.message, "File created");
    }

    #[tokio::test]
    async fn test_multiple_subscribers() {
        let bus = EventBus::new(100);
        let mut receiver1 = bus.subscribe();
        let mut receiver2 = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 2);

        let event = Event::new(EventCategory::Auth, EventLevel::Warn, "Login failed");
        bus.publish(event.clone()).unwrap();

        let received1 = receiver1.recv().await.unwrap();
        let received2 = receiver2.recv().await.unwrap();

        assert_eq!(received1.message, "Login failed");
        assert_eq!(received2.message, "Login failed");
    }

    #[tokio::test]
    async fn test_try_recv_empty() {
        let bus = EventBus::new(100);
        let mut receiver = bus.subscribe();

        match receiver.try_recv() {
            Err(TryRecvError::Empty) => (),
            _ => panic!("Expected Empty error"),
        }
    }

    #[tokio::test]
    async fn test_try_recv_available() {
        let bus = EventBus::new(100);
        let mut receiver = bus.subscribe();

        bus.publish(Event::new(
            EventCategory::Network,
            EventLevel::Debug,
            "Connected",
        ))
        .unwrap();

        let event = receiver.try_recv().unwrap();
        assert_eq!(event.message, "Connected");
    }
}
