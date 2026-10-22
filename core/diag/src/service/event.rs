// SPDX-License-Identifier: AGPL-3.0-or-later
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Event category for filtering and routing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventCategory {
    VFS,
    WASM,
    System,
    IPC,
    Sync,
    Auth,
    Network,
    Database,
    Storage,
}

/// Event severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

/// Whose activity an event describes — and therefore which log it belongs in.
///
/// This is what makes per-principal event logs possible (RFC-0063). Without it
/// the daemon has one bus and no way to say whose event is whose, which is how
/// the first attempt at the events split came to write *every* user's events
/// into the first loaded user's database, sealed under that user's HMAC chain.
///
/// **`Device` is the default because it is the fail-safe one.** An event that
/// should have been attributed to a user but was not loses its attribution and
/// lands in the device log, which no user's key chains. The opposite default —
/// picking some user — is precisely the cross-principal write this type exists
/// to prevent, so the two mistakes are not symmetric and the default follows
/// the one that cannot leak.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventScope {
    /// The device itself: boot, shutdown, transport, discovery, pairing.
    /// Belongs to the machine, not to anyone using it.
    #[default]
    Device,

    /// A named principal's activity, by `user_id`. Lands in that user's own log.
    User(String),
}

impl EventScope {
    /// The scope for work done on behalf of `user_id`, where the caller may or
    /// may not have one.
    ///
    /// Several handlers carry `Option<&str>` because the same verb serves both
    /// a logged-in principal and the device (an app launched by the shell before
    /// anyone logs in, say). This keeps that `None` reading as `Device` in one
    /// place, rather than at each call site where it could quietly become
    /// something else.
    pub fn of(user_id: Option<&str>) -> Self {
        user_id.map_or(EventScope::Device, |u| EventScope::User(u.to_string()))
    }
}

/// Core event structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Event category for filtering
    pub category: EventCategory,

    /// Severity level
    pub level: EventLevel,

    /// Human-readable message
    pub message: String,

    /// Optional structured payload (JSON)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,

    /// Event timestamp
    #[serde(with = "systemtime_as_secs")]
    pub timestamp: SystemTime,

    /// Whose activity this is. `#[serde(default)]` so a row written before the
    /// scope existed reads back as `Device` rather than failing to parse.
    #[serde(default)]
    pub scope: EventScope,
}

impl Event {
    /// Create a new device-scoped event.
    ///
    /// Use [`Event::for_user`] — or [`Event::in_scope`] — when the publishing
    /// site knows whose activity this is. Leaving it device-scoped is safe but
    /// loses the attribution, so the event will not reach that user's log.
    pub fn new(category: EventCategory, level: EventLevel, message: impl Into<String>) -> Self {
        Self {
            category,
            level,
            message: message.into(),
            payload: None,
            timestamp: SystemTime::now(),
            scope: EventScope::Device,
        }
    }

    /// Create event with payload (device-scoped; see [`Event::new`]).
    pub fn with_payload(
        category: EventCategory,
        level: EventLevel,
        message: impl Into<String>,
        payload: serde_json::Value,
    ) -> Self {
        Self {
            category,
            level,
            message: message.into(),
            payload: Some(payload),
            timestamp: SystemTime::now(),
            scope: EventScope::Device,
        }
    }

    /// Create an event attributed to `user_id`, so it reaches that principal's
    /// own log rather than the device's.
    pub fn for_user(
        user_id: impl Into<String>,
        category: EventCategory,
        level: EventLevel,
        message: impl Into<String>,
    ) -> Self {
        Self::new(category, level, message).in_scope(EventScope::User(user_id.into()))
    }

    /// Attribute this event to a scope — the builder form, for the sites that
    /// already construct with a payload.
    pub fn in_scope(mut self, scope: EventScope) -> Self {
        self.scope = scope;
        self
    }

    /// Check if event matches minimum level
    pub fn matches_level(&self, min_level: EventLevel) -> bool {
        self.level >= min_level
    }

    /// Check if event matches category
    pub fn matches_category(&self, category: EventCategory) -> bool {
        self.category == category
    }

    /// Whether this event belongs in the log owned by `owner`.
    ///
    /// The routing rule, in one place so the device log and every per-user log
    /// cannot drift apart: a log takes exactly the events whose scope is its
    /// own. An unattributed (device) event never lands in a user's log, and one
    /// user's events never land in another's.
    pub fn belongs_to(&self, owner: &EventScope) -> bool {
        &self.scope == owner
    }
}

// Custom serialization for SystemTime as seconds since UNIX_EPOCH
mod systemtime_as_secs {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::{SystemTime, UNIX_EPOCH};

    pub fn serialize<S>(time: &SystemTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let duration = time
            .duration_since(UNIX_EPOCH)
            .map_err(serde::ser::Error::custom)?;
        serializer.serialize_u64(duration.as_secs())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SystemTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(UNIX_EPOCH + std::time::Duration::from_secs(secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_creation() {
        let event = Event::new(EventCategory::VFS, EventLevel::Info, "File created");
        assert_eq!(event.category, EventCategory::VFS);
        assert_eq!(event.level, EventLevel::Info);
        assert_eq!(event.message, "File created");
        assert!(event.payload.is_none());
    }

    #[test]
    fn test_event_with_payload() {
        let payload = serde_json::json!({
            "path": "/test/file.txt",
            "size": 1024
        });
        let event = Event::with_payload(
            EventCategory::VFS,
            EventLevel::Debug,
            "File operation",
            payload.clone(),
        );
        assert_eq!(event.payload, Some(payload));
    }

    #[test]
    fn test_level_filtering() {
        let warn_event = Event::new(EventCategory::System, EventLevel::Warn, "Warning");
        let info_event = Event::new(EventCategory::System, EventLevel::Info, "Info");

        assert!(warn_event.matches_level(EventLevel::Info));
        assert!(warn_event.matches_level(EventLevel::Warn));
        assert!(!warn_event.matches_level(EventLevel::Error));

        assert!(info_event.matches_level(EventLevel::Info));
        assert!(!info_event.matches_level(EventLevel::Warn));
    }

    #[test]
    fn test_category_filtering() {
        let event = Event::new(EventCategory::Auth, EventLevel::Info, "Login");
        assert!(event.matches_category(EventCategory::Auth));
        assert!(!event.matches_category(EventCategory::VFS));
    }

    #[test]
    fn test_event_serialization() {
        let event = Event::new(
            EventCategory::Network,
            EventLevel::Error,
            "Connection failed",
        );
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: Event = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.category, event.category);
        assert_eq!(deserialized.level, event.level);
        assert_eq!(deserialized.message, event.message);
    }
}
