// SPDX-License-Identifier: AGPL-3.0-or-later
//! Time and clock abstraction
//!
//! This trait abstracts time operations to enable:
//! - Standard OS time
//! - Simulated time for testing
//! - Future bare-metal RTC support

use async_trait::async_trait;
use std::time::Duration;

/// Represents a point in time (Unix timestamp)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant {
    /// Seconds since Unix epoch
    pub secs: i64,
    /// Nanoseconds component
    pub nanos: u32,
}

impl Instant {
    /// Get duration since another instant
    pub fn duration_since(&self, earlier: Instant) -> Duration {
        let secs = self.secs.saturating_sub(earlier.secs) as u64;
        let nanos = if self.nanos >= earlier.nanos {
            self.nanos - earlier.nanos
        } else {
            1_000_000_000 + self.nanos - earlier.nanos
        };
        Duration::new(secs, nanos)
    }

    /// Add a duration to this instant
    pub fn add(&self, duration: Duration) -> Instant {
        let total_nanos = self.nanos as u64 + duration.subsec_nanos() as u64;
        let extra_secs = total_nanos / 1_000_000_000;
        let nanos = (total_nanos % 1_000_000_000) as u32;

        Instant {
            secs: self.secs + duration.as_secs() as i64 + extra_secs as i64,
            nanos,
        }
    }
}

/// Abstraction for time/clock operations
///
/// Implementations must handle:
/// - Getting current time
/// - Sleep operations
/// - Monotonic time for measurements
#[async_trait]
pub trait Clock: Send + Sync {
    /// Get the current time (wall clock)
    fn now(&self) -> Instant;

    /// Get a monotonic timestamp for measuring durations
    /// Not affected by system time changes
    fn monotonic(&self) -> Instant;

    /// Sleep for a duration (blocking current task)
    async fn sleep(&self, duration: Duration);
}
