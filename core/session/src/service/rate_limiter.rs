// SPDX-License-Identifier: AGPL-3.0-or-later
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use thiserror::Error;

/// Rate limiter to prevent brute-force authentication attempts
pub struct RateLimiter {
    attempts: HashMap<String, Vec<SystemTime>>,
    max_attempts: usize,
    window_duration: Duration,
}

impl RateLimiter {
    /// Create a new rate limiter with default settings
    /// Default: 5 attempts per 15 minutes (900 seconds)
    pub fn new() -> Self {
        Self {
            attempts: HashMap::new(),
            max_attempts: 5,
            window_duration: Duration::from_secs(900),
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    /// Create a new rate limiter
    ///
    /// # Arguments
    /// * `max_attempts` - Maximum attempts allowed in the time window
    /// * `window_secs` - Time window in seconds
    ///
    /// # Example
    /// ```ignore
    /// use kotton_diag::RateLimiter;
    /// let limiter = RateLimiter::with_limits(5, 900); // 5 attempts per 15 minutes
    /// ```
    pub fn with_limits(max_attempts: usize, window_secs: u64) -> Self {
        Self {
            attempts: HashMap::new(),
            max_attempts,
            window_duration: Duration::from_secs(window_secs),
        }
    }

    /// Check if an attempt is allowed
    pub fn allow_attempt(&mut self, username: &str) -> bool {
        let now = SystemTime::now();
        let cutoff = now - self.window_duration;

        let attempts = self.attempts.entry(username.to_string()).or_default();

        // Remove old attempts outside window
        attempts.retain(|&time| time > cutoff);

        // Check if under limit
        attempts.len() < self.max_attempts
    }

    /// Record a failed attempt
    pub fn record_failure(&mut self, username: &str) {
        let now = SystemTime::now();
        let attempts = self.attempts.entry(username.to_string()).or_default();
        attempts.push(now);
    }

    /// Record a successful attempt (clears rate limit)
    pub fn record_success(&mut self, username: &str) {
        self.attempts.remove(username);
    }

    /// Check if username is rate limited
    ///
    /// Returns Ok(()) if request is allowed, Err if rate limited
    pub fn check(&mut self, username: &str) -> Result<(), RateLimitError> {
        let now = SystemTime::now();
        let cutoff = now - self.window_duration;

        // Get or create attempt history
        let attempts = self.attempts.entry(username.to_string()).or_default();

        // Remove old attempts outside window
        attempts.retain(|&time| time > cutoff);

        // Check if rate limited
        if attempts.len() >= self.max_attempts {
            let oldest_attempt = attempts[0];
            let retry_after = oldest_attempt + self.window_duration;
            let retry_after_secs = retry_after
                .duration_since(now)
                .unwrap_or(Duration::from_secs(0))
                .as_secs();

            return Err(RateLimitError::TooManyAttempts {
                retry_after_secs,
                max_attempts: self.max_attempts,
                window_secs: self.window_duration.as_secs(),
            });
        }

        // Record this attempt
        attempts.push(now);
        Ok(())
    }

    /// Clear rate limit for user (after successful login)
    pub fn clear(&mut self, username: &str) {
        self.attempts.remove(username);
    }

    /// Get remaining attempts for user
    pub fn remaining_attempts(&mut self, username: &str) -> usize {
        let now = SystemTime::now();
        let cutoff = now - self.window_duration;

        let attempts = self.attempts.entry(username.to_string()).or_default();

        // Clean up old attempts
        attempts.retain(|&time| time > cutoff);

        self.max_attempts.saturating_sub(attempts.len())
    }
}

#[derive(Debug, Error)]
pub enum RateLimitError {
    #[error("Too many failed login attempts ({max_attempts} in {window_secs} seconds). Try again in {retry_after_secs} seconds.")]
    TooManyAttempts {
        retry_after_secs: u64,
        max_attempts: usize,
        window_secs: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_rate_limiter_allows_under_limit() {
        let mut limiter = RateLimiter::with_limits(5, 60); // 5 attempts per minute

        // First 5 attempts should succeed
        for _ in 0..5 {
            assert!(limiter.allow_attempt("alice"));
            limiter.record_failure("alice"); // Record the attempt
        }
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let mut limiter = RateLimiter::with_limits(3, 60);

        // First 3 attempts succeed
        for _ in 0..3 {
            assert!(limiter.allow_attempt("bob"));
            limiter.record_failure("bob");
        }

        // 4th attempt fails
        assert!(!limiter.allow_attempt("bob"));
    }

    #[test]
    fn test_rate_limiter_clears_on_success() {
        let mut limiter = RateLimiter::with_limits(3, 60);

        // Make 2 failed attempts
        assert!(limiter.allow_attempt("charlie"));
        limiter.record_failure("charlie");
        assert!(limiter.allow_attempt("charlie"));
        limiter.record_failure("charlie");

        // Clear after success
        limiter.record_success("charlie");

        // Should have full quota again
        assert!(limiter.allow_attempt("charlie"));
    }

    #[test]
    fn test_rate_limiter_window_expires() {
        let mut limiter = RateLimiter::with_limits(2, 1); // 2 attempts per second

        // Use up quota
        assert!(limiter.allow_attempt("dave"));
        limiter.record_failure("dave");
        assert!(limiter.allow_attempt("dave"));
        limiter.record_failure("dave");
        assert!(!limiter.allow_attempt("dave"));

        // Wait for window to expire
        thread::sleep(Duration::from_secs(2));

        // Should be allowed again
        assert!(limiter.allow_attempt("dave"));
    }

    #[test]
    fn test_rate_limiter_per_user() {
        let mut limiter = RateLimiter::with_limits(2, 60);

        // Alice uses quota
        assert!(limiter.allow_attempt("alice"));
        limiter.record_failure("alice");
        assert!(limiter.allow_attempt("alice"));
        limiter.record_failure("alice");
        assert!(!limiter.allow_attempt("alice"));

        // Bob still has quota
        assert!(limiter.allow_attempt("bob"));
    }
}
