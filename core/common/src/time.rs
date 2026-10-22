// SPDX-License-Identifier: AGPL-3.0-or-later
//! Wall-clock time, in one place.
//!
//! Kotton stamps unix seconds onto grants, sessions, KEL events, pack
//! manifests, and relay envelopes. Before this module, eighteen files defined
//! their own helper to get one, under three names (`now_secs`, `unix_now`,
//! `now_unix`) and five return types (`i64`, `u64`, `Option<u64>`,
//! `Result<i64, RendezvousError>`, `anyhow::Result<i64>`). Eleven of them lived
//! in `kuserd`.
//!
//! None was wrong. The cost was that "the current unix second" was not something
//! the codebase agreed on, so every new file wrote a nineteenth, and any change
//! to how time is read — a monotonic source, an injectable clock for tests, a
//! different epoch — had eighteen sites to find.
//!
//! It also blocked something concrete: testing that a session expires without
//! sleeping for the TTL needs a clock you can move, and there was no shared clock
//! to move.
//!
//! Tier 00, so every tier can reach it.

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the unix epoch.
///
/// Saturates to `0` rather than returning a `Result`, because the only way
/// `SystemTime::now()` precedes the epoch is a system clock set before 1970 —
/// on which every timestamp Kotton writes is already meaningless, and which no
/// caller can do anything useful about. The previous helpers agreed: all but one
/// swallowed the error with `unwrap_or_default()`, and this makes that shared
/// judgement explicit rather than repeated.
///
/// `i64` because these values are stored in SQLite `INTEGER` columns and compared
/// against expiry arithmetic that can legitimately go negative.
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Milliseconds since the unix epoch, for the few call sites that need finer
/// resolution than a second.
pub fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A weak assertion on purpose: this pins the epoch and the unit, which are
    /// the things a caller depends on, without pinning the clock itself.
    #[test]
    fn now_secs_is_unix_seconds() {
        // 2026-01-01 and 2100-01-01. Wide enough never to flake, narrow enough
        // to catch a millisecond/second mix-up or a non-unix epoch.
        let now = now_secs();
        assert!(
            (1_767_225_600..4_102_444_800).contains(&now),
            "now_secs() returned {now}, which is not plausible unix seconds"
        );
    }

    #[test]
    fn now_millis_is_a_thousand_times_now_secs() {
        let millis = now_millis();
        let secs = now_secs();
        assert!(
            (millis / 1000 - secs).abs() <= 1,
            "now_millis() and now_secs() disagree: {millis}ms vs {secs}s"
        );
    }
}
