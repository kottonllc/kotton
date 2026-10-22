// SPDX-License-Identifier: AGPL-3.0-or-later
//! In-memory peer-address store with TTL eviction.
//!
//! Maps device fingerprints → (external socket address string, expiry instant).
//! Entries are inserted with a configurable TTL and evicted by a background task
//! that runs every 10 seconds. No persistence — if the coord server restarts,
//! devices re-push on their next sync attempt (devices push every `ttl / 2`).

use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, trace};

use crate::logid::tag;

/// A single address entry in the store.
#[derive(Clone, Debug)]
struct Entry {
    addr: String,
    turn_relay_addr: Option<String>,
    relayable: bool,
    expires_at: Instant,
}

/// Thread-safe, TTL-aware address store.
///
/// Clone-cheap: the inner map is `Arc`-wrapped.
#[derive(Clone, Debug)]
pub struct RendezvousStore {
    map: Arc<DashMap<String, Entry>>,
}

impl RendezvousStore {
    pub fn new() -> Self {
        Self {
            map: Arc::new(DashMap::new()),
        }
    }

    /// Insert or overwrite the entry for `fingerprint`.
    ///
    /// Returns the TTL (in seconds) that was applied.
    pub fn push(
        &self,
        fingerprint: &str,
        addr: String,
        turn_relay_addr: Option<String>,
        relayable: bool,
        ttl_secs: u32,
    ) -> u32 {
        let expires_at = Instant::now() + Duration::from_secs(u64::from(ttl_secs));
        self.map.insert(
            fingerprint.to_owned(),
            Entry {
                addr,
                turn_relay_addr,
                relayable,
                expires_at,
            },
        );
        debug!(device = %tag(fingerprint), ttl_secs, "relay push");
        ttl_secs
    }

    /// Look up the address for `fingerprint`.
    ///
    /// Returns `(addr, turn_relay_addr, relayable, remaining_secs)` if the entry
    /// is present and unexpired, or `None` if it is absent or expired.
    pub fn lookup(&self, fingerprint: &str) -> Option<(String, Option<String>, bool, u32)> {
        let entry = self.map.get(fingerprint)?;
        let now = Instant::now();
        if entry.expires_at <= now {
            drop(entry);
            self.map.remove(fingerprint);
            trace!(device = %tag(fingerprint), "relay lookup — expired inline");
            return None;
        }
        let remaining = entry.expires_at.duration_since(now).as_secs() as u32;
        let addr = entry.addr.clone();
        let turn_relay_addr = entry.turn_relay_addr.clone();
        let relayable = entry.relayable;
        trace!(device = %tag(fingerprint), %addr, remaining_secs = remaining, "relay lookup hit");
        Some((addr, turn_relay_addr, relayable, remaining))
    }

    /// Remove all entries whose TTL has elapsed.
    ///
    /// Called by the background eviction task.
    pub fn evict_expired(&self) {
        let now = Instant::now();
        let before = self.map.len();
        self.map.retain(|_, v| v.expires_at > now);
        let after = self.map.len();
        if before != after {
            debug!(
                evicted = before - after,
                remaining = after,
                "relay address store eviction"
            );
        }
    }

    /// Every fingerprint an entry is held under, for a test that reads what the
    /// relay holds.
    #[cfg(test)]
    pub fn fingerprints(&self) -> Vec<String> {
        self.map.iter().map(|e| e.key().clone()).collect()
    }

    /// Current number of live (possibly un-evicted-but-expired) entries.
    pub fn len(&self) -> usize {
        self.map.len()
    }
}

impl Default for RendezvousStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Spawn a background task that evicts expired entries every 10 seconds.
pub fn spawn_eviction_task(store: RendezvousStore) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let interval = Duration::from_secs(10);
        loop {
            tokio::time::sleep(interval).await;
            store.evict_expired();
        }
    })
}
