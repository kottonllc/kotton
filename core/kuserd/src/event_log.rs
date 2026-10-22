// SPDX-License-Identifier: AGPL-3.0-or-later
//! SQLite-backed event log subscriber
//!
//! Persists events from the daemon's EventBus to a local SQLite database.
//! This is the storage layer that unblocks `Kotton events` CLI and
//! MCP `get_events` (both read directly from the DB once it exists).
//!
//! Schema lives in `core/device/migrations/0001_create_events.sql`. New schema changes
//! get a new numbered file; sqlx tracks which migrations have run.
//!
//! # HMAC integrity chain
//!
//! When constructed with [`SqliteEventLog::new_with_hmac_key`] each inserted
//! row carries a rolling HMAC-SHA256 tag:
//!
//! ```text
//! hmac_key = HKDF(master_secret, "kotton:hmac:events:v1")   // derived, never stored
//! prev_hmac = \x00 * 32 for the first event, else previous row's hmac
//! hmac = HMAC-SHA256(key=hmac_key, data=prev_hmac || id_bytes || payload_bytes)
//! ```
//!
//! Rows inserted without a key (cold-start events, before any user unlocks)
//! carry the zero sentinel `X''` and are skipped during verification.

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use kotton_diag::service::{Event, EventScope, EventSubscriber};
use sha2::Sha256;
use sqlx::SqlitePool;
use std::path::Path;
use std::sync::Arc;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// Persists events to SQLite.
///
/// Implements [`EventSubscriber`] so it can be registered with
/// [`kotton_diag::service::spawn_subscriber_task`].
pub struct SqliteEventLog {
    pool: SqlitePool,
    /// HMAC-SHA256 key for the rolling integrity chain.
    /// `None` when operating in cold-start mode (no active session).
    hmac_key: Option<[u8; 32]>,
    /// Whose log this is. Every subscriber sees every event on the device-wide
    /// bus, so this is what decides which ones it *writes* — the device log
    /// takes `Device` events, a user's log takes only their own. Without it,
    /// one bus plus several logs means every log holds everyone's events.
    owner: EventScope,
}

impl SqliteEventLog {
    /// Open (or create) the event log at `path` and run any pending migrations.
    ///
    /// Parent directories are created if they don't exist.
    /// Events written through this instance carry an empty HMAC sentinel
    /// (cold-start mode — no active session, no key material available).
    pub async fn new<P: AsRef<Path>>(path: P) -> Result<Self, sqlx::Error> {
        let pool = kotton_record::open_sqlite(path.as_ref()).await?;
        kotton_device::db::MIGRATOR.run(&pool).await.map_err(|e| {
            sqlx::Error::Io(std::io::Error::other(format!("migration failed: {e}")))
        })?;
        Ok(Self {
            pool,
            hmac_key: None,
            owner: EventScope::Device,
        })
    }

    /// Wrap an already-open (and already-migrated) pool — the per-user
    /// `agent.db`. Runs no migrations; the
    /// user pool's own migrator owns that schema.
    ///
    /// `owner` is whose events this log accepts; anything else on the bus is
    /// ignored. `hmac_key` should be derived as
    /// `derive_db_key(&master_secret, kdf_labels::HMAC_EVENTS)`; `Some` arms
    /// the rolling integrity chain, `None` writes the cold-start sentinel.
    pub fn from_pool(pool: SqlitePool, hmac_key: Option<[u8; 32]>, owner: EventScope) -> Self {
        Self {
            pool,
            hmac_key,
            owner,
        }
    }
}

/// Live per-user event-log subscriber tasks, keyed by `user_id`.
///
/// Tracked rather than detached, because each task owns a clone of that user's
/// `agent.db` pool. An untracked task holds the file open past logout and no
/// eviction path can reach it — it is in neither the pool cache nor the runtime
/// — which is exactly how the first attempt at this split ran aground on
/// Windows refusing to delete a directory with an open file in it.
pub type EventLogTasks =
    Arc<std::sync::Mutex<std::collections::HashMap<String, tokio::task::JoinHandle<()>>>>;

/// Stop a user's event-log task and release the pool handle it owns.
///
/// Must run **before** `user_db::evict` closes that pool: `abort()` only
/// *requests* cancellation, so the await is what makes the task — and its pool
/// clone — actually gone before anyone closes the pool underneath it. Skipping
/// the await turns an ordered shutdown back into the race this replaced.
pub async fn stop_user_log(tasks: &EventLogTasks, user_id: &str) {
    // The guard is dropped before the await: holding a std::sync::Mutex across
    // an await point is how this would deadlock the next logout.
    let handle = tasks.lock().unwrap().remove(user_id);
    if let Some(handle) = handle {
        handle.abort();
        let _ = handle.await;
    }
}

/// Open (or create) the machine-wide `system/agent.db` and run its
/// migrations. This is the one place the machine schema is versioned from;
/// the daemon opens the file exactly once through here.
pub use kotton_device::db::open_machine_db;

#[async_trait]
impl EventSubscriber for SqliteEventLog {
    async fn on_event(&self, event: Arc<Event>) {
        // The routing decision, and the only thing keeping one principal's
        // activity out of another's log. Every subscriber on the device-wide
        // bus is offered every event; this is where a log declines the ones
        // that are not its own.
        if !event.belongs_to(&self.owner) {
            return;
        }

        let id = Uuid::new_v4().to_string();

        // Use serde's lowercase names ("auth", "vfs", "storage", etc.)
        let category = serde_json::to_value(event.category)
            .ok()
            .and_then(|v| {
                if let serde_json::Value::String(s) = v {
                    Some(s)
                } else {
                    None
                }
            })
            .unwrap_or_else(|| format!("{:?}", event.category));

        let level = serde_json::to_value(event.level)
            .ok()
            .and_then(|v| {
                if let serde_json::Value::String(s) = v {
                    Some(s)
                } else {
                    None
                }
            })
            .unwrap_or_else(|| format!("{:?}", event.level));

        let payload = event.payload.as_ref().map(|p| p.to_string());

        let timestamp = event
            .timestamp
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // ISO 8601 timestamp for human-readable display in the inspector.
        let iso_timestamp = {
            use std::time::UNIX_EPOCH;
            let secs = event
                .timestamp
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let dt =
                ::chrono::DateTime::from_timestamp(secs as i64, 0).unwrap_or_else(chrono::Utc::now);
            dt.to_rfc3339()
        };

        // -- HMAC integrity chain -----------------------------------------------
        // When a key is available, compute:
        //   prev_hmac = last row's hmac (or 32 zero bytes for the first row)
        //   hmac = HMAC-SHA256(key, prev_hmac || id_bytes || payload_bytes)
        // Without a key, write the empty sentinel so cold-start rows are skipped.
        let hmac_bytes: Vec<u8> = if let Some(key) = &self.hmac_key {
            // Fetch the previous row's hmac (empty or 32-byte blob).
            let prev: Option<Vec<u8>> =
                sqlx::query_scalar("SELECT hmac FROM events ORDER BY rowid DESC LIMIT 1")
                    .fetch_optional(&self.pool)
                    .await
                    .ok()
                    .flatten();

            let prev_hmac: [u8; 32] = prev
                .as_deref()
                .filter(|b| b.len() == 32)
                .and_then(|b| b.try_into().ok())
                .unwrap_or([0u8; 32]);

            let payload_bytes = payload.as_deref().unwrap_or("").as_bytes();

            let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key is 32 bytes");
            mac.update(&prev_hmac);
            mac.update(id.as_bytes());
            mac.update(payload_bytes);
            mac.finalize().into_bytes().to_vec()
        } else {
            Vec::new() // sentinel: skipped during verification
        };

        let result = sqlx::query(
            "INSERT INTO events \
             (id, category, level, message, payload, timestamp, iso_timestamp, hmac) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&category)
        .bind(&level)
        .bind(&event.message)
        .bind(&payload)
        .bind(timestamp)
        .bind(&iso_timestamp)
        .bind(&hmac_bytes)
        .execute(&self.pool)
        .await;

        if let Err(e) = result {
            eprintln!("WARN [SqliteEventLog]: failed to persist event: {e}");
        }
    }

    fn name(&self) -> &str {
        "SqliteEventLog"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotton_diag::service::{spawn_subscriber_task, EventBus, EventCategory, EventLevel};
    use tempfile::tempdir;

    /// Rows currently in `log`, by optional category.
    async fn rows(log: &SqliteEventLog, category: Option<&str>) -> i64 {
        match category {
            Some(c) => {
                sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM events WHERE category = ?")
                    .bind(c)
            }
            None => sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM events"),
        }
        .fetch_one(&log.pool)
        .await
        .unwrap()
        .0
    }

    /// Wait until `log` holds `want` rows, or give up after a bounded wait.
    ///
    /// These tests used a fixed 50ms sleep, which is a bet that a spawned
    /// subscriber gets scheduled inside that window — a bet that gets worse
    /// every time the binary gains a test, and that duly started losing when
    /// this module gained one. Polling says what is actually being waited for,
    /// and a longer sleep would only have moved the threshold.
    async fn wait_for_rows(log: &SqliteEventLog, category: Option<&str>, want: i64) -> i64 {
        for _ in 0..500 {
            let n = rows(log, category).await;
            if n >= want {
                return n;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }
        rows(log, category).await
    }

    #[tokio::test]
    async fn test_event_log_persists_events() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("events.db");

        let log = Arc::new(SqliteEventLog::new(&db_path).await.unwrap());
        let bus = EventBus::new(64);
        let receiver = bus.subscribe();
        let _task = spawn_subscriber_task(log.clone(), receiver);

        bus.publish(kotton_diag::service::Event::new(
            EventCategory::Auth,
            EventLevel::Info,
            "User created: alice",
        ))
        .unwrap();

        assert_eq!(wait_for_rows(&log, Some("auth"), 1).await, 1);
    }

    /// One bus, several logs: each takes only its own principal's events.
    ///
    /// This is the regression pin for the defect that stalled the events split.
    /// The bus is device-wide, so before events carried a scope the daemon had
    /// no way to say whose event was whose and wrote *everyone's* into the first
    /// loaded user's database — sealed under that user's HMAC chain. A
    /// cross-principal write, in the change whose whole purpose is to end them.
    #[tokio::test]
    async fn a_users_events_never_land_in_another_users_log() {
        let dir = tempdir().unwrap();
        let bus = EventBus::new(64);

        async fn log_for(path: &std::path::Path, owner: EventScope) -> Arc<SqliteEventLog> {
            let pool = kotton_record::open_sqlite(path).await.unwrap();
            kotton_device::db::MIGRATOR.run(&pool).await.unwrap();
            Arc::new(SqliteEventLog::from_pool(pool, None, owner))
        }

        let alice = log_for(
            &dir.path().join("alice.db"),
            EventScope::User("alice".into()),
        )
        .await;
        let bob = log_for(&dir.path().join("bob.db"), EventScope::User("bob".into())).await;
        let device = log_for(&dir.path().join("device.db"), EventScope::Device).await;

        for l in [&alice, &bob, &device] {
            // Bound like its two neighbours in this file rather than dropped.
            // Not a correctness fix: the task is already running by the time this
            // returns, and dropping a JoinHandle detaches rather than cancels.
            // Clippy flags it only because JoinHandle implements Future.
            let _task = spawn_subscriber_task(l.clone(), bus.subscribe());
        }

        bus.publish(Event::for_user(
            "alice",
            EventCategory::VFS,
            EventLevel::Info,
            "alice wrote a file",
        ))
        .unwrap();
        // Unattributed: belongs to the machine, not to whoever is logged in.
        bus.publish(Event::new(
            EventCategory::Network,
            EventLevel::Info,
            "listener bound",
        ))
        .unwrap();

        // Wait for the two events that *should* land. Bob's emptiness is only
        // evidence once they have: asserting zero straight away would pass
        // before any subscriber had run at all, which is the same number for
        // the right reason and the wrong one.
        assert_eq!(
            wait_for_rows(&alice, None, 1).await,
            1,
            "alice keeps her own event"
        );
        assert_eq!(
            wait_for_rows(&device, None, 1).await,
            1,
            "the unattributed event belongs to the device log, and only there"
        );
        assert_eq!(
            rows(&bob, None).await,
            0,
            "bob's log must not hold alice's activity — this is the whole point"
        );
    }

    #[tokio::test]
    async fn test_event_log_storage_category() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("events.db");

        let log = Arc::new(SqliteEventLog::new(&db_path).await.unwrap());
        let bus = EventBus::new(64);
        let receiver = bus.subscribe();
        let _task = spawn_subscriber_task(log.clone(), receiver);

        bus.publish(kotton_diag::service::Event::new(
            EventCategory::Storage,
            EventLevel::Info,
            "Remote added: my-backup",
        ))
        .unwrap();

        assert_eq!(wait_for_rows(&log, Some("storage"), 1).await, 1);
    }
}
