// SPDX-License-Identifier: AGPL-3.0-or-later
//! Read-only queries against the persisted event log.
//!
//! The write side lives in `crate::event_log::SqliteEventLog`.
//! These functions are used by the IPC `QueryEvents`, `VerifyEventLog`, and
//! `DaemonStatus` handlers.

use hmac::{Hmac, Mac};
use kotton_wire::ipc::EventEntry;
use sha2::Sha256;
use sqlx::SqlitePool;
use std::io;

type HmacSha256 = Hmac<Sha256>;

/// Query events from the log with optional filters.
///
/// - `category` — exact match on the `category` column.
/// - `min_level` — minimum severity ("trace" < "debug" < "info" < "warn" < "error").
/// - `since` — Unix-seconds cursor; only events with `timestamp > since` are returned.
/// - `limit` — maximum rows to return (capped to 500).
pub async fn query_events(
    db: &SqlitePool,
    category: Option<&str>,
    min_level: Option<&str>,
    since: Option<i64>,
    limit: u32,
) -> io::Result<Vec<EventEntry>> {
    let limit = limit.min(500) as i64;
    let since = since.unwrap_or(0);

    // Numeric level so we can do `>= min_level` comparisons in pure SQL.
    let min_level_num: i64 = match min_level.unwrap_or("trace") {
        "debug" => 1,
        "info" => 2,
        "warn" => 3,
        "error" => 4,
        _ => 0, // "trace" or unknown → include everything
    };

    let rows = sqlx::query_as::<_, EventRow>(
        r#"
        SELECT id, timestamp, iso_timestamp, level, category, message, payload
        FROM events
        WHERE
            timestamp > ?
            AND (? IS NULL OR category = ?)
            AND CASE level
                    WHEN 'trace' THEN 0
                    WHEN 'debug' THEN 1
                    WHEN 'info'  THEN 2
                    WHEN 'warn'  THEN 3
                    WHEN 'error' THEN 4
                    ELSE 0
                END >= ?
        ORDER BY timestamp ASC, rowid ASC
        LIMIT ?
        "#,
    )
    .bind(since)
    .bind(category)
    .bind(category)
    .bind(min_level_num)
    .bind(limit)
    .fetch_all(db)
    .await
    .map_err(|e| io::Error::other(format!("query_events failed: {e}")))?;

    Ok(rows.into_iter().map(EventEntry::from).collect())
}

// ── Internal row type ─────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct EventRow {
    id: String,
    timestamp: i64,
    iso_timestamp: Option<String>,
    level: String,
    category: String,
    message: String,
    payload: Option<String>,
}

impl From<EventRow> for EventEntry {
    fn from(r: EventRow) -> Self {
        Self {
            id: r.id,
            timestamp: r.timestamp,
            iso_timestamp: r.iso_timestamp,
            level: r.level,
            category: r.category,
            message: r.message,
            payload: r.payload,
        }
    }
}

// ── Daemon health queries ─────────────────────────────────────────────────────

/// Total number of events stored in the log.
pub(crate) async fn count_events(db: &SqlitePool) -> io::Result<u64> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
        .fetch_one(db)
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;
    Ok(count as u64)
}

/// Number of error-level events in the last 24 hours.
pub(crate) async fn count_recent_errors(db: &SqlitePool) -> io::Result<u64> {
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
        - 86_400;
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE level = 'error' AND timestamp >= ?")
            .bind(since)
            .fetch_one(db)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;
    Ok(count as u64)
}

/// Unix seconds of the most recent event. Returns `None` if the log is empty.
pub(crate) async fn last_event_timestamp(db: &SqlitePool) -> io::Result<Option<i64>> {
    let ts: Option<i64> = sqlx::query_scalar("SELECT MAX(timestamp) FROM events")
        .fetch_one(db)
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;
    Ok(ts)
}

// ── HMAC integrity chain ──────────────────────────────────────────────────────

/// Verify the rolling HMAC-SHA256 integrity chain of the event log.
///
/// Walks all rows in insertion order (rowid ASC). Rows with an empty `hmac`
/// blob (the cold-start sentinel) are skipped — they predate the chain.
///
/// Returns `(ok, first_broken_at)`:
/// - `ok = true` if every chained row's stored HMAC matches the recomputed value.
/// - `first_broken_at` is the Unix timestamp of the first broken row, if any.
pub async fn verify_event_log(
    db: &SqlitePool,
    hmac_key: &[u8; 32],
) -> io::Result<(bool, Option<u64>)> {
    #[derive(sqlx::FromRow)]
    struct ChainRow {
        id: String,
        payload: Option<String>,
        timestamp: i64,
        hmac: Vec<u8>,
    }

    let rows: Vec<ChainRow> =
        sqlx::query_as("SELECT id, payload, timestamp, hmac FROM events ORDER BY rowid ASC")
            .fetch_all(db)
            .await
            .map_err(|e| io::Error::other(format!("verify_event_log query failed: {e}")))?;

    let mut prev_hmac = [0u8; 32];

    for row in &rows {
        if row.hmac.is_empty() {
            // Cold-start sentinel — skip but do NOT reset prev_hmac.
            // The next chained row will use the prev_hmac from before the gap.
            continue;
        }

        let payload_bytes = row.payload.as_deref().unwrap_or("").as_bytes();

        let mut mac = HmacSha256::new_from_slice(hmac_key).expect("HMAC key is 32 bytes");
        mac.update(&prev_hmac);
        mac.update(row.id.as_bytes());
        mac.update(payload_bytes);
        let expected = mac.finalize().into_bytes();

        if row.hmac.as_slice() != expected.as_slice() {
            return Ok((false, Some(row.timestamp as u64)));
        }

        // Advance the chain.
        prev_hmac.copy_from_slice(&row.hmac);
    }

    Ok((true, None))
}
