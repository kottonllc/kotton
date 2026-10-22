// SPDX-License-Identifier: AGPL-3.0-or-later
//! Database access layer for the daemon.
//!
//! Instead of inlining `sqlx::query(...)` calls directly in handlers, all SQL
//! lives here.  Each sub-module owns one logical concern (network pairing,
//! handler registry, device config) and exposes typed async functions.
//!
//! Handlers receive `&Arc<SqlitePool>`, call functions in this module, and
//! pattern-match the typed results — they never write SQL themselves.

// `device_config_db` is `kotton_device::config::db` — the machine's own
// configuration storage, not the daemon's.
pub mod event_log_db;
pub mod extension_registry_db;
pub mod user_db;

/// Tests for the network tables, which live in `peer` but migrate from here.
#[cfg(test)]
mod network_db_tests;

/// Map a `sqlx` error to `io::Error`.
///
/// Lives here because **eight** of the modules below use it. In
/// `app_registry_db`, `extension_registry_db` would reach into the app domain
/// for an error mapper — and follow it into another crate. A shared utility parked in one
/// domain's module is a dependency waiting to be mistaken for a real one.
pub(crate) fn db_err(e: sqlx::Error) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// How long [`close_pool`] waits for connections still out before it says so and
/// returns. A holder has to be stuck, not slow, to reach it: a pass that is mid-query
/// finishes in milliseconds.
const POOL_DRAIN_LIMIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Close `pool` and return only once **every connection it opened is closed**.
///
/// `SqlitePool::close` alone does not promise that on the version in the tree.
/// sqlx-core 0.8.0's `close()` closes each idle connection through a guard that
/// gives back a semaphore permit `release()` already gave back when the connection
/// went idle, so once it has closed any idle connection its final
/// `acquire(max_connections)` succeeds around a connection that is still checked
/// out — and returns. Measured: after `DeviceDaemon::shutdown`'s evictions the
/// per-user pool still held one or two connections in 337 of 600, and five cores of
/// a suite run that aborted at exit had one of them inside SQLCipher's calls into
/// libcrypto after `exit()` had run libcrypto's `OPENSSL_cleanup`.
///
/// A second face of the same loop: a connection returning from a task aborted
/// mid-query checks `is_closed()` before `close()` runs, waits on a ping queued behind
/// its statement, and is pushed onto the idle queue after `close()` has popped it for
/// the last time. It is then idle in a closed pool, and nothing will ever close it.
/// So this calls `close()` again on each pass, because each call pops and closes whatever
/// is idle by then. Waiting for `size()` alone, in a loaded `just test` the machine
/// pool keeps one such connection until the drain limit.
///
/// `size()` is the measure that holds: a connection leaves it only when its guard
/// drops, after its worker has acknowledged the close — that is, after
/// `sqlite3_close` has returned on that worker's thread. sqlx has no event for it,
/// so this polls. Delete the loop when sqlx's `close()` closes everything it counts.
pub(crate) async fn close_pool(pool: &sqlx::SqlitePool) {
    let deadline = std::time::Instant::now() + POOL_DRAIN_LIMIT;
    loop {
        // Bounded like the rest: `close()` itself waits for permits a stuck holder
        // may never give back.
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        let _ = tokio::time::timeout(left, pool.close()).await;
        if pool.size() == 0 {
            return;
        }
        if std::time::Instant::now() >= deadline {
            tracing::warn!(
                open = pool.size(),
                "a closed pool still has connections out after {POOL_DRAIN_LIMIT:?}; \
                 their worker threads may outlive this shutdown"
            );
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}
