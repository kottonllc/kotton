// SPDX-License-Identifier: AGPL-3.0-or-later
//! [`Immediate`]: a transaction that begins as the writer — the one form a
//! read-then-write on a shared SQLite file may take.
//!
//! **Why a read-then-write must begin as the writer.** Every pool here is WAL
//! with a busy timeout ([`crate::open_sqlite`]), and a file is shared: the
//! machine database is written by request handlers and by the device's event
//! log from its own task at once. sqlx's `begin()` issues a deferred `BEGIN`,
//! whose first read takes a snapshot; if another connection commits before the
//! transaction's first write, that write fails at once with SQLITE_BUSY
//! (`SQLITE_BUSY_SNAPSHOT`, "database is locked"), and the busy timeout does
//! not wait it out, because waiting cannot make a stale snapshot current.
//! `BEGIN IMMEDIATE` takes the write lock first, so the busy timeout waits for
//! the other writer and the transaction then reads and writes one current
//! state.
//!
//! **Why a guard, and not a raw `BEGIN IMMEDIATE`.** sqlx's own transactions
//! cannot say `IMMEDIATE` (0.8.0), and a raw `BEGIN` is invisible to the pool:
//! a connection dropped mid-transaction — a cancelled request, or an end
//! statement that failed — would return to the pool holding the lock, and
//! every write on the file would wait out the busy timeout and fail until that
//! connection was reaped. So a transaction that is not ended cleanly takes its
//! connection out of the pool (`detach`) and closes it, which rolls the
//! transaction back in SQLite, and the pool opens a fresh one (kotton #70).

use sqlx::SqlitePool;
use std::io;

/// A pooled connection inside a raw `BEGIN IMMEDIATE`, which never goes back
/// to the pool still inside it (module doc).
pub struct Immediate {
    conn: Option<sqlx::pool::PoolConnection<sqlx::Sqlite>>,
}

impl Immediate {
    /// Take a connection and the write lock, waiting out another writer for
    /// the pool's busy timeout.
    pub async fn begin(db: &SqlitePool) -> io::Result<Self> {
        let mut conn = db.acquire().await.map_err(io::Error::other)?;
        // A failed BEGIN opened nothing; the connection goes back as it came.
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await.map_err(io::Error::other)?;
        Ok(Self { conn: Some(conn) })
    }

    /// The connection, inside the transaction, for every statement in it.
    pub fn conn(&mut self) -> &mut sqlx::SqliteConnection {
        self.conn.as_mut().expect("a transaction holds its connection until it ends")
    }

    /// End with `COMMIT`.
    pub async fn commit(self) -> io::Result<()> {
        self.end("COMMIT").await
    }

    /// End with `statement`. On success the connection goes back to the pool,
    /// outside any transaction; on failure it is closed and never returns.
    pub async fn end(mut self, statement: &str) -> io::Result<()> {
        let mut conn = self.conn.take().expect("a transaction ends once");
        match sqlx::query(statement).execute(&mut *conn).await {
            Ok(_) => Ok(()),
            Err(e) => {
                use sqlx::Connection as _;
                let _ = conn.detach().close().await;
                Err(io::Error::other(e))
            }
        }
    }
}

impl Drop for Immediate {
    fn drop(&mut self) {
        // Not ended: dropped on a cancellation or an early return. Closing the
        // detached connection rolls back whatever it held.
        if let Some(conn) = self.conn.take() {
            drop(conn.detach());
        }
    }
}
