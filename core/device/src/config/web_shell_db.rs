// SPDX-License-Identifier: AGPL-3.0-or-later
//! DB access for the `browser_devices` table: the browsers a user has admitted
//! by the six-digit ceremony, keyed by the device key each proved.
//!
//! A browser is paired like a device, not handed a bearer token: nothing issues,
//! stores, or validates a token, and `0022_drop_web_shell_credentials` drops the
//! `web_shell_credentials` table.

use super::db::db_err;
use sqlx::SqlitePool;
use std::io;

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Browser devices — the sealed channel's admitted keys
// ---------------------------------------------------------------------------
//
// Not bearer credentials: a bearer token is what the browser door must not
// use. A browser device is a public key a human admitted on this
// node's screen; the migration is `migrations_user/0009_browser_devices.sql`.

/// Admit `device_pub` for `user_id` under `name`. Returns the row id.
///
/// Fails if the name or the key is already registered for this user; callers
/// surface that rather than overwriting, because a second registration of the
/// same key under a new name is exactly what a stolen key would try.
pub async fn add_browser_device(
    db: &SqlitePool,
    user_id: &str,
    name: &str,
    device_pub: &[u8; 32],
) -> io::Result<String> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    sqlx::query(
        "INSERT INTO browser_devices (id, user_id, name, device_pub, created_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(user_id)
    .bind(name)
    .bind(&device_pub[..])
    .bind(now)
    .execute(db)
    .await
    .map_err(db_err)?;
    Ok(id)
}

/// Is `device_pub` admitted for `user_id`? On a hit, touch `last_used_at` and
/// return the row id — the credential id a `Principal::Browser` carries.
pub async fn find_browser_device(
    db: &SqlitePool,
    user_id: &str,
    device_pub: &[u8; 32],
) -> io::Result<Option<String>> {
    let id: Option<String> =
        sqlx::query_scalar("SELECT id FROM browser_devices WHERE user_id = ? AND device_pub = ?")
            .bind(user_id)
            .bind(&device_pub[..])
            .fetch_optional(db)
            .await
            .map_err(db_err)?;
    let Some(id) = id else {
        return Ok(None);
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    sqlx::query("UPDATE browser_devices SET last_used_at = ? WHERE id = ?")
        .bind(now)
        .bind(&id)
        .execute(db)
        .await
        .map_err(db_err)?;
    Ok(Some(id))
}

/// Every browser device admitted for `user_id`, oldest first.
pub async fn list_browser_devices(
    db: &SqlitePool,
    user_id: &str,
) -> io::Result<Vec<kotton_wire::ipc::types::BrowserDevice>> {
    let rows: Vec<(String, i64, Option<i64>)> = sqlx::query_as(
        "SELECT name, created_at, last_used_at FROM browser_devices \
         WHERE user_id = ? ORDER BY created_at ASC",
    )
    .bind(user_id)
    .fetch_all(db)
    .await
    .map_err(db_err)?;
    Ok(rows
        .into_iter()
        .map(
            |(name, created_at, last_used_at)| kotton_wire::ipc::types::BrowserDevice {
                name,
                created_at,
                last_used_at,
            },
        )
        .collect())
}

/// Forget the browser device `(user_id, name)`, returning the credential id
/// the row carried — the id every session its admission minted is bound to —
/// or `None` if no browser by that name was admitted. Its next visit is refused
/// at the signature check, before anything is sealed to it; ending the sessions
/// and channels it already holds is the caller's, which holds them.
pub async fn revoke_browser_device(
    db: &SqlitePool,
    user_id: &str,
    name: &str,
) -> io::Result<Option<String>> {
    // One statement, so the id read and the row removed are the same row: a
    // read then a delete could name a row a concurrent admission replaced.
    //
    // In its own transaction, committed before this returns. As an autocommit
    // statement its commit is its *next* step, which `fetch_optional` does not
    // wait for once it has the id: the revoke answered while the row was still
    // readable on every other connection, and when a read held the commit past
    // the busy timeout the delete was never committed at all, and a revoked
    // browser could still be listed after the revoke answered.
    // The row is what the signature check admits by, so "revoked" is said only
    // once it is gone for everyone; a commit that fails is this call's error.
    let mut tx = db.begin().await.map_err(db_err)?;
    let id = sqlx::query_scalar(
        "DELETE FROM browser_devices WHERE user_id = ? AND name = ? RETURNING id",
    )
    .bind(user_id)
    .bind(name)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode};
    use std::time::Duration;

    /// A file database with `browser_devices` in it, opened as `kuserd`'s
    /// `open_at` opens a person's: WAL. Named
    /// here because these tests are only worth anything in the mode production
    /// runs; `kuserd`'s `a_persons_database_runs_wal_so_a_held_read_holds_back_no_revoke`
    /// pins `open_at` itself to it. Under WAL a read keeps the snapshot it began
    /// with and holds back no commit; the one thing that holds back a delete is
    /// another writer, and it holds it back at the delete's first step.
    async fn pool_at(dir: &std::path::Path, busy: Duration) -> SqlitePool {
        let opts = SqliteConnectOptions::new()
            .filename(dir.join("agent.db"))
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(busy);
        let pool = SqlitePool::connect_with(opts).await.unwrap();
        sqlx::raw_sql(include_str!(
            "../../../kuserd/migrations_user/0009_browser_devices.sql"
        ))
        .execute(&pool)
        .await
        .unwrap();
        pool
    }

    async fn rows(conn: &mut sqlx::SqliteConnection) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM browser_devices")
            .fetch_one(conn)
            .await
            .unwrap()
    }

    /// Security — a revoked browser is never listed after the revoke answers:
    /// no read that starts after the revoke answers can see the row — the row
    /// the signature check admits by.
    ///
    /// Another connection holds a read open while the revoke runs, which is what
    /// a concurrent `list_browsers` or signature check is. Under WAL the revoke
    /// does not wait for it, and the held read keeps its snapshot, row and all,
    /// until it ends: that read began before the revoke and is ordered before it.
    /// Under the rollback journal the revoke waited for it instead, so no
    /// connection at all could read the row once it answered. That stronger
    /// property is the one that changed with the journal; nothing
    /// relied on it, since a read that ended a moment before the delete saw the
    /// same row under either journal.
    ///
    /// The explicit commit is still what this holds. Measured with it reverted
    /// to `fetch_optional` in autocommit: red in 4 of 10 runs, a read
    /// started after the answer seeing the row before the statement's next step
    /// committed it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn no_read_started_after_the_revoke_answers_sees_the_row() {
        let dir = tempfile::tempdir().unwrap();
        let pool = pool_at(dir.path(), Duration::from_secs(5)).await;
        let id = add_browser_device(&pool, "u", "phone", &[7; 32])
            .await
            .unwrap();

        let mut held = pool.acquire().await.unwrap();
        sqlx::query("BEGIN").execute(&mut *held).await.unwrap();
        assert_eq!(rows(&mut held).await, 1);

        let answer = tokio::time::timeout(
            Duration::from_secs(1),
            revoke_browser_device(&pool, "u", "phone"),
        )
        .await
        .expect("the revoke waited on a read another connection holds");
        assert_eq!(answer.unwrap(), Some(id));

        let mut after = pool.acquire().await.unwrap();
        assert_eq!(
            rows(&mut after).await,
            0,
            "a read started after the revoke answered still saw the row"
        );
        assert_eq!(
            rows(&mut held).await,
            1,
            "the read held from before the revoke keeps its snapshot"
        );
        sqlx::query("COMMIT").execute(&mut *held).await.unwrap();
        assert_eq!(
            rows(&mut held).await,
            0,
            "and once it ends, the row is gone for every connection"
        );
    }

    /// A delete held back past the busy timeout must not answer "revoked".
    /// Under WAL what holds it back is another writer, and it does so at the
    /// delete's first step, so the revoke fails before it has an id to answer.
    /// Under the rollback journal it was an open read, at the commit — after the
    /// id — the lost delete an explicit commit fixes. The commit stays: it is
    /// correct under either journal and does not depend on which one is open.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_revoke_whose_delete_cannot_commit_does_not_answer_revoked() {
        let dir = tempfile::tempdir().unwrap();
        let pool = pool_at(dir.path(), Duration::from_millis(100)).await;
        add_browser_device(&pool, "u", "phone", &[7; 32])
            .await
            .unwrap();

        let mut writer = pool.acquire().await.unwrap();
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *writer)
            .await
            .unwrap();

        let answer = revoke_browser_device(&pool, "u", "phone").await;
        // Past the busy timeout while the write is still open: if the delete
        // was going to be retried, it has been refused by now.
        tokio::time::sleep(Duration::from_millis(500)).await;
        sqlx::query("COMMIT").execute(&mut *writer).await.unwrap();
        let left = rows(&mut writer).await;

        assert!(
            !(matches!(answer, Ok(Some(_))) && left == 1),
            "the revoke answered {answer:?} and the row is still there"
        );
        let err = answer.expect_err("a delete that could not commit is reported");
        assert!(
            err.to_string().contains("database is locked"),
            "refused for the other writer's lock, not something else: {err}"
        );
        assert_eq!(
            left, 1,
            "and the browser is still admitted, as the error says"
        );
    }
}
