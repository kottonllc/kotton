// SPDX-License-Identifier: AGPL-3.0-or-later
//! **Where this device's access log goes** (kotton #450): kept on this device, or pinned to
//! `personal`.
//!
//! The protocol's *The first release is a platform a stranger can use from the command line*
//! keeps the access log on the device and puts it in a drive only if the person pins it there.
//! The pin is a setting of this device's own, kept in its own database (`access_log_pin`,
//! migration `0033`) as the pin settings are ([`super::pins`]): nothing of it replicates and no
//! drive holds it. `personal` is the only drive it names. No row is the log kept here, every
//! device's default, and a database that does not read is taken as no row ([`pin_for`]), so a
//! fault keeps the log here rather than sending it.
//!
//! **What it does.** Pinned, this device's rows of `access-log` ride the record log to
//! `personal` like any record, its rows from before the pin among them, on the next pass that
//! runs anyway (`kotton_record::replication::AccessLogPin`). Unpinned again, no new row
//! leaves this device; a row already logged stays in the drive, and in a snapshot of it, and
//! nothing is retracted, since a delete would be a new row of the log sent to the drive.
//!
//! **No verb sets it yet**: the `log` noun is its own issue. [`set`] is the handle, on the
//! device's own database, that the daemon and its tests use.

use kotton_record::replication::AccessLogPin;
use kotton_wire::ipc::FIRST_DRIVE_NAME;
use sqlx::SqlitePool;
use std::io;

fn err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

/// The drive this device's access log is pinned to for `user_id`, or `None` when it is kept
/// on this device.
pub async fn pinned(db: &SqlitePool, user_id: &str) -> io::Result<Option<String>> {
    sqlx::query_scalar::<_, String>("SELECT drive FROM access_log_pin WHERE user_id = ?")
        .bind(user_id)
        .fetch_optional(db)
        .await
        .map_err(err)
}

/// Pin this device's access log for `user_id` to `drive`, or with `None` keep it on this
/// device again. `personal` is the only drive a log is pinned to; another is refused and
/// nothing is written. Unpinning sends nothing and retracts nothing (module doc).
pub async fn set(db: &SqlitePool, user_id: &str, drive: Option<&str>) -> io::Result<()> {
    match drive {
        Some(drive) if drive != FIRST_DRIVE_NAME => Err(err(format!(
            "the access log is pinned to '{FIRST_DRIVE_NAME}' or kept on this device; '{drive}' is neither"
        ))),
        Some(drive) => {
            sqlx::query(
                "INSERT INTO access_log_pin (user_id, drive, set_at) VALUES (?, ?, ?) \
                 ON CONFLICT (user_id) DO UPDATE SET drive = excluded.drive, set_at = excluded.set_at",
            )
            .bind(user_id)
            .bind(drive)
            .bind(kotton_common::time::now_secs())
            .execute(db)
            .await
            .map_err(err)?;
            Ok(())
        }
        None => {
            sqlx::query("DELETE FROM access_log_pin WHERE user_id = ?")
                .bind(user_id)
                .execute(db)
                .await
                .map_err(err)?;
            Ok(())
        }
    }
}

/// What a pass of `mount` does with `user_id`'s access log on this device: pinned only for
/// the mount of `personal`, `local`, and only when this device's setting says `personal`.
/// Any other mount, no setting, and a setting that does not read all keep the log here.
pub async fn pin_for(db: &SqlitePool, user_id: &str, mount: &str) -> AccessLogPin {
    if mount != "local" {
        return AccessLogPin::Unpinned;
    }
    match pinned(db, user_id).await {
        Ok(Some(drive)) if drive == FIRST_DRIVE_NAME => AccessLogPin::Personal,
        Ok(_) => AccessLogPin::Unpinned,
        Err(e) => {
            tracing::warn!(user_id, error = %e, "the access log's pin does not read; it is kept on this device");
            AccessLogPin::Unpinned
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn machine_db() -> (tempfile::TempDir, SqlitePool) {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::open_machine_db(dir.path().join("agent.db")).await.unwrap();
        (dir, db)
    }

    /// Kept here by default; pinned to `personal` by the setting, for `personal`'s mount
    /// alone; kept here again when unpinned; and no other drive is a target.
    #[tokio::test]
    async fn the_log_is_kept_here_unless_pinned_to_personal_and_only_personal() {
        let (_dir, db) = machine_db().await;
        assert_eq!(pinned(&db, "alice").await.unwrap(), None);
        assert_eq!(pin_for(&db, "alice", "local").await, AccessLogPin::Unpinned);

        set(&db, "alice", Some(FIRST_DRIVE_NAME)).await.unwrap();
        assert_eq!(pinned(&db, "alice").await.unwrap().as_deref(), Some(FIRST_DRIVE_NAME));
        assert_eq!(pin_for(&db, "alice", "local").await, AccessLogPin::Personal);
        assert_eq!(pin_for(&db, "alice", "photos").await, AccessLogPin::Unpinned, "another mount");
        assert_eq!(pin_for(&db, "bob", "local").await, AccessLogPin::Unpinned, "the setting is alice's");

        let refused = set(&db, "alice", Some("photos")).await.unwrap_err();
        assert!(refused.to_string().contains("'photos' is neither"), "{refused}");
        assert_eq!(pin_for(&db, "alice", "local").await, AccessLogPin::Personal, "a refusal changed it");

        set(&db, "alice", None).await.unwrap();
        assert_eq!(pinned(&db, "alice").await.unwrap(), None);
        assert_eq!(pin_for(&db, "alice", "local").await, AccessLogPin::Unpinned);
    }
}
