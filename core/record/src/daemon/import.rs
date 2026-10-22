// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `Import` IPC handler, and the boundary that holds the reader.
//!
//! The same shape as [`crate::daemon::records`]: call the domain verb, wrap the
//! result in a [`UserResponse`]. It declares the importer's shape first, through
//! the same [`register_and_persist`] the `SchemaRegister` verb uses — registry
//! and `app_schemas` in one step, so a shape declared by an import is still
//! there after a restart and there is one description of what declaring means.
//!
//! ## Why the reader runs on a blocking thread
//!
//! Two reasons, and the second is the one that matters.
//!
//! It is **CPU-bound over a buffer the caller sized** — up to the CLI's 6 MiB —
//! with no `await` in it, which is what `spawn_blocking` is for; leaving it on
//! the runtime's worker stalls every other connection that worker is driving.
//!
//! And it is a **hand-written parser of bytes a stranger wrote**, which is the
//! one thing in this path that has aborted twice. `ics.rs` holds the property
//! that it does not panic, proven by a sweep over deformed input rather than by
//! a list of sites — but a property proven today is a property somebody can
//! break tomorrow, and the cost of breaking it must not be the person's
//! connection. On this side of the join, a panicking reader is a `JoinError`
//! with `is_panic()` set, and that is answered like any other failure: one
//! reply, on a connection that stays open.
//!
//! **This is by construction, not by a test.** There is no contrived panic to
//! assert against — the reader is the thing being guarded and it does not panic
//! — so the evidence is the arm below and `ics.rs`'s
//! `no_deformation_of_a_content_line_makes_the_reader_panic`. It is the same
//! posture every reader of caller bytes should be able to inherit;
//! `TASK-a-daemon-reader-of-caller-bytes-can-be-made-to-panic` carries the gate
//! that would require it rather than leaving it to whoever writes the next one.
//!
//! [`register_and_persist`]: crate::daemon::records::register_and_persist

use std::io;
use std::sync::{Arc, RwLock};

use sqlx::SqlitePool;

use kotton_wire::ipc::UserResponse;

use crate::{SchemaRegistry, SqliteRecordStore};

/// Read an `.ics` export into the person's records.
pub async fn import_ics(
    schema_registry: &Arc<RwLock<SchemaRegistry>>,
    store: &Arc<SqliteRecordStore>,
    user_db: &Arc<SqlitePool>,
    user_id: String,
    source_name: String,
    content: Vec<u8>,
) -> io::Result<UserResponse> {
    // Read first, and off this task. Nothing is written until the whole export
    // has been read, so a refusal here leaves the person's store untouched.
    let read = match tokio::task::spawn_blocking(move || crate::ics::read(&content)).await {
        Ok(Ok(read)) => read,
        // The reader said no: not UTF-8, so not an iCalendar stream.
        Ok(Err(e)) => {
            return Ok(UserResponse::Error {
                message: e.to_string(),
            })
        }
        Err(join) if join.is_panic() => {
            // The reader aborted. Nothing here re-raises it: the person gets a
            // sentence and keeps the connection, which is the whole point of
            // reading on a thread that is allowed to die.
            tracing::error!(
                user = %user_id,
                source = %source_name,
                "the .ics reader panicked; refusing the import and keeping the connection"
            );
            return Ok(UserResponse::Error {
                message: "the import could not be read".to_string(),
            });
        }
        Err(join) => {
            return Ok(UserResponse::Error {
                message: format!("the import could not be read: {join}"),
            })
        }
    };

    // Declare the shape before writing anything under it. Idempotent: the second
    // import of the day re-registers the same version, which joins the same owner
    // and changes nothing.
    let definition = match serde_json::to_string(&crate::import_cmds::imported_calendar_schema()) {
        Ok(json) => json,
        Err(e) => {
            return Ok(UserResponse::Error {
                message: format!("serialize the import shape: {e}"),
            })
        }
    };
    if let Err(e) = crate::daemon::records::register_and_persist(
        schema_registry,
        store,
        user_db,
        &definition,
        &user_id,
    )
    .await
    {
        return Ok(UserResponse::Error {
            message: e.to_string(),
        });
    }

    let imported_at = chrono::Utc::now().to_rfc3339();
    match crate::import_cmds::Import::new(schema_registry, store)
        .write_calendar(&read, &source_name, &imported_at)
        .await
    {
        Ok(outcome) => Ok(UserResponse::Imported {
            schema_nsid: outcome.schema_nsid,
            imported: outcome.imported as u32,
            skipped: outcome.skipped as u32,
        }),
        Err(e) => Ok(UserResponse::Error {
            message: e.to_string(),
        }),
    }
}
