// SPDX-License-Identifier: AGPL-3.0-or-later
//! Record and schema IPC handlers.
//!
//! These handlers call [`kotton_record`] directly and wrap the result into a
//! [`DeviceResponse`].
//!
//! *They went through a `record_cmds` wrapper in `05_runtime` until 2026-08-20
//! (RFC-0080 step 3).* Every one of its eight verbs did the same two things —
//! resolve this user's record store and the schema registry off the machine,
//! then call `record` — and **both of those are `record`'s own types.** A layer
//! whose entire content is fetching a domain's types out of a god-struct is the
//! god-struct's problem, not the domain's. The caller resolves them now.
//!
//! ## Grant enforcement (RFC-0003)
//!
//! When a request carries `app_id = Some(id)`, the handler checks the
//! `schema_grants` table before proceeding.  CLI / shell callers pass
//! `app_id = None` and receive unconditional access as the device owner.
//!
//! ## A schema kept from apps is the terminal's
//!
//! A schema kept from every app (`CoreSchema::is_kept_from_apps`: `secret` and `access-log`)
//! is refused to an app by the grant check whatever is stored. Naming no app does not make a
//! caller the person at their terminal: a remote client or an admitted browser names none.
//! So every record verb that names a schema is also handed the connection's origin, bound at
//! `Authenticate` from the credential and never the caller's to say, and a kept schema is
//! answered only at [`ConnTrustOrigin::Local`] ([`refuse_kept_off_terminal`]), before any
//! grant or row is read.
//!
//! ## Root enforcement (RFC-0071 R12, R17)
//!
//! Every record verb also takes the person's [`RootAccess`] and, where it names
//! one, a root. The grant check above says *which schemas an app may see*; the
//! root check says *which roots the person is in*, and it runs for every caller
//! — the shell and the CLI included, because membership is the person's and not
//! the app's. The two are independent and neither is widened by the other: an
//! app holding `schema.read` on calendar sees calendar rows in every root the
//! person is a member of, and no row from one they are not.

use kotton_grant::daemon::db::schema_grants_db;
use crate::roots::RootAccess;
use crate::{SchemaRegistry, SqliteRecordStore};
use std::sync::RwLock;
use sqlx::SqlitePool;
use std::io;
use std::sync::Arc;

use kotton_wire::ipc::{UserResponse, PERSONAL_ROOT};
use kotton_wire::ConnTrustOrigin;

// ── Record operations ─────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub async fn record_insert(
    schema_registry: &Arc<RwLock<SchemaRegistry>>,
    store: &Arc<SqliteRecordStore>,
    user_db: &Arc<SqlitePool>,
    access: &RootAccess,
    root: Option<String>,
    schema_nsid: String,
    record: serde_json::Value,
    app_id: Option<String>,
    origin: ConnTrustOrigin,
) -> io::Result<UserResponse> {
    if let Some(message) = refuse_kept_off_terminal(&schema_nsid, origin) {
        return Ok(UserResponse::Error { message });
    }
    // Compute body size before moving `record`.
    let body_bytes = serde_json::to_string(&record)
        .map(|s| s.len() as i64)
        .unwrap_or(0);

    // Grant + quota check when the caller identifies as a specific app.
    if let Some(ref aid) = app_id {
        if let Err(e) = schema_grants_db::check_write(user_db, aid, &schema_nsid, body_bytes).await
        {
            return Ok(UserResponse::Error {
                message: e.to_string(),
            });
        }
    }

    let root = match root_the_caller_may_name(root, &app_id) {
        Ok(root) => root,
        Err(message) => return Ok(UserResponse::Error { message }),
    };
    let verb = match crate::record_cmds::Record::new(schema_registry, store)
        .within(access, root.as_deref())
    {
        Ok(verb) => verb,
        Err(e) => {
            return Ok(UserResponse::Error {
                message: e.to_string(),
            })
        }
    };
    match verb.insert(&schema_nsid, record).await {
        Ok(record_id) => {
            // Update quota counters after a successful insert.
            if let Some(ref aid) = app_id {
                let _ =
                    schema_grants_db::increment_counters(user_db, aid, &schema_nsid, body_bytes)
                        .await;
            }
            Ok(UserResponse::RecordInserted { record_id })
        }
        Err(e) => Ok(UserResponse::Error {
            message: e.to_string(),
        }),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn record_query(
    schema_registry: &Arc<RwLock<SchemaRegistry>>,
    store: &Arc<SqliteRecordStore>,
    user_db: &Arc<SqlitePool>,
    access: &RootAccess,
    root: Option<String>,
    schema_nsid: String,
    field_eq: Vec<(String, serde_json::Value)>,
    limit: Option<usize>,
    offset: Option<usize>,
    app_id: Option<String>,
    origin: ConnTrustOrigin,
) -> io::Result<UserResponse> {
    if let Some(message) = refuse_kept_off_terminal(&schema_nsid, origin) {
        return Ok(UserResponse::Error { message });
    }
    if let Some(ref aid) = app_id {
        if let Err(e) = schema_grants_db::check_read(user_db, aid, &schema_nsid).await {
            return Ok(UserResponse::Error {
                message: e.to_string(),
            });
        }
    }

    let root = match root_the_caller_may_name(root, &app_id) {
        Ok(root) => root,
        Err(message) => return Ok(UserResponse::Error { message }),
    };
    let verb = match crate::record_cmds::Record::new(schema_registry, store)
        .within(access, root.as_deref())
    {
        Ok(verb) => verb,
        Err(e) => {
            return Ok(UserResponse::Error {
                message: e.to_string(),
            })
        }
    };
    match verb
        .query(
        &schema_nsid,
        field_eq,
        limit,
        offset,
        None,
    )
    .await
    {
        Ok(mut records) => {
            if app_id.is_some() {
                records.iter_mut().for_each(crate::record_cmds::withhold_from_apps);
            }
            Ok(UserResponse::RecordQueryResult { records })
        }
        // The per-user schema table is created lazily on the first insert.
        // A query before any inserts should return an empty result, not an error.
        Err(e) if e.to_string().contains("no such table") => {
            Ok(UserResponse::RecordQueryResult { records: vec![] })
        }
        Err(e) => Ok(UserResponse::Error {
            message: e.to_string(),
        }),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn record_delete(
    schema_registry: &Arc<RwLock<SchemaRegistry>>,
    store: &Arc<SqliteRecordStore>,
    user_db: &Arc<SqlitePool>,
    access: &RootAccess,
    root: Option<String>,
    schema_nsid: String,
    record_id: String,
    app_id: Option<String>,
    origin: ConnTrustOrigin,
) -> io::Result<UserResponse> {
    if let Some(message) = refuse_kept_off_terminal(&schema_nsid, origin) {
        return Ok(UserResponse::Error { message });
    }
    if let Some(ref aid) = app_id {
        if let Err(e) = schema_grants_db::check_write(user_db, aid, &schema_nsid, 0).await {
            return Ok(UserResponse::Error {
                message: e.to_string(),
            });
        }
    }

    let root = match root_the_caller_may_name(root, &app_id) {
        Ok(root) => root,
        Err(message) => return Ok(UserResponse::Error { message }),
    };
    let verb = match crate::record_cmds::Record::new(schema_registry, store)
        .within(access, root.as_deref())
    {
        Ok(verb) => verb,
        Err(e) => {
            return Ok(UserResponse::Error {
                message: e.to_string(),
            })
        }
    };
    match verb.delete(&schema_nsid, &record_id).await {
        Ok(()) => {
            // Decrement counters (0 body bytes — we don't store the original size).
            if let Some(ref aid) = app_id {
                let _ = schema_grants_db::decrement_counters(user_db, aid, &schema_nsid, 0).await;
            }
            Ok(UserResponse::RecordDeleted)
        }
        Err(e) => Ok(UserResponse::Error {
            message: e.to_string(),
        }),
    }
}

/// The refusal for a schema kept from apps (`CoreSchema::is_kept_from_apps`) asked for by a
/// connection that is not the person's own terminal on this device, or `None`.
///
/// Only [`ConnTrustOrigin::Local`] is the terminal: a client on this device's own socket. A
/// `Remote` session (a paired node `kquicd` minted one for, or a gateway) and a `Paired` one (a
/// browser admitted by ceremony) are refused whether or not they name an app, because naming
/// none is what the person's terminal does and is not evidence of being it. The origin is the
/// one `Authenticate` bound from the credential, so no request can claim it.
pub fn refuse_kept_off_terminal(nsid: &str, origin: ConnTrustOrigin) -> Option<String> {
    let kept = kotton_schemas::CoreSchema::kept_from_apps(nsid)?;
    (origin != ConnTrustOrigin::Local).then(|| kept.kept_off_terminal_refusal())
}

/// The root a request names, as its caller may name it: the word for Personal
/// is the person's, never an app's (kotton #38).
///
/// An app names no root: it cannot list them, so the only root it can name is
/// none, every root the person is in ([`withhold_root_ids`]). Were
/// [`PERSONAL_ROOT`] open to it, an app could ask for none and for the word and
/// take the difference, learning which rows are Personal's and that the person
/// is in some other root at all: one bit per row that the ruling below
/// withholds. So a request from an app that names the word is refused, in a
/// sentence, before any verb runs. A root named by its id is left to the
/// membership check, as it was.
fn root_the_caller_may_name(
    root: Option<String>,
    app_id: &Option<String>,
) -> Result<Option<String>, String> {
    match (&root, app_id) {
        (Some(word), Some(_)) if word == PERSONAL_ROOT => {
            Err(format!("an app names no root by the word `{PERSONAL_ROOT}`; name none"))
        }
        _ => Ok(root),
    }
}

/// A root's local id is the person's, and never an app's to hold (RFC-0071 R17).
///
/// The first design test, applied: a root id is random and never changes, so an
/// app that was handed it would hold a durable identifier of the person's
/// roots — the same value in every answer, on every day, that could leave with
/// anything the app sends and join one disclosure to another (Article VII).
/// An app has no use for it: it cannot list roots (that interface is the
/// occupant's alone), so the only root it can name is none — every root the
/// person is in — and not Personal by its word either
/// ([`root_the_caller_may_name`]). So a caller that identifies as an app gets
/// its rows without the key, and the shell and the CLI, which are the person,
/// keep it.
///
/// `_filed_at` goes with it, for a neighbouring reason: it is not an
/// identifier, but it is when this person's devices filed each row, which is
/// attention data an app has no use for and Article VII keeps on the person's
/// side. The person's own surfaces order a conversation by it
/// (`TASK-a-conversation-is-ordered-by-a-clock-it-does-not-hold`). And
/// `_updated_at`, when one of them last wrote the row, for the same reason; the
/// keychain tells two records under one label apart by it (kotton #483). A
/// query's answer takes all three out through one list
/// ([`crate::record_cmds::WITHHELD_FROM_APPS`]).
fn withhold_root_ids(records: &mut [serde_json::Value], key: &str) {
    for record in records {
        if let Some(obj) = record.as_object_mut() {
            obj.remove(key);
        }
    }
}

/// Search across schemas, in every root the person is a member of.
///
/// `app_id` does not gate the search — that is `RecordSearch`'s own
/// pre-existing shape — but it does withhold each row's root id from an app,
/// for the reason [`withhold_root_ids`] gives.
pub async fn record_search(
    schema_registry: &Arc<RwLock<SchemaRegistry>>,
    store: &Arc<SqliteRecordStore>,
    access: &RootAccess,
    nsid: Option<String>,
    text: Option<String>,
    limit: Option<u32>,
    app_id: Option<String>,
) -> io::Result<UserResponse> {
    let verb = match crate::record_cmds::Record::new(schema_registry, store).within(access, None) {
        Ok(verb) => verb,
        Err(e) => {
            return Ok(UserResponse::Error {
                message: e.to_string(),
            })
        }
    };
    match verb
        .search(nsid.as_deref(), text.as_deref(), limit)
        .await
    {
        Ok(mut records) => {
            if app_id.is_some() {
                withhold_root_ids(&mut records, "root");
            }
            Ok(UserResponse::RecordQueryResult { records })
        }
        Err(e) => Ok(UserResponse::Error {
            message: e.to_string(),
        }),
    }
}

// ── Schema management ─────────────────────────────────────────────────────────

pub async fn schema_list(
    schema_registry: &Arc<RwLock<SchemaRegistry>>,
    user_id: String,
) -> io::Result<UserResponse> {
    let schemas = crate::schema_cmds::schema_list(&schema_registry.read().unwrap(), &user_id);
    Ok(UserResponse::SchemaList { schemas })
}

pub async fn schema_register(
    schema_registry: &Arc<RwLock<SchemaRegistry>>,
    store: &Arc<SqliteRecordStore>,
    user_db: &Arc<SqlitePool>,
    user_id: String,
    definition_json: String,
    app_id: Option<String>,
) -> io::Result<UserResponse> {
    // When called by a specific app, require can_register on the target schema.
    if let Some(ref aid) = app_id {
        // Read the schema's identity out of the definition JSON to check the grant.
        let nsid = serde_json::from_str::<serde_json::Value>(&definition_json)
            .ok()
            .and_then(|v| {
                Some(format!("{}/{}", v["publisher"].as_str()?, v["name"].as_str()?))
            });

        match nsid {
            Some(ref nsid_str) => {
                if let Err(e) = schema_grants_db::check_register(user_db, aid, nsid_str).await {
                    return Ok(UserResponse::Error {
                        message: e.to_string(),
                    });
                }
            }
            None => {
                return Ok(UserResponse::Error {
                    message: "invalid schema definition: missing publisher or name".to_owned(),
                });
            }
        }
    }

    match register_and_persist(schema_registry, store, user_db, &definition_json, &user_id).await {
        Ok(()) => Ok(UserResponse::SchemaRegistered),
        Err(e) => Ok(UserResponse::Error {
            message: e.to_string(),
        }),
    }
}

/// Register a schema **and** make the registration survive a restart.
///
/// The two halves are one operation and this is the only place they are written
/// down. `schema_cmds::schema_register` applies the version rules to the
/// in-memory registry; that registry is rebuilt from the sealed core set at every
/// start, so a definition that is not also in `app_schemas` leaves the person's
/// records on disk and unreadable the next morning
/// (`TASK-custom-schemas-do-not-survive-a-restart`).
///
/// It is a function rather than a step each caller repeats because there are now
/// two callers — the `SchemaRegister` verb above and the importer, which declares
/// a shape of its own before writing under it. The importer carried its own copy
/// of the persistence half for one commit; two copies of one truth is how the
/// second one goes stale.
///
/// **What is persisted is what the registry accepted**, read back from the
/// registry rather than from the caller's JSON: the registry applied the version
/// rules, so it holds the definition actually in force, and writing the request's
/// copy would silently downgrade a row someone else had raised.
pub async fn register_and_persist(
    schema_registry: &Arc<RwLock<SchemaRegistry>>,
    store: &Arc<SqliteRecordStore>,
    user_db: &Arc<SqlitePool>,
    definition_json: &str,
    user_id: &str,
) -> anyhow::Result<()> {
    crate::schema_cmds::schema_register(schema_registry, store, definition_json, user_id).await?;
    let id = serde_json::from_str::<kotton_schemas::SchemaDefinition>(definition_json)
        .ok()
        .and_then(|def| def.try_id().ok());
    persist_registered(schema_registry, user_db, id).await
}

/// [`register_and_persist`] for a definition **this tree's own code declares** — the
/// importer's shape — through [`crate::schema_cmds::declare`], which applies the revision
/// rules and checks no signature, since a schema of Kotton's carries none before the first
/// tag and this definition never arrived in a request.
pub(crate) async fn declare_and_persist(
    schema_registry: &Arc<RwLock<SchemaRegistry>>,
    store: &Arc<SqliteRecordStore>,
    user_db: &Arc<SqlitePool>,
    def: kotton_schemas::SchemaDefinition,
    user_id: &str,
) -> anyhow::Result<()> {
    let id = def.try_id().ok();
    crate::schema_cmds::declare(schema_registry, store, def, user_id).await?;
    persist_registered(schema_registry, user_db, id).await
}

/// The persistence half: write the definition the registry holds for `id` to `app_schemas`.
async fn persist_registered(
    schema_registry: &Arc<RwLock<SchemaRegistry>>,
    user_db: &Arc<SqlitePool>,
    id: Option<kotton_schemas::SchemaId>,
) -> anyhow::Result<()> {
    let stored = {
        let reg = schema_registry.read().unwrap();
        id.and_then(|id| reg.get(&id).cloned())
    };
    if let Some(def) = stored {
        // A write failure must not answer "registered" — the caller would believe
        // a registration that dies at the next restart, which is the whole defect
        // this persistence closes.
        crate::daemon::db::app_schemas_db::upsert(user_db, &def)
            .await
            .map_err(|e| anyhow::anyhow!("schema registered in memory but not persisted: {e}"))?;
    }
    Ok(())
}

pub async fn schema_get(
    schema_registry: &Arc<RwLock<SchemaRegistry>>,
    user_id: String,
    nsid: String,
) -> io::Result<UserResponse> {
    match crate::schema_cmds::schema_get(&schema_registry.read().unwrap(), &user_id, &nsid) {
        Ok(definition_json) => Ok(UserResponse::SchemaGetResult { definition_json }),
        Err(_) => Ok(UserResponse::SchemaNotFound { nsid }),
    }
}

/// Open one record by URL, from any root the person is a member of and no other.
pub async fn record_open(
    schema_registry: &Arc<RwLock<SchemaRegistry>>,
    store: &Arc<SqliteRecordStore>,
    access: &RootAccess,
    url: String,
    origin: ConnTrustOrigin,
) -> io::Result<UserResponse> {
    // The URL names its schema, so a kept one is refused as a query of it is; a URL that does
    // not parse names none, and the verb refuses it below.
    if let Ok(parsed) = kotton_schemas::RecordUrl::parse(&url) {
        if let Some(message) = refuse_kept_off_terminal(&parsed.schema.to_string(), origin) {
            return Ok(UserResponse::Error { message });
        }
    }
    let verb = match crate::record_cmds::Record::new(schema_registry, store).within(access, None) {
        Ok(verb) => verb,
        Err(e) => {
            return Ok(UserResponse::Error {
                message: e.to_string(),
            })
        }
    };
    match verb.open(&url).await {
        Ok(Some((nsid, record))) => Ok(UserResponse::RecordOpenResult { record, nsid }),
        Ok(None) => Ok(UserResponse::RecordOpenNotFound { url }),
        Err(e) => Ok(UserResponse::Error {
            message: e.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The word for Personal is the person's to say. An app that says it is refused in a
    /// sentence; an app that names no root, or a root by its id, goes on to the membership
    /// check as before; the person may say the word.
    #[test]
    fn the_personal_word_is_refused_from_an_app_alone() {
        let app = Some("app.example".to_owned());
        let person = None;
        let word = || Some(PERSONAL_ROOT.to_owned());
        let id = || Some("0123456789abcdef0123456789abcdef".to_owned());

        let message = root_the_caller_may_name(word(), &app).expect_err("an app naming the word is refused");
        assert!(message.contains(PERSONAL_ROOT), "{message}");

        assert_eq!(root_the_caller_may_name(None, &app).unwrap(), None);
        assert_eq!(root_the_caller_may_name(id(), &app).unwrap(), id());
        assert_eq!(root_the_caller_may_name(word(), &person).unwrap(), word());
        assert_eq!(root_the_caller_may_name(None, &person).unwrap(), None);
    }
}
