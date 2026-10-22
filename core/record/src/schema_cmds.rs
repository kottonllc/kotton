// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `schema` verbs of the `record` domain.
//!
//! Moved out of `05_runtime` (RFC-0060). Each function receives exactly what it
//! uses — a registry, a user, and for registration the one store a migration
//! must be validated against — rather than a `DeviceRuntime` that also holds the
//! content key, the user registry and every other user's data.
//!
//! The verbs here are **principal-scoped**: they act as the named user, on that
//! user's store, and answer with that user's view of the registry. The registry
//! itself is still one per process (the interim position recorded in
//! `IDEA-schema-registry-is-machine-wide`; RFC-0063 is the
//! shape that retires it), which is why the scoping lives in these functions
//! rather than falling out of the process boundary.
//!
//! `schema_register` takes the registry behind its lock rather than `&mut`,
//! because it reads, awaits a migration against the store, and only then
//! writes. A `&mut` held across that await would serialise the daemon.

use std::sync::RwLock;

use anyhow::{anyhow, Result};
use kotton_schemas::nsid::Nsid;

use crate::provider::sqlite_record_store::SqliteRecordStore;
use crate::record_store::RecordStore as _;
use crate::registry::SchemaRegistry;

/// List the schema NSIDs visible to `user_id`: core plus their own
/// registrations.
pub fn schema_list(reg: &SchemaRegistry, user_id: &str) -> Vec<String> {
    reg.list_for(user_id)
        .into_iter()
        .map(|def| def.nsid.as_str().to_owned())
        .collect()
}

/// Register an app-supplied schema from its JSON definition, as `user_id`.
///
/// Deserializes `definition_json` into a `SchemaDefinition` and adds it to the
/// in-memory registry with `user_id` as an owner. Registrations do not survive
/// a daemon restart — see the persistence note on [`crate::registry`].
///
/// ## Migration enforcement (M17a)
///
/// If a schema with the same NSID is already registered, the version field is
/// compared.  When `new.version > old.version`, the **caller's** record store is
/// validated via [`RecordStore::migrate_table`] before the registry is updated
/// — ensuring no destructive or non-additive change sneaks through, and that a
/// registration never rewrites a store its principal does not own. A version
/// downgrade is refused; re-registering the current version is idempotent and
/// joins `user_id` to the schema's owners.
pub async fn schema_register(
    registry: &RwLock<SchemaRegistry>,
    store: &SqliteRecordStore,
    definition_json: &str,
    user_id: &str,
) -> Result<()> {

    let new_def: kotton_schemas::definition::SchemaDefinition =
        serde_json::from_str(definition_json).map_err(|e| anyhow!("invalid schema JSON: {e}"))?;

    // Refuse a core NSID before touching anything. `SchemaRegistry::register`
    // already rejects `sh.kotton.*` with `CoreConflict`, but it is the *last*
    // step here — and the migration below runs first, so a proposal naming a core
    // schema at a higher version used to migrate every open store's table and
    // only then be refused. The registry stayed correct and the tables did not.
    //
    // Article IX seals this namespace: core schemas change by changing
    // `kotton_schemas::core`, which is a commit, not a request. Everything
    // outside `sh.kotton.*` is untouched by this check — an app defines schemas
    // under a namespace it already controls, with no approval and no registry to
    // petition, which is the whole point of reverse-domain NSIDs.
    {
        let reg = registry.read().unwrap();
        if reg.is_core(&new_def.nsid) {
            return Err(anyhow!(
                "'{}' is a core schema, sealed by Article IX — it changes through \
                 the Constitution's ratification process, not through registration. \
                 Extend it instead, under your own namespace.",
                new_def.nsid.as_str(),
            ));
        }
    }

    // Capture any previously registered definition for the same NSID.
    let existing = {
        let reg = registry.read().unwrap();
        reg.get(&new_def.nsid).cloned()
    };

    if let Some(old_def) = &existing {
        if new_def.version > old_def.version {
            // Validate the migration against the caller's store before the
            // registry is updated. Only this store: rewriting another
            // principal's tables on the authority of a request that never named
            // them is the defect this function used to have.
            store
                .migrate_table(old_def, &new_def)
                .await
                .map_err(|e| anyhow!("schema migration rejected: {e}"))?;
        } else if new_def.version < old_def.version {
            return Err(anyhow!(
                "schema downgrade rejected: '{}' is at version {}, proposed version {}",
                new_def.nsid.as_str(),
                old_def.version,
                new_def.version,
            ));
        }
        // version == old.version falls through: registering the current version
        // again is idempotent, and must still reach the registry so a second
        // user joins the owner set.
    }

    let mut reg = registry.write().unwrap();
    reg.register(new_def, user_id)
        .map_err(|e| anyhow!("schema registration failed: {e}"))?;
    Ok(())
}

/// Retrieve the full JSON definition of a schema visible to `user_id`.
///
/// Returns a pretty-printed JSON string containing the [`SchemaDefinition`].
/// Another user's registration answers "unknown schema", indistinguishable from
/// the schema not existing — the accessor discloses nothing either way.
pub fn schema_get(reg: &SchemaRegistry, user_id: &str, nsid_str: &str) -> Result<String> {
    let nsid = Nsid::new(nsid_str).map_err(|e| anyhow!("invalid NSID '{nsid_str}': {e}"))?;
    let def = reg
        .get_for(user_id, &nsid)
        .ok_or_else(|| anyhow!("unknown schema: {nsid_str}"))?;
    serde_json::to_string_pretty(def).map_err(|e| anyhow!("serialize error: {e}"))
}
