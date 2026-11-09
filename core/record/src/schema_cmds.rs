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
use kotton_schemas::SchemaId;

use crate::provider::sqlite_record_store::SqliteRecordStore;
use crate::record_store::RecordStore as _;
use crate::registry::SchemaRegistry;

/// List the schema identities visible to `user_id`: core plus their own
/// registrations.
pub fn schema_list(reg: &SchemaRegistry, user_id: &str) -> Vec<String> {
    reg.list_for(user_id)
        .into_iter()
        .map(|def| def.id().to_string())
        .collect()
}

/// Register a published schema from its JSON definition, as `user_id`.
///
/// Deserializes `definition_json` into a `SchemaDefinition`, checks the publisher's
/// signature over it, and adds it to the in-memory registry with `user_id` as an owner.
/// The persistence that makes a registration survive a restart is
/// [`crate::daemon::records::register_and_persist`]'s.
///
/// ## The signature
///
/// A schema is named by the key that publishes it, and a definition whose signature does
/// not check against its publisher is no schema at all (the protocol's decision of that
/// title): `kotton_crypto::schema_signature::verify` holds it, before the migration below
/// touches the store. A definition with no signature is refused the same way. The core set is
/// never registered here — it is compiled in and admitted as core by the registry — so its
/// being unsigned before the first tag costs this path nothing.
///
/// ## Migration enforcement (M17a)
///
/// If a schema with the same identity is already registered, the revision is
/// compared.  When `new.revision > old.revision`, the **caller's** record store is
/// validated via [`RecordStore::migrate_table`] before the registry is updated
/// — ensuring no destructive or non-additive change sneaks through, and that a
/// registration never rewrites a store its principal does not own. A revision
/// downgrade is refused; re-registering the current revision is idempotent and
/// joins `user_id` to the schema's owners.
pub async fn schema_register(
    registry: &RwLock<SchemaRegistry>,
    store: &SqliteRecordStore,
    definition_json: &str,
    user_id: &str,
) -> Result<()> {
    let new_def: kotton_schemas::definition::SchemaDefinition =
        serde_json::from_str(definition_json).map_err(|e| anyhow!("invalid schema JSON: {e}"))?;
    let id = new_def
        .try_id()
        .map_err(|e| anyhow!("invalid schema definition: {e}"))?;

    // Refuse a core identity before touching anything. `SchemaRegistry::register`
    // already rejects one with `CoreConflict`, but it is the *last* step here — and
    // the migration below runs first, so a proposal naming a core schema at a
    // higher revision used to migrate every open store's table and only then be
    // refused. The registry stayed correct and the tables did not.
    //
    // A core schema changes by changing the files under `core/schemas/schemas/kotton/`,
    // which is a commit, not a request. Every other identity is untouched by this
    // check — a publisher defines schemas under its own key, with no approval and no
    // registry to petition, which is the whole point of naming a schema by the key
    // that publishes it.
    {
        let reg = registry.read().unwrap();
        if reg.is_core(&id) {
            return Err(anyhow!(
                "'{id}' is a core schema, shipped with this device and present on every \
                 one — it changes in Kotton's tree, not through registration. Publish your \
                 own schema under your own key instead.",
            ));
        }
    }

    // The publisher's word on the definition, before anything is migrated or kept.
    kotton_crypto::schema_signature::verify(&new_def)
        .map_err(|e| anyhow!("'{id}' is not signed by its publisher: {e}"))?;

    declare(registry, store, new_def, user_id).await
}

/// Admit a definition **this tree's own code declares**, as `user_id`: the revision rules
/// of [`schema_register`] without its signature check.
///
/// For a schema compiled into the daemon that is not in the core set, such as the importer's
/// ([`crate::import_cmds::imported_calendar_schema`]): it is Kotton's, carries no signature
/// before the first tag as the core set does not, and reaches the registry from code that
/// shipped with the device, which is the same ground the core set is admitted on. **Never for
/// a definition that arrived in a request**: that is [`schema_register`], and a request that
/// names Kotton's publisher without Kotton's signature is refused there.
pub async fn declare(
    registry: &RwLock<SchemaRegistry>,
    store: &SqliteRecordStore,
    new_def: kotton_schemas::definition::SchemaDefinition,
    user_id: &str,
) -> Result<()> {
    let id = new_def
        .try_id()
        .map_err(|e| anyhow!("invalid schema definition: {e}"))?;

    // Capture any previously registered definition for the same identity.
    let existing = {
        let reg = registry.read().unwrap();
        reg.get(&id).cloned()
    };

    if let Some(old_def) = &existing {
        if new_def.revision > old_def.revision {
            // Validate the migration against the caller's store before the
            // registry is updated. Only this store: rewriting another
            // principal's tables on the authority of a request that never named
            // them is the defect this function used to have.
            store
                .migrate_table(old_def, &new_def)
                .await
                .map_err(|e| anyhow!("schema migration rejected: {e}"))?;
        } else if new_def.revision < old_def.revision {
            return Err(anyhow!(
                "schema downgrade rejected: '{id}' is at revision {}, proposed revision {}",
                old_def.revision,
                new_def.revision,
            ));
        }
        // revision == old.revision falls through: registering the current revision
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
pub fn schema_get(reg: &SchemaRegistry, user_id: &str, id_str: &str) -> Result<String> {
    let id = SchemaId::parse(id_str).map_err(|e| anyhow!("'{id_str}' is not a schema identity: {e}"))?;
    let def = reg
        .get_for(user_id, &id)
        .ok_or_else(|| anyhow!("unknown schema: {id_str}"))?;
    serde_json::to_string_pretty(def).map_err(|e| anyhow!("serialize error: {e}"))
}
