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
/// ## The form
///
/// The signature is over the 49-byte message `kotton_crypto::schema_signature` builds: its
/// tag, one zero byte, then the digest of the definition's canonical form. So the document
/// handed in must be the definition and nothing beside it: with `signature` and
/// `forked_from` set aside, its own canonical form is the parsed definition's, or it is
/// refused before the signature is looked at. A member the definition does not have, an
/// omitted `nullable`, or a `description` of `null` would otherwise share a digest and a
/// signature with the document they are not.
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

    // The document as it arrived is the one its digest is taken over, or it is refused. The
    // signature is over the parsed definition's canonical form, and parsing forgets: an
    // extra member, an omitted `nullable`, a `"description": null` all parse to a definition
    // whose canonical form is not the received document's, so a signature would vouch for a
    // document other than the one sent, and two documents would carry one version.
    received_is_canonical(definition_json, &new_def)
        .map_err(|e| anyhow!("'{id}' is not in the form its digest is taken over: {e}"))?;

    // The publisher's word on the definition, before anything is migrated or kept.
    kotton_crypto::schema_signature::verify(&new_def)
        .map_err(|e| anyhow!("'{id}' is not signed by its publisher: {e}"))?;

    declare(registry, store, new_def, user_id).await
}

/// Hold the received JSON to `def`, the definition it parsed to: the received object less
/// `signature` and `forked_from` (the members the digest is not over) must have the same
/// canonical form (RFC 8785) as `def`'s.
fn received_is_canonical(
    definition_json: &str,
    def: &kotton_schemas::definition::SchemaDefinition,
) -> std::result::Result<(), String> {
    let mut received: serde_json::Value =
        serde_json::from_str(definition_json).map_err(|e| e.to_string())?;
    let Some(members) = received.as_object_mut() else {
        return Err("the definition is not a JSON object".to_owned());
    };
    members.remove("signature");
    members.remove("forked_from");
    let received = kotton_schemas::canonical_json(&received).map_err(|e| e.to_string())?;
    let parsed = def.canonical().map_err(|e| e.to_string())?;
    if received == parsed {
        Ok(())
    } else {
        Err("the document received has a member the definition does not, or writes one \
             other than the definition does (an omitted `nullable`, a `null` for a member \
             that is absent); send the definition as it serialises"
            .to_owned())
    }
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
pub(crate) async fn declare(
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

#[cfg(test)]
mod tests {
    use super::*;
    use kotton_common::namespace as ns;
    use kotton_schemas::{FieldType, Publisher, SchemaDefinition, SchemaField, SchemaName};
    use serde_json::{json, Value};

    /// A registry and a store of the core set, in a directory the test holds.
    fn a_device() -> (tempfile::TempDir, RwLock<SchemaRegistry>, SqliteRecordStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SqliteRecordStore::open(&dir.path().join("records.db"), None).expect("open");
        (dir, RwLock::new(SchemaRegistry::new()), store)
    }

    /// A definition under a publisher of its own, with a nullable and a required field and a
    /// description: every member the received document can be held to.
    fn a_definition() -> SchemaDefinition {
        let publisher = Publisher::from_ed25519_public_key(&[0x42; 32]);
        SchemaDefinition::new(
            SchemaId::new(publisher, SchemaName::new("bookmark").unwrap()).unwrap(),
            1,
            vec![
                SchemaField::required("url", FieldType::String),
                SchemaField::nullable("title", FieldType::String),
            ],
        )
        .with_description("A bookmark.")
    }

    async fn register(doc: &Value) -> Result<()> {
        let (_dir, registry, store) = a_device();
        schema_register(&registry, &store, &doc.to_string(), "alice").await
    }

    async fn refused_for_its_form(doc: Value) {
        let err = register(&doc).await.expect_err("refused");
        assert!(err.to_string().contains("not in the form its digest is taken over"), "{err}");
    }

    #[tokio::test]
    async fn a_member_the_definition_does_not_have_is_refused() {
        let mut doc = serde_json::to_value(a_definition()).unwrap();
        doc["extra"] = json!("ignored by the parser, and so by the digest");
        refused_for_its_form(doc).await;
    }

    #[tokio::test]
    async fn a_member_a_field_does_not_have_is_refused() {
        let mut doc = serde_json::to_value(a_definition()).unwrap();
        doc["fields"][0]["note"] = json!("ignored by the parser");
        refused_for_its_form(doc).await;
    }

    #[tokio::test]
    async fn an_omitted_nullable_is_refused() {
        let mut doc = serde_json::to_value(a_definition()).unwrap();
        doc["fields"][0].as_object_mut().unwrap().remove("nullable");
        refused_for_its_form(doc).await;
    }

    #[tokio::test]
    async fn a_null_description_is_refused() {
        let mut def = a_definition();
        def.description = None;
        let mut doc = serde_json::to_value(&def).unwrap();
        doc["description"] = Value::Null;
        refused_for_its_form(doc).await;
    }

    /// The document as the definition serialises, its members in another order and with
    /// `signature` and `forked_from` beside it, is the form its digest is taken over: it
    /// passes this check and goes on to the signature's, which it fails, being signed by no
    /// key (a signed one is accepted end to end in the integration suite's
    /// `schema_management`).
    #[tokio::test]
    async fn the_canonical_equivalent_document_is_accepted() {
        let def = a_definition();
        let doc = json!({
            "signature": "AAAA",
            "forked_from": format!("{}/notes", ns::NSID_PREFIX),
            "description": "A bookmark.",
            "fields": [
                { "nullable": false, "type": "string", "name": "url" },
                { "type": "string", "name": "title", "nullable": true }
            ],
            "revision": 1,
            "name": "bookmark",
            "publisher": def.publisher.as_str(),
        });
        let parsed: SchemaDefinition = serde_json::from_str(&doc.to_string()).unwrap();
        received_is_canonical(&doc.to_string(), &parsed).expect("the canonical-equivalent document");
        let err = register(&doc).await.expect_err("signed by no key");
        assert!(err.to_string().contains("not signed by its publisher"), "{err}");
    }

    /// `secret` and `access-log` are held back from the registry until #449 and #450: a record
    /// put under either is refused as under an unknown schema, and a registration of either is
    /// refused as a core identity's, never admitted.
    #[tokio::test]
    async fn the_held_back_core_schemas_take_no_record_and_no_registration() {
        let (_dir, registry, store) = a_device();
        let err = crate::record_cmds::Record::new(&registry, &store)
            .insert(ns::NSID_SECRET, json!({ "label": "bank", "value": "hunter2", "kind": "password" }))
            .await
            .expect_err("no record under a held-back schema");
        assert!(err.to_string().contains("unknown schema"), "{err}");

        for held_back in [kotton_schemas::CoreSchema::Secret, kotton_schemas::CoreSchema::AccessLog] {
            let err = schema_register(&registry, &store, held_back.file(), "alice")
                .await
                .expect_err("a core identity is not registered");
            assert!(err.to_string().contains("core schema"), "{err}");
            assert!(registry.read().unwrap().get(&held_back.id()).is_none());
        }
    }
}
