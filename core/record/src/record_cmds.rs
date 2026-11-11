// SPDX-License-Identifier: AGPL-3.0-or-later
//! The record verbs of the `record` domain.
//!
//! Moved out of `05_runtime` (RFC-0060). Each function receives the registry it
//! reads and the one store it acts on, instead of a `DeviceRuntime` that also
//! holds the content key, the user registry, and every *other* user's self.store.
//! Passing the wrong user's records is no longer a mistake these functions can
//! make, because they never see a second one.
//!
//! The registry comes in behind its lock rather than as `&SchemaRegistry`. These
//! are async and a `std::sync` read guard cannot be held across an `await`, so
//! the lock has to be taken and released inside — the same reason
//! [`crate::schema_cmds::schema_register`] takes it that way.

use std::sync::RwLock;

use anyhow::{anyhow, Result};
use serde_json::Value;

use crate::record_store::{RecordFilter, RecordStore as _};
use crate::provider::sqlite_record_store::SqliteRecordStore;
use crate::registry::SchemaRegistry;
use kotton_schemas::SchemaId;

/// The `record` domain, bound to one user's registry and store.
///
/// These two travel together through every verb below, which is the test for
/// when a struct earns its place over parameters: the same state, in all five.
/// It is a narrower claim than it looks — the handle can reach one registry and
/// one store, so passing the wrong user's records is still not a mistake these
/// functions can make.
///
/// That is the distinction from a context object. `UserRuntime` holds the
/// content key, every store and every user; this holds two things it names.
/// Bounded, not ambient.
pub struct Record<'a> {
    registry: &'a RwLock<SchemaRegistry>,
    store: &'a SqliteRecordStore,
    /// Which roots this handle reads and deletes in, and where it writes
    /// (RFC-0071 R17). Personal alone unless [`within`](Self::within) said
    /// otherwise — so every caller that predates roots acts exactly where it
    /// always did.
    scope: Scope,
}

/// The roots a [`Record`] handle acts in, already checked against membership.
#[derive(Debug, Clone)]
struct Scope {
    /// What reads and deletes may reach.
    reads: crate::record_store::RootSelection,
    /// Where an insert lands, as stored: `None` is Personal. A refusal is kept
    /// rather than raised, so a handle built to read is not refused for a
    /// write it will never make.
    writes: std::result::Result<Option<String>, crate::roots::NotAMember>,
    /// How a stored root is named back to the caller — Personal's id for an
    /// unmarked row, where it is known.
    access: Option<crate::roots::RootAccess>,
}

impl<'a> Record<'a> {
    /// Bind the registry and store this domain acts on, in Personal.
    pub fn new(registry: &'a RwLock<SchemaRegistry>, store: &'a SqliteRecordStore) -> Self {
        Self {
            registry,
            store,
            scope: Scope {
                reads: crate::record_store::RootSelection::personal(),
                writes: Ok(None),
                access: None,
            },
        }
    }

    /// Act in `root` as `access` allows — every root the person is a member of
    /// for a read naming none, Personal for a write naming none (RFC-0071 R12,
    /// R17).
    ///
    /// **The membership check is here, once, before any verb runs.** A root
    /// the person is not a member of is refused whether it exists or not, and
    /// a handle that was refused is never built, so no verb below can be
    /// reached with a selection that includes one.
    pub fn within(
        mut self,
        access: &crate::roots::RootAccess,
        root: Option<&str>,
    ) -> Result<Self> {
        self.scope = Scope {
            reads: access.read(root)?,
            writes: access.write(root),
            access: Some(access.clone()),
        };
        Ok(self)
    }

    /// The root a row belongs to, as the caller is told it.
    fn root_of(&self, stored: Option<&str>) -> Option<String> {
        match &self.scope.access {
            Some(access) => access.label(stored),
            None => stored.map(str::to_owned),
        }
    }
}

impl Record<'_> {
/// Insert a JSON record into the named user's record self.store.
///
/// # Steps
///
/// 1. Parse and look up `schema_nsid` in the registry — error if unknown.
/// 2. Open (or reuse) the user's `SqliteRecordStore`.
/// 3. Refuse, naming it, a field the schema does not declare ([`undeclared_field`]).
/// 4. For `petname` alone, hold the body to its rules and to Personal ([`Self::hold_petname`]).
/// 5. Ensure the schema table exists (`create_table` is idempotent).
/// 6. Insert the record; for `petname`, remove any other naming the same key. Return its ID.
    pub async fn insert(
        &self,
    schema_nsid: &str,
    record: Value,
) -> Result<String> {
    let nsid = SchemaId::parse(schema_nsid)
        .map_err(|e| anyhow!("'{schema_nsid}' is not a schema identity: {e}"))?;

    // Look up the schema definition.
    let schema = {
        let reg = self.registry.read().unwrap();
        reg.get(&nsid)
            .ok_or_else(|| anyhow!("unknown schema: {schema_nsid}"))?
            .clone()
    };

    if let Some(field) = undeclared_field(&schema, &record) {
        return Err(anyhow!(
            "'{field}' is not a field of {schema_nsid}, so the record is not stored{}",
            if field.starts_with('_') {
                "; a field beginning with `_` is the daemon's, added to a query's answer, \
                 and is removed before a record is put back"
            } else {
                ""
            }
        ));
    }

    let petname = if nsid == SchemaId::from_static(kotton_common::namespace::NSID_PETNAME) {
        Some(self.hold_petname(&record)?)
    } else {
        None
    };

    self.store.create_table(&schema).await?;
    let record_id = self
        .store
        .insert_in(&nsid, self.scope.writes.clone()?, record)
        .await?;
    if let Some(key) = petname {
        self.replace_other_petnames(&nsid, &key, &record_id).await?;
    }
    Ok(record_id)
}

/// Hold a petname's body before it is written, for this one identity, by name (as
/// replication holds `access-log`): the rules of [`kotton_schemas::petname::check`], and
/// Personal alone, where the person's names for keys are kept. The refusal names the rule
/// broken and says no more of the body than the name. Returns the key it names.
fn hold_petname(&self, record: &Value) -> Result<kotton_schemas::Publisher> {
    let petname = kotton_schemas::petname::check(record)
        .map_err(|e| anyhow!("the petname is not stored: {e}"))?;
    if self.scope.writes.clone()?.is_some() {
        return Err(anyhow!("the petname is not stored: a petname is kept in Personal, and no other root"));
    }
    Ok(petname.key)
}

/// **One petname per key**: a petname written for a key already named replaces the one
/// before it. Every other live row of `petname` in Personal naming `key` is removed once the
/// new one is written, so the person changes a name by giving it again; a removal travels to
/// their other devices as any does. A row merged from another device before this one is read
/// by the reader's own rule until then (`kotton_schemas::Petnames::from_records`).
async fn replace_other_petnames(&self, nsid: &SchemaId, key: &kotton_schemas::Publisher, kept: &str) -> Result<()> {
    let personal = crate::record_store::RootSelection::personal();
    let filter = RecordFilter::new().eq("key", serde_json::json!(key.as_str())).roots(personal.clone());
    for row in self.store.query(nsid, filter).await? {
        if row.id != kept {
            self.store.delete_in(nsid, &row.id, &personal).await?;
        }
    }
    Ok(())
}

/// Query non-deleted records from the named user's record self.store.
///
/// # Steps
///
/// 1. Parse `schema_nsid` — error if syntactically invalid.
/// 2. Verify the schema is known.
/// 3. Open (or reuse) the user's record self.store.
/// 4. Run the query; return matching record bodies as JSON values.
    pub async fn query(
        &self,
    schema_nsid: &str,
    field_eq: Vec<(String, Value)>,
    limit: Option<usize>,
    offset: Option<usize>,
    before_id: Option<String>,
) -> Result<Vec<Value>> {
    let nsid = SchemaId::parse(schema_nsid)
        .map_err(|e| anyhow!("'{schema_nsid}' is not a schema identity: {e}"))?;

    // Verify schema is known.
    {
        let reg = self.registry.read().unwrap();
        if reg.get(&nsid).is_none() {
            return Err(anyhow!("unknown schema: {schema_nsid}"));
        }
    }

    let mut filter = RecordFilter::new();
    for (field, val) in field_eq {
        filter = filter.eq(field, val);
    }
    if let Some(l) = limit {
        filter = filter.limit(l);
    }
    if let Some(o) = offset {
        filter = filter.offset(o);
    }
    if let Some(bid) = before_id {
        filter = filter.before_id(bid);
    }
    let filter = filter.roots(self.scope.reads.clone());

    // One schema, one answer. A fork is not a subtype, so nothing widens this
    // query and nothing is appended to it (DEC-0027). Every row carries `_id`
    // because there is one branch producing rows, and `_root` — the root it
    // belongs to (RFC-0071 R17) — wherever that can be named.
    //
    // And `_filed_at`: when the person's device that first filed the row
    // filed it, on that device's clock (`Record::filed_at` — strictly ordered
    // per filing device, not across devices). Rows already come back ordered
    // by it; a caller merging two answers — the two directions of
    // a conversation — needs the key itself, because a body's own time is
    // whatever its author claimed
    // (`TASK-a-conversation-is-ordered-by-a-clock-it-does-not-hold`). It is the
    // store's fact about the owner's own copy, so it goes to whoever may read
    // the row and no further: the guest paths strip it with `_id` and `_root`.
    let records: Vec<Value> = self
        .store
        .query(&nsid, filter)
        .await?
        .into_iter()
        .map(|r| {
            let root = self.root_of(r.root.as_deref());
            let mut body = r.body;
            body["_id"] = serde_json::json!(r.id);
            body["_filed_at"] = serde_json::json!(r.filed_at);
            if let Some(root) = root {
                body["_root"] = serde_json::json!(root);
            }
            body
        })
        .collect();

    Ok(records)
}

/// Soft-delete a record (write tombstone).
///
/// # Steps
///
/// 1. Parse `schema_nsid`.
/// 2. Verify schema is known.
/// 3. Call `delete` on the user's record self.store.
    pub async fn delete(
        &self,
    schema_nsid: &str,
    record_id: &str,
) -> Result<()> {
    let nsid = SchemaId::parse(schema_nsid)
        .map_err(|e| anyhow!("'{schema_nsid}' is not a schema identity: {e}"))?;

    {
        let reg = self.registry.read().unwrap();
        if reg.get(&nsid).is_none() {
            return Err(anyhow!("unknown schema: {schema_nsid}"));
        }
    }

    self.store
        .delete_in(&nsid, &record_id.to_owned(), &self.scope.reads)
        .await?;
    Ok(())
}

/// Open a single record by its `kotton://records/<publisher>/<name>/<id>` URL.
///
/// Parses the URL, looks up the schema, then queries the user's record store
/// for the exact record ID.  Returns `Some((nsid_str, body))` if found, or
/// `None` if the schema is unknown or no row with that ID exists.
    pub async fn open(
        &self,
    url: &str,
) -> Result<Option<(String, Value)>> {
    let record_url =
        kotton_schemas::RecordUrl::parse(url).map_err(|e| anyhow!("invalid record URL: {e}"))?;

    let nsid_str = record_url.schema.to_string();

    let results = self.query(
        &nsid_str,
        vec![("id".to_owned(), serde_json::json!(record_url.id))],
        Some(1),
        None,
        None,
    )
    .await;

    match results {
        // Unknown schema or other runtime error → treat as not found.
        Err(_) => Ok(None),
        Ok(records) => Ok(records.into_iter().next().map(|body| (nsid_str, body))),
    }
}

/// Cross-schema search for the hub feed and search bar.
///
/// Queries all registered schemas (or just `nsid_filter` if provided) with an
/// optional case-insensitive body substring match, then merges and sorts the
/// results by `updated_at` descending.  Each returned `Value` is an envelope:
/// `{ "id", "schema_nsid", "updated_at", "body" }`.
///
/// **A schema kept from apps is never searched**
/// ([`kotton_schemas::CoreSchema::is_kept_from_apps`]: `secret`, `access-log` and
/// `petname`), on both branches: left out of every schema searched when none is named, and
/// answered with no rows when it is the one named, for every caller. Search is the hub's and the search bar's, and
/// a caller that names no app is not thereby the person at their terminal; the person reads
/// their keychain with the `secret` verbs, which ask for it by its schema.
    pub async fn search(
        &self,
    nsid_filter: Option<&str>,
    text_filter: Option<&str>,
    limit: Option<u32>,
) -> Result<Vec<Value>> {

    let nsids: Vec<SchemaId> = {
        let reg = self.registry.read().unwrap();
        if let Some(nsid_str) = nsid_filter {
            let nsid = SchemaId::parse(nsid_str)
                .map_err(|e| anyhow!("'{nsid_str}' is not a schema identity: {e}"))?;
            vec![nsid]
        } else {
            reg.list().into_iter().map(|def| def.id()).collect()
        }
    };
    let kept = |nsid: &str| kotton_schemas::CoreSchema::kept_from_apps(nsid).is_some();
    let nsids: Vec<SchemaId> = nsids.into_iter().filter(|nsid| !kept(&nsid.to_string())).collect();


    let mut all: Vec<Value> = Vec::new();
    for nsid in nsids {
        let mut filter = RecordFilter::new().roots(self.scope.reads.clone());
        if let Some(text) = text_filter {
            filter = filter.text(text);
        }
        if let Some(l) = limit {
            filter = filter.limit(l as usize);
        }
        // Ignore errors from tables that don't exist yet (no records inserted).
        if let Ok(records) = self.store.query(&nsid, filter).await {
            for r in records.into_iter().filter(|r| !kept(&r.schema_nsid)) {
                all.push(serde_json::json!({
                    "id": r.id,
                    "schema_nsid": r.schema_nsid,
                    "updated_at": r.updated_at,
                    "root": self.root_of(r.root.as_deref()),
                    "body": r.body,
                }));
            }
        }
    }

    // Sort across schemas by updated_at descending.
    all.sort_by(|a, b| {
        let ta = a["updated_at"].as_i64().unwrap_or(0);
        let tb = b["updated_at"].as_i64().unwrap_or(0);
        tb.cmp(&ta)
    });

    if let Some(l) = limit {
        all.truncate(l as usize);
    }

    Ok(all)
}
}

/// The first top-level field of `record` that an insert under `schema` refuses, if any: one
/// beginning with `_`, which is the daemon's (a query's answer adds `_id`, `_root` and
/// `_filed_at`), or one the schema does not declare. `id` is the store's, so it is allowed
/// whether the schema declares it or not. Only an insert asks this: replication's merge
/// carries rows another device already accepted, and a row already stored is left as it is.
fn undeclared_field<'r>(schema: &kotton_schemas::SchemaDefinition, record: &'r Value) -> Option<&'r str> {
    let body = record.as_object()?;
    body.keys().map(String::as_str).find(|name| {
        name.starts_with('_')
            || (*name != "id" && !schema.fields.iter().any(|f| f.name == *name))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotton_common::namespace::NSID_NOTES;
    use serde_json::json;

    fn a_device() -> (tempfile::TempDir, RwLock<SchemaRegistry>, SqliteRecordStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SqliteRecordStore::open(&dir.path().join("records.db"), None).expect("open");
        (dir, RwLock::new(SchemaRegistry::new()), store)
    }

    /// An insert refuses, naming it, a field beginning with `_` and a field the schema does not
    /// declare, and stores nothing; `id`, the store's, is taken whether declared or not.
    #[tokio::test]
    async fn an_insert_refuses_a_field_its_schema_does_not_declare() {
        let (_dir, registry, store) = a_device();
        let records = Record::new(&registry, &store);
        for (field, body) in [
            ("_root", json!({ "id": "n1", "title": "t", "_root": "a-root" })),
            ("_id", json!({ "title": "t", "_id": "n1" })),
            ("pinned", json!({ "title": "t", "pinned": true })),
        ] {
            let err = records.insert(NSID_NOTES, body).await.expect_err("an undeclared field");
            assert!(err.to_string().contains(&format!("'{field}'")), "{err}");
        }
        assert!(records.query(NSID_NOTES, vec![], None, None, None).await.unwrap().is_empty());

        let id = records.insert(NSID_NOTES, json!({ "id": "n1", "title": "t", "body": "b" })).await.unwrap();
        assert_eq!(id, "n1");
    }

    const ACME: &str = "did:key:z6MkeXBLjYiSvqnhFb6D7sHm8yKm4jV45wwBFRaatf1cfZ76";

    /// A petname is held to its rules at insert: each refusal names the rule broken, repeats
    /// no more of the body than the name, and stores nothing.
    #[tokio::test]
    async fn a_petname_is_held_to_its_rules_at_insert() {
        use kotton_common::namespace::{NSID_PETNAME, NSID_PREFIX};
        let (_dir, registry, store) = a_device();
        let records = Record::new(&registry, &store);
        for (said, body) in [
            ("not a did:key", json!({ "key": "did:web:hidden-host.example", "name": "Acme" })),
            ("is empty", json!({ "key": ACME, "name": "" })),
            ("at most 64 characters", json!({ "key": ACME, "name": "a".repeat(65) })),
            ("holds no `/`", json!({ "key": ACME, "name": "my/bank" })),
            ("no control", json!({ "key": ACME, "name": "bank\u{1b}[2K" })),
            ("no control", json!({ "key": ACME, "name": "\u{202E}knab" })),
            ("does not begin with `did:`", json!({ "key": ACME, "name": "did:key:z6Mk" })),
            ("`kotton` names Kotton's publisher", json!({ "key": ACME, "name": "kotton" })),
            ("`kotton` names Kotton's publisher", json!({ "key": ACME, "name": "Kotton " })),
            ("no control", json!({ "key": ACME, "name": "My\u{200B}Bank" })),
        ] {
            let err = records.insert(NSID_PETNAME, body).await.expect_err("a petname that breaks a rule").to_string();
            assert!(err.contains("the petname is not stored") && err.contains(said), "{said}: {err}");
            assert!(!err.contains("hidden-host") && !err.contains(ACME), "the refusal repeated the key: {err}");
        }
        assert!(records.query(NSID_PETNAME, vec![], None, None, None).await.unwrap().is_empty());
        records.insert(NSID_PETNAME, json!({ "key": NSID_PREFIX, "name": "kotton" })).await.expect("kotton is Kotton's");
    }

    /// **A second petname for a key already named replaces the first**: one record per key,
    /// so the person renames a key by naming it again; a petname for another key is kept.
    #[tokio::test]
    async fn a_second_petname_for_a_key_replaces_the_first() {
        use kotton_common::namespace::{NSID_PETNAME, NSID_PREFIX};
        let (_dir, registry, store) = a_device();
        let records = Record::new(&registry, &store);
        records.insert(NSID_PETNAME, json!({ "key": ACME, "name": "Acme" })).await.unwrap();
        records.insert(NSID_PETNAME, json!({ "key": NSID_PREFIX, "name": "Kotton LLC" })).await.unwrap();
        let second = records.insert(NSID_PETNAME, json!({ "key": ACME, "name": "My Bank" })).await.unwrap();
        let held = records.query(NSID_PETNAME, vec![], None, None, None).await.unwrap();
        assert_eq!(held.len(), 2, "{held:?}");
        let acme: Vec<&Value> = held.iter().filter(|r| r["key"] == ACME).collect();
        assert_eq!(acme.len(), 1, "{held:?}");
        assert_eq!((acme[0]["name"].as_str(), acme[0]["_id"].as_str()), (Some("My Bank"), Some(second.as_str())));
        let names = kotton_schemas::Petnames::from_records(&held);
        assert_eq!(names.name_for(&kotton_schemas::Publisher::from_static(ACME)), Some("My Bank"));
    }
}
