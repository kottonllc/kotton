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
use kotton_schemas::nsid::Nsid;

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
/// 3. Ensure the schema table exists (`create_table` is idempotent).
/// 4. Insert the record; return its stable ID.
    pub async fn insert(
        &self,
    schema_nsid: &str,
    record: Value,
) -> Result<String> {
    let nsid =
        Nsid::new(schema_nsid).map_err(|e| anyhow!("invalid schema NSID '{schema_nsid}': {e}"))?;

    // Look up the schema definition.
    let schema = {
        let reg = self.registry.read().unwrap();
        reg.get(&nsid)
            .ok_or_else(|| anyhow!("unknown schema: {schema_nsid}"))?
            .clone()
    };

    self.store.create_table(&schema).await?;
    let record_id = self
        .store
        .insert_in(&nsid, self.scope.writes.clone()?, record)
        .await?;
    Ok(record_id)
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
    let nsid =
        Nsid::new(schema_nsid).map_err(|e| anyhow!("invalid schema NSID '{schema_nsid}': {e}"))?;

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
    let nsid =
        Nsid::new(schema_nsid).map_err(|e| anyhow!("invalid schema NSID '{schema_nsid}': {e}"))?;

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

/// Open a single record by its `kotton://records/<nsid>/<id>` URL.
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

    let nsid_str = record_url.nsid.as_str().to_owned();

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
    pub async fn search(
        &self,
    nsid_filter: Option<&str>,
    text_filter: Option<&str>,
    limit: Option<u32>,
) -> Result<Vec<Value>> {

    let nsids: Vec<Nsid> = {
        let reg = self.registry.read().unwrap();
        if let Some(nsid_str) = nsid_filter {
            let nsid = Nsid::new(nsid_str)
                .map_err(|e| anyhow!("invalid schema NSID '{nsid_str}': {e}"))?;
            vec![nsid]
        } else {
            reg.list().into_iter().map(|def| def.nsid.clone()).collect()
        }
    };


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
            for r in records {
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
