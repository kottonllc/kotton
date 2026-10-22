// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `record` domain — schema-aware records, the schemas that describe them,
//! and the handlers that open them.
//!
//! Reached through [`KottonClient::record`], which binds the user once:
//!
//! ```no_run
//! # async fn example(client: &mut kotton::KottonClient) -> std::io::Result<()> {
//! let mut record = client.record("did:key:…");
//! let id = record.insert("app.kotton.note", serde_json::json!({ "title": "hi" })).await?;
//! let hits = record.search(None, Some("hi"), Some(10)).await?;
//! # Ok(())
//! # }
//! ```
//!
//! RFC-0055 folds the SDK's
//! separate `records` and `schema` modules into this one domain: a record and the
//! schema describing it are one capability, not two. The domain name is
//! RFC-0054's.

use std::io;

use serde_json::Value;

use super::{HandlerEntry, KottonClient, UserRequest, UserResponse};
pub use kotton_wire::ipc::ImportFormat;

/// The `record` domain, bound to one user.
///
/// Borrows the client, so it costs nothing to construct and cannot outlive the
/// connection it speaks over.
pub struct Record<'a> {
    client: &'a mut KottonClient,
    user_id: String,
}

impl KottonClient {
    /// Enter the `record` domain for a user.
    pub fn record(&mut self, user_id: &str) -> Record<'_> {
        Record {
            client: self,
            user_id: user_id.to_string(),
        }
    }
}

impl Record<'_> {
    /// Insert a record. See [`KottonClient::record_insert`].
    pub async fn insert(&mut self, schema_nsid: &str, record: Value) -> io::Result<String> {
        let u = self.user_id.clone();
        self.client.record_insert(&u, schema_nsid, record).await
    }

    /// Query records by exact-equality predicates. See [`KottonClient::record_query`].
    pub async fn query(
        &mut self,
        schema_nsid: &str,
        field_eq: Vec<(String, Value)>,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> io::Result<Vec<Value>> {
        let u = self.user_id.clone();
        self.client
            .record_query(&u, schema_nsid, field_eq, limit, offset)
            .await
    }

    /// Soft-delete a record. See [`KottonClient::record_delete`].
    pub async fn delete(&mut self, schema_nsid: &str, record_id: &str) -> io::Result<()> {
        let u = self.user_id.clone();
        self.client.record_delete(&u, schema_nsid, record_id).await
    }

    /// Search across schemas. See [`KottonClient::record_search`].
    pub async fn search(
        &mut self,
        nsid: Option<&str>,
        text: Option<&str>,
        limit: Option<u32>,
    ) -> io::Result<Vec<Value>> {
        let u = self.user_id.clone();
        self.client.record_search(&u, nsid, text, limit).await
    }

    /// Open one record by its `kotton://records/<nsid>/<id>` URL.
    /// See [`KottonClient::record_open`].
    pub async fn open(&mut self, url: &str) -> io::Result<Option<(String, Value)>> {
        let u = self.user_id.clone();
        self.client.record_open(&u, url).await
    }

    /// Read an export into this user's records. See [`KottonClient::import`].
    pub async fn import(
        &mut self,
        format: ImportFormat,
        source_name: &str,
        content: Vec<u8>,
    ) -> io::Result<(String, u32, u32)> {
        let u = self.user_id.clone();
        self.client.import(&u, format, source_name, content).await
    }

    // -- Schemas and handlers ------------------------------------------------

    /// List the schema NSIDs visible to this user. See [`KottonClient::schema_list`].
    pub async fn schema_list(&mut self) -> io::Result<Vec<String>> {
        let u = self.user_id.clone();
        self.client.schema_list(&u).await
    }

    /// Register a schema definition as this user. See [`KottonClient::schema_register`].
    pub async fn schema_register(&mut self, definition_json: &str) -> io::Result<()> {
        let u = self.user_id.clone();
        self.client.schema_register(&u, definition_json).await
    }

    /// Fetch one schema definition visible to this user. See [`KottonClient::schema_get`].
    pub async fn schema_get(&mut self, nsid: &str) -> io::Result<String> {
        let u = self.user_id.clone();
        self.client.schema_get(&u, nsid).await
    }

    /// Register an app as a handler for a schema. See [`KottonClient::handler_register`].
    pub async fn handler_register(&mut self, app_id: &str, nsid: &str) -> io::Result<()> {
        self.client.handler_register(app_id, nsid).await
    }

    /// Remove an app as a handler. See [`KottonClient::handler_unregister`].
    pub async fn handler_unregister(&mut self, app_id: &str, nsid: &str) -> io::Result<()> {
        self.client.handler_unregister(app_id, nsid).await
    }

    /// The handler that opens a schema. See [`KottonClient::handler_get_for`].
    pub async fn handler_get_for(&mut self, nsid: &str) -> io::Result<HandlerEntry> {
        self.client.handler_get_for(nsid).await
    }

    /// Every registered handler. See [`KottonClient::handler_list`].
    pub async fn handler_list(&mut self) -> io::Result<Vec<HandlerEntry>> {
        self.client.handler_list().await
    }

    /// Choose the default handler for a schema. See [`KottonClient::handler_set_default`].
    pub async fn handler_set_default(&mut self, app_id: &str, nsid: &str) -> io::Result<()> {
        self.client.handler_set_default(app_id, nsid).await
    }
}

impl KottonClient {
    // -- Schema-aware records (M16 v0.4) -------------------------------------

    /// Insert a JSON record into the schema table for `schema_nsid`.
    ///
    /// The `record` value should be a JSON object whose keys match the fields
    /// declared in the schema. If no `id` field is present one is generated.
    ///
    /// Returns the stable record ID (UUID v4).
    pub async fn record_insert(
        &mut self,
        user_id: &str,
        schema_nsid: &str,
        record: Value,
    ) -> io::Result<String> {
        let request = UserRequest::RecordInsert {
            user_id: user_id.to_owned(),
            schema_nsid: schema_nsid.to_owned(),
            record,
            root: None,
            app_id: None,
        };
        match self.client.send(&request).await? {
            UserResponse::RecordInserted { record_id } => Ok(record_id),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Query non-deleted records for `schema_nsid` matching `field_eq` predicates.
    ///
    /// `field_eq` is a list of `(field_name, expected_value)` exact-equality predicates.
    /// All predicates must match (AND semantics). An empty list returns all records.
    pub async fn record_query(
        &mut self,
        user_id: &str,
        schema_nsid: &str,
        field_eq: Vec<(String, Value)>,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> io::Result<Vec<Value>> {
        let request = UserRequest::RecordQuery {
            user_id: user_id.to_owned(),
            schema_nsid: schema_nsid.to_owned(),
            field_eq,
            limit,
            offset,
            root: None,
            app_id: None,
        };
        match self.client.send(&request).await? {
            UserResponse::RecordQueryResult { records } => Ok(records),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Soft-delete a record by writing a tombstone.
    ///
    /// The deletion propagates to paired devices via cr-sqlite sync.
    pub async fn record_delete(
        &mut self,
        user_id: &str,
        schema_nsid: &str,
        record_id: &str,
    ) -> io::Result<()> {
        let request = UserRequest::RecordDelete {
            user_id: user_id.to_owned(),
            schema_nsid: schema_nsid.to_owned(),
            record_id: record_id.to_owned(),
            root: None,
            app_id: None,
        };
        match self.client.send(&request).await? {
            UserResponse::RecordDeleted => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Cross-schema search for the hub feed and search bar.
    ///
    /// Returns enriched records `{id, schema_nsid, updated_at, body}` sorted by
    /// `updated_at` descending.  Pass `nsid = None` to query all schemas.
    pub async fn record_search(
        &mut self,
        user_id: &str,
        nsid: Option<&str>,
        text: Option<&str>,
        limit: Option<u32>,
    ) -> io::Result<Vec<Value>> {
        let request = UserRequest::RecordSearch {
            user_id: user_id.to_owned(),
            nsid: nsid.map(str::to_owned),
            text: text.map(str::to_owned),
            limit,
            app_id: None,
        };
        match self.client.send(&request).await? {
            UserResponse::RecordQueryResult { records } => Ok(records),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Open a single record by its `kotton://records/<nsid>/<id>` URL.
    ///
    /// Returns `Ok(Some((nsid, body)))` if the record exists, `Ok(None)` if
    /// it was not found.
    pub async fn record_open(
        &mut self,
        user_id: &str,
        url: &str,
    ) -> io::Result<Option<(String, Value)>> {
        let request = UserRequest::RecordOpen {
            user_id: user_id.to_owned(),
            url: url.to_owned(),
        };
        match self.client.send(&request).await? {
            UserResponse::RecordOpenResult { record, nsid } => Ok(Some((nsid, record))),
            UserResponse::RecordOpenNotFound { .. } => Ok(None),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    // -- Import (TASK-a-person-brings-their-history-with-them) ----------------

    /// Read an export the person brought with them into their own records.
    ///
    /// The caller has already read the file: the bytes travel, the path does
    /// not, and `source_name` is provenance the daemon reduces to a file name.
    /// Returns `(schema_nsid, imported, skipped)` — both counts, because only
    /// their sum matches the file.
    ///
    /// Local only. A remote session cannot reach this verb.
    pub async fn import(
        &mut self,
        user_id: &str,
        format: ImportFormat,
        source_name: &str,
        content: Vec<u8>,
    ) -> io::Result<(String, u32, u32)> {
        let request = UserRequest::Import {
            user_id: user_id.to_owned(),
            format,
            source_name: source_name.to_owned(),
            content,
        };
        match self.client.send(&request).await? {
            UserResponse::Imported {
                schema_nsid,
                imported,
                skipped,
            } => Ok((schema_nsid, imported, skipped)),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }
}
