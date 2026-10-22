// SPDX-License-Identifier: AGPL-3.0-or-later
//! The project's records in a root an org owns (RFC-0088, phase one).
//!
//! ```no_run
//! # async fn example(client: &mut kotton::KottonClient) -> std::io::Result<()> {
//! let org = client.org_new("alice", "kotton").await?;
//! let made = client.org_root_create("alice", &org, "kotton").await?;
//! let report = kotton::records_import(client, "alice", &made.root, "records".as_ref()).await?;
//! kotton::records_export(client, "alice", &made.root, "/tmp/records".as_ref()).await?;
//! # let _ = report;
//! # Ok(())
//! # }
//! ```
//!
//! **Import and export read and write rows as [`PRINCIPAL`], never as the person.** Each asks
//! the daemon with that app id, so each is refused unless the person granted the principal
//! `schema.read` and `schema.write` on [`NSID`] — the grant rule 6 asks be readable, and
//! `kotton schema` shows it. This is the converter declaring its reach, not a confinement of
//! it: the CLI is the person's own tool on the person's own connection, and a caller that
//! named no app would be answered as the person. What the grant buys is a reach a person can
//! read and revoke, which is the same thing it buys every other app.
//!
//! **A file is the wire format** (rule 2): [`kotton_record_file::row`] maps each file to its row
//! and back byte for byte, and import writes a row only when it differs from the one the root
//! holds, so importing the same directory twice changes nothing.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use kotton_record_file::row::{self, NSID};
use kotton_record_file::schema::PRINCIPAL;
use serde_json::Value;

use super::{KottonClient, UserRequest, UserResponse};
pub use kotton_wire::ipc::OrgRootDelegation;

/// What `OrgRootCreate` made.
#[derive(Debug, Clone)]
pub struct OrgRoot {
    /// The root's id.
    pub root: String,
    /// Its owner — the org.
    pub owner: String,
    /// How `org.invite` on it reached the person.
    pub delegation: OrgRootDelegation,
}

/// What an import did, row by row.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImportReport {
    /// Rows the root did not hold.
    pub inserted: usize,
    /// Rows the root held with different content, replaced by name.
    pub replaced: usize,
    /// Rows the root held already exactly — not written.
    pub unchanged: usize,
}

/// How many rows one page of an export or a comparison asks for.
const PAGE: usize = 200;

impl KottonClient {
    /// Create a root owned by `org_did`, with this person as its first member, and have the
    /// org delegate `org.invite` on it to them.
    pub async fn org_root_create(&mut self, user_id: &str, org_did: &str, name: &str) -> io::Result<OrgRoot> {
        match self
            .client
            .send(&UserRequest::OrgRootCreate {
                user_id: user_id.to_owned(),
                org_did: org_did.to_owned(),
                name: name.to_owned(),
            })
            .await?
        {
            UserResponse::OrgRootCreated { root, owner, delegation } => Ok(OrgRoot { root, owner, delegation }),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Admit `member` to `root` under this person's `org.invite` on it. Returns whether they
    /// were newly added, and the membership grant's JSON.
    pub async fn org_root_invite(&mut self, user_id: &str, root: &str, member: &str) -> io::Result<(bool, String)> {
        match self
            .client
            .send(&UserRequest::OrgRootInvite {
                user_id: user_id.to_owned(),
                root: root.to_owned(),
                member: member.to_owned(),
            })
            .await?
        {
            UserResponse::OrgRootInvited { added, grant_json, .. } => Ok((added, grant_json)),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Insert (or replace, by `record["id"]`) a record in `root`, as `app_id` where one is
    /// named — so under that app's schema grant.
    pub async fn record_insert_in(
        &mut self,
        user_id: &str,
        root: Option<&str>,
        app_id: Option<&str>,
        schema_nsid: &str,
        record: Value,
    ) -> io::Result<String> {
        match self
            .client
            .send(&UserRequest::RecordInsert {
                user_id: user_id.to_owned(),
                schema_nsid: schema_nsid.to_owned(),
                record,
                root: root.map(str::to_owned),
                app_id: app_id.map(str::to_owned),
            })
            .await?
        {
            UserResponse::RecordInserted { record_id } => Ok(record_id),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Query one page of `schema_nsid`'s rows in `root`, as `app_id` where one is named.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_query_in(
        &mut self,
        user_id: &str,
        root: Option<&str>,
        app_id: Option<&str>,
        schema_nsid: &str,
        field_eq: Vec<(String, Value)>,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> io::Result<Vec<Value>> {
        match self
            .client
            .send(&UserRequest::RecordQuery {
                user_id: user_id.to_owned(),
                schema_nsid: schema_nsid.to_owned(),
                field_eq,
                limit,
                offset,
                root: root.map(str::to_owned),
                app_id: app_id.map(str::to_owned),
            })
            .await?
        {
            UserResponse::RecordQueryResult { records } => Ok(records),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }
}

/// Every row of [`NSID`] in `root`, read as [`PRINCIPAL`], a page at a time.
async fn rows_in(client: &mut KottonClient, user_id: &str, root: &str) -> io::Result<Vec<Value>> {
    let mut all = Vec::new();
    loop {
        let page = client
            .record_query_in(user_id, Some(root), Some(PRINCIPAL), NSID, vec![], Some(PAGE), Some(all.len()))
            .await?;
        let done = page.len() < PAGE;
        all.extend(page);
        if done {
            return Ok(all);
        }
    }
}

/// Every `*.md` file directly in `dir`, as `(stem, text)`, in name order.
fn record_files(dir: &Path) -> io::Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if !path.is_file() || path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| io::Error::other(format!("{} has no UTF-8 name", path.display())))?
            .to_owned();
        out.push((stem, std::fs::read_to_string(&path)?));
    }
    out.sort();
    Ok(out)
}

/// `kotton records import <dir>`: read every record file in `dir` into `root`, inserting or
/// replacing each by its name.
///
/// **All or nothing on the files, idempotent on the rows.** Every file is converted before any
/// row is written, so a file the converter refuses stops the import with nothing written and
/// the refusal named. Then each row is compared with the one the root holds, and written only
/// if it differs — a second import of the same directory changes no row.
pub async fn records_import(
    client: &mut KottonClient,
    user_id: &str,
    root: &str,
    dir: &Path,
) -> io::Result<ImportReport> {
    let mut rows = Vec::new();
    let mut refused = Vec::new();
    for (name, text) in record_files(dir)? {
        match row::to_row(&name, &text) {
            Ok(r) => rows.push((name, r)),
            Err(e) => refused.push(format!("{name}: {e}")),
        }
    }
    if !refused.is_empty() {
        return Err(io::Error::other(format!(
            "{} of {} files are not records the converter can take; nothing was imported:\n{}",
            refused.len(),
            refused.len() + rows.len(),
            refused.join("\n")
        )));
    }

    let held: BTreeMap<String, Value> = rows_in(client, user_id, root)
        .await?
        .iter()
        .filter_map(|r| Some((r.get("name")?.as_str()?.to_owned(), row::content(r))))
        .collect();
    let mut report = ImportReport::default();
    for (name, r) in rows {
        match held.get(&name) {
            Some(existing) if *existing == r => {
                report.unchanged += 1;
                continue;
            }
            Some(_) => report.replaced += 1,
            None => report.inserted += 1,
        }
        client
            .record_insert_in(user_id, Some(root), Some(PRINCIPAL), NSID, r)
            .await
            .map_err(|e| io::Error::other(format!("{name}: {e}")))?;
    }
    Ok(report)
}

/// `kotton records export <dir>`: write every row of `root` back to `dir/<name>.md`, byte for
/// byte as it was imported. Returns how many files were written.
///
/// Every row is converted before any file is written, so a row the converter refuses — a name
/// that is a path, a row that does not account for its lines — stops the export with nothing
/// written. Files in `dir` that no row names are left alone.
pub async fn records_export(
    client: &mut KottonClient,
    user_id: &str,
    root: &str,
    dir: &Path,
) -> io::Result<usize> {
    let files = rows_in(client, user_id, root)
        .await?
        .iter()
        .map(|r| row::to_file(r).map_err(|e| io::Error::other(e.to_string())))
        .collect::<io::Result<Vec<_>>>()?;
    std::fs::create_dir_all(dir)?;
    for (name, text) in &files {
        std::fs::write(dir.join(format!("{name}.md")), text)?;
    }
    Ok(files.len())
}
