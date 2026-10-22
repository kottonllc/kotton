// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `import` verb of the `record` domain — a person's history, as ordinary
//! records.
//!
//! `TASK-a-person-brings-their-history-with-them`. **Import is not a storage
//! path.** It is a reader that produces records the store already seals and the
//! sync engine already carries, which is `DEC-0071`'s cohesion rule: nothing
//! here opens a database, writes a table, or knows where a byte lands. It builds
//! JSON bodies and hands them to [`crate::record_cmds::Record::insert`], the
//! same verb an app uses.
//!
//! It runs here, in the daemon, under the person's unlocked context, because
//! import is the one operation that must see plaintext (`RFC-0058`): the export
//! is the person's own file and the records are sealed on the way in. A vault
//! holds no content key and can never do this.
//!
//! ## The shape, and the ruling it is waiting on
//!
//! `DEC-0042` says a declaring party states a **shape**, never a name, and
//! `DEC-0043` says every leaf of it is a type the node can decode. This module
//! declares the first real one: [`imported_calendar_schema`], a fork of
//! `sh.kotton.calendar` that keeps what an `.ics` actually carries — the
//! recurrence rule, the zone, the all-day flag, the `UID` — and carries
//! provenance in a `source` facet.
//!
//! **It is a fork because it cannot be the commons.** `sh.kotton.calendar` has
//! five fields and no room for any of that; Article IX seals it, so adding room
//! is an amendment and not an executive act. `forked_from` is exactly how
//! `RFC-0003` says to record that — *"a field appearing in eleven forks of one
//! core schema is the commons being told what belongs in it"* — and the argument
//! for the commons adopting it is
//! `IDEA-imported-records-have-nowhere-to-say-where-they-came-from`. Two
//! consequences travel with the fork, and both are written down there: a device
//! that has never seen the declaration skips the rows
//! ([`crate::replication::apply_record_segments`]), and a reader looking only at
//! `sh.kotton.calendar` does not see imported events (`DEC-0027` — a fork is not
//! a subtype).

use std::sync::RwLock;

use anyhow::Result;
use kotton_schemas::{
    definition::SchemaDefinition,
    field::{FieldType, SchemaField},
    nsid::Nsid,
};
use serde_json::json;

use crate::provider::sqlite_record_store::SqliteRecordStore;
use crate::record_cmds::Record;
use crate::registry::SchemaRegistry;

/// The local identifier for the shape imported calendar events take.
///
/// Deliberately **not** under `sh.kotton.*`: that namespace is the commons
/// Article IX seals, and a shape declared by an importer is not the commons
/// (`DEC-0042` — the name carries no authority and resolves nowhere; it is a
/// local handle on a shape, and only the shape means anything).
pub const IMPORTED_CALENDAR_NSID: &str = "import.calendar.event";

/// What one import did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportOutcome {
    /// The shape the items were written under.
    pub schema_nsid: String,
    /// Items written as records.
    pub imported: usize,
    /// Items the reader could not make a record of, and said so about.
    ///
    /// Reported rather than swallowed: "imported 412" over a file with 415
    /// events is the confident wrong answer this repository keeps cataloguing.
    pub skipped: usize,
}

/// The shape of an imported calendar event.
///
/// The first five fields are `sh.kotton.calendar`'s, name for name and type for
/// type, so the fork reads as a superset of the commons rather than a rival to
/// it. The rest is what an `.ics` carries and the commons has no room for, and
/// `source` is the facet `DEC-0043` added `FieldType::Record` for.
pub fn imported_calendar_schema() -> SchemaDefinition {
    SchemaDefinition::new(
        Nsid::from_static(IMPORTED_CALENDAR_NSID),
        1,
        vec![
            // ── `sh.kotton.calendar`, unchanged ──────────────────────────────
            SchemaField::required("title", FieldType::String),
            SchemaField::required("start_at", FieldType::Datetime),
            SchemaField::required("end_at", FieldType::Datetime),
            SchemaField::required("participants", FieldType::List(Box::new(FieldType::String))),
            SchemaField::nullable("location", FieldType::String),
            // ── what the export carries and the commons cannot hold ──────────
            // An all-day event's `end_at` is exclusive (RFC 5545 §3.6.1), so a
            // reader has to know which convention it is looking at.
            SchemaField::with_default("all_day", FieldType::Bool, json!(false)),
            SchemaField::nullable("time_zone", FieldType::String),
            SchemaField::nullable("description", FieldType::String),
            SchemaField::nullable("recurrence", FieldType::String),
            SchemaField::nullable("recurrence_id", FieldType::String),
            SchemaField::nullable("uid", FieldType::String),
            // ── provenance ───────────────────────────────────────────────────
            // "when did I say that" is answered from here, and so is "where did
            // this come from" when two exports disagree.
            SchemaField::required(
                "source",
                FieldType::Record(vec![
                    SchemaField::required("file", FieldType::String),
                    SchemaField::required("imported_at", FieldType::Datetime),
                ]),
            ),
        ],
    )
    .with_forked_from(Nsid::from_static(kotton_common::namespace::NSID_CALENDAR))
    .with_description(
        "A calendar event brought in from an export, with the recurrence rule, \
         zone and provenance the core calendar schema has no field for.",
    )
}

/// The `import` verb, bound to one person's registry and store.
///
/// The same pairing as [`Record`], for the same reason: a handle that can reach
/// exactly one registry and one store cannot write another person's records.
pub struct Import<'a> {
    registry: &'a RwLock<SchemaRegistry>,
    store: &'a SqliteRecordStore,
}

impl<'a> Import<'a> {
    pub fn new(registry: &'a RwLock<SchemaRegistry>, store: &'a SqliteRecordStore) -> Self {
        Self { registry, store }
    }
}

impl Import<'_> {
    /// Write an already-read `.ics` export as records.
    ///
    /// **Reading happens before this and off this task** — the handler runs
    /// [`crate::ics::read`] on a blocking thread, so a reader that aborts costs a
    /// reply rather than the connection. Taking the parsed [`IcsRead`] rather
    /// than the bytes is what makes that possible, and it keeps this function to
    /// one job: turning events into records.
    ///
    /// **The caller declares [`imported_calendar_schema`] first**, through
    /// `daemon::records::register_and_persist` — declaring is half registry and
    /// half database, and this tier holds no database handle. Doing it here with
    /// the registry alone is what produced two copies of the persistence step;
    /// there is one now, and it is that function.
    ///
    /// `source_name` is **provenance, not a path**: only its last component is
    /// kept, so the person's home-directory layout does not end up in a record
    /// that then syncs to every device they own. Nothing here opens it — the
    /// bytes already arrived.
    pub async fn write_calendar(
        &self,
        read: &crate::ics::IcsRead,
        source_name: &str,
        imported_at: &str,
    ) -> Result<ImportOutcome> {
        let file = provenance_name(source_name);
        let records = Record::new(self.registry, self.store);
        let mut imported = 0usize;
        for event in &read.events {
            let body = json!({
                "title": event.summary.clone().unwrap_or_default(),
                "start_at": event.start_at,
                "end_at": event.end_at,
                "participants": event.participants,
                "location": event.location,
                "all_day": event.all_day,
                "time_zone": event.time_zone,
                "description": event.description,
                "recurrence": event.recurrence,
                "recurrence_id": event.recurrence_id,
                "uid": event.uid,
                "source": { "file": file, "imported_at": imported_at },
            });
            records.insert(IMPORTED_CALENDAR_NSID, body).await?;
            imported += 1;
        }

        Ok(ImportOutcome {
            schema_nsid: IMPORTED_CALENDAR_NSID.to_owned(),
            imported,
            skipped: read.skipped,
        })
    }
}

/// Keep the export's file name and drop everything in front of it.
///
/// A record travels to every device the person owns; `/home/ada/Downloads/…`
/// says where she keeps things and answers no question anyone will ask of the
/// record. Both separators, because the client may be running on either
/// platform and the daemon must not take the caller's word for the shape of a
/// path.
fn provenance_name(source_name: &str) -> String {
    source_name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(source_name)
        .trim()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fork is a superset of the commons, field for field — so promoting it
    /// is an amendment rather than a rewrite, and a reader of one can read the
    /// other.
    #[test]
    fn the_import_shape_contains_the_core_calendar_shape() {
        let core = kotton_schemas::core::CoreSchema::Calendar.definition();
        let import = imported_calendar_schema();
        for field in &core.fields {
            let mine = import
                .field(&field.name)
                .unwrap_or_else(|| panic!("the import shape drops `{}`", field.name));
            assert_eq!(
                mine.field_type, field.field_type,
                "`{}` has a different type than the commons",
                field.name
            );
            assert_eq!(mine.nullable, field.nullable, "`{}` nullability", field.name);
        }
        assert_eq!(
            import.forked_from.as_ref().map(|n| n.as_str()),
            Some(kotton_common::namespace::NSID_CALENDAR),
            "a fork records where it came from (DEC-0027, RFC-0003)",
        );
    }

    /// `DEC-0043`: every leaf is a type the node can decode, the facet included.
    #[test]
    fn every_leaf_of_the_import_shape_is_a_primitive() {
        let import = imported_calendar_schema();
        let source = import.field("source").expect("provenance is a field");
        let FieldType::Record(inner) = &source.field_type else {
            panic!("provenance is a facet, not a smuggled string");
        };
        assert_eq!(inner.len(), 2);
        for field in &import.fields {
            for leaf in field.field_type.leaves() {
                assert!(
                    !matches!(leaf, FieldType::Record(_) | FieldType::List(_) | FieldType::Map(_)),
                    "`{}` bottoms out in a constructor, not a leaf",
                    field.name
                );
            }
        }
    }

    /// The shape must not name the sealed namespace. Registration would refuse a
    /// core NSID outright, but a near-miss like `sh.kotton.calendar-import`
    /// registers fine and squats on the commons, which nothing else checks.
    #[test]
    fn the_import_shape_does_not_claim_the_commons() {
        assert!(
            !IMPORTED_CALENDAR_NSID.starts_with(kotton_common::namespace::NSID_PREFIX),
            "Article IX seals `{}`",
            kotton_common::namespace::NSID_PREFIX,
        );
    }

    #[test]
    fn provenance_is_a_file_name_not_a_path() {
        assert_eq!(provenance_name("/home/ada/Downloads/cal.ics"), "cal.ics");
        assert_eq!(provenance_name(r"C:\Users\Ada\cal.ics"), "cal.ics");
        assert_eq!(provenance_name("cal.ics"), "cal.ics");
    }
}
