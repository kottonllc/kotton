// SPDX-License-Identifier: AGPL-3.0-or-later
//! Schema definition — the typed, versioned declaration of a record table.
//!
//! A [`SchemaDefinition`] is what an app ships in its manifest and what the
//! daemon stores in its DB. It is the contract between the app and the runtime.
//!
//! ## Versioning rules
//!
//! - Additive changes (adding a nullable field or a field with a default) bump
//!   the minor version counter and are applied automatically on upgrade.
//! - Breaking changes (removing or renaming a field) require a new NSID version
//!   segment (e.g. `com.acme.notes` → `com.acme.notes-v2`) and an explicit
//!   migration converter.

use crate::{nsid::Nsid, SchemaField};
use serde::{Deserialize, Serialize};

/// The full typed declaration of a record table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaDefinition {
    /// Unique schema identifier, e.g. `sh.kotton.notes`.
    pub nsid: Nsid,

    /// Schema version. Starts at 1. Incremented for every additive migration.
    /// The runtime uses this to determine whether `migrations` need to run.
    pub version: u32,

    /// Ordered list of field declarations.
    /// Order determines column order in the resulting SQLite table.
    pub fields: Vec<SchemaField>,

    /// The schema this definition was copied from, if any. **Provenance only.**
    ///
    /// A fork is a new schema, not a subtype: it participates in no type
    /// relation, a query for the named origin does not return records of this
    /// type, and a grant on the origin does not reach them.
    ///
    /// Nothing reads this to decide behaviour. It is recorded so forks can be
    /// **counted**: a field appearing in eleven forks of one core schema is the
    /// commons being told what belongs in it, and unrecorded provenance cannot
    /// be counted. The origin need not still exist — you forked it, then it was
    /// retired — so this is never validated.
    ///
    /// The `extends` alias reads definitions persisted before the rename. It can
    /// go once no `app_schemas` row predates it, which for a pre-alpha with no
    /// shipped installs is "whenever someone wants to".
    #[serde(default, alias = "extends", skip_serializing_if = "Option::is_none")]
    pub forked_from: Option<Nsid>,

    /// Human-readable description for tooling and the community index.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl SchemaDefinition {
    pub fn new(nsid: Nsid, version: u32, fields: Vec<SchemaField>) -> Self {
        Self {
            nsid,
            version,
            fields,
            forked_from: None,
            description: None,
        }
    }

    pub fn with_forked_from(mut self, origin: Nsid) -> Self {
        self.forked_from = Some(origin);
        self
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Return the field with the given name, if present.
    pub fn field(&self, name: &str) -> Option<&SchemaField> {
        self.fields.iter().find(|f| f.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FieldType;

    fn notes_schema() -> SchemaDefinition {
        SchemaDefinition::new(
            Nsid::from_static("sh.kotton.notes"),
            1,
            vec![
                SchemaField::required("title", FieldType::String),
                SchemaField::required("body", FieldType::String),
            ],
        )
    }

    #[test]
    fn roundtrip() {
        let def = notes_schema();
        let json = serde_json::to_string(&def).unwrap();
        let back: SchemaDefinition = serde_json::from_str(&json).unwrap();
        assert_eq!(back.nsid.as_str(), "sh.kotton.notes");
        assert_eq!(back.version, 1);
        assert_eq!(back.fields.len(), 2);
    }

    #[test]
    fn field_lookup() {
        let def = notes_schema();
        assert!(def.field("title").is_some());
        assert!(def.field("missing").is_none());
    }
}
