// SPDX-License-Identifier: AGPL-3.0-or-later
//! `RecordUrl` — the canonical `kotton://` URL type for addressing records.
//!
//! ## Format
//!
//! ```text
//! kotton://records/<publisher>/<name>/<id>
//! ```
//!
//! For example, a note of Kotton's core set:
//!
//! ```text
//! kotton://records/did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/notes/019612ab-e3f2-7000-abcd-1234567890ab
//! ```
//!
//! `<publisher>/<name>` is the record's schema, a [`SchemaId`]: the publisher is before the
//! first `/` after the prefix, the id after the last, and the name between. `<id>` is opaque
//! (UUID v7 in practice) and holds no `/`.

use crate::schema_id::{SchemaId, SchemaIdError};
use std::fmt;
use thiserror::Error;

const SCHEME_PREFIX: &str = "kotton://records/";

/// A validated `kotton://records/<publisher>/<name>/<id>` URL.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RecordUrl {
    /// The record's schema.
    pub schema: SchemaId,
    /// The stable record identifier (opaque string, UUID v7 in practice).
    pub id: String,
}

/// Errors produced when parsing a `kotton://` URL.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RecordUrlError {
    #[error("URL must start with 'kotton://records/', got: {0:?}")]
    MissingScheme(String),

    #[error("URL is missing a record ID after the schema")]
    MissingId,

    #[error("the schema in the URL is not a schema identity: {0}")]
    InvalidSchema(#[from] SchemaIdError),
}

impl RecordUrl {
    /// Parse a `kotton://records/<publisher>/<name>/<id>` URL.
    pub fn parse(url: &str) -> Result<Self, RecordUrlError> {
        let rest = url
            .strip_prefix(SCHEME_PREFIX)
            .ok_or_else(|| RecordUrlError::MissingScheme(url.to_owned()))?;

        // The id holds no '/', so the last '/' separates the schema from the id.
        let slash = rest.rfind('/').ok_or(RecordUrlError::MissingId)?;

        let schema_str = &rest[..slash];
        let id = rest[slash + 1..].to_owned();

        if id.is_empty() {
            return Err(RecordUrlError::MissingId);
        }

        let schema = SchemaId::parse(schema_str)?;
        Ok(RecordUrl { schema, id })
    }
}

impl fmt::Display for RecordUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "kotton://records/{}/{}", self.schema, self.id)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use kotton_common::namespace::NSID_NOTES;

    #[test]
    fn roundtrip() {
        let url = format!("kotton://records/{NSID_NOTES}/019612ab-e3f2-7000-abcd-1234567890ab");
        let parsed = RecordUrl::parse(&url).unwrap();
        assert_eq!(parsed.schema.to_string(), NSID_NOTES);
        assert_eq!(parsed.schema.name().as_str(), "notes");
        assert_eq!(parsed.id, "019612ab-e3f2-7000-abcd-1234567890ab");
        assert_eq!(parsed.to_string(), url);
    }

    #[test]
    fn missing_scheme_error() {
        let err = RecordUrl::parse(&format!("https://records/{NSID_NOTES}/abc")).unwrap_err();
        assert!(matches!(err, RecordUrlError::MissingScheme(_)));
    }

    #[test]
    fn missing_id_error() {
        let err = RecordUrl::parse(&format!("kotton://records/{NSID_NOTES}/")).unwrap_err();
        assert!(matches!(err, RecordUrlError::MissingId));
    }

    #[test]
    fn a_schema_alone_has_no_id() {
        // `<publisher>/<name>` has one slash, so the last one leaves no id and a publisher
        // for a schema; the refusal names the schema, since a name without an id is not one.
        let err = RecordUrl::parse(&format!("kotton://records/{NSID_NOTES}")).unwrap_err();
        assert!(matches!(err, RecordUrlError::InvalidSchema(SchemaIdError::NoSlash(_))), "{err:?}");
    }

    #[test]
    fn the_old_form_is_refused() {
        let err = RecordUrl::parse("kotton://records/sh.kotton.notes/abc").unwrap_err();
        assert!(matches!(err, RecordUrlError::InvalidSchema(_)));
    }

    #[test]
    fn invalid_schema_error() {
        let err = RecordUrl::parse("kotton://records/NOT_VALID/x/abc").unwrap_err();
        assert!(matches!(err, RecordUrlError::InvalidSchema(_)));
    }
}
