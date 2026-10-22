// SPDX-License-Identifier: AGPL-3.0-or-later
//! `RecordUrl` — the canonical `kotton://` URL type for addressing records.
//!
//! ## Format
//!
//! ```text
//! kotton://records/<nsid>/<id>
//! ```
//!
//! Examples:
//! - `kotton://records/sh.kotton.notes/019612ab-e3f2-7000-abcd-1234567890ab`
//! - `kotton://records/sh.kotton.contacts/019612ab-e3f2-7000-abcd-000000000001`
//!
//! The `<nsid>` must be a valid [`Nsid`]; `<id>` is opaque (UUID v7 in practice).

use crate::nsid::{Nsid, NsidError};
use std::fmt;
use thiserror::Error;

const SCHEME_PREFIX: &str = "kotton://records/";

/// A validated `kotton://records/<nsid>/<id>` URL.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RecordUrl {
    /// The schema identifier for the record.
    pub nsid: Nsid,
    /// The stable record identifier (opaque string, UUID v7 in practice).
    pub id: String,
}

/// Errors produced when parsing a `kotton://` URL.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RecordUrlError {
    #[error("URL must start with 'kotton://records/', got: {0:?}")]
    MissingScheme(String),

    #[error("URL is missing a record ID after the NSID")]
    MissingId,

    #[error("NSID in URL is invalid: {0}")]
    InvalidNsid(#[from] NsidError),
}

impl RecordUrl {
    /// Parse a `kotton://records/<nsid>/<id>` URL.
    pub fn parse(url: &str) -> Result<Self, RecordUrlError> {
        let rest = url
            .strip_prefix(SCHEME_PREFIX)
            .ok_or_else(|| RecordUrlError::MissingScheme(url.to_owned()))?;

        // The NSID must not contain '/', so the last '/' separates NSID from id.
        let slash = rest.rfind('/').ok_or(RecordUrlError::MissingId)?;

        let nsid_str = &rest[..slash];
        let id = rest[slash + 1..].to_owned();

        if id.is_empty() {
            return Err(RecordUrlError::MissingId);
        }

        let nsid = Nsid::new(nsid_str)?;
        Ok(RecordUrl { nsid, id })
    }
}

impl fmt::Display for RecordUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "kotton://records/{}/{}", self.nsid, self.id)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let url = "kotton://records/sh.kotton.notes/019612ab-e3f2-7000-abcd-1234567890ab";
        let parsed = RecordUrl::parse(url).unwrap();
        assert_eq!(parsed.nsid.as_str(), "sh.kotton.notes");
        assert_eq!(parsed.id, "019612ab-e3f2-7000-abcd-1234567890ab");
        assert_eq!(parsed.to_string(), url);
    }

    #[test]
    fn missing_scheme_error() {
        let err = RecordUrl::parse("https://records/sh.kotton.notes/abc").unwrap_err();
        assert!(matches!(err, RecordUrlError::MissingScheme(_)));
    }

    #[test]
    fn missing_id_error() {
        let err = RecordUrl::parse("kotton://records/sh.kotton.notes/").unwrap_err();
        assert!(matches!(err, RecordUrlError::MissingId));
    }

    #[test]
    fn missing_id_no_slash() {
        let err = RecordUrl::parse("kotton://records/sh.kotton.notes").unwrap_err();
        assert!(matches!(err, RecordUrlError::MissingId));
    }

    #[test]
    fn invalid_nsid_error() {
        let err = RecordUrl::parse("kotton://records/NOT_VALID/abc").unwrap_err();
        assert!(matches!(err, RecordUrlError::InvalidNsid(_)));
    }
}
