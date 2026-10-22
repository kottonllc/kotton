// SPDX-License-Identifier: AGPL-3.0-or-later
//! NSID — Namespaced Schema Identifiers.
//!
//! An NSID is a reverse-domain string that uniquely identifies a schema:
//! `sh.kotton.notes`, `com.acme.pinnable-note`, etc.
//!
//! Format rules (subset of AT Protocol Lexicon NSID):
//! - Two or more dot-separated segments
//! - Each segment: lowercase letters, digits, hyphens; must start with a letter
//! - Total length ≤ 128 characters
//!
//! NSIDs are case-sensitive and compared bytewise. `sh.kotton.Notes` and
//! `sh.kotton.notes` are different identifiers.

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// A validated namespaced schema identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-types", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-types", ts(export))]
#[serde(transparent)]
pub struct Nsid(String);

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NsidError {
    #[error("NSID must have at least two dot-separated segments, got: {0:?}")]
    TooFewSegments(String),
    #[error("NSID segment is empty in: {0:?}")]
    EmptySegment(String),
    #[error("NSID segment must start with a letter, got segment {1:?} in {0:?}")]
    SegmentMustStartWithLetter(String, String),
    #[error("NSID segment contains invalid character {1:?} in {0:?}")]
    InvalidCharacter(String, char),
    #[error("NSID exceeds 128 characters: {0:?}")]
    TooLong(String),
}

impl Nsid {
    /// Parse and validate an NSID string.
    pub fn new(s: impl Into<String>) -> Result<Self, NsidError> {
        let s = s.into();
        if s.len() > 128 {
            return Err(NsidError::TooLong(s));
        }
        let segments: Vec<String> = s.split('.').map(|seg| seg.to_owned()).collect();
        if segments.len() < 2 {
            return Err(NsidError::TooFewSegments(s));
        }
        for seg in &segments {
            if seg.is_empty() {
                return Err(NsidError::EmptySegment(s));
            }
            let first = seg.chars().next().unwrap();
            if !first.is_ascii_lowercase() {
                return Err(NsidError::SegmentMustStartWithLetter(s, seg.clone()));
            }
            for c in seg.chars() {
                if !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '-' {
                    return Err(NsidError::InvalidCharacter(s, c));
                }
            }
        }
        Ok(Self(s))
    }

    /// Return the string value without validation (for use with known-valid constants).
    ///
    /// # Panics
    /// Panics in debug builds if the string is not a valid NSID. Use [`Nsid::new`]
    /// for runtime input.
    pub fn from_static(s: &'static str) -> Self {
        debug_assert!(
            Self::new(s).is_ok(),
            "from_static called with invalid NSID: {s:?}"
        );
        Self(s.to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Nsid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for Nsid {
    type Error = NsidError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<&str> for Nsid {
    type Error = NsidError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_nsids() {
        assert!(Nsid::new("sh.kotton.notes").is_ok());
        assert!(Nsid::new("com.acme.pinnable-note").is_ok());
        assert!(Nsid::new("io.github.myapp.tasks").is_ok());
        assert!(Nsid::new("a.b").is_ok());
    }

    #[test]
    fn invalid_nsids() {
        assert!(Nsid::new("notes").is_err()); // only one segment
        assert!(Nsid::new("sh.Kotton.notes").is_err()); // uppercase
        assert!(Nsid::new("com..notes").is_err()); // empty segment
        assert!(Nsid::new("com.1notes.foo").is_err()); // segment starts with digit
        assert!(Nsid::new("com.notes_extra.foo").is_err()); // underscore not allowed
        assert!(Nsid::new("a.".repeat(65)).is_err()); // too long
    }

    #[test]
    fn display_roundtrip() {
        let s = "sh.kotton.notes";
        let nsid = Nsid::new(s).unwrap();
        assert_eq!(nsid.to_string(), s);
    }
}
