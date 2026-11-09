// SPDX-License-Identifier: AGPL-3.0-or-later
//! An app's id, as its manifest declares it: a reverse-domain string.
//!
//! `com.acme.notes-pro`: two or more dot-separated segments of lowercase ASCII letters, digits
//! and hyphens, each beginning with a letter, at most 128 bytes. It is the id an app is
//! installed, launched and granted under, and the directory its bytes are kept in.
//!
//! This is not a schema's identity. A schema is named by the key that publishes it
//! ([`crate::SchemaId`]); an app is shown by the key that signed it, and its id is a label
//! the app's author chose that resolves nowhere and grants nothing by itself. The grammar
//! here is the one the id has always had, kept so that no manifest in the tree changes
//! shape while a schema's name does.

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// A validated app id.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-types", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-types", ts(export, type = "string"))]
#[serde(try_from = "String", into = "String")]
pub struct AppId(String);

/// Why a string is not an app id.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AppIdError {
    #[error("an app id has at least two dot-separated segments, got: {0:?}")]
    TooFewSegments(String),
    #[error("an app id's segment is empty in: {0:?}")]
    EmptySegment(String),
    #[error("an app id's segment begins with a letter, got segment {1:?} in {0:?}")]
    SegmentMustStartWithLetter(String, String),
    #[error("an app id is lowercase letters, digits, hyphens and dots, got {1:?} in {0:?}")]
    InvalidCharacter(String, char),
    #[error("an app id is at most 128 bytes: {0:?}")]
    TooLong(String),
}

impl AppId {
    /// Parse and validate an app id.
    pub fn new(s: impl Into<String>) -> Result<Self, AppIdError> {
        let s = s.into();
        if s.len() > 128 {
            return Err(AppIdError::TooLong(s));
        }
        let segments: Vec<&str> = s.split('.').collect();
        if segments.len() < 2 {
            return Err(AppIdError::TooFewSegments(s));
        }
        for seg in &segments {
            if seg.is_empty() {
                return Err(AppIdError::EmptySegment(s));
            }
            let first = seg.chars().next().expect("a non-empty segment has a first char");
            if !first.is_ascii_lowercase() {
                return Err(AppIdError::SegmentMustStartWithLetter(s.clone(), (*seg).to_owned()));
            }
            if let Some(c) =
                seg.chars().find(|c| !c.is_ascii_lowercase() && !c.is_ascii_digit() && *c != '-')
            {
                return Err(AppIdError::InvalidCharacter(s, c));
            }
        }
        Ok(Self(s))
    }

    /// The id as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AppId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for AppId {
    type Error = AppIdError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<&str> for AppId {
    type Error = AppIdError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl From<AppId> for String {
    fn from(id: AppId) -> String {
        id.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_app_ids() {
        assert!(AppId::new("sh.kotton.shell").is_ok());
        assert!(AppId::new("com.acme.notes-pro").is_ok());
        assert!(AppId::new("io.github.myapp.tasks").is_ok());
        assert!(AppId::new("a.b").is_ok());
    }

    #[test]
    fn invalid_app_ids() {
        assert!(AppId::new("shell").is_err()); // only one segment
        assert!(AppId::new("sh.Kotton.shell").is_err()); // uppercase
        assert!(AppId::new("com..notes").is_err()); // empty segment
        assert!(AppId::new("com.1notes.foo").is_err()); // segment starts with digit
        assert!(AppId::new("com.notes_extra.foo").is_err()); // underscore not allowed
        assert!(AppId::new("record-file:converter").is_err()); // a colon, and no dot
        assert!(AppId::new("a.".repeat(65)).is_err()); // too long
    }

    #[test]
    fn display_roundtrip() {
        let s = "sh.kotton.shell";
        let id = AppId::new(s).unwrap();
        assert_eq!(id.to_string(), s);
        assert_eq!(serde_json::to_string(&id).unwrap(), "\"sh.kotton.shell\"");
        assert!(serde_json::from_str::<AppId>("\"shell\"").is_err());
    }
}
