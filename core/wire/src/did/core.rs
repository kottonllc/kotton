// SPDX-License-Identifier: AGPL-3.0-or-later
use super::error::{DidError, Result};
use serde::{Deserialize, Serialize};
use std::fmt;

/// W3C Decentralized Identifier (DID)
///
/// Format: `did:<method>:<method-specific-id>`
/// Example: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
///
/// Serializes/deserializes as the canonical string form `"did:key:z6Mk…"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "ts-types", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-types", ts(type = "string"))]
pub struct Did {
    method: String,
    identifier: String,
}

impl Did {
    /// Create a new DID
    pub fn new(method: impl Into<String>, identifier: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            identifier: identifier.into(),
        }
    }

    /// Parse a DID from string format
    ///
    /// # Example
    /// ```
    /// use kotton_wire::did::Did;
    ///
    /// # fn main() -> Result<(), kotton_wire::did::DidError> {
    /// let did = Did::parse("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")?;
    /// assert_eq!(did.method(), "key");
    /// assert_eq!(did.identifier(), "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
    /// # Ok(())
    /// # }
    /// ```
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split(':').collect();

        if parts.len() < 3 {
            return Err(DidError::InvalidFormat(
                "DID must have at least 3 parts separated by ':'".to_string(),
            ));
        }

        if parts[0] != "did" {
            return Err(DidError::InvalidFormat(
                "DID must start with 'did:'".to_string(),
            ));
        }

        let method = parts[1].to_string();
        let identifier = parts[2..].join(":");

        if method.is_empty() || identifier.is_empty() {
            return Err(DidError::InvalidFormat(
                "DID method and identifier cannot be empty".to_string(),
            ));
        }

        Ok(Self { method, identifier })
    }

    /// Get the DID method
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Get the method-specific identifier
    pub fn identifier(&self) -> &str {
        &self.identifier
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "did:{}:{}", self.method, self.identifier)
    }
}

impl std::str::FromStr for Did {
    type Err = DidError;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl Serialize for Did {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Did {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Did::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_parse() {
        let did = Did::parse("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap();
        assert_eq!(did.method(), "key");
        assert_eq!(
            did.identifier(),
            "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        );
    }

    #[test]
    fn test_did_to_string() {
        let did = Did::new("key", "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        assert_eq!(
            did.to_string(),
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        );
    }

    #[test]
    fn test_did_invalid_format() {
        assert!(Did::parse("not-a-did").is_err());
        assert!(Did::parse("did:").is_err());
        assert!(Did::parse("did:key").is_err());
        assert!(Did::parse("key:identifier").is_err());
    }

    #[test]
    fn test_did_with_colons() {
        let did = Did::parse("did:example:123:456:789").unwrap();
        assert_eq!(did.method(), "example");
        assert_eq!(did.identifier(), "123:456:789");
    }
}
