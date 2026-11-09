// SPDX-License-Identifier: AGPL-3.0-or-later
//! A schema's identity: the key that publishes it, and its name under that key.
//!
//! The protocol's decision *A schema is named by the key that publishes it* fixes the form:
//! `<publisher>/<name>`, where the publisher is the `did:key` of the key that publishes the
//! schema and signs its definition, and the name is one or more dot-separated segments of
//! lowercase letters, digits and hyphens, each beginning with a letter. Nothing resolves,
//! registers or reserves a name: nobody can publish under a key they do not hold, so no one
//! can wear another publisher's name, whatever string they choose for their own.
//!
//! ## What is held here
//!
//! - [`Publisher`]: a `did:key` whose multibase is base58btc (`z`) and whose multicodec is
//!   Ed25519 (`0xed 0x01`), so it names one Ed25519 public key. The grammar is checked here,
//!   and nothing else: whether a definition is signed by that key is `kotton_crypto`'s
//!   `schema_signature`, since this crate links no signature scheme.
//! - [`SchemaName`]: the name under the key, as the decision writes its grammar.
//! - [`SchemaId`]: the two together, at most 256 bytes written out, parsed from and shown as
//!   `<did:key:…>/<name>`. The publisher holds no `/`, so the first `/` separates the two.
//!
//! Each is compared bytewise and serialised as its string, validated again on the way in.
//! An identity is shared vocabulary, the same for everyone who uses the schema: it names no
//! person and joins nothing. A publisher's key names the publisher, as a release key names a
//! releaser, which is the one identity this design means to be public.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

/// The whole identity, `<publisher>/<name>`, written out, is at most this many bytes.
pub const MAX_LEN: usize = 256;

const DID_KEY_Z: &str = "did:key:z";
const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];

// ── Publisher ────────────────────────────────────────────────────────────────

/// The key that publishes a schema, as the `did:key` of its public half.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-types", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-types", ts(export, type = "string"))]
#[serde(try_from = "String", into = "String")]
pub struct Publisher(String);

/// Why a string is not a publisher.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PublisherError {
    #[error("a publisher is a `did:key:z…` (base58btc), got: {0:?}")]
    NotDidKey(String),
    #[error("the multibase after `did:key:z` is not base58btc in: {0:?}")]
    NotBase58(String),
    #[error("the key is not a 32-byte Ed25519 key under its multicodec (0xed01) in: {0:?}")]
    NotEd25519Key(String),
}

impl Publisher {
    /// Parse and validate a `did:key`.
    pub fn new(s: impl Into<String>) -> Result<Self, PublisherError> {
        let s = s.into();
        let Some(multibase) = s.strip_prefix(DID_KEY_Z) else {
            return Err(PublisherError::NotDidKey(s));
        };
        let Ok(bytes) = bs58::decode(multibase).into_vec() else {
            return Err(PublisherError::NotBase58(s));
        };
        if bytes.len() != 2 + 32 || bytes[..2] != ED25519_MULTICODEC {
            return Err(PublisherError::NotEd25519Key(s));
        }
        Ok(Self(s))
    }

    /// The `did:key` of an Ed25519 public key.
    pub fn from_ed25519_public_key(key: &[u8; 32]) -> Self {
        let mut bytes = Vec::with_capacity(34);
        bytes.extend_from_slice(&ED25519_MULTICODEC);
        bytes.extend_from_slice(key);
        Self(format!("{DID_KEY_Z}{}", bs58::encode(bytes).into_string()))
    }

    /// The 32 bytes of the Ed25519 public key this `did:key` names.
    pub fn ed25519_public_key(&self) -> [u8; 32] {
        let bytes = bs58::decode(&self.0[DID_KEY_Z.len()..])
            .into_vec()
            .expect("a Publisher was validated as base58btc");
        bytes[2..].try_into().expect("a Publisher was validated as 34 bytes")
    }

    /// The `did:key` string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// A publisher known valid at compile time, such as a constant.
    ///
    /// # Panics
    /// Panics if `s` is not a publisher: a constant that is not one is a defect in the tree,
    /// not an input to refuse.
    pub fn from_static(s: &'static str) -> Self {
        Self::new(s).unwrap_or_else(|e| panic!("from_static: {e}"))
    }
}

impl fmt::Display for Publisher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Publisher {
    type Err = PublisherError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl TryFrom<String> for Publisher {
    type Error = PublisherError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<&str> for Publisher {
    type Error = PublisherError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl From<Publisher> for String {
    fn from(p: Publisher) -> String {
        p.0
    }
}

// ── SchemaName ───────────────────────────────────────────────────────────────

/// A schema's name under its publisher: one or more dot-separated segments of lowercase
/// ASCII letters, digits and hyphens, each beginning with a letter.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-types", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-types", ts(export, type = "string"))]
#[serde(try_from = "String", into = "String")]
pub struct SchemaName(String);

/// Why a string is not a schema name.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SchemaNameError {
    #[error("a schema name has a segment in it, got an empty name")]
    Empty,
    #[error("a schema name's segment is empty in: {0:?}")]
    EmptySegment(String),
    #[error("a schema name's segment begins with a letter, got segment {1:?} in {0:?}")]
    SegmentMustStartWithLetter(String, String),
    #[error("a schema name is lowercase letters, digits, hyphens and dots, got {1:?} in {0:?}")]
    InvalidCharacter(String, char),
    #[error("a schema name is at most {MAX_LEN} bytes: {0:?}")]
    TooLong(String),
}

impl SchemaName {
    /// Parse and validate a schema name.
    pub fn new(s: impl Into<String>) -> Result<Self, SchemaNameError> {
        let s = s.into();
        if s.is_empty() {
            return Err(SchemaNameError::Empty);
        }
        if s.len() > MAX_LEN {
            return Err(SchemaNameError::TooLong(s));
        }
        for seg in s.split('.') {
            if seg.is_empty() {
                return Err(SchemaNameError::EmptySegment(s));
            }
            let first = seg.chars().next().expect("a non-empty segment has a first char");
            if !first.is_ascii_lowercase() {
                return Err(SchemaNameError::SegmentMustStartWithLetter(s.clone(), seg.to_owned()));
            }
            if let Some(c) =
                seg.chars().find(|c| !c.is_ascii_lowercase() && !c.is_ascii_digit() && *c != '-')
            {
                return Err(SchemaNameError::InvalidCharacter(s, c));
            }
        }
        Ok(Self(s))
    }

    /// The name as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// A name known valid at compile time, such as a constant.
    ///
    /// # Panics
    /// Panics if `s` is not a schema name; see [`Publisher::from_static`].
    pub fn from_static(s: &'static str) -> Self {
        Self::new(s).unwrap_or_else(|e| panic!("from_static: {e}"))
    }
}

impl fmt::Display for SchemaName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for SchemaName {
    type Err = SchemaNameError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl TryFrom<String> for SchemaName {
    type Error = SchemaNameError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<&str> for SchemaName {
    type Error = SchemaNameError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl From<SchemaName> for String {
    fn from(n: SchemaName) -> String {
        n.0
    }
}

// ── SchemaId ─────────────────────────────────────────────────────────────────

/// A schema's identity: its publisher and its name, `<did:key:…>/<name>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-types", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-types", ts(export, type = "string"))]
#[serde(try_from = "String", into = "String")]
pub struct SchemaId {
    publisher: Publisher,
    name: SchemaName,
}

/// Why a string is not a schema identity.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SchemaIdError {
    #[error("a schema identity is `<did:key:…>/<name>`, and there is no `/` in: {0:?}")]
    NoSlash(String),
    #[error("a schema identity is at most {MAX_LEN} bytes: {0:?}")]
    TooLong(String),
    #[error("{0}")]
    Publisher(#[from] PublisherError),
    #[error("{0}")]
    Name(#[from] SchemaNameError),
}

impl SchemaId {
    /// An identity from its two parts, bounded as a whole.
    pub fn new(publisher: Publisher, name: SchemaName) -> Result<Self, SchemaIdError> {
        if publisher.as_str().len() + 1 + name.as_str().len() > MAX_LEN {
            return Err(SchemaIdError::TooLong(format!("{publisher}/{name}")));
        }
        Ok(Self { publisher, name })
    }

    /// Parse `<did:key:…>/<name>`. The publisher holds no `/`, so the first one separates
    /// the two.
    pub fn parse(s: impl AsRef<str>) -> Result<Self, SchemaIdError> {
        let s = s.as_ref();
        if s.len() > MAX_LEN {
            return Err(SchemaIdError::TooLong(s.to_owned()));
        }
        let Some((publisher, name)) = s.split_once('/') else {
            return Err(SchemaIdError::NoSlash(s.to_owned()));
        };
        Ok(Self { publisher: Publisher::new(publisher)?, name: SchemaName::new(name)? })
    }

    /// An identity known valid at compile time, such as a constant of
    /// `kotton_common::namespace`.
    ///
    /// # Panics
    /// Panics if `s` is not a schema identity; see [`Publisher::from_static`].
    pub fn from_static(s: &'static str) -> Self {
        Self::parse(s).unwrap_or_else(|e| panic!("from_static: {e}"))
    }

    /// The key that publishes the schema.
    pub fn publisher(&self) -> &Publisher {
        &self.publisher
    }

    /// The schema's name under its publisher.
    pub fn name(&self) -> &SchemaName {
        &self.name
    }

    /// The identity's two parts.
    pub fn into_parts(self) -> (Publisher, SchemaName) {
        (self.publisher, self.name)
    }
}

impl fmt::Display for SchemaId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.publisher, self.name)
    }
}

impl FromStr for SchemaId {
    type Err = SchemaIdError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<String> for SchemaId {
    type Error = SchemaIdError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}

impl TryFrom<&str> for SchemaId {
    type Error = SchemaIdError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}

impl From<SchemaId> for String {
    fn from(id: SchemaId) -> String {
        id.to_string()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A publisher of the right shape, for tests of the grammar: 0xed01 then 32 bytes of
    /// 0x01, base58btc.
    pub(crate) const PUB_A: &str = "did:key:z6MkeXBLjYiSvqnhFb6D7sHm8yKm4jV45wwBFRaatf1cfZ76";
    /// Another, 32 bytes of 0x02.
    pub(crate) const PUB_B: &str = "did:key:z6Mkeb6dsrBTX95vPgLiZAcgRr6XJthFm1czoqFEx34DQtRo";

    #[test]
    fn valid_publishers() {
        assert!(Publisher::new(PUB_A).is_ok());
        assert!(Publisher::new(PUB_B).is_ok());
        assert!(Publisher::new(kotton_common::namespace::NSID_PREFIX).is_ok());
        assert_eq!(Publisher::from_ed25519_public_key(&[1u8; 32]).as_str(), PUB_A);
        assert_eq!(Publisher::new(PUB_B).unwrap().ed25519_public_key(), [2u8; 32]);
    }

    #[test]
    fn invalid_publishers() {
        // Not did:key.
        assert!(matches!(Publisher::new("did:web:example.com"), Err(PublisherError::NotDidKey(_))));
        // did:key, but not base58btc.
        assert!(matches!(Publisher::new("did:key:u7QEJX5oaWJ"), Err(PublisherError::NotDidKey(_))));
        // base58btc with a character outside the alphabet (`0`, `O`, `I`, `l`).
        assert!(matches!(Publisher::new("did:key:z6Mk0OIl"), Err(PublisherError::NotBase58(_))));
        // Decodes, but not to 0xed01 and 32 bytes: an X25519 key (0xec01).
        let x25519 = format!("did:key:z{}", bs58::encode([[0xec, 0x01].as_slice(), &[7u8; 32]].concat()).into_string());
        assert!(matches!(Publisher::new(x25519), Err(PublisherError::NotEd25519Key(_))));
        // The right multicodec, the wrong length.
        let short = format!("did:key:z{}", bs58::encode([[0xed, 0x01].as_slice(), &[7u8; 31]].concat()).into_string());
        assert!(matches!(Publisher::new(short), Err(PublisherError::NotEd25519Key(_))));
        assert!(Publisher::new("").is_err());
        assert!(Publisher::new("did:key:z").is_err());
    }

    #[test]
    fn valid_names() {
        assert!(SchemaName::new("notes").is_ok());
        assert!(SchemaName::new("keeps-whole").is_ok());
        assert!(SchemaName::new("message.v1").is_ok());
        assert!(SchemaName::new("channel.key-grant").is_ok());
        assert!(SchemaName::new("a.b.c.d").is_ok());
        assert!(SchemaName::new("a1-2.b3").is_ok());
    }

    #[test]
    fn invalid_names() {
        assert!(matches!(SchemaName::new(""), Err(SchemaNameError::Empty)));
        assert!(matches!(SchemaName::new("Notes"), Err(SchemaNameError::SegmentMustStartWithLetter(..)))); // uppercase
        assert!(matches!(SchemaName::new("a..b"), Err(SchemaNameError::EmptySegment(_)))); // empty segment
        assert!(matches!(SchemaName::new(".a"), Err(SchemaNameError::EmptySegment(_))));
        assert!(matches!(SchemaName::new("a."), Err(SchemaNameError::EmptySegment(_))));
        assert!(matches!(SchemaName::new("1notes"), Err(SchemaNameError::SegmentMustStartWithLetter(..)))); // digit first
        assert!(matches!(SchemaName::new("a.-b"), Err(SchemaNameError::SegmentMustStartWithLetter(..)))); // hyphen first
        assert!(matches!(SchemaName::new("notes_extra"), Err(SchemaNameError::InvalidCharacter(_, '_')))); // underscore
        assert!(matches!(SchemaName::new("notes/x"), Err(SchemaNameError::InvalidCharacter(_, '/'))));
        assert!(matches!(SchemaName::new("note\u{e9}"), Err(SchemaNameError::InvalidCharacter(..))));
        assert!(matches!(SchemaName::new("a".repeat(257)), Err(SchemaNameError::TooLong(_))));
    }

    #[test]
    fn valid_identities() {
        for s in [
            format!("{PUB_A}/notes"),
            format!("{PUB_A}/channel.key-grant"),
            format!("{PUB_B}/a.b"),
            format!("{}/keeps-whole", kotton_common::namespace::NSID_PREFIX),
        ] {
            let id = SchemaId::parse(&s).unwrap_or_else(|e| panic!("{s}: {e}"));
            assert_eq!(id.to_string(), s);
        }
        let id = SchemaId::parse(format!("{PUB_A}/message.v1")).unwrap();
        assert_eq!(id.publisher().as_str(), PUB_A);
        assert_eq!(id.name().as_str(), "message.v1");
    }

    #[test]
    fn invalid_identities() {
        assert!(matches!(SchemaId::parse("notes"), Err(SchemaIdError::NoSlash(_)))); // no publisher
        assert!(matches!(SchemaId::parse("sh.kotton.notes"), Err(SchemaIdError::NoSlash(_)))); // the old form
        assert!(matches!(SchemaId::parse(PUB_A), Err(SchemaIdError::NoSlash(_)))); // no name
        assert!(matches!(SchemaId::parse(format!("{PUB_A}/")), Err(SchemaIdError::Name(SchemaNameError::Empty))));
        assert!(matches!(SchemaId::parse(format!("{PUB_A}/Notes")), Err(SchemaIdError::Name(_))));
        assert!(matches!(SchemaId::parse(format!("{PUB_A}/notes/x")), Err(SchemaIdError::Name(_)))); // a second slash is the name's
        assert!(matches!(SchemaId::parse(format!("{PUB_A}//notes")), Err(SchemaIdError::Name(_))));
        assert!(matches!(SchemaId::parse("did:web:example.com/notes"), Err(SchemaIdError::Publisher(_))));
        assert!(matches!(SchemaId::parse(format!("/{PUB_A}/notes")), Err(SchemaIdError::Publisher(_))));
        // The whole identity is bounded: a name that fits alone does not fit beside a publisher.
        let long = format!("{PUB_A}/{}", "a".repeat(MAX_LEN - PUB_A.len()));
        assert!(matches!(SchemaId::parse(&long), Err(SchemaIdError::TooLong(_))));
        let fits = format!("{PUB_A}/{}", "a".repeat(MAX_LEN - PUB_A.len() - 1));
        assert!(SchemaId::parse(&fits).is_ok());
        assert!(SchemaId::new(Publisher::new(PUB_A).unwrap(), SchemaName::new("a".repeat(MAX_LEN - PUB_A.len())).unwrap()).is_err());
    }

    #[test]
    fn display_roundtrip() {
        let s = format!("{PUB_A}/notes");
        let id = SchemaId::parse(&s).unwrap();
        assert_eq!(id.to_string(), s);
        assert_eq!(id.publisher().to_string(), PUB_A);
        assert_eq!(id.name().to_string(), "notes");
        let (p, n) = id.clone().into_parts();
        assert_eq!(SchemaId::new(p, n).unwrap(), id);
        assert_eq!(s.parse::<SchemaId>().unwrap(), id);
        assert_eq!(SchemaId::try_from(s.as_str()).unwrap(), id);
        assert_eq!(SchemaId::try_from(s.clone()).unwrap(), id);
    }

    #[test]
    fn serde_is_the_string_and_validates_on_the_way_in() {
        let s = format!("{PUB_A}/notes");
        let id = SchemaId::parse(&s).unwrap();
        assert_eq!(serde_json::to_string(&id).unwrap(), format!("\"{s}\""));
        let back: SchemaId = serde_json::from_str(&format!("\"{s}\"")).unwrap();
        assert_eq!(back, id);
        assert!(serde_json::from_str::<SchemaId>("\"sh.kotton.notes\"").is_err());
        assert!(serde_json::from_str::<Publisher>("\"did:key:zNotAKey\"").is_err());
        assert!(serde_json::from_str::<SchemaName>("\"Notes\"").is_err());
        assert_eq!(serde_json::to_string(id.publisher()).unwrap(), format!("\"{PUB_A}\""));
        assert_eq!(serde_json::to_string(id.name()).unwrap(), "\"notes\"");
    }
}
