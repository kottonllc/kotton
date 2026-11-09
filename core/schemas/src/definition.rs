// SPDX-License-Identifier: AGPL-3.0-or-later
//! Schema definition — the typed, versioned declaration of a record table.
//!
//! A [`SchemaDefinition`] is what a publisher ships, what an app's manifest cites and what the
//! daemon keeps. It is the contract between the app and the runtime, and it is one JSON
//! document: `publisher`, `name`, `revision`, `fields` and `description`, with the publisher's
//! `signature` beside them and, when the schema was copied from another, `forked_from`.
//!
//! ## Identity and version
//!
//! The protocol's decision *A schema is named by the key that publishes it* fixes both. The
//! identity is `<publisher>/<name>` ([`SchemaDefinition::id`]). The version is the digest of
//! the definition: BLAKE3 over the five members above serialised by the JSON Canonicalization
//! Scheme (RFC 8785; [`crate::canonical`]), written as lowercase hex
//! ([`SchemaDefinition::digest`], [`SchemaDefinition::digest_hex`]). Neither `signature` nor
//! `forked_from` is under the digest: the signature is over it, and provenance is not part of
//! what a reader holds. `description` is under it as a string when there is one, and absent
//! when there is none.
//!
//! The digest refuses a definition whose field default is a non-integer number, since the
//! canonical form of such a number is not written here ([`crate::canonical`] says why).
//!
//! ## Versioning rules
//!
//! - A change to a field is a new `revision` and a new digest of the same schema. An additive
//!   change (a nullable field, or a field with a default) is applied to a store's table on
//!   upgrade; a removal or a rename is refused by the store's migration.
//! - A breaking change is a new schema: a new name under the same publisher.
//! - The publisher states which revisions a reader of a later one may still read; nothing
//!   infers that from the digests. Where a version must be exact, the digest is cited; where
//!   a person reads, the revision is shown.

use crate::canonical::{canonical_json, CanonicalError};
use crate::schema_id::{Publisher, SchemaId, SchemaName};
use crate::SchemaField;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The full typed declaration of a record table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaDefinition {
    /// The key that publishes this schema, as its `did:key`.
    pub publisher: Publisher,

    /// The schema's name under its publisher, e.g. `notes`.
    pub name: SchemaName,

    /// The definition's revision. Starts at 1, and is raised for every change to the fields.
    /// The runtime uses it to decide whether a store's table needs migrating.
    pub revision: u32,

    /// Ordered list of field declarations.
    /// Order determines column order in the resulting SQLite table.
    pub fields: Vec<SchemaField>,

    /// Human-readable description for tooling and the people who read a prompt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

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
    /// retired — so this is never validated. It is not under the digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forked_from: Option<SchemaId>,

    /// The publisher's Ed25519 signature over the definition's 32-byte digest, base64
    /// (standard alphabet, padded). Checked by `kotton_crypto::schema_signature`; a definition
    /// whose signature does not check against its publisher is no schema at all. The core
    /// set compiled into this tree carries none before the first tag, as the protocol's
    /// decision says, and is admitted as core without one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// Why a definition has no digest.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DigestError {
    /// The definition has no canonical form (a non-integer number in a field's default).
    #[error("{0}")]
    Canonical(#[from] CanonicalError),
}

impl SchemaDefinition {
    pub fn new(id: SchemaId, revision: u32, fields: Vec<SchemaField>) -> Self {
        let (publisher, name) = id.into_parts();
        Self {
            publisher,
            name,
            revision,
            fields,
            description: None,
            forked_from: None,
            signature: None,
        }
    }

    pub fn with_forked_from(mut self, origin: SchemaId) -> Self {
        self.forked_from = Some(origin);
        self
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// The schema's identity, `<publisher>/<name>`.
    ///
    /// The two parts were each validated on the way in and a definition is bounded by its
    /// JSON, so the identity's own bound is the only thing left to hold, and a definition
    /// whose name does not fit beside its publisher is refused where it is read
    /// (`try_id`), never here.
    pub fn id(&self) -> SchemaId {
        self.try_id().expect("a definition's publisher and name make an identity")
    }

    /// The schema's identity, or why the two parts do not make one.
    pub fn try_id(&self) -> Result<SchemaId, crate::schema_id::SchemaIdError> {
        SchemaId::new(self.publisher.clone(), self.name.clone())
    }

    /// The document the digest is taken over: `publisher`, `name`, `revision`, `fields` and
    /// `description` (absent when none), as JSON.
    fn digest_document(&self) -> serde_json::Value {
        let mut doc = serde_json::to_value(self).expect("a definition serialises");
        if let Some(members) = doc.as_object_mut() {
            members.remove("signature");
            members.remove("forked_from");
        }
        doc
    }

    /// The definition's canonical form (RFC 8785) — what the digest is over.
    pub fn canonical(&self) -> Result<String, DigestError> {
        Ok(canonical_json(&self.digest_document())?)
    }

    /// The definition's version: BLAKE3 over its canonical form (module doc).
    pub fn digest(&self) -> Result<[u8; 32], DigestError> {
        Ok(*blake3::hash(self.canonical()?.as_bytes()).as_bytes())
    }

    /// [`digest`](Self::digest) as lowercase hex, the form the store and the logs cite.
    pub fn digest_hex(&self) -> Result<String, DigestError> {
        Ok(blake3::hash(self.canonical()?.as_bytes()).to_hex().to_string())
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
    use crate::schema_id::tests::PUB_A;

    fn notes_schema() -> SchemaDefinition {
        SchemaDefinition::new(
            SchemaId::parse(format!("{PUB_A}/notes")).unwrap(),
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
        assert_eq!(back.publisher.as_str(), PUB_A);
        assert_eq!(back.name.as_str(), "notes");
        assert_eq!(back.id().to_string(), format!("{PUB_A}/notes"));
        assert_eq!(back.revision, 1);
        assert_eq!(back.fields.len(), 2);
        assert!(back.signature.is_none());
        // The five members, in the order the protocol's files write them, and nothing else.
        assert_eq!(
            json,
            format!(
                r#"{{"publisher":"{PUB_A}","name":"notes","revision":1,"fields":[{{"name":"title","type":"string","nullable":false}},{{"name":"body","type":"string","nullable":false}}]}}"#
            )
        );
    }

    #[test]
    fn the_old_shape_does_not_read() {
        assert!(serde_json::from_str::<SchemaDefinition>(
            r#"{"nsid":"sh.kotton.notes","version":1,"fields":[]}"#
        )
        .is_err());
    }

    #[test]
    fn field_lookup() {
        let def = notes_schema();
        assert!(def.field("title").is_some());
        assert!(def.field("missing").is_none());
    }

    /// **The fixture the protocol's check shares.** A definition, its canonical form written
    /// out by hand, and its digest as a constant: an implementation that holds the same
    /// definition writes the same two strings.
    const FIXTURE_CANONICAL: &str = "{\"description\":\"A note: a title, a body and the tags on it. \\\"Quoted\\\", with a tab\\t and \u{e9}.\",\"fields\":[{\"name\":\"title\",\"nullable\":false,\"type\":\"string\"},{\"name\":\"body\",\"nullable\":false,\"type\":\"string\"},{\"default\":[],\"name\":\"tags\",\"nullable\":false,\"type\":{\"list\":\"string\"}},{\"default\":0,\"name\":\"stars\",\"nullable\":true,\"type\":\"int\"}],\"name\":\"note\",\"publisher\":\"did:key:z6MkeXBLjYiSvqnhFb6D7sHm8yKm4jV45wwBFRaatf1cfZ76\",\"revision\":2}";
    const FIXTURE_DIGEST: &str = "dc71c0fad492119ac60d10e8489b43439c152786c201b3f41e63c83fb2e188c2";

    fn fixture() -> SchemaDefinition {
        SchemaDefinition::new(
            SchemaId::parse(format!("{PUB_A}/note")).unwrap(),
            2,
            vec![
                SchemaField::required("title", FieldType::String),
                SchemaField::required("body", FieldType::String),
                SchemaField::with_default(
                    "tags",
                    FieldType::List(Box::new(FieldType::String)),
                    serde_json::json!([]),
                ),
                SchemaField { name: "stars".into(), field_type: FieldType::Int, nullable: true, default: Some(serde_json::json!(0)) },
            ],
        )
        .with_description("A note: a title, a body and the tags on it. \"Quoted\", with a tab\t and \u{e9}.")
        // Neither of these is under the digest.
        .with_forked_from(SchemaId::parse(format!("{PUB_A}/notes")).unwrap())
    }

    #[test]
    fn the_canonical_form_and_digest_are_the_fixtures() {
        let mut def = fixture();
        assert_eq!(def.canonical().unwrap(), FIXTURE_CANONICAL);
        assert_eq!(def.digest_hex().unwrap(), FIXTURE_DIGEST);
        assert_eq!(def.digest().unwrap(), *blake3::hash(FIXTURE_CANONICAL.as_bytes()).as_bytes());
        assert_eq!(hex_of(&def.digest().unwrap()), FIXTURE_DIGEST);
        // A signature and a provenance change neither.
        def.signature = Some("c2ln".into());
        def.forked_from = None;
        assert_eq!(def.digest_hex().unwrap(), FIXTURE_DIGEST);
        // A change to anything under it changes the digest.
        for change in [
            |d: &mut SchemaDefinition| d.revision = 3,
            |d: &mut SchemaDefinition| d.description = None,
            |d: &mut SchemaDefinition| d.name = SchemaName::new("notes").unwrap(),
            |d: &mut SchemaDefinition| d.publisher = Publisher::new(crate::schema_id::tests::PUB_B).unwrap(),
            |d: &mut SchemaDefinition| d.fields.pop().map(drop).unwrap_or(()),
            |d: &mut SchemaDefinition| d.fields[0].nullable = true,
        ] {
            let mut changed = fixture();
            change(&mut changed);
            assert_ne!(changed.digest_hex().unwrap(), FIXTURE_DIGEST);
        }
    }

    #[test]
    fn a_description_is_absent_when_there_is_none() {
        let def = notes_schema();
        assert!(!def.canonical().unwrap().contains("description"));
        let described = notes_schema().with_description("x");
        assert!(described.canonical().unwrap().contains("\"description\":\"x\""));
        assert_ne!(def.digest_hex().unwrap(), described.digest_hex().unwrap());
    }

    #[test]
    fn a_float_default_has_no_digest_and_the_refusal_names_the_field() {
        let mut def = notes_schema();
        def.fields.push(SchemaField::with_default("ratio", FieldType::Float, serde_json::json!(0.5)));
        let err = def.digest_hex().unwrap_err();
        assert!(err.to_string().contains("$.fields[2].default"), "{err}");
        assert!(err.to_string().contains("RFC 8785"), "{err}");
    }

    /// The three files the protocol publishes, their canonical forms and their digests, as
    /// constants the protocol's check can hold beside its files.
    #[test]
    fn the_protocol_files_canonical_forms_and_digests() {
        const KOTTON: &str = "did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB";
        let cases: [(&str, &str, &str); 3] = [
            (
                include_str!("../schemas/kotton/secret.json"),
                "{\"description\":\"A password or a token the person keeps in their keychain.\",\"fields\":[{\"name\":\"label\",\"nullable\":false,\"type\":\"string\"},{\"name\":\"value\",\"nullable\":false,\"type\":\"string\"},{\"name\":\"kind\",\"nullable\":false,\"type\":\"string\"},{\"name\":\"note\",\"nullable\":true,\"type\":\"string\"}],\"name\":\"secret\",\"publisher\":\"did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB\",\"revision\":1}",
                "0dde03f0db6c052c3aef0050a3f02b1289516a0802b7bfccf9d14d0e235ff8cf",
            ),
            (
                include_str!("../schemas/kotton/keeps-whole.json"),
                "{\"description\":\"That one of the person's devices keeps one of their drives whole.\",\"fields\":[{\"name\":\"device\",\"nullable\":false,\"type\":\"string\"},{\"name\":\"drive\",\"nullable\":false,\"type\":\"string\"}],\"name\":\"keeps-whole\",\"publisher\":\"did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB\",\"revision\":1}",
                "fe72403dbd67195aa91d7ed7f0ad79575797755812f7cfcc359adba7c38248fb",
            ),
            (
                include_str!("../schemas/kotton/access-log.json"),
                "{\"description\":\"One thing a device's daemon was asked: who asked, through which door, to read or write what, and when.\",\"fields\":[{\"name\":\"device\",\"nullable\":false,\"type\":\"string\"},{\"name\":\"at\",\"nullable\":false,\"type\":\"datetime\"},{\"name\":\"asker\",\"nullable\":false,\"type\":\"string\"},{\"name\":\"door\",\"nullable\":false,\"type\":\"string\"},{\"name\":\"act\",\"nullable\":false,\"type\":\"string\"},{\"name\":\"what\",\"nullable\":false,\"type\":\"string\"}],\"name\":\"access-log\",\"publisher\":\"did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB\",\"revision\":1}",
                "c528463861f2da609647040008a307f99c06e9bcf34e81ccfba23afff7dbdb55",
            ),
        ];
        for (file, canonical, digest) in cases {
            let def: SchemaDefinition = serde_json::from_str(file).unwrap();
            assert_eq!(def.publisher.as_str(), KOTTON);
            assert!(def.signature.is_none(), "unsigned before the first tag");
            assert_eq!(def.canonical().unwrap(), canonical);
            assert_eq!(def.digest_hex().unwrap(), digest, "{}", def.name);
        }
    }

    fn hex_of(bytes: &[u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
