// SPDX-License-Identifier: AGPL-3.0-or-later
//! The person's names for keys, read on this device, and what a person types for a schema.
//!
//! A schema is named by the key that publishes it (the protocol's decision of that title):
//! `did:key:…/<name>`, long to type and impossible to read at a glance. So a person types
//! `<petname>/<name>` too, the petname being their own name for the publisher's key, a record
//! in Personal ([`kotton_schemas::petname`]). `kotton` names Kotton's publisher on every device
//! without one, so `kotton/notes` is Kotton's notes on a device fresh from setup.
//!
//! - [`read`]: **the one reader of petnames**, for every verb that takes or prints a schema
//!   and for the grant prompt. It reads Personal through the person's own session; a stored
//!   record that breaks a petname's rules is never a name, and a read that fails says so.
//! - [`SchemaArg`]: the one parser of a typed schema, both forms, and [`SchemaArg::resolve`],
//!   which turns the short form into the identity against what [`read`] gave.
//! - [`said`]: a schema as output prints it, the short form wherever the person's name for
//!   the publisher reads back as that publisher alone, else the whole identity.
//!
//! The resolution is the device's: a petname never leaves it in a request, which carries the
//! whole identity alone.

use kotton_common::namespace::NSID_PETNAME;
use kotton_schemas::petname::is_hostile_char;
use kotton_schemas::{Petnames, SchemaId, SchemaName};
use kotton_wire::ipc::PERSONAL_ROOT;

/// What a person may type for a schema, said in a refusal and in help.
pub const FORMS: &str = "`<petname>/<name>` (such as `kotton/notes`) or `did:key:…/<name>`";

/// The person's names for keys, read from Personal through their own session, or why they
/// could not be.
///
/// A session that is not the person's own terminal is refused `petname`, which is kept from
/// apps, and a daemon can fail a read; either way this says so, and a caller that shows who
/// stands behind something says it could not read the names rather than show every key as
/// unnamed (`crate::grant_prompt`). Nothing it reads is shown that breaks a petname's rules.
pub async fn read(client: &mut kotton::KottonClient, user_id: &str) -> Result<Petnames, String> {
    client
        .record_query_in(user_id, Some(PERSONAL_ROOT), None, NSID_PETNAME, vec![], None, None)
        .await
        .map(|records| Petnames::from_records(&records))
        .map_err(|e| e.to_string())
}

/// [`read`], for resolving what a person typed: the names every device gives (`kotton`
/// alone) when the person's could not be read, so a short form of another name is refused as
/// one no key has. Never for saying who stands behind something; that is [`read`]'s.
pub async fn read_for_typing(client: &mut kotton::KottonClient, user_id: &str) -> Petnames {
    read(client, user_id).await.unwrap_or_else(|_| Petnames::built_in())
}

/// A schema as typed, parsed and not yet resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaArg {
    /// `did:key:…/<name>`: the identity, whole.
    Full(SchemaId),
    /// `<petname>/<name>`: the person's name for the publisher's key, and the schema's name.
    Short { petname: String, name: SchemaName },
}

impl SchemaArg {
    /// Parse a typed schema. A word beginning `did:` is the whole identity; any other is a
    /// petname, a `/`, and a schema's name (a petname holds no `/` and never begins `did:`,
    /// so the two cannot be mistaken).
    pub fn parse(word: &str) -> Result<Self, String> {
        if word.starts_with("did:") {
            return SchemaId::parse(word)
                .map(Self::Full)
                .map_err(|e| format!("'{}' is not a schema identity: {e}", shown(word)));
        }
        let Some((petname, name)) = word.split_once('/') else {
            return Err(format!("'{}' is not a schema: a schema is {FORMS}", shown(word)));
        };
        if petname.is_empty() || petname.chars().any(is_hostile_char) {
            return Err(format!("'{}' is not a schema: a schema is {FORMS}", shown(word)));
        }
        let name = SchemaName::new(name).map_err(|e| format!("'{}' is not a schema: {e}", shown(word)))?;
        Ok(Self::Short { petname: petname.to_owned(), name })
    }

    /// The identity this names, on this device: the short form's petname must name exactly
    /// one key. A petname no key has is refused saying so; one that names several is refused
    /// naming them, since only the whole identity can say which.
    pub fn resolve(&self, names: &Petnames) -> Result<SchemaId, String> {
        let (petname, name) = match self {
            Self::Full(id) => return Ok(id.clone()),
            Self::Short { petname, name } => (petname, name),
        };
        match names.keys_named(petname).as_slice() {
            [] => Err(format!(
                "no key has the name '{petname}' on this device, so '{petname}/{name}' names no schema; \
                 type the whole identity, `did:key:…/{name}`"
            )),
            [key] => SchemaId::new((*key).clone(), name.clone()).map_err(|e| e.to_string()),
            several => Err(format!(
                "'{petname}' names {} keys ({}), so '{petname}/{name}' could be any of their schemas; \
                 type the whole identity, `did:key:…/{name}`",
                several.len(),
                several.iter().map(|k| k.as_str()).collect::<Vec<_>>().join(", ")
            )),
        }
    }
}

/// `schema` as output prints it: `<petname>/<name>` when the person's name for its publisher
/// names that key alone, so that what is printed resolves back to it; else the whole identity.
pub fn said(schema: &SchemaId, names: &Petnames) -> String {
    match names.name_for(schema.publisher()) {
        Some(petname) if names.keys_named(petname).len() == 1 => format!("{petname}/{}", schema.name()),
        _ => schema.to_string(),
    }
}

/// A typed word as a refusal repeats it, with any character that could rewrite the line
/// escaped.
fn shown(word: &str) -> String {
    word.chars().map(|c| if is_hostile_char(c) { c.escape_unicode().to_string() } else { c.to_string() }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotton_common::namespace::{NSID_NOTES, NSID_PREFIX};
    use serde_json::json;

    const ACME: &str = "did:key:z6MkeXBLjYiSvqnhFb6D7sHm8yKm4jV45wwBFRaatf1cfZ76";
    const OTHER: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    fn names(records: &[serde_json::Value]) -> Petnames {
        Petnames::from_records(records)
    }

    /// Both forms parse; the short form resolves by the person's names, `kotton` built in.
    #[test]
    fn both_forms_parse_and_resolve() {
        let full = SchemaArg::parse(NSID_NOTES).unwrap();
        assert_eq!(full, SchemaArg::Full(SchemaId::from_static(NSID_NOTES)));
        let short = SchemaArg::parse("kotton/notes").unwrap();
        assert!(matches!(&short, SchemaArg::Short { petname, .. } if petname == "kotton"));
        let built_in = Petnames::built_in();
        assert_eq!(short.resolve(&built_in).unwrap(), SchemaId::from_static(NSID_NOTES));
        assert_eq!(full.resolve(&built_in).unwrap(), SchemaId::from_static(NSID_NOTES));

        let mine = names(&[json!({ "key": ACME, "name": "My Bank", "_id": "p1", "_filed_at": 1 })]);
        let statement = SchemaArg::parse("My Bank/statement").unwrap().resolve(&mine).unwrap();
        assert_eq!(statement.to_string(), format!("{ACME}/statement"));
    }

    /// A word that is neither form is refused, saying both.
    #[test]
    fn a_word_that_is_neither_form_is_refused() {
        for word in ["notes", "/notes", "kotton/", "kotton/Notes", "did:key:nope/notes", "sh.kotton.notes", "a\u{202E}/notes"] {
            let err = SchemaArg::parse(word).expect_err(word);
            assert!(err.contains("not a schema"), "{word}: {err}");
            assert!(!err.contains('\u{202E}'), "the refusal repeated a bidi override: {err}");
        }
    }

    /// An unknown petname is refused saying no key has that name.
    #[test]
    fn an_unknown_petname_is_refused() {
        let err = SchemaArg::parse("acme/notes").unwrap().resolve(&Petnames::built_in()).unwrap_err();
        assert!(err.contains("no key has the name 'acme'"), "{err}");
    }

    /// A petname that names several keys is refused, naming the keys.
    #[test]
    fn an_ambiguous_petname_is_refused_naming_the_keys() {
        let two = names(&[
            json!({ "key": ACME, "name": "bank", "_id": "p1", "_filed_at": 1 }),
            json!({ "key": OTHER, "name": "bank", "_id": "p2", "_filed_at": 2 }),
        ]);
        let err = SchemaArg::parse("bank/statement").unwrap().resolve(&two).unwrap_err();
        assert!(err.contains("names 2 keys") && err.contains(ACME) && err.contains(OTHER), "{err}");
        // Printed whole, since the short form would not resolve back.
        let id = SchemaId::parse(format!("{ACME}/statement")).unwrap();
        assert_eq!(said(&id, &two), id.to_string());
    }

    /// Output prints the short form when the publisher has a name, else the whole identity;
    /// a renamed Kotton prints by the person's name.
    #[test]
    fn output_prints_the_petname_form_when_there_is_one() {
        let notes = SchemaId::from_static(NSID_NOTES);
        assert_eq!(said(&notes, &Petnames::built_in()), "kotton/notes");
        let theirs = SchemaId::parse(format!("{ACME}/notes")).unwrap();
        assert_eq!(said(&theirs, &Petnames::built_in()), theirs.to_string());
        let renamed = names(&[json!({ "key": NSID_PREFIX, "name": "K", "_id": "p1", "_filed_at": 1 })]);
        assert_eq!(said(&notes, &renamed), "K/notes");
    }
}
