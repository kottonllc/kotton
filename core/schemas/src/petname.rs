// SPDX-License-Identifier: AGPL-3.0-or-later
//! A petname: the person's own name for a key, kept as a record of Kotton's `petname` schema.
//!
//! A schema is named by the key that publishes it (the protocol's decision of that title), and
//! a grant prompt says who stands behind a schema or an app only by the person's own name for
//! the publisher's key, or by its absence. A petname is that name: `key`, a `did:key`, and
//! `name`, what the person calls it. Kept in Personal, one record per key, and kept from every
//! app ([`crate::CoreSchema::is_kept_from_apps`]), since a prompt trusts what it says.
//!
//! What is held here, for both halves to share:
//!
//! - [`check`]: the rules a petname's body is held to. The record daemon asks it at insert,
//!   for this one identity (`kotton_record::record_cmds`), so no record that breaks them is
//!   written on this device; the reader asks it of every stored record, so one that breaks
//!   them anyway (written before the rule, or merged from another device) is never a name.
//! - [`Petnames`]: the reader's answer, built from the stored records: for a key, the person's
//!   name for it or none; for a name, the keys it names. `kotton` names Kotton's publisher on
//!   every device with no record, and a record for that key replaces it.
//!
//! A petname is the person's, read on their own devices and shown to them alone: it is never
//! sent with a request, so it joins nothing beyond the record it is.

use crate::schema_id::Publisher;
use kotton_common::namespace::NSID_PREFIX;
use serde_json::Value;
use thiserror::Error;

/// A name is at most this many characters.
pub const MAX_NAME_CHARS: usize = 64;

/// The name every device gives Kotton's publisher without a record.
pub const KOTTON: &str = "kotton";

/// A petname, as a record holds it and the rules allow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Petname {
    /// The key it names.
    pub key: Publisher,
    /// What the person calls it.
    pub name: String,
}

/// Why a body is not a petname. Each names the rule broken, and none says more of the body
/// than the name, so a refusal never repeats a key or any other field.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PetnameError {
    #[error("a petname is an object of `key` and `name`")]
    NotAnObject,
    #[error("a petname's `key` is the did:key it names, as a string, and there is none")]
    NoKey,
    #[error("a petname's `key` is not a did:key (`did:key:z…`, an Ed25519 key)")]
    KeyNotDidKey,
    #[error("a petname's `name` is a string, and there is none")]
    NoName,
    #[error("a petname's `name` is empty")]
    Empty,
    #[error("a petname's `name` is at most {MAX_NAME_CHARS} characters, and this one is {0}")]
    TooLong(usize),
    #[error("a petname's `name` holds no `/`, which separates it from a schema's name: {0:?}")]
    Slash(String),
    #[error("a petname's `name` holds no control, bidirectional-formatting or invisible character")]
    Control,
    #[error("a petname's `name` does not begin with `did:`, so it is never read as a key: {0:?}")]
    DidPrefix(String),
    #[error("`kotton` names Kotton's publisher and no other key, in any case and with any spaces around it")]
    KottonIsKottons,
}

/// Whether `c` is a character no name may hold, and none is shown of another party's text
/// (`kotton_shell::grant_prompt::others`): a control character; one of Unicode's
/// bidirectional formatting characters, which reorder the line they sit in; the line and
/// paragraph separators (U+2028, U+2029), which break it; the zero-width and invisible ones
/// (U+200B to U+200D, U+2060 to U+2064, U+FEFF), which make two different strings look alike;
/// and the tag characters (U+E0000 to U+E007F), which carry text no one sees.
pub fn is_hostile_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}'
                | '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
                | '\u{E0000}'..='\u{E007F}'
        )
}

/// `name` as names are compared for sameness: spaces around it trimmed, each run of
/// whitespace one space, and the case folded. `kotton` is reserved by it, and two keys whose
/// names compare the same by it are said to share one, since a person reading the two cannot
/// tell them apart.
pub fn folded(name: &str) -> String {
    name.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase()
}

/// Hold `name`, given to `key`, to the rules: not empty, at most [`MAX_NAME_CHARS`]
/// characters, no `/` and no character [`is_hostile_char`] names, not beginning with `did:`,
/// and [`KOTTON`] for Kotton's publisher alone, compared [`folded`] (so `Kotton` and
/// `kotton ` are Kotton's too).
pub fn check_name(key: &Publisher, name: &str) -> Result<(), PetnameError> {
    if name.is_empty() {
        return Err(PetnameError::Empty);
    }
    if name.chars().any(is_hostile_char) {
        return Err(PetnameError::Control);
    }
    let chars = name.chars().count();
    if chars > MAX_NAME_CHARS {
        return Err(PetnameError::TooLong(chars));
    }
    if name.contains('/') {
        return Err(PetnameError::Slash(name.to_owned()));
    }
    if name.starts_with("did:") {
        return Err(PetnameError::DidPrefix(name.to_owned()));
    }
    if folded(name) == KOTTON && key.as_str() != NSID_PREFIX {
        return Err(PetnameError::KottonIsKottons);
    }
    Ok(())
}

/// Hold a petname record's body to the rules, and read it: `key` parses as a `did:key`
/// ([`Publisher`]) and `name` keeps [`check_name`]. Fields beside the two are not looked at;
/// an insert refuses an undeclared one before this is asked.
pub fn check(body: &Value) -> Result<Petname, PetnameError> {
    let body = body.as_object().ok_or(PetnameError::NotAnObject)?;
    let key = body.get("key").and_then(Value::as_str).ok_or(PetnameError::NoKey)?;
    let key = Publisher::new(key).map_err(|_| PetnameError::KeyNotDidKey)?;
    let name = body.get("name").and_then(Value::as_str).ok_or(PetnameError::NoName)?;
    check_name(&key, name)?;
    Ok(Petname { key, name: name.to_owned() })
}

/// The person's names for keys, as their stored petname records give them: one per key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Petnames {
    names: Vec<Petname>,
}

impl Petnames {
    /// The names `records` give, with [`KOTTON`] for Kotton's publisher unless a record names
    /// that key. A record that breaks the rules ([`check`]) is ignored, never a name. Where two
    /// records name one key (one merged from another device before this one replaced it), the
    /// one filed last wins, by `_filed_at` as a query answers it, then by `_id`, so every
    /// device that holds both reads the same name.
    pub fn from_records<'a>(records: impl IntoIterator<Item = &'a Value>) -> Self {
        let mut held: Vec<(i64, String, Petname)> = records
            .into_iter()
            .filter_map(|r| {
                let petname = check(r).ok()?;
                let filed = r.get("_filed_at").and_then(Value::as_i64).unwrap_or(0);
                let id = r.get("_id").or_else(|| r.get("id")).and_then(Value::as_str).unwrap_or("").to_owned();
                Some((filed, id, petname))
            })
            .collect();
        held.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
        let mut names: Vec<Petname> = Vec::new();
        for (_, _, petname) in held {
            names.retain(|p| p.key != petname.key);
            names.push(petname);
        }
        let kotton = Publisher::from_static(NSID_PREFIX);
        if !names.iter().any(|p| p.key == kotton) {
            names.push(Petname { key: kotton, name: KOTTON.to_owned() });
        }
        Self { names }
    }

    /// The names a device with no petname record gives: [`KOTTON`] for Kotton's publisher.
    pub fn built_in() -> Self {
        Self::from_records(std::iter::empty())
    }

    /// The person's name for `key`, or `None` when they gave it none.
    pub fn name_for(&self, key: &Publisher) -> Option<&str> {
        self.names.iter().find(|p| &p.key == key).map(|p| p.name.as_str())
    }

    /// The keys `name` names, exactly as written: none, one, or several (two keys the person
    /// gave one name).
    pub fn keys_named(&self, name: &str) -> Vec<&Publisher> {
        self.names.iter().filter(|p| p.name == name).map(|p| &p.key).collect()
    }

    /// The keys whose names compare the same as `name` when [`folded`]: the keys a person
    /// reading `name` could take it for. More than one, and a prompt showing the name says it
    /// is shared.
    pub fn keys_called(&self, name: &str) -> Vec<&Publisher> {
        let name = folded(name);
        self.names.iter().filter(|p| folded(&p.name) == name).map(|p| &p.key).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ACME: &str = "did:key:z6MkeXBLjYiSvqnhFb6D7sHm8yKm4jV45wwBFRaatf1cfZ76";

    fn acme() -> Publisher {
        Publisher::from_static(ACME)
    }

    fn kotton() -> Publisher {
        Publisher::from_static(NSID_PREFIX)
    }

    /// Each rule refuses what it names, and says no more of the body than the name.
    #[test]
    fn the_name_rules() {
        assert_eq!(check_name(&acme(), "My Bank"), Ok(()));
        assert_eq!(check_name(&acme(), &"a".repeat(MAX_NAME_CHARS)), Ok(()));
        assert_eq!(check_name(&acme(), ""), Err(PetnameError::Empty));
        let long = "é".repeat(MAX_NAME_CHARS + 1);
        assert_eq!(check_name(&acme(), &long), Err(PetnameError::TooLong(MAX_NAME_CHARS + 1)));
        assert!(matches!(check_name(&acme(), "my/bank"), Err(PetnameError::Slash(_))));
        assert_eq!(check_name(&acme(), "bank\u{7}"), Err(PetnameError::Control));
        assert_eq!(check_name(&acme(), "bank\n"), Err(PetnameError::Control));
        assert_eq!(check_name(&acme(), "\u{202E}knab"), Err(PetnameError::Control));
        assert_eq!(check_name(&acme(), "bank\u{2066}"), Err(PetnameError::Control));
        assert!(matches!(check_name(&acme(), "did:key:z6Mk"), Err(PetnameError::DidPrefix(_))));
        for invisible in ["\u{2028}", "\u{2029}", "\u{200B}", "\u{200D}", "\u{2060}", "\u{FEFF}", "\u{E0041}"] {
            assert_eq!(check_name(&acme(), &format!("My{invisible} Bank")), Err(PetnameError::Control), "{invisible:?}");
        }
        for kotton_too in [KOTTON, "Kotton", "KOTTON", "kotton ", " Kotton\u{3000}"] {
            assert_eq!(check_name(&acme(), kotton_too), Err(PetnameError::KottonIsKottons), "{kotton_too:?}");
        }
        assert_eq!(check_name(&kotton(), KOTTON), Ok(()));
        assert_eq!(check_name(&kotton(), "Kotton"), Ok(()));
        assert_eq!(check_name(&acme(), "Kotton LLC"), Ok(()), "only `kotton` itself is Kotton's");
    }

    /// A body is a petname only with a `did:key` for `key` and a name the rules allow; a
    /// refusal of a bad key does not repeat it.
    #[test]
    fn a_body_is_held_to_the_rules() {
        let ok = check(&json!({ "key": ACME, "name": "Acme" })).unwrap();
        assert_eq!(ok, Petname { key: acme(), name: "Acme".into() });
        assert_eq!(check(&json!("Acme")), Err(PetnameError::NotAnObject));
        assert_eq!(check(&json!({ "name": "Acme" })), Err(PetnameError::NoKey));
        let bad = check(&json!({ "key": "did:web:secret-host.example", "name": "Acme" })).unwrap_err();
        assert_eq!(bad, PetnameError::KeyNotDidKey);
        assert!(!bad.to_string().contains("secret-host"), "{bad}");
        assert_eq!(check(&json!({ "key": ACME })), Err(PetnameError::NoName));
        assert_eq!(check(&json!({ "key": ACME, "name": 7 })), Err(PetnameError::NoName));
    }

    /// With no record, `kotton` names Kotton's publisher and nothing names another key.
    #[test]
    fn kotton_is_built_in() {
        let names = Petnames::built_in();
        assert_eq!(names.name_for(&kotton()), Some(KOTTON));
        assert_eq!(names.keys_named(KOTTON), vec![&kotton()]);
        assert_eq!(names.name_for(&acme()), None);
        assert!(names.keys_named("acme").is_empty());
    }

    /// A record for Kotton's key replaces the built-in name, so `kotton` then names none.
    #[test]
    fn a_record_replaces_the_built_in_name() {
        let records = [json!({ "key": NSID_PREFIX, "name": "Kotton LLC", "_id": "p1", "_filed_at": 1 })];
        let names = Petnames::from_records(&records);
        assert_eq!(names.name_for(&kotton()), Some("Kotton LLC"));
        assert!(names.keys_named(KOTTON).is_empty());
    }

    /// Two keys given one name are both named by it, so a reader can refuse it as ambiguous.
    #[test]
    fn a_name_can_name_several_keys() {
        let other = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let records = [
            json!({ "key": ACME, "name": "bank", "_id": "p1", "_filed_at": 1 }),
            json!({ "key": other, "name": "bank", "_id": "p2", "_filed_at": 2 }),
        ];
        let names = Petnames::from_records(&records);
        let keys: Vec<&str> = names.keys_named("bank").iter().map(|k| k.as_str()).collect();
        assert_eq!(keys, vec![ACME, other]);
    }

    /// Names that read alike are called alike: case and spacing aside, two keys share one.
    #[test]
    fn names_that_read_alike_are_called_alike() {
        let other = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let records = [
            json!({ "key": ACME, "name": "My Bank", "_id": "p1", "_filed_at": 1 }),
            json!({ "key": other, "name": " my  BANK", "_id": "p2", "_filed_at": 2 }),
        ];
        let names = Petnames::from_records(&records);
        assert_eq!(names.keys_named("My Bank").len(), 1, "the short form still resolves exactly");
        let keys: Vec<&str> = names.keys_called("My Bank").iter().map(|k| k.as_str()).collect();
        assert_eq!(keys, vec![ACME, other]);
        assert_eq!(folded(" My\t Bank "), "my bank");
    }

    /// A stored record that breaks a rule is never a name: one naming another key `kotton`
    /// leaves the built-in name, and a name with a control character is ignored.
    #[test]
    fn a_stored_record_that_breaks_the_rules_is_ignored() {
        let records = [
            json!({ "key": ACME, "name": "kotton", "_id": "p1", "_filed_at": 1 }),
            json!({ "key": ACME, "name": "evil\u{202E}", "_id": "p2", "_filed_at": 2 }),
            json!({ "key": "not a key", "name": "x", "_id": "p3", "_filed_at": 3 }),
        ];
        let names = Petnames::from_records(&records);
        assert_eq!(names.name_for(&acme()), None);
        assert_eq!(names.keys_named(KOTTON), vec![&kotton()]);
        assert!(names.keys_named("x").is_empty());
    }

    /// Two records for one key: the one filed last is the name, on every device.
    #[test]
    fn of_two_records_for_a_key_the_last_filed_wins() {
        let records = [
            json!({ "key": ACME, "name": "new", "_id": "b", "_filed_at": 5 }),
            json!({ "key": ACME, "name": "old", "_id": "a", "_filed_at": 4 }),
        ];
        assert_eq!(Petnames::from_records(&records).name_for(&acme()), Some("new"));
    }
}
