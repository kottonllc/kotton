// SPDX-License-Identifier: AGPL-3.0-or-later
//! What a grant prompt says of who stands behind what it asks.
//!
//! A schema is named by the key that publishes it (the protocol's decision of that title), and
//! the decision fixes what a prompt may say. **A schema's name is shown as its publisher wrote
//! it**, since it says what the records are and claims nothing about who stands behind them.
//! **Who stands behind it is said only by the person's own name for the publisher's key, or by
//! its absence**: "your *notes* records from **kotton**" when the person (or the name every
//! device gives Kotton's key) named it, "from a publisher you have not named" when not. An app
//! is shown the same way, by the key that signed its manifest; an app with no `[publisher]`
//! block is "from an app nobody signed". When the app's publisher and a schema's differ, the
//! prompt says so on a line of its own. A string a publisher or an app chose (an app's name,
//! its id, a path it suggests, a label) is never shown as who stands behind anything, and is
//! printed with every control and bidirectional-formatting character removed, so it cannot
//! rewrite the line it sits in or the lines around it.
//!
//! Every function here is pure, so each case's text is held by a test; the asking (the first
//! meeting with a key, where the person decides what to call it) is the sideload's.

use kotton_schemas::petname::is_hostile_char;
use kotton_schemas::{CapabilityGrant, CapabilityKind, CapabilityTarget, Petnames, Publisher, SchemaId};

/// Said of a key the person has not named.
pub const NOT_NAMED: &str = "a publisher you have not named";

/// Said of an app with no `[publisher]` block.
pub const UNSIGNED: &str = "an app nobody signed";

/// Said of an app whose `[publisher]` block names a key its signature does not check against.
pub const NOT_CHECKED: &str = "an app whose signature does not check";

/// Said, on a line of its own, under a schema its app's publisher did not publish.
pub const DIFFERS: &str = "the app's publisher did not publish this schema";

/// Who signed an app, as the prompt may say it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signer {
    /// The manifest's signature checked against this key.
    Key(Publisher),
    /// The manifest has no `[publisher]` block.
    Nobody,
    /// The manifest names a key, and its signature does not check against it (the install
    /// refuses it).
    NotChecked,
}

impl Signer {
    /// The signer of a manifest that names `publisher_did`, or none, whose signature the
    /// daemon's preview found `verified` or not.
    pub fn of(publisher_did: Option<&str>, verified: bool) -> Self {
        match (publisher_did, verified) {
            (None, _) => Self::Nobody,
            (Some(did), true) => Publisher::new(did).map(Self::Key).unwrap_or(Self::NotChecked),
            (Some(_), false) => Self::NotChecked,
        }
    }

    /// The key, when there is one that checked.
    pub fn key(&self) -> Option<&Publisher> {
        match self {
            Self::Key(key) => Some(key),
            _ => None,
        }
    }
}

/// `text`, chosen by an app or a publisher, as a prompt prints it: every control and
/// bidirectional-formatting character removed.
pub fn plain(text: &str) -> String {
    text.chars().filter(|c| !is_hostile_char(*c)).collect()
}

/// Who stands behind `key`, as a prompt says it: the person's name for it, or that they gave
/// none.
pub fn who(key: &Publisher, names: &Petnames) -> String {
    names.name_for(key).map(str::to_owned).unwrap_or_else(|| NOT_NAMED.to_owned())
}

/// The prompt's first line: the app as it calls itself, and who signed it.
pub fn app_line(name: &str, version: &str, app_id: &str, signer: &Signer, names: &Petnames) -> String {
    let from = match signer {
        Signer::Key(key) => who(key, names),
        Signer::Nobody => UNSIGNED.to_owned(),
        Signer::NotChecked => NOT_CHECKED.to_owned(),
    };
    format!("{} {} ({}) from {from}", plain(name), plain(version), plain(app_id))
}

/// A schema grant as the prompt says it: "read your notes records from kotton".
pub fn schema_line(kind: &CapabilityKind, schema: &SchemaId, names: &Petnames) -> String {
    let verb = match kind {
        CapabilityKind::Read => "read",
        CapabilityKind::Write => "write",
        CapabilityKind::Use => "use",
    };
    format!("{verb} your {} records from {}", schema.name(), who(schema.publisher(), names))
}

/// The lines a requested grant takes in the prompt, unindented: a schema grant by
/// [`schema_line`], with [`DIFFERS`] under it when the app's key checked and is not the
/// schema's publisher; any other as its capability string, with what the app chose in it
/// made [`plain`].
pub fn grant_lines(grant: &CapabilityGrant, signer: &Signer, names: &Petnames) -> Vec<String> {
    match &grant.target {
        CapabilityTarget::Schema { nsid } => {
            let mut lines = vec![schema_line(&grant.kind, nsid, names)];
            if signer.key().is_some_and(|key| key != nsid.publisher()) {
                lines.push(format!("  {DIFFERS}"));
            }
            lines
        }
        _ => vec![plain(&grant.display_string())],
    }
}

/// The keys a prompt shows that the person has not named, each once, in the order shown:
/// the app's signer, then each schema's publisher.
pub fn unnamed_keys(signer: &Signer, requested: &[CapabilityGrant], names: &Petnames) -> Vec<Publisher> {
    let schemas = requested.iter().filter_map(|g| match &g.target {
        CapabilityTarget::Schema { nsid } => Some(nsid.publisher().clone()),
        _ => None,
    });
    let mut keys: Vec<Publisher> = Vec::new();
    for key in signer.key().cloned().into_iter().chain(schemas) {
        if names.name_for(&key).is_none() && !keys.contains(&key) {
            keys.push(key);
        }
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotton_common::namespace::{NSID_NOTES, NSID_PREFIX};
    use serde_json::json;

    const ACME: &str = "did:key:z6MkeXBLjYiSvqnhFb6D7sHm8yKm4jV45wwBFRaatf1cfZ76";

    fn acme() -> Publisher {
        Publisher::from_static(ACME)
    }

    fn named_acme() -> Petnames {
        Petnames::from_records(&[json!({ "key": ACME, "name": "My Bank", "_id": "p1", "_filed_at": 1 })])
    }

    fn statement() -> SchemaId {
        SchemaId::parse(format!("{ACME}/statement")).unwrap()
    }

    /// A schema whose publisher the person named: its name as written, from their name.
    #[test]
    fn a_named_schema_publisher() {
        let line = schema_line(&CapabilityKind::Read, &statement(), &named_acme());
        assert_eq!(line, "read your statement records from My Bank");
        let notes = schema_line(&CapabilityKind::Write, &SchemaId::from_static(NSID_NOTES), &Petnames::built_in());
        assert_eq!(notes, "write your notes records from kotton");
    }

    /// A schema whose publisher the person has not named: says so, and names no key.
    #[test]
    fn an_unnamed_schema_publisher() {
        let line = schema_line(&CapabilityKind::Read, &statement(), &Petnames::built_in());
        assert_eq!(line, "read your statement records from a publisher you have not named");
        assert!(!line.contains("did:key"));
    }

    /// An app is shown by the key that signed it: the person's name, or that they gave none.
    #[test]
    fn a_named_app_publisher_and_an_unnamed_one() {
        let signer = Signer::Key(acme());
        assert_eq!(app_line("Ledger", "1.0.0", "com.example.ledger", &signer, &named_acme()),
            "Ledger 1.0.0 (com.example.ledger) from My Bank");
        assert_eq!(app_line("Ledger", "1.0.0", "com.example.ledger", &signer, &Petnames::built_in()),
            "Ledger 1.0.0 (com.example.ledger) from a publisher you have not named");
    }

    /// An app with no publisher block is "from an app nobody signed"; one whose signature
    /// does not check says that, and neither names a key.
    #[test]
    fn an_unsigned_app() {
        assert_eq!(Signer::of(None, false), Signer::Nobody);
        assert_eq!(Signer::of(Some(ACME), false), Signer::NotChecked);
        assert_eq!(Signer::of(Some("did:key:zbad"), true), Signer::NotChecked);
        assert_eq!(Signer::of(Some(ACME), true), Signer::Key(acme()));
        let names = Petnames::built_in();
        assert_eq!(app_line("Ledger", "1.0.0", "com.example.ledger", &Signer::Nobody, &names),
            "Ledger 1.0.0 (com.example.ledger) from an app nobody signed");
        assert_eq!(app_line("Ledger", "1.0.0", "com.example.ledger", &Signer::NotChecked, &names),
            "Ledger 1.0.0 (com.example.ledger) from an app whose signature does not check");
        let grant = CapabilityGrant::schema(CapabilityKind::Read, SchemaId::from_static(NSID_NOTES));
        assert_eq!(grant_lines(&grant, &Signer::Nobody, &names), vec!["read your notes records from kotton"]);
    }

    /// When the app's publisher and the schema's differ, a line of its own says so; when
    /// they are one key, nothing does.
    #[test]
    fn the_two_publishers_differing() {
        let names = named_acme();
        let notes = CapabilityGrant::schema(CapabilityKind::Read, SchemaId::from_static(NSID_NOTES));
        assert_eq!(
            grant_lines(&notes, &Signer::Key(acme()), &names),
            vec!["read your notes records from kotton".to_string(), format!("  {DIFFERS}")]
        );
        let own = CapabilityGrant::schema(CapabilityKind::Write, statement());
        assert_eq!(grant_lines(&own, &Signer::Key(acme()), &names), vec!["write your statement records from My Bank"]);
        let kotton = Signer::Key(Publisher::from_static(NSID_PREFIX));
        assert_eq!(grant_lines(&notes, &kotton, &names), vec!["read your notes records from kotton"]);
    }

    /// A hostile app name, id or path loses its control and bidirectional characters, so it
    /// cannot rewrite the line, and what it chose is never said as who stands behind it.
    #[test]
    fn a_hostile_app_name() {
        let name = "Ledger\u{202E}knaB yM morf\u{202C}\r\n\u{1b}[2KMy Bank\u{2066}";
        let line = app_line(name, "1.0\u{7}", "com.example\u{200F}.ledger", &Signer::Nobody, &Petnames::built_in());
        assert_eq!(line, "LedgerknaB yM morf[2KMy Bank 1.0 (com.example.ledger) from an app nobody signed");
        assert!(!line.chars().any(is_hostile_char), "{line:?}");
        let path = CapabilityGrant::vfs(CapabilityKind::Read, "/notes\u{202E}txt.exe");
        assert_eq!(grant_lines(&path, &Signer::Nobody, &Petnames::built_in()), vec!["vfs.read:/notestxt.exe"]);
    }

    /// The keys to offer to name: each unnamed key once, the signer's first.
    #[test]
    fn the_unnamed_keys_are_each_offered_once() {
        let grants = [
            CapabilityGrant::schema(CapabilityKind::Read, statement()),
            CapabilityGrant::schema(CapabilityKind::Write, statement()),
            CapabilityGrant::schema(CapabilityKind::Read, SchemaId::from_static(NSID_NOTES)),
        ];
        assert_eq!(unnamed_keys(&Signer::Key(acme()), &grants, &Petnames::built_in()), vec![acme()]);
        assert!(unnamed_keys(&Signer::Key(acme()), &grants, &named_acme()).is_empty());
        assert_eq!(unnamed_keys(&Signer::Nobody, &grants, &Petnames::built_in()), vec![acme()]);
    }
}
