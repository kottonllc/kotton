// SPDX-License-Identifier: AGPL-3.0-or-later
//! What a grant prompt says of who stands behind what it asks, and what it shows of the words
//! other parties chose.
//!
//! A schema is named by the key that publishes it (the protocol's decision of that title), and
//! the decision fixes what a prompt may say. Two kinds of text meet in a prompt, and the
//! prompt's shape keeps them apart:
//!
//! - **What this device says**, from what it checked: who stands behind the app and each
//!   schema. Who stands behind a thing is said only by the person's own name for the key,
//!   marked as theirs (`a publisher you call "My Bank"`), or by its absence (`a publisher you
//!   have not named`, with the key), or as `an app nobody signed`. A name the person gave more
//!   than one key is said to be shared, with the key this one is. These lines come first, and
//!   no other party's string stands in them: they are said in a fixed shape, with the person's
//!   name and a key the only words in them that vary.
//! - **What another party wrote**: everything from the manifest or the bundle (the app's name,
//!   version, id and description, a path it suggests, a label), and a schema's name. Each sits
//!   on a line of its own beginning [`GUTTER`], which no line of the device's begins with,
//!   labelled as whose it is and quoted, made by [`others`]: whitespace one space, the
//!   characters that rewrite or hide a line removed, at most [`WORDS_MAX`] characters shown.
//!
//! **Only what was checked is said.** The publisher's signature is over the digest of the
//! app's code alone; its manifest (its name, its id, what it asks for) is signed by no one, and
//! the prompt says so in one sentence ([`ASKS_UNSIGNED`]) that signing the manifest replaces.
//! A schema is shown as its publisher's only when this device holds its signed definition,
//! which it admits only once the signature checks (or as Kotton's own code); one the manifest
//! cites that this device does not hold is [`NOT_HELD`], with nothing said of who.
//!
//! Every function here is pure, so each case's text is held by a test; the asking (the first
//! meeting with a key, where the person decides what to call it) is the sideload's.

use kotton_schemas::petname::is_hostile_char;
use kotton_schemas::{
    CapabilityGrant, CapabilityKind, CapabilityTarget, Petnames, Publisher, SchemaId,
};

/// Said of a key the person has not named.
pub const NOT_NAMED: &str = "a publisher you have not named";

/// Said of an app with no `[publisher]` block.
pub const UNSIGNED: &str = "an app nobody signed";

/// Said of a schema the manifest cites whose signed definition this device does not hold.
pub const NOT_HELD: &str = "a schema this device does not hold";

/// The one sentence on what the publisher's signature does not cover: everything but the
/// code. Signing the manifest with the code replaces this sentence alone.
pub const ASKS_UNSIGNED: &str =
    "What it asks for, and every word of the app's below, is not signed by anyone.";

/// Said, on a line of its own, under a schema whose publisher did not sign the app's code.
pub const DIFFERS: &str = "The app's code is not signed by this schema's publisher.";

/// Said, on a line of its own, under a schema an app nobody signed asks for.
pub const DIFFERS_UNSIGNED: &str =
    "No key signed the app's code, so it is not this schema's publisher's.";

/// Said when the person's names for keys could not be read.
pub const NAMES_UNREAD: &str =
    "Your names for keys could not be read, so no key here is shown by your name.";

/// Said when this device could not say which schemas it holds.
pub const HELD_UNREAD: &str =
    "This device could not say which schemas it holds, so no schema here is shown as a publisher's.";

/// What every line of another party's words begins with, and no line of the device's.
pub const GUTTER: &str = "  | ";

/// At most this many characters of another party's string are shown.
pub const WORDS_MAX: usize = 64;

/// At most this many combining marks are kept on one base character.
pub const MARKS_MAX: usize = 4;

/// Who signed an app's code, as the prompt may say it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signer {
    /// The signature over the code's digest checked against this key.
    Key(Publisher),
    /// The manifest has no `[publisher]` block.
    Nobody,
    /// The manifest names a key, and the signature does not check against it (the install
    /// refuses it).
    NotChecked,
    /// Not known here: `app grants`, whose answer carries no key.
    Unknown,
}

impl Signer {
    /// The signer of an app whose manifest names `publisher_did`, or none, whose signature
    /// over the code the daemon's preview found `verified` or not.
    pub fn of(publisher_did: Option<&str>, verified: bool) -> Self {
        match (publisher_did, verified) {
            (None, _) => Self::Nobody,
            (Some(did), true) => Publisher::new(did)
                .map(Self::Key)
                .unwrap_or(Self::NotChecked),
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

/// What the prompt knows to say who stands behind a thing: the person's names for keys, and
/// the schemas this device holds a signed definition of, each as read or `None` when the read
/// failed.
#[derive(Debug, Clone)]
pub struct Known {
    /// The person's names for keys; `None` when they could not be read.
    pub names: Option<Petnames>,
    /// The schemas this device holds; `None` when it could not say.
    pub held: Option<Vec<SchemaId>>,
}

impl Known {
    /// What the prompt knows from the two reads.
    pub fn new(names: Result<Petnames, String>, held: Result<Vec<String>, String>) -> Self {
        let held = held.ok().map(|ids| {
            ids.iter()
                .filter_map(|id| SchemaId::parse(id).ok())
                .collect()
        });
        Self {
            names: names.ok(),
            held,
        }
    }

    fn holds(&self, schema: &SchemaId) -> bool {
        self.held.as_ref().is_some_and(|held| held.contains(schema))
    }
}

/// `text`, another party's, as a prompt shows it, and whether it was cut: every run of
/// whitespace (line breaks and the line and paragraph separators among it) one space, trimmed;
/// every character [`is_hostile_char`] names removed (control, bidirectional-formatting,
/// zero-width and tag characters); more than [`MARKS_MAX`] combining marks on one character
/// cut to that many; and at most [`WORDS_MAX`] characters kept. **The one function for every
/// string another party chose.**
pub fn others(text: &str) -> (String, Option<usize>) {
    let mut out = String::new();
    let mut marks = 0;
    let mut space = false;
    for c in text.chars() {
        if c.is_whitespace() {
            space = !out.is_empty();
            continue;
        }
        if is_hostile_char(c) {
            continue;
        }
        if is_combining_mark(c) {
            marks += 1;
            if marks > MARKS_MAX || out.is_empty() {
                continue;
            }
        } else {
            marks = 0;
            if space {
                out.push(' ');
                space = false;
            }
        }
        out.push(c);
    }
    let total = out.chars().count();
    if total > WORDS_MAX {
        (out.chars().take(WORDS_MAX).collect(), Some(total))
    } else {
        (out, None)
    }
}

/// `text`, another party's, quoted as a prompt shows it ([`others`]), with `"` and `\`
/// escaped so the quote is the one the prompt closed, and the fact that it was cut.
pub fn quoted(text: &str) -> String {
    let (shown, cut) = others(text);
    let escaped = shown.replace('\\', "\\\\").replace('"', "\\\"");
    match cut {
        Some(total) => {
            format!("\"{escaped}…\" (cut: {WORDS_MAX} of its {total} characters shown)")
        }
        None => format!("\"{escaped}\""),
    }
}

/// A line of another party's words: [`GUTTER`], whose they are, and the words [`quoted`].
pub fn words_line(whose: &str, text: &str) -> String {
    format!("{GUTTER}{whose}: {}", quoted(text))
}

/// Whether `c` is a combining mark, of the blocks Unicode gives to marks for any script
/// (Combining Diacritical Marks, Extended and Supplement, for Symbols, Half Marks) and the
/// marks of the scripts most stacked (Cyrillic, Hebrew, Arabic, Thai, and Japanese kana).
fn is_combining_mark(c: char) -> bool {
    matches!(
        c,
        '\u{0300}'..='\u{036F}'
            | '\u{0483}'..='\u{0489}'
            | '\u{0591}'..='\u{05BD}'
            | '\u{05BF}'
            | '\u{05C1}'..='\u{05C2}'
            | '\u{05C4}'..='\u{05C5}'
            | '\u{05C7}'
            | '\u{0610}'..='\u{061A}'
            | '\u{064B}'..='\u{065F}'
            | '\u{0670}'
            | '\u{06D6}'..='\u{06DC}'
            | '\u{06DF}'..='\u{06E4}'
            | '\u{06E7}'..='\u{06E8}'
            | '\u{06EA}'..='\u{06ED}'
            | '\u{0E31}'
            | '\u{0E34}'..='\u{0E3A}'
            | '\u{0E47}'..='\u{0E4E}'
            | '\u{1AB0}'..='\u{1AFF}'
            | '\u{1DC0}'..='\u{1DFF}'
            | '\u{20D0}'..='\u{20FF}'
            | '\u{3099}'..='\u{309A}'
            | '\u{FE20}'..='\u{FE2F}'
    )
}

/// Who stands behind `key`, as the device says it: the person's name for it, marked as
/// theirs and said to be shared when they gave it to more than one key; that they gave none,
/// with the key; or that their names could not be read, with the key.
pub fn who(key: &Publisher, known: &Known) -> String {
    let Some(names) = &known.names else {
        return format!("the key {key} (your names for keys could not be read)");
    };
    match names.name_for(key) {
        Some(name) => match names.keys_called(name).len() {
            1 => format!("a publisher you call {}", quoted(name)),
            n => format!(
                "a publisher you call {} (a name you gave {n} keys; this is {key})",
                quoted(name)
            ),
        },
        None => format!("{NOT_NAMED} ({key})"),
    }
}

/// The prompt's first lines, the device's own: who signed the app's code, then what that
/// signature does not cover ([`ASKS_UNSIGNED`]), then what could not be read.
pub fn signer_lines(signer: &Signer, known: &Known) -> Vec<String> {
    let first = match signer {
        Signer::Key(key) => format!("This app's code is signed by {}.", who(key, known)),
        Signer::Nobody => format!("This is {UNSIGNED}: no key signed its code."),
        Signer::NotChecked => {
            "This app names a key, and the signature over its code does not check against it, so no \
             one is shown as signing it."
                .to_owned()
        }
        Signer::Unknown => "Who signed this app's code is not kept, so no line here says who did.".to_owned(),
    };
    let mut lines = vec![first, ASKS_UNSIGNED.to_owned()];
    if known.names.is_none() {
        lines.push(NAMES_UNREAD.to_owned());
    }
    if known.held.is_none() {
        lines.push(HELD_UNREAD.to_owned());
    }
    lines
}

/// The app's own words, after the device's lines: a heading of the device's, then the name,
/// version and id, each on a [`words_line`].
pub fn app_words(name: &str, version: &str, app_id: &str) -> Vec<String> {
    vec![
        "The app's own words, which no one has checked:".to_owned(),
        words_line("the app's name", name),
        words_line("the app's version", version),
        words_line("the app's id", app_id),
    ]
}

fn verb(kind: &CapabilityKind) -> &'static str {
    match kind {
        CapabilityKind::Read => "read",
        CapabilityKind::Write => "write",
        CapabilityKind::Use => "use",
    }
}

/// The lines a requested grant takes in the prompt, as indented as they are printed.
///
/// A schema grant: the device's line first, saying whose schema it is ([`who`]) when this
/// device holds it and [`NOT_HELD`] when not, then the schema's name on a [`words_line`] (the
/// publisher's when held; the app's when not, with the key it cites beside it), then
/// [`DIFFERS`] or [`DIFFERS_UNSIGNED`] when the schema is held and the app's code is not its
/// publisher's. A grant whose target is a
/// string the app chose (a path, an id, a root): what kind it is, then the string on a
/// [`words_line`]. Any other is the device's own capability string.
pub fn grant_lines(grant: &CapabilityGrant, signer: &Signer, known: &Known) -> Vec<String> {
    let rw = verb(&grant.kind);
    match &grant.target {
        CapabilityTarget::Schema { nsid } if known.holds(nsid) => {
            let mut lines = vec![
                format!(
                    "  {rw} your records of a schema published by {}",
                    who(nsid.publisher(), known)
                ),
                words_line("its publisher's name for it", &nsid.name().to_string()),
            ];
            match signer {
                Signer::Key(key) if key != nsid.publisher() => {
                    lines.push(format!("      {DIFFERS}"))
                }
                Signer::Nobody | Signer::NotChecked => {
                    lines.push(format!("      {DIFFERS_UNSIGNED}"))
                }
                _ => {}
            }
            lines
        }
        CapabilityTarget::Schema { nsid } => vec![
            format!("  {rw} your records of {NOT_HELD}"),
            words_line("the app's name for it", &nsid.name().to_string()),
            words_line("the key the app cites for it", nsid.publisher().as_str()),
        ],
        CapabilityTarget::Vfs { path } => {
            vec![
                format!("  {rw} your files under a path the app names"),
                words_line("the app's path", path),
            ]
        }
        CapabilityTarget::Quarantine { extension_id } => vec![
            format!("  {rw} the quarantine of an extension the app names"),
            words_line("the app's extension id", extension_id),
        ],
        CapabilityTarget::OrgInvite { root } => {
            vec![
                "  invite to a root the app names".to_owned(),
                words_line("the app's root", root),
            ]
        }
        CapabilityTarget::RootMember { root } => {
            vec![
                "  act as a member of a root the app names".to_owned(),
                words_line("the app's root", root),
            ]
        }
        _ => vec![format!("  {}", grant.display_string())],
    }
}

/// The keys a prompt shows that the person has not named, each once, in the order shown: the
/// app's signer, then the publisher of each schema this device holds. None when the names
/// could not be read, since no one can say which are unnamed.
pub fn unnamed_keys(
    signer: &Signer,
    requested: &[CapabilityGrant],
    known: &Known,
) -> Vec<Publisher> {
    let Some(names) = &known.names else {
        return Vec::new();
    };
    let schemas = requested.iter().filter_map(|g| match &g.target {
        CapabilityTarget::Schema { nsid } if known.holds(nsid) => {
            Some(nsid.publisher().clone())
        }
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
    const OTHER: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    fn acme() -> Publisher {
        Publisher::from_static(ACME)
    }

    fn statement() -> SchemaId {
        SchemaId::parse(format!("{ACME}/statement")).unwrap()
    }

    /// What the prompt knows: `records` for names, and notes and the bank's statement held.
    fn knowing(records: &[serde_json::Value]) -> Known {
        Known::new(
            Ok(Petnames::from_records(records)),
            Ok(vec![NSID_NOTES.to_owned(), statement().to_string()]),
        )
    }

    fn named_acme() -> Known {
        knowing(&[json!({ "key": ACME, "name": "My Bank", "_id": "p1", "_filed_at": 1 })])
    }

    fn nothing_named() -> Known {
        knowing(&[])
    }

    /// Every line, joined, and the lines that are the device's own (not [`GUTTER`] lines).
    fn device_lines(lines: &[String]) -> Vec<&String> {
        lines.iter().filter(|l| !l.starts_with(GUTTER)).collect()
    }

    /// A held schema whose publisher the person named: the device's line by their name, marked
    /// as theirs, then the schema's name as the publisher's words.
    #[test]
    fn a_named_schema_publisher() {
        let read = CapabilityGrant::schema(CapabilityKind::Read, statement());
        assert_eq!(
            grant_lines(&read, &Signer::Key(acme()), &named_acme()),
            vec![
                "  read your records of a schema published by a publisher you call \"My Bank\""
                    .to_owned(),
                "  | its publisher's name for it: \"statement\"".to_owned(),
            ]
        );
        let notes =
            CapabilityGrant::schema(CapabilityKind::Write, SchemaId::from_static(NSID_NOTES));
        let kotton = Signer::Key(Publisher::from_static(NSID_PREFIX));
        assert_eq!(
            grant_lines(&notes, &kotton, &nothing_named())[0],
            "  write your records of a schema published by a publisher you call \"kotton\""
        );
    }

    /// A held schema whose publisher the person has not named: says so, with the key.
    #[test]
    fn an_unnamed_schema_publisher() {
        let read = CapabilityGrant::schema(CapabilityKind::Read, statement());
        let lines = grant_lines(&read, &Signer::Key(acme()), &nothing_named());
        assert_eq!(
            lines[0],
            format!("  read your records of a schema published by {NOT_NAMED} ({ACME})")
        );
    }

    /// **A schema this device does not hold is attributed to no one**: a manifest citing the
    /// named bank's key with a name of its choosing prints no publisher's name on that line,
    /// and its key is not offered to be named.
    #[test]
    fn a_schema_this_device_does_not_hold_is_attributed_to_no_one() {
        let cited = SchemaId::parse(format!("{ACME}/approved-by-my-bank")).unwrap();
        let grant = CapabilityGrant::schema(CapabilityKind::Read, cited.clone());
        let lines = grant_lines(&grant, &Signer::Nobody, &named_acme());
        assert_eq!(
            lines,
            vec![
                format!("  read your records of {NOT_HELD}"),
                "  | the app's name for it: \"approved-by-my-bank\"".to_owned(),
                format!("  | the key the app cites for it: \"{ACME}\""),
            ]
        );
        assert!(
            lines
                .iter()
                .all(|l| !l.contains("My Bank") && !l.contains("publisher")),
            "{lines:?}"
        );
        let stranger = Signer::Key(Publisher::from_static(OTHER));
        let offered = unnamed_keys(&stranger, &[grant], &nothing_named());
        assert_eq!(offered, vec![Publisher::from_static(OTHER)], "the signer alone, not the cited key");
    }

    /// The app's lines: the device's statement first and on its own lines, the code signed by
    /// the key, what it asks for signed by no one; then the app's words, quoted and labelled.
    #[test]
    fn a_named_app_publisher_and_an_unnamed_one() {
        let signer = Signer::Key(acme());
        assert_eq!(
            signer_lines(&signer, &named_acme()),
            vec![
                "This app's code is signed by a publisher you call \"My Bank\".".to_owned(),
                ASKS_UNSIGNED.to_owned()
            ]
        );
        assert_eq!(
            signer_lines(&signer, &nothing_named())[0],
            format!("This app's code is signed by {NOT_NAMED} ({ACME}).")
        );
        assert_eq!(
            app_words("Ledger", "1.0.0", "com.example.ledger"),
            vec![
                "The app's own words, which no one has checked:".to_owned(),
                "  | the app's name: \"Ledger\"".to_owned(),
                "  | the app's version: \"1.0.0\"".to_owned(),
                "  | the app's id: \"com.example.ledger\"".to_owned(),
            ]
        );
    }

    /// An app with no publisher block is "an app nobody signed"; one whose signature does not
    /// check says that; neither names a key.
    #[test]
    fn an_unsigned_app() {
        assert_eq!(Signer::of(None, false), Signer::Nobody);
        assert_eq!(Signer::of(Some(ACME), false), Signer::NotChecked);
        assert_eq!(Signer::of(Some("did:key:zbad"), true), Signer::NotChecked);
        assert_eq!(Signer::of(Some(ACME), true), Signer::Key(acme()));
        let known = named_acme();
        assert_eq!(
            signer_lines(&Signer::Nobody, &known)[0],
            "This is an app nobody signed: no key signed its code."
        );
        for signer in [Signer::Nobody, Signer::NotChecked] {
            assert!(!signer_lines(&signer, &known).concat().contains("did:key"));
        }
    }

    /// **An unsigned app asking for a named publisher's schema has its own line saying the
    /// two differ**, so deleting the publisher block does not delete the warning.
    #[test]
    fn an_unsigned_app_asking_for_a_named_publishers_schema_is_told_apart() {
        let read = CapabilityGrant::schema(CapabilityKind::Read, statement());
        for signer in [Signer::Nobody, Signer::NotChecked] {
            let lines = grant_lines(&read, &signer, &named_acme());
            assert_eq!(
                lines.last().unwrap(),
                &format!("      {DIFFERS_UNSIGNED}"),
                "{signer:?}"
            );
        }
        assert_eq!(
            grant_lines(&read, &Signer::Unknown, &named_acme()).len(),
            2,
            "not known, not said"
        );
    }

    /// When the app's publisher and the schema's differ, a line of its own says so; when they
    /// are one key, nothing does.
    #[test]
    fn the_two_publishers_differing() {
        let known = named_acme();
        let notes =
            CapabilityGrant::schema(CapabilityKind::Read, SchemaId::from_static(NSID_NOTES));
        assert_eq!(
            grant_lines(&notes, &Signer::Key(acme()), &known)[2],
            format!("      {DIFFERS}")
        );
        let own = CapabilityGrant::schema(CapabilityKind::Write, statement());
        assert_eq!(grant_lines(&own, &Signer::Key(acme()), &known).len(), 2);
        let kotton = Signer::Key(Publisher::from_static(NSID_PREFIX));
        assert_eq!(grant_lines(&notes, &kotton, &known).len(), 2);
    }

    /// **One name on two keys is never shown as one**: each key's line says the name is
    /// shared, and which key this is. Names that read alike are shared too.
    #[test]
    fn two_keys_with_one_name() {
        let known = knowing(&[
            json!({ "key": ACME, "name": "My Bank", "_id": "p1", "_filed_at": 1 }),
            json!({ "key": OTHER, "name": "my bank ", "_id": "p2", "_filed_at": 2 }),
        ]);
        assert_eq!(
            signer_lines(&Signer::Key(acme()), &known)[0],
            format!("This app's code is signed by a publisher you call \"My Bank\" (a name you gave 2 keys; this is {ACME}).")
        );
        assert_eq!(
            who(&Publisher::from_static(OTHER), &known),
            format!(
                "a publisher you call \"my bank\" (a name you gave 2 keys; this is {OTHER})"
            )
        );
    }

    /// **When the names cannot be read, the prompt says so**, shows each key as a key and not
    /// as unnamed, and offers none to be named. When the held schemas cannot be read, none is
    /// shown as a publisher's.
    #[test]
    fn names_that_could_not_be_read_are_said_so() {
        let known = Known::new(Err("refused".into()), Ok(vec![statement().to_string()]));
        let lines = signer_lines(&Signer::Key(acme()), &known);
        assert_eq!(lines[0], format!("This app's code is signed by the key {ACME} (your names for keys could not be read)."));
        assert_eq!(lines[2], NAMES_UNREAD);
        assert!(!lines.concat().contains(NOT_NAMED), "{lines:?}");
        let read = CapabilityGrant::schema(CapabilityKind::Read, statement());
        assert!(unnamed_keys(&Signer::Key(acme()), std::slice::from_ref(&read), &known).is_empty());
        let blind = Known::new(Ok(Petnames::built_in()), Err("refused".into()));
        assert_eq!(
            signer_lines(&Signer::Nobody, &blind).last().unwrap(),
            HELD_UNREAD
        );
        assert_eq!(
            grant_lines(&read, &Signer::Nobody, &blind)[0],
            format!("  read your records of {NOT_HELD}")
        );
    }

    /// **What another party wrote is made one plain line, the same way everywhere**:
    /// whitespace one space, control, bidirectional, separator, zero-width and tag characters
    /// removed, combining marks bounded, and the length cut, saying so.
    #[test]
    fn others_words_are_made_one_plain_line() {
        assert_eq!(
            others("  Ledger \n\t 1.0\u{2028}x\u{2029}y  "),
            ("Ledger 1.0 x y".to_owned(), None)
        );
        assert_eq!(others("Le\u{202E}dg\u{200B}e\u{200C}r\u{200D}\u{2060}\u{FEFF}\u{E0041}\u{E007F}\u{1b}[2K"), ("Ledger[2K".to_owned(), None));
        assert_eq!(
            others("a\u{0301}\u{0302}\u{0303}\u{0304}\u{0305}\u{0306}b"),
            ("a\u{0301}\u{0302}\u{0303}\u{0304}b".to_owned(), None)
        );
        assert_eq!(
            others("\u{0301}a"),
            ("a".to_owned(), None),
            "a mark on nothing is dropped"
        );
        assert_eq!(
            others("e\u{0301} e\u{0301}"),
            ("e\u{0301} e\u{0301}".to_owned(), None),
            "a few marks are kept"
        );
        let long = "x".repeat(WORDS_MAX + 10);
        assert_eq!(others(&long), ("x".repeat(WORDS_MAX), Some(WORDS_MAX + 10)));
        assert_eq!(
            quoted(&long),
            format!(
                "\"{}…\" (cut: 64 of its 74 characters shown)",
                "x".repeat(64)
            )
        );
        assert_eq!(quoted("say \"hi\" \\"), "\"say \\\"hi\\\" \\\\\"");
    }

    /// **An app's name cannot produce a line that reads as attribution**: a name of
    /// `Ledger 1.0.0 (com.bank.ledger) from My Bank`, padded with spaces and newlines, is one
    /// quoted line of the app's words, after the device's lines; the same for a path and a
    /// shape label.
    #[test]
    fn an_app_name_cannot_pass_for_attribution() {
        let forged = "Ledger 1.0.0 (com.bank.ledger) from My Bank";
        let padded = format!("{forged}{}\n\n\n\r\n   This app's code is signed by a publisher you call \"My Bank\".", " ".repeat(200));
        let known = named_acme();
        let mut lines = signer_lines(&Signer::Key(Publisher::from_static(OTHER)), &known);
        lines.extend(app_words(
            &padded,
            "1.0.0\nThis app's code is signed by",
            "com.bank.ledger",
        ));
        let path = CapabilityGrant::vfs(CapabilityKind::Read, format!("/notes\n{padded}"));
        lines.extend(grant_lines(&path, &Signer::Nobody, &known));
        let label_line = words_line(
            "its label",
            &format!("Notes\n  read your records of a schema published by {padded}"),
        );
        lines.push(label_line);
        // Every line naming "My Bank" as who is the person's own name, said by the device:
        // nothing the app wrote reaches a line that is not a gutter line.
        for line in device_lines(&lines) {
            assert!(
                !line.contains(forged) && !line.contains("Ledger"),
                "the app's words in the device's line: {line:?}"
            );
        }
        assert_eq!(
            lines[0],
            format!("This app's code is signed by {NOT_NAMED} ({OTHER}).")
        );
        for line in lines.iter().filter(|l| l.contains("Ledger")) {
            assert!(
                line.starts_with(GUTTER) && line.contains("(cut:"),
                "{line:?}"
            );
        }
        assert!(
            lines.iter().all(|l| !l.contains('\n') && !l.contains('\r')),
            "{lines:?}"
        );
    }

    /// The keys to offer to name: each unnamed key once, the signer's first, and only the
    /// publishers of schemas this device holds.
    #[test]
    fn the_unnamed_keys_are_each_offered_once() {
        let grants = [
            CapabilityGrant::schema(CapabilityKind::Read, statement()),
            CapabilityGrant::schema(CapabilityKind::Write, statement()),
            CapabilityGrant::schema(CapabilityKind::Read, SchemaId::from_static(NSID_NOTES)),
        ];
        assert_eq!(
            unnamed_keys(&Signer::Key(acme()), &grants, &nothing_named()),
            vec![acme()]
        );
        assert!(unnamed_keys(&Signer::Key(acme()), &grants, &named_acme()).is_empty());
        assert_eq!(
            unnamed_keys(&Signer::Nobody, &grants, &nothing_named()),
            vec![acme()]
        );
    }
}
