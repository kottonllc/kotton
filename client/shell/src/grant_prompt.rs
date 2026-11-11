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
//!   than one key is said to be shared, with the key this one is; the name every device gives
//!   Kotton's release key is said to be built in, not the person's ([`BUILT_IN`]). These lines
//!   come first, and no other party's string stands in them: they are said in a fixed shape,
//!   with the person's name and a key the only words in them that vary.
//! - **What another party wrote**: everything from the manifest or the bundle (the app's name,
//!   version, id and description, a path it suggests, a label), a schema's name, and a reason
//!   the daemon gives that can quote them. Each is labelled as whose it is and quoted, made by
//!   [`others`]: whitespace and what renders blank one space, the characters that rewrite or
//!   hide a line removed, at most [`WORDS_MAX`] columns shown as escaped. It is laid out by
//!   [`words_line`] in rows that fit the terminal, **every row beginning [`GUTTER`]**, which no
//!   line of the device's begins with, so no row of a terminal begins with another party's
//!   words.
//!
//! **Only what was checked is said.** The publisher's signature is over the digest of the
//! app's code alone; its manifest (its name, its id, what it asks for) is signed by no one, and
//! the prompt says so in one sentence ([`ASKS_UNSIGNED`]) that signing the manifest replaces.
//! A schema is shown as its publisher's only when this device holds its signed definition,
//! which it admits only once the signature checks (or as Kotton's own code); one the manifest
//! cites that this device does not hold is [`NOT_HELD`], with nothing said of who.
//!
//! Every function here is pure but for the terminal's width, so each case's text is held by a
//! test; the asking (the first meeting with a key, where the person decides what to call it)
//! is the sideload's.

use kotton_schemas::petname::{is_combining_mark, is_hostile_char, renders_blank};
use kotton_schemas::{
    CapabilityGrant, CapabilityKind, CapabilityTarget, Petnames, Publisher, SchemaId,
};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Said of a key the person has not named.
pub const NOT_NAMED: &str = "a publisher you have not named";

/// Said of Kotton's release key while it has the name every device gives it, which the
/// person did not.
pub const BUILT_IN: &str = "Kotton's own release key";

/// Said of an app with no `[publisher]` block.
pub const UNSIGNED: &str = "an app nobody signed";

/// Said of a schema the manifest cites whose signed definition this device does not hold.
pub const NOT_HELD: &str =
    "a schema this device holds no signed definition of, so who publishes it is not shown";

/// The one sentence on what the publisher's signature does not cover: everything but the
/// code. Signing the manifest with the code replaces this sentence alone.
pub const ASKS_UNSIGNED: &str =
    "What it asks for, and every word of the app's below, is not signed by anyone.";

/// The heading over the app's own words; [`ASKS_UNSIGNED`] says what is true of them.
pub const APP_WORDS: &str = "The app's own words:";

/// Said, on a line of its own, under a schema whose publisher did not sign the app's code.
pub const DIFFERS: &str = "The app's code is not signed by this schema's publisher.";

/// Said, on a line of its own, under a schema an app asks for when no signature on its code
/// checked: an app nobody signed, or one whose signature failed.
pub const DIFFERS_UNSIGNED: &str =
    "No signature on the app's code checked, so nothing shows it comes from this schema's publisher.";

/// Said in the offer to name a key, before the question: the prompt shows the key, and
/// nothing in it (least of all the app's words) shows who holds it.
pub const OFFER_CAUTION: &str =
    "Nothing above shows whose key this is. Name it only if you know by some other way.";

/// Said when the person's names for keys could not be read.
pub const NAMES_UNREAD: &str =
    "Your names for keys could not be read, so no key here is shown by your name.";

/// Said when this device could not say which schemas it holds.
pub const HELD_UNREAD: &str =
    "This device could not say which schemas it holds, so no schema here is shown as a publisher's.";

/// What every row of another party's words begins with, and no line of the device's.
pub const GUTTER: &str = "  | ";

/// What a row that carries on another party's words begins with: [`GUTTER`], indented, so a
/// row carried on never lines up with a row a label begins.
pub const CONTINUED: &str = "  |   ";

/// What a row that carries on another party's words begins with when its first letter would
/// be written right to left: [`CONTINUED`] and a word of the device's written left to right.
pub const CARRIED_RTL: &str = "  |   (more) ";

/// Said, on a row of its own under words that hold right-to-left letters, since a terminal
/// can show those in another order than they were written.
pub const RIGHT_TO_LEFT: &str =
    "(right-to-left letters here can show in another order than written)";

/// At most this many columns of another party's string are shown, as escaped.
pub const WORDS_MAX: usize = 64;

/// At most this many columns of a reason the daemon gives are shown, as escaped: a reason can
/// quote a manifest, so it is shown as another party's words are, with room for a sentence.
pub const REASON_MAX: usize = 400;

/// At most this many combining marks are kept on one base character.
pub const MARKS_MAX: usize = 4;

/// The columns the prompt lays rows out in: the terminal's, and 80 under test.
fn width() -> usize {
    #[cfg(test)]
    return 80;
    #[cfg(not(test))]
    crate::ui::term_width()
}

/// The columns `text` takes, counted the wider way wherever a terminal may differ (a
/// character of ambiguous width as two), so a row measured to fit does fit.
pub(crate) fn cols(text: &str) -> usize {
    let each: usize = text.chars().map(char_cols).sum();
    each.max(text.width()).max(text.width_cjk())
}

/// The columns one character takes, counted alone: the wider of its normal and East Asian
/// widths, and one for a character the crate gives none that is not a combining mark, since a
/// terminal may draw it in a cell. A row is never measured narrower than the sum of these, as
/// a terminal that gives each character its own cells lays it out.
fn char_cols(c: char) -> usize {
    let w = c.width().unwrap_or(0).max(c.width_cjk().unwrap_or(0));
    if w == 0 && !is_combining_mark(c) {
        1
    } else {
        w
    }
}

/// Whether `c` is a format character a terminal may draw in a cell, though Unicode's widths
/// give it none, and not [`is_hostile_char`]'s: the soft hyphen (U+00AD), the Mongolian vowel
/// separator (U+180E), U+2065, the deprecated format characters (U+206A to U+206F), the
/// interlinear annotation characters (U+FFF9 to U+FFFB), and the format characters above the
/// Basic Multilingual Plane. Another party's string loses each. The list stands until
/// Unicode's general category replaces it (kottonllc/kotton#498).
fn is_unseen_format(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{180E}'
            | '\u{2065}'
            | '\u{206A}'..='\u{206F}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
    )
}

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

/// `text`, another party's, made one plain run: every run of whitespace (line breaks and the
/// line and paragraph separators among it) and of characters that [`renders_blank`] one
/// space, trimmed; every character [`is_hostile_char`] names removed (control,
/// bidirectional-formatting, zero-width and tag characters), and every other character that
/// takes no column but a combining mark ([`is_unseen_format`] among them); and more than
/// [`MARKS_MAX`] combining marks on one character cut to that many, and none on nothing.
fn cleaned(text: &str) -> String {
    let mut out = String::new();
    let mut marks = 0;
    let mut space = false;
    for c in text.chars() {
        if c.is_whitespace() || renders_blank(c) {
            space = !out.is_empty();
            continue;
        }
        // A character that takes no column is kept only as a combining mark; any other (a
        // format character among them) is lost, since a terminal may draw it in a cell.
        if is_hostile_char(c) || is_unseen_format(c) || (c.width() == Some(0) && !is_combining_mark(c)) {
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
    out
}

/// `c` as a quote shows it: `"` and `\` escaped, so the quote is the one the prompt closed.
fn escaped(c: char) -> String {
    match c {
        '"' => "\\\"".to_owned(),
        '\\' => "\\\\".to_owned(),
        c => c.to_string(),
    }
}

/// `text`, another party's, as a prompt shows it, and whether it was cut: [`cleaned`], then at
/// most [`WORDS_MAX`] columns kept, measured as the quote shows it (escaped). **The one
/// function for every string another party chose.**
pub fn others(text: &str) -> (String, Option<usize>) {
    others_within(text, WORDS_MAX)
}

/// [`others`], keeping at most `max` columns; the count of characters it held when cut.
fn others_within(text: &str, max: usize) -> (String, Option<usize>) {
    let clean = cleaned(text);
    let mut shown = String::new();
    let mut quote = String::new();
    for c in clean.chars() {
        let next = format!("{quote}{}", escaped(c));
        if cols(&next) > max {
            return (shown, Some(clean.chars().count()));
        }
        quote = next;
        shown.push(c);
    }
    (shown, None)
}

/// `text`, another party's, quoted as a prompt shows it ([`others`]), with `"` and `\`
/// escaped so the quote is the one the prompt closed, and the fact that it was cut.
pub fn quoted(text: &str) -> String {
    quoted_within(text, WORDS_MAX).0
}

/// [`quoted`] within `max` columns, and whether what is shown holds right-to-left letters.
fn quoted_within(text: &str, max: usize) -> (String, bool) {
    let (shown, cut) = others_within(text, max);
    let rtl = shown.chars().any(is_right_to_left);
    let quote: String = shown.chars().map(escaped).collect();
    let quote = match cut {
        Some(total) => format!(
            "\"{quote}…\" (cut: {} of its {total} characters shown)",
            shown.chars().count()
        ),
        None => format!("\"{quote}\""),
    };
    (quote, rtl)
}

/// The person's own name for a key, quoted as a device line says it: [`cleaned`] and
/// escaped, and never cut, since the rules hold a name to [`kotton_schemas::petname::MAX_NAME_CHARS`].
fn persons(name: &str) -> String {
    format!("\"{}\"", cleaned(name).chars().map(escaped).collect::<String>())
}

/// Whether `c` is a letter of a script written right to left (Hebrew, Arabic, Syriac, Thaana,
/// N'Ko and their neighbours, and their presentation forms).
fn is_right_to_left(c: char) -> bool {
    matches!(
        c,
        '\u{0590}'..='\u{08FF}'
            | '\u{FB1D}'..='\u{FDFF}'
            | '\u{FE70}'..='\u{FEFE}'
            | '\u{10800}'..='\u{10FFF}'
            | '\u{1E800}'..='\u{1EFFF}'
    )
}

/// `content` laid out in rows of at most `width` columns ([`cols`]), the first beginning
/// `first` and every other [`CONTINUED`]: broken at the last space of a row where it has one,
/// else between two characters, and never before a character that takes no column. A row
/// carried on whose first letter would be written right to left begins [`CARRIED_RTL`]
/// instead, so a terminal that takes a row's direction from its first letter keeps the
/// gutter on the left.
fn rows(content: &str, width: usize, first: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut row = String::new();
    let mut prefix = first;
    let mut pending: std::collections::VecDeque<char> = content.chars().collect();
    while let Some(c) = pending.pop_front() {
        if row.is_empty() && !out.is_empty() {
            let letter = std::iter::once(c).chain(pending.iter().copied()).find(|c| c.is_alphabetic());
            prefix = if letter.is_some_and(is_right_to_left) { CARRIED_RTL } else { CONTINUED };
        }
        let room = width.saturating_sub(cols(prefix)).max(2);
        let next = format!("{row}{c}");
        if cols(&next) <= room || row.is_empty() {
            row = next;
            continue;
        }
        pending.push_front(c);
        if let Some(at) = row.rfind(' ').filter(|&at| at > 0) {
            for carried in row[at + 1..].chars().rev() {
                pending.push_front(carried);
            }
            row.truncate(at);
        }
        out.push(format!("{prefix}{row}"));
        row.clear();
        if pending.front() == Some(&' ') {
            pending.pop_front();
        }
    }
    out.push(format!("{prefix}{row}"));
    out
}

/// A line of another party's words, in as many rows as it takes at `width`: whose they are,
/// then the words quoted within `max` columns, every row beginning [`GUTTER`]; then, when the
/// words hold right-to-left letters, [`RIGHT_TO_LEFT`] on rows of its own.
fn words_rows(whose: &str, text: &str, max: usize, width: usize) -> Vec<String> {
    let (quote, rtl) = quoted_within(text, max);
    let mut lines = rows(&format!("{whose}: {quote}"), width, GUTTER);
    if rtl {
        lines.extend(rows(RIGHT_TO_LEFT, width, CONTINUED));
    }
    lines
}

/// A line of another party's words: whose they are, and the words [`quoted`], in rows that
/// fit the terminal, every one beginning [`GUTTER`].
pub fn words_line(whose: &str, text: &str) -> Vec<String> {
    words_rows(whose, text, WORDS_MAX, width())
}

/// A reason the daemon gave, which can quote another party's words: shown as they are
/// ([`words_line`]), within [`REASON_MAX`] columns.
pub fn reason_line(text: &str) -> Vec<String> {
    words_rows("the reason given", text, REASON_MAX, width())
}

/// Who stands behind `key`, as the device says it: the person's name for it, marked as
/// theirs and said to be shared when they gave it to more than one key; the name every
/// device gives Kotton's release key, said to be built in and not theirs; that they gave
/// none, with the key; or that their names could not be read, with the key.
pub fn who(key: &Publisher, known: &Known) -> String {
    let Some(names) = &known.names else {
        return format!("the key {key} (your names for keys could not be read)");
    };
    match names.name_for(key) {
        Some(name) if names.is_built_in(key) => {
            format!("{BUILT_IN} (built-in name {}; not a name you gave)", persons(name))
        }
        Some(name) => match names.keys_called(name).len() {
            1 => format!("a publisher you call {}", persons(name)),
            n => format!(
                "a publisher you call {} (a name you gave {n} keys; this is {key})",
                persons(name)
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

/// The app's own words, after the device's lines: the heading [`APP_WORDS`], then the name,
/// version and id, each a [`words_line`].
pub fn app_words(name: &str, version: &str, app_id: &str) -> Vec<String> {
    let mut lines = vec![APP_WORDS.to_owned()];
    lines.extend(words_line("the app's name", name));
    lines.extend(words_line("the app's version", version));
    lines.extend(words_line("the app's id", app_id));
    lines
}

fn verb(kind: &CapabilityKind) -> &'static str {
    match kind {
        CapabilityKind::Read => "read",
        CapabilityKind::Write => "write",
        CapabilityKind::Use => "use",
    }
}

/// The lines a grant takes in a prompt, as indented as they are printed.
///
/// A schema grant: the device's lines first, saying whose schema it is ([`who`]) when this
/// device holds it and [`NOT_HELD`] when not, and, when it is held and the app's code is not
/// its publisher's, [`DIFFERS`] or [`DIFFERS_UNSIGNED`]; then the schema's name, a
/// [`words_line`] (the publisher's when held; the app's when not, with the key it cites
/// beside it). A grant whose target is a string the app chose (a path, an id, a root): what
/// kind it is, then the string, a [`words_line`]. A grant whose target carries no string is
/// the device's own capability string. The match names every target, so a new one that
/// carries a string cannot reach a device line unseen.
pub fn grant_lines(grant: &CapabilityGrant, signer: &Signer, known: &Known) -> Vec<String> {
    let rw = verb(&grant.kind);
    let with = |head: String, whose: &str, text: &str| {
        let mut lines = vec![head];
        lines.extend(words_line(whose, text));
        lines
    };
    match &grant.target {
        CapabilityTarget::Schema { nsid } if known.holds(nsid) => {
            let mut lines = vec![format!(
                "  {rw} your records of a schema published by {}",
                who(nsid.publisher(), known)
            )];
            match signer {
                Signer::Key(key) if key != nsid.publisher() => {
                    lines.push(format!("      {DIFFERS}"))
                }
                Signer::Nobody | Signer::NotChecked => {
                    lines.push(format!("      {DIFFERS_UNSIGNED}"))
                }
                Signer::Key(_) | Signer::Unknown => {}
            }
            lines.extend(words_line("its publisher's name for it", &nsid.name().to_string()));
            lines
        }
        CapabilityTarget::Schema { nsid } => {
            let mut lines = with(
                format!("  {rw} your records of {NOT_HELD}"),
                "the app's name for it",
                &nsid.name().to_string(),
            );
            lines.extend(words_line("the key the app cites for it", nsid.publisher().as_str()));
            lines
        }
        CapabilityTarget::Vfs { path } => with(
            format!("  {rw} your files under this path"),
            "the path (the app's, or one you bound)",
            path,
        ),
        CapabilityTarget::Quarantine { extension_id } => with(
            format!("  {rw} the quarantine of an extension the app names"),
            "the app's extension id",
            extension_id,
        ),
        CapabilityTarget::OrgInvite { root } => with(
            "  invite to a root the app names".to_owned(),
            "the app's root",
            root,
        ),
        CapabilityTarget::RootMember { root } => with(
            "  act as a member of a root the app names".to_owned(),
            "the app's root",
            root,
        ),
        CapabilityTarget::Media { .. }
        | CapabilityTarget::Call { .. }
        | CapabilityTarget::Messages { .. }
        | CapabilityTarget::Events
        | CapabilityTarget::Network
        | CapabilityTarget::Infer
        | CapabilityTarget::AppLaunch
        | CapabilityTarget::Ui => vec![format!("  {}", grant.display_string())],
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

    /// The lines as written before rows were laid out: a [`GUTTER`] row and the
    /// [`CONTINUED`] rows after it, joined by a space; any other line as it is.
    fn logical(lines: &[String]) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for line in lines {
            match line.strip_prefix(CONTINUED) {
                Some(more) if !out.is_empty() => {
                    let last = out.last_mut().unwrap();
                    last.push(' ');
                    last.push_str(more);
                }
                _ => out.push(line.clone()),
            }
        }
        out
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
            "  write your records of a schema published by Kotton's own release key (built-in name \"kotton\"; not a name you gave)"
        );
    }

    /// **`you call` is said only of a name the person gave**: Kotton's release key, by the
    /// name every device gives it, is said to be built in; once the person gives it a name,
    /// even the same one, it is theirs.
    #[test]
    fn the_built_in_name_is_not_said_to_be_the_persons() {
        let kotton = Publisher::from_static(NSID_PREFIX);
        let said = who(&kotton, &nothing_named());
        assert_eq!(said, format!("{BUILT_IN} (built-in name \"kotton\"; not a name you gave)"));
        assert!(!said.contains("you call"), "{said}");
        let given = knowing(&[json!({ "key": NSID_PREFIX, "name": "kotton", "_id": "p1", "_filed_at": 1 })]);
        assert_eq!(who(&kotton, &given), "a publisher you call \"kotton\"");
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
                "  | the key the app cites for it:".to_owned(),
                format!("  |   \"{ACME}\""),
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
                APP_WORDS.to_owned(),
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
            assert_eq!(lines[1], format!("      {DIFFERS_UNSIGNED}"), "{signer:?}");
            assert!(lines[2].starts_with(GUTTER), "the device's lines first: {lines:?}");
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
        let differing = grant_lines(&notes, &Signer::Key(acme()), &known);
        assert_eq!(differing[1], format!("      {DIFFERS}"), "the device's lines first");
        assert_eq!(differing[2], "  | its publisher's name for it: \"notes\"");
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
        lines.extend(label_line);
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
            assert!(line.starts_with(GUTTER), "{line:?}");
        }
        for words in logical(&lines).iter().filter(|w| w.contains("Ledger")) {
            assert!(words.contains("(cut:"), "{words:?}");
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

    /// **No row of a terminal 80 columns wide begins with another party's words**: a label
    /// that fills a row, 64 quotes, 64 wide characters, characters that render blank and a
    /// reason of many lines, each measured in columns as escaped and laid out behind the
    /// gutter, every row at most 80 columns, so none is wrapped by the terminal.
    #[test]
    fn every_row_of_anothers_words_fits_behind_the_gutter() {
        let quotes = "\"".repeat(64);
        let wide = "漢".repeat(64);
        let blank = format!("a{}b", "\u{3164}\u{115F}\u{1160}\u{FFA0}\u{2800}".repeat(20));
        let long = "x".repeat(300);
        let reason = format!("manifest parse error: TOML parse error at line 3\n  |\n3 | name = \"{}\u{1b}[2K\"\n  |        ^\n{long}", "y".repeat(90));
        let [toned, lam_alef, shy] = narrower_than_drawn();
        let mut lines = Vec::new();
        for text in [&quotes, &wide, &blank, &long, &toned, &lam_alef, &shy] {
            lines.extend(app_words(text, text, text));
            let path = CapabilityGrant::vfs(CapabilityKind::Read, text.as_str());
            lines.extend(grant_lines(&path, &Signer::Nobody, &nothing_named()));
            lines.extend(words_line("the app's id for it (for --bind) and a label long enough to fill most of a row", text));
        }
        lines.extend(reason_line(&reason));
        for line in &lines {
            assert!(!line.contains('\n') && !line.contains('\u{1b}'), "{line:?}");
            if line.starts_with(GUTTER) {
                assert!(cols(line) <= 80, "{} columns: {line:?}", cols(line));
                assert!(each_cell(line) <= 80, "{} columns by its characters: {line:?}", each_cell(line));
            } else {
                for theirs in ["\"\"", "漢", "xxxx", "yyyy", "a b", "\u{1F44D}", "\u{0644}", "itself"] {
                    assert!(!line.contains(theirs), "another party's words on a device line: {line:?}");
                }
            }
        }
        // Measured in columns as escaped: 64 quotes are 128 columns, and 32 are shown.
        assert_eq!(quoted(&quotes), format!("\"{}…\" (cut: 32 of its 64 characters shown)", "\\\"".repeat(32)));
        assert_eq!(quoted(&wide), format!("\"{}…\" (cut: 32 of its 64 characters shown)", "漢".repeat(32)));
        // What renders blank is the one space.
        assert_eq!(others(&blank), ("a b".to_owned(), None));
        assert_eq!(others("\u{3164}\u{2800}"), (String::new(), None));
        // A reason is shown longer, and cut too.
        let reasoned = logical(&reason_line(&reason)).concat();
        assert!(reasoned.contains("yyyy") && reasoned.contains("(cut:"), "{reasoned}");
        // Never measured narrower than its characters: a skin tone is its own two columns,
        // and lam and alef one each.
        assert!(cols("\u{1F44D}\u{1F3FD}") >= 4 && cols("\u{0644}\u{0627}") >= 2);
        assert_eq!(cols("\u{263A}\u{FE0F}"), 2, "a character shown as an emoji counts 2");
    }

    /// The three kinds of string the third design review found measured narrower than a
    /// terminal draws them, each the app's name at 80 columns: 14 thumbs with a skin tone,
    /// 29 lam-alefs, and 12 letters each with four soft hyphens, each then `x` and 24 ASCII
    /// characters.
    fn narrower_than_drawn() -> [String; 3] {
        let tail = "xSigned by Kotton itself.";
        [
            format!("{}{tail}", "\u{1F44D}\u{1F3FD}".repeat(14)),
            format!("{}{tail}", "\u{0644}\u{0627}".repeat(29)),
            format!("{}{tail}", "a\u{AD}\u{AD}\u{AD}\u{AD}".repeat(12)),
        ]
    }

    /// The columns a row takes in a terminal that gives every character its own cells: the
    /// sum of each one's width alone, the wider way.
    fn each_cell(row: &str) -> usize {
        row.chars().map(|c| c.width().unwrap_or(0).max(c.width_cjk().unwrap_or(0))).sum()
    }

    /// **A row of the app's name is measured as a terminal draws it**: each of the three is
    /// laid out in rows of at most 80 columns by its characters; the soft hyphens and every
    /// other character that takes no column but a mark are removed; the thumbs are cut.
    #[test]
    fn no_row_is_measured_narrower_than_its_characters() {
        let [toned, lam_alef, shy] = narrower_than_drawn();
        for name in [&toned, &lam_alef, &shy] {
            let lines = app_words(name, "1.0.0", "com.example.x");
            for line in &lines[1..] {
                assert!(line.starts_with(GUTTER), "{line:?}");
                assert!(each_cell(line) <= 80, "{} columns by its characters: {line:?}", each_cell(line));
            }
        }
        assert_eq!(others(&shy).0, format!("{}xSigned by Kotton itself.", "a".repeat(12)));
        assert!(quoted(&toned).contains("(cut:"), "{}", quoted(&toned));
        for unseen in ["\u{AD}", "\u{180E}", "\u{2065}", "\u{206A}", "\u{206F}", "\u{FFF9}", "\u{FFFB}", "\u{110BD}", "\u{1D173}", "\u{FE0F}"] {
            assert_eq!(others(&format!("a{unseen}b")).0, "ab", "{unseen:?}");
        }
        assert_eq!(others("e\u{0301}").0, "e\u{0301}", "a combining mark is kept");
    }

    /// The layout itself: the first row behind [`GUTTER`], the rest behind [`CONTINUED`],
    /// broken at a space where a row has one, at any width the terminal gives.
    #[test]
    fn a_line_of_anothers_words_is_laid_out_in_rows() {
        assert_eq!(words_rows("the app's name", "Ledger", WORDS_MAX, 80), vec!["  | the app's name: \"Ledger\""]);
        let at_30 = words_rows("the app's name", "Ledger of every account you hold", WORDS_MAX, 30);
        assert_eq!(
            at_30,
            vec![
                "  | the app's name: \"Ledger",
                "  |   of every account you",
                "  |   hold\"",
            ]
        );
        for width in [20, 24, 33, 47, 80, 81, 200] {
            for line in words_rows("its label", &"漢a\"".repeat(40), REASON_MAX, width) {
                assert!(line.starts_with(GUTTER) && cols(&line) <= width, "{width}: {line:?}");
            }
        }
    }

    /// **Right-to-left letters carry a note of the device's**, on a row of the gutter after
    /// the words, and no character that reorders a line is added.
    #[test]
    fn right_to_left_letters_are_noted() {
        let lines = words_rows("the app's name", "בנק שלי", WORDS_MAX, 80);
        assert_eq!(lines, vec!["  | the app's name: \"בנק שלי\"".to_owned(), format!("{CONTINUED}{RIGHT_TO_LEFT}")]);
        assert!(lines.concat().chars().all(|c| !is_hostile_char(c)));
        assert_eq!(words_rows("the app's name", "Ledger", WORDS_MAX, 80).len(), 1);
    }

    /// **No carried-on row begins with a right-to-left letter**: one that would begins with a
    /// word of the device's written left to right, so the gutter stays on the left.
    #[test]
    fn a_row_carried_on_begins_left_to_right() {
        let lines = words_rows("the app's description", &"בנק שלי ".repeat(20), REASON_MAX, 40);
        assert!(lines.len() > 2, "{lines:#?}");
        for line in &lines[1..] {
            assert!(line.starts_with(CONTINUED) && cols(line) <= 40, "{line:?}");
            let first = line[CONTINUED.len()..].chars().find(|c| c.is_alphabetic());
            assert!(!first.is_some_and(is_right_to_left), "a row begins right to left: {line:?}");
        }
        assert!(lines[1].starts_with(CARRIED_RTL), "{lines:#?}");
        let plain = words_rows("the app's description", &"ledger ".repeat(20), REASON_MAX, 40);
        assert!(plain.iter().all(|l| !l.contains("(more)")), "{plain:#?}");
    }

    /// Every kind of grant has its lines; one whose target carries a string puts it behind
    /// the gutter, and one that carries none is the device's capability string.
    #[test]
    fn every_target_is_said() {
        let stringed = [
            CapabilityGrant::org_invite("Root\nThis app's code is signed by"),
            CapabilityGrant::root_member("Root\nThis app's code is signed by"),
            CapabilityGrant { kind: CapabilityKind::Read, target: CapabilityTarget::Quarantine { extension_id: "ext\nThis app's code is signed by".into() } },
        ];
        for grant in &stringed {
            let lines = grant_lines(grant, &Signer::Nobody, &nothing_named());
            assert!(device_lines(&lines).iter().all(|l| !l.contains("signed")), "{lines:?}");
        }
        let plain = CapabilityGrant::action(CapabilityTarget::Network);
        assert_eq!(grant_lines(&plain, &Signer::Nobody, &nothing_named()), vec!["  network.fetch"]);
    }
}
