// SPDX-License-Identifier: AGPL-3.0-or-later
//! **A note beside a listing's rows**, for a row whose key is not what it seems
//! (kottonllc/kotton#597, choices 8B, 18B and 22A; kottonllc/kotton#605).
//!
//! A row stored by an earlier build may sit under bytes the Ed25519 rule refuses,
//! or name its key by a string that is not that key's `did:key`. Such a row is
//! listed as any other, and the answer that lists it carries a [`RowNote`]
//! beside the rows, one per such row: the row's name as a command takes it, and
//! which of two things is true of it. No row type changes for it, so nothing a
//! ceremony carries between devices changes either.
//!
//! The daemon says what is true; the surface says what to type. [`sentence`]
//! makes the one sentence a person reads from a note and the verb the surface
//! registers, so every surface says it the same way and none names a verb it
//! does not have.
//!
//! Where a note may travel has two bounds (kottonllc/kotton#597, 22A):
//!
//! - **In an answer a remote asker may be given, a note is made from a row of
//!   that answer and from nothing else** (the node listing's): the asker already
//!   holds what it says, in the row.
//! - **In an answer given only at the machine, a note may be about a node of the
//!   person's that the answer carries no row for**, where that asker can already
//!   list that node, and the note names it as the node listing does (`drive
//!   list`'s, and the admitting side's of a join).
//!
//! One note is about something no listing shows: an own-device member of the
//! person's set whose bytes are no key and that no row stands for, noted by the
//! node listing by its DID as stored (kottonllc/kotton#610). It is carried only
//! in the answer given to the person whose set it is, on their own device, and
//! `device revoke` resolves it there and nowhere else.
//!
//! A note's name is one the verb its sentence names takes to the row, typed as
//! the sentence gives it (20A): it is put in a command only when it is
//! [`one_plain_word`]. A row whose name is not one is told its verb and the name
//! that verb takes, and given no command (23A). Every name a sentence prints is
//! printed as data, by [`shown`].

use serde::{Deserialize, Serialize};

/// One row of a listing that names no key, or that stands by its key's bytes
/// under a name that is not the key's `did:key`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RowNote {
    /// The row's name as the command that finds it takes it: a node's label
    /// where that label finds this row and no other, else the DID as stored;
    /// an operator's DID as stored; a kept credential's name.
    pub name: String,
    /// Which of the two is true of the row.
    pub is: NoteKind,
}

/// What a [`RowNote`] says of its row. Two kinds and no third: a third is a
/// change to the local messages, with its own review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteKind {
    /// The row names no Ed25519 key: nothing is reached or checked under it,
    /// and the surface's removal verb removes it by `name`. Said of a member of
    /// the set with no row as well, named by its DID as stored.
    NamesNoKey,
    /// The row stands by its key's bytes, which pass, and is reached and
    /// checked under that key as before; the DID stored beside them is not the
    /// key's `did:key`. A command finds the row by `name` or by `stored`, not
    /// by `did_key`.
    StandsByBytes {
        /// The key's `did:key`, as the derivation makes it of the row's bytes.
        did_key: String,
        /// The DID as stored beside the bytes.
        stored: String,
    },
}

impl RowNote {
    /// A note for a row that names no key, under `name`.
    pub fn names_no_key(name: impl Into<String>) -> Self {
        Self { name: name.into(), is: NoteKind::NamesNoKey }
    }
}

/// Whether `name` is one plain word: one a surface reads back, from a typed
/// line, as exactly that name (kottonllc/kotton#597, 20A: a note's name is one
/// the verb takes to its row). A name is a note's name to type only when this
/// holds, and [`sentence`] names a command with a name only when it holds.
///
/// It is an allow-list, read by the shell's parser and by a POSIX shell alike as
/// one word with nothing to expand: one or more of the characters
/// [`plain_word_char`] admits, not starting with `-`. So no whitespace, no
/// control character, no quote, backtick, `\\`, `$`, `*`, `;`, `|`, `&`, `<` or
/// `>`, and nothing a command would read as a flag. A `did:key` is such a word in
/// every multibase spelling but Base45's and Base256Emoji's.
///
/// **That the set is ASCII is a concession** (kottonllc/kotton#597, 25A):
///
/// - *What is conceded.* A command is printed only with a name in ASCII. Nothing
///   is refused for it: a name in any script is stored, listed, shown in full
///   ([`shown`]), and taken by every verb, whole and by equality.
/// - *What it costs.* A person who names a device in another script is given the
///   DID as stored to copy in a note's command, where a person who names it in
///   ASCII is given the word. A person who names a vault or a relay so is given
///   the verb and the name, and no line to copy. Both are told the same facts
///   about the row.
/// - *Why it is conceded and not lifted.* A printed command is held to this:
///   typed as printed, the name is the stored name (20A). The stores compare a
///   name as stored, byte for byte. For ASCII, what a person types from a printed
///   word is those bytes; in other scripts one printed name has more than one
///   encoding. A name a vault or a relay is minted under is in NFC (41A); a
///   label and a DID as stored are in no normal form, and no normal form is
///   applied where a typed name is compared, so a command printed with such a
///   name is not held to reach its row.
/// - *The seam.* This is the one predicate, and [`sentence`] the one caller that
///   prints a command. Widening it is a normal form applied where a name is
///   stored and where a typed name is compared, then this set, then each
///   surface's read-back test over the wider set. The first step is done for a
///   minted name. No store, row type or message changes for it.
pub fn one_plain_word(name: &str) -> bool {
    !name.is_empty() && !name.starts_with('-') && name.chars().all(plain_word_char)
}

/// Whether `c` is in [`one_plain_word`]'s set: an ASCII letter or digit, or one
/// of `.`, `_`, `:`, `-`, `+`, `/`, `=`. The one set: the mint of an operator
/// credential's name holds the name's ASCII to it (kottonllc/kotton#597, 24B).
pub fn plain_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-' | '+' | '/' | '=')
}

/// `name` as a sentence or a listing prints it: as data, each character it holds
/// shown (kottonllc/kotton#597, 23A). A character is printed as it is where
/// [`kotton_schemas::petname::is_printed_as_is`] holds, by its class (42A): the
/// space, and a letter, mark, number, punctuation mark or symbol that is not
/// default-ignorable, other than `\`, U+2800, and a mark with nothing before it
/// to sit on. Every other character is printed by its escape: `\t`, `\n` and `\r`, `\\`
/// for `\` (so an escape is told from the characters of a name), and `\u{…}`
/// for the rest. A quote, a backtick and a letter of any script are printed as
/// they are, and a [`one_plain_word`] is printed unchanged.
///
/// This print has no delimiter of its own, as a cell of a table has none (43A).
/// Where a name sits between delimiters, in prose, it is printed by [`quoted`].
pub fn shown(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for (i, c) in name.chars().enumerate() {
        shown_char(c, i == 0, &mut out);
    }
    out
}

/// One character of [`shown`]'s print, `first` when it is the string's first.
/// Each character is printed by itself and by whether it is the first, so the
/// print of a prefix is a prefix of the print.
fn shown_char(c: char, first: bool, out: &mut String) {
    match c {
        '\\' => out.push_str("\\\\"),
        '\t' => out.push_str("\\t"),
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        c if !kotton_schemas::petname::is_printed_as_is(c, first) => out.push_str(&escape(c)),
        c => out.push(c),
    }
}

/// `c` by its `\u{…}` escape.
fn escape(c: char) -> String {
    format!("\\u{{{:x}}}", u32::from(c))
}

/// `name` as prose prints it, between backticks: [`shown`], with each backtick
/// it holds printed by its escape, `\u{60}` (kottonllc/kotton#597, 43A). So a
/// backtick in a line is always the line's own, and a printed name never ends
/// before its closing delimiter. A [`one_plain_word`] is printed as the word
/// between backticks. A sentence, the join's line and the mint's refusal print
/// a name through this and nowhere else.
pub fn quoted(name: &str) -> String {
    format!("`{}`", shown(name).replace('`', &escape('`')))
}

/// The most characters [`quoted_cut`] prints between its backticks
/// (kottonllc/kotton#597, 74A). It bounds the print, not the string: a
/// character prints in 1 to 10 ([`shown`], [`quoted`]). 512 is past every
/// sentence a vault's code sends today (the longest prints in 358) and short of
/// a screen: six lines and a half at 80 columns.
pub const MAX_SAID_CHARS: usize = 512;

/// `text`, a string another node sent, as prose prints it: as [`quoted`] prints
/// it when its print fits in [`MAX_SAID_CHARS`] characters (kottonllc/kotton#597,
/// 74A, 75A). A longer one is printed as the longest prefix of `text` whose
/// print fits, between its backticks, so the cut never ends inside an escape;
/// then, after the closing backtick, in the device's own words, `(cut: N more
/// characters)`, N the characters of `text` left out.
///
/// The cut is made where text is printed and nowhere a string is compared: a
/// reader that looks for words in an answer reads the answer as it came.
pub fn quoted_cut(text: &str) -> String {
    let mut inside = String::with_capacity(text.len().min(MAX_SAID_CHARS));
    let mut used = 0;
    let mut piece = String::new();
    for (i, c) in text.chars().enumerate() {
        piece.clear();
        match c {
            '`' => piece.push_str(&escape('`')),
            c => shown_char(c, i == 0, &mut piece),
        }
        let len = piece.chars().count();
        if used + len > MAX_SAID_CHARS {
            let left = text.chars().count() - i;
            let unit = if left == 1 { "character" } else { "characters" };
            return format!("`{inside}` (cut: {left} more {unit})");
        }
        used += len;
        inside.push_str(&piece);
    }
    format!("`{inside}`")
}

/// The one sentence a person reads for `note`. `verb` is the removal verb the
/// surface registers (`device revoke`, `kctl sudoers remove`, `vault forget`,
/// `relay forget`), and is said for a row that names no key only: a row that
/// stands by its bytes works, and its sentence is not an instruction.
///
/// A name is put in a command only when it is [`one_plain_word`]. A row that
/// names no key under any other name is told the verb that removes it, by that
/// name, as recorded, and given no command (23A, 44A). A row that stands by its
/// bytes is told which names a command takes, plain words or not, and given no
/// command. Each name is printed by [`quoted`], between its backticks.
pub fn sentence(note: &RowNote, verb: &str) -> String {
    let name = quoted(&note.name);
    match &note.is {
        NoteKind::NamesNoKey if one_plain_word(&note.name) => format!(
            "{name} names no Ed25519 key, so nothing is reached or checked under it; `{verb} {}` removes it",
            shown(&note.name)
        ),
        NoteKind::NamesNoKey => format!(
            "{name} names no Ed25519 key, so nothing is reached or checked under it; `{verb}` is the verb that removes it, by this name, as recorded"
        ),
        NoteKind::StandsByBytes { did_key, stored } => {
            let takes = if *stored == note.name {
                "that recorded name".to_string()
            } else {
                format!("{name} or that recorded name")
            };
            // A name that is no plain word is typed so that the surface reads it
            // as recorded; the sentence says so and composes no command for it.
            let as_recorded =
                if one_plain_word(&note.name) && one_plain_word(stored) { "" } else { ", as recorded" };
            format!(
                "{name} is reached and checked under its key, {}, as before. It is recorded here as {}, and a \
                 command that names it takes {takes}{as_recorded}, not the key's",
                quoted(did_key),
                quoted(stored)
            )
        }
    }
}

/// A listing's rows as a client hands them to its caller, with the notes the
/// answer carried beside them. It reads as its rows (`Deref`, `IntoIterator`),
/// so a caller that wants only the rows reads it as it read the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed<T> {
    /// The rows, as the answer listed them.
    pub rows: Vec<T>,
    /// A note for each row that names no key, or stands by its bytes.
    pub notes: Vec<RowNote>,
}

impl<T> std::ops::Deref for Listed<T> {
    type Target = Vec<T>;
    fn deref(&self) -> &Vec<T> {
        &self.rows
    }
}

impl<T> IntoIterator for Listed<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;
    fn into_iter(self) -> Self::IntoIter {
        self.rows.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a Listed<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.rows.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **A row that names no key is told so, with the verb and its name; a row
    /// that stands by its bytes is told which names a command takes, and no
    /// removal verb.**
    #[test]
    fn the_sentence_names_the_verb_for_a_row_that_names_no_key_only() {
        let said = sentence(&RowNote::names_no_key("attic"), "vault forget");
        assert_eq!(
            said,
            "`attic` names no Ed25519 key, so nothing is reached or checked under it; `vault forget attic` removes it"
        );

        let stands = |name: &str| RowNote {
            name: name.into(),
            is: NoteKind::StandsByBytes { did_key: "did:key:z6MkKey".into(), stored: "did:key:mOther".into() },
        };
        for name in ["phone", "did:key:mOther"] {
            let said = sentence(&stands(name), "device revoke");
            assert!(!said.contains("device revoke"), "a working row was told how to remove it: {said}");
            assert!(said.contains("`did:key:z6MkKey`") && said.contains("`did:key:mOther`"), "{said}");
            assert!(said.contains("as before") && said.contains("not the key's"), "{said}");
        }
        assert!(sentence(&stands("phone"), "device revoke").contains("takes `phone` or that recorded name"));
        assert!(sentence(&stands("did:key:mOther"), "device revoke").contains("takes that recorded name"));
    }

    /// The removal verbs the surfaces register, each of which a first-kind
    /// sentence is said with (kottonllc/kotton#618).
    const VERBS: [&str; 4] = ["device revoke", "vault forget", "relay forget", "kctl sudoers remove"];

    /// A name in another script, a name with a quote, and a name that starts
    /// with `-`: none is one plain word (kottonllc/kotton#618).
    const NO_PLAIN_NAME: [&str; 3] = ["\u{5c4b}\u{6839}\u{88cf}", "it's", "-attic"];

    /// **A name is one plain word by the allow-list, and a sentence puts a name in
    /// a command only when it is one** (20A): a row that names no key under a name
    /// that is not one is told its verb and that the verb removes it by this name,
    /// as recorded (23A, 44A); a row that stands by its bytes is told the names a command takes,
    /// as recorded. Neither is given a command.
    #[test]
    fn a_sentence_names_a_command_only_with_one_plain_word() {
        for word in ["attic", "phone-2", "my_box.local", "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"] {
            assert!(one_plain_word(word), "{word}");
            assert_eq!(shown(word), word, "a plain word is shown as it is");
        }
        let not_words =
            ["", "my phone", "a;b", "a|b", "a&&b", "it's", "say\"x", "a`b", "--x", "--browser", "-x", "bell\u{7}", "a\tb", "$HOME", "a\\b", "a>b", "caf\u{e9}"];
        for name in not_words {
            assert!(!one_plain_word(name), "{name:?}");
            let said = sentence(&RowNote::names_no_key(name), "device revoke");
            assert!(said.contains("names no Ed25519 key"), "{said}");
            assert!(said.ends_with("; `device revoke` is the verb that removes it, by this name, as recorded"), "{said}");
            assert!(!said.contains("device revoke "), "a command was composed: {said}");
            let stands = RowNote {
                name: name.into(),
                is: NoteKind::StandsByBytes { did_key: "did:key:z6MkKey".into(), stored: name.into() },
            };
            let said = sentence(&stands, "device revoke");
            assert!(!said.contains("device revoke"), "{said}");
            assert!(said.ends_with("takes that recorded name, as recorded, not the key's"), "{said}");
            assert!(said.contains(&format!("recorded here as {}", quoted(name))), "{said}");
        }
        let label_beside_odd_did = RowNote {
            name: "phone".into(),
            is: NoteKind::StandsByBytes { did_key: "did:key:z6MkKey".into(), stored: "did:key:a b".into() },
        };
        assert!(sentence(&label_beside_odd_did, "device revoke")
            .ends_with("takes `phone` or that recorded name, as recorded, not the key's"));

        // A DID as stored is one plain word in every multibase spelling but
        // Base45's and Base256Emoji's, whose row's sentence names its verb and
        // composes no command.
        for line in include_str!("did/did-key-spellings.txt").lines().filter(|l| !l.starts_with('#')) {
            let (base, did) = line.split_once(' ').unwrap();
            let a_word = !matches!(base, "Base45" | "Base256Emoji");
            assert_eq!(one_plain_word(did), a_word, "{line}");
            let said = sentence(&RowNote::names_no_key(did), "device revoke");
            assert_eq!(said.contains("`device revoke "), a_word, "{said}");
            assert_eq!(said.contains("`device revoke` is the verb that removes it"), !a_word, "{said}");
        }
    }

    /// **A row of the first kind whose name is not one plain word is told the
    /// verb that removes it, by that name, and given no command**, for each verb a
    /// surface says it with (kottonllc/kotton#618, 23A): a name in another script,
    /// one with a quote, and one that starts with `-`. Of the second kind, the
    /// sentence says which names a command takes, and names no verb.
    #[test]
    fn a_row_with_no_plain_name_is_told_its_verb_and_given_no_command() {
        for verb in VERBS {
            for name in NO_PLAIN_NAME {
                let said = sentence(&RowNote::names_no_key(name), verb);
                assert!(said.contains(&format!("`{verb}` is the verb that removes it, by this name, as recorded")), "{said}");
                assert!(said.starts_with(&format!("`{name}` names no Ed25519 key")), "the name is not shown: {said}");
                assert!(!said.contains(&format!("{verb} ")), "a command was composed: {said}");
                assert!(!said.contains(&format!("{verb} {name}")), "{said}");
            }
        }
        for name in NO_PLAIN_NAME {
            let stands = RowNote {
                name: name.into(),
                is: NoteKind::StandsByBytes { did_key: "did:key:z6MkKey".into(), stored: "did:key:z6MkOld".into() },
            };
            let said = sentence(&stands, "device revoke");
            assert!(!said.contains("device revoke"), "{said}");
            assert!(said.ends_with(&format!("takes `{name}` or that recorded name, as recorded, not the key's")), "{said}");
        }
    }

    /// **A name that is not one plain word is printed as data: each character it
    /// holds is shown, a control character by its escape** (kottonllc/kotton#618).
    /// A letter of another script, a quote and a backtick are shown as they are;
    /// a control, invisible, bidirectional or blank character, whitespace other
    /// than the space, and a mark with nothing to sit on are shown escaped, and
    /// `\` is escaped so an escape is told from a name's own characters.
    #[test]
    fn a_name_is_shown_with_each_character_it_holds() {
        for as_is in ["\u{5c4b}\u{6839}\u{88cf}", "it's", "-attic", "say\"x", "a`b", "my phone", "caf\u{e9}", "e\u{301}"] {
            assert_eq!(shown(as_is), as_is);
        }
        for (name, said) in [
            ("bell\u{7}", "bell\\u{7}"),
            ("a\tb", "a\\tb"),
            ("a\nb", "a\\nb"),
            ("a\rb", "a\\rb"),
            ("esc\u{1b}[2K", "esc\\u{1b}[2K"),
            ("\u{202e}kcatta", "\\u{202e}kcatta"),
            ("at\u{200b}tic", "at\\u{200b}tic"),
            ("at\u{a0}tic", "at\\u{a0}tic"),
            ("at\u{3164}tic", "at\\u{3164}tic"),
            ("\u{301}attic", "\\u{301}attic"),
            ("a\\u{7}", "a\\\\u{7}"),
        ] {
            assert_eq!(shown(name), said, "{name:?}");
            let sentence = sentence(&RowNote::names_no_key(name), "vault forget");
            assert!(sentence.starts_with(&format!("`{said}` names no Ed25519 key")), "{sentence}");
            assert!(!sentence.contains(name), "a character was printed unshown: {sentence:?}");
        }
        assert_ne!(shown("a\u{7}"), shown("a\\u{7}"), "a control character and its escape typed out read alike");
        // A backtick is printed as it is in a cell, which has no delimiter, and by its
        // escape between a sentence's backticks (43A).
        let said = sentence(&RowNote::names_no_key("a`b"), "vault forget");
        assert!(said.starts_with("`a\\u{60}b` names no Ed25519 key"), "{said}");
    }

    /// The general category of `c`, and whether it is default-ignorable, read from
    /// Unicode's tables here and not through the predicate under test.
    fn class_of(c: char) -> (icu_properties::props::GeneralCategory, bool) {
        use icu_properties::props::{DefaultIgnorableCodePoint, GeneralCategory};
        (
            icu_properties::CodePointMapData::<GeneralCategory>::new().get(c),
            icu_properties::CodePointSetData::new::<DefaultIgnorableCodePoint>().contains(c),
        )
    }

    /// **`shown` is held by class, not by list** (kottonllc/kotton#597, 42A), in both
    /// directions, over every code point, each class read from Unicode's tables here:
    ///
    /// - a control, format, private-use or unassigned character, a separator other than
    ///   the space, and a default-ignorable character is printed by its escape, and a name
    ///   that holds it prints apart from the name without it and from its own print typed
    ///   out; every character the list `shown` was built on escaped is still escaped,
    ///   U+2800 and the Hangul fillers among them;
    /// - each letter, mark after a letter, number, punctuation mark and symbol that is not
    ///   default-ignorable, and the space, is printed as it is, less `\` and U+2800;
    /// - a mark of any block with nothing before it is printed by its escape.
    #[test]
    fn shown_is_held_by_class_not_by_list() {
        use icu_properties::props::{GeneralCategory as Gc, GeneralCategoryGroup as G};
        use kotton_schemas::petname::{is_hostile_char, renders_blank};
        let plain = shown("ab");
        let mut escaped = 0usize;
        let mut as_is = 0usize;
        let mut marks = 0usize;
        for c in (0..=0x10ffffu32).filter_map(char::from_u32) {
            let (class, ignorable) = class_of(c);
            let by_class = matches!(class, Gc::Control | Gc::Format | Gc::PrivateUse | Gc::Unassigned)
                || (G::Separator.contains(class) && c != ' ')
                || ignorable;
            let by_list = is_hostile_char(c) || (c.is_whitespace() && c != ' ') || renders_blank(c);
            let drawn = c == ' '
                || [G::Letter, G::Mark, G::Number, G::Punctuation, G::Symbol].iter().any(|g| g.contains(class));
            let name = format!("a{c}b");
            let print = shown(&name);
            if drawn && !ignorable && !matches!(c, '\\' | '\u{2800}') {
                as_is += 1;
                assert_eq!(print, name, "{c:?} ({class:?}) after a letter was not printed as it is");
            }
            if G::Mark.contains(class) {
                marks += 1;
                let first = format!("{c}a");
                assert_eq!(
                    shown(&first),
                    format!("\\u{{{:x}}}a", u32::from(c)),
                    "{c:?} ({class:?}) with nothing before it was not printed by its escape"
                );
            }
            if by_class || by_list {
                escaped += 1;
                assert!(!print.contains(c), "{c:?} ({class:?}) was printed as it is: {print:?}");
                let escape = match c {
                    '\t' => "\\t".to_string(),
                    '\n' => "\\n".to_string(),
                    '\r' => "\\r".to_string(),
                    c => format!("\\u{{{:x}}}", u32::from(c)),
                };
                assert_eq!(print, format!("a{escape}b"), "{c:?}");
                assert_ne!(print, plain, "{c:?}: a name with it and without it print alike");
                assert_ne!(print, shown(&print), "{c:?}: a name and its print typed out print alike");
            }
        }
        assert!(escaped > 900_000, "{escaped}: the tables were not read");
        assert!(as_is > 150_000, "{as_is}: the printed-as-it-is classes were not read");
        assert!(marks > 2_000, "{marks}: the marks were not read");
        for filler in ['\u{115f}', '\u{1160}', '\u{2800}', '\u{3164}', '\u{ffa0}'] {
            assert_eq!(shown(&format!("a{filler}")), format!("a\\u{{{:x}}}", u32::from(filler)));
        }
        for as_is in ["\u{5c4b}\u{6839}\u{88cf}", "\u{0434}\u{043e}\u{043c}", "it's", "say\"x", "e\u{301}", "my phone", "a`b", "\u{2603}"] {
            assert_eq!(shown(as_is), as_is, "{as_is:?}");
        }
    }

    /// Names that hold the delimiter, a space, and each verb's own words: none may
    /// end its print before its closing backtick (kottonllc/kotton#597, 43A).
    fn delimiter_names() -> Vec<String> {
        let mut names: Vec<String> =
            ["`", "a`b", "``", "my phone", "a` b", "x` removes it; `y"].iter().map(|n| n.to_string()).collect();
        for verb in VERBS {
            names.push(format!("x` {verb} y"));
            names.push(format!("x`; `{verb} x` removes it"));
            names.push(format!("{verb} `x`"));
        }
        names
    }

    /// **A printed name never ends before its closing delimiter** (kottonllc/kotton#597,
    /// 43A): for names that hold a backtick, a space and each verb's words, of both kinds
    /// and for each verb, the sentence holds exactly as many backticks as the same
    /// sentence for a name of the same branch that holds none. Two names that differ only
    /// in a backtick print differently.
    #[test]
    fn a_printed_name_never_ends_before_its_closing_delimiter() {
        let ticks = |s: &str| s.matches('`').count();
        let stands = |name: &str, did_key: &str, stored: &str| RowNote {
            name: name.into(),
            is: NoteKind::StandsByBytes { did_key: did_key.into(), stored: stored.into() },
        };
        for verb in VERBS {
            let first = ticks(&sentence(&RowNote::names_no_key("it's"), verb));
            let other_stored = ticks(&sentence(&stands("it's", "did:key:z6MkKey", "did:key:z6MkOld"), verb));
            let same_stored = ticks(&sentence(&stands("it's", "did:key:z6MkKey", "it's"), verb));
            for name in delimiter_names() {
                let said = sentence(&RowNote::names_no_key(&name), verb);
                assert_eq!(ticks(&said), first, "{name:?}: {said}");
                assert!(said.starts_with(&quoted(&name)), "{said}");
                let said = sentence(&stands(&name, "did:key:z6MkKey", "did:key:z6MkOld"), verb);
                assert_eq!(ticks(&said), other_stored, "{name:?}: {said}");
                let said = sentence(&stands(&name, "did:key:z6MkKey", &name), verb);
                assert_eq!(ticks(&said), same_stored, "{name:?}: {said}");
                let said = sentence(&stands("phone", &name, &name), verb);
                assert_eq!(ticks(&said), ticks(&sentence(&stands("phone", "it's", "it's"), verb)), "{name:?}: {said}");
            }
        }
        assert_ne!(quoted("ab"), quoted("a`b"));
        assert_ne!(sentence(&RowNote::names_no_key("a b"), "vault forget"), sentence(&RowNote::names_no_key("a` b"), "vault forget"));
        assert_ne!(quoted("a`b"), quoted("a\\u{60}b"), "a backtick and its escape typed out read alike");
        assert_eq!(quoted("attic"), "`attic`");
    }

    /// **The second kind's key is printed through the same print as its names**
    /// (kottonllc/kotton#597, 42A, 43A): a `did_key` that holds a character `shown`
    /// escapes, or a backtick, is printed by its escapes.
    #[test]
    fn the_second_kinds_key_is_printed_as_data() {
        for did_key in ["did:key:z6Mk\u{202e}yeK", "did:key:z6Mk\u{200d}Key", "did:key:z6Mk`Key", "did:key:z6Mk\u{7}"] {
            let note = RowNote {
                name: "phone".into(),
                is: NoteKind::StandsByBytes { did_key: did_key.into(), stored: "did:key:z6MkOld".into() },
            };
            let said = sentence(&note, "device revoke");
            assert!(said.contains(&format!("under its key, {}, as before", quoted(did_key))), "{said}");
            assert!(!said.contains(did_key), "the key was printed as given: {said:?}");
        }
    }

    /// What `quoted_cut` printed between its backticks, and the words after.
    fn cut_parts(said: &str) -> (&str, &str) {
        let close = said[1..].find('`').expect("a closing backtick") + 1;
        assert!(said.starts_with('`'), "{said}");
        (&said[1..close], &said[close + 1..])
    }

    /// **A string whose print fits is printed as `quoted` prints it, whole**
    /// (kottonllc/kotton#597, 74A): at the bound, and with a backtick and a line
    /// break, each printed by its escape.
    #[test]
    fn a_said_string_that_fits_is_printed_as_quoted_prints_it() {
        let at = "a".repeat(MAX_SAID_CHARS);
        assert_eq!(quoted_cut(&at), quoted(&at));
        let said = quoted_cut("no drive `photos`\nhere");
        assert_eq!(said, quoted("no drive `photos`\nhere"));
        assert_eq!(said, "`no drive \\u{60}photos\\u{60}\\nhere`");
        assert!(!said.contains('\n'), "{said:?}");
        for text in ["", "attic", "\u{301}mark first", "caf\u{e9} \u{202e}x\u{7}", "a\\b\tc\r"] {
            assert_eq!(quoted_cut(text), quoted(text), "{text:?}");
        }
    }

    /// **A string past the bound is cut, and says so after its closing
    /// backtick, counting the string's characters left out** (74A).
    #[test]
    fn a_said_string_past_the_bound_is_cut_and_says_by_how_much() {
        let past = "\u{e9}".repeat(MAX_SAID_CHARS + 40);
        let said = quoted_cut(&past);
        let (inside, after) = cut_parts(&said);
        assert_eq!(inside, "\u{e9}".repeat(MAX_SAID_CHARS));
        assert_eq!(after, " (cut: 40 more characters)");
        let one = "a".repeat(MAX_SAID_CHARS + 1);
        assert_eq!(cut_parts(&quoted_cut(&one)).1, " (cut: 1 more character)");
    }

    /// **A string of escapes past the bound ends on a whole escape, with at most
    /// `MAX_SAID_CHARS` characters between its backticks, and the count is the
    /// string's, not the print's** (74A).
    #[test]
    fn a_cut_never_ends_inside_an_escape() {
        // `\u{7}` prints in 6, a backtick in 6, `\u{10ffff}` in 10, `\n` in 2.
        for unit in ["\u{7}", "`", "\u{10ffff}", "\n", "x\u{7}"] {
            let text = unit.repeat(MAX_SAID_CHARS);
            let said = quoted_cut(&text);
            let (inside, after) = cut_parts(&said);
            let printed = inside.chars().count();
            assert!(printed <= MAX_SAID_CHARS, "{unit:?}: {printed}");
            let whole = quoted(&text);
            let whole = &whole[1..whole.len() - 1];
            assert!(whole.starts_with(inside), "{unit:?}: the cut is not a prefix of the print");
            // The longest prefix: one more character of the string would not fit.
            let kept = (0..=text.chars().count())
                .rev()
                .find(|n| shown(&text.chars().take(*n).collect::<String>()).replace('`', "\\u{60}") == inside)
                .expect("the cut is the print of a prefix");
            let next: String = text.chars().take(kept + 1).collect();
            assert!(quoted(&next).chars().count() - 2 > MAX_SAID_CHARS, "{unit:?}: a longer prefix fits");
            let left = text.chars().count() - kept;
            assert_eq!(after, format!(" (cut: {left} more characters)"), "{unit:?}");
        }
    }

    /// **A note's wire is its name and its kind**, so an older reader that
    /// does not know the field beside the rows ignores it whole.
    #[test]
    fn a_note_reads_back_as_written() {
        for note in [
            RowNote::names_no_key("did:key:zOld"),
            RowNote { name: "laptop".into(), is: NoteKind::StandsByBytes { did_key: "k".into(), stored: "s".into() } },
        ] {
            let wire = serde_json::to_string(&note).unwrap();
            assert_eq!(serde_json::from_str::<RowNote>(&wire).unwrap(), note, "{wire}");
        }
        assert_eq!(
            serde_json::to_string(&RowNote::names_no_key("x")).unwrap(),
            r#"{"name":"x","is":"names_no_key"}"#
        );
    }
}
