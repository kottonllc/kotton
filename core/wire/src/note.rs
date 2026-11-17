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
///   encoding, and no normal form is applied where a name is stored or where it
///   is typed, so a command printed with such a name is not held to reach its row.
/// - *The seam.* This is the one predicate, and [`sentence`] the one caller that
///   prints a command. Widening it is a normal form applied where a name is
///   stored and where a typed name is compared, then this set, then each
///   surface's read-back test over the wider set. No store, row type or message
///   changes for it.
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
/// shown (kottonllc/kotton#597, 23A). A character that would not be seen, or
/// would change the line it sits in, is shown by its escape: a control
/// character (`\t`, `\n`, `\r`, else `\u{…}`), whitespace other than
/// the space, a character that renders blank, a bidirectional, zero-width or
/// tag character ([`kotton_schemas::petname::is_hostile_char`]), and a
/// combining mark with nothing before it to sit on. `\` is shown as `\\`, so
/// an escape is told from the characters of a name. Every other character,
/// a quote, a backtick and a letter of any script among them, is shown as it is.
/// A [`one_plain_word`] is shown unchanged.
pub fn shown(name: &str) -> String {
    use kotton_schemas::petname::{is_combining_mark, is_hostile_char, renders_blank};
    let mut out = String::with_capacity(name.len());
    for (i, c) in name.chars().enumerate() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if is_hostile_char(c)
                || (c.is_whitespace() && c != ' ')
                || renders_blank(c)
                || (i == 0 && is_combining_mark(c)) =>
            {
                out.push_str(&format!("\\u{{{:x}}}", u32::from(c)))
            }
            c => out.push(c),
        }
    }
    out
}

/// The one sentence a person reads for `note`. `verb` is the removal verb the
/// surface registers (`device revoke`, `kctl sudoers remove`, `vault forget`,
/// `relay forget`), and is said for a row that names no key only: a row that
/// stands by its bytes works, and its sentence is not an instruction.
///
/// A name is put in a command only when it is [`one_plain_word`]. A row that
/// names no key under any other name is told the verb that removes it, by that
/// name, and given no command (23A). A row that stands by its bytes is told
/// which names a command takes, plain words or not, and given no command. Each
/// name is printed by [`shown`].
pub fn sentence(note: &RowNote, verb: &str) -> String {
    let name = shown(&note.name);
    match &note.is {
        NoteKind::NamesNoKey if one_plain_word(&note.name) => format!(
            "`{name}` names no Ed25519 key, so nothing is reached or checked under it; `{verb} {name}` removes it"
        ),
        NoteKind::NamesNoKey => format!(
            "`{name}` names no Ed25519 key, so nothing is reached or checked under it; `{verb}` is the verb that removes it, by this name"
        ),
        NoteKind::StandsByBytes { did_key, stored } => {
            let takes = if *stored == note.name {
                "that recorded name".to_string()
            } else {
                format!("`{name}` or that recorded name")
            };
            // A name that is no plain word is typed so that the surface reads it
            // as recorded; the sentence says so and composes no command for it.
            let as_recorded =
                if one_plain_word(&note.name) && one_plain_word(stored) { "" } else { ", as recorded" };
            format!(
                "`{name}` is reached and checked under its key, `{}`, as before. It is recorded here as `{}`, and a \
                 command that names it takes {takes}{as_recorded}, not the key's",
                shown(did_key),
                shown(stored)
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
    /// that is not one is told its verb and that the verb removes it by this name
    /// (23A); a row that stands by its bytes is told the names a command takes,
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
            assert!(said.ends_with("; `device revoke` is the verb that removes it, by this name"), "{said}");
            assert!(!said.contains("device revoke "), "a command was composed: {said}");
            let stands = RowNote {
                name: name.into(),
                is: NoteKind::StandsByBytes { did_key: "did:key:z6MkKey".into(), stored: name.into() },
            };
            let said = sentence(&stands, "device revoke");
            assert!(!said.contains("device revoke"), "{said}");
            assert!(said.ends_with("takes that recorded name, as recorded, not the key's"), "{said}");
            assert!(said.contains(&format!("recorded here as `{}`", shown(name))), "{said}");
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
                assert!(said.contains(&format!("`{verb}` is the verb that removes it, by this name")), "{said}");
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
