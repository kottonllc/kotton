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
//! A note's name is one the verb its sentence names takes to the row, typed as
//! the sentence gives it (20A): it is put in a command only when it is
//! [`one_plain_word`].

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
    /// and the surface's removal verb removes it by `name`.
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
/// one word with nothing to expand: one or more of the ASCII letters and digits
/// and `.`, `_`, `:`, `-`, `+`, `/`, `=`, not starting with `-`. So no
/// whitespace, no control character, no quote, backtick, `\\`, `$`, `*`, `;`,
/// `|`, `&`, `<` or `>`, and nothing a command would read as a flag. A `did:key`
/// is such a word in every multibase spelling but Base45's and Base256Emoji's.
pub fn one_plain_word(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('-')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-' | '+' | '/' | '='))
}

/// The one sentence a person reads for `note`. `verb` is the removal verb the
/// surface registers (`device revoke`, `kctl sudoers remove`, `vault forget`),
/// and is said, with the note's name, for a row that names no key only: a row
/// that stands by its bytes works, and its sentence is not an instruction.
///
/// A name is put in a command, or said to be one a command takes, only when it
/// is [`one_plain_word`]; a row whose names are none such is told what is true
/// of it and given no command to type.
pub fn sentence(note: &RowNote, verb: &str) -> String {
    let name = &note.name;
    match &note.is {
        NoteKind::NamesNoKey if one_plain_word(name) => format!(
            "`{name}` names no Ed25519 key, so nothing is reached or checked under it; `{verb} {name}` removes it"
        ),
        NoteKind::NamesNoKey => format!("`{name}` names no Ed25519 key, so nothing is reached or checked under it"),
        NoteKind::StandsByBytes { did_key, stored } => {
            let said = format!(
                "`{name}` is reached and checked under its key, `{did_key}`, as before. It is recorded here as `{stored}`"
            );
            let takes = match (one_plain_word(name), one_plain_word(stored)) {
                (_, true) if stored == name => "that recorded name".to_string(),
                (true, true) => format!("`{name}` or that recorded name"),
                (true, false) => format!("`{name}`"),
                (false, true) => "that recorded name".to_string(),
                (false, false) => return format!("{said}."),
            };
            format!("{said}, and a command that names it takes {takes}, not the key's")
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

    /// **A name is one plain word by the allow-list, and a sentence puts a name in
    /// a command only when it is one** (20A): a row whose name is not one is told
    /// what is true of it and given nothing to type.
    #[test]
    fn a_sentence_names_a_command_only_with_one_plain_word() {
        for word in ["attic", "phone-2", "my_box.local", "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"] {
            assert!(one_plain_word(word), "{word}");
        }
        let not_words =
            ["", "my phone", "a;b", "a|b", "a&&b", "it's", "say\"x", "a`b", "--x", "--browser", "-x", "bell\u{7}", "a\tb", "$HOME", "a\\b", "a>b", "caf\u{e9}"];
        for name in not_words {
            assert!(!one_plain_word(name), "{name:?}");
            let said = sentence(&RowNote::names_no_key(name), "device revoke");
            assert!(!said.contains("device revoke") && said.contains("names no Ed25519 key"), "{said}");
            let stands = RowNote {
                name: name.into(),
                is: NoteKind::StandsByBytes { did_key: "did:key:z6MkKey".into(), stored: name.into() },
            };
            let said = sentence(&stands, "device revoke");
            assert!(!said.contains("takes") && said.ends_with('.'), "{said}");
        }
        let label_beside_odd_did = RowNote {
            name: "phone".into(),
            is: NoteKind::StandsByBytes { did_key: "did:key:z6MkKey".into(), stored: "did:key:a b".into() },
        };
        assert!(sentence(&label_beside_odd_did, "device revoke").ends_with("takes `phone`, not the key's"));

        // A DID as stored is one plain word in every multibase spelling but
        // Base45's and Base256Emoji's, whose row's sentence names no command.
        for line in include_str!("did/did-key-spellings.txt").lines().filter(|l| !l.starts_with('#')) {
            let (base, did) = line.split_once(' ').unwrap();
            let a_word = !matches!(base, "Base45" | "Base256Emoji");
            assert_eq!(one_plain_word(did), a_word, "{line}");
            let said = sentence(&RowNote::names_no_key(did), "device revoke");
            assert_eq!(said.contains("`device revoke "), a_word, "{said}");
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
