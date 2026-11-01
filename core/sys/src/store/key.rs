// SPDX-License-Identifier: AGPL-3.0-or-later
//! A storage key, admitted once, where it enters (kotton #265).
//!
//! A sync pass takes the keys it moves from listings: its own, and the
//! remote's, which is whatever a drive or another device chose to answer. A
//! serving device answers `ReadSealed`, `WriteSealed` and `ListSealed` with
//! keys and prefixes a peer named. Every one of those keys becomes a path when
//! a filesystem store resolves it, and a path follows `..`: before this type,
//! a listed key such as `../x` was written beside the puller's mount, and
//! `./_pack/i-1` landed in the pack directory under a name the namespace rule
//! (`kotton_store::packed::kind`) read as a file.
//!
//! So a key from outside is parsed into a [`StorageKey`] before anything is
//! built from it, and refused when it is not in the one form the store writes:
//!
//! - not empty, and no component empty: no leading `/`, no trailing `/`, no
//!   `//`;
//! - no component `.` or `..`;
//! - no `\`, which a Windows host reads as a separator;
//! - no control character.
//!
//! Each such key names exactly one object under the mount root, and no other
//! spelling names the same one. What reads a key after admission (the
//! namespace rule, the sync scope, the keep step) reads it as it is, with no
//! leading `/` to read past.
//!
//! What this does **not** hold is the alphabet: a component is not required
//! to be base32 or one of the reserved names. Stores hold keys outside it
//! today (a mount not yet migrated to blinded keys, and objects a test or a
//! tenant writes under a plain name), so that tightening is its own change.
//!
//! ## Who reads it, and why it lives here
//!
//! - `kotton-store` admits a sync pass's listings, a peer's `ReadSealed` and
//!   `WriteSealed` keys, and builds its pack ids on it
//!   (`kotton_store::packed::PackId`); it re-exports both types, so
//!   `kotton_store::StorageKey` is the same type as this one.
//! - `kotton-sealed` takes it in `Sealed::{read, write, list}`, so the sealed
//!   view of a store has no `&str` door that rewrites a key it was handed
//!   (kotton #275, #320).
//! - This crate's store trait names it, so `packs_holding` hands back keys
//!   already admitted rather than text a caller must parse again
//!   (kotton #301).
//! - `kotton-device` parses a peer's `ListSealed` prefix into one before it
//!   asks a store anything.
//!
//! It is here, not in `kotton-store`, because `kotton-store` depends on
//! `kotton-sealed`: `Sealed` cannot name a type `kotton-store` owns, and
//! neither can this crate's trait. This crate is the layer every
//! store-facing crate can name, so the one parser sits here and nothing
//! keeps a second spelling of it.
//!
//! Three other homes were weighed and rejected (kotton #275). A copy of the
//! parser in `kotton-sealed` would be two spellings of one admission, free
//! to drift apart. The type in `kotton-sealed` alone would serve `Sealed`
//! but not this crate's store trait, which names it too (kotton #301), so it
//! would have to move again. Folding `Sealed` into `kotton-store` would undo
//! the tier `kotton-sealed`'s crate doc defends: the sealed view sits below
//! the store, not inside it.

use std::borrow::Borrow;
use std::fmt;
use std::path::Path;

/// A storage key in canonical form (module doc). Built only by
/// [`StorageKey::parse`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StorageKey(String);

/// Why a key was refused: the key as it was given, and what about it is not
/// canonical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotCanonical {
    /// The key as given.
    pub key: String,
    /// What is wrong with it, in words.
    pub why: &'static str,
}

impl fmt::Display for NotCanonical {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "storage key {:?} refused: {}", self.key, self.why)
    }
}

impl std::error::Error for NotCanonical {}

impl NotCanonical {
    /// `n` refused keys as a person reads them: "1 key that is not a storage key", "3 keys
    /// that are not storage keys". The one spelling every door that counts them reads, so the
    /// daemon's answer and the shell's note cannot say it two ways (kotton #315).
    pub fn counted(n: usize) -> String {
        if n == 1 {
            "1 key that is not a storage key".to_string()
        } else {
            format!("{n} keys that are not storage keys")
        }
    }
}

impl StorageKey {
    /// Admit `key`, or say why it is not canonical.
    pub fn parse(key: &str) -> Result<Self, NotCanonical> {
        let refuse = |why| Err(NotCanonical { key: key.to_string(), why });
        if key.is_empty() {
            return refuse("it is empty");
        }
        if key.starts_with('/') {
            return refuse("it starts with `/`");
        }
        if key.contains('\\') {
            return refuse("it holds a `\\`");
        }
        if key.chars().any(char::is_control) {
            return refuse("it holds a control character");
        }
        for component in key.split('/') {
            match component {
                "" => return refuse("a component is empty"),
                "." | ".." => return refuse("a component is `.` or `..`"),
                _ => {}
            }
        }
        Ok(Self(key.to_string()))
    }

    /// The key as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The key as the path a store is addressed by.
    pub fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }
}

impl fmt::Display for StorageKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for StorageKey {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl AsRef<Path> for StorageKey {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

/// Lets a set or map of keys be asked by `&str`; the order is the string's.
impl Borrow<str> for StorageKey {
    fn borrow(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every spelling that is not the one form is refused, each with its reason.
    #[test]
    fn a_key_that_is_not_canonical_is_refused() {
        for (key, why) in [
            ("", "it is empty"),
            ("../x", "a component is `.` or `..`"),
            ("_pack/../x", "a component is `.` or `..`"),
            ("..", "a component is `.` or `..`"),
            ("./_pack/i-1", "a component is `.` or `..`"),
            ("_pack/./i-1", "a component is `.` or `..`"),
            ("/_pack/i-1", "it starts with `/`"),
            ("/", "it starts with `/`"),
            ("_pack/", "a component is empty"),
            ("_pack//i-1", "a component is empty"),
            ("_pack\\i-1", "it holds a `\\`"),
            ("..\\x", "it holds a `\\`"),
            ("_pack/i-1\0", "it holds a control character"),
        ] {
            assert_eq!(
                StorageKey::parse(key),
                Err(NotCanonical { key: key.to_string(), why }),
                "{key:?}"
            );
        }
    }

    /// One refused key is said in the singular, any other count in the plural.
    #[test]
    fn a_count_of_refused_keys_is_said_in_its_number() {
        assert_eq!(NotCanonical::counted(1), "1 key that is not a storage key");
        assert_eq!(NotCanonical::counted(3), "3 keys that are not storage keys");
    }
}
