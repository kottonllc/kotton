// SPDX-License-Identifier: AGPL-3.0-or-later
//! A storage key, admitted once, where it enters (kotton #265).
//!
//! A sync pass takes the keys it moves from listings: its own, and the
//! remote's, which is whatever a drive or another device chose to answer. A
//! serving device answers `ReadSealed` and `WriteSealed` with keys a peer
//! named. Every one of those keys becomes a path when a filesystem store
//! resolves it, and a path follows `..`: before this type, a listed key such
//! as `../x` was written beside the puller's mount, and `./_pack/i-1` landed
//! in the pack directory under a name the namespace rule
//! ([`crate::packed::kind`]) read as a file.
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

    /// The keys the store writes are admitted as they are.
    #[test]
    fn the_keys_the_store_writes_are_admitted() {
        let blinded = kotton_crypto::path_blind::blind_object_key(
            &kotton_crypto::path_blind::derive_path_blind_key(&[0x42; 32]),
            "files/notes/a.txt",
        );
        for key in [
            blinded.as_str(),
            "_pack/c-00ff",
            "_pack/00ff",
            "_superblock/00000000000000000007-00ff",
            crate::packed::TOMBSTONES_KEY,
            // A key outside the blinded alphabet is not refused here (module doc).
            "a/big.bin",
        ] {
            assert_eq!(StorageKey::parse(key).map(|k| k.to_string()), Ok(key.to_string()));
        }
    }

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
}
