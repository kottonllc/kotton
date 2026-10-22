// SPDX-License-Identifier: AGPL-3.0-or-later
//! Blinded object keys (RFC-0044).
//!
//! An object's storage key is derived from its path with a key only the user's
//! devices hold, so a replica storing the ciphertext cannot read the names.
//! `family/legal/filing.pdf` becomes three opaque components.
//!
//! # What this hides, and what it does not
//!
//! It hides **names**: the components, their lengths, and their equality with
//! names anywhere outside their own directory. It does not hide **shape** — the
//! separator survives so `list(prefix)` still works, so a replica can still see
//! that a directory has three children and one of them holds forty objects.
//! RFC-0045's packed store removes the tree entirely; until then, shape is the
//! residual leak and is documented as such.
//!
//! # Why HMAC and not encryption
//!
//! A reversible per-component encryption would let a device recover names
//! straight from the key. It would also make the ciphertext length track the
//! name length, which is itself identifying, and inflate paths further against
//! `MAX_PATH`. A fixed-width one-way function avoids both; names are recovered
//! from the object's own sealed header instead (RFC-0044 M2), which keeps the
//! mnemonic sufficient and leaves no index load-bearing.

use crate::pair_handshake::hmac_sha256;
use hkdf::Hkdf;
use kotton_common::base32;
use kotton_common::crypto::kdf_labels;
use sha2::Sha256;

/// Bytes of HMAC output kept per component.
///
/// 16 bytes → 26 base32 characters. Not a security parameter: an adversary
/// without `K_path` cannot compute *any* blinded value, so collisions are not
/// adversarially reachable. It is a birthday bound (2⁶⁴) against accidental
/// collision inside one user's namespace, and it is truncated this far because
/// path length is a real constraint — `MAX_PATH` on Windows bounds how deep a
/// blinded tree can nest.
const COMPONENT_BYTES: usize = 16;

/// Derive the path-blinding key from the user's **CEK**.
///
/// From the CEK, the object key domain — a path is object metadata, so keeping
/// this key in the domain of the data it protects is what preserves RFC-0036's
/// blast-radius isolation. See RFC-0044 M1 for why the `master_secret`
/// alternative would instead leak every path on a record-database compromise.
pub fn derive_path_blind_key(cek: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, cek);
    let mut out = [0u8; 32];
    hk.expand(kdf_labels::PATH_BLIND.as_bytes(), &mut out)
        .expect("HKDF expand is infallible for 32B output");
    out
}

/// Blind one path component in the context of its already-blinded parent.
///
/// Chaining through the parent is what stops every directory named `photos`
/// blinding to the same value across the whole tree. Equality then leaks only
/// *within* a directory, where a shared prefix already implies the sibling
/// relationship.
fn blind_component(key: &[u8; 32], parent_blinded: &str, component: &str) -> String {
    // The 0x00 separator makes the input unambiguous: without it,
    // ("ab", "c") and ("a", "bc") would hash identically.
    let mut input = Vec::with_capacity(parent_blinded.len() + component.len() + 1);
    input.extend_from_slice(parent_blinded.as_bytes());
    input.push(0x00);
    input.extend_from_slice(component.as_bytes());

    let tag = hmac_sha256(key, &input);
    base32::encode(&tag[..COMPONENT_BYTES])
}

/// Blind an object key, component by component.
///
/// `key` is a canonical object key — forward slashes, no leading slash, already
/// through `normalize_vfs_path` (so no `.` or `..` remain). An empty key blinds
/// to empty, which keeps `list("")` meaning "everything".
///
/// Deterministic: the same path always yields the same blinded key, so writes
/// stay idempotent and a replica's dedup keeps working.
///
/// Prefix-structured: blinding a prefix and blinding a full path agree on their
/// shared components, so `list(prefix)` works by blinding the prefix and listing
/// against it. RFC-0002 path scoping is unaffected — a scope is a path.
pub fn blind_object_key(key: &[u8; 32], object_key: &str) -> String {
    let mut blinded = String::new();
    for component in object_key.split('/').filter(|c| !c.is_empty()) {
        let next = blind_component(key, &blinded, component);
        if !blinded.is_empty() {
            blinded.push('/');
        }
        blinded.push_str(&next);
    }
    blinded
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: [u8; 32] = [0x11; 32];

    fn k() -> [u8; 32] {
        derive_path_blind_key(&MS)
    }

    /// The property the whole RFC rests on: no component of the plaintext path
    /// survives into the stored key.
    #[test]
    fn a_blinded_key_contains_no_component_of_the_path() {
        let blinded = blind_object_key(&k(), "family/legal/divorce-filing-2026.pdf");
        for part in ["family", "legal", "divorce", "filing", "2026", "pdf"] {
            assert!(
                !blinded.contains(part),
                "{part:?} leaked into the blinded key {blinded}"
            );
        }
    }

    /// Parent-chaining: the same name in two places must not blind alike, or the
    /// replica learns that two directories share a name.
    #[test]
    fn the_same_name_under_different_parents_blinds_differently() {
        let key = k();
        let a = blind_object_key(&key, "work/photos");
        let b = blind_object_key(&key, "family/photos");
        let (leaf_a, leaf_b) = (a.rsplit('/').next().unwrap(), b.rsplit('/').next().unwrap());
        assert_ne!(leaf_a, leaf_b, "`photos` blinded identically under two parents");
    }

    /// …but the same path must blind identically every time, or writes stop being
    /// idempotent and every re-sync duplicates the corpus.
    #[test]
    fn blinding_is_deterministic() {
        let key = k();
        assert_eq!(
            blind_object_key(&key, "notes/2026/trip.md"),
            blind_object_key(&key, "notes/2026/trip.md"),
        );
    }

    /// Prefix structure survives, which is what keeps `list(prefix)` and RFC-0002
    /// path scoping working.
    #[test]
    fn a_blinded_prefix_is_a_prefix_of_the_blinded_path() {
        let key = k();
        let prefix = blind_object_key(&key, "notes/2026");
        let full = blind_object_key(&key, "notes/2026/trip.md");
        assert!(
            full.starts_with(&format!("{prefix}/")),
            "{full} should sit under {prefix}"
        );
    }

    /// Every component is the same width, so the stored key discloses nothing
    /// about how long the original names were.
    #[test]
    fn components_are_fixed_width() {
        let key = k();
        let blinded = blind_object_key(&key, "a/considerably-longer-name-than-a/x");
        for component in blinded.split('/') {
            assert_eq!(component.len(), 26, "component {component} is not 26 chars");
        }
    }

    /// A different user cannot compute another's keys, so a replica serving two
    /// users learns nothing by comparing them.
    #[test]
    fn a_different_key_yields_a_different_blinding() {
        let other = derive_path_blind_key(&[0x22; 32]);
        assert_ne!(
            blind_object_key(&k(), "notes/trip.md"),
            blind_object_key(&other, "notes/trip.md"),
        );
    }

    /// The separator is unambiguous: two different splits of the same characters
    /// must not collide.
    #[test]
    fn component_boundaries_are_unambiguous() {
        let key = k();
        assert_ne!(
            blind_object_key(&key, "ab/c"),
            blind_object_key(&key, "a/bc"),
        );
    }

    #[test]
    fn empty_key_blinds_to_empty() {
        assert_eq!(blind_object_key(&k(), ""), "");
    }
}
