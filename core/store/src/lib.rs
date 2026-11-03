// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `store` domain.
//!
//! Laid out by tier within the domain: `provider` holds the implementations,
//! and `runtime` the tier above them.

pub mod fetch;
pub mod fs_view;
pub mod provider;
pub mod runtime;
pub mod shelf;
pub mod stack;

pub use provider::*;
pub use fs_view::Fs;
pub use shelf::LocalShelves;
/// A storage key, admitted ([`kotton_sys::store::key`]). It lives in
/// `kotton-sys`, the layer `kotton-sealed` and the store trait can name too
/// (kotton #275); this re-export keeps `kotton_store::StorageKey` the one
/// spelling callers above this crate use.
pub use kotton_sys::store::key::{NotCanonical, StorageKey};

#[cfg(test)]
mod tests {
    use super::*;

    /// The keys the store writes are admitted as they are.
    ///
    /// The parser's own tests are in `kotton_sys::store::key`; this one stays
    /// here because it names the keys this crate writes, blinded by
    /// `kotton-crypto`, which `kotton-sys` cannot depend on (`kotton-crypto`
    /// depends on it).
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
            // A key outside the blinded alphabet is not refused here (`kotton_sys::store::key`'s doc).
            "a/big.bin",
        ] {
            assert_eq!(StorageKey::parse(key).map(|k| k.to_string()), Ok(key.to_string()));
        }
    }
}
