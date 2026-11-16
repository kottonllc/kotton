// SPDX-License-Identifier: AGPL-3.0-or-later
//! Decentralized identifiers: `did:key`, and the resolvers that read a DID document.
//!
//! A `did:key` that [`DidKeyMethod`] makes or reads names an Ed25519 key that passed the rule
//! ([`kotton_ed25519::VerifyingKey::from_bytes`], re-exported as `kotton_crypto::ed25519`), or
//! it names nothing. [`DidKeyMethod::from_public_key`] takes the rule's key,
//! [`DidKeyMethod::from_public_key_bytes`] constructs it or refuses, and
//! [`DidKeyMethod::to_public_key`] returns it or refuses, with [`DidError::InvalidKey`] and not
//! the clause.
//!
//! **One key has one `did:key`:** `did:key:z` followed by the base58btc of `0xed 0x01` and the
//! key's 32 bytes, the string [`DidKeyMethod::from_public_key`] makes. The decode returns a key
//! only where the DID equals that string of the key it reads, so another spelling of the same
//! bytes, under any other base the multibase codec reads, names no key. Two strings never name
//! one key, as the protocol's Ed25519 rule says: a list of admitted keys, an index by key and a
//! `did:key` compare as bytes. [`DidKeyMethod::to_document`], and [`DidKeyResolver`] through
//! it, go through the decode.
//!
//! **The key is held by `DidKeyMethod` only.** The tree has two other readers of a `did:key`:
//! `kotton_schemas::Publisher::new`, and the relay's `ed25519_key_from_did`. All three read
//! the same one spelling, held by one committed file of spellings
//! (`kotton-wire`'s `src/did/did-key-spellings.txt`) and a test of each reader over it. They
//! do not yet agree on the key: `Publisher` holds the string's grammar and not the rule
//! (kottonllc/kotton#607), and the relay builds the library's key (kottonllc/kotton#565).
//!
//! A row stored under bytes the rule refuses, or under a string that is not its key's
//! `did:key`, is read by what it is read by (kottonllc/kotton#597). Where the string is all
//! that is stored, the row is read as no key: nothing is admitted, indexed or checked under
//! it, and the verb that removes any row removes it by what is stored, not through the decode.
//! Where the key's bytes are stored beside it, the row stands by its bytes if they pass, and
//! the string beside them is never passed on as the key's name.
//!
//! A listing tells the person of each such row (kottonllc/kotton#605): its answer carries,
//! beside the rows, a `kotton_wire::note::RowNote` for each, with the name a command takes
//! and which of the two it is, and `kotton_wire::note::sentence` says it with the removal
//! verb the surface registers. The node listing, `kctl sudoers list`, `drive list`, the
//! network readout's kept credentials and the admitting side of a join each say it.
//!
//! [`DidError::InvalidKey`]: kotton_wire::did::DidError::InvalidKey
//! [`DidKeyResolver`]: resolver::DidKeyResolver
pub mod key_method;
pub mod resolver;

pub use key_method::DidKeyMethod;
pub use resolver::{CompositeDidResolver, DidKeyResolver, DidResolver, DidWebResolver};
