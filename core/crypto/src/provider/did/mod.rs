// SPDX-License-Identifier: AGPL-3.0-or-later
//! Decentralized identifiers: `did:key`, and the resolvers that read a DID document.
//!
//! A `did:key` this tree makes or reads names an Ed25519 key that passed the rule
//! ([`kotton_ed25519::VerifyingKey::from_bytes`], re-exported as `kotton_crypto::ed25519`), or
//! it names nothing. [`DidKeyMethod::from_public_key`] takes the rule's key,
//! [`DidKeyMethod::from_public_key_bytes`] constructs it or refuses, and
//! [`DidKeyMethod::to_public_key`] returns it or refuses, with [`DidError::InvalidKey`] and not
//! the clause. So one key has one `did:key`, and two strings never name one key, as the
//! protocol's Ed25519 rule says: a list of admitted keys, an index by key and a `did:key`
//! compare as bytes.
//!
//! A row an earlier build stored under bytes the rule refuses is read as no key: the decode
//! refuses it, so nothing is admitted, indexed or checked under it. It is removed by the verb
//! that removes any row, which matches what is stored and not through the decode
//! (kottonllc/kotton#597).
//!
//! [`DidError::InvalidKey`]: kotton_wire::did::DidError::InvalidKey
pub mod key_method;
pub mod resolver;

pub use key_method::DidKeyMethod;
pub use resolver::{CompositeDidResolver, DidKeyResolver, DidResolver, DidWebResolver};
