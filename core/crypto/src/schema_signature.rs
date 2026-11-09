// SPDX-License-Identifier: AGPL-3.0-or-later
//! A schema definition's signature: the publisher's word that the definition is theirs.
//!
//! The protocol's decision *A schema is named by the key that publishes it* says how a
//! definition is signed and checked: an Ed25519 signature, under the key the publisher's
//! `did:key` names, over the definition's 32-byte digest (BLAKE3 over its canonical form,
//! `kotton_schemas::definition`), carried beside the definition as `signature`, base64 with
//! the standard alphabet and padding, never inside the digest or the identity. A definition
//! whose signature does not check against its publisher is no schema at all, and so is one
//! that carries no signature: [`verify`] refuses both, and `schema register` refuses what
//! [`verify`] refuses.
//!
//! **The core set carries no signature before the first tag**, as the decision says: nothing
//! depends on a schema by version yet, the release key never leaves the maintainer's machine,
//! and the files under `core/schemas/schemas/kotton/` are what every page of the protocol is,
//! a change the maintainer signed off. They are compiled in and admitted as core by the
//! registry without passing here; from the first tag on they carry the release key's
//! signature, and this is what checks it.
//!
//! This lives here and not in `kotton-schemas` because that crate links no signature scheme
//! and this one depends on it, so the reverse is impossible. [`sign`] is the other half, for
//! a publisher's own tool and for tests: it takes the signing key where the key is, and
//! carries nothing across a process boundary.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use kotton_schemas::{DigestError, Publisher, SchemaDefinition};
use thiserror::Error;

/// Why a definition's signature does not check.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SchemaSignatureError {
    /// The definition carries no `signature`.
    #[error("the definition carries no signature; a schema is signed by the key that publishes it")]
    Missing,
    /// `signature` is not base64 (standard alphabet, padded).
    #[error("the signature is not base64: {0}")]
    NotBase64(String),
    /// `signature` decodes to something other than 64 bytes.
    #[error("the signature is {0} bytes, and an Ed25519 signature is 64")]
    WrongLength(usize),
    /// The publisher's `did:key` names no Ed25519 public key (a point off the curve).
    #[error("the publisher's did:key names no Ed25519 public key: {0}")]
    PublisherKey(String),
    /// The definition has no digest to sign or check.
    #[error("{0}")]
    Digest(#[from] DigestError),
    /// The signature does not check against the publisher's key over the digest.
    #[error("the signature does not check against the publisher's key over the definition's digest")]
    Invalid,
    /// [`sign`] was handed a key that is not the definition's publisher.
    #[error("the signing key is {key}, and the definition's publisher is {publisher}")]
    PublisherMismatch { key: Publisher, publisher: Publisher },
}

/// The publisher a public key is: its `did:key`.
pub fn publisher_of(key: &VerifyingKey) -> Publisher {
    Publisher::from_ed25519_public_key(key.as_bytes())
}

/// The public key a publisher's `did:key` names.
fn key_of(publisher: &Publisher) -> Result<VerifyingKey, SchemaSignatureError> {
    VerifyingKey::from_bytes(&publisher.ed25519_public_key())
        .map_err(|e| SchemaSignatureError::PublisherKey(e.to_string()))
}

/// Check `def.signature` against `def.publisher` over `def`'s digest (module doc).
pub fn verify(def: &SchemaDefinition) -> Result<(), SchemaSignatureError> {
    let Some(signature) = def.signature.as_deref() else {
        return Err(SchemaSignatureError::Missing);
    };
    let bytes = STANDARD
        .decode(signature)
        .map_err(|e| SchemaSignatureError::NotBase64(e.to_string()))?;
    let bytes: [u8; 64] =
        bytes.as_slice().try_into().map_err(|_| SchemaSignatureError::WrongLength(bytes.len()))?;
    let signature = Signature::from_bytes(&bytes);
    let key = key_of(&def.publisher)?;
    let digest = def.digest()?;
    // Strict, as every other Ed25519 check in this crate is: a small-order key or `R` is
    // refused, so a key with no secret behind it cannot be named as a publisher whose
    // "signature" anyone can write.
    key.verify_strict(&digest, &signature).map_err(|_| SchemaSignatureError::Invalid)
}

/// Sign `def` with `key`, which must be the key `def.publisher` names, and set its
/// `signature`. The definition is signed as it stands: a change to it after this is a
/// definition [`verify`] refuses.
pub fn sign(def: &mut SchemaDefinition, key: &SigningKey) -> Result<(), SchemaSignatureError> {
    let signer = publisher_of(&key.verifying_key());
    if signer != def.publisher {
        return Err(SchemaSignatureError::PublisherMismatch { key: signer, publisher: def.publisher.clone() });
    }
    let digest = def.digest()?;
    def.signature = Some(STANDARD.encode(key.sign(&digest).to_bytes()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotton_schemas::{FieldType, SchemaField, SchemaId, SchemaName};

    fn a_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// A definition published under `key`, signed.
    fn signed(key: &SigningKey) -> SchemaDefinition {
        let publisher = publisher_of(&key.verifying_key());
        let mut def = SchemaDefinition::new(
            SchemaId::new(publisher, SchemaName::new("bookmark").unwrap()).unwrap(),
            1,
            vec![
                SchemaField::required("url", FieldType::String),
                SchemaField::nullable("title", FieldType::String),
            ],
        )
        .with_description("A bookmark.");
        sign(&mut def, key).unwrap();
        def
    }

    #[test]
    fn a_definition_signed_by_a_fresh_key_verifies() {
        let key = a_key(7);
        let def = signed(&key);
        assert!(def.signature.is_some());
        verify(&def).unwrap();
        // Through JSON, as `schema register` receives it.
        let back: SchemaDefinition = serde_json::from_str(&serde_json::to_string(&def).unwrap()).unwrap();
        verify(&back).unwrap();
        let sig = STANDARD.decode(def.signature.as_deref().unwrap()).unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn a_changed_field_is_refused() {
        let key = a_key(7);
        let mut def = signed(&key);
        def.fields.push(SchemaField::nullable("note", FieldType::String));
        assert_eq!(verify(&def), Err(SchemaSignatureError::Invalid));
        let mut def = signed(&key);
        def.revision = 2;
        assert_eq!(verify(&def), Err(SchemaSignatureError::Invalid));
        let mut def = signed(&key);
        def.description = None;
        assert_eq!(verify(&def), Err(SchemaSignatureError::Invalid));
        // Provenance is not under the digest, so it may change under a signature.
        let mut def = signed(&key);
        def.forked_from = Some(def.id());
        verify(&def).unwrap();
    }

    #[test]
    fn a_wrong_key_is_refused() {
        let theirs = a_key(7);
        let mine = a_key(8);
        // Their signature under my publisher.
        let mut def = signed(&theirs);
        def.publisher = publisher_of(&mine.verifying_key());
        assert_eq!(verify(&def), Err(SchemaSignatureError::Invalid));
        // My signature over their definition: `sign` refuses to make one.
        let mut def = signed(&theirs);
        let err = sign(&mut def, &mine).unwrap_err();
        assert!(matches!(err, SchemaSignatureError::PublisherMismatch { .. }), "{err}");
        // And a signature pasted in from another definition under the same key.
        let mut def = signed(&theirs);
        def.signature = signed(&mine).signature;
        assert_eq!(verify(&def), Err(SchemaSignatureError::Invalid));
    }

    #[test]
    fn a_missing_or_malformed_signature_is_refused() {
        let key = a_key(7);
        let mut def = signed(&key);
        def.signature = None;
        assert_eq!(verify(&def), Err(SchemaSignatureError::Missing));
        def.signature = Some("not base64!".into());
        assert!(matches!(verify(&def), Err(SchemaSignatureError::NotBase64(_))));
        def.signature = Some(STANDARD.encode([0u8; 63]));
        assert_eq!(verify(&def), Err(SchemaSignatureError::WrongLength(63)));
        // Unpadded base64 is not the form the decision names.
        let good = signed(&key).signature.unwrap();
        def.signature = Some(good.trim_end_matches('=').to_string());
        assert!(matches!(verify(&def), Err(SchemaSignatureError::NotBase64(_))));
    }

    /// A publisher whose key is the identity point, a small-order point no secret stands
    /// behind, and a forged signature with `R` the identity and `S` zero. Plain `verify`
    /// accepts it over any digest: it checks `[S]B = R + [k]A`, and with `S = 0`, `R` the
    /// identity and `A` the identity both sides are the identity whatever `k` is. The strict
    /// check refuses a small-order key, so the forgery is refused.
    #[test]
    fn a_small_order_publisher_key_with_a_forged_signature_is_refused() {
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let key = VerifyingKey::from_bytes(&identity).expect("the identity point decodes");
        let mut forged = [0u8; 64];
        forged[0] = 1; // R: the identity's encoding; S: 32 zero bytes.
        let mut def = SchemaDefinition::new(
            SchemaId::new(publisher_of(&key), SchemaName::new("bookmark").unwrap()).unwrap(),
            1,
            vec![SchemaField::required("url", FieldType::String)],
        );
        def.signature = Some(STANDARD.encode(forged));
        // What the forgery passes: the check this module used to make.
        use ed25519_dalek::Verifier as _;
        key.verify(&def.digest().unwrap(), &Signature::from_bytes(&forged))
            .expect("plain verify accepts the forgery, which is why it is not the check");
        assert_eq!(verify(&def), Err(SchemaSignatureError::Invalid));
    }

    #[test]
    fn the_core_set_is_unsigned_before_the_first_tag() {
        for schema in kotton_schemas::CoreSchema::all() {
            let def = schema.definition();
            assert_eq!(verify(&def), Err(SchemaSignatureError::Missing), "{}", def.name);
        }
    }

    /// Kotton's publisher is the release key in `infra/release/allowed_signers`, derived
    /// here from the key the file carries.
    #[test]
    fn kottons_publisher_is_the_release_key() {
        let signers = include_str!("../../../infra/release/allowed_signers");
        let line = signers.lines().find(|l| !l.starts_with('#') && !l.trim().is_empty()).expect("a key line");
        let blob = line.split_whitespace().find(|w| w.starts_with("AAAA")).expect("the key's base64");
        let bytes = STANDARD.decode(blob).unwrap();
        // ssh wire format: u32 length and "ssh-ed25519", then u32 length and the 32-byte key.
        let kind_len = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
        assert_eq!(&bytes[4..4 + kind_len], b"ssh-ed25519");
        let at = 4 + kind_len;
        let key_len = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        assert_eq!(key_len, 32);
        let key: [u8; 32] = bytes[at + 4..at + 4 + 32].try_into().unwrap();
        let publisher = publisher_of(&VerifyingKey::from_bytes(&key).unwrap());
        assert_eq!(publisher.as_str(), kotton_common::namespace::NSID_PREFIX);
        for schema in kotton_schemas::CoreSchema::all() {
            assert_eq!(schema.definition().publisher, publisher);
        }
    }
}
