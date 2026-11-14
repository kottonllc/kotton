// SPDX-License-Identifier: AGPL-3.0-or-later
//! A schema definition's signature: the publisher's word that the definition is theirs.
//!
//! The protocol's decision *A schema is named by the key that publishes it* says how a
//! definition is signed and checked: an Ed25519 signature, under the key the publisher's
//! `did:key` names, carried beside the definition as `signature`, base64 with the standard
//! alphabet and padding, never inside the digest or the identity. The signature is over a
//! domain-tagged message, not the bare digest: the 16 bytes [`DOMAIN`], `kotton-schema-v1`,
//! then one zero byte, then the definition's 32-byte digest (BLAKE3 over its canonical form,
//! `kotton_schemas::definition`), 49 bytes in all. The tag says what the signature is the
//! publisher's word for, so a signature the same key makes over 32 bytes for any other
//! purpose is not a schema's, and a signature over the bare digest is refused. A definition
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
    /// The signature does not check against the publisher's key over the message for the
    /// definition's digest.
    #[error("the signature does not check against the publisher's key over the definition's signed message")]
    Invalid,
    /// [`sign`] was handed a key that is not the definition's publisher.
    #[error("the signing key is {key}, and the definition's publisher is {publisher}")]
    PublisherMismatch { key: Publisher, publisher: Publisher },
}

/// The tag a schema definition's signature opens its message with (module doc): the signed
/// message is these 16 ASCII bytes, one zero byte, and the definition's 32-byte digest. The
/// `v1` is the signed message's form, not a schema's revision: every revision of every
/// schema is signed under it, and it changes only if the message itself does.
pub const DOMAIN: &[u8; 16] = b"kotton-schema-v1";

/// The message a definition's signature is over, for its 32-byte `digest`: [`DOMAIN`], one
/// zero byte, the digest.
fn message(digest: &[u8; 32]) -> [u8; 49] {
    let mut m = [0u8; 49];
    m[..16].copy_from_slice(DOMAIN);
    m[17..].copy_from_slice(digest);
    m
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

/// Check `def.signature` against `def.publisher` over the message for `def`'s digest
/// (module doc).
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
    // The strict check made with `ed25519-dalek` (the checks made otherwise are #564's): a
    // publisher key or `R` of small order is refused.
    crate::ed25519::verify(&key, &message(&digest), &signature).map_err(|_| SchemaSignatureError::Invalid)
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
    def.signature = Some(STANDARD.encode(key.sign(&message(&digest)).to_bytes()));
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
    /// accepts it over any message, the signed message for the definition's digest among
    /// them: it checks `[S]B = R + [k]A`, and with `S = 0`, `R` the identity and `A` the
    /// identity both sides are the identity whatever `k` is. The strict check refuses a
    /// small-order key, so the forgery is refused.
    ///
    /// The tree's one exemption from the workspace's refusal of the unstrict check, named in
    /// `cargo xtask ed25519-check`: this test holds the difference between the two checks, so
    /// it makes the other one.
    #[test]
    #[allow(clippy::disallowed_methods)]
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
        key.verify(&message(&def.digest().unwrap()), &Signature::from_bytes(&forged))
            .expect("plain verify accepts the forgery, which is why it is not the check");
        assert_eq!(verify(&def), Err(SchemaSignatureError::Invalid));
    }

    /// The signed message is exactly the tag, one zero byte and the digest: 49 bytes.
    #[test]
    fn the_signed_message_is_the_tag_a_zero_byte_and_the_digest() {
        let digest: [u8; 32] = core::array::from_fn(|i| i as u8 + 0xa0);
        let m = message(&digest);
        assert_eq!(m.len(), 49);
        assert_eq!(&m[..16], b"kotton-schema-v1");
        assert_eq!(m[16], 0);
        assert_eq!(&m[17..], &digest);
        let mut expected = b"kotton-schema-v1\0".to_vec();
        expected.extend_from_slice(&digest);
        assert_eq!(m.as_slice(), expected.as_slice());
    }

    /// A signature over the bare digest, by the publisher's own key, is refused: the
    /// publisher's word is for the tagged message, and 32 bytes it signed for any other
    /// purpose are not a schema's signature.
    #[test]
    fn a_signature_over_the_bare_digest_is_refused() {
        let key = a_key(7);
        let mut def = signed(&key);
        verify(&def).unwrap();
        let bare = key.sign(&def.digest().unwrap());
        // The signature is good for what it signed, so the refusal is about the message.
        crate::ed25519::verify(&key.verifying_key(), &def.digest().unwrap(), &bare).unwrap();
        def.signature = Some(STANDARD.encode(bare.to_bytes()));
        assert_eq!(verify(&def), Err(SchemaSignatureError::Invalid));
    }

    // A known answer, for another implementation to check itself against and for the
    // protocol's fixtures: the signing key whose seed is the 32 bytes 0x01 to 0x20 (byte `i`
    // is `i + 1`), the definition [`known_answer_definition`] builds under the publisher that
    // key names, and what this module makes of it. Ed25519 is deterministic, so the signature
    // is fixed too.

    /// The known answer's publisher: the `did:key` of the key whose seed is 0x01 to 0x20.
    const KNOWN_ANSWER_PUBLISHER: &str = "did:key:z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7";

    /// The known answer's definition in its canonical form, the bytes its digest is over.
    const KNOWN_ANSWER_CANONICAL: &str = r#"{"description":"A known-answer definition.","fields":[{"name":"title","nullable":false,"type":"string"}],"name":"example","publisher":"did:key:z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7","revision":1}"#;

    /// The known answer's digest, BLAKE3 over its canonical form, as lowercase hex.
    const KNOWN_ANSWER_DIGEST_HEX: &str = "81b76f8c79ffbe19465217b89db5645c3cbad734aae0bd5797c2184c2e2ae69f";

    /// The known answer's signed message, 49 bytes as lowercase hex: [`DOMAIN`], one zero
    /// byte, the digest.
    const KNOWN_ANSWER_MESSAGE_HEX: &str =
        "6b6f74746f6e2d736368656d612d76310081b76f8c79ffbe19465217b89db5645c3cbad734aae0bd5797c2184c2e2ae69f";

    /// The known answer's signature, base64 with the standard alphabet and padding.
    const KNOWN_ANSWER_SIGNATURE: &str =
        "1Bv2xonxDK8cFzz4wL4XcAUWMSbpNikiB+rljXIUBMHolcxEnCwZkA9BnOTe006pr4C/Q8M/aITTklZAhRZDDA==";

    /// The known answer's key: seed byte `i` is `i + 1`.
    fn known_answer_key() -> SigningKey {
        SigningKey::from_bytes(&core::array::from_fn(|i| i as u8 + 1))
    }

    /// The known answer's definition, unsigned: `example`, revision 1, one required string
    /// field `title`, described as "A known-answer definition.", under `key`'s publisher.
    fn known_answer_definition(key: &SigningKey) -> SchemaDefinition {
        SchemaDefinition::new(
            SchemaId::new(publisher_of(&key.verifying_key()), SchemaName::new("example").unwrap()).unwrap(),
            1,
            vec![SchemaField::required("title", FieldType::String)],
        )
        .with_description("A known-answer definition.")
    }

    /// **The known answer holds**: the publisher, the canonical form, the digest, the signed
    /// message and the signature are the constants above, and the signature verifies.
    #[test]
    fn the_known_answer_holds() {
        let key = known_answer_key();
        let mut def = known_answer_definition(&key);
        assert_eq!(def.publisher.as_str(), KNOWN_ANSWER_PUBLISHER);
        assert_eq!(def.canonical().unwrap(), KNOWN_ANSWER_CANONICAL);
        assert_eq!(def.digest_hex().unwrap(), KNOWN_ANSWER_DIGEST_HEX);
        assert_eq!(hex::encode(message(&def.digest().unwrap())), KNOWN_ANSWER_MESSAGE_HEX);
        sign(&mut def, &key).unwrap();
        assert_eq!(def.signature.as_deref(), Some(KNOWN_ANSWER_SIGNATURE));
        verify(&def).unwrap();
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
