// SPDX-License-Identifier: AGPL-3.0-or-later
use kotton_ed25519::VerifyingKey;
use kotton_wire::did::{Did, DidDocument, DidError, Result, VerificationMethod};
use multibase::Base;

/// did:key method implementation for Ed25519 keys
///
/// The did:key method generates a DID from a public key using multibase/multicodec encoding.
/// Format: `did:key:<multibase-encoded-public-key>`
///
/// The key is one that passed the Ed25519 rule ([`VerifyingKey::from_bytes`]): the derivation
/// takes such a key or constructs it, and the decode returns one or refuses. A `did:key` this
/// type makes or reads names a key or names nothing.
pub struct DidKeyMethod;

impl DidKeyMethod {
    /// Ed25519 multicodec prefix (0xed01)
    const ED25519_MULTICODEC: &'static [u8] = &[0xed, 0x01];

    /// The `did:key` of a key that passed the rule.
    ///
    /// # Example
    /// ```
    /// use kotton_crypto::did::DidKeyMethod;
    /// use kotton_crypto::ed25519::VerifyingKey;
    ///
    /// let signing_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    /// let public_key = VerifyingKey::from_bytes(signing_key.verifying_key().as_bytes())?;
    /// let did = DidKeyMethod::from_public_key(&public_key);
    /// println!("{}", did); // did:key:z6Mk...
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_public_key(public_key: &VerifyingKey) -> Did {
        let multicodec = Self::encode_multicodec(public_key.as_bytes());
        let multibase = multibase::encode(Base::Base58Btc, &multicodec);

        Did::new("key", multibase)
    }

    /// The `did:key` of 32 bytes, if they pass the rule as a key.
    ///
    /// # Errors
    /// [`DidError::InvalidKey`] where the rule refuses the bytes. It does not say which clause.
    pub fn from_public_key_bytes(public_key_bytes: &[u8; 32]) -> Result<Did> {
        let key = VerifyingKey::from_bytes(public_key_bytes)
            .map_err(|e| DidError::InvalidKey(format!("not an Ed25519 key: {e}")))?;
        Ok(Self::from_public_key(&key))
    }

    /// The key a `did:key` names, if it names one: an Ed25519 key that passed the rule.
    ///
    /// # Errors
    /// [`DidError::UnsupportedMethod`] for a method other than `key`,
    /// [`DidError::InvalidMultibase`] where the identifier does not decode, and
    /// [`DidError::InvalidKey`] where it is not 32 bytes of Ed25519 key, the rule refuses them,
    /// or the DID is not the one string [`Self::from_public_key`] makes of that key.
    pub fn to_public_key(did: &Did) -> Result<VerifyingKey> {
        if did.method() != "key" {
            return Err(DidError::UnsupportedMethod(did.method().to_string()));
        }

        // Decode multibase
        let (_base, bytes) = multibase::decode(did.identifier())
            .map_err(|e| DidError::InvalidMultibase(e.to_string()))?;

        // Check multicodec prefix
        if !bytes.starts_with(Self::ED25519_MULTICODEC) {
            return Err(DidError::InvalidKey(
                "Not an Ed25519 key (invalid multicodec prefix)".to_string(),
            ));
        }

        // Extract public key bytes (skip 2-byte multicodec prefix)
        let key_bytes = &bytes[2..];
        if key_bytes.len() != 32 {
            return Err(DidError::InvalidKey(format!(
                "Invalid Ed25519 key length: expected 32, got {}",
                key_bytes.len()
            )));
        }

        let key_array: [u8; 32] = key_bytes.try_into().map_err(|_| {
            DidError::InvalidKey("Failed to convert key bytes to array".to_string())
        })?;

        let key = VerifyingKey::from_bytes(&key_array)
            .map_err(|e| DidError::InvalidKey(format!("not an Ed25519 key: {e}")))?;
        // One key has one `did:key`: the string the derivation makes of it, compared as
        // stored. The codec reads other spellings of the same bytes; none of them names it.
        if Self::from_public_key(&key) != *did {
            return Err(DidError::InvalidKey(
                "not the did:key of its key: a key's did:key is did:key:z and the base58btc of 0xed 0x01 and the key"
                    .to_string(),
            ));
        }
        Ok(key)
    }

    /// A `did:key` spelled over any 32 bytes, with nothing put to the rule: the string an
    /// earlier build, or a peer, could have written under bytes that are no key. For the tests
    /// that hold a reader to reading such a string as no key and a removal to matching it as
    /// stored; it is not a way to name a key.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn spelled_over(bytes: &[u8; 32]) -> Did {
        Did::new("key", multibase::encode(Base::Base58Btc, Self::encode_multicodec(bytes)))
    }

    /// The same bytes as [`Self::spelled_over`] under another base the codec reads (base58
    /// Flickr, `Z`, whose alphabet keeps the string a single path component):
    /// a string an earlier build or a peer could have written beside a key, which names no key
    /// however good the bytes. For the tests that hold a table to what the row is read by.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn spelled_otherwise(bytes: &[u8; 32]) -> Did {
        Did::new("key", multibase::encode(Base::Base58Flickr, Self::encode_multicodec(bytes)))
    }

    /// The DID document of a `did:key` that names a key: it goes through [`Self::to_public_key`],
    /// and a DID that names none has no document.
    pub fn to_document(did: &Did) -> Result<DidDocument> {
        Self::to_public_key(did)?;
        let did_string = did.to_string();
        let verification_method_id = format!("{}#{}", did_string, did.identifier());

        let vm = VerificationMethod::new(
            &verification_method_id,
            "Ed25519VerificationKey2020",
            &did_string,
        )
        .with_public_key_multibase(did.identifier());

        let doc = DidDocument::new(&did_string)
            .add_verification_method(vm)
            .add_authentication(&verification_method_id)
            .add_assertion_method(&verification_method_id)
            .add_key_agreement(&verification_method_id);

        Ok(doc)
    }

    /// Encode public key with multicodec prefix
    fn encode_multicodec(public_key_bytes: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(2 + public_key_bytes.len());
        encoded.extend_from_slice(Self::ED25519_MULTICODEC);
        encoded.extend_from_slice(public_key_bytes);
        encoded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    /// The rule's key of `signing_key`.
    fn key_of(signing_key: &SigningKey) -> VerifyingKey {
        VerifyingKey::from_bytes(signing_key.verifying_key().as_bytes()).expect("a key made from a seed passes")
    }

    /// The derivation refuses every vector the rule refuses: no `did:key` is made of bytes that
    /// are no key.
    #[test]
    fn the_derivation_refuses_every_refused_key() {
        let made: Vec<String> = crate::ed25519::refused_keys()
            .into_iter()
            .filter(|(_, bytes)| DidKeyMethod::from_public_key_bytes(bytes).is_ok())
            .map(|(name, _)| name)
            .collect();
        assert!(made.is_empty(), "a did:key was made of bytes the rule refuses: {made:?}");
    }

    /// The decode refuses every vector the rule refuses, and says it is no key.
    #[test]
    fn the_decode_refuses_every_refused_key() {
        for (name, bytes) in crate::ed25519::refused_keys() {
            match DidKeyMethod::to_public_key(&DidKeyMethod::spelled_over(&bytes)) {
                Err(DidError::InvalidKey(_)) => {}
                other => panic!("{name}: the decode gave {other:?}"),
            }
        }
    }

    /// The bytes form and the key form make one string for one key, and the decode gives the
    /// key back.
    #[test]
    fn one_key_has_one_did() {
        let key = key_of(&SigningKey::from_bytes(&[7u8; 32]));
        let did = DidKeyMethod::from_public_key(&key);
        assert_eq!(DidKeyMethod::from_public_key_bytes(key.as_bytes()).unwrap(), did);
        assert_eq!(DidKeyMethod::spelled_over(key.as_bytes()), did);
        assert_eq!(DidKeyMethod::to_public_key(&did).unwrap(), key);
    }

    #[test]
    fn test_did_key_from_public_key() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let public_key = key_of(&signing_key);

        let did = DidKeyMethod::from_public_key(&public_key);

        assert_eq!(did.method(), "key");
        assert!(did.identifier().starts_with('z')); // Base58btc encoding
    }

    #[test]
    fn test_did_key_round_trip() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let original_key = key_of(&signing_key);

        let did = DidKeyMethod::from_public_key(&original_key);
        let recovered_key = DidKeyMethod::to_public_key(&did).unwrap();

        assert_eq!(original_key.as_bytes(), recovered_key.as_bytes());
    }

    #[test]
    fn test_did_key_to_document() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let public_key = key_of(&signing_key);

        let did = DidKeyMethod::from_public_key(&public_key);
        let doc = DidKeyMethod::to_document(&did).unwrap();

        assert_eq!(doc.id, did.to_string());
        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(doc.authentication.len(), 1);
        assert_eq!(doc.assertion_method.len(), 1);

        // Verify JSON serialization
        let json = doc.to_json().unwrap();
        assert!(json.contains("Ed25519VerificationKey2020"));
        assert!(json.contains("publicKeyMultibase"));
    }

    #[test]
    fn test_did_key_invalid_method() {
        let did = Did::new("example", "123");
        assert!(DidKeyMethod::to_public_key(&did).is_err());
    }

    #[test]
    // The vector below is zero-padded to three columns so the 32 bytes line up
    // and can be diffed against the spec by eye. They are decimal and meant to
    // be: `zero_prefixed_literal` reads `097` as a possible octal typo, which is
    // the right suspicion in general and wrong here. Reformatting a published
    // test vector to satisfy a lint would cost the property that makes it
    // checkable.
    #[allow(clippy::zero_prefixed_literal)]
    fn test_known_did_key_vector() {
        // Known test vector from W3C did:key spec
        let signing_key = SigningKey::from_bytes(&[
            157, 097, 177, 157, 239, 253, 090, 096, 186, 132, 074, 244, 146, 236, 044, 196, 068,
            073, 197, 105, 123, 050, 105, 025, 112, 059, 172, 003, 028, 174, 127, 096,
        ]);
        let public_key = key_of(&signing_key);

        let did = DidKeyMethod::from_public_key(&public_key);
        let did_string = did.to_string();

        // Should produce a valid did:key DID
        assert!(did_string.starts_with("did:key:z"));

        // Round-trip should work
        let recovered = DidKeyMethod::to_public_key(&did).unwrap();
        assert_eq!(public_key.as_bytes(), recovered.as_bytes());
    }

    /// The committed spellings of one key's `did:key` (`kotton_wire`'s `did/did-key-spellings.txt`),
    /// which the relay's decode is held to as well.
    const SPELLINGS: &str = include_str!("../../../../wire/src/did/did-key-spellings.txt");

    /// The key the spellings are of: one made from a seed.
    fn spelled_key() -> VerifyingKey {
        key_of(&SigningKey::from_bytes(&[1u8; 32]))
    }

    /// What the spellings file says: the key's `did:key` under every base the codec offers, the
    /// one `did:key` first. A base whose encoder cannot write these bytes as text is named and
    /// left out: the identity base, which writes the bytes as they are, and `0xed` is no
    /// UTF-8 text.
    fn spellings() -> String {
        let bytes = DidKeyMethod::encode_multicodec(spelled_key().as_bytes());
        let mut bases: Vec<Base> = Vec::new();
        for code in (0..=0x10ffffu32).filter_map(char::from_u32) {
            if let Ok(base) = Base::from_code(code) {
                if !bases.contains(&base) {
                    bases.push(base);
                }
            }
        }
        bases.sort_by_key(|b| (*b != Base::Base58Btc, b.code()));
        let mut out = String::from(
            "# One Ed25519 key's did:key, spelled under every base the multibase codec offers.\n\
             # The first line is the key's did:key; no other line names a key.\n\
             # Rebuilt and checked by kotton-crypto (did::key_method::tests); read by the relay's tests.\n",
        );
        for base in bases {
            if base == Base::Identity {
                assert!(std::str::from_utf8(&bytes).is_err(), "the identity base writes these bytes as text");
                continue;
            }
            out.push_str(&format!("{base:?} did:key:{}\n", multibase::encode(base, &bytes)));
        }
        out
    }

    /// The spellings, as `(base, did)`, the one `did:key` first.
    fn spelled() -> Vec<(String, String)> {
        SPELLINGS
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .map(|l| {
                let (base, did) = l.split_once(' ').expect("a base and a did per line");
                (base.to_string(), did.to_string())
            })
            .collect()
    }

    /// **The committed spellings are the codec's**: rebuilt from it, they match the file, so a
    /// base the codec gains is a red test until the file says so.
    #[test]
    fn the_spellings_file_is_every_base_the_codec_offers() {
        if let Ok(path) = std::env::var("KOTTON_WRITE_DID_KEY_SPELLINGS") {
            std::fs::write(path, spellings()).expect("write the spellings");
        }
        assert_eq!(SPELLINGS, spellings(), "the spellings file is not the codec's: run this test with KOTTON_WRITE_DID_KEY_SPELLINGS=<path to the file> to rebuild it");
        assert_eq!(spelled()[0].1, DidKeyMethod::from_public_key(&spelled_key()).to_string());
        assert!(spelled().len() > 20, "{} spellings", spelled().len());
    }

    /// **One key has one `did:key`**: of every spelling of one key, the decode reads the
    /// derivation's string as that key and refuses every other, a document is made for that
    /// string alone, and `Publisher::new` takes the same one string and no other.
    #[test]
    fn exactly_one_spelling_of_a_key_decodes() {
        let key = spelled_key();
        for (i, (base, did)) in spelled().into_iter().enumerate() {
            let decoded = Did::parse(&did).ok().and_then(|d| DidKeyMethod::to_public_key(&d).ok());
            let published = kotton_schemas::Publisher::new(did.clone()).is_ok();
            let documented = Did::parse(&did).ok().is_some_and(|d| DidKeyMethod::to_document(&d).is_ok());
            assert_eq!(documented, i == 0, "{base}: a document was made for {did}");
            if i == 0 {
                assert_eq!(decoded, Some(key), "{base}: the did:key did not decode to its key");
                assert!(published, "{base}: Publisher::new refused the did:key");
            } else {
                assert_eq!(decoded, None, "{base}: {did} decoded");
                assert!(!published, "{base}: Publisher::new took {did}");
            }
        }
    }
}

