// SPDX-License-Identifier: AGPL-3.0-or-later
//! An app's publisher signature: the publisher's word for what the app asks for and the code
//! that asks it.
//!
//! A manifest's `[publisher]` block carries a `did:key` and a `signature`, base64 with the
//! standard alphabet and padding. The signature is Ed25519, under the key the `did:key` names,
//! over the 78-byte message [`kotton_schemas::app_signed_message`] makes: the tag
//! `kotton-app-v1`, one zero byte, the BLAKE3 of the manifest's canonical form with
//! `[publisher]` set aside ([`kotton_schemas::canonical_manifest`]), and the BLAKE3 of
//! `app.wasm`. So the signature covers the app's name, id, version, what it asks for, and the
//! code, and a signature over anything else (the code's digest alone, or a schema's message
//! under the same key) is not an app's.
//!
//! [`verify`] checks it the way `kotton_crypto::schema_signature` checks a schema's: strictly,
//! so a small-order key or `R` is refused. A signed manifest with no canonical form (a key
//! outside its types, or in `[publisher]` beside `did` and `signature`) is refused as signed,
//! naming the key ([`AppSignatureError::NotCanonical`]).
//! An unsigned manifest never comes here.
//!
//! [`sign`] is the other half, for a publisher's tool and for tests: it takes the signing key
//! where the key is, and carries nothing across a process boundary.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Signer as _, SigningKey};
use kotton_crypto::DidKeyMethod;
use kotton_schemas::{app_signed_message_for, ManifestCanonicalError, Publisher};
use thiserror::Error;

/// Why an app's publisher signature does not check.
#[derive(Debug, Error)]
pub enum AppSignatureError {
    /// The manifest is signed and has no canonical form, so it is not signed by its publisher.
    #[error("{0}")]
    NotCanonical(#[from] ManifestCanonicalError),
    /// `signature` is not base64 (standard alphabet, padded).
    #[error("the signature is not base64: {0}")]
    NotBase64(String),
    /// `signature` decodes to something other than 64 bytes.
    #[error("the signature is {0} bytes, and an Ed25519 signature is 64")]
    WrongLength(usize),
    /// The publisher's `did:key` names no Ed25519 public key.
    #[error("the publisher's did:key names no Ed25519 public key: {0}")]
    PublisherKey(String),
    /// The signature does not check against the publisher's key over the app's signed message.
    #[error("the signature does not check against the publisher's key over the app's manifest and code")]
    Invalid,
}

/// Check `signature` (base64) against `publisher_did` over the message for `manifest_toml`
/// and `code` (module doc).
pub fn verify(
    publisher_did: &str,
    signature: &str,
    manifest_toml: &str,
    code: &[u8],
) -> Result<(), AppSignatureError> {
    let message = app_signed_message_for(manifest_toml, code)?;
    let bytes = STANDARD
        .decode(signature)
        .map_err(|e| AppSignatureError::NotBase64(e.to_string()))?;
    let bytes: [u8; 64] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| AppSignatureError::WrongLength(bytes.len()))?;
    let signature = Signature::from_bytes(&bytes);
    let did = kotton_wire::did::Did::parse(publisher_did)
        .map_err(|e| AppSignatureError::PublisherKey(e.to_string()))?;
    let key = DidKeyMethod::to_public_key(&did).map_err(|e| AppSignatureError::PublisherKey(e.to_string()))?;
    // A publisher's key is checked as a schema's signature is, by the strict check: the key
    // and `R` must each be a point of full order, and the signature must check against both.
    kotton_crypto::ed25519::verify(&key, &message, &signature).map_err(|_| AppSignatureError::Invalid)
}

/// The publisher `key` is, as a manifest's `[publisher] did` names it.
pub fn publisher_of(key: &SigningKey) -> Publisher {
    Publisher::from_ed25519_public_key(key.verifying_key().as_bytes())
}

/// The signature (base64) `key` makes over `manifest_toml` and `code`. A `[publisher]` block
/// in `manifest_toml` is set aside, so a manifest is signed the same before and after one is
/// added.
pub fn sign(manifest_toml: &str, code: &[u8], key: &SigningKey) -> Result<String, AppSignatureError> {
    let message = app_signed_message_for(manifest_toml, code)?;
    Ok(STANDARD.encode(key.sign(&message).to_bytes()))
}

/// `manifest_toml`, which has no `[publisher]` block, with one appended: `key`'s publisher
/// and its signature over the manifest and `code`.
pub fn signed_manifest(manifest_toml: &str, code: &[u8], key: &SigningKey) -> Result<String, AppSignatureError> {
    let signature = sign(manifest_toml, code, key)?;
    let did = publisher_of(key);
    Ok(format!("{manifest_toml}\n[publisher]\ndid = \"{did}\"\nsignature = \"{signature}\"\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotton_schemas::{manifest_digest, AppManifest};

    const MANIFEST: &str = "[app]\nid = \"com.example.ledger\"\nname = \"Ledger\"\nversion = \"1.0.0\"\n\n\
        [capabilities]\n\"schema.read\" = [\"did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/notes\"]\n";
    const CODE: &[u8] = b"the ledger's code";

    fn a_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// The manifest's publisher block, as written.
    fn parts(signed: &str) -> (String, String) {
        let m = AppManifest::from_toml(signed).unwrap();
        (m.publisher_did.unwrap(), m.publisher_signature.unwrap())
    }

    fn check(signed: &str, code: &[u8]) -> Result<(), AppSignatureError> {
        let (did, sig) = parts(signed);
        verify(&did, &sig, signed, code)
    }

    #[test]
    fn a_manifest_and_code_signed_together_verify() {
        let signed = signed_manifest(MANIFEST, CODE, &a_key(7)).unwrap();
        check(&signed, CODE).unwrap();
    }

    /// Someone else's manifest over this publisher's code, and this publisher's manifest over
    /// someone else's code: each is refused.
    #[test]
    fn a_manifest_and_code_are_signed_as_a_pair() {
        let key = a_key(7);
        let (did, sig) = parts(&signed_manifest(MANIFEST, CODE, &key).unwrap());
        let theirs = MANIFEST.replace("Ledger", "Not The Ledger").replace("schema.read", "schema.write");
        assert!(matches!(verify(&did, &sig, &theirs, CODE), Err(AppSignatureError::Invalid)));
        assert!(matches!(verify(&did, &sig, MANIFEST, b"someone else's code"), Err(AppSignatureError::Invalid)));
        // A value that differs, however small.
        let differs = MANIFEST.replace("1.0.0", "1.0.1");
        assert!(matches!(verify(&did, &sig, &differs, CODE), Err(AppSignatureError::Invalid)));
        // Another key's signature over the same pair, under this publisher.
        let other = sign(MANIFEST, CODE, &a_key(8)).unwrap();
        assert!(matches!(verify(&did, &other, MANIFEST, CODE), Err(AppSignatureError::Invalid)));
        verify(&did, &sig, MANIFEST, CODE).unwrap();
    }

    /// A reordered, respaced manifest is the same manifest, and its signature still checks.
    #[test]
    fn a_reordered_manifest_keeps_its_signature() {
        let key = a_key(7);
        let (did, sig) = parts(&signed_manifest(MANIFEST, CODE, &key).unwrap());
        let reordered = "[capabilities]\n'schema.read' = [ \"did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/notes\" ]\n\n\
            [app]\nversion='1.0.0'\n  name = \"Ledger\"\nid = \"com.example.ledger\"   # the id\n";
        assert_eq!(manifest_digest(reordered).unwrap(), manifest_digest(MANIFEST).unwrap());
        verify(&did, &sig, reordered, CODE).unwrap();
    }

    /// A signed manifest with a key outside its types is refused as signed, naming the key,
    /// whether the key was there when it was signed or added after.
    #[test]
    fn a_signed_manifest_with_a_key_outside_its_types_is_refused_naming_it() {
        let key = a_key(7);
        let (did, sig) = parts(&signed_manifest(MANIFEST, CODE, &key).unwrap());
        let extra = MANIFEST.replace("version = \"1.0.0\"\n", "version = \"1.0.0\"\nrole = \"shell\"\n");
        let err = verify(&did, &sig, &extra, CODE).unwrap_err();
        assert!(matches!(&err, AppSignatureError::NotCanonical(e) if e.key() == Some("app.role")), "{err}");
        assert!(err.to_string().contains("`app.role`"), "{err}");
        // Nor can one be signed.
        let err = sign(&extra, CODE, &key).unwrap_err();
        assert!(matches!(&err, AppSignatureError::NotCanonical(e) if e.key() == Some("app.role")), "{err}");
    }

    /// A signature over the code's digest alone, by the publisher's own key, is refused: it is
    /// good for what it signed, and that is not an app's signed message.
    #[test]
    fn a_signature_over_the_code_alone_is_refused() {
        let key = a_key(7);
        let code_only = key.sign(blake3::hash(CODE).as_bytes());
        kotton_crypto::ed25519::verify(&key.verifying_key(), blake3::hash(CODE).as_bytes(), &code_only).unwrap();
        let did = publisher_of(&key);
        let sig = STANDARD.encode(code_only.to_bytes());
        assert!(matches!(verify(did.as_str(), &sig, MANIFEST, CODE), Err(AppSignatureError::Invalid)));
    }

    #[test]
    fn a_malformed_signature_is_refused() {
        let did = publisher_of(&a_key(7));
        assert!(matches!(verify(did.as_str(), "not base64!", MANIFEST, CODE), Err(AppSignatureError::NotBase64(_))));
        let short = STANDARD.encode([0u8; 63]);
        assert!(matches!(verify(did.as_str(), &short, MANIFEST, CODE), Err(AppSignatureError::WrongLength(63))));
        let sig = sign(MANIFEST, CODE, &a_key(7)).unwrap();
        assert!(matches!(verify("did:key:zbad", &sig, MANIFEST, CODE), Err(AppSignatureError::PublisherKey(_))));
    }

    /// The identity point as a publisher's key, and a forged signature with `R` the identity
    /// and `S` zero: the strict check refuses it, as a schema's does.
    #[test]
    fn a_small_order_publisher_key_is_refused() {
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let did = Publisher::from_ed25519_public_key(&identity);
        let mut forged = [0u8; 64];
        forged[0] = 1;
        let sig = STANDARD.encode(forged);
        assert!(matches!(verify(did.as_str(), &sig, MANIFEST, CODE), Err(AppSignatureError::Invalid)));
    }

    // ── The known answer (`vectors/app-v1.txt`) ──────────────────────────────

    const VECTORS: &str = include_str!("../vectors/app-v1.txt");

    fn parse_vectors() -> Vec<(String, String)> {
        VECTORS
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .map(|l| {
                let (k, v) = l.split_once(" = ").expect("a `key = value` line");
                (k.to_string(), v.to_string())
            })
            .collect()
    }

    fn vector(name: &str) -> String {
        parse_vectors().into_iter().find(|(k, _)| k == name).unwrap_or_else(|| panic!("no `{name}`")).1
    }

    /// **The committed known answer is what this module and `kotton_schemas` make**: from the
    /// manifest, the code and the seed in the file, the canonical form, both digests, the
    /// 78-byte message and the signature are the file's, and the signed manifest verifies.
    #[test]
    fn the_committed_vectors_are_what_signing_makes() {
        let seed: [u8; 32] = hex::decode(vector("seed")).unwrap().try_into().unwrap();
        let key = SigningKey::from_bytes(&seed);
        let manifest: String = serde_json::from_str(&vector("manifest")).unwrap();
        let code = hex::decode(vector("code")).unwrap();
        let canonical = kotton_schemas::canonical_manifest(&manifest).unwrap();
        let digest = manifest_digest(&manifest).unwrap();
        let message = kotton_schemas::app_signed_message_for(&manifest, &code).unwrap();
        let signature = sign(&manifest, &code, &key).unwrap();
        let made: Vec<(String, String)> = [
            ("seed", hex::encode(seed)),
            ("publisher", publisher_of(&key).to_string()),
            ("manifest", serde_json::to_string(&manifest).unwrap()),
            ("code", hex::encode(&code)),
            ("canonical", canonical),
            ("manifest_digest", hex::encode(digest)),
            ("code_digest", hex::encode(blake3::hash(&code).as_bytes())),
            ("message", hex::encode(message)),
            ("signature", signature.clone()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        let printed: String = made.iter().map(|(k, v)| format!("{k} = {v}\n")).collect();
        assert_eq!(parse_vectors(), made, "vectors/app-v1.txt differs from what is made:\n{printed}");
        assert_eq!(message.len(), 78);
        let signed = format!("{manifest}\n[publisher]\ndid = \"{}\"\nsignature = \"{signature}\"\n", publisher_of(&key));
        check(&signed, &code).unwrap();
        assert_eq!(signed_manifest(&manifest, &code, &key).unwrap(), signed);
    }
}
