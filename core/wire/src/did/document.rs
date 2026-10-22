// SPDX-License-Identifier: AGPL-3.0-or-later
use super::verification::VerificationMethod;
use serde::{Deserialize, Serialize};

/// W3C DID Document
///
/// A set of data describing the DID subject, including mechanisms such as
/// cryptographic public keys, that the DID subject can use to authenticate
/// itself and prove its association with the DID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDocument {
    /// JSON-LD context
    #[serde(rename = "@context")]
    pub context: Vec<String>,

    /// The DID that this document describes
    pub id: String,

    /// Verification methods for authentication
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub verification_method: Vec<VerificationMethod>,

    /// Authentication verification methods (can reference verification_method)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub authentication: Vec<String>,

    /// Assertion method verification methods
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub assertion_method: Vec<String>,

    /// Key agreement verification methods
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub key_agreement: Vec<String>,
}

impl DidDocument {
    /// Create a new DID document
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            context: vec![
                "https://www.w3.org/ns/did/v1".to_string(),
                "https://w3id.org/security/suites/ed25519-2020/v1".to_string(),
            ],
            id: id.into(),
            verification_method: Vec::new(),
            authentication: Vec::new(),
            assertion_method: Vec::new(),
            key_agreement: Vec::new(),
        }
    }

    /// Add a verification method
    pub fn add_verification_method(mut self, method: VerificationMethod) -> Self {
        self.verification_method.push(method);
        self
    }

    /// Add an authentication method (references a verification method)
    pub fn add_authentication(mut self, method_id: impl Into<String>) -> Self {
        self.authentication.push(method_id.into());
        self
    }

    /// Add an assertion method (references a verification method)
    pub fn add_assertion_method(mut self, method_id: impl Into<String>) -> Self {
        self.assertion_method.push(method_id.into());
        self
    }

    /// Add a key agreement method (references a verification method)
    pub fn add_key_agreement(mut self, method_id: impl Into<String>) -> Self {
        self.key_agreement.push(method_id.into());
        self
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> super::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Parse from JSON
    pub fn from_json(json: &str) -> super::Result<Self> {
        Ok(serde_json::from_str(json)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_document_creation() {
        let doc = DidDocument::new("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");

        assert_eq!(
            doc.id,
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        );
        assert_eq!(doc.context.len(), 2);
        assert!(doc.verification_method.is_empty());
    }

    #[test]
    fn test_did_document_serialization() {
        let vm = VerificationMethod::new(
            "did:key:z6Mk...#z6Mk...",
            "Ed25519VerificationKey2020",
            "did:key:z6Mk...",
        )
        .with_public_key_multibase("z6Mk...");

        let doc = DidDocument::new("did:key:z6Mk...")
            .add_verification_method(vm)
            .add_authentication("did:key:z6Mk...#z6Mk...");

        let json = doc.to_json().unwrap();
        assert!(json.contains("@context"));
        assert!(json.contains("verificationMethod"));
        assert!(json.contains("authentication"));

        // Round-trip test
        let parsed = DidDocument::from_json(&json).unwrap();
        assert_eq!(parsed, doc);
    }
}
