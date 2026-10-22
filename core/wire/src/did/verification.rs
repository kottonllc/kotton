// SPDX-License-Identifier: AGPL-3.0-or-later
use serde::{Deserialize, Serialize};

/// Verification method for a DID document
///
/// Used to express verification methods, such as cryptographic public keys,
/// which can be used to authenticate or authorize interactions with the DID subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethod {
    /// Verification method ID (typically DID + #key-1)
    pub id: String,

    /// Type of verification method (e.g., "Ed25519VerificationKey2020")
    #[serde(rename = "type")]
    pub type_: String,

    /// DID of the controller
    pub controller: String,

    /// Public key in multibase format
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,
}

impl VerificationMethod {
    /// Create a new verification method
    pub fn new(
        id: impl Into<String>,
        type_: impl Into<String>,
        controller: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            type_: type_.into(),
            controller: controller.into(),
            public_key_multibase: None,
        }
    }

    /// Set the public key in multibase format
    pub fn with_public_key_multibase(mut self, key: impl Into<String>) -> Self {
        self.public_key_multibase = Some(key.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_method_serialization() {
        let vm = VerificationMethod::new(
            "did:key:z6Mk...#z6Mk...",
            "Ed25519VerificationKey2020",
            "did:key:z6Mk...",
        )
        .with_public_key_multibase("z6Mk...");

        let json = serde_json::to_string_pretty(&vm).unwrap();
        assert!(json.contains("Ed25519VerificationKey2020"));
        assert!(json.contains("publicKeyMultibase"));
    }
}
