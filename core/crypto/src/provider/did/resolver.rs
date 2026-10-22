// SPDX-License-Identifier: AGPL-3.0-or-later
//! `DidResolver` trait and implementations.
//!
//! # Trait hierarchy
//!
//! ```text
//! DidResolver (trait)
//! ├── DidKeyResolver    — pure-math did:key resolution, always available
//! ├── DidWebResolver    — stub, TODO(v0.4): implement DID web resolution
//! └── CompositeDidResolver — dispatches to the right resolver by method prefix
//! ```
//!
//! # Usage
//!
//! ```rust
//! use kotton_crypto::did::resolver::CompositeDidResolver;
//! // create a resolver pre-configured for v0.3
//! let resolver = CompositeDidResolver::default_v0_3();
//! ```

use async_trait::async_trait;
use kotton_wire::did::{Did, DidDocument, DidError, Result as DidResult};

use super::DidKeyMethod;

// ---------------------------------------------------------------------------
// DidResolver trait
// ---------------------------------------------------------------------------

/// Resolves a [`Did`] to its [`DidDocument`].
///
/// Access is async because some resolvers (`did:web`, `did:ion`, …) make
/// network requests. `did:key` and `did:peer` resolve purely in-memory.
#[async_trait]
pub trait DidResolver: Send + Sync {
    /// Return the [`DidDocument`] for `did`, or an error.
    async fn resolve(&self, did: &Did) -> DidResult<DidDocument>;

    /// The DID method strings handled by this resolver, e.g. `["key"]`.
    fn supported_methods(&self) -> &[&'static str];
}

// ---------------------------------------------------------------------------
// DidKeyResolver
// ---------------------------------------------------------------------------

/// Pure-math `did:key` resolver.
///
/// Derives the [`DidDocument`] entirely from the multibase-encoded public key
/// embedded in the DID string. No network access, no external dependencies.
///
/// Supports: Ed25519 keys with the `0xed01` multicodec prefix.
pub struct DidKeyResolver;

#[async_trait]
impl DidResolver for DidKeyResolver {
    async fn resolve(&self, did: &Did) -> DidResult<DidDocument> {
        if did.method() != "key" {
            return Err(DidError::UnsupportedMethod(did.method().to_string()));
        }
        DidKeyMethod::to_document(did)
    }

    fn supported_methods(&self) -> &[&'static str] {
        &["key"]
    }
}

// ---------------------------------------------------------------------------
// DidWebResolver (stub — TODO v0.4)
// ---------------------------------------------------------------------------

/// `did:web` resolver stub.
///
/// **TODO(v0.4):** Implement HTTP(S) resolution following the DID Web spec.
/// See <https://w3c-ccg.github.io/did-method-web/>.
///
/// Currently always returns [`DidError::UnsupportedMethod`] to make it clear
/// that `did:web` is not yet implemented rather than silently failing.
pub struct DidWebResolver;

#[async_trait]
impl DidResolver for DidWebResolver {
    async fn resolve(&self, did: &Did) -> DidResult<DidDocument> {
        // TODO(v0.4): fetch https://{did.identifier()}/.well-known/did.json and
        // deserialize the returned DID Document JSON.
        let _ = did;
        Err(DidError::UnsupportedMethod(
            "did:web resolution is not yet implemented (planned for v0.4)".to_string(),
        ))
    }

    fn supported_methods(&self) -> &[&'static str] {
        &["web"]
    }
}

// ---------------------------------------------------------------------------
// CompositeDidResolver
// ---------------------------------------------------------------------------

/// Dispatching resolver — routes each DID to the first resolver that claims
/// the same method prefix.
///
/// Resolution order: resolvers are checked in insertion order; the first match
/// wins. If no resolver supports the DID method, [`DidError::UnsupportedMethod`]
/// is returned.
///
/// # Example
///
/// ```rust
/// use kotton_crypto::did::resolver::{CompositeDidResolver, DidResolver};
/// let resolver = CompositeDidResolver::default_v0_3();
/// // supported_methods() returns a Vec<&str> with all registered methods
/// assert_eq!(resolver.supported_methods(), vec!["key", "web"]);
/// ```
pub struct CompositeDidResolver {
    resolvers: Vec<Box<dyn DidResolver>>,
}

impl CompositeDidResolver {
    /// Build a resolver from an explicit list of delegates.
    ///
    /// Resolution is attempted in order; the first delegate whose
    /// [`supported_methods`] includes the DID's method string wins.
    pub fn new(resolvers: Vec<Box<dyn DidResolver>>) -> Self {
        Self { resolvers }
    }

    /// Default resolver configuration for Kotton v0.3.
    ///
    /// Supports: `did:key` (DidKeyResolver) and `did:web` (stub — not yet
    /// implemented).
    pub fn default_v0_3() -> Self {
        Self::new(vec![Box::new(DidKeyResolver), Box::new(DidWebResolver)])
    }

    /// Return all method strings supported by any registered resolver, in order.
    pub fn supported_methods(&self) -> Vec<&str> {
        let mut methods = Vec::new();
        for r in &self.resolvers {
            for &m in r.supported_methods() {
                if !methods.contains(&m) {
                    methods.push(m);
                }
            }
        }
        methods
    }
}

#[async_trait]
impl DidResolver for CompositeDidResolver {
    async fn resolve(&self, did: &Did) -> DidResult<DidDocument> {
        let method = did.method();
        for resolver in &self.resolvers {
            if resolver.supported_methods().contains(&method) {
                return resolver.resolve(did).await;
            }
        }
        Err(DidError::UnsupportedMethod(format!(
            "no resolver registered for did:{} (supported: {:?})",
            method,
            self.supported_methods()
        )))
    }

    fn supported_methods(&self) -> &[&'static str] {
        // CompositeDidResolver exposes a flattened dynamic list — we can't
        // return a static slice. Callers should use `CompositeDidResolver::supported_methods()`.
        &[]
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn make_did_key() -> Did {
        let key = SigningKey::generate(&mut OsRng);
        DidKeyMethod::from_public_key(&key.verifying_key())
    }

    // -- DidKeyResolver -------------------------------------------------------

    #[tokio::test]
    async fn key_resolver_resolves_valid_did_key() {
        let did = make_did_key();
        let resolver = DidKeyResolver;
        let doc = resolver.resolve(&did).await.expect("should resolve");
        assert_eq!(doc.id, did.to_string(), "document id must match the DID");
    }

    #[tokio::test]
    async fn key_resolver_unsupported_method_returns_error() {
        let did = Did::new("web", "example.com");
        let resolver = DidKeyResolver;
        let err = resolver.resolve(&did).await.unwrap_err();
        assert!(
            matches!(err, DidError::UnsupportedMethod(_)),
            "expected UnsupportedMethod, got {err:?}"
        );
    }

    // -- round-trip test (generate→DID→resolve→verify pubkey) ----------------

    #[tokio::test]
    async fn round_trip_key_matches_generated_keypair() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let expected_bytes = verifying_key.as_bytes();

        let did = DidKeyMethod::from_public_key(&verifying_key);
        let resolver = DidKeyResolver;
        let doc = resolver.resolve(&did).await.expect("should resolve");

        // The VerificationMethod public key should match the original key
        let vms = &doc.verification_method;
        assert!(
            !vms.is_empty(),
            "document must have at least one verification method"
        );

        // Re-derive pubkey bytes from the DID and compare
        let recovered_key = DidKeyMethod::to_public_key(&did).expect("to_public_key should work");
        assert_eq!(
            recovered_key.as_bytes(),
            expected_bytes,
            "recovered pubkey must match original"
        );
    }

    // -- CompositeDidResolver -------------------------------------------------

    #[tokio::test]
    async fn composite_resolves_did_key() {
        let did = make_did_key();
        let resolver = CompositeDidResolver::default_v0_3();
        let doc = resolver
            .resolve(&did)
            .await
            .expect("composite should resolve did:key");
        assert_eq!(doc.id, did.to_string());
    }

    #[tokio::test]
    async fn composite_unknown_method_returns_unsupported() {
        let did = Did::new("ion", "abc123");
        let resolver = CompositeDidResolver::default_v0_3();
        let err = resolver.resolve(&did).await.unwrap_err();
        assert!(
            matches!(err, DidError::UnsupportedMethod(_)),
            "expected UnsupportedMethod for did:ion"
        );
    }

    // -- DidWebResolver (stub) ------------------------------------------------

    #[tokio::test]
    async fn web_resolver_stub_returns_unsupported() {
        let did = Did::new("web", "example.com");
        let resolver = DidWebResolver;
        let err = resolver.resolve(&did).await.unwrap_err();
        assert!(
            matches!(err, DidError::UnsupportedMethod(_)),
            "DidWebResolver stub must return UnsupportedMethod, not panic"
        );
    }
}
