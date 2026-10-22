// SPDX-License-Identifier: AGPL-3.0-or-later
//! Verifying an extension package before it is installed (RFC-0049/RFC-0050;
//! Sprint 03 Phase 2).
//!
//! Everything security-relevant about installing an extension, as a pure
//! function: no database, no filesystem, no daemon. Give it a manifest and the
//! component bytes; it either produces a [`VerifiedExtension`] the installer
//! can act on, or refuses with a reason.
//!
//! Keeping it pure is deliberate — this is the point where a package earns the
//! right to run, so it should be exhaustively testable without standing
//! anything up. The daemon-side install handler is then plumbing: write files,
//! insert a row, store grants.
//!
//! ## What is checked, and in what order
//!
//! 1. **The manifest parses** and satisfies its own invariants
//!    ([`ExtensionManifest`] — notably that `dynamic-endpoints` and credentials
//!    cannot coexist).
//! 2. **The content hash** is computed here, from the bytes, never trusted from
//!    the package. BLAKE3, same identity primitive as RFC-0013 apps.
//! 3. **The publisher signature**, if present, verifies over that hash. If
//!    absent the package installs but is marked unsigned, and consent says so —
//!    provenance is a fact to show the user, not a gate the core imposes
//!    (RFC-0013: no mandatory gatekeeper).
//! 4. **Every declared endpoint pattern parses** as an [`EndpointPattern`]. A
//!    pattern the enforcer cannot understand is refused at install rather than
//!    silently ignored at request time.
//!
//! ## Grants are derived, never requested
//!
//! The capability set an extension receives is computed **from its class**, not
//! read from its manifest. A fetcher gets quarantine access to its own
//! namespace and, if it declared network, the network capability — because that
//! is what a fetcher is. There is no manifest key by which an author could ask
//! for anything else, and the quarantine namespace is bound to the id the
//! installer verified. That is the difference between "the author declares what
//! it needs" and "the author declares what it *is*."

use kotton_schemas::{
    CapabilityGrant, CapabilityKind, CapabilitySet, CapabilityTarget, ExtensionClass,
    ExtensionManifest, ExtensionManifestError, NetworkDeclaration,
};
use kotton_sys::outbound::{DestinationPolicy, EndpointPattern};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum InstallError {
    #[error("manifest: {0}")]
    Manifest(#[from] ExtensionManifestError),
    #[error("endpoint pattern `{pattern}` is not usable: {reason}")]
    BadEndpointPattern { pattern: String, reason: String },
    #[error("publisher signature is invalid: {0}")]
    BadSignature(String),
    #[error("the package is empty")]
    EmptyPackage,
}

/// A package that has earned the right to be installed.
#[derive(Debug, Clone)]
pub struct VerifiedExtension {
    pub manifest: ExtensionManifest,
    /// BLAKE3 of the component bytes, hex. Computed here from the bytes —
    /// never taken from the package.
    pub content_hash: String,
    /// Whether a publisher signature was present *and* verified. `false` means
    /// unsigned, which installs but must be surfaced.
    pub signed: bool,
    /// Where this extension may connect, ready for the mediator.
    pub destination_policy: DestinationPolicy,
    /// The capabilities the daemon will mint — derived from the class.
    pub grants: CapabilitySet,
}

impl VerifiedExtension {
    /// Consent lines, with the unsigned case made explicit by construction.
    pub fn consent_summary(&self) -> Vec<String> {
        self.manifest.consent_summary()
    }
}

/// Verify a package. `verify_signature` performs the DID signature check —
/// injected so this module stays free of crypto-provider wiring and can be
/// tested against both outcomes.
///
/// The callback receives `(publisher_did, signature_b64, content_hash_hex)`.
pub fn verify_package<F>(
    manifest_toml: &str,
    wasm_bytes: &[u8],
    verify_signature: F,
) -> Result<VerifiedExtension, InstallError>
where
    F: FnOnce(&str, &str, &str) -> Result<(), String>,
{
    if wasm_bytes.is_empty() {
        return Err(InstallError::EmptyPackage);
    }

    let manifest = ExtensionManifest::from_toml(manifest_toml)?;
    let content_hash = hex::encode(blake3::hash(wasm_bytes).as_bytes());

    let signed = match &manifest.publisher {
        Some(p) => {
            verify_signature(&p.did, &p.signature, &content_hash)
                .map_err(InstallError::BadSignature)?;
            true
        }
        None => false,
    };

    let destination_policy = destination_policy_for(&manifest)?;
    let grants = grants_for(&manifest);

    Ok(VerifiedExtension {
        manifest,
        content_hash,
        signed,
        destination_policy,
        grants,
    })
}

/// Turn the manifest's declared endpoints into the policy the mediator
/// enforces, failing the install on any pattern the enforcer cannot parse.
fn destination_policy_for(manifest: &ExtensionManifest) -> Result<DestinationPolicy, InstallError> {
    match &manifest.network {
        // No network declared permits nothing — absence is refusal, never
        // permission.
        NetworkDeclaration::None => Ok(DestinationPolicy::none()),
        NetworkDeclaration::Endpoints { patterns, .. } => {
            let mut parsed = Vec::with_capacity(patterns.len());
            for pattern in patterns {
                parsed.push(EndpointPattern::parse(pattern).map_err(|e| {
                    InstallError::BadEndpointPattern {
                        pattern: pattern.clone(),
                        reason: e.to_string(),
                    }
                })?);
            }
            Ok(DestinationPolicy::declared(parsed))
        }
    }
}

/// The capability set for a class. Derived, not requested.
fn grants_for(manifest: &ExtensionManifest) -> CapabilitySet {
    let mut grants = Vec::new();

    if !matches!(manifest.network, NetworkDeclaration::None) {
        grants.push(CapabilityGrant::action(CapabilityTarget::Network));
    }

    match manifest.class {
        // A fetcher lands what it pulled in its own quarantine and reads back
        // only what it wrote. The namespace is bound to the verified id, so an
        // author cannot name someone else's.
        ExtensionClass::Fetcher => {
            let target = CapabilityTarget::Quarantine {
                extension_id: manifest.id.clone(),
            };
            grants.push(CapabilityGrant {
                kind: CapabilityKind::Write,
                target: target.clone(),
            });
            grants.push(CapabilityGrant {
                kind: CapabilityKind::Read,
                target,
            });
        }
        // A storage backend is driven by the sync engine over sealed blobs; it
        // needs no VFS or quarantine reach of its own.
        ExtensionClass::StorageBackend => {}
    }

    CapabilitySet::new(grants)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_sig(_did: &str, _sig: &str, _hash: &str) -> Result<(), String> {
        Ok(())
    }
    fn bad_sig(_did: &str, _sig: &str, _hash: &str) -> Result<(), String> {
        Err("signature verification failed".into())
    }

    const FETCHER: &str = r#"
[extension]
id = "sh.kotton.feed-reader"
name = "Feed Reader"
version = "0.1.0"
class = "fetcher"

[network]
purpose = "Fetch the feed you configure."
endpoints = ["*.substack.com", "news.ycombinator.com"]
"#;

    #[test]
    fn a_fetcher_package_verifies_and_derives_its_policy() {
        let v = verify_package(FETCHER, b"\0asm-not-really", ok_sig).unwrap();

        assert!(!v.signed, "no publisher section means unsigned");
        assert_eq!(v.content_hash.len(), 64, "BLAKE3 hex");

        assert_eq!(v.destination_policy.patterns().len(), 2);
        assert!(v.destination_policy.allows_host("blog.substack.com"));
        assert!(
            !v.destination_policy.allows_host("evil.test"),
            "only what was declared"
        );
    }

    /// The property that makes quarantine safe: the grant is minted from the
    /// verified id and the class, so an author cannot ask for another's
    /// namespace — there is no manifest key that would express it.
    #[test]
    fn grants_are_derived_from_the_class_not_requested() {
        let v = verify_package(FETCHER, b"wasm", ok_sig).unwrap();

        let mine = CapabilityTarget::Quarantine {
            extension_id: "sh.kotton.feed-reader".into(),
        };
        let theirs = CapabilityTarget::Quarantine {
            extension_id: "sh.kotton.someone-else".into(),
        };
        assert!(v.grants.allows(&CapabilityKind::Write, &mine));
        assert!(v.grants.allows(&CapabilityKind::Read, &mine));
        assert!(!v.grants.allows(&CapabilityKind::Read, &theirs));
        assert!(v
            .grants
            .allows(&CapabilityKind::Use, &CapabilityTarget::Network));

        // And nothing that would reach the user's data.
        for path in ["/", "/notes", "/notes/todo.md"] {
            assert!(
                !v.grants.allows(
                    &CapabilityKind::Read,
                    &CapabilityTarget::Vfs { path: path.into() }
                ),
                "a fetcher must hold no VFS read on {path}"
            );
        }
    }

    #[test]
    fn a_storage_backend_gets_network_but_no_quarantine() {
        let toml = r#"
[extension]
id = "sh.kotton.s3"
name = "S3 Backend"
version = "0.1.0"
class = "storage-backend"

[network]
purpose = "Store sealed packs."
endpoints = ["*.amazonaws.com"]

[[credential]]
slot = "access-key"
description = "Your S3 access key."
"#;
        let v = verify_package(toml, b"wasm", ok_sig).unwrap();
        assert!(v
            .grants
            .allows(&CapabilityKind::Use, &CapabilityTarget::Network));
        assert!(!v.grants.allows(
            &CapabilityKind::Write,
            &CapabilityTarget::Quarantine {
                extension_id: "sh.kotton.s3".into()
            }
        ));
        assert_eq!(v.manifest.credentials.len(), 1);
    }

    /// A pattern the *enforcer* cannot parse must fail the install, not be
    /// quietly dropped — otherwise consent would show an endpoint that binds
    /// nothing.
    #[test]
    fn an_unenforceable_endpoint_pattern_fails_the_install() {
        for bad in ["https://example.com", "example.com/path", "*"] {
            let toml = format!(
                r#"
[extension]
id = "sh.kotton.x"
name = "X"
version = "0.1.0"
class = "fetcher"

[network]
purpose = "p"
endpoints = ["{bad}"]
"#
            );
            let err = verify_package(&toml, b"wasm", ok_sig)
                .expect_err(&format!("`{bad}` must fail the install"));
            assert!(
                matches!(err, InstallError::BadEndpointPattern { .. }),
                "got: {err}"
            );
        }
    }

    #[test]
    fn a_bad_publisher_signature_refuses_the_package() {
        let toml =
            format!("{FETCHER}\n[publisher]\ndid = \"did:key:z6Mk\"\nsignature = \"AAAA\"\n");
        let err = verify_package(&toml, b"wasm", bad_sig).expect_err("must refuse");
        assert!(matches!(err, InstallError::BadSignature(_)), "got: {err}");

        // The same package with a valid signature installs, and is marked signed.
        let v = verify_package(&toml, b"wasm", ok_sig).unwrap();
        assert!(v.signed);
    }

    /// The hash is computed from the bytes, so a package cannot assert its own
    /// identity — and different bytes are a different extension.
    #[test]
    fn the_content_hash_comes_from_the_bytes() {
        let a = verify_package(FETCHER, b"component-a", ok_sig).unwrap();
        let b = verify_package(FETCHER, b"component-b", ok_sig).unwrap();
        assert_ne!(a.content_hash, b.content_hash);
        assert_eq!(
            a.content_hash,
            hex::encode(blake3::hash(b"component-a").as_bytes())
        );
    }

    #[test]
    fn an_empty_package_is_refused() {
        let err = verify_package(FETCHER, b"", ok_sig).expect_err("must refuse");
        assert_eq!(err, InstallError::EmptyPackage);
    }

    /// An extension declaring no network gets a policy that permits nothing,
    /// rather than one that permits everything by absence.
    #[test]
    fn no_network_declaration_permits_no_destination() {
        let toml = r#"
[extension]
id = "sh.kotton.quiet"
name = "Quiet"
version = "0.1.0"
class = "fetcher"
"#;
        let v = verify_package(toml, b"wasm", ok_sig).unwrap();
        assert!(!v.destination_policy.allows_host("example.com"));
        assert!(!v
            .grants
            .allows(&CapabilityKind::Use, &CapabilityTarget::Network));
    }
}
