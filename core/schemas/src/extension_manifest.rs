// SPDX-License-Identifier: AGPL-3.0-or-later
//! The extension manifest (RFC-0049/RFC-0050; Sprint 03 Phase 2).
//!
//! What an extension author declares, and what the user is shown before
//! consenting. Deliberately separate from [`crate::AppManifest`]: an app
//! declares which of the user's data it wants, an extension declares which
//! *class* it is — and the class determines the WIT world, which determines
//! what it can reach at all.
//!
//! ```toml
//! [extension]
//! id = "sh.kotton.feed-reader"
//! name = "Feed Reader"
//! version = "0.1.0"
//! class = "fetcher"
//! description = "Mirrors an RSS or Atom feed into Kotton."
//!
//! [network]
//! purpose = "Fetch the feed you configure."
//! endpoints = ["*.substack.com", "news.ycombinator.com"]
//!
//! [[credential]]
//! slot = "api-token"
//! description = "Your API token for the service."
//!
//! [publisher]
//! did = "did:key:z6Mk..."
//! signature = "..."
//! ```
//!
//! **There is no way to declare "any host."** An extension names the hosts it
//! connects to, or holds no network. An earlier draft carried a
//! `dynamic-endpoints` opt-out for runtime-determined destinations; it was
//! removed before anything used it, for three reasons: an opt-out from a
//! security control is policy-shaped in a system whose thesis is structure; an
//! escape hatch cheaper than enumerating hosts gets taken by default, turning
//! the consent screen into noise; and nothing needed it. When a genuinely
//! general fetcher does, the answer is a destination set grown from
//! **user-authored configuration** — each host consented as the user types it —
//! rather than author-declared breadth.
//!
//! Removing it also removed an invariant: the old rule that `dynamic-endpoints`
//! and credentials could not coexist existed only because the hatch did.
//!
//! One thing is deliberately *not* validated here: **endpoint patterns are text
//! in this crate, parsed where they are enforced.** This is tier 01 and cannot
//! see `EndpointPattern` (tier 01 platform), so patterns are carried as strings
//! and parsed by the installer, which fails the install on a bad one. One
//! parser at the enforcement point beats two that can disagree.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Which extension class this is — the discriminator for which WIT world the
/// component is instantiated against, and therefore for what it can reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExtensionClass {
    /// Pulls external data *in*. Holds `external-net` + quarantine; imports
    /// nothing that reads the user's existing data.
    Fetcher,
    /// Implements the blind-store interface for a remote store. Holds
    /// `external-net`; only ever handed sealed blobs.
    StorageBackend,
}

impl ExtensionClass {
    /// The WIT world a component of this class is instantiated against.
    pub fn world(&self) -> &'static str {
        match self {
            Self::Fetcher => "fetcher",
            Self::StorageBackend => "storage-backend",
        }
    }
}

/// Where an extension declares it will connect.
///
/// There is no "any host" option. An extension either names the hosts it
/// connects to or holds no network at all — see [`crate::extension_manifest`]
/// module docs for why the escape hatch an earlier draft carried was removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkDeclaration {
    /// No network at all.
    None,
    /// Only these host patterns. Enforced (RFC-0049: declared and binding).
    Endpoints {
        purpose: String,
        patterns: Vec<String>,
    },
}

impl NetworkDeclaration {
    pub fn purpose(&self) -> Option<&str> {
        match self {
            Self::None => None,
            Self::Endpoints { purpose, .. } => Some(purpose),
        }
    }
}

/// A named secret the user supplies at configuration time and the **host**
/// holds. The extension names the slot; only the host can resolve it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialSlot {
    pub slot: String,
    /// Shown to the user when they are asked to supply it.
    pub description: String,
}

/// Author identity over the package's content hash. Same primitives as
/// [`crate::AppManifest`]'s publisher — one trust model, two package kinds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionPublisher {
    pub did: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionManifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub class: ExtensionClass,
    pub description: String,
    pub network: NetworkDeclaration,
    pub credentials: Vec<CredentialSlot>,
    pub publisher: Option<ExtensionPublisher>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ExtensionManifestError {
    #[error("manifest is not valid TOML: {0}")]
    Toml(String),
    #[error("`{0}` is required")]
    Missing(&'static str),
    #[error("extension id `{0}` is not a reverse-domain identifier")]
    BadId(String),
    #[error(
        "`dynamic-endpoints` is not supported: declare the hosts this extension connects to \
         (RFC-0049 — endpoint declarations are binding, with no opt-out)"
    )]
    DynamicEndpointsUnsupported,
    #[error("[network] declares no `endpoints`")]
    EmptyNetwork,
    #[error("credential slot `{0}` is declared more than once")]
    DuplicateSlot(String),
    #[error("[publisher] must have both `did` and `signature`")]
    PartialPublisher,
}

// ── Raw TOML shapes ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RawManifest {
    extension: RawExtension,
    network: Option<RawNetwork>,
    #[serde(default)]
    credential: Vec<RawCredential>,
    publisher: Option<RawPublisher>,
}

#[derive(Deserialize)]
struct RawExtension {
    id: String,
    name: String,
    version: String,
    class: ExtensionClass,
    #[serde(default)]
    description: String,
}

#[derive(Deserialize)]
struct RawNetwork {
    #[serde(default)]
    purpose: String,
    #[serde(default)]
    endpoints: Vec<String>,
    #[serde(default, rename = "dynamic-endpoints")]
    dynamic_endpoints: bool,
}

#[derive(Deserialize)]
struct RawCredential {
    slot: String,
    #[serde(default)]
    description: String,
}

#[derive(Deserialize)]
struct RawPublisher {
    did: Option<String>,
    signature: Option<String>,
}

impl ExtensionManifest {
    pub fn from_toml(toml_str: &str) -> Result<Self, ExtensionManifestError> {
        let raw: RawManifest =
            toml::from_str(toml_str).map_err(|e| ExtensionManifestError::Toml(e.to_string()))?;

        if raw.extension.id.trim().is_empty() {
            return Err(ExtensionManifestError::Missing("extension.id"));
        }
        // Reverse-domain, same shape as an app id: at least one dot, no path
        // or whitespace. The id names a directory and a capability namespace,
        // so it must be boring.
        let id = raw.extension.id.trim().to_string();
        if !id.contains('.')
            || id.contains('/')
            || id.contains('\\')
            || id.contains("..")
            || id.chars().any(|c| c.is_whitespace())
        {
            return Err(ExtensionManifestError::BadId(id));
        }

        let network = match raw.network {
            None => NetworkDeclaration::None,
            Some(n) => {
                // Refused explicitly rather than ignored: a manifest written
                // against the older draft must fail loudly, not install with
                // silently narrower reach than its author expected.
                if n.dynamic_endpoints {
                    return Err(ExtensionManifestError::DynamicEndpointsUnsupported);
                }
                if n.endpoints.is_empty() {
                    return Err(ExtensionManifestError::EmptyNetwork);
                }
                NetworkDeclaration::Endpoints {
                    purpose: n.purpose,
                    patterns: n.endpoints,
                }
            }
        };

        let mut credentials = Vec::new();
        for c in raw.credential {
            if credentials
                .iter()
                .any(|existing: &CredentialSlot| existing.slot == c.slot)
            {
                return Err(ExtensionManifestError::DuplicateSlot(c.slot));
            }
            credentials.push(CredentialSlot {
                slot: c.slot,
                description: c.description,
            });
        }

        let publisher = match raw.publisher {
            None => None,
            Some(p) => match (p.did, p.signature) {
                (Some(did), Some(signature)) => Some(ExtensionPublisher { did, signature }),
                _ => return Err(ExtensionManifestError::PartialPublisher),
            },
        };

        Ok(Self {
            id,
            name: raw.extension.name,
            version: raw.extension.version,
            class: raw.extension.class,
            description: raw.extension.description,
            network,
            credentials,
            publisher,
        })
    }

    /// The lines a consent screen shows, in the order a user should read them.
    ///
    /// Built here so every surface (CLI, shell, future GUI) says the same
    /// thing — the consent text is part of the security model, not per-client
    /// copy, and a discrepancy between surfaces is a way to mislead.
    pub fn consent_summary(&self) -> Vec<String> {
        let mut lines = vec![
            format!("{} ({}) v{}", self.name, self.id, self.version),
            format!(
                "Class: {} — {}",
                self.class.world(),
                match self.class {
                    ExtensionClass::Fetcher =>
                        "pulls external data in; cannot read your existing data",
                    ExtensionClass::StorageBackend =>
                        "stores your sealed data remotely; cannot read it",
                }
            ),
        ];
        if !self.description.is_empty() {
            lines.push(self.description.clone());
        }
        match &self.network {
            NetworkDeclaration::None => lines.push("Network: none.".into()),
            NetworkDeclaration::Endpoints { purpose, patterns } => {
                lines.push(format!(
                    "Network: only {} — {}",
                    patterns.join(", "),
                    purpose
                ));
            }
        }
        for c in &self.credentials {
            lines.push(format!(
                "Credential `{}`: {} (stored by Kotton; the extension never reads it)",
                c.slot, c.description
            ));
        }
        lines.push(match &self.publisher {
            Some(p) => format!("Signed by {}", p.did),
            None => "UNSIGNED — no publisher signature".into(),
        });
        lines
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const FETCHER: &str = r#"
[extension]
id = "sh.kotton.feed-reader"
name = "Feed Reader"
version = "0.1.0"
class = "fetcher"
description = "Mirrors a feed."

[network]
purpose = "Fetch the feed you configure."
endpoints = ["*.substack.com", "news.ycombinator.com"]
"#;

    #[test]
    fn a_fetcher_manifest_parses() {
        let m = ExtensionManifest::from_toml(FETCHER).unwrap();
        assert_eq!(m.id, "sh.kotton.feed-reader");
        assert_eq!(m.class, ExtensionClass::Fetcher);
        assert_eq!(m.class.world(), "fetcher");
        match m.network {
            NetworkDeclaration::Endpoints { patterns, .. } => {
                assert_eq!(patterns, vec!["*.substack.com", "news.ycombinator.com"]);
            }
            other => panic!("expected declared endpoints, got {other:?}"),
        }
        assert!(m.publisher.is_none());
    }

    /// There is no way to ask for unrestricted reach. A manifest written
    /// against the older draft fails loudly rather than installing with
    /// silently narrower reach than its author expected.
    #[test]
    fn dynamic_endpoints_is_refused_not_ignored() {
        let toml = r#"
[extension]
id = "sh.kotton.greedy"
name = "Greedy"
version = "0.1.0"
class = "fetcher"

[network]
purpose = "Anything."
dynamic-endpoints = true
"#;
        assert_eq!(
            ExtensionManifest::from_toml(toml),
            Err(ExtensionManifestError::DynamicEndpointsUnsupported)
        );
    }

    #[test]
    fn a_network_section_must_declare_endpoints() {
        let neither = r#"
[extension]
id = "sh.kotton.x"
name = "X"
version = "0.1.0"
class = "fetcher"

[network]
purpose = "Vague."
"#;
        assert_eq!(
            ExtensionManifest::from_toml(neither),
            Err(ExtensionManifestError::EmptyNetwork)
        );
    }

    /// The id names a directory and a capability namespace, so it must not be
    /// able to escape either.
    #[test]
    fn a_hostile_id_is_refused() {
        for bad in [
            "../../etc/passwd",
            "sh.kotton/../other",
            "sh\\kotton\\x",
            "no-dots",
            "sh.kotton has spaces",
        ] {
            let toml = format!(
                r#"
[extension]
id = "{bad}"
name = "X"
version = "0.1.0"
class = "fetcher"
"#
            );
            assert!(
                ExtensionManifest::from_toml(&toml).is_err(),
                "`{bad}` must be refused"
            );
        }
    }

    #[test]
    fn a_partial_publisher_section_is_refused() {
        let toml = r#"
[extension]
id = "sh.kotton.x"
name = "X"
version = "0.1.0"
class = "fetcher"

[publisher]
did = "did:key:z6Mk"
"#;
        assert_eq!(
            ExtensionManifest::from_toml(toml),
            Err(ExtensionManifestError::PartialPublisher)
        );
    }

    #[test]
    fn duplicate_credential_slots_are_refused() {
        let toml = r#"
[extension]
id = "sh.kotton.x"
name = "X"
version = "0.1.0"
class = "storage-backend"

[network]
purpose = "Store."
endpoints = ["*.amazonaws.com"]

[[credential]]
slot = "key"
description = "one"

[[credential]]
slot = "key"
description = "two"
"#;
        assert_eq!(
            ExtensionManifest::from_toml(toml),
            Err(ExtensionManifestError::DuplicateSlot("key".into()))
        );
    }

    /// Consent text is part of the security model, so it is built once here
    /// rather than written per client — every surface must say the same thing.
    #[test]
    fn consent_summary_names_the_endpoints_and_the_signing_state() {
        let declared = ExtensionManifest::from_toml(FETCHER).unwrap();
        let lines = declared.consent_summary().join("\n");
        assert!(lines.contains("only *.substack.com"), "got:\n{lines}");
        assert!(
            lines.contains("UNSIGNED"),
            "an unsigned package must say so:\n{lines}"
        );
        assert!(
            lines.contains("cannot read your existing data"),
            "the class's guarantee is the point of showing the class:\n{lines}"
        );
    }
}
