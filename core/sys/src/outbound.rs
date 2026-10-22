// SPDX-License-Identifier: AGPL-3.0-or-later
//! Mediated outbound requests — the contract (RFC-0049; Sprint 03 Phase 1).
//!
//! Confined extensions never touch the network directly. They compose a
//! request and hand it to the host, which decides whether it may leave, adds
//! any credential the extension is not allowed to see, performs it, and
//! returns the response. This module holds the *contract* for that path —
//! types and the [`NetMediator`] trait, no I/O. The HTTP implementation lives
//! in `kotton-providers-net-mediator` (tier 03); per-extension policy
//! enforcement lives in the runtime (tier 05).
//!
//! Three guarantees are expressed here, in the order they are checked:
//!
//! 1. **Destination is never local.** [`DestinationPolicy::LOCAL_ONLY`] —
//!    private, loopback, link-local, and unspecified addresses are refused for
//!    extension traffic, always, with no opt-out. This guards the user's LAN
//!    and the daemon's own ports: devices that never consented to being
//!    reachable by an installed extension. Enforced against **resolved
//!    addresses**, not the hostname string, so a DNS name that resolves inward
//!    is refused too (DNS rebinding).
//! 2. **Destination matches what the author declared** (RFC-0049: declared and
//!    binding). There is no opt-out — see [`DestinationPolicy`] for why the
//!    escape hatch an earlier draft carried was removed.
//! 3. **Credentials are host-held.** The extension writes
//!    [`CredentialRef`] placeholders; the host substitutes real secret material
//!    only when 1 and 2 pass. The secret never crosses into guest memory.

use std::fmt;
use std::net::IpAddr;

use async_trait::async_trait;
use thiserror::Error;

/// Largest response body the mediator will buffer for one request.
///
/// Matches RFC-0048's `RANGE_LEN`, the chunk size the rest of the system
/// moves bytes in; larger payloads are ranged by the caller rather than
/// buffered whole.
pub const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

// ── Request / response ────────────────────────────────────────────────────────

/// An outbound request composed by a confined extension.
///
/// Deliberately general (arbitrary method, headers, body) — RFC-0049's
/// "the interface can be loose" argument: generality costs nothing because
/// the *destination* is constrained and the extension holds nothing worth
/// leaking. What is *not* general: where it may go, and what secrets it may
/// carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundRequest {
    pub method: String,
    /// Absolute URL. Scheme must be `https` (or `http` only for a destination
    /// the policy explicitly allows, e.g. a test container).
    pub url: String,
    pub headers: Vec<(String, HeaderValue)>,
    pub body: Vec<u8>,
}

/// A header value: either literal bytes the extension wrote, or a reference to
/// a host-held credential the extension may use but never read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderValue {
    /// What the extension wrote, or a credential the host rendered in place of
    /// a [`CredentialRef`]. Either may be a bearer's words, so it is
    /// [`HeaderText`] and prints `<redacted>`.
    Literal(HeaderText),
    /// Substituted host-side with the named credential slot's material.
    Credential(CredentialRef),
}

/// A literal header's text. Nothing on the mediated path can tell which
/// literal is a credential: an extension may write an `authorization` or
/// `cookie` value it obtained itself, and the host writes a slot's material
/// here once it has resolved a [`CredentialRef`]. So every literal prints
/// `<redacted>` in a `{:?}`, has no `Display`, and is read through
/// [`HeaderText::expose`] by the transport that writes it onto the request.
///
/// The same shape as `kotton_wire::ipc::SecretText`, which carries the literal
/// across the runner wire; this crate holds the platform seam and names no
/// crate above `common`, so it cannot name that one.
#[derive(Clone, PartialEq, Eq)]
pub struct HeaderText(String);

impl HeaderText {
    pub fn new(text: impl Into<String>) -> Self {
        Self(text.into())
    }

    /// The text, for the one writer that puts it on the outgoing request.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for HeaderText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// A named credential slot declared in the extension manifest and filled by
/// the user at configuration time.
///
/// The extension refers to the slot; only the host can resolve it. `template`
/// lets the extension shape the header it needs (`"Bearer {}"`) without ever
/// holding the secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRef {
    pub slot: String,
    pub template: String,
}

impl CredentialRef {
    pub fn new(slot: impl Into<String>, template: impl Into<String>) -> Self {
        Self {
            slot: slot.into(),
            template: template.into(),
        }
    }

    /// Render the header value for `secret`, as the literal that carries it.
    pub fn render(&self, secret: &str) -> HeaderText {
        HeaderText::new(self.template.replacen("{}", secret, 1))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

// ── Destination policy ────────────────────────────────────────────────────────

/// A destination pattern an extension author declared in the manifest.
///
/// Host-only (never a path or query): the mediator constrains *where* a
/// request may go, never its shape. A leading `*.` matches any subdomain but
/// **not** the bare parent, so `*.example.com` does not authorize
/// `example.com` — widening must be declared, not inferred.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointPattern {
    host: String,
    wildcard: bool,
}

impl EndpointPattern {
    /// Parse a declared pattern. Rejects anything that is not a bare host
    /// pattern, and rejects a bare `*` — an author who wants unrestricted
    /// destinations must say so with `dynamic-endpoints`, where consent can
    /// surface it, rather than hiding it in a pattern list.
    pub fn parse(pattern: &str) -> Result<Self, PatternError> {
        let p = pattern.trim().to_ascii_lowercase();
        if p.is_empty() {
            return Err(PatternError::Empty);
        }
        if p.contains('/') || p.contains(':') || p.contains('?') {
            return Err(PatternError::NotBareHost(pattern.to_string()));
        }
        if p == "*" {
            return Err(PatternError::BareWildcard);
        }
        if let Some(rest) = p.strip_prefix("*.") {
            if rest.is_empty() || rest.contains('*') {
                return Err(PatternError::NotBareHost(pattern.to_string()));
            }
            return Ok(Self {
                host: rest.to_string(),
                wildcard: true,
            });
        }
        if p.contains('*') {
            return Err(PatternError::NotBareHost(pattern.to_string()));
        }
        Ok(Self {
            host: p,
            wildcard: false,
        })
    }

    /// Does `host` (already lowercased, no port) match this pattern?
    pub fn matches(&self, host: &str) -> bool {
        if self.wildcard {
            // A subdomain only: "a.example.com" yes, "example.com" no,
            // "notexample.com" no (the dot boundary is required).
            host.len() > self.host.len() + 1
                && host.ends_with(&self.host)
                && host.as_bytes()[host.len() - self.host.len() - 1] == b'.'
        } else {
            host == self.host
        }
    }
}

impl fmt::Display for EndpointPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.wildcard {
            write!(f, "*.{}", self.host)
        } else {
            f.write_str(&self.host)
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PatternError {
    #[error("endpoint pattern is empty")]
    Empty,
    #[error("`*` is not a valid endpoint pattern — declare the hosts this extension connects to")]
    BareWildcard,
    #[error("endpoint pattern must be a bare host (no scheme, port, or path): {0}")]
    NotBareHost(String),
}

/// Where an extension's traffic may go.
///
/// One variant, deliberately. An earlier design carried a `DynamicEndpoints`
/// escape hatch for extensions with runtime-determined destinations; it was
/// removed before anything used it. An opt-out from a security control is
/// policy-shaped in a system whose thesis is structure, and an escape hatch
/// that is easier than enumerating hosts gets taken by default — which would
/// turn the consent screen into noise. When a genuinely general fetcher needs
/// runtime destinations, the answer is a set grown from **user-authored
/// configuration** (each host consented individually, as the user types it),
/// not author-declared breadth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationPolicy {
    /// The author-declared patterns. An empty set permits nothing, which is
    /// the correct default for an extension that declared no network.
    patterns: Vec<EndpointPattern>,
}

impl DestinationPolicy {
    /// Non-negotiable rule applied under every policy: extension traffic may
    /// never reach a local, private, or otherwise non-routable address.
    pub const LOCAL_ONLY: &'static str =
        "private, loopback, and link-local destinations are never reachable by extensions";

    pub fn declared(patterns: Vec<EndpointPattern>) -> Self {
        Self { patterns }
    }

    /// A policy that permits no destination at all.
    pub fn none() -> Self {
        Self {
            patterns: Vec::new(),
        }
    }

    pub fn patterns(&self) -> &[EndpointPattern] {
        &self.patterns
    }

    pub fn allows_host(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        self.patterns.iter().any(|p| p.matches(&host))
    }
}

/// Is this a resolved address extension traffic must never reach?
///
/// Checked against every address a destination resolves to, after resolution
/// and before connecting. Rejecting on *any* resolved address (rather than the
/// one finally used) is deliberate: a name resolving to both a public and a
/// private address is a rebinding attempt, not a fallback.
///
/// IPv4-mapped and IPv4-compatible IPv6 addresses are unwrapped first —
/// `::ffff:127.0.0.1` is loopback wearing a v6 costume, and treating it as an
/// ordinary v6 address is the trap this project has already hit once (see the
/// pairing socket's v4-mapped bug).
pub fn is_forbidden_destination(addr: IpAddr) -> bool {
    // Unwrap v4-MAPPED addresses only (::ffff:a.b.c.d). The broader
    // `to_ipv4()` also converts obsolete v4-compatible addresses and turns
    // `::1` into `0.0.0.1`, which would sneak loopback past the check.
    let addr = match addr {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    };
    match addr {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast()
                || v4.is_unspecified()
                // 0.0.0.0/8 "this network"
                || v4.octets()[0] == 0
                // 100.64.0.0/10 carrier-grade NAT / Tailscale-style overlays
                || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
                // 192.0.0.0/24 IETF protocol assignments
                || (v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 0)
                // 198.18.0.0/15 benchmarking
                || (v4.octets()[0] == 198 && (18..20).contains(&v4.octets()[1]))
                // 240.0.0.0/4 reserved
                || v4.octets()[0] >= 240
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // fc00::/7 unique local
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // fe80::/10 link-local
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

// ── The mediator ──────────────────────────────────────────────────────────────

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NetError {
    #[error("destination refused: {0}")]
    DestinationRefused(String),
    #[error("credential slot `{0}` is not configured")]
    CredentialMissing(String),
    #[error("credentials cannot be injected under a dynamic-endpoints policy")]
    CredentialsForbidden,
    #[error("request malformed: {0}")]
    Malformed(String),
    #[error("rate limit exceeded")]
    RateLimited,
    #[error("response exceeded {MAX_RESPONSE_BYTES} bytes")]
    ResponseTooLarge,
    #[error("transport error: {0}")]
    Transport(String),
}

pub type NetResult<T> = Result<T, NetError>;

/// Performs a request that policy has already authorized.
///
/// Implementations own DNS resolution, the forbidden-address check against
/// resolved addresses, and the HTTP exchange. They do **not** know about
/// extensions, manifests, or credentials — the runtime resolves those first
/// and hands down a request with real header values.
#[async_trait]
pub trait NetMediator: Send + Sync {
    async fn perform(&self, request: OutboundRequest) -> NetResult<OutboundResponse>;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_matches_subdomains_but_not_the_bare_parent() {
        let p = EndpointPattern::parse("*.example.com").unwrap();
        assert!(p.matches("s3.example.com"));
        assert!(p.matches("a.b.example.com"));
        assert!(!p.matches("example.com"), "bare parent must not match");
        assert!(!p.matches("notexample.com"), "dot boundary required");
        assert!(!p.matches("example.com.evil.test"));
    }

    #[test]
    fn exact_pattern_matches_only_itself() {
        let p = EndpointPattern::parse("Example.COM").unwrap();
        assert!(p.matches("example.com"), "matching is case-insensitive");
        assert!(!p.matches("s3.example.com"));
    }

    #[test]
    fn bare_wildcard_is_refused_so_consent_can_show_dynamic_endpoints() {
        assert_eq!(EndpointPattern::parse("*"), Err(PatternError::BareWildcard));
    }

    #[test]
    fn patterns_must_be_bare_hosts() {
        for bad in [
            "https://example.com",
            "example.com/path",
            "example.com:443",
            "*.*.example.com",
        ] {
            assert!(
                EndpointPattern::parse(bad).is_err(),
                "{bad} must be rejected"
            );
        }
    }

    #[test]
    fn declared_policy_refuses_undeclared_hosts() {
        let policy = DestinationPolicy::declared(vec![
            EndpointPattern::parse("*.amazonaws.com").unwrap(),
            EndpointPattern::parse("example.com").unwrap(),
        ]);
        assert!(policy.allows_host("s3.us-east-1.amazonaws.com"));
        assert!(policy.allows_host("EXAMPLE.COM"));
        assert!(!policy.allows_host("evil.test"));
        assert!(!policy.allows_host("amazonaws.com"));
    }

    /// There is no policy that permits an arbitrary host. An extension that
    /// declared nothing reaches nothing — absence is refusal, never permission.
    #[test]
    fn no_declaration_permits_nothing() {
        let policy = DestinationPolicy::none();
        for host in ["example.com", "anything.test", "localhost"] {
            assert!(!policy.allows_host(host), "{host} must be refused");
        }
    }

    /// The LAN guard, including the v4-mapped-IPv6 trap.
    #[test]
    fn local_and_private_destinations_are_forbidden() {
        for addr in [
            "127.0.0.1",
            "::1",
            "::ffff:127.0.0.1", // loopback in a v6 costume
            "::ffff:192.168.1.1",
            "10.0.0.5",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.169.254", // cloud metadata endpoint
            "fe80::1",
            "fd00::1",
            "0.0.0.0",
            "::",
            "100.64.0.1",
            "198.18.0.1",
            "255.255.255.255",
        ] {
            assert!(
                is_forbidden_destination(addr.parse().unwrap()),
                "{addr} must be forbidden"
            );
        }
    }

    #[test]
    fn public_destinations_are_permitted() {
        for addr in ["1.1.1.1", "93.184.216.34", "2606:4700::1111", "8.8.8.8"] {
            assert!(
                !is_forbidden_destination(addr.parse().unwrap()),
                "{addr} must be allowed"
            );
        }
    }

    #[test]
    fn credential_ref_renders_into_its_template() {
        let c = CredentialRef::new("s3-key", "Bearer {}");
        assert_eq!(c.render("secret-value").expose(), "Bearer secret-value");
    }

    /// `value` does not appear in `printed`, `<redacted>` does, and `text`
    /// still reads back `value` as it was written.
    fn hides(printed: &str, text: &HeaderText, value: &str) {
        assert!(!printed.contains(value), "{value:?} prints in {printed}");
        assert!(printed.contains("<redacted>"), "{printed}");
        assert_eq!(text.expose(), value, "the transport must read what was written");
    }

    /// A literal header is whatever the extension wrote, a bearer token among
    /// them, or a slot's material the host rendered; neither prints wherever
    /// the request the mediator evaluates does.
    #[test]
    fn no_literal_header_prints_the_value_it_carries() {
        const BEARER: &str = "Bearer 3f9a1c7e-guest-held";
        const SLOT: &str = "slot-material-9d2e";
        let literal = HeaderText::new(BEARER);
        hides(&format!("{literal:?}"), &literal, BEARER);
        hides(&format!("{:?}", HeaderValue::Literal(literal.clone())), &literal, BEARER);

        let rendered = CredentialRef::new("api-token", "Bearer {}").render(SLOT);
        let request = OutboundRequest {
            method: "GET".into(),
            url: "https://api.example.com/".into(),
            headers: vec![
                ("authorization".into(), HeaderValue::Literal(literal.clone())),
                ("x-api-key".into(), HeaderValue::Literal(rendered.clone())),
            ],
            body: vec![],
        };
        let printed = format!("{request:?}");
        hides(&printed, &literal, BEARER);
        assert!(!printed.contains(SLOT), "{SLOT:?} prints in {printed}");
        assert_eq!(rendered.expose(), format!("Bearer {SLOT}"));
    }
}
