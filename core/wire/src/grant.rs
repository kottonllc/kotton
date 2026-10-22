// SPDX-License-Identifier: AGPL-3.0-or-later
//! `GrantEnvelope` — the canonical signed capability wire format.
//!
//! A `GrantEnvelope` wraps a set of [`CapabilityGrant`]s together with issuer and
//! subject identity, an optional node scope, a timestamp, and an Ed25519 signature.
//! It is the single accepted format for all capability grants in Kotton — self-signed
//! personal app grants and cross-DID org grants use the same type.
//!
//! ## Canonical form for signing
//!
//! Before signing, the envelope is serialised to a canonical JSON string:
//!
//! - The `issuer_signature` field is excluded entirely.
//! - Object keys are sorted alphabetically at every level.
//! - No whitespace outside string values.
//!
//! The signature covers the UTF-8 bytes of this canonical string.
//!
//! Use [`GrantEnvelope::canonical_json`] to produce the canonical form.
//!
//! ## Node scope
//!
//! `node_did` scopes the envelope to a specific node. At OSS launch only a single
//! device DID is ever set here and enforcement is a simple equality check. Post-OSS
//! `node_did` may hold a deployment DID whose membership record is checked instead.
//! The wire format is the same in both cases — the expansion is additive.

use crate::did::Did;
use kotton_schemas::CapabilityGrant;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// How long a grant is meant to last, chosen at the moment it is issued.
///
/// This exists because the alternative is a literal at the call site, and a
/// literal cannot be reviewed: `now + 365 * 24 * 3600` was the only lifetime
/// any app grant had, it was invisible in the type, and nothing re-issued it —
/// so every installed app was one year from losing every capability with a
/// `GrantDenied::Expired` (raised in `kotton-wasm`'s `grant_check`) that looks
/// exactly like a capability it never held.
///
/// # The four the consent standard needs
///
/// `capability-and-consent.md` asks a consent prompt to offer *once*, *while
/// open*, and *always*, with the least-privilege option the calm default. All
/// four are representable now, and none of them rounds a use count or a process
/// lifetime to a timestamp — [`Self::Uses`] and [`Self::WhileOpen`] carry
/// `expires_at: None` and are enforced by the daemon's use counter and instance
/// binding, not by a clock (`TASK-a-grant-cannot-be-once-or-while-open`).
///
/// - *once* → `Uses(1)`; *while open* → `WhileOpen`; *always* → `UntilRevoked`;
///   a countdown → `Seconds`.
/// - The two counted lifetimes are daemon-enforced: a `Uses` grant's counter is
///   decremented once per activation (a launch, or a message to a one-shot app)
///   and denies at zero, and a `WhileOpen` grant is exhausted when its instance
///   is torn down. Both route through the same revocation the runner already
///   checks, so an exhausted grant denies without a new code path. A prompt may
///   offer all four and tell the truth about each, at that granularity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantLifetime {
    /// No expiry. The grant ends when it is revoked, and only then.
    ///
    /// Correct for a **self-issued** grant — the user granting capabilities to an
    /// app on their own device — which is the case this envelope's `expires_at`
    /// doc already sanctions `None` for. Revocation is the control here, and it
    /// exists: an envelope id in the revocation list is checked on every access.
    UntilRevoked,

    /// Expires this many seconds after issuance.
    ///
    /// Correct for anything issued **to another party** — a cross-DID grant to
    /// another user or an org member — where the issuer cannot rely on reaching
    /// the holder to revoke.
    Seconds(u64),

    /// Valid for a bounded number of **activations**, then exhausted — the
    /// consent standard's *allow once* with `uses` of 1.
    ///
    /// Not a timestamp: `expires_at` is `None` here, because "one use" and
    /// "sixty seconds" are different promises and a type must not round one to
    /// the other. Enforced by a durable counter the daemon decrements, once,
    /// each time it hands the grant to a running app — a launch, or a message to
    /// a one-shot app. When the counter reaches zero the grant denies exactly as
    /// a revoked one does. An **activation** is that hand-off, which is the unit
    /// the daemon can meter without trusting the guest to report its own use;
    /// finer per-call metering would need the runner to count and report, and is
    /// not what this enforces. See `TASK-a-grant-cannot-be-once-or-while-open`.
    Uses(u32),

    /// Valid while an instance of the app is running, revoked when it exits —
    /// the consent standard's *while the app is open*.
    ///
    /// Not a timestamp either: the grant is bound to a process, not a clock. The
    /// daemon supplies it to the running instance and exhausts it when that
    /// instance is torn down (crash, terminate, uninstall), so a later launch
    /// does not inherit it without being granted again.
    WhileOpen,
}

impl GrantLifetime {
    /// The `expires_at` this lifetime produces for an envelope issued at `issued_at`.
    ///
    /// Saturating rather than wrapping: a caller passing a nonsensically large
    /// TTL gets "effectively never", which is the same failure the value asked
    /// for, instead of a timestamp in the past that denies everything.
    ///
    /// The `try_from` is load-bearing and was a bug first: `u64::MAX as i64` is
    /// `-1`, so `saturating_add` moved the expiry *backwards* and the grant was
    /// born expired. A lossy cast on the way into a security decision is worth
    /// spelling out rather than trusting to a suffix.
    pub fn expires_at(self, issued_at: i64) -> Option<i64> {
        match self {
            // No time-based expiry: `UntilRevoked` never expires, and `Uses` /
            // `WhileOpen` expire on a use count and a process lifetime the daemon
            // tracks, not on a clock.
            GrantLifetime::UntilRevoked | GrantLifetime::Uses(_) | GrantLifetime::WhileOpen => None,
            GrantLifetime::Seconds(s) => {
                Some(issued_at.saturating_add(i64::try_from(s).unwrap_or(i64::MAX)))
            }
        }
    }

    /// The use budget this lifetime starts with, if it is counted.
    ///
    /// `Some(n)` only for [`GrantLifetime::Uses`]; every other lifetime is not
    /// use-limited and returns `None`. The daemon records this at issuance and
    /// the runner decrements it as the grant is exercised.
    pub fn initial_uses(self) -> Option<u32> {
        match self {
            GrantLifetime::Uses(n) => Some(n),
            _ => None,
        }
    }

    /// Whether this lifetime is bound to a running instance and must be exhausted
    /// when that instance exits.
    pub fn is_while_open(self) -> bool {
        matches!(self, GrantLifetime::WhileOpen)
    }
}

/// A signed, expiry-bearing capability envelope.
///
/// Issued by an identity (user or org) to grant a subject specific capabilities
/// on a specific node. Both parties are identified by DID. The envelope is
/// self-contained: any party with the issuer's public key can verify it offline.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-types", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-types", ts(export))]
pub struct GrantEnvelope {
    /// UUID v4 uniquely identifying this envelope. Stored in the revocation list
    /// by id when revoked.
    pub id: String,

    /// DID of the entity that issued this grant (user or org).
    pub issuer_did: Did,

    /// DID of the entity this grant is issued to.
    pub subject_did: Did,

    /// DID of the node this grant is scoped to.
    ///
    /// `None` means the grant is valid on any node the subject presents it to.
    /// At OSS launch a device DID is always set here. Post-OSS this may be a
    /// deployment DID — enforcement changes (membership check vs. equality) but
    /// the wire format does not.
    pub node_did: Option<Did>,

    /// The capabilities this envelope grants to `subject_did`.
    pub grants: Vec<CapabilityGrant>,

    /// Unix timestamp (seconds) when this envelope was issued.
    #[cfg_attr(feature = "ts-types", ts(type = "number"))]
    pub issued_at: i64,

    /// Unix timestamp (seconds) after which this envelope is no longer valid.
    ///
    /// `None` means no expiry. Not recommended for cross-DID grants issued to
    /// other users or org members — always set an explicit TTL there.
    #[cfg_attr(feature = "ts-types", ts(type = "number | null"))]
    pub expires_at: Option<i64>,

    /// The app this envelope was issued to, and **inside the signature**
    /// (`DEC-0052`, Article IV).
    ///
    /// Until 2026-09-09 the app lived only in the `app_grant_envelopes.app_id`
    /// column, which nobody signed. The signed body bound issuer and subject —
    /// both the user, since an install grant is self-issued — so every one of a
    /// user's app grants was cryptographically identical and told apart only by a
    /// column. Anything that could write that column could move a capability the
    /// user approved for one app onto another, and the envelope would still
    /// verify. The minting function even took an `app_id` and discarded it:
    /// `_app_id`.
    ///
    /// `None` means an envelope from before this field existed. It is **not**
    /// treated as a wildcard: `check_grant` refuses it as unbound, because the
    /// permissive reading is the one that keeps the hole open. Such an envelope
    /// is re-minted from the recorded approval — the actual consent — rather than
    /// from the column.
    ///
    /// Serialised only when set, which keeps the canonical form of an
    /// already-signed legacy envelope byte-identical, so it still verifies and
    /// fails for the reason it should — *unbound* — rather than as a signature
    /// mystery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-types", ts(type = "string | null"))]
    pub app_id: Option<String>,

    /// Base64url-encoded Ed25519 signature by `issuer_did` over the canonical
    /// JSON form of this envelope (all fields except `issuer_signature`, keys
    /// sorted alphabetically).
    ///
    /// An empty string means the envelope has not yet been signed (construction
    /// in progress). The daemon rejects any unsigned envelope presented to it.
    pub issuer_signature: String,
}

impl GrantEnvelope {
    /// Produce the canonical JSON string used as the signing input.
    ///
    /// All fields except `issuer_signature` are included. Object keys are sorted
    /// alphabetically. No whitespace outside string values.
    ///
    /// # Errors
    ///
    /// Returns an error if any field fails to serialise (should not occur for
    /// well-formed envelopes).
    pub fn canonical_json(&self) -> serde_json::Result<String> {
        // BTreeMap sorts keys alphabetically on serialisation.
        let mut map: BTreeMap<&str, serde_json::Value> = BTreeMap::new();

        // Only when set, so a legacy envelope's canonical form is exactly what
        // was signed before this field existed. A `null` here would change every
        // stored envelope's digest and turn "unbound" into "bad signature".
        if let Some(app_id) = &self.app_id {
            map.insert("app_id", serde_json::Value::String(app_id.clone()));
        }
        map.insert("expires_at", serde_json::to_value(self.expires_at)?);
        map.insert("grants", serde_json::to_value(&self.grants)?);
        map.insert("id", serde_json::Value::String(self.id.clone()));
        map.insert("issued_at", serde_json::to_value(self.issued_at)?);
        map.insert("issuer_did", serde_json::to_value(&self.issuer_did)?);
        map.insert("node_did", serde_json::to_value(&self.node_did)?);
        map.insert("subject_did", serde_json::to_value(&self.subject_did)?);

        serde_json::to_string(&map)
    }
}

/// A membership grant: the envelope that admits an identity to a root, and the authority it
/// was issued under (RFC-0088, "Ownership and membership").
///
/// `grant` carries `root.member:<root>` to the member. Its issuer is either the root's
/// owner — then `authority` is absent — or a person the owner delegated `org.invite:<root>`
/// to, and then `authority` is **that delegation**, so anyone holding this can walk it back
/// to the owner with no call to anybody: the member's signature chain is two envelopes and
/// both are here. That is what lets a person who holds `org.invite` admit someone without
/// holding the org's key — and what makes a membership nobody delegated verify as nothing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipGrant {
    /// The envelope admitting the member.
    pub grant: GrantEnvelope,
    /// The owner's `org.invite` envelope to `grant`'s issuer, where the issuer is not the
    /// owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<GrantEnvelope>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotton_schemas::{CapabilityKind, Nsid};

    fn test_envelope() -> GrantEnvelope {
        GrantEnvelope {
            id: "00000000-0000-0000-0000-000000000001".into(),
            issuer_did: Did::parse("did:key:z6MkissuerDIDfake").unwrap(),
            subject_did: Did::parse("did:key:z6MksubjectDIDfake").unwrap(),
            node_did: Some(Did::parse("did:key:z6MknodeDIDfake").unwrap()),
            grants: vec![CapabilityGrant::schema(
                CapabilityKind::Read,
                Nsid::from_static("sh.kotton.notes"),
            )],
            issued_at: 1_700_000_000,
            expires_at: Some(1_700_086_400),
            app_id: Some("sh.kotton.notes".into()),
            issuer_signature: String::new(),
        }
    }

    #[test]
    fn canonical_json_excludes_signature() {
        let env = test_envelope();
        let canon = env.canonical_json().unwrap();
        assert!(
            !canon.contains("issuer_signature"),
            "canonical form must not contain issuer_signature"
        );
    }

    #[test]
    fn canonical_json_keys_are_sorted() {
        let env = test_envelope();
        let canon = env.canonical_json().unwrap();
        let v: serde_json::Value = serde_json::from_str(&canon).unwrap();
        let obj = v.as_object().unwrap();
        let keys: Vec<&String> = obj.keys().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(
            keys, sorted,
            "canonical JSON keys must be alphabetically sorted"
        );
    }

    #[test]
    fn canonical_json_is_stable() {
        let env = test_envelope();
        let a = env.canonical_json().unwrap();
        let b = env.canonical_json().unwrap();
        assert_eq!(a, b, "canonical_json must be deterministic");
    }

    #[test]
    fn roundtrip_serde() {
        let env = test_envelope();
        let json = serde_json::to_string(&env).unwrap();
        let back: GrantEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(env.id, back.id);
        assert_eq!(env.issuer_did, back.issuer_did);
        assert_eq!(env.subject_did, back.subject_did);
        assert_eq!(env.node_did, back.node_did);
        assert_eq!(env.issued_at, back.issued_at);
        assert_eq!(env.expires_at, back.expires_at);
    }

    #[test]
    fn until_revoked_sets_no_expiry_so_nothing_can_burn_down() {
        // The property the 365-day literal broke: a self-issued grant that
        // nothing re-issues must not carry an expiry, or every capability the
        // app declared stops working on a timer nobody set deliberately.
        assert_eq!(GrantLifetime::UntilRevoked.expires_at(1_700_000_000), None);
    }

    #[test]
    fn seconds_expires_relative_to_issuance_not_to_now() {
        let issued = 1_700_000_000;
        assert_eq!(
            GrantLifetime::Seconds(3600).expires_at(issued),
            Some(issued + 3600)
        );
    }

    #[test]
    fn an_absurd_ttl_saturates_instead_of_wrapping_into_the_past() {
        // i64::MAX seconds would overflow and land before `issued`, which would
        // deny every access — the opposite of what the caller asked for.
        let issued = 1_700_000_000;
        let got = GrantLifetime::Seconds(u64::MAX).expires_at(issued).unwrap();
        assert!(got > issued, "saturating add must stay in the future");
        assert_eq!(got, i64::MAX);
    }
}
