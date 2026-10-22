// SPDX-License-Identifier: AGPL-3.0-or-later
//! Wire types for the `kotton-relay` peer-address exchange and DM store-and-forward service.
//!
//! `kotton-relay` is a lightweight relay binary. Devices push their current external
//! address (STUN-discovered) and look up peers' addresses so that simultaneous QUIC
//! hole-punching can be attempted. The relay also accepts and queues encrypted DM blobs
//! for offline delivery — it never inspects or decrypts any content.
//!
//! ## Security model
//!
//! Every `POST /push` payload is signed with the device's Ed25519 key so the
//! rendezvous server can verify that the claim came from the device that owns the
//! fingerprint. The server verifies the signature and a recency timestamp to
//! prevent spoofing and replay attacks.
//!
//! The rendezvous server does **not** know which devices are paired — it only stores
//! (fingerprint → external_addr) entries with a short TTL. Pairing verification
//! stays in the QUIC mTLS layer where it always was.
//!
//! ## Layer note
//!
//! This module is part of `wire` and therefore must not depend on
//! `05_runtime` or higher.

use serde::{Deserialize, Serialize};

/// Payload sent by a device to register its current external address.
///
/// Sent as a JSON body to `POST /push` on the rendezvous server.
///
/// The `sig` field is an Ed25519 signature over the canonical string:
/// `"{fingerprint}\n{addr}\n{timestamp_unix}\n{turn_relay_addr_or_empty}\n{relayable}"`
/// (newline-separated, no trailing newline). If `turn_relay_addr` is absent the
/// fourth line is an empty string; the fifth line is `"true"` or `"false"`. The
/// signing key is the device's identity key (same key whose public half appears
/// in the `fingerprint` DID).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RendezvousPushPayload {
    /// DID key fingerprint of the pushing device, e.g. `"did:key:z6Mk..."`.
    pub fingerprint: String,
    /// External socket address discovered via STUN, e.g. `"203.0.113.45:51820"`.
    pub addr: String,
    /// Unix timestamp (seconds). Server rejects payloads where
    /// `|server_time - timestamp| > 30`.
    pub timestamp: i64,
    /// Base64url-encoded Ed25519 signature over
    /// `fingerprint\naddr\ntimestamp\nturn_relay_addr_or_empty\nrelayable`.
    pub sig: String,
    /// TURN relay address allocated for this device, e.g. `"198.51.100.20:49152"`.
    ///
    /// `None` (omitted from JSON) when no TURN relay has been allocated yet.
    /// Present during the TURN fallback phase so peers can reach each other
    /// through the relay.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub turn_relay_addr: Option<String>,
    /// Whether this node accepts a relayed (ciphertext-only) fallback connection
    /// via the trusted relay (RFC-0024 / sprint 07). Signed as the 5th line so a
    /// peer can trust the advertisement when direct + hole-punch fail.
    #[serde(default)]
    pub relayable: bool,
    /// The admission tag the relay's rule asks for (see [`admission_tag_input`]):
    /// a MAC under the relay's current admission key over `fingerprint` and
    /// `timestamp`. Absent when the device holds no key for this relay, which a
    /// relay whose rule is [`AdmissionRule::Anyone`] does not ask for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission: Option<String>,
}

/// Response body returned from `POST /push` on success.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RendezvousPushResponse {
    /// How many seconds until this entry expires and must be re-pushed.
    pub expires_in: u32,
}

/// Query parameters for `GET /lookup/:fingerprint`.
///
/// The requester identifies itself so the coord server can enforce a
/// signed-lookup policy (optional, configurable per deployment). Where the
/// server does not enforce signed lookups the `Authorization` header is still
/// produced by the client for forward compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RendezvousLookupQuery {
    /// Fingerprint of the device performing the lookup (for audit logging).
    pub requester: String,
}

/// Response body returned from `GET /lookup/:fingerprint`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RendezvousLookupResponse {
    /// External socket address last pushed by the requested device.
    pub addr: String,
    /// Seconds remaining before this entry expires.
    pub expires_in: u32,
    /// TURN relay address for the device, if one was registered.
    ///
    /// `None` (absent from JSON) when the peer has not pushed a relay address.
    #[serde(default)]
    pub turn_relay_addr: Option<String>,
    /// `true` while the device has a live, unexpired presence entry (RFC-0024 /
    /// sprint 07). A `200` lookup is always `online`; the explicit field makes
    /// presence part of the response contract.
    #[serde(default)]
    pub online: bool,
    /// Whether the device advertised that it accepts a relayed fallback.
    #[serde(default)]
    pub relayable: bool,
}

/// Error body returned from the rendezvous server for all 4xx / 5xx responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RendezvousErrorResponse {
    pub error: String,
}

/// Summary of this device's current relay configuration and recent activity.
///
/// Returned by the `RendezvousStatus` IPC response and surfaced via
/// `kotton node rendezvous status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RendezvousStatusInfo {
    /// Relay server URL configured for this device, if any.
    pub url: Option<String>,
    /// ISO 8601 timestamp of the last successful push, if any.
    pub last_push: Option<String>,
    /// ISO 8601 timestamp of the last successful lookup, if any.
    pub last_lookup: Option<String>,
    /// Whether the relay server was reachable on the most recent attempt.
    pub server_reachable: Option<bool>,
}

// ---------------------------------------------------------------------------
// The relay's one rule, and its operator's two requests
// ---------------------------------------------------------------------------
//
// `TASK-a-relays-admission-rule-is-set-by-its-operator-over-the-wire`. A relay
// holds one rule, and the rule is who may use it. It is checked at the upgrade —
// before a reservation is held, a circuit opened or an address answered — and it
// is checked by *proof*, never by who you are: a device presents a MAC under an
// admission key beside its handle's signature, and the relay learns only that the
// caller is one of the set that holds the key. The handle still rotates and still
// names nobody (RFC-0083 R4); the relay never holds an allowlist of keys.
//
// These types are pinned by `cargo xtask wire-check` (the relay operator channel,
// `core/wire/relay-operator-surface.txt`).

/// Who a relay admits. One of three, and a relay holds exactly one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionRule {
    /// A tag under the key the operator's own devices hold, and nothing else.
    OnlyMyDevices,
    /// That, or a tag under the key the operator hands the people they invite —
    /// their contacts and the tenants of their vault.
    PeopleIInvite,
    /// Every request with a valid handle signature. No tag is read.
    Anyone,
}

/// What the relay's operator may say to it: read the rule, or set it.
///
/// Sent as the JSON body of `POST /operator`, under an `Authorization:
/// KottonOperator key=<hex> ts=<unix> sig=<base64url>` header whose signature is
/// over [`operator_signing_input`] of these exact body bytes. There is no third
/// request: who the operators are is set at the relay's own terminal
/// (`kotton-relay operator enrol|revoke`) and never over the wire, so no key on
/// the wire can enrol a key or keep itself from being revoked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelayOperatorRequest {
    /// The rule and each key's epoch. Never the keys themselves.
    ReadRule,
    /// Set the rule, and rotate either key by naming a new one (32 bytes,
    /// base64url without padding). A rotated key's predecessor is still accepted
    /// for one epoch — until the next rotation — so a device that has not yet
    /// learned the new key is not refused in between.
    SetRule {
        rule: AdmissionRule,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mine: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        invited: Option<String>,
    },
}

/// The relay's answer to a [`RelayOperatorRequest`] it authenticated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelayOperatorResponse {
    /// The rule now held, and how many times each key has been rotated. A count
    /// and not a key, so a read tells nobody anything they could admit with.
    Rule {
        rule: AdmissionRule,
        mine_epoch: u64,
        invited_epoch: u64,
    },
    /// The request was the operator's and could not be done; nothing changed.
    Refused { reason: String },
}

/// The domain an operator's signature is made under, so it can never be read as
/// a handle's signature or anything else a Kotton key signs.
pub const OPERATOR_SIG_DOMAIN: &str = "kotton-relay-operator-v1";

/// The domain of the admission MAC, for the same reason.
pub const ADMISSION_TAG_DOMAIN: &str = "kotton-relay-admission-v1";

/// The bytes an operator signs: the domain, the operator's key (hex), the
/// timestamp, and the request body exactly as sent.
pub fn operator_signing_input(key_hex: &str, ts: i64, body: &[u8]) -> Vec<u8> {
    let mut out = format!("{OPERATOR_SIG_DOMAIN}\n{key_hex}\n{ts}\n").into_bytes();
    out.extend_from_slice(body);
    out
}

/// The bytes a device MACs under an admission key: the domain, the handle's
/// fingerprint and the timestamp its own signature covers. HMAC-SHA256, sent
/// base64url without padding as `admit=` in the `Authorization` header (or
/// [`RendezvousPushPayload::admission`]).
pub fn admission_tag_input(fingerprint: &str, ts: i64) -> Vec<u8> {
    format!("{ADMISSION_TAG_DOMAIN}\n{fingerprint}\n{ts}").into_bytes()
}

// ---------------------------------------------------------------------------
// The relay's own key, and its proof
// ---------------------------------------------------------------------------
//
// `TASK-a-relay-has-a-key-of-its-own-and-proves-it` (RFC-0084 V9). A relay is
// identified by its key and an address is where the key was last found. Whoever
// dials `GET /identity?nonce=<hex>` is answered the key and a signature over the
// nonce they chose and the address the relay announces, so a stand-in at the same
// address cannot answer with the relay's key: it cannot sign.

/// The domain the relay's identity signature is made under. The relay signs a
/// nonce any stranger chooses, so the domain is what keeps that signature from
/// ever being read as anything else — and the key signs nothing but this.
pub const IDENTITY_SIG_DOMAIN: &str = "kotton-relay-identity-v1";

/// The longest nonce the relay signs, in bytes. A dialler's freshness needs 32;
/// the bound is only so a stranger cannot hand the relay a megabyte to hash.
pub const IDENTITY_NONCE_MAX: usize = 64;

/// The bytes a relay signs to prove its key: the domain, the nonce as lowercase
/// hex, and the address it announces (empty when it announces none). The address
/// is last, so no byte of it can be read as the nonce.
pub fn identity_signing_input(nonce: &[u8], addr: &str) -> Vec<u8> {
    let mut out = format!("{IDENTITY_SIG_DOMAIN}\n").into_bytes();
    for b in nonce {
        out.extend_from_slice(format!("{b:02x}").as_bytes());
    }
    out.push(b'\n');
    out.extend_from_slice(addr.as_bytes());
    out
}

/// The body of `GET /identity`: the relay's public key, the address it announces
/// (a hint, never compared to how it was dialled), and the signature over
/// [`identity_signing_input`] of the caller's nonce and that address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayIdentity {
    /// Ed25519 public key, 64 hex.
    pub key: String,
    /// The address the relay announces about itself; empty when it has none.
    pub addr: String,
    /// Ed25519 signature, 128 hex.
    pub sig: String,
}

/// What a node hands a paired asker, beside the relay it reserves at
/// (`UserRequest::NodeRelay`), so the asker is admitted there under the relay's
/// rule (`TASK-a-device-presents-its-relays-admission-tag-and-the-reach-row-sets-the-rule`).
///
/// **`present`** is the key the asker MACs its handle under at that relay
/// ([`admission_tag_input`]). **`offer`** is the *invited* key, and it is set
/// only by one of the relay operator's own devices answering another of them:
/// it is what the operator's reach note carries to their contacts. An invitee
/// is never handed an `offer`, so a contact of a contact is never invited.
///
/// Both are secrets and print as `<redacted>`. Neither names anyone: every
/// holder of one key presents the same key, so a tag says *one of the set* and
/// never *which one*.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayAdmission {
    pub present: crate::ipc::SecretText,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offer: Option<crate::ipc::SecretText>,
}

/// One relay of a vault's reach set, as its operator's desktop tells it
/// (`UserRequest::StandAt`, RFC-0084 V10): the relay **by its key**, the address
/// the key was last found at as a hint, and the admission keys that relay's rule
/// reads — *mine*, which the vault presents there as one of its operator's
/// machines, and *invited*, which it hands each tenant. A relay whose rule nobody
/// narrowed reads no key, and carries none.
///
/// Nothing here names a person or a vault; the relay is told none of it (V11).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stand {
    /// The relay's Ed25519 public key, 64 hex — what the relay *is* (V9).
    pub key: String,
    /// Where the key was last found: dialled, and the key proved there. It
    /// is never what decides which relay this is — the key does. The vault
    /// compares it with the address it reserves at now only to tell whether a
    /// telling moves its reservations (`kvaultd::reach::stand_at`).
    pub hint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mine: Option<crate::ipc::SecretText>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invited: Option<crate::ipc::SecretText>,
}

#[cfg(test)]
mod relay_rule_tests {
    use super::*;

    /// The three rules and the two requests, byte for byte. A rename here is a
    /// relay that no longer understands its operator's desktop.
    #[test]
    fn the_rule_and_its_requests_have_a_fixed_shape_on_the_wire() {
        assert_eq!(
            serde_json::to_string(&AdmissionRule::OnlyMyDevices).unwrap(),
            "\"only_my_devices\""
        );
        assert_eq!(
            serde_json::to_string(&AdmissionRule::PeopleIInvite).unwrap(),
            "\"people_i_invite\""
        );
        assert_eq!(serde_json::to_string(&AdmissionRule::Anyone).unwrap(), "\"anyone\"");
        assert_eq!(
            serde_json::to_string(&RelayOperatorRequest::ReadRule).unwrap(),
            "\"ReadRule\""
        );
        assert_eq!(
            serde_json::to_string(&RelayOperatorRequest::SetRule {
                rule: AdmissionRule::Anyone,
                mine: None,
                invited: None,
            })
            .unwrap(),
            r#"{"SetRule":{"rule":"anyone"}}"#
        );
        assert_eq!(
            operator_signing_input("ab", 7, b"{}"),
            b"kotton-relay-operator-v1\nab\n7\n{}".to_vec()
        );
        assert_eq!(
            admission_tag_input("did:key:zH", 7),
            b"kotton-relay-admission-v1\ndid:key:zH\n7".to_vec()
        );
    }

    /// The relay's proof, byte for byte: a relay and a dialler of different
    /// releases meet here, and a changed byte is every relay refused.
    #[test]
    fn the_relays_identity_has_a_fixed_shape_on_the_wire() {
        assert_eq!(
            identity_signing_input(&[0x0a, 0xff], "relay.example:7700"),
            b"kotton-relay-identity-v1\n0aff\nrelay.example:7700".to_vec()
        );
        assert_eq!(
            identity_signing_input(&[1], ""),
            b"kotton-relay-identity-v1\n01\n".to_vec()
        );
        assert_eq!(
            serde_json::to_string(&RelayIdentity {
                key: "k".into(),
                addr: String::new(),
                sig: "s".into(),
            })
            .unwrap(),
            r#"{"key":"k","addr":"","sig":"s"}"#
        );
    }
}
