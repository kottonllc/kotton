// SPDX-License-Identifier: AGPL-3.0-or-later
//! Peer network schema types.
//!
//! These types are persisted to the daemon's SQLite database and sent over IPC.
//! They have no runtime logic — they are pure data carriers.

use crate::did::Did;
use crate::grant::GrantEnvelope;
use crate::kel::KelEvent;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;

// ---------------------------------------------------------------------------
// PairedNode
// ---------------------------------------------------------------------------

/// A device that has been paired with this device via the pairing ceremony.
///
/// `id` is a stable human-chosen label (e.g. "my-vps", "phone"). It is used
/// as a foreign key in `MountConfig`, and names a drive's node to a person.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-types", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-types", ts(export))]
pub struct PairedNode {
    /// Stable human label chosen at pairing time.
    pub id: String,
    /// `did:key` of the paired device.
    pub device_did: Did,
    /// Raw 32-byte Ed25519 public key — redundant with `device_did` but avoids
    /// a DID parse on every mTLS allowlist lookup.
    #[cfg_attr(feature = "ts-types", ts(skip))]
    pub public_key: [u8; 32],
    /// Unix timestamp (seconds) when the pairing was completed.
    #[cfg_attr(feature = "ts-types", ts(type = "number"))]
    pub paired_at: i64,
    /// Last known addresses for the peer; updated on each successful connect.
    #[cfg_attr(feature = "ts-types", ts(type = "string[]"))]
    pub addresses: Vec<SocketAddr>,
    /// The relay this peer holds reservations at — where a dial that cannot go
    /// direct finds it (RFC-0083 R5). Learned from the peer itself on every
    /// successful connect (`NodeRelay`), or from the ceremony's handout for a
    /// gateway. `None` for a peer never asked: the dialer then tries its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_url: Option<String>,
    /// The posture this device recorded for the peer (RFC-0036) — the paired
    /// row's column, **as the row spells it** (`Posture::as_str`), read with
    /// the row. `None` for a row written before postures were recorded, or by a
    /// path that knew none: the issuer's row on a device it enrolled is one,
    /// and is the person's own *full* device.
    ///
    /// Text and not a parsed `Posture`, so a posture this build does not
    /// recognise — a newer variant read after a downgrade, a corrupted row —
    /// stays distinct from *none recorded* rather than collapsing into it.
    ///
    /// Read where what the peer *says* is weighed by what it *is*: a relay key
    /// offered on as one of the person's own devices is learned only from a
    /// *full* one (`kotton_peer::relay_keys::offers_from`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-types", ts(skip))]
    pub posture: Option<String>,
}

// ---------------------------------------------------------------------------
// SyncRule
// ---------------------------------------------------------------------------

/// This device's rule for one of its person's drives: which way it syncs it,
/// and whether the background pass does.
///
/// A rule names a drive — a tenancy on a vault — and never a device: devices
/// replicate to drives and read from them, and no device is another's target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRule {
    /// The node the drive is reached through, as this device names it now;
    /// empty when the drive the rule was kept for is no longer recorded here.
    pub drive: String,
    /// The vault's key, hex: what the rule is kept under, with the tenancy.
    pub vault_key: String,
    /// The tenancy on that vault.
    pub tenancy: String,
    /// This device's direction for the drive; `None` is both ways.
    pub direction: Option<crate::ipc::SyncDirection>,
    /// If `true`, the background pass syncs this drive as well.
    pub watch: bool,
    /// Unix timestamp when this rule was created or last modified.
    pub configured_at: i64,
}

// ---------------------------------------------------------------------------
// MountConfig
// ---------------------------------------------------------------------------

/// Configuration for a virtual path mount backed by a paired node's storage.
///
/// A mount adds a `local_path → (node, remote_path)` entry to `UserStorageRouter`.
/// It is NOT an OS-level mount; it is internal to the Kotton VFS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountConfig {
    /// References `PairedNode::id`.
    pub node_id: String,
    /// The path on the remote node to expose.
    pub remote_path: String,
    /// The local path at which the remote tree appears.
    pub local_path: String,
    /// Maximum bytes the local cache may use for this mount. `None` = unlimited.
    pub cache_budget_bytes: Option<u64>,
    /// Subpaths that are always kept local (pre-fetched, never evicted).
    pub pins: Vec<String>,
    /// Unix timestamp when this mount was created.
    pub mounted_at: i64,
}

// ---------------------------------------------------------------------------
// EphemeralSession
// ---------------------------------------------------------------------------

/// An ephemeral session ticket issued to a guest device.
///
/// A guest device presents this token to gain time-limited, scoped access
/// to a subset of the user's storage without going through the full pairing
/// ceremony. The ticket expires at `grant.expires_at` and can be revoked early.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-types", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-types", ts(export))]
pub struct EphemeralSession {
    /// UUID v4.
    pub id: String,
    /// `did:key` of the guest device.
    pub guest_did: Did,
    /// Raw 32-byte Ed25519 public key of the guest device.
    #[cfg_attr(feature = "ts-types", ts(skip))]
    pub guest_public_key: [u8; 32],
    /// The capability grant governing this session's access.
    /// Contains scoped `CapabilityGrant`s, expiry, and issuer signature.
    pub grant: GrantEnvelope,
    /// Unix timestamp when the session was issued.
    #[cfg_attr(feature = "ts-types", ts(type = "number"))]
    pub issued_at: i64,
    /// Set to `true` when the session has been explicitly revoked before expiry.
    pub revoked: bool,
    /// Per-path DEKs re-wrapped to the guest's session key (AES-256-KW).
    ///
    /// Populated when `PairNodeEphemeral.guest_ephemeral_pubkey` is provided.
    /// Empty when the caller did not supply a guest ephemeral key.
    ///
    /// Key: VFS path. Value: 40-byte AES-256-KW-wrapped DEK.
    #[serde(default)]
    pub wrapped_deks: HashMap<String, Vec<u8>>,
}

/// Operations a guest session may perform.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "ts-types", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-types", ts(export))]
pub enum SessionPermissions {
    /// Read-only access.
    Read,
    /// Read and write access.
    ReadWrite,
}

// ---------------------------------------------------------------------------
// RFC-0040 committed-handshake wire messages
// ---------------------------------------------------------------------------

/// The five messages of the RFC-0040 committed ephemeral-ECDH pairing handshake,
/// in wire order. Pure data carriers — the key schedule and all crypto live in
/// `kotton_crypto::pair_handshake` (tier 03); the ceremony state machine
/// that reads/writes these lives in `core/05_runtime/src/user/pairing.rs` (tier 05).
///
/// ```text
/// Joiner J                                  Issuer I
/// 1. → PairHello  { v, sid }
///                                           2. ← PairCommit { commit }
/// 3. → PairReveal { eph_pub_J, nonce_J }
///                                           4. ← PairReveal { eph_pub_I, nonce_I }
/// 5. verify commit; both derive the session + SAS; humans compare
///                                           (I → J: PairInfo, first k_enc frame)
/// 7/8. ⇄ PairConfirm { mac }  (each side only after its local human confirms)
///                                           9. ← RFC-0033 payload, AEAD under k_enc
/// ```
///
/// **The commit round and the field set are security-load-bearing (RFC-0040 §4).**
/// Removing a message or a field re-opens the SAS grinding attack — that is a
/// design regression, not a simplification.
///
/// The six structs — `PairHello`, `PairCommit`, `PairReveal`, `PairInfo`,
/// `PairConfirm`, `PairAttestation` — are defined in `kotton_pair::wire` and
/// re-exported here unchanged, so the browser joiner (RFC-0078) speaks the same
/// bytes as the QUIC ceremony from a crate that builds for `wasm32`.
pub use kotton_pair::wire::{
    PairAttestation, PairCommit, PairConfirm, PairHello, PairInfo, PairReveal,
};

// ---------------------------------------------------------------------------
// PairingPayload
// ---------------------------------------------------------------------------

/// What a gateway is handed by the ceremony: whom it serves and where the node
/// is reachable. The node's own key it learns from the handshake it just ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayHandout {
    /// The user the gateway serves.
    pub user_id: String,
    /// The relay the node holds reservations at, which the gateway dials.
    pub relay_url: String,
    /// The node's name, for a person telling two gateways apart.
    pub node_label: String,
}

/// Payload sealed inside the RFC-0004 ECDH envelope during the pairing ceremony.
///
/// The initiator seals one of these variants into the ChaCha20-Poly1305 envelope
/// (see `core/05_runtime/src/user/pairing.rs`).  The acceptor unseals it and
/// branches:
///
/// - [`PairingPayload::FullAccess`]: derive CEK from `seed32`, zero `seed32`.
/// - [`PairingPayload::FrostShare`]: store the share + any [`DataKeys`].
/// - [`PairingPayload::BlindRelay`]: boot with `session_cek = None`.
// `Debug` is hand-written below to redact key material — a derived `Debug` would
// leak the root `seed32`, a FROST `share`, or a `DataKeys` root into any
// `{payload:?}` log or error string (e.g. the node-join catch-all in pairing.rs).
// Security audit.
#[derive(Clone, Serialize, Deserialize)]
// `FrostShare` is much larger than the other variants (a delegation + share + keys),
// but a `PairingPayload` is transient — one per pairing ceremony — so boxing's heap
// indirection and match-site churn aren't worth it here.
#[allow(clippy::large_enum_variant)]
pub enum PairingPayload {
    /// **First device only** (1-of-1 degenerate FROST group): receives the 32-byte
    /// root `seed32` and can derive the CEK.
    ///
    /// `seed32` is the BIP-39 PBKDF2 output — the minimum root material from
    /// which both the CEK and the Ed25519 identity key are derived.  It must
    /// be zeroed from memory immediately after CEK derivation.
    FullAccess { seed32: [u8; 32] },
    /// **Second-or-later device** (RFC-0031 / custody): receives a FROST key
    /// **share**, not `seed32`. The device holds one share of the threshold; no
    /// single device (after the first) holds the root scalar. A quorum-signed
    /// [`WarmKeyDelegation`] lets it perform routine ops, and — for a `data`
    /// posture — the operational [`DataKeys`] ride in this payload (confidential
    /// via the outer ECDH pairing seal; both are derived from `seed32`, which is
    /// itself never sent).
    FrostShare {
        /// The new device's opaque FROST key share.
        share: FrostSharePayload,
        /// Warm device key delegation, signed by the existing FROST quorum.
        warm_key_delegation: WarmKeyDelegation,
        /// Quorum certificate binding the share + warm key to this device
        /// (base64url Ed25519 signature by the root group over the RFC-0033
        /// canonical message `"kotton:enroll-cert:v1\n{share_hex}\n{warm_pubkey_hex}"`).
        quorum_certificate: String,
        /// The **data capability** (RFC-0036's `data` axis): both operational key
        /// domains, or neither. `Some` for a `Full` device; **`None` for a
        /// `Cosigner`** — a cosigner holds the share (can co-sign) but no data
        /// keys, so it cannot decrypt (RFC-0036). Confidential via the outer ECDH
        /// pairing seal, so it is not separately sealed; the mnemonic-wrapped
        /// recovery copy lives in the VFS, never on the wire.
        data_keys: Option<DataKeys>,
        /// The group **`PublicKeyPackage`** (hex-serialised `frost-ed25519`), the
        /// public half of the threshold. A signing coordinator needs it to
        /// aggregate signature shares (`frost::aggregate`). Public material, but
        /// delivered here so a Full device can co-sign without a separate fetch
        /// (RFC-0036 — distributed signing prerequisite).
        pubkey_package: String,
        /// The issuer's **key event log** (RFC-0038): the identity's autonomic
        /// history. The joiner stores it and adopts the `did:kel` AID as its user
        /// identity — a joined device cannot reconstruct the AID itself (it never
        /// holds the mnemonic), so the KEL is delivered here. The joiner binds it to
        /// the enrollment by checking `resolve_current_key(kel)` equals the root
        /// group key it received. Empty only from a pre-KEL issuer (none exist).
        kel: Vec<KelEvent>,
    },
    /// A gateway (RFC-0078): receives no key material and no chain — only what it
    /// needs to reach the node it will relay for. Everything else a gateway is,
    /// it is by the posture the node records for it.
    Gateway(GatewayHandout),
    /// Blind relay: receives no key material; stores and forwards ciphertext only.
    ///
    /// A `kuserd` that receives this variant boots with no CEK.  Any request
    /// requiring decryption returns `UserResponse::Error { message }` where
    /// message starts with `"NoCek:"`.  Sync blob storage and listing work
    /// normally because they operate on raw ciphertext bytes.
    BlindRelay {
        /// The issuer's **key event log** (RFC-0038), delivered to a blind storage node
        /// for one reason: so it can later admit a device that proves control of
        /// the user's root (RFC-0081). Without a chain to verify against, a node
        /// whose only device has been lost can never admit its replacement — the
        /// identity-continuity invariant failing at exactly the case it covers.
        ///
        /// This is **not** key material and does not soften the blind posture. A
        /// KEL is public by KERI construction (a key event log exists to be
        /// witnessed); it carries key *state*, never a CEK, a FROST share, or a
        /// data root. A `BlindRelay` still decrypts nothing.
        ///
        /// Nor is it a new join key: `paired_nodes` already stores `user_id` and
        /// `device_did` in plaintext on every node, and blind enrolment already
        /// carried `root_did` — a durable identifier for the same user. The node
        /// is blind to the user's *data*, not to which user it hosts.
        ///
        /// Empty only from a pre-RFC-0081 issuer, which is why the joiner treats
        /// an empty chain as "no proof available" rather than as an error.
        #[serde(default)]
        kel: Vec<KelEvent>,
        /// The issuer's recovery copy — its data roots sealed under the recovery
        /// phrase (`RFC-0066`), as the JSON the issuer wrote. Delivered so that a
        /// device holding only the phrase can get them back from this node
        /// (`RFC-0081`, the cold fetch).
        ///
        /// Not key material *to this node*: it opens under the phrase and under
        /// nothing else, and the phrase is never here. Article X is satisfied the
        /// way the phrase itself satisfies it — ciphertext no grant can open is
        /// what a vault keeps. `None` when the issuer had not set up a phrase yet.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        recovery_bundle: Option<String>,
    },
}

/// The two operational key-domain roots a `data`-posture node receives at
/// enrollment (RFC-0036 "Payload: share and data keys travel independently").
///
/// They are one struct rather than three optional fields because RFC-0036's
/// `data` capability is a **single bit**: a node either holds the operational
/// data domain or it does not. Delivering the CEK without `master_secret`
/// produces a device that reads objects but derives a *different*
/// `K_log = HKDF(master_secret)` and so cannot open the fleet's history log —
/// a half-provisioned state that is not a posture anyone chose. Making the pair
/// unsplittable in the type keeps that state unrepresentable on the wire.
///
/// Both roots are one-way derivations of the mnemonic. `seed32` itself is
/// **never** delivered to any node (RFC-0036 I1) — it stays the cold recovery
/// root, so no node can reconstruct it from what it holds here.
// `Debug` is hand-written to redact both roots; a derived one would print them.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct DataKeys {
    /// Operational Content Encryption Key (RFC-0033 Hybrid CEK) — the **object**
    /// key domain. Roots per-file keys, the path-blinding key (RFC-0044) and the
    /// pack key (RFC-0045).
    pub cek: [u8; 32],
    /// CEK rotation epoch this copy is for (RFC-0033).
    pub cek_epoch: u32,
    /// The **db** key domain root. Roots the history-log segment key
    /// (`K_log`, RFC-0046/0047) and the per-user record-database key, which is
    /// why a device without it cannot participate in record sync or encrypt its
    /// own records at rest.
    ///
    /// Deliberately *not* derived from the CEK: the two domains are kept apart
    /// so a compromise of one does not yield the other (RFC-0036, RFC-0041 B4).
    /// Re-rooting the db domain under the CEK was considered and rejected in
    /// RFC-0036 ("Rationale and alternatives").
    pub master_secret: [u8; 32],
}

/// A `Debug` placeholder for secret material — prints `<redacted>` with no quotes
/// so key bytes never reach a log or error string.
struct Redacted;
impl std::fmt::Debug for Redacted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl std::fmt::Debug for DataKeys {
    /// Redacts both domain roots. The epoch is not secret and is the field worth
    /// seeing in a log, so it prints.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataKeys")
            .field("cek", &Redacted)
            .field("cek_epoch", &self.cek_epoch)
            .field("master_secret", &Redacted)
            .finish()
    }
}

impl std::fmt::Debug for PairingPayload {
    /// Redacts key material (`seed32`, the FROST `share`, `cek`) — a derived
    /// `Debug` would leak the root of the key hierarchy into any `{:?}` log or
    /// error. Public fields (delegation, quorum cert, pubkey package, KEL) are
    /// summarised, not dumped; `finish_non_exhaustive` marks them elided.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FullAccess { .. } => f
                .debug_struct("FullAccess")
                .field("seed32", &Redacted)
                .finish(),
            Self::FrostShare {
                data_keys, kel, ..
            } => f
                .debug_struct("FrostShare")
                .field("share", &Redacted)
                .field("data_keys", data_keys)
                .field("kel_events", &kel.len())
                .finish_non_exhaustive(),
            Self::Gateway(handout) => f.debug_tuple("Gateway").field(handout).finish(),
            Self::BlindRelay {
                kel,
                recovery_bundle,
            } => write!(
                f,
                "BlindRelay {{ kel: {} events, recovery_bundle: {} }}",
                kel.len(),
                if recovery_bundle.is_some() { "sealed" } else { "none" }
            ),
        }
    }
}

/// An opaque FROST key share for one device — the serialised `KeyPackage` produced
/// by the DKG ceremony (`kotton_crypto::frost::dkg_part3`). The device
/// stores it in its keychain and uses it to participate in threshold signing; it is
/// one share of the root key, never the whole key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrostSharePayload(pub String);

/// A warm device key delegation (RFC-0031 / custody sprint 02): the FROST quorum's
/// statement that `warm_pubkey` is a short-lived routine-operations key delegated
/// from the root identity `root_did` until `expires_at`. Routine acts (signing
/// grants, unlocking sessions) use the warm key; constitutional acts still require
/// the FROST quorum.
///
/// `quorum_signature` is the root FROST group's base64url Ed25519 signature over
/// [`signing_message`](Self::signing_message). This crate carries the data only;
/// verification (against the root group key) lives in a higher tier that has crypto.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarmKeyDelegation {
    /// The warm device key's DID (`did:key:…`).
    pub warm_did: Did,
    /// The warm key's raw Ed25519 public key (redundant with `warm_did`, denormalised).
    pub warm_pubkey: [u8; 32],
    /// Unix seconds after which the warm key is invalid.
    pub expires_at: i64,
    /// The root identity DID this warm key is delegated from.
    pub root_did: Did,
    /// Base64url Ed25519 signature by the root FROST group over `signing_message()`.
    pub quorum_signature: String,
}

impl WarmKeyDelegation {
    /// The canonical message the quorum signs:
    /// `"{warm_did}\n{expires_at}\n{root_did}"`.
    ///
    /// `warm_did` is `did:key(warm_pubkey)`, so it binds the warm key without this
    /// tier needing a hex/base64 dependency to encode the raw bytes.
    pub fn signing_message(&self) -> String {
        format!("{}\n{}\n{}", self.warm_did, self.expires_at, self.root_did)
    }
}

// ---------------------------------------------------------------------------
// GuestAccessToken
// ---------------------------------------------------------------------------

/// Access level for an ephemeral guest session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "ts-types", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-types", ts(export))]
pub enum GuestAccess {
    /// Read-only access to the granted paths.
    Read,
    /// Read and write access to the granted paths.
    ReadWrite,
}

/// A signed, scoped, expiring capability token for ephemeral guest access.
///
/// Issued by `kuserd` via `PairNodeEphemeral`.  The guest device does not
/// receive the user's `seed32`, CEK, or identity key — only the DEKs for
/// the specific granted paths, wrapped to a session key derived from ECDH
/// with the guest's ephemeral public key.
///
/// # Session key derivation
///
/// ```text
/// shared = ECDH(issuer_identity_privkey, guest_ephemeral_pubkey)
/// session_key = HKDF-SHA256(shared, info="kotton:guest-session:v1")
/// wrapped_deks[path] = AES-256-KW(session_key, dek_for_path)
/// ```
///
/// The `issuer_signature` covers all fields except itself (via a canonical
/// JSON serialization), signed with the issuer's Ed25519 identity key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-types", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-types", ts(export))]
pub struct GuestAccessToken {
    /// VFS paths this token grants access to.  No wildcard parent traversal.
    pub paths: Vec<String>,
    /// Access level granted to the guest.
    pub access: GuestAccess,
    /// Unix timestamp (seconds) after which this token is rejected.
    pub expires_at: i64,
    /// Per-path DEKs wrapped (AES-256-KW) with the derived guest session key.
    ///
    /// Key: VFS path.  Value: AES-256-KW-wrapped DEK bytes.
    pub wrapped_deks: HashMap<String, Vec<u8>>,
    /// Guest device ephemeral X25519 public key (32 bytes).
    ///
    /// Used by the issuer to derive the session key that wraps the DEKs.
    /// The guest uses their corresponding ephemeral private key + the
    /// issuer's `did:key` public key to derive the same session key.
    #[cfg_attr(feature = "ts-types", ts(skip))]
    pub guest_ephemeral_pubkey: [u8; 32],
    /// Ed25519 signature (64 bytes) over the canonical JSON of all fields
    /// above, signed by the issuing user's identity key.
    ///
    /// Verification: reconstruct the signable bytes (all fields except this
    /// one, sorted by key), then `Ed25519::verify(issuer_pubkey, bytes, sig)`.
    #[cfg_attr(feature = "ts-types", ts(skip))]
    pub issuer_signature: Vec<u8>,
    /// `did:key` of the issuing user.
    pub issuer_did: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TypeScript binding export — run with:
//   $env:TS_RS_EXPORT_DIR = "..\..\packages\types\src"
//   cargo test -p kotton-wire --features ts-types -- ts_export::export_ts_bindings --nocapture
#[cfg(all(test, feature = "ts-types"))]
mod ts_export {
    use super::{EphemeralSession, PairedNode, SessionPermissions};
    use ts_rs::TS as _;

    #[test]
    fn export_ts_bindings() {
        PairedNode::export_all().expect("export PairedNode");
        SessionPermissions::export_all().expect("export SessionPermissions");
        EphemeralSession::export_all().expect("export EphemeralSession");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_did() -> Did {
        Did::new("key", "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
    }

    #[test]
    fn warm_key_delegation_round_trips_and_signs_canonically() {
        let d = WarmKeyDelegation {
            warm_did: make_did(),
            warm_pubkey: [9u8; 32],
            expires_at: 1_800_000_000,
            root_did: Did::new("key", "z6MkRootExample"),
            quorum_signature: "c2lnbmF0dXJl".to_string(),
        };
        let back: WarmKeyDelegation =
            serde_json::from_str(&serde_json::to_string(&d).unwrap()).unwrap();
        assert_eq!(d, back);
        assert_eq!(
            d.signing_message(),
            format!("{}\n1800000000\n{}", d.warm_did, d.root_did)
        );
    }

    #[test]
    fn frost_share_pairing_payload_round_trips() {
        let payload = PairingPayload::FrostShare {
            share: FrostSharePayload("deadbeef".to_string()),
            warm_key_delegation: WarmKeyDelegation {
                warm_did: make_did(),
                warm_pubkey: [9u8; 32],
                expires_at: 1_800_000_000,
                root_did: make_did(),
                quorum_signature: "c2ln".to_string(),
            },
            quorum_certificate: "cert".to_string(),
            data_keys: Some(DataKeys {
                cek: [7u8; 32],
                cek_epoch: 0,
                master_secret: [8u8; 32],
            }),
            pubkey_package: "pubkeypkg".to_string(),
            kel: vec![],
        };
        let back: PairingPayload =
            serde_json::from_str(&serde_json::to_string(&payload).unwrap()).unwrap();
        match back {
            PairingPayload::FrostShare {
                share,
                data_keys,
                pubkey_package,
                ..
            } => {
                assert_eq!(share, FrostSharePayload("deadbeef".to_string()));
                let keys = data_keys.expect("data capability round-trips");
                assert_eq!(keys.cek, [7u8; 32], "the operational CEK round-trips");
                assert_eq!(keys.cek_epoch, 0);
                assert_eq!(
                    keys.master_secret, [8u8; 32],
                    "the db-domain root round-trips — a joined device needs it for K_log"
                );
                assert_eq!(pubkey_package, "pubkeypkg", "group key round-trips");
            }
            other => panic!("expected FrostShare, got {other:?}"),
        }
    }

    #[test]
    fn debug_redacts_key_material() {
        // The root seed must never appear in Debug output — a `{payload:?}` in an
        // error/log (e.g. the node-join catch-all) would otherwise leak it.
        let full = PairingPayload::FullAccess { seed32: [0xAB; 32] };
        let d = format!("{full:?}");
        assert!(d.contains("<redacted>"), "seed must be redacted: {d}");
        assert!(!d.contains("171"), "raw seed bytes leaked: {d}");

        // A FROST share and both data-domain roots are secret; public metadata
        // may still show.
        let frost = PairingPayload::FrostShare {
            share: FrostSharePayload("deadbeefsecret".to_string()),
            warm_key_delegation: WarmKeyDelegation {
                warm_did: make_did(),
                warm_pubkey: [9u8; 32],
                expires_at: 1_800_000_000,
                root_did: make_did(),
                quorum_signature: "c2ln".to_string(),
            },
            quorum_certificate: "cert".to_string(),
            data_keys: Some(DataKeys {
                cek: [7u8; 32],
                cek_epoch: 3,
                master_secret: [5u8; 32],
            }),
            pubkey_package: "pubkeypkg".to_string(),
            kel: vec![],
        };
        let d = format!("{frost:?}");
        assert!(!d.contains("deadbeefsecret"), "FROST share leaked: {d}");
        assert!(!d.contains("7, 7"), "CEK bytes leaked: {d}");
        assert!(
            !d.contains("5, 5"),
            "master_secret bytes leaked — it is the db-domain root: {d}"
        );
        assert!(d.contains("<redacted>"), "secrets must be redacted: {d}");
        assert!(
            d.contains("cek_epoch: 3"),
            "public metadata should show: {d}"
        );
    }

    fn sample_node() -> PairedNode {
        PairedNode {
            id: "my-server".to_string(),
            device_did: make_did(),
            public_key: [1u8; 32],
            paired_at: 1_700_000_000,
            addresses: vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                9000,
            )],
            relay_url: None,
            posture: None,
        }
    }

    #[test]
    fn paired_node_round_trip() {
        let node = sample_node();
        let json = serde_json::to_string(&node).expect("serialize");
        let back: PairedNode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.id, node.id);
        assert_eq!(back.public_key, node.public_key);
        assert_eq!(back.paired_at, node.paired_at);
        assert_eq!(back.addresses, node.addresses);
    }

    #[test]
    fn sync_rule_round_trip() {
        let rule = SyncRule {
            drive: "vault".to_string(),
            vault_key: "ab".repeat(32),
            tenancy: "alice".to_string(),
            direction: Some(crate::ipc::SyncDirection::Push),
            watch: true,
            configured_at: 1_700_000_001,
        };
        let json = serde_json::to_string(&rule).expect("serialize");
        let back: SyncRule = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.drive, rule.drive);
        assert_eq!(back.vault_key, rule.vault_key);
        assert_eq!(back.tenancy, rule.tenancy);
        assert!(matches!(back.direction, Some(crate::ipc::SyncDirection::Push)));
        assert_eq!(back.watch, rule.watch);
        assert_eq!(back.configured_at, rule.configured_at);
    }

    #[test]
    fn mount_config_round_trip() {
        let cfg = MountConfig {
            node_id: "my-server".to_string(),
            remote_path: "/docs".to_string(),
            local_path: "/mnt/docs".to_string(),
            cache_budget_bytes: Some(1024 * 1024 * 512),
            pins: vec!["/readme.md".to_string()],
            mounted_at: 1_700_000_002,
        };
        let json = serde_json::to_string(&cfg).expect("serialize");
        let back: MountConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.node_id, cfg.node_id);
        assert_eq!(back.cache_budget_bytes, cfg.cache_budget_bytes);
        assert_eq!(back.pins, cfg.pins);
    }

    #[test]
    fn ephemeral_session_round_trip() {
        use kotton_schemas::{CapabilityGrant, CapabilityKind};
        let grant = GrantEnvelope {
            id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            issuer_did: make_did(),
            subject_did: make_did(),
            node_did: None,
            grants: vec![CapabilityGrant::vfs(CapabilityKind::Read, "/shared")],
            issued_at: 1_700_000_000,
            expires_at: Some(1_700_003_600),
            // A paired-node session grant, not an app grant.
            app_id: None,
            issuer_signature: String::new(),
        };
        let session = EphemeralSession {
            id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            guest_did: make_did(),
            guest_public_key: [2u8; 32],
            grant,
            issued_at: 1_700_000_000,
            revoked: false,
            wrapped_deks: HashMap::new(),
        };
        let json = serde_json::to_string(&session).expect("serialize");
        let back: EphemeralSession = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.id, session.id);
        assert_eq!(back.grant.expires_at, session.grant.expires_at);
        assert!(!back.revoked);
    }

    #[test]
    fn pairing_wire_messages_round_trip() {
        // Each RFC-0040 handshake frame must survive serde intact — the ceremony
        // reads them straight off the wire.
        let hello = PairHello { v: 1, sid: [9u8; 16] };
        let back: PairHello = serde_json::from_str(&serde_json::to_string(&hello).unwrap()).unwrap();
        assert_eq!(back, hello);

        let commit = PairCommit { commit: [3u8; 32] };
        let back: PairCommit =
            serde_json::from_str(&serde_json::to_string(&commit).unwrap()).unwrap();
        assert_eq!(back, commit);

        let reveal = PairReveal { eph_pub: [1u8; 32], nonce: [2u8; 32] };
        let back: PairReveal =
            serde_json::from_str(&serde_json::to_string(&reveal).unwrap()).unwrap();
        assert_eq!(back, reveal);

        let info = PairInfo { label: "austin's PC".to_string() };
        let back: PairInfo = serde_json::from_str(&serde_json::to_string(&info).unwrap()).unwrap();
        assert_eq!(back, info);

        let confirm = PairConfirm { mac: [7u8; 32] };
        let back: PairConfirm =
            serde_json::from_str(&serde_json::to_string(&confirm).unwrap()).unwrap();
        assert_eq!(back, confirm);
    }

    #[test]
    fn session_permissions_variants() {
        let read = serde_json::to_string(&SessionPermissions::Read).unwrap();
        let rw = serde_json::to_string(&SessionPermissions::ReadWrite).unwrap();
        assert_ne!(read, rw);
        let p: SessionPermissions = serde_json::from_str(&read).unwrap();
        assert_eq!(p, SessionPermissions::Read);
    }
}
