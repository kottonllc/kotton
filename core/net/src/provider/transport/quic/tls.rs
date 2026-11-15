// SPDX-License-Identifier: AGPL-3.0-or-later
//! TLS primitives for Kotton peer-to-peer QUIC connections.
//!
//! # Design
//!
//! Kotton uses mutual TLS (mTLS) between paired devices. Each device has a stable
//! Ed25519 identity key (stored in the device keychain). When establishing a peer
//! connection we:
//!
//! 1. **Generate a self-signed certificate** derived from the Ed25519 identity key
//!    (`Ed25519DeviceCert`). The certificate's Subject Public Key is the identity key,
//!    so the peer can authenticate us by public key, not by a CA chain.
//!
//! 2. **Verify peers against an allowlist** (`PairedDeviceVerifier`). After pairing,
//!    the remote device's Ed25519 public key is stored in a live, shared `HashSet`.
//!    Revocation is instant: remove the key from the set and the next connection attempt
//!    fails at the TLS handshake — no daemon restart required. That holds because no peer
//!    config resumes a TLS session: a resumed handshake presents no certificate, so every
//!    connection is a full one and meets the allowlist as it stands.
//!
//! Both sides present and verify certificates (mTLS), so trust is symmetric.
//!
//! 3. **Hold the peer's key and the handshake's signature to the Ed25519 rule.** The key a
//!    peer's certificate carries is constructed as a [`VerifyingKey`] where it is read
//!    ([`extract_ed25519_pubkey_from_cert`]), so a key the rule refuses admits nothing; and
//!    the handshake's `CertificateVerify` signature is checked under that key by the rule
//!    ([`verify_handshake_signature`]), Ed25519 alone, for every verifier here. The TLS
//!    library's own signature check is not called.

use kotton_crypto::ed25519::{Signature, VerifyingKey};
use kotton_sys::net::TransportError;
use quinn::{ClientConfig, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::collections::HashSet;
use std::sync::{Arc, RwLock};

// ---------------------------------------------------------------------------
// Ed25519DeviceCert
// ---------------------------------------------------------------------------

/// Wrap bytes as a DER `OCTET STRING` — tag `0x04`, a definite length, then the payload.
///
/// Hand-rolled rather than pulling an ASN.1 crate into a transport-security module for one
/// two-branch encoding. The only subtlety is the length: DER requires the *shortest* form, so
/// under 128 bytes is a single byte and anything larger is `0x80 | n` followed by `n`
/// big-endian bytes. An admission payload is about a kilobyte, so the long form is the live
/// path and the short one is what a test would otherwise never reach.
fn der_octet_string(payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x04];
    let n = payload.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let be = n.to_be_bytes();
        let first = be.iter().position(|b| *b != 0).unwrap_or(be.len() - 1);
        let sig = &be[first..];
        out.push(0x80 | sig.len() as u8);
        out.extend_from_slice(sig);
    }
    out.extend_from_slice(payload);
    out
}

/// Read back what [`der_octet_string`] wrote, rejecting anything else.
///
/// Deliberately strict and total: this parses bytes chosen by whoever is dialling, so every
/// malformed shape has to be a clean `None` rather than a panic or an over-read. A length
/// claiming more than the buffer holds is the obvious hostile case and the one a slice index
/// would panic on.
fn parse_der_octet_string(der: &[u8]) -> Option<&[u8]> {
    if der.first()? != &0x04 {
        return None;
    }
    let len_byte = *der.get(1)?;
    let (len, body_at) = if len_byte < 0x80 {
        (len_byte as usize, 2)
    } else {
        let n = (len_byte & 0x7f) as usize;
        if n == 0 || n > 8 {
            return None; // indefinite length, or a length wider than any real payload
        }
        let bytes = der.get(2..2 + n)?;
        let mut v = 0usize;
        for b in bytes {
            v = v.checked_mul(256)?.checked_add(*b as usize)?;
        }
        (v, 2 + n)
    };
    let body = der.get(body_at..body_at + len)?;
    if body_at + len != der.len() {
        return None; // trailing bytes: not a single well-formed OCTET STRING
    }
    Some(body)
}

/// A self-signed TLS certificate derived from this device's Ed25519 identity key.
///
/// The certificate's Subject Public Key IS the identity key, enabling allowlist-based
/// peer authentication without a certificate authority.
pub struct Ed25519DeviceCert {
    /// The DER-encoded certificate to present during TLS handshakes.
    pub cert_der: CertificateDer<'static>,
    /// Raw PKCS8 v1 DER bytes of the private key (kept private to avoid accidental exposure).
    key_bytes: Vec<u8>,
    /// The raw 32-byte Ed25519 public key — peers add this to their allowlists.
    pub public_key_bytes: [u8; 32],
}

impl Ed25519DeviceCert {
    /// Create a self-signed TLS certificate from an Ed25519 identity key.
    ///
    /// The certificate is ephemeral — it does not need to be persisted across restarts.
    /// It will be regenerated from the stable identity key each time the daemon starts.
    pub fn from_signing_key(
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<Self, TransportError> {
        Self::from_signing_key_with_admission(signing_key, &[])
    }

    /// The OID under which a recovered device offers the key events its peer has not seen.
    ///
    /// Private-enterprise arc, unregistered on purpose: this is read by Kotton and by nothing
    /// else, and a squatted public arc would be worse than an unregistered private one.
    /// **Non-critical**, so any TLS stack that does not know it ignores it rather than
    /// rejecting the handshake — a peer running an older build must refuse this device for
    /// *not being paired*, which is true, rather than for a malformed certificate.
    pub const ADMISSION_EVENTS_OID: &'static [u64] = &[1, 3, 6, 1, 4, 1, 58888, 81, 1];

    /// A certificate that also carries `since_tip` — the key events the peer needs to admit
    /// this device (`RFC-0081` gap 3).
    ///
    /// Populated **only on a connection that needs it**: a device already in a peer's
    /// allowlist presents an empty slice and pays nothing. Carrying this unconditionally was
    /// the thing that made the same mechanism wrong when it meant a whole chain; one event is
    /// about a kilobyte, and only on a retry after refusal.
    pub fn from_signing_key_with_admission(
        signing_key: &ed25519_dalek::SigningKey,
        since_tip: &[kotton_wire::kel::KelEvent],
    ) -> Result<Self, TransportError> {
        Self::from_signing_key_with_offer(
            signing_key,
            &CertOffer {
                admission: since_tip.to_vec(),
                claim: None,
            },
        )
    }

    /// The OID under which a device that holds nothing but a recovery phrase proves it
    /// (`RFC-0081`, the cold-device fetch).
    ///
    /// Sibling arc of [`Self::ADMISSION_EVENTS_OID`], same registration status, same
    /// non-critical marking, for the same reasons.
    pub const RECOVERY_CLAIM_OID: &'static [u64] = &[1, 3, 6, 1, 4, 1, 58888, 81, 2];

    /// A certificate carrying whatever `offer` holds: the key events a peer has not seen,
    /// a recovery claim, or — the common case — nothing, which is byte-identical to
    /// [`Self::from_signing_key`].
    pub fn from_signing_key_with_offer(
        signing_key: &ed25519_dalek::SigningKey,
        offer: &CertOffer,
    ) -> Result<Self, TransportError> {
        let since_tip: &[kotton_wire::kel::KelEvent] = &offer.admission;
        let public_key_bytes = signing_key.verifying_key().to_bytes();
        let private_key_raw = signing_key.to_bytes();

        // Build PKCS8 v1 DER: fixed 16-byte header + 32-byte Ed25519 private key.
        //   SEQUENCE (46 bytes)
        //     INTEGER 0              -- version
        //     SEQUENCE               -- algorithm
        //       OID 1.3.101.112      -- id-Ed25519
        //     OCTET STRING           -- privateKey
        //       OCTET STRING (32 bytes)
        #[rustfmt::skip]
        const PKCS8_ED25519_HEADER: [u8; 16] = [
            0x30, 0x2e,              // SEQUENCE
            0x02, 0x01, 0x00,        // INTEGER 0
            0x30, 0x05,              // SEQUENCE
            0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112
            0x04, 0x22, 0x04, 0x20, // OCTET STRING wrapping
        ];

        let mut key_bytes = Vec::with_capacity(48);
        key_bytes.extend_from_slice(&PKCS8_ED25519_HEADER);
        key_bytes.extend_from_slice(&private_key_raw);

        // rcgen 0.13 requires a PrivateKeyDer, not raw bytes.
        let key_der_for_rcgen = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_bytes.clone()),
        );
        let key_pair =
            rcgen::KeyPair::from_der_and_sign_algo(&key_der_for_rcgen, &rcgen::PKCS_ED25519)
                .map_err(|e| TransportError::ConfigError(e.to_string()))?;

        // rcgen 0.13: algorithm is inferred from KeyPair; no params.alg field.
        //
        // The SAN below is a placeholder, not an identity. Both verifiers here take
        // `_server_name` and ignore it — a peer is identified by its public key, which is
        // what pairing records. It is unrelated to the `kotton-operator` crate despite the
        // spelling, so a crate rename should leave it alone; changing it is harmless but
        // buys nothing.
        let mut params = rcgen::CertificateParams::new(vec!["kotton-device".to_string()])
            .map_err(|e| TransportError::ConfigError(e.to_string()))?;

        if !since_tip.is_empty() {
            let json = serde_json::to_vec(since_tip)
                .map_err(|e| TransportError::ConfigError(format!("encode admission events: {e}")))?;
            // Wrapped as a DER OCTET STRING: RFC 5280 requires an extension's value to be
            // DER, and a bare JSON body would be a malformed certificate rather than an
            // unrecognised extension.
            let content = der_octet_string(&json);
            params.custom_extensions.push(rcgen::CustomExtension::from_oid_content(
                Self::ADMISSION_EVENTS_OID,
                content,
            ));
        }
        if let Some(claim) = &offer.claim {
            let json = serde_json::to_vec(claim)
                .map_err(|e| TransportError::ConfigError(format!("encode recovery claim: {e}")))?;
            params.custom_extensions.push(rcgen::CustomExtension::from_oid_content(
                Self::RECOVERY_CLAIM_OID,
                der_octet_string(&json),
            ));
        }

        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| TransportError::ConfigError(e.to_string()))?;

        let cert_der = CertificateDer::from(cert.der().to_vec());

        Ok(Self {
            cert_der,
            key_bytes,
            public_key_bytes,
        })
    }

    /// Return the private key in PKCS8 DER format, suitable for building rustls configs.
    pub fn private_key_der(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_bytes.clone()))
    }
}

// ---------------------------------------------------------------------------
// What a dialling device can offer beyond its key
// ---------------------------------------------------------------------------

/// Domain tag a recovery claim's signature is taken over, so it can never be replayed
/// as any other signature the reserve key makes (a KEL event, most importantly).
pub const RECOVERY_CLAIM_DOMAIN: &str = "kotton:recovery-claim:v1";

/// Proof that the dialler holds a recovery authority of some identity this node hosts —
/// offered by a device that has the phrase and nothing else (`RFC-0081`, the cold fetch).
///
/// The reserve key signs **the dialling device's own TLS key**. That binds the claim to
/// this connection: nobody who captured it can present it from a different device,
/// because the handshake proves possession of the key it names. The phrase itself never
/// leaves the device; what crosses is one signature by a key the chain already committed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RecoveryClaim {
    /// The committed recovery public key — one rung of the phrase's ladder.
    pub reserve_pub: [u8; 32],
    /// `sign(reserve_sk, RECOVERY_CLAIM_DOMAIN || device_pub)`.
    #[serde(with = "serde_bytes_vec")]
    pub sig: Vec<u8>,
}

mod serde_bytes_vec {
    pub fn serialize<S: serde::Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(d)?;
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}

impl RecoveryClaim {
    fn message(device_pub: &[u8; 32]) -> Vec<u8> {
        let mut m = RECOVERY_CLAIM_DOMAIN.as_bytes().to_vec();
        m.extend_from_slice(device_pub);
        m
    }

    /// Sign a claim for the device whose TLS key is `device_pub`.
    pub fn sign(reserve_sk: &ed25519_dalek::SigningKey, device_pub: &[u8; 32]) -> Self {
        use ed25519_dalek::Signer;
        Self {
            reserve_pub: reserve_sk.verifying_key().to_bytes(),
            sig: reserve_sk.sign(&Self::message(device_pub)).to_bytes().to_vec(),
        }
    }

    /// Does this claim's signature hold for the device presenting it?
    ///
    /// The reserve key enters here, from the dialler's certificate, and is constructed as a
    /// [`VerifyingKey`] before anything is checked under it: a key the Ed25519 rule refuses
    /// makes no claim hold, and the signature is checked by the rule.
    pub fn verifies_for(&self, device_pub: &[u8; 32]) -> bool {
        let Ok(reserve) = VerifyingKey::from_bytes(&self.reserve_pub) else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(&self.sig) else {
            return false;
        };
        reserve.verify(&Self::message(device_pub), &sig).is_ok()
    }
}

/// What a certificate carries beyond the device key. Empty for every ordinary
/// connection, which is what keeps the ordinary connection free.
#[derive(Debug, Clone, Default)]
pub struct CertOffer {
    /// The key events the peer has not seen — usually one, a recovery rotation.
    pub admission: Vec<kotton_wire::kel::KelEvent>,
    /// Proof of a recovery authority, for a device that must fetch before it can rotate.
    pub claim: Option<RecoveryClaim>,
}

impl CertOffer {
    /// Offer the events since the peer's tip.
    pub fn events(admission: Vec<kotton_wire::kel::KelEvent>) -> Self {
        Self {
            admission,
            claim: None,
        }
    }

    /// Offer a recovery claim.
    pub fn claim(claim: RecoveryClaim) -> Self {
        Self {
            admission: Vec::new(),
            claim: Some(claim),
        }
    }
}

/// How a device that was not on the allowlist got in — recorded by the verifier at the
/// handshake, read by the request handler, which is the side that can persist it.
///
/// The handshake is where admission is *decided* (`RFC-0081`: the trust boundary does not
/// move); the handler is where it is *written down*, because a verifier has no database.
/// This map is the one place the two meet, keyed by the TLS key the handshake proved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admitted {
    /// The events offered continued the tip this node held and named the device key.
    /// The handler persists membership and advances the tip (rule 4).
    ByProof {
        aid: String,
        events: Vec<kotton_wire::kel::KelEvent>,
    },
    /// The device proved a recovery authority of `aid`. It may fetch that identity's
    /// public chain and phrase-sealed recovery copy, and nothing else.
    ByClaim { aid: String },
}

/// Everything a node knows that lets it admit a device it was never told about.
///
/// Three live maps behind one handle, shared between the listener's verifier and the
/// daemon that keeps them current: the identity tips (`RFC-0081`'s tip model), the
/// recovery authorities each hosted chain has committed, and the admissions the
/// verifier has granted and the handler has not yet persisted. Cloning shares.
#[derive(Debug, Clone, Default)]
pub struct Admission {
    /// AID → the latest key event this node holds for that identity.
    pub tips: KnownTips,
    /// Committed recovery public key → the AID whose chain committed it.
    pub authorities: Arc<RwLock<std::collections::HashMap<[u8; 32], String>>>,
    /// Device TLS key → how it was admitted, pending persistence.
    pub admitted: Arc<RwLock<std::collections::HashMap<[u8; 32], Admitted>>>,
}

impl Admission {
    /// Learn (or re-learn) a hosted identity's chain: its tip, and every recovery
    /// authority any of its events committed.
    ///
    /// Indexes the whole chain, not just the tip, on purpose. A phrase added by a
    /// `RotationAddRecovery` appears in that event's set and in no later one, and a
    /// recovering device can only sign with a rung it knows it holds — the first.
    pub fn learn_chain(&self, chain: &[kotton_wire::kel::KelEvent]) {
        let Some(tip) = chain.last() else { return };
        let aid = tip.aid.to_string();
        {
            let mut authorities = self.authorities.write().unwrap();
            for e in chain {
                for member in &e.recovery_set {
                    authorities.insert(*member, aid.clone());
                }
            }
        }
        self.tips.write().unwrap().insert(aid, tip.clone());
    }

    /// Forget an identity this node no longer hosts: its tip, every recovery
    /// authority that names it, and any admission granted for it and not yet
    /// written down. The inverse of [`Self::learn_chain`], for a vault dropping a
    /// tenant — after it, a device proving that identity's root or claiming one
    /// of its phrases is a stranger at the handshake.
    ///
    /// Keyed by AID alone. A caller hosting the same identity under another name
    /// re-learns that chain afterwards, which is additive and restores it.
    pub fn forget(&self, aid: &str) {
        self.tips.write().unwrap().remove(aid);
        self.authorities.write().unwrap().retain(|_, owner| owner != aid);
        self.admitted.write().unwrap().retain(|_, how| match how {
            Admitted::ByProof { aid: a, .. } | Admitted::ByClaim { aid: a } => a != aid,
        });
    }

    /// Take the pending admission for `device_pub`, if the verifier granted one.
    pub fn take_admitted(&self, device_pub: &[u8; 32]) -> Option<Admitted> {
        self.admitted.write().unwrap().remove(device_pub)
    }

    /// Peek at the pending admission for `device_pub` without consuming it.
    pub fn admitted(&self, device_pub: &[u8; 32]) -> Option<Admitted> {
        self.admitted.read().unwrap().get(device_pub).cloned()
    }
}

// ---------------------------------------------------------------------------
// PairedDeviceVerifier
// ---------------------------------------------------------------------------

/// Allowlist-based certificate verifier for paired Kotton devices.
///
/// Implements both `ClientCertVerifier` (used by the server side of mTLS) and
/// `ServerCertVerifier` (used by the client side). Both sides of a peer connection
/// verify that the remote device's Ed25519 public key is in the shared allowlist.
///
/// The allowlist is a live `Arc<RwLock<HashSet<[u8; 32]>>>`. Revoking a device is
/// instant: remove its key, and the next connection attempt is rejected at the TLS
/// handshake with no daemon restart needed.
///
/// The presented key is admitted only once it has passed the Ed25519 rule as a key, and the
/// handshake's signature is checked under it by the rule ([`verify_handshake_signature`]), so
/// the verifier holds no crypto provider of its own.
/// AID → the latest key event this node holds for that identity.
///
/// A **tip**, not a log: `validate` reads only the immediately preceding event, so a verifier
/// kept current needs one event per identity and nothing before it (`RFC-0081`).
pub type KnownTips = Arc<RwLock<std::collections::HashMap<String, kotton_wire::kel::KelEvent>>>;

#[derive(Debug)]
pub struct PairedDeviceVerifier {
    allowed_keys: Arc<RwLock<HashSet<[u8; 32]>>>,
    /// Empty for every peer that is not a replica of somebody's identity — a verifier with no
    /// tips and no authorities behaves exactly as it did before admission-by-proof existed.
    admission: Admission,
}

impl PairedDeviceVerifier {
    /// Create a verifier backed by the given allowlist.
    ///
    /// Admits on the allowlist alone. A node that holds a user's identity tip should use
    /// [`Self::new_with_tips`] so a recovered device can be admitted on proof of control of
    /// the root rather than on a key the node was told about in advance.
    pub fn new(allowed_keys: Arc<RwLock<HashSet<[u8; 32]>>>) -> Arc<Self> {
        Self::new_with_tips(allowed_keys, Default::default())
    }

    /// As [`Self::new`], plus the identity tips this node holds (`RFC-0081` gap 3).
    pub fn new_with_tips(
        allowed_keys: Arc<RwLock<HashSet<[u8; 32]>>>,
        known_tips: KnownTips,
    ) -> Arc<Self> {
        Self::new_with_admission(
            allowed_keys,
            Admission {
                tips: known_tips,
                ..Default::default()
            },
        )
    }

    /// As [`Self::new`], plus everything this node knows that can admit a device it was
    /// not told about: identity tips, committed recovery authorities, and the map the
    /// handshake writes its verdicts into for the handler to persist.
    pub fn new_with_admission(
        allowed_keys: Arc<RwLock<HashSet<[u8; 32]>>>,
        admission: Admission,
    ) -> Arc<Self> {
        Arc::new(Self {
            allowed_keys,
            admission,
        })
    }

    /// The presented key enters here, and is admitted by nothing until it has passed the
    /// Ed25519 rule: [`extract_ed25519_pubkey_from_cert`] constructs it as a [`VerifyingKey`].
    fn check_cert(&self, cert: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        let pubkey = extract_ed25519_pubkey_from_cert(cert).ok_or_else(|| {
            rustls::Error::General(
                "Certificate carries no Ed25519 public key that passes the rule".into(),
            )
        })?;
        if self.allowed_keys.read().unwrap().contains(pubkey.as_bytes()) {
            return Ok(());
        }
        self.admit_by_proof(cert, &pubkey)
    }

    /// Every refusal on the not-on-the-allowlist path reads the same. See
    /// [`Self::admit_by_proof`] for why that is a property and not an oversight.
    const REFUSED: &'static str = "Device public key not in paired allowlist, and no key \
                                   events were offered that authorize it. If this device was \
                                   recovered from the recovery phrase, run `kotton user \
                                   recover` on it.";

    /// The recovered-device path: the caller is not on the allowlist, so ask whether the key
    /// events it offers prove it now speaks for an identity this node already holds.
    ///
    /// Tried **only after** the allowlist misses, so the ordinary paired connection costs
    /// nothing extra — no parsing, no chain crypto, no lock beyond the one it already took.
    ///
    /// The refusal message is deliberately the same in every failing case, and deliberately
    /// names `recover`. Same, because a caller choosing these bytes must not be able to learn
    /// *which* check refused it — whether an identity is hosted here, how current this node
    /// is, and whether a chain nearly verified are all things a stranger would like to probe
    /// for. Names `recover` because the ruling on
    /// `IDEA-what-a-phrase-login-should-rotate` requires it: a user who has lost every device
    /// and signed in with `login` is otherwise left with their identity back, their data
    /// unreachable, and nothing saying which command fixes it.
    fn admit_by_proof(
        &self,
        cert: &CertificateDer<'_>,
        pubkey: &VerifyingKey,
    ) -> Result<(), rustls::Error> {
        let refuse = || rustls::Error::General(Self::REFUSED.into());

        let offered = extract_admission_events(cert);
        let Some(first) = offered.first() else {
            return self.admit_by_claim(cert, pubkey);
        };
        let aid = first.aid.to_string();
        let tip = self
            .admission
            .tips
            .read()
            .unwrap()
            .get(&aid)
            .cloned()
            .ok_or_else(refuse)?;

        kotton_crypto::kel_verify::admits_device(
            &tip,
            &offered,
            pubkey.as_bytes(),
            &kotton_crypto::kel_verify::LocalArbiter,
            false,
        )
        .map_err(|_| refuse())?;

        // Decided here; written down by the handler (rule 4). Until it is, the tip this
        // verifier holds is the old one, and a second connection from the same device
        // re-proves against it and lands here again — harmless, and short-lived.
        self.admission.admitted.write().unwrap().insert(
            *pubkey.as_bytes(),
            Admitted::ByProof {
                aid,
                events: offered,
            },
        );
        Ok(())
    }

    /// The cold-device path: the caller offers no events because it has no chain to build
    /// one from, only a phrase. It proves a recovery authority instead, and is admitted to
    /// **fetch** — the chain and the phrase-sealed recovery copy — and to nothing else.
    ///
    /// Same refusal as [`Self::admit_by_proof`] in every failing case, for the same
    /// reason: whether this node hosts an identity whose recovery set contains a given key
    /// is exactly what a stranger with a guessed phrase would like to learn.
    fn admit_by_claim(
        &self,
        cert: &CertificateDer<'_>,
        pubkey: &VerifyingKey,
    ) -> Result<(), rustls::Error> {
        let refuse = || rustls::Error::General(Self::REFUSED.into());
        let claim = extract_recovery_claim(cert).ok_or_else(refuse)?;
        let aid = self
            .admission
            .authorities
            .read()
            .unwrap()
            .get(&claim.reserve_pub)
            .cloned()
            .ok_or_else(refuse)?;
        if !claim.verifies_for(pubkey.as_bytes()) {
            return Err(refuse());
        }
        self.admission
            .admitted
            .write()
            .unwrap()
            .insert(*pubkey.as_bytes(), Admitted::ByClaim { aid });
        Ok(())
    }
}

impl rustls::server::danger::ClientCertVerifier for PairedDeviceVerifier {
    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        self.check_cert(end_entity)?;
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General(
            "TLS 1.2 not supported for Kotton peer connections".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_handshake_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        HANDSHAKE_SCHEMES.to_vec()
    }
}

impl rustls::client::danger::ServerCertVerifier for PairedDeviceVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.check_cert(end_entity)?;
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General(
            "TLS 1.2 not supported for Kotton peer connections".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_handshake_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        HANDSHAKE_SCHEMES.to_vec()
    }
}

// ---------------------------------------------------------------------------
// Config builders
// ---------------------------------------------------------------------------

/// Build a QUIC `ServerConfig` for peer-to-peer mTLS.
///
/// The server presents `device_cert` and requires the connecting client to
/// present a certificate whose public key is in `verifier`'s allowlist, on every
/// connection: it is [`build_peer_rustls_server_config`] carried over QUIC, and
/// resumes no session.
pub fn build_peer_server_config(
    device_cert: &Ed25519DeviceCert,
    verifier: Arc<PairedDeviceVerifier>,
    provider: Arc<rustls::crypto::CryptoProvider>,
    keepalive: Option<std::time::Duration>,
) -> Result<ServerConfig, TransportError> {
    let rustls_server = build_peer_rustls_server_config(device_cert, verifier, provider)?;

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(rustls_server)
            .map_err(|e| TransportError::ConfigError(e.to_string()))?,
    ));

    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(100u32.into());
    transport.max_concurrent_uni_streams(100u32.into());
    if let Some(interval) = keepalive {
        transport.keep_alive_interval(Some(interval));
    }
    server_config.transport_config(Arc::new(transport));

    Ok(server_config)
}

/// Build a QUIC `ClientConfig` for peer-to-peer mTLS.
///
/// The client presents `device_cert` and verifies the server's certificate
/// public key against `verifier`'s allowlist, on every connection: it is
/// [`build_peer_rustls_client_config`] carried over QUIC, and resumes no session.
pub fn build_peer_client_config(
    device_cert: &Ed25519DeviceCert,
    verifier: Arc<PairedDeviceVerifier>,
    provider: Arc<rustls::crypto::CryptoProvider>,
    keepalive: Option<std::time::Duration>,
) -> Result<ClientConfig, TransportError> {
    let rustls_client = build_peer_rustls_client_config(device_cert, verifier, provider)?;

    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(rustls_client)
            .map_err(|e| TransportError::ConfigError(e.to_string()))?,
    ));

    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(100u32.into());
    transport.max_concurrent_uni_streams(100u32.into());
    if let Some(interval) = keepalive {
        transport.keep_alive_interval(Some(interval));
    }
    client_config.transport_config(Arc::new(transport));

    Ok(client_config)
}

/// Build a plain rustls `ServerConfig` for peer mTLS: the device cert and the
/// paired-key verifier, without the quinn wrapping [`build_peer_server_config`]
/// gives it. A relay's circuit does not run it: that carries the handshake
/// (`transport::relayed`).
///
/// It keeps no session and issues no ticket, so no connection resumes one. A
/// resumed TLS 1.3 handshake carries no client certificate and rustls asks no
/// verifier about it, so a session kept here would admit a device on the allowlist
/// as it stood when the session began; with none kept, every connection presents
/// its certificate to `verifier`, and a key removed from the allowlist is refused
/// at its next handshake (decision 0011).
pub fn build_peer_rustls_server_config(
    device_cert: &Ed25519DeviceCert,
    verifier: Arc<PairedDeviceVerifier>,
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Result<rustls::ServerConfig, TransportError> {
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TransportError::ConfigError(e.to_string()))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![device_cert.cert_der.clone()],
            device_cert.private_key_der(),
        )
        .map_err(|e| TransportError::ConfigError(e.to_string()))?;
    // The builder's ticketer already produces nothing; the store is what a
    // stateful ticket would be looked up in, so nothing is kept there either.
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    Ok(config)
}

/// Build a plain rustls `ClientConfig` for peer mTLS over a reliable byte stream
/// (counterpart to [`build_peer_rustls_server_config`]).
///
/// It keeps no ticket a server issues and so never offers one: the server's
/// certificate is checked against `verifier` on every connection, whatever a
/// server built some other way would resume (decision 0011).
pub fn build_peer_rustls_client_config(
    device_cert: &Ed25519DeviceCert,
    verifier: Arc<PairedDeviceVerifier>,
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Result<rustls::ClientConfig, TransportError> {
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TransportError::ConfigError(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(
            vec![device_cert.cert_der.clone()],
            device_cert.private_key_der(),
        )
        .map_err(|e| TransportError::ConfigError(e.to_string()))?;
    config.resumption = rustls::client::Resumption::disabled();
    Ok(config)
}

// ---------------------------------------------------------------------------
// Bootstrap cert verifier (pairing ceremony only)
// ---------------------------------------------------------------------------

/// Certificate verifier that accepts **any** self-signed Ed25519 certificate.
///
/// Used exclusively for the pairing ceremony bootstrap QUIC connection, where
/// mTLS (allowlist-based) is not yet available — identity is bootstrapped via
/// the ECDH pairing protocol at the application layer.
///
/// **SECURITY NOTE:** This verifier provides TLS *confidentiality* (encrypted
/// channel) but does NOT authenticate the remote peer at the TLS layer.
/// Authentication is the responsibility of the pairing ECDH protocol:
/// the sealed `UserKeychain` can only be decrypted if the peer holds the
/// private key corresponding to the Ed25519 public key in the pairing code.
/// Any MITM will fail at the ECDH / AEAD decrypt step.
///
/// Do NOT use this verifier for anything other than the pairing bootstrap.
///
/// It does hold the handshake to the Ed25519 rule, as [`PairedDeviceVerifier`] does: the
/// signature must be Ed25519, under a key that passes the rule, and check by the rule
/// ([`verify_handshake_signature`]). A certificate that is not Ed25519 is refused.
#[derive(Debug)]
pub struct BootstrapCertVerifier(());

impl BootstrapCertVerifier {
    /// Create a new bootstrap verifier.
    pub fn new() -> Arc<Self> {
        Arc::new(Self(()))
    }
}

impl rustls::server::danger::ClientCertVerifier for BootstrapCertVerifier {
    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General(
            "TLS 1.2 not supported for bootstrap pairing connections".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_handshake_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        HANDSHAKE_SCHEMES.to_vec()
    }
}

impl rustls::client::danger::ServerCertVerifier for BootstrapCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General(
            "TLS 1.2 not supported for bootstrap pairing connections".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_handshake_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        HANDSHAKE_SCHEMES.to_vec()
    }
}

/// Build a QUIC `ServerConfig` for the bootstrap pairing endpoint.
///
/// The server presents `device_cert` and accepts **any** client certificate
/// (or no certificate). Used only for the pairing bootstrap step.
pub fn build_bootstrap_server_config(
    device_cert: &Ed25519DeviceCert,
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Result<ServerConfig, TransportError> {
    let verifier = BootstrapCertVerifier::new();
    let rustls_server = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TransportError::ConfigError(e.to_string()))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![device_cert.cert_der.clone()],
            device_cert.private_key_der(),
        )
        .map_err(|e| TransportError::ConfigError(e.to_string()))?;

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(rustls_server)
            .map_err(|e| TransportError::ConfigError(e.to_string()))?,
    ));

    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(4u32.into());
    transport.max_concurrent_uni_streams(0u32.into());
    server_config.transport_config(Arc::new(transport));

    Ok(server_config)
}

/// Build a QUIC `ClientConfig` for the bootstrap pairing connection.
///
/// The client presents `device_cert` (so the server can extract the client's
/// Ed25519 public key) and accepts any server certificate.
pub fn build_bootstrap_client_config(
    device_cert: &Ed25519DeviceCert,
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Result<ClientConfig, TransportError> {
    let verifier = BootstrapCertVerifier::new();
    let rustls_client = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TransportError::ConfigError(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(
            vec![device_cert.cert_der.clone()],
            device_cert.private_key_der(),
        )
        .map_err(|e| TransportError::ConfigError(e.to_string()))?;

    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(rustls_client)
            .map_err(|e| TransportError::ConfigError(e.to_string()))?,
    ));

    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(4u32.into());
    transport.max_concurrent_uni_streams(0u32.into());
    client_config.transport_config(Arc::new(transport));

    Ok(client_config)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// The one signature scheme a peer handshake accepts.
const HANDSHAKE_SCHEMES: [rustls::SignatureScheme; 1] = [rustls::SignatureScheme::ED25519];

/// The handshake's `CertificateVerify` signature, checked by the Ed25519 rule: every
/// verifier in this module checks a TLS 1.3 signature here and nowhere else.
///
/// The scheme must be Ed25519; the key is the certificate's, read by
/// [`extract_ed25519_pubkey_from_cert`] (the same function the allowlist check reads it with)
/// and so constructed as a [`VerifyingKey`]; and the signature over `message`, the bytes the
/// TLS library hands a verifier, is checked by [`VerifyingKey::verify`].
fn verify_handshake_signature(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &rustls::DigitallySignedStruct,
) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
    let bad = || rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature);
    if !HANDSHAKE_SCHEMES.contains(&dss.scheme) {
        return Err(bad());
    }
    let key = extract_ed25519_pubkey_from_cert(cert).ok_or_else(bad)?;
    let signature = Signature::from_slice(dss.signature()).map_err(|_| bad())?;
    key.verify(message, &signature).map_err(|_| bad())?;
    Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
}

/// The Ed25519 public key a certificate's SubjectPublicKeyInfo carries, as a
/// [`VerifyingKey`]: `None` if the certificate does not parse, is not Ed25519, or carries
/// 32 bytes the Ed25519 rule refuses as a key.
///
/// This is where a peer's key enters from its certificate, so it is where the key is
/// constructed; a caller that needs only the bytes takes [`VerifyingKey::as_bytes`].
///
/// Parses the certificate and reads the key from the **SubjectPublicKeyInfo** —
/// the exact field [`verify_handshake_signature`] checks the TLS 1.3
/// `CertificateVerify` signature against, because it reads the key here too.
///
/// # Why structural parsing, not a byte-scan
///
/// A previous implementation scanned the raw DER for the Ed25519 OID pattern
/// (`06 03 2b 65 70` + a `03 21 00` BIT STRING). That is a **parser
/// differential**: attacker-controlled octets in issuer/subject DN attributes
/// *precede* the real SPKI in the certificate, so an attacker could plant
/// `…OID…BITSTRING…<victim_pubkey>` in a DN field, sign the handshake with their
/// **own** key (which the signature check reads from the true SPKI), and have this
/// function match the *planted* victim key against the paired allowlist —
/// impersonating any allowlisted DID without its private key. Gating the
/// allowlist on the same SPKI the signature is checked against closes that gap.
///
/// North star ([SECURITY-DESIGN-AUDIT-2026-07] C1): drop X.509 entirely and use
/// TLS 1.3 raw public keys (RFC 7250) so "the cert *is* the identity key" is
/// structural rather than parsed.
pub fn extract_ed25519_pubkey_from_cert(cert_der: &CertificateDer<'_>) -> Option<VerifyingKey> {
    use x509_parser::prelude::FromDer;

    let (_, cert) =
        x509_parser::certificate::X509Certificate::from_der(cert_der.as_ref()).ok()?;
    let spki = cert.public_key();

    // Reject anything that is not id-Ed25519 (OID 1.3.101.112). `as_bytes()`
    // returns the OID's DER content octets, which for 1.3.101.112 are `2b 65 70`.
    const ED25519_OID_OCTETS: [u8; 3] = [0x2b, 0x65, 0x70];
    if spki.algorithm.algorithm.as_bytes() != ED25519_OID_OCTETS.as_slice() {
        return None;
    }

    // The Ed25519 subjectPublicKey is exactly 32 raw bytes; `try_into` enforces it.
    let key: [u8; 32] = spki.subject_public_key.data.as_ref().try_into().ok()?;
    VerifyingKey::from_bytes(&key).ok()
}

/// The key events a peer offers in its certificate so this node can admit it
/// (`RFC-0081` gap 3), or an empty vec when it offers none.
///
/// **Every failure is an empty vec, never an error.** These bytes are chosen by whoever is
/// dialling: a missing extension, a malformed one, and a well-formed one full of nonsense are
/// all just "this device offered nothing usable", and the caller then refuses it for not being
/// admitted — which is the truthful reason. Returning a hard error would let a stranger turn a
/// junk extension into a distinguishable failure, and a panic would let them stop the daemon.
///
/// Nothing here is trusted. The events are *claims*; `kel_verify::admits_device` decides
/// whether they continue the tip this node holds.
pub fn extract_admission_events(
    cert_der: &CertificateDer<'_>,
) -> Vec<kotton_wire::kel::KelEvent> {
    extension_body(cert_der, Ed25519DeviceCert::ADMISSION_EVENTS_OID)
        .and_then(|body| serde_json::from_slice(&body).ok())
        .unwrap_or_default()
}

/// The recovery claim a certificate offers, or `None` — for a missing extension, a
/// malformed one, and one that does not parse alike, per the same rule as
/// [`extract_admission_events`]: a dialler must not be able to tell those apart.
pub fn extract_recovery_claim(cert_der: &CertificateDer<'_>) -> Option<RecoveryClaim> {
    extension_body(cert_der, Ed25519DeviceCert::RECOVERY_CLAIM_OID)
        .and_then(|body| serde_json::from_slice(&body).ok())
}

/// The OCTET STRING body of the extension under `oid`, if the certificate carries one.
fn extension_body(cert_der: &CertificateDer<'_>, oid: &[u64]) -> Option<Vec<u8>> {
    use x509_parser::prelude::FromDer;

    let (_, cert) =
        x509_parser::certificate::X509Certificate::from_der(cert_der.as_ref()).ok()?;
    // `oid-registry`'s `Oid` compares by its dotted arcs; build the same one the writer used.
    for ext in cert.extensions() {
        let arcs: Vec<u64> = match ext.oid.iter() {
            Some(it) => it.collect(),
            None => continue,
        };
        if arcs != oid {
            continue;
        }
        return parse_der_octet_string(ext.value).map(<[u8]>::to_vec);
    }
    None
}

// ---------------------------------------------------------------------------
// Test certificate helpers (public so integration tests can use them)
// ---------------------------------------------------------------------------

/// Generate a self-signed certificate using an ephemeral key, for testing only.
pub fn generate_self_signed_cert() -> Result<
    (
        rustls::pki_types::CertificateDer<'static>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ),
    Box<dyn std::error::Error>,
> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    let cert_der = cert.cert.der().clone();
    Ok((cert_der, key))
}

/// Build a `quinn::ServerConfig` with a self-signed certificate, for testing only.
pub fn test_server_config() -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let (cert, key) = generate_self_signed_cert()?;

    let crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?,
    ));

    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(100u32.into());
    transport.max_concurrent_uni_streams(100u32.into());
    server_config.transport_config(Arc::new(transport));

    Ok(server_config)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    /// A claim under a reserve key of small order holds for no device.
    #[test]
    fn a_claim_under_a_small_order_reserve_key_is_refused() {
        use kotton_crypto::ed25519::refused;
        let claim = RecoveryClaim {
            reserve_pub: refused::SMALL_ORDER_KEY,
            sig: refused::under_small_order_key_bytes().to_vec(),
        };
        assert!(!claim.verifies_for(&SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes()));
    }

    /// A non-canonical signature by the reserve key holds for no device.
    #[test]
    fn a_claim_with_a_non_canonical_signature_is_refused() {
        use kotton_crypto::ed25519::refused;
        let reserve = SigningKey::from_bytes(&[4; 32]);
        let device = SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes();
        assert!(RecoveryClaim::sign(&reserve, &device).verifies_for(&device));
        for sig in refused::non_canonical(&reserve, &RecoveryClaim::message(&device)) {
            let claim = RecoveryClaim { reserve_pub: reserve.verifying_key().to_bytes(), sig: sig.to_bytes().to_vec() };
            assert!(!claim.verifies_for(&device));
        }
    }

    fn init_crypto() {
        use std::sync::Once;
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            rustls::crypto::ring::default_provider()
                .install_default()
                .ok();
        });
    }

    #[test]
    fn test_device_cert_round_trip() {
        init_crypto();
        let signing_key = SigningKey::generate(&mut OsRng);
        let cert = Ed25519DeviceCert::from_signing_key(&signing_key).unwrap();

        // The stored public key bytes must match the signing key's verifying key.
        assert_eq!(
            cert.public_key_bytes,
            signing_key.verifying_key().to_bytes()
        );
    }

    #[test]
    fn test_extract_ed25519_pubkey_from_cert() {
        init_crypto();
        let signing_key = SigningKey::generate(&mut OsRng);
        let cert = Ed25519DeviceCert::from_signing_key(&signing_key).unwrap();

        let extracted = extract_ed25519_pubkey_from_cert(&cert.cert_der).unwrap();
        assert_eq!(*extracted.as_bytes(), cert.public_key_bytes);
    }

    #[test]
    fn test_paired_device_verifier_allows_known_key() {
        init_crypto();
        let signing_key = SigningKey::generate(&mut OsRng);
        let cert = Ed25519DeviceCert::from_signing_key(&signing_key).unwrap();

        let mut allowed = HashSet::new();
        allowed.insert(cert.public_key_bytes);
        let verifier = PairedDeviceVerifier::new(Arc::new(RwLock::new(allowed)));

        verifier.check_cert(&cert.cert_der).unwrap();
    }

    #[test]
    fn test_paired_device_verifier_rejects_unknown_key() {
        init_crypto();
        let signing_key = SigningKey::generate(&mut OsRng);
        let cert = Ed25519DeviceCert::from_signing_key(&signing_key).unwrap();

        let verifier = PairedDeviceVerifier::new(
            Arc::new(RwLock::new(HashSet::new())), // empty allowlist
        );

        assert!(verifier.check_cert(&cert.cert_der).is_err());
    }

    #[test]
    fn test_paired_device_verifier_live_revocation() {
        init_crypto();
        let signing_key = SigningKey::generate(&mut OsRng);
        let cert = Ed25519DeviceCert::from_signing_key(&signing_key).unwrap();

        let allowed = Arc::new(RwLock::new(HashSet::new()));
        let verifier = PairedDeviceVerifier::new(Arc::clone(&allowed));

        // Add key → allowed
        allowed.write().unwrap().insert(cert.public_key_bytes);
        verifier.check_cert(&cert.cert_der).unwrap();

        // Remove key → rejected immediately (no restart)
        allowed.write().unwrap().remove(&cert.public_key_bytes);
        assert!(verifier.check_cert(&cert.cert_der).is_err());
    }

    /// The pre-fix byte-scan, reproduced so the regression test can prove its
    /// fixture actually triggered the parser differential the fix closes.
    fn legacy_byte_scan(bytes: &[u8]) -> Option<[u8; 32]> {
        const ED25519_OID: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
        for pos in 0..bytes.len().saturating_sub(ED25519_OID.len() + 3 + 32) {
            if bytes[pos..pos + ED25519_OID.len()] != *ED25519_OID {
                continue;
            }
            let after_oid = pos + ED25519_OID.len();
            if bytes[after_oid] == 0x03
                && bytes[after_oid + 1] == 0x21
                && bytes[after_oid + 2] == 0x00
            {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes[after_oid + 3..after_oid + 35]);
                return Some(key);
            }
        }
        None
    }

    /// C1 regression: a cert with a victim's key planted in a DN attribute (which
    /// precedes the real SubjectPublicKeyInfo) but signed with the attacker's own
    /// key must NOT authenticate as the victim. The old byte-scan matched the
    /// planted key; structural SPKI extraction matches only what rustls verifies.
    #[test]
    fn test_cert_parser_differential_is_closed() {
        init_crypto();
        use rcgen::{CertificateParams, DnType, DnValue, KeyPair, PKCS_ED25519};

        // Victim key to impersonate. Bytes < 0x80 so the decoy is valid UTF-8 and
        // can ride inside a DN attribute value.
        let victim_key: [u8; 32] = std::array::from_fn(|i| 0x41 + i as u8);

        // The attacker's decoy: the exact SPKI byte pattern the old scanner keyed
        // on — Ed25519 OID (06 03 2b 65 70) + BIT STRING header (03 21 00) + the
        // victim's 32 bytes — planted in the subject CommonName, ahead of the
        // real SPKI in the DER.
        let mut decoy = vec![0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
        decoy.extend_from_slice(&victim_key);
        let decoy_dn = String::from_utf8(decoy).expect("decoy is valid utf-8");

        // The attacker's real key pair — what rustls actually verifies against.
        let attacker = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let attacker_key: [u8; 32] = attacker.public_key_raw().try_into().unwrap();
        assert_ne!(attacker_key, victim_key);

        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, DnValue::Utf8String(decoy_dn));
        let cert_der = params.self_signed(&attacker).unwrap().der().clone();

        // The fixture is only meaningful if it actually fooled the old scanner.
        assert_eq!(
            legacy_byte_scan(cert_der.as_ref()),
            Some(victim_key),
            "fixture must trigger the old parser differential"
        );

        // The fix: extraction returns the real SPKI key, never the planted one.
        let extracted = *extract_ed25519_pubkey_from_cert(&cert_der).unwrap().as_bytes();
        assert_eq!(extracted, attacker_key);
        assert_ne!(extracted, victim_key);

        // End-to-end: with only the victim allowlisted, the crafted cert is
        // rejected — no impersonation.
        let mut allowed = HashSet::new();
        allowed.insert(victim_key);
        let verifier =
            PairedDeviceVerifier::new(Arc::new(RwLock::new(allowed)));
        assert!(
            verifier.check_cert(&cert_der).is_err(),
            "attacker cert with a planted victim key must not authenticate as the victim"
        );
    }
}

#[cfg(test)]
mod admission_der_tests {
    use super::*;

    /// The long-form length is the live path — an admission payload is about a kilobyte —
    /// and the short form is the one a test would otherwise never reach.
    #[test]
    fn octet_string_round_trips_across_the_length_boundary() {
        for n in [0usize, 1, 127, 128, 255, 256, 1024, 4096] {
            let payload = vec![0xABu8; n];
            let der = der_octet_string(&payload);
            assert_eq!(
                parse_der_octet_string(&der),
                Some(payload.as_slice()),
                "round trip failed at length {n}"
            );
        }
    }

    /// DER requires the shortest length form. 127 must be one byte; 128 must not be.
    #[test]
    fn lengths_use_the_shortest_der_form() {
        assert_eq!(der_octet_string(&[0u8; 127])[1], 127);
        assert_eq!(der_octet_string(&[0u8; 128])[1], 0x81);
        assert_eq!(der_octet_string(&vec![0u8; 256])[1], 0x82);
    }

    /// These bytes come from whoever is dialling, so every malformed shape must be a clean
    /// `None`. A length claiming more than the buffer holds is the hostile case a slice index
    /// would panic on.
    #[test]
    fn malformed_input_is_refused_rather_than_panicking() {
        assert_eq!(parse_der_octet_string(&[]), None);
        assert_eq!(parse_der_octet_string(&[0x30, 0x01, 0x00]), None, "wrong tag");
        assert_eq!(parse_der_octet_string(&[0x04]), None, "truncated");
        assert_eq!(parse_der_octet_string(&[0x04, 0x05, 0x01]), None, "length exceeds buffer");
        assert_eq!(parse_der_octet_string(&[0x04, 0x80]), None, "indefinite length");
        assert_eq!(parse_der_octet_string(&[0x04, 0x89, 1, 2, 3, 4, 5, 6, 7, 8, 9]), None, "absurd width");
        assert_eq!(
            parse_der_octet_string(&[0x04, 0x01, 0xAA, 0xBB]),
            None,
            "trailing bytes must not be ignored"
        );
    }

    /// A certificate with no events must carry no extension at all — the common case pays
    /// nothing, which is the whole reason this is conditional.
    #[test]
    fn a_cert_with_no_events_carries_no_admission_extension() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let plain = Ed25519DeviceCert::from_signing_key(&sk).expect("cert");
        let needle: Vec<u8> = vec![0x06]; // any OID tag; we assert on size instead
        let _ = needle;
        let with = Ed25519DeviceCert::from_signing_key_with_admission(&sk, &[]).expect("cert");
        assert_eq!(
            plain.cert_der.len(),
            with.cert_der.len(),
            "an empty admission slice must produce the same certificate as no slice at all"
        );
    }
}

#[cfg(test)]
mod admission_extract_tests {
    use super::*;
    use kotton_crypto::kel_verify::{build_mnemonic_rotation, build_user_inception};

    fn one_rotation() -> Vec<kotton_wire::kel::KelEvent> {
        let seed = [42u8; 32];
        let inc = build_user_inception(&seed);
        let new = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        vec![build_mnemonic_rotation(&inc, &seed, 0, &new, 0, &[kotton_crypto::kel_verify::kel_recovery_pubkey(&kotton_crypto::kdf::derive_kel_recovery_key(&seed, 0))])]
    }

    #[test]
    fn events_survive_the_certificate_round_trip() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let events = one_rotation();
        let cert = Ed25519DeviceCert::from_signing_key_with_admission(&sk, &events).expect("cert");
        assert_eq!(extract_admission_events(&cert.cert_der), events);
        // The identity the allowlist checks is unaffected by the passenger.
        assert_eq!(
            extract_ed25519_pubkey_from_cert(&cert.cert_der).map(|k| *k.as_bytes()),
            Some(sk.verifying_key().to_bytes())
        );
    }

    #[test]
    fn a_plain_certificate_offers_nothing() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let cert = Ed25519DeviceCert::from_signing_key(&sk).expect("cert");
        assert!(extract_admission_events(&cert.cert_der).is_empty());
    }

    /// Hostile input must read as "offered nothing", never as an error and never as a panic:
    /// a stranger must not be able to turn a junk extension into a distinguishable failure.
    #[test]
    fn junk_is_indistinguishable_from_offering_nothing() {
        assert!(extract_admission_events(&CertificateDer::from(vec![])).is_empty());
        assert!(extract_admission_events(&CertificateDer::from(vec![0xFFu8; 64])).is_empty());
        let sk = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let cert = Ed25519DeviceCert::from_signing_key(&sk).expect("cert");
        let mut mangled = cert.cert_der.as_ref().to_vec();
        for b in mangled.iter_mut().skip(20).take(40) {
            *b ^= 0x5A;
        }
        assert!(extract_admission_events(&CertificateDer::from(mangled)).is_empty());
    }

    /// A payload measured, so the size claim in the record is checked rather than asserted.
    #[test]
    fn one_event_costs_about_a_kilobyte() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let plain = Ed25519DeviceCert::from_signing_key(&sk).expect("cert");
        let with = Ed25519DeviceCert::from_signing_key_with_admission(&sk, &one_rotation())
            .expect("cert");
        let overhead = with.cert_der.len() - plain.cert_der.len();
        assert!(
            (500..3000).contains(&overhead),
            "one admission event added {overhead} bytes; the design rests on this being ~1 KB"
        );
    }
}

#[cfg(test)]
mod admission_verifier_tests {
    use super::*;
    use kotton_crypto::kel_verify::{build_mnemonic_rotation, build_user_inception};

    /// A blind node holding only the inception, and a device recovered from the phrase.
    fn scenario() -> (kotton_wire::kel::KelEvent, ed25519_dalek::SigningKey, Vec<kotton_wire::kel::KelEvent>) {
        let seed = [42u8; 32];
        let inception = build_user_inception(&seed);
        let recovered = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let rotation = build_mnemonic_rotation(&inception, &seed, 0, &recovered, 0, &[kotton_crypto::kel_verify::kel_recovery_pubkey(&kotton_crypto::kdf::derive_kel_recovery_key(&seed, 0))]);
        (inception, recovered, vec![rotation])
    }

    fn tips(events: &[(&str, &kotton_wire::kel::KelEvent)]) -> KnownTips {
        let mut m = std::collections::HashMap::new();
        for (aid, e) in events {
            m.insert((*aid).to_string(), (*e).clone());
        }
        Arc::new(RwLock::new(m))
    }

    /// M1's shape at the transport: a device the node was never told about, admitted because
    /// the events it offers prove it now speaks for an identity the node holds.
    #[test]
    fn a_recovered_device_is_admitted_on_proof() {
        let (inception, recovered, offered) = scenario();
        let v = PairedDeviceVerifier::new_with_tips(
            Arc::new(RwLock::new(HashSet::new())),
            tips(&[(&inception.aid.to_string(), &inception)]),
        );
        let cert = Ed25519DeviceCert::from_signing_key_with_admission(&recovered, &offered)
            .expect("cert");
        assert!(v.check_cert(&cert.cert_der).is_ok());
    }

    /// The allowlist still decides the ordinary case, with no events offered and no tips held.
    #[test]
    fn an_allowlisted_device_is_admitted_with_no_events() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let v = PairedDeviceVerifier::new(
            Arc::new(RwLock::new(HashSet::from([sk.verifying_key().to_bytes()]))),
        );
        let cert = Ed25519DeviceCert::from_signing_key(&sk).expect("cert");
        assert!(v.check_cert(&cert.cert_der).is_ok());
    }

    /// A stranger offering a perfectly valid chain for their *own* identity is refused: the
    /// node holds no tip it continues.
    #[test]
    fn a_valid_chain_for_an_identity_this_node_does_not_host_is_refused() {
        let (inception, _, _) = scenario();
        let other_seed = [77u8; 32];
        let their_inception = build_user_inception(&other_seed);
        let attacker = ed25519_dalek::SigningKey::from_bytes(&[12u8; 32]);
        let their_rot = build_mnemonic_rotation(&their_inception, &other_seed, 0, &attacker, 0, &[kotton_crypto::kel_verify::kel_recovery_pubkey(&kotton_crypto::kdf::derive_kel_recovery_key(&other_seed, 0))]);

        let v = PairedDeviceVerifier::new_with_tips(
            Arc::new(RwLock::new(HashSet::new())),
            tips(&[(&inception.aid.to_string(), &inception)]),
        );
        let cert = Ed25519DeviceCert::from_signing_key_with_admission(&attacker, &[their_rot])
            .expect("cert");
        assert!(v.check_cert(&cert.cert_der).is_err());
    }

    /// Offering nothing, offering junk, and offering events for a hosted identity that do not
    /// authorize you must be **indistinguishable**. A caller choosing these bytes must not be
    /// able to learn which check refused it — whether an identity is hosted here, and whether
    /// a chain nearly verified, are both things a stranger would probe for.
    #[test]
    fn every_refusal_reads_the_same() {
        let (inception, _, offered) = scenario();
        let stranger = ed25519_dalek::SigningKey::from_bytes(&[13u8; 32]);
        let v = PairedDeviceVerifier::new_with_tips(
            Arc::new(RwLock::new(HashSet::new())),
            tips(&[(&inception.aid.to_string(), &inception)]),
        );

        let nothing = Ed25519DeviceCert::from_signing_key(&stranger).expect("cert");
        // Valid events for a hosted identity, presented by a key they do not name.
        let wrong_key =
            Ed25519DeviceCert::from_signing_key_with_admission(&stranger, &offered).expect("cert");

        let a = v.check_cert(&nothing.cert_der).unwrap_err().to_string();
        let b = v.check_cert(&wrong_key.cert_der).unwrap_err().to_string();
        assert_eq!(a, b, "refusals must not be distinguishable");
        assert!(a.contains("recover"), "the refusal must name the command that fixes it");
    }

    /// A verifier that has learned a hosted chain, for the claim tests below.
    fn hosting(chain: &[kotton_wire::kel::KelEvent]) -> (Arc<PairedDeviceVerifier>, Admission) {
        let admission = Admission::default();
        admission.learn_chain(chain);
        let v = PairedDeviceVerifier::new_with_admission(
            Arc::new(RwLock::new(HashSet::new())),
            admission.clone(),
        );
        (v, admission)
    }

    /// The cold-device shape (`RFC-0081`): a device with no chain proves a recovery
    /// authority the hosted chain committed, and is admitted — to fetch, which the
    /// recorded verdict says.
    #[test]
    fn a_device_holding_only_the_phrase_is_admitted_on_a_recovery_claim() {
        let seed = [42u8; 32];
        let inception = build_user_inception(&seed);
        let (v, admission) = hosting(std::slice::from_ref(&inception));
        let device = ed25519_dalek::SigningKey::from_bytes(&[21u8; 32]);
        let reserve = ed25519_dalek::SigningKey::from_bytes(
            &kotton_crypto::kdf::derive_kel_recovery_key(&seed, 0),
        );
        let claim = RecoveryClaim::sign(&reserve, &device.verifying_key().to_bytes());
        let cert = Ed25519DeviceCert::from_signing_key_with_offer(&device, &CertOffer::claim(claim))
            .expect("cert");
        assert!(v.check_cert(&cert.cert_der).is_ok());
        assert_eq!(
            admission.admitted(&device.verifying_key().to_bytes()),
            Some(Admitted::ByClaim {
                aid: inception.aid.to_string()
            }),
            "the verdict names the identity the claim proved, and only a claim"
        );
    }

    /// An identity forgotten is a stranger at the handshake: the phrase-only
    /// device admitted above on a claim is refused once the node forgets the
    /// chain, and so is one proving the root — while another hosted identity's
    /// claim still admits.
    #[test]
    fn a_forgotten_identity_is_admitted_by_neither_claim_nor_proof() {
        let seed = [42u8; 32];
        let inception = build_user_inception(&seed);
        let other_seed = [43u8; 32];
        let other = build_user_inception(&other_seed);
        let (v, admission) = hosting(std::slice::from_ref(&inception));
        admission.learn_chain(std::slice::from_ref(&other));
        let claim_for = |seed: &[u8; 32], device: &ed25519_dalek::SigningKey| {
            let reserve = ed25519_dalek::SigningKey::from_bytes(
                &kotton_crypto::kdf::derive_kel_recovery_key(seed, 0),
            );
            let claim = RecoveryClaim::sign(&reserve, &device.verifying_key().to_bytes());
            Ed25519DeviceCert::from_signing_key_with_offer(device, &CertOffer::claim(claim)).expect("cert")
        };
        let device = ed25519_dalek::SigningKey::from_bytes(&[21u8; 32]);
        assert!(v.check_cert(&claim_for(&seed, &device).cert_der).is_ok());
        assert!(admission.admitted(&device.verifying_key().to_bytes()).is_some());
        let (_, recovered, offered) = scenario();
        let proof = Ed25519DeviceCert::from_signing_key_with_admission(&recovered, &offered).expect("cert");
        assert!(v.check_cert(&proof.cert_der).is_ok(), "proof of the root admits while it is hosted");

        admission.forget(&inception.aid.to_string());
        assert_eq!(
            admission.admitted(&device.verifying_key().to_bytes()),
            None,
            "a pending admission for the forgotten identity goes with it"
        );
        assert!(
            v.check_cert(&claim_for(&seed, &device).cert_der).is_err(),
            "a claim on a forgotten identity is refused"
        );
        assert_eq!(admission.admitted(&recovered.verifying_key().to_bytes()), None);
        assert!(v.check_cert(&proof.cert_der).is_err(), "and so is proof of its root");
        let neighbour = ed25519_dalek::SigningKey::from_bytes(&[24u8; 32]);
        assert!(
            v.check_cert(&claim_for(&other_seed, &neighbour).cert_der).is_ok(),
            "the identity not forgotten is still admitted"
        );
    }

    /// A claim is bound to the TLS key it was signed over: replayed from another
    /// device it is refused, and the refusal is the one every refusal gets.
    #[test]
    fn a_recovery_claim_replayed_from_another_device_reads_like_every_other_refusal() {
        let seed = [42u8; 32];
        let inception = build_user_inception(&seed);
        let (v, _) = hosting(std::slice::from_ref(&inception));
        let victim = ed25519_dalek::SigningKey::from_bytes(&[21u8; 32]);
        let thief = ed25519_dalek::SigningKey::from_bytes(&[22u8; 32]);
        let reserve = ed25519_dalek::SigningKey::from_bytes(
            &kotton_crypto::kdf::derive_kel_recovery_key(&seed, 0),
        );
        // Signed for the victim's key, presented under the thief's.
        let claim = RecoveryClaim::sign(&reserve, &victim.verifying_key().to_bytes());
        let replayed =
            Ed25519DeviceCert::from_signing_key_with_offer(&thief, &CertOffer::claim(claim))
                .expect("cert");
        // A claim by an authority no hosted chain committed.
        let unknown = ed25519_dalek::SigningKey::from_bytes(&[23u8; 32]);
        let unknown_claim = RecoveryClaim::sign(&unknown, &thief.verifying_key().to_bytes());
        let unhosted =
            Ed25519DeviceCert::from_signing_key_with_offer(&thief, &CertOffer::claim(unknown_claim))
                .expect("cert");
        let nothing = Ed25519DeviceCert::from_signing_key(&thief).expect("cert");

        let a = v.check_cert(&replayed.cert_der).unwrap_err().to_string();
        let b = v.check_cert(&unhosted.cert_der).unwrap_err().to_string();
        let c = v.check_cert(&nothing.cert_der).unwrap_err().to_string();
        assert_eq!(a, b, "a bad signature and an unknown authority must read the same");
        assert_eq!(b, c, "and the same as offering nothing at all");
    }

    /// Admission by proof records a verdict the handler can persist: the identity
    /// and the events, keyed by the key the handshake proved.
    #[test]
    fn admission_by_proof_records_what_the_handler_must_persist() {
        let (inception, recovered, offered) = scenario();
        let (v, admission) = hosting(std::slice::from_ref(&inception));
        let cert = Ed25519DeviceCert::from_signing_key_with_admission(&recovered, &offered)
            .expect("cert");
        assert!(v.check_cert(&cert.cert_der).is_ok());
        let key = recovered.verifying_key().to_bytes();
        assert_eq!(
            admission.take_admitted(&key),
            Some(Admitted::ByProof {
                aid: inception.aid.to_string(),
                events: offered
            })
        );
        assert_eq!(admission.take_admitted(&key), None, "taken once, gone");
    }

    /// A node holding no tips at all behaves exactly as it did before this existed.
    #[test]
    fn a_node_with_no_tips_is_unchanged() {
        let (_, recovered, offered) = scenario();
        let v = PairedDeviceVerifier::new(Arc::new(RwLock::new(HashSet::new())));
        let cert = Ed25519DeviceCert::from_signing_key_with_admission(&recovered, &offered)
            .expect("cert");
        assert!(v.check_cert(&cert.cert_der).is_err());
    }
}

/// Every peer connection is a full handshake, so the allowlist decides every one of them.
///
/// A resumed TLS 1.3 handshake carries neither side's certificate, and rustls does not consult
/// a verifier for a certificate that was not sent: it restores the one from the original
/// handshake. These drive the peer configs' plain-rustls form in memory, where
/// [`rustls::CommonState::handshake_kind`] says whether a handshake resumed. The QUIC configs
/// wrap these, and are held end to end in `quic::tests`.
#[cfg(test)]
mod resumption_tests {
    use super::*;
    use rustls::{ClientConnection, ConnectionCommon, HandshakeKind, ServerConnection};

    fn provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    /// Two devices paired with each other: each side's allowlist names the other.
    struct Pair {
        server: Ed25519DeviceCert,
        client: Ed25519DeviceCert,
        server_allows: Arc<RwLock<HashSet<[u8; 32]>>>,
        client_allows: Arc<RwLock<HashSet<[u8; 32]>>>,
    }

    impl Pair {
        fn new() -> Self {
            let cert = |seed| {
                let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
                Ed25519DeviceCert::from_signing_key(&key).unwrap()
            };
            let (server, client) = (cert(3u8), cert(4u8));
            let server_allows = Arc::new(RwLock::new(HashSet::from([client.public_key_bytes])));
            let client_allows = Arc::new(RwLock::new(HashSet::from([server.public_key_bytes])));
            Self { server, client, server_allows, client_allows }
        }

        fn server_config(&self) -> rustls::ServerConfig {
            let verifier = PairedDeviceVerifier::new(Arc::clone(&self.server_allows));
            build_peer_rustls_server_config(&self.server, verifier, provider()).unwrap()
        }

        fn client_config(&self) -> rustls::ClientConfig {
            let verifier = PairedDeviceVerifier::new(Arc::clone(&self.client_allows));
            build_peer_rustls_client_config(&self.client, verifier, provider()).unwrap()
        }
    }

    /// A server that stores sessions and issues tickets for them: rustls' default, and what
    /// a peer built any other way may still do.
    fn issuing_tickets(mut config: rustls::ServerConfig) -> rustls::ServerConfig {
        config.session_storage = rustls::server::ServerSessionMemoryCache::new(256);
        config.send_tls13_tickets = 2;
        config
    }

    /// A client that keeps the tickets it is issued and offers them again: rustls' default.
    fn keeping_tickets(mut config: rustls::ClientConfig) -> rustls::ClientConfig {
        config.resumption = rustls::client::Resumption::default();
        config
    }

    /// Move everything `from` has to send into `to`. False when there was nothing to send.
    pub(super) fn deliver<A, B>(
        from: &mut ConnectionCommon<A>,
        to: &mut ConnectionCommon<B>,
    ) -> Result<bool, rustls::Error> {
        let mut wire = Vec::new();
        while from.wants_write() {
            from.write_tls(&mut wire).unwrap();
        }
        let mut unread = &wire[..];
        while !unread.is_empty() {
            to.read_tls(&mut unread).unwrap();
            to.process_new_packets()?;
        }
        Ok(!wire.is_empty())
    }

    /// One connection, run until neither side has anything left to say, so that any ticket
    /// the server issues after the handshake reaches the client. The kind of handshake both
    /// sides agree they had, or the refusal.
    pub(super) fn connect(
        client: &Arc<rustls::ClientConfig>,
        server: &Arc<rustls::ServerConfig>,
    ) -> Result<HandshakeKind, rustls::Error> {
        let mut c = ClientConnection::new(Arc::clone(client), "localhost".try_into().unwrap())?;
        let mut s = ServerConnection::new(Arc::clone(server))?;
        while deliver(&mut c, &mut s)? | deliver(&mut s, &mut c)? {}
        assert!(!c.is_handshaking() && !s.is_handshaking());
        assert_eq!(c.handshake_kind(), s.handshake_kind());
        Ok(s.handshake_kind().unwrap())
    }

    /// The premise the rest stand on. Were the peer configs to resume, a device the server
    /// revoked after its first connection would be admitted on its second, with the allowlist
    /// never asked. If rustls ever re-verifies on resumption this fails, and the reason the
    /// peer configs refuse to resume is gone with it.
    #[test]
    fn a_resumed_handshake_is_not_shown_to_the_verifier() {
        let pair = Pair::new();
        let server = Arc::new(issuing_tickets(pair.server_config()));
        let client = Arc::new(keeping_tickets(pair.client_config()));

        assert_eq!(connect(&client, &server).unwrap(), HandshakeKind::Full);
        pair.server_allows.write().unwrap().remove(&pair.client.public_key_bytes);
        assert_eq!(connect(&client, &server).unwrap(), HandshakeKind::Resumed);
    }

    #[test]
    fn a_reconnection_between_peers_is_a_full_handshake() {
        let pair = Pair::new();
        let server = Arc::new(pair.server_config());
        let client = Arc::new(pair.client_config());

        assert_eq!(connect(&client, &server).unwrap(), HandshakeKind::Full);
        assert_eq!(connect(&client, &server).unwrap(), HandshakeKind::Full);
    }

    /// The server holds its own allowlist whatever the client keeps: it stores no session, so
    /// a client offering one is met with a full handshake and its certificate is checked.
    #[test]
    fn a_revoked_device_that_kept_its_session_is_refused_on_reconnection() {
        let pair = Pair::new();
        let server = Arc::new(pair.server_config());
        let client = Arc::new(keeping_tickets(pair.client_config()));

        assert_eq!(connect(&client, &server).unwrap(), HandshakeKind::Full);
        pair.server_allows.write().unwrap().remove(&pair.client.public_key_bytes);
        assert!(connect(&client, &server).is_err());
    }

    /// The client holds its own allowlist whatever the server issues: it keeps no ticket, so
    /// it never offers one, and the server it revoked must present its certificate again.
    #[test]
    fn a_revoked_server_that_issued_a_ticket_is_refused_on_reconnection() {
        let pair = Pair::new();
        let server = Arc::new(issuing_tickets(pair.server_config()));
        let client = Arc::new(pair.client_config());

        assert_eq!(connect(&client, &server).unwrap(), HandshakeKind::Full);
        pair.client_allows.write().unwrap().remove(&pair.server.public_key_bytes);
        assert!(connect(&client, &server).is_err());
    }
}

/// The handshake holds the peer's key and its signature to the Ed25519 rule, in both
/// directions and for both verifiers: a certificate under a key the rule refuses, and a
/// `CertificateVerify` signature the rule refuses under an admitted key, end the handshake.
///
/// A test-only signer puts whatever 64 bytes a case needs into the handshake, under whatever
/// key its certificate names, so each refusal is the verifier's and not the signer's. Each
/// test first completes the same handshake with an honest signature, to show the harness is
/// not what refuses.
#[cfg(test)]
mod rule_tests {
    use super::resumption_tests::connect;
    use super::*;
    use kotton_crypto::ed25519::refused;

    fn provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    /// What a test signer puts in the handshake for the message it is handed.
    type Forge = Arc<dyn Fn(&[u8]) -> [u8; 64] + Send + Sync>;

    /// A rustls signing key that signs by [`Forge`] and labels its signature with the scheme
    /// it carries, whatever the peer offered.
    #[derive(Clone)]
    struct Forger(Forge, rustls::SignatureScheme);

    impl Forger {
        fn ed25519(forge: Forge) -> Self {
            Self(forge, rustls::SignatureScheme::ED25519)
        }
    }

    impl std::fmt::Debug for Forger {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("Forger")
        }
    }

    impl rustls::sign::SigningKey for Forger {
        fn choose_scheme(&self, _offered: &[rustls::SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
            Some(Box::new(self.clone()))
        }

        fn algorithm(&self) -> rustls::SignatureAlgorithm {
            rustls::SignatureAlgorithm::ED25519
        }
    }

    impl rustls::sign::Signer for Forger {
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
            Ok((self.0)(message).to_vec())
        }

        fn scheme(&self) -> rustls::SignatureScheme {
            self.1
        }
    }

    /// An rcgen key that names `public` and signs the certificate with zeros: nothing here
    /// checks a peer certificate's own signature, only the handshake's.
    struct Named([u8; 32]);

    impl rcgen::RemoteKeyPair for Named {
        fn public_key(&self) -> &[u8] {
            &self.0
        }

        fn sign(&self, _msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
            Ok(vec![0; 64])
        }

        fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
            &rcgen::PKCS_ED25519
        }
    }

    /// A certificate under `public`, carrying `offer`, as a peer certificate is built.
    fn cert_under(public: [u8; 32], offer: &CertOffer) -> CertificateDer<'static> {
        let key = rcgen::KeyPair::from_remote(Box::new(Named(public))).unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["kotton-device".to_string()]).unwrap();
        if let Some(claim) = &offer.claim {
            params.custom_extensions.push(rcgen::CustomExtension::from_oid_content(
                Ed25519DeviceCert::RECOVERY_CLAIM_OID,
                der_octet_string(&serde_json::to_vec(claim).unwrap()),
            ));
        }
        CertificateDer::from(params.self_signed(&key).unwrap().der().to_vec())
    }

    /// The certificate and signer of a peer presenting `public` and signing by `forge`.
    fn forged(public: [u8; 32], forge: Forge) -> Arc<rustls::sign::CertifiedKey> {
        Arc::new(rustls::sign::CertifiedKey::new(
            vec![cert_under(public, &CertOffer::default())],
            Arc::new(Forger::ed25519(forge)),
        ))
    }

    /// A signer that signs honestly with `key`.
    fn honestly(key: &ed25519_dalek::SigningKey) -> Forge {
        use ed25519_dalek::Signer as _;
        let key = key.clone();
        Arc::new(move |m| key.sign(m).to_bytes())
    }

    /// A signature over `message` under [`refused::mixed_order_key`] that satisfies the
    /// equation without the cofactor and whose `R` is of prime order: a signature check
    /// alone accepts it, so only the key's construction refuses it.
    ///
    /// The key is `A + T`, the honest key of the seed `[42; 32]` plus a point of order eight.
    /// A nonce is drawn until the challenge `k` is a multiple of eight, so `[k]T` is the
    /// identity and `[S]B - [k](A + T) = R`.
    fn under_mixed_order_key(message: &[u8]) -> [u8; 64] {
        use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};
        use sha2::{Digest as _, Sha512};
        let a = ed25519_dalek::SigningKey::from_bytes(&[42; 32]).to_scalar();
        let key = refused::mixed_order_key();
        for nonce in 0u64.. {
            let wide: [u8; 64] = Sha512::new().chain_update(nonce.to_le_bytes()).chain_update(message).finalize().into();
            let r = Scalar::from_bytes_mod_order_wide(&wide);
            let big_r = EdwardsPoint::mul_base(&r).compress();
            let wide: [u8; 64] =
                Sha512::new().chain_update(big_r.as_bytes()).chain_update(key).chain_update(message).finalize().into();
            let k = Scalar::from_bytes_mod_order_wide(&wide);
            if k.as_bytes()[0] & 7 != 0 {
                continue;
            }
            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(big_r.as_bytes());
            sig[32..].copy_from_slice((r + k * a).as_bytes());
            return sig;
        }
        unreachable!()
    }

    /// The signature a case puts under the refused key `public`: for the identity, the one a
    /// check without the small-order clauses accepts over any message; for the mixed-order
    /// key, [`under_mixed_order_key`]; for the others, the same bytes as the identity's,
    /// since no signature is any of theirs.
    fn under_refused(public: [u8; 32]) -> Forge {
        if public == refused::mixed_order_key() {
            Arc::new(under_mixed_order_key)
        } else {
            Arc::new(|_| refused::under_small_order_key_bytes())
        }
    }

    /// Every key the rule refuses, each named with its clause.
    fn refused_keys() -> Vec<(String, [u8; 32])> {
        let small = [
            "identity",
            "order two",
            "order four, x positive",
            "order four, x negative",
            "order eight, a",
            "order eight, a negated",
            "order eight, b",
            "order eight, b negated",
        ];
        small
            .iter()
            .map(|n| format!("small order: {n}"))
            .zip(refused::SMALL_ORDER_KEYS)
            .chain(
                ["identity, y = 1 with the sign bit", "identity, y = p + 1", "identity, y = p + 1 with the sign bit"]
                    .map(String::from)
                    .into_iter()
                    .zip(refused::IDENTITY_OTHER_ENCODINGS),
            )
            .chain([
                ("mixed order".to_string(), refused::mixed_order_key()),
                ("not canonical".to_string(), refused::NON_CANONICAL_KEY),
                ("not a point".to_string(), refused::NOT_A_POINT),
            ])
            .collect()
    }

    /// Every signature the rule refuses under an honest `key`, each named with its clause.
    fn refused_signatures(key: &ed25519_dalek::SigningKey) -> Vec<(&'static str, Forge)> {
        let (a, b) = (key.clone(), key.clone());
        vec![
            ("R of small order", Arc::new(move |m: &[u8]| refused::small_order_r(&a, m).to_bytes())),
            ("S not reduced", Arc::new(move |m: &[u8]| refused::unreduced_s(&b, m).to_bytes())),
        ]
    }

    /// Which verifier a case puts on the side that checks.
    #[derive(Clone, Copy)]
    enum Verifier {
        Paired,
        Bootstrap,
    }

    /// The verifier, admitting `admit` by allowlist where it keeps one.
    fn server_verifier(v: Verifier, admit: [u8; 32]) -> Arc<dyn rustls::server::danger::ClientCertVerifier> {
        match v {
            Verifier::Paired => PairedDeviceVerifier::new(Arc::new(RwLock::new(HashSet::from([admit])))),
            Verifier::Bootstrap => BootstrapCertVerifier::new(),
        }
    }

    fn client_verifier(v: Verifier, admit: [u8; 32]) -> Arc<dyn rustls::client::danger::ServerCertVerifier> {
        match v {
            Verifier::Paired => PairedDeviceVerifier::new(Arc::new(RwLock::new(HashSet::from([admit])))),
            Verifier::Bootstrap => BootstrapCertVerifier::new(),
        }
    }

    fn honest_cert(key: &ed25519_dalek::SigningKey) -> Arc<rustls::sign::CertifiedKey> {
        let cert = Ed25519DeviceCert::from_signing_key(key).unwrap();
        Arc::new(rustls::sign::CertifiedKey::new(vec![cert.cert_der.clone()], Arc::new(Forger::ed25519(honestly(key)))))
    }

    fn server_config(
        verifier: Arc<dyn rustls::server::danger::ClientCertVerifier>,
        presents: Arc<rustls::sign::CertifiedKey>,
    ) -> Arc<rustls::ServerConfig> {
        let config = rustls::ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(presents)));
        Arc::new(config)
    }

    fn client_config(
        verifier: Arc<dyn rustls::client::danger::ServerCertVerifier>,
        presents: Arc<rustls::sign::CertifiedKey>,
    ) -> Arc<rustls::ClientConfig> {
        let config = rustls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(presents)));
        Arc::new(config)
    }

    /// A handshake in which the server checks a client presenting `public` and signing by
    /// `forge`; the server's verifier admits `public` where it keeps an allowlist.
    fn server_checks(v: Verifier, public: [u8; 32], forge: Forge) -> Result<rustls::HandshakeKind, rustls::Error> {
        let server_key = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let server = server_config(server_verifier(v, public), honest_cert(&server_key));
        let client = client_config(
            client_verifier(v, server_key.verifying_key().to_bytes()),
            forged(public, forge),
        );
        connect(&client, &server)
    }

    /// A handshake in which the client checks a server presenting `public` and signing by
    /// `forge`; the client's verifier admits `public` where it keeps an allowlist.
    fn client_checks(v: Verifier, public: [u8; 32], forge: Forge) -> Result<rustls::HandshakeKind, rustls::Error> {
        let client_key = ed25519_dalek::SigningKey::from_bytes(&[4; 32]);
        let server = server_config(
            server_verifier(v, client_key.verifying_key().to_bytes()),
            forged(public, forge),
        );
        let client = client_config(client_verifier(v, public), honest_cert(&client_key));
        connect(&client, &server)
    }

    type Handshake = fn(Verifier, [u8; 32], Forge) -> Result<rustls::HandshakeKind, rustls::Error>;

    /// Each refused key, presented by the side `handshake` checks, ends the handshake; an
    /// honest key and signature in the same place complete it.
    fn refuses_every_refused_key(v: Verifier, handshake: Handshake) {
        let honest = ed25519_dalek::SigningKey::from_bytes(&[5; 32]);
        handshake(v, honest.verifying_key().to_bytes(), honestly(&honest)).expect("an honest peer is admitted");
        let admitted: Vec<String> = refused_keys()
            .into_iter()
            .filter(|(_, public)| handshake(v, *public, under_refused(*public)).is_ok())
            .map(|(name, _)| name)
            .collect();
        assert!(admitted.is_empty(), "the handshake admitted a key the rule refuses: {admitted:?}");
    }

    /// Each refused signature by an admitted key ends the handshake.
    fn refuses_every_refused_signature(v: Verifier, handshake: Handshake) {
        let honest = ed25519_dalek::SigningKey::from_bytes(&[5; 32]);
        let public = honest.verifying_key().to_bytes();
        handshake(v, public, honestly(&honest)).expect("an honest peer is admitted");
        let admitted: Vec<&str> = refused_signatures(&honest)
            .into_iter()
            .filter(|(_, forge)| handshake(v, public, Arc::clone(forge)).is_ok())
            .map(|(name, _)| name)
            .collect();
        assert!(admitted.is_empty(), "the handshake accepted a signature the rule refuses: {admitted:?}");
    }

    /// The mixed-order case is the one a signature check alone would pass: its signature
    /// satisfies the equation without the cofactor, and its `R` is not of small order.
    #[test]
    fn the_mixed_order_signature_satisfies_the_equation_and_only_the_key_is_refused() {
        use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
        use curve25519_dalek::scalar::Scalar;
        use sha2::{Digest as _, Sha512};
        let message = b"a handshake transcript";
        let sig = under_mixed_order_key(message);
        let key = refused::mixed_order_key();
        let a = CompressedEdwardsY(key).decompress().unwrap();
        let r = CompressedEdwardsY(sig[..32].try_into().unwrap()).decompress().unwrap();
        let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(sig[32..].try_into().unwrap())).expect("S is reduced");
        let wide: [u8; 64] = Sha512::new().chain_update(&sig[..32]).chain_update(key).chain_update(message).finalize().into();
        let k = Scalar::from_bytes_mod_order_wide(&wide);
        assert_eq!(EdwardsPoint::mul_base(&s) - k * a, r);
        assert!(!r.is_small_order() && !a.is_small_order());
        assert_eq!(VerifyingKey::from_bytes(&key), Err(kotton_crypto::ed25519::Refused));
    }

    #[test]
    fn a_paired_server_refuses_a_client_presenting_a_key_the_rule_refuses() {
        refuses_every_refused_key(Verifier::Paired, server_checks);
    }

    #[test]
    fn a_paired_client_refuses_a_server_presenting_a_key_the_rule_refuses() {
        refuses_every_refused_key(Verifier::Paired, client_checks);
    }

    #[test]
    fn a_bootstrap_server_refuses_a_client_presenting_a_key_the_rule_refuses() {
        refuses_every_refused_key(Verifier::Bootstrap, server_checks);
    }

    #[test]
    fn a_bootstrap_client_refuses_a_server_presenting_a_key_the_rule_refuses() {
        refuses_every_refused_key(Verifier::Bootstrap, client_checks);
    }

    #[test]
    fn a_paired_server_refuses_a_handshake_signature_the_rule_refuses_under_an_admitted_key() {
        refuses_every_refused_signature(Verifier::Paired, server_checks);
    }

    #[test]
    fn a_paired_client_refuses_a_handshake_signature_the_rule_refuses_under_an_admitted_key() {
        refuses_every_refused_signature(Verifier::Paired, client_checks);
    }

    #[test]
    fn a_bootstrap_server_refuses_a_handshake_signature_the_rule_refuses() {
        refuses_every_refused_signature(Verifier::Bootstrap, server_checks);
    }

    #[test]
    fn a_bootstrap_client_refuses_a_handshake_signature_the_rule_refuses() {
        refuses_every_refused_signature(Verifier::Bootstrap, client_checks);
    }

    /// An honest Ed25519 signature by an admitted key, labelled with any other scheme, ends the
    /// handshake in both directions for both verifiers: the TLS library hands a verifier the
    /// scheme the peer named, and only Ed25519 is checked.
    #[test]
    fn a_handshake_signature_labelled_with_another_scheme_is_refused() {
        let honest = ed25519_dalek::SigningKey::from_bytes(&[5; 32]);
        let public = honest.verifying_key().to_bytes();
        let cert = || cert_under(public, &CertOffer::default());
        let other = |scheme| Arc::new(rustls::sign::CertifiedKey::new(vec![cert()], Arc::new(Forger(honestly(&honest), scheme))));
        let peer = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let mut accepted = Vec::new();
        for v in [Verifier::Paired, Verifier::Bootstrap] {
            for scheme in [rustls::SignatureScheme::ED25519, rustls::SignatureScheme::ECDSA_NISTP256_SHA256, rustls::SignatureScheme::ED448] {
                let as_client = connect(
                    &client_config(client_verifier(v, peer.verifying_key().to_bytes()), other(scheme)),
                    &server_config(server_verifier(v, public), honest_cert(&peer)),
                );
                let as_server = connect(
                    &client_config(client_verifier(v, public), honest_cert(&peer)),
                    &server_config(server_verifier(v, peer.verifying_key().to_bytes()), other(scheme)),
                );
                if scheme == rustls::SignatureScheme::ED25519 {
                    as_client.expect("labelled Ed25519, the client is admitted");
                    as_server.expect("labelled Ed25519, the server is admitted");
                    continue;
                }
                if as_client.is_ok() {
                    accepted.push(format!("{scheme:?} from a client"));
                }
                if as_server.is_ok() {
                    accepted.push(format!("{scheme:?} from a server"));
                }
            }
        }
        assert!(accepted.is_empty(), "accepted under another scheme: {accepted:?}");
    }

    /// A certificate that is not Ed25519 completes no bootstrap handshake, from either side.
    #[test]
    fn a_bootstrap_verifier_refuses_a_certificate_that_is_not_ed25519() {
        let (ecdsa_cert, ecdsa_key) = generate_self_signed_cert().unwrap();
        let ed = ed25519_dalek::SigningKey::from_bytes(&[6; 32]);

        let server = rustls::ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier(BootstrapCertVerifier::new())
            .with_single_cert(vec![ecdsa_cert.clone()], ecdsa_key.clone_key())
            .unwrap();
        let client = client_config(BootstrapCertVerifier::new(), honest_cert(&ed));
        assert!(connect(&Arc::new(client.as_ref().clone()), &Arc::new(server)).is_err());

        let server = server_config(BootstrapCertVerifier::new(), honest_cert(&ed));
        let client = rustls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(BootstrapCertVerifier::new())
            .with_client_auth_cert(vec![ecdsa_cert], ecdsa_key)
            .unwrap();
        assert!(connect(&Arc::new(client), &server).is_err());
    }

    /// A paired server hosting an identity whose recovery authorities `authorities` names,
    /// facing a device with no allowlist entry whose certificate carries `claim`. The
    /// handshake's outcome, and whether the server recorded an admission.
    fn claim_at_the_handshake(
        authorities: &[[u8; 32]],
        claim: RecoveryClaim,
    ) -> (Result<rustls::HandshakeKind, rustls::Error>, bool) {
        let server_key = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let device = ed25519_dalek::SigningKey::from_bytes(&[21; 32]);
        let admission = Admission::default();
        for a in authorities {
            admission.authorities.write().unwrap().insert(*a, "did:example:hosted".to_string());
        }
        let verifier = PairedDeviceVerifier::new_with_admission(Arc::new(RwLock::new(HashSet::new())), admission.clone());
        let server = server_config(verifier, honest_cert(&server_key));
        let device_cert = Ed25519DeviceCert::from_signing_key_with_offer(&device, &CertOffer::claim(claim)).unwrap();
        let client = client_config(
            client_verifier(Verifier::Paired, server_key.verifying_key().to_bytes()),
            Arc::new(rustls::sign::CertifiedKey::new(vec![device_cert.cert_der], Arc::new(Forger::ed25519(honestly(&device))))),
        );
        let outcome = connect(&client, &server);
        (outcome, admission.admitted(&device.verifying_key().to_bytes()).is_some())
    }

    fn device_pub() -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(&[21; 32]).verifying_key().to_bytes()
    }

    /// A recovery claim under a reserve key the rule refuses admits no device at the
    /// handshake, though the node holds that key as an authority; an honest claim does.
    #[test]
    fn a_recovery_claim_under_a_reserve_key_the_rule_refuses_admits_no_device_at_the_handshake() {
        let reserve = ed25519_dalek::SigningKey::from_bytes(&[4; 32]);
        let (honest, recorded) = claim_at_the_handshake(
            &[reserve.verifying_key().to_bytes()],
            RecoveryClaim::sign(&reserve, &device_pub()),
        );
        assert!(honest.is_ok() && recorded, "an honest claim admits");

        let message = RecoveryClaim::message(&device_pub());
        let admitted: Vec<String> = refused_keys()
            .into_iter()
            .filter(|(_, public)| {
                let claim = RecoveryClaim { reserve_pub: *public, sig: under_refused(*public)(&message).to_vec() };
                let (outcome, recorded) = claim_at_the_handshake(&[*public], claim);
                outcome.is_ok() || recorded
            })
            .map(|(name, _)| name)
            .collect();
        assert!(admitted.is_empty(), "a claim under a refused reserve key admitted a device: {admitted:?}");
    }

    /// A recovery claim whose signature the rule refuses admits no device at the handshake.
    #[test]
    fn a_recovery_claim_signature_the_rule_refuses_admits_no_device_at_the_handshake() {
        let reserve = ed25519_dalek::SigningKey::from_bytes(&[4; 32]);
        let message = RecoveryClaim::message(&device_pub());
        let admitted: Vec<&str> = refused_signatures(&reserve)
            .into_iter()
            .filter(|(_, forge)| {
                let claim = RecoveryClaim { reserve_pub: reserve.verifying_key().to_bytes(), sig: forge(&message).to_vec() };
                let (outcome, recorded) = claim_at_the_handshake(&[reserve.verifying_key().to_bytes()], claim);
                outcome.is_ok() || recorded
            })
            .map(|(name, _)| name)
            .collect();
        assert!(admitted.is_empty(), "a refused claim signature admitted a device: {admitted:?}");
    }
}
