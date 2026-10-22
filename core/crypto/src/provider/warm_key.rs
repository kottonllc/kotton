// SPDX-License-Identifier: AGPL-3.0-or-later
//! Warm device key delegation verification (RFC-0031 / RFC-0033).
//!
//! A **warm device key** is a short-lived Ed25519 keypair that performs routine
//! operations on the user's behalf (signing `GrantEnvelope`s, session/peer auth)
//! so the root FROST quorum is not touched on every action. Each device's warm
//! key is authorised by a [`WarmKeyDelegation`] the root quorum signs at
//! enrollment.
//!
//! The [`WarmKeyDelegation`] wire type (tier 02) carries data only; its doc
//! comment points verification at "a higher tier that has crypto" — this module
//! is that tier. Every consumer that is about to trust a warm key (the
//! `grant_check.rs` chain walk, peer authentication, session unlock) calls
//! [`verify_warm_key_delegation`] first.
//!
//! Verification is the named privilege-escalation surface in RFC-0031: the check
//! order is fixed and each step is a hard reject, so a delegation is trusted only
//! when it is bound to the expected root, self-consistent, unexpired, and signed
//! by the root quorum.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey};
use kotton_wire::did::Did;
use kotton_wire::WarmKeyDelegation;

use crate::did::DidKeyMethod;

/// Why a warm-key delegation failed verification.
///
/// Each variant is a typed reason so callers — and tests — can assert the exact
/// failure rather than a boolean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WarmKeyDenied {
    /// `delegation.root_did` is not the root identity the caller expected — a
    /// cross-identity delegation. Rejected before any signature work.
    WrongRoot,
    /// `delegation.warm_did` does not equal `did:key(delegation.warm_pubkey)`:
    /// the signed DID and the denormalised public key disagree.
    InconsistentWarmKey,
    /// `now_secs` is past `delegation.expires_at`.
    Expired,
    /// The expected root DID could not be decoded to a verifying key.
    BadRootDid,
    /// The quorum signature is malformed, the wrong length, or does not verify
    /// over `signing_message()` under the root key.
    BadQuorumSignature,
}

impl std::fmt::Display for WarmKeyDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WarmKeyDenied::WrongRoot => {
                write!(f, "warm-key delegation is bound to a different root identity")
            }
            WarmKeyDenied::InconsistentWarmKey => {
                write!(f, "warm_did does not match the delegated warm public key")
            }
            WarmKeyDenied::Expired => write!(f, "warm-key delegation has expired"),
            WarmKeyDenied::BadRootDid => write!(f, "root DID could not be decoded to a key"),
            WarmKeyDenied::BadQuorumSignature => {
                write!(f, "warm-key delegation quorum signature did not verify")
            }
        }
    }
}

impl std::error::Error for WarmKeyDenied {}

/// Verify a warm-key delegation against the expected root identity at `now_secs`.
///
/// Checks, in this fixed order (each a hard reject — see RFC-0033 §"Warm-key
/// delegation verification"):
///
/// 1. `delegation.root_did == expected_root_did` — no cross-identity delegation.
/// 2. `delegation.warm_did == did:key(delegation.warm_pubkey)` — self-consistent.
/// 3. `now_secs <= delegation.expires_at` — not expired.
/// 4. `quorum_signature` verifies over `signing_message()` under the root key.
///
/// On `Ok(())` the caller may trust `delegation.warm_did` / `warm_pubkey` as a
/// routine-operations authority delegated by the user's root quorum. The root
/// key is the FROST group verifying key (a standard Ed25519 key), so this is a
/// plain Ed25519 verification — a FROST aggregate signature verifies identically.
pub fn verify_warm_key_delegation(
    delegation: &WarmKeyDelegation,
    expected_root_did: &Did,
    now_secs: i64,
) -> Result<(), WarmKeyDenied> {
    // 1. Root binding — reject a delegation from any other identity first.
    if &delegation.root_did != expected_root_did {
        return Err(WarmKeyDenied::WrongRoot);
    }

    // 2. The signed warm_did must match the denormalised warm public key, or the
    //    quorum signed a different key than this delegation claims to carry.
    let derived_warm_did = DidKeyMethod::from_public_key_bytes(&delegation.warm_pubkey)
        .map_err(|_| WarmKeyDenied::InconsistentWarmKey)?;
    if derived_warm_did != delegation.warm_did {
        return Err(WarmKeyDenied::InconsistentWarmKey);
    }

    // 3. Expiry.
    if now_secs > delegation.expires_at {
        return Err(WarmKeyDenied::Expired);
    }

    // 4. Quorum signature over the canonical message under the root key.
    let root_key =
        DidKeyMethod::to_public_key(expected_root_did).map_err(|_| WarmKeyDenied::BadRootDid)?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(&delegation.quorum_signature)
        .map_err(|_| WarmKeyDenied::BadQuorumSignature)?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| WarmKeyDenied::BadQuorumSignature)?;
    let signature = Signature::from_bytes(&sig_arr);
    root_key
        // verify_strict rejects malleable / non-canonical signatures and
        // small-order keys on this identity-delegation path (audit).
        .verify_strict(delegation.signing_message().as_bytes(), &signature)
        .map_err(|_| WarmKeyDenied::BadQuorumSignature)?;

    Ok(())
}

/// Issue a warm-key delegation by signing it with a **single** root key — the
/// 1-of-1 / device-1 bootstrap case (the root identity is one mnemonic-derived
/// Ed25519 key). The root signs `signing_message()` over the warm key's identity
/// and expiry; the result verifies under [`verify_warm_key_delegation`].
///
/// For the n≥2 FROST case the quorum produces the same 64-byte Ed25519 signature
/// via `frost::aggregate` — build the delegation with an empty `quorum_signature`,
/// FROST-sign `signing_message()`, and set the base64url-encoded result. The
/// verifier cannot tell the two apart (a FROST aggregate is a standard Ed25519
/// signature), which is the whole point.
///
/// # Errors
/// Returns an error only if `warm_pubkey` is not a valid Ed25519 public key.
pub fn issue_warm_key_delegation(
    root_key: &SigningKey,
    warm_pubkey: &[u8; 32],
    expires_at: i64,
) -> anyhow::Result<WarmKeyDelegation> {
    let warm_did = DidKeyMethod::from_public_key_bytes(warm_pubkey)?;
    let root_did = DidKeyMethod::from_public_key(&root_key.verifying_key());

    let mut delegation = WarmKeyDelegation {
        warm_did,
        warm_pubkey: *warm_pubkey,
        expires_at,
        root_did,
        quorum_signature: String::new(),
    };
    let sig = root_key.sign(delegation.signing_message().as_bytes());
    delegation.quorum_signature = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    Ok(delegation)
}

/// The canonical message the root signs to bind a FROST **share** to a **warm
/// key** at enrollment (RFC-0033):
/// `"kotton:enroll-cert:v1\n{share_hex}\n{warm_pubkey_hex}"`.
///
/// The [`WarmKeyDelegation`] binds warm-key ↔ root; this certificate adds
/// share ↔ warm-key, closing the triangle so a valid delegation cannot be paired
/// with a foreign share.
pub fn enrollment_cert_message(share_hex: &str, warm_pubkey: &[u8; 32]) -> String {
    format!(
        "kotton:enroll-cert:v1\n{}\n{}",
        share_hex,
        hex::encode(warm_pubkey)
    )
}

/// Sign the enrollment certificate with the root key (the issuer's 1-of-1 key in
/// the bootstrap; a FROST aggregate at n≥2). Returns the base64url signature for
/// `PairingPayload::FrostShare::quorum_certificate`.
pub fn sign_enrollment_cert(root_key: &SigningKey, share_hex: &str, warm_pubkey: &[u8; 32]) -> String {
    let sig = root_key.sign(enrollment_cert_message(share_hex, warm_pubkey).as_bytes());
    URL_SAFE_NO_PAD.encode(sig.to_bytes())
}

/// Verify an enrollment certificate binds `share_hex` to `warm_pubkey` under the
/// root identity `root_did`. Reuses [`WarmKeyDenied`] reasons.
pub fn verify_enrollment_cert(
    cert: &str,
    root_did: &Did,
    share_hex: &str,
    warm_pubkey: &[u8; 32],
) -> Result<(), WarmKeyDenied> {
    let root_key = DidKeyMethod::to_public_key(root_did).map_err(|_| WarmKeyDenied::BadRootDid)?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(cert)
        .map_err(|_| WarmKeyDenied::BadQuorumSignature)?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| WarmKeyDenied::BadQuorumSignature)?;
    let signature = Signature::from_bytes(&sig_arr);
    root_key
        .verify_strict(
            enrollment_cert_message(share_hex, warm_pubkey).as_bytes(),
            &signature,
        )
        .map_err(|_| WarmKeyDenied::BadQuorumSignature)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    /// Deterministic Ed25519 key from a fixed seed byte.
    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// Build a delegation via the real issuance path — so the verify tests also
    /// exercise `issue_warm_key_delegation`. (`root_key` stands in for the FROST
    /// quorum; in the 1-of-1 case it literally is the root.)
    fn make_delegation(root_key: &SigningKey, warm_key: &SigningKey, expires_at: i64) -> WarmKeyDelegation {
        issue_warm_key_delegation(root_key, &warm_key.verifying_key().to_bytes(), expires_at)
            .expect("valid warm pubkey")
    }

    #[test]
    fn valid_delegation_verifies() {
        let root = key(1);
        let warm = key(2);
        let d = make_delegation(&root, &warm, 9_999_999_999);
        let root_did = DidKeyMethod::from_public_key(&root.verifying_key());
        assert_eq!(verify_warm_key_delegation(&d, &root_did, 1_000), Ok(()));
    }

    #[test]
    fn rejects_wrong_root() {
        let root = key(1);
        let warm = key(2);
        let d = make_delegation(&root, &warm, 9_999_999_999);
        // Verify against a different root identity.
        let other_root_did = DidKeyMethod::from_public_key(&key(42).verifying_key());
        assert_eq!(
            verify_warm_key_delegation(&d, &other_root_did, 1_000),
            Err(WarmKeyDenied::WrongRoot)
        );
    }

    #[test]
    fn rejects_expired() {
        let root = key(1);
        let warm = key(2);
        let d = make_delegation(&root, &warm, 500); // expired in the past
        let root_did = DidKeyMethod::from_public_key(&root.verifying_key());
        assert_eq!(
            verify_warm_key_delegation(&d, &root_did, 1_000), // now > expires_at
            Err(WarmKeyDenied::Expired)
        );
    }

    #[test]
    fn rejects_tampered_signature() {
        let root = key(1);
        let warm = key(2);
        let mut d = make_delegation(&root, &warm, 9_999_999_999);
        d.quorum_signature = URL_SAFE_NO_PAD.encode([0u8; 64]);
        let root_did = DidKeyMethod::from_public_key(&root.verifying_key());
        assert_eq!(
            verify_warm_key_delegation(&d, &root_did, 1_000),
            Err(WarmKeyDenied::BadQuorumSignature)
        );
    }

    #[test]
    fn rejects_signature_by_non_root() {
        // A delegation signed by some key other than the root quorum must fail,
        // even though it is otherwise well-formed and bound to the right root_did.
        let root = key(1);
        let warm = key(2);
        let impostor = key(3);
        let mut d = make_delegation(&root, &warm, 9_999_999_999);
        let forged = impostor.sign(d.signing_message().as_bytes());
        d.quorum_signature = URL_SAFE_NO_PAD.encode(forged.to_bytes());
        let root_did = DidKeyMethod::from_public_key(&root.verifying_key());
        assert_eq!(
            verify_warm_key_delegation(&d, &root_did, 1_000),
            Err(WarmKeyDenied::BadQuorumSignature)
        );
    }

    #[test]
    fn rejects_inconsistent_warm_key() {
        let root = key(1);
        let warm = key(2);
        let mut d = make_delegation(&root, &warm, 9_999_999_999);
        // Swap in a different pubkey than warm_did encodes.
        d.warm_pubkey = key(7).verifying_key().to_bytes();
        // Re-sign so the signature itself is valid over the (now inconsistent) message.
        let sig = root.sign(d.signing_message().as_bytes());
        d.quorum_signature = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        let root_did = DidKeyMethod::from_public_key(&root.verifying_key());
        assert_eq!(
            verify_warm_key_delegation(&d, &root_did, 1_000),
            Err(WarmKeyDenied::InconsistentWarmKey)
        );
    }

    #[test]
    fn at_expiry_boundary_is_valid() {
        let root = key(1);
        let warm = key(2);
        let d = make_delegation(&root, &warm, 1_000);
        let root_did = DidKeyMethod::from_public_key(&root.verifying_key());
        // now == expires_at is still valid (reject only when now > expires_at).
        assert_eq!(verify_warm_key_delegation(&d, &root_did, 1_000), Ok(()));
    }

    #[test]
    fn issued_delegation_round_trips() {
        let root = key(1);
        let warm = key(2);
        let warm_pub = warm.verifying_key().to_bytes();
        let d = issue_warm_key_delegation(&root, &warm_pub, 9_999_999_999).unwrap();

        let root_did = DidKeyMethod::from_public_key(&root.verifying_key());
        let warm_did = DidKeyMethod::from_public_key(&warm.verifying_key());
        // Issuance sets the fields it should.
        assert_eq!(d.root_did, root_did);
        assert_eq!(d.warm_did, warm_did);
        assert_eq!(d.warm_pubkey, warm_pub);
        assert_eq!(d.expires_at, 9_999_999_999);
        // And the issued delegation verifies under the issuing root.
        assert_eq!(verify_warm_key_delegation(&d, &root_did, 1_000), Ok(()));
    }

    #[test]
    fn issued_delegation_fails_under_a_different_root() {
        let root = key(1);
        let warm = key(2);
        let d = issue_warm_key_delegation(&root, &warm.verifying_key().to_bytes(), 9_999_999_999).unwrap();
        let other_root = DidKeyMethod::from_public_key(&key(9).verifying_key());
        assert_eq!(
            verify_warm_key_delegation(&d, &other_root, 1_000),
            Err(WarmKeyDenied::WrongRoot)
        );
    }

    #[test]
    fn enrollment_cert_round_trips() {
        let root = key(1);
        let root_did = DidKeyMethod::from_public_key(&root.verifying_key());
        let warm_pub = key(2).verifying_key().to_bytes();
        let cert = sign_enrollment_cert(&root, "share-hex", &warm_pub);
        assert!(verify_enrollment_cert(&cert, &root_did, "share-hex", &warm_pub).is_ok());
    }

    #[test]
    fn enrollment_cert_rejects_wrong_share_or_warm_key() {
        let root = key(1);
        let root_did = DidKeyMethod::from_public_key(&root.verifying_key());
        let warm_pub = key(2).verifying_key().to_bytes();
        let cert = sign_enrollment_cert(&root, "share-hex", &warm_pub);
        // A different share under the same warm key must not verify.
        assert!(verify_enrollment_cert(&cert, &root_did, "OTHER-share", &warm_pub).is_err());
        // A different warm key under the same share must not verify.
        let other_warm = key(5).verifying_key().to_bytes();
        assert!(verify_enrollment_cert(&cert, &root_did, "share-hex", &other_warm).is_err());
    }

    #[test]
    fn enrollment_cert_rejects_wrong_root() {
        let root = key(1);
        let warm_pub = key(2).verifying_key().to_bytes();
        let cert = sign_enrollment_cert(&root, "share-hex", &warm_pub);
        let other_root = DidKeyMethod::from_public_key(&key(9).verifying_key());
        assert!(verify_enrollment_cert(&cert, &other_root, "share-hex", &warm_pub).is_err());
    }
}
