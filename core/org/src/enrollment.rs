// SPDX-License-Identifier: AGPL-3.0-or-later
//! Node-enrollment payload verification (RFC-0033, multi-node milestone).
//!
//! When a new device (device-2) accepts a FROST enrollment it receives a
//! `PairingPayload::FrostShare` carrying its FROST key-package share and a
//! root-quorum-signed [`WarmKeyDelegation`]. Before installing any of it the
//! device must verify that the delegation is bound to the expected root identity,
//! unexpired, **issued for this device's own key**, and that the share is a
//! well-formed FROST key package.
//!
//! This is the **security gate** of the accept side. Quorum-certificate binding
//! (share ↔ warm-key ↔ device), CEK delivery, keychain storage, and the live
//! bootstrap flow build on top of it in following slices.

use anyhow::{anyhow, Result};
use ed25519_dalek::SigningKey;
use kotton_wire::did::Did;
use kotton_wire::kel::KelEvent;
use kotton_wire::peer::{DataKeys, FrostSharePayload, PairingPayload, WarmKeyDelegation};
use kotton_crypto::warm_key::{
    issue_warm_key_delegation, sign_enrollment_cert, verify_enrollment_cert,
};
use kotton_crypto::{frost, verify_warm_key_delegation, DidKeyMethod};

/// Verify a received FROST enrollment share before installing it.
///
/// This is the **complete** accept-side gate: a caller that gets `Ok(())` has
/// checked everything required to safely install the share + warm key. The
/// checks (each fatal), in order:
///
/// 1. the [`WarmKeyDelegation`] verifies under `expected_root_did` and is
///    unexpired ([`verify_warm_key_delegation`]);
/// 2. the delegation is issued for **this device** — `delegation.warm_pubkey`
///    equals `this_device_warm_pubkey`, the key this device holds the secret for.
///    Without this, a device would accept a delegation minted for a *different*
///    device's warm key;
/// 3. the share deserialises as a valid FROST `KeyPackage`;
/// 4. the share's embedded **group verifying key** derives to `expected_root_did`
///    — a cryptographic binding of the share to the identity being joined, taken
///    directly from the share rather than trusted from the issuer's certificate;
/// 5. the `quorum_certificate` binds *this* share to *this* warm key under the
///    root ([`verify_enrollment_cert`]) — closing the share↔warm-key↔root triangle.
///
/// Folding the certificate check in (rather than leaving it to the caller) means
/// a consumer physically cannot install a share without the full triangle —
/// there is no "validated the delegation but forgot the cert" path.
pub fn verify_received_frost_share(
    delegation: &WarmKeyDelegation,
    share: &FrostSharePayload,
    quorum_certificate: &str,
    this_device_warm_pubkey: &[u8; 32],
    expected_root_did: &Did,
    now_secs: i64,
) -> Result<()> {
    verify_warm_key_delegation(delegation, expected_root_did, now_secs)
        .map_err(|e| anyhow!("warm-key delegation invalid: {e}"))?;

    if &delegation.warm_pubkey != this_device_warm_pubkey {
        return Err(anyhow!(
            "warm-key delegation is issued for a different device's key, not this one"
        ));
    }

    frost::validate_key_package(&share.0)
        .map_err(|e| anyhow!("frost share is not a valid key package: {e}"))?;

    // The share carries the group verifying key; confirm it is the identity we
    // think we are joining, independent of the issuer's certificate.
    let group_vk = frost::key_package_verifying_key(&share.0)
        .map_err(|e| anyhow!("frost share has no readable group key: {e}"))?;
    let share_did = DidKeyMethod::from_public_key_bytes(&group_vk)
        .map_err(|e| anyhow!("derive did from share group key: {e}"))?;
    if &share_did != expected_root_did {
        return Err(anyhow!(
            "frost share belongs to a different identity than the expected root"
        ));
    }

    verify_enrollment_cert(
        quorum_certificate,
        expected_root_did,
        &share.0,
        this_device_warm_pubkey,
    )
    .map_err(|e| anyhow!("enrollment certificate invalid: {e}"))?;

    Ok(())
}

/// The result of building a FROST enrollment on the issuer (device-1) side.
pub struct IssuedEnrollment {
    /// The payload to ECDH-seal to the new device's node key and send.
    pub payload: PairingPayload,
    /// The issuer's own retained FROST share. The issuer must store this and
    /// discard its former 1-of-1 key — it is now one party of the 2-of-2.
    pub issuer_share: FrostSharePayload,
    /// The group `PublicKeyPackage` (hex). Both parties persist it; a signing
    /// coordinator needs it to aggregate (RFC-0036 distributed-signing prereq).
    pub pubkey_package: String,
    /// The group / root DID, preserved across the split.
    pub root_did: Did,
}

/// Build a `keys::split` 1→2 FROST enrollment for a new device (RFC-0033 issuer
/// side). Splits the issuer's existing identity into a 2-of-2 (the DID is
/// preserved), issues the new device a warm-key delegation + an enrollment
/// certificate, and packages its share + (for a `Full` device) the operational
/// [`DataKeys`] into a `PairingPayload::FrostShare`.
///
/// `data_keys` is `Some` for a `Full` device and **`None` for a `Cosigner`** — a
/// cosigner gets the share (can co-sign) but no data keys (RFC-0036), so the
/// payload carries `data_keys: None`. Both domain roots travel together or not
/// at all; see [`DataKeys`] for why that is a type and not two options.
///
/// The caller seals `payload` to the new device's node key (the pairing ECDH)
/// and stores `issuer_share`.
pub fn build_frost_enrollment(
    issuer_identity_seed: &[u8; 32],
    new_device_warm_pubkey: &[u8; 32],
    data_keys: Option<DataKeys>,
    warm_key_expires_at: i64,
    issuer_kel: Vec<KelEvent>,
) -> Result<IssuedEnrollment> {
    // 1. Split the existing identity into 2-of-2 — group key, and thus the DID,
    //    preserved. shares[0] is the issuer's; shares[1] is the new device's.
    let (shares, pubkey_package, did) = frost::split_existing_identity(issuer_identity_seed, 2, 2)?;
    let issuer_share = FrostSharePayload(shares[0].1.clone());
    let new_device_share_hex = shares[1].1.clone();

    // 2. The issuer's ed25519 key is the (preserved) group key; it signs the
    //    delegation + certificate (1-of-1 bootstrap; a FROST aggregate at n≥2).
    let root_key = SigningKey::from_bytes(issuer_identity_seed);
    let warm_key_delegation =
        issue_warm_key_delegation(&root_key, new_device_warm_pubkey, warm_key_expires_at)?;
    let quorum_certificate =
        sign_enrollment_cert(&root_key, &new_device_share_hex, new_device_warm_pubkey);

    let payload = PairingPayload::FrostShare {
        share: FrostSharePayload(new_device_share_hex),
        warm_key_delegation,
        quorum_certificate,
        data_keys,
        pubkey_package: pubkey_package.clone(),
        kel: issuer_kel,
    };

    Ok(IssuedEnrollment {
        payload,
        issuer_share,
        pubkey_package,
        root_did: Did::parse(&did)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotton_crypto::warm_key::verify_enrollment_cert;
    use kotton_crypto::DidKeyMethod;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// A `Full` posture's data capability. The two roots differ so a test can
    /// tell them apart — delivering one in place of the other must not pass.
    fn full_keys(cek: [u8; 32]) -> DataKeys {
        DataKeys {
            cek,
            cek_epoch: 0,
            master_secret: [cek[0] ^ 0xff; 32],
        }
    }

    /// A genuine FROST key-package share (from a 2-of-2 split), hex-serialised.
    fn valid_share() -> FrostSharePayload {
        let (shares, _pk, _did) = frost::generate_key_shares(2, 2).unwrap();
        FrostSharePayload(shares[0].1.clone())
    }

    fn delegation_from(root: &SigningKey, warm: &SigningKey) -> WarmKeyDelegation {
        issue_warm_key_delegation(root, &warm.verifying_key().to_bytes(), 9_999_999_999)
            .expect("issue delegation")
    }

    /// Build fully-consistent enrollment material (share, delegation, and cert
    /// all bound to one root) via the real issuer path. Returns
    /// `(share, delegation, cert, root_did)`.
    fn consistent_enrollment(
        issuer_seed: &[u8; 32],
        warm: &SigningKey,
    ) -> (FrostSharePayload, WarmKeyDelegation, String, Did) {
        let warm_pub = warm.verifying_key().to_bytes();
        let issued =
            build_frost_enrollment(issuer_seed, &warm_pub, Some(full_keys([3u8; 32])), 9_999_999_999, vec![])
            .expect("build enrollment");
        match issued.payload {
            PairingPayload::FrostShare {
                share,
                warm_key_delegation,
                quorum_certificate,
                ..
            } => (share, warm_key_delegation, quorum_certificate, issued.root_did),
            other => panic!("expected FrostShare, got {other:?}"),
        }
    }

    #[test]
    fn accepts_valid_share_and_delegation() {
        let issuer_seed = [11u8; 32];
        let warm = key(2);
        let warm_pub = warm.verifying_key().to_bytes();
        let (share, delegation, cert, root_did) = consistent_enrollment(&issuer_seed, &warm);
        assert!(
            verify_received_frost_share(&delegation, &share, &cert, &warm_pub, &root_did, 1_000)
                .is_ok()
        );
    }

    #[test]
    fn rejects_share_from_a_different_identity() {
        // A well-formed share whose group key is NOT the expected root must be
        // rejected on the share→root binding (finding 1), before the cert check.
        let issuer_seed = [11u8; 32];
        let warm = key(2);
        let warm_pub = warm.verifying_key().to_bytes();
        let (_real_share, delegation, cert, root_did) = consistent_enrollment(&issuer_seed, &warm);
        let foreign = valid_share(); // a valid package from an unrelated group
        let err = verify_received_frost_share(
            &delegation,
            &foreign,
            &cert,
            &warm_pub,
            &root_did,
            1_000,
        )
        .expect_err("a share from another identity must be rejected");
        assert!(
            err.to_string().contains("different identity"),
            "expected the share→root binding to fire, got: {err}"
        );
    }

    #[test]
    fn rejects_tampered_certificate() {
        // A valid share + delegation but a certificate that does not bind them
        // must fail the folded cert check.
        let issuer_seed = [11u8; 32];
        let warm = key(2);
        let warm_pub = warm.verifying_key().to_bytes();
        let (share, delegation, _good_cert, root_did) = consistent_enrollment(&issuer_seed, &warm);
        let bad_cert = sign_enrollment_cert(&key(1), "some-other-share", &warm_pub);
        assert!(
            verify_received_frost_share(&delegation, &share, &bad_cert, &warm_pub, &root_did, 1_000)
                .is_err(),
            "a certificate not signed by the root over this share must reject"
        );
    }

    /// The group `PublicKeyPackage` distributed by enrollment, together with the
    /// two shares it hands out, produces a threshold signature that verifies as a
    /// standard Ed25519 signature under the user's identity DID — i.e. the
    /// distributed group key actually unblocks distributed signing (RFC-0036).
    #[test]
    fn distributed_group_key_enables_a_verifying_threshold_signature() {
        use ed25519_dalek::{Signature, Verifier};

        let issuer_seed = [11u8; 32];
        let new_warm = SigningKey::from_bytes(&[2u8; 32]);
        let issued = build_frost_enrollment(
            &issuer_seed,
            &new_warm.verifying_key().to_bytes(),
            Some(full_keys([3u8; 32])),
            9_999_999_999,
            vec![],
        )
        .unwrap();

        let new_device_share = match &issued.payload {
            PairingPayload::FrostShare {
                share,
                pubkey_package,
                ..
            } => {
                assert_eq!(
                    *pubkey_package, issued.pubkey_package,
                    "issuer and joiner receive the same group key"
                );
                share.0.clone()
            }
            other => panic!("expected FrostShare, got {other:?}"),
        };

        // Drive a 2-of-2 threshold signature with the two distributed shares.
        let msg = b"constitutional act: revoke device";
        let shares = [issued.issuer_share.0.as_str(), new_device_share.as_str()];
        let mut commitments = Vec::new();
        let mut nonces = Vec::new();
        for kp in &shares {
            let (n, c, id) = frost::signing_commit(kp).unwrap();
            commitments.push((id, c));
            nonces.push(n);
        }
        let pkg = frost::create_signing_package(msg, &commitments).unwrap();
        let mut sig_shares = Vec::new();
        for (i, kp) in shares.iter().enumerate() {
            let s = frost::signing_sign(kp, &nonces[i], &pkg).unwrap();
            sig_shares.push((commitments[i].0.clone(), s));
        }
        let sig = frost::aggregate(&pkg, &issued.pubkey_package, &sig_shares).unwrap();
        assert_eq!(sig.len(), 64, "Ed25519 signature is 64 bytes");

        // The aggregate verifies under the group key — the issuer's preserved
        // identity public key (the DID).
        let group_pubkey = SigningKey::from_bytes(&issuer_seed).verifying_key();
        let sig_arr: [u8; 64] = sig.try_into().unwrap();
        group_pubkey
            .verify(msg, &Signature::from_bytes(&sig_arr))
            .expect("threshold signature verifies under the group identity key");
    }

    #[test]
    fn rejects_delegation_from_wrong_root() {
        let warm = key(2);
        let delegation = delegation_from(&key(1), &warm);
        let warm_pub = warm.verifying_key().to_bytes();
        let other_root = DidKeyMethod::from_public_key(&key(9).verifying_key());
        // Fails at step 1 (delegation root binding), before share/cert checks.
        assert!(verify_received_frost_share(
            &delegation,
            &valid_share(),
            "unused-cert",
            &warm_pub,
            &other_root,
            1_000
        )
        .is_err());
    }

    #[test]
    fn rejects_delegation_for_a_different_device() {
        let root = key(1);
        let warm = key(2);
        let root_did = DidKeyMethod::from_public_key(&root.verifying_key());
        let delegation = delegation_from(&root, &warm); // issued for key(2)
        let some_other_device = key(5).verifying_key().to_bytes();
        // Fails at step 2 (this-device binding), before share/cert checks.
        assert!(
            verify_received_frost_share(
                &delegation,
                &valid_share(),
                "unused-cert",
                &some_other_device,
                &root_did,
                1_000
            )
            .is_err(),
            "a delegation minted for another device's warm key must be rejected"
        );
    }

    #[test]
    fn rejects_expired_delegation() {
        let root = key(1);
        let warm = key(2);
        let root_did = DidKeyMethod::from_public_key(&root.verifying_key());
        let expired =
            issue_warm_key_delegation(&root, &warm.verifying_key().to_bytes(), 500).unwrap();
        let warm_pub = warm.verifying_key().to_bytes();
        assert!(
            verify_received_frost_share(
                &expired,
                &valid_share(),
                "unused-cert",
                &warm_pub,
                &root_did,
                1_000
            )
            .is_err(),
            "now (1000) > expiry (500) must reject"
        );
    }

    #[test]
    fn rejects_malformed_share() {
        let root = key(1);
        let warm = key(2);
        let root_did = DidKeyMethod::from_public_key(&root.verifying_key());
        let delegation = delegation_from(&root, &warm);
        let warm_pub = warm.verifying_key().to_bytes();
        let bad = FrostSharePayload("not-a-key-package".to_string());
        // Fails at step 3 (share validity), before share→root and cert checks.
        assert!(
            verify_received_frost_share(&delegation, &bad, "unused-cert", &warm_pub, &root_did, 1_000)
                .is_err()
        );
    }

    #[test]
    fn build_round_trips_against_accept_side() {
        let issuer_seed = [11u8; 32];
        let new_warm = SigningKey::from_bytes(&[2u8; 32]);
        let new_warm_pub = new_warm.verifying_key().to_bytes();
        let cek = [3u8; 32];

        let issued =
            build_frost_enrollment(&issuer_seed, &new_warm_pub, Some(full_keys(cek)), 9_999_999_999, vec![])
            .expect("build enrollment");

        // The split preserves the issuer's existing identity DID.
        let issuer_did =
            DidKeyMethod::from_public_key(&SigningKey::from_bytes(&issuer_seed).verifying_key());
        assert_eq!(issued.root_did, issuer_did, "DID preserved across the split");

        match &issued.payload {
            PairingPayload::FrostShare {
                share,
                warm_key_delegation,
                quorum_certificate,
                data_keys,
                ..
            } => {
                let delivered = data_keys.expect("a Full enrollment carries the data capability");
                assert_eq!(delivered.cek, cek, "operational CEK delivered in the payload");
                assert_eq!(
                    delivered.master_secret,
                    full_keys(cek).master_secret,
                    "the db-domain root travels with the CEK (RFC-0036) — without it a \
                     joined device derives a different K_log and cannot open the record log"
                );
                // The accept-side gate accepts delegation + share + cert for this device.
                verify_received_frost_share(
                    warm_key_delegation,
                    share,
                    quorum_certificate,
                    &new_warm_pub,
                    &issued.root_did,
                    1_000,
                )
                .expect("accept side verifies");
                // And the certificate independently verifies standalone.
                verify_enrollment_cert(
                    quorum_certificate,
                    &issued.root_did,
                    &share.0,
                    &new_warm_pub,
                )
                .expect("enrollment certificate verifies");
            }
            other => panic!("expected FrostShare, got {other:?}"),
        }
    }

}
