// SPDX-License-Identifier: AGPL-3.0-or-later
//! FROST threshold signature provider — stateless math layer.
//!
//! This module wraps the `frost-ed25519` crate (Zcash Foundation, audited).
//! All types are serialised as hex strings so that upper layers (daemon, CLI)
//! never need to import `frost-ed25519` directly.
//!
//! ## Phase A note
//!
//! Key generation uses the **trusted-dealer** path: the initiator generates all
//! share material and distributes encrypted shares out-of-band.  No participant
//! ever sees the full scalar — the dealer discards it immediately after share
//! generation — but the dealer _does_ compute the full key transiently.
//!
//! Phase B (after the peer transport is live) will switch to the full
//! distributed DKG (`frost::keys::dkg`) where even the initiator never holds
//! the full key.  The signing ceremony and all downstream code are identical
//! in both phases; only key generation changes.

use frost_ed25519 as frost;
use frost_ed25519::keys::dkg;
use frost_ed25519::keys::{KeyPackage, PublicKeyPackage};
use frost_ed25519::{round1, round2, Identifier, SigningPackage};
use std::collections::BTreeMap;

use crate::did::DidKeyMethod;

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum FrostError {
    #[error("FROST: {0}")]
    Frost(#[from] frost_ed25519::Error),
    #[error("serialise: {0}")]
    Serialise(String),
    #[error("deserialise: {0}")]
    Deserialise(String),
    #[error("invalid participant index {0}")]
    InvalidIndex(u16),
}

pub type FrostResult<T> = Result<T, FrostError>;

/// Output of generating or splitting a group key:
/// `(shares as (index, key_package_hex), pubkey_package_hex, did)`.
pub type KeyShares = FrostResult<(Vec<(u16, String)>, String, String)>;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn id_from_index(idx: u16) -> FrostResult<Identifier> {
    Identifier::try_from(idx).map_err(|_| FrostError::InvalidIndex(idx))
}

fn hex_enc(b: &[u8]) -> String {
    hex::encode(b)
}

fn hex_dec(s: &str) -> FrostResult<Vec<u8>> {
    hex::decode(s).map_err(|e| FrostError::Deserialise(e.to_string()))
}

fn serialise<T: serde::Serialize>(v: &T) -> FrostResult<String> {
    let bytes = serde_json::to_vec(v).map_err(|e| FrostError::Serialise(e.to_string()))?;
    Ok(hex_enc(&bytes))
}

fn deserialise<T: serde::de::DeserializeOwned>(hex: &str) -> FrostResult<T> {
    let bytes = hex_dec(hex)?;
    serde_json::from_slice(&bytes).map_err(|e| FrostError::Deserialise(e.to_string()))
}

// ── Key generation (trusted dealer) ──────────────────────────────────────────

/// Generate a t-of-n FROST key using the trusted-dealer path.
///
/// Returns:
/// - `shares` — `(participant_index, key_package_hex)` for each participant.
///   Index 1 is for the initiator; indices 2..=n are for the other participants.
///   **Distribute each share to its participant over a confidential channel.**
/// - `pubkey_hex` — serialised `PublicKeyPackage`; also stored by the initiator.
/// - `org_did` — `did:key:…` string derived from the group Ed25519 verifying key.
pub fn generate_key_shares(
    threshold: u16,
    total: u16,
) -> KeyShares {
    let rng = rand::rngs::OsRng;

    let (shares_map, pubkey_package) = frost::keys::generate_with_dealer(
        total,
        threshold,
        frost::keys::IdentifierList::Default,
        rng,
    )?;

    let vk_bytes: [u8; 32] = pubkey_package
        .verifying_key()
        .serialize()
        .map_err(|e| FrostError::Serialise(format!("serialize verifying key: {e}")))?[..]
        .try_into()
        .map_err(|_| FrostError::Serialise("verifying key must be 32 bytes".into()))?;

    let org_did = DidKeyMethod::from_public_key_bytes(&vk_bytes)
        .map_err(|e| FrostError::Serialise(format!("did derivation: {e}")))?
        .to_string();

    let pubkey_hex = serialise(&pubkey_package)?;

    let mut out = Vec::with_capacity(total as usize);
    for idx in 1..=total {
        let id = id_from_index(idx)?;
        let secret_share = shares_map.get(&id).ok_or_else(|| {
            FrostError::Deserialise(format!("missing share for participant {idx}"))
        })?;
        let key_package = KeyPackage::try_from(secret_share.clone())?;
        let kp_hex = serialise(&key_package)?;
        out.push((idx, kp_hex));
    }

    Ok((out, pubkey_hex, org_did))
}

/// Split an **existing** Ed25519 identity (the device-1 / 1-of-1 root) into a
/// `threshold`-of-`total` FROST sharing that **preserves the group public key — and
/// therefore the DID**.
///
/// `ed25519_seed` is the 32-byte seed the identity key was created from
/// (`derive_identity_key`'s output; the input to `Ed25519Keypair::from_seed`). The
/// bridge takes that key's secret scalar (`clamp(SHA512(seed)[..32]) mod L`) and
/// builds a FROST `SigningKey` from it; FROST's group key is `g^scalar`, which equals
/// the original Ed25519 public key (proven by
/// `spike_ed25519_identity_bridges_to_frost_preserving_did`). This is the `keys::split`
/// 1→2 enrollment path (RFC-0033): adding a second device does **not** churn the
/// identifier.
///
/// Returns `(shares, pubkey_hex, did)` in the same shape as [`generate_key_shares`];
/// the caller keeps share 1 and distributes shares 2..=n to the new devices.
pub fn split_existing_identity(
    ed25519_seed: &[u8; 32],
    threshold: u16,
    total: u16,
) -> KeyShares {
    use sha2::{Digest, Sha512};

    // Ed25519 secret scalar = clamp(SHA512(seed)[..32]); reduce to a canonical
    // FROST scalar (g^clamped == g^(clamped mod L) since g has order L).
    let hash = Sha512::digest(ed25519_seed);
    let mut s = [0u8; 32];
    s.copy_from_slice(&hash[..32]);
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
    let scalar_bytes = curve25519_dalek::Scalar::from_bytes_mod_order(s).to_bytes();

    let signing_key = frost::SigningKey::deserialize(&scalar_bytes)
        .map_err(|e| FrostError::Deserialise(format!("ed25519→frost scalar: {e}")))?;

    let mut rng = rand::rngs::OsRng;
    let (shares_map, pubkey_package) = frost::keys::split(
        &signing_key,
        total,
        threshold,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )?;

    let vk_bytes: [u8; 32] = pubkey_package
        .verifying_key()
        .serialize()
        .map_err(|e| FrostError::Serialise(format!("serialize verifying key: {e}")))?[..]
        .try_into()
        .map_err(|_| FrostError::Serialise("verifying key must be 32 bytes".into()))?;
    let did = DidKeyMethod::from_public_key_bytes(&vk_bytes)
        .map_err(|e| FrostError::Serialise(format!("did derivation: {e}")))?
        .to_string();
    let pubkey_hex = serialise(&pubkey_package)?;

    let mut out = Vec::with_capacity(total as usize);
    for (idx, (_id, secret_share)) in shares_map.iter().enumerate() {
        let key_package = KeyPackage::try_from(secret_share.clone())?;
        out.push(((idx + 1) as u16, serialise(&key_package)?));
    }
    Ok((out, pubkey_hex, did))
}

/// Deserialise and validate a `KeyPackage` hex blob received from the dealer.
///
/// Returns the same hex if valid (noop from the perspective of the caller; the
/// point is the validation step).
pub fn validate_key_package(key_package_hex: &str) -> FrostResult<String> {
    let _kp: KeyPackage = deserialise(key_package_hex)?;
    Ok(key_package_hex.to_string())
}

/// Extract the **group verifying key** embedded in a `KeyPackage` (the FROST
/// group public key — the same 32 bytes for every share of one group).
///
/// A `KeyPackage` carries the group verifying key alongside the participant's
/// own share, so a recipient can confirm — without any external attestation —
/// that a received share belongs to the identity it expects: derive the DID
/// from these bytes and compare it to the expected root DID. The enrollment
/// accept gate uses this to bind the share to the root cryptographically rather
/// than trusting the issuer's certificate alone.
pub fn key_package_verifying_key(key_package_hex: &str) -> FrostResult<[u8; 32]> {
    let kp: KeyPackage = deserialise(key_package_hex)?;
    let bytes: [u8; 32] = kp
        .verifying_key()
        .serialize()
        .map_err(|e| FrostError::Serialise(format!("serialize verifying key: {e}")))?[..]
        .try_into()
        .map_err(|_| FrostError::Serialise("verifying key must be 32 bytes".into()))?;
    Ok(bytes)
}

// ── Signing — round 1 (commit) ────────────────────────────────────────────────

/// Generate signing nonces and commitments for one participant.
///
/// Returns:
/// - `nonces_hex` — **keep secret**; stored in the daemon and used in round 2.
/// - `commitment_hex` — broadcast to the coordinator.
/// - `participant_id_hex` — the participant's FROST `Identifier` (serialised).
pub fn signing_commit(key_package_hex: &str) -> FrostResult<(String, String, String)> {
    let kp: KeyPackage = deserialise(key_package_hex)?;
    let mut rng = rand::rngs::OsRng;

    let (nonces, commitment) = frost::round1::commit(kp.signing_share(), &mut rng);

    let nonces_hex = serialise(&nonces)?;
    let commitment_hex = serialise(&commitment)?;
    let participant_id_hex = serialise(kp.identifier())?;

    Ok((nonces_hex, commitment_hex, participant_id_hex))
}

// ── Signing — round 2 (sign + optionally aggregate) ──────────────────────────

/// Create a `SigningPackage` from a message and a map of participant commitments.
///
/// `commitments` is `&[(participant_id_hex, commitment_hex)]`.
pub fn create_signing_package(
    message: &[u8],
    commitments: &[(String, String)],
) -> FrostResult<String> {
    let mut map = BTreeMap::new();
    for (id_hex, comm_hex) in commitments {
        let id: Identifier = deserialise(id_hex)?;
        let comm: round1::SigningCommitments = deserialise(comm_hex)?;
        map.insert(id, comm);
    }
    let pkg = SigningPackage::new(map, message);
    serialise(&pkg)
}

/// Produce a signature share for one participant.
///
/// `nonces_hex` was returned by [`signing_commit`] and stored by the daemon.
/// Returns `signature_share_hex`.
pub fn signing_sign(
    key_package_hex: &str,
    nonces_hex: &str,
    signing_package_hex: &str,
) -> FrostResult<String> {
    let kp: KeyPackage = deserialise(key_package_hex)?;
    let nonces: round1::SigningNonces = deserialise(nonces_hex)?;
    let pkg: SigningPackage = deserialise(signing_package_hex)?;

    let share = frost::round2::sign(&pkg, &nonces, &kp)?;
    serialise(&share)
}

/// Aggregate signature shares into a final Ed25519 signature.
///
/// `shares` is `&[(participant_id_hex, signature_share_hex)]`.
/// Returns raw 64-byte Ed25519 signature bytes.
pub fn aggregate(
    signing_package_hex: &str,
    pubkey_package_hex: &str,
    shares: &[(String, String)],
) -> FrostResult<Vec<u8>> {
    let pkg: SigningPackage = deserialise(signing_package_hex)?;
    let pubkey: PublicKeyPackage = deserialise(pubkey_package_hex)?;

    let mut map = BTreeMap::new();
    for (id_hex, share_hex) in shares {
        let id: Identifier = deserialise(id_hex)?;
        let share: round2::SignatureShare = deserialise(share_hex)?;
        map.insert(id, share);
    }

    let sig = frost::aggregate(&pkg, &map, &pubkey)?;
    Ok(sig
        .serialize()
        .map_err(|e| FrostError::Serialise(format!("serialize signature: {e}")))?
        .to_vec())
}

// ── Distributed key generation (DKG, Phase B) ─────────────────────────────────
//
// The trusted-dealer path above has one party transiently compute the full key.
// The DKG below removes that: each participant contributes randomness across three
// rounds, and no participant — not even the initiator — ever holds the full scalar.
// The daemon orchestrates the package exchange over the (now live) peer transport;
// secret packages are held between rounds (serialised, like the signing nonces).

/// DKG round 1 for one participant (`index` is 1-based; `threshold`-of-`total`).
///
/// Returns `(secret_package_hex, round1_package_hex, participant_id_hex)`:
/// - `secret_package_hex` — **keep secret**; held by the daemon for rounds 2 and 3.
/// - `round1_package_hex` — broadcast to every other participant.
/// - `participant_id_hex` — this participant's serialised `Identifier`.
pub fn dkg_part1(index: u16, threshold: u16, total: u16) -> FrostResult<(String, String, String)> {
    let id = id_from_index(index)?;
    let (secret, package) = dkg::part1(id, total, threshold, rand::rngs::OsRng)?;
    Ok((serialise(&secret)?, serialise(&package)?, serialise(&id)?))
}

/// DKG round 2. `round1_packages` is `&[(participant_id_hex, round1_package_hex)]`
/// for every **other** participant (not self).
///
/// Returns `(round2_secret_hex, round2_packages)`:
/// - `round2_secret_hex` — **keep secret**; held for round 3.
/// - `round2_packages` — `(recipient_id_hex, round2_package_hex)`; send each to its
///   named recipient over a confidential point-to-point channel.
pub fn dkg_part2(
    secret_package_hex: &str,
    round1_packages: &[(String, String)],
) -> FrostResult<(String, Vec<(String, String)>)> {
    let secret: dkg::round1::SecretPackage = deserialise(secret_package_hex)?;
    let mut r1 = BTreeMap::new();
    for (id_hex, pkg_hex) in round1_packages {
        r1.insert(deserialise::<Identifier>(id_hex)?, deserialise(pkg_hex)?);
    }
    let (round2_secret, round2_map) = dkg::part2(secret, &r1)?;
    let mut out = Vec::with_capacity(round2_map.len());
    for (id, pkg) in &round2_map {
        out.push((serialise(id)?, serialise(pkg)?));
    }
    Ok((serialise(&round2_secret)?, out))
}

/// DKG round 3 (finalise). `round1_packages` is every other participant's round-1
/// package; `round2_packages` is the round-2 packages addressed **to** this
/// participant (keyed by sender).
///
/// Returns `(key_package_hex, pubkey_package_hex, org_did)`. After this the
/// participant holds a FROST share; no participant holds the full key, and all
/// participants derive the same group `pubkey_package` / `org_did`.
pub fn dkg_part3(
    round2_secret_hex: &str,
    round1_packages: &[(String, String)],
    round2_packages: &[(String, String)],
) -> FrostResult<(String, String, String)> {
    let round2_secret: dkg::round2::SecretPackage = deserialise(round2_secret_hex)?;
    let mut r1 = BTreeMap::new();
    for (id_hex, pkg_hex) in round1_packages {
        r1.insert(deserialise::<Identifier>(id_hex)?, deserialise(pkg_hex)?);
    }
    let mut r2 = BTreeMap::new();
    for (id_hex, pkg_hex) in round2_packages {
        r2.insert(deserialise::<Identifier>(id_hex)?, deserialise(pkg_hex)?);
    }
    let (key_package, pubkey_package) = dkg::part3(&round2_secret, &r1, &r2)?;

    let vk_bytes: [u8; 32] = pubkey_package
        .verifying_key()
        .serialize()
        .map_err(|e| FrostError::Serialise(format!("serialize verifying key: {e}")))?[..]
        .try_into()
        .map_err(|_| FrostError::Serialise("verifying key must be 32 bytes".into()))?;
    let org_did = DidKeyMethod::from_public_key_bytes(&vk_bytes)
        .map_err(|e| FrostError::Serialise(format!("did derivation: {e}")))?
        .to_string();

    Ok((serialise(&key_package)?, serialise(&pubkey_package)?, org_did))
}

#[cfg(test)]
mod tests {
    //! Round-trip coverage of the FROST math layer — the foundation the custody
    //! milestone (RFC-0031) builds on. Until now this module had no tests.

    use super::*;

    /// Drive a full threshold-signing ceremony with `threshold`-of-`total` shares,
    /// using the first `signers` participants. Returns the aggregated 64-byte
    /// signature and the serialised `PublicKeyPackage` (group key).
    /// Run a threshold-signing ceremony over the first `signers` of `shares`
    /// (whatever produced them — trusted dealer or DKG). Returns the aggregated
    /// 64-byte signature.
    fn sign_with_shares(
        shares: &[(u16, String)],
        pubkey_hex: &str,
        signers: usize,
        message: &[u8],
    ) -> FrostResult<Vec<u8>> {
        let chosen: Vec<&(u16, String)> = shares.iter().take(signers).collect();

        let mut commitments = Vec::new();
        let mut nonces = Vec::new();
        for (_idx, kp_hex) in &chosen {
            let (n, c, id) = signing_commit(kp_hex)?;
            commitments.push((id, c));
            nonces.push(n);
        }

        let pkg_hex = create_signing_package(message, &commitments)?;

        let mut sig_shares = Vec::new();
        for (i, (_idx, kp_hex)) in chosen.iter().enumerate() {
            let share = signing_sign(kp_hex, &nonces[i], &pkg_hex)?;
            sig_shares.push((commitments[i].0.clone(), share));
        }

        aggregate(&pkg_hex, pubkey_hex, &sig_shares)
    }

    fn sign_with(
        threshold: u16,
        total: u16,
        signers: usize,
        message: &[u8],
    ) -> FrostResult<(Vec<u8>, String)> {
        let (shares, pubkey_hex, _did) = generate_key_shares(threshold, total)?;
        let sig = sign_with_shares(&shares, &pubkey_hex, signers, message)?;
        Ok((sig, pubkey_hex))
    }

    /// Verify an aggregated 64-byte signature against a serialised group key.
    fn verify_group_sig(sig_bytes: &[u8], pubkey_hex: &str, message: &[u8]) {
        let pubkey: PublicKeyPackage = deserialise(pubkey_hex).unwrap();
        let arr: [u8; 64] = sig_bytes.try_into().expect("64-byte signature");
        let sig = frost::Signature::deserialize(&arr).expect("valid signature bytes");
        pubkey
            .verifying_key()
            .verify(message, &sig)
            .expect("threshold signature verifies against the group key");
    }

    #[test]
    fn keygen_derives_a_did_key_group_identity() {
        let (shares, pubkey_hex, org_did) = generate_key_shares(2, 3).unwrap();
        assert_eq!(shares.len(), 3, "3 shares for a 2-of-3 group");
        assert!(org_did.starts_with("did:key:z"), "group DID is did:key");
        assert!(!pubkey_hex.is_empty());
        // Every share validates as a KeyPackage.
        for (_idx, kp_hex) in &shares {
            validate_key_package(kp_hex).unwrap();
        }
    }

    #[test]
    fn threshold_signature_round_trips_and_verifies() {
        let message = b"constitutional act: enroll device";
        let (sig_bytes, pubkey_hex) = sign_with(2, 3, 2, message).unwrap();
        assert_eq!(sig_bytes.len(), 64, "Ed25519 signature is 64 bytes");

        // Independently verify the aggregated signature against the group key.
        let pubkey: PublicKeyPackage = deserialise(&pubkey_hex).unwrap();
        let arr: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();
        let sig = frost::Signature::deserialize(&arr).expect("valid signature bytes");
        pubkey
            .verifying_key()
            .verify(message, &sig)
            .expect("aggregated threshold signature verifies against the group key");
    }

    #[test]
    fn full_quorum_of_two_of_two_signs() {
        let message = b"2-of-2 device quorum";
        let (sig_bytes, _pk) = sign_with(2, 2, 2, message).unwrap();
        assert_eq!(sig_bytes.len(), 64);
    }

    #[test]
    fn below_threshold_cannot_produce_a_valid_signature() {
        // One signer alone must not satisfy a 2-of-3 threshold.
        let result = sign_with(2, 3, 1, b"forge attempt");
        assert!(
            result.is_err(),
            "a single share must not produce a valid 2-of-3 signature"
        );
    }

    /// Full 2-of-3 distributed DKG across three participants entirely in-process:
    /// no party holds the full key, all derive the same group identity, and the
    /// DKG-produced shares threshold-sign successfully.
    #[test]
    fn dkg_three_party_produces_working_shares() {
        use std::collections::HashMap;
        let (threshold, total) = (2u16, 3u16);

        // ── Round 1 ──────────────────────────────────────────────────────────
        let mut secrets1: Vec<(u16, String)> = Vec::new();
        let mut r1_pkgs: Vec<(String, String)> = Vec::new(); // (id_hex, package_hex)
        let mut id_by_index: HashMap<u16, String> = HashMap::new();
        for idx in 1..=total {
            let (sec, pkg, id) = dkg_part1(idx, threshold, total).unwrap();
            secrets1.push((idx, sec));
            r1_pkgs.push((id.clone(), pkg));
            id_by_index.insert(idx, id);
        }
        let index_by_id: HashMap<String, u16> =
            id_by_index.iter().map(|(i, id)| (id.clone(), *i)).collect();

        // ── Round 2 — process others' round-1 packages; route round-2 packages ─
        let mut secrets2: Vec<(u16, String)> = Vec::new();
        // recipient_index -> [(sender_id_hex, round2_pkg_hex)]
        let mut inbox: HashMap<u16, Vec<(String, String)>> = HashMap::new();
        for (idx, sec1) in &secrets1 {
            let my_id = &id_by_index[idx];
            let others_r1: Vec<(String, String)> =
                r1_pkgs.iter().filter(|(id, _)| id != my_id).cloned().collect();
            let (sec2, r2_out) = dkg_part2(sec1, &others_r1).unwrap();
            secrets2.push((*idx, sec2));
            for (recipient_id, pkg) in r2_out {
                let recipient_idx = index_by_id[&recipient_id];
                inbox.entry(recipient_idx).or_default().push((my_id.clone(), pkg));
            }
        }

        // ── Round 3 — finalise; all participants must agree on the group key ───
        let mut key_packages: Vec<(u16, String)> = Vec::new();
        let mut group: Option<(String, String)> = None; // (pubkey_hex, did)
        for (idx, sec2) in &secrets2 {
            let my_id = &id_by_index[idx];
            let others_r1: Vec<(String, String)> =
                r1_pkgs.iter().filter(|(id, _)| id != my_id).cloned().collect();
            let my_r2 = inbox.get(idx).cloned().unwrap_or_default();
            let (kp, pk, did) = dkg_part3(sec2, &others_r1, &my_r2).unwrap();
            key_packages.push((*idx, kp));
            match &group {
                Some((pk0, did0)) => {
                    assert_eq!(pk0, &pk, "all participants derive the same group key");
                    assert_eq!(did0, &did, "all participants derive the same group DID");
                }
                None => group = Some((pk, did)),
            }
        }
        let (pubkey_hex, group_did) = group.unwrap();
        assert!(group_did.starts_with("did:key:z"));

        // The DKG-produced shares must threshold-sign (2 of 3) and verify.
        let message = b"DKG quorum signs a constitutional act";
        let sig = sign_with_shares(&key_packages, &pubkey_hex, 2, message).unwrap();
        verify_group_sig(&sig, &pubkey_hex, message);
    }

    /// SPIKE (2026-06-25, gates RFC-0033 reshare-stable vs minimal): does
    /// frost-ed25519 2.2 `keys::refresh` support *adding* a participant / raising the
    /// threshold while preserving the group key (the DID)? Findings, asserted below:
    ///   - 1 -> 2 via `keys::split`:   DID PRESERVED   (reshare-stable 1->2 is viable)
    ///   - 2 -> 3 via `keys::refresh`: ADDITION REJECTED (no DID-stable growth past 2 in 2.2)
    ///   - same-size refresh:          DID PRESERVED   (rotation / participant-removal works)
    #[test]
    fn spike_reshare_addition_capability() {
        let mut rng = rand::rngs::OsRng;

        // 1-of-1: device 1 holds the whole key; its verifying key is the DID.
        let sk = frost::SigningKey::new(&mut rng);
        let did_vk = frost::VerifyingKey::from(&sk);

        // 1 -> 2 via `split`: must preserve the group verifying key (DID stable across 1->2).
        let (shares, pubkeys) =
            frost::keys::split(&sk, 2, 2, frost::keys::IdentifierList::Default, &mut rng).unwrap();
        assert_eq!(
            pubkeys.verifying_key(),
            &did_vk,
            "split 1->2 must preserve the group verifying key (DID)"
        );
        let kps: BTreeMap<Identifier, KeyPackage> = shares
            .iter()
            .map(|(id, ss)| (*id, KeyPackage::try_from(ss.clone()).unwrap()))
            .collect();
        assert_eq!(kps.len(), 2, "1->2 split yields two shares");

        // 2 -> 3: attempt to ADD a brand-new participant (identifier 3) via refresh.
        // Expect rejection — refresh only refreshes EXISTING identifiers.
        let ids_3: Vec<Identifier> = (1u16..=3)
            .map(|i| Identifier::try_from(i).unwrap())
            .collect();
        let add = frost::keys::refresh::compute_refreshing_shares::<frost::Ed25519Sha512, _>(
            pubkeys.clone(),
            3,
            2,
            &ids_3,
            &mut rng,
        );
        if let Err(e) = &add {
            eprintln!("SPIKE: refresh add-participant rejected with: {e:?}");
        }
        assert!(
            add.is_err(),
            "frost-ed25519 2.2 refresh must NOT be able to ADD a new participant"
        );

        // Same-size refresh (2-of-2 -> 2-of-2): supported, DID preserved.
        let ids_2: Vec<Identifier> = kps.keys().copied().collect();
        let (refresh_shares, refreshed_pub) =
            frost::keys::refresh::compute_refreshing_shares::<frost::Ed25519Sha512, _>(
                pubkeys.clone(),
                2,
                2,
                &ids_2,
                &mut rng,
            )
            .unwrap();
        assert_eq!(
            refreshed_pub.verifying_key(),
            &did_vk,
            "same-size refresh must preserve the DID"
        );
        for (id, rshare) in ids_2.iter().zip(refresh_shares) {
            frost::keys::refresh::refresh_share::<frost::Ed25519Sha512>(rshare, &kps[id]).unwrap();
        }
    }

    /// VERIFY (2026-06-25, gates the split-path issuer side): can the existing
    /// ed25519-dalek 1-of-1 identity be bridged into FROST so `keys::split`
    /// preserves the DID? The bridge: take the ed25519 secret scalar
    /// (`clamp(SHA512(seed)[..32]) mod L`), build a FROST `SigningKey` from it, and
    /// confirm FROST's group key equals the *original* ed25519 public key — then a
    /// FROST threshold signature must verify under that original identity key.
    #[test]
    fn spike_ed25519_identity_bridges_to_frost_preserving_did() {
        use ed25519_dalek::Verifier as _;
        use sha2::{Digest, Sha512};

        // The n=1 identity as the system creates it: ed25519 from a 32-byte seed
        // (the HKDF identity-key output).
        let seed = [11u8; 32];
        let ed_sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let ed_pub: [u8; 32] = ed_sk.verifying_key().to_bytes();

        // Derive the ed25519 secret scalar: clamp(SHA512(seed)[..32]), reduced mod L
        // to a canonical scalar (g^clamped == g^(clamped mod L) since g has order L).
        let h = Sha512::digest(seed);
        let mut s = [0u8; 32];
        s.copy_from_slice(&h[..32]);
        s[0] &= 248;
        s[31] &= 127;
        s[31] |= 64;
        let scalar_bytes = curve25519_dalek::Scalar::from_bytes_mod_order(s).to_bytes();

        // Bridge into FROST and confirm the group key == the original DID's key.
        let frost_sk =
            frost::SigningKey::deserialize(&scalar_bytes).expect("frost key from ed25519 scalar");
        let frost_pub = frost::VerifyingKey::from(&frost_sk)
            .serialize()
            .expect("serialize frost verifying key");
        assert_eq!(
            frost_pub.as_slice(),
            &ed_pub,
            "FROST group key must equal the original ed25519 identity pubkey (DID preserved)"
        );

        // A 2-of-2 split of it must threshold-sign so the aggregate verifies under
        // the ORIGINAL ed25519 public key.
        let mut rng = rand::rngs::OsRng;
        let (shares_map, pubkeys) =
            frost::keys::split(&frost_sk, 2, 2, frost::keys::IdentifierList::Default, &mut rng)
                .unwrap();
        let shares: Vec<(u16, String)> = shares_map
            .iter()
            .enumerate()
            .map(|(i, (_id, ss))| {
                let kp = KeyPackage::try_from(ss.clone()).unwrap();
                ((i + 1) as u16, serialise(&kp).unwrap())
            })
            .collect();
        let pubkey_hex = serialise(&pubkeys).unwrap();
        let msg = b"enroll: split identity threshold-signs under the original DID";
        let sig = sign_with_shares(&shares, &pubkey_hex, 2, msg).unwrap();

        let ed_vk = ed25519_dalek::VerifyingKey::from_bytes(&ed_pub).unwrap();
        let sig_arr: [u8; 64] = sig.as_slice().try_into().unwrap();
        let ed_sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        ed_vk.verify(msg, &ed_sig).expect(
            "FROST threshold signature must verify under the original ed25519 identity key",
        );
    }

    #[test]
    fn split_existing_identity_preserves_did_and_threshold_signs() {
        let seed = [11u8; 32];
        let ed_did = crate::did::DidKeyMethod::from_public_key(
            &ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key(),
        )
        .to_string();

        let (shares, pubkey_hex, did) = split_existing_identity(&seed, 2, 2).unwrap();
        assert_eq!(shares.len(), 2, "2-of-2 split yields two shares");
        assert_eq!(did, ed_did, "split preserves the existing identity's DID");

        // The split shares threshold-sign and verify against the (preserved) group key.
        let msg = b"split-existing-identity threshold signs";
        let sig = sign_with_shares(&shares, &pubkey_hex, 2, msg).unwrap();
        verify_group_sig(&sig, &pubkey_hex, msg);
    }
}
