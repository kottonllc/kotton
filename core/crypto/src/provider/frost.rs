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
use crate::ed25519::{Signature, VerifyingKey};

// ── Error type ────────────────────────────────────────────────────────────────

/// A failure of this module, in this crate's own fixed words. Its surface names no type of the
/// threshold library: a dependent of this crate names the tree's own types only, and the library
/// stays a dependency of this crate alone. `threshold_surface` holds that for every public item of
/// the crate.
///
/// No variant's `Display` or `Debug` holds a byte of the input it failed on: an error's text holds
/// nothing that is not this device's own to say. A reader's or writer's own error (the hex
/// decoder's, the JSON reader's) is not kept, because its text echoes the input; the variant
/// names the kind of thing that could not be read or written instead.
#[derive(Debug, thiserror::Error)]
pub enum FrostError {
    /// A failure the threshold library reported, as this crate's fixed words for it (see
    /// `library`). Each of the library's failures has its own words, so two of them are told
    /// apart by it; the words are the same as the library's own message for it, which the tests
    /// hold, and no value the failure carries (a participant's identifier) is part of them.
    #[error("FROST: {0}")]
    Frost(&'static str),
    /// A value of this module that could not be written.
    #[error("could not write {0}")]
    Serialise(FrostPart),
    /// A serialised value that could not be read as the kind of thing it was given as.
    #[error("could not read {0}")]
    Deserialise(FrostPart),
    /// A participant index that names no participant. The index is not part of the text.
    #[error("invalid participant index")]
    InvalidIndex,
    /// A group key, or an aggregated signature under it, that the Ed25519 rule refuses.
    #[error("FROST: {0}")]
    Refused(#[from] crate::ed25519::Refused),
}

/// The kind of thing a [`FrostError::Serialise`] or [`FrostError::Deserialise`] could not write
/// or read. Its text is this crate's fixed words for the kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrostPart {
    /// A participant's key package: its secret share and the group key.
    KeyPackage,
    /// The group's public key package.
    PublicKeyPackage,
    /// A participant's identifier.
    Identifier,
    /// A participant's round-one signing nonces.
    Nonces,
    /// A participant's round-one signing commitments.
    Commitments,
    /// A signing package: the message and every participant's commitments.
    SigningPackage,
    /// A participant's signature share.
    SignatureShare,
    /// The aggregated signature.
    Signature,
    /// The group's verifying key.
    GroupKey,
    /// The group's DID, derived from its verifying key.
    GroupDid,
    /// The secret share the dealer made for a participant.
    SecretShare,
    /// An existing identity's key, taken as a threshold signing key.
    SigningKey,
    /// A participant's key-generation round-one secret package.
    Round1Secret,
    /// A participant's key-generation round-one package.
    Round1Package,
    /// A participant's key-generation round-two secret package.
    Round2Secret,
    /// A key-generation round-two package.
    Round2Package,
}

impl std::fmt::Display for FrostPart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::KeyPackage => "a key package",
            Self::PublicKeyPackage => "a public key package",
            Self::Identifier => "a participant identifier",
            Self::Nonces => "round-one signing nonces",
            Self::Commitments => "round-one signing commitments",
            Self::SigningPackage => "a signing package",
            Self::SignatureShare => "a signature share",
            Self::Signature => "a signature",
            Self::GroupKey => "the group verifying key",
            Self::GroupDid => "the group DID",
            Self::SecretShare => "a secret share",
            Self::SigningKey => "a signing key",
            Self::Round1Secret => "a key-generation round-one secret package",
            Self::Round1Package => "a key-generation round-one package",
            Self::Round2Secret => "a key-generation round-two secret package",
            Self::Round2Package => "a key-generation round-two package",
        })
    }
}

pub type FrostResult<T> = Result<T, FrostError>;

/// Output of generating or splitting a group key:
/// `(shares as (index, key_package_hex), pubkey_package_hex, did)`.
pub type KeyShares = FrostResult<(Vec<(u16, String)>, String, String)>;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// The library's failure as [`FrostError::Frost`], in this crate's fixed words for it. A function
/// and not a `From` impl, because an impl of a public trait for a public type is public and would
/// name the library's type.
///
/// The words are this crate's own, chosen by the variant and never taken from the error, so no
/// value a failure carries reaches the text, nor would one a later version of the library added
/// to its message. They equal the library's own message for every variant this crate names,
/// which `every_library_failure_says_the_fixed_words_the_library_gives_it` holds; a variant this
/// crate does not name says so in fixed words.
fn library(e: frost::Error) -> FrostError {
    use frost::Error as E;
    FrostError::Frost(match e {
        E::InvalidMinSigners => "min_signers must be at least 2 and not larger than max_signers",
        E::InvalidMaxSigners => "max_signers must be at least 2",
        E::InvalidCoefficients => "coefficients must have min_signers-1 elements",
        E::MalformedIdentifier => "Malformed identifier is unserializable.",
        E::DuplicatedIdentifier => "Duplicated identifier.",
        E::UnknownIdentifier => "Unknown identifier.",
        E::IncorrectNumberOfIdentifiers => "Incorrect number of identifiers.",
        E::MalformedSigningKey => "Malformed signing key encoding.",
        E::MalformedVerifyingKey => "Malformed verifying key encoding.",
        E::MalformedSignature => "Malformed signature encoding.",
        E::InvalidSignature => "Invalid signature.",
        E::DuplicatedShares => "Duplicated shares provided.",
        E::IncorrectNumberOfShares => "Incorrect number of shares.",
        E::IdentityCommitment => "Commitment equals the identity.",
        E::MissingCommitment => "The Signing Package must contain the participant's Commitment.",
        E::IncorrectCommitment => "The participant's commitment is incorrect.",
        E::IncorrectNumberOfCommitments => "Incorrect number of commitments.",
        E::InvalidSignatureShare { .. } => "Invalid signature share.",
        E::InvalidSecretShare { .. } => "Invalid secret share.",
        E::PackageNotFound => "Round 1 package not found for Round 2 participant.",
        E::IncorrectNumberOfPackages => "Incorrect number of packages.",
        E::IncorrectPackage => "The incorrect package was specified.",
        E::DKGNotSupported => "The ciphersuite does not support DKG.",
        E::InvalidProofOfKnowledge { .. } => "The proof of knowledge is not valid.",
        E::FieldError(_) => "Error in scalar Field.",
        E::GroupError(_) => "Error in elliptic curve Group.",
        E::InvalidCoefficient => "Invalid coefficient",
        E::IdentifierDerivationNotSupported => {
            "The ciphersuite does not support deriving identifiers from strings."
        }
        E::SerializationError => "Error serializing value.",
        E::DeserializationError => "Error deserializing value.",
        _ => "a failure this crate has no words for",
    })
}

fn id_from_index(idx: u16) -> FrostResult<Identifier> {
    Identifier::try_from(idx).map_err(|_| FrostError::InvalidIndex)
}

fn hex_enc(b: &[u8]) -> String {
    hex::encode(b)
}

/// `s` as bytes, or [`FrostError::Deserialise`] naming `part`. The decoder's own error names the
/// character it stopped at, so it is not kept.
fn hex_dec(s: &str, part: FrostPart) -> FrostResult<Vec<u8>> {
    hex::decode(s).map_err(|_| FrostError::Deserialise(part))
}

/// `v` as hex of its JSON, or [`FrostError::Serialise`] naming `part`. The writer's own error is
/// not kept.
fn serialise<T: serde::Serialize>(v: &T, part: FrostPart) -> FrostResult<String> {
    let bytes = serde_json::to_vec(v).map_err(|_| FrostError::Serialise(part))?;
    Ok(hex_enc(&bytes))
}

/// `hex` read as hex of a `T`'s JSON, or [`FrostError::Deserialise`] naming `part`. The JSON
/// reader's own error quotes the input it stopped at, so it is not kept.
fn deserialise<T: serde::de::DeserializeOwned>(hex: &str, part: FrostPart) -> FrostResult<T> {
    let bytes = hex_dec(hex, part)?;
    serde_json::from_slice(&bytes).map_err(|_| FrostError::Deserialise(part))
}

/// The group's verifying key as a key that passed the Ed25519 rule: its 32 bytes constructed as
/// [`VerifyingKey`]. Every group key this module reads or returns comes through here.
fn group_key(key: &frost::VerifyingKey) -> FrostResult<VerifyingKey> {
    let bytes: [u8; 32] = key
        .serialize()
        .map_err(|_| FrostError::Serialise(FrostPart::GroupKey))?[..]
        .try_into()
        .map_err(|_| FrostError::Serialise(FrostPart::GroupKey))?;
    Ok(VerifyingKey::from_bytes(&bytes)?)
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
    )
    .map_err(library)?;

    let vk_bytes = *group_key(pubkey_package.verifying_key())?.as_bytes();

    let org_did = DidKeyMethod::from_public_key_bytes(&vk_bytes)
        .map_err(|_| FrostError::Serialise(FrostPart::GroupDid))?
        .to_string();

    let pubkey_hex = serialise(&pubkey_package, FrostPart::PublicKeyPackage)?;

    let mut out = Vec::with_capacity(total as usize);
    for idx in 1..=total {
        let id = id_from_index(idx)?;
        let secret_share =
            shares_map.get(&id).ok_or(FrostError::Deserialise(FrostPart::SecretShare))?;
        let key_package = KeyPackage::try_from(secret_share.clone()).map_err(library)?;
        let kp_hex = serialise(&key_package, FrostPart::KeyPackage)?;
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
        .map_err(|_| FrostError::Deserialise(FrostPart::SigningKey))?;

    let mut rng = rand::rngs::OsRng;
    let (shares_map, pubkey_package) = frost::keys::split(
        &signing_key,
        total,
        threshold,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )
    .map_err(library)?;

    let vk_bytes = *group_key(pubkey_package.verifying_key())?.as_bytes();
    let did = DidKeyMethod::from_public_key_bytes(&vk_bytes)
        .map_err(|_| FrostError::Serialise(FrostPart::GroupDid))?
        .to_string();
    let pubkey_hex = serialise(&pubkey_package, FrostPart::PublicKeyPackage)?;

    let mut out = Vec::with_capacity(total as usize);
    for (idx, (_id, secret_share)) in shares_map.iter().enumerate() {
        let key_package = KeyPackage::try_from(secret_share.clone()).map_err(library)?;
        out.push(((idx + 1) as u16, serialise(&key_package, FrostPart::KeyPackage)?));
    }
    Ok((out, pubkey_hex, did))
}

/// Deserialise and validate a `KeyPackage` hex blob received from the dealer.
///
/// Returns the same hex if valid (noop from the perspective of the caller; the
/// point is the validation step).
pub fn validate_key_package(key_package_hex: &str) -> FrostResult<String> {
    let _kp: KeyPackage = deserialise(key_package_hex, FrostPart::KeyPackage)?;
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
///
/// The group key is constructed as [`VerifyingKey`], so it is a key that passed the Ed25519 rule;
/// a package whose group key the rule refuses yields [`FrostError::Refused`].
pub fn key_package_verifying_key(key_package_hex: &str) -> FrostResult<VerifyingKey> {
    let kp: KeyPackage = deserialise(key_package_hex, FrostPart::KeyPackage)?;
    group_key(kp.verifying_key())
}

// ── Signing — round 1 (commit) ────────────────────────────────────────────────

/// Generate signing nonces and commitments for one participant.
///
/// Returns:
/// - `nonces_hex` — **keep secret**; stored in the daemon and used in round 2.
/// - `commitment_hex` — broadcast to the coordinator.
/// - `participant_id_hex` — the participant's FROST `Identifier` (serialised).
pub fn signing_commit(key_package_hex: &str) -> FrostResult<(String, String, String)> {
    let kp: KeyPackage = deserialise(key_package_hex, FrostPart::KeyPackage)?;
    let mut rng = rand::rngs::OsRng;

    let (nonces, commitment) = frost::round1::commit(kp.signing_share(), &mut rng);

    let nonces_hex = serialise(&nonces, FrostPart::Nonces)?;
    let commitment_hex = serialise(&commitment, FrostPart::Commitments)?;
    let participant_id_hex = serialise(kp.identifier(), FrostPart::Identifier)?;

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
        let id: Identifier = deserialise(id_hex, FrostPart::Identifier)?;
        let comm: round1::SigningCommitments = deserialise(comm_hex, FrostPart::Commitments)?;
        map.insert(id, comm);
    }
    let pkg = SigningPackage::new(map, message);
    serialise(&pkg, FrostPart::SigningPackage)
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
    let kp: KeyPackage = deserialise(key_package_hex, FrostPart::KeyPackage)?;
    let nonces: round1::SigningNonces = deserialise(nonces_hex, FrostPart::Nonces)?;
    let pkg: SigningPackage = deserialise(signing_package_hex, FrostPart::SigningPackage)?;

    let share = frost::round2::sign(&pkg, &nonces, &kp).map_err(library)?;
    serialise(&share, FrostPart::SignatureShare)
}

/// Aggregate signature shares into a final Ed25519 signature.
///
/// `shares` is `&[(participant_id_hex, signature_share_hex)]`.
/// Returns raw 64-byte Ed25519 signature bytes.
///
/// A threshold signature is an Ed25519 signature, and a side that assembles one checks it by the
/// Ed25519 rule before it gives it to anyone. So the group key is constructed as
/// [`VerifyingKey`], and the signature is returned only if that key's
/// [`verify`](VerifyingKey::verify) accepts it over the signing package's message; otherwise
/// this is [`FrostError::Refused`].
pub fn aggregate(
    signing_package_hex: &str,
    pubkey_package_hex: &str,
    shares: &[(String, String)],
) -> FrostResult<Vec<u8>> {
    let pkg: SigningPackage = deserialise(signing_package_hex, FrostPart::SigningPackage)?;
    let pubkey: PublicKeyPackage = deserialise(pubkey_package_hex, FrostPart::PublicKeyPackage)?;

    let mut map = BTreeMap::new();
    for (id_hex, share_hex) in shares {
        let id: Identifier = deserialise(id_hex, FrostPart::Identifier)?;
        let share: round2::SignatureShare = deserialise(share_hex, FrostPart::SignatureShare)?;
        map.insert(id, share);
    }

    let key = group_key(pubkey.verifying_key())?;
    let sig = frost::aggregate(&pkg, &map, &pubkey).map_err(library)?;
    let bytes: [u8; 64] = sig
        .serialize()
        .map_err(|_| FrostError::Serialise(FrostPart::Signature))?[..]
        .try_into()
        .map_err(|_| FrostError::Serialise(FrostPart::Signature))?;
    released(&key, pkg.message(), bytes)
}

/// `signature` as bytes to give out, if `key`'s [`verify`](VerifyingKey::verify) accepts it over
/// `message`. [`aggregate`] returns only through here.
fn released(key: &VerifyingKey, message: &[u8], signature: [u8; 64]) -> FrostResult<Vec<u8>> {
    key.verify(message, &Signature::from_bytes(&signature))?;
    Ok(signature.to_vec())
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
    let (secret, package) = dkg::part1(id, total, threshold, rand::rngs::OsRng).map_err(library)?;
    Ok((
        serialise(&secret, FrostPart::Round1Secret)?,
        serialise(&package, FrostPart::Round1Package)?,
        serialise(&id, FrostPart::Identifier)?,
    ))
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
    let secret: dkg::round1::SecretPackage =
        deserialise(secret_package_hex, FrostPart::Round1Secret)?;
    let mut r1 = BTreeMap::new();
    for (id_hex, pkg_hex) in round1_packages {
        r1.insert(
            deserialise::<Identifier>(id_hex, FrostPart::Identifier)?,
            deserialise(pkg_hex, FrostPart::Round1Package)?,
        );
    }
    let (round2_secret, round2_map) = dkg::part2(secret, &r1).map_err(library)?;
    let mut out = Vec::with_capacity(round2_map.len());
    for (id, pkg) in &round2_map {
        let id_hex = serialise(id, FrostPart::Identifier)?;
        out.push((id_hex, serialise(pkg, FrostPart::Round2Package)?));
    }
    Ok((serialise(&round2_secret, FrostPart::Round2Secret)?, out))
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
    let round2_secret: dkg::round2::SecretPackage =
        deserialise(round2_secret_hex, FrostPart::Round2Secret)?;
    let mut r1 = BTreeMap::new();
    for (id_hex, pkg_hex) in round1_packages {
        r1.insert(
            deserialise::<Identifier>(id_hex, FrostPart::Identifier)?,
            deserialise(pkg_hex, FrostPart::Round1Package)?,
        );
    }
    let mut r2 = BTreeMap::new();
    for (id_hex, pkg_hex) in round2_packages {
        r2.insert(
            deserialise::<Identifier>(id_hex, FrostPart::Identifier)?,
            deserialise(pkg_hex, FrostPart::Round2Package)?,
        );
    }
    let (key_package, pubkey_package) = dkg::part3(&round2_secret, &r1, &r2).map_err(library)?;

    let vk_bytes = *group_key(pubkey_package.verifying_key())?.as_bytes();
    let org_did = DidKeyMethod::from_public_key_bytes(&vk_bytes)
        .map_err(|_| FrostError::Serialise(FrostPart::GroupDid))?
        .to_string();

    Ok((
        serialise(&key_package, FrostPart::KeyPackage)?,
        serialise(&pubkey_package, FrostPart::PublicKeyPackage)?,
        org_did,
    ))
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

    /// Verify an aggregated 64-byte signature against a serialised group key, by the Ed25519
    /// rule: the group key constructed as [`VerifyingKey`] and the signature checked by its
    /// `verify`.
    fn verify_group_sig(sig_bytes: &[u8], pubkey_hex: &str, message: &[u8]) {
        let pubkey: PublicKeyPackage = deserialise(pubkey_hex, FrostPart::PublicKeyPackage).unwrap();
        let key = group_key(pubkey.verifying_key()).expect("the group key passes the rule");
        let arr: [u8; 64] = sig_bytes.try_into().expect("64-byte signature");
        key.verify(message, &Signature::from_bytes(&arr))
            .expect("threshold signature verifies against the group key by the rule");
    }

    /// Every key vector the rule refuses, by name: the eight small-order encodings, the
    /// identity's three other encodings, the mixed-order key, the non-canonical key and the
    /// non-point.
    fn refused_keys() -> Vec<(String, [u8; 32])> {
        use crate::ed25519::refused::*;
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
        let identity = ["identity, y = 1 with the sign bit", "identity, y = p + 1", "identity, y = p + 1 with the sign bit"];
        let keys: Vec<(String, [u8; 32])> = small
            .iter()
            .map(|n| format!("small order: {n}"))
            .zip(SMALL_ORDER_KEYS)
            .chain(identity.iter().map(|n| n.to_string()).zip(IDENTITY_OTHER_ENCODINGS))
            .chain([
                ("mixed order".to_string(), mixed_order_key()),
                ("not canonical".to_string(), NON_CANONICAL_KEY),
                ("not a point".to_string(), NOT_A_POINT),
            ])
            .collect();
        assert_eq!(keys.len(), SMALL_ORDER_KEYS.len() + IDENTITY_OTHER_ENCODINGS.len() + 3);
        keys
    }

    /// `serialised` (a hex blob of this module's) with its `verifying_key` field set to `key`.
    fn with_group_key(serialised: &str, key: &[u8; 32]) -> String {
        let mut value: serde_json::Value = deserialise(serialised, FrostPart::KeyPackage).unwrap();
        let field = value.get_mut("verifying_key").expect("the package names its group key");
        assert!(field.is_string(), "the group key is serialised as hex");
        *field = serde_json::Value::String(hex::encode(key));
        serialise(&value, FrostPart::KeyPackage).unwrap()
    }

    /// The pieces of one 2-of-2 ceremony up to aggregation, by the trusted dealer:
    /// `(signing_package_hex, pubkey_package_hex, shares, key_package_hex of participant 1)`.
    fn ceremony(message: &[u8]) -> (String, String, Vec<(String, String)>, String) {
        let (shares, pubkey_hex, _did) = generate_key_shares(2, 2).unwrap();
        let mut commitments = Vec::new();
        let mut nonces = Vec::new();
        for (_idx, kp_hex) in &shares {
            let (n, c, id) = signing_commit(kp_hex).unwrap();
            commitments.push((id, c));
            nonces.push(n);
        }
        let pkg_hex = create_signing_package(message, &commitments).unwrap();
        let sig_shares = shares
            .iter()
            .zip(&nonces)
            .zip(&commitments)
            .map(|(((_idx, kp_hex), n), (id, _))| (id.clone(), signing_sign(kp_hex, n, &pkg_hex).unwrap()))
            .collect();
        (pkg_hex, pubkey_hex, sig_shares, shares[0].1.clone())
    }

    /// `signature` with the group order added to its `S`: the same point equation, `S` not
    /// reduced.
    fn with_order_added_to_s(signature: &[u8]) -> [u8; 64] {
        let mut sig: [u8; 64] = signature.try_into().unwrap();
        let order_minus_one = (curve25519_dalek::Scalar::ZERO - curve25519_dalek::Scalar::ONE).to_bytes();
        let mut carry = 1u16;
        for i in 0..32 {
            let sum = sig[32 + i] as u16 + order_minus_one[i] as u16 + carry;
            sig[32 + i] = sum as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0, "S plus the order fits in 256 bits");
        sig
    }

    /// The group key a ceremony's public key package names, by the rule.
    fn ceremony_key(pubkey_hex: &str) -> VerifyingKey {
        let pubkey: PublicKeyPackage = deserialise(pubkey_hex, FrostPart::PublicKeyPackage).unwrap();
        group_key(pubkey.verifying_key()).unwrap()
    }

    /// Where the group key enters `aggregate`: the public key package. A package naming any
    /// refused key yields no signature from shares that aggregate under the honest one.
    #[test]
    fn aggregate_refuses_a_public_key_package_whose_group_key_the_rule_refuses() {
        let message = b"a quorum signs";
        let (pkg_hex, pubkey_hex, shares, _kp) = ceremony(message);
        let honest = *ceremony_key(&pubkey_hex).as_bytes();
        let sig = aggregate(&pkg_hex, &with_group_key(&pubkey_hex, &honest), &shares)
            .expect("the package with its own group key written back aggregates");
        verify_group_sig(&sig, &pubkey_hex, message);

        let accepted: Vec<String> = refused_keys()
            .into_iter()
            .filter(|(_, key)| aggregate(&pkg_hex, &with_group_key(&pubkey_hex, key), &shares).is_ok())
            .map(|(name, _)| name)
            .collect();
        assert!(accepted.is_empty(), "aggregate accepted a group key the rule refuses: {accepted:?}");
    }

    /// Where the group key enters from a received share: the key package. A package naming any
    /// refused key yields no key.
    #[test]
    fn a_key_package_whose_group_key_the_rule_refuses_yields_no_key() {
        let (_pkg, pubkey_hex, _shares, kp_hex) = ceremony(b"unused");
        let honest = ceremony_key(&pubkey_hex);
        assert_eq!(key_package_verifying_key(&with_group_key(&kp_hex, honest.as_bytes())).unwrap(), honest);
        assert_eq!(key_package_verifying_key(&kp_hex).unwrap(), honest);

        let accepted: Vec<String> = refused_keys()
            .into_iter()
            .filter(|(_, key)| key_package_verifying_key(&with_group_key(&kp_hex, key)).is_ok())
            .map(|(name, _)| name)
            .collect();
        assert!(accepted.is_empty(), "a key package yielded a group key the rule refuses: {accepted:?}");
    }

    /// The signature `aggregate` returns, from a real ceremony, with the group order added to
    /// its `S`: `released` gives out the real one and refuses the variant.
    #[test]
    fn released_refuses_a_real_aggregate_with_the_group_order_added_to_s() {
        let message = b"a quorum signs";
        let (pkg_hex, pubkey_hex, shares, _kp) = ceremony(message);
        let key = ceremony_key(&pubkey_hex);
        let sig: [u8; 64] = aggregate(&pkg_hex, &pubkey_hex, &shares).unwrap().try_into().unwrap();
        assert_eq!(released(&key, message, sig).unwrap(), sig.to_vec());
        assert!(matches!(released(&key, message, with_order_added_to_s(&sig)), Err(FrostError::Refused(_))));
    }

    /// A signature under the group key whose `R` is the identity, with the `S` that completes
    /// the equation. The group key is a split of a known seed, so the test can make it;
    /// `released` refuses it.
    #[test]
    fn released_refuses_a_signature_under_the_group_key_whose_r_is_of_small_order() {
        let seed = [11u8; 32];
        let (_shares, pubkey_hex, _did) = split_existing_identity(&seed, 2, 2).unwrap();
        let key = ceremony_key(&pubkey_hex);
        let signer = ed25519_dalek::SigningKey::from_bytes(&seed);
        assert_eq!(key.as_bytes(), signer.verifying_key().as_bytes());

        let message = b"a quorum signs";
        let sig = crate::ed25519::refused::small_order_r(&signer, message);
        assert!(matches!(released(&key, message, sig.to_bytes()), Err(FrostError::Refused(_))));
    }

    /// Why no test shows `aggregate` refusing a signature its library accepted: the library
    /// decodes `S` only below the group order and `R` only as a point of the prime-order
    /// subgroup other than the identity, and checks the equation without the cofactor. So the
    /// rule's signature vectors under the group key do not decode as the library's signature at
    /// all, and what does decode and check is what the rule accepts.
    #[test]
    fn the_threshold_library_does_not_decode_a_signature_the_rule_refuses() {
        use crate::ed25519::refused::*;
        let seed = [11u8; 32];
        let signer = ed25519_dalek::SigningKey::from_bytes(&seed);
        let message = b"a quorum signs";
        let (pkg_hex, pubkey_hex, shares, _kp) = ceremony(message);
        let real = aggregate(&pkg_hex, &pubkey_hex, &shares).unwrap();

        let mut cases = vec![
            ("S not reduced, a real aggregate".to_string(), with_order_added_to_s(&real)),
            ("R the identity".to_string(), small_order_r(&signer, message).to_bytes()),
            ("S not reduced".to_string(), unreduced_s(&signer, message).to_bytes()),
        ];
        cases.extend(
            IDENTITY_OTHER_ENCODINGS
                .iter()
                .enumerate()
                .map(|(i, r)| (format!("R another encoding of the identity, {i}"), with_r(&signer, message, *r).to_bytes())),
        );
        let real: [u8; 64] = real.try_into().unwrap();
        assert!(frost::Signature::deserialize(&real).is_ok(), "the library decodes the real aggregate");
        let decoded: Vec<String> = cases
            .into_iter()
            .filter(|(_, sig)| frost::Signature::deserialize(sig).is_ok())
            .map(|(name, _)| name)
            .collect();
        assert!(decoded.is_empty(), "the library decoded a signature the rule refuses: {decoded:?}");
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

        // Independently verify the aggregated signature against the group key, by the rule.
        verify_group_sig(&sig_bytes, &pubkey_hex, message);
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
                ((i + 1) as u16, serialise(&kp, FrostPart::KeyPackage).unwrap())
            })
            .collect();
        let pubkey_hex = serialise(&pubkeys, FrostPart::PublicKeyPackage).unwrap();
        let msg = b"enroll: split identity threshold-signs under the original DID";
        let sig = sign_with_shares(&shares, &pubkey_hex, 2, msg).unwrap();

        let ed_vk = ed25519_dalek::VerifyingKey::from_bytes(&ed_pub).unwrap();
        let sig_arr: [u8; 64] = sig.as_slice().try_into().unwrap();
        let ed_sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        crate::ed25519::verify(&ed_vk, msg, &ed_sig).expect(
            "FROST threshold signature must verify under the original ed25519 identity key",
        );
    }

    #[test]
    fn split_existing_identity_preserves_did_and_threshold_signs() {
        let seed = [11u8; 32];
        let ed_did = crate::did::DidKeyMethod::from_public_key(
            &crate::ed25519::verifying_key(&ed25519_dalek::SigningKey::from_bytes(&seed)),
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

    /// A failure of the threshold library comes back as [`FrostError::Frost`] saying the
    /// library's own text for it, and two different failures come back told apart: a threshold
    /// under two and a group under two are not the same error.
    #[test]
    fn a_library_failure_keeps_the_library_text_that_tells_it_apart() {
        let said = |r: KeyShares| match r {
            Err(e @ FrostError::Frost(_)) => e.to_string(),
            other => panic!("expected the library's failure, got {other:?}"),
        };
        let threshold = said(generate_key_shares(1, 3));
        let group = said(generate_key_shares(2, 1));
        assert_eq!(threshold, format!("FROST: {}", frost::Error::InvalidMinSigners));
        assert_eq!(group, format!("FROST: {}", frost::Error::InvalidMaxSigners));
        assert_ne!(threshold, group);
        assert_eq!(said(split_existing_identity(&[7; 32], 1, 3)), threshold);
    }

    /// What each [`FrostError`] says, and that none says the input it failed on. Every input
    /// here carries a marker placed where a reader's own error would echo it; the assertion
    /// messages name what was read and never the text, which could hold the input.
    mod error_text {
        use super::*;

        /// Not hex, and not a word any of this module's texts holds.
        const MARKER: &str = "M4RK3R-QX";

        /// Every kind of thing, with this crate's words for it.
        const PARTS: [(FrostPart, &str); 16] = [
            (FrostPart::KeyPackage, "a key package"),
            (FrostPart::PublicKeyPackage, "a public key package"),
            (FrostPart::Identifier, "a participant identifier"),
            (FrostPart::Nonces, "round-one signing nonces"),
            (FrostPart::Commitments, "round-one signing commitments"),
            (FrostPart::SigningPackage, "a signing package"),
            (FrostPart::SignatureShare, "a signature share"),
            (FrostPart::Signature, "a signature"),
            (FrostPart::GroupKey, "the group verifying key"),
            (FrostPart::GroupDid, "the group DID"),
            (FrostPart::SecretShare, "a secret share"),
            (FrostPart::SigningKey, "a signing key"),
            (FrostPart::Round1Secret, "a key-generation round-one secret package"),
            (FrostPart::Round1Package, "a key-generation round-one package"),
            (FrostPart::Round2Secret, "a key-generation round-two secret package"),
            (FrostPart::Round2Package, "a key-generation round-two package"),
        ];

        /// `e` says exactly `display` and `debug`, and neither holds any of `markers`.
        fn says(what: &str, e: &FrostError, display: &str, debug: &str, markers: &[String]) {
            let shown = e.to_string();
            let dbg = format!("{e:?}");
            for m in markers {
                assert!(!shown.contains(m.as_str()), "the Display of the failure to read {what} holds the input's marker");
                assert!(!dbg.contains(m.as_str()), "the Debug of the failure to read {what} holds the input's marker");
            }
            assert!(shown == display, "the failure to read {what} does not say {display:?}");
            assert!(dbg == debug, "the failure to read {what} does not debug as {debug:?}");
        }

        /// The failure of `r`, without printing what it would have returned.
        fn failure<T>(what: &str, r: FrostResult<T>) -> FrostError {
            match r {
                Err(e) => e,
                Ok(_) => panic!("reading a marked {what} did not fail"),
            }
        }

        /// Inputs that cannot be read, each carrying the marker where a reader would echo it:
        /// a character that is not hex; hex of a JSON string where another type belongs; and,
        /// for each top-level field of `valid` (hex of a JSON object), that field as an over-long
        /// string that is not hex where it was a string, and as the marker where it was not.
        fn marked(valid: Option<&str>) -> Vec<(String, Vec<String>)> {
            let mut out = vec![
                (format!("00~{MARKER}"), vec![MARKER.to_string(), "~".to_string()]),
                (hex::encode(format!("\"{MARKER}\"")), vec![MARKER.to_string()]),
            ];
            let Some(valid) = valid else { return out };
            let value: serde_json::Value = serde_json::from_slice(&hex::decode(valid).unwrap()).unwrap();
            let fields = value.as_object().expect("a package is a JSON object");
            assert!(!fields.is_empty());
            for (name, field) in fields {
                let mut changed = value.clone();
                changed[name] = serde_json::Value::String(if field.is_string() {
                    MARKER.repeat(16)
                } else {
                    MARKER.to_string()
                });
                out.push((hex::encode(serde_json::to_vec(&changed).unwrap()), vec![MARKER.to_string()]));
            }
            out
        }

        /// Every marked input to `read` fails as [`FrostError::Deserialise`] of `part`, saying so in
        /// this crate's words and nothing of the input.
        fn reads_marked<T>(part: FrostPart, valid: Option<&str>, read: impl Fn(&str) -> FrostResult<T>) {
            let words = PARTS.iter().find(|(p, _)| *p == part).unwrap().1;
            let inputs = marked(valid);
            assert!(inputs.len() >= 2);
            for (input, markers) in &inputs {
                let e = failure(words, read(input));
                says(words, &e, &format!("could not read {words}"), &format!("Deserialise({part:?})"), markers);
            }
        }

        /// A value whose writer fails with the marker as its error.
        struct Unwritable;

        impl serde::Serialize for Unwritable {
            fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom(MARKER))
            }
        }

        #[test]
        fn each_kind_of_thing_has_its_own_words() {
            let words: std::collections::BTreeSet<_> = PARTS.iter().map(|(p, _)| p.to_string()).collect();
            assert_eq!(words.len(), PARTS.len(), "two kinds of thing share their words");
            for (part, said) in PARTS {
                assert_eq!(part.to_string(), said);
            }
        }

        /// A writer's own error is not part of [`FrostError::Serialise`]: the text names the
        /// kind of thing and holds nothing the writer said.
        #[test]
        fn a_failure_to_write_names_the_thing_and_not_the_writers_text() {
            assert!(serde_json::to_vec(&Unwritable).unwrap_err().to_string().contains(MARKER));
            for (part, words) in PARTS {
                let e = failure(words, serialise(&Unwritable, part));
                let shown = e.to_string();
                let dbg = format!("{e:?}");
                assert!(!shown.contains(MARKER), "the Display of the failure to write {words} holds the writer's text");
                assert!(!dbg.contains(MARKER), "the Debug of the failure to write {words} holds the writer's text");
                assert_eq!(shown, format!("could not write {words}"));
                assert_eq!(dbg, format!("Serialise({part:?})"));
            }
        }

        /// The secret material a participant holds (its key package, its signing nonces) and
        /// what it reads from others in a signing ceremony each fail to read as the kind of
        /// thing it is, with none of the input in the text.
        #[test]
        fn a_failure_to_read_a_signing_piece_names_it_and_holds_none_of_the_input() {
            let message = b"marked inputs";
            let (shares, pk, _did) = generate_key_shares(2, 2).unwrap();
            let (kp1, kp2) = (&shares[0].1, &shares[1].1);
            let (n1, c1, id1) = signing_commit(kp1).unwrap();
            let (n2, c2, id2) = signing_commit(kp2).unwrap();
            let commitments = [(id1.clone(), c1.clone()), (id2.clone(), c2.clone())];
            let pkg = create_signing_package(message, &commitments).unwrap();
            let s1 = signing_sign(kp1, &n1, &pkg).unwrap();
            let s2 = signing_sign(kp2, &n2, &pkg).unwrap();
            let sig_shares = [(id1.clone(), s1.clone()), (id2.clone(), s2.clone())];
            assert!(aggregate(&pkg, &pk, &sig_shares).is_ok());

            reads_marked(FrostPart::KeyPackage, Some(kp1), validate_key_package);
            reads_marked(FrostPart::KeyPackage, Some(kp1), key_package_verifying_key);
            reads_marked(FrostPart::KeyPackage, Some(kp1), signing_commit);
            reads_marked(FrostPart::Nonces, Some(&n1), |x| signing_sign(kp1, x, &pkg));
            reads_marked(FrostPart::SigningPackage, Some(&pkg), |x| signing_sign(kp1, &n1, x));
            reads_marked(FrostPart::SigningPackage, Some(&pkg), |x| aggregate(x, &pk, &sig_shares));
            reads_marked(FrostPart::Identifier, None, |x| {
                create_signing_package(message, &[(x.to_string(), c1.clone()), (id2.clone(), c2.clone())])
            });
            reads_marked(FrostPart::Commitments, Some(&c1), |x| {
                create_signing_package(message, &[(id1.clone(), x.to_string()), (id2.clone(), c2.clone())])
            });
            reads_marked(FrostPart::PublicKeyPackage, Some(&pk), |x| aggregate(&pkg, x, &sig_shares));
            reads_marked(FrostPart::Identifier, None, |x| {
                aggregate(&pkg, &pk, &[(x.to_string(), s1.clone()), (id2.clone(), s2.clone())])
            });
            reads_marked(FrostPart::SignatureShare, None, |x| {
                aggregate(&pkg, &pk, &[(id1.clone(), x.to_string()), (id2.clone(), s2.clone())])
            });
        }

        /// The round secrets of key generation, and the packages a participant reads from the
        /// others, each fail to read as the kind of thing it is, with none of the input in the
        /// text.
        #[test]
        fn a_failure_to_read_a_key_generation_piece_names_it_and_holds_none_of_the_input() {
            let (sec1, p1, id1) = dkg_part1(1, 2, 2).unwrap();
            let (sec2, p2, id2) = dkg_part1(2, 2, 2).unwrap();
            let from_2 = [(id2.clone(), p2.clone())];
            let from_1 = [(id1.clone(), p1.clone())];
            let (r2sec1, _to_others_1) = dkg_part2(&sec1, &from_2).unwrap();
            let (_r2sec2, to_others_2) = dkg_part2(&sec2, &from_1).unwrap();
            let to_1: Vec<(String, String)> =
                to_others_2.into_iter().map(|(_to, pkg)| (id2.clone(), pkg)).collect();
            assert!(dkg_part3(&r2sec1, &from_2, &to_1).is_ok());

            reads_marked(FrostPart::Round1Secret, Some(&sec1), |x| dkg_part2(x, &from_2));
            reads_marked(FrostPart::Identifier, None, |x| dkg_part2(&sec1, &[(x.to_string(), p2.clone())]));
            reads_marked(FrostPart::Round1Package, Some(&p2), |x| dkg_part2(&sec1, &[(id2.clone(), x.to_string())]));
            reads_marked(FrostPart::Round2Secret, Some(&r2sec1), |x| dkg_part3(x, &from_2, &to_1));
            reads_marked(FrostPart::Round1Package, Some(&p2), |x| {
                dkg_part3(&r2sec1, &[(id2.clone(), x.to_string())], &to_1)
            });
            reads_marked(FrostPart::Round2Package, Some(&to_1[0].1), |x| {
                dkg_part3(&r2sec1, &from_2, &[(id2.clone(), x.to_string())])
            });
        }

        /// An index that names no participant says so without the index.
        #[test]
        fn an_invalid_index_does_not_say_the_index() {
            let e = failure("a participant index", dkg_part1(0, 2, 2));
            assert!(matches!(e, FrostError::InvalidIndex));
            for text in [e.to_string(), format!("{e:?}")] {
                assert!(!text.chars().any(|c| c.is_ascii_digit()), "the failure for an index holds a digit");
            }
            assert_eq!(e.to_string(), "invalid participant index");
        }

        /// A key package naming a group key the Ed25519 rule refuses fails without the key in
        /// its text, whether the library refuses to read the key (the package could not be
        /// read) or the rule refuses it; and a signature the rule refuses fails without the
        /// signature in its text.
        #[test]
        fn a_refused_key_or_signature_is_not_in_the_text() {
            let not_in = |what: &str, e: &FrostError, bytes: &[u8]| {
                let markers = [hex::encode(bytes), hex::encode(&bytes[..4]), format!("{:?}", &bytes[..4])];
                for text in [e.to_string(), format!("{e:?}")] {
                    for m in &markers {
                        assert!(!text.contains(m.as_str()), "{what}: the failure holds the bytes refused");
                    }
                }
            };
            let (shares, _pk, _did) = generate_key_shares(2, 2).unwrap();
            for (name, key) in refused_keys() {
                let e = failure(&name, key_package_verifying_key(&with_group_key(&shares[0].1, &key)));
                not_in(&name, &e, &key);
                match e {
                    FrostError::Refused(_) => assert_eq!(e.to_string(), "FROST: refused by the Ed25519 rule"),
                    FrostError::Deserialise(FrostPart::KeyPackage) => {
                        assert_eq!(e.to_string(), "could not read a key package")
                    }
                    _ => panic!("{name}: neither refused by the rule nor unread as a key package"),
                }
            }

            let message = b"a quorum signs";
            let (pkg_hex, pubkey_hex, sig_shares, _kp) = ceremony(message);
            let key = ceremony_key(&pubkey_hex);
            let sig = aggregate(&pkg_hex, &pubkey_hex, &sig_shares).unwrap();
            let refused = with_order_added_to_s(&sig);
            let e = failure("a signature", released(&key, message, refused));
            assert!(matches!(e, FrostError::Refused(_)));
            not_in("a signature", &e, &refused[32..]);
            assert_eq!(e.to_string(), "FROST: refused by the Ed25519 rule");
            assert_eq!(format!("{e:?}"), "Refused(Refused)");
        }

        /// Every failure of the threshold library this crate names comes back in fixed words that
        /// equal the library's own message for it, so a message of the library that carried a
        /// value would differ and fail here; and no value a failure carries (a participant's
        /// identifier, here a marked one) is in the `Display` or `Debug`. This holds the variants
        /// the library has at the version in the lockfile; a variant a later version adds is not
        /// listed here, and `library` gives it fixed words of its own.
        #[test]
        fn every_library_failure_says_the_fixed_words_the_library_gives_it() {
            use frost::{Error as E, FieldError, GroupError};
            let culprit = Identifier::try_from(0xbeef_u16).unwrap();
            let markers = [
                hex::encode(culprit.serialize()),
                "efbe".to_string(),
                "beef".to_string(),
                0xbeef_u16.to_string(),
                format!("{culprit:?}"),
            ];
            let failures = [
                E::InvalidMinSigners,
                E::InvalidMaxSigners,
                E::InvalidCoefficients,
                E::MalformedIdentifier,
                E::DuplicatedIdentifier,
                E::UnknownIdentifier,
                E::IncorrectNumberOfIdentifiers,
                E::MalformedSigningKey,
                E::MalformedVerifyingKey,
                E::MalformedSignature,
                E::InvalidSignature,
                E::DuplicatedShares,
                E::IncorrectNumberOfShares,
                E::IdentityCommitment,
                E::MissingCommitment,
                E::IncorrectCommitment,
                E::IncorrectNumberOfCommitments,
                E::InvalidSignatureShare { culprit },
                E::InvalidSecretShare { culprit: Some(culprit) },
                E::InvalidSecretShare { culprit: None },
                E::PackageNotFound,
                E::IncorrectNumberOfPackages,
                E::IncorrectPackage,
                E::DKGNotSupported,
                E::InvalidProofOfKnowledge { culprit },
                E::FieldError(FieldError::MalformedScalar),
                E::FieldError(FieldError::InvalidZeroScalar),
                E::GroupError(GroupError::MalformedElement),
                E::GroupError(GroupError::InvalidIdentityElement),
                E::GroupError(GroupError::InvalidNonPrimeOrderElement),
                E::InvalidCoefficient,
                E::IdentifierDerivationNotSupported,
                E::SerializationError,
                E::DeserializationError,
            ];
            let mut distinct = std::collections::BTreeSet::new();
            for e in failures {
                let theirs = e.to_string();
                let ours = library(e);
                assert!(matches!(ours, FrostError::Frost(_)));
                assert_eq!(ours.to_string(), format!("FROST: {theirs}"), "the words for a library failure differ from the library's");
                for text in [ours.to_string(), format!("{ours:?}")] {
                    for m in &markers {
                        assert!(!text.contains(m.as_str()), "a library failure's text holds the identifier it carries");
                    }
                }
                distinct.insert(ours.to_string());
            }
            // Variants that carry a different value, or a different inner error, share their words;
            // every other pair is told apart.
            assert_eq!(distinct.len(), failures.len() - 1 - 1 - 2);
        }
    }
}
