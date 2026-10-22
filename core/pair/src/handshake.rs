// SPDX-License-Identifier: AGPL-3.0-or-later
//! Committed ephemeral-ECDH pairing handshake (RFC-0040 §2, §4).
//!
//! This module is the **security-load-bearing core** of the device-pairing
//! ceremony: it turns a fresh, ephemeral X25519 exchange into a 6-digit
//! short authentication string (SAS) that a human compares on two screens, plus
//! the confirmation MACs and channel key that gate the RFC-0033 payload transfer.
//! It is pure crypto — no network, no state machine, no I/O. The tier-05 ceremony
//! (`core/05_runtime/src/user/pairing.rs`) drives the wire; this module owns the
//! math so the wire cannot get the key schedule wrong.
//!
//! # Why a commitment round (the grinding attack)
//!
//! A naive SAS — exchange ephemeral keys, derive `SAS = H(ss, pubs)`, compare — is
//! broken cheaply (RFC-0040 §4). A man-in-the-middle runs two handshakes and
//! controls ordering: it finishes the joiner side first (fixing `SAS_J`), then
//! *grinds* candidate ephemeral keypairs on the issuer side until the issuer SAS
//! equals `SAS_J`. Six digits is ~2²⁰ ≈ 10⁶ X25519 ops — a few seconds. Both
//! screens then show the same digits and the humans confirm a channel the attacker
//! owns.
//!
//! The fix (ZRTP RFC 6189 / Bluetooth numeric comparison): the **issuer commits**
//! `SHA-256(eph_pub_I ‖ nonce_I)` before seeing the joiner's key, and the joiner
//! **reveals** before seeing the issuer's key. Neither party — and no interposer —
//! can choose a key after learning anything about the resulting SAS, so a MITM's
//! success is exactly `10⁻⁶` per human-initiated ceremony with no computational
//! shortcut. **The commit round is not optional; removing it re-opens the grind.**
//!
//! # Key schedule (RFC-0040 reference-level notes — do not improvise)
//!
//! ```text
//! transcript = "kotton:pair:v1" ‖ sid ‖ commit ‖ eph_pub_I ‖ eph_pub_J ‖ nonce_I ‖ nonce_J
//!              (every field fixed-length, so plain concatenation is unambiguous)
//! prk        = HKDF-Extract(salt = SHA-256(transcript), ikm = X25519(own_eph_priv, peer_eph_pub))
//! k_enc      = HKDF-Expand(prk, "kotton:pair:enc:v1",          32)
//! k_conf_I   = HKDF-Expand(prk, "kotton:pair:conf-issuer:v1",  32)
//! k_conf_J   = HKDF-Expand(prk, "kotton:pair:conf-joiner:v1",  32)
//! sas_seed   = HKDF-Expand(prk, "kotton:pair:sas:v1",           8)
//! SAS        = u64_be(sas_seed) mod 1_000_000        // bias ≈ 10⁻¹³, negligible
//! confirm    = HMAC-SHA256(k_conf_role, b"<role>-confirmed" ‖ transcript)
//! ```
//!
//! **Stability contract:** the domain-separation strings above are pinned by
//! RFC-0040. A wire-compatible peer must use them byte-for-byte; a future v2
//! bumps `:v1` → `:v2` throughout (the version is transcript-bound, so v1 and v2
//! cannot be confused).

use anyhow::{anyhow, Result};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use ring::digest;
use ring::hmac;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

// ── Pinned domain-separation labels (RFC-0040 key schedule) ────────────────────

/// Prefix binding every transcript to this protocol and version.
const TRANSCRIPT_PREFIX: &[u8] = b"kotton:pair:v1";
const LABEL_ENC: &[u8] = b"kotton:pair:enc:v1";
const LABEL_CONF_ISSUER: &[u8] = b"kotton:pair:conf-issuer:v1";
const LABEL_CONF_JOINER: &[u8] = b"kotton:pair:conf-joiner:v1";
const LABEL_SAS: &[u8] = b"kotton:pair:sas:v1";

/// The SAS is six decimal digits: `u64_be(sas_seed) mod 10^6`.
const SAS_MODULUS: u64 = 1_000_000;

// ── HMAC-SHA256 helper (RFC-0040 asks for one here if absent) ──────────────────

/// Compute an HMAC-SHA256 tag over `msg` under `key`. Returns the 32-byte tag.
///
/// A thin wrapper over `ring::hmac` so higher tiers get a fixed-output helper
/// without depending on `ring` directly. Used for the pairing confirmation MACs;
/// generic enough to reuse elsewhere.
pub fn hmac_sha256(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    hmac_sha256_var(key, msg)
}

/// HMAC-SHA256 with a variable-length key.
///
/// The general primitive; [`hmac_sha256`] is the fixed-32-byte-key form used
/// by the pairing MACs. Needed by derived-signature schemes whose keys are not
/// 32 bytes — the extension credential oracle (RFC-0049) keys chained HMACs
/// with secret material of arbitrary length, the way AWS SigV4 does.
pub fn hmac_sha256_var(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&k, msg);
    let mut out = [0u8; 32];
    // HMAC-SHA256 always produces 32 bytes.
    out.copy_from_slice(tag.as_ref());
    out
}

// ── EnrollmentSide ───────────────────────────────────────────────────────────────────────

/// Which side of the pairing a value belongs to. The two sides derive
/// **separate** confirmation keys (`k_conf_I` / `k_conf_J`) so a confirmation MAC
/// cannot be reflected from one direction to the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Which side of an *enrollment* handshake this device is.
///
/// Not [`crate::...`]-style membership `EnrollmentSide` (OwnDevice / Contact), which is a
/// standing relationship, and not who dialled. This is who holds the keychain:
/// three different axes that were all called some variant of "role" until
/// 2026-08-24. Confusing a durable relationship with a position in one exchange
/// is how a handshake ends up granting standing access.
pub enum EnrollmentSide {
    /// The device that already holds the keychain and is admitting a new one.
    Issuer,
    /// The new device joining the identity.
    Joiner,
}

impl EnrollmentSide {
    /// Domain-separation context prefixed to the transcript inside the MAC, so a
    /// MAC computed for one role can never validate as the other's.
    fn confirm_context(self) -> &'static [u8] {
        match self {
            EnrollmentSide::Issuer => b"issuer-confirmed",
            EnrollmentSide::Joiner => b"joiner-confirmed",
        }
    }
}

// ── Commitment ───────────────────────────────────────────────────────────────

/// The issuer's commitment: `SHA-256(eph_pub ‖ nonce)`.
///
/// Sent **before** the issuer sees the joiner's ephemeral key. It binds the
/// issuer to a keypair it can no longer grind (RFC-0040 §4).
pub fn commit(eph_pub: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(eph_pub);
    buf[32..].copy_from_slice(nonce);
    let d = digest::digest(&digest::SHA256, &buf);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// Check that a revealed `(eph_pub, nonce)` opens `commitment`.
///
/// The joiner calls this on the issuer's reveal; a mismatch means the issuer
/// tried to change its key after committing — **abort the ceremony**. Plain
/// equality is fine: every input is public (the peer already knows them all), so
/// there is no secret for a timing side channel to leak.
pub fn verify_commitment(commitment: &[u8; 32], eph_pub: &[u8; 32], nonce: &[u8; 32]) -> bool {
    *commitment == commit(eph_pub, nonce)
}

// ── Ephemeral keypair ────────────────────────────────────────────────────────

/// A fresh X25519 keypair generated for exactly one pairing ceremony.
///
/// Ephemerality is what gives the pairing channel **forward secrecy** (RFC-0040):
/// recording the ceremony plus a later compromise of any long-term key no longer
/// decrypts the transferred share/CEK. `StaticSecret` zeroizes on drop.
pub struct PairEphemeral {
    secret: StaticSecret,
    public: [u8; 32],
}

impl PairEphemeral {
    /// Generate a fresh ephemeral keypair from the OS CSPRNG.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret).to_bytes();
        Self { secret, public }
    }

    /// This keypair's public value, to send in the commit/reveal.
    pub fn public(&self) -> [u8; 32] {
        self.public
    }

    /// Raw X25519 Diffie-Hellman against the peer's ephemeral public key.
    ///
    /// Rejects a **non-contributory** exchange (peer sent a low-order point that
    /// forces a known all-zero secret) — defence in depth alongside the transcript
    /// binding.
    fn diffie_hellman(&self, peer_pub: &[u8; 32]) -> Result<[u8; 32]> {
        let peer = X25519PublicKey::from(*peer_pub);
        let shared = self.secret.diffie_hellman(&peer);
        if !shared.was_contributory() {
            return Err(anyhow!(
                "pairing DH is non-contributory (peer sent a low-order point)"
            ));
        }
        Ok(shared.to_bytes())
    }
}

// ── Transcript ───────────────────────────────────────────────────────────────

/// The exact bytes hashed into the key schedule. Every field is fixed-length, so
/// the concatenation is unambiguous by construction — **do not add variable-length
/// fields without length framing** (RFC-0040 reference notes).
#[derive(Debug, Clone)]
pub struct Transcript {
    /// 16-byte random session id (the mDNS offer instance name).
    pub sid: [u8; 16],
    /// The issuer's commitment `SHA-256(eph_pub_I ‖ nonce_I)`.
    pub commit: [u8; 32],
    /// Issuer ephemeral public key.
    pub eph_pub_i: [u8; 32],
    /// Joiner ephemeral public key.
    pub eph_pub_j: [u8; 32],
    /// Issuer nonce (opened the commitment).
    pub nonce_i: [u8; 32],
    /// Joiner nonce.
    pub nonce_j: [u8; 32],
}

impl Transcript {
    /// Serialize to the pinned wire order:
    /// `prefix ‖ sid ‖ commit ‖ eph_pub_I ‖ eph_pub_J ‖ nonce_I ‖ nonce_J`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf =
            Vec::with_capacity(TRANSCRIPT_PREFIX.len() + 16 + 32 + 32 + 32 + 32 + 32);
        buf.extend_from_slice(TRANSCRIPT_PREFIX);
        buf.extend_from_slice(&self.sid);
        buf.extend_from_slice(&self.commit);
        buf.extend_from_slice(&self.eph_pub_i);
        buf.extend_from_slice(&self.eph_pub_j);
        buf.extend_from_slice(&self.nonce_i);
        buf.extend_from_slice(&self.nonce_j);
        buf
    }
}

// ── Key schedule + session ───────────────────────────────────────────────────

/// The derived material for one pairing ceremony.
///
/// Holds the channel key, both confirmation keys (each side derives both so it can
/// *verify* the peer's MAC), and the SAS the humans compare.
pub struct PairSession {
    k_enc: [u8; 32],
    k_conf_i: [u8; 32],
    k_conf_j: [u8; 32],
    sas: u32,
}

/// Derive the full key schedule from a shared secret and transcript bytes.
///
/// Exposed for testing the schedule directly (e.g. a tampered transcript must
/// change the SAS); production callers use [`derive_session`], which runs the DH
/// for you and cannot pass a mismatched `ss`.
pub fn derive_pair_keys(ss: &[u8; 32], transcript: &[u8]) -> PairSession {
    derive_pair_keys_ikm(ss, transcript)
}

fn derive_pair_keys_ikm(ikm: &[u8], transcript: &[u8]) -> PairSession {
    // salt = SHA-256(transcript); prk = HKDF-Extract(salt, ikm).
    let salt = digest::digest(&digest::SHA256, transcript);
    let hk = Hkdf::<Sha256>::new(Some(salt.as_ref()), ikm);

    let mut k_enc = [0u8; 32];
    let mut k_conf_i = [0u8; 32];
    let mut k_conf_j = [0u8; 32];
    let mut sas_seed = [0u8; 8];
    // HKDF-Expand into fixed-length outputs never fails at these lengths.
    hk.expand(LABEL_ENC, &mut k_enc).expect("expand k_enc");
    hk.expand(LABEL_CONF_ISSUER, &mut k_conf_i)
        .expect("expand k_conf_i");
    hk.expand(LABEL_CONF_JOINER, &mut k_conf_j)
        .expect("expand k_conf_j");
    hk.expand(LABEL_SAS, &mut sas_seed).expect("expand sas_seed");

    let sas = (u64::from_be_bytes(sas_seed) % SAS_MODULUS) as u32;
    PairSession {
        k_enc,
        k_conf_i,
        k_conf_j,
        sas,
    }
}

/// Run the ceremony's key agreement: DH the two ephemerals, then derive the
/// schedule bound to `transcript`. Both sides call this and — on an honest run —
/// obtain identical keys and SAS.
///
/// `transcript.eph_pub_i` / `eph_pub_j` must already hold both public keys; the
/// caller passes its own [`PairEphemeral`] and the peer's public key.
pub fn derive_session(
    own_eph: &PairEphemeral,
    peer_eph_pub: &[u8; 32],
    transcript: &Transcript,
) -> Result<PairSession> {
    let ss = own_eph.diffie_hellman(peer_eph_pub)?;
    Ok(derive_pair_keys(&ss, &transcript.to_bytes()))
}

/// [`derive_session`] with a second secret folded into the key material.
///
/// A ceremony that also ran a PAKE (RFC-0022: two strangers keyed by a spoken
/// code) hands its PAKE key here as `extra_ikm`, so every derived key — the
/// channel key, both confirmation keys, the SAS — depends on the code as well
/// as on the ephemeral agreement. An interposer that forwarded both reveals but
/// never knew the code derives nothing that verifies, whatever the humans
/// compare. The ikm is `ss ‖ extra`, both fixed-length for a given caller, so
/// the concatenation is unambiguous; a caller with no second secret gets
/// exactly [`derive_session`].
pub fn derive_session_with(
    own_eph: &PairEphemeral,
    peer_eph_pub: &[u8; 32],
    transcript: &Transcript,
    extra_ikm: &[u8],
) -> Result<PairSession> {
    let ss = own_eph.diffie_hellman(peer_eph_pub)?;
    if extra_ikm.is_empty() {
        return Ok(derive_pair_keys(&ss, &transcript.to_bytes()));
    }
    let mut ikm = Vec::with_capacity(32 + extra_ikm.len());
    ikm.extend_from_slice(&ss);
    ikm.extend_from_slice(extra_ikm);
    Ok(derive_pair_keys_ikm(&ikm, &transcript.to_bytes()))
}

impl PairSession {
    /// The six-digit SAS as an integer in `0..1_000_000`.
    pub fn sas(&self) -> u32 {
        self.sas
    }

    /// The SAS formatted for a human to read: zero-padded, grouped `"472 913"`.
    pub fn sas_display(&self) -> String {
        let s = format!("{:06}", self.sas);
        format!("{} {}", &s[..3], &s[3..])
    }

    /// The AEAD channel key for the RFC-0033 payload transfer.
    ///
    /// Used with ChaCha20-Poly1305 under counter nonces (issuer even / joiner odd)
    /// — see the tier-05 ceremony. The key is fresh per ceremony, so nonce reuse
    /// is structurally impossible.
    pub fn k_enc(&self) -> &[u8; 32] {
        &self.k_enc
    }

    /// The `k_conf` key for `role`.
    fn conf_key(&self, role: EnrollmentSide) -> &[u8; 32] {
        match role {
            EnrollmentSide::Issuer => &self.k_conf_i,
            EnrollmentSide::Joiner => &self.k_conf_j,
        }
    }

    /// The MAC message for `role`: `"<role>-confirmed" ‖ transcript`.
    fn conf_msg(role: EnrollmentSide, transcript: &Transcript) -> Vec<u8> {
        let mut msg = role.confirm_context().to_vec();
        msg.extend_from_slice(&transcript.to_bytes());
        msg
    }

    /// This side's confirmation MAC for `role`: `HMAC(k_conf_role,
    /// "<role>-confirmed" ‖ transcript)`. Released **only after** the local human
    /// confirms the SAS (RFC-0040 §3).
    pub fn confirm_mac(&self, role: EnrollmentSide, transcript: &Transcript) -> [u8; 32] {
        hmac_sha256(self.conf_key(role), &Self::conf_msg(role, transcript))
    }

    /// Constant-time verification of the peer's confirmation MAC for `peer_role`.
    ///
    /// Uses `ring::hmac::verify` (recompute-and-compare in constant time) so a
    /// forged MAC leaks nothing byte-by-byte. A commitment-cheating peer that could
    /// not compute the shared secret fails here even if a human mis-confirms the
    /// SAS (RFC-0040 §2, key confirmation).
    pub fn verify_confirm(&self, peer_role: EnrollmentSide, transcript: &Transcript, mac: &[u8; 32]) -> bool {
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.conf_key(peer_role));
        hmac::verify(&key, &Self::conf_msg(peer_role, transcript), mac).is_ok()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build both sides of an honest ceremony and return
    /// `(issuer_session, joiner_session, transcript, nonce_i, nonce_j, eph pubs)`.
    fn honest_run() -> (PairSession, PairSession, Transcript) {
        let sid = [7u8; 16];
        let eph_i = PairEphemeral::generate();
        let eph_j = PairEphemeral::generate();
        let nonce_i = [11u8; 32];
        let nonce_j = [22u8; 32];

        let commitment = commit(&eph_i.public(), &nonce_i);
        let transcript = Transcript {
            sid,
            commit: commitment,
            eph_pub_i: eph_i.public(),
            eph_pub_j: eph_j.public(),
            nonce_i,
            nonce_j,
        };

        let issuer = derive_session(&eph_i, &eph_j.public(), &transcript).unwrap();
        let joiner = derive_session(&eph_j, &eph_i.public(), &transcript).unwrap();
        (issuer, joiner, transcript)
    }

    #[test]
    fn honest_run_derives_equal_sas_and_keys() {
        let (issuer, joiner, _t) = honest_run();
        assert_eq!(issuer.sas(), joiner.sas(), "both sides must derive one SAS");
        assert_eq!(issuer.k_enc(), joiner.k_enc(), "channel key must agree");
        assert!(issuer.sas() < 1_000_000, "SAS is six decimal digits");
    }

    #[test]
    fn sas_display_is_six_grouped_digits() {
        // Force a known SAS by driving the schedule with fixed inputs.
        let s = derive_pair_keys(&[9u8; 32], b"fixed-transcript");
        let disp = s.sas_display();
        assert_eq!(disp.len(), 7, "`NNN NNN` is 7 chars incl. the space: {disp}");
        assert_eq!(disp.as_bytes()[3], b' ', "grouped after 3 digits: {disp}");
        assert!(
            disp.chars().enumerate().all(|(i, c)| i == 3 || c.is_ascii_digit()),
            "digits only apart from the group space: {disp}"
        );
    }

    #[test]
    fn reveal_not_matching_commitment_is_rejected() {
        let eph = PairEphemeral::generate();
        let nonce = [1u8; 32];
        let c = commit(&eph.public(), &nonce);
        // Honest opening verifies.
        assert!(verify_commitment(&c, &eph.public(), &nonce));
        // A different nonce (the issuer trying to change its opening) fails.
        assert!(!verify_commitment(&c, &eph.public(), &[2u8; 32]));
        // A different ephemeral key (the grinding attack) fails.
        let other = PairEphemeral::generate();
        assert!(!verify_commitment(&c, &other.public(), &nonce));
    }

    #[test]
    fn tampering_any_transcript_field_changes_the_sas() {
        let (base, _j, t) = honest_run();
        // The shared secret is fixed; flipping a transcript field must change the
        // whole key schedule (SAS included), so a reflected key / replayed session
        // / version confusion yields a different code the humans won't confirm.
        let ss = [3u8; 32];
        let baseline = derive_pair_keys(&ss, &t.to_bytes()).sas();
        let mutate = |f: &dyn Fn(&mut Transcript)| {
            let mut m = t.clone();
            f(&mut m);
            derive_pair_keys(&ss, &m.to_bytes()).sas()
        };
        assert_ne!(baseline, mutate(&|m| m.sid[0] ^= 1), "sid must bind");
        assert_ne!(baseline, mutate(&|m| m.commit[0] ^= 1), "commit must bind");
        assert_ne!(baseline, mutate(&|m| m.eph_pub_i[0] ^= 1), "eph_pub_I must bind");
        assert_ne!(baseline, mutate(&|m| m.eph_pub_j[0] ^= 1), "eph_pub_J must bind");
        assert_ne!(baseline, mutate(&|m| m.nonce_i[0] ^= 1), "nonce_I must bind");
        assert_ne!(baseline, mutate(&|m| m.nonce_j[0] ^= 1), "nonce_J must bind");
        // Sanity: `base` from the honest run is a real session, unused SAS aside.
        let _ = base.sas();
    }

    #[test]
    fn confirmation_macs_round_trip_and_resist_reflection() {
        let (issuer, joiner, t) = honest_run();
        // Each side releases its own role's MAC; the peer verifies it.
        let issuer_mac = issuer.confirm_mac(EnrollmentSide::Issuer, &t);
        let joiner_mac = joiner.confirm_mac(EnrollmentSide::Joiner, &t);
        assert!(joiner.verify_confirm(EnrollmentSide::Issuer, &t, &issuer_mac));
        assert!(issuer.verify_confirm(EnrollmentSide::Joiner, &t, &joiner_mac));

        // A joiner MAC must not verify as an issuer MAC (separate keys + context).
        assert!(!joiner.verify_confirm(EnrollmentSide::Issuer, &t, &joiner_mac));
        // A tampered MAC fails.
        let mut bad = issuer_mac;
        bad[0] ^= 1;
        assert!(!joiner.verify_confirm(EnrollmentSide::Issuer, &t, &bad));
        // A MAC bound to a different transcript fails (transcript binding).
        let mut t2 = t.clone();
        t2.nonce_j[0] ^= 1;
        assert!(!joiner.verify_confirm(EnrollmentSide::Issuer, &t2, &issuer_mac));
    }

    #[test]
    fn a_mitm_running_two_sessions_gets_two_different_sas() {
        // The attacker sits between a real issuer and a real joiner, running a
        // fresh ephemeral toward each. Because it cannot open the issuer's
        // commitment with a *ground* key (it commits before seeing the joiner),
        // the two sessions derive independent SAS values with overwhelming
        // probability — the humans see different codes and abort.
        let real_issuer_eph = PairEphemeral::generate();
        let real_joiner_eph = PairEphemeral::generate();
        let attacker_to_issuer = PairEphemeral::generate();
        let attacker_to_joiner = PairEphemeral::generate();

        let n_i = [1u8; 32];
        let n_j = [2u8; 32];
        let n_ai = [3u8; 32];
        let n_aj = [4u8; 32];

        // Issuer↔attacker session (attacker plays joiner).
        let issuer_commit = commit(&real_issuer_eph.public(), &n_i);
        let t_issuer = Transcript {
            sid: [0u8; 16],
            commit: issuer_commit,
            eph_pub_i: real_issuer_eph.public(),
            eph_pub_j: attacker_to_issuer.public(),
            nonce_i: n_i,
            nonce_j: n_aj,
        };
        let issuer_sas = derive_session(&real_issuer_eph, &attacker_to_issuer.public(), &t_issuer)
            .unwrap()
            .sas();

        // Attacker↔joiner session (attacker plays issuer, commits its own key).
        let atk_commit = commit(&attacker_to_joiner.public(), &n_ai);
        let t_joiner = Transcript {
            sid: [0u8; 16],
            commit: atk_commit,
            eph_pub_i: attacker_to_joiner.public(),
            eph_pub_j: real_joiner_eph.public(),
            nonce_i: n_ai,
            nonce_j: n_j,
        };
        let joiner_sas = derive_session(&real_joiner_eph, &attacker_to_joiner.public(), &t_joiner)
            .unwrap()
            .sas();

        assert_ne!(
            issuer_sas, joiner_sas,
            "the two legs must show different codes (they collide only ~10^-6)"
        );
    }

    #[test]
    fn non_contributory_peer_key_is_rejected() {
        // An all-zero public key is the canonical low-order point; DH against it is
        // non-contributory and must be refused rather than yield a shared secret.
        let eph = PairEphemeral::generate();
        assert!(eph.diffie_hellman(&[0u8; 32]).is_err());
    }
}
