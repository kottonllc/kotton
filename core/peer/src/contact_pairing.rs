// SPDX-License-Identifier: AGPL-3.0-or-later
//! Contact pairing: two strangers, a spoken code, a relay that learns nothing
//! (`docs/design/conversations.md`).
//!
//! ## The ceremony
//!
//! ```text
//! Alice (issuer)                relay                    Bob (joiner)
//! code = three words
//! handle, sid = HKDF(code)                               handle, sid = HKDF(code)
//! reserve /relay/reserve as handle ─▶
//!                                    ◀─ open /relay/open?to=handle, as a one-time key
//!            ◀════════ raw bridged bytes, mTLS-free ════════▶
//! J: PairHello{sid} · PAKE keyed by the code · key confirmation
//! I: commit  J: reveal  I: reveal  · both derive keys and six digits
//! each human compares the digits and confirms · confirm MACs
//! I ─ signed identity record ─▶        ◀─ signed identity record ─ J
//! both: verify the signature against the transcript, the key log against the key
//! both: write a `contact` member, keep the key log, admit the key
//! ```
//!
//! ## What each party learns, and what the relay does not
//!
//! The relay bridges one circuit between two labels it has never seen and will
//! never see again: a handle derived from the code, and a key the joiner made
//! for this dial. Neither is a durable identity, and the two do not compose
//! with anything (Article VII). Inside the circuit, the PAKE is what a party
//! without the code cannot pass — the relay may deny but never forge — and the
//! six digits are what a human checks against a party that *did* hear the code.
//! Nothing crosses before both confirm, and the identity record each side sends
//! is signed over this ceremony's transcript, so a record captured once cannot
//! enter a later ceremony. Out of it comes exactly one thing on each side: an
//! authenticated public key and the key log it resolves from, written as a
//! `contact` member that grants nothing.
//!
//! ## What is reused, and what is new
//!
//! The committed handshake, the six digits, the confirmation MACs and the AEAD
//! channel are the device ceremony's, unchanged ([`crate::pair_channel`]); this
//! module adds
//! the code as a PAKE password and as the rendezvous, and an identity record
//! instead of an enrollment payload. Two ceremonies that differ in what the
//! other end can do — everything, or message-you — stay two ceremonies (E1);
//! what they share is the mechanism, because a second handshake is a second
//! chance to get the transcript order wrong.

use crate::pair_channel::{issuer_establish_with, joiner_establish_with, SasConfirmer};
use crate::relay_keys::{FirstContact, Presenting, RefusedAtTheRelay};
use crate::rendezvous::unix_now;
use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use kotton_crypto::kel_verify::{resolve_current_key, LocalArbiter};
use kotton_crypto::provider::daily_credential::spoken_word_list;
use kotton_crypto::reach_note::{self, ReachNote};
use kotton_crypto::DidKeyMethod;
use kotton_net::transport::{rendezvous_dial, rendezvous_reserve, RelayedByteStream};
use kotton_wire::kel::KelEvent;
use rand::rngs::OsRng;
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

/// Words in a spoken code. Three from the 2048-word list is 33 bits: enough
/// that a rendezvous is not stumbled into, and short enough to read aloud once.
/// The PAKE, not the length, is what stops guessing.
pub const CODE_WORDS: usize = 3;

/// How long a joiner keeps trying to reach a code whose issuer is still setting
/// up its reservation — the two humans are not perfectly synchronised.
const JOIN_DIAL_WINDOW: Duration = Duration::from_secs(20);

const RENDEZVOUS_INFO: &[u8] = b"kotton:contact-rendezvous:v1";
const SID_INFO: &[u8] = b"kotton:contact-sid:v1";
const IDENTITY_SIG_DOMAIN: &[u8] = b"kotton:contact-identity:v1";

/// A fresh spoken code: `word-word-word`.
pub fn generate_code() -> String {
    let list = spoken_word_list();
    let mut rng = OsRng;
    (0..CODE_WORDS)
        .map(|_| list[rng.gen_range(0..list.len())])
        .collect::<Vec<_>>()
        .join("-")
}

/// The code as both sides must see it: lowercase, trimmed, with any run of
/// spaces or dashes as one dash — so what one person reads aloud and the
/// other types is the same password whether it was heard as "ripple canyon
/// ember" or "ripple-canyon-ember".
pub fn normalize_code(code: &str) -> String {
    code.trim()
        .to_lowercase()
        .split(|c: char| c == '-' || c.is_whitespace())
        .filter(|w| !w.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

/// Where a code meets: the handle the issuer reserves under (and the key that
/// proves it), and the session id the handshake binds to. Both derived from the
/// code by both sides, so nothing about the rendezvous has to be sent.
pub struct Rendezvous {
    /// The `did:key` label the relay routes by.
    pub handle: String,
    /// Proves the handle to the relay.
    pub handle_key: SigningKey,
    /// The handshake's session id.
    pub sid: [u8; 16],
}

/// The labels a code's rendezvous is derived under. Two ceremonies that use
/// the same words must not meet at the same handle — a contact code and a
/// vault invite that happened to share three words would otherwise reserve
/// under one label and pair the wrong pair — so each ceremony derives in its
/// own domain, and the domain is fixed at the call site rather than sent.
pub struct RendezvousDomain {
    /// Salts the stretch and labels the handle seed.
    pub rendezvous: &'static [u8],
    /// Labels the session id.
    pub sid: &'static [u8],
}

/// Contact pairing's domain.
pub const CONTACT_DOMAIN: RendezvousDomain = RendezvousDomain {
    rendezvous: RENDEZVOUS_INFO,
    sid: SID_INFO,
};

/// Derive the rendezvous for a (normalised) contact code.
pub fn rendezvous_for(code: &str) -> Result<Rendezvous> {
    rendezvous_in(code, &CONTACT_DOMAIN)
}

/// Derive the rendezvous for a (normalised) code, in `domain`.
///
/// **Slow on purpose.** The relay sees the handle on the wire, and a handle
/// that was a fast hash of a 33-bit code would let anyone watching the relay
/// grind the code back out of it within the ceremony's window — and with the
/// code, pass the PAKE. Argon2id at these parameters costs each honest side
/// about a tenth of a second once and costs a grinder that much per guess,
/// which turns eight billion guesses into decades. The PAKE is still what
/// stops an online guess; this is what stops the handle from being the leak.
pub fn rendezvous_in(code: &str, domain: &RendezvousDomain) -> Result<Rendezvous> {
    use argon2::{Algorithm, Argon2, Params, Version};
    // Memory in KiB; a per-guess cost that does not parallelise well on a GPU.
    let params = Params::new(64 * 1024, 3, 1, Some(32)).map_err(|e| anyhow!("argon2 params: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut stretched = [0u8; 32];
    argon
        .hash_password_into(code.as_bytes(), domain.rendezvous, &mut stretched)
        .map_err(|e| anyhow!("argon2: {e}"))?;
    let hk = Hkdf::<Sha256>::new(None, &stretched);
    let mut seed = [0u8; 32];
    hk.expand(domain.rendezvous, &mut seed).expect("32-byte expand");
    let mut sid = [0u8; 16];
    hk.expand(domain.sid, &mut sid).expect("16-byte expand");
    let handle_key = SigningKey::from_bytes(&seed);
    let handle = DidKeyMethod::from_public_key_bytes(&handle_key.verifying_key().to_bytes())
        .map_err(|e| anyhow!("rendezvous handle: {e}"))?
        .to_string();
    Ok(Rendezvous { handle, handle_key, sid })
}

/// What a party presents about itself once the channel is authenticated.
#[derive(Debug, Clone)]
pub struct ContactIdentity {
    /// The identity's AID (`did:kel:…`), or its `did:key` for a legacy identity.
    pub aid: String,
    /// The current identity key — what `kel` resolves to, and what signs.
    pub public_key: [u8; 32],
    /// What the other side's screen will call this person.
    pub display_name: String,
    /// This identity's reach note, signed by `public_key`: every relay it is
    /// admitted to and its device keys. The first one the other side's card
    /// holds; later ones arrive sealed over the relationship this makes.
    pub reach: ReachNote,
    /// The key log the AID resolves from. Empty for a `did:key` identity.
    pub kel: Vec<KelEvent>,
}

/// The other party, as the ceremony authenticated them.
#[derive(Debug, Clone)]
pub struct PairedContact {
    pub did: String,
    pub public_key: [u8; 32],
    pub label: String,
    /// Their reach note, already held to their key, their name and its expiry.
    pub reach: ReachNote,
    pub kel: Vec<KelEvent>,
}

/// The identity record on the wire, signed over the ceremony transcript.
#[derive(Debug, Serialize, Deserialize)]
struct ContactIdentityRecord {
    aid: String,
    public_key: [u8; 32],
    display_name: String,
    reach: ReachNote,
    kel: Vec<KelEvent>,
    #[serde(with = "sig_bytes")]
    sig: Vec<u8>,
}

mod sig_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        hex::encode(v).serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}

/// The bytes an identity record's signature covers: the domain, this
/// ceremony's whole transcript, and every field — length-framed where a field
/// is variable-length, and the key log and the reach note by digest. The note
/// carries its own signature as well; this one binds it to *this* ceremony.
fn identity_signed_bytes(transcript: &[u8], r: &ContactIdentityRecord) -> Result<Vec<u8>> {
    let kel_json = serde_json::to_vec(&r.kel).context("serialize key log")?;
    let reach_json = serde_json::to_vec(&r.reach).context("serialize reach note")?;
    let mut out = Vec::with_capacity(256 + transcript.len());
    out.extend_from_slice(IDENTITY_SIG_DOMAIN);
    out.extend_from_slice(transcript);
    for field in [r.aid.as_bytes(), r.display_name.as_bytes()] {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field);
    }
    out.extend_from_slice(&r.public_key);
    out.extend_from_slice(&Sha256::digest(&kel_json));
    out.extend_from_slice(&Sha256::digest(&reach_json));
    Ok(out)
}

fn sign_identity(transcript: &[u8], ours: &ContactIdentity, key: &SigningKey) -> Result<ContactIdentityRecord> {
    if key.verifying_key().to_bytes() != ours.public_key {
        bail!("the identity key does not match the public key being presented");
    }
    let mut r = ContactIdentityRecord {
        aid: ours.aid.clone(),
        public_key: ours.public_key,
        display_name: ours.display_name.clone(),
        reach: ours.reach.clone(),
        kel: ours.kel.clone(),
        sig: Vec::new(),
    };
    r.sig = key.sign(&identity_signed_bytes(transcript, &r)?).to_bytes().to_vec();
    Ok(r)
}

/// Check the other side's record: the signature is by the key it presents,
/// over *this* transcript; and the key is the one its name resolves to — by
/// replaying its key log for a `did:kel`, or by the name itself for a `did:key`.
fn verify_identity(transcript: &[u8], r: &ContactIdentityRecord) -> Result<PairedContact> {
    let vk = VerifyingKey::from_bytes(&r.public_key).context("contact public key")?;
    let sig = Signature::from_slice(&r.sig).context("contact signature")?;
    vk.verify(&identity_signed_bytes(transcript, r)?, &sig)
        .map_err(|_| anyhow!("the contact's identity record is not signed by the key it presents, over this ceremony"))?;
    if r.kel.is_empty() {
        let did_key = DidKeyMethod::from_public_key_bytes(&r.public_key)
            .map_err(|e| anyhow!("contact did:key: {e}"))?
            .to_string();
        if did_key != r.aid {
            bail!("the contact named {} but presented the key of {did_key}, with no key log to bridge them", r.aid);
        }
    } else {
        let first_aid = r.kel[0].aid.to_string();
        if first_aid != r.aid {
            bail!("the contact named {} but its key log belongs to {first_aid}", r.aid);
        }
        let resolved = resolve_current_key(&r.kel, &LocalArbiter, false)
            .map_err(|e| anyhow!("the contact's key log does not replay: {e}"))?;
        if resolved != r.public_key {
            bail!("the contact's key log resolves to a different key than the one it presented");
        }
    }
    if r.display_name.trim().is_empty() {
        bail!("the contact sent no name");
    }
    // Their note, held to the key the ceremony just authenticated: the card
    // starts from something they signed, never from something asserted.
    reach_note::verify(&r.reach, &r.public_key, &r.aid, unix_now())
        .map_err(|e| anyhow!("the contact's reach note: {e}"))?;
    Ok(PairedContact {
        did: r.aid.clone(),
        public_key: r.public_key,
        label: r.display_name.clone(),
        reach: r.reach.clone(),
        kel: r.kel.clone(),
    })
}

/// The issuer's half: reserve under the code's handle at `relay_url`, wait up
/// to `ttl` for the joiner, run the ceremony, and return who arrived.
///
/// `admission` is what this device presents at the relay it stands at, with
/// what it is: a relay that refuses the reservation at its door is said as
/// [`RefusedAtTheRelay`], what was presented and which invite admits it.
pub async fn run_issuer(
    relay_url: &str,
    code: &str,
    ours: &ContactIdentity,
    identity_key: &SigningKey,
    confirmer: &dyn SasConfirmer,
    ttl: Duration,
    admission: &Presenting,
) -> Result<PairedContact> {
    let code = normalize_code(code);
    let rv = rendezvous_for(&code)?;
    let reservation = rendezvous_reserve(relay_url, &rv.handle, &rv.handle_key, admission.key())
        .await
        .map_err(|e| match RefusedAtTheRelay::of(&e, relay_url, admission, FirstContact::SpokenCode) {
            Some(refused) => anyhow::Error::new(refused),
            None => anyhow!("relay reservation for the code: {e}"),
        })?;
    let stream = tokio::time::timeout(ttl, reservation.accept_one())
        .await
        .map_err(|_| anyhow!("nobody joined with the code within {}s", ttl.as_secs()))?
        .map_err(|e| anyhow!("relay circuit: {e}"))?;
    let (read, write) = tokio::io::split(stream);
    let mut channel = issuer_establish_with(
        write,
        read,
        rv.sid,
        &ours.display_name,
        confirmer,
        Some(code.as_bytes()),
    )
    .await?;
    let transcript = channel.transcript().to_bytes();
    let mine = sign_identity(&transcript, ours, identity_key)?;
    channel
        .send_encrypted(&serde_json::to_vec(&mine).context("serialize identity")?)
        .await?;
    let theirs: ContactIdentityRecord =
        serde_json::from_slice(&channel.recv_encrypted().await?).context("contact identity record")?;
    let contact = verify_identity(&transcript, &theirs)?;
    let _ = channel.finish().await;
    Ok(contact)
}

/// The joiner's half: open a circuit to the code's handle at `relay_url` as a
/// one-time key, run the ceremony, and return who was waiting.
///
/// A dial that finds nobody is tried again for [`JOIN_DIAL_WINDOW`], since the
/// issuer may still be reserving. A dial the relay refuses at its door is not:
/// the relay answers the same key the same way, so the joiner stops at once with
/// [`RefusedAtTheRelay`], saying what `admission` presented there.
pub async fn run_joiner(
    relay_url: &str,
    code: &str,
    ours: &ContactIdentity,
    identity_key: &SigningKey,
    confirmer: &dyn SasConfirmer,
    admission: &Presenting,
) -> Result<PairedContact> {
    let code = normalize_code(code);
    let rv = rendezvous_for(&code)?;
    // A key for this dial only: the relay learns a label that names nobody.
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let dial_key = SigningKey::from_bytes(&seed);
    let dial_did = DidKeyMethod::from_public_key_bytes(&dial_key.verifying_key().to_bytes())
        .map_err(|e| anyhow!("dial key: {e}"))?
        .to_string();
    let deadline = tokio::time::Instant::now() + JOIN_DIAL_WINDOW;
    let stream = loop {
        let e = match rendezvous_dial(relay_url, &dial_did, &dial_key, &rv.handle, admission.key()).await {
            Ok(s) => break s,
            Err(e) => e,
        };
        match RefusedAtTheRelay::of(&e, relay_url, admission, FirstContact::SpokenCode) {
            Some(refused) => return Err(refused.into()),
            None if tokio::time::Instant::now() < deadline => {
                tracing::debug!(error = %e, "contact join: code not reserved yet; retrying");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            None => {
                return Err(anyhow!(
                    "nobody is waiting on that code at this relay ({e}) — check the words, and that they started first"
                ))
            }
        }
    };
    let (read, write) = tokio::io::split(stream);
    let mut channel = joiner_establish_with(write, read, rv.sid, confirmer, Some(code.as_bytes())).await?;
    let transcript = channel.transcript().to_bytes();
    let theirs: ContactIdentityRecord =
        serde_json::from_slice(&channel.recv_encrypted().await?).context("contact identity record")?;
    let contact = verify_identity(&transcript, &theirs)?;
    let mine = sign_identity(&transcript, ours, identity_key)?;
    channel
        .send_encrypted(&serde_json::to_vec(&mine).context("serialize identity")?)
        .await?;
    let _ = channel.finish().await;
    Ok(contact)
}

/// Run both halves over an in-memory duplex — the whole ceremony minus the
/// relay, for tests of the ceremony itself.
#[cfg(test)]
async fn run_in_memory(
    code_issuer: &str,
    code_joiner: &str,
    issuer: (&ContactIdentity, &SigningKey, &dyn SasConfirmer),
    joiner: (&ContactIdentity, &SigningKey, &dyn SasConfirmer),
) -> (Result<PairedContact>, Result<PairedContact>) {
    let (a, b) = tokio::io::duplex(1 << 16);
    let code_i = normalize_code(code_issuer);
    let code_j = normalize_code(code_joiner);
    let rv_i = rendezvous_for(&code_i).unwrap();
    let rv_j = rendezvous_for(&code_j).unwrap();
    let (ours_i, key_i, conf_i) = issuer;
    let (ours_j, key_j, conf_j) = joiner;
    let issuer_side = async {
        let (read, write) = tokio::io::split(a);
        let mut ch = issuer_establish_with(write, read, rv_i.sid, &ours_i.display_name, conf_i, Some(code_i.as_bytes())).await?;
        let t = ch.transcript().to_bytes();
        let mine = sign_identity(&t, ours_i, key_i)?;
        ch.send_encrypted(&serde_json::to_vec(&mine)?).await?;
        let theirs: ContactIdentityRecord = serde_json::from_slice(&ch.recv_encrypted().await?)?;
        verify_identity(&t, &theirs)
    };
    let joiner_side = async {
        let (read, write) = tokio::io::split(b);
        let mut ch = joiner_establish_with(write, read, rv_j.sid, conf_j, Some(code_j.as_bytes())).await?;
        let t = ch.transcript().to_bytes();
        let theirs: ContactIdentityRecord = serde_json::from_slice(&ch.recv_encrypted().await?)?;
        let c = verify_identity(&t, &theirs)?;
        let mine = sign_identity(&t, ours_j, key_j)?;
        ch.send_encrypted(&serde_json::to_vec(&mine)?).await?;
        Ok(c)
    };
    tokio::join!(issuer_side, joiner_side)
}

#[allow(dead_code)]
fn _assert_stream_bounds<S: AsyncRead + AsyncWrite + Unpin + Send>(_: &S) {}
#[allow(dead_code)]
fn _relayed_is_a_stream(s: &RelayedByteStream) {
    _assert_stream_bounds(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Mutex;

    struct Yes(Mutex<Option<u32>>);
    #[async_trait]
    impl SasConfirmer for Yes {
        async fn confirm(&self, sas: u32, _label: Option<&str>) -> bool {
            *self.0.lock().unwrap() = Some(sas);
            true
        }
    }
    struct No;
    #[async_trait]
    impl SasConfirmer for No {
        async fn confirm(&self, _sas: u32, _label: Option<&str>) -> bool {
            false
        }
    }

    fn identity(name: &str) -> (ContactIdentity, SigningKey) {
        let key = SigningKey::generate(&mut OsRng);
        let pk = key.verifying_key().to_bytes();
        let aid = DidKeyMethod::from_public_key_bytes(&pk).unwrap().to_string();
        let reach = reach_note::next(
            None,
            &aid,
            &[reach_note::RelayRef { key: None, addr: format!("http://relay.{name}.test"), admit: None }],
            &[],
            &key,
            unix_now(),
        )
        .unwrap();
        (
            ContactIdentity {
                aid,
                public_key: pk,
                display_name: name.into(),
                reach,
                kel: Vec::new(),
            },
            key,
        )
    }

    #[test]
    fn a_code_is_three_words_and_normalises_to_itself() {
        let c = generate_code();
        assert_eq!(c.split('-').count(), CODE_WORDS);
        assert_eq!(normalize_code(&c), c);
        assert_eq!(normalize_code("  Ripple Canyon  ember "), "ripple-canyon-ember");
        assert_eq!(normalize_code("ripple - canyon-ember"), "ripple-canyon-ember");
    }

    #[test]
    fn the_rendezvous_is_a_function_of_the_code_alone() {
        let a = rendezvous_for("ripple-canyon-ember").unwrap();
        let b = rendezvous_for("ripple-canyon-ember").unwrap();
        let c = rendezvous_for("ripple-canyon-amber").unwrap();
        assert_eq!(a.handle, b.handle);
        assert_eq!(a.sid, b.sid);
        assert_ne!(a.handle, c.handle);
        assert!(a.handle.starts_with("did:key:z6Mk"));
    }

    #[tokio::test]
    async fn the_same_code_pairs_and_each_learns_the_others_key() {
        let (alice, ka) = identity("alice");
        let (bob, kb) = identity("bob");
        let (ya, yb) = (Yes(Mutex::new(None)), Yes(Mutex::new(None)));
        let (ra, rb) = run_in_memory("ripple canyon ember", "Ripple-Canyon-Ember", (&alice, &ka, &ya), (&bob, &kb, &yb)).await;
        let (got_bob, got_alice) = (ra.unwrap(), rb.unwrap());
        assert_eq!(got_bob.did, bob.aid);
        assert_eq!(got_bob.public_key, bob.public_key);
        assert_eq!(got_bob.label, "bob");
        assert_eq!(got_bob.reach, bob.reach, "the first reach note travels in the ceremony");
        assert_eq!(got_bob.reach.relays_at(unix_now()), vec!["http://relay.bob.test"]);
        assert_eq!(got_alice.did, alice.aid);
        assert_eq!(got_alice.public_key, alice.public_key);
        assert_eq!(*ya.0.lock().unwrap(), *yb.0.lock().unwrap(), "both screens show the same digits");
    }

    /// The first note a card holds is one the person signed. A joiner that
    /// presents a note under any key but its own is not paired: the card would
    /// otherwise start from a relay somebody else chose.
    #[tokio::test]
    async fn a_reach_note_signed_by_another_key_pairs_nobody() {
        let (alice, ka) = identity("alice");
        let (mut bob, kb) = identity("bob");
        let stranger = SigningKey::generate(&mut OsRng);
        bob.reach = reach_note::sign(
            &bob.aid,
            vec![reach_note::RelayRef { key: None, addr: "http://relay.chosen-for-bob.test".into(), admit: None }],
            vec![],
            bob.reach.version,
            bob.reach.expires_at,
            &stranger,
        );
        let (ya, yb) = (Yes(Mutex::new(None)), Yes(Mutex::new(None)));
        let (ra, _rb) = run_in_memory("ripple canyon ember", "ripple canyon ember", (&alice, &ka, &ya), (&bob, &kb, &yb)).await;
        let err = ra.expect_err("alice must not hold a card started from a forged note");
        assert!(format!("{err:#}").contains("reach note"), "{err:#}");
    }

    /// A wrong code never reaches the digits: over a relay it reaches nothing (the
    /// handle differs), and even handed the right stream it answers a different
    /// session id. Either way no SAS is shown.
    #[tokio::test]
    async fn a_different_code_fails_before_any_digits_are_shown() {
        let (alice, ka) = identity("alice");
        let (bob, kb) = identity("bob");
        let (ya, yb) = (Yes(Mutex::new(None)), Yes(Mutex::new(None)));
        let (ra, rb) = run_in_memory("ripple-canyon-ember", "ripple-canyon-amber", (&alice, &ka, &ya), (&bob, &kb, &yb)).await;
        assert!(ra.is_err() && rb.is_err());
        assert!(ya.0.lock().unwrap().is_none() && yb.0.lock().unwrap().is_none(), "no SAS was ever shown");
    }

    /// The case the PAKE exists for: a party that reached the right handle and
    /// session (it watched the relay) but never heard the code. It fails as
    /// "the codes differ", before either side is shown digits.
    #[tokio::test]
    async fn the_right_handle_without_the_code_fails_the_pake() {
        let (alice, _ka) = identity("alice");
        let ya = Yes(Mutex::new(None));
        let yb = Yes(Mutex::new(None));
        let sid = rendezvous_for("ripple-canyon-ember").unwrap().sid;
        let (a, b) = tokio::io::duplex(1 << 16);
        let issuer = async {
            let (r, w) = tokio::io::split(a);
            issuer_establish_with(w, r, sid, &alice.display_name, &ya, Some(b"ripple-canyon-ember")).await.map(|_| ())
        };
        let joiner = async {
            let (r, w) = tokio::io::split(b);
            joiner_establish_with(w, r, sid, &yb, Some(b"a-guess-that-is-wrong")).await.map(|_| ())
        };
        let (ri, rj) = tokio::join!(issuer, joiner);
        assert!(ri.unwrap_err().to_string().contains("codes differ"), "issuer");
        assert!(rj.is_err(), "joiner");
        assert!(ya.0.lock().unwrap().is_none() && yb.0.lock().unwrap().is_none(), "no SAS was ever shown");
    }

    /// One side declining the digits means nothing was exchanged.
    #[tokio::test]
    async fn a_declined_comparison_exchanges_nothing() {
        let (alice, ka) = identity("alice");
        let (bob, kb) = identity("bob");
        let ya = Yes(Mutex::new(None));
        let (ra, rb) = run_in_memory("ripple-canyon-ember", "ripple-canyon-ember", (&alice, &ka, &ya), (&bob, &kb, &No)).await;
        assert!(ra.is_err() && rb.is_err());
    }

    /// A record signed for one ceremony does not verify in another.
    #[tokio::test]
    async fn an_identity_record_is_bound_to_its_ceremony() {
        let (alice, ka) = identity("alice");
        let r = sign_identity(b"transcript-one", &alice, &ka).unwrap();
        assert!(verify_identity(b"transcript-one", &r).is_ok());
        assert!(verify_identity(b"transcript-two", &r).is_err());
        // A name that is not the key's name, with nothing to bridge them.
        let mut forged = sign_identity(b"t", &alice, &ka).unwrap();
        forged.aid = "did:key:z6MkSomebodyElse".into();
        forged.sig = ka.sign(&identity_signed_bytes(b"t", &forged).unwrap()).to_bytes().to_vec();
        assert!(verify_identity(b"t", &forged).is_err());
    }

    /// A relay at a loopback port that answers its first `answered` upgrades
    /// `404` — nobody reserved there yet — and every one after `403`, its rule's
    /// one refusal. Returns its URL and how many upgrades it has been asked.
    async fn a_relay_that_refuses_after(answered: usize) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let asked = std::sync::Arc::new(AtomicUsize::new(0));
        let counted = asked.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf).await;
                let status = if counted.fetch_add(1, Ordering::SeqCst) < answered {
                    "404 Not Found"
                } else {
                    "403 Forbidden"
                };
                let body = r#"{"error":"not admitted by this relay's rule"}"#;
                let _ = s
                    .write_all(format!("HTTP/1.1 {status}\r\ncontent-length: {}\r\n\r\n{body}", body.len()).as_bytes())
                    .await;
            }
        });
        (url, asked)
    }

    /// **A relay's refusal ends a join at once; anything else is waited out**
    /// (`run_joiner`). A dial that finds nobody reserved is tried again, since
    /// the person who read the code may still be starting; a `403` at the door
    /// is the relay's one refusal, which it gives the same key every time, so
    /// the joiner stops there with a typed refusal saying what it presented —
    /// here nothing, at the relay this device stands at — and not twenty seconds
    /// later as nobody waiting.
    #[tokio::test]
    async fn a_join_the_relay_refuses_ends_at_its_refusal_and_says_what_was_presented() {
        let (relay, asked) = a_relay_that_refuses_after(2).await;
        let (bob, kb) = identity("bob");
        let started = std::time::Instant::now();
        let err = run_joiner(&relay, "ripple canyon ember", &bob, &kb, &No, &Presenting::handed(None))
            .await
            .expect_err("a join the relay refused paired somebody");
        let refused = err.downcast_ref::<RefusedAtTheRelay>().expect("the refusal is typed");
        assert_eq!(
            refused,
            &RefusedAtTheRelay { url: relay.clone(), presented: crate::relay_keys::Presented::Nothing, meeting: FirstContact::SpokenCode }
        );
        assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 3, "nobody reserved was not waited for, or a refusal was retried");
        assert!(started.elapsed() < Duration::from_secs(10), "a refusal was waited out: {:?}", started.elapsed());
    }

    /// **A relay's refusal of the issuer's reservation is said as one too**
    /// (`run_issuer`), with what the issuer presented.
    #[tokio::test]
    async fn a_code_the_relay_refuses_to_reserve_says_what_was_presented() {
        let (relay, _) = a_relay_that_refuses_after(0).await;
        let (alice, ka) = identity("alice");
        let presenting = Presenting::held(Some((kotton_net::rendezvous::AdmissionKey::generate(), crate::relay_keys::Tier::Invited)));
        let err = run_issuer(&relay, "ripple canyon ember", &alice, &ka, &No, Duration::from_secs(5), &presenting)
            .await
            .expect_err("a reservation the relay refused was held");
        let refused = err.downcast_ref::<RefusedAtTheRelay>().expect("the refusal is typed");
        assert_eq!(refused.presented, crate::relay_keys::Presented::Held(crate::relay_keys::Tier::Invited));
        assert_eq!(refused.meeting, FirstContact::SpokenCode);
    }
}
