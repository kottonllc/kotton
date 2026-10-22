// SPDX-License-Identifier: AGPL-3.0-or-later
//! Distributed FROST signing — the coordinator and its participant interface.
//!
//! A threshold signature is produced across several participants, each holding
//! one FROST share. No participant ever reveals its share; instead each
//! contributes a **round-1 commitment** and then a **round-2 signature share**,
//! which the coordinator aggregates into a single Ed25519 signature using the
//! group [`PublicKeyPackage`](kotton_crypto) distributed at enrollment
//! (RFC-0036).
//!
//! This module is **transport-agnostic**: [`coordinate_threshold_sign`] drives
//! the two rounds over a slice of [`FrostSigner`]s. A [`LocalFrostSigner`] runs a
//! share held in this process; a future QUIC-backed signer will run a share on
//! another of the user's nodes — the coordinator is identical either way. That
//! separation is what lets a hosted [`Cosigner`](kotton_schemas::membership)
//! contribute to the threshold without the coordinator ever holding its share.
//!
//! The crypto round-trip itself is proven in
//! `kotton_crypto::frost`; this layer is the orchestration over it.

use anyhow::{anyhow, Result};
use kotton_crypto::frost;
use std::sync::Mutex;

/// One party to a threshold signature. Implementations hold a single FROST share
/// and keep their secret signing nonces between the two rounds.
///
/// The interface is async so a remote (network-backed) signer fits the same
/// coordinator; the in-process [`LocalFrostSigner`] satisfies it trivially.
#[async_trait::async_trait]
pub trait FrostSigner: Send + Sync {
    /// Round 1 — produce this participant's signing commitment, stashing its
    /// secret nonces for round 2. Returns `(participant_id_hex, commitment_hex)`.
    async fn commit(&self) -> Result<(String, String)>;

    /// Round 2 — produce this participant's signature share over the coordinator's
    /// `signing_package_hex`, using the nonces stashed in round 1.
    async fn sign(&self, signing_package_hex: &str) -> Result<String>;
}

/// A [`FrostSigner`] for a share held in this process (this node's own share).
///
/// Stashes the round-1 nonces internally; one instance signs one message. The
/// nonces never leave the process and are consumed by [`sign`](Self::sign).
pub struct LocalFrostSigner {
    key_package_hex: String,
    /// Secret round-1 nonces, set by `commit`, read by `sign`.
    nonces: Mutex<Option<String>>,
}

impl LocalFrostSigner {
    /// Build a local signer from a hex-serialised FROST `KeyPackage` (this node's
    /// share, e.g. loaded from the `frost_share` keychain entry).
    pub fn new(key_package_hex: String) -> Self {
        Self {
            key_package_hex,
            nonces: Mutex::new(None),
        }
    }
}

#[async_trait::async_trait]
impl FrostSigner for LocalFrostSigner {
    async fn commit(&self) -> Result<(String, String)> {
        let (nonces, commitment, id) = frost::signing_commit(&self.key_package_hex)
            .map_err(|e| anyhow!("frost round-1 commit: {e}"))?;
        *self.nonces.lock().unwrap() = Some(nonces);
        Ok((id, commitment))
    }

    async fn sign(&self, signing_package_hex: &str) -> Result<String> {
        let nonces = self
            .nonces
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| anyhow!("sign called before commit (no round-1 nonces)"))?;
        frost::signing_sign(&self.key_package_hex, &nonces, signing_package_hex)
            .map_err(|e| anyhow!("frost round-2 sign: {e}"))
    }
}

/// Coordinate a threshold signature over `message` across `signers`.
///
/// Drives both FROST rounds and aggregates with the group `pubkey_package_hex`
/// (the `PublicKeyPackage` distributed at enrollment). `signers` must be a quorum
/// — at least the group's threshold of participants; fewer makes
/// [`frost::aggregate`] fail. Returns the raw 64-byte Ed25519 signature, which
/// verifies as a standard signature under the group identity's public key.
///
/// The coordinator itself holds no share beyond whatever it provides as one of
/// the `signers` (typically a [`LocalFrostSigner`] over its own share); the
/// others contribute only commitments and signature shares.
pub async fn coordinate_threshold_sign(
    signers: &[&dyn FrostSigner],
    pubkey_package_hex: &str,
    message: &[u8],
) -> Result<Vec<u8>> {
    if signers.is_empty() {
        return Err(anyhow!("threshold signing needs at least one participant"));
    }

    // Round 1 — collect each participant's commitment (id paired for round 2).
    let mut commitments: Vec<(String, String)> = Vec::with_capacity(signers.len());
    for signer in signers {
        commitments.push(signer.commit().await?);
    }

    // The coordinator binds the message + commitments into one signing package.
    let signing_package = frost::create_signing_package(message, &commitments)
        .map_err(|e| anyhow!("build signing package: {e}"))?;

    // Round 2 — collect each participant's signature share, paired with its id.
    let mut shares: Vec<(String, String)> = Vec::with_capacity(signers.len());
    for (signer, (id, _commitment)) in signers.iter().zip(commitments.iter()) {
        let share = signer.sign(&signing_package).await?;
        shares.push((id.clone(), share));
    }

    frost::aggregate(&signing_package, pubkey_package_hex, &shares)
        .map_err(|e| anyhow!("aggregate threshold signature: {e}"))
}

// ── QUIC transport for a remote participant (distributed-signing #3) ──────────
//
// A coordinator on one node co-signs with a share held on another of the user's
// nodes. The two signing rounds ride one QUIC bi-stream: the coordinator's
// `QuicFrostSigner` sends a round-1 then a round-2 request; the remote runs
// `serve_frost_signing`, holding its secret nonces in the function's scope
// between the two — they never leave that node. The coordinator never sees the
// remote's share, only its commitment and signature share.

use serde::{Deserialize, Serialize};

/// Coordinator → participant, over the shared bi-stream.
#[derive(Serialize, Deserialize)]
enum SignRequest {
    /// Round 1: produce a commitment.
    Round1,
    /// Round 2: sign the coordinator's signing package.
    Round2 { signing_package: String },
}

/// Participant → coordinator.
#[derive(Serialize, Deserialize)]
enum SignReply {
    Round1 { id: String, commitment: String },
    Round2 { signature_share: String },
}

const MAX_SIGN_MSG: usize = 1024 * 1024;

async fn write_msg<T: Serialize>(send: &mut quinn::SendStream, msg: &T) -> Result<()> {
    let bytes = serde_json::to_vec(msg).map_err(|e| anyhow!("serialize sign message: {e}"))?;
    let len = bytes.len() as u32;
    send.write_all(&len.to_be_bytes())
        .await
        .map_err(|e| anyhow!("write len: {e}"))?;
    send.write_all(&bytes)
        .await
        .map_err(|e| anyhow!("write body: {e}"))?;
    Ok(())
}

async fn read_msg<T: for<'de> Deserialize<'de>>(recv: &mut quinn::RecvStream) -> Result<T> {
    let mut len_bytes = [0u8; 4];
    recv.read_exact(&mut len_bytes)
        .await
        .map_err(|e| anyhow!("read len: {e}"))?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > MAX_SIGN_MSG {
        return Err(anyhow!("sign message too large ({len} bytes)"));
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| anyhow!("read body: {e}"))?;
    serde_json::from_slice(&buf).map_err(|e| anyhow!("parse sign message: {e}"))
}

/// Participant side: serve one threshold-signing session for `key_package_hex`
/// over `connection`. Accepts the coordinator's bi-stream, answers round 1, holds
/// the round-1 nonces, then answers round 2. The share and nonces never leave.
pub async fn serve_frost_signing(
    connection: &quinn::Connection,
    key_package_hex: &str,
) -> Result<()> {
    let (mut send, mut recv) = connection
        .accept_bi()
        .await
        .map_err(|e| anyhow!("accept signing stream: {e}"))?;

    match read_msg::<SignRequest>(&mut recv).await? {
        SignRequest::Round1 => {}
        _ => return Err(anyhow!("expected a round-1 request first")),
    }
    let (nonces, commitment, id) =
        frost::signing_commit(key_package_hex).map_err(|e| anyhow!("round-1 commit: {e}"))?;
    write_msg(&mut send, &SignReply::Round1 { id, commitment }).await?;

    let signing_package = match read_msg::<SignRequest>(&mut recv).await? {
        SignRequest::Round2 { signing_package } => signing_package,
        _ => return Err(anyhow!("expected a round-2 request second")),
    };
    let signature_share = frost::signing_sign(key_package_hex, &nonces, &signing_package)
        .map_err(|e| anyhow!("round-2 sign: {e}"))?;
    write_msg(&mut send, &SignReply::Round2 { signature_share }).await?;
    send.finish().map_err(|e| anyhow!("finish signing stream: {e}"))?;
    Ok(())
}

/// Coordinator-side [`FrostSigner`] for a participant on another node, reached
/// over an established QUIC `connection`. Holds one bi-stream for the whole
/// session (round 1 in [`commit`](FrostSigner::commit), round 2 in
/// [`sign`](FrostSigner::sign)); the remote runs [`serve_frost_signing`].
pub struct QuicFrostSigner {
    stream: tokio::sync::Mutex<(quinn::SendStream, quinn::RecvStream)>,
}

impl QuicFrostSigner {
    /// Open the signing bi-stream to the participant on `connection`.
    pub async fn open(connection: &quinn::Connection) -> Result<Self> {
        let stream = connection
            .open_bi()
            .await
            .map_err(|e| anyhow!("open signing stream: {e}"))?;
        Ok(Self {
            stream: tokio::sync::Mutex::new(stream),
        })
    }
}

#[async_trait::async_trait]
impl FrostSigner for QuicFrostSigner {
    async fn commit(&self) -> Result<(String, String)> {
        let mut g = self.stream.lock().await;
        let (send, recv) = &mut *g;
        write_msg(send, &SignRequest::Round1).await?;
        match read_msg::<SignReply>(recv).await? {
            SignReply::Round1 { id, commitment } => Ok((id, commitment)),
            _ => Err(anyhow!("expected a round-1 reply")),
        }
    }

    async fn sign(&self, signing_package_hex: &str) -> Result<String> {
        let mut g = self.stream.lock().await;
        let (send, recv) = &mut *g;
        write_msg(
            send,
            &SignRequest::Round2 {
                signing_package: signing_package_hex.to_string(),
            },
        )
        .await?;
        match read_msg::<SignReply>(recv).await? {
            SignReply::Round2 { signature_share } => Ok(signature_share),
            _ => Err(anyhow!("expected a round-2 reply")),
        }
    }
}

// ── Request/response transport for the daemon's peer channel ──────────────────
//
// The daemon's operational inter-node transport is request/response — one
// bi-stream per call, `PeerChannel::request(bytes) -> bytes`, dispatched as a
// `UserRequest` → `UserResponse` (the same channel file sync and record sync
// ride). It is NOT a held-open stream, and reaching for a raw `quinn::Connection`
// would bypass the NAT/TURN/relay channel abstraction. So distributed signing
// over the daemon models the two FROST rounds as two independent requests:
//
//   coordinator --Round1{session}-->            participant
//               <--{id, commitment}--           (stashes nonces under `session`)
//   coordinator --Round2{session, package}-->   participant
//               <--{signature_share}--           (consumes nonces, drops session)
//
// This mirrors the org-frost signing handlers and keeps `QuicFrostSigner` as a
// held-stream reference. The participant's share and round-1 nonces never leave
// its process; only a commitment and a signature share cross the wire.
//
// Both halves here are transport-agnostic — the coordinator is generic over an
// async round-trip closure (the daemon supplies one that wraps the round in a
// `UserRequest` and sends it over the peer channel; a test supplies one that
// calls the participant in-process), and the participant operates on typed
// rounds, not bytes. That keeps this layer unit-testable without a daemon
// harness and without an IPC dependency.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

/// One coordinator → participant round (the body of one peer request).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FrostRound {
    /// Round 1: produce a commitment, opening a nonce session under `session_id`.
    Round1 { session_id: String },
    /// Round 2: sign `signing_package` using the nonces stashed under `session_id`.
    Round2 {
        session_id: String,
        signing_package: String,
    },
}

/// Participant → coordinator reply to a [`FrostRound`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FrostRoundReply {
    Round1 { id: String, commitment: String },
    Round2 { signature_share: String },
}

/// How long a round-1 nonce session may sit before it is considered abandoned.
///
/// A threshold-signing round-trip is sub-second; this is a generous upper bound
/// that bounds both memory and secret-nonce retention without any risk of
/// evicting a live session. A coordinator that opens round 1 and never sends
/// round 2 therefore leaks nothing past this window.
/// Public so the tests, which live in `05_runtime` because they need a real
/// QUIC listener, can assert the expiry boundary rather than hardcoding 120 and
/// silently passing if it ever changes.
pub const SESSION_TTL_SECS: i64 = 120;

/// Hard cap on concurrently-open round-1 sessions — a backstop so a coordinator
/// that floods round-1 requests (without round 2) cannot grow memory without
/// bound between TTL sweeps.
const MAX_OPEN_SESSIONS: usize = 256;

/// A stashed round-1 nonce session: the secret nonces plus when they were
/// created, so an abandoned session can be aged out.
struct NonceSession {
    /// Secret round-1 nonces (never leave the process).
    nonces: String,
    /// Unix seconds at which round 1 stashed these nonces.
    created_at: i64,
}

/// Participant-side responder for peer-driven threshold signing.
///
/// One per node; the daemon's peer handler routes incoming `FrostRound` requests
/// here. Round 1 stashes the secret round-1 nonces under the coordinator's
/// `session_id`; round 2 consumes them. The share and the nonces never leave the
/// process. Concurrent signing sessions are isolated by `session_id`.
///
/// Sessions are **bounded**: each carries its creation time, abandoned sessions
/// are swept on the next round 1 (and a late round 2 against an expired session
/// is rejected), and the open-session count is capped — so a coordinator that
/// opens round 1 without ever sending round 2 cannot pin memory or retain secret
/// nonces beyond [`SESSION_TTL_SECS`]. The caller supplies the clock (`now_secs`)
/// rather than this layer reading an ambient one, matching the rest of the
/// enrollment code.
///
/// **Blind-signing posture (RFC-0036 I5).** This participant signs whatever
/// signing package the coordinator hands it; it does not vet the act. That is
/// the accepted posture *only* while every signer is one of the user's own
/// `Full` devices (trusted hardware), where the M-of-N threshold is the whole
/// guarantee. Before an untrusted `Cosigner` may join a *constitutional-act*
/// quorum, the round-1 request must carry an authenticated, human/policy-readable
/// act description and this responder must gate its share on it (RFC-0029
/// trusted-path consent). The seam is additive — a new field on [`FrostRound`]
/// that `Full`-only quorums ignore — so it is deferred, not foreclosed.
#[derive(Default)]
pub struct FrostParticipant {
    /// `session_id` → round-1 nonce session; set by round 1, removed by round 2.
    sessions: Mutex<HashMap<String, NonceSession>>,
}

impl FrostParticipant {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Answer one round for `key_package_hex` (this node's FROST share, loaded
    /// from the `frost_share` keychain entry). `now_secs` is the current Unix
    /// time, used to age out abandoned round-1 sessions.
    pub fn handle(
        &self,
        key_package_hex: &str,
        round: FrostRound,
        now_secs: i64,
    ) -> Result<FrostRoundReply> {
        match round {
            FrostRound::Round1 { session_id } => {
                let (nonces, commitment, id) = frost::signing_commit(key_package_hex)
                    .map_err(|e| anyhow!("frost round-1 commit: {e}"))?;
                {
                    let mut sessions = self.sessions.lock().unwrap();
                    // Sweep abandoned sessions before admitting a new one.
                    sessions.retain(|_, s| !Self::is_expired(s, now_secs));
                    if sessions.len() >= MAX_OPEN_SESSIONS {
                        return Err(anyhow!(
                            "too many open signing sessions ({MAX_OPEN_SESSIONS}); refusing round 1"
                        ));
                    }
                    sessions.insert(
                        session_id,
                        NonceSession {
                            nonces,
                            created_at: now_secs,
                        },
                    );
                }
                Ok(FrostRoundReply::Round1 { id, commitment })
            }
            FrostRound::Round2 {
                session_id,
                signing_package,
            } => {
                let session = self
                    .sessions
                    .lock()
                    .unwrap()
                    .remove(&session_id)
                    .ok_or_else(|| anyhow!("no round-1 session for {session_id}"))?;
                if Self::is_expired(&session, now_secs) {
                    return Err(anyhow!("round-1 session for {session_id} has expired"));
                }
                let share = frost::signing_sign(key_package_hex, &session.nonces, &signing_package)
                    .map_err(|e| anyhow!("frost round-2 sign: {e}"))?;
                Ok(FrostRoundReply::Round2 {
                    signature_share: share,
                })
            }
        }
    }

    /// `true` once a session has outlived [`SESSION_TTL_SECS`]. A `created_at`
    /// in the future (clock skew) simply yields a non-expired session that ages
    /// out from `now` — never a spurious early eviction.
    fn is_expired(session: &NonceSession, now_secs: i64) -> bool {
        now_secs.saturating_sub(session.created_at) >= SESSION_TTL_SECS
    }
}

/// An async round-trip: send one [`FrostRound`] to a remote participant and
/// return its [`FrostRoundReply`]. The daemon builds one that serialises the
/// round into a `UserRequest` and sends it over the peer [`PeerChannel`].
pub type FrostRoundTrip = Box<
    dyn Fn(FrostRound) -> Pin<Box<dyn Future<Output = Result<FrostRoundReply>> + Send>>
        + Send
        + Sync,
>;

/// Coordinator-side [`FrostSigner`] for a participant reached over a
/// request/response transport (the daemon's peer channel). Each FROST round is
/// one round-trip; the coordinator never holds the participant's share.
pub struct PeerFrostSigner {
    session_id: String,
    round_trip: FrostRoundTrip,
}

impl PeerFrostSigner {
    /// Build a signer for one signing session. `session_id` correlates the two
    /// rounds on the participant; `round_trip` performs one request/response.
    pub fn new(session_id: String, round_trip: FrostRoundTrip) -> Self {
        Self {
            session_id,
            round_trip,
        }
    }
}

#[async_trait::async_trait]
impl FrostSigner for PeerFrostSigner {
    async fn commit(&self) -> Result<(String, String)> {
        let reply = (self.round_trip)(FrostRound::Round1 {
            session_id: self.session_id.clone(),
        })
        .await?;
        match reply {
            FrostRoundReply::Round1 { id, commitment } => Ok((id, commitment)),
            _ => Err(anyhow!("expected a round-1 reply")),
        }
    }

    async fn sign(&self, signing_package_hex: &str) -> Result<String> {
        let reply = (self.round_trip)(FrostRound::Round2 {
            session_id: self.session_id.clone(),
            signing_package: signing_package_hex.to_string(),
        })
        .await?;
        match reply {
            FrostRoundReply::Round2 { signature_share } => Ok(signature_share),
            _ => Err(anyhow!("expected a round-2 reply")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotton_crypto::frost;
    use kotton_crypto::DidKeyMethod;
    use ed25519_dalek::{Signature, Verifier};

    /// Verify a 64-byte aggregate as a standard Ed25519 signature under the group
    /// key (derived from the group DID).
    fn verify_under_group(did: &str, sig: &[u8], message: &[u8]) {
        let vk = DidKeyMethod::to_public_key(&did.parse().unwrap()).unwrap();
        let arr: [u8; 64] = sig.try_into().expect("64-byte signature");
        vk.verify(message, &Signature::from_bytes(&arr))
            .expect("threshold signature verifies under the group key");
    }

    fn local_signers(shares: &[(u16, String)], n: usize) -> Vec<LocalFrostSigner> {
        shares
            .iter()
            .take(n)
            .map(|(_idx, kp)| LocalFrostSigner::new(kp.clone()))
            .collect()
    }

    #[tokio::test]
    async fn coordinator_produces_a_verifying_two_of_two_signature() {
        let (shares, pubkey_package, did) = frost::generate_key_shares(2, 2).unwrap();
        let owned = local_signers(&shares, 2);
        let signers: Vec<&dyn FrostSigner> = owned.iter().map(|s| s as &dyn FrostSigner).collect();

        let message = b"constitutional act: enroll device";
        let sig = coordinate_threshold_sign(&signers, &pubkey_package, message)
            .await
            .unwrap();

        assert_eq!(sig.len(), 64);
        verify_under_group(&did, &sig, message);
    }

    #[tokio::test]
    async fn coordinator_signs_with_a_two_of_three_quorum() {
        let (shares, pubkey_package, did) = frost::generate_key_shares(2, 3).unwrap();
        // Any 2 of the 3 shares form a quorum.
        let owned = local_signers(&shares, 2);
        let signers: Vec<&dyn FrostSigner> = owned.iter().map(|s| s as &dyn FrostSigner).collect();

        let message = b"threshold ok with a sub-quorum of the group";
        let sig = coordinate_threshold_sign(&signers, &pubkey_package, message)
            .await
            .unwrap();
        verify_under_group(&did, &sig, message);
    }

    #[tokio::test]
    async fn below_threshold_fails_to_aggregate() {
        let (shares, pubkey_package, _did) = frost::generate_key_shares(2, 3).unwrap();
        // Only one signer — below the 2-of-3 threshold; aggregation must fail.
        let owned = local_signers(&shares, 1);
        let signers: Vec<&dyn FrostSigner> = owned.iter().map(|s| s as &dyn FrostSigner).collect();

        let result = coordinate_threshold_sign(&signers, &pubkey_package, b"lonely").await;
        assert!(result.is_err(), "a single share cannot meet a 2-of-3 threshold");
    }

    /// End-to-end distributed signing over a real loopback QUIC connection: the
    /// coordinator holds one share locally and co-signs with a second share held
    /// by a participant on the other end of the wire. The participant's share and
    /// its round-1 nonces never leave its process — only a commitment and a
    /// signature share cross the connection — yet the aggregate verifies as a
    /// standard Ed25519 signature under the group key (RFC-0036).
    /// The request/response path that the daemon uses: a coordinator drives a
    /// remote participant through two independent round-trips (as the peer
    /// channel does), the participant holds its round-1 nonces under the session
    /// id between them, and the aggregate verifies under the group key. This is
    /// the daemon's exact signing logic minus the IPC byte-framing.

    #[tokio::test]
    async fn peer_signer_round_trips_a_verifying_signature() {
        use std::sync::Arc;
        let (shares, pubkey_package, did) = frost::generate_key_shares(2, 2).unwrap();
        let coordinator_share = shares[0].1.clone();
        let participant_share = shares[1].1.clone();

        // The participant lives "on another node" — reached only via round-trips.
        let participant = Arc::new(FrostParticipant::new());
        let p_share = participant_share.clone();
        let p = Arc::clone(&participant);
        let round_trip: FrostRoundTrip = Box::new(move |round| {
            let p = Arc::clone(&p);
            let share = p_share.clone();
            Box::pin(async move { p.handle(&share, round, 0) })
        });

        let local = LocalFrostSigner::new(coordinator_share);
        let remote = PeerFrostSigner::new("session-1".to_string(), round_trip);
        let signers: Vec<&dyn FrostSigner> = vec![&local, &remote];

        let message = b"constitutional act co-signed over request/response";
        let sig = coordinate_threshold_sign(&signers, &pubkey_package, message)
            .await
            .expect("request/response distributed signing succeeds");

        assert_eq!(sig.len(), 64);
        verify_under_group(&did, &sig, message);
    }

    /// A round-2 with no prior round-1 (lost/expired session) is rejected — the
    /// participant has no nonces stashed under that id.

    #[tokio::test]
    async fn participant_rejects_round2_without_a_session() {
        let (shares, _pubkey_package, _did) = frost::generate_key_shares(2, 2).unwrap();
        let participant = FrostParticipant::new();
        let err = participant
            .handle(
                &shares[1].1,
                FrostRound::Round2 {
                    session_id: "never-opened".to_string(),
                    signing_package: "00".to_string(),
                },
                0,
            )
            .unwrap_err();
        assert!(err.to_string().contains("no round-1 session"));
    }

    /// An abandoned round 1 is aged out: a round 2 that arrives past the TTL is
    /// rejected as expired, and a later round 1 sweeps the stale session so its
    /// secret nonces do not linger.

    #[tokio::test]
    async fn participant_expires_an_abandoned_round1() {
        let (shares, _pubkey_package, _did) = frost::generate_key_shares(2, 2).unwrap();
        let participant = FrostParticipant::new();
        let share = &shares[1].1;

        // Round 1 at t=0 stashes nonces.
        participant
            .handle(share, FrostRound::Round1 { session_id: "s1".into() }, 0)
            .expect("round 1 opens a session");

        // A round 2 well past the TTL is rejected as expired (not signed).
        let err = participant
            .handle(
                share,
                FrostRound::Round2 {
                    session_id: "s1".into(),
                    signing_package: "00".into(),
                },
                SESSION_TTL_SECS + 1,
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("has expired"),
            "a round 2 past the TTL must be rejected as expired, got: {err}"
        );

        // Re-open and abandon, then a fresh round 1 past the TTL sweeps it: the
        // map holds only the new session, so the abandoned nonces are gone.
        participant
            .handle(share, FrostRound::Round1 { session_id: "old".into() }, 0)
            .unwrap();
        participant
            .handle(
                share,
                FrostRound::Round1 { session_id: "new".into() },
                SESSION_TTL_SECS + 5,
            )
            .unwrap();
        let sessions = participant.sessions.lock().unwrap();
        assert!(!sessions.contains_key("old"), "abandoned session was swept");
        assert!(sessions.contains_key("new"), "the fresh session remains");
    }
}
