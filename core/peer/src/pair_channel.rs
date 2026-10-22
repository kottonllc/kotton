// SPDX-License-Identifier: AGPL-3.0-or-later
//! Committed-handshake pairing **channel** over any byte stream.
//!
//! This is the transport-level state machine that turns a bootstrap stream — a
//! QUIC bi-stream on a LAN, or a relay-bridged WebSocket between two strangers
//! — into a forward-secret, SAS-authenticated channel. It runs the
//! commit-then-reveal ephemeral-X25519 handshake (crypto in
//! [`kotton_crypto::pair_handshake`]), asks the local human to compare
//! the six-digit SAS, exchanges mutual confirmation MACs, and hands back an
//! [`EstablishedChannel`] over which the caller AEAD-transfers the enrollment
//! payload. It is **payload-agnostic** — enrollment (`FrostShare`), blind relay,
//! and future rungs all ride the same channel.
//!
//! Why not a static–static ECDH seal: that seal keys the envelope off both
//! devices' *long-term* keys, so a recorded ceremony plus a later key compromise
//! decrypts the transferred share/CEK. The
//! ephemeral keys here give the channel **forward secrecy**; the commitment round
//! makes the six-digit SAS worth exactly one-in-a-million to a MITM.
//!
//! Wire order (`J` dials, opens the bi-stream, and speaks first):
//!
//! ```text
//! J → PairHello { v, sid }
//! (with a code:)
//! J → PakeMsg          I → PakeMsg          both derive k_pake from the code
//! I → PakeConfirm      J → PakeConfirm      each verified before going on
//! I → PairCommit { commit = SHA-256(eph_pub_I ‖ nonce_I) }
//! J → PairReveal { eph_pub_J, nonce_J }
//! I → PairReveal { eph_pub_I, nonce_I }        J verifies it opens the commit
//! both derive the session + SAS
//! I → PairInfo { label }                       first frame AEAD under k_enc
//! (each human compares the SAS and confirms locally)
//! J → PairConfirm { mac_J }   I → PairConfirm { mac_I }   (either order)
//! → EstablishedChannel: caller transfers the enrollment payload AEAD under k_enc
//! ```
//!
//! With a code, `k_pake` is folded into the key schedule
//! ([`kotton_pair::derive_session_with`]), so the channel key, both confirmation
//! MACs and the six digits all depend on it: a relay that forwards every frame
//! but never heard the code derives nothing that verifies. The confirmation
//! round right after the PAKE is what makes a mistyped code fail as *"the codes
//! differ"* before either screen shows digits.

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use kotton_wire::peer::{PairCommit, PairConfirm, PairHello, PairInfo, PairReveal};
use kotton_pair::handshake::{
    commit, derive_session_with, verify_commitment, EnrollmentSide, PairEphemeral,
    PairSession, Transcript as PairTranscript,
};
use kotton_pair::pake::{confirm_tag, Pake, PakeRole};
use kotton_pair::wire::{PakeConfirm, PakeMsg};
use kotton_pair::AeadChannel;
use rand::rngs::OsRng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use rand::RngCore;
use serde::de::DeserializeOwned;
use serde::Serialize;

/// The pinned handshake protocol version (transcript-bound, so a future v2 cannot
/// be confused into v1 semantics).
pub const PAIR_PROTOCOL_VERSION: u16 = 1;

/// Cap on a single wire frame. Handshake frames are tiny; the payload frame is
/// bounded by the enrollment bundle. 10 MiB is generous headroom against a hostile
/// peer trying to exhaust memory.
const MAX_FRAME_BYTES: usize = 10 * 1024 * 1024;

// ── Human confirmation ─────────────────────────────────────────────────────────

/// The local human's verdict on the six-digit SAS. Implemented by whatever surface
/// drives the ceremony — a CLI prompt, a shell consent dialog, or (in tests) an
/// auto-confirmer. The channel calls it exactly once, after deriving the SAS and
/// (on the joiner) learning the peer's label.
#[async_trait]
pub trait SasConfirmer: Send + Sync {
    /// Present `sas` (0..1_000_000, render zero-padded and grouped) and, when known,
    /// the peer's `label` to the human. Return `true` iff the human confirms the
    /// codes match; `false` cancels the ceremony (nothing is transferred).
    async fn confirm(&self, sas: u32, peer_label: Option<&str>) -> bool;
}

// ── Errors ───────────────────────────────────────────────────────────────────

/// Why a pairing channel failed to establish. Distinguished so the daemon/CLI can
/// map each to the calm, specific failure copy (mismatch vs. peer-vanished vs.
/// expired). `SasRejected` is the one genuinely dangerous branch — it earns the
/// serious "someone may have interfered" wording.
#[derive(Debug, thiserror::Error)]
pub enum PairChannelError {
    /// The local human said the codes do **not** match, or cancelled. Nothing was
    /// transferred. May mean a MITM on the network.
    #[error("codes did not match / cancelled locally")]
    SasRejected,
    /// The issuer's reveal did not open its commitment — it tried to change its key
    /// after committing (the grinding attack). Abort.
    #[error("commitment mismatch — issuer changed its key after committing (possible MITM)")]
    CommitmentMismatch,
    /// The peer's confirmation MAC did not verify: it could not compute the shared
    /// secret (a commitment-forwarding interposer) even if a human mis-confirmed.
    #[error("peer confirmation MAC failed to verify")]
    ConfirmMacFailed,
    /// The peer speaks a different handshake version.
    #[error("protocol version mismatch: peer sent v{got}, expected v{want}")]
    VersionMismatch { got: u16, want: u16 },
    /// The joiner answered a different offer than the one this issuer advertised.
    #[error("session id mismatch: peer answered a different offer")]
    SidMismatch,
    /// The PAKE keys disagree: the other side used a different code. Nothing
    /// past the code was exchanged, and no digits were shown.
    #[error("the codes differ: the other side used a different code")]
    PakeMismatch,
    /// Transport / serialization failure (peer vanished, malformed frame, …).
    #[error(transparent)]
    Transport(#[from] anyhow::Error),
}

// ── AEAD channel ───────────────────────────────────────────────────────────────
//
// The ChaCha20-Poly1305 counter-nonce channel is `kotton_pair::AeadChannel` now —
// sans-I/O, so the browser joiner (the reach tier) runs the same code on
// the far side of a gateway that cannot read it. This file keeps the QUIC framing.

// ── Established channel ─────────────────────────────────────────────────────────

/// A SAS-authenticated, forward-secret channel, returned once both humans have
/// confirmed. The caller transfers the enrollment payload over it with
/// [`send_encrypted`](Self::send_encrypted) / [`recv_encrypted`](Self::recv_encrypted)
/// and can bind an attestation signature to [`transcript`](Self::transcript).
pub struct EstablishedChannel<W, R> {
    session: PairSession,
    transcript: PairTranscript,
    peer_label: Option<String>,
    aead: AeadChannel,
    send: W,
    recv: R,
}

impl<W: AsyncWrite + Unpin + Send, R: AsyncRead + Unpin + Send> EstablishedChannel<W, R> {
    /// The six-digit SAS the humans compared (0..1_000_000).
    pub fn sas(&self) -> u32 {
        self.session.sas()
    }

    /// The issuer's label, learned by the joiner over the encrypted channel. `None`
    /// on the issuer side (it does not receive a joiner label).
    pub fn peer_label(&self) -> Option<&str> {
        self.peer_label.as_deref()
    }

    /// The handshake transcript, for binding an attestation signature or
    /// auditing.
    pub fn transcript(&self) -> &PairTranscript {
        &self.transcript
    }

    /// AEAD-encrypt and send one frame under `k_enc`.
    pub async fn send_encrypted(&mut self, plaintext: &[u8]) -> Result<()> {
        let ct = self.aead.seal(plaintext)?;
        write_bytes(&mut self.send, &ct).await
    }

    /// Receive and AEAD-decrypt one frame under `k_enc`.
    pub async fn recv_encrypted(&mut self) -> Result<Vec<u8>> {
        let ct = read_bytes(&mut self.recv).await?;
        self.aead.open(&ct)
    }

    /// Cleanly finish the send side (call after the last frame).
    pub async fn finish(&mut self) -> Result<()> {
        self.send
            .shutdown()
            .await
            .map_err(|e| anyhow!("finish send: {e}"))
    }
}

// ── Establish: issuer side ─────────────────────────────────────────────────────

/// Run the issuer (existing-device) side of the handshake over an accepted
/// bi-stream. `expected_sid` is the offer's session id the issuer advertised;
/// `label` is the issuer's human label, delivered to the joiner over the encrypted
/// channel. `confirmer` is asked to compare the SAS.
///
/// Returns the [`EstablishedChannel`] only after **both** sides confirm; any
/// abort (local reject, bad peer MAC, transport loss) returns an error and
/// transfers nothing.
pub async fn issuer_establish<W, R>(
    send: W,
    recv: R,
    expected_sid: [u8; 16],
    label: &str,
    confirmer: &dyn SasConfirmer,
) -> std::result::Result<EstablishedChannel<W, R>, PairChannelError>
where
    W: AsyncWrite + Unpin + Send,
    R: AsyncRead + Unpin + Send,
{
    issuer_establish_with(send, recv, expected_sid, label, confirmer, None).await
}

/// [`issuer_establish`] for a ceremony keyed by a spoken `code` as well:
/// a SPAKE2 round runs right after the hello and its key is folded
/// into the schedule. `None` is exactly [`issuer_establish`].
pub async fn issuer_establish_with<W, R>(
    mut send: W,
    mut recv: R,
    expected_sid: [u8; 16],
    label: &str,
    confirmer: &dyn SasConfirmer,
    code: Option<&[u8]>,
) -> std::result::Result<EstablishedChannel<W, R>, PairChannelError>
where
    W: AsyncWrite + Unpin + Send,
    R: AsyncRead + Unpin + Send,
{
    // 1. Read the joiner's hello; bind version + session id.
    let hello: PairHello = read_msg(&mut recv).await?;
    if hello.v != PAIR_PROTOCOL_VERSION {
        return Err(PairChannelError::VersionMismatch {
            got: hello.v,
            want: PAIR_PROTOCOL_VERSION,
        });
    }
    if hello.sid != expected_sid {
        return Err(PairChannelError::SidMismatch);
    }

    // 1b. With a code: the PAKE, then prove its key before anything else.
    let extra_ikm = match code {
        Some(code) => {
            let msg_j: PakeMsg = read_msg(&mut recv).await?;
            let (pake, msg_i) = Pake::start(PakeRole::Issuer, code, OsRng);
            write_msg(&mut send, &PakeMsg { msg: msg_i }).await?;
            let k = pake.finish(&msg_j.msg).map_err(PairChannelError::Transport)?;
            write_msg(&mut send, &PakeConfirm { mac: confirm_tag(&k, PakeRole::Issuer, &hello.sid) })
                .await?;
            let theirs: PakeConfirm = read_msg(&mut recv).await?;
            if theirs.mac != confirm_tag(&k, PakeRole::Joiner, &hello.sid) {
                return Err(PairChannelError::PakeMismatch);
            }
            pake_ikm(&k)
        }
        None => Vec::new(),
    };

    // 2. Commit to a fresh ephemeral key before seeing the joiner's.
    let eph_i = PairEphemeral::generate();
    let mut nonce_i = [0u8; 32];
    OsRng.fill_bytes(&mut nonce_i);
    let commitment = commit(&eph_i.public(), &nonce_i);
    write_msg(&mut send, &PairCommit { commit: commitment }).await?;

    // 3. Read the joiner's reveal.
    let reveal_j: PairReveal = read_msg(&mut recv).await?;

    // 4. Reveal our own.
    write_msg(
        &mut send,
        &PairReveal {
            eph_pub: eph_i.public(),
            nonce: nonce_i,
        },
    )
    .await?;

    // 5. Derive the session + SAS.
    let transcript = PairTranscript {
        sid: hello.sid,
        commit: commitment,
        eph_pub_i: eph_i.public(),
        eph_pub_j: reveal_j.eph_pub,
        nonce_i,
        nonce_j: reveal_j.nonce,
    };
    let session = derive_session_with(&eph_i, &reveal_j.eph_pub, &transcript, &extra_ikm)?;
    let mut aead = AeadChannel::new(session.k_enc(), EnrollmentSide::Issuer);

    // 6. Send our label as the first encrypted frame (the joiner's dialog needs it).
    send_aead(&mut send, &mut aead, &PairInfo { label: label.to_string() }).await?;

    // 7. Ask the human to compare the SAS; abort if they decline.
    if !confirmer.confirm(session.sas(), None).await {
        return Err(PairChannelError::SasRejected);
    }

    // 8. Release our confirmation MAC, then verify the peer's.
    let mac_i = session.confirm_mac(EnrollmentSide::Issuer, &transcript);
    write_msg(&mut send, &PairConfirm { mac: mac_i }).await?;
    let confirm_j: PairConfirm = read_msg(&mut recv).await?;
    if !session.verify_confirm(EnrollmentSide::Joiner, &transcript, &confirm_j.mac) {
        return Err(PairChannelError::ConfirmMacFailed);
    }

    Ok(EstablishedChannel {
        session,
        transcript,
        peer_label: None,
        aead,
        send,
        recv,
    })
}

// ── Establish: joiner side ─────────────────────────────────────────────────────

/// Run the joiner (new-device) side of the handshake over a freshly opened
/// bi-stream. `sid` is the offer's session id (from the mDNS advertisement or the
/// connection code). `confirmer` is asked to compare the SAS after the joiner
/// learns the issuer's label.
pub async fn joiner_establish<W, R>(
    send: W,
    recv: R,
    sid: [u8; 16],
    confirmer: &dyn SasConfirmer,
) -> std::result::Result<EstablishedChannel<W, R>, PairChannelError>
where
    W: AsyncWrite + Unpin + Send,
    R: AsyncRead + Unpin + Send,
{
    joiner_establish_with(send, recv, sid, confirmer, None).await
}

/// [`joiner_establish`] for a ceremony keyed by a typed `code` as well.
/// See [`issuer_establish_with`].
pub async fn joiner_establish_with<W, R>(
    mut send: W,
    mut recv: R,
    sid: [u8; 16],
    confirmer: &dyn SasConfirmer,
    code: Option<&[u8]>,
) -> std::result::Result<EstablishedChannel<W, R>, PairChannelError>
where
    W: AsyncWrite + Unpin + Send,
    R: AsyncRead + Unpin + Send,
{
    // 1. Open with hello.
    write_msg(
        &mut send,
        &PairHello {
            v: PAIR_PROTOCOL_VERSION,
            sid,
        },
    )
    .await?;

    // 1b. With a code: the PAKE, then prove its key before anything else.
    let extra_ikm = match code {
        Some(code) => {
            let (pake, msg_j) = Pake::start(PakeRole::Joiner, code, OsRng);
            write_msg(&mut send, &PakeMsg { msg: msg_j }).await?;
            let msg_i: PakeMsg = read_msg(&mut recv).await?;
            let k = pake.finish(&msg_i.msg).map_err(PairChannelError::Transport)?;
            // Send ours before judging theirs: a tag under a key the peer cannot
            // verify discloses nothing, and it lets the issuer report the same
            // mismatch rather than a dropped stream.
            write_msg(&mut send, &PakeConfirm { mac: confirm_tag(&k, PakeRole::Joiner, &sid) })
                .await?;
            let theirs: PakeConfirm = read_msg(&mut recv).await?;
            if theirs.mac != confirm_tag(&k, PakeRole::Issuer, &sid) {
                return Err(PairChannelError::PakeMismatch);
            }
            pake_ikm(&k)
        }
        None => Vec::new(),
    };

    // 2. Read the issuer's commitment.
    let commit_msg: PairCommit = read_msg(&mut recv).await?;

    // 3. Reveal our fresh ephemeral.
    let eph_j = PairEphemeral::generate();
    let mut nonce_j = [0u8; 32];
    OsRng.fill_bytes(&mut nonce_j);
    write_msg(
        &mut send,
        &PairReveal {
            eph_pub: eph_j.public(),
            nonce: nonce_j,
        },
    )
    .await?;

    // 4. Read the issuer's reveal.
    let reveal_i: PairReveal = read_msg(&mut recv).await?;

    // 5. The reveal must open the commitment (else the issuer ground its key).
    if !verify_commitment(&commit_msg.commit, &reveal_i.eph_pub, &reveal_i.nonce) {
        return Err(PairChannelError::CommitmentMismatch);
    }

    // 6. Derive the session + SAS.
    let transcript = PairTranscript {
        sid,
        commit: commit_msg.commit,
        eph_pub_i: reveal_i.eph_pub,
        eph_pub_j: eph_j.public(),
        nonce_i: reveal_i.nonce,
        nonce_j,
    };
    let session = derive_session_with(&eph_j, &reveal_i.eph_pub, &transcript, &extra_ikm)?;
    let mut aead = AeadChannel::new(session.k_enc(), EnrollmentSide::Joiner);

    // 7. Read the issuer's label (first encrypted frame).
    let info: PairInfo = recv_aead(&mut recv, &mut aead).await?;

    // 8. Ask the human to compare the SAS; abort if they decline.
    if !confirmer.confirm(session.sas(), Some(&info.label)).await {
        return Err(PairChannelError::SasRejected);
    }

    // 9. Release our confirmation MAC, then verify the peer's.
    let mac_j = session.confirm_mac(EnrollmentSide::Joiner, &transcript);
    write_msg(&mut send, &PairConfirm { mac: mac_j }).await?;
    let confirm_i: PairConfirm = read_msg(&mut recv).await?;
    if !session.verify_confirm(EnrollmentSide::Issuer, &transcript, &confirm_i.mac) {
        return Err(PairChannelError::ConfirmMacFailed);
    }

    Ok(EstablishedChannel {
        session,
        transcript,
        peer_label: Some(info.label),
        aead,
        send,
        recv,
    })
}

/// The PAKE key as the schedule's second secret, domain-tagged so a contact
/// ceremony and a device ceremony can never derive the same keys from the
/// same ephemerals.
fn pake_ikm(k_pake: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(24 + 32);
    v.extend_from_slice(b"kotton:contact-pair:v1:");
    v.extend_from_slice(k_pake);
    v
}

// ── Frame I/O (length-prefixed) ─────────────────────────────────────────────────

async fn write_bytes<W: AsyncWrite + Unpin>(send: &mut W, bytes: &[u8]) -> Result<()> {
    let len = u32::try_from(bytes.len()).context("frame exceeds u32 length")?;
    send.write_all(&len.to_be_bytes())
        .await
        .map_err(|e| anyhow!("write frame length: {e}"))?;
    send.write_all(bytes)
        .await
        .map_err(|e| anyhow!("write frame body: {e}"))?;
    // A frame is a message: on a stream that batches writes into one send
    // (the relay-bridged WebSocket), nothing leaves until this.
    send.flush()
        .await
        .map_err(|e| anyhow!("flush frame: {e}"))?;
    Ok(())
}

async fn read_bytes<R: AsyncRead + Unpin>(recv: &mut R) -> Result<Vec<u8>> {
    let mut len_bytes = [0u8; 4];
    recv.read_exact(&mut len_bytes)
        .await
        .map_err(|e| anyhow!("read frame length: {e}"))?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > MAX_FRAME_BYTES {
        bail!("pairing frame too large ({len} bytes)");
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| anyhow!("read frame body: {e}"))?;
    Ok(buf)
}

async fn write_msg<W: AsyncWrite + Unpin, T: Serialize>(send: &mut W, msg: &T) -> Result<()> {
    let bytes = serde_json::to_vec(msg).context("serialize handshake frame")?;
    write_bytes(send, &bytes).await
}

async fn read_msg<R: AsyncRead + Unpin, T: DeserializeOwned>(recv: &mut R) -> Result<T> {
    let bytes = read_bytes(recv).await?;
    serde_json::from_slice(&bytes).context("deserialize handshake frame")
}

async fn send_aead<W: AsyncWrite + Unpin, T: Serialize>(
    send: &mut W,
    aead: &mut AeadChannel,
    msg: &T,
) -> Result<()> {
    let plaintext = serde_json::to_vec(msg).context("serialize encrypted frame")?;
    let ct = aead.seal(&plaintext)?;
    write_bytes(send, &ct).await
}

async fn recv_aead<R: AsyncRead + Unpin, T: DeserializeOwned>(recv: &mut R, aead: &mut AeadChannel) -> Result<T> {
    let ct = read_bytes(recv).await?;
    let plaintext = aead.open(&ct)?;
    serde_json::from_slice(&plaintext).context("deserialize encrypted frame")
}

// ── Tests ─────────────────────────────────────────────────────────────────────
