// SPDX-License-Identifier: AGPL-3.0-or-later
//! kotton-handshake: the one handshake every connection begins with, as pure mechanism.
//!
//! kotton-protocol's *One handshake admits a device, by the identity's log*. Every
//! connection a device opens to a drive or to another device begins with
//! `Noise_XK_25519_ChaChaPoly_SHA256`:
//!
//! ```text
//! initiator                                   responder
//! 0. -> the version, one byte
//! 1. -> e, es
//! 2.                                          <- e, ee
//! 3. -> s, se      payload: kotton_wire::handshake::ThirdPayload
//! ```
//!
//! The prologue is the ASCII bytes `kotton-handshake-` followed by the version byte. What that
//! binds is Noise's handshake hash: the prologue enters it, and every handshake message is
//! sealed under it as associated data, so no message made under one version opens under
//! another, and neither side reaches the transport without having made or read all three
//! under one.
//! The prologue enters no key: Noise's chaining key mixes only the protocol name and the
//! exchanges, so the cipher keys and the transport keys are the same under any version for
//! the same exchanges. So the version is bound into the handshake's hash, under which every
//! message is sealed, as kottonllc/kotton-protocol#57 decided the handshake page says.
//!
//! Each message is one frame, its length first as two bytes, most significant first. After
//! the third message the channel is Noise's transport, frames of at most 65535 bytes, the
//! first of which is the responder's ([`kotton_wire::handshake::ResponderFrame`]).
//!
//! **No socket, no clock, no authority.** This crate turns bytes into bytes. It names no
//! principal and decides nobody's admission: the responder hands back the initiator's static
//! key and payload, and its caller answers. Keys are handed in already in Montgomery form;
//! `kotton_crypto::x25519` owns the conversion from Ed25519. A static key is never written in
//! any frame this crate makes in the clear, and nothing is signed.
//!
//! **What `snow` keeps.** `snow` does not zero its chaining key, its cipher keys or an
//! exchange's output when it drops them; that is the Noise implementation decision a chose,
//! not this crate's. This crate zeroes only what it owns, the copies of the statics and both
//! halves its exchange holds, and a caller should assume no more of a dropped handshake.
//!
//! **The one wait.** A responder that has not read the whole first frame, the version byte and
//! the first message, holds nothing to answer. [`read_opening`] says `Incomplete` until it
//! has; the caller holds the bytes in that state for [`FIRST_FRAME_WAIT`] and no longer, then
//! closes as it closes on any refusal: having written nothing.
//!
//! **The ask, and a recovery claim.** A responder that does not admit the initiator by what it
//! holds asks for its events ([`Admitting::ask`]), and reads the one frame that answers
//! ([`Asked::read_reply`]). That frame may be a recovery claim in place of events. Its tag is
//! the 32 bytes HKDF-SHA256 yields from an exchange between the Montgomery form of the claimed
//! authority's key and the responder's ephemeral value, with the handshake's hash once the
//! third message is read as the salt and [`CLAIM_INFO`] followed by the 32 bytes of the
//! authority's key as the info. The initiator makes it ([`AwaitingAnswer::claim`]); the
//! responder makes the one it expects ([`Asked::expected_claim_tag`]) and its caller compares
//! with [`kotton_wire::handshake::RecoveryClaim::tag_matches`]. The responder keeps its
//! ephemeral value for that and drops it with the [`Asked`]: once it has read the reply, or
//! not at all where it answers without asking.

mod dh;

use std::time::Duration;

use kotton_wire::handshake::{
    Answer, EventRef, ResponderFrame, ThirdPayload, Versions, MAX_FRAME_LEN, MAX_FRAME_PLAINTEXT,
    TAG_LEN, THIRD_PAYLOAD_LEN, VERSION_1,
};
use hkdf::Hkdf;
use kotton_wire::handshake::{AskReply, RecoveryClaim};
use sha2::Sha256;
use snow::{Builder, HandshakeState, TransportState};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub use kotton_wire::handshake;

/// The version this crate opens with: the latest it speaks.
pub const VERSION: u8 = VERSION_1;

/// What the prologue begins with; the version byte follows.
pub const PROLOGUE_PREFIX: &[u8] = b"kotton-handshake-";

/// The Noise protocol name.
pub const PROTOCOL_NAME: &str = "Noise_XK_25519_ChaChaPoly_SHA256";

/// How long a responder waits for the whole first frame before it closes, writing nothing.
pub const FIRST_FRAME_WAIT: Duration = Duration::from_secs(10);

/// The first message: an ephemeral value and an empty payload's tag.
const FIRST_LEN: usize = 32 + TAG_LEN;

/// What a recovery claim's info begins with; the 32 bytes of the authority's key follow.
pub const CLAIM_INFO: &[u8] = b"kotton-recovery-claim";

/// The prologue for `version`.
pub fn prologue(version: u8) -> Vec<u8> {
    let mut p = PROLOGUE_PREFIX.to_vec();
    p.push(version);
    p
}

/// Why a side closed. Nothing of it crosses the wire: every close is the connection ending.
///
/// It derives `Debug` for this crate's tests. It does not belong in a log line on refusal:
/// a refusal reads the same to everyone, and a line that says why is a record of who tried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Closed {
    /// A first frame of the wrong length, a version this side does not speak, or one no key
    /// opens under: it read one frame and writes nothing.
    Refused,
    /// An exchange yielded all zeros: a key of low order.
    LowOrder,
    /// A frame did not open under the channel's keys.
    Unopened,
    /// A frame or payload out of its one form.
    Malformed,
    /// Longer than a frame can be.
    TooLong,
    /// Both sides speak a later version than the one in use.
    LaterVersion,
}

impl From<snow::Error> for Closed {
    fn from(e: snow::Error) -> Self {
        match e {
            snow::Error::Dh => Closed::LowOrder,
            snow::Error::Decrypt => Closed::Unopened,
            _ => Closed::Malformed,
        }
    }
}

// ── Frames ────────────────────────────────────────────────────────────────────

/// `body` behind its two-byte length. A body longer than 65535 bytes is refused.
pub fn frame(body: &[u8]) -> Result<Vec<u8>, Closed> {
    let len = u16::try_from(body.len()).map_err(|_| Closed::TooLong)?;
    let mut out = Vec::with_capacity(2 + body.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

/// The first whole frame at the start of `buf`, and how many bytes it took, length included.
/// `None` until the frame is whole.
pub fn read_frame(buf: &[u8]) -> Option<(&[u8], usize)> {
    let len = usize::from(u16::from_be_bytes([*buf.first()?, *buf.get(1)?]));
    let body = buf.get(2..2 + len)?;
    Some((body, 2 + len))
}

/// What a responder has read of a connection's first bytes.
#[derive(Debug, PartialEq, Eq)]
pub enum Opening<'a> {
    /// The version byte and the first frame are not yet whole: the state the caller times
    /// with [`FIRST_FRAME_WAIT`].
    Incomplete,
    /// The version byte and the first frame, and how many bytes they took. Nothing past them
    /// is read.
    Complete {
        version: u8,
        first: &'a [u8],
        consumed: usize,
    },
}

/// Read the version byte and the one frame after it, and nothing more.
pub fn read_opening(buf: &[u8]) -> Opening<'_> {
    let Some((&version, rest)) = buf.split_first() else {
        return Opening::Incomplete;
    };
    match read_frame(rest) {
        Some((first, used)) => Opening::Complete {
            version,
            first,
            consumed: 1 + used,
        },
        None => Opening::Incomplete,
    }
}

// ── Keys ──────────────────────────────────────────────────────────────────────

fn secret_bytes(key: &StaticSecret) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(key.to_bytes())
}

/// What one run of the handshake is made with besides its keys. Outside this crate's tests
/// it is always the default: the version this crate opens with, the versions it speaks, and a
/// fresh ephemeral value.
struct Run {
    version: u8,
    speaks: Versions,
    #[cfg(test)]
    ephemeral: Option<Zeroizing<[u8; 32]>>,
}

impl Default for Run {
    fn default() -> Self {
        Self {
            version: VERSION,
            speaks: Versions::spoken(),
            #[cfg(test)]
            ephemeral: None,
        }
    }
}

fn builder<'a>(
    run: &'a Run,
    prologue: &'a [u8],
    keep: Option<dh::EphemeralSlot>,
) -> Builder<'a> {
    let params = PROTOCOL_NAME.parse().expect("the protocol name parses");
    let resolver = match keep {
        Some(slot) => dh::responder_resolver(slot),
        None => dh::resolver(),
    };
    let b = Builder::with_resolver(params, resolver).prologue(prologue);
    #[cfg(test)]
    let b = match &run.ephemeral {
        Some(e) => b.fixed_ephemeral_key_for_testing_only(&e[..]),
        None => b,
    };
    #[cfg(not(test))]
    let _ = run;
    b
}

fn write(hs: &mut HandshakeState, payload: &[u8]) -> Result<Vec<u8>, Closed> {
    let mut out = vec![0u8; MAX_FRAME_LEN];
    let n = hs.write_message(payload, &mut out)?;
    out.truncate(n);
    frame(&out)
}

// ── The initiator ─────────────────────────────────────────────────────────────

/// An initiator that has sent the version byte and the first message.
pub struct Initiator {
    hs: HandshakeState,
    run: Run,
    payload: ThirdPayload,
}

impl Initiator {
    /// Open a connection to the responder whose static key is `responder`, as `own`, acting
    /// for `identity` and holding `latest` of its log. Returns the bytes to send: the version
    /// byte and the first frame.
    pub fn open(
        own: &StaticSecret,
        responder: &PublicKey,
        identity: Option<[u8; 32]>,
        latest: Option<EventRef>,
    ) -> Result<(Self, Vec<u8>), Closed> {
        Self::open_with(Run::default(), own, responder, identity, latest)
    }

    fn open_with(
        run: Run,
        own: &StaticSecret,
        responder: &PublicKey,
        identity: Option<[u8; 32]>,
        latest: Option<EventRef>,
    ) -> Result<(Self, Vec<u8>), Closed> {
        let payload = ThirdPayload {
            identity,
            latest,
            versions: run.speaks,
        };
        // Refuse what the responder would refuse, before anything is sent.
        ThirdPayload::decode(&payload.encode()).map_err(|_| Closed::Malformed)?;
        let own = secret_bytes(own);
        let prologue = prologue(run.version);
        let mut hs = builder(&run, &prologue, None)
            .local_private_key(&own[..])
            .remote_public_key(responder.as_bytes())
            .build_initiator()?;
        let mut out = vec![run.version];
        out.extend(write(&mut hs, &[])?);
        Ok((Self { hs, run, payload }, out))
    }

    /// Read the second message's frame body; returns the third message's frame to send.
    pub fn read_second(mut self, second: &[u8]) -> Result<(AwaitingAnswer, Vec<u8>), Closed> {
        let mut scratch = vec![0u8; MAX_FRAME_LEN];
        let n = self.hs.read_message(second, &mut scratch)?;
        if n != 0 {
            return Err(Closed::Malformed);
        }
        // The responder's ephemeral value, the first 32 bytes of the message that just opened.
        let responder_ephemeral: [u8; 32] = second
            .get(..32)
            .and_then(|e| e.try_into().ok())
            .ok_or(Closed::Malformed)?;
        let third = write(&mut self.hs, &self.payload.encode())?;
        let hash = handshake_hash(&self.hs)?;
        let transport = self.hs.into_transport_mode()?;
        Ok((
            AwaitingAnswer {
                channel: Channel { transport },
                run: self.run,
                responder_ephemeral,
                hash,
            },
            third,
        ))
    }
}

/// Noise's `h` once the third message is made or read.
fn handshake_hash(hs: &HandshakeState) -> Result<[u8; 32], Closed> {
    hs.get_handshake_hash()
        .try_into()
        .map_err(|_| Closed::Malformed)
}

/// A recovery claim's tag from the exchange `shared`, under the handshake's `hash`, for the
/// authority whose key is `authority_key`.
fn claim_tag(shared: &[u8; 32], hash: &[u8; 32], authority_key: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(hash), shared);
    let mut info = Vec::with_capacity(CLAIM_INFO.len() + 32);
    info.extend_from_slice(CLAIM_INFO);
    info.extend_from_slice(authority_key);
    let mut tag = [0u8; 32];
    hk.expand(&info, &mut tag)
        .expect("32 bytes is a length HKDF-SHA256 yields");
    tag
}

/// An exchange, or `None` where it yields all zeros.
fn exchange(secret: &StaticSecret, public: &PublicKey) -> Option<Zeroizing<[u8; 32]>> {
    let shared = secret.diffie_hellman(public);
    shared
        .was_contributory()
        .then(|| Zeroizing::new(*shared.as_bytes()))
}

/// An initiator that has sent the third message and waits for the responder's first frame.
pub struct AwaitingAnswer {
    channel: Channel,
    run: Run,
    /// What a recovery claim is made over: the responder's ephemeral value and the hash.
    responder_ephemeral: [u8; 32],
    hash: [u8; 32],
}

impl AwaitingAnswer {
    /// A recovery claim for this connection, by the authority whose key is `authority_key`
    /// and whose Montgomery form is `authority`. `None` where the exchange yields all zeros.
    /// It answers this connection and no other: the hash covers both ephemeral values and
    /// both statics.
    pub fn claim(&self, authority: &StaticSecret, authority_key: [u8; 32]) -> Option<RecoveryClaim> {
        let shared = exchange(authority, &PublicKey::from(self.responder_ephemeral))?;
        Some(RecoveryClaim::new(
            authority_key,
            claim_tag(&shared, &self.hash, &authority_key),
        ))
    }

    /// Read the responder's first frame body. A side that finds both speak a later version
    /// than the one in use closes.
    pub fn read_first(mut self, body: &[u8]) -> Result<(Channel, Answer), Closed> {
        let plain = self.channel.open(body)?;
        let first = ResponderFrame::decode(&plain).map_err(|_| Closed::Malformed)?;
        if later_in_common(&self.run, &first.versions) {
            return Err(Closed::LaterVersion);
        }
        Ok((self.channel, first.answer))
    }
}

fn later_in_common(run: &Run, theirs: &Versions) -> bool {
    run.speaks
        .latest_common(theirs)
        .is_some_and(|v| v > run.version)
}

// ── The responder ─────────────────────────────────────────────────────────────

/// A responder that has answered the first message with the second.
pub struct Responder {
    hs: HandshakeState,
    run: Run,
    key: usize,
    /// Its ephemeral value's private half, checked against the second message.
    ephemeral: Zeroizing<[u8; 32]>,
}

#[cfg(test)]
thread_local! {
    /// How many keys this thread has tried on a first message: the tests read it to hold
    /// that every key is tried on every first frame.
    static TRIALS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Try one key on the first message, under the prologue of the version byte it came with.
fn try_key(
    run: &Run,
    key: &StaticSecret,
    first: &[u8],
) -> Result<(HandshakeState, dh::EphemeralSlot), snow::Error> {
    #[cfg(test)]
    TRIALS.with(|t| t.set(t.get() + 1));
    let own = secret_bytes(key);
    let prologue = prologue(run.version);
    let slot = dh::EphemeralSlot::default();
    let mut hs = builder(run, &prologue, Some(slot.clone()))
        .local_private_key(&own[..])
        .build_responder()?;
    let mut scratch = vec![0u8; MAX_FRAME_LEN];
    let n = hs.read_message(first, &mut scratch)?;
    if n != 0 {
        return Err(snow::Error::Input);
    }
    Ok((hs, slot))
}

/// The ephemeral value the slot holds, where it is the one `second` (a whole frame) carries.
fn kept_ephemeral(slot: &dh::EphemeralSlot, second: &[u8]) -> Result<Zeroizing<[u8; 32]>, Closed> {
    let kept = slot
        .lock()
        .map_err(|_| Closed::Malformed)?
        .take()
        .ok_or(Closed::Malformed)?;
    let sent = second.get(2..34).ok_or(Closed::Malformed)?;
    if PublicKey::from(&StaticSecret::from(*kept)).as_bytes() != sent {
        return Err(Closed::Malformed);
    }
    Ok(kept)
}

impl Responder {
    /// Answer an opening [`read_opening`] found whole, holding `keys`. The one the first
    /// message opens under answers; returns the second message's frame to send. A version
    /// this side does not speak, or a first message no key opens, is [`Closed::Refused`]
    /// with nothing to send, whatever the reason.
    ///
    /// The work is the same whichever key opens it and whatever its version byte: every key
    /// is tried on every first frame of the right length, under the prologue of the byte it
    /// came with, and only then is the version or the outcome read.
    pub fn answer_opening(
        keys: &[StaticSecret],
        version: u8,
        first: &[u8],
    ) -> Result<(Self, Vec<u8>), Closed> {
        Self::answer_with(
            Run {
                version,
                ..Run::default()
            },
            keys,
            first,
        )
    }

    fn answer_with(
        run: Run,
        keys: &[StaticSecret],
        first: &[u8],
    ) -> Result<(Self, Vec<u8>), Closed> {
        if first.len() != FIRST_LEN {
            return Err(Closed::Refused);
        }
        // Every trial runs before any is read: no early stop.
        let trials: Vec<Result<(HandshakeState, dh::EphemeralSlot), snow::Error>> =
            keys.iter().map(|k| try_key(&run, k, first)).collect();
        let opened = trials
            .into_iter()
            .enumerate()
            .find_map(|(i, t)| t.ok().map(|hs| (i, hs)));
        if !run.speaks.contains(run.version) {
            return Err(Closed::Refused);
        }
        let (key, (mut hs, slot)) = opened.ok_or(Closed::Refused)?;
        let second = write(&mut hs, &[])?;
        let ephemeral = kept_ephemeral(&slot, &second)?;
        Ok((
            Self {
                hs,
                run,
                key,
                ephemeral,
            },
            second,
        ))
    }

    /// Which of the keys handed in the first message opened under.
    pub fn key_index(&self) -> usize {
        self.key
    }

    /// Read the third message's frame body. Returns the initiator's static key, in the form
    /// the pattern delivered it, and its payload, for the caller to answer.
    pub fn read_third(mut self, third: &[u8]) -> Result<Admitting, Closed> {
        let mut scratch = vec![0u8; MAX_FRAME_LEN];
        let n = self.hs.read_message(third, &mut scratch)?;
        if n != THIRD_PAYLOAD_LEN {
            return Err(Closed::Malformed);
        }
        let payload = ThirdPayload::decode(&scratch[..n]).map_err(|_| Closed::Malformed)?;
        let initiator: [u8; 32] = self
            .hs
            .get_remote_static()
            .and_then(|s| s.try_into().ok())
            .ok_or(Closed::Malformed)?;
        let hash = handshake_hash(&self.hs)?;
        let transport = self.hs.into_transport_mode()?;
        Ok(Admitting {
            channel: Channel { transport },
            run: self.run,
            initiator: PublicKey::from(initiator),
            payload,
            claim: ClaimKey {
                ephemeral: self.ephemeral,
                hash,
            },
        })
    }
}

/// What a responder checks a recovery claim with: its ephemeral value and the hash. Zeroed
/// when dropped.
struct ClaimKey {
    ephemeral: Zeroizing<[u8; 32]>,
    hash: [u8; 32],
}

/// A responder that has read the third message and has yet to answer it.
pub struct Admitting {
    channel: Channel,
    run: Run,
    initiator: PublicKey,
    payload: ThirdPayload,
    claim: ClaimKey,
}

impl Admitting {
    /// The initiator's static key, Montgomery form.
    pub fn initiator(&self) -> &PublicKey {
        &self.initiator
    }

    pub fn payload(&self) -> &ThirdPayload {
        &self.payload
    }

    /// Answer with the responder's first frame, which states the versions it speaks. Returns
    /// that frame, to send whatever follows, and the channel; or, where both sides speak a
    /// later version than the one in use, [`Closed::LaterVersion`] once the frame is sent.
    pub fn answer(mut self, answer: Answer) -> Result<(Vec<u8>, Result<Channel, Closed>), Closed> {
        let first = ResponderFrame {
            versions: self.run.speaks,
            answer,
        }
        .encode();
        let sent = self.channel.seal(&first)?;
        if later_in_common(&self.run, &self.payload.versions) {
            return Ok((sent, Err(Closed::LaterVersion)));
        }
        Ok((sent, Ok(self.channel)))
    }

    /// Answer with the one ask for events, keeping the ephemeral value until the frame that
    /// answers it is read. Returns that first frame and what reads the answer; or, as
    /// [`Self::answer`] does, [`Closed::LaterVersion`] once the frame is sent.
    pub fn ask(mut self) -> Result<(Vec<u8>, Result<Asked, Closed>), Closed> {
        let first = ResponderFrame {
            versions: self.run.speaks,
            answer: Answer::AskForEvents,
        }
        .encode();
        let sent = self.channel.seal(&first)?;
        if later_in_common(&self.run, &self.payload.versions) {
            return Ok((sent, Err(Closed::LaterVersion)));
        }
        Ok((
            sent,
            Ok(Asked {
                channel: self.channel,
                speaks: self.run.speaks,
                claim: self.claim,
            }),
        ))
    }
}

/// A responder that has asked for the initiator's events.
pub struct Asked {
    channel: Channel,
    speaks: Versions,
    claim: ClaimKey,
}

impl Asked {
    /// Read the frame that answers the ask: events, or a recovery claim.
    pub fn read_reply(&mut self, body: &[u8]) -> Result<AskReply, Closed> {
        let plain = self.channel.open(body)?;
        AskReply::decode(&plain).map_err(|_| Closed::Malformed)
    }

    /// The tag a claim by the authority whose key is `authority_key`, and whose Montgomery
    /// form is `authority`, must carry on this connection. `None` where the exchange yields
    /// all zeros, which is closed on as any refusal is. The caller compares with
    /// [`RecoveryClaim::tag_matches`], and does so before it looks the authority up.
    pub fn expected_claim_tag(&self, authority: &PublicKey, authority_key: &[u8; 32]) -> Option<[u8; 32]> {
        let shared = exchange(&StaticSecret::from(*self.claim.ephemeral), authority)?;
        Some(claim_tag(&shared, &self.claim.hash, authority_key))
    }

    /// The initiator is now admitted: the frame that says so, as the first frame would have,
    /// and the channel. The ephemeral value is dropped with this.
    pub fn admit(mut self, latest: Option<EventRef>) -> Result<(Vec<u8>, Channel), Closed> {
        let frame = ResponderFrame {
            versions: self.speaks,
            answer: Answer::Admitted { latest },
        }
        .encode();
        let sent = self.channel.seal(&frame)?;
        Ok((sent, self.channel))
    }
}

// ── The channel ───────────────────────────────────────────────────────────────

/// Noise's transport: frames of at most 65535 bytes, each sealed, read in the order sent.
pub struct Channel {
    transport: TransportState,
}

impl Channel {
    /// Seal `plaintext` as one frame, its length first. A plaintext that would make a frame
    /// longer than 65535 bytes is refused.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Closed> {
        if plaintext.len() > MAX_FRAME_PLAINTEXT {
            return Err(Closed::TooLong);
        }
        let mut out = vec![0u8; MAX_FRAME_LEN];
        let n = self.transport.write_message(plaintext, &mut out)?;
        out.truncate(n);
        frame(&out)
    }

    /// Read the frame a responder sends once it has read the answer to its ask: the
    /// initiator is admitted, and the latest event the responder holds, or none.
    pub fn read_admitted(&mut self, body: &[u8]) -> Result<Option<EventRef>, Closed> {
        let plain = self.open(body)?;
        match ResponderFrame::decode(&plain).map_err(|_| Closed::Malformed)?.answer {
            Answer::Admitted { latest } => Ok(latest),
            Answer::AskForEvents => Err(Closed::Malformed),
        }
    }

    /// Open one frame's body.
    pub fn open(&mut self, body: &[u8]) -> Result<Vec<u8>, Closed> {
        if body.len() > MAX_FRAME_LEN {
            return Err(Closed::TooLong);
        }
        let mut out = vec![0u8; MAX_FRAME_LEN];
        let n = self.transport.read_message(body, &mut out)?;
        out.truncate(n);
        Ok(out)
    }
}

#[cfg(test)]
mod tests;
