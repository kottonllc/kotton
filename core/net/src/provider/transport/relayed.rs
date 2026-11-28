// SPDX-License-Identifier: AGPL-3.0-or-later
//! A relay's circuit, and the handshake it carries.
//!
//! When direct connection and NAT hole-punching both fail, two nodes reach each other
//! through the Kotton relay, which bridges a WebSocket between them (see `infra/relay`).
//! Over that bridged byte stream runs the one handshake every connection begins with
//! (kotton-protocol's *One handshake admits a device, by the identity's log*;
//! [`kotton_handshake`]): a version byte, three Noise XK messages each behind a two-byte
//! length, then Noise's transport in sealed frames of at most 65535 bytes. A request and
//! its answer each cross as one message across as many frames as it takes
//! ([`kotton_wire::handshake::split_message`]), one at a time on a circuit.
//!
//! **What the relay sees.** The version byte, two fresh ephemeral values, each frame's
//! length, and sealed bytes with their tags. No static key in either form, no certificate,
//! no name: the initiator's key, and whatever it offers to be admitted, cross only sealed,
//! after the responder has shown it holds the key the initiator expected.
//!
//! **Each door's static.** A door answers under the Montgomery form of the Ed25519 key it
//! presents: a device's reservation under the device's key, a contact's door under the
//! pair's key for the hour. The dialer holds that key before it begins and the pattern
//! never sends it. A door holds at most [`MAX_DOOR_KEYS`] keys, since every first frame of
//! the right length costs one trial for each.
//!
//! **Who is admitted** is [`Admits`]'s answer, asked with the key the handshake delivered.
//! A door that does not admit the initiator by the key asks, in one form whatever the
//! reason, for its events; the frame that answers carries the events a recovered device
//! offers, or a recovery claim, and is put to [`Admits`] again. A refusal is the circuit
//! closing: no frame says why, and nothing here writes the initiator's key or identity down.
//!
//! **A claimant has no name** (#511). A device admitted on a recovery claim is known on its
//! connection by the claim's standing ([`Peer::Claim`]) and by no key; nothing about it is
//! written to a table shared across connections. A dialer makes its claim through
//! [`MakesClaim`], which the caller that holds the authority answers: no key of the
//! authority's crosses into this crate.
//!
//! **Every stage at a door has a bound, in places and in time.** Each expiry closes the
//! circuit as every refusal does: no frame, no reason, no line.
//! - *The dial-back.* A circuit takes one of the reservation's [`MAX_OPENING`] places before
//!   its data leg is dialled back, and the dial-back has [`DIAL_BACK_WAIT`]; a circuit past
//!   the bound is not dialled back.
//! - *The first frame.* The place is held until the version byte and first frame are whole,
//!   for [`kotton_handshake::FIRST_FRAME_WAIT`] at most; one that runs out the wait is closed
//!   on having been written nothing.
//! - *Admission.* A circuit whose first frame is whole takes one of [`MAX_ADMITTING`] places
//!   and gives up its opening place; one past that bound is closed on, written nothing. The
//!   whole of [`RelayedConnection::accept`], from its start to the frame that admits, has
//!   [`ADMIT_WAIT`], which covers the third message and the answer to an ask.
//! - *The dialer.* [`RelayedConnection::connect`] has [`ADMIT_WAIT`] too, from its first
//!   frame to being admitted.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use futures::{Sink, Stream, StreamExt};
use kotton_crypto::DidKeyMethod;
use kotton_handshake::handshake::{split_message, Answer, AskReply, MessageReader};
use kotton_handshake::{read_opening, Channel, Initiator, Opening, Responder};
use kotton_sys::net::TransportError;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, Mutex, OwnedSemaphorePermit, Semaphore};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use tracing::warn;
use x25519_dalek::StaticSecret;

use super::admits::Admits;

pub use kotton_handshake::{AwaitingAnswer, FIRST_FRAME_WAIT};
pub use kotton_wire::handshake::RecoveryClaim;
pub use super::admits::Peer;
use crate::provider::rendezvous::AdmissionKey;
use std::time::Duration;

/// The most static keys one door hands the responder. Every first frame of the right length
/// costs one trial for each, whoever sent it.
pub const MAX_DOOR_KEYS: usize = 8;

/// The most circuits one reservation holds before their version byte and first frame are
/// whole, the dial-back of their data leg included. Each is held for [`DIAL_BACK_WAIT`] and
/// then [`FIRST_FRAME_WAIT`] at most; one past the bound is not dialled back.
pub const MAX_OPENING: usize = 16;

/// The most circuits one reservation holds once their first frame is whole and before they
/// are admitted or refused. Each is held for what is left of [`ADMIT_WAIT`] at most; one
/// past the bound is closed on, having been written nothing.
pub const MAX_ADMITTING: usize = 16;

/// How long a door waits for the relay to answer the dial-back of a circuit's data leg.
pub const DIAL_BACK_WAIT: Duration = FIRST_FRAME_WAIT;

/// How long a circuit's handshake may take, from its start to the frame that admits: on the
/// door's side from the first byte read, on the dialer's from the first frame sent. Three
/// first frames' waits: the first frame, then the third message and the answer to an ask.
pub const ADMIT_WAIT: Duration = Duration::from_secs(3 * FIRST_FRAME_WAIT.as_secs());

/// The one error a circuit that ends in the handshake gives, whatever ended it: a refusal
/// says nothing of why, to the far side or to whoever reads this side's log.
fn closed() -> TransportError {
    TransportError::ConnectionFailed("the circuit closed".into())
}

/// The keys a door answers under, and who it admits.
pub struct Door {
    keys: Vec<StaticSecret>,
    admits: Arc<dyn Admits>,
}

impl Door {
    /// A door answering under the Montgomery form of each of `keys`, at least one and at most
    /// [`MAX_DOOR_KEYS`], admitting whom `admits` admits.
    pub fn new(keys: &[SigningKey], admits: Arc<dyn Admits>) -> Result<Self, TransportError> {
        if keys.is_empty() || keys.len() > MAX_DOOR_KEYS {
            return Err(TransportError::ConfigError(format!(
                "a door answers under one to {MAX_DOOR_KEYS} keys, not {}",
                keys.len()
            )));
        }
        Ok(Self {
            keys: keys
                .iter()
                .map(kotton_crypto::x25519::ed25519_priv_to_x25519)
                .collect(),
            admits,
        })
    }
}

/// What makes a recovery claim for one connection: answered by whoever holds the recovery
/// authority, which never hands it here. The door's side has [`Admits`]; this is the dialer's.
///
/// Called at most once per connection, with that connection's handshake: the claim it makes
/// answers that connection and no other ([`AwaitingAnswer::claim`]).
pub trait MakesClaim: Send + Sync {
    /// A claim for the connection `awaiting` is the handshake of; `None` where none is made.
    fn claim(&self, awaiting: &AwaitingAnswer) -> Option<RecoveryClaim>;
}

/// What a dialer offers a door that asks for its events: the key events it holds that the
/// door may not, or a recovery claim in their place. Empty for every ordinary dial, which is
/// then asked nothing.
#[derive(Clone, Default)]
pub struct CircuitOffer {
    /// The key events since the door's tip, oldest first: usually one, a recovery rotation.
    pub events: Vec<kotton_wire::kel::KelEvent>,
    /// What makes a recovery claim, for a device that holds nothing else.
    pub claim: Option<Arc<dyn MakesClaim>>,
}

impl std::fmt::Debug for CircuitOffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CircuitOffer")
            .field("events", &self.events.len())
            .field("claim", &self.claim.is_some())
            .finish()
    }
}

/// The places a reservation holds circuits in: [`MAX_OPENING`] before a first frame is whole,
/// and [`MAX_ADMITTING`] after it and before admission.
#[derive(Clone)]
pub struct Openings {
    opening: Arc<Semaphore>,
    admitting: Arc<Semaphore>,
}

impl Default for Openings {
    fn default() -> Self {
        Self {
            opening: Arc::new(Semaphore::new(MAX_OPENING)),
            admitting: Arc::new(Semaphore::new(MAX_ADMITTING)),
        }
    }
}

impl Openings {
    /// A place for one more circuit's opening, or `None` where [`MAX_OPENING`] are held.
    pub fn admit(&self) -> Option<Place> {
        let opening = Arc::clone(&self.opening).try_acquire_owned().ok()?;
        Some(Place {
            opening,
            admitting: Arc::clone(&self.admitting),
        })
    }
}

/// One circuit's place in a reservation's opening ([`Openings::admit`]). Its first frame
/// whole, it moves to an admitting place, if one is free.
pub struct Place {
    opening: OwnedSemaphorePermit,
    admitting: Arc<Semaphore>,
}

impl Place {
    /// Give up the opening place for an admitting one; `None` where [`MAX_ADMITTING`] are
    /// held, and the opening place is given up either way.
    fn advance(self) -> Option<OwnedSemaphorePermit> {
        drop(self.opening);
        self.admitting.try_acquire_owned().ok()
    }
}

/// A channel to a peer over a relay-bridged byte stream, the handshake done.
///
/// The stream and the channel are behind one mutex so `request` and `serve_one_request`
/// carry one message at a time.
pub struct RelayedConnection<S> {
    inner: Mutex<Carried<S>>,
    peer: Peer,
}

struct Carried<S> {
    stream: S,
    channel: Channel,
}

impl<S> RelayedConnection<S> {
    /// Who the peer is: on the dialer's side the key it dialled; on the door's the key it
    /// admitted, or the standing of the recovery claim it admitted on, which names no key.
    pub fn peer(&self) -> &Peer {
        &self.peer
    }

    /// The `did:key` of the peer's Ed25519 key, where the peer is a key; a claimant has none.
    pub fn peer_did(&self) -> Option<&str> {
        self.peer.did()
    }
}

fn did_of(key: &[u8; 32]) -> Result<String, TransportError> {
    DidKeyMethod::from_public_key_bytes(key)
        .map(|d| d.to_string())
        .map_err(|_| closed())
}

/// One frame's body, after its two-byte length; `None` where the stream ended before it.
async fn read_body<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Vec<u8>>, TransportError> {
    let mut len = [0u8; 2];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(io_err(e)),
    }
    let mut body = vec![0u8; usize::from(u16::from_be_bytes(len))];
    r.read_exact(&mut body).await.map_err(io_err)?;
    Ok(Some(body))
}

async fn send<W: AsyncWrite + Unpin>(w: &mut W, frame: &[u8]) -> Result<(), TransportError> {
    w.write_all(frame).await.map_err(io_err)?;
    w.flush().await.map_err(io_err)
}

/// The door's next handshake frame, to a dialer. Any end of the stream before the frame is
/// whole, an I/O error among them, is the circuit closing: the one reading of a refusal,
/// whether the dialer's leg ends in a close or a reset.
async fn from_door<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>, TransportError> {
    read_body(r).await.ok().flatten().ok_or_else(closed)
}

/// A dialer's handshake frame to the door; a stream that has ended is the circuit closing,
/// as [`from_door`] reads one.
async fn to_door<W: AsyncWrite + Unpin>(w: &mut W, frame: &[u8]) -> Result<(), TransportError> {
    send(w, frame).await.map_err(|_| closed())
}

/// The version byte and the first frame, read whole and nothing past them.
async fn read_opening_bytes<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut head = [0u8; 3];
    r.read_exact(&mut head).await?;
    let len = usize::from(u16::from_be_bytes([head[1], head[2]]));
    let mut opening = Vec::with_capacity(3 + len);
    opening.extend_from_slice(&head);
    opening.resize(3 + len, 0);
    r.read_exact(&mut opening[3..]).await?;
    Ok(opening)
}

impl<S> RelayedConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Dial the door whose key is `responder` over `stream` (the relay-bridged channel), as
    /// `own`, offering `offer` if the door asks for events. Admitted within [`ADMIT_WAIT`], or
    /// closed: a refusal, an expiry and any end of the stream during the handshake read as one.
    pub async fn connect(
        stream: S,
        own: &SigningKey,
        responder: &[u8; 32],
        offer: &CircuitOffer,
    ) -> Result<Self, TransportError> {
        tokio::time::timeout(ADMIT_WAIT, Self::dial_in(stream, own, responder, offer))
            .await
            .map_err(|_| closed())?
    }

    async fn dial_in(
        mut stream: S,
        own: &SigningKey,
        responder: &[u8; 32],
        offer: &CircuitOffer,
    ) -> Result<Self, TransportError> {
        let own_static = kotton_crypto::x25519::ed25519_priv_to_x25519(own);
        let responder = kotton_crypto::ed25519::VerifyingKey::from_bytes(responder)
            .map_err(|e| TransportError::ConfigError(format!("the door's key: {e}")))?;
        let responder_static = kotton_crypto::x25519::ed25519_pub_to_x25519(&responder);
        let (initiator, opening) =
            Initiator::open(&own_static, &responder_static, None, None).map_err(|_| closed())?;
        to_door(&mut stream, &opening).await?;
        let second = from_door(&mut stream).await?;
        let (awaiting, third) = initiator.read_second(&second).map_err(|_| closed())?;
        to_door(&mut stream, &third).await?;
        let claim = offer.claim.as_ref().and_then(|maker| maker.claim(&awaiting));
        let first = from_door(&mut stream).await?;
        let (mut channel, answer) = awaiting.read_first(&first).map_err(|_| closed())?;
        if answer == Answer::AskForEvents {
            let reply = match claim {
                Some(claim) => AskReply::Claim(claim),
                None => {
                    // Each event's JSON until step 1 of #496 gives events their binary form
                    // (#512); step 1 replaces this encoding.
                    let events: Vec<Vec<u8>> = offer
                        .events
                        .iter()
                        .map(serde_json::to_vec)
                        .collect::<Result<_, _>>()
                        .map_err(|e| TransportError::ConfigError(format!("an offered event: {e}")))?;
                    AskReply::latest_of(&events)
                }
            };
            let body = reply.encode().map_err(|_| closed())?;
            to_door(&mut stream, &channel.seal(&body).map_err(|_| closed())?).await?;
            let admitted = from_door(&mut stream).await?;
            channel.read_admitted(&admitted).map_err(|_| closed())?;
        }
        Ok(Self {
            inner: Mutex::new(Carried { stream, channel }),
            peer: Peer::Key(DidKeyMethod::from_public_key(&responder).to_string()),
        })
    }

    /// Answer a circuit on `stream` at `door`. `place` is the place [`Openings`] gave this
    /// circuit, held until its first frame is whole or the wait runs out; then an admitting
    /// place is held until it is admitted or refused. The whole has [`ADMIT_WAIT`]. Every
    /// refusal, and every expiry, is the stream dropped, having written nothing past what the
    /// handshake writes to anyone who holds the door's key, and reads the same.
    pub async fn accept(stream: S, door: &Door, place: Place) -> Result<Self, TransportError> {
        tokio::time::timeout(ADMIT_WAIT, Self::admit(stream, door, place))
            .await
            .map_err(|_| closed())?
    }

    async fn admit(mut stream: S, door: &Door, place: Place) -> Result<Self, TransportError> {
        let bytes = tokio::time::timeout(FIRST_FRAME_WAIT, read_opening_bytes(&mut stream))
            .await
            .map_err(|_| closed())?
            .map_err(|_| closed())?;
        // Held until this returns: admitted, refused or expired.
        let _admitting = place.advance().ok_or_else(closed)?;
        let Opening::Complete { version, first, .. } = read_opening(&bytes) else {
            return Err(closed());
        };
        let (responder, second) =
            Responder::answer_opening(&door.keys, version, first).map_err(|_| closed())?;
        send(&mut stream, &second).await?;
        let third = read_body(&mut stream).await?.ok_or_else(closed)?;
        let admitting = responder.read_third(&third).map_err(|_| closed())?;
        let initiator = admitting.initiator().to_bytes();

        let (peer, channel) = match door.admits.by_key(&initiator) {
            Some(key) => {
                let (first, channel) = admitting
                    .answer(Answer::Admitted { latest: None })
                    .map_err(|_| closed())?;
                send(&mut stream, &first).await?;
                (Peer::Key(did_of(&key)?), channel.map_err(|_| closed())?)
            }
            None => {
                let (ask, asked) = admitting.ask().map_err(|_| closed())?;
                send(&mut stream, &ask).await?;
                let mut asked = asked.map_err(|_| closed())?;
                let body = read_body(&mut stream).await?.ok_or_else(closed)?;
                let peer = match asked.read_reply(&body).map_err(|_| closed())? {
                    AskReply::Events(events) => door
                        .admits
                        .by_events(&initiator, &events)
                        .map(|key| did_of(&key).map(Peer::Key))
                        .transpose()?,
                    AskReply::Claim(claim) => {
                        // The tag first: one who does not hold the key it names learns nothing
                        // from how long the door took to look it up.
                        let tagged = kotton_crypto::ed25519::VerifyingKey::from_bytes(claim.key())
                            .ok()
                            .map(|authority| kotton_crypto::x25519::ed25519_pub_to_x25519(&authority))
                            .and_then(|authority| asked.expected_claim_tag(&authority, claim.key()))
                            .is_some_and(|expected| claim.tag_matches(&expected));
                        if tagged {
                            door.admits.by_claim(claim.key()).map(|aid| Peer::Claim { aid })
                        } else {
                            None
                        }
                    }
                }
                .ok_or_else(closed)?;
                let (admitted, channel) = asked.admit(None).map_err(|_| closed())?;
                send(&mut stream, &admitted).await?;
                (peer, channel)
            }
        };
        Ok(Self {
            inner: Mutex::new(Carried { stream, channel }),
            peer,
        })
    }

    /// Send one request and read its answer (the dialer's side).
    pub async fn request(&self, req: &[u8]) -> Result<Vec<u8>, TransportError> {
        let mut carried = self.inner.lock().await;
        carried.send_message(req).await?;
        carried
            .read_message()
            .await?
            .ok_or_else(|| TransportError::ConnectionFailed("peer closed mid-response".into()))
    }

    /// Read one request, invoke `handler`, and send its answer. Returns `Ok(false)` when the
    /// peer closed the channel cleanly.
    pub async fn serve_one_request<F, Fut>(&self, handler: F) -> Result<bool, TransportError>
    where
        F: FnOnce(Vec<u8>) -> Fut,
        Fut: std::future::Future<Output = Vec<u8>>,
    {
        let mut carried = self.inner.lock().await;
        let Some(req) = carried.read_message().await? else {
            return Ok(false);
        };
        let resp = handler(req).await;
        carried.send_message(&resp).await?;
        Ok(true)
    }
}

impl<S> Carried<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    async fn send_message(&mut self, message: &[u8]) -> Result<(), TransportError> {
        let plaintexts = split_message(message).map_err(|_| {
            TransportError::ConfigError(format!("message too large: {} bytes", message.len()))
        })?;
        for plaintext in plaintexts {
            let frame = self.channel.seal(&plaintext).map_err(|_| closed())?;
            self.stream.write_all(&frame).await.map_err(io_err)?;
        }
        self.stream.flush().await.map_err(io_err)
    }

    /// One whole message, or `None` where the peer closed before it began.
    async fn read_message(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        let mut reader = MessageReader::new();
        let mut begun = false;
        loop {
            let Some(body) = read_body(&mut self.stream).await? else {
                return if begun {
                    Err(TransportError::ConnectionFailed("peer closed mid-message".into()))
                } else {
                    Ok(None)
                };
            };
            begun = true;
            let plaintext = self.channel.open(&body).map_err(|_| closed())?;
            if let Some(message) = reader.push(&plaintext).map_err(|_| closed())? {
                return Ok(Some(message));
            }
        }
    }
}

fn io_err(e: std::io::Error) -> TransportError {
    TransportError::ConnectionFailed(e.to_string())
}

// ---------------------------------------------------------------------------
// WebSocket ↔ byte-stream adapter
// ---------------------------------------------------------------------------

/// Presents a binary WebSocket as an `AsyncRead + AsyncWrite` byte stream, so the
/// handshake and its channel run over the relay-bridged WebSocket.
///
/// Each write is sent as one binary WebSocket frame; reads drain inbound binary
/// frames in order (buffering any bytes a single `poll_read` cannot take). The
/// handshake frames its own bytes on top, so frame boundaries do not matter.
/// Non-binary control frames (ping/pong/text) are ignored; a close frame or stream
/// end is surfaced as EOF.
pub struct WsByteStream<S> {
    inner: S,
    /// Bytes from the last inbound frame not yet handed to a `poll_read`.
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl<S> WsByteStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            read_buf: Vec::new(),
            read_pos: 0,
        }
    }
}

impl<S> AsyncRead for WsByteStream<S>
where
    S: Stream<Item = Result<Message, WsError>> + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            // Drain buffered bytes from a previous frame first.
            if this.read_pos < this.read_buf.len() {
                let avail = &this.read_buf[this.read_pos..];
                let n = avail.len().min(buf.remaining());
                buf.put_slice(&avail[..n]);
                this.read_pos += n;
                return Poll::Ready(Ok(()));
            }
            // Otherwise pull the next inbound frame.
            match Pin::new(&mut this.inner).poll_next(cx) {
                Poll::Ready(Some(Ok(Message::Binary(data)))) => {
                    if data.is_empty() {
                        continue; // empty frame carries no bytes
                    }
                    this.read_buf = data;
                    this.read_pos = 0;
                    // loop to drain into buf
                }
                Poll::Ready(Some(Ok(Message::Close(_)))) | Poll::Ready(None) => {
                    return Poll::Ready(Ok(())); // EOF: zero bytes read
                }
                Poll::Ready(Some(Ok(_))) => continue, // ignore ping/pong/text
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(std::io::Error::other(e)))
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> AsyncWrite for WsByteStream<S>
where
    S: Sink<Message, Error = WsError> + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_ready(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(std::io::Error::other(e))),
            Poll::Pending => return Poll::Pending,
        }
        match Pin::new(&mut this.inner).start_send(Message::Binary(data.to_vec())) {
            Ok(()) => Poll::Ready(Ok(data.len())),
            Err(e) => Poll::Ready(Err(std::io::Error::other(e))),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match Pin::new(&mut self.get_mut().inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match Pin::new(&mut self.get_mut().inner).poll_close(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}

// ---------------------------------------------------------------------------
// Relay client (node ↔ relay circuit endpoints)
// ---------------------------------------------------------------------------

/// The relay-bridged WebSocket type returned by `connect_async`.
type RelayWs = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// The relay-bridged byte stream itself, before anything runs over it.
pub type RelayedByteStream = WsByteStream<RelayWs>;

/// Outbound relayed connection (dialer side): the handshake's channel over the bridge.
pub type RelayedDial = RelayedConnection<RelayedByteStream>;
/// Inbound relayed connection (reserved side): the handshake's channel over the bridge.
pub type RelayedInbound = RelayedConnection<RelayedByteStream>;

/// `ws://` / `wss://` base for a relay's HTTP URL.
fn ws_base_of(relay_url: &str) -> String {
    relay_url
        .replacen("https://", "wss://", 1)
        .replacen("http://", "ws://", 1)
        .trim_end_matches('/')
        .to_string()
}

/// Signed `Authorization` header (same scheme as rendezvous lookups):
/// `Ed25519 fingerprint=<fp> ts=<ts> sig=<sig over "fp\nts"> [admit=<tag>]` —
/// the tag under the relay's admission key when the device holds one, which a
/// relay whose rule is narrowed reads at the upgrade.
fn auth_header_for(
    fingerprint: &str,
    signing_key: &SigningKey,
    admission: Option<&AdmissionKey>,
) -> Result<String, TransportError> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|e| TransportError::ConfigError(e.to_string()))?;
    let payload = format!("{fingerprint}\n{ts}");
    let sig = URL_SAFE_NO_PAD.encode(signing_key.sign(payload.as_bytes()).to_bytes());
    let mut header = format!("Ed25519 fingerprint={fingerprint} ts={ts} sig={sig}");
    if let Some(k) = admission {
        header.push_str(&format!(" admit={}", k.tag(fingerprint, ts)));
    }
    Ok(header)
}

/// A reservation held under a one-time handle, for a ceremony rather than a
/// peer: the bridged bytes come back **raw**, with no handshake, because the party
/// on the other end is a stranger whose key the ceremony exists to learn
/// (RFC-0022). What authenticates the stream is what runs over it — a PAKE
/// keyed by the spoken code — and the handle itself is derived from that code,
/// so the relay learns a label that names nobody and is never used twice.
pub struct RendezvousReservation {
    ws_base: String,
    control: RelayWs,
}

/// Hold a reservation under `fingerprint` (a handle `signing_key` proves) at
/// `relay_url`. Exists from the moment this returns.
pub async fn rendezvous_reserve(
    relay_url: &str,
    fingerprint: &str,
    signing_key: &SigningKey,
    admission: Option<&AdmissionKey>,
) -> Result<RendezvousReservation, TransportError> {
    let ws_base = ws_base_of(relay_url);
    let url = format!("{ws_base}/relay/reserve");
    let control =
        connect_ws(&url, Some(&auth_header_for(fingerprint, signing_key, admission)?)).await?;
    Ok(RendezvousReservation { ws_base, control })
}

impl RendezvousReservation {
    /// Wait for the first circuit to this handle, dial back its data leg, and
    /// hand over the raw bridged stream. The reservation is consumed: a
    /// ceremony handle admits exactly one party.
    pub async fn accept_one(mut self) -> Result<RelayedByteStream, TransportError> {
        while let Some(msg) = self.control.next().await {
            let circuit_id = match msg {
                Ok(Message::Text(id)) => id,
                Ok(Message::Close(_)) => break,
                Err(e) => return Err(TransportError::ConnectionFailed(e.to_string())),
                Ok(_) => continue,
            };
            let accept_url = format!("{}/relay/accept?circuit={}", self.ws_base, circuit_id);
            let data_ws = connect_ws(&accept_url, None).await?;
            return Ok(WsByteStream::new(data_ws));
        }
        Err(TransportError::ConnectionFailed(
            "relay closed the reservation before anyone arrived".into(),
        ))
    }
}

/// Open a raw circuit to the handle `target` at `relay_url`, authenticating the
/// dial as `fingerprint` (a one-time key — the dialer is a stranger too).
pub async fn rendezvous_dial(
    relay_url: &str,
    fingerprint: &str,
    signing_key: &SigningKey,
    target: &str,
    admission: Option<&AdmissionKey>,
) -> Result<RelayedByteStream, TransportError> {
    let url = format!("{}/relay/open?to={}", ws_base_of(relay_url), target);
    let ws = connect_ws(&url, Some(&auth_header_for(fingerprint, signing_key, admission)?)).await?;
    Ok(WsByteStream::new(ws))
}

/// Client for the relay's circuit endpoints (`/relay/reserve`, `/relay/open`,
/// `/relay/accept`) — the node's side of the relayed fallback (relay side in
/// `infra/relay`), under one label: the handle it reserves or dials as.
///
/// The label is how the relay routes and nothing more. Who answers inside a circuit is the
/// handshake's: the key a dial names ([`Self::dial`]) and the [`Door`] a reservation
/// answers at ([`Reservation::serve`]).
pub struct RelayClient {
    /// WebSocket base URL (`ws://` / `wss://`) derived from the relay URL.
    ws_base: String,
    fingerprint: String,
    /// Proves the label to the relay.
    signing_key: SigningKey,
    /// The relay's admission key this device holds, if any
    /// ([`Self::with_admission`]).
    admission: Option<AdmissionKey>,
}

impl RelayClient {
    pub fn new(relay_url: &str, fingerprint: String, signing_key: SigningKey) -> Self {
        Self {
            ws_base: ws_base_of(relay_url),
            fingerprint,
            signing_key,
            admission: None,
        }
    }

    /// Present a tag under `key` at every reservation and circuit this client
    /// makes.
    pub fn with_admission(mut self, key: Option<AdmissionKey>) -> Self {
        self.admission = key;
        self
    }

    /// Signed `Authorization` header (same scheme as rendezvous lookups), with
    /// the admission tag when this client holds a key.
    fn auth_header(&self) -> Result<String, TransportError> {
        auth_header_for(&self.fingerprint, &self.signing_key, self.admission.as_ref())
    }

    /// Dial through the relay: open a circuit to `target_did` and run the handshake over it
    /// as `own`, to the door whose key is `responder`, offering `offer` if it asks.
    pub async fn dial(
        &self,
        target_did: &str,
        own: &SigningKey,
        responder: &[u8; 32],
        offer: &CircuitOffer,
    ) -> Result<RelayedDial, TransportError> {
        let url = format!("{}/relay/open?to={}", self.ws_base, target_did);
        let ws = connect_ws(&url, Some(&self.auth_header()?)).await?;
        RelayedConnection::connect(WsByteStream::new(ws), own, responder, offer).await
    }

    /// Open a reservation on the relay. It exists from the moment this returns —
    /// the relay routes circuits for this fingerprint to it until
    /// [`Reservation::serve`] ends — which is what lets a holder say *held* as a
    /// fact rather than *attempted* (RFC-0083 R6's readout reads this moment).
    pub async fn reserve(&self) -> Result<Reservation<'_>, TransportError> {
        let url = format!("{}/relay/reserve", self.ws_base);
        let control = connect_ws(&url, Some(&self.auth_header()?)).await?;
        Ok(Reservation { client: self, control })
    }

    /// Hold a reservation on the relay and answer inbound circuits at `door`, sending each
    /// admitted connection to `out`. Runs until the reservation drops or `out` is closed.
    /// [`reserve`](Self::reserve) then [`Reservation::serve`].
    pub async fn run_reservation(
        &self,
        door: Door,
        out: mpsc::Sender<RelayedInbound>,
    ) -> Result<(), TransportError> {
        self.reserve().await?.serve(Arc::new(door), out).await
    }
}

/// A reservation held on the relay: the open control socket circuits arrive on.
pub struct Reservation<'a> {
    client: &'a RelayClient,
    control: RelayWs,
}

impl Reservation<'_> {
    /// Answer inbound circuits at `door` for as long as the reservation holds, sending each
    /// admitted connection to `out`. Returns when the relay closes the control socket or
    /// `out` is closed.
    ///
    /// Each circuit is answered on its own task, so one that sends nothing holds no other
    /// up. Its places and waits are the module's *Every stage at a door has a bound*: a
    /// circuit past [`MAX_OPENING`] is not dialled back. A refused or expired circuit is
    /// dropped without a line: what it sent is nobody's record.
    pub async fn serve(
        mut self,
        door: Arc<Door>,
        out: mpsc::Sender<RelayedInbound>,
    ) -> Result<(), TransportError> {
        let ws_base = self.client.ws_base.clone();
        let openings = Openings::default();
        while let Some(msg) = self.control.next().await {
            let circuit_id = match msg {
                Ok(Message::Text(id)) => id,
                Ok(Message::Close(_)) => break,
                Err(e) => return Err(TransportError::ConnectionFailed(e.to_string())),
                Ok(_) => continue, // ping/pong/binary on the control channel: ignore
            };
            if out.is_closed() {
                break; // consumer gone
            }
            let Some(place) = openings.admit() else {
                continue;
            };
            // Dial back the data leg; the circuit id is the capability (no auth).
            let accept_url = format!("{ws_base}/relay/accept?circuit={circuit_id}");
            tokio::spawn(answer_circuit(accept_url, Arc::clone(&door), place, out.clone()));
        }
        Ok(())
    }
}

/// Dial back one circuit's data leg at `accept_url`, within [`DIAL_BACK_WAIT`], holding
/// `place` while it does; answer it at `door`, and send it to `out` if admitted.
async fn answer_circuit(
    accept_url: String,
    door: Arc<Door>,
    place: Place,
    out: mpsc::Sender<RelayedInbound>,
) {
    let data_ws = match tokio::time::timeout(DIAL_BACK_WAIT, connect_ws(&accept_url, None)).await {
        Ok(Ok(ws)) => ws,
        Ok(Err(e)) => {
            warn!(error = %e, "relay accept dial-back failed");
            return;
        }
        // Expired: let go of the place, as every expiry does, without a line.
        Err(_) => return,
    };
    if let Ok(conn) = RelayedConnection::accept(WsByteStream::new(data_ws), &door, place).await {
        let _ = out.send(conn).await;
    }
}

/// Open a WebSocket to `url`, optionally with an `Authorization` header.
///
/// A relay that answers the upgrade `403` has refused it by its rule — the one
/// refusal it gives, whatever the caller lacked (`not admitted by this relay's
/// rule`) — and that is returned as [`TransportError::AuthenticationFailed`],
/// apart from every failure to reach the relay at all, which stays
/// [`TransportError::ConnectionFailed`]. A caller that says *why* to a person
/// tells the two apart by the variant
/// (`TASK-a-first-contact-ceremony-meets-at-a-relay-whose-rule-refuses-a-stranger`).
async fn connect_ws(url: &str, auth: Option<&str>) -> Result<RelayWs, TransportError> {
    let mut req = url
        .into_client_request()
        .map_err(|e| TransportError::ConfigError(e.to_string()))?;
    if let Some(a) = auth {
        let value = a
            .parse()
            .map_err(|_| TransportError::ConfigError("invalid Authorization header".into()))?;
        req.headers_mut().insert("Authorization", value);
    }
    let (ws, _) = connect_async(req).await.map_err(|e| match e {
        WsError::Http(ref answer) if answer.status() == 403 => {
            TransportError::AuthenticationFailed(format!("the relay refused: {e}"))
        }
        e => TransportError::ConnectionFailed(e.to_string()),
    })?;
    Ok(ws)
}

#[cfg(test)]
mod tests {
    //! In-process, over `tokio::io::duplex` and a real WebSocket pair (no relay): a door
    //! admits the key it holds and exchanges requests, closes on a key it does not, admits a
    //! recovery claim by its tag, and holds its bounds.

    use super::*;
    use crate::provider::transport::admits::HeldKeys;
    use crate::provider::transport::quic::tls::{Admission, Admitted};
    use std::collections::HashSet;
    use std::sync::RwLock;
    use kotton_crypto::ed25519::VerifyingKey;

    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }

    fn pub_of(k: &SigningKey) -> [u8; 32] {
        k.verifying_key().to_bytes()
    }

    fn door_admitting(own: &SigningKey, admitted: &[[u8; 32]], admission: Admission) -> Door {
        let held = HeldKeys::new(
            Arc::new(RwLock::new(
                admitted.iter().map(|k| VerifyingKey::from_bytes(k).unwrap()).collect::<HashSet<_>>(),
            )),
            admission,
        );
        Door::new(std::slice::from_ref(own), Arc::new(held)).unwrap()
    }

    fn place() -> Place {
        Openings::default().admit().unwrap()
    }

    /// The device side's claim-maker, as `recover` answers it: the authority is held here and
    /// makes one claim for the connection it is asked about.
    struct Authority(SigningKey);

    impl MakesClaim for Authority {
        fn claim(&self, awaiting: &AwaitingAnswer) -> Option<RecoveryClaim> {
            awaiting.claim(
                &kotton_crypto::x25519::ed25519_priv_to_x25519(&self.0),
                self.0.verifying_key().to_bytes(),
            )
        }
    }

    fn claiming(authority: SigningKey) -> CircuitOffer {
        CircuitOffer {
            events: Vec::new(),
            claim: Some(Arc::new(Authority(authority))),
        }
    }

    /// A valid opening to `door_key` from `dialer_key`, sent on `io`; then the door's second
    /// message is read and nothing more is sent.
    async fn open_and_stall(io: &mut tokio::io::DuplexStream, door_key: &SigningKey, dialer_key: &SigningKey) {
        let (_, opening) = Initiator::open(
            &kotton_crypto::x25519::ed25519_priv_to_x25519(dialer_key),
            &kotton_crypto::x25519::ed25519_pub_to_x25519(&kotton_crypto::ed25519::verifying_key(door_key)),
            None,
            None,
        )
        .unwrap();
        io.write_all(&opening).await.unwrap();
        read_body(io).await.unwrap().expect("the door's second message");
    }

    async fn echo<S: AsyncRead + AsyncWrite + Unpin + Send>(conn: &RelayedConnection<S>) -> bool {
        conn.serve_one_request(|req| async move {
            let mut resp = b"echo:".to_vec();
            resp.extend_from_slice(&req);
            resp
        })
        .await
        .expect("serve")
    }

    #[tokio::test]
    async fn an_admitted_key_completes_the_handshake_and_exchanges_requests() {
        let (door_key, dialer_key) = (key(1), key(2));
        let (s_io, c_io) = tokio::io::duplex(64 * 1024);
        let door = door_admitting(&door_key, &[pub_of(&dialer_key)], Admission::default());
        let dialer_did = did_of(&pub_of(&dialer_key)).unwrap();
        let server = tokio::spawn(async move {
            let conn = RelayedConnection::accept(s_io, &door, place())
                .await
                .expect("the door admits the key it holds");
            assert_eq!(conn.peer(), &Peer::Key(dialer_did));
            assert!(echo(&conn).await);
            // A request longer than one frame crosses as one message.
            assert!(echo(&conn).await);
        });

        let conn = RelayedConnection::connect(
            c_io,
            &dialer_key,
            &pub_of(&door_key),
            &CircuitOffer::default(),
        )
        .await
        .expect("the dial completes");
        assert_eq!(conn.peer_did(), Some(did_of(&pub_of(&door_key)).unwrap().as_str()));
        assert_eq!(conn.request(b"ping").await.unwrap(), b"echo:ping");
        let long = vec![0x5a; 200_000];
        let resp = conn.request(&long).await.unwrap();
        assert_eq!(&resp[..5], b"echo:");
        assert_eq!(&resp[5..], &long[..]);
        server.await.unwrap();
    }

    /// A key the door does not hold is asked for its events, offers none, and is closed on:
    /// no request reaches the handler.
    #[tokio::test]
    async fn a_key_the_door_does_not_admit_is_asked_and_closed_on() {
        let (door_key, stranger) = (key(3), key(4));
        let (s_io, c_io) = tokio::io::duplex(64 * 1024);
        let door = door_admitting(&door_key, &[pub_of(&key(5))], Admission::default());
        let server = tokio::spawn(async move { RelayedConnection::accept(s_io, &door, place()).await });
        let dialled =
            RelayedConnection::connect(c_io, &stranger, &pub_of(&door_key), &CircuitOffer::default())
                .await;
        assert!(dialled.is_err(), "the stranger's dial ends");
        assert!(server.await.unwrap().is_err(), "and the door admitted nobody");
    }

    /// A dial to a door under the wrong key reads its own first frame back as nothing: the
    /// door reads one frame and writes no byte.
    #[tokio::test]
    async fn a_door_dialled_under_another_key_writes_nothing() {
        let (door_key, dialer_key) = (key(6), key(7));
        let (s_io, mut c_io) = tokio::io::duplex(64 * 1024);
        let door = door_admitting(&door_key, &[pub_of(&dialer_key)], Admission::default());
        let server = tokio::spawn(async move { RelayedConnection::accept(s_io, &door, place()).await });
        let (_, opening) = Initiator::open(
            &kotton_crypto::x25519::ed25519_priv_to_x25519(&dialer_key),
            &kotton_crypto::x25519::ed25519_pub_to_x25519(&kotton_crypto::ed25519::verifying_key(&key(8))),
            None,
            None,
        )
        .unwrap();
        c_io.write_all(&opening).await.unwrap();
        assert!(server.await.unwrap().is_err());
        let mut written = Vec::new();
        c_io.read_to_end(&mut written).await.unwrap();
        assert!(written.is_empty(), "the door wrote {} bytes", written.len());
    }

    /// A device that holds only a recovery authority is admitted by its claim, whose tag
    /// answers this connection; the claim's standing is the connection's, and it is named by
    /// no key. A claim by an authority the door holds no identity for is closed on as any
    /// refusal is.
    ///
    /// The claimant is `key(2)`, whose key's sign bit is set: the key a name derived from its
    /// Montgomery form would give is not its own (#511). It is given none, and nothing is
    /// written to the admission's shared table.
    #[tokio::test]
    async fn a_recovery_claim_is_admitted_by_its_tag_and_the_authority_held() {
        let (door_key, claimant, authority) = (key(9), key(2), key(11));
        assert_ne!(pub_of(&claimant)[31] & 0x80, 0, "the claimant's key has its sign bit set");
        let admission = Admission::default();
        let held = kotton_crypto::kel_verify::build_inception(&key(10), &[pub_of(&authority)]);
        admission.learn_chain(std::slice::from_ref(&held));

        for (offered, admitted) in [(authority.clone(), true), (key(12), false)] {
            let (s_io, c_io) = tokio::io::duplex(64 * 1024);
            let door = door_admitting(&door_key, &[], admission.clone());
            let server =
                tokio::spawn(async move { RelayedConnection::accept(s_io, &door, place()).await });
            let dialled =
                RelayedConnection::connect(c_io, &claimant, &pub_of(&door_key), &claiming(offered))
                    .await;
            let accepted = server.await.unwrap();
            assert_eq!(dialled.is_ok(), admitted);
            assert_eq!(accepted.is_ok(), admitted);
            if let Ok(conn) = accepted {
                assert_eq!(
                    conn.peer(),
                    &Peer::Claim {
                        aid: held.aid.to_string()
                    }
                );
                assert_eq!(conn.peer_did(), None, "a claimant has no name");
            }
        }
        assert!(
            admission.admitted.read().unwrap().is_empty(),
            "a circuit's claim writes nothing to the shared table"
        );
    }

    /// For each kind of event, a hosted chain in which that one event carries a set that does
    /// not make its commitment admits no claim by the key it carries beyond that commitment:
    /// the circuit is closed on as any refusal is, and nothing is written to the admission's
    /// shared table. A claim by the phrase the chain commits is admitted.
    #[tokio::test]
    async fn a_claim_by_a_key_no_event_commits_is_closed_on_as_any_refusal_is() {
        use kotton_crypto::kel_verify::committed_set;
        let seed = [42u8; 32];
        let honest = crate::provider::transport::quic::tls::a_hosted_chain_of_every_kind(&seed);
        let (door_key, claimant, outside) = (key(9), key(2), key(33));
        let phrase = SigningKey::from_bytes(&kotton_crypto::kdf::derive_kel_recovery_key(&seed, 0));
        for at in 0..honest.len() {
            let mut chain = honest.clone();
            let mut carried = committed_set(&chain[at]).unwrap_or_default().to_vec();
            carried.push(pub_of(&outside));
            chain[at].recovery_set = carried;
            let kind = chain[at].kind;
            let admission = Admission::default();
            admission.learn_chain(&chain);
            for (offered, admitted) in [(outside.clone(), false), (phrase.clone(), true)] {
                let (s_io, c_io) = tokio::io::duplex(64 * 1024);
                let door = door_admitting(&door_key, &[], admission.clone());
                let server =
                    tokio::spawn(async move { RelayedConnection::accept(s_io, &door, place()).await });
                let dialled =
                    RelayedConnection::connect(c_io, &claimant, &pub_of(&door_key), &claiming(offered))
                        .await;
                let accepted = server.await.unwrap();
                assert_eq!(dialled.is_ok(), admitted, "{kind:?}");
                assert_eq!(accepted.is_ok(), admitted, "{kind:?}");
            }
            assert!(admission.admitted.read().unwrap().is_empty(), "{kind:?}: nothing is written");
        }
    }

    /// One dial: who dials, under which door key, offering what, and whether every admitting
    /// place at the door is already held.
    struct Dial {
        dialer: SigningKey,
        towards: SigningKey,
        offer: CircuitOffer,
        bound_held: bool,
    }

    fn dial(dialer: &SigningKey, towards: &SigningKey, offer: CircuitOffer) -> Dial {
        Dial {
            dialer: dialer.clone(),
            towards: towards.clone(),
            offer,
            bound_held: false,
        }
    }

    /// What each side reads of `d` at a door under `door_key` admitting `admitted` by key and
    /// whom `admission` admits: the dialer's reading first, then the door's.
    async fn readings(
        door_key: &SigningKey,
        admitted: &[[u8; 32]],
        admission: &Admission,
        d: &Dial,
    ) -> (Result<(), String>, Result<(), String>) {
        let door = door_admitting(door_key, admitted, admission.clone());
        let openings = Openings::default();
        let place = openings.admit().unwrap();
        let _bound = d.bound_held.then(|| {
            let all = u32::try_from(MAX_ADMITTING).unwrap();
            openings.admitting.clone().try_acquire_many_owned(all).unwrap()
        });
        let (s_io, c_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            RelayedConnection::accept(s_io, &door, place)
                .await
                .map(drop)
                .map_err(|e| format!("{e:?}"))
        });
        let dialled = RelayedConnection::connect(c_io, &d.dialer, &pub_of(&d.towards), &d.offer)
            .await
            .map(drop)
            .map_err(|e| format!("{e:?}"));
        (dialled, server.await.unwrap())
    }

    /// A claim-maker that names one authority's key and holds another: its tag answers no
    /// claim by the key it names.
    struct Misnamed {
        holds: SigningKey,
        names: [u8; 32],
    }

    impl MakesClaim for Misnamed {
        fn claim(&self, awaiting: &AwaitingAnswer) -> Option<RecoveryClaim> {
            awaiting.claim(&kotton_crypto::x25519::ed25519_priv_to_x25519(&self.holds), self.names)
        }
    }

    /// Every refusal a dialer can meet at a relayed door reads the same to it, whatever the
    /// reason (kotton-protocol's *One handshake admits a device, by the identity's log*: a
    /// refusal is the circuit closing, and no frame says why); and the door's side reads each
    /// the same, so its log says nothing of why either. Each refused dial is set beside one
    /// the same door admits, so each refusal is met where it is made and not at the setup.
    ///
    /// The dials through `connect` cover every refusal `connect` can produce: under another
    /// key, past the admitting bound, a key not held offering nothing, events for an identity
    /// the door does not host, events naming another key, events naming the dialer's key that
    /// the replay from the hosted tip does not admit, a claim by an authority no hosted
    /// identity holds, a claim whose tag the authority it names did not make, a claim whose
    /// named key is not an Ed25519 point, and a claim by a key the hosted chain carries and
    /// does not commit. One refusal `connect` cannot produce is driven by hand: an ask answered
    /// with a reply that does not decode, which the door reads as it reads the others and
    /// answers by writing nothing. The other refusals only raw bytes reach are not driven: a
    /// wrong version byte or an incomplete opening, a third message that does not decode, and
    /// offered events that are not JSON.
    #[tokio::test]
    async fn every_refusal_reads_the_same() {
        use kotton_crypto::kdf::derive_kel_recovery_key;
        use kotton_crypto::kel_verify::{build_inception, build_mnemonic_rotation, committed_set, kel_recovery_pubkey};
        let door_key = key(40);
        let (held, stranger, claimant) = (key(41), key(42), key(2));

        // A tip the door hosts, and the rotation that names a recovered device's key.
        let seed = [42u8; 32];
        let rung = |i| kel_recovery_pubkey(&derive_kel_recovery_key(&seed, i));
        let tip = build_inception(&key(30), &[rung(0)]);
        let recovered = key(31);
        let rotation = build_mnemonic_rotation(&tip, &seed, 0, &recovered, 0, &[rung(0)]);
        let hosting_tip = Admission::default();
        hosting_tip.tips.write().unwrap().insert(tip.aid.to_string(), tip.clone());
        let offering = |events: Vec<kotton_wire::kel::KelEvent>| CircuitOffer { events, claim: None };
        // A rotation of the hosted tip naming `stranger`, by a phrase the tip does not commit.
        let other_seed = [77u8; 32];
        let unadmitted = build_mnemonic_rotation(
            &tip,
            &other_seed,
            0,
            &stranger,
            0,
            &[kel_recovery_pubkey(&derive_kel_recovery_key(&other_seed, 0))],
        );

        // A hosted identity whose inception commits `authority`.
        let authority = key(11);
        let hosting_authority = Admission::default();
        hosting_authority.learn_chain(&[build_inception(&key(10), &[pub_of(&authority)])]);
        // Thirty-two bytes that are not an Ed25519 point.
        let not_a_point = (0u8..=u8::MAX)
            .map(|n| [n; 32])
            .find(|b| VerifyingKey::from_bytes(b).is_err())
            .unwrap();

        // A hosted chain whose inception carries `outside` beyond what it commits.
        let mut chain = crate::provider::transport::quic::tls::a_hosted_chain_of_every_kind(&seed);
        let outside = key(33);
        let mut carried = committed_set(&chain[0]).unwrap_or_default().to_vec();
        carried.push(pub_of(&outside));
        chain[0].recovery_set = carried;
        let hosting_uncommitted = Admission::default();
        hosting_uncommitted.learn_chain(&chain);
        let phrase = SigningKey::from_bytes(&derive_kel_recovery_key(&seed, 0));

        let by_key = [pub_of(&held)];
        // What is refused; whom the door admits by key, and whom by its admission; the dial it
        // refuses, and the dial it admits.
        type Case<'a> = (&'a str, &'a [[u8; 32]], &'a Admission, Dial, Dial);
        let cases: [Case; 10] = [
            (
                "a door dialled under another key",
                &by_key,
                &Admission::default(),
                dial(&held, &key(44), CircuitOffer::default()),
                dial(&held, &door_key, CircuitOffer::default()),
            ),
            (
                "a circuit past the bound of circuits being admitted",
                &by_key,
                &Admission::default(),
                Dial {
                    bound_held: true,
                    ..dial(&held, &door_key, CircuitOffer::default())
                },
                dial(&held, &door_key, CircuitOffer::default()),
            ),
            (
                "a key the door does not hold, offering nothing",
                &by_key,
                &Admission::default(),
                dial(&stranger, &door_key, CircuitOffer::default()),
                dial(&held, &door_key, CircuitOffer::default()),
            ),
            (
                "a key the door does not hold, offering events for an identity it does not host",
                &by_key,
                &Admission::default(),
                dial(&recovered, &door_key, offering(vec![rotation.clone()])),
                dial(&held, &door_key, CircuitOffer::default()),
            ),
            (
                "a key the door does not hold, offering events that name another key",
                &[],
                &hosting_tip,
                dial(&stranger, &door_key, offering(vec![rotation.clone()])),
                dial(&recovered, &door_key, offering(vec![rotation.clone()])),
            ),
            (
                "a key the door does not hold, offering events naming it that the hosted tip does not admit",
                &[],
                &hosting_tip,
                dial(&stranger, &door_key, offering(vec![unadmitted])),
                dial(&recovered, &door_key, offering(vec![rotation.clone()])),
            ),
            (
                "a claim by an authority no hosted identity holds",
                &[],
                &hosting_authority,
                dial(&claimant, &door_key, claiming(key(12))),
                dial(&claimant, &door_key, claiming(authority.clone())),
            ),
            (
                "a claim whose tag was not made by the authority it names",
                &[],
                &hosting_authority,
                dial(
                    &claimant,
                    &door_key,
                    CircuitOffer {
                        events: Vec::new(),
                        claim: Some(Arc::new(Misnamed {
                            holds: key(12),
                            names: pub_of(&authority),
                        })),
                    },
                ),
                dial(&claimant, &door_key, claiming(authority.clone())),
            ),
            (
                "a claim whose named key is not an Ed25519 point",
                &[],
                &hosting_authority,
                dial(
                    &claimant,
                    &door_key,
                    CircuitOffer {
                        events: Vec::new(),
                        claim: Some(Arc::new(Misnamed {
                            holds: key(12),
                            names: not_a_point,
                        })),
                    },
                ),
                dial(&claimant, &door_key, claiming(authority.clone())),
            ),
            (
                "a claim by a key the hosted chain carries and does not commit",
                &[],
                &hosting_uncommitted,
                dial(&claimant, &door_key, claiming(outside)),
                dial(&claimant, &door_key, claiming(phrase)),
            ),
        ];

        let one = format!("{:?}", closed());
        for (what, admitted, admission, refused, admits) in &cases {
            let (dialer, door) = readings(&door_key, admitted, admission, admits).await;
            assert!(dialer.is_ok() && door.is_ok(), "{what}: the same door admits its counterpart");
            let (dialer, door) = readings(&door_key, admitted, admission, refused).await;
            assert_eq!(dialer.as_ref(), Err(&one), "{what}: refusals must not be distinguishable");
            assert_eq!(door.as_ref(), Err(&one), "{what}: nor read apart at the door");
        }

        // An ask answered with a reply that does not decode, beside one that offers the events
        // the hosted tip admits: the door reads it as it reads every refusal, and writes nothing.
        let events = vec![serde_json::to_vec(&rotation).unwrap()];
        let admits_reply = AskReply::latest_of(&events).encode().unwrap();
        let (door, answered) = replying(&door_key, &hosting_tip, &recovered, &admits_reply).await;
        assert!(door.is_ok() && answered, "a malformed reply: the same door admits its counterpart");
        let (door, answered) = replying(&door_key, &hosting_tip, &recovered, b"not a reply").await;
        assert_eq!(door.as_ref(), Err(&one), "a malformed reply: read apart at the door");
        assert!(!answered, "a malformed reply: the door writes nothing to it");
    }

    /// A dialer that answers the door's ask with `reply`, sealed and sent as `connect` sends
    /// one, at a door under `door_key` admitting no key by itself and whom `admission` admits:
    /// the door's reading, and whether it then wrote the dialer anything.
    async fn replying(
        door_key: &SigningKey,
        admission: &Admission,
        dialer: &SigningKey,
        reply: &[u8],
    ) -> (Result<(), String>, bool) {
        let door = door_admitting(door_key, &[], admission.clone());
        let (s_io, mut c_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            RelayedConnection::accept(s_io, &door, place())
                .await
                .map(drop)
                .map_err(|e| format!("{e:?}"))
        });
        let (initiator, opening) = Initiator::open(
            &kotton_crypto::x25519::ed25519_priv_to_x25519(dialer),
            &kotton_crypto::x25519::ed25519_pub_to_x25519(&kotton_crypto::ed25519::verifying_key(door_key)),
            None,
            None,
        )
        .unwrap();
        send(&mut c_io, &opening).await.unwrap();
        let second = read_body(&mut c_io).await.unwrap().unwrap();
        let (awaiting, third) = initiator.read_second(&second).unwrap();
        send(&mut c_io, &third).await.unwrap();
        let first = read_body(&mut c_io).await.unwrap().unwrap();
        let (mut channel, answer) = awaiting.read_first(&first).unwrap();
        assert_eq!(answer, Answer::AskForEvents);
        send(&mut c_io, &channel.seal(reply).unwrap()).await.unwrap();
        let door = server.await.unwrap();
        let mut rest = Vec::new();
        c_io.read_to_end(&mut rest).await.unwrap();
        (door, !rest.is_empty())
    }

    /// What [`HeldKeys`] admits, with each recovery claim put to it counted.
    struct CountingClaims {
        inner: HeldKeys,
        claims: std::sync::atomic::AtomicUsize,
    }

    impl Admits for CountingClaims {
        fn by_key(&self, initiator: &[u8; 32]) -> Option<[u8; 32]> {
            self.inner.by_key(initiator)
        }

        fn by_events(&self, initiator: &[u8; 32], events: &[Vec<u8>]) -> Option<[u8; 32]> {
            self.inner.by_events(initiator, events)
        }

        fn by_claim(&self, authority: &[u8; 32]) -> Option<String> {
            self.claims.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.by_claim(authority)
        }
    }

    /// The door's refusals take one path whatever they refuse: what the dialer proves on this
    /// connection is checked before the door looks up anything it hosts, for offered events
    /// as for a recovery claim. Events that name no key the dialer holds are refused while
    /// every reader of the hosted tips is held off, and a claim whose tag the authority it
    /// names did not make, or whose named key is no point, is refused with no authority looked
    /// up. Beside each, its counterpart is looked up and admitted.
    #[tokio::test]
    async fn the_dialers_proof_is_checked_before_any_lookup_by_events_as_by_a_claim() {
        use kotton_crypto::kel_verify::{build_inception, build_mnemonic_rotation, kel_recovery_pubkey};
        use std::sync::atomic::Ordering;
        use std::time::Duration;

        // The events path: a hosted tip, and the rotation that names `recovered`.
        let seed = [42u8; 32];
        let rung = |i| kel_recovery_pubkey(&kotton_crypto::kdf::derive_kel_recovery_key(&seed, i));
        let tip = build_inception(&key(30), &[rung(0)]);
        let (recovered, stranger) = (key(31), key(42));
        let rotation = build_mnemonic_rotation(&tip, &seed, 0, &recovered, 0, &[rung(0)]);
        let hosting_tip = Admission::default();
        hosting_tip.tips.write().unwrap().insert(tip.aid.to_string(), tip.clone());
        let held = HeldKeys::new(Arc::new(RwLock::new(HashSet::new())), hosting_tip.clone());
        let events = vec![serde_json::to_vec(&rotation).unwrap()];
        let montgomery = |k: &SigningKey| {
            kotton_crypto::x25519::ed25519_pub_to_x25519(&kotton_crypto::ed25519::verifying_key(k)).to_bytes()
        };
        // The events put to the door by `initiator` while a writer holds the hosted tips:
        // whether the answer came while they were held, and the answer.
        let asked_while_held = |initiator: [u8; 32], wait: Duration| {
            let writer = hosting_tip.tips.write().unwrap();
            let (tx, rx) = std::sync::mpsc::channel();
            let (held, events) = (held.clone(), events.clone());
            let asking = std::thread::spawn(move || tx.send(held.by_events(&initiator, &events)).unwrap());
            let early = rx.recv_timeout(wait).ok();
            drop(writer);
            let answer = early.unwrap_or_else(|| rx.recv().unwrap());
            asking.join().unwrap();
            (early.is_some(), answer)
        };
        assert_eq!(
            asked_while_held(montgomery(&stranger), Duration::from_secs(5)),
            (true, None),
            "events naming another key are refused before the hosted tips are read"
        );
        assert_eq!(
            asked_while_held(montgomery(&recovered), Duration::from_millis(300)),
            (false, Some(pub_of(&recovered))),
            "events naming the dialer's key are put to the hosted tips, and admit it"
        );

        // The claim path: a hosted identity whose inception commits `authority`.
        let (door_key, claimant, authority) = (key(40), key(2), key(11));
        let hosting_authority = Admission::default();
        hosting_authority.learn_chain(&[build_inception(&key(10), &[pub_of(&authority)])]);
        let not_a_point = (0u8..=u8::MAX)
            .map(|n| [n; 32])
            .find(|b| VerifyingKey::from_bytes(b).is_err())
            .unwrap();
        let misnamed = |names| CircuitOffer {
            events: Vec::new(),
            claim: Some(Arc::new(Misnamed { holds: key(12), names })),
        };
        let counting = Arc::new(CountingClaims {
            inner: HeldKeys::new(Arc::new(RwLock::new(HashSet::new())), hosting_authority),
            claims: std::sync::atomic::AtomicUsize::new(0),
        });
        for (what, offer, admitted, looked_up) in [
            ("a claim whose tag the named authority did not make", misnamed(pub_of(&authority)), false, 0),
            ("a claim whose named key is no point", misnamed(not_a_point), false, 0),
            ("a claim by the authority the identity commits", claiming(authority.clone()), true, 1),
        ] {
            let door = Door::new(std::slice::from_ref(&door_key), counting.clone()).unwrap();
            let (s_io, c_io) = tokio::io::duplex(64 * 1024);
            let server = tokio::spawn(async move { RelayedConnection::accept(s_io, &door, place()).await.map(drop) });
            let dialled = RelayedConnection::connect(c_io, &claimant, &pub_of(&door_key), &offer).await;
            assert_eq!(dialled.is_ok(), admitted, "{what}: the dialer's reading");
            assert_eq!(server.await.unwrap().is_ok(), admitted, "{what}: the door's reading");
            assert_eq!(counting.claims.swap(0, Ordering::SeqCst), looked_up, "{what}: authorities looked up");
        }
    }

    /// A recovered device offers, inside the channel, the rotation that names its key, and
    /// is admitted by it; the same rotation offered from another key admits nobody.
    #[tokio::test]
    async fn a_recovered_device_is_admitted_by_the_events_it_offers_inside_the_channel() {
        use kotton_crypto::kel_verify::{build_inception, build_mnemonic_rotation, kel_recovery_pubkey};
        let seed = [42u8; 32];
        let rung = |i| kel_recovery_pubkey(&kotton_crypto::kdf::derive_kel_recovery_key(&seed, i));
        let tip = build_inception(&key(30), &[rung(0)]);
        let recovered = key(31);
        let rotation = build_mnemonic_rotation(&tip, &seed, 0, &recovered, 0, &[rung(0)]);
        let door_key = key(32);

        for (dialer, admitted) in [(recovered.clone(), true), (key(33), false)] {
            let admission = Admission::default();
            admission.tips.write().unwrap().insert(tip.aid.to_string(), tip.clone());
            let (s_io, c_io) = tokio::io::duplex(64 * 1024);
            let door = door_admitting(&door_key, &[], admission.clone());
            let server =
                tokio::spawn(async move { RelayedConnection::accept(s_io, &door, place()).await });
            let offer = CircuitOffer {
                events: vec![rotation.clone()],
                claim: None,
            };
            let dialled = RelayedConnection::connect(c_io, &dialer, &pub_of(&door_key), &offer).await;
            let accepted = server.await.unwrap();
            assert_eq!(dialled.is_ok(), admitted);
            assert_eq!(accepted.is_ok(), admitted);
            let pending = admission.admitted(&pub_of(&recovered));
            assert_eq!(
                pending,
                admitted.then(|| Admitted::ByProof {
                    aid: tip.aid.to_string(),
                    events: vec![rotation.clone()],
                })
            );
        }
    }

    #[tokio::test]
    async fn the_handshake_runs_over_a_real_websocket() {
        use tokio::net::TcpListener;
        let (door_key, dialer_key) = (key(13), key(14));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let door = door_admitting(&door_key, &[pub_of(&dialer_key)], Admission::default());
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let conn = RelayedConnection::accept(WsByteStream::new(ws), &door, place())
                .await
                .expect("the door over a websocket");
            assert!(echo(&conn).await);
        });
        let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}"))
            .await
            .unwrap();
        let conn = RelayedConnection::connect(
            WsByteStream::new(ws),
            &dialer_key,
            &pub_of(&door_key),
            &CircuitOffer::default(),
        )
        .await
        .expect("the dial over a websocket");
        assert_eq!(conn.request(b"ping").await.unwrap(), b"echo:ping");
        server.await.unwrap();
    }

    /// A door holds one to [`MAX_DOOR_KEYS`] keys, and is not made with more.
    #[test]
    fn a_door_holds_at_most_its_bound_of_keys() {
        let admits: Arc<dyn Admits> = Arc::new(HeldKeys::only(Arc::default()));
        let keys: Vec<SigningKey> = (0..=MAX_DOOR_KEYS as u8).map(|n| key(100 + n)).collect();
        assert!(Door::new(&keys[..MAX_DOOR_KEYS], Arc::clone(&admits)).is_ok());
        assert!(Door::new(&keys, Arc::clone(&admits)).is_err());
        assert!(Door::new(&[], admits).is_err());
    }

    /// A reservation holds at most [`MAX_OPENING`] circuits in their opening; a place frees
    /// when a first frame is whole or its wait runs out.
    #[test]
    fn a_reservation_holds_at_most_its_bound_of_openings() {
        let openings = Openings::default();
        let held: Vec<_> = (0..MAX_OPENING).map(|_| openings.admit().expect("a place")).collect();
        assert!(openings.admit().is_none(), "one past the bound has no place");
        drop(held);
        assert!(openings.admit().is_some());
    }

    /// A circuit that sends nothing is closed on once the first frame's wait runs out, and
    /// is written nothing; its place in the openings is free again.
    #[tokio::test(start_paused = true)]
    async fn a_silent_circuit_is_closed_on_after_the_wait_having_been_written_nothing() {
        let door = door_admitting(&key(20), &[pub_of(&key(21))], Admission::default());
        let openings = Openings::default();
        let held: Vec<_> = (0..MAX_OPENING - 1).map(|_| openings.admit().unwrap()).collect();
        let (s_io, mut c_io) = tokio::io::duplex(1024);
        let opening = openings.admit().expect("the last place");
        assert!(openings.admit().is_none());
        let started = tokio::time::Instant::now();
        let server =
            tokio::spawn(async move { RelayedConnection::accept(s_io, &door, opening).await });
        let mut written = Vec::new();
        c_io.read_to_end(&mut written).await.unwrap();
        assert!(written.is_empty());
        assert!(server.await.unwrap().is_err());
        assert!(started.elapsed() >= FIRST_FRAME_WAIT);
        assert!(openings.admit().is_some(), "the place is free again");
        drop(held);
    }

    /// A circuit that sends a whole first frame and then nothing is closed on once
    /// [`ADMIT_WAIT`] has run from its start, though no single read has a wait of its own;
    /// it is written only the second message, and its admitting place is free again.
    #[tokio::test(start_paused = true)]
    async fn a_circuit_that_stalls_after_its_first_frame_is_closed_on_at_the_admit_wait() {
        let (door_key, dialer_key) = (key(22), key(23));
        let door = door_admitting(&door_key, &[pub_of(&dialer_key)], Admission::default());
        let openings = Openings::default();
        let place = openings.admit().unwrap();
        let (s_io, mut c_io) = tokio::io::duplex(64 * 1024);
        let started = tokio::time::Instant::now();
        let server = tokio::spawn(async move { RelayedConnection::accept(s_io, &door, place).await });
        open_and_stall(&mut c_io, &door_key, &dialer_key).await;
        assert!(server.await.unwrap().is_err());
        assert!(started.elapsed() >= ADMIT_WAIT);
        assert!(started.elapsed() < ADMIT_WAIT + FIRST_FRAME_WAIT);
        let mut rest = Vec::new();
        c_io.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty(), "nothing after the second message: {} bytes", rest.len());
        let held: Vec<_> = (0..MAX_ADMITTING)
            .map(|_| openings.admitting.clone().try_acquire_owned().expect("every admitting place free"))
            .collect();
        drop(held);
    }

    /// A dial-back the relay never answers holds its opening place for [`DIAL_BACK_WAIT`] and
    /// then lets it go, having sent nothing on.
    #[tokio::test(start_paused = true)]
    async fn a_stalled_dial_back_lets_its_place_go_at_its_wait() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Takes the connection and never answers the upgrade.
        let silent = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
            drop(tcp);
        });
        let door = Arc::new(door_admitting(&key(24), &[], Admission::default()));
        let openings = Openings::default();
        let held: Vec<_> = (0..MAX_OPENING - 1).map(|_| openings.admit().unwrap()).collect();
        let place = openings.admit().expect("the last place");
        let (out, mut admitted) = mpsc::channel(1);
        let started = tokio::time::Instant::now();
        let answering = tokio::spawn(answer_circuit(
            format!("ws://{addr}/relay/accept?circuit=x"),
            door,
            place,
            out,
        ));
        tokio::task::yield_now().await;
        assert!(openings.admit().is_none(), "the dial-back holds its place");
        answering.await.unwrap();
        assert!(started.elapsed() >= DIAL_BACK_WAIT);
        assert!(openings.admit().is_some(), "and lets it go");
        assert!(admitted.recv().await.is_none(), "nothing was sent on");
        drop(held);
        silent.abort();
    }

    /// At most [`MAX_ADMITTING`] circuits are held past their first frame and before
    /// admission; one more, its first frame whole and under the door's key, is closed on
    /// having been written nothing, and does not hold an opening place.
    #[tokio::test(start_paused = true)]
    async fn a_reservation_holds_at_most_its_bound_of_circuits_being_admitted() {
        let (door_key, dialer_key) = (key(25), key(26));
        let door = Arc::new(door_admitting(&door_key, &[pub_of(&dialer_key)], Admission::default()));
        let openings = Openings::default();
        let mut stalled = Vec::new();
        for _ in 0..MAX_ADMITTING {
            let (s_io, mut c_io) = tokio::io::duplex(64 * 1024);
            let (door, place) = (Arc::clone(&door), openings.admit().unwrap());
            let server = tokio::spawn(async move { RelayedConnection::accept(s_io, &door, place).await });
            open_and_stall(&mut c_io, &door_key, &dialer_key).await;
            stalled.push((server, c_io));
        }

        let (s_io, mut c_io) = tokio::io::duplex(64 * 1024);
        let place = openings.admit().expect("an opening place is free");
        let one_more = {
            let door = Arc::clone(&door);
            tokio::spawn(async move { RelayedConnection::accept(s_io, &door, place).await })
        };
        let (_, opening) = Initiator::open(
            &kotton_crypto::x25519::ed25519_priv_to_x25519(&dialer_key),
            &kotton_crypto::x25519::ed25519_pub_to_x25519(&kotton_crypto::ed25519::verifying_key(&door_key)),
            None,
            None,
        )
        .unwrap();
        c_io.write_all(&opening).await.unwrap();
        assert!(one_more.await.unwrap().is_err(), "one past the bound is closed on");
        let mut written = Vec::new();
        c_io.read_to_end(&mut written).await.unwrap();
        assert!(written.is_empty(), "and written nothing: {} bytes", written.len());
        let opening_places: Vec<_> = (0..MAX_OPENING)
            .map(|_| openings.admit().expect("no opening place is held by a circuit being admitted"))
            .collect();
        drop(opening_places);

        for (server, _c_io) in stalled {
            assert!(server.await.unwrap().is_err(), "each stalled circuit expires");
        }
    }
}
