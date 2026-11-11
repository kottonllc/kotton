// SPDX-License-Identifier: AGPL-3.0-or-later
//! The bytes the handshake carries inside its channel (kotton-protocol's *One handshake
//! admits a device, by the identity's log*).
//!
//! The handshake itself, its version byte, its prologue and its three Noise messages, is
//! `core/handshake`'s. What is here is what crosses sealed once Noise has keyed the channel,
//! each with one fixed binary encoding:
//!
//! - [`ThirdPayload`]: the payload of the third message. The identity the initiator acts for,
//!   or none; the latest event of that identity's log it holds, or none; the versions it
//!   speaks. Every field has a fixed place and an absent one is zeros, so the payload is
//!   [`THIRD_PAYLOAD_LEN`] bytes whoever sends it: a device, an operator, or one with a claim
//!   to make. The path cannot tell them apart by its length.
//! - [`ResponderFrame`]: the responder's first frame, to any initiator that completed the
//!   handshake. It states the versions the responder speaks, and either that the initiator is
//!   admitted (with the latest event the responder holds, or none) or the one ask for events,
//!   which reads the same whatever the reason it was asked.
//! - [`EventsFrame`]: the events an initiator sends in answer to that ask, at most
//!   [`MAX_EVENTS`], or none. An event is carried as the bytes of its canonical form; this
//!   module does not read it.
//! - [`split_message`] and [`MessageReader`]: one request, or one answer, across as many
//!   transport frames as it takes.
//!
//! Nothing here names a key. The initiator's static key reaches the responder through the
//! pattern, never through a payload.

use thiserror::Error;

/// The handshake's version this tree speaks. There is no version before it.
pub const VERSION_1: u8 = 1;

/// The longest frame, its two-byte length excluded: the most two bytes can say.
pub const MAX_FRAME_LEN: usize = 65535;

/// The tag ChaCha20-Poly1305 appends to every sealed frame.
pub const TAG_LEN: usize = 16;

/// The most plaintext one transport frame carries.
pub const MAX_FRAME_PLAINTEXT: usize = MAX_FRAME_LEN - TAG_LEN;

/// The most events one [`EventsFrame`] carries.
pub const MAX_EVENTS: usize = 64;

/// The longest request or answer [`split_message`] frames, its length prefix excluded. The
/// same bound the transports this channel replaces put on one message.
pub const MAX_MESSAGE_LEN: usize = 10 * 1024 * 1024;

/// One malformed or over-long value. The channel closes on any of them, the same way.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Malformed {
    #[error("the bytes are not this value's length")]
    Length,
    #[error("a tag byte is not one this value defines")]
    Tag,
    #[error("an absent field is not zeros")]
    NotZero,
    #[error("the version set is empty or names version 0")]
    Versions,
    #[error("an event is named without the identity it belongs to")]
    EventWithoutIdentity,
    #[error("more events than one frame carries")]
    TooManyEvents,
    #[error("an event is empty")]
    EmptyEvent,
    #[error("the value does not fit one frame")]
    TooLong,
}

// ── Versions ──────────────────────────────────────────────────────────────────

/// The length of a [`Versions`] on the wire.
pub const VERSIONS_LEN: usize = 32;

/// A set of handshake versions, as 256 bits: version `v` is bit `v % 8` of byte `v / 8`.
/// Version 0 is never in it, and it is never empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Versions([u8; VERSIONS_LEN]);

impl Versions {
    /// The set holding exactly these versions. `None` where one is 0 or none is given.
    pub fn of(versions: &[u8]) -> Option<Self> {
        let mut bits = [0u8; VERSIONS_LEN];
        for &v in versions {
            if v == 0 {
                return None;
            }
            bits[usize::from(v / 8)] |= 1 << (v % 8);
        }
        Self::from_bytes(bits).ok()
    }

    /// The versions this tree speaks.
    pub fn spoken() -> Self {
        Self::of(&[VERSION_1]).expect("version 1 is a version")
    }

    pub fn contains(&self, v: u8) -> bool {
        self.0[usize::from(v / 8)] & (1 << (v % 8)) != 0
    }

    /// The latest version both sets hold, if any.
    pub fn latest_common(&self, other: &Versions) -> Option<u8> {
        (1..=u8::MAX)
            .rev()
            .find(|&v| self.contains(v) && other.contains(v))
    }

    pub fn to_bytes(&self) -> [u8; VERSIONS_LEN] {
        self.0
    }

    pub fn from_bytes(bits: [u8; VERSIONS_LEN]) -> Result<Self, Malformed> {
        if bits[0] & 1 != 0 || bits.iter().all(|&b| b == 0) {
            return Err(Malformed::Versions);
        }
        Ok(Self(bits))
    }
}

// ── An event, named ───────────────────────────────────────────────────────────

/// One event of an identity's log, named by its sequence number and its digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventRef {
    pub seq: u64,
    pub digest: [u8; 32],
}

/// The length of an optional [`EventRef`] on the wire: a presence byte, the sequence number
/// as eight bytes most significant first, and the digest.
const EVENT_REF_LEN: usize = 1 + 8 + 32;

fn put_event(out: &mut Vec<u8>, event: Option<&EventRef>) {
    match event {
        Some(e) => {
            out.push(1);
            out.extend_from_slice(&e.seq.to_be_bytes());
            out.extend_from_slice(&e.digest);
        }
        None => out.extend_from_slice(&[0u8; EVENT_REF_LEN]),
    }
}

fn take_event(bytes: &[u8]) -> Result<Option<EventRef>, Malformed> {
    debug_assert_eq!(bytes.len(), EVENT_REF_LEN);
    match bytes[0] {
        0 if bytes[1..].iter().all(|&b| b == 0) => Ok(None),
        0 => Err(Malformed::NotZero),
        1 => Ok(Some(EventRef {
            seq: u64::from_be_bytes(bytes[1..9].try_into().expect("eight bytes")),
            digest: bytes[9..].try_into().expect("32 bytes"),
        })),
        _ => Err(Malformed::Tag),
    }
}

// ── The third message's payload ───────────────────────────────────────────────

/// The length of a [`ThirdPayload`] on the wire, whoever sends it.
pub const THIRD_PAYLOAD_LEN: usize = 1 + 32 + EVENT_REF_LEN + VERSIONS_LEN;

/// The payload of the handshake's third message.
///
/// On the wire: a presence byte and the 32 bytes of the identity's identifier (its
/// inception's digest), the latest event as [`EventRef`] with its presence byte, then
/// [`Versions`]. An absent field is its presence byte 0 and zeros.
///
/// It does not belong in a log line on refusal: it names the identity an initiator acts for
/// and where its log stands, and a responder that writes it down on a refusal keeps the record
/// the handshake was built not to show. It derives `Debug` for tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThirdPayload {
    /// The identity the initiator acts for, as its inception's digest; `None` for one that
    /// names none (an operator, a contact's door, a device that holds only a recovery
    /// authority).
    pub identity: Option<[u8; 32]>,
    /// The latest event of that identity's log the initiator holds.
    pub latest: Option<EventRef>,
    /// The versions the initiator speaks.
    pub versions: Versions,
}

impl ThirdPayload {
    pub fn encode(&self) -> [u8; THIRD_PAYLOAD_LEN] {
        let mut out = Vec::with_capacity(THIRD_PAYLOAD_LEN);
        match &self.identity {
            Some(id) => {
                out.push(1);
                out.extend_from_slice(id);
            }
            None => out.extend_from_slice(&[0u8; 33]),
        }
        put_event(&mut out, self.latest.as_ref());
        out.extend_from_slice(&self.versions.to_bytes());
        out.try_into()
            .expect("the layout is THIRD_PAYLOAD_LEN bytes")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Malformed> {
        if bytes.len() != THIRD_PAYLOAD_LEN {
            return Err(Malformed::Length);
        }
        let identity = match bytes[0] {
            0 if bytes[1..33].iter().all(|&b| b == 0) => None,
            0 => return Err(Malformed::NotZero),
            1 => Some(bytes[1..33].try_into().expect("32 bytes")),
            _ => return Err(Malformed::Tag),
        };
        let latest = take_event(&bytes[33..33 + EVENT_REF_LEN])?;
        if latest.is_some() && identity.is_none() {
            return Err(Malformed::EventWithoutIdentity);
        }
        let versions = Versions::from_bytes(
            bytes[33 + EVENT_REF_LEN..]
                .try_into()
                .expect("VERSIONS_LEN bytes"),
        )?;
        Ok(Self {
            identity,
            latest,
            versions,
        })
    }
}

// ── The responder's first frame ───────────────────────────────────────────────

/// What the responder answers the third message with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// The initiator is admitted. `latest` is the latest event the responder holds of the
    /// identity's log, or `None` where it admits the key by no log.
    Admitted { latest: Option<EventRef> },
    /// The one ask for events: the same bytes whatever the reason it was asked.
    AskForEvents,
}

/// The length of a [`ResponderFrame`] on the wire, whichever its answer.
pub const RESPONDER_FRAME_LEN: usize = 1 + VERSIONS_LEN + EVENT_REF_LEN;

/// The responder's first frame: the versions it speaks, and its answer.
///
/// On the wire: a tag byte (1 admitted, 2 the ask), [`Versions`], then the latest event as
/// an [`EventRef`] with its presence byte, which is zeros for the ask. Both answers are one
/// length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResponderFrame {
    pub versions: Versions,
    pub answer: Answer,
}

impl ResponderFrame {
    pub fn encode(&self) -> [u8; RESPONDER_FRAME_LEN] {
        let mut out = Vec::with_capacity(RESPONDER_FRAME_LEN);
        let latest = match &self.answer {
            Answer::Admitted { latest } => {
                out.push(1);
                latest.as_ref()
            }
            Answer::AskForEvents => {
                out.push(2);
                None
            }
        };
        out.extend_from_slice(&self.versions.to_bytes());
        put_event(&mut out, latest);
        out.try_into()
            .expect("the layout is RESPONDER_FRAME_LEN bytes")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Malformed> {
        if bytes.len() != RESPONDER_FRAME_LEN {
            return Err(Malformed::Length);
        }
        let versions =
            Versions::from_bytes(bytes[1..1 + VERSIONS_LEN].try_into().expect("VERSIONS_LEN"))?;
        let latest = take_event(&bytes[1 + VERSIONS_LEN..])?;
        let answer = match bytes[0] {
            1 => Answer::Admitted { latest },
            2 if latest.is_none() => Answer::AskForEvents,
            2 => return Err(Malformed::NotZero),
            _ => return Err(Malformed::Tag),
        };
        Ok(Self { versions, answer })
    }
}

// ── The events frame ──────────────────────────────────────────────────────────

/// The events an initiator sends when it is asked: at most [`MAX_EVENTS`], in the log's
/// order, each as the bytes of its canonical form.
///
/// On the wire: for each event, its length as two bytes most significant first, then its
/// bytes. No count: an initiator that holds no event sends an empty frame, which is zero
/// events.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct EventsFrame {
    pub events: Vec<Vec<u8>>,
}

impl EventsFrame {
    /// The frame for the latest events of `log` (oldest first): as many as one frame
    /// holds, and at most [`MAX_EVENTS`].
    pub fn latest_of(log: &[Vec<u8>]) -> Self {
        let mut taken = 0usize;
        let mut len = 0usize;
        for event in log.iter().rev() {
            let next = len + 2 + event.len();
            if taken == MAX_EVENTS || event.is_empty() || next > MAX_FRAME_PLAINTEXT {
                break;
            }
            len = next;
            taken += 1;
        }
        Self {
            events: log[log.len() - taken..].to_vec(),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, Malformed> {
        if self.events.len() > MAX_EVENTS {
            return Err(Malformed::TooManyEvents);
        }
        let mut out = Vec::new();
        for event in &self.events {
            if event.is_empty() {
                return Err(Malformed::EmptyEvent);
            }
            let len = u16::try_from(event.len()).map_err(|_| Malformed::TooLong)?;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(event);
        }
        if out.len() > MAX_FRAME_PLAINTEXT {
            return Err(Malformed::TooLong);
        }
        Ok(out)
    }

    pub fn decode(mut bytes: &[u8]) -> Result<Self, Malformed> {
        if bytes.len() > MAX_FRAME_PLAINTEXT {
            return Err(Malformed::TooLong);
        }
        let mut events = Vec::new();
        while !bytes.is_empty() {
            if events.len() == MAX_EVENTS {
                return Err(Malformed::TooManyEvents);
            }
            if bytes.len() < 2 {
                return Err(Malformed::Length);
            }
            let len = usize::from(u16::from_be_bytes([bytes[0], bytes[1]]));
            if len == 0 {
                return Err(Malformed::EmptyEvent);
            }
            let rest = &bytes[2..];
            if rest.len() < len {
                return Err(Malformed::Length);
            }
            events.push(rest[..len].to_vec());
            bytes = &rest[len..];
        }
        Ok(Self { events })
    }
}

// ── A request across transport frames ─────────────────────────────────────────

/// The plaintexts of the transport frames that carry `message`, one request or one answer.
///
/// The message is its length as four bytes most significant first, then its bytes, cut into
/// frames of [`MAX_FRAME_PLAINTEXT`] each but the last, which holds the rest. A frame
/// carries bytes of one message only: a connection carries one request at a time.
pub fn split_message(message: &[u8]) -> Result<Vec<Vec<u8>>, Malformed> {
    if message.len() > MAX_MESSAGE_LEN {
        return Err(Malformed::TooLong);
    }
    let len = u32::try_from(message.len()).map_err(|_| Malformed::TooLong)?;
    let mut whole = Vec::with_capacity(4 + message.len());
    whole.extend_from_slice(&len.to_be_bytes());
    whole.extend_from_slice(message);
    Ok(whole
        .chunks(MAX_FRAME_PLAINTEXT)
        .map(<[u8]>::to_vec)
        .collect())
}

/// Reassembles one message from the plaintexts [`split_message`] cut it into.
#[derive(Debug, Default)]
pub struct MessageReader {
    expected: Option<usize>,
    body: Vec<u8>,
}

impl MessageReader {
    pub fn new() -> Self {
        Self::default()
    }

    /// Take one frame's plaintext. `Ok(Some(message))` once the message is whole, after which
    /// the reader starts on the next. A frame that is not the length the framing gives it is
    /// refused: every frame but a message's last is full, and none runs past its message.
    pub fn push(&mut self, plaintext: &[u8]) -> Result<Option<Vec<u8>>, Malformed> {
        let (expected, rest) = match self.expected {
            Some(n) => (n, plaintext),
            None => {
                if plaintext.len() < 4 {
                    return Err(Malformed::Length);
                }
                let n = u32::from_be_bytes(plaintext[..4].try_into().expect("four bytes"));
                let n = usize::try_from(n).map_err(|_| Malformed::TooLong)?;
                if n > MAX_MESSAGE_LEN {
                    return Err(Malformed::TooLong);
                }
                (n, &plaintext[4..])
            }
        };
        let remaining = expected - self.body.len();
        let full = plaintext.len() == MAX_FRAME_PLAINTEXT;
        if rest.len() > remaining || (rest.len() < remaining && !full) {
            return Err(Malformed::Length);
        }
        self.expected = Some(expected);
        self.body.extend_from_slice(rest);
        if self.body.len() == expected {
            self.expected = None;
            return Ok(Some(std::mem::take(&mut self.body)));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn event() -> EventRef {
        EventRef {
            seq: 0x0102_0304_0506_0708,
            digest: [0xd1; 32],
        }
    }

    #[test]
    fn versions_are_bits_and_never_version_zero() {
        let v = Versions::of(&[1, 9]).unwrap();
        let bytes = v.to_bytes();
        assert_eq!(bytes[0], 0b10, "version 1 is bit 1 of byte 0");
        assert_eq!(bytes[1], 0b10, "version 9 is bit 1 of byte 1");
        assert!(Versions::of(&[0]).is_none());
        assert!(Versions::of(&[]).is_none());
        assert_eq!(Versions::from_bytes([0; 32]), Err(Malformed::Versions));
        assert_eq!(v.latest_common(&Versions::of(&[1, 2, 9]).unwrap()), Some(9));
        assert_eq!(v.latest_common(&Versions::of(&[2]).unwrap()), None);
        assert!(Versions::spoken().contains(VERSION_1));
    }

    #[test]
    fn the_third_payload_is_one_length_whoever_sends_it() {
        let device = ThirdPayload {
            identity: Some([0xaa; 32]),
            latest: Some(event()),
            versions: Versions::spoken(),
        };
        let none = ThirdPayload {
            identity: None,
            latest: None,
            versions: Versions::spoken(),
        };
        assert_eq!(device.encode().len(), THIRD_PAYLOAD_LEN);
        assert_eq!(none.encode().len(), THIRD_PAYLOAD_LEN);
        assert_eq!(ThirdPayload::decode(&device.encode()), Ok(device));
        assert_eq!(ThirdPayload::decode(&none.encode()), Ok(none));
        // The vector: these bytes, and no others, are the payload.
        let device_bytes = format!(
            "01{}01{}{}02{}",
            "aa".repeat(32),
            "0102030405060708",
            "d1".repeat(32),
            "00".repeat(31),
        );
        assert_eq!(hex(&device.encode()), device_bytes);
        let none_bytes = format!("{}02{}", "00".repeat(1 + 32 + 41), "00".repeat(31));
        assert_eq!(hex(&none.encode()), none_bytes);
    }

    #[test]
    fn a_third_payload_out_of_its_one_form_is_refused() {
        let good = ThirdPayload {
            identity: Some([0xaa; 32]),
            latest: Some(event()),
            versions: Versions::spoken(),
        }
        .encode();
        assert_eq!(
            ThirdPayload::decode(&good[..THIRD_PAYLOAD_LEN - 1]),
            Err(Malformed::Length)
        );
        let mut b = good;
        b[0] = 2;
        assert_eq!(ThirdPayload::decode(&b), Err(Malformed::Tag));
        let mut b = good;
        b[0] = 0;
        assert_eq!(ThirdPayload::decode(&b), Err(Malformed::NotZero));
        let mut b = [0u8; THIRD_PAYLOAD_LEN];
        b[33..].copy_from_slice(&good[33..]);
        assert_eq!(
            ThirdPayload::decode(&b),
            Err(Malformed::EventWithoutIdentity)
        );
        let mut b = good;
        b[33 + 41] |= 1;
        assert_eq!(ThirdPayload::decode(&b), Err(Malformed::Versions));
    }

    #[test]
    fn the_responders_first_frame_is_one_length_for_either_answer() {
        let admitted = ResponderFrame {
            versions: Versions::spoken(),
            answer: Answer::Admitted {
                latest: Some(event()),
            },
        };
        let ask = ResponderFrame {
            versions: Versions::spoken(),
            answer: Answer::AskForEvents,
        };
        assert_eq!(admitted.encode().len(), ask.encode().len());
        assert_eq!(ResponderFrame::decode(&admitted.encode()), Ok(admitted));
        assert_eq!(ResponderFrame::decode(&ask.encode()), Ok(ask));
        assert_eq!(
            hex(&admitted.encode()),
            format!(
                "0102{}010102030405060708{}",
                "00".repeat(31),
                "d1".repeat(32)
            )
        );
        assert_eq!(
            hex(&ask.encode()),
            format!("0202{}{}", "00".repeat(31), "00".repeat(41))
        );
        let mut b = ask.encode();
        b[RESPONDER_FRAME_LEN - 1] = 1;
        assert_eq!(ResponderFrame::decode(&b), Err(Malformed::NotZero));
        let mut b = admitted.encode();
        b[0] = 3;
        assert_eq!(ResponderFrame::decode(&b), Err(Malformed::Tag));
    }

    #[test]
    fn the_events_frame_holds_at_most_64_and_an_empty_one_holds_none() {
        assert_eq!(EventsFrame::default().encode().unwrap(), Vec::<u8>::new());
        assert_eq!(EventsFrame::decode(&[]).unwrap(), EventsFrame::default());
        let two = EventsFrame {
            events: vec![vec![0xe1], vec![0xe2, 0xe3]],
        };
        assert_eq!(hex(&two.encode().unwrap()), "0001e10002e2e3");
        assert_eq!(EventsFrame::decode(&two.encode().unwrap()).unwrap(), two);

        let log: Vec<Vec<u8>> = (0..100u8).map(|i| vec![i; 10]).collect();
        let frame = EventsFrame::latest_of(&log);
        assert_eq!(frame.events.len(), MAX_EVENTS);
        assert_eq!(
            frame.events[0],
            vec![36u8; 10],
            "the latest 64, oldest first"
        );
        assert_eq!(frame.events[63], vec![99u8; 10]);

        let over = EventsFrame {
            events: vec![vec![1]; MAX_EVENTS + 1],
        };
        assert_eq!(over.encode(), Err(Malformed::TooManyEvents));
        let mut bytes = Vec::new();
        for _ in 0..=MAX_EVENTS {
            bytes.extend_from_slice(&[0, 1, 7]);
        }
        assert_eq!(EventsFrame::decode(&bytes), Err(Malformed::TooManyEvents));
        assert_eq!(EventsFrame::decode(&[0, 0]), Err(Malformed::EmptyEvent));
        assert_eq!(EventsFrame::decode(&[0, 3, 1]), Err(Malformed::Length));

        // As many as one frame holds: three events of 30000 bytes do not fit, two do.
        let big: Vec<Vec<u8>> = (0..3u8).map(|i| vec![i; 30000]).collect();
        assert_eq!(EventsFrame::latest_of(&big).events, big[1..].to_vec());
    }

    #[test]
    fn a_message_crosses_frames_and_comes_back_whole() {
        let small = b"{\"Ping\":null}".to_vec();
        let frames = split_message(&small).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(hex(&frames[0][..4]), "0000000d");
        let mut r = MessageReader::new();
        assert_eq!(r.push(&frames[0]).unwrap(), Some(small));

        let big: Vec<u8> = (0..(MAX_FRAME_PLAINTEXT * 2 + 5))
            .map(|i| i as u8)
            .collect();
        let frames = split_message(&big).unwrap();
        assert_eq!(frames.len(), 3);
        assert!(frames[..2].iter().all(|f| f.len() == MAX_FRAME_PLAINTEXT));
        let mut r = MessageReader::new();
        assert_eq!(r.push(&frames[0]).unwrap(), None);
        assert_eq!(r.push(&frames[1]).unwrap(), None);
        assert_eq!(r.push(&frames[2]).unwrap(), Some(big));

        let empty = split_message(&[]).unwrap();
        assert_eq!(empty, vec![vec![0, 0, 0, 0]]);
        assert_eq!(MessageReader::new().push(&empty[0]).unwrap(), Some(vec![]));
    }

    #[test]
    fn a_message_out_of_its_framing_is_refused() {
        assert_eq!(
            split_message(&vec![0; MAX_MESSAGE_LEN + 1]),
            Err(Malformed::TooLong)
        );
        let mut r = MessageReader::new();
        assert_eq!(r.push(&[0, 0xa0, 0, 1]), Err(Malformed::TooLong));
        // A short frame that is not the message's last.
        let mut r = MessageReader::new();
        assert_eq!(r.push(&[0, 0, 0, 5, 1, 2]), Err(Malformed::Length));
        // A frame that runs past its message.
        let mut r = MessageReader::new();
        assert_eq!(r.push(&[0, 0, 0, 1, 1, 2]), Err(Malformed::Length));
        assert_eq!(
            MessageReader::new().push(&[0, 0, 0]),
            Err(Malformed::Length)
        );
    }
}
