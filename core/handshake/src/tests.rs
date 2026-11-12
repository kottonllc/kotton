// SPDX-License-Identifier: AGPL-3.0-or-later
//! The handshake held to kotton-protocol's page for it, and to its committed vectors (`vectors/v1.txt`).

use super::*;
use ed25519_dalek::SigningKey;
use kotton_wire::handshake::{
    split_message, AskReply, MessageReader, RecoveryClaim, RECOVERY_CLAIM_LEN,
};
use rand::rngs::OsRng;

const VECTORS: &str = include_str!("../vectors/v1.txt");

fn ed(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn mont(key: &SigningKey) -> StaticSecret {
    kotton_crypto::x25519::ed25519_priv_to_x25519(key)
}

fn mont_pub(key: &SigningKey) -> PublicKey {
    kotton_crypto::x25519::ed25519_pub_to_x25519(&key.verifying_key().to_bytes())
        .expect("an Ed25519 key is a curve point")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn fixed(e: u8) -> Run {
    Run {
        ephemeral: Some(Zeroizing::new([e; 32])),
        ..Run::default()
    }
}

fn speaking(version: u8, speaks: &[u8]) -> Run {
    Run {
        version,
        speaks: Versions::of(speaks).expect("versions"),
        ephemeral: None,
    }
}

const IDENTITY: [u8; 32] = [0x55; 32];

fn latest() -> EventRef {
    EventRef {
        seq: 7,
        digest: [0x66; 32],
    }
}

/// What crossed, both ways, in one whole run.
struct Flights {
    opening: Vec<u8>,
    second: Vec<u8>,
    third: Vec<u8>,
    responder_first: Vec<u8>,
    /// The responder's view of the initiator, and which of its keys answered.
    initiator_seen: PublicKey,
    payload_seen: ThirdPayload,
    key_index: usize,
    initiator_channel: Channel,
    responder_channel: Channel,
}

fn whole(
    i_run: Run,
    r_run: Run,
    initiator: &StaticSecret,
    responder_pub: &PublicKey,
    responder_keys: &[StaticSecret],
) -> Flights {
    let (init, opening) = Initiator::open_with(
        i_run,
        initiator,
        responder_pub,
        Some(IDENTITY),
        Some(latest()),
    )
    .expect("open");
    let Opening::Complete {
        version,
        first,
        consumed,
    } = read_opening(&opening)
    else {
        panic!("the opening is whole");
    };
    assert_eq!(consumed, opening.len());
    let (resp, second) = Responder::answer_with(Run { version, ..r_run }, responder_keys, first)
        .expect("the responder answers");
    let key_index = resp.key_index();
    let (await_answer, third) = init.read_second(&second[2..]).expect("second");
    let admitting = resp.read_third(&third[2..]).expect("third");
    let initiator_seen = *admitting.initiator();
    let payload_seen = *admitting.payload();
    let (responder_first, responder_channel) = admitting
        .answer(Answer::Admitted {
            latest: Some(latest()),
        })
        .expect("answer");
    let responder_channel = responder_channel.expect("the channel stays");
    let (initiator_channel, answer) = await_answer
        .read_first(&responder_first[2..])
        .expect("first frame");
    assert_eq!(
        answer,
        Answer::Admitted {
            latest: Some(latest())
        }
    );
    Flights {
        opening,
        second,
        third,
        responder_first,
        initiator_seen,
        payload_seen,
        key_index,
        initiator_channel,
        responder_channel,
    }
}

/// The claim in the vectors: an authority's key of 0x77s, then a tag of 0x88s.
fn claim_body() -> [u8; RECOVERY_CLAIM_LEN] {
    let mut body = [0x88; RECOVERY_CLAIM_LEN];
    body[..32].copy_from_slice(&[0x77; 32]);
    body
}

fn parse_vectors() -> Vec<(String, String)> {
    VECTORS
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let (k, v) = l.split_once(" = ").expect("`name = value`");
            (k.to_string(), v.to_string())
        })
        .collect()
}

#[test]
fn the_committed_vectors_are_what_the_handshake_makes() {
    let (i_ed, r_ed) = (ed(0x11), ed(0x22));
    let (i_key, r_key) = (mont(&i_ed), mont(&r_ed));
    assert_eq!(
        PublicKey::from(&i_key),
        mont_pub(&i_ed),
        "the two halves of one conversion"
    );
    assert_eq!(PublicKey::from(&r_key), mont_pub(&r_ed));

    let mut t = whole(
        fixed(0x33),
        fixed(0x44),
        &i_key,
        &mont_pub(&r_ed),
        std::slice::from_ref(&r_key),
    );
    let request = split_message(b"ping").expect("framing");
    let initiator_first = t.initiator_channel.seal(&request[0]).expect("seal");
    let mut reader = MessageReader::new();
    let opened = t
        .responder_channel
        .open(&initiator_first[2..])
        .expect("open");
    assert_eq!(
        reader.push(&opened).expect("framing"),
        Some(b"ping".to_vec())
    );

    let made = vec![
        ("version", hex(&[VERSION])),
        ("prologue", hex(&prologue(VERSION))),
        ("initiator_ed25519_seed", hex(i_ed.as_bytes())),
        (
            "initiator_ed25519_public",
            hex(i_ed.verifying_key().as_bytes()),
        ),
        ("initiator_static_private", hex(&i_key.to_bytes())),
        ("initiator_static_public", hex(mont_pub(&i_ed).as_bytes())),
        ("initiator_ephemeral_private", hex(&[0x33; 32])),
        ("responder_ed25519_seed", hex(r_ed.as_bytes())),
        (
            "responder_ed25519_public",
            hex(r_ed.verifying_key().as_bytes()),
        ),
        ("responder_static_private", hex(&r_key.to_bytes())),
        ("responder_static_public", hex(mont_pub(&r_ed).as_bytes())),
        ("responder_ephemeral_private", hex(&[0x44; 32])),
        ("third_payload", hex(&t.payload_seen.encode())),
        ("opening", hex(&t.opening)),
        ("second", hex(&t.second)),
        ("third", hex(&t.third)),
        (
            "responder_first_plaintext",
            hex(&ResponderFrame {
                versions: Versions::spoken(),
                answer: Answer::Admitted {
                    latest: Some(latest()),
                },
            }
            .encode()),
        ),
        ("responder_first", hex(&t.responder_first)),
        ("initiator_first_plaintext", hex(&request[0])),
        ("initiator_first", hex(&initiator_first)),
        (
            "ask_reply_events_plaintext",
            hex(&AskReply::Events(vec![vec![0xe1], vec![0xe2, 0xe3]])
                .encode()
                .expect("events")),
        ),
        (
            "ask_reply_no_events_plaintext",
            hex(&AskReply::Events(vec![]).encode().expect("events")),
        ),
        (
            "ask_reply_claim_plaintext",
            hex(&AskReply::Claim(RecoveryClaim(claim_body()))
                .encode()
                .expect("claim")),
        ),
        (
            "first_frame_wait_seconds",
            FIRST_FRAME_WAIT.as_secs().to_string(),
        ),
    ];
    let made: Vec<(String, String)> = made.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
    let printed: String = made.iter().map(|(k, v)| format!("{k} = {v}\n")).collect();
    assert_eq!(
        parse_vectors(),
        made,
        "vectors/v1.txt differs from what is made:\n{printed}"
    );
    assert_eq!(t.initiator_seen, mont_pub(&i_ed));
    assert_eq!(t.opening[0], 1, "the version byte is 1");
    assert_eq!(
        &t.opening[1..3],
        &[0, 48],
        "the first message is e and a tag"
    );
    assert_eq!(
        FIRST_FRAME_WAIT,
        Duration::from_secs(10),
        "the one wait is 10 seconds"
    );
}

/// Every run of `len` or more bytes of `needle` that is not all zeros.
fn windows(needle: &[u8], len: usize) -> Vec<&[u8]> {
    needle
        .windows(len)
        .filter(|w| w.iter().any(|&b| b != 0))
        .collect()
}

fn holds_any(hay: &[u8], needle: &[u8]) -> bool {
    windows(needle, 8)
        .iter()
        .any(|w| hay.windows(w.len()).any(|h| h == *w))
}

#[test]
fn no_durable_key_is_in_the_first_three_flights() {
    let fixed_keys = (ed(0x11), ed(0x22));
    let random_keys = (
        SigningKey::generate(&mut OsRng),
        SigningKey::generate(&mut OsRng),
    );
    for ((i_ed, r_ed), i_run, r_run) in [
        (fixed_keys, fixed(0x33), fixed(0x44)),
        (random_keys, Run::default(), Run::default()),
    ] {
        let (i_key, r_key) = (mont(&i_ed), mont(&r_ed));
        let t = whole(
            i_run,
            r_run,
            &i_key,
            &mont_pub(&r_ed),
            std::slice::from_ref(&r_key),
        );
        let clear: Vec<u8> = [&t.opening[..], &t.second[..], &t.third[..]].concat();
        let payload = t.payload_seen.encode();
        let durable: [(&str, Vec<u8>); 9] = [
            (
                "initiator Ed25519 public",
                i_ed.verifying_key().to_bytes().to_vec(),
            ),
            ("initiator Ed25519 seed", i_ed.to_bytes().to_vec()),
            (
                "initiator Montgomery public",
                mont_pub(&i_ed).to_bytes().to_vec(),
            ),
            ("initiator Montgomery private", i_key.to_bytes().to_vec()),
            (
                "responder Ed25519 public",
                r_ed.verifying_key().to_bytes().to_vec(),
            ),
            ("responder Ed25519 seed", r_ed.to_bytes().to_vec()),
            (
                "responder Montgomery public",
                mont_pub(&r_ed).to_bytes().to_vec(),
            ),
            ("responder Montgomery private", r_key.to_bytes().to_vec()),
            ("the third message's payload", payload.to_vec()),
        ];
        for (name, bytes) in durable {
            assert!(!holds_any(&clear, &bytes), "{name} crossed in the clear");
        }
        // What does cross: the version, two fresh values, three lengths, sealed bytes.
        assert_eq!(
            clear.len(),
            1 + (2 + 48) + (2 + 48) + (2 + 48 + THIRD_PAYLOAD_LEN + 16)
        );
    }
}

#[test]
fn a_responder_without_the_key_reads_one_frame_and_writes_nothing() {
    let (i_key, wanted) = (mont(&ed(0x11)), ed(0x22));
    let held = [mont(&ed(0x77)), mont(&ed(0x78))];
    let (_init, opening) =
        Initiator::open(&i_key, &mont_pub(&wanted), Some(IDENTITY), None).expect("open");
    // Bytes that follow the first frame are not read.
    let mut buf = opening.clone();
    buf.extend_from_slice(&[0xab; 100]);
    let Opening::Complete {
        version,
        first,
        consumed,
    } = read_opening(&buf)
    else {
        panic!("whole");
    };
    assert_eq!(
        consumed,
        opening.len(),
        "one frame and its version byte, no more"
    );
    // The refusal carries nothing to send: there is no frame in it.
    assert!(matches!(
        Responder::answer_opening(&held, version, first),
        Err(Closed::Refused)
    ));
    // With the key, the same bytes are answered.
    assert!(Responder::answer_opening(&[mont(&wanted)], version, first).is_ok());
}

#[test]
fn an_unspoken_version_reads_one_frame_and_writes_nothing() {
    let (i_key, r_ed) = (mont(&ed(0x11)), ed(0x22));
    let (_init, mut opening) =
        Initiator::open(&i_key, &mont_pub(&r_ed), Some(IDENTITY), None).expect("open");
    for unspoken in [0u8, 2, 0xff] {
        opening[0] = unspoken;
        let mut buf = opening.clone();
        buf.extend_from_slice(&[0xab; 100]);
        let Opening::Complete {
            version,
            first,
            consumed,
        } = read_opening(&buf)
        else {
            panic!("whole");
        };
        assert_eq!(consumed, opening.len());
        assert_eq!(version, unspoken);
        assert!(matches!(
            Responder::answer_opening(&[mont(&r_ed)], version, first),
            Err(Closed::Refused)
        ));
    }
}

#[test]
fn a_first_frame_that_never_completes_is_the_state_the_caller_times() {
    let (_init, opening) =
        Initiator::open(&mont(&ed(0x11)), &mont_pub(&ed(0x22)), None, None).expect("open");
    for cut in 0..opening.len() {
        assert_eq!(
            read_opening(&opening[..cut]),
            Opening::Incomplete,
            "cut at {cut}"
        );
    }
    assert!(matches!(read_opening(&opening), Opening::Complete { .. }));
    assert!(FIRST_FRAME_WAIT > Duration::ZERO);
}

/// Every encoding of a u-coordinate of small order that X25519 accepts: an exchange with any
/// yields all zeros. Where each comes from:
/// - the curve's points of small order have four u-coordinates: 0 (order 2), 1 (order 4),
///   and the two of order 8;
/// - p-1 is of order 4 on the twist, which X25519 also computes over, since it reads a
///   u-coordinate without checking which of the two it lies on;
/// - the rest are non-canonical encodings of those five values: p and p+1 (0 and 1 plus p,
///   which fit below 2^255), and each of the seven with the top bit set, which X25519 masks.
///
/// The check is on the exchange's output, so it refuses each.
const LOW_ORDER: [[u8; 32]; 14] = [
    // canonical
    hex32("0000000000000000000000000000000000000000000000000000000000000000"),
    hex32("0100000000000000000000000000000000000000000000000000000000000000"),
    hex32("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    hex32("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
    hex32("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
    // non-canonical: p, p+1, and each with the top bit set
    hex32("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    hex32("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    hex32("0000000000000000000000000000000000000000000000000000000000000080"),
    hex32("0100000000000000000000000000000000000000000000000000000000000080"),
    hex32("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    hex32("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880"),
    hex32("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7"),
    hex32("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    hex32("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
];

const fn hex32(s: &str) -> [u8; 32] {
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("hex"),
        }
    }
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nibble(b[2 * i]) << 4 | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

/// A static key that claims a value of low order and computes with a scalar of its own. The
/// first key the builder asks for is the static; the second, the ephemeral, is honest.
struct Claims {
    low: [u8; 32],
    handed: std::sync::atomic::AtomicBool,
}

impl snow::resolvers::CryptoResolver for Claims {
    fn resolve_rng(&self) -> Option<Box<dyn snow::types::Random>> {
        None
    }
    fn resolve_dh(&self, choice: &snow::params::DHChoice) -> Option<Box<dyn snow::types::Dh>> {
        if self.handed.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return dh::resolver().resolve_dh(choice);
        }
        Some(Box::new(Claimed {
            private: [0; 32],
            public: self.low,
        }))
    }
    fn resolve_hash(&self, _: &snow::params::HashChoice) -> Option<Box<dyn snow::types::Hash>> {
        None
    }
    fn resolve_cipher(
        &self,
        _: &snow::params::CipherChoice,
    ) -> Option<Box<dyn snow::types::Cipher>> {
        None
    }
}

struct Claimed {
    private: [u8; 32],
    public: [u8; 32],
}

impl snow::types::Dh for Claimed {
    fn name(&self) -> &'static str {
        "25519"
    }
    fn pub_len(&self) -> usize {
        32
    }
    fn priv_len(&self) -> usize {
        32
    }
    fn set(&mut self, private: &[u8]) {
        self.private.copy_from_slice(private);
    }
    fn generate(&mut self, _: &mut dyn snow::types::Random) {
        unreachable!("a static is set, never generated")
    }
    fn pubkey(&self) -> &[u8] {
        &self.public
    }
    fn privkey(&self) -> &[u8] {
        &self.private
    }
    fn dh(&self, public: &[u8], out: &mut [u8]) -> Result<(), snow::Error> {
        // snow hands its whole key buffer in; the value is its first 32 bytes.
        let public: [u8; 32] = public
            .get(..32)
            .and_then(|p| p.try_into().ok())
            .ok_or(snow::Error::Dh)?;
        let shared = StaticSecret::from(self.private).diffie_hellman(&PublicKey::from(public));
        out[..32].copy_from_slice(shared.as_bytes());
        Ok(())
    }
}

#[test]
fn a_low_order_value_closes_either_side() {
    let (i_key, r_ed) = (mont(&ed(0x11)), ed(0x22));
    let r_key = mont(&r_ed);
    for low in LOW_ORDER {
        // An initiator asked to open to a responder key of low order closes before it sends.
        assert!(matches!(
            Initiator::open(&i_key, &PublicKey::from(low), None, None),
            Err(Closed::LowOrder)
        ));

        // A responder handed a first message whose ephemeral is of low order: the exchange
        // under its own key yields zeros, and it refuses as it refuses any first message.
        let (_init, opening) = Initiator::open(&i_key, &mont_pub(&r_ed), None, None).expect("open");
        let mut first = opening[3..].to_vec();
        first[..32].copy_from_slice(&low);
        assert!(matches!(
            try_key(&Run::default(), &r_key, &first),
            Err(snow::Error::Dh)
        ));
        assert!(matches!(
            Responder::answer_opening(std::slice::from_ref(&r_key), VERSION, &first),
            Err(Closed::Refused)
        ));

        // An initiator handed a second message whose ephemeral is of low order closes.
        let (init, opening) = Initiator::open(&i_key, &mont_pub(&r_ed), None, None).expect("open");
        let (_resp, second) =
            Responder::answer_opening(std::slice::from_ref(&r_key), VERSION, &opening[3..])
                .expect("answer");
        let mut second = second[2..].to_vec();
        second[..32].copy_from_slice(&low);
        assert!(matches!(init.read_second(&second), Err(Closed::LowOrder)));

        // A responder handed a third message from a static key of low order closes: its `se`
        // meets the low-order value and yields zeros. Such a key has no private half, so the
        // initiator here claims the value while it computes with a scalar of its own.
        let mut liar = Builder::with_resolver(
            PROTOCOL_NAME.parse().expect("name"),
            Box::new(snow::resolvers::FallbackResolver::new(
                Box::new(Claims {
                    low,
                    handed: std::sync::atomic::AtomicBool::new(false),
                }),
                Box::new(snow::resolvers::RingResolver),
            )),
        )
        .prologue(&prologue(VERSION))
        .local_private_key(&[0x42; 32])
        .remote_public_key(mont_pub(&r_ed).as_bytes())
        .build_initiator()
        .expect("build");
        let first = write(&mut liar, &[]).expect("first");
        let (resp, second) =
            Responder::answer_opening(std::slice::from_ref(&r_key), VERSION, &first[2..])
                .expect("answer");
        let mut scratch = vec![0u8; MAX_FRAME_LEN];
        liar.read_message(&second[2..], &mut scratch)
            .expect("second");
        let payload = ThirdPayload {
            identity: None,
            latest: None,
            versions: Versions::spoken(),
        }
        .encode();
        let third = write(&mut liar, &payload).expect("third");
        assert!(matches!(
            resp.read_third(&third[2..]),
            Err(Closed::LowOrder)
        ));
    }
}

#[test]
fn the_version_is_bound_into_the_handshake_hash() {
    // What holds: the prologue enters Noise's handshake hash, and every handshake message is
    // sealed under that hash as associated data, so no message made under one version opens
    // under another, and no side reaches the transport without reading all three under one.
    //
    // What does not, pinned below so this test says no more than is true: the prologue
    // enters no key. Noise's chaining key mixes only the protocol name and the exchanges, so
    // with the same statics and ephemerals two versions seal under the same cipher keys (the
    // ciphertext is the same keystream; only the tags differ) and split into the same
    // transport keys. So the version is bound into the handshake's hash, under which every
    // message is sealed, as kottonllc/kotton-protocol#57 decided the handshake page says.
    let (i_ed, r_ed) = (ed(0x11), ed(0x22));
    let (i_key, r_key) = (mont(&i_ed), mont(&r_ed));
    let run = |version: u8, e: u8| Run {
        version,
        speaks: Versions::of(&[version]).expect("versions"),
        ephemeral: Some(Zeroizing::new([e; 32])),
    };
    let at = |version: u8| {
        whole(
            run(version, 0x33),
            run(version, 0x44),
            &i_key,
            &mont_pub(&r_ed),
            std::slice::from_ref(&r_key),
        )
    };
    let (mut one, mut two) = (at(1), at(2));

    // Holds: no handshake message opens across versions.
    // es: a responder under version 2 opens no first message made under 1.
    assert!(matches!(
        try_key(&run(2, 0x44), &r_key, &one.opening[3..]),
        Err(snow::Error::Decrypt)
    ));
    // ee: an initiator under version 1 opens no second message made under 2.
    let (init, _) =
        Initiator::open_with(run(1, 0x33), &i_key, &mont_pub(&r_ed), Some(IDENTITY), None)
            .expect("open");
    assert!(matches!(
        init.read_second(&two.second[2..]),
        Err(Closed::Unopened)
    ));
    // se: a responder under version 2 opens no third message made under 1.
    let (resp, _) = Responder::answer_with(
        run(2, 0x44),
        std::slice::from_ref(&r_key),
        &two.opening[3..],
    )
    .expect("answer");
    assert!(matches!(
        resp.read_third(&one.third[2..]),
        Err(Closed::Unopened)
    ));
    // Each message's tag is made under the hash, so each differs.
    assert_ne!(
        one.opening[35..51],
        two.opening[35..51],
        "es: the first message's tag"
    );
    assert_ne!(
        one.second[34..50],
        two.second[34..50],
        "ee: the second message's tag"
    );
    assert_ne!(
        one.third[34..50],
        two.third[34..50],
        "the third message's static's tag"
    );
    assert_ne!(
        one.third[156..],
        two.third[156..],
        "se: the third message's payload's tag"
    );

    // Does not hold: the same exchanges give the same keys under either version.
    assert_eq!(one.opening[3..35], two.opening[3..35], "the same ephemeral");
    assert_eq!(one.second[2..34], two.second[2..34], "the same ephemeral");
    assert_eq!(
        one.third[2..34],
        two.third[2..34],
        "the initiator's static is sealed under the same key and nonce: equal ciphertext"
    );
    // The two payloads differ only in their version sets, and their ciphertexts differ by
    // exactly as much: one keystream.
    let xor = |a: &[u8], b: &[u8]| a.iter().zip(b).map(|(x, y)| x ^ y).collect::<Vec<u8>>();
    assert_eq!(
        xor(&one.third[50..156], &two.third[50..156]),
        xor(&one.payload_seen.encode(), &two.payload_seen.encode()),
        "the payload is sealed under the same key under either version"
    );
    // The transport keys are equal: the same plaintext seals to the same frame on each side.
    assert_eq!(
        one.initiator_channel.seal(b"same").expect("seal"),
        two.initiator_channel.seal(b"same").expect("seal"),
        "the initiator's transport key is the same under either version"
    );
    assert_eq!(
        one.responder_channel.seal(b"same").expect("seal"),
        two.responder_channel.seal(b"same").expect("seal"),
        "the responder's transport key is the same under either version"
    );
}

#[test]
fn a_frame_longer_than_65535_is_refused() {
    assert_eq!(frame(&vec![0; 65536]), Err(Closed::TooLong));
    assert_eq!(
        frame(&vec![0; 65535]).expect("the longest frame").len(),
        2 + 65535
    );
    let (i_ed, r_ed) = (ed(0x11), ed(0x22));
    let mut t = whole(
        Run::default(),
        Run::default(),
        &mont(&i_ed),
        &mont_pub(&r_ed),
        &[mont(&r_ed)],
    );
    assert!(matches!(
        t.initiator_channel.seal(&vec![0; MAX_FRAME_PLAINTEXT + 1]),
        Err(Closed::TooLong)
    ));
    let longest = t
        .initiator_channel
        .seal(&vec![7; MAX_FRAME_PLAINTEXT])
        .expect("fits");
    assert_eq!(longest.len(), 2 + 65535);
    assert_eq!(&longest[..2], &[0xff, 0xff]);
    assert_eq!(
        t.responder_channel.open(&longest[2..]).expect("opens"),
        vec![7; MAX_FRAME_PLAINTEXT]
    );
    assert!(matches!(
        t.responder_channel.open(&vec![0; 65536]),
        Err(Closed::TooLong)
    ));
}

#[test]
fn a_responder_with_several_keys_answers_under_the_one_the_message_opens() {
    let i_key = mont(&ed(0x11));
    let eds = [ed(0x21), ed(0x22), ed(0x23)];
    let keys: Vec<StaticSecret> = eds.iter().map(mont).collect();
    for (i, named) in eds.iter().enumerate() {
        let t = whole(
            Run::default(),
            Run::default(),
            &i_key,
            &mont_pub(named),
            &keys,
        );
        assert_eq!(
            t.key_index, i,
            "answered under the key the first message names"
        );
        assert_eq!(t.initiator_seen, PublicKey::from(&i_key));
        assert_eq!(t.payload_seen.identity, Some(IDENTITY));
    }
}

#[test]
fn both_speaking_a_later_version_close() {
    let (i_ed, r_ed) = (ed(0x11), ed(0x22));
    let (i_key, r_key) = (mont(&i_ed), mont(&r_ed));
    let attempt = |i_speaks: &[u8], r_speaks: &[u8]| {
        let (init, opening) = Initiator::open_with(
            speaking(1, i_speaks),
            &i_key,
            &mont_pub(&r_ed),
            Some(IDENTITY),
            None,
        )
        .expect("open");
        let (resp, second) = Responder::answer_with(
            speaking(opening[0], r_speaks),
            std::slice::from_ref(&r_key),
            &opening[3..],
        )
        .expect("answer");
        let (awaiting, third) = init.read_second(&second[2..]).expect("second");
        let (first, responder) = resp
            .read_third(&third[2..])
            .expect("third")
            .answer(Answer::AskForEvents)
            .expect("answer");
        let initiator = awaiting.read_first(&first[2..]).map(|(_, a)| a);
        (responder.map(|_| ()), initiator)
    };
    // Both speak 2 and run 1: each side closes, the responder once its first frame is sent.
    let (responder, initiator) = attempt(&[1, 2], &[1, 2]);
    assert_eq!(responder, Err(Closed::LaterVersion));
    assert_eq!(initiator, Err(Closed::LaterVersion));
    // Where only one side speaks 2, version 1 is the latest both speak and the channel stays.
    for (i, r) in [(&[1u8, 2][..], &[1u8][..]), (&[1], &[1, 2])] {
        let (responder, initiator) = attempt(i, r);
        assert_eq!(responder, Ok(()));
        assert_eq!(initiator, Ok(Answer::AskForEvents));
    }
}

#[test]
fn the_responder_tries_every_key_on_every_first_frame() {
    let i_key = mont(&ed(0x11));
    let eds = [ed(0x21), ed(0x22), ed(0x23)];
    let keys: Vec<StaticSecret> = eds.iter().map(mont).collect();
    let trials = |version: u8, first: &[u8]| {
        TRIALS.with(|t| t.set(0));
        let answered = Responder::answer_opening(&keys, version, first).map(|r| r.0.key_index());
        (TRIALS.with(|t| t.get()), answered)
    };
    for (i, named) in eds.iter().enumerate() {
        let (_init, opening) = Initiator::open(&i_key, &mont_pub(named), None, None).expect("open");
        // Named first, second or third: all three keys are tried.
        assert_eq!(trials(VERSION, &opening[3..]), (3, Ok(i)));
        // An unspoken version: all three are tried before it is refused.
        assert_eq!(trials(2, &opening[3..]), (3, Err(Closed::Refused)));
    }
    // A first message no key opens: all three are tried.
    let (_init, opening) = Initiator::open(&i_key, &mont_pub(&ed(0x77)), None, None).expect("open");
    assert_eq!(trials(VERSION, &opening[3..]), (3, Err(Closed::Refused)));

    // A first message made under an unspoken version's prologue, to a key the responder
    // holds: that key opens it, all three are tried, and the version alone refuses it.
    for named in &eds {
        let (_init, opening) = Initiator::open_with(
            speaking(2, &[1, 2]),
            &i_key,
            &mont_pub(named),
            Some(IDENTITY),
            None,
        )
        .expect("open");
        assert_eq!(opening[0], 2);
        assert_eq!(trials(2, &opening[3..]), (3, Err(Closed::Refused)));
    }

    // The length gate: a first frame that is not 48 bytes is refused with no trial.
    let (_init, opening) = Initiator::open(&i_key, &mont_pub(&eds[0]), None, None).expect("open");
    let mut long = opening[3..].to_vec();
    long.push(0);
    assert_eq!(trials(VERSION, &opening[3..50]), (0, Err(Closed::Refused)));
    assert_eq!(trials(VERSION, &long), (0, Err(Closed::Refused)));
    assert_eq!((opening[3..50].len(), long.len()), (47, 49));
}
