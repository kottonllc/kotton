// SPDX-License-Identifier: AGPL-3.0-or-later
//! A relay's circuit, carrying the handshake, through a **real** `kotton-relay` process.
//!
//! A target holds a reservation under a label and answers at a door under its own key; a
//! dialer opens a circuit to the label and runs the handshake to that key over the
//! relay-bridged WebSocket (kotton-protocol's *One handshake admits a device, by the
//! identity's log*). Where a case reads what the relay saw, every connection to the relay
//! passes through a tap that keeps each byte both ways, and the WebSocket frames are read
//! back out of it as the relay reads them.
//!
//! # Running
//!
//! ```sh
//! KOTTON_PAIR_LOCAL_ONLY=1 cargo test -p kotton-integration-tests --test suite -- relay_circuit::
//! ```
//!
//! Starts a `kotton-relay` of its own (`common::relay::spawn`, which asks `common::bins`
//! for the built binary and fails naming it when it is not). `KOTTON_RELAY_ADDR` names a
//! relay already running to use in its place.

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use kotton_crypto::DidKeyMethod;
use kotton_net::transport::quic::tls::Admission;
use kotton_net::transport::relayed::{CircuitOffer, Door, RelayClient, FIRST_FRAME_WAIT};
use kotton_net::transport::{rendezvous_dial, AwaitingAnswer, HeldKeys, MakesClaim, RecoveryClaim};
use kotton_wire::handshake::{RESPONDER_FRAME_LEN, TAG_LEN, THIRD_PAYLOAD_LEN};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn random_key() -> SigningKey {
    SigningKey::generate(&mut rand::rngs::OsRng)
}

fn pub_of(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

fn did_of(pubkey: &[u8; 32]) -> String {
    DidKeyMethod::from_public_key_bytes(pubkey).unwrap().to_string()
}

fn montgomery(k: &SigningKey) -> [u8; 32] {
    kotton_crypto::x25519::ed25519_pub_to_x25519(&kotton_crypto::ed25519::verifying_key(k)).to_bytes()
}

/// A recovery authority held by the test, as `recover` holds one: the circuit is handed this,
/// and it makes one claim for the connection it is shown.
struct Authority(SigningKey);

impl MakesClaim for Authority {
    fn claim(&self, awaiting: &AwaitingAnswer) -> Option<RecoveryClaim> {
        awaiting.claim(
            &kotton_crypto::x25519::ed25519_priv_to_x25519(&self.0),
            pub_of(&self.0),
        )
    }
}

fn claiming(authority: &SigningKey) -> CircuitOffer {
    CircuitOffer {
        events: Vec::new(),
        claim: Some(Arc::new(Authority(authority.clone()))),
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// The first message, and the second: an ephemeral value and an empty payload's tag.
const EPHEMERAL_FRAME: usize = 32 + TAG_LEN;
/// The third message: the sealed static, then the sealed payload.
const THIRD_FRAME: usize = 32 + TAG_LEN + THIRD_PAYLOAD_LEN + TAG_LEN;
/// The responder's first frame, sealed.
const FIRST_ANSWER: usize = RESPONDER_FRAME_LEN + TAG_LEN;

/// A door holding a reservation under its own label, answering under `door_key`, admitting
/// whom `admits` admits, and echoing every request it is sent. Returns the label, the task
/// and how many requests were served.
async fn hold_door(
    relay_url: &str,
    door_key: &SigningKey,
    admits: HeldKeys,
) -> (String, tokio::task::JoinHandle<()>, Arc<AtomicUsize>) {
    let label_key = random_key();
    let label = did_of(&pub_of(&label_key));
    let client = RelayClient::new(relay_url, label.clone(), label_key);
    let door = Door::new(std::slice::from_ref(door_key), Arc::new(admits)).unwrap();
    let served = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&served);
    let task = tokio::spawn(async move {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let reservation = tokio::spawn(async move { client.run_reservation(door, tx).await });
        while let Some(conn) = rx.recv().await {
            let count = Arc::clone(&count);
            tokio::spawn(async move {
                while let Ok(true) = conn
                    .serve_one_request(|req| async move {
                        let mut resp = b"echo:".to_vec();
                        resp.extend_from_slice(&req);
                        resp
                    })
                    .await
                {
                    count.fetch_add(1, Ordering::SeqCst);
                }
            });
        }
        reservation.abort();
    });
    // Let the reservation register on the relay.
    tokio::time::sleep(Duration::from_millis(500)).await;
    (label, task, served)
}

fn admitting(keys: &[[u8; 32]], admission: Admission) -> HeldKeys {
    HeldKeys::new(
        Arc::new(RwLock::new(keys.iter().map(|k| kotton_crypto::ed25519::VerifyingKey::from_bytes(k).unwrap()).collect::<HashSet<_>>())),
        admission,
    )
}

/// A dial to `label` as `own`, to the door whose key is `door`.
async fn dial(
    relay_url: &str,
    label: &str,
    own: &SigningKey,
    door: &SigningKey,
    offer: &CircuitOffer,
) -> Result<kotton_net::transport::RelayedDial, kotton_sys::net::TransportError> {
    let label_key = random_key();
    RelayClient::new(relay_url, did_of(&pub_of(&label_key)), label_key)
        .dial(label, own, &pub_of(door), offer)
        .await
}

// ── The tap ───────────────────────────────────────────────────────────────────

/// One TCP connection to the relay, both ways, as it crossed.
#[derive(Default, Clone)]
struct Leg {
    up: Vec<u8>,
    down: Vec<u8>,
}

type Legs = Arc<Mutex<Vec<Arc<Mutex<Leg>>>>>;

/// A listener that forwards every connection to `relay_addr` and keeps what crossed.
async fn tap(relay_addr: &str) -> (String, Legs) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let legs: Legs = Arc::default();
    let all = Arc::clone(&legs);
    let relay_addr = relay_addr.to_string();
    tokio::spawn(async move {
        while let Ok((near, _)) = listener.accept().await {
            let Ok(far) = tokio::net::TcpStream::connect(&relay_addr).await else {
                continue;
            };
            let leg = Arc::new(Mutex::new(Leg::default()));
            all.lock().unwrap().push(Arc::clone(&leg));
            let (mut near_r, mut near_w) = near.into_split();
            let (mut far_r, mut far_w) = far.into_split();
            let up = Arc::clone(&leg);
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                while let Ok(n) = near_r.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    up.lock().unwrap().up.extend_from_slice(&buf[..n]);
                    if far_w.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                let _ = far_w.shutdown().await;
            });
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                while let Ok(n) = far_r.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    leg.lock().unwrap().down.extend_from_slice(&buf[..n]);
                    if near_w.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                let _ = near_w.shutdown().await;
            });
        }
    });
    (addr, legs)
}

/// One direction of a WebSocket connection, read as the relay reads it: the HTTP head, the
/// binary payloads in order and unmasked, and the close frames' payloads.
struct Read {
    head: Vec<u8>,
    binary: Vec<u8>,
    closes: Vec<Vec<u8>>,
}

fn read_ws(raw: &[u8]) -> Read {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .unwrap_or(raw.len());
    let (head, mut rest) = raw.split_at(end);
    let mut out = Read {
        head: head.to_vec(),
        binary: Vec::new(),
        closes: Vec::new(),
    };
    while rest.len() >= 2 {
        let opcode = rest[0] & 0x0f;
        let masked = rest[1] & 0x80 != 0;
        let (len, mut at) = match rest[1] & 0x7f {
            126 if rest.len() >= 4 => (usize::from(u16::from_be_bytes([rest[2], rest[3]])), 4),
            127 if rest.len() >= 10 => (
                usize::try_from(u64::from_be_bytes(rest[2..10].try_into().unwrap())).unwrap(),
                10,
            ),
            n if n < 126 => (usize::from(n), 2),
            _ => break,
        };
        let mask = if masked {
            if rest.len() < at + 4 {
                break;
            }
            let m = [rest[at], rest[at + 1], rest[at + 2], rest[at + 3]];
            at += 4;
            Some(m)
        } else {
            None
        };
        if rest.len() < at + len {
            break;
        }
        let mut payload = rest[at..at + len].to_vec();
        if let Some(m) = mask {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= m[i % 4];
            }
        }
        match opcode {
            0 | 2 => out.binary.extend_from_slice(&payload),
            8 => out.closes.push(payload),
            _ => {}
        }
        rest = &rest[at + len..];
    }
    out
}

/// The handshake's frames in `stream`, each behind its two-byte length; `None` unless the
/// stream is those frames and nothing else.
fn frames(mut stream: &[u8]) -> Option<Vec<&[u8]>> {
    let mut out = Vec::new();
    while !stream.is_empty() {
        let len = usize::from(u16::from_be_bytes([*stream.first()?, *stream.get(1)?]));
        out.push(stream.get(2..2 + len)?);
        stream = &stream[2 + len..];
    }
    Some(out)
}

/// A data leg of one circuit, as the relay saw it: the dialer's (`/relay/open`) or the
/// door's dial-back (`/relay/accept`).
struct DataLeg {
    up: Read,
    down: Read,
}

fn data_legs(legs: &Legs, path: &str) -> Vec<DataLeg> {
    let start = format!("GET {path}");
    legs.lock()
        .unwrap()
        .iter()
        .map(|l| l.lock().unwrap().clone())
        .filter(|l| l.up.starts_with(start.as_bytes()))
        .map(|l| DataLeg {
            up: read_ws(&l.up),
            down: read_ws(&l.down),
        })
        .collect()
}

fn everything(legs: &Legs) -> Vec<u8> {
    let mut all = Vec::new();
    for l in legs.lock().unwrap().iter() {
        let l = l.lock().unwrap().clone();
        for raw in [&l.up, &l.down] {
            all.extend_from_slice(raw);
            let read = read_ws(raw);
            all.extend_from_slice(&read.binary);
            for c in read.closes {
                all.extend_from_slice(&c);
            }
        }
    }
    all
}

// ── The cases ─────────────────────────────────────────────────────────────────

/// A door admits the key it holds, and the two exchange a request through a real relay.
#[tokio::test]
async fn relayed_circuit_through_real_relay_carries_the_handshake() {
    let (_relay, relay_addr) = crate::common::relay::spawn().await;
    let relay_url = format!("http://{relay_addr}");
    let (a, b) = (random_key(), random_key());
    let (label, door, served) = hold_door(&relay_url, &b, admitting(&[pub_of(&a)], Admission::default())).await;

    let conn = dial(&relay_url, &label, &a, &b, &CircuitOffer::default())
        .await
        .expect("A: dial via relay");
    assert_eq!(conn.peer_did(), Some(did_of(&pub_of(&b)).as_str()), "A names the key it dialled");
    let resp = conn.request(b"ping").await.expect("A: request");
    assert_eq!(resp, b"echo:ping");
    assert_eq!(served.load(Ordering::SeqCst), 1);
    door.abort();
}

/// The relay sees a version, two fresh values, lengths and ciphertext. A tap records both
/// legs of four circuits: two from a device the door admits by its key, one from a
/// recovered device admitted by the rotation it offers, and one from a device that holds only
/// a recovery authority, admitted by its claim. Neither side's static key is in what it saw,
/// in either form or as a `did:key`, nor the authority's; nor a certificate, a server name,
/// the event, the identity, or the request.
#[tokio::test]
async fn the_relay_sees_a_version_two_fresh_values_lengths_and_ciphertext() {
    use kotton_crypto::kel_verify::{build_inception, build_mnemonic_rotation, kel_recovery_pubkey};

    let (_relay, relay_addr) = crate::common::relay::spawn().await;
    let (tap_addr, legs) = tap(&relay_addr).await;
    let relay_url = format!("http://{tap_addr}");

    let (a, b, recovered) = (random_key(), random_key(), random_key());
    let (claimant, authority) = (random_key(), random_key());
    let seed = [7u8; 32];
    let rung = |i| kel_recovery_pubkey(&kotton_crypto::kdf::derive_kel_recovery_key(&seed, i));
    let committed = [rung(0), pub_of(&authority)];
    let tip = build_inception(&random_key(), &committed);
    let rotation = build_mnemonic_rotation(&tip, &seed, 0, &recovered, 0, &committed);
    let admission = Admission::default();
    admission.learn_chain(std::slice::from_ref(&tip));
    let (label, door, served) =
        hold_door(&relay_url, &b, admitting(&[pub_of(&a)], admission.clone())).await;

    let secret = b"a request the relay must not read".to_vec();
    for (own, offer) in [
        (&a, CircuitOffer::default()),
        (&a, CircuitOffer::default()),
        (
            &recovered,
            CircuitOffer {
                events: vec![rotation.clone()],
                claim: None,
            },
        ),
        (&claimant, claiming(&authority)),
    ] {
        let conn = dial(&relay_url, &label, own, &b, &offer).await.expect("the dial");
        assert_eq!(conn.request(&secret).await.unwrap()[5..], secret[..]);
    }
    assert_eq!(served.load(Ordering::SeqCst), 4);
    let pending = admission.admitted.read().unwrap().clone();
    assert!(
        !pending.contains_key(&pub_of(&claimant)) && pending.len() == 1,
        "the claim is the circuit's, and is written to no shared table"
    );
    door.abort();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // The control: the tap sees what the relay sees, the label a dial names included.
    let opens = data_legs(&legs, "/relay/open");
    let accepts = data_legs(&legs, "/relay/accept");
    assert_eq!((opens.len(), accepts.len()), (4, 4), "four circuits, both legs each");
    for open in &opens {
        assert!(contains(&open.up.head, label.as_bytes()), "the tap reads the dial's label");
    }

    let mut ephemerals = Vec::new();
    for open in &opens {
        let sent = &open.up.binary;
        assert_eq!(sent[0], kotton_wire::handshake::VERSION_1, "a version byte first");
        let sent_frames = frames(&sent[1..]).expect("then frames behind their lengths, only");
        let got_frames = frames(&open.down.binary).expect("frames behind their lengths, only");
        assert_eq!(sent_frames[0].len(), EPHEMERAL_FRAME);
        assert_eq!(sent_frames[1].len(), THIRD_FRAME);
        assert_eq!(got_frames[0].len(), EPHEMERAL_FRAME);
        assert_eq!(got_frames[1].len(), FIRST_ANSWER);
        ephemerals.push(sent_frames[0][..32].to_vec());
        ephemerals.push(got_frames[0][..32].to_vec());
        // The door's leg carries the same bytes, each way: the relay forwards and reads none.
        assert!(
            accepts
                .iter()
                .any(|acc| acc.down.binary == open.up.binary && acc.up.binary == open.down.binary),
            "the door's leg is the dialer's, reversed"
        );
    }
    let distinct: HashSet<&Vec<u8>> = ephemerals.iter().collect();
    assert_eq!(distinct.len(), ephemerals.len(), "every ephemeral value is fresh");

    let saw = everything(&legs);
    let event = serde_json::to_vec(&rotation).unwrap();
    let mut needles: Vec<(String, Vec<u8>)> = Vec::new();
    for (who, k) in [
        ("the door", &b),
        ("the dialer", &a),
        ("the recovered device", &recovered),
        ("the claimant", &claimant),
        ("the recovery authority", &authority),
    ] {
        needles.push((format!("{who}'s key"), pub_of(k).to_vec()));
        needles.push((format!("{who}'s key, Montgomery form"), montgomery(k).to_vec()));
        needles.push((format!("{who}'s did:key"), did_of(&pub_of(k)).into_bytes()));
    }
    needles.extend([
        ("a certificate's name".into(), b"kotton-device".to_vec()),
        ("an Ed25519 certificate key's OID".into(), vec![0x06, 0x03, 0x2b, 0x65, 0x70]),
        ("a server name".into(), b"kotton-peer".to_vec()),
        ("a server name".into(), b"localhost".to_vec()),
        ("the event".into(), event),
        ("the event's identity".into(), tip.aid.to_string().into_bytes()),
        ("the event's key".into(), rotation.key_state.group_key.to_vec()),
        ("the request".into(), secret),
    ]);
    for (what, needle) in needles {
        assert!(!contains(&saw, &needle), "the relay saw {what}");
    }
}

/// One who opens a circuit to a door's label without the door's key, the relay itself
/// among them, is sent nothing: not on a first frame under another key, not on a frame of
/// the wrong length, and not on silence, which is closed on once the first frame's wait runs
/// out. The door answers a dial under its key afterwards as before.
#[tokio::test]
async fn a_relay_that_opens_a_circuit_itself_is_sent_nothing() {
    let (_relay, relay_addr) = crate::common::relay::spawn().await;
    let relay_url = format!("http://{relay_addr}");
    let (a, b) = (random_key(), random_key());
    let (label, door, served) =
        hold_door(&relay_url, &b, admitting(&[pub_of(&a)], Admission::default())).await;

    let mut under_another_key = vec![kotton_wire::handshake::VERSION_1, 0, EPHEMERAL_FRAME as u8];
    under_another_key.extend((0..EPHEMERAL_FRAME).map(|_| rand::random::<u8>()));
    let wrong_length = vec![kotton_wire::handshake::VERSION_1, 0, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let unspoken_version = {
        let mut v = under_another_key.clone();
        v[0] = 2;
        v
    };
    for (what, sent) in [
        ("a first frame under another key", under_another_key),
        ("a first frame of the wrong length", wrong_length),
        ("a version the door does not speak", unspoken_version),
        ("nothing", Vec::new()),
    ] {
        let opener = random_key();
        let mut raw = rendezvous_dial(&relay_url, &did_of(&pub_of(&opener)), &opener, &label, None)
            .await
            .expect("anyone may open a circuit to a reservation");
        let started = std::time::Instant::now();
        raw.write_all(&sent).await.unwrap();
        raw.flush().await.unwrap();
        let mut got = Vec::new();
        let read = tokio::time::timeout(FIRST_FRAME_WAIT + Duration::from_secs(5), raw.read_to_end(&mut got)).await;
        assert!(read.is_ok(), "{what}: the door closed the circuit");
        assert!(got.is_empty(), "{what}: the door sent {} bytes", got.len());
        if sent.is_empty() {
            assert!(
                started.elapsed() >= FIRST_FRAME_WAIT - Duration::from_millis(500),
                "silence is held for the first frame's wait"
            );
        }
    }
    assert_eq!(served.load(Ordering::SeqCst), 0);

    let conn = dial(&relay_url, &label, &a, &b, &CircuitOffer::default())
        .await
        .expect("the door still answers its key");
    assert_eq!(conn.request(b"ping").await.unwrap(), b"echo:ping");
    door.abort();
}

/// A key the door does not admit completes the handshake, since it holds the door's key, and
/// is asked for its events in the one form; whatever it answers with, none, an event that
/// does not admit it or a claim by an authority the door holds no identity for, the circuit
/// closes and it is sent nothing more: no event, no reason. Every refusal reads the same
/// length, and no request reaches the handler.
#[tokio::test]
async fn a_key_the_door_does_not_admit_is_closed_on_without_a_word() {
    use kotton_crypto::kel_verify::{build_inception, build_mnemonic_rotation, kel_recovery_pubkey};

    let (_relay, relay_addr) = crate::common::relay::spawn().await;
    let (tap_addr, legs) = tap(&relay_addr).await;
    let relay_url = format!("http://{tap_addr}");
    let (a, b) = (random_key(), random_key());
    let (label, door, served) =
        hold_door(&relay_url, &b, admitting(&[pub_of(&a)], Admission::default())).await;

    let seed = [9u8; 32];
    let rung = |i| kel_recovery_pubkey(&kotton_crypto::kdf::derive_kel_recovery_key(&seed, i));
    let stranger = random_key();
    let tip = build_inception(&random_key(), &[rung(0)]);
    let rotation = build_mnemonic_rotation(&tip, &seed, 0, &stranger, 0, &[rung(0)]);
    for offer in [
        CircuitOffer::default(),
        CircuitOffer {
            events: vec![rotation],
            claim: None,
        },
        claiming(&random_key()),
    ] {
        let refused = dial(&relay_url, &label, &stranger, &b, &offer).await;
        assert!(refused.is_err(), "{offer:?}: the stranger is not admitted");
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(served.load(Ordering::SeqCst), 0, "no request reached the handler");

    let opens = data_legs(&legs, "/relay/open");
    assert_eq!(opens.len(), 3);
    for open in &opens {
        let got = frames(&open.down.binary).expect("frames behind their lengths, only");
        let lens: Vec<usize> = got.iter().map(|f| f.len()).collect();
        assert_eq!(
            lens,
            vec![EPHEMERAL_FRAME, FIRST_ANSWER],
            "the second message and the ask, and nothing after"
        );
        for close in &open.down.closes {
            assert!(close.len() <= 2, "a close carries no reason: {close:?}");
        }
    }
    door.abort();
}

// ── How a dialer's leg ends ───────────────────────────────────────────────────

/// A recovery authority's claim-maker that names one key and holds another: its tag answers
/// no claim by the key it names.
struct Misnamed {
    holds: SigningKey,
    names: [u8; 32],
}

impl MakesClaim for Misnamed {
    fn claim(&self, awaiting: &AwaitingAnswer) -> Option<RecoveryClaim> {
        awaiting.claim(&kotton_crypto::x25519::ed25519_priv_to_x25519(&self.holds), self.names)
    }
}

/// How a dialer's leg ends once the relay ends its side: as the relay ends it, with a
/// WebSocket close, or with a TCP reset. A close the relay sends is withheld from the last two,
/// so that the dialer meets the ending named and no other.
#[derive(Clone, Copy, Debug)]
enum Ending {
    AsTheRelayEndsIt,
    Close,
    Reset,
}

/// A frame at the front of `buf` from the relay (unmasked): its opcode and whole length, once
/// it is all there.
fn whole_frame(buf: &[u8]) -> Option<(u8, usize)> {
    let (len, at) = match *buf.get(1)? & 0x7f {
        126 => (usize::from(u16::from_be_bytes([*buf.get(2)?, *buf.get(3)?])), 4),
        127 => (usize::try_from(u64::from_be_bytes(buf.get(2..10)?.try_into().ok()?)).ok()?, 10),
        n => (usize::from(n), 2),
    };
    (buf.len() >= at + len).then(|| (buf[0] & 0x0f, at + len))
}

/// A listener that forwards each connection to `relay_addr` and ends each dialer's leg as
/// `ending` says, once the relay has ended its side.
async fn ending_tap(relay_addr: &str, ending: Ending) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let relay_addr = relay_addr.to_string();
    tokio::spawn(async move {
        while let Ok((mut near, _)) = listener.accept().await {
            let Ok(mut far) = tokio::net::TcpStream::connect(&relay_addr).await else {
                continue;
            };
            tokio::spawn(async move {
                let (mut up, mut down) = ([0u8; 8192], [0u8; 8192]);
                // What the relay sent and the dialer has not been given: its HTTP head until
                // that is through, then frames until each is whole.
                let (mut pending, mut head_through) = (Vec::new(), false);
                'forward: loop {
                    tokio::select! {
                        n = near.read(&mut up) => match n {
                            Ok(0) | Err(_) => return,
                            Ok(n) => {
                                if far.write_all(&up[..n]).await.is_err() {
                                    return;
                                }
                            }
                        },
                        n = far.read(&mut down) => match n {
                            Ok(0) | Err(_) => break 'forward,
                            Ok(n) => {
                                pending.extend_from_slice(&down[..n]);
                                if !head_through {
                                    let Some(end) = pending.windows(4).position(|w| w == b"\r\n\r\n") else {
                                        continue 'forward;
                                    };
                                    let head: Vec<u8> = pending.drain(..end + 4).collect();
                                    if near.write_all(&head).await.is_err() {
                                        return;
                                    }
                                    head_through = true;
                                }
                                while let Some((opcode, len)) = whole_frame(&pending) {
                                    if opcode == 8 && !matches!(ending, Ending::AsTheRelayEndsIt) {
                                        break 'forward;
                                    }
                                    let frame: Vec<u8> = pending.drain(..len).collect();
                                    if near.write_all(&frame).await.is_err() {
                                        return;
                                    }
                                }
                            }
                        },
                    }
                }
                match ending {
                    Ending::AsTheRelayEndsIt => {
                        let _ = near.shutdown().await;
                    }
                    Ending::Close => {
                        // A close, normal closure, from the server's side and so unmasked.
                        let _ = near.write_all(&[0x88, 0x02, 0x03, 0xe8]).await;
                        let _ = near.shutdown().await;
                    }
                    Ending::Reset => {
                        let _ = near.set_zero_linger();
                        drop(near);
                    }
                }
            });
        }
    });
    addr
}

/// Every refusal a dialer can meet at a relayed door's admit stage, over a real relay, reads
/// the circuit closing and nothing else, whether its leg ends as the relay ends it, in a
/// close or in a reset (kotton-protocol's *One handshake admits a device, by the identity's
/// log*: a refusal is the circuit closing, and no frame says why). Each is set beside a dial
/// the same door admits, and each is met when the door refuses, well before any wait runs out.
#[tokio::test]
async fn every_refusal_at_the_door_reads_the_circuit_closing_however_the_leg_ends() {
    use kotton_crypto::kel_verify::{build_inception, build_mnemonic_rotation, kel_recovery_pubkey};

    let (_relay, relay_addr) = crate::common::relay::spawn().await;
    let relay_url = format!("http://{relay_addr}");

    // One door: a key it admits, a tip it hosts and an identity whose inception commits
    // `authority`.
    let (door_key, held, stranger, recovered, claimant) =
        (random_key(), random_key(), random_key(), random_key(), random_key());
    let seed = [11u8; 32];
    let rung = |seed: &[u8; 32], i| kel_recovery_pubkey(&kotton_crypto::kdf::derive_kel_recovery_key(seed, i));
    let authority = random_key();
    let committed = [rung(&seed, 0), pub_of(&authority)];
    let tip = build_inception(&random_key(), &committed);
    let rotation = build_mnemonic_rotation(&tip, &seed, 0, &recovered, 0, &committed);
    let other_seed = [12u8; 32];
    let unadmitted = build_mnemonic_rotation(&tip, &other_seed, 0, &stranger, 0, &[rung(&other_seed, 0)]);
    let elsewhere = build_inception(&random_key(), &[rung(&seed, 0)]);
    let unhosted = build_mnemonic_rotation(&elsewhere, &seed, 0, &stranger, 0, &[rung(&seed, 0)]);
    let admission = Admission::default();
    admission.learn_chain(std::slice::from_ref(&tip));
    let (label, door, served) = hold_door(&relay_url, &door_key, admitting(&[pub_of(&held)], admission)).await;

    let offering = |events| CircuitOffer { events, claim: None };
    let misnamed = |names| CircuitOffer {
        events: Vec::new(),
        claim: Some(Arc::new(Misnamed { holds: random_key(), names })),
    };
    let not_a_point = (0u8..=u8::MAX)
        .map(|n| [n; 32])
        .find(|b| ed25519_dalek::VerifyingKey::from_bytes(b).is_err())
        .unwrap();
    let wrong_door = random_key();
    let by_key = (&held, &door_key, CircuitOffer::default());
    let by_events = (&recovered, &door_key, offering(vec![rotation.clone()]));
    let by_claim = (&claimant, &door_key, claiming(&authority));
    // What is refused: the dial the door refuses (as whom, towards which key, offering what),
    // and the one it admits.
    type Dial<'a> = (&'a SigningKey, &'a SigningKey, CircuitOffer);
    let cases: [(&str, Dial, &Dial); 8] = [
        ("a door dialled under another key", (&held, &wrong_door, CircuitOffer::default()), &by_key),
        ("a key the door does not hold, offering nothing", (&stranger, &door_key, CircuitOffer::default()), &by_key),
        (
            "events for an identity the door does not host",
            (&stranger, &door_key, offering(vec![unhosted])),
            &by_events,
        ),
        ("events that name another key", (&stranger, &door_key, offering(vec![rotation.clone()])), &by_events),
        (
            "events naming the dialer that the hosted tip does not admit",
            (&stranger, &door_key, offering(vec![unadmitted])),
            &by_events,
        ),
        ("a claim by an authority no hosted identity holds", (&claimant, &door_key, claiming(&random_key())), &by_claim),
        (
            "a claim whose tag the authority it names did not make",
            (&claimant, &door_key, misnamed(pub_of(&authority))),
            &by_claim,
        ),
        ("a claim whose named key is no point", (&claimant, &door_key, misnamed(not_a_point)), &by_claim),
    ];

    let mut taps = Vec::new();
    for ending in [Ending::AsTheRelayEndsIt, Ending::Close, Ending::Reset] {
        taps.push((ending, format!("http://{}", ending_tap(&relay_addr, ending).await)));
    }
    let one = format!("{:?}", kotton_sys::net::TransportError::ConnectionFailed("the circuit closed".into()));
    let mut admitted = 0;
    for (what, (own, towards, offer), (a_own, a_towards, a_offer)) in &cases {
        for (ending, tap_url) in &taps {
            let conn = dial(tap_url, &label, a_own, a_towards, a_offer)
                .await
                .unwrap_or_else(|e| panic!("{what}, {ending:?}: the same door admits its counterpart: {e:?}"));
            assert_eq!(conn.request(b"ping").await.unwrap(), b"echo:ping");
            admitted += 1;
            drop(conn);

            let started = std::time::Instant::now();
            let reading = dial(tap_url, &label, own, towards, offer).await.err().map(|e| format!("{e:?}"));
            assert_eq!(reading.as_ref(), Some(&one), "{what}, {ending:?}: refusals must read as one");
            assert!(
                started.elapsed() < FIRST_FRAME_WAIT,
                "{what}, {ending:?}: met when the door refused, not when a wait ran out"
            );
        }
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(served.load(Ordering::SeqCst), admitted, "only the admitted dials reached the handler");
    door.abort();
}
