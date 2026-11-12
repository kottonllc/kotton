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
use kotton_net::transport::{rendezvous_dial, HeldKeys};
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
    kotton_crypto::x25519::ed25519_pub_to_x25519(&pub_of(k))
        .unwrap()
        .to_bytes()
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
        Arc::new(RwLock::new(keys.iter().copied().collect::<HashSet<_>>())),
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
    assert_eq!(conn.peer_did(), did_of(&pub_of(&b)), "A names the key it dialled");
    let resp = conn.request(b"ping").await.expect("A: request");
    assert_eq!(resp, b"echo:ping");
    assert_eq!(served.load(Ordering::SeqCst), 1);
    door.abort();
}

/// The relay sees a version, two fresh values, lengths and ciphertext. A tap records both
/// legs of three circuits: two from a device the door admits by its key, one from a
/// recovered device admitted by the rotation it offers. Neither side's static key is in what
/// it saw, in either form or as a `did:key`; nor a certificate, a server name, the event,
/// or the request.
#[tokio::test]
async fn the_relay_sees_a_version_two_fresh_values_lengths_and_ciphertext() {
    use kotton_crypto::kel_verify::{build_inception, build_mnemonic_rotation, kel_recovery_pubkey};

    let (_relay, relay_addr) = crate::common::relay::spawn().await;
    let (tap_addr, legs) = tap(&relay_addr).await;
    let relay_url = format!("http://{tap_addr}");

    let (a, b, recovered) = (random_key(), random_key(), random_key());
    let seed = [7u8; 32];
    let rung = |i| kel_recovery_pubkey(&kotton_crypto::kdf::derive_kel_recovery_key(&seed, i));
    let tip = build_inception(&random_key(), &[rung(0)]);
    let rotation = build_mnemonic_rotation(&tip, &seed, 0, &recovered, 0, &[rung(0)]);
    let admission = Admission::default();
    admission.tips.write().unwrap().insert(tip.aid.to_string(), tip.clone());
    let (label, door, served) = hold_door(&relay_url, &b, admitting(&[pub_of(&a)], admission)).await;

    let secret = b"a request the relay must not read".to_vec();
    for (own, offer) in [
        (&a, CircuitOffer::default()),
        (&a, CircuitOffer::default()),
        (
            &recovered,
            CircuitOffer {
                events: vec![rotation.clone()],
                authority: None,
            },
        ),
    ] {
        let conn = dial(&relay_url, &label, own, &b, &offer).await.expect("the dial");
        assert_eq!(conn.request(&secret).await.unwrap()[5..], secret[..]);
    }
    assert_eq!(served.load(Ordering::SeqCst), 3);
    door.abort();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // The control: the tap sees what the relay sees, the label a dial names included.
    let opens = data_legs(&legs, "/relay/open");
    let accepts = data_legs(&legs, "/relay/accept");
    assert_eq!((opens.len(), accepts.len()), (3, 3), "three circuits, both legs each");
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
    for (who, k) in [("the door", &b), ("the dialer", &a), ("the recovered device", &recovered)] {
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
            authority: None,
        },
        CircuitOffer {
            events: Vec::new(),
            authority: Some(random_key()),
        },
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
