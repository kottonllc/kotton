// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration — the browser reach tier, end to end at the IPC boundary
//! (RFC-0078 / DEC-0053).
//!
//! A browser holds a per-device Ed25519 key and joins the RFC-0040 ceremony
//! through the gateway. Here the gateway is stood in for by an `IpcClient`
//! authenticated with the daemon's real gateway bootstrap token, relaying each
//! opaque frame as `BrowserFrame` — exactly what `khttpd` does, minus the
//! WebSocket. The browser side is the real `kotton_pair::browser::Joiner`.
//!
//! What these prove:
//! - A first-time browser is admitted only after a human at the node compares
//!   six digits (the `WebShellPair` desk), then reads and writes the user's files
//!   through the sealed channel.
//! - The digits shown to the browser and to the node's screen are the same.
//! - A returning browser with a registered key is admitted by signature, no human.
//! - An unknown browser with no desk open is refused, nothing sealed to it.
//! - The gateway (this relay) never sees plaintext: every frame it forwards is a
//!   handshake message or ciphertext.

use crate::common::{TestEnv, TEST_PASSPHRASE};
use ed25519_dalek::SigningKey;
use kotton_ipc::IpcClient;
use kotton_pair::browser::{Joiner, JoinerStep};
use kotton_wire::{UserRequest, UserResponse};
use rand::rngs::OsRng;

pub(crate) const USER: &str = "browsertest";

/// Relay one frame the way khttpd does: `BrowserFrame` in, `BrowserFrame` out.
pub(crate) async fn relay(gw: &mut IpcClient<UserRequest, UserResponse>, frame: Vec<u8>) -> Vec<u8> {
    match gw
        .send(&UserRequest::BrowserFrame { bytes: frame, channel: None, user_id: None })
        .await
        .expect("relay BrowserFrame")
    {
        UserResponse::BrowserFrame { bytes } => bytes,
        other => panic!("gateway relay returned a non-frame: {other:?}"),
    }
}

/// Connect and authenticate as the gateway (its bootstrap token → Principal::Gateway).
/// One call through an established channel: seal a `ChannelCall`, relay it,
/// and return the response its `ChannelFrame` carries.
///
/// Written once, here, because the inner protocol is a protocol
/// (`DEC-0059`) — a test that hand-rolls the envelope is a second
/// implementation of it, and the browser has the only other one.
pub(crate) async fn call(
    gw: &mut IpcClient<UserRequest, UserResponse>,
    j: &mut kotton_pair::browser::Joiner,
    id: u64,
    request: &str,
) -> serde_json::Value {
    let inner = format!(r#"{{"id":{id},"request":{request}}}"#);
    let sealed = j.seal(inner.as_bytes()).expect("seal the call");
    let reply = relay(gw, sealed).await;
    let frame: serde_json::Value =
        serde_json::from_slice(&j.open(&reply).expect("open the frame")).expect("a ChannelFrame");
    assert_eq!(
        frame["id"].as_u64(),
        Some(id),
        "a frame must name the call it answers: {frame}"
    );
    assert_eq!(
        frame["end"].as_bool(),
        Some(true),
        "a single-response verb ends its call in one frame: {frame}"
    );
    frame["response"].clone()
}

pub(crate) async fn gateway(env: &TestEnv) -> IpcClient<UserRequest, UserResponse> {
    let mut gw = IpcClient::connect(env.endpoint.clone()).await.expect("connect gateway");
    // A gateway token for THIS user (the harness mints one for "owner" by default).
    let token = env.daemon.mint_gateway_bootstrap_token(USER);
    match gw
        .send(&UserRequest::Authenticate {
            token: kotton_wire::ipc::SecretText::new(token),
            scope: Some(vec!["BrowserFrame".to_string()]),
        })
        .await
        .expect("gateway auth")
    {
        UserResponse::ActiveSession { .. } => {}
        other => panic!("gateway auth: {other:?}"),
    }
    gw
}

/// Open the operator's `WebShellPair` desk on its own connection and
/// auto-confirm the six digits. Returns the SAS the node's screen showed and a
/// receiver that fires once the desk is registered.
pub(crate) async fn open_desk(env: &TestEnv) -> (tokio::sync::oneshot::Receiver<()>, tokio::task::JoinHandle<Option<u32>>) {
    let endpoint = env.endpoint.clone();
    let session = env.client.session_token.clone().expect("session token");
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        let operator = IpcClient::<UserRequest, UserResponse>::connect(endpoint.clone())
            .await
            .expect("operator connect");
        // Local operator session — the desk is Local-tier.
        let mut operator = operator;
        match operator
            .send(&UserRequest::Authenticate { token: kotton_wire::ipc::SecretText::new(session), scope: None })
            .await
            .expect("operator auth")
        {
            UserResponse::ActiveSession { .. } => {}
            other => panic!("operator auth: {other:?}"),
        }
        let mut rx = operator
            .send_streaming(&UserRequest::WebShellPair {
                user_id: USER.to_string(),
                ttl_seconds: 60,
            })
            .await
            .expect("WebShellPair stream");
        let mut ready_tx = Some(ready_tx);
        let mut confirm = IpcClient::<UserRequest, UserResponse>::connect(endpoint)
            .await
            .expect("confirm connect");
        // A confirm connection needs a Local session too.
        let mut sas_shown = None;
        while let Some(frame) = rx.recv().await {
            match frame {
                UserResponse::WebShellPairReady => {
                    if let Some(tx) = ready_tx.take() {
                        let _ = tx.send(());
                    }
                }
                UserResponse::PairShowCode { token, sas, .. } => {
                    sas_shown = Some(sas);
                    // The human says yes. PairConfirmCode is session-less + Local.
                    let _ = confirm
                        .send(&UserRequest::PairConfirmCode {
                            user_id: USER.to_string(),
                            token,
                            matches: true,
                        })
                        .await;
                    // One browser per desk in these tests: the verdict is delivered,
                    // so close the desk rather than wait for another.
                    break;
                }
                _ => {}
            }
        }
        sas_shown
    });
    (ready_rx, handle)
}

/// Drive the browser's handshake up to the point where its confirmation frame is
/// the next thing to send. Returns the joiner, the pending confirm frame, the
/// browser's SAS, and whether the node reported the key as known.
pub(crate) async fn handshake_to_confirm(
    gw: &mut IpcClient<UserRequest, UserResponse>,
    device: SigningKey,
    pinned: Option<[u8; 32]>,
) -> (Joiner, Vec<u8>, u32, bool, [u8; 32]) {
    let (mut j, hello) = Joiner::start(device, "test phone", pinned);
    let commit = relay(gw, hello).await;
    let reveal = match j.receive(&commit).expect("commit") {
        JoinerStep::Send(f) => f,
        s => panic!("{s:?}"),
    };
    let node_reveal = relay(gw, reveal).await;
    let dev_hello = match j.receive(&node_reveal).expect("reveal") {
        JoinerStep::Send(f) => f,
        s => panic!("{s:?}"),
    };
    let welcome = relay(gw, dev_hello).await;
    match j.receive(&welcome).expect("welcome") {
        JoinerStep::Sas { sas, node_pub, known, send, .. } => (j, send, sas, known, node_pub),
        s => panic!("{s:?}"),
    }
}

#[tokio::test]
async fn a_first_time_browser_pairs_by_six_digits_then_reads_and_writes_files() {
    let mut env = TestEnv::spawn().await;
    env.client.create_user(USER, TEST_PASSPHRASE).await.expect("create_user");
    env.client
        .write_file(USER, "notes/hello.txt", b"the whole of what is mine")
        .await
        .expect("seed a file");

    let (ready, desk) = open_desk(&env).await;
    ready.await.expect("the desk registers");

    let device = SigningKey::generate(&mut OsRng);
    let mut gw = gateway(&env).await;
    let (mut j, confirm, browser_sas, known, node_pub) =
        handshake_to_confirm(&mut gw, device.clone(), None).await;
    assert!(!known, "a brand-new device key must not be reported as known");

    // Send the browser's confirm; the node blocks on the human, who says yes.
    let node_confirm = relay(&mut gw, confirm).await;
    match j.receive(&node_confirm).expect("node confirm") {
        JoinerStep::Established => {}
        s => panic!("expected establishment, got {s:?}"),
    }
    assert_eq!(j.node_pub(), Some(node_pub));

    let node_sas = desk.await.expect("desk task").expect("a SAS was shown at the node");
    assert_eq!(browser_sas, node_sas, "the two screens must show the same six digits");

    // Read the seeded file back through the sealed channel.
    let req = format!(r#"{{"ReadFile":{{"user_id":"{USER}","path":"notes/hello.txt","offset":0,"length":4096}}}}"#);
    let resp = call(&mut gw, &mut j, 1, &req).await;
    let b64 = resp["FileData"]["data"].as_str().expect("a FileData response with data");
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64).expect("base64");
    assert_eq!(bytes, b"the whole of what is mine", "the file came back through the sealed channel");
}

#[tokio::test]
async fn a_returning_browser_is_admitted_by_its_key_with_no_human() {
    let mut env = TestEnv::spawn().await;
    env.client.create_user(USER, TEST_PASSPHRASE).await.expect("create_user");
    env.client
        .write_file(USER, "notes/a.txt", b"x")
        .await
        .expect("seed");

    let device = SigningKey::generate(&mut OsRng);

    // First visit: admit it with a human at the desk.
    {
        let (ready, desk) = open_desk(&env).await;
        ready.await.expect("desk");
        let mut gw = gateway(&env).await;
        let (mut j, confirm, _, known, _) = handshake_to_confirm(&mut gw, device.clone(), None).await;
        assert!(!known, "first visit: the key is new");
        let node_confirm = relay(&mut gw, confirm).await;
        assert!(matches!(j.receive(&node_confirm).expect("confirm"), JoinerStep::Established));
        let _ = desk.await;
    }

    // Second visit: no desk open anywhere. A known key is admitted by signature
    // alone, and can act.
    let mut gw = gateway(&env).await;
    let node_pub = device.verifying_key(); // unused placeholder; pin what the node returns
    let _ = node_pub;
    let (mut j, confirm, _, known, returned_node) =
        handshake_to_confirm(&mut gw, device.clone(), None).await;
    assert!(known, "second visit: the node recognises the key it admitted");
    let node_confirm = relay(&mut gw, confirm).await;
    assert!(
        matches!(j.receive(&node_confirm).expect("confirm"), JoinerStep::Established),
        "a known key must be admitted with no desk open",
    );
    assert_eq!(j.node_pub(), Some(returned_node));

    let list = format!(r#"{{"ListFiles":{{"user_id":"{USER}","prefix":""}}}}"#);
    let resp = call(&mut gw, &mut j, 1, &list).await;
    assert!(resp.get("Error").is_none(), "a returning browser must be able to act: {resp}");
}

#[tokio::test]
async fn an_unknown_browser_is_refused_when_no_one_is_at_the_node() {
    let mut env = TestEnv::spawn().await;
    env.client.create_user(USER, TEST_PASSPHRASE).await.expect("create_user");

    // No desk opened. An unknown device reaching its confirm must be refused,
    // and the browser's own state machine must surface that as an error.
    let device = SigningKey::generate(&mut OsRng);
    let mut gw = gateway(&env).await;
    let (mut j, confirm, _, known, _) = handshake_to_confirm(&mut gw, device, None).await;
    assert!(!known);
    let refusal = relay(&mut gw, confirm).await;
    let err = j.receive(&refusal).expect_err("an unknown browser with no desk must be refused");
    assert!(
        err.to_string().contains("not accepting") || err.to_string().contains("refused"),
        "the refusal must be legible: {err}",
    );
}

/// **On the local path the bootstrap token names the person, and a frame that
/// names another is refused** (kotton #119). The gateway's token is for
/// `USER`; a first frame naming someone else is answered with the refusal
/// frame, which the browser's own joiner reads as a refusal, and the channel
/// takes no step. The same frame naming `USER` is carried as any other.
#[tokio::test]
async fn a_local_frame_naming_another_person_than_the_gateways_token_is_refused() {
    let mut env = TestEnv::spawn().await;
    env.client.create_user(USER, TEST_PASSPHRASE).await.expect("create_user");
    let mut gw = gateway(&env).await;

    let (mut j, hello) = Joiner::start(SigningKey::generate(&mut OsRng), "test phone", None);
    let reply = match gw
        .send(&UserRequest::BrowserFrame {
            bytes: hello,
            channel: None,
            user_id: Some("someone-else".to_string()),
        })
        .await
        .expect("relay a frame naming another person")
    {
        UserResponse::BrowserFrame { bytes } => bytes,
        other => panic!("the refusal is a frame the browser reads: {other:?}"),
    };
    let err = j.receive(&reply).expect_err("a frame for another person than the token's was carried");
    assert!(
        err.to_string().contains("another person than the frame names"),
        "the refusal must say why: {err}"
    );

    let (mut j, hello) = Joiner::start(SigningKey::generate(&mut OsRng), "test phone", None);
    let reply = match gw
        .send(&UserRequest::BrowserFrame {
            bytes: hello,
            channel: None,
            user_id: Some(USER.to_string()),
        })
        .await
        .expect("relay a frame naming the token's person")
    {
        UserResponse::BrowserFrame { bytes } => bytes,
        other => panic!("the node did not answer the frame: {other:?}"),
    };
    assert!(
        matches!(j.receive(&reply).expect("the token's own person is carried"), JoinerStep::Send(_)),
        "a frame naming the token's person did not reach the ceremony"
    );
}

// ── the channel's other direction (DEC-0059) ─────────────────────────────────

/// A gateway holding both halves of a channel, the way `khttpd` does: one
/// connection carrying calls in, one carrying frames out, and a channel name
/// that ties them together.
struct Duplex {
    calls: IpcClient<UserRequest, UserResponse>,
    frames: tokio::sync::mpsc::Receiver<UserResponse>,
    channel: String,
}

impl Duplex {
    /// Hand one frame to the node and take the one it sends back.
    ///
    /// Every frame comes off the outbound stream now, replies included — the
    /// node has one writer, because the seal's counter is implicit and two
    /// writers can interleave into frames that will not open.
    async fn exchange(&mut self, frame: Vec<u8>) -> Vec<u8> {
        match self
            .calls
            .send(&UserRequest::BrowserFrame {
                bytes: frame,
                channel: Some(self.channel.clone()),
                user_id: None,
            })
            .await
            .expect("relay a browser frame")
        {
            UserResponse::Ok => {}
            other => panic!("the node did not take the frame: {other:?}"),
        }
        self.next().await
    }

    /// The next frame off the outbound stream.
    async fn next(&mut self) -> Vec<u8> {
        match tokio::time::timeout(std::time::Duration::from_secs(30), self.frames.recv())
            .await
            .expect("timed out waiting for a frame on the channel's own direction")
            .expect("the outbound stream ended")
        {
            UserResponse::BrowserFrame { bytes } => bytes,
            other => panic!("the outbound stream carried something else: {other:?}"),
        }
    }

    /// Send a call and take nothing: a streamed verb answers later, on its own.
    async fn call_only(&mut self, id: u64, request: &str, j: &mut Joiner) {
        let inner = format!(r#"{{"id":{id},"request":{request}}}"#);
        let sealed = j.seal(inner.as_bytes()).expect("seal the call");
        match self
            .calls
            .send(&UserRequest::BrowserFrame {
                bytes: sealed,
                channel: Some(self.channel.clone()),
                user_id: None,
            })
            .await
            .expect("relay a call")
        {
            UserResponse::Ok => {}
            other => panic!("the node did not take the call: {other:?}"),
        }
    }

    /// The next `ChannelFrame` off the stream, opened.
    async fn frame(&mut self, j: &mut Joiner) -> serde_json::Value {
        let bytes = self.next().await;
        serde_json::from_slice(&j.open(&bytes).expect("open the frame")).expect("a ChannelFrame")
    }
}

async fn duplex(env: &TestEnv) -> Duplex {
    let channel = uuid::Uuid::new_v4().simple().to_string();
    // Outbound first, as khttpd does it, so the channel exists before the first
    // frame arrives.
    let out = gateway(env).await;
    let mut frames = out
        .send_streaming(&UserRequest::BrowserOutbound {
            channel: channel.clone(),
        })
        .await
        .expect("open the channel's outbound side");
    // The node marks the stream when it has attached this side; relaying before
    // that is a race, and khttpd waits for the same mark.
    match tokio::time::timeout(std::time::Duration::from_secs(30), frames.recv())
        .await
        .expect("timed out waiting for the outbound side to attach")
    {
        Some(UserResponse::Ok) => {}
        other => panic!("the node did not attach the outbound side: {other:?}"),
    }
    Duplex {
        calls: gateway(env).await,
        frames,
        channel,
    }
}

/// `DEC-0059`: a browser runs a contact-pairing ceremony inside its sealed
/// channel, and the ceremony's frames — which no call is sitting waiting for —
/// reach it on the channel's own direction, under the id of the call that
/// started it.
///
/// This is what DEC-0057 ruled a browser may do and could not, before this,
/// actually do: every layer between the browser and the daemon answered one
/// frame per frame, and a ceremony is three or more frames arriving over the
/// time a person reads three words out loud.
/// `DEC-0059` / unit 2b item 1: a ceremony asked for on a channel that has no
/// outbound side is refused **before** it starts.
///
/// The single-connection channel — one `BrowserFrame` in, one out, which is
/// what a browser behind a gateway *device* has — can carry a reply and
/// nothing else. A ceremony is frames nobody asked for, so there is nowhere to
/// put them. Before this check the node took the call, answered `Ok`, and
/// reserved a mailbox at the relay to advertise a code that could never reach
/// a screen: a reservation held open for a person who was never going to be
/// shown anything.
#[tokio::test]
async fn a_stream_with_nowhere_to_go_is_refused_before_it_starts() {
    let (_relay, relay_addr) = crate::common::relay::spawn().await;
    let mut env = crate::common::relay::env_on(&relay_addr).await;
    env.client
        .create_user(USER, TEST_PASSPHRASE)
        .await
        .expect("create_user");

    let (ready, desk) = open_desk(&env).await;
    ready.await.expect("desk");
    let mut gw = gateway(&env).await;
    let device = SigningKey::generate(&mut OsRng);
    let (mut j, confirm, _, _, _) = handshake_to_confirm(&mut gw, device, None).await;
    let established = relay(&mut gw, confirm).await;
    assert!(matches!(
        j.receive(&established).expect("confirm"),
        JoinerStep::Established
    ));
    let _ = desk.await;

    let before = crate::common::relay::reservations(&relay_addr).await;

    let start =
        format!(r#"{{"ContactPairStart":{{"user_id":"{USER}","as_name":null,"ttl_seconds":30}}}}"#);
    let resp = call(&mut gw, &mut j, 1, &start).await;
    let message = resp["Error"]["message"]
        .as_str()
        .unwrap_or_else(|| panic!("a ceremony with nowhere to go must be refused: {resp}"));
    assert!(
        message.contains("no way to carry"),
        "the refusal must say what is missing: {message}"
    );

    // And nothing was started. The reservation is the ceremony's first act, so
    // watching the relay for a couple of seconds is watching for the handler
    // having run at all: without the check the gauge climbs by one here.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        assert_eq!(
            crate::common::relay::reservations(&relay_addr).await,
            before,
            "a refused ceremony must reserve no mailbox at the relay",
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn a_browser_runs_a_ceremony_and_its_frames_arrive_unasked_for() {
    let (_relay, relay_addr) = crate::common::relay::spawn().await;
    let mut env = crate::common::relay::env_on(&relay_addr).await;
    let (browser_did, _) = env
        .client
        .create_user(USER, TEST_PASSPHRASE)
        .await
        .expect("create_user");
    // The stranger: a second node on the same relay, which is the only thing
    // the two of them share.
    let mut stranger = crate::common::relay::env_on(&relay_addr).await;
    let (stranger_did, _) = stranger
        .client
        .create_user("bob", TEST_PASSPHRASE)
        .await
        .expect("create bob");

    let (ready, desk) = open_desk(&env).await;
    ready.await.expect("desk");

    // The handshake, over the two connections. Each node frame comes back on
    // the outbound stream rather than as the reply.
    let mut d = duplex(&env).await;
    let device = SigningKey::generate(&mut OsRng);
    let (mut j, hello) = Joiner::start(device, "test phone", None);
    let commit = d.exchange(hello).await;
    let reveal = match j.receive(&commit).expect("commit") {
        JoinerStep::Send(f) => f,
        s => panic!("{s:?}"),
    };
    let node_reveal = d.exchange(reveal).await;
    let dev_hello = match j.receive(&node_reveal).expect("reveal") {
        JoinerStep::Send(f) => f,
        s => panic!("{s:?}"),
    };
    let welcome = d.exchange(dev_hello).await;
    let confirm = match j.receive(&welcome).expect("welcome") {
        JoinerStep::Sas { send, .. } => send,
        s => panic!("{s:?}"),
    };
    let established = d.exchange(confirm).await;
    assert!(matches!(
        j.receive(&established).expect("confirm"),
        JoinerStep::Established
    ));
    let _ = desk.await;

    // Now the ceremony. The call answers nothing at the moment it is made.
    let start =
        format!(r#"{{"ContactPairStart":{{"user_id":"{USER}","as_name":null,"ttl_seconds":30}}}}"#);
    d.call_only(7, &start, &mut j).await;

    // …and its first frame arrives on the channel's own direction, naming the
    // call it belongs to. Three spoken words for the other person to hear.
    let frame = d.frame(&mut j).await;
    assert_eq!(
        frame["id"].as_u64(),
        Some(7),
        "a ceremony's frame names the call that started it: {frame}"
    );
    assert_eq!(
        frame["end"].as_bool(),
        Some(false),
        "the ceremony is not over when it has only advertised: {frame}"
    );
    let code = frame["response"]["PairAdvertising"]["code"]
        .as_str()
        .unwrap_or_else(|| panic!("expected the ceremony to be advertising: {frame}"))
        .to_string();
    assert_eq!(
        code.split('-').count(),
        3,
        "three spoken words, as at any other screen: {code}"
    );

    // The other person hears the three words and joins from their own node.
    // As heard, not as printed: case and spacing are the listener's.
    let heard = code.replace('-', " ").to_uppercase();
    let joining = async {
        let mut rx = stranger
            .client
            .contact_pair_join_stream("bob", &heard, Some("Bob from the bakery"))
            .await
            .expect("contact_pair_join_stream");
        let mut sas_seen = None;
        while let Some(f) = rx.recv().await {
            match f {
                UserResponse::PairShowCode { token, sas, .. } => {
                    sas_seen = Some(sas);
                    stranger
                        .client
                        .pair_confirm_code("bob", token.expose(), true)
                        .await
                        .expect("the stranger says the digits match");
                }
                UserResponse::ContactPaired { did, .. } => return (sas_seen, Some(did), None),
                UserResponse::PairFailed { reason } => return (sas_seen, None, Some(reason)),
                _ => {}
            }
        }
        (sas_seen, None, Some("the stranger's stream ended".to_string()))
    };

    // The two halves run at once, because each waits on the other: the browser
    // cannot be shown digits until the stranger has dialled the code, and the
    // stranger cannot finish until the browser has said they match.
    let browsing = async {
        // The browser's screen is asked to compare six digits — a frame nobody
        // called for, on the channel's own direction, under the same id.
        let show = d.frame(&mut j).await;
        assert_eq!(show["id"].as_u64(), Some(7), "still the same call: {show}");
        assert_eq!(show["end"].as_bool(), Some(false), "not over yet: {show}");
        let token = show["response"]["PairShowCode"]["token"]
        .as_str()
        .unwrap_or_else(|| panic!("expected the digits to be shown: {show}"))
        .to_string();
        let browser_sas = show["response"]["PairShowCode"]["sas"]
        .as_u64()
        .unwrap_or_else(|| panic!("expected six digits: {show}"));

        // The person at the browser says they match. That is an ordinary
        // single-response call on the same channel — `Paired` is the tier DEC-0057
        // put it at — sent while the ceremony's call is still open.
        let confirm = format!(
        r#"{{"PairConfirmCode":{{"user_id":"{USER}","token":"{token}","matches":true}}}}"#
        );
        d.call_only(8, &confirm, &mut j).await;

        // What arrives now is two calls' frames sharing one direction: the confirm's
        // one-frame answer under 8, and the ceremony finishing under 7. The order
        // between them is the node's, so read until the ceremony's `end`.
        let mut ceremony = Vec::new();
        let mut acked = false;
        let last = loop {
        let f = d.frame(&mut j).await;
        match f["id"].as_u64() {
            Some(8) => {
                assert_eq!(f["end"].as_bool(), Some(true), "a single-response verb ends in one frame: {f}");
                assert!(
                    f["response"]["Error"].is_null(),
                    "the browser's confirmation must be accepted at `Paired`: {f}"
                );
                acked = true;
            }
            Some(7) => {
                if f["end"].as_bool() == Some(true) {
                    break f;
                }
                ceremony.push(f);
            }
            other => panic!("a frame arrived under an id nobody called: {other:?} in {f}"),
        }
        };
        assert!(acked, "the confirmation's own answer never came back");
        assert!(
        last["response"].is_null(),
        "the frame that closes a call carries no response: {last}"
        );
        let paired = ceremony
            .iter()
            .find_map(|f| f["response"]["ContactPaired"]["did"].as_str())
            .unwrap_or_else(|| panic!("the ceremony never reached ContactPaired: {ceremony:?}"))
            .to_string();
        (paired, browser_sas)
    };

    let ((stranger_sas, stranger_paired, stranger_failed), (paired, browser_sas)) =
        tokio::time::timeout(std::time::Duration::from_secs(90), async {
            tokio::join!(joining, browsing)
        })
        .await
        .expect("the ceremony finished on both sides");

    assert_eq!(
        paired, stranger_did,
        "the browser holds the stranger's identity, and it is theirs"
    );
    assert_eq!(stranger_failed, None, "the stranger's side");
    assert_eq!(
        stranger_sas,
        Some(browser_sas as u32),
        "both screens showed the same six digits"
    );
    assert_eq!(
        stranger_paired.as_deref(),
        Some(browser_did.as_str()),
        "and the stranger holds the browser owner's identity"
    );

    // The contact is on the node, not only in the frames the browser was shown.
    let contacts = env.client.contact_list(USER).await.expect("contact_list");
    assert_eq!(
        contacts,
        vec![(stranger_did.clone(), Some("Bob from the bakery".to_string()))],
        "a ceremony run from a browser leaves a contact behind, like any other",
    );
}

// ── revocation (TASK-a-browser-is-admitted-and-cannot-be-un-admitted) ────────

/// Admit a browser at the desk and return its established channel: the
/// gateway connection carrying it, and the browser's joiner.
async fn admitted(
    env: &TestEnv,
    device: SigningKey,
) -> (IpcClient<UserRequest, UserResponse>, Joiner) {
    let (ready, desk) = open_desk(env).await;
    ready.await.expect("desk");
    let mut gw = gateway(env).await;
    let (mut j, confirm, _, known, _) = handshake_to_confirm(&mut gw, device, None).await;
    assert!(
        !known,
        "a brand-new device key must not be reported as known"
    );
    let established = relay(&mut gw, confirm).await;
    assert!(matches!(
        j.receive(&established).expect("confirm"),
        JoinerStep::Established
    ));
    let _ = desk.await;
    (gw, j)
}

/// Article IV, on a live channel: a person sees the browser they admitted,
/// revokes it, and the next call on the channel the browser is **still
/// holding** is refused — not only its next handshake.
///
/// Three things end, and the test watches each: the row (the list is empty and
/// the key is a stranger again), the session its admission minted (counted
/// live before and after), and the channel (the next sealed frame on the same
/// connection is answered with a refusal in the clear, which the browser
/// cannot open as a reply). Delete either of the last two from `revoke` and
/// this goes red: without the session's end the count stays at one, and
/// without the channel's the call is answered sealed.
#[tokio::test]
async fn a_revoked_browser_is_refused_on_the_channel_it_already_holds() {
    let mut env = TestEnv::spawn().await;
    env.client
        .create_user(USER, TEST_PASSPHRASE)
        .await
        .expect("create_user");
    env.client
        .write_file(USER, "notes/a.txt", b"mine")
        .await
        .expect("seed");

    let device = SigningKey::generate(&mut OsRng);
    let (mut gw, mut j) = admitted(&env, device.clone()).await;

    // The channel works.
    let list = format!(r#"{{"ListFiles":{{"user_id":"{USER}","prefix":""}}}}"#);
    let resp = call(&mut gw, &mut j, 1, &list).await;
    assert!(
        resp.get("Error").is_none(),
        "an admitted browser can act: {resp}"
    );

    // The person sees it, by the name it was admitted under.
    let browsers = env.client.list_browsers(USER).await.expect("list browsers");
    assert_eq!(
        browsers.iter().map(|b| b.name.as_str()).collect::<Vec<_>>(),
        vec!["test phone"],
        "the admitted browser is on the person's list"
    );
    assert_eq!(
        env.daemon.live_browser_sessions(USER),
        1,
        "its admission minted one session"
    );

    // And revokes it, from the trusted screen. The browser is asked nothing.
    let closed = env
        .client
        .revoke_browser(USER, "test phone")
        .await
        .expect("revoke the browser");
    assert_eq!(closed, 1, "the one channel it held open was ended");
    assert_eq!(
        env.daemon.live_browser_sessions(USER),
        0,
        "the session its admission minted is gone, not merely unreachable"
    );
    assert!(
        env.client
            .list_browsers(USER)
            .await
            .expect("list")
            .is_empty(),
        "a revoked browser is off the list"
    );

    // The next call, on the same channel, over the same gateway connection.
    let inner = format!(r#"{{"id":2,"request":{list}}}"#);
    let sealed = j.seal(inner.as_bytes()).expect("seal the call");
    let reply = relay(&mut gw, sealed).await;
    let err = j
        .open(&reply)
        .expect_err("a revoked browser's call must not be answered on its channel");
    assert!(
        err.to_string().contains("refused"),
        "the refusal is the node's, in the clear: {err}"
    );

    // Its next handshake meets a stranger's key: it is not re-admitted by its
    // signature, and would wait for a human like any browser never seen. The
    // confirm is not sent — the desk this test opened outlives its stream
    // (`TASK-a-closed-browser-desk-stays-open-and-its-ttl-is-never-read`), so
    // a stranger reaching it waits out the confirmer's five minutes.
    let mut gw = gateway(&env).await;
    let (_, _, _, known, _) = handshake_to_confirm(&mut gw, device, None).await;
    assert!(!known, "a revoked key is not recognised by its signature");

    // A name that was never admitted is an error, not a silent success.
    assert!(env.client.revoke_browser(USER, "test phone").await.is_err());
}

/// Revoking ends the channel's outbound side, which is how `khttpd` learns to
/// drop the browser's socket: the door closes with the decision, not with the
/// ten-minute idle timer.
#[tokio::test]
async fn revoking_a_browser_ends_its_channels_outbound_stream() {
    let mut env = TestEnv::spawn().await;
    env.client
        .create_user(USER, TEST_PASSPHRASE)
        .await
        .expect("create_user");

    let (ready, desk) = open_desk(&env).await;
    ready.await.expect("desk");
    let mut d = duplex(&env).await;
    let device = SigningKey::generate(&mut OsRng);
    let (mut j, hello) = Joiner::start(device, "test phone", None);
    let commit = d.exchange(hello).await;
    let reveal = match j.receive(&commit).expect("commit") {
        JoinerStep::Send(f) => f,
        s => panic!("{s:?}"),
    };
    let node_reveal = d.exchange(reveal).await;
    let dev_hello = match j.receive(&node_reveal).expect("reveal") {
        JoinerStep::Send(f) => f,
        s => panic!("{s:?}"),
    };
    let welcome = d.exchange(dev_hello).await;
    let confirm = match j.receive(&welcome).expect("welcome") {
        JoinerStep::Sas { send, .. } => send,
        s => panic!("{s:?}"),
    };
    let established = d.exchange(confirm).await;
    assert!(matches!(
        j.receive(&established).expect("confirm"),
        JoinerStep::Established
    ));
    let _ = desk.await;

    assert_eq!(
        env.client
            .revoke_browser(USER, "test phone")
            .await
            .expect("revoke"),
        1
    );
    let end = tokio::time::timeout(std::time::Duration::from_secs(10), d.frames.recv())
        .await
        .expect("the outbound stream must end when its browser is revoked");
    assert!(
        end.is_none(),
        "nothing more is sent to a revoked browser: {end:?}"
    );
}

/// The roster and the revoke are `Local`: a browser — `Paired` — is floored
/// out of both, so it neither reads its siblings nor revokes them.
#[tokio::test]
async fn a_browser_can_neither_list_nor_revoke_browsers_through_its_channel() {
    let mut env = TestEnv::spawn().await;
    env.client
        .create_user(USER, TEST_PASSPHRASE)
        .await
        .expect("create_user");
    let (mut gw, mut j) = admitted(&env, SigningKey::generate(&mut OsRng)).await;

    let list = format!(r#"{{"BrowserDeviceList":{{"user_id":"{USER}"}}}}"#);
    let resp = call(&mut gw, &mut j, 1, &list).await;
    assert_eq!(
        resp,
        serde_json::json!("NotAllowed"),
        "the list is Local: {resp}"
    );

    let revoke = format!(r#"{{"BrowserDeviceRevoke":{{"user_id":"{USER}","name":"test phone"}}}}"#);
    let resp = call(&mut gw, &mut j, 2, &revoke).await;
    assert_eq!(
        resp,
        serde_json::json!("NotAllowed"),
        "the revoke is Local: {resp}"
    );
    assert_eq!(
        env.client.list_browsers(USER).await.expect("list").len(),
        1,
        "and nothing was revoked"
    );
}

// ── the Devices screen (TASK-the-devices-screen-does-not-list-admitted-browsers)

/// The Devices screen's two verbs, asked of the occupant host the designated
/// shell is handed: the admitted browser is listed by the name it was admitted
/// under, and revoking it there ends its live channel exactly as
/// `BrowserDeviceRevoke` does — the session its admission minted is gone, the
/// next call on the channel the browser still holds is refused in the clear,
/// and the terminal's verb, asked afterwards, finds nothing left to revoke.
///
/// The host asks for no user and is given none: it resolves the one person on
/// this machine, as its `list-devices` does.
#[tokio::test]
async fn the_devices_screen_lists_an_admitted_browser_and_its_revoke_ends_the_live_channel() {
    use kotton_app::daemon::apps::OccupantHost;

    let mut env = TestEnv::spawn().await;
    env.client
        .create_user(USER, TEST_PASSPHRASE)
        .await
        .expect("create_user");
    let (mut gw, mut j) = admitted(&env, SigningKey::generate(&mut OsRng)).await;

    let list = format!(r#"{{"ListFiles":{{"user_id":"{USER}","prefix":""}}}}"#);
    let resp = call(&mut gw, &mut j, 1, &list).await;
    assert!(resp.get("Error").is_none(), "an admitted browser can act: {resp}");

    // The screen sees what the terminal sees.
    let host = env.daemon.occupant_host();
    let on_screen = host.list_browsers().await.expect("the screen's list");
    assert_eq!(
        on_screen.iter().map(|b| b.name.as_str()).collect::<Vec<_>>(),
        vec!["test phone"],
        "the admitted browser is on the Devices screen's list"
    );
    let at_terminal = env.client.list_browsers(USER).await.expect("the terminal's list");
    assert_eq!(on_screen[0].admitted_at, at_terminal[0].created_at);
    assert_eq!(on_screen[0].last_visit, at_terminal[0].last_used_at);
    assert_eq!(env.daemon.live_browser_sessions(USER), 1, "its admission minted one session");

    // Revoked from the screen. The browser is asked nothing.
    host.revoke_browser("test phone").await.expect("revoke from the screen");
    assert_eq!(
        env.daemon.live_browser_sessions(USER),
        0,
        "the session its admission minted is gone, as the IPC verb ends it"
    );
    assert!(host.list_browsers().await.expect("list").is_empty(), "off the screen's list");
    assert!(
        env.client.list_browsers(USER).await.expect("list").is_empty(),
        "and off the terminal's: one row, one revoke"
    );

    // The next call on the same channel, over the same gateway connection.
    let inner = format!(r#"{{"id":2,"request":{list}}}"#);
    let sealed = j.seal(inner.as_bytes()).expect("seal the call");
    let reply = relay(&mut gw, sealed).await;
    let err = j
        .open(&reply)
        .expect_err("a browser revoked from the screen must not be answered on its channel");
    assert!(err.to_string().contains("refused"), "the node's refusal, in the clear: {err}");

    // Both doors now agree there is nothing by that name.
    assert!(host.revoke_browser("test phone").await.is_err());
    assert!(env.client.revoke_browser(USER, "test phone").await.is_err());
}
