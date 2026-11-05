// SPDX-License-Identifier: AGPL-3.0-or-later
//! **A contact ceremony ends with the stream that started it (#436).**
//!
//! A ceremony runs as a task of its own, and before #436 nothing ended it when
//! its stream did: once the six digits were shown, a session that logged out
//! ended the stream (`streamed::while_live`, #397), but the ceremony waited out
//! its ttl, and the session-less `PairConfirmCode` could still confirm it and
//! admit a contact into the logged-out person's store.
//!
//! Through a booted daemon, the streamed door's own `answer` (so the stream is
//! driven by `while_live`, as at the door), and a relay at a loopback port that
//! bridges the two halves as `kotton-relay` does: a reservation per handle, a
//! circuit per dial. Alice starts; the other side is the joiner's half of the
//! ceremony itself (`contact_pairing::run_joiner`), which says yes at once.
//! Nothing binds the daemon's door path: `answer` is called in-process.
//!
//! Platform: every one. The relay listens on `127.0.0.1`, and every wait is
//! bounded generously (seconds where the fixed code takes milliseconds).

use super::*;
use kotton_peer::contact_pairing::{self, ContactIdentity};
use kotton_peer::membership::Membership as _;
use kotton_wire::ipc::{Principal, SecretText, UserRequest, UserResponse};
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, watch};

const PASSPHRASE: &str = "canyon-orbit-velvet-fish-hospital";

/// How long anything here may take where the fixed code is immediate.
const BOUND: Duration = Duration::from_secs(10);

/// A relay at a loopback port: `/relay/reserve` holds a reservation under the
/// handle its caller proves (read from the `Authorization` header, not
/// verified), `/relay/open?to=` is a dial to one (`404` when nobody holds it,
/// which a joiner waits out), and `/relay/accept?circuit=` is the reserver's
/// data leg, bridged to the dial's. What it holds is what a test reads.
mod relay {
    use futures::{SinkExt, StreamExt};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;
    use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
    use tokio_tungstenite::tungstenite::{http, Message};

    type Ws = tokio_tungstenite::WebSocketStream<TcpStream>;

    #[derive(Default)]
    struct State {
        /// Each handle held, and where to tell its holder of a circuit.
        reserved: HashMap<String, mpsc::UnboundedSender<String>>,
        /// Each dial's leg, waiting for the reserver's.
        circuits: HashMap<String, Ws>,
        next: u64,
    }

    pub struct Relay {
        pub url: String,
        state: Arc<Mutex<State>>,
    }

    impl Relay {
        /// Whether a reservation is held under `handle` now.
        pub fn holds(&self, handle: &str) -> bool {
            self.state.lock().unwrap().reserved.contains_key(handle)
        }
    }

    enum Leg {
        Reserve(String),
        Open(String),
        Accept(String),
    }

    pub async fn spawn() -> Relay {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind the relay");
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(State::default()));
        let shared = Arc::clone(&state);
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                tokio::spawn(serve(tcp, Arc::clone(&shared)));
            }
        });
        Relay { url, state }
    }

    // The handshake callback's type is tungstenite's, `Err` and all: a refused
    // upgrade is its whole HTTP response.
    #[allow(clippy::result_large_err)]
    async fn serve(tcp: TcpStream, state: Arc<Mutex<State>>) {
        let mut leg = None;
        let read = |request: &Request, response: Response| -> Result<Response, ErrorResponse> {
            let query = request.uri().query().unwrap_or("");
            let param = |key: &str| query.split('&').find_map(|kv| kv.strip_prefix(key)).map(str::to_string);
            let fingerprint = request
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|h| h.split(' ').find_map(|p| p.strip_prefix("fingerprint=")))
                .map(str::to_string);
            leg = match request.uri().path() {
                "/relay/reserve" => fingerprint.map(Leg::Reserve),
                "/relay/open" => param("to=")
                    .filter(|to| state.lock().unwrap().reserved.contains_key(to))
                    .map(Leg::Open),
                "/relay/accept" => param("circuit=").map(Leg::Accept),
                _ => None,
            };
            match leg {
                Some(_) => Ok(response),
                None => Err(http::Response::builder().status(404).body(Some("nobody is here".into())).unwrap()),
            }
        };
        let Ok(ws) = tokio_tungstenite::accept_hdr_async(tcp, read).await else {
            return;
        };
        match leg {
            Some(Leg::Reserve(handle)) => hold(ws, handle, state).await,
            Some(Leg::Open(to)) => {
                let tell = {
                    let mut st = state.lock().unwrap();
                    st.next += 1;
                    let id = format!("circuit-{}", st.next);
                    st.circuits.insert(id.clone(), ws);
                    st.reserved.get(&to).cloned().map(|tell| (tell, id))
                };
                if let Some((tell, id)) = tell {
                    let _ = tell.send(id);
                }
            }
            Some(Leg::Accept(id)) => {
                let dial = state.lock().unwrap().circuits.remove(&id);
                if let Some(dial) = dial {
                    bridge(ws, dial).await;
                }
            }
            None => {}
        }
    }

    /// Hold `handle` for as long as its holder's connection is open.
    async fn hold(mut ws: Ws, handle: String, state: Arc<Mutex<State>>) {
        let (tell, mut circuits) = mpsc::unbounded_channel();
        state.lock().unwrap().reserved.insert(handle.clone(), tell);
        loop {
            tokio::select! {
                id = circuits.recv() => match id {
                    Some(id) => if ws.send(Message::Text(id)).await.is_err() { break },
                    None => break,
                },
                msg = ws.next() => match msg {
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                    Some(Ok(_)) => {}
                },
            }
        }
        state.lock().unwrap().reserved.remove(&handle);
    }

    /// Carry each side's bytes to the other until either goes; then both go.
    async fn bridge(a: Ws, b: Ws) {
        let (mut a_out, mut a_in) = a.split();
        let (mut b_out, mut b_in) = b.split();
        let a_to_b = async {
            while let Some(Ok(m)) = a_in.next().await {
                if m.is_close() {
                    break;
                }
                if (m.is_binary() || m.is_text()) && b_out.send(m).await.is_err() {
                    break;
                }
            }
        };
        let b_to_a = async {
            while let Some(Ok(m)) = b_in.next().await {
                if m.is_close() {
                    break;
                }
                if (m.is_binary() || m.is_text()) && a_out.send(m).await.is_err() {
                    break;
                }
            }
        };
        tokio::select! {
            () = a_to_b => {}
            () = b_to_a => {}
        }
    }
}

/// A daemon booted at `base`, meeting strangers at `relay_url`, with alice
/// created and unlocked, and alice's connection holding her live session.
async fn alice_at(base: &Path, relay_url: &str) -> (DeviceDaemon, streamed::ConnSession) {
    let keychain: Arc<dyn SecretsStore + Send + Sync> = Arc::new(kotton_secret::MemorySecrets::new());
    let runtime = DeviceRuntime::new_with_secrets(
        base.to_path_buf(),
        kotton_device::config::RuntimeConfig::default(),
        keychain.clone(),
    )
    .await
    .unwrap();
    runtime.create_user("alice", PASSPHRASE).await.unwrap();
    drop(runtime);
    #[cfg(unix)]
    let endpoint = IpcEndpoint::UnixSocket(base.join("kuserd.sock"));
    #[cfg(windows)]
    let endpoint = IpcEndpoint::NamedPipe(format!("kotton-test-{}", uuid::Uuid::new_v4().simple()));
    let daemon = DeviceDaemon::new_with_base_secrets_and_relay(
        base.to_path_buf(),
        endpoint,
        keychain,
        RelayChoice::At(relay_url.to_string()),
    )
    .await
    .expect("the daemon boots");
    let resp = dispatch::handle_request(
        &daemon.agent_context(),
        UserRequest::UnlockWithPin { user_id: "alice".into(), pin: SecretText::new(PASSPHRASE), repair: false },
        kotton_ipc::Caller::anonymous(),
        Arc::new(std::sync::Mutex::new(None)),
    )
    .await
    .unwrap();
    assert!(matches!(resp, UserResponse::UnlockOk { .. }), "alice unlocks: {resp:?}");

    let ctx = daemon.agent_context();
    sessions::insert(&ctx.sessions, "alice-session".to_string(), "alice".to_string());
    let principal = Principal::LocalOperator;
    let conn: streamed::ConnSession = Arc::new(std::sync::Mutex::new(Some(ConnSessionData {
        origin: principal.trust_origin(),
        token: "alice-session".to_string(),
        scope: None,
        cek_available: true,
        principal,
        browser_key: None,
    })));
    (daemon, conn)
}

/// Alice's `ContactPairStart`, opened through the streamed door's `answer`, so
/// its stream is driven by `while_live` as at the door.
async fn alice_starts(ctx: &AgentContext, conn: &streamed::ConnSession) -> mpsc::Receiver<UserResponse> {
    let (changes, _) = broadcast::channel(16);
    let (_watching, watcher) = watch::channel(kotton_sync::engine::FsWatchState::Watching);
    let vfs = streamed::VfsWatchSource { changes: &changes, watcher: &watcher };
    let request = UserRequest::ContactPairStart { user_id: "alice".into(), as_name: None, ttl_seconds: 60 };
    streamed::answer(ctx, &request, conn, vfs)
        .await
        .expect("answered as a stream")
        .expect("the ceremony starts")
}

/// The next frame on `stream`, or a panic naming `what` was awaited.
async fn next(stream: &mut mpsc::Receiver<UserResponse>, what: &str) -> UserResponse {
    match tokio::time::timeout(BOUND, stream.recv()).await {
        Ok(Some(frame)) => frame,
        Ok(None) => panic!("the stream ended before {what}"),
        Err(_) => panic!("no frame within {BOUND:?}, waiting for {what}"),
    }
}

/// The code alice's ceremony advertises, from its opening frame.
async fn advertised(stream: &mut mpsc::Receiver<UserResponse>) -> String {
    match next(stream, "the advertising frame").await {
        UserResponse::PairAdvertising { code, .. } => code.expose().to_string(),
        other => panic!("expected the advertising frame, got {other:?}"),
    }
}

/// The joiner's yes, given at once: the other person, comparing nothing.
struct Yes;

#[async_trait::async_trait]
impl kotton_peer::pair_channel::SasConfirmer for Yes {
    async fn confirm(&self, _sas: u32, _label: Option<&str>) -> bool {
        true
    }
}

/// Bob, the other side: a key of his own, and a reach note it signs.
fn bob() -> (ContactIdentity, ed25519_dalek::SigningKey) {
    let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let public_key = key.verifying_key().to_bytes();
    let aid = kotton_crypto::DidKeyMethod::from_public_key_bytes(&public_key).unwrap().to_string();
    let relay = kotton_crypto::reach_note::RelayRef { key: None, addr: "http://relay.bob.test".into(), admit: None };
    let reach = kotton_crypto::reach_note::next(None, &aid, &[relay], &[], &key, kotton_peer::rendezvous::unix_now())
        .expect("bob's note");
    (ContactIdentity { aid, public_key, display_name: "bob".into(), reach, kel: Vec::new() }, key)
}

/// Bob joins alice's ceremony at `relay_url` by `code`, on a task of his own.
fn bob_joins(relay_url: &str, code: &str) -> tokio::task::JoinHandle<anyhow::Result<contact_pairing::PairedContact>> {
    let (relay_url, code) = (relay_url.to_string(), code.to_string());
    tokio::spawn(async move {
        let (ours, key) = bob();
        contact_pairing::run_joiner(
            &relay_url,
            &code,
            &ours,
            &key,
            &Yes,
            &kotton_peer::relay_keys::Presenting::handed(None),
        )
        .await
    })
}

/// The confirmation token alice's ceremony shows, once bob has arrived.
async fn shown(stream: &mut mpsc::Receiver<UserResponse>) -> String {
    loop {
        match next(stream, "the six digits").await {
            UserResponse::PairShowCode { token, .. } => return token.expose().to_string(),
            UserResponse::PairFailed { reason } => panic!("the ceremony failed before the digits: {reason}"),
            _ => {}
        }
    }
}

/// What `stream` carries to its end.
async fn to_the_end(mut stream: mpsc::Receiver<UserResponse>) -> Vec<UserResponse> {
    let mut frames = vec![];
    loop {
        match tokio::time::timeout(BOUND, stream.recv()).await {
            Ok(Some(frame)) => frames.push(frame),
            Ok(None) => return frames,
            Err(_) => panic!("the stream had not ended {BOUND:?} after {frames:?}"),
        }
    }
}

/// `PairConfirmCode` with alice's yes, on a connection holding no session, as
/// the session-less verb arrives: what the door answers.
async fn confirm_yes(ctx: &AgentContext, token: &str) -> UserResponse {
    dispatch::handle_request(
        ctx,
        UserRequest::PairConfirmCode { user_id: "alice".into(), token: SecretText::new(token), matches: true },
        kotton_ipc::Caller::anonymous(),
        Arc::new(std::sync::Mutex::new(None)),
    )
    .await
    .expect("the door answers")
}

/// After the ceremony's stream has closed, with the digits shown: a later yes
/// reaches nothing, the ceremony has ended (bob's half sees the circuit go),
/// nothing is parked, and alice holds no contact.
async fn the_ceremony_ended_and_admitted_nothing(
    ctx: &AgentContext,
    token: &str,
    joiner: tokio::task::JoinHandle<anyhow::Result<contact_pairing::PairedContact>>,
) {
    // The session-less verb is answered as any late token is: read, and
    // taken by nothing.
    let answer = confirm_yes(ctx, token).await;
    assert!(matches!(answer, UserResponse::PairConfirmAck), "PairConfirmCode answered {answer:?}");

    let joined = tokio::time::timeout(BOUND, joiner)
        .await
        .expect("bob's half had not ended: alice's ceremony did not end with its stream")
        .expect("bob's half ran");
    assert!(
        joined.is_err(),
        "bob paired with alice after her ceremony's stream had closed: the ceremony went on and took the yes"
    );
    assert!(
        ctx.pending_confirms.lock().await.is_empty(),
        "a confirmation is still parked for a ceremony whose stream closed"
    );
    let alice = kotton_device::users::residency::Residency::get(&ctx.users, "alice").expect("alice is resident");
    let contacts = alice.list_contacts().await.expect("alice's contacts read");
    assert!(contacts.is_empty(), "a contact was admitted after the ceremony's stream closed: {contacts:?}");
}

/// **A ceremony whose session is revoked after the code is shown admits
/// nothing (#436).**
///
/// Alice starts, bob joins and says yes, and alice's stream shows the digits.
/// Alice logs out (`remove_user`, which drops her tokens and not her
/// residency), so her stream ends with the gate's refusal. Then a yes for the
/// shown token arrives on the session-less `PairConfirmCode`: it is answered
/// `PairConfirmAck` and reaches nothing; the ceremony has ended, so bob's half
/// fails; and alice holds no contact.
///
/// Red before #436: the ceremony waited out its ttl behind the ended stream,
/// the yes reached it, and bob was admitted into the logged-out alice's store.
#[tokio::test]
async fn a_ceremony_whose_session_is_revoked_after_the_code_is_shown_admits_nothing() {
    let relay = relay::spawn().await;
    let temp = tempfile::tempdir().unwrap();
    let (daemon, conn) = alice_at(temp.path(), &relay.url).await;
    let ctx = daemon.agent_context();
    let mut stream = alice_starts(&ctx, &conn).await;
    let code = advertised(&mut stream).await;
    let joiner = bob_joins(&relay.url, &code);
    let token = shown(&mut stream).await;

    sessions::remove_user(&ctx.sessions, "alice");
    let rest = to_the_end(stream).await;
    assert!(
        matches!(rest.last(), Some(UserResponse::NoActiveSession)),
        "the stream did not end with the gate's refusal: {rest:?}"
    );

    the_ceremony_ended_and_admitted_nothing(&ctx, &token, joiner).await;
}

/// **The same, when the client goes away instead.** Nothing is revoked:
/// alice's client drops the stream once the digits are shown, as a closed
/// window or a dead connection does, and the ceremony ends with it.
///
/// Red before #436, as above: a client that had gone away left a ceremony a
/// later yes could still confirm.
#[tokio::test]
async fn a_ceremony_whose_client_goes_away_after_the_code_is_shown_admits_nothing() {
    let relay = relay::spawn().await;
    let temp = tempfile::tempdir().unwrap();
    let (daemon, conn) = alice_at(temp.path(), &relay.url).await;
    let ctx = daemon.agent_context();
    let mut stream = alice_starts(&ctx, &conn).await;
    let code = advertised(&mut stream).await;
    let joiner = bob_joins(&relay.url, &code);
    let token = shown(&mut stream).await;

    drop(stream);
    // The client's going is seen by `while_live` as its sender closing, at
    // once; give its task the turn to drop the ceremony's receiver.
    tokio::time::sleep(Duration::from_millis(200)).await;

    the_ceremony_ended_and_admitted_nothing(&ctx, &token, joiner).await;
}

/// **A ceremony nobody has joined is withdrawn from the relay when its stream
/// closes.** Alice starts and her code's handle is reserved at the relay;
/// her client goes away before anyone joins, and the reservation goes with
/// it — not at the end of the ttl (here 60 s).
///
/// Red before #436: the issuer held the reservation until a joiner came or
/// the ttl ran out.
#[tokio::test]
async fn a_ceremony_nobody_joined_withdraws_its_reservation_when_its_stream_closes() {
    let relay = relay::spawn().await;
    let temp = tempfile::tempdir().unwrap();
    let (daemon, conn) = alice_at(temp.path(), &relay.url).await;
    let ctx = daemon.agent_context();
    let mut stream = alice_starts(&ctx, &conn).await;
    let code = advertised(&mut stream).await;
    let handle = contact_pairing::rendezvous_for(&contact_pairing::normalize_code(&code)).unwrap().handle;

    let started = std::time::Instant::now();
    while !relay.holds(&handle) {
        assert!(started.elapsed() < BOUND, "alice's code was never reserved at the relay");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    drop(stream);
    let closed = std::time::Instant::now();
    while relay.holds(&handle) {
        assert!(
            closed.elapsed() < BOUND,
            "the code was still reserved at the relay {BOUND:?} after its ceremony's stream closed"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ctx.pending_confirms.lock().await.is_empty(), "nothing was ever shown, and something is parked");
}
