// SPDX-License-Identifier: AGPL-3.0-or-later
//! The relay's one rule, at its real doors
//! (`TASK-a-relays-admission-rule-is-set-by-its-operator-over-the-wire`).
//!
//! Every test here runs the relay's own router on a real socket and speaks to it
//! as a device does: a WebSocket upgrade for a reservation or a circuit, plain
//! HTTP for a push, a lookup or an operator's request. A refusal is read off the
//! status the upgrade was answered with, so "refused at the upgrade" means the
//! socket never opened.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use kotton_wire::rendezvous::{
    admission_tag_input, operator_signing_input, AdmissionRule, RelayOperatorRequest,
    RelayOperatorResponse,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use crate::admission::{self, Admission, RuleState, Tier};
use crate::circuit::Circuits;
use crate::server::{build_router, AppState};
use crate::store::RendezvousStore;

// ---------------------------------------------------------------------------
// A device, an operator, and a relay to meet them
// ---------------------------------------------------------------------------

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// A handle: a key that signs, under a `did:key` that names nobody. What a
/// device presents at a relay.
struct Handle {
    sk: SigningKey,
    did: String,
}

impl Handle {
    fn new() -> Self {
        let sk = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let mut prefixed = vec![0xed_u8, 0x01];
        prefixed.extend_from_slice(sk.verifying_key().as_bytes());
        let did = format!("did:key:z{}", bs58::encode(&prefixed).into_string());
        Self { sk, did }
    }

    /// The handle's `Authorization` header, with a tag under `key` if given.
    fn header(&self, key: Option<&[u8; 32]>) -> String {
        let ts = now();
        let sig = URL_SAFE_NO_PAD.encode(
            self.sk
                .sign(format!("{}\n{ts}", self.did).as_bytes())
                .to_bytes(),
        );
        let mut h = format!("Ed25519 fingerprint={} ts={ts} sig={sig}", self.did);
        if let Some(k) = key {
            let tag = admission::tag(k, &admission_tag_input(&self.did, ts));
            h.push_str(&format!(" admit={}", URL_SAFE_NO_PAD.encode(tag)));
        }
        h
    }

    /// A signed `/push` body, with a tag under `key` if given.
    fn push_body(&self, key: Option<&[u8; 32]>) -> String {
        let ts = now();
        let addr = "203.0.113.7:4444";
        let msg = format!("{}\n{addr}\n{ts}\n\n{}", self.did, false);
        let sig = URL_SAFE_NO_PAD.encode(self.sk.sign(msg.as_bytes()).to_bytes());
        let admission = key.map(|k| {
            URL_SAFE_NO_PAD.encode(admission::tag(k, &admission_tag_input(&self.did, ts)))
        });
        serde_json::json!({
            "fingerprint": self.did, "addr": addr, "timestamp": ts, "sig": sig,
            "relayable": false, "admission": admission,
        })
        .to_string()
    }
}

fn key() -> [u8; 32] {
    rand::random()
}

fn b64(k: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(k)
}

/// An operator: an Ed25519 key, enrolled at the relay by its hex.
struct Operator {
    sk: SigningKey,
}

impl Operator {
    fn new() -> Self {
        Self {
            sk: SigningKey::from_bytes(&rand::random::<[u8; 32]>()),
        }
    }

    fn hex(&self) -> String {
        self.sk
            .verifying_key()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn header(&self, body: &[u8], ts: i64) -> String {
        let sig = self.sk.sign(&operator_signing_input(&self.hex(), ts, body));
        format!(
            "KottonOperator key={} ts={ts} sig={}",
            self.hex(),
            URL_SAFE_NO_PAD.encode(sig.to_bytes())
        )
    }
}

pub(crate) fn state_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "kotton-relay-rule-{}",
        hex_of(&rand::random::<[u8; 8]>())
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A created relay whose operator's first set was *anyone* — what the tests
/// that narrow a rule start from. Written as the set leaves it, at time zero,
/// so every later set in the test is newer.
fn set_to_anyone_first(dir: &std::path::Path) {
    let state = RuleState { rule: AdmissionRule::Anyone, ..RuleState::default() };
    std::fs::write(dir.join("rule.json"), serde_json::to_vec_pretty(&state).unwrap()).unwrap();
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn rule_state(rule: AdmissionRule, mine: Option<[u8; 32]>, invited: Option<[u8; 32]>) -> RuleState {
    RuleState {
        rule,
        mine: Tier {
            epoch: mine.is_some() as u64,
            current: mine,
            previous: None,
        },
        invited: Tier {
            epoch: invited.is_some() as u64,
            current: invited,
            previous: None,
        },
        last_set: 0,
    }
}

async fn serve(admission: Admission) -> (String, Arc<AppState>) {
    let state = Arc::new(AppState {
        store: RendezvousStore::new(),
        ttl_secs: 60,
        require_lookup_auth: true,
        admission,
        circuits: Circuits::new(),
        identity: crate::identity::RelayKey::in_memory(),
        advertise: String::new(),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let router = build_router(state.clone());
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (addr, state)
}

/// Upgrade to a WebSocket at `path`. `Ok` holds the open socket; `Err` is the
/// status the upgrade was refused with.
async fn upgrade(addr: &str, path: &str, auth: &str) -> Result<Ws, u16> {
    let mut req = format!("ws://{addr}{path}").into_client_request().unwrap();
    req.headers_mut()
        .insert("Authorization", auth.parse().unwrap());
    match tokio_tungstenite::connect_async(req).await {
        Ok((ws, _)) => Ok(ws),
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => Err(resp.status().as_u16()),
        Err(e) => panic!("the upgrade failed for a reason that is not a refusal: {e}"),
    }
}

/// One HTTP/1.1 request, `Connection: close`; the status and the body.
pub(crate) async fn http(
    addr: &str,
    method: &str,
    path: &str,
    auth: Option<&str>,
    body: &[u8],
) -> (u16, String) {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(a) = auth {
        req.push_str(&format!("Authorization: {a}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    s.write_all(body).await.unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.unwrap();
    let text = String::from_utf8_lossy(&out).to_string();
    let status = text.split_whitespace().nth(1).unwrap().parse().unwrap();
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, body)
}

async fn operator_says(
    addr: &str,
    op: &Operator,
    request: &RelayOperatorRequest,
    ts: i64,
) -> (u16, String) {
    let body = serde_json::to_vec(request).unwrap();
    http(
        addr,
        "POST",
        "/operator",
        Some(&op.header(&body, ts)),
        &body,
    )
    .await
}

fn answer(body: &str) -> RelayOperatorResponse {
    // A chunked body carries its length lines around the JSON; the JSON is the
    // one line that parses.
    body.lines()
        .find_map(|l| serde_json::from_str(l.trim()).ok())
        .unwrap_or_else(|| panic!("no operator answer in {body:?}"))
}

/// Each door a device passes, asked as `handle` with a tag under `key`.
/// A reservation to open a circuit to is held by `target` first.
struct Doors {
    reserve: Result<(), u16>,
    open: Result<(), u16>,
    lookup: u16,
    push: u16,
}

async fn doors(addr: &str, handle: &Handle, key: Option<&[u8; 32]>, target: &str) -> Doors {
    let reserve = upgrade(addr, "/relay/reserve", &handle.header(key))
        .await
        .map(|_| ());
    let open = upgrade(
        addr,
        &format!("/relay/open?to={target}"),
        &handle.header(key),
    )
    .await
    .map(|_| ());
    let (lookup, _) = http(
        addr,
        "GET",
        &format!("/lookup/{target}"),
        Some(&handle.header(key)),
        b"",
    )
    .await;
    let (push, _) = http(
        addr,
        "POST",
        "/push",
        None,
        handle.push_body(key).as_bytes(),
    )
    .await;
    Doors {
        reserve,
        open,
        lookup,
        push,
    }
}

fn refused_everywhere(d: &Doors, who: &str) {
    assert_eq!(
        d.reserve.err(),
        Some(403),
        "{who} was not refused a reservation at the upgrade"
    );
    assert_eq!(
        d.open.err(),
        Some(403),
        "{who} was not refused a circuit at the upgrade"
    );
    assert_eq!(d.lookup, 403, "{who} was answered a lookup");
    assert_eq!(d.push, 403, "{who} had an address kept");
}

fn admitted_everywhere(d: &Doors, who: &str) {
    assert!(
        d.reserve.is_ok(),
        "{who} was refused a reservation: {:?}",
        d.reserve
    );
    assert!(d.open.is_ok(), "{who} was refused a circuit: {:?}", d.open);
    assert_ne!(d.lookup, 403, "{who} was refused a lookup");
    assert_eq!(d.push, 200, "{who} was refused a push");
}

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// A reservation held by one of the operator's own devices, for a circuit to be
/// opened to. The socket is returned so the reservation lasts the test.
async fn target(addr: &str, mine: &[u8; 32]) -> (Handle, Ws) {
    let t = Handle::new();
    let ws = upgrade(addr, "/relay/reserve", &t.header(Some(mine)))
        .await
        .expect("the target reserves");
    (t, ws)
}

// ---------------------------------------------------------------------------
// The doors, under each rule
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_stranger_is_refused_at_the_upgrade_under_only_my_devices() {
    let (mine, invited) = (key(), key());
    let (addr, state) = serve(Admission::in_memory(&Operator::new().hex(), rule_state(
        AdmissionRule::OnlyMyDevices,
        Some(mine),
        Some(invited),
    )))
    .await;
    let (t, _hold) = target(&addr, &mine).await;

    let stranger = Handle::new();
    refused_everywhere(
        &doors(&addr, &stranger, None, &t.did).await,
        "a handle with no tag",
    );
    refused_everywhere(
        &doors(&addr, &Handle::new(), Some(&key()), &t.did).await,
        "a tag under a key nobody set",
    );
    assert_eq!(
        state.circuits.holders_of(&stranger.did),
        0,
        "a refused handle holds a reservation anyway"
    );

    // And the operator's own device, under the key it was given, passes every one.
    admitted_everywhere(
        &doors(&addr, &Handle::new(), Some(&mine), &t.did).await,
        "the operator's own device",
    );
}

#[tokio::test]
async fn a_contacts_device_is_admitted_under_the_people_i_invite_and_refused_under_only_my_devices()
{
    let (mine, invited) = (key(), key());
    let dir = state_dir();
    let op = Operator::new();
    crate::instance::create(&dir, &op.hex(), "").unwrap();
    let (addr, _state) = serve(Admission::open(&dir).unwrap()).await;

    let set = |rule| RelayOperatorRequest::SetRule {
        rule,
        mine: Some(b64(&mine)),
        invited: Some(b64(&invited)),
    };
    let (status, _) = operator_says(&addr, &op, &set(AdmissionRule::PeopleIInvite), now()).await;
    assert_eq!(status, 200);
    let (t, _hold) = target(&addr, &mine).await;

    // A contact holds the key the people the operator invites are handed.
    let contact = Handle::new();
    admitted_everywhere(
        &doors(&addr, &contact, Some(&invited), &t.did).await,
        "a contact's device",
    );
    admitted_everywhere(
        &doors(&addr, &Handle::new(), Some(&mine), &t.did).await,
        "the operator's own device",
    );
    refused_everywhere(
        &doors(&addr, &Handle::new(), None, &t.did).await,
        "a stranger",
    );

    // The rule narrows; the same contact, the same key, is refused at once.
    let (status, _) = operator_says(
        &addr,
        &op,
        &RelayOperatorRequest::SetRule {
            rule: AdmissionRule::OnlyMyDevices,
            mine: None,
            invited: None,
        },
        now() + 1,
    )
    .await;
    assert_eq!(status, 200);
    refused_everywhere(
        &doors(&addr, &contact, Some(&invited), &t.did).await,
        "a contact under only my devices",
    );
    admitted_everywhere(
        &doors(&addr, &Handle::new(), Some(&mine), &t.did).await,
        "the operator's own device",
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn anyone_admits_every_signed_handle() {
    let mine = key();
    let (addr, _state) = serve(Admission::in_memory(&Operator::new().hex(), rule_state(
        AdmissionRule::Anyone,
        Some(mine),
        None,
    )))
    .await;
    let (t, _hold) = target(&addr, &mine).await;

    admitted_everywhere(
        &doors(&addr, &Handle::new(), None, &t.did).await,
        "a signed handle with no tag",
    );
    admitted_everywhere(
        &doors(&addr, &Handle::new(), Some(&key()), &t.did).await,
        "a signed handle with any tag",
    );

    // What *anyone* still refuses is a handle that did not sign: the one key it
    // does not admit is one the caller cannot prove it holds.
    let forger = Handle::new();
    let forged = forger.header(None).replace(&forger.did, &Handle::new().did);
    assert_eq!(
        upgrade(&addr, "/relay/reserve", &forged).await.err(),
        Some(401)
    );
    assert_eq!(
        upgrade(&addr, &format!("/relay/open?to={}", t.did), &forged)
            .await
            .err(),
        Some(401)
    );
    assert_eq!(
        http(
            &addr,
            "GET",
            &format!("/lookup/{}", t.did),
            Some(&forged),
            b""
        )
        .await
        .0,
        401
    );
}

#[tokio::test]
async fn a_tag_under_the_previous_epochs_key_is_admitted_and_one_older_is_refused() {
    let dir = state_dir();
    let op = Operator::new();
    crate::instance::create(&dir, &op.hex(), "").unwrap();
    let (addr, _state) = serve(Admission::open(&dir).unwrap()).await;

    let (k0, k1, k2) = (key(), key(), key());
    for (i, k) in [k0, k1, k2].iter().enumerate() {
        let (status, body) = operator_says(
            &addr,
            &op,
            &RelayOperatorRequest::SetRule {
                rule: AdmissionRule::OnlyMyDevices,
                mine: Some(b64(k)),
                invited: None,
            },
            now() + i as i64,
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(
            answer(&body),
            RelayOperatorResponse::Rule {
                rule: AdmissionRule::OnlyMyDevices,
                mine_epoch: i as u64 + 1,
                invited_epoch: 0,
            }
        );
    }
    let reserve = |k: [u8; 32]| {
        let addr = addr.clone();
        async move {
            upgrade(&addr, "/relay/reserve", &Handle::new().header(Some(&k)))
                .await
                .map(|_| ())
        }
    };
    assert!(reserve(k2).await.is_ok(), "the current key is refused");
    assert!(reserve(k1).await.is_ok(), "the previous epoch's key is refused, so a device that has not learned the new one is locked out in between");
    assert_eq!(
        reserve(k0).await.err(),
        Some(403),
        "a key two rotations old is still admitted"
    );
    let _ = std::fs::remove_dir_all(dir);
}

// ---------------------------------------------------------------------------
// The operator
// ---------------------------------------------------------------------------

#[tokio::test]
async fn only_the_operator_key_reads_or_sets_the_rule() {
    let dir = state_dir();
    let op = Operator::new();
    crate::instance::create(&dir, &op.hex(), "").unwrap();
    set_to_anyone_first(&dir);
    let (addr, state) = serve(Admission::open(&dir).unwrap()).await;
    let mine = key();
    let set = RelayOperatorRequest::SetRule {
        rule: AdmissionRule::OnlyMyDevices,
        mine: Some(b64(&mine)),
        invited: None,
    };

    // A key that signs well and is not enrolled: refused, read and set alike.
    let stranger = Operator::new();
    assert_eq!(
        operator_says(&addr, &stranger, &RelayOperatorRequest::ReadRule, now())
            .await
            .0,
        403
    );
    assert_eq!(operator_says(&addr, &stranger, &set, now()).await.0, 403);

    // A device admitted by the rule, speaking as a handle: not an operator.
    let body = serde_json::to_vec(&set).unwrap();
    assert_eq!(
        http(
            &addr,
            "POST",
            "/operator",
            Some(&Handle::new().header(Some(&mine))),
            &body
        )
        .await
        .0,
        401
    );

    // The operator's key over a body it did not sign: refused.
    let signed = serde_json::to_vec(&RelayOperatorRequest::ReadRule).unwrap();
    assert_eq!(
        http(
            &addr,
            "POST",
            "/operator",
            Some(&op.header(&signed, now())),
            &body
        )
        .await
        .0,
        401
    );
    assert_eq!(
        state.admission.rule(),
        AdmissionRule::Anyone,
        "a refused set changed the rule"
    );

    // The operator: reads, then sets.
    let (status, body) = operator_says(&addr, &op, &RelayOperatorRequest::ReadRule, now()).await;
    assert_eq!(
        (status, answer(&body)),
        (
            200,
            RelayOperatorResponse::Rule {
                rule: AdmissionRule::Anyone,
                mine_epoch: 0,
                invited_epoch: 0
            }
        )
    );
    let t = now();
    assert_eq!(operator_says(&addr, &op, &set, t).await.0, 200);
    assert_eq!(state.admission.rule(), AdmissionRule::OnlyMyDevices);

    // The same set again — captured on the wire and replayed — changes nothing.
    let (_, body) = operator_says(
        &addr,
        &op,
        &RelayOperatorRequest::SetRule {
            rule: AdmissionRule::Anyone,
            mine: None,
            invited: None,
        },
        t,
    )
    .await;
    assert!(
        matches!(answer(&body), RelayOperatorResponse::Refused { .. }),
        "a set no newer than the last was taken"
    );
    assert_eq!(state.admission.rule(), AdmissionRule::OnlyMyDevices);

    // Revoked at the terminal: the next request is refused, with no restart.
    // Another operator is enrolled first, because the last is never revoked.
    admission::enrol_operator(&dir, &Operator::new().hex()).unwrap();
    assert_eq!(
        admission::revoke_operator(&dir, admission::Revoke::One(&op.hex())).unwrap(),
        1
    );
    assert_eq!(
        operator_says(&addr, &op, &RelayOperatorRequest::ReadRule, now())
            .await
            .0,
        403
    );
    assert_eq!(
        operator_says(
            &addr,
            &op,
            &RelayOperatorRequest::SetRule {
                rule: AdmissionRule::Anyone,
                mine: None,
                invited: None
            },
            now() + 5
        )
        .await
        .0,
        403
    );
    assert_eq!(
        state.admission.rule(),
        AdmissionRule::OnlyMyDevices,
        "a revoked operator set the rule"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn the_operator_standing_reaches_the_rule_and_nothing_else() {
    let dir = state_dir();
    let op = Operator::new();
    crate::instance::create(&dir, &op.hex(), "").unwrap();
    let mine = key();
    std::fs::write(
        dir.join("rule.json"),
        serde_json::to_vec(&rule_state(AdmissionRule::OnlyMyDevices, Some(mine), None)).unwrap(),
    )
    .unwrap();
    let (addr, _state) = serve(Admission::open(&dir).unwrap()).await;
    let (t, _hold) = target(&addr, &mine).await;

    // The operator's header on a device's door is no header at all.
    let hdr = op.header(b"", now());
    assert_eq!(
        upgrade(&addr, "/relay/reserve", &hdr).await.err(),
        Some(401)
    );
    assert_eq!(
        upgrade(&addr, &format!("/relay/open?to={}", t.did), &hdr)
            .await
            .err(),
        Some(401)
    );
    assert_eq!(
        http(&addr, "GET", &format!("/lookup/{}", t.did), Some(&hdr), b"")
            .await
            .0,
        401
    );

    // The operator's key presented as a handle is a stranger's: being an operator
    // admits nothing at the door the rule keeps.
    let as_handle = {
        let mut prefixed = vec![0xed_u8, 0x01];
        prefixed.extend_from_slice(op.sk.verifying_key().as_bytes());
        Handle {
            sk: op.sk.clone(),
            did: format!("did:key:z{}", bs58::encode(&prefixed).into_string()),
        }
    };
    refused_everywhere(
        &doors(&addr, &as_handle, None, &t.did).await,
        "the operator's key as a handle",
    );

    // Two requests and no third: nothing on this wire enrols an operator.
    let enrol = format!(r#"{{"Enrol":{{"key":"{}"}}}}"#, Operator::new().hex());
    assert_eq!(
        http(
            &addr,
            "POST",
            "/operator",
            Some(&op.header(enrol.as_bytes(), now())),
            enrol.as_bytes()
        )
        .await
        .0,
        400
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("operators"))
            .unwrap()
            .lines()
            .count(),
        1
    );

    // And a read answers counts, never a key a device could admit with.
    let (_, body) = operator_says(&addr, &op, &RelayOperatorRequest::ReadRule, now()).await;
    assert!(
        !body.contains(&b64(&mine)),
        "the rule's read handed out the key: {body}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_rule_whose_key_nobody_was_given_is_refused_rather_than_set() {
    let dir = state_dir();
    let op = Operator::new();
    crate::instance::create(&dir, &op.hex(), "").unwrap();
    set_to_anyone_first(&dir);
    let (addr, state) = serve(Admission::open(&dir).unwrap()).await;
    for (i, rule) in [AdmissionRule::OnlyMyDevices, AdmissionRule::PeopleIInvite]
        .into_iter()
        .enumerate()
    {
        let (_, body) = operator_says(
            &addr,
            &op,
            &RelayOperatorRequest::SetRule {
                rule,
                mine: None,
                invited: None,
            },
            now() + i as i64,
        )
        .await;
        assert!(
            matches!(answer(&body), RelayOperatorResponse::Refused { .. }),
            "{rule:?} with no key was set"
        );
    }
    let (_, body) = operator_says(
        &addr,
        &op,
        &RelayOperatorRequest::SetRule {
            rule: AdmissionRule::PeopleIInvite,
            mine: Some(b64(&key())),
            invited: None,
        },
        now() + 3,
    )
    .await;
    assert!(
        matches!(answer(&body), RelayOperatorResponse::Refused { .. }),
        "the people I invite with no key for them was set"
    );
    assert_eq!(state.admission.rule(), AdmissionRule::Anyone);
    let _ = std::fs::remove_dir_all(dir);
}

// ---------------------------------------------------------------------------
// What the relay keeps
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_relays_state_holds_no_durable_key_after_a_run() {
    let dir = state_dir();
    let op = Operator::new();
    crate::instance::create(&dir, &op.hex(), "").unwrap();
    set_to_anyone_first(&dir);
    let (addr, state) = serve(Admission::open(&dir).unwrap()).await;
    let (mine, invited) = (key(), key());
    assert_eq!(
        operator_says(
            &addr,
            &op,
            &RelayOperatorRequest::SetRule {
                rule: AdmissionRule::PeopleIInvite,
                mine: Some(b64(&mine)),
                invited: Some(b64(&invited)),
            },
            now()
        )
        .await
        .0,
        200
    );

    // A device speaks under two handles, one per pair, and admits each with the
    // network's key; a contact speaks under a handle of its own. None of them
    // shows the relay anything but a handle and a tag.
    let (h1, h2) = (Handle::new(), Handle::new());
    let _r1 = upgrade(&addr, "/relay/reserve", &h1.header(Some(&mine)))
        .await
        .expect("reserves");
    let _r2 = upgrade(&addr, "/relay/reserve", &h2.header(Some(&mine)))
        .await
        .expect("reserves");
    assert_eq!(
        http(&addr, "POST", "/push", None, h1.push_body(Some(&mine)).as_bytes())
            .await
            .0,
        200
    );
    let contact = Handle::new();
    let _c = upgrade(
        &addr,
        &format!("/relay/open?to={}", h1.did),
        &contact.header(Some(&invited)),
    )
    .await
    .expect("opens");
    assert_eq!(
        http(
            &addr,
            "GET",
            &format!("/lookup/{}", h1.did),
            Some(&contact.header(Some(&invited))),
            b""
        )
        .await
        .0,
        200
    );

    // The operator rotates the invited key after all of that, so whatever the
    // run left in the rule's state is written to disk with it.
    let invited_next = key();
    assert_eq!(
        operator_says(
            &addr,
            &op,
            &RelayOperatorRequest::SetRule {
                rule: AdmissionRule::PeopleIInvite,
                mine: None,
                invited: Some(b64(&invited_next)),
            },
            now() + 1
        )
        .await
        .0,
        200
    );

    // Everything the relay holds in memory is keyed by handles, and only by
    // the handles that reserved or pushed.
    let mut held: Vec<String> = Vec::new();
    held.extend(state.store.fingerprints());
    held.extend(state.circuits.addresses());
    for id in &held {
        assert!(
            [&h1.did, &h2.did].contains(&id),
            "the relay holds {id}, which is no handle a device reserved or pushed under"
        );
    }

    // On disk, exactly the relay's own: its key, its lock, its operators and
    // its rule — nothing of any device. The rule's has exactly its four fields and
    // each tier exactly its three: a rule, keys, counts and a time. A field
    // that kept whom it admitted would be a fifth, and a join key.
    let mut files: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    files.sort();
    assert_eq!(files, ["identity.key", "instance.lock", "operators", "rule.json"]);
    let kept: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("rule.json")).unwrap()).unwrap();
    let fields = |v: &serde_json::Value| {
        let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
        k.sort();
        k
    };
    assert_eq!(fields(&kept), ["invited", "last_set", "mine", "rule"]);
    for tier in ["mine", "invited"] {
        assert_eq!(fields(&kept[tier]), ["current", "epoch", "previous"]);
    }
    // The operators' file holds the one credential the terminal enrolled — the
    // relay's operator key, which the operator never presents as a handle — and
    // nothing a device or a contact showed the relay.
    assert_eq!(
        std::fs::read_to_string(dir.join("operators")).unwrap(),
        format!("{}\n", op.hex())
    );
    let on_disk = std::fs::read_to_string(dir.join("rule.json")).unwrap();
    assert!(!on_disk.contains("did:"), "the relay's rule names someone: {on_disk}");
    for h in [&h1, &h2, &contact] {
        assert!(!on_disk.contains(&hex_of(h.sk.verifying_key().as_bytes())));
    }

    let rule = state.admission.snapshot();
    assert_eq!(rule.rule, AdmissionRule::PeopleIInvite);
    assert_eq!(
        (rule.mine.current, rule.invited.current, rule.invited.previous),
        (Some(mine), Some(invited_next), Some(invited))
    );
    assert_eq!((rule.mine.epoch, rule.invited.epoch), (1, 2));
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn the_rule_and_its_keys_survive_a_restart() {
    let dir = state_dir();
    let op = Operator::new();
    crate::instance::create(&dir, &op.hex(), "").unwrap();
    let (mine, invited) = (key(), key());
    {
        let (addr, _state) = serve(Admission::open(&dir).unwrap()).await;
        assert_eq!(
            operator_says(
                &addr,
                &op,
                &RelayOperatorRequest::SetRule {
                    rule: AdmissionRule::PeopleIInvite,
                    mine: Some(b64(&mine)),
                    invited: Some(b64(&invited)),
                },
                now()
            )
            .await
            .0,
            200
        );
    }

    // A second process on the same directory, and no operator anywhere near it:
    // the last rule the relay was given is the rule it keeps.
    let again = Admission::open(&dir).unwrap();
    assert_eq!(again.rule(), AdmissionRule::PeopleIInvite);
    let (addr, _state) = serve(again).await;
    let (t, _hold) = target(&addr, &mine).await;
    admitted_everywhere(
        &doors(&addr, &Handle::new(), Some(&invited), &t.did).await,
        "a contact after the restart",
    );
    refused_everywhere(
        &doors(&addr, &Handle::new(), None, &t.did).await,
        "a stranger after the restart",
    );

    // A rule file gone bad does not become *anyone*: the relay does not start.
    std::fs::write(dir.join("rule.json"), b"{ not a rule").unwrap();
    assert!(
        Admission::open(&dir).is_err(),
        "a corrupt rule was read as a relay that admits anyone"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Whether `ws`'s socket was closed by the relay within a few seconds.
async fn closed_by_the_relay(ws: &mut Ws) -> bool {
    use futures_util::StreamExt as _;
    matches!(
        tokio::time::timeout(std::time::Duration::from_secs(5), ws.next()).await,
        Ok(None | Some(Err(_)) | Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_))))
    )
}

/// Whether `ws` is still open: nothing arrives on it for a moment.
async fn still_open(ws: &mut Ws) -> bool {
    use futures_util::StreamExt as _;
    tokio::time::timeout(std::time::Duration::from_millis(300), ws.next())
        .await
        .is_err()
}

async fn set(addr: &str, op: &Operator, rule: AdmissionRule, mine: Option<&[u8; 32]>, invited: Option<&[u8; 32]>, ts: i64) {
    let (status, body) = operator_says(
        addr,
        op,
        &RelayOperatorRequest::SetRule {
            rule,
            mine: mine.map(b64),
            invited: invited.map(b64),
        },
        ts,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        matches!(answer(&body), RelayOperatorResponse::Rule { .. }),
        "the set was refused: {body}"
    );
}

/// **What a narrowed rule no longer admits is dropped, and what it admits is
/// kept** (`TASK-a-tenant-with-no-key-reads-as-held-under-a-loaded-suite`).
///
/// Three reservations are taken under *anyone*: a handle presenting no tag, one
/// presenting a tag under the key the people I invite hold, and one under the
/// key the operator's devices hold. The rule narrows to *only my devices*. The
/// relay asks each held reservation the new rule: the first two are dropped and
/// their sockets closed by the relay, the operator's is kept and still open, and
/// the count says one. Nobody reconnected; the relay acted on the tag each
/// presented at its door and nothing else.
#[tokio::test]
async fn a_reservation_the_narrowed_rule_no_longer_admits_is_dropped() {
    let dir = state_dir();
    let op = Operator::new();
    crate::instance::create(&dir, &op.hex(), "").unwrap();
    set_to_anyone_first(&dir);
    let (addr, state) = serve(Admission::open(&dir).unwrap()).await;
    let (mine, invited) = (key(), key());

    let (stranger, contact, own) = (Handle::new(), Handle::new(), Handle::new());
    let mut stranger_ws = upgrade(&addr, "/relay/reserve", &stranger.header(None))
        .await
        .expect("anyone reserves under the rule of anyone");
    let mut contact_ws = upgrade(&addr, "/relay/reserve", &contact.header(Some(&invited)))
        .await
        .expect("a contact reserves under anyone");
    let mut own_ws = upgrade(&addr, "/relay/reserve", &own.header(Some(&mine)))
        .await
        .expect("the operator's device reserves under anyone");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(state.circuits.reservation_count(), 3);

    set(&addr, &op, AdmissionRule::OnlyMyDevices, Some(&mine), Some(&invited), now()).await;

    assert_eq!(
        state.circuits.holders_of(&stranger.did),
        0,
        "a handle presenting no tag was still carried after the rule narrowed"
    );
    assert_eq!(
        state.circuits.holders_of(&contact.did),
        0,
        "a contact was still carried under only my devices"
    );
    assert_eq!(state.circuits.holders_of(&own.did), 1, "the operator's own device was dropped");
    assert_eq!(state.circuits.reservation_count(), 1, "the count kept what was dropped");
    assert!(closed_by_the_relay(&mut stranger_ws).await, "the stranger's socket was left open");
    assert!(closed_by_the_relay(&mut contact_ws).await, "the contact's socket was left open");
    assert!(still_open(&mut own_ws).await, "the operator's device's socket was closed");

    // Its next upgrade meets the rule at the door, as before.
    assert_eq!(
        upgrade(&addr, "/relay/reserve", &stranger.header(None)).await.err(),
        Some(403),
        "the same handle's next upgrade did not meet the new rule"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// **A reservation under a key two rotations old is dropped at the second
/// rotation** (`TASK-a-tenant-with-no-key-reads-as-held-under-a-loaded-suite`;
/// revocation is rotation).
///
/// A contact reserves under *the people I invite* with the invited key. The key
/// rotates once: the one before the current is still read, so the reservation
/// is kept — the grace the door already gives. It rotates again: the contact's
/// key is two back, the door would refuse it, and the relay drops the
/// reservation it is holding under it.
#[tokio::test]
async fn a_reservation_under_a_key_two_rotations_old_is_dropped() {
    let dir = state_dir();
    let op = Operator::new();
    crate::instance::create(&dir, &op.hex(), "").unwrap();
    let (addr, state) = serve(Admission::open(&dir).unwrap()).await;
    let (mine, first, second, third) = (key(), key(), key(), key());
    let ts = now();
    set(&addr, &op, AdmissionRule::PeopleIInvite, Some(&mine), Some(&first), ts).await;

    let contact = Handle::new();
    let mut ws = upgrade(&addr, "/relay/reserve", &contact.header(Some(&first)))
        .await
        .expect("a contact reserves with the invited key");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    set(&addr, &op, AdmissionRule::PeopleIInvite, None, Some(&second), ts + 1).await;
    assert_eq!(state.circuits.holders_of(&contact.did), 1, "the previous key's grace was not kept");
    assert!(still_open(&mut ws).await);

    set(&addr, &op, AdmissionRule::PeopleIInvite, None, Some(&third), ts + 2).await;
    assert_eq!(
        state.circuits.holders_of(&contact.did),
        0,
        "a reservation under a key two rotations old was still carried"
    );
    assert!(closed_by_the_relay(&mut ws).await, "its socket was left open");
    let _ = std::fs::remove_dir_all(dir);
}

/// **A created relay admits nobody before its operator's first rule**
/// (RFC-0084, fork 2, the owner's ruling of 2026-10-01). Creation records an
/// operator and no rule, because the rule's keys are minted at the desktop and
/// handed over the operator wire; until that first set, no handle — with no
/// tag, or a tag under any key — reserves, opens a circuit or has an address
/// kept. Once the operator sets a rule, the doors are that rule's.
#[tokio::test]
async fn a_created_relay_admits_nobody_before_its_operators_first_rule() {
    let dir = state_dir();
    let op = Operator::new();
    crate::instance::create(&dir, &op.hex(), "").unwrap();
    assert!(!dir.join("rule.json").exists(), "creation sets no rule");
    let (addr, state) = serve(Admission::open(&dir).unwrap()).await;
    assert_eq!(state.admission.rule(), AdmissionRule::OnlyMyDevices);

    let target = Handle::new();
    for (who, key) in [("a handle with no tag", None), ("a handle with a tag", Some(key()))] {
        let handle = Handle::new();
        refused_everywhere(&doors(&addr, &handle, key.as_ref(), &target.did).await, who);
        assert_eq!(state.circuits.holders_of(&handle.did), 0, "{who} holds a reservation");
    }
    assert_eq!(state.circuits.reservation_count(), 0, "nothing reserved before the first rule");

    // The operator's first set, and the doors are its rule's.
    set(&addr, &op, AdmissionRule::Anyone, None, None, now()).await;
    let (t, _hold) = upgrade(&addr, "/relay/reserve", &target.header(None))
        .await
        .map(|ws| (target, ws))
        .expect("a reservation under the rule the operator set");
    admitted_everywhere(&doors(&addr, &Handle::new(), None, &t.did).await, "a handle under anyone");
    let _ = std::fs::remove_dir_all(dir);
}
