// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — per-principal gateway sessions (RFC-0043).
//!
//! Covers the invariant that does the work:
//! 1. P1 — a gateway bootstrap token may mint, and nothing else.
//! 2. Minting is gated on evidence kuserd validates, not on the gateway's claim.
//! 3. A browser admitted by the sealed channel acts under a session floored
//!    *beneath* `Local`: the channel is its session (DEC-0053), and the floor
//!    holds there. Since DEC-0057 that floor is `Paired` rather than `Remote` —
//!    a step that lets the browser run contact pairing and nothing else new — so
//!    both halves are pinned here: a `Local` verb is still refused, and the three
//!    `Paired` verbs are no longer refused by the floor.
//!
//! Until 2026-09-04 this file also minted browser sessions from bearer
//! credentials (`PrincipalEvidence::BrowserCredential`). That door is retired:
//! a browser is paired like a device, its session is minted by the channel when
//! the ceremony establishes (`browser_channel.rs` proves it can act and that two
//! browsers are two channels), and nothing a gateway says names a browser.

use crate::browser_channel::{call, gateway, handshake_to_confirm, open_desk, relay, USER as BROWSER_USER};
use crate::common::{TestEnv, TEST_PASSPHRASE};
use ed25519_dalek::SigningKey;
use kotton_ipc::IpcClient;
use kotton_pair::browser::JoinerStep;
use kotton_sys::ipc::IpcEndpoint;
use kotton_wire::ipc::PrincipalEvidence;
use kotton_wire::{UserRequest, UserResponse};
use rand::rngs::OsRng;

const USER: &str = "owner";

// ── helpers ───────────────────────────────────────────────────────────────────

async fn connect_as(endpoint: &IpcEndpoint, token: &str) -> IpcClient<UserRequest, UserResponse> {
    let mut client = IpcClient::<UserRequest, UserResponse>::connect(endpoint.clone())
        .await
        .expect("IpcClient::connect");
    match client
        .send(&UserRequest::Authenticate {
            token: kotton_wire::ipc::SecretText::new(token),
            scope: None,
        })
        .await
        .expect("Authenticate send")
    {
        UserResponse::ActiveSession { .. } => {}
        other => panic!("unexpected auth response: {other:?}"),
    }
    client
}

#[tokio::test]
async fn p1_a_gateway_token_may_only_mint() {
    let mut env = TestEnv::spawn().await;
    env.client.create_user(USER, TEST_PASSPHRASE).await.expect("create_user");

    let gw_token = env.gateway_token.clone();
    let mut gw = connect_as(&env.endpoint, &gw_token).await;

    let resp = gw
        .send(&UserRequest::ListFiles {
            user_id: USER.to_string(),
            prefix: String::new(),
        })
        .await
        .expect("ListFiles send");
    assert!(
        matches!(resp, UserResponse::NotAllowed),
        "a gateway token must not read the user's data; got {resp:?}"
    );

    let resp = gw
        .send(&UserRequest::NodeList {
            user_id: USER.to_string(),
        })
        .await
        .expect("NodeList send");
    assert!(
        matches!(resp, UserResponse::NotAllowed),
        "a gateway token must not enumerate the user's devices; got {resp:?}"
    );
}

#[tokio::test]
async fn minting_rejects_an_unauthorised_peer_key() {
    let mut env = TestEnv::spawn().await;
    env.client.create_user(USER, TEST_PASSPHRASE).await.expect("create_user");

    let gw_token = env.gateway_token.clone();
    let mut gw = connect_as(&env.endpoint, &gw_token).await;

    let resp = gw
        .send(&UserRequest::MintPrincipalSession {
            user_id: USER.to_string(),
            evidence: PrincipalEvidence::VerifiedPeerKey {
                pubkey_hex: hex::encode([7u8; 32]),
            },
        })
        .await
        .expect("MintPrincipalSession send");

    assert!(
        matches!(resp, UserResponse::NotAllowed),
        "a key that is not an authorised client must mint nothing; got {resp:?}"
    );
}

/// The channel's session is a browser's, and it sits beneath `Local`: a
/// `Local`-tier verb is refused inside it exactly as it was refused to a
/// bearer-minted session.
///
/// This said `at_remote` until 2026-09-07. DEC-0057 moved a browser to `Paired`,
/// which is a *different* origin and the *same* refusal — so the name now states
/// the property the test actually checks. Its sibling below checks the half that
/// changed; between them, "beneath local" is pinned from both sides rather than
/// asserted by a name.
#[tokio::test]
async fn a_channel_admitted_browser_is_floored_beneath_local() {
    let mut env = TestEnv::spawn().await;
    env.client
        .create_user(BROWSER_USER, TEST_PASSPHRASE)
        .await
        .expect("create_user");

    let (ready, desk) = open_desk(&env).await;
    ready.await.expect("desk");
    let mut gw = gateway(&env).await;
    let device = SigningKey::generate(&mut OsRng);
    let (mut j, confirm, _, _, _) = handshake_to_confirm(&mut gw, device, None).await;
    let node_confirm = relay(&mut gw, confirm).await;
    assert!(matches!(j.receive(&node_confirm).expect("confirm"), JoinerStep::Established));
    let _ = desk.await;

    // A verb the floor forbids from anywhere but this machine.
    let req = format!(r#"{{"GetDeviceCert":{{"user_id":"{BROWSER_USER}"}}}}"#);
    let resp = call(&mut gw, &mut j, 1, &req).await;
    assert!(
        resp.get("NotAllowed").is_some() || resp == serde_json::json!("NotAllowed"),
        "a browser's session is floored beneath Local: {resp}"
    );

    // And a verb inside the floor is answered, so the refusal above was the floor's.
    let list = format!(r#"{{"ListFiles":{{"user_id":"{BROWSER_USER}","prefix":""}}}}"#);
    let resp = call(&mut gw, &mut j, 2, &list).await;
    assert!(resp.get("Error").is_none() && resp.get("NotAllowed").is_none(), "{resp}");
}
/// The half DEC-0057 changed: contact pairing is no longer floored out of a
/// browser's channel.
///
/// `ContactPairStart` was `Local`, which is what a People screen on a phone would
/// have had to say *go to your PC* about. It is `Paired` now, and a browser
/// admitted by the six-digit ceremony is `Paired`, so the floor lets it through.
///
/// **What this pins, exactly.** The floor, and only the floor. This channel is
/// the one-connection kind — one frame in, one frame out, no direction for
/// frames nobody asked for — so past the floor the request meets the check that
/// refuses a stream with nowhere to go, and that is the assertion below. The
/// ceremony itself, run to `ContactPaired` on a channel that *does* have an
/// outbound side, is
/// `browser_channel::a_browser_runs_a_ceremony_and_its_frames_arrive_unasked_for`;
/// what is pinned here is that nothing refused it *on the way to* that check.
///
/// The order matters and is what keeps this test discriminating: the floor runs
/// first, so a browser demoted below `Paired` is answered `NotAllowed` and never
/// reaches the outbound check at all.
///
/// The control is `GetDeviceCert` in the same channel: still `Local`, still
/// refused. Without it this test would pass just as well against a floor that had
/// stopped running at all, which is the failure mode the tier is supposed to make
/// visible.
#[tokio::test]
async fn a_paired_browser_is_not_floored_out_of_contact_pairing() {
    let mut env = TestEnv::spawn().await;
    env.client
        .create_user(BROWSER_USER, TEST_PASSPHRASE)
        .await
        .expect("create_user");

    let (ready, desk) = open_desk(&env).await;
    ready.await.expect("desk");
    let mut gw = gateway(&env).await;
    let device = SigningKey::generate(&mut OsRng);
    let (mut j, confirm, _, _, _) = handshake_to_confirm(&mut gw, device, None).await;
    let node_confirm = relay(&mut gw, confirm).await;
    assert!(matches!(j.receive(&node_confirm).expect("confirm"), JoinerStep::Established));
    let _ = desk.await;

    let start = format!(
        r#"{{"ContactPairStart":{{"user_id":"{BROWSER_USER}","as_name":null,"ttl_seconds":30}}}}"#
    );
    let resp = call(&mut gw, &mut j, 1, &start).await;
    assert!(
        resp.get("NotAllowed").is_none() && resp != serde_json::json!("NotAllowed"),
        "a browser is Paired and ContactPairStart is a Paired verb, so the floor must \
         not refuse it: {resp}"
    );
    // What it meets past the floor is the check that refuses a stream with
    // nowhere to go: this channel has one connection, and a ceremony is frames
    // nobody asked for. That refusal is *after* the floor, so reaching it is
    // the evidence the floor let the verb through.
    let past_the_floor = resp
        .get("Error")
        .and_then(|e| e.get("message"))
        .and_then(|m| m.as_str())
        .is_some_and(|m| m.contains("no way to carry"));
    assert!(
        past_the_floor || resp.get("PairAdvertising").is_some(),
        "expected the request to get past the floor: {resp}"
    );

    // The control: a Local verb in the same channel is still refused, so the
    // assertion above is the tier's doing and not a floor that stopped running.
    let cert = format!(r#"{{"GetDeviceCert":{{"user_id":"{BROWSER_USER}"}}}}"#);
    let resp = call(&mut gw, &mut j, 2, &cert).await;
    assert!(
        resp.get("NotAllowed").is_some() || resp == serde_json::json!("NotAllowed"),
        "GetDeviceCert is Local-tier and must still be refused: {resp}"
    );
}

/// The floor holds on the streaming path too (`DEC-0057`;
/// `TASK-the-streamed-ceremony-verbs-never-meet-the-trust-floor`).
///
/// Nine verbs return `HandlerOutput::Stream` and are intercepted in the
/// acceptor closure before `handle_request` runs, so they never met the floor
/// that lives inside it. Each carried a session check instead — and a gateway
/// holds a real session, minted by `MintPrincipalSession` and spoken on this
/// same socket, so those checks were satisfied and `DeviceAdd` was reachable
/// from a `Remote` origin with nothing on the path reading the tier.
///
/// The session here is live and owns the user, so `NoActiveSession` would mean
/// the old check answered. `NotAllowed` is the floor, and only the floor.
#[tokio::test]
async fn a_gateway_minted_session_is_floored_out_of_device_add() {
    let mut env = TestEnv::spawn().await;
    env.client.create_user(USER, TEST_PASSPHRASE).await.expect("create_user");

    // A key the node has authorised, so the mint below succeeds on evidence
    // rather than on the gateway's word.
    let client_key = SigningKey::generate(&mut OsRng);
    let pubkey = client_key.verifying_key().to_bytes();
    let did = kotton_crypto::did::DidKeyMethod::from_public_key(&client_key.verifying_key())
        .to_string();
    env.client
        .peer_add(
            USER,
            "a-remote-client",
            &did,
            &hex::encode(pubkey),
            "127.0.0.1:1".parse().unwrap(),
        )
        .await
        .expect("authorise the client key");

    let gw_token = env.gateway_token.clone();
    let mut gw = connect_as(&env.endpoint, &gw_token).await;
    let token = match gw
        .send(&UserRequest::MintPrincipalSession {
            user_id: USER.to_string(),
            evidence: PrincipalEvidence::VerifiedPeerKey {
                pubkey_hex: hex::encode(pubkey),
            },
        })
        .await
        .expect("MintPrincipalSession send")
    {
        UserResponse::PrincipalSession { token } => token,
        other => panic!("expected a minted session, got {other:?}"),
    };

    let remote = connect_as(&env.endpoint, token.expose()).await;
    let mut frames = remote
        .send_streaming(&UserRequest::DeviceAdd {
            user_id: USER.to_string(),
            as_name: None,
            ttl_seconds: 30,
            port: 0,
            posture: kotton_schemas::membership::Posture::Full,
        })
        .await
        .expect("send_streaming DeviceAdd");
    let frame = tokio::time::timeout(std::time::Duration::from_secs(30), frames.recv())
        .await
        .expect("timeout waiting for the answer to DeviceAdd")
        .expect("channel closed unexpectedly");

    assert!(
        matches!(frame, UserResponse::NotAllowed),
        "DeviceAdd is Local-tier and this session is Remote-origin, so the floor must \
         refuse it; got {frame:?}"
    );
}

/// P1 holds on the streaming path too (RFC-0043).
///
/// A gateway's own bootstrap token is **mint-only**: it may exchange evidence
/// about a third party for a session minted for that party, and do nothing
/// else. `handle_request` enforces that against a list of five permitted
/// variants — and the nine streamed verbs never reach `handle_request`.
///
/// `SubscribeEvents` is `Remote`-tier, so the trust floor passes it, and a
/// bootstrap token is a live session, so the session guard passes it too. Only
/// P1 says no. Without P1 on this path a gateway acting as itself could read
/// the node's event bus — which is a description of what the person is doing,
/// held by the network-facing sidecar P1 exists to disarm.
#[tokio::test]
async fn a_gateway_bootstrap_token_may_not_subscribe_to_events() {
    let mut env = TestEnv::spawn().await;
    env.client.create_user(USER, TEST_PASSPHRASE).await.expect("create_user");

    let gw = connect_as(&env.endpoint, &env.gateway_token.clone()).await;
    let mut frames = gw
        .send_streaming(&UserRequest::SubscribeEvents {
            category: None,
            level: None,
        })
        .await
        .expect("send_streaming SubscribeEvents");
    let frame = tokio::time::timeout(std::time::Duration::from_secs(30), frames.recv())
        .await
        .expect("timeout waiting for the answer to SubscribeEvents")
        .expect("channel closed unexpectedly");

    assert!(
        matches!(frame, UserResponse::NotAllowed),
        "a bootstrap token is mint-only, so the event bus must be refused; got {frame:?}"
    );
}
