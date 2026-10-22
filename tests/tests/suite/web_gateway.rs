// SPDX-License-Identifier: AGPL-3.0-or-later
//! **DEC-0052's demonstration, whole.** A person opens a page on their phone
//! and sees the files that sit on their machine at home, *through a rented
//! relay that carries and keeps nothing*.
//!
//! Three processes, none sharing a socket with another: a `kotton-relay`
//! (`common::relay`), the node (`TestEnv`), and a `khttpd` started the way a
//! person starts one on a rented host — from a gateway bundle, with no daemon
//! socket and no bootstrap token (`common::khttpd::spawn_gateway`), admitted by
//! the six-digit ceremony with the transport reversed (`khttpd enroll`). The
//! gateway is a paired device of gateway posture (RFC-0078): it dials the node through
//! the relay under a per-contact handle (RFC-0083 R4), and the node admits it to
//! one verb. The page's ceremony and the files are `web_surface.rs`'s, unchanged:
//! what this test adds is the machine in the middle.

use crate::common::khttpd;
use crate::common::relay;
use crate::common::{TestEnv, TEST_PASSPHRASE};
use crate::web_surface::{authed, open_desk, repo_root, Page, NOTE, STEP_TIMEOUT, USER};
use kotton_wire::{UserRequest, UserResponse};

/// The gateway joins by the ceremony (RFC-0076, transport reversed): `khttpd
/// enroll` in `dir` prints a code and listens; the node dials it and shows six
/// digits; the test compares them with the six the gateway printed and confirms
/// at the node. The gateway's key never leaves `dir`.
async fn enrol_gateway(env: &TestEnv, dir: &std::path::Path) {
    let (_enroll, code, lines) = khttpd::spawn_enroll(dir).await;
    let lines = std::sync::Arc::new(std::sync::Mutex::new(lines));
    let desk = authed(env).await;
    let mut rx = desk
        .send_streaming(&UserRequest::GatewayEnroll {
            user_id: USER.to_string(),
            code: kotton_wire::ipc::SecretText::new(code),
            ttl_seconds: 120,
        })
        .await
        .expect("GatewayEnroll stream");
    let mut confirmer = authed(env).await;
    loop {
        let frame = tokio::time::timeout(STEP_TIMEOUT, rx.recv())
            .await
            .expect("a ceremony frame in time")
            .expect("the ceremony stream stays open");
        match frame {
            UserResponse::PairShowCode { token, sas, .. } => {
                // The gateway printed its six; the node derived its six.
                let lines = std::sync::Arc::clone(&lines);
                let printed = tokio::task::spawn_blocking(move || {
                    let rx = lines.lock().unwrap();
                    loop {
                        let line = rx.recv_timeout(STEP_TIMEOUT).expect("the gateway prints its digits");
                        if let Some(d) = line.strip_prefix("sas=") {
                            return d.to_string();
                        }
                    }
                })
                .await
                .expect("reader");
                assert_eq!(printed, format!("{sas:06}"), "the gateway and the node show the same six");
                match confirmer
                    .send(&UserRequest::PairConfirmCode {
                        user_id: USER.to_string(),
                        token,
                        matches: true,
                    })
                    .await
                    .expect("confirm")
                {
                    UserResponse::PairConfirmAck | UserResponse::Ok => {}
                    other => panic!("confirm: {other:?}"),
                }
            }
            UserResponse::PairingComplete { node, .. } => {
                assert_eq!(node.id, "vps-gateway", "the node knows the gateway by the name it announced");
                break;
            }
            UserResponse::PairFailed { reason } => panic!("gateway enrolment failed: {reason}"),
            UserResponse::Error { message } => panic!("gateway enrolment: {message}"),
            _ => {}
        }
    }
    let deadline = std::time::Instant::now() + STEP_TIMEOUT;
    while !dir.join("gateway.json").exists() && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(dir.join("gateway.json").exists(), "the gateway wrote its bundle");
    assert!(dir.join("gateway.key").exists(), "the gateway's key stays where it was made");
}

/// RFC-0083 R6: whether a person can be reached right now is a fact the relay's
/// state answers, and the failure case is never silent. One node, three states,
/// with the relay changed live: no relay named → `None`; a relay named that
/// nothing is held at → `Down`, with the count of what should be held; the real
/// relay → `Up`. The readout is what the reservation listener knows — a held
/// reservation is an open control socket the relay accepted — so `Up` is a fact
/// about the relay, not about the URL.
#[tokio::test(flavor = "multi_thread")]
async fn the_relay_readout_names_its_state() {
    use kotton_wire::ipc::RelayState;

    // No relay, said to this daemon. It used to be `remove_var` on a
    // process-wide variable, which unset it for every daemon any other test was
    // constructing at that instant, and said nothing about this one a moment
    // later (`TASK-a-process-global-relay-url-is-shared-by-tests-that-run-in-parallel`).
    let mut env = TestEnv::spawn_without_relay().await;
    env.client.create_user(USER, TEST_PASSPHRASE).await.expect("create_user");
    env.daemon
        .start_peer_listener_background(khttpd::free_port())
        .await
        .expect("the node's peer listener");

    async fn readout(env: &mut TestEnv) -> kotton_wire::ipc::RelayReadout {
        env.client.network_status(USER).await.expect("network status").relay
    }

    // Nothing named: the readout says so rather than staying blank.
    let none = readout(&mut env).await;
    assert_eq!(none.state, RelayState::None, "no relay is named: {none:?}");

    // A relay named where nothing answers, and a paired device to hold for.
    env.client
        .node_rendezvous_set(Some("http://127.0.0.1:9"))
        .await
        .expect("name a relay nothing listens at");
    let elsewhere = tempfile::tempdir().expect("the other machine");
    enrol_gateway(&env, elsewhere.path()).await;
    let mut down = readout(&mut env).await;
    assert_eq!(down.state, RelayState::Down, "a relay is named and nothing is held there: {down:?}");
    assert_eq!(down.reservations_live, 0);
    let wanted_at = std::time::Instant::now();
    while down.reservations_wanted == 0 && wanted_at.elapsed() < STEP_TIMEOUT {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        down = readout(&mut env).await;
    }
    assert_eq!(
        down.reservations_wanted, 2,
        "one paired device wants one reservation per epoch in the window: {down:?}"
    );
    assert_eq!(down.state, RelayState::Down, "{down:?}");

    // The real relay, set live: the reservations move, and the readout follows.
    let (_relay, relay_addr) = relay::spawn().await;
    env.client
        .node_rendezvous_set(Some(&format!("http://{relay_addr}")))
        .await
        .expect("move to a relay that answers");
    let started = std::time::Instant::now();
    let mut up = readout(&mut env).await;
    while up.state != RelayState::Up && started.elapsed() < STEP_TIMEOUT {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        up = readout(&mut env).await;
    }
    assert_eq!(up.state, RelayState::Up, "the relay accepted a reservation: {up:?}");
    // Four wanted, not two: the relay being left is held through its forwarding
    // window (R5), and nothing answers there, so those two stay unheld.
    assert_eq!(up.reservations_wanted, 4, "{up:?}");
    assert!(up.reservations_live >= 1, "at least one reservation is held: {up:?}");
    assert!(up.reservations_live <= 2, "nothing is held at the relay nobody listens at: {up:?}");
}

/// The phone's half of the six digits, driven through a real browser at `url`:
/// the page shows its digits, the node's desk shows the same, both say they
/// match. Returns the page one `next()` before home.
async fn phone_pairs(env: &TestEnv, url: &str) -> Page {
    let (ready, node_sas) = open_desk(env).await;
    ready.await.expect("the desk registers");

    let mut page = Page::open(url);
    let shown = page.next().await;
    let browser_sas = shown["sas"].as_str().expect("the page showed digits").to_string();
    page.tell("match");

    let (token, node_digits) =
        tokio::time::timeout(STEP_TIMEOUT, node_sas).await.expect("node SAS").expect("desk");
    assert_eq!(
        browser_sas,
        format!("{node_digits:06}"),
        "the phone and the node show the same six digits, through the relay"
    );
    let mut operator = authed(env).await;
    match operator
        .send(&UserRequest::PairConfirmCode {
            user_id: USER.to_string(),
            token: kotton_wire::ipc::SecretText::new(token),
            matches: true,
        })
        .await
        .expect("confirm at the node")
    {
        UserResponse::PairConfirmAck | UserResponse::Ok => {}
        other => panic!("node confirm: {other:?}"),
    }
    page
}

/// RFC-0083 R5: a relay change is a forwarding address. The node moves from one
/// relay to another while its gateway still names the first. The gateway lands
/// at the first — the node keeps holding there through a forwarding window —
/// asks where the node reserves now, records the answer in its bundle, and the
/// phone reaches home. Then the first relay is gone, and the same phone reaches
/// home again through the second, with nothing re-enrolled: the identity did
/// not change, and the address followed the pair.
#[tokio::test(flavor = "multi_thread")]
async fn a_relay_change_is_a_forwarding_address() {
    use kotton_wire::ipc::types::GatewayBundle;
    use kotton_wire::ipc::RelayState;

    let wasm = repo_root().join("client/web/assets/pair.wasm");
    assert!(wasm.exists(), "{} is missing — run `cargo xtask build-web`", wasm.display());

    let (relay_a, addr_a) = relay::spawn().await;
    let (_relay_b, addr_b) = relay::spawn().await;
    let (url_a, url_b) = (format!("http://{addr_a}"), format!("http://{addr_b}"));

    let mut env = TestEnv::spawn_at_relay(&url_a).await;
    env.client.create_user(USER, TEST_PASSPHRASE).await.expect("create_user");
    env.client
        .write_file(USER, "notes/hello.txt", NOTE.as_bytes())
        .await
        .expect("seed a note");
    env.daemon
        .start_peer_listener_background(khttpd::free_port())
        .await
        .expect("the node's peer listener");

    let elsewhere = tempfile::tempdir().expect("the other machine");
    enrol_gateway(&env, elsewhere.path()).await;
    let bundle_path = elsewhere.path().join("gateway.json");
    let bundle = |path: &std::path::Path| -> GatewayBundle {
        serde_json::from_str(&std::fs::read_to_string(path).expect("bundle")).expect("bundle shape")
    };
    assert_eq!(bundle(&bundle_path).relay_url, url_a, "the ceremony handed the gateway the first relay");

    // The node moves. It holds at the relay it left through the forwarding
    // window, so what still names that relay lands — two per peer at each.
    env.client.node_rendezvous_set(Some(&url_b)).await.expect("move to the second relay");
    let started = std::time::Instant::now();
    loop {
        let r = env.client.network_status(USER).await.expect("network status").relay;
        if r.state == RelayState::Up && r.reservations_wanted == 4 && r.reservations_live == 4 {
            break;
        }
        assert!(started.elapsed() < STEP_TIMEOUT, "reservations held at both relays: {r:?}");
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    // The gateway still names the first relay, and nobody told it otherwise.
    let static_dir = repo_root().join("client/web").display().to_string();
    let (_gateway, addr) = khttpd::spawn_gateway(elsewhere.path(), &static_dir).await;
    let url = format!("https://{addr}/");
    let mut page = phone_pairs(&env, &url).await;
    let home = page.next().await;
    assert_eq!(home["screen"], "home", "the phone reaches home through the relay the node left: {home}");
    assert_eq!(home["relay"], "up", "{home}");

    // Having landed, the gateway asked where the node reserves and recorded it.
    let asked = std::time::Instant::now();
    while bundle(&bundle_path).relay_url != url_b && asked.elapsed() < STEP_TIMEOUT {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(bundle(&bundle_path).relay_url, url_b, "the gateway follows the forwarding address");

    // The page reads a file, as any visit does.
    let files = page.next().await;
    assert_eq!(files["screen"], "files", "{files}");
    page.tell(r#"{"open":"notes/hello.txt"}"#);
    let file = page.next().await;
    assert_eq!(file["content"], NOTE, "{file}");

    // Then the first relay is gone, and the same phone comes back: a new circuit,
    // through the second relay, nothing re-enrolled.
    drop(relay_a);
    page.tell("again");
    let again = page.next().await;
    assert_eq!(again["screen"], "home", "the returning phone reaches home through the new relay: {again}");
    assert_eq!(again["relay"], "up", "{again}");
    let after = env.client.network_status(USER).await.expect("network status").relay;
    assert_eq!(after.state, RelayState::Up, "{after:?}");
}
#[tokio::test]
async fn a_phone_reaches_home_through_the_relay() {
    let wasm = repo_root().join("client/web/assets/pair.wasm");
    assert!(
        wasm.exists(),
        "{} is missing — run `cargo xtask build-web` (just test does)",
        wasm.display()
    );

    // The relay: rented, blind, holding nothing.
    let (_relay, relay_addr) = relay::spawn().await;
    let relay_url = format!("http://{relay_addr}");

    // The node at home, told to hold reservations at that relay — told to *this*
    // daemon, not announced to the process
    // (`TASK-a-process-global-relay-url-is-shared-by-tests-that-run-in-parallel`).
    let mut env = TestEnv::spawn_at_relay(&relay_url).await;
    env.client.create_user(USER, TEST_PASSPHRASE).await.expect("create_user");
    env.client
        .write_file(USER, "notes/hello.txt", NOTE.as_bytes())
        .await
        .expect("seed a note");
    env.client
        .write_file(USER, "readme.txt", b"a file at the top")
        .await
        .expect("seed a second file");
    env.daemon
        .start_peer_listener_background(khttpd::free_port())
        .await
        .expect("the node's peer listener, which holds the relay reservations");

    // The gateway, elsewhere, joins by the ceremony: a device that holds nothing
    // and speaks one verb, whose key was made on that machine and stays there.
    let elsewhere = tempfile::tempdir().expect("the other machine");
    enrol_gateway(&env, elsewhere.path()).await;
    let bundle: kotton_wire::ipc::types::GatewayBundle =
        serde_json::from_str(&std::fs::read_to_string(elsewhere.path().join("gateway.json")).unwrap()).unwrap();
    assert_eq!(bundle.user_id, USER);
    assert_eq!(bundle.relay_url, relay_url, "the ceremony handed the gateway the node's relay");

    // No socket to the node, only its own directory.
    let static_dir = repo_root().join("client/web").display().to_string();
    let (_gateway, addr) = khttpd::spawn_gateway(elsewhere.path(), &static_dir).await;
    let url = format!("https://{addr}/");

    // From here the ceremony is the phone's and the node's; the gateway and the
    // relay between them read none of it.
    let mut page = phone_pairs(&env, &url).await;

    let home = page.next().await;
    assert_eq!(home["screen"], "home", "after the digits, the page reaches home: {home}");
    // RFC-0083 R6: reachability is a readout beside the holders. The page got
    // here through the relay, so the node's reservation there is held, and the
    // readout says so — read from the relay listener's own state, not inferred.
    assert_eq!(home["relay"], "up", "the phone reached home through the relay, and home shows the relay up: {home}");

    let files = page.next().await;
    assert_eq!(files["screen"], "files");
    let entries: Vec<&str> = files["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    eprintln!("[test] the phone lists: {entries:?}");
    assert!(entries.contains(&"notes/"), "the folder is listed: {entries:?}");
    assert!(entries.contains(&"readme.txt"), "the top-level file is listed: {entries:?}");
    // The node's own records — membership under `network/`, which this very
    // gateway's enrolment wrote — are not a person's files, and the page does
    // not show them as such.
    assert!(
        !entries.iter().any(|e| e.starts_with("network")),
        "system records are not listed as the person's files: {entries:?}"
    );
    // Home's count is the listing's length: the two numbers are one number.
    assert_eq!(
        home["files"].as_u64(),
        Some(entries.len() as u64),
        "home counts what files lists: {home} vs {entries:?}"
    );

    page.tell(r#"{"open":"notes/hello.txt"}"#);
    let file = page.next().await;
    assert_eq!(file["screen"], "file");
    assert_eq!(
        file["content"], NOTE,
        "the file that sits on the machine at home is readable on the phone, through the relay"
    );

    page.tell("again");
    let again = page.next().await;
    assert_eq!(again["screen"], "home", "a returning phone lands on home: {again}");
    assert_eq!(again["sasShown"], false, "a returning phone is not shown digits");
}

/// The gateway's key is a device's, and its posture is the whole of its reach:
/// on the peer path it may speak `BrowserFrame` and nothing else. Proven at the
/// node's peer handler rather than through a browser, because a browser cannot
/// ask for anything else — the gateway itself is the party this bounds.
#[tokio::test]
async fn a_gateway_key_reaches_one_verb_and_no_data() {
    use kotton_net::transport::quic::tls::{Ed25519DeviceCert, PairedDeviceVerifier};
    use kotton_net::transport::RelayClient;
    use std::collections::HashSet;
    use std::sync::{Arc, RwLock};

    let (_relay, relay_addr) = relay::spawn().await;
    let relay_url = format!("http://{relay_addr}");
    let mut env = TestEnv::spawn_at_relay(&relay_url).await;
    env.client.create_user(USER, TEST_PASSPHRASE).await.expect("create_user");
    env.client
        .write_file(USER, "secret.txt", b"not for a gateway")
        .await
        .expect("seed");
    env.daemon
        .start_peer_listener_background(khttpd::free_port())
        .await
        .expect("peer listener");

    let elsewhere = tempfile::tempdir().expect("the other machine");
    enrol_gateway(&env, elsewhere.path()).await;
    let bundle: kotton_wire::ipc::types::GatewayBundle =
        serde_json::from_str(&std::fs::read_to_string(elsewhere.path().join("gateway.json")).unwrap()).unwrap();

    // Dial the node as the gateway would, with the key it made, under its handle.
    let key_hex = std::fs::read_to_string(elsewhere.path().join("gateway.key")).unwrap();
    let key: [u8; 32] = hex::decode(key_hex.trim()).unwrap().try_into().unwrap();
    let gateway_sk = ed25519_dalek::SigningKey::from_bytes(&key);
    let node_pub: [u8; 32] = hex::decode(&bundle.node_pubkey_hex).unwrap().try_into().unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut conn = None;
    // Ten seconds of dialling, in forty attempts. What runs out here is a
    // budget, so the failure below says so: the old message — "the gateway's
    // key opens a circuit to the node" — stated a *security* conclusion for a
    // timer expiring, and cost a re-run to diagnose when the suite lost this
    // test under load
    // (`TASK-a-process-global-relay-url-is-shared-by-tests-that-run-in-parallel`).
    const ATTEMPTS: usize = 40;
    const GAP: std::time::Duration = std::time::Duration::from_millis(250);
    let mut last_err = None;
    let began = std::time::Instant::now();
    for _ in 0..ATTEMPTS {
        let attempt = kotton_peer::rendezvous::circuit_attempts(
            &gateway_sk,
            &node_pub,
            kotton_peer::rendezvous::unix_now(),
        )
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
        let client = RelayClient::new(
            &relay_url,
            attempt.auth_did,
            attempt.auth_key,
            Ed25519DeviceCert::from_signing_key(&gateway_sk).unwrap(),
            PairedDeviceVerifier::new(
                Arc::new(RwLock::new(HashSet::from([node_pub]))),
                Arc::clone(&provider),
            ),
            Arc::clone(&provider),
        );
        match client.dial(&attempt.target).await {
            Ok(c) => {
                conn = Some(c);
                break;
            }
            Err(e) => {
                last_err = Some(e.to_string());
                tokio::time::sleep(GAP).await;
            }
        }
    }
    let conn = conn.unwrap_or_else(|| {
        panic!(
            "no circuit to the node within the dial budget — {ATTEMPTS} attempts \
             {GAP:?} apart, {:?} elapsed, against relay {relay_url}. Last error: {}. \
             This is the budget running out, not a verdict on the gateway's key.",
            began.elapsed(),
            last_err.as_deref().unwrap_or("none recorded"),
        )
    });

    // A data verb, as a paired Full device would send it: refused by posture.
    let req = serde_json::to_vec(&UserRequest::ReadFile {
        user_id: USER.to_string(),
        path: "secret.txt".to_string(),
        offset: 0,
        length: 0,
    })
    .unwrap();
    let raw = conn.request(&req).await.expect("the circuit answers");
    match serde_json::from_slice::<UserResponse>(&raw).unwrap() {
        UserResponse::Error { message } => {
            assert!(
                message.contains("gateway speaks one verb"),
                "refused for its posture, not by accident: {message}"
            );
        }
        other => panic!("a gateway key read a file: {other:?}"),
    }

    // The one verb it may speak is answered — with a ceremony frame, not data.
    let req = serde_json::to_vec(&UserRequest::BrowserFrame {
        bytes: b"not a handshake".to_vec(),
        channel: Some("c1".to_string()),
    })
    .unwrap();
    let raw = conn.request(&req).await.expect("the circuit answers");
    assert!(
        matches!(serde_json::from_slice::<UserResponse>(&raw).unwrap(), UserResponse::BrowserFrame { .. }),
        "BrowserFrame is the gateway's verb"
    );
}

/// On a rented host the gateway sits behind a proxy that holds the hostname's
/// certificate (`infra/gateway`): it speaks plain HTTP on loopback and nothing
/// else. The page and its assets come from it over that; the frames inside are
/// the browser's ciphertext either way.
#[tokio::test]
async fn a_gateway_behind_a_proxy_serves_the_page_over_plain_http_on_loopback() {
    let (_relay, relay_addr) = relay::spawn().await;
    let relay_url = format!("http://{relay_addr}");
    let mut env = TestEnv::spawn_at_relay(&relay_url).await;
    env.client.create_user(USER, TEST_PASSPHRASE).await.expect("create_user");
    env.daemon
        .start_peer_listener_background(khttpd::free_port())
        .await
        .expect("peer listener");
    let elsewhere = tempfile::tempdir().expect("the other machine");
    enrol_gateway(&env, elsewhere.path()).await;

    let static_dir = repo_root().join("client/web").display().to_string();
    let (_gateway, addr) = khttpd::spawn_gateway_plain(elsewhere.path(), &static_dir).await;

    let page = reqwest::get(format!("http://{addr}/")).await.expect("plain HTTP on loopback");
    assert_eq!(page.status(), 200);
    let body = page.text().await.unwrap();
    assert!(body.contains("assets/app.js"), "the shell's page is served: {body:.120}");
    let wasm = reqwest::get(format!("http://{addr}/assets/pair.wasm")).await.expect("asset");
    assert_eq!(wasm.status(), 200, "the ceremony's wasm is served beside it");
}
