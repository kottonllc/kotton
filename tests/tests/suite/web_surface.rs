// SPDX-License-Identifier: AGPL-3.0-or-later
//! **DEC-0052's demonstration, through a browser.** A person opens a page on
//! their phone and sees the files that sit on their machine at home.
//!
//! Everything below the page was proven at the IPC boundary by
//! `browser_channel.rs`. This test adds the page: a real `khttpd` serving
//! `client/web`, a real Chromium driven by Playwright, the six digits read off
//! the screen and compared with the six the node showed, and a file read back
//! through the sealed channel and rendered. The browser half is
//! `client/web/e2e/pair.mjs`; the two sides talk in JSON lines.
//!
//! It needs three things a Rust toolchain does not bring: `node`, the
//! `playwright` package resolvable by it, and `client/web/assets/pair.wasm`.
//! This repository does not build that file: the web half of pairing belongs to
//! the gateway and the portal, which are not here, so these cases fail here
//! naming the missing file, never silently. Nothing to do until the gateway and
//! the portal have repositories of their own.

use crate::common::khttpd::{self, free_port};
use crate::common::{TestEnv, TEST_PASSPHRASE};
use kotton_ipc::IpcClient;
use kotton_wire::{UserRequest, UserResponse};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

pub(crate) const USER: &str = "phoneowner";
pub(crate) const NOTE: &str = "the whole of what is mine";
pub(crate) const STEP_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("tests/ has a parent")
        .to_path_buf()
}

/// Where node can find `playwright`: its own resolution, then the global tree.
fn playwright_node_path() -> String {
    let global = Command::new("npm")
        .args(["root", "-g"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let candidates: Vec<String> = [std::env::var("NODE_PATH").ok(), Some(global)]
        .into_iter()
        .flatten()
        .filter(|s| !s.is_empty())
        .collect();
    let node_path = candidates.join(":");
    let probe = Command::new("node")
        .env("NODE_PATH", &node_path)
        .args(["-e", "require.resolve('playwright')"])
        .output();
    match probe {
        Ok(o) if o.status.success() => node_path,
        Ok(o) => panic!(
            "node cannot resolve `playwright` (NODE_PATH={node_path}). Install it — \
             `npm install -g playwright` — or set NODE_PATH to a tree that has it.\n{}",
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => panic!("`node` is not runnable ({e}); the surface test drives a real browser"),
    }
}

pub(crate) async fn authed(env: &TestEnv) -> IpcClient<UserRequest, UserResponse> {
    let mut c = IpcClient::connect(env.endpoint.clone()).await.expect("connect");
    let token = env.client.session_token.clone().expect("session token");
    match c
        .send(&UserRequest::Authenticate { token: kotton_wire::ipc::SecretText::new(token), scope: None })
        .await
        .expect("authenticate")
    {
        UserResponse::ActiveSession { .. } => c,
        other => panic!("auth: {other:?}"),
    }
}

/// The node's side of the ceremony: a desk open for the page, reporting the
/// digits it shows. Confirming is the test's, once both sides have been read.
pub(crate) async fn open_desk(
    env: &TestEnv,
) -> (
    tokio::sync::oneshot::Receiver<()>,
    tokio::sync::oneshot::Receiver<(String, u32)>,
) {
    let operator = authed(env).await;
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (sas_tx, sas_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut rx = operator
            .send_streaming(&UserRequest::WebShellPair {
                user_id: USER.to_string(),
                ttl_seconds: 120,
            })
            .await
            .expect("WebShellPair stream");
        let mut ready_tx = Some(ready_tx);
        let mut sas_tx = Some(sas_tx);
        while let Some(frame) = rx.recv().await {
            match frame {
                UserResponse::WebShellPairReady => {
                    if let Some(tx) = ready_tx.take() {
                        let _ = tx.send(());
                    }
                }
                UserResponse::PairShowCode { token, sas, .. } => {
                    if let Some(tx) = sas_tx.take() {
                        let _ = tx.send((token.expose().to_owned(), sas));
                    }
                }
                UserResponse::PairingComplete { .. } | UserResponse::PairFailed { .. } => break,
                _ => {}
            }
        }
    });
    (ready_rx, sas_rx)
}

pub(crate) struct Page {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    lines: std::sync::mpsc::Receiver<String>,
}

impl Drop for Page {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Page {
    pub(crate) fn open(url: &str) -> Self {
        Self::driven_by("pair.mjs", url)
    }

    /// As [`open`](Self::open), with a different browser half. Each `.mjs` under
    /// `client/web/e2e/` drives one journey and reports it as JSON lines.
    pub(crate) fn driven_by(script: &str, url: &str) -> Self {
        let script = repo_root().join("client/web/e2e").join(script);
        let mut child = Command::new("node")
            .env("NODE_PATH", playwright_node_path())
            .arg(&script)
            .arg(url)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn node for the browser half");
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        let (tx, lines) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    return;
                }
            }
        });
        Self { child, stdin, lines }
    }

    /// The page's next observation.
    pub(crate) async fn next(&mut self) -> serde_json::Value {
        let line = tokio::time::timeout(STEP_TIMEOUT, async {
            loop {
                match self.lines.try_recv() {
                    Ok(l) => break l,
                    Err(std::sync::mpsc::TryRecvError::Empty) => {
                        tokio::time::sleep(Duration::from_millis(50)).await
                    }
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        panic!("the browser half exited before the page produced what was expected")
                    }
                }
            }
        })
        .await
        .expect("the page produced nothing within the step timeout");
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("page said {line:?}: {e}"))
    }

    pub(crate) fn tell(&mut self, line: &str) {
        writeln!(self.stdin, "{line}").expect("write to the browser half");
        self.stdin.flush().expect("flush");
    }
}

#[tokio::test]
async fn a_phone_pairs_by_six_digits_and_sees_the_files_at_home() {
    let wasm = repo_root().join("client/web/assets/pair.wasm");
    assert!(
        wasm.exists(),
        "{} is missing: this repository does not build the web half of pairing, so this case cannot run here. Nothing to do until the gateway and the portal have repositories of their own",
        wasm.display()
    );

    // Deterministically no relay: this test asserts home says so. Nothing reads
    // `KOTTON_RELAY_URL` any more; `env_without` still says "no relay" to this
    // daemon, which is the statement the assertion rests on.
    let mut env = crate::common::relay::env_without().await;
    env.client.create_user(USER, TEST_PASSPHRASE).await.expect("create_user");
    env.client
        .write_file(USER, "notes/hello.txt", NOTE.as_bytes())
        .await
        .expect("seed a note");
    env.client
        .write_file(USER, "readme.txt", b"a file at the top")
        .await
        .expect("seed a second file");

    // The gateway is configured on the node and serves the shell from the repo.
    let mut operator = authed(&env).await;
    let set = operator
        .send(&UserRequest::WebShellSet {
            enabled: Some(true),
            port: Some(free_port()),
            bind: Some("loopback".to_string()),
            static_dir: Some(repo_root().join("client/web").display().to_string()),
            allow: None,
        })
        .await
        .expect("WebShellSet");
    assert!(matches!(set, UserResponse::Ok), "WebShellSet: {set:?}");
    // The gateway speaks for this user: kuserd mints its bootstrap token for the
    // shell's owner at spawn, and so does the test.
    let token = env.daemon.mint_gateway_bootstrap_token(USER);
    let (_gateway, addr) = khttpd::spawn_as(&env, token).await;
    let url = format!("https://{addr}/");

    // Someone is at the node, ready to compare digits.
    let (ready, node_sas) = open_desk(&env).await;
    ready.await.expect("the desk registers");

    let mut page = Page::open(&url);

    // The page shows six digits. The person with the phone answers first — the
    // node's screen asks only once the phone has committed (RFC-0040: the
    // joiner's confirmation MAC precedes the issuer's) — so the page is told to
    // press "They match" before the node's side is read.
    let shown = page.next().await;
    let browser_sas = shown["sas"].as_str().expect("the page showed digits").to_string();
    page.tell("match");

    // Now the node shows its six, and they are the same six.
    let (token, node_digits) =
        tokio::time::timeout(STEP_TIMEOUT, node_sas).await.expect("node SAS").expect("desk");
    assert_eq!(
        browser_sas,
        format!("{node_digits:06}"),
        "the phone and the node must show the same six digits"
    );
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

    let home = page.next().await;
    assert_eq!(home["screen"], "home", "after the digits, the page reaches home: {home}");
    assert_eq!(home["files"], 2, "home counts the files the node holds: {home}");
    // No relay is named for this node: the readout is the row that names the fix,
    // never a blank (RFC-0083 R6).
    assert_eq!(home["relay"], "none", "with no relay named, home says so: {home}");

    let files = page.next().await;
    assert_eq!(files["screen"], "files");
    let entries: Vec<&str> = files["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(entries.contains(&"notes/"), "the folder is listed: {entries:?}");
    assert!(entries.contains(&"readme.txt"), "the top-level file is listed: {entries:?}");

    page.tell(r#"{"open":"notes/hello.txt"}"#);
    let file = page.next().await;
    assert_eq!(file["screen"], "file");
    assert_eq!(
        file["content"], NOTE,
        "the file that sits on the machine at home is readable on the phone"
    );

    // The same browser comes back: its key is known and the node is pinned, so
    // nobody is asked to compare anything, and no desk is open.
    page.tell("again");
    let again = page.next().await;
    assert_eq!(again["screen"], "home", "a returning phone lands on home: {again}");
    assert_eq!(again["sasShown"], false, "a returning phone is not shown digits");
}

/// `DEC-0059` / unit 2b item 2: the page shows a ceremony's frames **as they
/// arrive**, not when the ceremony is over.
///
/// A contact ceremony is three or more frames spread over the time a person
/// reads three words out loud and hears six digits back. `Node.call` resolves
/// on the call's `end` frame, so a page built on it would hold the three words
/// in a buffer until the pairing had already finished or expired — the person
/// would be handed the code after the moment they needed it had passed.
/// `Node.open` hands each frame over as it lands.
///
/// The assertion is on the DOM **while the call is still open**: nobody joins
/// this ceremony, so it cannot have ended when the words are read off the
/// screen. With `call` in place of `open` there is nothing there to read.
///
/// It also pins what the door says. Three words and one instruction — no DID,
/// no handle, and not the word "relay". What the person needs is what they say;
/// everything else is the machine's business (`DEC-0056`, and the design skill's
/// *custody is a readout, never prose*).
#[tokio::test]
async fn a_phone_reads_out_three_words_while_the_ceremony_is_still_running() {
    let wasm = repo_root().join("client/web/assets/pair.wasm");
    assert!(
        wasm.exists(),
        "{} is missing: this repository does not build the web half of pairing, so this case cannot run here. Nothing to do until the gateway and the portal have repositories of their own",
        wasm.display()
    );

    // A relay, because a ceremony reserves a mailbox at one before it can
    // advertise a code at all.
    let (_relay, relay_addr) = crate::common::relay::spawn().await;
    let mut env = crate::common::relay::env_on(&relay_addr).await;
    env.client.create_user(USER, TEST_PASSPHRASE).await.expect("create_user");

    let mut operator = authed(&env).await;
    let set = operator
        .send(&UserRequest::WebShellSet {
            enabled: Some(true),
            port: Some(free_port()),
            bind: Some("loopback".to_string()),
            static_dir: Some(repo_root().join("client/web").display().to_string()),
            allow: None,
        })
        .await
        .expect("WebShellSet");
    assert!(matches!(set, UserResponse::Ok), "WebShellSet: {set:?}");
    let token = env.daemon.mint_gateway_bootstrap_token(USER);
    let (_gateway, addr) = khttpd::spawn_as(&env, token).await;

    let (ready, node_sas) = open_desk(&env).await;
    ready.await.expect("the desk registers");

    let mut page = Page::driven_by("pair-someone.mjs", &format!("https://{addr}/"));

    // Admit the phone, the way the other surface test does.
    let shown = page.next().await;
    let browser_sas = shown["sas"].as_str().expect("the page showed digits").to_string();
    let (token, node_digits) =
        tokio::time::timeout(STEP_TIMEOUT, node_sas).await.expect("node SAS").expect("desk");
    assert_eq!(browser_sas, format!("{node_digits:06}"), "the two screens show the same six");
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

    // The door, read while nobody has joined and the call is therefore open.
    let door = page.next().await;
    assert_eq!(
        door["screen"], "pair-someone",
        "the page is still inside the ceremony when the words are read: {door}"
    );
    let code = door["code"].as_str().expect("the page drew the code");
    assert_eq!(code.split('-').count(), 3, "three spoken words: {code}");
    let words: Vec<&str> = door["words"]
        .as_array()
        .expect("words")
        .iter()
        .filter_map(|w| w.as_str())
        .collect();
    assert_eq!(
        words,
        code.split('-').collect::<Vec<_>>(),
        "each word is drawn as its own thing to read out: {door}"
    );

    // And what it does not say.
    let text = door["text"].as_str().expect("the door's text").to_lowercase();
    for forbidden in ["did:", "relay"] {
        assert!(
            !text.contains(forbidden),
            "the door must not show {forbidden:?}: {text}"
        );
    }
}

/// **Unit 4 of the five-day record: the phone draws People and Messages.**
///
/// A phone pairs with its owner's node, that owner pairs with a stranger on
/// another daemon over a real relay, and the *phone* then does the rest: it
/// reads People from `ContactList`, opens the conversation, sends a message,
/// and is shown the one word the send came back with — *delivered*. The
/// stranger replies from their own node, and the phone opens it.
///
/// Everything below the page was proven elsewhere; what this adds is that a
/// person holding a phone, away from the machine, can do it.
///
/// **What it also pins is what the phone does not say.** `DEC-0056` gives the
/// sender four words and nothing else about where a message went — a sender who
/// can tell a phone from a vault is timing that person's day. The thread's own
/// text is asserted to carry none of "vault", "node", "their phone", "read",
/// "seen", "online" or "awake".
#[tokio::test]
async fn a_phone_messages_a_stranger_and_is_told_one_word() {
    let wasm = repo_root().join("client/web/assets/pair.wasm");
    assert!(
        wasm.exists(),
        "{} is missing: this repository does not build the web half of pairing, so this case cannot run here. Nothing to do until the gateway and the portal have repositories of their own",
        wasm.display()
    );

    let (_relay, relay_addr) = crate::common::relay::spawn().await;
    let mut env = crate::common::relay::env_on(&relay_addr).await;
    env.client.create_user(USER, TEST_PASSPHRASE).await.expect("create_user");
    let mut stranger = crate::common::relay::env_on(&relay_addr).await;
    let (stranger_did, _) = stranger
        .client
        .create_user("bob", TEST_PASSPHRASE)
        .await
        .expect("create bob");

    // The two of them pair, as `contact_pairing::pair` does it: one advertises
    // three words, the other hears them, both compare six digits.
    let owner_did = pair_over_the_relay(&env, &stranger).await;

    let mut operator = authed(&env).await;
    let set = operator
        .send(&UserRequest::WebShellSet {
            enabled: Some(true),
            port: Some(free_port()),
            bind: Some("loopback".to_string()),
            static_dir: Some(repo_root().join("client/web").display().to_string()),
            allow: None,
        })
        .await
        .expect("WebShellSet");
    assert!(matches!(set, UserResponse::Ok), "WebShellSet: {set:?}");
    let token = env.daemon.mint_gateway_bootstrap_token(USER);
    let (_gateway, addr) = khttpd::spawn_as(&env, token).await;

    let (ready, node_sas) = open_desk(&env).await;
    ready.await.expect("the desk registers");
    let mut page = Page::driven_by("message.mjs", &format!("https://{addr}/"));

    let shown = page.next().await;
    let browser_sas = shown["sas"].as_str().expect("the page showed digits").to_string();
    let (token, node_digits) =
        tokio::time::timeout(STEP_TIMEOUT, node_sas).await.expect("node SAS").expect("desk");
    assert_eq!(browser_sas, format!("{node_digits:06}"), "the two screens show the same six");
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

    // Home counts the person the node paired with — which is `ContactList`
    // answering a browser at all, and it did not before `DEC-0060`.
    let home = page.next().await;
    assert_eq!(home["people"], 1, "home counts the one contact: {home}");

    let people = page.next().await;
    assert_eq!(people["screen"], "people");
    let names: Vec<&str> = people["names"].as_array().expect("names").iter().filter_map(|v| v.as_str()).collect();
    assert_eq!(names, vec!["Bob from the bakery"], "People names the person, not their key");
    let people_text = people["text"].as_str().expect("the People screen's text");
    assert!(
        !people_text.contains(&stranger_did) && !people_text.contains("did:"),
        "People never shows a DID: {people_text}"
    );

    // The phone sends.
    page.tell(r#"{"send":"the ferry leaves at 6:40, not 7"}"#);
    let sent = page.next().await;
    assert_eq!(
        sent["word"], "delivered",
        "their node was awake, so the one word the sender is owed is `delivered`: {sent}"
    );
    let mine: Vec<&str> = sent["mine"].as_array().expect("mine").iter().filter_map(|v| v.as_str()).collect();
    assert_eq!(
        mine,
        vec!["the ferry leaves at 6:40, not 7"],
        "the phone shows what it sent: {mine:?}"
    );

    // The stranger reads it and answers from their own node.
    let inbox = stranger.client.message_poll_inbox("bob").await.expect("bob's inbox");
    assert_eq!(inbox.len(), 1, "bob has the phone's message: {inbox:?}");
    let m = &inbox[0];
    let text = stranger
        .client
        .message_decrypt_dm(
            "bob",
            m["body"].as_str().expect("body"),
            m["nonce"].as_str().expect("nonce"),
            m["ephemeral_pub"].as_str().expect("ephemeral_pub"),
        )
        .await
        .expect("bob opens it");
    assert_eq!(text, "the ferry leaves at 6:40, not 7", "and it is what the phone typed");
    // The reply goes straight back, with no wait. Until 2026-09-25 this waited
    // for the clock's second to turn: the page ordered a conversation by
    // `sent_at`, whole seconds on each *sender's* clock, so the phone's message
    // and a reply inside the same second had no order and the assertion below
    // flipped both ways. The page now orders by where this node filed each
    // message, which is strictly increasing in the order it filed them
    // (`TASK-a-conversation-is-ordered-by-a-clock-it-does-not-hold`).
    stranger
        .client
        .message_send("bob", &owner_did, "got it, thanks", None)
        .await
        .expect("bob replies");

    // **Measured here, because the page lives on it.** The sender's own filed
    // copy is sealed to the *sender*, so it opens on their key from their own
    // node, and the page draws a sent message from the store rather than from
    // what it remembers typing (`TASK-a-sender-cannot-reopen-what-they-sent`).
    // This asserted the opposite until that record landed.
    let own = env
        .client
        .message_poll_inbox(USER)
        .await
        .expect("the owner's own store");
    let sent_copy = env
        .client
        .record_query(
            USER,
            "sh.kotton.message.v1",
            vec![("to_did".to_string(), serde_json::json!(stranger_did))],
            None,
            None,
        )
        .await
        .expect("the record the owner filed for what they sent");
    assert_eq!(sent_copy.len(), 1, "one message was sent: {sent_copy:?}");
    // The inbox is what came *to* you: the message this phone sent is not in it,
    // which is why the page reads the two directions from two different verbs.
    assert_eq!(own.len(), 1, "the inbox holds the reply and nothing else: {own:?}");
    assert_eq!(
        own[0]["from_did"].as_str(),
        Some(stranger_did.as_str()),
        "and it came from the stranger, not from this person"
    );
    let r = &sent_copy[0];
    let reopened = env
        .client
        .message_decrypt_dm(
            USER,
            r["body"].as_str().expect("body"),
            r["nonce"].as_str().expect("nonce"),
            r["ephemeral_pub"].as_str().expect("ephemeral_pub"),
        )
        .await;
    assert_eq!(
        reopened.as_deref().ok(),
        Some("the ferry leaves at 6:40, not 7"),
        "the sender's own copy opens on the sender's key: {reopened:?}"
    );

    page.tell("look");
    let reply = page.next().await;
    let theirs: Vec<&str> = reply["theirs"].as_array().expect("theirs").iter().filter_map(|v| v.as_str()).collect();
    assert_eq!(theirs, vec!["got it, thanks"], "the phone opens the reply: {theirs:?}");

    // What the thread must not say. The sender is told one word and never which
    // of the recipient's nodes answered (`DEC-0056`).
    let thread_text = reply["text"].as_str().expect("the thread's text").to_lowercase();
    for forbidden in ["vault", "their phone", "seen", "online", "awake", "did:"] {
        assert!(
            !thread_text.contains(forbidden),
            "the thread must not say {forbidden:?}: {thread_text}"
        );
    }

    // And the conversations list carries the same one word, once.
    let list = page.next().await;
    let words: Vec<&str> = list["words"].as_array().expect("words").iter().filter_map(|v| v.as_str()).collect();
    assert_eq!(
        words,
        Vec::<&str>::new(),
        "the last message in this conversation is the stranger's reply, and a \
         message they sent carries no word at all: {words:?}"
    );
}

/// The badge goes up when messages arrive and **down** when they are read.
///
/// Down is the whole assertion. A count that only ever grows is the inbox's
/// size wearing a badge's clothes, which is what this card showed until
/// `DEC-0061` — every message ever received, counted as if it still needed you.
///
/// Three readings, on a real browser against a real node: nothing sent, two
/// arrived, and after the person opens the conversation. The middle one is what
/// makes the third mean anything.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn a_phone_counts_what_is_unread_and_stops_counting_it_once_read() {
    let wasm = repo_root().join("client/web/assets/pair.wasm");
    assert!(
        wasm.exists(),
        "{} is missing: this repository does not build the web half of pairing, so this case cannot run here. Nothing to do until the gateway and the portal have repositories of their own",
        wasm.display()
    );

    let (_relay, relay_addr) = crate::common::relay::spawn().await;
    let mut env = crate::common::relay::env_on(&relay_addr).await;
    env.client.create_user(USER, TEST_PASSPHRASE).await.expect("create_user");
    let mut stranger = crate::common::relay::env_on(&relay_addr).await;
    stranger
        .client
        .create_user("bob", TEST_PASSPHRASE)
        .await
        .expect("create bob");

    let owner_did = pair_over_the_relay(&env, &stranger).await;

    let mut operator = authed(&env).await;
    let set = operator
        .send(&UserRequest::WebShellSet {
            enabled: Some(true),
            port: Some(free_port()),
            bind: Some("loopback".to_string()),
            static_dir: Some(repo_root().join("client/web").display().to_string()),
            allow: None,
        })
        .await
        .expect("WebShellSet");
    assert!(matches!(set, UserResponse::Ok), "WebShellSet: {set:?}");
    let token = env.daemon.mint_gateway_bootstrap_token(USER);
    let (_gateway, addr) = khttpd::spawn_as(&env, token).await;

    let (ready, node_sas) = open_desk(&env).await;
    ready.await.expect("the desk registers");
    let mut page = Page::driven_by("unread.mjs", &format!("https://{addr}/"));

    let shown = page.next().await;
    let browser_sas = shown["sas"].as_str().expect("the page showed digits").to_string();
    let (token, node_digits) =
        tokio::time::timeout(STEP_TIMEOUT, node_sas).await.expect("node SAS").expect("desk");
    assert_eq!(browser_sas, format!("{node_digits:06}"), "the two screens show the same six");
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

    // Nothing has arrived. Zero, and **counted** — the attribute is present with
    // `0` rather than absent, because "nothing waiting" and "this could not be
    // asked" are different answers and the card draws them differently.
    let empty = page.next().await;
    assert_eq!(empty["counted"], true, "the count was answered: {empty}");
    assert_eq!(empty["unread"], 0, "nothing has been sent yet: {empty}");
    assert_eq!(
        empty["words"].as_str().map(str::trim),
        Some("Messages"),
        "a badge is for what needs you, so nothing unread says nothing: {empty}"
    );

    // Two arrive, back to back. This waited for the clock's second to turn
    // until 2026-09-25, because the mark was `(sent_at, id)` and two messages in
    // one second were ordered only by their random ids. The mark is now where
    // this node filed the message, strictly increasing in the order it files things, so the
    // two are in order however close together they land
    // (`TASK-a-conversation-is-ordered-by-a-clock-it-does-not-hold`).
    stranger
        .client
        .message_send("bob", &owner_did, "ferry's booked", None)
        .await
        .expect("bob sends one");
    stranger
        .client
        .message_send("bob", &owner_did, "8:40 on the Saturday", None)
        .await
        .expect("bob sends another");

    page.tell("look");
    let arrived = page.next().await;
    assert_eq!(arrived["counted"], true, "the count was answered: {arrived}");
    assert_eq!(
        arrived["unread"], 2,
        "both of them are unread, because neither has been drawn: {arrived}"
    );
    assert_eq!(
        arrived["words"].as_str().map(str::trim),
        Some("Messages2 unread"),
        "the card says how many need you: {arrived}"
    );

    // The person opens the conversation, and the badge clears.
    let after = page.next().await;
    let read: Vec<&str> = after["read"].as_array().expect("read").iter().filter_map(|v| v.as_str()).collect();
    assert_eq!(
        read,
        vec!["ferry's booked", "8:40 on the Saturday"],
        "the thread drew both, oldest first: {read:?}"
    );
    assert_eq!(after["counted"], true, "the count was answered: {after}");
    assert_eq!(
        after["unread"], 0,
        "drawing a conversation is reading it, so nothing is left: {after}"
    );
    assert_eq!(
        after["words"].as_str().map(str::trim),
        Some("Messages"),
        "and the badge is gone rather than showing a zero: {after}"
    );

    // The count is the person's own, and the *sender* is not told any of it.
    // `DEC-0056` allows them four words and read state is not a fifth: bob's
    // node holds nothing about what alice has looked at.
    let bobs_view = stranger
        .client
        .record_query(
            "bob",
            "sh.kotton.message.v1",
            vec![("to_did".to_string(), serde_json::json!(owner_did))],
            None,
            None,
        )
        .await
        .expect("what bob filed for what he sent");
    assert_eq!(bobs_view.len(), 2, "bob filed both: {bobs_view:?}");
    for r in &bobs_view {
        let fields: Vec<&str> = r.as_object().expect("a record").keys().map(String::as_str).collect();
        for leak in ["read", "read_at", "seen", "seen_at", "opened_at"] {
            assert!(
                !fields.contains(&leak),
                "the sender's copy must carry nothing about what the recipient read, \
                 and it has {leak:?}: {fields:?}"
            );
        }
    }
}

/// Alice's node and Bob's run the RFC-0040 contact ceremony over the test relay,
/// the way `contact_pairing::pair` does. Returns Alice's DID.
async fn pair_over_the_relay(env: &TestEnv, stranger: &TestEnv) -> String {
    use kotton_wire::UserResponse as R;
    let (code_tx, code_rx) = tokio::sync::oneshot::channel();
    let issuer = async {
        let mut rx = env
            .client
            .contact_pair_start_stream(USER, None, 60)
            .await
            .expect("contact_pair_start_stream");
        let mut code_tx = Some(code_tx);
        while let Some(f) = rx.recv().await {
            match f {
                R::PairAdvertising { code, .. } => {
                    let _ = code_tx.take().expect("one advertising frame").send(code.expose().to_string());
                }
                R::PairShowCode { token, .. } => {
                    env.client.pair_confirm_code(USER, token.expose(), true).await.expect("confirm");
                }
                R::ContactPaired { .. } => return,
                R::PairFailed { reason } => panic!("the owner's side: {reason}"),
                _ => {}
            }
        }
        panic!("the owner's ceremony ended without pairing");
    };
    let joiner = async {
        let code = code_rx.await.expect("a code");
        let heard = code.replace('-', " ").to_uppercase();
        let mut rx = stranger
            .client
            .contact_pair_join_stream("bob", &heard, Some("Bob from the bakery"))
            .await
            .expect("contact_pair_join_stream");
        while let Some(f) = rx.recv().await {
            match f {
                R::PairShowCode { token, .. } => {
                    stranger.client.pair_confirm_code("bob", token.expose(), true).await.expect("confirm");
                }
                R::ContactPaired { did, .. } => return did,
                R::PairFailed { reason } => panic!("the stranger's side: {reason}"),
                _ => {}
            }
        }
        panic!("the stranger's ceremony ended without pairing");
    };
    let (_, owner_did) = tokio::time::timeout(STEP_TIMEOUT, async { tokio::join!(issuer, joiner) })
        .await
        .expect("the two of them paired");
    owner_did
}
