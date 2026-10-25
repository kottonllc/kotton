// SPDX-License-Identifier: AGPL-3.0-or-later
//! A real `kotton-relay` for a test, spawned from its own workspace's build.
//!
//! The relay-gated tests used to wait on `KOTTON_RELAY_ADDR` and skip without it,
//! which is how a suite about the machine in the middle went unrun. Now each test
//! starts its own relay on a free port and stops it when done. `KOTTON_RELAY_ADDR`
//! is still honoured, for pointing the suite at a relay somewhere else.
//!
//! A relay is started on port 0 and the test reads back the address it bound, from
//! the `listening http=<addr> stun=<addr>` line every start prints once its sockets
//! are bound ([`started`]). A port picked first and let go could be taken by
//! anything on the host before the relay bound it (#152).
//!
//! The binary comes from `infra/relay` (its own workspace, so it never shares this
//! one's build lock): `cargo xtask build-relay`, which `just test` runs and which
//! builds into `out/relay`. A missing binary fails with that command, never silently.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const READY_TIMEOUT: Duration = Duration::from_secs(20);

/// A running relay; killed when dropped. Its state directory goes with it.
///
/// **Every relay the suite starts is created with a key and given a rule**
/// (RFC-0084 V18, V19 and fork 2): a relay does not start without an operator,
/// and admits nobody before its operator's first set. So each is created for an
/// operator key — the suite's own, minted here, or the one a test hands it — and
/// the suite's operator sets *anyone* before any test handle is admitted, as a
/// host's desktop would set the rule asked at the mint.
pub struct Relay {
    child: Option<Child>,
    state: Option<tempfile::TempDir>,
}

impl Drop for Relay {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// Where `just test` left the relay binary, or a failure that names every binary the
/// suite runs that is not built ([`super::bins`], which says where the relay builds).
///
/// `KOTTON_RELAY_BIN` still wins: it names one binary, and the default only says which
/// directory cargo was writing into.
pub(crate) fn relay_bin() -> PathBuf {
    super::bins::require(super::bins::Bin::Relay).to_path_buf()
}

/// Start a relay (or adopt the one `KOTTON_RELAY_ADDR` names) and return its
/// `host:port` once `/health` answers.
///
/// With a state directory of its own, as every released relay has one: that is
/// where a relay makes its key, and a relay is its key
/// (`TASK-the-desktop-tells-the-vault-which-relays-to-stand-at`) — a vault is
/// told to stand at a relay by that key, and nothing names a keyless one.
pub async fn spawn() -> (Relay, String) {
    if let Ok(addr) = std::env::var("KOTTON_RELAY_ADDR") {
        return (Relay { child: None, state: None }, addr);
    }
    spawn_with_state().await
}

/// The key the relay at `relay_addr` proves — what it is named by.
pub async fn key_of(relay_addr: &str) -> [u8; 32] {
    kotton_peer::relay_key::prove_relay(&format!("http://{relay_addr}"), None)
        .await
        .expect("the relay proves its key")
        .expect("a relay with a state directory keeps a key")
}

/// A relay with `operator_hex` — the public half a test's desktop minted — as
/// its operator, so its rule can be read and set over the wire
/// (`TASK-a-device-presents-its-relays-admission-tag-and-the-reach-row-sets-the-rule`).
/// Created for the suite's own operator and given *anyone* under it, as
/// [`spawn_with_state`] is, and then `operator_hex` enrolled at its terminal:
/// the desktop holds the half the suite cannot sign with, so the suite's key
/// gives the rule a relay needs before any test handle is admitted.
/// Never `KOTTON_RELAY_ADDR`'s relay: a relay somewhere else has no terminal here.
pub async fn spawn_with_operator(operator_hex: &str) -> (Relay, String) {
    let (relay, addr) = spawn_with_state().await;
    relay.operator_enrol(operator_hex);
    (relay, addr)
}

/// A relay with a state directory of its own, created for an operator key the
/// suite mints and the test never holds, and given *anyone* under it: every
/// other key's operator call is refused until [`Relay::operator_enrol`] adds one
/// at its terminal (`TASK-no-test-enrols-the-relay-after-box-enrol`).
pub async fn spawn_with_state() -> (Relay, String) {
    let operator = ed25519_dalek::SigningKey::from_bytes(&rand::random());
    let state = tempfile::tempdir().expect("a relay state directory");
    create_at(state.path(), &hex::encode(operator.verifying_key().to_bytes()));
    let (relay, addr) = spawn_in(Some(state)).await;
    give_it_a_rule(&addr, &operator).await;
    (relay, addr)
}

/// `kotton-relay --state-dir <state> create --operator <operator_hex>`, as the
/// self-host adapter runs it; its last output is the relay's line, returned.
pub fn create_at(state: &std::path::Path, operator_hex: &str) -> String {
    let out = Command::new(relay_bin())
        .arg("--state-dir")
        .arg(state)
        .args(["create", "--operator", operator_hex])
        .stderr(Stdio::inherit())
        .output()
        .expect("kotton-relay create");
    assert!(out.status.success(), "the relay was not created");
    String::from_utf8(out.stdout).expect("its line").lines().last().expect("a line").to_owned()
}

/// The operator's first set, *anyone*, said over the wire as its desktop would.
async fn give_it_a_rule(addr: &str, operator: &ed25519_dalek::SigningKey) {
    let set = kotton_wire::rendezvous::RelayOperatorRequest::SetRule {
        rule: kotton_wire::rendezvous::AdmissionRule::Anyone,
        mine: None,
        invited: None,
    };
    match kotton_net::rendezvous::say_as_operator(&format!("http://{addr}"), operator, &set).await {
        Ok(kotton_wire::rendezvous::RelayOperatorResponse::Rule { .. }) => {}
        other => panic!("the suite's relay was not given its rule: {other:?}"),
    }
}

/// A `kotton-relay` from `state` — created already — at `bind`, announcing
/// `advertise`, once it has said where it listens: the child, the address it bound,
/// and its whole log (stdout, as the journal takes it) for as long as it runs
/// ([`started`]). A relay at a state directory, for a test that starts one itself.
/// `bind` is `127.0.0.1:0` unless the case is about the address itself: a
/// stranger's relay at another's address.
pub(crate) async fn relay_at(
    state: &std::path::Path,
    bind: &str,
    advertise: &str,
) -> (Child, String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    let mut command = Command::new(relay_bin());
    command
        .arg("--state-dir")
        .arg(state)
        .args(["--advertise", advertise])
        .env("RUST_LOG", "kotton_relay=info");
    started(command, bind)
}

impl Relay {
    /// `kotton-relay operator enrol <operator_hex>` at this running relay's
    /// terminal — a second operator beside the one it was created for. No
    /// restart: the relay reads its operators' file on every call.
    pub fn operator_enrol(&self, operator_hex: &str) {
        let state = self.state.as_ref().expect("a relay spawned with a state directory");
        enrol_at_the_terminal(state.path(), operator_hex);
    }
}

impl Relay {
    /// `kotton-relay operator revoke <operator_hex>` at this running relay's
    /// terminal. The relay never revokes its last operator; one spawned with
    /// [`spawn_with_operator`] keeps the suite's own.
    pub fn operator_revoke(&self, operator_hex: &str) {
        let state = self.state.as_ref().expect("a relay spawned with a state directory");
        let revoked = Command::new(relay_bin())
            .args(["operator", "revoke", operator_hex, "--state-dir"])
            .arg(state.path())
            .stdout(Stdio::null())
            .status()
            .expect("kotton-relay operator revoke");
        assert!(revoked.success(), "the relay's terminal did not revoke the operator");
    }
}

fn enrol_at_the_terminal(state: &std::path::Path, operator_hex: &str) {
    let enrolled = Command::new(relay_bin())
        .args(["operator", "enrol", operator_hex, "--state-dir"])
        .arg(state)
        .stdout(Stdio::null())
        .status()
        .expect("kotton-relay operator enrol");
    assert!(enrolled.success(), "the relay's terminal did not enrol the operator");
}

async fn spawn_in(state: Option<tempfile::TempDir>) -> (Relay, String) {
    let mut command = Command::new(relay_bin());
    if let Some(dir) = &state {
        command.arg("--state-dir").arg(dir.path());
    }
    command.env("RUST_LOG", std::env::var("RUST_LOG").unwrap_or_else(|_| "kotton_relay=warn".into()));
    let (child, addr, _) = started(command, "127.0.0.1:0");
    (Relay { child: Some(child), state }, addr)
}

/// The relay `command` starts, at `bind`, once it has said where it listens: the
/// child, the HTTP address it bound, and its whole stdout (as the journal takes
/// it) for as long as it runs.
///
/// Read off the line the relay prints once its sockets are bound
/// (`listening http=<addr> stun=<addr>`, `infra/relay/src/main.rs`), never
/// composed from what it was asked to bind: on port 0 the OS gives the port, at the
/// bind. Its STUN socket takes a port of its own the same way; nothing here dials
/// it. A relay that exits before it says so fails here with its status and what it
/// printed; its stderr is the test's.
fn started(mut command: Command, bind: &str) -> (Child, String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    use std::io::BufRead as _;
    let mut child = command
        .args(["--bind", bind, "--stun-bind", "127.0.0.1:0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn kotton-relay");
    let out = child.stdout.take().expect("its stdout");
    let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let kept = std::sync::Arc::clone(&log);
    let (bound, listening) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(out).lines().map_while(Result::ok) {
            if let Some(addr) = listening_at(&line) {
                let _ = bound.send(addr.to_owned());
            }
            kept.lock().unwrap().push(line);
        }
    });
    match listening.recv_timeout(READY_TIMEOUT) {
        Ok(addr) => (child, addr, log),
        Err(e) => {
            let _ = child.kill();
            let status = child.wait().map(|s| s.to_string()).unwrap_or_else(|e| e.to_string());
            let printed = log.lock().unwrap().join("\n");
            panic!("kotton-relay never said where it listens ({e}; {status}); it printed:\n{printed}")
        }
    }
}

/// The HTTP address in a relay's `listening http=<addr> stun=<addr>` line.
pub(crate) fn listening_at(line: &str) -> Option<&str> {
    line.strip_prefix("listening http=")?.split_whitespace().next()
}

/// A `TestEnv` whose daemon is pointed at `relay_addr`.
///
/// It used to set `KOTTON_RELAY_URL` around the spawn under a process-wide
/// lock, because that variable was the only door. A lock over a global is not
/// isolation — it orders the tests that take it and says nothing about the rest
/// of a suite constructing daemons on other threads — so the relay is now handed
/// to the daemon and no global is touched
/// (`TASK-a-process-global-relay-url-is-shared-by-tests-that-run-in-parallel`).
pub async fn env_on(relay_addr: &str) -> crate::common::TestEnv {
    keep_the_daemons_log();
    crate::common::TestEnv::spawn_at_relay(&format!("http://{relay_addr}")).await
}

/// What a relayed delivery's sender logs about each path that failed, kept in the
/// test's own output: libtest shows it for a failing test and drops it for a
/// passing one.
///
/// A daemon names why one path of a delivery failed only in its log
/// (`deliver_on`, "a contact's door did not answer"); the sender is owed four
/// words and no path (`DEC-0056`). The suite used to install no subscriber, so a
/// relayed test that failed at random kept only those four words, and the
/// transport error behind them was gone
/// (`TASK-a-reply-sent-at-once-can-find-no-door-open-for-it`). The mailbox's
/// warning is kept beside them: a rebuild that could not list a person's
/// contacts drops every door they hold, and it was the line that named why a
/// contact who rotated found none
/// (`TASK-a-contact-who-learned-a-rotated-key-is-sometimes-unreachable-at-the-new-door`).
/// With no `RUST_LOG`, only those lines are kept; `RUST_LOG` replaces the
/// filter whole, for reading more.
fn keep_the_daemons_log() {
    const WHY_A_DELIVERY_FAILED: &str =
        "kuserd::agent::message_host=info,kotton_msg::daemon::outbox=warn,kuserd::agent::mailbox=warn";
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(WHY_A_DELIVERY_FAILED));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).with_test_writer().try_init();
}

/// Stand the in-process `vault` at the relay at `relay_addr`, as its operator's
/// desktop tells it (`StandAt`), with no admission keys — a relay whose rule
/// nobody narrowed reads none. The telling in process, for a test that holds
/// the vault itself and is not testing the desktop's half; the vault reads no
/// relay from anywhere else
/// (`TASK-the-desktop-tells-the-vault-which-relays-to-stand-at`). It replaced
/// `spawned_on`, which set `KOTTON_RELAY_URL` around the vault's construction
/// under a process-wide lock.
pub async fn stand_at(vault: &kvaultd::Vault, relay_addr: &str) {
    let stand = kotton_wire::rendezvous::Stand {
        key: hex::encode(key_of(relay_addr).await),
        hint: format!("http://{relay_addr}"),
        mine: None,
        invited: None,
    };
    vault.stand_at(vec![stand]).await.expect("the vault stands where it is told");
}

/// A `TestEnv` whose daemon is pointed at **no** relay, stated. Nothing reads a
/// relay from the process environment any more, so this and a bare
/// `TestEnv::spawn()` are the same daemon; it stays as the statement.
pub async fn env_without() -> crate::common::TestEnv {
    crate::common::TestEnv::spawn_without_relay().await
}

/// How many control sockets the relay is holding, off its own `/metrics`.
///
/// A reservation is invisible from outside the relay process, so this is the
/// only instrument pointed at "did a ceremony reserve a mailbox?". The gauge is
/// a count and names nobody.
pub async fn reservations(relay_addr: &str) -> u32 {
    let body = reqwest::get(format!("http://{relay_addr}/metrics"))
        .await
        .expect("the relay answers /metrics")
        .text()
        .await
        .expect("a metrics body");
    body.lines()
        .find_map(|l| l.strip_prefix("kotton_relay_reservations "))
        .unwrap_or_else(|| panic!("no reservations gauge in:\n{body}"))
        .trim()
        .parse()
        .expect("the gauge is a number")
}

/// How many circuits the relay has bridged since it started, off its own
/// `/metrics` — the instrument that says a dial went through *this* relay. A
/// count, and it names nobody.
pub async fn circuits_bridged(relay_addr: &str) -> u64 {
    let body = reqwest::get(format!("http://{relay_addr}/metrics"))
        .await
        .expect("the relay answers /metrics")
        .text()
        .await
        .expect("a metrics body");
    body.lines()
        .find_map(|l| l.strip_prefix("kotton_relay_circuits_bridged_total "))
        .unwrap_or_else(|| panic!("no bridged counter in:\n{body}"))
        .trim()
        .parse()
        .expect("the counter is a number")
}
