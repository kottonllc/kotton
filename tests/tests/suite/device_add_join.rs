// SPDX-License-Identifier: AGPL-3.0-or-later
//! End-to-end: the RFC-0040 streamed six-digit pairing ceremony across two
//! daemons. Drives the real `device_add_stream` / `device_join_stream` +
//! `pair_confirm_code` SDK path (the CLI's `device add` / `device join`), proving
//! the committed handshake, the streamed §7 states, the out-of-band SAS confirm,
//! and the shared completion (share persistence, AID adoption, session issuance).
//!
//! Self-contained: two in-process daemons on loopback, direct QUIC, no relay.
//!
//! The same ceremony is then walked the way a person walks it, each side a `kotton`
//! process at its own device's terminal: `kotton device add` where the identity is,
//! `kotton id join` on a device with none, the six digits read off one and typed
//! into the other.

use kotton_sys::secret::SecretsStore;
use kotton_secret::MemorySecrets;
use kotton_schemas::membership::Posture;
use kotton::{KottonClient, UserResponse};
use kuserd::DeviceDaemon;
use std::sync::Arc;
use tokio::sync::oneshot;

use crate::common::{connect_when_ready, unique_ipc, wait_for_daemon};

fn init_crypto() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
    });
}

/// Outcome collected from one side's ceremony stream.
struct Outcome {
    /// The SAS shown to this side's human (they must match across both sides).
    sas: u32,
    /// The terminal frame: the paired node + an optional session token.
    node_id: String,
    session_token: Option<String>,
}

/// Drive one ceremony stream to completion, auto-confirming the SAS via
/// `pair_confirm_code`. Optionally forwards the connection code (issuer only).
async fn drive(
    client: KottonClient,
    user: String,
    mut rx: tokio::sync::mpsc::Receiver<UserResponse>,
    mut code_tx: Option<oneshot::Sender<String>>,
) -> Result<Outcome, String> {
    let mut sas_seen: Option<u32> = None;
    while let Some(frame) = rx.recv().await {
        match frame {
            UserResponse::PairAdvertising { code, .. } => {
                if let Some(tx) = code_tx.take() {
                    let _ = tx.send(code.expose().to_string());
                }
            }
            UserResponse::PairShowCode { token, sas, .. } => {
                sas_seen = Some(sas);
                client
                    .pair_confirm_code(&user, token.expose(), true)
                    .await
                    .map_err(|e| format!("confirm failed: {e}"))?;
            }
            UserResponse::PairingComplete {
                node,
                session_token,
                ..
            } => {
                return Ok(Outcome {
                    sas: sas_seen.expect("a SAS was shown before completion"),
                    node_id: node.id,
                    session_token: session_token.map(|t| t.expose().to_owned()),
                });
            }
            UserResponse::PairFailed { reason } => return Err(reason),
            _ => {}
        }
    }
    Err("stream closed before completion".to_string())
}

#[tokio::test]
async fn device_add_join_streams_a_confirmed_six_digit_ceremony() {
    init_crypto();

    // Both daemons share this host: bind the bootstrap listener to loopback and skip
    // mDNS, so the OS firewall never prompts on a LAN-facing socket during the test.
    // The joiner uses the connection code, not discovery, so nothing is lost.
    #[allow(unsafe_code)] // env::set_var is unsafe in Rust 1.81+; single test, set before any daemon binds
    unsafe {
        std::env::set_var("KOTTON_PAIR_LOCAL_ONLY", "1");
    }

    // ── Two in-process daemons on unique sockets ──────────────────────────────
    let base_e = tempfile::tempdir().expect("base_e");
    let ipc_e = unique_ipc();
    let secrets_e: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    let daemon_e = DeviceDaemon::new_with_base_and_secrets(
        base_e.path().to_owned(),
        ipc_e.clone(),
        Arc::clone(&secrets_e),
    )
    .await
    .expect("daemon E");

    let base_n = tempfile::tempdir().expect("base_n");
    let ipc_n = unique_ipc();
    let secrets_n: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    let daemon_n = DeviceDaemon::new_with_base_and_secrets(
        base_n.path().to_owned(),
        ipc_n.clone(),
        Arc::clone(&secrets_n),
    )
    .await
    .expect("daemon N");

    let _task_e = tokio::spawn(async move { std::sync::Arc::new(daemon_e).run().await });
    let _task_n = tokio::spawn(async move { std::sync::Arc::new(daemon_n).run().await });
    wait_for_daemon(&ipc_e, "daemon E").await;
    wait_for_daemon(&ipc_n, "daemon N").await;

    let mut client_e = connect_when_ready(&ipc_e, "client_e").await;
    let client_n = connect_when_ready(&ipc_n, "client_n").await;

    // E creates the user (this authenticates client_e for the session-gated add).
    let (did_e, _fp) = client_e.create_user("alice", crate::common::TEST_PASSPHRASE).await.expect("create_user E");

    // ── Run the streamed ceremony: E adds, N joins, both confirm the SAS. ──────
    let (code_tx, code_rx) = oneshot::channel::<String>();

    // Each device announces its OWN name; the peer adopts it (RFC-0040 §1). E is
    // the existing device, N is the new one.
    // Port 0: E's daemon binds what the OS gives it and says it in the code. A
    // port picked here and bound there is a race with every other test binding
    // one meanwhile (#110).
    let issuer = tokio::spawn(async move {
        let rx = client_e
            .device_add_stream("alice", Some("device-e"), 30, 0, Posture::Full)
            .await
            .expect("device_add_stream");
        drive(client_e, "alice".to_string(), rx, Some(code_tx)).await
    });

    let joiner = tokio::spawn(async move {
        let code = code_rx.await.expect("issuer produced a connection code");
        let rx = client_n
            .device_join_stream("alice", &code, Some("device-n"))
            .await
            .expect("device_join_stream");
        drive(client_n, "alice".to_string(), rx, None).await
    });

    let issuer_out = issuer.await.unwrap().expect("issuer ceremony completed");
    let joiner_out = joiner.await.unwrap().expect("joiner ceremony completed");

    // ── The security invariant: both humans saw the SAME six digits. ──────────
    assert_eq!(
        issuer_out.sas, joiner_out.sas,
        "both sides derived the same SAS ({} vs {})",
        issuer_out.sas, joiner_out.sas
    );
    assert!(issuer_out.sas < 1_000_000, "SAS is six decimal digits");

    // The issuer recorded the joiner; the joiner recorded the issuer.
    assert_eq!(issuer_out.node_id, "device-n");
    assert_eq!(joiner_out.node_id, "device-e");

    // The join cryptographically authenticated the new device, so it was issued a
    // session; the issuer keeps its existing session (no new token).
    assert!(
        joiner_out.session_token.is_some(),
        "the joined device received a session"
    );
    assert!(
        issuer_out.session_token.is_none(),
        "the issuer keeps its existing session"
    );

    // ── Both persisted a distinct FROST share (the DID-preserving 2-of-2). ────
    let share_e = secrets_e
        .get_secret(&kotton_common::crypto::kdf_labels::frost_share("alice"))
        .unwrap();
    let share_n = secrets_n
        .get_secret(&kotton_common::crypto::kdf_labels::frost_share("alice"))
        .unwrap();
    assert!(share_e.is_some(), "issuer persisted its share");
    assert!(share_n.is_some(), "joiner persisted its share");
    assert_ne!(share_e, share_n, "the two shares are distinct");

    // ── RFC-0038: the joiner adopted the issuer's did:kel AID via the attested,
    //    delivered KEL — the whole fleet agrees on one identity. ───────────────
    let kel_n = kotton_identity::kel_store::load_chain(base_n.path(), "alice")
        .expect("load N's stored KEL");
    assert!(!kel_n.is_empty(), "the joiner stored the delivered KEL");
    assert_eq!(
        kel_n[0].aid.to_string(),
        did_e,
        "the joined device adopts the issuer's did:kel AID as its user identity"
    );
}

/// A `kotton` process on pipes, and everything it has written to either stream so far.
struct Typed {
    child: std::process::Child,
    said: Arc<std::sync::Mutex<Said>>,
    pumps: Vec<std::thread::JoinHandle<()>>,
}

/// What a `kotton` process wrote, **each stream kept on its own**.
///
/// Its two streams are pipes read by two threads. One string for both held them
/// in whatever order the threads ran, so under load a refusal on stderr landed on
/// the line where stdout's `[y/N] $` prompt waits with no newline, and a case
/// counting lines that *start* `error:` counted none (#136). Nothing here reads
/// where one stream's text falls against the other's: what a person waits for is
/// read off stdout's own lines, and a refusal off stderr's, where the CLI writes it.
#[derive(Clone, Default)]
struct Said {
    out: String,
    err: String,
}

impl Said {
    /// The lines it wrote to stdout: its prompts, the code, the digits, the result.
    fn lines(&self) -> std::str::Lines<'_> {
        self.out.lines()
    }

    /// Each sentence of refusal it wrote: each stderr line that starts `error:`.
    ///
    /// That is the CLI's contract, in one place: `finish()` (`client/cli/src/bridge.rs`)
    /// writes a refusal as `error: {e}` at the start of a stderr line, once, and never
    /// on stdout. An `error:` a refusal quotes, or one in the middle of a warning's
    /// line, is not another refusal (#156).
    fn refusals(&self) -> Vec<&str> {
        self.err.lines().filter(|line| line.starts_with("error:")).collect()
    }
}

impl std::fmt::Display for Said {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "--- stdout ---\n{}\n--- stderr ---\n{}", self.out, self.err)
    }
}

impl Typed {
    fn start(cli: &crate::common::cli::Cli, args: &[&str]) -> Self {
        use std::io::Read as _;
        let mut child = cli.spawn_on_pipes(args);
        let said = Arc::new(std::sync::Mutex::new(Said::default()));
        // Each stream into its own string: `false` is stdout, `true` stderr.
        let streams: [(Box<dyn std::io::Read + Send>, bool); 2] = [
            (Box::new(child.stdout.take().expect("stdout")), false),
            (Box::new(child.stderr.take().expect("stderr")), true),
        ];
        let pumps = streams
            .into_iter()
            .map(|(mut stream, is_err)| {
                let said = Arc::clone(&said);
                std::thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    while let Ok(n @ 1..) = stream.read(&mut buf) {
                        let mut said = said.lock().unwrap();
                        let into = if is_err { &mut said.err } else { &mut said.out };
                        into.push_str(&String::from_utf8_lossy(&buf[..n]));
                    }
                })
            })
            .collect();
        Self { child, said, pumps }
    }

    fn said(&self) -> Said {
        self.said.lock().unwrap().clone()
    }

    /// Wait for a line this process prints to stdout that `read` finds something in —
    /// what a person waits for before reading it off the screen.
    async fn shows<T>(&self, what: &str, read: impl Fn(&str) -> Option<T>) -> T {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            if let Some(found) = self.said().lines().find_map(&read) {
                return found;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "it never showed {what}\n--- its terminal ---\n{}",
                self.said()
            );
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    fn types(&mut self, line: &str) {
        use std::io::Write as _;
        let stdin = self.child.stdin.as_mut().expect("stdin");
        writeln!(stdin, "{line}").expect("type at its prompt");
    }

    /// Wait for it to exit; whether it succeeded, and all it said.
    async fn exits(mut self) -> (bool, Said) {
        drop(self.child.stdin.take());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
        let status = loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                let _ = self.child.kill();
                panic!("it never exited\n--- its terminal ---\n{}", self.said());
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        };
        for pump in self.pumps.drain(..) {
            pump.join().expect("the output is read");
        }
        (status.success(), self.said())
    }
}

impl Drop for Typed {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

/// The connection code a `device add` prints, from the line it tells the new device to
/// type: `kotton id join <name> <code>`.
fn code_in(line: &str) -> Option<String> {
    match line.split_whitespace().collect::<Vec<_>>().as_slice() {
        ["kotton", "id", "join", "alice", code] => Some(code.to_string()),
        _ => None,
    }
}

/// The six digits the new device shows, as `NNN NNN` on a line of their own.
fn digits_in(line: &str) -> Option<String> {
    match line.split_whitespace().collect::<Vec<_>>().as_slice() {
        [a, b] if a.len() == 3 && b.len() == 3 && a.chars().chain(b.chars()).all(|c| c.is_ascii_digit()) => {
            Some(format!("{a}{b}"))
        }
        _ => None,
    }
}

/// Two devices, each a daemon a `kotton` process finds on its own: the one you have,
/// where `alice` lives and whose session its terminal holds, and a new one with no
/// identity at all. The add runs at the first's terminal; the join is started at the
/// second's with the code the add printed, and has shown its six digits.
async fn an_add_and_a_join_showing_digits() -> (
    crate::common::TestEnv,
    crate::common::TestEnv,
    Typed,
    Typed,
    String,
) {
    use crate::common::{cli::Cli, TestEnv};
    init_crypto();
    // Both daemons are in this process and on this host: loopback, no mDNS, as above.
    #[allow(unsafe_code)] // env::set_var is unsafe in Rust 1.81+; set before either daemon binds
    unsafe {
        std::env::set_var("KOTTON_PAIR_LOCAL_ONLY", "1");
    }
    let mut have = TestEnv::spawn_cli_reachable().await;
    let new = TestEnv::spawn_cli_reachable().await;
    have.client
        .create_user("alice", crate::common::TEST_PASSPHRASE)
        .await
        .expect("create_user");
    let at_have = Cli::for_env(&have);
    at_have.seed_session("alice", have.client.session_token.as_deref().expect("create_user bound a session"));

    let add = Typed::start(&at_have, &["device", "--user", "alice", "add", "--as", "device-e"]);
    let code = add.shows("a code for the new device", code_in).await;
    let join = Typed::start(&Cli::for_env(&new), &["id", "join", "alice", &code]);
    let digits = join.shows("six digits", digits_in).await;
    (have, new, add, join, digits)
}

/// **Joining an identity from a second device is one command at its terminal.** On
/// the device you have, `kotton device add` prints the command; on a device with no
/// identity, `kotton id join alice <code>` shows six digits, they are typed where
/// the add asks for them, and the join answers `y`. Both exit 0; the new device acts
/// as `alice` and says so on its last line, and its next command, with no terminal
/// to ask a credential at, acts as `alice` on the session the ceremony issued.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn id_join_at_a_terminal_with_no_identity_takes_the_digits_device_add_asks_for() {
    let (_have, new, mut add, mut join, digits) = an_add_and_a_join_showing_digits().await;
    join.types("y");
    add.types(&digits);
    let (added, add_said) = add.exits().await;
    let (joined, join_said) = join.exits().await;
    assert!(added, "the add, given the digits the new device showed, failed\n{add_said}");
    assert!(joined, "the join failed\n--- the new device ---\n{join_said}");
    // The last line it printed to stdout; a refusal or a warning on stderr is not it,
    // wherever the pipes put one against the other.
    let last = join_said.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or_default();
    assert!(
        last.contains("this device acts as") && last.contains("alice"),
        "the join's last line does not say the device acts as alice: {last:?}\n{join_said}"
    );

    let at_new = crate::common::cli::Cli::for_env(&new);
    assert_eq!(
        std::fs::read_to_string(new.base_dir.join("active_identity")).ok().as_deref().map(str::trim),
        Some("alice"),
        "the new device does not act as alice"
    );
    let listed = at_new.run(&["device", "list"]);
    let said = crate::common::cli::said(&listed);
    assert!(listed.status.success(), "the new device's next command could not act as alice\n{said}");
    assert!(said.contains("device-e"), "the new device does not list the one it joined\n{said}");
}

/// **When the device you have refuses, the join says so in one sentence and exits
/// non-zero**, and the new device is left acting as nobody.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn id_join_refused_by_the_device_you_have_exits_non_zero_in_one_sentence() {
    let (_have, new, mut add, mut join, digits) = an_add_and_a_join_showing_digits().await;
    let shown: u32 = digits.parse().expect("six digits");
    join.types("y");
    add.types(&format!("{:06}", (shown + 1) % 1_000_000));
    let (added, add_said) = add.exits().await;
    let (joined, join_said) = join.exits().await;
    assert!(!added, "the add took digits the new device never showed\n{add_said}");
    assert!(!joined, "the join completed though the other device refused it\n{join_said}");
    let refusals = join_said.refusals();
    assert_eq!(refusals.len(), 1, "not one sentence of refusal: {refusals:?}\n{join_said}");
    assert!(!join_said.to_string().contains("this device acts as"), "{join_said}");
    assert!(
        !new.base_dir.join("active_identity").exists(),
        "a refused join left the new device acting as someone"
    );
}

/// **A refusal is one sentence, read where the CLI writes it** (#136, #156): a stderr
/// line that starts `error:`, whatever stdout's prompt was doing when it came — and
/// neither an `error:` the sentence quotes nor one inside a warning's line counts again.
#[test]
fn a_refusal_is_found_wherever_the_terminal_put_it() {
    let refusal = "error: Lost the connection before anything was shared. Try again.";
    let nested = "error: Joined, but saving your keys failed: io error: No space left on device";
    let warning = "warning: the relay said error: busy, trying the next one";
    let prompt = "  join \"device-e\"? [y/N] $ ";
    for (out, err, sentence) in [
        // After a prompt that waits with no newline.
        (prompt.to_string(), format!("{refusal}\n"), refusal),
        // A refusal that quotes an inner error is still one sentence.
        (prompt.to_string(), format!("{nested}\n"), nested),
        // A warning with `error:` mid-line is not a refusal; the refusal after it is.
        (format!("{prompt}\n"), format!("{warning}\n{refusal}\n"), refusal),
    ] {
        let said = Said { out, err };
        assert_eq!(said.refusals(), [sentence], "{said}");
    }
    let warned = Said { out: String::new(), err: format!("{warning}\n") };
    assert!(warned.refusals().is_empty(), "{warned}");
    // The CLI never writes a refusal to stdout, so nothing there is read as one.
    let on_stdout = Said { out: format!("{refusal}\n"), err: String::new() };
    assert!(on_stdout.refusals().is_empty(), "{on_stdout}");
    let twice = Said { out: String::new(), err: format!("{refusal}\n{refusal}\n") };
    assert_eq!(twice.refusals().len(), 2, "{twice}");
}
