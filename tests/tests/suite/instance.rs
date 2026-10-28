// SPDX-License-Identifier: AGPL-3.0-or-later
//! A relay is created for its operator's key, prints its line, and does not
//! start without an operator — the binary, as a host runs it (RFC-0084, the
//! amendment of 2026-10-01: V18, V19, V20). What replaced `claim::`.
//!
//! The vault's half of each is `core/kvaultd/tests/a_vault_is_created_with_its_operator.rs`
//! and `kvaultd::instance`'s own tests; the in-process vault's admission is
//! `vault::a_service_started_with_its_operators_key_admits_that_key_and_no_other`
//! and `vault::a_strangers_handshake_is_refused_at_a_vault_and_no_claim_is_ever_open`.

use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use kotton_wire::ipc::OperatedService;
use kotton_wire::line::InstanceLine;

use crate::common::relay::{create_at, relay_bin};

/// ed25519's base point: a key whose secret half nobody here holds.
const OPERATOR: &str = "5866666666666666666666666666666666666666666666666666666666666666";

fn said(out: &Output) -> String {
    format!(
        "exit {:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// `kotton-relay` with `args`, on loopback ports the OS gives it, run to its end
/// or for at most ten seconds.
fn relay_run(args: &[&str]) -> Output {
    let mut child = Command::new(relay_bin())
        .args(args)
        .args(["--bind", "127.0.0.1:0", "--stun-bind", "127.0.0.1:0"])
        .env("RUST_LOG", "kotton_relay=warn")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn kotton-relay");
    let deadline = Instant::now() + Duration::from_secs(10);
    while child.try_wait().expect("the relay's status").is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().expect("its output")
}

/// A refused start bound nothing: it never printed where it listens, the line a
/// start prints once its sockets are bound. It was given port 0 for both, so no
/// port was named before it ran for the test to look at instead.
fn bound_nothing(out: &Output) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.lines().any(|l| crate::common::relay::listening_at(l).is_some()),
        "a refused start bound a socket first: {}",
        said(out)
    );
}

/// Every run of hex digits exactly 32 long — the shape of the claim's
/// one-time secret.
fn tokens_of_32_hex(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|b| !b.is_ascii_hexdigit())
        .filter(|run| run.len() == 32)
        .map(|run| String::from_utf8_lossy(run).into_owned())
        .collect()
}

fn kept(dir: &Path) -> Vec<(String, Vec<u8>)> {
    std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| (e.file_name().to_string_lossy().into_owned(), std::fs::read(e.path()).unwrap_or_default()))
        .collect()
}

/// **A relay whose state names no operator, and a relay with no state
/// directory given no `--operator`, each exit non-zero before binding
/// anything, with one sentence naming `create --operator`** (RFC-0084 V19,
/// fork 4) — the first naming its state directory too, and making nothing in
/// it.
#[test]
fn an_instance_with_no_operator_refuses_to_start_and_names_create() {
    let state = tempfile::tempdir().expect("a relay state directory");
    let dir = state.path().display().to_string();
    let out = relay_run(&["--state-dir", &dir]);
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains(&dir) && err.contains("kotton-relay create --state-dir"), "{}", said(&out));
    assert!(err.contains("--operator <key>"), "{}", said(&out));
    let made: Vec<String> = kept(state.path()).into_iter().map(|(f, _)| f).collect();
    assert_eq!(made, ["instance.lock"], "the refused start made something in the state directory but its lock");
    bound_nothing(&out);

    let out = relay_run(&[]);
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("kotton-relay --operator <key>") && err.contains("create --state-dir <dir> --operator <key>"), "{}", said(&out));
    bound_nothing(&out);
}

/// **`kotton-relay create` prints the relay's line as its last output; every
/// start — with a state directory, and in memory with `--operator` — prints a
/// line; and no 32-hex token appears in anything a relay prints or keeps**
/// (RFC-0084 V18, V19, V20). The created relay's start prints the line its
/// creation printed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_services_start_prints_its_line_and_no_secret() {
    let state = tempfile::tempdir().expect("a relay state directory");
    // The hint its line carries, written at creation, before it runs: what it says
    // it is reached at, signed, never dialled here — so not a port it binds.
    let url = "http://relay.test:7700";
    let created = Command::new(relay_bin())
        .arg("--state-dir")
        .arg(state.path())
        .args(["--advertise", url, "create", "--operator", OPERATOR])
        .output()
        .expect("kotton-relay create");
    assert!(created.status.success(), "{}", said(&created));
    let stdout = String::from_utf8_lossy(&created.stdout);
    let line = InstanceLine::parse(stdout.lines().last().unwrap_or_default()).unwrap_or_else(|e| panic!("{e}: {}", said(&created)));
    assert_eq!((line.kind, line.hint.as_str()), (OperatedService::Relay, url));

    let (mut relay, addr, log) = crate::common::relay::relay_at(state.path(), "127.0.0.1:0", url).await;
    let key = crate::common::relay::key_of(&addr).await;
    let _ = relay.kill();
    let _ = relay.wait();
    let printed = log.lock().unwrap().join("\n");
    assert!(printed.lines().any(|l| l == line.to_text()), "the start printed another line than creation's:\n{printed}");
    assert_eq!(line.key, key, "the line names the key the relay proves");

    let in_memory = relay_run(&["--operator", OPERATOR]);
    let in_memory_out = String::from_utf8_lossy(&in_memory.stdout).to_string();
    let first = in_memory_out.lines().next().unwrap_or_default();
    let line = InstanceLine::parse(first).unwrap_or_else(|e| panic!("{e}: {}", said(&in_memory)));
    assert_eq!(line.kind, OperatedService::Relay, "an in-memory relay prints its line too");

    let mut found = Vec::new();
    for (what, bytes) in [
        ("create's stdout", created.stdout.clone()),
        ("create's stderr", created.stderr.clone()),
        ("the start's stdout", printed.into_bytes()),
        ("the in-memory start's output", [in_memory.stdout.clone(), in_memory.stderr.clone()].concat()),
    ] {
        found.extend(tokens_of_32_hex(&bytes).into_iter().map(|t| format!("{what}: {t}")));
    }
    for (file, bytes) in kept(state.path()) {
        found.extend(tokens_of_32_hex(&bytes).into_iter().map(|t| format!("{file}: {t}")));
    }
    assert!(found.is_empty(), "a 32-hex token was printed or kept:\n{}", found.join("\n"));
}

/// **`create` is refused while a relay serves on the state, and changes
/// nothing; and a relay does not start on a state `create` holds** — the
/// exclusive lock on `instance.lock`, taken here as `create` takes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_refuses_while_an_instance_runs_on_the_state() {
    let state = tempfile::tempdir().expect("a relay state directory");
    create_at(state.path(), OPERATOR);
    let (mut relay, _, _) = crate::common::relay::relay_at(state.path(), "127.0.0.1:0", "").await;
    let before = kept(state.path());
    let out = Command::new(relay_bin())
        .arg("--state-dir")
        .arg(state.path())
        .args(["create", "--operator", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"])
        .output()
        .expect("kotton-relay create");
    let _ = relay.kill();
    let _ = relay.wait();
    assert!(!out.status.success(), "{}", said(&out));
    assert!(String::from_utf8_lossy(&out.stderr).contains("held by another kotton-relay"), "{}", said(&out));
    assert_eq!(kept(state.path()), before, "create changed a served state");
}

#[test]
fn an_instance_does_not_start_while_create_holds_its_state() {
    let state = tempfile::tempdir().expect("a relay state directory");
    create_at(state.path(), OPERATOR);
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(state.path().join("instance.lock"))
        .expect("the lock file creation made");
    lock.try_lock().expect("held here, as create holds it");
    let dir = state.path().display().to_string();
    let out = relay_run(&["--state-dir", &dir]);
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    assert!(String::from_utf8_lossy(&out.stderr).contains("held by another kotton-relay"), "{}", said(&out));
    bound_nothing(&out);
    drop(lock);
}

/// **A start deletes a leftover claim file**: a relay operated before the
/// claim was deleted may still keep the claim's file, with a secret in it;
/// nothing reads it, and the relay removes it as it starts rather than keep a
/// dead secret on disk.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_start_deletes_a_leftover_claim_file() {
    let state = tempfile::tempdir().expect("a relay state directory");
    create_at(state.path(), OPERATOR);
    let leftover = state.path().join("claim");
    std::fs::write(&leftover, b"an open secret the deleted claim kept").unwrap();
    let (mut relay, _, _) = crate::common::relay::relay_at(state.path(), "127.0.0.1:0", "").await;
    let _ = relay.kill();
    let _ = relay.wait();
    assert!(!leftover.exists(), "the start kept the claim's secret on disk");
}

/// **A start never makes a key over existing state** (the relay's half): a
/// relay created and then missing `identity.key` is refused its start by the
/// binary, naming the key file and that a start makes none, and no key is
/// made — where a minting start would come up as a relay nobody knows,
/// printing a line with a key no desktop expects.
#[test]
fn a_start_never_mints_a_key_over_existing_state() {
    let state = tempfile::tempdir().expect("a relay state directory");
    create_at(state.path(), OPERATOR);
    let key = state.path().join("identity.key");
    std::fs::remove_file(&key).unwrap();
    let dir = state.path().display().to_string();
    let out = relay_run(&["--state-dir", &dir]);
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("identity.key") && err.contains("never makes a"), "{}", said(&out));
    assert!(!key.exists(), "the start made a key over existing state");
    bound_nothing(&out);
}
