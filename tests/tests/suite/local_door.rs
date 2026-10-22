// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — the local-network door is closed on a fresh device, and the row's
//! verb opens and shuts it
//! (`TASK-the-local-network-is-a-door-opened-on-purpose-for-ten-minutes-and-a-relay-introduces-your-devices`).
//!
//! # Why the fresh-device test runs in a child process
//!
//! The property is *this device opens no network socket*, and the instrument is the
//! process's own socket table: every descriptor in `/proc/self/fd` that is a socket,
//! looked up in `/proc/self/net/{tcp,tcp6,udp,udp6}`. That table is the whole process,
//! and this suite runs every test in one process — a neighbour's relay or gateway would
//! read as this daemon's. So the test re-runs its own binary filtered to itself, and the
//! child holds exactly one daemon and nothing else. It samples the table for six seconds
//! and counts every inet socket it ever sees, the loopback ones included:
//! `KOTTON_PAIR_LOCAL_ONLY=1` narrows an open door to loopback, and a door on loopback is
//! still a door this test must find.
//!
//! Linux-only, as `bind-check` is: the table it reads is Linux's.

#![cfg(target_os = "linux")]

use crate::common::{TestEnv, TEST_PASSPHRASE};
use kotton_wire::{UserRequest, UserResponse};
use std::collections::HashSet;
use std::time::Duration;

/// Set in the child's environment; the child runs the check, the parent reads it.
const CHILD: &str = "KOTTON_LOCAL_DOOR_FRESH_CHILD";
/// The line the child prints, so the parent can tell a clean result from a child that
/// never ran the check.
const MARK: &str = "FRESH-DEVICE-INET-SOCKETS";

/// Every inet socket this process holds, as `proto local-address` lines.
fn inet_sockets_of_this_process() -> Vec<String> {
    let mine: HashSet<String> = std::fs::read_dir("/proc/self/fd")
        .expect("read /proc/self/fd")
        .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
        .filter_map(|link| {
            let s = link.to_string_lossy().into_owned();
            s.strip_prefix("socket:[")?.strip_suffix(']').map(str::to_owned)
        })
        .collect();
    let mut found = Vec::new();
    for proto in ["tcp", "tcp6", "udp", "udp6"] {
        let table = std::fs::read_to_string(format!("/proc/self/net/{proto}")).unwrap_or_default();
        for line in table.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() > 9 && mine.contains(f[9]) {
                found.push(format!("{proto} {} state {}", f[1], f[3]));
            }
        }
    }
    found
}

async fn operator(env: &TestEnv) -> kotton_ipc::IpcClient<UserRequest, UserResponse> {
    let session = env.client.session_token.clone().expect("session token");
    let mut op = kotton_ipc::IpcClient::<UserRequest, UserResponse>::connect(env.endpoint.clone())
        .await
        .expect("connect");
    match op.send(&UserRequest::Authenticate { token: kotton_wire::ipc::SecretText::new(session), scope: None }).await {
        Ok(UserResponse::ActiveSession { .. }) => op,
        other => panic!("unexpected auth response: {other:?}"),
    }
}

async fn door(
    op: &mut kotton_ipc::IpcClient<UserRequest, UserResponse>,
    answer: Option<&str>,
) -> (String, Option<String>) {
    match op.send(&UserRequest::LocalDoor { answer: answer.map(str::to_owned) }).await {
        Ok(UserResponse::LocalDoorResult { answer, listening, .. }) => (answer, listening),
        other => panic!("LocalDoor({answer:?}): {other:?}"),
    }
}

/// A fresh device — booted, with a person on it, and nothing opened — holds no inet
/// socket at all: no listener on any address and no mDNS socket on `:5353`.
#[tokio::test]
async fn a_fresh_device_binds_no_port_and_announces_nothing() {
    if std::env::var_os(CHILD).is_some() {
        let mut env = TestEnv::spawn_without_relay().await;
        env.client.create_user("fresh", TEST_PASSPHRASE).await.expect("create_user");
        // Sampled every 100 ms for six seconds — the keeper's first pass and a second
        // one after it — and every socket seen at any sample is reported. A socket held
        // for less than a sample can slip between two; `bind-check`, which `just test`
        // runs over this suite, sees every non-loopback `bind(2)` exactly and is the
        // instrument for that case.
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..60 {
            seen.extend(inet_sockets_of_this_process());
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let sockets: Vec<String> = seen.into_iter().collect();
        println!("{MARK} {}", sockets.len());
        for s in &sockets {
            println!("  {s}");
        }
        assert!(sockets.is_empty(), "a fresh device holds network sockets: {sockets:?}");
        return;
    }

    let out = std::process::Command::new(std::env::current_exe().expect("this test binary"))
        .args([
            "--exact",
            "local_door::a_fresh_device_binds_no_port_and_announces_nothing",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, "1")
        .env_remove("KOTTON_PEER_LISTEN_PORT")
        .env_remove("KOTTON_RELAY_URL")
        .output()
        .expect("run the child");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(&format!("{MARK} 0")),
        "the child did not report a clean socket table (exit {:?}):\n{stdout}\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(out.status.success(), "the child failed:\n{stdout}");
}

/// The row's verb, end to end: *10 minutes* opens a listener, *Closed* removes it, and
/// the door reads closed before anyone touches it.
#[tokio::test]
async fn ten_minutes_opens_the_door_and_closed_shuts_it() {
    let mut env = TestEnv::spawn_without_relay().await;
    env.client.create_user("doorkeeper", TEST_PASSPHRASE).await.expect("create_user");
    let mut op = operator(&env).await;

    assert_eq!(door(&mut op, None).await, ("closed".to_owned(), None));

    let (answer, _) = door(&mut op, Some("10m")).await;
    assert_eq!(answer, "10m");
    let mut listening = None;
    for _ in 0..50 {
        listening = door(&mut op, None).await.1;
        if listening.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let addr = listening.expect("the door opens a listener within five seconds");

    let (answer, _) = door(&mut op, Some("closed")).await;
    assert_eq!(answer, "closed");
    let mut shut = false;
    for _ in 0..50 {
        if door(&mut op, None).await.1.is_none() {
            shut = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(shut, "the door at {addr} was still listening five seconds after closed");
}

/// Anything but the three answers is refused, not guessed at.
#[tokio::test]
async fn an_answer_that_is_not_one_of_the_three_is_refused() {
    let mut env = TestEnv::spawn_without_relay().await;
    env.client.create_user("doorword", TEST_PASSPHRASE).await.expect("create_user");
    let mut op = operator(&env).await;
    match op.send(&UserRequest::LocalDoor { answer: Some("open".into()) }).await {
        Ok(UserResponse::Error { message }) => assert!(message.contains("closed, 10m or always")),
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert_eq!(door(&mut op, None).await.0, "closed");
}
