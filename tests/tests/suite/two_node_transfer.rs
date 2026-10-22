// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration test — two_node_transfer
//!
//! Two separate `kuserd` processes, each with its own base directory and IPC
//! socket, exchange identity via `GetNodeIdentity` + `PeerAdd`, and B attempts
//! to pull files written on A over a real QUIC mTLS connection.
//!
//! **What this asserts changed with RFC-0041.** Each daemon runs its own
//! `create_user("alice")`, so the two "alices" are unrelated identities with
//! unrelated CEKs — different key domains. Pre-RFC-0041 sync moved plaintext,
//! so the pull "worked"; that was the defect. Now sealed replication across
//! key domains must be **refused at the boundary**: pulling blobs this node's
//! keys cannot open would store objects nobody can attribute to a key. The
//! cross-process *happy path* — same identity on both nodes, via enrollment —
//! lives in `enroll_threshold_sign::file_written_on_one_device_syncs_to_a_joined_device`.
//!
//! History: this test once also exposed a keychain-collision defect — OS
//! keychain entries are keyed by user_id alone and machine-global, so B's
//! `create_user("alice")` rewrote A's roots, and A then *advertised* the
//! keychain's domain while *sealing* under its runtime's CEK. The blobs passed
//! B's domain gate and landed unopenable. `user_cek_domain_id` now derives
//! from the live runtime's CEK, making the gate truthful and this refusal
//! deterministic.
//!
//! This test promotes the Phase 2 "two-node loopback sync integration test"
//! deferred item from `oss-ready-v2/rfc_0017_ksyncd.md`.
//!
//! # Environment
//!
//! `KUSERD_BIN` is set at compile time by `build.rs` to the path of the
//! `kuserd` binary in the current build profile.  The binary must have been
//! built before running this test (`cargo build --bin kuserd`).

use kotton_sys::ipc::IpcEndpoint;
use kotton_wire::remote::RemoteBackend;
use kotton::SyncDirection;
use std::net::UdpSocket;
use std::process::{Child, Command, Stdio};
use tempfile::TempDir;
use uuid::Uuid;

use crate::common::{connect_when_ready, wait_for_daemon};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn free_udp_port() -> u16 {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind :0 for port probe");
    sock.local_addr().expect("local_addr").port()
}

fn unique_pipe() -> String {
    Uuid::new_v4().simple().to_string()
}

struct DaemonProcess {
    child: Child,
    endpoint: IpcEndpoint,
    _base: TempDir,
    _base_path: std::path::PathBuf,
}

impl DaemonProcess {
    /// Spawn a `kuserd` process with an isolated base dir, unique IPC name,
    /// and a QUIC peer listener on `peer_port`.
    fn spawn(peer_port: u16) -> Self {
        let base = tempfile::tempdir().expect("create tempdir");
        let base_path = base.path().to_owned();
        let ipc_name = unique_pipe();

        let kuserd_bin = crate::common::kuserd_bin();

        #[cfg(windows)]
        let endpoint = IpcEndpoint::NamedPipe(ipc_name.clone());
        #[cfg(unix)]
        let endpoint = {
            // The door the daemon will bind, asked of the rule it asks, over the
            // environment it gets: this process's, with the two variables set below.
            // Writing the runtime-dir tiers out here left out the `sun_path` fallback, so
            // under a long `XDG_RUNTIME_DIR` or `TMPDIR` this waited at a door nobody
            // opened (`TASK-a-suite-test-and-xtasks-poller-still-derive-kuserds-door-by-a-copy-of-the-rule`).
            let base = base_path.to_str().expect("the test base dir is UTF-8").to_string();
            let env = |key: &str| match key {
                "KOTTON_BASE_DIR" => Some(base.clone()),
                "KUSERD_IPC_NAME" => Some(ipc_name.clone()),
                _ => std::env::var(key).ok(),
            };
            IpcEndpoint::UnixSocket(kotton_common::paths::kuserd_door_in(&env).expect("kuserd_door_in"))
        };

        #[cfg(windows)]
        let ipc_env_val = ipc_name.clone();
        // On Unix, KUSERD_IPC_NAME is just the bare name — kuserd calls daemon_socket_path()
        // to construct the full socket path.  Passing a full path here caused double-suffixing.
        #[cfg(unix)]
        let ipc_env_val = ipc_name.clone();

        let child = Command::new(kuserd_bin)
            .env("KOTTON_BASE_DIR", &base_path)
            .env("KUSERD_IPC_NAME", &ipc_env_val)
            .env("KOTTON_PEER_LISTEN_PORT", peer_port.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn kuserd");

        DaemonProcess {
            child,
            endpoint,
            _base: base,
            _base_path: base_path,
        }
    }
}

impl Drop for DaemonProcess {
    fn drop(&mut self) {
        // Best-effort kill; ignore errors (process may have already exited).
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

/// End-to-end cross-process refusal of cross-domain sealed replication.
///
/// Two `kuserd` processes (A = source, B = sink) run in separate OS processes,
/// each with its own independently created "alice" — two unrelated key
/// domains. The test:
/// 1. Spawns A and B, each on their own base dir, IPC socket, and QUIC port.
/// 2. Queries each daemon's identity via `GetNodeIdentity`.
/// 3. Registers each as a peer of the other via `PeerAdd`.
/// 4. Writes 3 files on A.
/// 5. Adds A as a remote on B and attempts a pull.
/// 6. Asserts the pull is refused (key-domain mismatch) and that nothing
///    half-transferred: no file is readable on B, and A still reads its own.
///
/// This is the cross-process twin of the in-process
/// `peer_sync_across_key_domains_is_refused` (RFC-0041).
#[tokio::test]
async fn two_node_transfer_across_key_domains_is_refused() {
    let port_a = free_udp_port();
    let port_b = free_udp_port();

    let proc_a = DaemonProcess::spawn(port_a);
    let proc_b = DaemonProcess::spawn(port_b);

    // This test had the only correct version of this wait; it is now the shared
    // one, so the five files that slept instead get it too.
    wait_for_daemon(&proc_a.endpoint, "daemon A").await;
    wait_for_daemon(&proc_b.endpoint, "daemon B").await;

    // ── Connect SDK clients ──────────────────────────────────────────────────
    let mut client_a = connect_when_ready(&proc_a.endpoint, "connect client_a").await;
    let mut client_b = connect_when_ready(&proc_b.endpoint, "connect client_b").await;

    // ── Get each daemon's identity ───────────────────────────────────────────
    let (did_a, pubkey_hex_a) = client_a
        .get_node_identity()
        .await
        .expect("get_node_identity A");
    let (did_b, pubkey_hex_b) = client_b
        .get_node_identity()
        .await
        .expect("get_node_identity B");

    // ── Create users on both nodes ───────────────────────────────────────────
    client_a.create_user("alice", crate::common::TEST_PASSPHRASE).await.expect("create_user A");
    client_b.create_user("alice", crate::common::TEST_PASSPHRASE).await.expect("create_user B");

    // ── Cross-register as peers ──────────────────────────────────────────────
    let addr_a: std::net::SocketAddr = format!("127.0.0.1:{port_a}").parse().unwrap();
    let addr_b: std::net::SocketAddr = format!("127.0.0.1:{port_b}").parse().unwrap();

    // A trusts B's key so B can connect inbound to A.
    client_a
        .peer_add("alice", "node-b", &did_b, &pubkey_hex_b, addr_b)
        .await
        .expect("peer_add B into A");

    // B trusts A's key and stores A's listener address for the sync pull.
    client_b
        .peer_add("alice", "node-a", &did_a, &pubkey_hex_a, addr_a)
        .await
        .expect("peer_add A into B");

    // ── Write 3 objects on A ─────────────────────────────────────────────────
    for i in 1u8..=3 {
        client_a
            .write_file("alice", &format!("transfer{i}.bin"), &[i; 64])
            .await
            .expect("write_file A");
    }

    // ── B adds A as a Kotton remote and pulls ────────────────────────────────
    client_b
        .remote_add(
            "alice",
            "node-a",
            RemoteBackend::Kotton {
                peer_did: did_a.clone(),
                label: "node-a".to_string(),
            },
            None,
        )
        .await
        .expect("remote_add Kotton on B");

    // B's "alice" holds a different CEK than A's — sealed replication across
    // key domains must be refused, not "succeed" by moving blobs B can never
    // open (RFC-0041).
    let result = client_b
        .sync_mount("alice", "local", "node-a", Some(SyncDirection::Pull))
        .await;
    match result {
        Err(e) => {
            let msg = e.to_string().to_lowercase();
            assert!(
                msg.contains("domain"),
                "pull must be refused as a key-domain mismatch, got: {e}"
            );
        }
        Ok(r) => panic!(
            "cross-domain pull must be refused, but reported pulled={} pushed={}",
            r.pulled, r.pushed
        ),
    }

    // Nothing half-transferred: no unopenable blob is served on B…
    for i in 1u8..=3 {
        assert!(
            client_b
                .read_file("alice", &format!("transfer{i}.bin"))
                .await
                .is_err(),
            "transfer{i}.bin must not be readable on B — it was never legitimately its"
        );
    }
    // …and A's own copies are untouched by the refusal.
    for i in 1u8..=3 {
        let data = client_a
            .read_file("alice", &format!("transfer{i}.bin"))
            .await
            .expect("read_file A");
        assert_eq!(data, vec![i; 64], "transfer{i}.bin damaged on A");
    }
}
