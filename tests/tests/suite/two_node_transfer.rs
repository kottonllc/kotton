// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration test — two_node_transfer
//!
//! Two separate `kuserd` processes, each with its own base directory and IPC
//! socket, each with its own "alice" and a real vault enrolled as her drive;
//! B attempts to pull, from a drive made to serve A's packs, over a real QUIC
//! mTLS connection. A device syncs only with a drive, never with another
//! device, so the two processes never dial each other.
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

/// End-to-end cross-process refusal of cross-domain sealed replication, toward
/// a drive.
///
/// Two `kuserd` processes run in separate OS processes, each with its own
/// independently created "alice" — two unrelated key domains — and each
/// enrols a real vault as its own drive and keeps a file there. A keeps three
/// files on its drive; B's vault is then made to serve A's pool whole — its
/// packs and the key domain recorded for them — as B's own
/// (`drive_sync::a_drive_serving_another_domains_packs`). B's pull from its
/// drive is refused as a key-domain mismatch, nothing half-transfers, and A
/// still reads its own. A device syncs only with a drive, so the two
/// processes never dial each other, and no test records a device as a drive.
///
/// This is the cross-process twin of the in-process
/// `peer_sync::a_drive_serving_another_key_domain_is_refused`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_node_transfer_across_key_domains_is_refused() {
    crate::common::init_crypto();
    let proc_a = DaemonProcess::spawn(free_udp_port());
    let proc_b = DaemonProcess::spawn(free_udp_port());
    wait_for_daemon(&proc_a.endpoint, "daemon A").await;
    wait_for_daemon(&proc_b.endpoint, "daemon B").await;

    let mut client_a = connect_when_ready(&proc_a.endpoint, "connect client_a").await;
    let mut client_b = connect_when_ready(&proc_b.endpoint, "connect client_b").await;
    client_a.create_user("alice", crate::common::TEST_PASSPHRASE).await.expect("create_user A");
    client_b.create_user("alice", crate::common::TEST_PASSPHRASE).await.expect("create_user B");

    let (mut client_a, mut client_b, files, (a_domain, b_domain), _vaults) =
        crate::drive_sync::a_drive_serving_another_domains_packs(client_a, client_b, "alice").await;

    // B's "alice" holds a different CEK than A's — sealed replication across
    // key domains must be refused at the boundary, in words naming both
    // domains, not "succeed" by moving blobs B can never open.
    let result = client_b.sync_mount("alice", "local", "vault", Some(SyncDirection::Pull)).await;
    match result {
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains(&format!("belongs to key domain {a_domain}, this node holds {b_domain}")),
                "pull must be refused at the key-domain boundary naming both domains, got: {e}"
            );
        }
        Ok(r) => panic!("cross-domain pull must be refused, but reported pulled={} pushed={}", r.pulled, r.pushed),
    }

    // Nothing half-transferred: nothing of A's is readable on B, and A's own
    // copies are untouched by the refusal.
    for (name, body) in &files {
        assert!(client_b.read_file("alice", name).await.is_err(), "{name} must not be readable on B");
        assert_eq!(&client_a.read_file("alice", name).await.expect("read_file A"), body, "{name} damaged on A");
    }
}
