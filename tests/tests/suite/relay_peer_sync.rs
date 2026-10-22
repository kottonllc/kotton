// SPDX-License-Identifier: AGPL-3.0-or-later
//! End-to-end peer sync forced through the relayed fallback (RFC-0024 sprint 07
//! item 2). Companion to `peer_sync.rs`'s loopback-QUIC test: this one proves the
//! tier-4 relay path — `connect_peer`'s relayed fallback dialing through the relay
//! to the other node's `Reachability` reservation (`core/peer/src/reachability.rs`).
//!
//! How the relay path is forced:
//!   * Both daemons are told their `relay_url` at construction (so A holds a
//!     reservation and B can fall back to the relay).
//!   * B's `PairedNode` record for A carries a dead direct address (127.0.0.1:1), so
//!     direct QUIC fails fast; A registers no presence, so hole-punch finds nothing;
//!     no TURN is configured — the ladder falls through to the relayed tier, which
//!     reaches A by DID through the relay regardless of address.
//!
//! **Since `TASK-a-relay-introduces-your-devices`** the relay also introduces them:
//! over the relayed circuit B asks A for an introduction, and the pull itself goes
//! direct once it lands (`introduction.rs` asserts that). What this test still proves
//! is the relayed tier — the circuit, and the requests it carries before the pair goes
//! direct. The relayed tier carrying a whole transfer is the vault suite's, since
//! `kvaultd` answers no introduction.
//!
//! # Why B *joins* A rather than being paired by hand
//!
//! This test spent its life `#[ignore]`d, and while it was dark RFC-0041 landed:
//! a transfer between two nodes in different key domains is now refused with a
//! `SealedDomainMismatch` rather than laundered through plaintext. The setup here
//! used to write reciprocal `paired_nodes` rows on two daemons that had each run
//! `create_user("alice")` independently — which is precisely the "genuinely
//! strangers" setup that `peer_sync::peer_sync_across_key_domains_is_refused` now
//! asserts *must fail*. So the first real run of this test failed, correctly, and
//! the expectation was the stale part.
//!
//! B therefore joins A's identity through the real streamed ceremony
//! (`enroll_streamed`, `Posture::Full`), exactly as
//! `enroll_threshold_sign::file_written_on_one_device_syncs_to_a_joined_device`
//! does. One key domain, one CEK, so a successful pull is a meaningful assertion.
//! The bootstrap leg of enrollment runs over loopback — it is out-of-band setup;
//! the **sync** is the leg that must traverse the relay, and that is what is
//! forced above.
//!
//! # Running
//!
//! ```sh
//! just test_suite relay_peer_sync::peer_sync_via_relay_fallback
//! ```
//!
//! Starts a `kotton-relay` of its own (`common::relay::spawn`, which asks `common::bins`
//! for the built binary and fails naming it when it is not). `KOTTON_RELAY_ADDR` names a
//! relay already running to use in its place (`just dev_services` provides one).

use kotton_wire::remote::RemoteBackend;
use kotton::SyncDirection;
use kotton_schemas::membership::Posture;

use crate::common::{connect_when_ready, enroll_streamed, unique_ipc, wait_for_daemon};

fn init_crypto() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
    });
}

fn free_port() -> u16 {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind :0 for port probe");
    s.local_addr().expect("local_addr").port()
}

/// Peer sync that must traverse the relayed fallback tier.
///
/// Runs against a relay the test starts, or the one `KOTTON_RELAY_ADDR` names.
#[tokio::test]
async fn peer_sync_via_relay_fallback() {
    use kotton_sys::secret::SecretsStore;
    use kotton_secret::MemorySecrets;
    use kuserd::DeviceDaemon;
    use std::sync::Arc;
    use std::time::Duration;

    let (_relay, relay_addr) = crate::common::relay::spawn().await;

    init_crypto();

    // Point both daemons at the relay by telling each one. `KOTTON_RELAY_URL` is
    // the deployment interface and it is process-wide, so a test setting it
    // around a construction is speaking to every daemon any other thread is
    // building in that window and to none of them a moment later
    // (`TASK-a-process-global-relay-url-is-shared-by-tests-that-run-in-parallel`).
    let relay = kotton_device::config::db::RelayChoice::At(format!("http://{relay_addr}"));

    // ── Device A (source) — holds a relay reservation ─────────────────────────
    let base_a = tempfile::tempdir().expect("base_a tempdir");
    let ipc_a = unique_ipc();
    let secrets_a: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    let daemon_a = Arc::new(
        DeviceDaemon::new_with_base_secrets_and_relay(
            base_a.path().to_owned(),
            ipc_a.clone(),
            Arc::clone(&secrets_a),
            relay.clone(),
        )
        .await
        .expect("DeviceDaemon A"),
    );
    let _ = daemon_a.device_signing_pubkey_bytes();

    // ── Device B (sink) — falls back to the relay to reach A ──────────────────
    let base_b = tempfile::tempdir().expect("base_b tempdir");
    let ipc_b = unique_ipc();
    let secrets_b: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    let daemon_b = DeviceDaemon::new_with_base_secrets_and_relay(
        base_b.path().to_owned(),
        ipc_b.clone(),
        Arc::clone(&secrets_b),
        relay,
    )
    .await
    .expect("DeviceDaemon B");

    let port_a = free_port();

    // Start A's peer listener — with relay_url set it also holds a relay reservation.
    daemon_a
        .start_peer_listener_background(port_a)
        .await
        .expect("start A peer listener");

    let daemon_a =
        Arc::try_unwrap(daemon_a).unwrap_or_else(|_| panic!("sole arc owner for daemon_a"));
    let _task_a = tokio::spawn(async move { std::sync::Arc::new(daemon_a).run().await });
    let _task_b = tokio::spawn(async move { std::sync::Arc::new(daemon_b).run().await });

    wait_for_daemon(&ipc_a, "daemon A").await;
    wait_for_daemon(&ipc_b, "daemon B").await;

    let client_a = connect_when_ready(&ipc_a, "client_a").await;
    let client_b = connect_when_ready(&ipc_b, "client_b").await;

    // A creates the identity; B joins it, so both hold the same CEK. Without this
    // the pull is refused with a `SealedDomainMismatch` — see the module doc.
    let mut client_a = client_a;
    client_a.create_user("alice", crate::common::TEST_PASSPHRASE).await.expect("create_user A");
    let (a_op_did, a_pubkey_hex) = client_a
        .get_node_identity()
        .await
        .expect("A node identity");

    let bootstrap_port = free_port();
    let (mut client_a, mut client_b, _node_b) = enroll_streamed(
        client_a,
        client_b,
        "alice",
        "device-b",
        bootstrap_port,
        Posture::Full,
    )
    .await;

    // Give B a DEAD direct address for A, keyed by A's operational DID as
    // enrollment recorded it. Direct QUIC then fails fast and the ladder must fall
    // through to the relayed tier, which routes by DID rather than address.
    let dead_a_addr: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
    client_b
        .peer_add("alice", "device-a", &a_op_did, &a_pubkey_hex, dead_a_addr)
        .await
        .expect("inject a dead address for A into B");

    // Give A's reservation time to register on the relay.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Write 3 objects to A.
    for i in 1u8..=3 {
        client_a
            .write_file("alice", &format!("obj{i}.bin"), &[i; 64])
            .await
            .expect("write_file A");
    }

    // B pulls from A — the dial must traverse the relay, which then introduces them.
    client_b
        .remote_add(
            "alice",
            "peer-a",
            RemoteBackend::Kotton {
                peer_did: a_op_did.clone(),
                label: "device-a".to_string(),
            },
            None,
        )
        .await
        .expect("remote_add Kotton on B");

    let result = client_b
        .sync_mount("alice", "local", "peer-a", Some(SyncDirection::Pull))
        .await
        .expect("sync_mount Pull via relay");

    // `>=` rather than `== 3`: a real join writes its own records into alice's
    // store on A, and those sync too. The faked-pairing setup this test used to
    // carry left the store holding nothing but the three test writes, which is why
    // it could assert an exact count. Both enrolled-peer sync tests in
    // `enroll_threshold_sign` assert `>=` for the same reason. The three objects
    // are pinned by content below, which is the assertion that actually matters.
    assert!(
        result.pulled >= 3,
        "expected the 3 test objects pulled from A via relay, got {}",
        result.pulled
    );
    assert_eq!(result.pushed, 0, "pull-only: no pushes expected");

    for i in 1u8..=3 {
        let data = client_b
            .read_file("alice", &format!("obj{i}.bin"))
            .await
            .expect("read_file B");
        assert_eq!(data, vec![i; 64], "obj{i}.bin content mismatch on B");
    }

    println!("peer sync via relay fallback: OK");
}
