// SPDX-License-Identifier: AGPL-3.0-or-later
//! A relay introduces your devices, end to end
//! (`TASK-a-relay-introduces-your-devices`).
//!
//! Two daemons on one relay, B joined to A's
//! identity, and B given a dead direct address for A so its dial falls through to
//! the relayed circuit. What this adds is the step after: over that circuit B asks
//! A for an introduction, A opens a listener that hears B's address and token and
//! nothing else, and what B asks of A — a co-signature, since devices sync by way
//! of a drive and never from each other — goes direct. The listener is gone when
//! the session is.
//!
//! Under `KOTTON_PAIR_LOCAL_ONLY` (which `bind-check`, and so `just test`, sets)
//! both ends bind loopback; without it they bind the machine's own address on its
//! network, which in a container is still this machine.

use kotton_schemas::membership::Posture;
use std::time::Duration;

use crate::common::{connect_when_ready, enroll_streamed, unique_ipc, wait_for_daemon};

fn free_port() -> u16 {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind :0 for port probe");
    s.local_addr().expect("local_addr").port()
}

/// B reaches A only through the relay; the relay introduces them; B's request of
/// A — a co-signature — lands over the introduced connection; and A's introduced
/// listener is closed once the session ends.
#[tokio::test]
async fn a_relay_introduces_two_devices_and_they_go_direct() {
    use kotton_secret::MemorySecrets;
    use kotton_sys::secret::SecretsStore;
    use kuserd::DeviceDaemon;
    use std::sync::Arc;

    let (_relay, relay_addr) = crate::common::relay::spawn().await;
    rustls::crypto::ring::default_provider().install_default().ok();
    let relay = kotton_device::config::db::RelayChoice::At(format!("http://{relay_addr}"));

    let base_a = tempfile::tempdir().expect("base_a tempdir");
    let ipc_a = unique_ipc();
    let secrets_a: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    let daemon_a = DeviceDaemon::new_with_base_secrets_and_relay(
        base_a.path().to_owned(),
        ipc_a.clone(),
        secrets_a,
        relay.clone(),
    )
    .await
    .expect("DeviceDaemon A");
    let base_b = tempfile::tempdir().expect("base_b tempdir");
    let ipc_b = unique_ipc();
    let secrets_b: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    let daemon_b = DeviceDaemon::new_with_base_secrets_and_relay(
        base_b.path().to_owned(),
        ipc_b.clone(),
        secrets_b,
        relay,
    )
    .await
    .expect("DeviceDaemon B");

    let daemon_a = Arc::new(daemon_a);
    daemon_a
        .start_peer_listener_background(free_port())
        .await
        .expect("start A peer listener");
    let runtime_a = daemon_a.runtime();
    assert!(
        runtime_a.introductions_open().is_empty(),
        "a fresh device has no introduced listener"
    );
    let daemon_a =
        Arc::try_unwrap(daemon_a).unwrap_or_else(|_| panic!("sole arc owner for daemon_a"));
    let _task_a = tokio::spawn(async move { Arc::new(daemon_a).run().await });
    let _task_b = tokio::spawn(async move { Arc::new(daemon_b).run().await });
    wait_for_daemon(&ipc_a, "daemon A").await;
    wait_for_daemon(&ipc_b, "daemon B").await;

    let mut client_a = connect_when_ready(&ipc_a, "client_a").await;
    let client_b = connect_when_ready(&ipc_b, "client_b").await;
    client_a
        .create_user("alice", crate::common::TEST_PASSPHRASE)
        .await
        .expect("create_user A");
    let (a_op_did, a_pubkey_hex) = client_a.get_node_identity().await.expect("A node identity");
    let (mut client_a, mut client_b, _node_b) = enroll_streamed(
        client_a,
        client_b,
        "alice",
        "device-b",
        Posture::Full,
    )
    .await;

    // A session on A — anything speaking to the daemon rather than a device over a
    // peer connection — cannot ask for a listener on A's network.
    let refused = client_a
        .inner()
        .send(&kotton_wire::UserRequest::Introduce {
            user_id: "alice".into(),
            addr: "127.0.0.1:9".into(),
            token: kotton_wire::ipc::SecretText::new("00".repeat(16)),
            router: None,
        })
        .await
        .expect("A answers");
    assert!(
        matches!(refused, kotton_wire::UserResponse::Error { .. }),
        "a session opened an introduction: {refused:?}"
    );
    assert!(runtime_a.introductions_open().is_empty(), "a session's ask bound a socket");

    // A dead direct address: the ladder falls through to the relay, which is the
    // only way B has to A until the relay introduces them.
    client_b
        .peer_add("alice", "device-a", &a_op_did, &a_pubkey_hex, "127.0.0.1:1".parse().unwrap())
        .await
        .expect("inject a dead address for A into B");
    tokio::time::sleep(Duration::from_millis(500)).await;

    // B speaks to A as one of the person's own devices does: a threshold
    // signature B coordinates, which A co-signs over the peer channel. Devices
    // do not sync from each other — what they replicate goes by way of a drive —
    // so a co-signature, and not a pull, is what B asks of A here.
    let before = runtime_a.introduced_requests();
    let signature = client_b
        .threshold_sign("alice", b"introduced, then direct")
        .await
        .expect("B and A co-sign after an introduction");
    assert_eq!(signature.len(), 64, "an Ed25519 signature");

    // The rounds went over a session A's introduced listener accepted: the relay
    // carried the introduction and the pair went direct. Counted in requests rather
    // than sessions because B's first dial to A — and so the introduction — can come
    // before the rounds, which then reuse the connection; what matters is that the
    // rounds' own requests were served there.
    assert!(runtime_a.introduced_sessions() >= 1, "no introduced session was opened on A");
    assert!(
        runtime_a.introduced_requests() > before,
        "the co-signing rounds were not served over an introduced session ({} before, {} after)",
        before,
        runtime_a.introduced_requests()
    );

    // And the listener did not outlive its session: once B has let the connection go,
    // A holds no introduced socket.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(40);
    while !runtime_a.introductions_open().is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "an introduced listener is still open on A: {:?}",
            runtime_a.introductions_open()
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
