// SPDX-License-Identifier: AGPL-3.0-or-later
//! End-to-end: FROST device enrollment + distributed threshold signing across two
//! daemons (sprint-08). Drives the RFC-0040 committed-SAS pairing ceremony (via the
//! shared `enroll_streamed` helper) to set up a two-node identity, then a
//! distributed `threshold_sign` across the two enrolled nodes.
//!
//! Flow:
//!   1. Issuer E creates user "alice" (1-of-1 seed root) and runs `device add`.
//!   2. Joiner N runs `device join`, completing the FROST 2-of-2 split; both persist
//!      their share + the group `PublicKeyPackage`; both record membership.
//!   3. E learns N's operational listener address (the harness provides it on
//!      loopback — in production this is presence/relay) and `threshold_sign`s a
//!      message: E co-signs with N over the operational peer channel.
//!   4. The 64-byte aggregate verifies as a standard Ed25519 signature under the
//!      group DID (the DID-preserving split keeps it equal to alice's user DID).
//!
//! Self-contained: two in-process daemons on loopback, direct QUIC, no relay.
//! Reachability over a relay is covered separately by `relay_peer_sync`.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use kotton_sys::secret::SecretsStore;
use kotton_wire::remote::RemoteBackend;
use kotton_secret::MemorySecrets;
use kotton_schemas::membership::Posture;
use kotton::SyncDirection;
use kuserd::DeviceDaemon;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::common::{connect_when_ready, enroll_streamed, init_crypto, unique_ipc, wait_for_daemon};


fn free_port() -> u16 {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind :0 for port probe");
    s.local_addr().expect("local_addr").port()
}

/// The ceremony recorded where `label` answers the protocol, so nothing here
/// has to say it. Replaces the `peer_add` that used to inject `op_port` right
/// after each enrolment
/// (`TASK-admitting-a-vault-records-the-wrong-port-for-it`).
async fn assert_recorded_at(
    user: &str,
    client: &mut kotton::KottonClient,
    label: &str,
    op_port: u16,
) {
    let nodes = client.list_nodes(user).await.expect("node list");
    let node = nodes
        .iter()
        .find(|n| n.id == label)
        .unwrap_or_else(|| panic!("{label} is not among {user}'s paired nodes"));
    let addr = *node
        .addresses
        .first()
        .unwrap_or_else(|| panic!("the ceremony recorded no address for {label}"));
    assert_eq!(
        addr.port(),
        op_port,
        "the ceremony recorded {addr} for {label}, not its peer listener on {op_port}"
    );
}


/// The identity's current group verifying key, read from its key history.
///
/// Under `did:kel` (RFC-0038) the user DID is the inception AID, not the key, so the
/// aggregate threshold signature is checked against the chain's group key — which the
/// DID-preserving FROST split keeps equal to the identity key.
///
/// This used to be `group_vk_from_mnemonic`, rebuilding the inception from the
/// phrase and taking its key-state — which only worked while the identity key was
/// mnemonic-derived. It is random now, so the phrase cannot produce it and the
/// chain is the source. That is also what a real verifier uses: the group key is
/// public and lives in the KEL, not in anybody's secret.
fn group_vk_from_chain(base_dir: &std::path::Path, user_id: &str) -> VerifyingKey {
    let group_key = kotton_identity::kel_store::resolve_current_key_for(base_dir, user_id, false)
        .expect("reading the key history")
        .expect("an identity with a key-state");
    VerifyingKey::from_bytes(&group_key).expect("group key is a valid ed25519 pubkey")
}

#[tokio::test]
async fn enroll_then_threshold_sign_across_two_nodes() {
    init_crypto();

    // ── Issuer E ──────────────────────────────────────────────────────────────
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

    // ── Joiner N — runs an operational peer listener so E can co-sign with it ──
    let base_n = tempfile::tempdir().expect("base_n");
    let ipc_n = unique_ipc();
    let secrets_n: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    let daemon_n = Arc::new(
        DeviceDaemon::new_with_base_and_secrets(
            base_n.path().to_owned(),
            ipc_n.clone(),
            Arc::clone(&secrets_n),
        )
        .await
        .expect("daemon N"),
    );
    let op_port_n = free_port();
    daemon_n
        .start_peer_listener_background(op_port_n)
        .await
        .expect("start N operational listener");
    let daemon_n =
        Arc::try_unwrap(daemon_n).unwrap_or_else(|_| panic!("sole arc owner for daemon_n"));

    let _task_e = tokio::spawn(async move { std::sync::Arc::new(daemon_e).run().await });
    let _task_n = tokio::spawn(async move { std::sync::Arc::new(daemon_n).run().await });
    wait_for_daemon(&ipc_e, "daemon E").await;
    wait_for_daemon(&ipc_n, "daemon N").await;

    let mut client_e = connect_when_ready(&ipc_e, "client_e").await;
    let client_n = connect_when_ready(&ipc_n, "client_n").await;

    // ── 1. E creates the user (group root); did_e is E's did:kel AID. ─────────
    let (did_e, _fp) = client_e.create_user("alice", crate::common::TEST_PASSPHRASE).await.expect("create_user E");
    // ── 2. Enrollment ceremony: E enrolls, N joins (RFC-0040 streamed). ────────
    let bootstrap_port = free_port();
    let (mut client_e, _client_n, node_n) =
        enroll_streamed(client_e, client_n, "alice", "device-n", bootstrap_port, Posture::Full).await;

    // ── RFC-0038 (8e): the joiner adopted E's did:kel identity. E delivered its
    //    KEL in the enrollment; N stored it and now agrees on the same user DID.
    //    Delivery is the only way N could have it: an AID is the digest of an
    //    inception event, so it is reconstructible from the chain and from nothing
    //    else — no secret either device holds computes it. ─────────────────────
    let kel_n = kotton_identity::kel_store::load_chain(base_n.path(), "alice")
        .expect("load N's stored KEL");
    assert!(!kel_n.is_empty(), "the joiner stored the delivered KEL");
    assert_eq!(
        kel_n[0].aid.to_string(),
        did_e,
        "the joined device adopts the issuer's did:kel AID as its user identity"
    );

    // Both sides persisted a FROST share (distinct) + the group public-key package.
    let share_e = secrets_e
        .get_secret(&kotton_common::crypto::kdf_labels::frost_share("alice"))
        .unwrap();
    let share_n = secrets_n
        .get_secret(&kotton_common::crypto::kdf_labels::frost_share("alice"))
        .unwrap();
    assert!(share_e.is_some(), "issuer persisted its 2-of-2 share");
    assert!(share_n.is_some(), "joiner persisted its 2-of-2 share");
    assert_ne!(share_e, share_n, "the two shares are distinct");

    // ── 3. Provide N's operational address to E (loopback harness stand-in for
    //       presence/relay), keyed by the exact DID enrollment recorded. ───────
    let n_op_addr: SocketAddr = format!("127.0.0.1:{op_port_n}").parse().unwrap();
    client_e
        .peer_add(
            "alice",
            "device-n",
            &node_n.device_did.to_string(),
            &hex::encode(node_n.public_key),
            n_op_addr,
        )
        .await
        .expect("inject N operational address");

    // ── 4. E coordinates a 2-of-2 threshold signature with N. ─────────────────
    let message = b"sprint-08: a constitutional act co-signed across two enrolled nodes";
    let sig = client_e
        .threshold_sign("alice", message)
        .await
        .expect("threshold_sign across two nodes");

    assert_eq!(sig.len(), 64, "aggregate is a 64-byte Ed25519 signature");

    // The aggregate verifies under the group key (the DID-preserving split keeps it
    // equal to alice's identity key; her did:kel AID is the inception, not the key).
    let group_vk = group_vk_from_chain(base_e.path(), "alice");
    let sig_arr: [u8; 64] = sig.as_slice().try_into().unwrap();
    group_vk
        .verify(message, &Signature::from_bytes(&sig_arr))
        .expect("distributed threshold signature verifies under the group key");
}

/// A locked coordinator says it is locked — not that its other devices are missing.
///
/// The same two-node enrolment as the test above, then E is taken to the state a
/// restart leaves it in and asked to sign. Until 2026-09-26 `threshold_sign`
/// resolved its co-signers with `list_members().await.unwrap_or_default()`, so the
/// locked store's refusal to list became *no co-signers*, nothing was dialled, and
/// the round failed for want of a quorum: the person was told N was missing when
/// the truth was that E could not look. N is here and listening throughout, so
/// *missing* would be false rather than merely unhelpful.
///
/// It ends by unlocking E with the daily credential and signing again, with N
/// unchanged — so the refusal is shown to be about E's lock, and not about the
/// enrolment having gone
/// (`TASK-a-locked-node-reports-no-co-signers-rather-than-that-it-is-locked`).
#[tokio::test]
async fn a_locked_coordinator_says_it_is_locked_rather_than_that_it_has_no_co_signers() {
    init_crypto();
    /// Five distinct wordlist words, above the RFC-0053 bar — `restarted_daemon`'s.
    const PASSPHRASE: &str = "abandon-ability-able-about-above";

    let base_e = tempfile::tempdir().expect("base_e");
    let ipc_e = unique_ipc();
    let secrets_e: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    // Kept as an `Arc` rather than moved into its task, so the test can reach it
    // to put it in the restarted state while it serves.
    let daemon_e = Arc::new(
        DeviceDaemon::new_with_base_and_secrets(
            base_e.path().to_owned(),
            ipc_e.clone(),
            Arc::clone(&secrets_e),
        )
        .await
        .expect("daemon E"),
    );

    let base_n = tempfile::tempdir().expect("base_n");
    let ipc_n = unique_ipc();
    let secrets_n: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    let daemon_n = Arc::new(
        DeviceDaemon::new_with_base_and_secrets(
            base_n.path().to_owned(),
            ipc_n.clone(),
            Arc::clone(&secrets_n),
        )
        .await
        .expect("daemon N"),
    );
    let op_port_n = free_port();
    daemon_n
        .start_peer_listener_background(op_port_n)
        .await
        .expect("start N operational listener");
    let daemon_n =
        Arc::try_unwrap(daemon_n).unwrap_or_else(|_| panic!("sole arc owner for daemon_n"));

    let serving_e = Arc::clone(&daemon_e);
    let _task_e = tokio::spawn(async move { serving_e.run().await });
    let _task_n = tokio::spawn(async move { std::sync::Arc::new(daemon_n).run().await });
    wait_for_daemon(&ipc_e, "daemon E").await;
    wait_for_daemon(&ipc_n, "daemon N").await;

    let mut client_e = connect_when_ready(&ipc_e, "client_e").await;
    let client_n = connect_when_ready(&ipc_n, "client_n").await;

    client_e
        .create_user("alice", crate::common::TEST_PASSPHRASE)
        .await
        .expect("create_user E");
    // A daily credential, so the restarted state has something to be unlocked with.
    client_e
        .set_lock_policy("alice", kotton::LockMode::Passphrase, 0, Some(PASSPHRASE))
        .await
        .expect("set_lock_policy");
    let bootstrap_port = free_port();
    let (mut client_e, _client_n, node_n) =
        enroll_streamed(client_e, client_n, "alice", "device-n", bootstrap_port, Posture::Full).await;
    let n_op_addr: SocketAddr = format!("127.0.0.1:{op_port_n}").parse().unwrap();
    client_e
        .peer_add(
            "alice",
            "device-n",
            &node_n.device_did.to_string(),
            &hex::encode(node_n.public_key),
            n_op_addr,
        )
        .await
        .expect("inject N operational address");

    let message = b"a quorum that is there, asked for by a node that cannot look";

    // E is the node that restarted. N is untouched: still enrolled, still listening.
    crate::common::lock_as_a_restart_would(&daemon_e, "alice").await;

    let refusal = client_e
        .threshold_sign("alice", message)
        .await
        .expect_err("a locked node must refuse to sign, not produce a signature");
    let refusal = refusal.to_string();
    assert!(
        refusal.contains("it is locked"),
        "the refusal says the node is locked, got: {refusal}"
    );
    assert!(
        !refusal.contains("threshold signing failed") && !refusal.contains("co-signer"),
        "the refusal is the lock, not a failed round or a missing co-signer: {refusal}"
    );

    assert_eq!(
        client_e.unlock_with_pin("alice", PASSPHRASE).await.expect("unlock"),
        kotton::PinUnlock::Unlocked
    );
    let sig = client_e
        .threshold_sign("alice", message)
        .await
        .expect("once unlocked, the same two nodes sign");
    let group_vk = group_vk_from_chain(base_e.path(), "alice");
    let sig_arr: [u8; 64] = sig.as_slice().try_into().unwrap();
    group_vk
        .verify(message, &Signature::from_bytes(&sig_arr))
        .expect("the signature after the unlock verifies under the group key");
}

/// The same enroll → threshold-sign flow, but the coordinator reaches the
/// co-signer **purely over the relay** — no address injection. After enrollment
/// the only recorded address for the co-signer is the dead bootstrap address, so
/// `threshold_sign`'s dial falls through the NAT ladder to the relayed tier,
/// which routes by the co-signer's operational DID (the same op-key DID
/// enrollment recorded and the co-signer registers its presence/reservation
/// under). This is the cross-network reachability proof for distributed signing,
/// the companion to `relay_peer_sync` (which proves the same path for file sync).
///
/// Requires a running `kotton-relay` (set `KOTTON_RELAY_ADDR`, e.g. via
/// `just dev_services`); `#[ignore]`d otherwise, matching the other relay tests.
/// Run: `KOTTON_RELAY_ADDR=127.0.0.1:7700 cargo test -p kotton-integration-tests \
///   --test enroll_threshold_sign -- --ignored --nocapture`.
#[tokio::test]
async fn enroll_then_threshold_sign_over_relay() {
    init_crypto();

    let (_relay, relay_addr) = crate::common::relay::spawn().await;
    // Each daemon is told its relay. `KOTTON_RELAY_URL` is process-wide and read
    // at construction, so setting it around these two spoke to every daemon any
    // other test was building in the same window
    // (`TASK-a-process-global-relay-url-is-shared-by-tests-that-run-in-parallel`).
    let relay = kotton_device::config::db::RelayChoice::At(format!("http://{relay_addr}"));

    let base_e = tempfile::tempdir().expect("base_e");
    let ipc_e = unique_ipc();
    let secrets_e: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    let daemon_e = DeviceDaemon::new_with_base_secrets_and_relay(
        base_e.path().to_owned(),
        ipc_e.clone(),
        Arc::clone(&secrets_e),
        relay.clone(),
    )
    .await
    .expect("daemon E");

    let base_n = tempfile::tempdir().expect("base_n");
    let ipc_n = unique_ipc();
    let secrets_n: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    let daemon_n = Arc::new(
        DeviceDaemon::new_with_base_secrets_and_relay(
            base_n.path().to_owned(),
            ipc_n.clone(),
            Arc::clone(&secrets_n),
            relay,
        )
        .await
        .expect("daemon N"),
    );

    // N starts its operational listener (holds a relay reservation so the
    // coordinator can reach it by DID through the relay).
    let op_port_n = free_port();
    daemon_n
        .start_peer_listener_background(op_port_n)
        .await
        .expect("start N operational listener");
    let daemon_n =
        Arc::try_unwrap(daemon_n).unwrap_or_else(|_| panic!("sole arc owner for daemon_n"));

    let _task_e = tokio::spawn(async move { std::sync::Arc::new(daemon_e).run().await });
    let _task_n = tokio::spawn(async move { std::sync::Arc::new(daemon_n).run().await });
    wait_for_daemon(&ipc_e, "daemon E").await;
    wait_for_daemon(&ipc_n, "daemon N").await;
    // Give N's reservation time to register on the relay.
    tokio::time::sleep(Duration::from_millis(600)).await;

    let mut client_e = connect_when_ready(&ipc_e, "client_e").await;
    let client_n = connect_when_ready(&ipc_n, "client_n").await;

    let (_did_e, _f) = client_e.create_user("alice", crate::common::TEST_PASSPHRASE).await.expect("create_user E");
    let bootstrap_port = free_port();
    let (mut client_e, _client_n, _node_n) =
        enroll_streamed(client_e, client_n, "alice", "device-n", bootstrap_port, Posture::Full).await;

    // No peer_add / address injection — reach is entirely via the relay.
    let message = b"sprint-08: threshold-signed across two nodes, reached via the relay";
    let sig = client_e
        .threshold_sign("alice", message)
        .await
        .expect("threshold_sign over the relay");
    assert_eq!(sig.len(), 64);

    let group_vk = group_vk_from_chain(base_e.path(), "alice");
    let sig_arr: [u8; 64] = sig.as_slice().try_into().unwrap();
    group_vk
        .verify(message, &Signature::from_bytes(&sig_arr))
        .expect("relay-reached threshold signature verifies under the group key");
}

/// A device that completes the FROST join is issued a **working session** — it
/// authenticated by completing the ceremony, so it needs no separate login (it
/// holds no mnemonic anyway). Verifies the runtime pivot's session-on-join: after
/// `node_join`, the joining client is bound to the user, and the joined device can
/// actually use its runtime (an authed VFS write/read round-trips). This is the
/// precondition for the "connect to a network" onboarding branch dropping straight
/// into the runtime. (TERMINAL-RUNTIME-PIVOT.)
#[tokio::test]
async fn joined_device_gets_a_working_session() {
    init_crypto();

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

    client_e.create_user("alice", crate::common::TEST_PASSPHRASE).await.expect("create_user E");

    let bootstrap_port = free_port();
    let (_client_e, mut client_n, _node_n) =
        enroll_streamed(client_e, client_n, "alice", "device-n", bootstrap_port, Posture::Full).await;

    // The join bound a session: the joined client is authenticated as "alice" with
    // no separate login (it never saw a mnemonic).
    let active = client_n
        .get_active_session()
        .await
        .expect("get_active_session on joined node");
    assert_eq!(
        active,
        Some("alice".to_string()),
        "the joined device holds an authenticated session for alice"
    );

    // And the joined device can actually use its runtime: an authenticated VFS
    // write/read round-trips (proves the session + the reloaded runtime are live).
    let payload: &[u8] = b"hello from the joined device";
    client_n
        .write_file("alice", "from-join.txt", payload)
        .await
        .expect("authenticated write on the joined node");
    let data = client_n
        .read_file("alice", "from-join.txt")
        .await
        .expect("read back on the joined node");
    assert_eq!(data.as_slice(), payload);
}

/// Setting the rendezvous relay at runtime (`relay set` → `RendezvousSet`) applies
/// live on the running daemon — it persists the value AND drives
/// `DeviceRuntime::reconfigure_network` without error (the dial side reads the new
/// value immediately; presence re-registers when the node has a reflexive). Smoke
/// test for the live-apply path: it runs and is non-destructive. Full
/// reachability-after-set is covered once the boot-relay-less STUN re-probe lands
/// (see NETWORK-CONFIG-LIVE-RELOAD.md).
#[tokio::test]
async fn rendezvous_set_applies_live_without_error() {
    init_crypto();

    let base = tempfile::tempdir().expect("base");
    let ipc = unique_ipc();
    let secrets: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    let daemon = DeviceDaemon::new_with_base_and_secrets(
        base.path().to_owned(),
        ipc.clone(),
        Arc::clone(&secrets),
    )
    .await
    .expect("daemon");
    let _task = tokio::spawn(async move { std::sync::Arc::new(daemon).run().await });
    wait_for_daemon(&ipc, "daemon").await;

    let mut client = connect_when_ready(&ipc, "client").await;
    client.create_user("alice", crate::common::TEST_PASSPHRASE).await.expect("create_user");

    // Set a relay at runtime — persists + live-reconfigures the network layer.
    client
        .node_rendezvous_set(Some("http://127.0.0.1:7700"))
        .await
        .expect("rendezvous_set applies live without error");
    let status = client.node_rendezvous_status().await.expect("status");
    assert_eq!(status.url.as_deref(), Some("http://127.0.0.1:7700"));

    // Clearing it applies live too.
    client
        .node_rendezvous_set(None)
        .await
        .expect("rendezvous clear applies live");
    let status = client.node_rendezvous_status().await.expect("status");
    assert_eq!(status.url, None);
}

/// Arc A end-to-end: a file written on one device syncs to a **joined** device of
/// the **same identity**, and the joined device can **decrypt and read** it. This
/// is "send a file to my phone": E enrolls N (Full), N joins (gets the operational
/// CEK + a usable runtime), E writes a file, N pulls it over QUIC mTLS, and the
/// bytes come back in the clear on N — proving the synced object decrypts with the
/// delivered CEK. Transport is the same proven path as `two_node_transfer`; the new
/// thing here is that it works across a FROST device-join. (TERMINAL-RUNTIME-PIVOT.)
#[tokio::test]
async fn file_written_on_one_device_syncs_to_a_joined_device() {
    init_crypto();

    // E = the device that holds the file; it must be dialable for N to pull.
    let base_e = tempfile::tempdir().expect("base_e");
    let ipc_e = unique_ipc();
    let secrets_e: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    let daemon_e = Arc::new(
        DeviceDaemon::new_with_base_and_secrets(
            base_e.path().to_owned(),
            ipc_e.clone(),
            Arc::clone(&secrets_e),
        )
        .await
        .expect("daemon E"),
    );
    let op_port_e = free_port();
    daemon_e
        .start_peer_listener_background(op_port_e)
        .await
        .expect("start E operational listener");
    let daemon_e =
        Arc::try_unwrap(daemon_e).unwrap_or_else(|_| panic!("sole arc owner for daemon_e"));

    // N = the joining device ("my phone").
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
    let mut client_n = connect_when_ready(&ipc_n, "client_n").await;

    // E creates the identity; N joins it (Full → gets the CEK + a usable runtime).
    client_e.create_user("alice", crate::common::TEST_PASSPHRASE).await.expect("create_user E");
    let (did_e_dev, pubkey_e_hex) = client_e.get_node_identity().await.expect("E node identity");
    let (did_n_dev, pubkey_n_hex) = client_n.get_node_identity().await.expect("N node identity");

    let bootstrap_port = free_port();
    let (mut client_e, mut client_n, node_n) =
        enroll_streamed(client_e, client_n, "alice", "device-n", bootstrap_port, Posture::Full).await;

    // `peer identity` on N and `peer list` on E name N by the same key
    // (`TASK-a-node-identity-is-two-keys-pretending-to-be-one`). Until
    // 2026-09-12 `GetNodeIdentity` answered with the DID of a key from
    // `identity.json` whose private half was never kept, beside the public
    // half of the key the ceremony actually authenticated; the two fields
    // named different keys, and this is the line M1's recovery card is made
    // of. The public key is asserted too, so the DID is shown to be *that*
    // key's and not merely a string the two sides agreed on.
    assert_eq!(
        node_n.device_did.to_string(),
        did_n_dev,
        "E records N by the DID N reports for itself"
    );
    assert_eq!(hex::encode(node_n.public_key), pubkey_n_hex);
    assert_eq!(
        kotton_crypto::DidKeyMethod::to_public_key(
            &kotton_wire::did::Did::parse(&did_n_dev).expect("a did:key")
        )
        .expect("decodes")
        .to_bytes(),
        node_n.public_key,
        "the DID is the operational key's, not a label"
    );

    // Give N E's operational address (loopback stand-in for presence/relay), so the
    // pull can dial E. Keyed by E's operational DID, as enrollment recorded.
    let e_op_addr: SocketAddr = format!("127.0.0.1:{op_port_e}").parse().unwrap();
    client_n
        .peer_add("alice", "device-e", &did_e_dev, &pubkey_e_hex, e_op_addr)
        .await
        .expect("inject E operational address into N");

    // E writes a top-level file and a nested one. The nested path is the pull
    // regression: `SealedListEntry` carries no `is_dir`, so unless the serving
    // side walks its own tree before answering, a puller sees only the top
    // level and the sync "succeeds" while silently missing everything below it.
    // Under RFC-0044 blinding, nested is the general case, not the edge.
    let files: Vec<(&str, Vec<u8>)> = vec![
        (
            "shared.txt",
            b"this file is on my laptop and should reach my phone".to_vec(),
        ),
        ("notes/2026/trip.md", b"nested two directories deep".to_vec()),
        // A large file exercises the whole RFC-0048 loop: the local write is
        // chunked (its 9 MiB would overflow the IPC frame cap otherwise), the
        // sealed pull ranges the object across, and the read on N is chunked
        // back. Before RFC-0048 the write alone closed the connection.
        ("big.bin", vec![0xABu8; 9 * 1024 * 1024]),
    ];
    for (path, body) in &files {
        client_e
            .write_file("alice", path, body)
            .await
            .unwrap_or_else(|e| panic!("write_file {path} on E: {e}"));
    }

    // …N adds E as a Kotton remote and pulls.
    client_n
        .remote_add(
            "alice",
            "device-e",
            RemoteBackend::Kotton {
                peer_did: did_e_dev.clone(),
                label: "device-e".to_string(),
            },
            None,
        )
        .await
        .expect("remote_add E on N");
    let result = client_n
        .sync_mount("alice", "local", "device-e", Some(SyncDirection::Pull))
        .await
        .expect("sync_mount Pull on N");
    assert!(
        result.pulled >= 3,
        "expected all objects pulled from E (nested + large included), got {}",
        result.pulled
    );

    // …and N reads them all back in the clear (decrypted with the delivered CEK),
    // the 9 MiB one included — proving the chunked write, the ranged sealed pull,
    // and the chunked read all reassemble correctly.
    for (path, body) in &files {
        let data = client_n
            .read_file("alice", path)
            .await
            .unwrap_or_else(|e| panic!("read_file {path} on N: {e}"));
        assert_eq!(
            &data, body,
            "{path} synced from E decrypts correctly on the joined device N"
        );
    }
}

/// Arc A for records: a record written on one device reaches a joined device of
/// the same identity — the record twin of the file-sync test above. E inserts a
/// record; `log_records` seals it into the history log; the pack push carries
/// that sealed segment to N; and `apply_record_segments` merges it into N's own
/// record store. Proves records ride the same sealed pack path as files
/// (RFC-0046 slice 4a), through the real daemon sync, with no `ApplyRecordChangeset`
/// plaintext push involved.
///
/// This is also the end-to-end proof of **data-capability delivery**: it passes
/// only because a `Full` enrollment now hands the joiner the whole `DataKeys`
/// pair (RFC-0036), not the CEK alone. Record segments seal under
/// `K_log = HKDF(master_secret)`, so a joiner holding only the CEK derives a
/// different `K_log` and cannot open the issuer's log — which is exactly why
/// this test was `#[ignore]`d before that landed. If `master_secret` ever stops
/// riding the enrollment payload, this test fails at the assertion.
#[tokio::test]
async fn a_record_written_on_one_device_syncs_to_a_joined_device() {
    init_crypto();

    // Both daemons dialable: E pushes its record segment, N applies on its pass.
    let base_e = tempfile::tempdir().expect("base_e");
    let ipc_e = unique_ipc();
    let secrets_e: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    let daemon_e = Arc::new(
        DeviceDaemon::new_with_base_and_secrets(
            base_e.path().to_owned(),
            ipc_e.clone(),
            Arc::clone(&secrets_e),
        )
        .await
        .expect("daemon E"),
    );
    let op_port_e = free_port();
    daemon_e
        .start_peer_listener_background(op_port_e)
        .await
        .expect("start E operational listener");
    let daemon_e =
        Arc::try_unwrap(daemon_e).unwrap_or_else(|_| panic!("sole arc owner for daemon_e"));

    let base_n = tempfile::tempdir().expect("base_n");
    let ipc_n = unique_ipc();
    let secrets_n: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    let daemon_n = Arc::new(
        DeviceDaemon::new_with_base_and_secrets(
            base_n.path().to_owned(),
            ipc_n.clone(),
            Arc::clone(&secrets_n),
        )
        .await
        .expect("daemon N"),
    );
    let op_port_n = free_port();
    daemon_n
        .start_peer_listener_background(op_port_n)
        .await
        .expect("start N operational listener");
    let daemon_n =
        Arc::try_unwrap(daemon_n).unwrap_or_else(|_| panic!("sole arc owner for daemon_n"));

    let _task_e = tokio::spawn(async move { std::sync::Arc::new(daemon_e).run().await });
    let _task_n = tokio::spawn(async move { std::sync::Arc::new(daemon_n).run().await });
    wait_for_daemon(&ipc_e, "daemon E").await;
    wait_for_daemon(&ipc_n, "daemon N").await;

    let mut client_e = connect_when_ready(&ipc_e, "client_e").await;
    let client_n = connect_when_ready(&ipc_n, "client_n").await;

    client_e.create_user("alice", crate::common::TEST_PASSPHRASE).await.expect("create_user E");
    let (did_e_dev, pubkey_e_hex) = client_e.get_node_identity().await.expect("E node identity");

    let bootstrap_port = free_port();
    let (mut client_e, mut client_n, _node_n) =
        enroll_streamed(client_e, client_n, "alice", "device-n", bootstrap_port, Posture::Full).await;
    let (did_n_dev, pubkey_n_hex) = client_n.get_node_identity().await.expect("N node identity");

    // Cross-register operational addresses both ways (loopback stand-in for
    // presence/relay), so E can dial N to push and N can dial E to pull.
    let e_addr: SocketAddr = format!("127.0.0.1:{op_port_e}").parse().unwrap();
    let n_addr: SocketAddr = format!("127.0.0.1:{op_port_n}").parse().unwrap();
    client_n
        .peer_add("alice", "device-e", &did_e_dev, &pubkey_e_hex, e_addr)
        .await
        .expect("inject E address into N");
    client_e
        .peer_add("alice", "device-n", &did_n_dev, &pubkey_n_hex, n_addr)
        .await
        .expect("inject N address into E");

    // The schema must be registered on both — E to insert, N to build the table
    // from its own registry when it applies the segment.
    //
    // In a namespace this test owns. It used to name `sh.kotton.notes` with a
    // single field while that core schema has five; registration silently no-opped
    // and both devices used the core definition instead, so the two `schema_register`
    // calls below did nothing and the comment above was not true of them.
    let schema = kotton_schemas::definition::SchemaDefinition::new(
        kotton_schemas::nsid::Nsid::new("com.test.notes").unwrap(),
        1,
        vec![kotton_schemas::field::SchemaField::required(
            "title",
            kotton_schemas::field::FieldType::String,
        )],
    );
    let schema_json = serde_json::to_string(&schema).unwrap();
    client_e.schema_register("alice", &schema_json).await.expect("schema on E");
    client_n.schema_register("alice", &schema_json).await.expect("schema on N");

    // E writes a record.
    client_e
        .record_insert(
            "alice",
            "com.test.notes",
            serde_json::json!({ "title": "reaches my phone" }),
        )
        .await
        .expect("record_insert on E");

    // E seals the record into its packs the way its background sync pass would:
    // the producer (`log_records`) runs on the syncing device, so a sync of E's
    // local mount — here to a local remote, standing in for E's own background
    // pass — is what puts the record segment into E's packs. (The joiner dials
    // the stable node in this model, so E does not push to N.)
    let scratch = base_e.path().join("scratch");
    client_e
        .remote_add("alice", "scratch", RemoteBackend::Local { path: scratch }, None)
        .await
        .expect("local remote on E");
    client_e
        .sync_mount("alice", "local", "scratch", None)
        .await
        .expect("E local sync logs its records");

    // N syncs from E: it pulls E's packs (the record segment included) and
    // apply_record_segments merges the delivered segment into N's record store.
    client_n
        .remote_add(
            "alice",
            "device-e",
            RemoteBackend::Kotton {
                peer_did: did_e_dev.clone(),
                label: "device-e".to_string(),
            },
            None,
        )
        .await
        .expect("remote_add E on N");
    client_n
        .sync_mount("alice", "local", "device-e", None)
        .await
        .expect("N sync from E");

    // N sees the record — carried as sealed segments in packs, no plaintext push.
    let recs = client_n
        .record_query("alice", "com.test.notes", vec![], None, None)
        .await
        .expect("record_query on N");
    assert_eq!(
        recs.len(),
        1,
        "the record written on E reached the joined device N via the sealed log"
    );
    assert_eq!(recs[0]["title"], "reaches my phone");
}

/// Recursively collect every regular file under `dir`.
fn walk_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

/// **The point of RFC-0041.** A `BlindStorage` receives replicated objects and
/// cannot read them — because it is handed sealed bytes, not because it politely
/// declines to decrypt.
///
/// This is the criterion the old sync path could never have met. It read through
/// the encrypting store (`get` decrypts) and wrote the result to the peer, so a
/// node with no CEK persisted the user's data in the clear — blind in posture and
/// not in fact. Here the marker is written on E, replicated to B, and then hunted
/// for across every byte B wrote to disk.
#[tokio::test]
async fn a_blind_storage_receives_ciphertext_it_cannot_read() {
    init_crypto();

    // B = the blind storage node. It listens, because replication is always initiated
    // by the side holding the data keys (RFC-0041) — B never dials.
    let base_b = tempfile::tempdir().expect("base_b");
    let ipc_b = unique_ipc();
    let secrets_b: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    let daemon_b = Arc::new(
        DeviceDaemon::new_with_base_and_secrets(
            base_b.path().to_owned(),
            ipc_b.clone(),
            Arc::clone(&secrets_b),
        )
        .await
        .expect("daemon B"),
    );
    let op_port_b = free_port();
    daemon_b
        .start_peer_listener_background(op_port_b)
        .await
        .expect("start B operational listener");
    let daemon_b =
        Arc::try_unwrap(daemon_b).unwrap_or_else(|_| panic!("sole arc owner for daemon_b"));

    // E = the trusted device that holds the identity and the data.
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

    let _task_b = tokio::spawn(async move { std::sync::Arc::new(daemon_b).run().await });
    let _task_e = tokio::spawn(async move { std::sync::Arc::new(daemon_e).run().await });
    wait_for_daemon(&ipc_b, "daemon B").await;
    wait_for_daemon(&ipc_e, "daemon E").await;

    let mut client_e = connect_when_ready(&ipc_e, "client_e").await;
    let client_b = connect_when_ready(&ipc_b, "client_b").await;

    client_e.create_user("alice", crate::common::TEST_PASSPHRASE).await.expect("create_user E");
    // E enrols B provider-blind: no FROST share, no CEK, no master_secret.
    let bootstrap_port = free_port();
    let (mut client_e, mut client_b, node_b) = enroll_streamed(
        client_e,
        client_b,
        "alice",
        "blind-vps",
        bootstrap_port,
        Posture::BlindStorage,
    )
    .await;
    assert_eq!(node_b.id, "blind-vps");
    // Who B is comes from the ceremony, not from asking B
    // (`TASK-a-node-identity-is-two-keys-pretending-to-be-one`).
    let did_b_dev = node_b.device_did.to_string();

    // E needs B's operational address to push, and the ceremony is where it
    // learns it. Until 2026-09-12 this was a `peer_add` that injected the
    // address the ceremony should have carried — the harness knowing what
    // `docs/use/run-a-vault.md` does not say
    // (`TASK-the-harness-may-not-know-what-the-runbook-does-not-say`). It is
    // now a check that the ceremony carried it.
    assert_recorded_at("alice", &mut client_e, "blind-vps", op_port_b).await;

    // A marker long and distinctive enough that finding it in ciphertext by
    // chance is not a thing that happens.
    let marker: &[u8] = b"PLAINTEXT-MARKER-a-blind-storage-must-never-see-this-string";
    client_e
        .write_file("alice", "secret-notes.txt", marker)
        .await
        .expect("write_file on E");

    // E pushes to B.
    client_e
        .remote_add(
            "alice",
            "blind-vps",
            RemoteBackend::Kotton {
                peer_did: did_b_dev.clone(),
                label: "blind-vps".to_string(),
            },
            None,
        )
        .await
        .expect("remote_add B on E");
    let result = client_e
        .sync_mount("alice", "local", "blind-vps", Some(SyncDirection::Push))
        .await
        .expect("sync_mount Push to the blind storage node");
    assert!(
        result.pushed >= 1,
        "expected at least 1 object pushed to the blind storage node, got {}",
        result.pushed
    );

    // ── The criterion ────────────────────────────────────────────────────────
    // Sweep every byte B wrote and prove the plaintext is not among them.
    let mut files = Vec::new();
    walk_files(base_b.path(), &mut files);
    assert!(
        !files.is_empty(),
        "the blind storage node wrote nothing — the push cannot have landed"
    );

    let mut sealed_bytes_seen = 0usize;
    for file in &files {
        let Ok(bytes) = std::fs::read(file) else {
            continue;
        };
        assert!(
            !bytes
                .windows(marker.len())
                .any(|w| w == marker),
            "plaintext marker found on the blind storage node at {}",
            file.display()
        );
        sealed_bytes_seen += bytes.len();
    }
    assert!(
        sealed_bytes_seen >= marker.len(),
        "the blind storage node holds less data than the object it was sent"
    );

    // It also cannot serve the plaintext: with no CEK there is no key domain to
    // open the envelope with, so a read either fails or yields non-plaintext.
    if let Ok(data) = client_b.read_file("alice", "secret-notes.txt").await {
        assert_ne!(
            data.as_slice(),
            marker,
            "the blind storage node returned the plaintext it must not be able to produce"
        );
    }
}

/// Boot-relay-less live-apply (the whole point of `reconfigure_network`): both nodes
/// start with **no relay configured**, then a runtime `relay set` (`RendezvousSet`)
/// makes them reachable — and a file syncs across **via the relay**, no manual
/// addressing, no restart. Proves the always-running reservation listener picks up a
/// runtime-set relay live. Requires a running relay (`KOTTON_RELAY_ADDR`).
#[tokio::test]
#[ignore = "requires a running kotton-relay; set KOTTON_RELAY_ADDR to enable"]
async fn relay_set_at_runtime_makes_a_relayless_node_reachable() {
    init_crypto();
    let relay_addr = std::env::var("KOTTON_RELAY_ADDR").expect(
        "this test was asked for and has no relay to run against: start one (`just dev_services`) \
         and set KOTTON_RELAY_ADDR to its host:port",
    );
    let relay_url = format!("http://{relay_addr}");
    // NOTE: this proves boot-relay-less when KOTTON_RELAY_URL is unset (the case when
    // run in isolation). We deliberately do NOT remove_var here — it's process-global
    // and would race with the other relay tests' env. Run this test alone to assert
    // the relay-less boot path specifically.

    // E (source). Start its peer listener so the always-running reservation listener
    // runs (it idles until a relay is set).
    let base_e = tempfile::tempdir().expect("base_e");
    let ipc_e = unique_ipc();
    let secrets_e: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    let daemon_e = Arc::new(
        DeviceDaemon::new_with_base_and_secrets(
            base_e.path().to_owned(),
            ipc_e.clone(),
            Arc::clone(&secrets_e),
        )
        .await
        .expect("daemon E"),
    );
    daemon_e
        .start_peer_listener_background(free_port())
        .await
        .expect("E peer listener");
    let daemon_e = Arc::try_unwrap(daemon_e).unwrap_or_else(|_| panic!("sole arc owner E"));

    let base_n = tempfile::tempdir().expect("base_n");
    let ipc_n = unique_ipc();
    let secrets_n: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    let daemon_n = Arc::new(
        DeviceDaemon::new_with_base_and_secrets(
            base_n.path().to_owned(),
            ipc_n.clone(),
            Arc::clone(&secrets_n),
        )
        .await
        .expect("daemon N"),
    );
    daemon_n
        .start_peer_listener_background(free_port())
        .await
        .expect("N peer listener");
    let daemon_n = Arc::try_unwrap(daemon_n).unwrap_or_else(|_| panic!("sole arc owner N"));

    let _task_e = tokio::spawn(async move { std::sync::Arc::new(daemon_e).run().await });
    let _task_n = tokio::spawn(async move { std::sync::Arc::new(daemon_n).run().await });
    wait_for_daemon(&ipc_e, "daemon E").await;
    wait_for_daemon(&ipc_n, "daemon N").await;

    let mut client_e = connect_when_ready(&ipc_e, "client_e").await;
    let client_n = connect_when_ready(&ipc_n, "client_n").await;

    // E creates the identity; N joins it.
    client_e.create_user("alice", crate::common::TEST_PASSPHRASE).await.expect("create_user E");
    let (did_e_dev, pubkey_e_hex) = client_e.get_node_identity().await.expect("E identity");

    let bootstrap_port = free_port();
    let (mut client_e, mut client_n, _node_n) =
        enroll_streamed(client_e, client_n, "alice", "device-n", bootstrap_port, Posture::Full).await;

    // Live-apply the relay on BOTH nodes — they booted relay-less.
    client_e
        .node_rendezvous_set(Some(&relay_url))
        .await
        .expect("E relay set");
    client_n
        .node_rendezvous_set(Some(&relay_url))
        .await
        .expect("N relay set");
    // Give the reservation listeners a moment to connect to the relay.
    tokio::time::sleep(Duration::from_millis(600)).await;

    // Pair E's OPERATIONAL identity (DID + key) with a DEAD direct address, so the
    // dial fails direct and falls through to the relay — reachability comes purely
    // from the runtime-set relay, no real address. (A join pairs E under its bootstrap
    // DID; pairing the operational identity for ongoing reach is a separate gap.)
    let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
    client_n
        .peer_add("alice", "device-e", &did_e_dev, &pubkey_e_hex, dead)
        .await
        .expect("pair E's operational identity (dead addr → relay)");

    // E writes a file; N pulls it — reachability is purely via the runtime-set relay.
    let payload: &[u8] = b"reachable via a relay I set at runtime";
    client_e
        .write_file("alice", "relayed.txt", payload)
        .await
        .expect("write E");
    client_n
        .remote_add(
            "alice",
            "device-e",
            RemoteBackend::Kotton {
                peer_did: did_e_dev.clone(),
                label: "device-e".to_string(),
            },
            None,
        )
        .await
        .expect("remote_add E on N");
    let result = client_n
        .sync_mount("alice", "local", "device-e", Some(SyncDirection::Pull))
        .await
        .expect("sync pull via runtime-set relay");
    assert!(
        result.pulled >= 1,
        "expected >=1 pulled via the relay, got {}",
        result.pulled
    );
    let data = client_n
        .read_file("alice", "relayed.txt")
        .await
        .expect("read N");
    assert_eq!(data.as_slice(), payload);
}

/// End-to-end BlindStorage enrollment (RFC-0036): the issuer enrolls a node
/// `--blind`, and the joiner installs **no** key material — no FROST share, no
/// operational CEK, no warm key. This is the provider-blind path: enrolling an
/// untrusted host hands it nothing it could decrypt with. Closes the Article I/II
/// gap end-to-end (companion to the runtime/daemon unit tests).
#[tokio::test]
async fn blind_enroll_delivers_the_chain_but_no_key_material_e2e() {
    init_crypto();

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

    client_e.create_user("alice", crate::common::TEST_PASSPHRASE).await.expect("create_user E");

    let bootstrap_port = free_port();
    // blind = true → provider-blind enrollment. The joiner announces its own name.
    let (_client_e, _client_n, node) = enroll_streamed(
        client_e,
        client_n,
        "alice",
        "blind-vps",
        bootstrap_port,
        Posture::BlindStorage,
    )
    .await;
    assert_eq!(node.id, "blind-vps");

    // The blind joiner installed NOTHING it could decrypt or sign with.
    use kotton_common::crypto::kdf_labels;
    assert!(
        secrets_n
            .get_secret(&kdf_labels::frost_share("alice"))
            .unwrap()
            .is_none(),
        "blind node holds no FROST share"
    );
    assert!(
        secrets_n
            .get_secret(&kdf_labels::operational_cek("alice"))
            .unwrap()
            .is_none(),
        "blind node holds no operational CEK"
    );
    assert!(
        secrets_n
            .get_secret(&kdf_labels::warm_signing_key("alice"))
            .unwrap()
            .is_none(),
        "blind node holds no warm signing key"
    );

    // ── …and it DOES hold the chain (RFC-0081 criterion 1) ───────────────────
    //
    // Asserted in the same test as the negative half deliberately. The risk of
    // delivering a KEL to a blind storage node is precisely that it smuggles key
    // material across with it; splitting these into two tests would let one half
    // drift while the other kept passing. "Delivers the chain and nothing else"
    // is a single claim and is checked as one.
    let kel_n = kotton_identity::kel_store::load_chain(base_n.path(), "alice")
        .expect("blind node's KEL is readable");
    assert!(
        !kel_n.is_empty(),
        "a blind storage node must receive the user's key event log: without a chain to \
         verify against, it can never admit a device that proves control of the \
         user's root, and a user who loses every device is stranded from data the \
         node is still holding (RFC-0081)"
    );
    assert_eq!(
        kel_n[0].kind,
        kotton_wire::kel::EventKind::Inception,
        "the delivered chain must start at the inception the node will verify \
         later admissions against"
    );

    // The chain is public key state, never key material. Replaying it must yield
    // a *public* key and must not have installed anything decryptable — the two
    // assertions above and the three below are the whole of the blind posture.
    let resolved = kotton_crypto::kel_verify::resolve_current_key(
        &kel_n,
        &kotton_crypto::kel_verify::LocalArbiter,
        false,
    )
    .expect("the delivered chain must replay");
    assert_eq!(
        resolved.len(),
        32,
        "a replayed chain yields a 32-byte public key and nothing else"
    );
}

/// End-to-end `Cosigner` enrollment (RFC-0036): the issuer enrolls a node
/// `--cosigner` — it receives a FROST **share** (so it can co-sign with the
/// quorum) but **no** operational CEK (so it cannot decrypt). The two-axis
/// posture: identity capability without data capability. Verified two ways: the
/// joiner holds a share but no CEK, and a `threshold_sign` driven by the issuer
/// succeeds by co-signing with the cosigner — proving its share is live in the
/// quorum while it remains data-blind.
#[tokio::test]
async fn cosigner_holds_a_share_but_no_data_keys_and_can_co_sign() {
    init_crypto();

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
    let daemon_n = Arc::new(
        DeviceDaemon::new_with_base_and_secrets(
            base_n.path().to_owned(),
            ipc_n.clone(),
            Arc::clone(&secrets_n),
        )
        .await
        .expect("daemon N"),
    );
    let op_port_n = free_port();
    daemon_n
        .start_peer_listener_background(op_port_n)
        .await
        .expect("start N operational listener");
    let daemon_n =
        Arc::try_unwrap(daemon_n).unwrap_or_else(|_| panic!("sole arc owner for daemon_n"));

    let _task_e = tokio::spawn(async move { std::sync::Arc::new(daemon_e).run().await });
    let _task_n = tokio::spawn(async move { std::sync::Arc::new(daemon_n).run().await });
    wait_for_daemon(&ipc_e, "daemon E").await;
    wait_for_daemon(&ipc_n, "daemon N").await;

    let mut client_e = connect_when_ready(&ipc_e, "client_e").await;
    let client_n = connect_when_ready(&ipc_n, "client_n").await;

    let (_did_e, _f) = client_e.create_user("alice", crate::common::TEST_PASSPHRASE).await.expect("create_user E");
    let bootstrap_port = free_port();
    let (mut client_e, _client_n, node_n) = enroll_streamed(
        client_e,
        client_n,
        "alice",
        "cosigner-vps",
        bootstrap_port,
        Posture::Cosigner,
    )
    .await;

    // The cosigner holds a SHARE (can co-sign) but NO CEK (cannot decrypt).
    use kotton_common::crypto::kdf_labels;
    assert!(
        secrets_n
            .get_secret(&kdf_labels::frost_share("alice"))
            .unwrap()
            .is_some(),
        "cosigner holds a FROST share"
    );
    assert!(
        secrets_n
            .get_secret(&kdf_labels::operational_cek("alice"))
            .unwrap()
            .is_none(),
        "cosigner holds NO operational CEK — it cannot decrypt"
    );

    // Provide the cosigner's operational address (loopback harness stand-in), then
    // the issuer co-signs with it: the cosigner's share is live in the quorum.
    let n_op_addr: SocketAddr = format!("127.0.0.1:{op_port_n}").parse().unwrap();
    client_e
        .peer_add(
            "alice",
            "cosigner-vps",
            &node_n.device_did.to_string(),
            &hex::encode(node_n.public_key),
            n_op_addr,
        )
        .await
        .expect("inject cosigner operational address");

    let message = b"sprint-08: constitutional act co-signed by a data-blind cosigner";
    let sig = client_e
        .threshold_sign("alice", message)
        .await
        .expect("threshold_sign co-signing with the cosigner");
    assert_eq!(sig.len(), 64);
    let group_vk = group_vk_from_chain(base_e.path(), "alice");
    let sig_arr: [u8; 64] = sig.as_slice().try_into().unwrap();
    group_vk
        .verify(message, &Signature::from_bytes(&sig_arr))
        .expect("cosigner-co-signed threshold signature verifies under the group key");
}

/// RFC-0038 fleet re-establishment: after a mnemonic rotation, re-enrolling a
/// device delivers the multi-event KEL (inception + rotation) and the joiner
/// resolves the ROTATED key — a recovered identity brings its fleet back under the
/// new key, with the `did:kel` AID unchanged.
#[tokio::test]
async fn a_reenrolled_device_resolves_the_rotated_key() {
    init_crypto();

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

    // E creates alice, then rotates her identity key via the mnemonic (recovery).
    let (did_e, _fp) = client_e.create_user("alice", crate::common::TEST_PASSPHRASE).await.expect("create_user E");
    let recovery_e = client_e
        .add_recovery_phrase("alice")
        .await
        .expect("add_recovery_phrase");
    let rotated_key_hex = client_e
        .rotate_identity("alice", &recovery_e, Some(crate::common::TEST_PASSPHRASE))
        .await
        .expect("rotate identity");

    // E enrolls N under the now-rotated identity.
    let bootstrap_port = free_port();
    let (_client_e, _client_n, _node_n) =
        enroll_streamed(client_e, client_n, "alice", "device-n", bootstrap_port, Posture::Full).await;

    // N stored the whole KEL and adopts the same AID; it replays to the ROTATED
    // key — not the retired inception key.
    //
    // Three events, not two: creation mints no phrase, so setting recovery up is
    // its own establishment event between the inception and the rotation. That the
    // count moved is the point of the assertion — a delivered chain is delivered
    // entire, and a joiner that dropped the middle event would resolve a key the
    // rotation had already retired.
    let kel_n =
        kotton_identity::kel_store::load_chain(base_n.path(), "alice").expect("load N's KEL");
    assert_eq!(
        kel_n.len(),
        3,
        "delivered KEL carries inception + add-recovery + rotation"
    );
    assert_eq!(kel_n[0].aid.to_string(), did_e, "N adopts the issuer AID");
    let current =
        kotton_identity::kel_store::resolve_current_key_for(base_n.path(), "alice", false)
            .unwrap()
            .unwrap();
    assert_eq!(
        hex::encode(current),
        rotated_key_hex,
        "the re-enrolled device resolves the rotated key, not the retired one"
    );
}

/// **M1's demonstration, verbatim:** *a blind node holds everything a user owns;
/// the user loses every device and recovers the whole of it from the recovery
/// phrase.*
///
/// The milestone insists on demonstrated rather than asserted, and the two halves
/// of this already had tests that did not meet in the middle:
/// `a_blind_storage_receives_ciphertext_it_cannot_read` proves the node holds
/// sealed bytes, and `mnemonic_recovers_db_key_via_recovery_bundle` proves the
/// phrase unseals the key — but that one reads `records.db` from the *same disk*,
/// so no test had ever lost the device.
///
/// Here the device's base directory is destroyed. What comes back has to come
/// back from the blind node, and the only thing carried across the gap is the
/// phrase.
///
/// # This is M1's gate
///
/// It was `#[ignore]`d from 2026-08-23 to 2026-09-04 because it failed, and it was
/// written down rather than deleted so that "are we done with M1" had a mechanical
/// answer. What it measured, in order, and what closed each:
///
/// - `login_with_recovery_key` on a cold device used to fail outright once the AID
///   stopped deriving from the phrase: nothing local to verify against. It now
///   claims the name **locked**, and says so.
/// - The pull then failed: `Device public key not in paired allowlist`. The
///   recovered device has a new key; the blind node's allowlist held only the key
///   of the device that no longer exists. `RFC-0081`: the node admits a device on
///   **proof of control of the root** — a recovery rotation chaining from the tip
///   it holds — and a device with only the phrase first proves a recovery
///   authority to fetch the chain and the sealed copy it needs to build one.
///
/// The step between login and the pull is `recover`, per the ruling on
/// `IDEA-what-a-phrase-login-should-rotate`: login stays non-destructive; recovery
/// is the verb that rotates.
#[tokio::test]
async fn a_user_who_loses_every_device_recovers_everything_from_the_phrase() {
    init_crypto();

    const NOTE: &[u8] = b"the whole of what alice owns";

    // B = the blind node. Outlives every device the user has.
    let base_b = tempfile::tempdir().expect("base_b");
    let ipc_b = unique_ipc();
    let secrets_b: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    let daemon_b = Arc::new(
        DeviceDaemon::new_with_base_and_secrets(
            base_b.path().to_owned(),
            ipc_b.clone(),
            Arc::clone(&secrets_b),
        )
        .await
        .expect("daemon B"),
    );
    let op_port_b = free_port();
    daemon_b
        .start_peer_listener_background(op_port_b)
        .await
        .expect("start B operational listener");
    let daemon_b =
        Arc::try_unwrap(daemon_b).unwrap_or_else(|_| panic!("sole arc owner for daemon_b"));
    let _task_b = tokio::spawn(async move { std::sync::Arc::new(daemon_b).run().await });
    wait_for_daemon(&ipc_b, "daemon B").await;

    let schema = kotton_schemas::definition::SchemaDefinition::new(
        kotton_schemas::nsid::Nsid::new("com.test.notes").unwrap(),
        1,
        vec![kotton_schemas::field::SchemaField::required(
            "title",
            kotton_schemas::field::FieldType::String,
        )],
    );
    let schema_json = serde_json::to_string(&schema).unwrap();

    // ---- The user's only device, and everything they own --------------------
    let recovery_phrase;
    let did_b_dev;
    let pubkey_b_hex;
    {
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
        let _task_e = tokio::spawn(async move { std::sync::Arc::new(daemon_e).run().await });
        wait_for_daemon(&ipc_e, "daemon E").await;

        let mut client_e = connect_when_ready(&ipc_e, "client_e").await;
        let client_b = connect_when_ready(&ipc_b, "client_b").await;

        let (_did, _fp) = client_e.create_user("alice", crate::common::TEST_PASSPHRASE).await.expect("create_user E");
        let phrase = client_e
            .add_recovery_phrase("alice")
            .await
            .expect("add_recovery_phrase");
        recovery_phrase = phrase;

        let bootstrap_port = free_port();
        let (mut client_e, _client_b, node_b) = enroll_streamed(
            client_e,
            client_b,
            "alice",
            "blind-vps",
            bootstrap_port,
            Posture::BlindStorage,
        )
        .await;
        assert_eq!(node_b.id, "blind-vps");
        did_b_dev = node_b.device_did.to_string();
        pubkey_b_hex = hex::encode(node_b.public_key);

        assert_recorded_at("alice", &mut client_e, "blind-vps", op_port_b).await;

        // A file and a record — both halves of what a user owns.
        client_e
            .write_file("alice", "notes.txt", NOTE)
            .await
            .expect("write_file on E");
        client_e
            .schema_register("alice", &schema_json)
            .await
            .expect("schema on E");
        client_e
            .record_insert(
                "alice",
                "com.test.notes",
                serde_json::json!({ "title": "survives the loss" }),
            )
            .await
            .expect("record_insert on E");

        client_e
            .remote_add(
                "alice",
                "blind-vps",
                RemoteBackend::Kotton {
                    peer_did: did_b_dev.clone(),
                    label: "blind-vps".to_string(),
                },
                None,
            )
            .await
            .expect("remote_add B on E");
        let pushed = client_e
            .sync_mount("alice", "local", "blind-vps", Some(SyncDirection::Push))
            .await
            .expect("push everything to the blind node");
        assert!(
            pushed.pushed >= 1,
            "the blind node must actually hold something to recover from"
        );

        // ---- Lose every device ----------------------------------------------
        // `base_e` drops here: the disk, the keychain, the identity, the records
        // database. Nothing of E survives this block but the phrase.
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ---- A brand-new device, holding only the phrase ------------------------
    let base_c = tempfile::tempdir().expect("base_c");
    let ipc_c = unique_ipc();
    let secrets_c: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    let daemon_c = DeviceDaemon::new_with_base_and_secrets(
        base_c.path().to_owned(),
        ipc_c.clone(),
        Arc::clone(&secrets_c),
    )
    .await
    .expect("daemon C");
    let _task_c = tokio::spawn(async move { std::sync::Arc::new(daemon_c).run().await });
    wait_for_daemon(&ipc_c, "daemon C").await;

    let mut client_c = connect_when_ready(&ipc_c, "client_c").await;
    client_c
        .login_with_recovery_key(&recovery_phrase, Some("alice".to_string()), None)
        .await
        .expect("the phrase alone claims the identity on a cold device");

    let b_op_addr: SocketAddr = format!("127.0.0.1:{op_port_b}").parse().unwrap();
    client_c
        .peer_add("alice", "blind-vps", &did_b_dev, &pubkey_b_hex, b_op_addr)
        .await
        .expect("tell C where its blind node is");
    // The phrase proves the identity against the chain the blind node kept, opens
    // the sealed copy of the data roots it kept beside it, and rotates the identity
    // onto this device — which is what the blind node then admits it on.
    let recovered_did = client_c
        .recover("alice", &recovery_phrase, crate::common::TEST_PASSPHRASE)
        .await
        .expect("recover from the phrase and the blind node alone")
        .did;
    assert!(
        recovered_did.starts_with("did:kel:"),
        "recovery restores the identity, not a name: {recovered_did}"
    );
    client_c
        .schema_register("alice", &schema_json)
        .await
        .expect("schema on C");
    client_c
        .remote_add(
            "alice",
            "blind-vps",
            RemoteBackend::Kotton {
                peer_did: did_b_dev.clone(),
                label: "blind-vps".to_string(),
            },
            None,
        )
        .await
        .expect("remote_add B on C");
    client_c
        .sync_mount("alice", "local", "blind-vps", Some(SyncDirection::Pull))
        .await
        .expect("pull the whole of it back from the blind node");

    // ---- The criterion ------------------------------------------------------
    assert_eq!(
        client_c
            .read_file("alice", "notes.txt")
            .await
            .expect("the file must come back")
            .as_slice(),
        NOTE,
        "the file the user owned must be readable on the recovered device"
    );

    let recs = client_c
        .record_query("alice", "com.test.notes", vec![], None, None)
        .await
        .expect("record_query on C");
    assert_eq!(
        recs.len(),
        1,
        "the record must come back too — the whole of it, not just the files"
    );
    assert_eq!(recs[0]["title"], "survives the loss");
}

/// RFC-0081's first open item: a phrase set up *after* a blind node was enrolled
/// never reached it, so that node could serve the chain but not the copy, and a
/// recovery through it stopped one step short. Now the device that seals the
/// copy hands it to every blind node it is paired with (`RecoveryStore`), and
/// the node keeps bytes it cannot open — the same bytes enrolment would have
/// carried.
#[tokio::test]
async fn a_phrase_set_up_after_a_blind_node_was_enrolled_reaches_it() {
    init_crypto();

    let base_b = tempfile::tempdir().expect("base_b");
    let ipc_b = unique_ipc();
    let secrets_b: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    let daemon_b = Arc::new(
        DeviceDaemon::new_with_base_and_secrets(
            base_b.path().to_owned(),
            ipc_b.clone(),
            Arc::clone(&secrets_b),
        )
        .await
        .expect("daemon B"),
    );
    let op_port_b = free_port();
    daemon_b
        .start_peer_listener_background(op_port_b)
        .await
        .expect("start B operational listener");
    let daemon_b =
        Arc::try_unwrap(daemon_b).unwrap_or_else(|_| panic!("sole arc owner for daemon_b"));
    let _task_b = tokio::spawn(async move { std::sync::Arc::new(daemon_b).run().await });
    wait_for_daemon(&ipc_b, "daemon B").await;

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
    let _task_e = tokio::spawn(async move { std::sync::Arc::new(daemon_e).run().await });
    wait_for_daemon(&ipc_e, "daemon E").await;

    let mut client_e = connect_when_ready(&ipc_e, "client_e").await;
    let client_b = connect_when_ready(&ipc_b, "client_b").await;
    client_e.create_user("alice", crate::common::TEST_PASSPHRASE).await.expect("create_user E");
    // Enrolled blind *before* any phrase exists: nothing to carry.
    let bootstrap_port = free_port();
    let (mut client_e, _client_b, node_b) = enroll_streamed(
        client_e,
        client_b,
        "alice",
        "blind-vps",
        bootstrap_port,
        Posture::BlindStorage,
    )
    .await;
    assert_eq!(node_b.id, "blind-vps");
    let copy_at_b = base_b.path().join("users").join("alice").join("recovery.json");
    assert!(!copy_at_b.exists(), "no phrase yet, so no copy travelled at enrolment");

    assert_recorded_at("alice", &mut client_e, "blind-vps", op_port_b).await;

    // Now the phrase. Sealing the copy is what delivers it.
    let _phrase = client_e
        .add_recovery_phrase("alice")
        .await
        .expect("add_recovery_phrase");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while !copy_at_b.exists() && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    assert!(copy_at_b.exists(), "the blind node keeps the copy the phrase sealed");
    let at_b = std::fs::read_to_string(&copy_at_b).unwrap();
    let at_e = std::fs::read_to_string(base_e.path().join("users").join("alice").join("recovery.json")).unwrap();
    assert_eq!(at_b, at_e, "verbatim: the node keeps what it cannot open, unchanged");

    // **And it can be served.** This test watched the file appear and stopped
    // there until 2026-09-12, which is one assertion short of the thing the
    // situation is for: setting up a phrase appends the key event that commits
    // the new authority, and a node that has the copy and not that event refuses
    // the only device that will ever ask for it
    // (`TASK-a-node-keeps-a-recovery-copy-it-will-refuse-to-serve`). The copy and
    // the events that authorize it now travel together, and this is the cheap
    // check that they still do.
    let chain_at_b = kotton_identity::kel_store::load_chain(base_b.path(), "alice")
        .expect("the blind node's copy of alice's chain");
    let chain_at_e = kotton_identity::kel_store::load_chain(base_e.path(), "alice")
        .expect("alice's own chain");
    assert_eq!(
        chain_at_b.len(),
        chain_at_e.len(),
        "the node's chain stops short of the event that committed the phrase, so the copy \
         beside it can never be asked for"
    );
    assert!(
        chain_at_b
            .last()
            .is_some_and(|tip| !tip.recovery_set.is_empty()),
        "the node holds no recovery authority for alice, so a phrase-only device is a stranger"
    );
}
