// SPDX-License-Identifier: AGPL-3.0-or-later
//! A person's name travels with their identity
//! (`TASK-a-persons-name-travels-with-their-identity`).
//!
//! The name is a sealed record in the person's own store, carried by the sync
//! that carries the rest of it, and each device's `display_name` is a copy of
//! that record. So a device admitted to the identity after the name was set
//! greets the person by it without asking, and a rename in Settings on one
//! device is followed by the other. The assertion is the launch argument,
//! because that is the whole of what the host tells an app who it is running
//! for — the menubar draws it.
//!
//! Two in-process daemons on loopback and the person's drive: E holds the
//! identity and enrols a vault as the drive, N joins it through the real
//! streamed ceremony (`enroll_streamed`, `Posture::Full`), and N takes what E
//! sent to the drive from there, exactly as
//! `enroll_threshold_sign::file_written_on_one_device_syncs_to_a_joined_device`
//! does. A device does not sync from another device. The name is set through Settings' door — `DaemonOccupantHost::set_display_name`,
//! which is what the shell's account row reaches.

use kotton::SyncDirection;
use kotton_schemas::membership::Posture;
use kotton_secret::MemorySecrets;
use kotton_sys::secret::SecretsStore;
use kuserd::DeviceDaemon;
use std::sync::Arc;

use crate::common::{connect_when_ready, enroll_streamed, unique_ipc, wait_for_daemon, InstallApprovingAll as _};

fn init_crypto() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        rustls::crypto::ring::default_provider().install_default().ok();
    });
}

fn free_port() -> u16 {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind :0 for port probe");
    s.local_addr().expect("local_addr").port()
}

/// Minimal valid WASM magic bytes: the mock runner reports the launch without
/// running anything. Long-lived, because that is the mode in which the mock's
/// `report-input` paints the launch arguments back.
const STUB_WASM: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

const PROBE_MANIFEST: &str = r#"
[app]
id      = "sh.kotton.test-name-travels"
name    = "Name Travels Probe"
version = "0.1.0"
kind    = "long-lived"
"#;

/// The `display_name` a launch on `client` is handed, read off the mock
/// runner's `report-input` frame.
async fn launched_display_name(client: &mut kotton::KottonClient, app_id: &str) -> Option<String> {
    let launched = client.app_launch(app_id, vec![]).await.expect("app_launch on N");
    let patch = launched.patches.first().unwrap_or_else(|| panic!("the mock paints its launch frame: {launched:?}"));
    let report: serde_json::Value =
        serde_json::from_slice(&patch[1..]).expect("the mock paints raw JSON (format version 0x00)");
    report["launch_args"]
        .as_array()
        .expect("launch args")
        .iter()
        .find(|pair| pair[0] == "display_name")
        .and_then(|pair| pair[1].as_str())
        .map(str::to_owned)
}

/// Every file under `base` whose bytes hold `name`, other than the one copy
/// that is meant to: `device/users.json`, which the lock screen reads before
/// anything of the person's is unlocked and which holds the name exactly as it
/// holds the id beside it. Everything else on the device — the store the
/// record rests in and every blob sync brought — must hold it only sealed.
fn files_holding_in_the_clear(base: &std::path::Path, name: &str) -> Vec<std::path::PathBuf> {
    let copy = base.join("device").join("users.json");
    let mut found = Vec::new();
    let mut stack = vec![base.to_path_buf()];
    while let Some(dir) = stack.pop() {
        // A directory or file the scan cannot open fails the test rather than
        // passing it: a scan that skips what it cannot read proves nothing about it.
        let entries = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("the scan cannot list {}: {e}", dir.display()));
        for entry in entries.flatten() {
            let path = entry.path();
            match entry.file_type() {
                Ok(t) if t.is_dir() => stack.push(path),
                Ok(t) if t.is_file() && path != copy => {
                    let bytes = std::fs::read(&path)
                        .unwrap_or_else(|e| panic!("the scan cannot read {}: {e}", path.display()));
                    if bytes.windows(name.len()).any(|w| w == name.as_bytes()) {
                        found.push(path);
                    }
                }
                _ => {}
            }
        }
    }
    found
}

/// **A second device admitted to an identity with a name set is handed the same
/// name, and follows a rename made on the first.**
///
/// E creates the identity, and the person sets their name in Settings. N joins
/// the identity; nothing on N is told the name. N pulls from E — the sync that
/// carries the person's members — and the launch that follows on N carries
/// `display_name` = the name. Then the person renames themselves on E, N pulls
/// again, and N's next launch carries the new name.
///
/// Before the pull N's launch carries no name, which is what makes the pull the
/// thing that brought it: nothing but the sealed record could have.
#[tokio::test]
#[serial_test::serial]
#[allow(unsafe_code)] // env::set_var is unsafe in Rust 1.81+; serialised by #[serial]
async fn a_second_device_admitted_to_an_identity_is_handed_the_name_it_already_has() {
    use kotton_app::daemon::apps::OccupantHost as _;
    init_crypto();

    // SAFETY: `#[serial_test::serial]` means nothing else is running; removed
    // before the assertions so a panic cannot leave it set.
    unsafe {
        std::env::set_var("MOCK_RUNNER_MODE", "report-input");
    }
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            // SAFETY: as above.
            unsafe {
                std::env::remove_var("MOCK_RUNNER_MODE");
            }
        }
    }
    let _restore = Restore;

    // ── E: the device that holds the identity, dialable for N's pull ─────────
    let base_e = tempfile::tempdir().expect("base_e");
    let ipc_e = unique_ipc();
    let secrets_e: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    let daemon_e = Arc::new(
        DeviceDaemon::new_with_base_and_secrets(base_e.path().to_owned(), ipc_e.clone(), secrets_e)
            .await
            .expect("daemon E"),
    );
    let op_port_e = free_port();
    daemon_e
        .start_peer_listener_background(op_port_e)
        .await
        .expect("start E operational listener");

    // ── N: the device the person adds later ──────────────────────────────────
    let base_n = tempfile::tempdir().expect("base_n");
    let ipc_n = unique_ipc();
    let secrets_n: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
    let daemon_n = Arc::new(
        DeviceDaemon::new_with_base_and_secrets(base_n.path().to_owned(), ipc_n.clone(), secrets_n)
            .await
            .expect("daemon N")
            .with_runner(std::path::PathBuf::from(crate::common::mock_runner_bin())),
    );

    let _serving_e = tokio::spawn({
        let d = Arc::clone(&daemon_e);
        async move { d.run().await }
    });
    let _serving_n = tokio::spawn({
        let d = Arc::clone(&daemon_n);
        async move { d.run().await }
    });
    wait_for_daemon(&ipc_e, "daemon E").await;
    wait_for_daemon(&ipc_n, "daemon N").await;

    let mut client_e = connect_when_ready(&ipc_e, "client_e").await;
    let client_n = connect_when_ready(&ipc_n, "client_n").await;

    // E makes the identity, and the person says what they are called — through
    // Settings' door, which may be said by an unlocked person.
    client_e
        .create_user("alice", crate::common::TEST_PASSPHRASE)
        .await
        .expect("create_user E");
    daemon_e
        .occupant_host()
        .set_display_name("Quillon")
        .await
        .expect("the person sets their name on E");
    assert_eq!(
        kuserd::device_users::load(base_e.path()).unwrap()["alice"].display_name.as_deref(),
        Some("Quillon"),
        "E's copy follows the record it just wrote"
    );

    // N joins the identity. The ceremony carries no name.
    // E keeps the person's things on a drive, enrolled before N joins so the
    // join introduces N to it.
    let (client_e, drive) = crate::drive_sync::a_drive_for(client_e, "device-e", "alice").await;
    let bootstrap_port = free_port();
    let (mut client_e, mut client_n, _node_n) =
        enroll_streamed(client_e, client_n, "alice", "device-n", bootstrap_port, Posture::Full).await;

    let (app_id, _, _) = client_n
        .app_install_approving_all("", PROBE_MANIFEST.to_string(), STUB_WASM.to_vec())
        .await
        .expect("install the launch probe on N");
    assert_eq!(
        launched_display_name(&mut client_n, &app_id).await,
        None,
        "N was handed a name before anything of the person's reached it"
    );

    // E syncs to the drive, and N takes from there the sync that carries the
    // person's members. N is never given E's address.
    let _ = op_port_e;
    client_e
        .sync_mount("alice", "local", "vault", Some(SyncDirection::Push))
        .await
        .expect("E pushes to the drive");
    crate::drive_sync::tell_of_the_drive(&mut client_n, "alice", &drive).await;
    client_n
        .sync_mount("alice", "local", "vault", Some(SyncDirection::Pull))
        .await
        .expect("N pulls from the drive");

    assert_eq!(
        launched_display_name(&mut client_n, &app_id).await.as_deref(),
        Some("Quillon"),
        "the joined device greets the person by the name they already have"
    );
    let copy = &kuserd::device_users::load(base_n.path()).unwrap()["alice"];
    assert_eq!(copy.display_name.as_deref(), Some("Quillon"), "N's registry holds the copy");
    assert_eq!(
        copy.did,
        kuserd::device_users::load(base_e.path()).unwrap()["alice"].did,
        "N's entry names the identity it joined"
    );

    // The name rests sealed on both devices: in E's store where it was
    // written, and in whatever N's pull brought across. The one copy in the
    // clear is each device's registry entry, beside the id.
    for (device, base) in [("E", base_e.path()), ("N", base_n.path())] {
        let clear = files_holding_in_the_clear(base, "Quillon");
        assert!(clear.is_empty(), "the name rests in the clear on {device}: {clear:?}");
    }

    // A rename on E is followed by N.
    daemon_e
        .occupant_host()
        .set_display_name("Quillon Ybarra")
        .await
        .expect("the person renames themselves on E");
    client_e
        .sync_mount("alice", "local", "vault", Some(SyncDirection::Push))
        .await
        .expect("E pushes the rename to the drive");
    client_n
        .sync_mount("alice", "local", "vault", Some(SyncDirection::Pull))
        .await
        .expect("N pulls from the drive again");
    assert_eq!(
        launched_display_name(&mut client_n, &app_id).await.as_deref(),
        Some("Quillon Ybarra"),
        "N follows the rename made on E"
    );
    for (device, base) in [("E", base_e.path()), ("N", base_n.path())] {
        let clear = files_holding_in_the_clear(base, "Ybarra");
        assert!(clear.is_empty(), "the renamed name rests in the clear on {device}: {clear:?}");
    }
}
