// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton keep`: a folder on one device goes into the person's tree, and reaches their
//! other device by sync.
//!
//! The keeping side is a `kotton` process, as a person runs it, against a daemon it finds
//! for itself (`common/cli.rs`); the other device is a second in-process daemon, joined by
//! the six-digit ceremony through the library with the digits confirmed for it, and it
//! pulls and reads through the library. What `keep` decides on a second run, file by file,
//! is the shell's own tests'; here it is said once, end to end, that the second run copies
//! nothing.

use kotton::SyncDirection;
use kotton_schemas::membership::Posture;

use crate::common::cli::{said, Cli};
use crate::common::{connect_when_ready, enroll_streamed, TestEnv, TEST_PASSPHRASE};

const USER: &str = "alice";

/// **A folder kept on one device is read on another.** `kotton keep <folder>` on E copies
/// the folder into the tree under its own name; run again, it copies nothing; N, joined to
/// the same identity, pulls from the person's drive what E synced there, and reads a file of
/// the folder back, nested one included. A device does not sync from another device.
/// What is kept is recorded sealed in the tree, in E's own file under `/.kept`: nothing on
/// E's disk holds the folder's path in the clear, and N, the person's own other device, reads
/// E's record as it reads any file of theirs.
///
/// **Multi-threaded on purpose**, as `cli_identity`'s card test is: `Cli::run` blocks until
/// the child exits, and the daemon the child talks to runs in this process.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_folder_kept_on_one_device_is_read_on_another() {
    // ── E: the device the folder is on, reached by `kotton` as a person reaches it ──
    let mut e = TestEnv::spawn_cli_reachable().await;
    e.client.create_user(USER, TEST_PASSPHRASE).await.expect("create_user on E");
    let token = e.client.session_token.clone().expect("create_user binds a session");
    let cli = Cli::for_env(&e);
    cli.seed_session(USER, &token);
    let (did_e, _) = e.client.get_node_identity().await.expect("E's node identity");

    // ── N: a second device, joined to the same identity ──────────────────────────
    let n = TestEnv::spawn().await;
    let mut alice_e = connect_when_ready(&e.endpoint, "alice on E").await;
    alice_e.authenticate(&token).await.expect("present E's session");
    // E keeps the person's things on a drive, enrolled before N joins so the
    // join introduces N to it: N reads what E keeps by way of the drive.
    let (alice_e, _drive) = crate::drive_sync::a_drive_for(alice_e, "device-e", USER).await;
    let fresh_n = connect_when_ready(&n.endpoint, "N").await;
    let (mut alice_e, mut alice_n, _) =
        enroll_streamed(alice_e, fresh_n, USER, "device-n", Posture::Full).await;

    // ── The folder, on E's computer ──────────────────────────────────────────────
    let home = tempfile::tempdir().expect("a folder of the person's");
    let photos = home.path().join("Photos");
    std::fs::create_dir_all(photos.join("2026")).unwrap();
    std::fs::write(photos.join("beach.jpg"), b"sand, and the sea behind it").unwrap();
    std::fs::write(photos.join("2026/lake.jpg"), b"a lake, nested a folder down").unwrap();
    let folder = photos.to_str().expect("a UTF-8 path");

    let out = cli.run(&["keep", "--user", USER, folder]);
    assert!(out.status.success(), "`kotton keep {folder}` failed.\n{}", said(&out));
    assert!(
        said(&out).contains("copied 2 files, 0 already there unchanged"),
        "the first run did not say both files went in.\n{}",
        said(&out)
    );

    let again = cli.run(&["keep", "--user", USER, folder]);
    assert!(again.status.success(), "the second `kotton keep` failed.\n{}", said(&again));
    assert!(
        said(&again).contains("copied 0 files, 2 already there unchanged"),
        "the second run copied a file that had not changed.\n{}",
        said(&again)
    );

    let listed = cli.run(&["keep", "--user", USER]);
    assert!(listed.status.success(), "`kotton keep` with no folder failed.\n{}", said(&listed));
    assert!(
        said(&listed).contains("/Photos") && said(&listed).contains(folder),
        "the listing does not say /Photos is kept from {folder}.\n{}",
        said(&listed)
    );

    // The record is sealed in the tree: nothing under the person's directory on E holds the
    // folder's path in the clear, and no record rests beside the command history.
    let person = e.base_dir.join("users").join(USER);
    assert!(!person.join("kept.json").exists(), "a record of what is kept rests on E's disk");
    let searched = assert_not_in_the_clear(&person, folder.as_bytes());
    assert!(searched > 0, "nothing under {} was searched", person.display());

    // ── E syncs to the drive; N pulls from there, and reads the folder back ──────
    alice_e
        .sync_mount(USER, "local", "vault", Some(SyncDirection::Push))
        .await
        .expect("E pushes to the drive");
    let pulled = alice_n
        .sync_mount(USER, "local", "vault", Some(SyncDirection::Pull))
        .await
        .expect("N pulls from the drive");
    assert!(pulled.pulled >= 1, "N pulled nothing from the drive: {pulled:?}");

    for (path, body) in [
        ("/Photos/beach.jpg", &b"sand, and the sea behind it"[..]),
        ("/Photos/2026/lake.jpg", &b"a lake, nested a folder down"[..]),
    ] {
        let read = alice_n
            .read_file(USER, path)
            .await
            .unwrap_or_else(|e| panic!("N cannot read {path}: {e}"));
        assert_eq!(read, body, "{path} on N is not the file kept on E");
    }

    // E's record is the person's own, in their tree, under E's own key.
    let record = format!("/.kept/{}.json", did_e.rsplit(':').next().unwrap());
    let read = alice_n
        .read_file(USER, &record)
        .await
        .unwrap_or_else(|e| panic!("N cannot read E's record {record}: {e}"));
    let read = String::from_utf8(read).expect("the record is JSON");
    assert!(
        read.contains("\"/Photos\"") && read.contains(folder),
        "E's record does not say /Photos is kept from {folder}:\n{read}"
    );
}

/// Every file under `dir`, searched for `needle`; how many were searched.
fn assert_not_in_the_clear(dir: &std::path::Path, needle: &[u8]) -> usize {
    let mut searched = 0;
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(d) = dirs.pop() {
        for entry in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                dirs.push(path);
            } else {
                let bytes = std::fs::read(&path).unwrap_or_default();
                assert!(
                    !bytes.windows(needle.len()).any(|w| w == needle),
                    "{} holds {} in the clear",
                    path.display(),
                    String::from_utf8_lossy(needle)
                );
                searched += 1;
            }
        }
    }
    searched
}
