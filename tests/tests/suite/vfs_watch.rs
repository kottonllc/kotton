// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — VfsWatch streaming subscription (RFC-0017)
//!
//! Covers:
//! 1. Unauthenticated VfsWatch returns `NoActiveSession`.
//! 2. Authenticated VfsWatch opens with `VfsWatchReady` and then streams
//!    `VfsChanged` frames when files change.
//! 3. SyncNow wakes the sync engine (verifies the signal path, not actual sync).


use crate::common::TestEnv;
use kotton_sys::ipc::IpcEndpoint;
use kotton_wire::{UserRequest, UserResponse};
use kotton_ipc::IpcClient;
use std::time::Duration;

const USER: &str = "vfstest";

// ── helpers ──────────────────────────────────────────────────────────────────

async fn open_raw(endpoint: &IpcEndpoint) -> IpcClient<UserRequest, UserResponse> {
    IpcClient::connect(endpoint.clone())
        .await
        .expect("IpcClient::connect")
}

/// Wait for the daemon to say the watch is established, and fail loudly if it
/// says anything else.
///
/// Every test below used to write its file the instant `send_streaming`
/// returned — which is when the *request* has been written to the socket, not
/// when the daemon has subscribed or its watcher thread has registered. A write
/// that lands in that window is simply not seen, with no error, which is how
/// `a_watcher_is_not_shown_another_users_paths` failed four full `just test`
/// runs between 2026-09-14 and 2026-09-17 while passing alone. A longer deadline
/// could not have saved it: the frame was not late, the write happened before
/// there was anything to catch it
/// (`TASK-a-watcher-test-times-out-under-a-loaded-suite`).
///
/// The deadline here is a hang guard, not the thing being waited on: a watcher
/// that never registers reports rather than stalls.
async fn watch_established(frame_rx: &mut tokio::sync::mpsc::Receiver<UserResponse>) {
    let first = tokio::time::timeout(Duration::from_secs(30), frame_rx.recv())
        .await
        .expect("the daemon says whether the VFS watch came up")
        .expect("the VfsWatch stream stays open");
    assert!(
        matches!(first, UserResponse::VfsWatchReady),
        "a VfsWatch stream opens with VfsWatchReady, got {first:?}"
    );
}

// ── tests ────────────────────────────────────────────────────────────────────

/// A VfsWatch request on an unauthenticated connection returns NoActiveSession.
#[tokio::test]
async fn vfs_watch_requires_authentication() {
    let env = TestEnv::spawn().await;

    // Raw connection — no Authenticate.
    let watch_client = open_raw(&env.endpoint).await;
    let mut frame_rx = watch_client
        .send_streaming(&UserRequest::VfsWatch {
            user_id: USER.to_string(),
            paths: vec![],
        })
        .await
        .expect("send_streaming");

    // First frame should be NoActiveSession.
    // 30s, not 2s. The deadline is here so a broken watcher fails instead of
    // hanging — it is not an assertion that the event is *fast*.
    //
    // Raised while chasing a failure it turned out not to explain: the real cause
    // was `spawn_fs_watcher` leaking one inotify instance per daemon, exhausting
    // the 128 the kernel allows, so the watcher never registered and no deadline
    // would have helped. Kept anyway — a wall-clock bound in a suite that now runs
    // 239 tests in four threads should guard against a hang, not measure latency.
    let frame = tokio::time::timeout(Duration::from_secs(30), frame_rx.recv())
        .await
        .expect("timeout waiting for first VfsWatch frame")
        .expect("channel closed unexpectedly");

    assert!(
        matches!(frame, UserResponse::NoActiveSession),
        "expected NoActiveSession, got {frame:?}"
    );
}

/// An authenticated client receives VfsChanged events when files are written
/// under the user's VFS directory.
#[tokio::test]
async fn vfs_watch_delivers_change_events() {
    let mut env = TestEnv::spawn().await;

    // Create user and authenticate.
    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let token = env.client.session_token.clone().expect("session token");

    // Open a dedicated connection for VfsWatch.
    let mut watch_raw = open_raw(&env.endpoint).await;
    match watch_raw
        .send(&UserRequest::Authenticate {
            token: kotton_wire::ipc::SecretText::new(token.clone()),
            scope: Some(vec!["VfsWatch".to_string()]),
        })
        .await
        .expect("auth send")
    {
        UserResponse::ActiveSession { .. } => {}
        other => panic!("unexpected auth response: {other:?}"),
    }

    let mut frame_rx = watch_raw
        .send_streaming(&UserRequest::VfsWatch {
            user_id: USER.to_string(),
            paths: vec![],
        })
        .await
        .expect("send_streaming VfsWatch");
    watch_established(&mut frame_rx).await;

    // Write a file into the user's VFS directory to trigger a change event.
    let user_dir = env.base_dir.join("users").join(USER);
    tokio::fs::create_dir_all(&user_dir)
        .await
        .expect("create user dir");
    let test_file = user_dir.join("test.txt");
    tokio::fs::write(&test_file, b"hello from integration test")
        .await
        .expect("write test file");

    // We should receive at least one VfsChanged frame. The watch is already
    // established, so this deadline guards against a watcher that never fires —
    // it is not standing in for the readiness the frame above now carries.
    let deadline = Duration::from_secs(30);
    let frame = tokio::time::timeout(deadline, frame_rx.recv())
        .await
        .expect("timeout waiting for VfsChanged")
        .expect("channel closed unexpectedly");

    assert!(
        matches!(frame, UserResponse::VfsChanged { .. }),
        "expected VfsChanged, got {frame:?}"
    );
}

/// `SyncDrives` returns a job id and the number of drives it syncs: none,
/// for a person with no drive yet (verifies the handler is wired up and the
/// sync engine signal path doesn't panic).
#[tokio::test]
async fn sync_now_returns_result() {
    let mut env = TestEnv::spawn().await;

    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");

    let result = env.client.sync_drives(USER).await;
    assert!(
        matches!(result, Ok((_, 0))),
        "a sync with no drive should succeed and sync none: {result:?}"
    );
}

/// VfsWatch with an empty `paths` filter receives all change events;
/// a non-matching prefix filter suppresses unrelated changes.
#[tokio::test]
async fn vfs_watch_path_filter_suppresses_unrelated() {
    let mut env = TestEnv::spawn().await;

    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let token = env.client.session_token.clone().expect("session token");

    // Subscribe watching only "/docs/" prefix.
    let mut watch_raw = open_raw(&env.endpoint).await;
    match watch_raw
        .send(&UserRequest::Authenticate {
            token: kotton_wire::ipc::SecretText::new(token.clone()),
            scope: None,
        })
        .await
        .expect("auth")
    {
        UserResponse::ActiveSession { .. } => {}
        other => panic!("unexpected auth: {other:?}"),
    }

    let user_dir = env.base_dir.join("users").join(USER);
    tokio::fs::create_dir_all(&user_dir)
        .await
        .expect("create user dir");

    let mut frame_rx = watch_raw
        .send_streaming(&UserRequest::VfsWatch {
            user_id: USER.to_string(),
            // Only watch the (non-existent) /docs prefix.
            paths: vec![user_dir.join("docs").to_string_lossy().into_owned()],
        })
        .await
        .expect("send_streaming VfsWatch");
    // Without this the silence below proves nothing: an unregistered watch is
    // silent for exactly the same 500 ms as a correctly filtered one.
    watch_established(&mut frame_rx).await;

    // Write a file OUTSIDE the watched prefix.
    let other_file = user_dir.join("other.txt");
    tokio::fs::write(&other_file, b"not in /docs")
        .await
        .expect("write other file");

    // No frame should arrive within 500 ms.
    let maybe_frame = tokio::time::timeout(Duration::from_millis(500), frame_rx.recv()).await;
    assert!(
        maybe_frame.is_err(),
        "should not receive VfsChanged for a file outside the watched prefix"
    );
}

/// One daemon can keep for two people (`two_people_keep_at_one_vault_…`), and
/// the filesystem watcher is one watcher over `<base>/users/` broadcasting
/// absolute paths to one channel. So the question this asks is whether a
/// session for one user is handed the other's paths: not their file contents,
/// which are sealed, but *which* files changed and *when* — which is a record
/// of another person's activity, accumulated by watching, and the thing
/// Article VII refuses.
///
/// Found 2026-09-07 while hoisting the streaming trust floor: `user_id` became
/// an unused parameter, which is how it came out that it had only ever been
/// compared against the session and never used to filter the stream. The doc
/// comment said "filtered by `user_id` and optional path prefixes"; the body
/// filtered by prefixes alone.
#[tokio::test]
async fn a_watcher_is_not_shown_another_users_paths() {
    const WATCHER: &str = "vfswatcher";
    const OTHER: &str = "vfsother";

    let mut env = TestEnv::spawn().await;
    env.client
        .create_user(WATCHER, crate::common::TEST_PASSPHRASE)
        .await
        .expect("create watcher");
    let token = env.client.session_token.clone().expect("session token");

    let mut watch_raw = open_raw(&env.endpoint).await;
    match watch_raw
        .send(&UserRequest::Authenticate {
            token: kotton_wire::ipc::SecretText::new(token),
            scope: Some(vec!["VfsWatch".to_string()]),
        })
        .await
        .expect("auth send")
    {
        UserResponse::ActiveSession { .. } => {}
        other => panic!("unexpected auth response: {other:?}"),
    }

    // The widest watch a caller can ask for: no prefixes at all.
    let mut frame_rx = watch_raw
        .send_streaming(&UserRequest::VfsWatch {
            user_id: WATCHER.to_string(),
            paths: vec![],
        })
        .await
        .expect("send_streaming VfsWatch");
    watch_established(&mut frame_rx).await;

    // Someone else's file changes, and then the watcher's own — so the test
    // measures *which* frames arrive rather than waiting on a silence that a
    // slow watcher would also produce.
    let other_dir = env.base_dir.join("users").join(OTHER);
    tokio::fs::create_dir_all(&other_dir).await.expect("other dir");
    tokio::fs::write(other_dir.join("their-secret-note.txt"), b"theirs")
        .await
        .expect("write their file");

    let own_dir = env.base_dir.join("users").join(WATCHER);
    tokio::fs::create_dir_all(&own_dir).await.expect("own dir");
    tokio::fs::write(own_dir.join("mine.txt"), b"mine")
        .await
        .expect("write own file");

    // Drain until the watcher's own file shows up, or time runs out. Every
    // frame seen on the way must be the watcher's. The watch was established
    // before either write, so this deadline is a hang guard — the race it used
    // to paper over is closed upstream of it.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut saw_own = false;
    while tokio::time::Instant::now() < deadline {
        let Ok(Some(frame)) =
            tokio::time::timeout_at(deadline, frame_rx.recv()).await
        else {
            break;
        };
        if let UserResponse::VfsChanged { path, .. } = frame {
            assert!(
                !path.contains(OTHER),
                "a session for {WATCHER} was handed {OTHER}'s path: {path}"
            );
            if path.contains("mine.txt") {
                saw_own = true;
                break;
            }
        }
    }
    assert!(
        saw_own,
        "the watcher never saw its own file, so this test proved nothing"
    );
}
