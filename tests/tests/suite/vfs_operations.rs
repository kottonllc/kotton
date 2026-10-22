// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — VFS file operations (RFC-0002)
//!
//! Exercises `write_file`, `read_file`, `list_files`, and `delete_file` via
//! the daemon IPC. Verifies:
//!
//! 1. Write → read roundtrip produces identical bytes.
//! 2. Delete removes the file; subsequent read returns an error.
//! 3. Overwriting a file replaces its contents.
//! 4. Listing files under a prefix returns only the expected entries.
//! 5. Writing to a path and then deleting removes it from the listing.

use crate::common::TestEnv;

const USER: &str = "alice";

// ── helpers ───────────────────────────────────────────────────────────────────

/// Create a user in the daemon. Returns the DID string.
async fn setup_user(env: &mut TestEnv) -> String {
    let (did, _fingerprint) =
        env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    did
}

// ── tests ─────────────────────────────────────────────────────────────────────

/// Write a file then read it back — bytes must be identical.
#[tokio::test]
async fn write_then_read_roundtrip() {
    let mut env = TestEnv::spawn().await;
    setup_user(&mut env).await;

    let data = b"hello, kotton!";
    env.client
        .write_file(USER, "/notes/hello.txt", data)
        .await
        .expect("write_file");

    let read_back = env
        .client
        .read_file(USER, "/notes/hello.txt")
        .await
        .expect("read_file");

    assert_eq!(read_back, data);
}

/// Overwriting a file replaces its contents.
#[tokio::test]
async fn overwrite_replaces_contents() {
    let mut env = TestEnv::spawn().await;
    setup_user(&mut env).await;

    env.client
        .write_file(USER, "/doc.txt", b"v1")
        .await
        .expect("write v1");

    env.client
        .write_file(USER, "/doc.txt", b"v2")
        .await
        .expect("write v2");

    let result = env
        .client
        .read_file(USER, "/doc.txt")
        .await
        .expect("read after overwrite");

    assert_eq!(result, b"v2");
}

/// Delete removes the file; a subsequent read returns an error.
#[tokio::test]
async fn delete_file_then_read_returns_error() {
    let mut env = TestEnv::spawn().await;
    setup_user(&mut env).await;

    env.client
        .write_file(USER, "/tmp/scratch.txt", b"disposable")
        .await
        .expect("write_file");

    // Sanity: file exists.
    let _ = env
        .client
        .read_file(USER, "/tmp/scratch.txt")
        .await
        .expect("read before delete");

    // Delete it.
    env.client
        .delete_file(USER, "/tmp/scratch.txt")
        .await
        .expect("delete_file");

    // Read should now fail.
    let err = env
        .client
        .read_file(USER, "/tmp/scratch.txt")
        .await
        .expect_err("read after delete should return error");

    // The SDK wraps the underlying error; any error is sufficient evidence
    // that the file no longer exists.
    let _ = err;
}

/// Deleting a non-existent file returns an error (not silent success).
#[tokio::test]
async fn delete_nonexistent_file_returns_error() {
    let mut env = TestEnv::spawn().await;
    setup_user(&mut env).await;

    let _err = env
        .client
        .delete_file(USER, "/nonexistent/ghost.txt")
        .await
        .expect_err("deleting nonexistent file should error");
}

/// Listing files under a prefix returns the expected paths.
#[tokio::test]
async fn list_files_returns_entries_under_prefix() {
    let mut env = TestEnv::spawn().await;
    setup_user(&mut env).await;

    env.client
        .write_file(USER, "/archive/2024/jan.txt", b"jan")
        .await
        .expect("write jan");
    env.client
        .write_file(USER, "/archive/2024/feb.txt", b"feb")
        .await
        .expect("write feb");
    // A file outside the prefix that must NOT appear in the listing.
    env.client
        .write_file(USER, "/other/unrelated.txt", b"x")
        .await
        .expect("write unrelated");

    let files = env
        .client
        .list_files(USER, "/archive/2024")
        .await
        .expect("list_files");

    // Both archive files must be present.
    assert!(
        files.iter().any(|f| f.contains("jan.txt")),
        "expected jan.txt in listing, got: {files:?}"
    );
    assert!(
        files.iter().any(|f| f.contains("feb.txt")),
        "expected feb.txt in listing, got: {files:?}"
    );
    // Unrelated file must NOT appear.
    assert!(
        !files.iter().any(|f| f.contains("unrelated.txt")),
        "unrelated.txt should not appear in prefix listing, got: {files:?}"
    );
}

/// After delete, the file no longer appears in a listing.
#[tokio::test]
async fn delete_removes_file_from_listing() {
    let mut env = TestEnv::spawn().await;
    setup_user(&mut env).await;

    env.client
        .write_file(USER, "/inbox/a.txt", b"a")
        .await
        .expect("write a");
    env.client
        .write_file(USER, "/inbox/b.txt", b"b")
        .await
        .expect("write b");

    // Delete a.txt.
    env.client
        .delete_file(USER, "/inbox/a.txt")
        .await
        .expect("delete a");

    let files = env
        .client
        .list_files(USER, "/inbox")
        .await
        .expect("list after delete");

    assert!(
        !files.iter().any(|f| f.contains("a.txt")),
        "a.txt should be gone from listing, got: {files:?}"
    );
    assert!(
        files.iter().any(|f| f.contains("b.txt")),
        "b.txt should still be in listing, got: {files:?}"
    );
}

/// `purge` is reachable, and erases the history a delete would have kept.
///
/// Worth an integration test rather than a unit one because the defect it
/// closes was never in the storage layer: `purge` has been implemented and
/// tested since RFC-0047 and had no IPC verb, no CLI command, and no caller
/// anywhere. It worked and could not be run.
#[tokio::test]
async fn purge_is_reachable_over_ipc() {
    let mut env = TestEnv::spawn().await;
    setup_user(&mut env).await;

    env.client
        .write_file(USER, "/notes/secret.txt", b"sensitive")
        .await
        .expect("write");
    assert_eq!(
        env.client.read_file(USER, "/notes/secret.txt").await.expect("read"),
        b"sensitive"
    );

    env.client
        .purge_file(USER, "/notes/secret.txt")
        .await
        .expect("purge must be reachable over IPC");

    assert!(
        env.client.read_file(USER, "/notes/secret.txt").await.is_err(),
        "the purged path must be gone"
    );
}

/// The conflict surface answers over IPC even when there is nothing to report.
///
/// An empty answer is the common case and the one most likely to be broken by a
/// missing wiring: a handler that errors on "no conflicts" would look fine in
/// every test that arranges one.
#[tokio::test]
async fn listing_conflicts_answers_when_there_are_none() {
    let mut env = TestEnv::spawn().await;
    setup_user(&mut env).await;

    env.client
        .write_file(USER, "/notes/a.txt", b"one")
        .await
        .expect("write");

    let conflicts = env
        .client
        .list_conflicts(USER)
        .await
        .expect("listing conflicts must not error when there are none");
    assert!(conflicts.is_empty(), "no concurrent write happened");
}
