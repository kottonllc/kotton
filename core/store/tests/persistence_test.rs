// SPDX-License-Identifier: AGPL-3.0-or-later
//! `UserStore` survives a restart: what is written before is readable after.
//!
//! It lives with the type it tests, in this crate.

//! Persistence tests — the core claim of the product.
//!
//! These tests prove that data written to a UserStore survives a simulated
//! daemon restart: the runtime is dropped, reloaded from disk, and the data
//! is still there and correct.

use kotton_store::runtime::user::UserStore;

/// Data keys for an **unlocked** node — the same key on both sides of the
/// simulated restart, as a real device would have.
///
/// These tests passed `UserKeys::default()`, which is keyless. Before
/// `SealedOnlyStorage` that silently produced a bare local store, so the most
/// important test in the codebase was proving that *unencrypted* files survive a
/// restart — while a real user's files are sealed. The claim being tested now
/// matches the claim that matters: data survives a restart **and is still
/// readable with the user's key**.
fn unlocked_keys() -> kotton_store::runtime::UserKeys {
    kotton_store::runtime::UserKeys::new(Some([7u8; 32]))
}

/// Write a file, drop the runtime, reload from disk, read back the file.
/// This is the most important test in the codebase.
#[tokio::test]
async fn files_survive_restart() {
    let temp = tempfile::tempdir().unwrap();
    let base_dir = temp.path().to_path_buf();

    // --- Before restart ---
    {
        let runtime = UserStore::create(
            "alice",
            "did:test:alice",
            base_dir.clone(),
            unlocked_keys(),
            &kotton_store::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();

        // Save config so the mount path is persisted to disk.
        runtime.save_config().unwrap();

        runtime
            .write_file("/documents/hello.txt", b"Hello, Kotton!")
            .await
            .unwrap();

        // runtime goes out of scope here — simulating a daemon shutdown.
    }

    // --- After restart ---
    {
        let runtime = UserStore::load(
            "alice",
            "did:test:alice",
            base_dir.clone(),
            unlocked_keys(),
            &kotton_store::LocalShelves(kotton_fs::OsFilesystem),
        )
        .await
        .unwrap();

        let contents = runtime
            .read_file("/documents/hello.txt")
            .await
            .unwrap();

        assert_eq!(contents, b"Hello, Kotton!");
    }
}

/// Multiple files at different paths all survive a restart.
#[tokio::test]
async fn multiple_files_survive_restart() {
    let temp = tempfile::tempdir().unwrap();
    let base_dir = temp.path().to_path_buf();

    let files: &[(&str, &[u8])] = &[
        ("/notes/meeting.txt", b"discussed the roadmap"),
        ("/docs/readme.md", b"# Kotton\n\nOwn your data."),
        ("/photos/meta.json", b"{\"count\": 42}"),
    ];

    // Write phase
    {
        let runtime = UserStore::create(
            "bob",
            "did:test:bob",
            base_dir.clone(),
            unlocked_keys(),
            &kotton_store::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();

        runtime.save_config().unwrap();

        for (path, content) in files {
            runtime.write_file(path, content).await.unwrap();
        }
    }

    // Reload and verify phase
    {
        let runtime = UserStore::load(
            "bob",
            "did:test:bob",
            base_dir.clone(),
            unlocked_keys(),
            &kotton_store::LocalShelves(kotton_fs::OsFilesystem),
        )
        .await
        .unwrap();

        for (path, expected) in files {
            let contents = runtime.read_file(path).await.unwrap();
            assert_eq!(
                contents.as_slice(),
                *expected,
                "Mismatch for file: {}",
                path
            );
        }
    }
}

/// A file written before a restart is still readable and unmodified after.
/// A file written after a restart that started fresh should not see old deleted files.
#[tokio::test]
async fn delete_before_restart_stays_deleted() {
    let temp = tempfile::tempdir().unwrap();
    let base_dir = temp.path().to_path_buf();

    {
        let runtime = UserStore::create(
            "carol",
            "did:test:carol",
            base_dir.clone(),
            unlocked_keys(),
            &kotton_store::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();

        runtime.save_config().unwrap();

        runtime
            .write_file("/temp/scratch.txt", b"temporary")
            .await
            .unwrap();

        // Delete before dropping
        runtime
            .delete_file("/temp/scratch.txt")
            .await
            .unwrap();
    }

    {
        let runtime = UserStore::load(
            "carol",
            "did:test:carol",
            base_dir.clone(),
            unlocked_keys(),
            &kotton_store::LocalShelves(kotton_fs::OsFilesystem),
        )
        .await
        .unwrap();

        let exists = runtime
            .file_exists("local", "/temp/scratch.txt")
            .await
            .unwrap();

        assert!(!exists, "Deleted file should not reappear after reload");
    }
}
