// SPDX-License-Identifier: AGPL-3.0-or-later
//! `files` handler tests, exercised against the daemon's real `FileHost`.
//!
//! The handlers are `kotton_device::users::files`; these tests are here. They build a
//! `DaemonFileHost` over this crate's `DaemonUserResources`: the trait travels with the
//! domain, the implementation stays with whoever can satisfy it, and the tests go with
//! the implementation.

#![cfg(test)]

use kotton_device::users::files::*;
/// The unlock credential these fixtures create identities with — five BIP-39
/// words, 55.00 bits by the wordlist path. Mirrors the integration suite's
/// `TEST_PASSPHRASE`; a literal rather than a shared import because this crate
/// does not depend on the test harness.
const TEST_PASSPHRASE: &str = "canyon-orbit-velvet-fish-hospital";

// Previously inherited via `use super::*` from the handler file.
use crate::residency::{DaemonUserResources, RecordStores, UserRegistry};
use kotton_wire::ipc::UserResponse;
use kotton_wire::ipc::MAX_STREAMED_FILE_BYTES;
use std::collections::HashMap;
use std::sync::Arc;
mod reassembly_tests {
    use super::*;
    use kotton_device::config::RuntimeConfig;
    use kotton_device::users::DeviceUsers as _;
    use kotton_device::DeviceRuntime;

    /// Returns the registry too: residency is the daemon's now, so a test that
    /// wants a resident user must hold the registry it registered into. Without
    /// this the local one was dropped on return and the user vanished.
    async fn env() -> (tempfile::TempDir, Arc<DeviceRuntime>, UserRegistry) {
        let users = UserRegistry::new();
        let dir = tempfile::tempdir().expect("tempdir");
        let secrets: Arc<dyn kotton_sys::secret::SecretsStore + Send + Sync> =
            Arc::new(kotton_secret::MemorySecrets::new());
        let rt = DeviceRuntime::new_with_secrets(
            dir.path().to_owned(),
            RuntimeConfig::default(),
            secrets,
        )
        .await
        .expect("DeviceRuntime");
        let (_, alice_rt) = rt
            .create_user("alice", TEST_PASSPHRASE)
            .await
            .expect("create_user");
        users.insert("alice".to_string(), alice_rt);
        (dir, Arc::new(rt), users)
    }

    fn map() -> SealedReassembly {
        Arc::new(tokio::sync::Mutex::new(HashMap::new()))
    }

    /// The daemon's per-user seam, over a test's registry.
    ///
    /// `file_host` takes one of these rather than a `UserRegistry` and a
    /// `RecordStores` — the same collapse the sync engine got. Built per call
    /// here because each of these tests wants a fresh, empty store cache, which
    /// is what the old inline `RecordStores::new()` was saying too.
    fn resources(rt: &Arc<DeviceRuntime>, users: &UserRegistry) -> Arc<DaemonUserResources> {
        DaemonUserResources::new(
            users.clone(),
            RecordStores::new(),
            Arc::new(std::sync::RwLock::new(HashMap::new())),
            Arc::clone(rt),
            None,
        )
    }

    /// Push `blob` to `path` as `chunk`-sized WriteSealed calls; return the final
    /// response (the earlier ones must all be `Ok`).
    async fn push(
        rt: &Arc<DeviceRuntime>,
        users: &UserRegistry,
        reasm: &SealedReassembly,
        path: &str,
        blob: &[u8],
        domain: &str,
        chunk: usize,
    ) -> UserResponse {
        let total = blob.len() as u64;
        let hash = blake3::hash(blob).to_hex().to_string();
        let mut off = 0usize;
        loop {
            let end = (off + chunk).min(blob.len());
            let resp = write_sealed(
                &crate::agent::file_host::file_host(rt, &*resources(rt, users)),
                "alice".into(),
                "local".into(),
                path.into(),
                blob[off..end].to_vec(),
                domain.into(),
                off as u64,
                total,
                hash.clone(),
                Some(reasm),
            )
            .await
            .unwrap();
            off = end;
            if off >= blob.len() {
                return resp;
            }
            assert!(
                matches!(resp, UserResponse::Ok),
                "mid-transfer chunk not Ok: {resp:?}"
            );
        }
    }

    /// A large blob pushed in many chunks reassembles, verifies, commits, and
    /// reads back byte-identical — and the buffer is cleared afterwards.
    #[tokio::test]
    async fn a_multi_chunk_sealed_write_reassembles_and_reads_back() {
        let _users = UserRegistry::new();
        let (_d, rt, users) = env().await;
        let domain = rt
            .user_cek_domain_id("alice", users.get("alice").as_deref())
            .expect("domain");
        let blob: Vec<u8> = (0..12_000u32).flat_map(|n| n.to_le_bytes()).collect(); // 48 KiB
        let reasm = map();

        let resp = push(&rt, &users, &reasm, "a/big.bin", &blob, &domain, 4096).await;
        assert!(matches!(resp, UserResponse::Ok), "final chunk: {resp:?}");
        assert!(
            reasm.lock().await.is_empty(),
            "buffer left behind after commit"
        );

        let got = read_sealed(
            &crate::agent::file_host::file_host(&rt, &*resources(&rt, &users)),
            "alice".into(),
            "local".into(),
            "a/big.bin".into(),
            0,
            blob.len() as u32,
        )
        .await
        .unwrap();
        match got {
            UserResponse::SealedObject {
                blob: b,
                total_size,
                ..
            } => {
                assert_eq!(b, blob);
                assert_eq!(total_size, blob.len() as u64);
            }
            other => panic!("expected SealedObject, got {other:?}"),
        }
    }

    /// A reassembly whose bytes do not hash to the declared `content_hash` is
    /// refused at write, and nothing is stored.
    #[tokio::test]
    async fn a_hash_mismatch_is_refused_and_stores_nothing() {
        let _users = UserRegistry::new();
        let (_d, rt, users) = env().await;
        let domain = rt
            .user_cek_domain_id("alice", users.get("alice").as_deref())
            .expect("domain");
        let blob = vec![9u8; 20_000];
        let reasm = map();
        let wrong = blake3::hash(b"not this blob").to_hex().to_string();

        // One complete chunk carrying the whole object but a wrong hash.
        let resp = write_sealed(
            &crate::agent::file_host::file_host(&rt, &*resources(&rt, &users)),
            "alice".into(),
            "local".into(),
            "a/x.bin".into(),
            blob.clone(),
            domain,
            0,
            blob.len() as u64,
            wrong,
            Some(&reasm),
        )
        .await
        .unwrap();
        match resp {
            UserResponse::Error { message } => {
                assert!(message.contains("content hash mismatch"), "{message}")
            }
            other => panic!("expected hash-mismatch error, got {other:?}"),
        }
        assert!(
            reasm.lock().await.is_empty(),
            "buffer not cleaned after mismatch"
        );
        // Nothing was written.
        assert!(matches!(
            read_sealed(
                &crate::agent::file_host::file_host(&rt, &*resources(&rt, &users)),
                "alice".into(),
                "local".into(),
                "a/x.bin".into(),
                0,
                100
            )
            .await
            .unwrap(),
            UserResponse::Error { .. }
        ));
    }

    /// **The claim this whole unit exists to make**: an object larger than the
    /// buffered ceiling installs, and reads back.
    ///
    /// This test cannot pass on the buffered path by construction. 300 MiB is
    /// above `MAX_BUFFERED_FILE_BYTES` (256 MiB), which is the single cap that
    /// governed every file write before this change — so on `main` this write is
    /// refused outright, and the only way it succeeds is by streaming into the
    /// store. That makes it the red-before-green for the unit rather than a test
    /// of a path I would otherwise be assuming was taken.
    ///
    /// Held well under `MAX_STREAMED_FILE_BYTES` (8 GiB), which is what a real
    /// model uses.
    #[tokio::test]
    async fn an_object_larger_than_the_buffered_cap_installs_and_reads_back() {
        let _users = UserRegistry::new();
        let (_d, rt, users) = env().await;
        let reasm = map();

        const PIECE: usize = 4 * 1024 * 1024;
        let total: u64 = 300 * 1024 * 1024;

        // Hash the object as it is built, so the declared hash is the true one.
        let mut hasher = blake3::Hasher::new();
        let mut offset: u64 = 0;
        let mut pieces: Vec<Vec<u8>> = Vec::new();
        while offset < total {
            let take = std::cmp::min(PIECE as u64, total - offset) as usize;
            // Vary by piece so the chunker does real work rather than deduping
            // the whole object down to one chunk.
            let p = vec![(pieces.len() % 251) as u8; take];
            hasher.update(&p);
            pieces.push(p);
            offset += take as u64;
        }
        let declared = hasher.finalize().to_hex().to_string();

        let mut offset: u64 = 0;
        for p in &pieces {
            let resp = write_file(
                &crate::agent::file_host::file_host(&rt, &*resources(&rt, &users)),
                "alice".into(),
                "/m/big.gguf".into(),
                p.clone(),
                offset,
                total,
                declared.clone(),
                Some(&reasm),
            )
            .await
            .unwrap();
            offset += p.len() as u64;
            if offset < total {
                assert!(matches!(resp, UserResponse::Ok), "mid-transfer: {resp:?}");
            } else {
                assert!(
                    matches!(resp, UserResponse::Ok),
                    "the object was refused at its last chunk: {resp:?}"
                );
            }
        }
        assert!(reasm.lock().await.is_empty(), "transfer not cleaned up");

        // And it reads back — at the far end, through the ranged path.
        let read = read_file(
            &crate::agent::file_host::file_host(&rt, &*resources(&rt, &users)),
            "alice".into(),
            "/m/big.gguf".into(),
            total - 16,
            16,
        )
        .await
        .unwrap();
        match read {
            UserResponse::FileData { data, total_size } => {
                assert_eq!(total_size, total, "the whole object is there");
                assert_eq!(data.len(), 16, "the far end reads");
            }
            other => panic!("expected the tail of the object, got {other:?}"),
        }
    }

    /// The streamed path applies the same integrity gate at the same point in
    /// the object's life: bytes whose hash is wrong never become visible.
    ///
    /// This is the property a whole-buffer seal gave for free and that streaming
    /// has to keep deliberately. The bytes here *are* written to disk before the
    /// check — that is what streaming means — so the test is not "nothing was
    /// written" but the stronger thing that matters: **no name resolves to
    /// them.** `MAX_STREAMED_FILE_BYTES` is what bounds the disk they occupied.
    ///
    /// Sized just over `STREAM_ABOVE_BYTES` (16 MiB) so it takes the streaming
    /// path rather than the buffered one; below that threshold this would be a
    /// second copy of `a_hash_mismatch_is_refused_and_stores_nothing`.
    #[tokio::test]
    async fn a_streamed_hash_mismatch_leaves_nothing_that_can_be_named() {
        let _users = UserRegistry::new();
        let (_d, rt, users) = env().await;
        let reasm = map();
        let total: u64 = 17 * 1024 * 1024;
        let wrong = blake3::hash(b"not these bytes at all").to_hex().to_string();

        // Feed the whole object in 4 MiB chunks, as the client does.
        let chunk = vec![7u8; 4 * 1024 * 1024];
        let mut offset: u64 = 0;
        let mut last = None;
        while offset < total {
            let take = std::cmp::min(chunk.len() as u64, total - offset) as usize;
            let resp = write_file(
                &crate::agent::file_host::file_host(&rt, &*resources(&rt, &users)),
                "alice".into(),
                "/m/w.gguf".into(),
                chunk[..take].to_vec(),
                offset,
                total,
                wrong.clone(),
                Some(&reasm),
            )
            .await
            .unwrap();
            offset += take as u64;
            last = Some(resp);
        }

        match last.expect("the last chunk answered") {
            UserResponse::Error { message } => {
                assert!(message.contains("content hash mismatch"), "{message}")
            }
            other => panic!("expected a hash-mismatch error, got {other:?}"),
        }
        assert!(
            reasm.lock().await.is_empty(),
            "the transfer was not cleaned up after the mismatch"
        );

        // The point of the test: the path resolves to nothing.
        let read = read_file(
            &crate::agent::file_host::file_host(&rt, &*resources(&rt, &users)),
            "alice".into(),
            "/m/w.gguf".into(),
            0,
            64,
        )
        .await
        .unwrap();
        match read {
            UserResponse::Error { .. } => {}
            UserResponse::FileData { data, total_size } => panic!(
                "refused bytes became readable: {} bytes, total {total_size}",
                data.len()
            ),
            other => panic!("unexpected response {other:?}"),
        }
    }

    /// A chunk that does not continue the buffer sequentially is dropped.
    #[tokio::test]
    async fn an_out_of_order_chunk_is_dropped() {
        let _users = UserRegistry::new();
        let (_d, rt, users) = env().await;
        let domain = rt
            .user_cek_domain_id("alice", users.get("alice").as_deref())
            .expect("domain");
        let reasm = map();
        let hash = blake3::hash(&[1u8; 8]).to_hex().to_string();

        // Start at offset 0 with 4 bytes of an 8-byte object…
        let r1 = write_sealed(
            &crate::agent::file_host::file_host(&rt, &*resources(&rt, &users)),
            "alice".into(),
            "local".into(),
            "a/y.bin".into(),
            vec![1u8; 4],
            domain.clone(),
            0,
            8,
            hash.clone(),
            Some(&reasm),
        )
        .await
        .unwrap();
        assert!(matches!(r1, UserResponse::Ok));
        // …then a chunk at the wrong offset (6, not 4) — rejected, buffer dropped.
        let r2 = write_sealed(
            &crate::agent::file_host::file_host(&rt, &*resources(&rt, &users)),
            "alice".into(),
            "local".into(),
            "a/y.bin".into(),
            vec![1u8; 2],
            domain,
            6,
            8,
            hash,
            Some(&reasm),
        )
        .await
        .unwrap();
        assert!(
            matches!(r2, UserResponse::Error { .. }),
            "out-of-order chunk not rejected: {r2:?}"
        );
        assert!(reasm.lock().await.is_empty());
    }

    /// The local path (`None`) admits a single complete chunk but refuses a
    /// **A model does not fit through this path, and here is the number.**
    ///
    /// A model is installed as a sealed object in the person's own store, and
    /// every model in view — a quantised 1–4B model — is between about
    /// 0.7 and 3 GiB. `MAX_SEALED_OBJECT_BYTES` is 256 MiB, because a chunked
    /// write is *reassembled in this process's memory* before anything is
    /// sealed, so the ceiling is a bound on what one stream can make the daemon
    /// buffer.
    ///
    /// Measured on `write_file`, which is the path `kotton model add` takes.
    /// The refusal arrives on the **declared** size, before a byte is buffered,
    /// which is why this test costs a kilobyte rather than eight gigabytes: the
    /// first chunk of an over-ceiling write is refused exactly as the last one
    /// would be.
    ///
    /// **The number is not the property.** A large file streams into the store,
    /// not buffered whole, so the ceiling is `MAX_STREAMED_FILE_BYTES` and bounds
    /// **disk** — what one unverified stream may write before its hash is checked. The pair is kept
    /// because the early refusal is the reason a too-large install fails in a
    /// second with a sentence instead of after streaming gigabytes, and the
    /// acceptance is what makes the refusal a boundary rather than some other
    /// failure wearing its name.
    #[tokio::test]
    async fn the_streaming_ceiling_is_enforced_on_the_declared_size() {
        let (_d, rt, users) = env().await;

        // The first chunk of an over-ceiling write, framed exactly as a real one
        // would be: a sub-cap chunk that declares the whole file's size.
        let head = vec![7u8; 1024];
        let over = MAX_STREAMED_FILE_BYTES + 1;
        let refused = write_file(
            &crate::agent::file_host::file_host(&rt, &*resources(&rt, &users)),
            "alice".into(),
            "models/deadbeef.weights".into(),
            head.clone(),
            0,
            over,
            "deadbeef".into(),
            Some(&map()),
        )
        .await
        .unwrap();
        match refused {
            UserResponse::Error { message } => assert!(
                message.contains("too large"),
                "the refusal must say what it is: {message}"
            ),
            other => panic!("an over-ceiling object must be refused, got {other:?}"),
        }

        // And the ceiling is where it says it is: a first chunk declaring exactly
        // the ceiling is accepted, so the refusal above is the boundary. Only the
        // first chunk is sent — the transfer is opened, not completed — so this
        // costs a kilobyte and not 8 GiB.
        let at_the_ceiling = write_file(
            &crate::agent::file_host::file_host(&rt, &*resources(&rt, &users)),
            "alice".into(),
            "models/cafe.weights".into(),
            head.clone(),
            0,
            MAX_STREAMED_FILE_BYTES,
            blake3::hash(&head).to_hex().to_string(),
            Some(&map()),
        )
        .await
        .unwrap();
        assert!(
            matches!(at_the_ceiling, UserResponse::Ok),
            "the ceiling is accepted, not one byte below it: {at_the_ceiling:?}"
        );
    }

    /// partial one — there is no local chunked-write caller.
    #[tokio::test]
    async fn the_local_path_requires_a_single_complete_chunk() {
        let _users = UserRegistry::new();
        let (_d, rt, users) = env().await;
        let domain = rt
            .user_cek_domain_id("alice", users.get("alice").as_deref())
            .expect("domain");
        let blob = vec![5u8; 1000];
        let hash = blake3::hash(&blob).to_hex().to_string();

        // Complete single chunk: accepted.
        let ok = write_sealed(
            &crate::agent::file_host::file_host(&rt, &*resources(&rt, &users)),
            "alice".into(),
            "local".into(),
            "a/z.bin".into(),
            blob.clone(),
            domain.clone(),
            0,
            blob.len() as u64,
            hash.clone(),
            None,
        )
        .await
        .unwrap();
        assert!(matches!(ok, UserResponse::Ok));

        // A partial chunk with no reassembly buffer: refused.
        let bad = write_sealed(
            &crate::agent::file_host::file_host(&rt, &*resources(&rt, &users)),
            "alice".into(),
            "local".into(),
            "a/z2.bin".into(),
            vec![5u8; 500],
            domain,
            0,
            1000,
            hash,
            None,
        )
        .await
        .unwrap();
        assert!(matches!(bad, UserResponse::Error { .. }));
    }

    // ── A model's weights: the daemon's object, through their own door ───────
    // (no `files` grant reaches them)

    /// Stream `body` as `chunk`-sized `ModelWeights` calls declaring `hash`;
    /// return the final response (the earlier ones must all be `Ok`).
    async fn push_weights(
        rt: &Arc<DeviceRuntime>,
        users: &UserRegistry,
        reasm: &SealedReassembly,
        body: &[u8],
        hash: &str,
        chunk: usize,
    ) -> UserResponse {
        let mut off = 0usize;
        loop {
            let end = (off + chunk).min(body.len());
            let resp = kotton_device::users::models::model_weights(
                &crate::agent::file_host::file_host(rt, &*resources(rt, users)),
                "alice".into(),
                body[off..end].to_vec(),
                off as u64,
                body.len() as u64,
                hash.to_string(),
                reasm,
            )
            .await
            .unwrap();
            off = end;
            if off >= body.len() {
                return resp;
            }
            assert!(matches!(resp, UserResponse::Ok), "mid-stream chunk not Ok: {resp:?}");
        }
    }

    fn alice_store(
        rt: &Arc<DeviceRuntime>,
        users: &UserRegistry,
    ) -> Arc<kotton_store::runtime::user::UserStore> {
        crate::agent::file_host::file_host(rt, &*resources(rt, users))
            .user_store("alice")
            .expect("alice is resident")
    }

    /// **Weights streamed in many chunks land at the daemon's key and nowhere
    /// in the person's tree** — the verb `kotton model add` sends them through.
    #[tokio::test]
    async fn weights_streamed_in_chunks_land_at_the_daemons_key_and_not_in_the_tree() {
        let (_d, rt, users) = env().await;
        let reasm = map();
        let body: Vec<u8> = (0..5_000_000u32).map(|i| (i % 241) as u8).collect();
        let hash = blake3::hash(&body).to_hex().to_string();

        let resp = push_weights(&rt, &users, &reasm, &body, &hash, 1 << 20).await;
        assert!(matches!(resp, UserResponse::Ok), "{resp:?}");
        assert!(reasm.lock().await.is_empty(), "the stream's buffer outlived it");

        let key = kotton_device::users::models::model_object_path(&hash).expect("a digest");
        let store = alice_store(&rt, &users);
        assert_eq!(store.read_daemon_object(&key).await.expect("the daemon's object"), body);
        assert!(
            store.read_file(&format!("/{key}")).await.is_err(),
            "the weights are readable through the person's tree"
        );
        assert!(
            store.list_files("/").await.expect("the tree lists").is_empty(),
            "the person's tree lists the weights"
        );
    }

    /// A stream that is not the hash it declared commits nothing, under any
    /// name — the bytes were down, and no key resolves to them.
    #[tokio::test]
    async fn weights_that_are_not_their_declared_hash_leave_nothing() {
        let (_d, rt, users) = env().await;
        let reasm = map();
        let body = vec![7u8; 3_000_000];
        let declared = blake3::hash(b"some other model").to_hex().to_string();

        let resp = push_weights(&rt, &users, &reasm, &body, &declared, 1 << 20).await;
        match resp {
            UserResponse::Error { message } => {
                assert!(message.contains("not the"), "{message}")
            }
            other => panic!("a mismatched stream was accepted: {other:?}"),
        }
        let key = kotton_device::users::models::model_object_path(&declared).expect("a digest");
        assert!(alice_store(&rt, &users).read_daemon_object(&key).await.is_err());
    }

    /// The key is derived from the caller's hash, so a "hash" that is not a
    /// BLAKE3 digest names no key at all — `../files/…` would otherwise reach
    /// into the person's tree from the daemon's side.
    #[tokio::test]
    async fn a_hash_that_is_not_a_digest_names_no_key() {
        let (_d, rt, users) = env().await;
        let reasm = map();
        let body = b"not weights".to_vec();
        for bad in [
            "../files/notes/a",
            "../../x",
            &"A".repeat(64),
            &"a".repeat(63),
            "",
        ] {
            let resp = push_weights(&rt, &users, &reasm, &body, bad, body.len()).await;
            assert!(
                matches!(&resp, UserResponse::Error { message } if message.contains("not a weights hash")),
                "'{bad}' was taken as a hash: {resp:?}"
            );
        }
        let store = alice_store(&rt, &users);
        assert!(store.list_files("/").await.expect("lists").is_empty());
        let models = store.list_daemon_objects("/models/").await.unwrap_or_default();
        assert!(models.is_empty(), "a refused stream left a daemon object: {models:?}");
    }

    /// `ListSealed`'s prefix is a peer's word, and a peer that asks for `../x`
    /// is refused for it, with the [`kotton_store::NotCanonical`] text: it is
    /// not answered for `x`, the prefix a rewrite would have made of it
    /// (kotton #275). An empty prefix is the root, and a canonical one lists
    /// what is under it.
    #[tokio::test]
    async fn a_sealed_listing_for_a_prefix_that_is_not_canonical_is_refused() {
        let (_d, rt, users) = env().await;
        let domain = rt
            .user_cek_domain_id("alice", users.get("alice").as_deref())
            .expect("domain");
        let resp = push(&rt, &users, &map(), "x/a.bin", b"sealed", &domain, 4096).await;
        assert!(matches!(resp, UserResponse::Ok), "{resp:?}");

        let list = |prefix: &str| {
            let (rt, users, prefix) = (Arc::clone(&rt), users.clone(), prefix.to_string());
            async move {
                list_sealed(
                    &crate::agent::file_host::file_host(&rt, &*resources(&rt, &users)),
                    "alice".into(),
                    "local".into(),
                    prefix,
                )
                .await
                .unwrap()
            }
        };
        let keys = |resp: UserResponse| match resp {
            UserResponse::SealedList { entries } => entries.into_iter().map(|e| e.key).collect::<Vec<_>>(),
            other => panic!("expected a listing, got {other:?}"),
        };
        assert!(keys(list("").await).contains(&"x/a.bin".to_string()), "the root lists the object");
        assert_eq!(keys(list("x").await), vec!["x/a.bin".to_string()]);
        match list("../x").await {
            UserResponse::Error { message } => {
                assert_eq!(message, "storage key \"../x\" refused: a component is `.` or `..`")
            }
            other => panic!("`../x` was answered: {other:?}"),
        }
    }
}

/// The device's host reads a mount's pin through the same trait as the vault's,
/// and a pin it cannot read must not be taken for no pin.
mod pin_tests {
    use super::*;
    use kotton_device::config::RuntimeConfig;
    use kotton_device::DeviceRuntime;
    use kotton_sys::secret::{SecretsError, SecretsResult, SecretsStore};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    /// A secrets store whose reads can be made to fail — a locked keychain is
    /// the device's case — and which records every key it is asked to write.
    struct UnreadableWhenLocked {
        inner: kotton_secret::MemorySecrets,
        locked: AtomicBool,
        written: Mutex<Vec<String>>,
    }

    impl SecretsStore for UnreadableWhenLocked {
        fn get_secret(&self, key: &str) -> SecretsResult<Option<String>> {
            if self.locked.load(Ordering::SeqCst) {
                return Err(SecretsError::Storage("the keychain is locked".into()));
            }
            self.inner.get_secret(key)
        }
        fn set_secret(&self, key: &str, value: &str) -> SecretsResult<()> {
            self.written.lock().unwrap().push(key.to_string());
            self.inner.set_secret(key, value)
        }
        fn delete_secret(&self, key: &str) -> SecretsResult<()> {
            self.inner.delete_secret(key)
        }
    }

    async fn write(rt: &Arc<DeviceRuntime>, users: &UserRegistry, path: &str, domain: &str) -> UserResponse {
        let resources = DaemonUserResources::new(
            users.clone(),
            RecordStores::new(),
            Arc::new(std::sync::RwLock::new(HashMap::new())),
            Arc::clone(rt),
            None,
        );
        let blob = format!("sealed under {domain}").into_bytes();
        let hash = blake3::hash(&blob).to_hex().to_string();
        write_sealed(
            &crate::agent::file_host::file_host(rt, &*resources),
            "alice".into(),
            "local".into(),
            path.into(),
            blob.clone(),
            domain.into(),
            0,
            blob.len() as u64,
            hash,
            None,
        )
        .await
        .unwrap()
    }

    /// The device's half of the vault's test: a blind user on this node, whose
    /// mount's domain is its pin. A pin the keychain cannot read refuses the
    /// write, naming the mount, and pins nothing; once the keychain reads
    /// again the mount still answers to its first write's domain.
    #[tokio::test]
    async fn a_pin_the_keychain_cannot_read_refuses_the_write_and_pins_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = Arc::new(UnreadableWhenLocked {
            inner: kotton_secret::MemorySecrets::new(),
            locked: AtomicBool::new(false),
            written: Mutex::new(Vec::new()),
        });
        let rt = Arc::new(
            DeviceRuntime::new_with_secrets(dir.path().join("device"), RuntimeConfig::default(), secrets.clone())
                .await
                .unwrap(),
        );
        let blind = kotton_store::runtime::user::UserStore::create(
            "alice",
            "did:key:zAlice",
            dir.path().join("alice"),
            kotton_store::runtime::UserKeys::new(None),
            &kotton_store::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();
        let users = UserRegistry::new();
        users.insert("alice".to_string(), Arc::new(blind));

        let first = write(&rt, &users, "a/first", "aaaa").await;
        assert!(matches!(first, UserResponse::Ok), "the first write pins the mount: {first:?}");

        secrets.written.lock().unwrap().clear();
        secrets.locked.store(true, Ordering::SeqCst);
        match write(&rt, &users, "a/second", "bbbb").await {
            UserResponse::Error { message } => assert!(message.contains("local"), "the refusal names the mount: {message}"),
            other => panic!("a write whose pin could not be read was not refused: {other:?}"),
        }
        assert!(secrets.written.lock().unwrap().is_empty(), "a pin was written: {:?}", secrets.written.lock().unwrap());

        secrets.locked.store(false, Ordering::SeqCst);
        match write(&rt, &users, "a/third", "bbbb").await {
            UserResponse::SealedDomainMismatch { expected, got } => {
                assert_eq!((expected.as_str(), got.as_str()), ("aaaa", "bbbb"));
            }
            other => panic!("the mount no longer answers to its first pin: {other:?}"),
        }
    }
}
