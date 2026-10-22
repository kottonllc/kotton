// SPDX-License-Identifier: AGPL-3.0-or-later
//! `ObjectStorage` behavioural contract tests.
//!
//! Every concrete `ObjectStorage` implementation must satisfy the contracts
//! defined here.  Backend test modules call [`run_all`] with a freshly
//! constructed store to verify compliance.
//!
//! # Usage
//!
//! ```rust,ignore
//! #[cfg(test)]
//! mod contract_tests {
//!     use crate::contracts;
//!     use crate::memory::MemoryObjectStorage;
//!
//!     #[tokio::test]
//!     async fn memory_satisfies_contract() {
//!         contracts::run_all(MemoryObjectStorage::new()).await;
//!     }
//! }
//! ```

use kotton_sys::store::{ObjectStorage, ObjectStorageError};
use std::path::Path;

/// Run the full contract test suite against `store`.
///
/// Panics on any contract violation; intended to be called from `#[tokio::test]`
/// functions in each backend's test module.
pub async fn run_all(store: impl ObjectStorage) {
    get_missing_returns_not_found(&store).await;
    put_and_get_roundtrip(&store).await;
    put_overwrites_existing(&store).await;
    a_replaced_object_is_read_whole(&store).await;
    metadata_reflects_size(&store).await;
    exists_true_after_put(&store).await;
    exists_false_after_delete(&store).await;
    delete_missing_returns_not_found(&store).await;
    list_returns_objects_under_prefix(&store).await;
    list_empty_prefix_returns_all(&store).await;
    list_no_match_returns_empty(&store).await;
    large_object_roundtrip(&store).await;
    empty_value_roundtrip(&store).await;
}

// ── Individual contract assertions ──────────────────────────────────────────

async fn get_missing_returns_not_found(store: &impl ObjectStorage) {
    let result = store.get(Path::new("does/not/exist")).await;
    assert!(
        matches!(result, Err(ObjectStorageError::NotFound(_))),
        "get of missing key must return NotFound; got {result:?}"
    );
}

async fn put_and_get_roundtrip(store: &impl ObjectStorage) {
    let key = Path::new("contract/roundtrip");
    let data = b"hello contract";
    store.put(key, data).await.unwrap();
    let got = store.get(key).await.unwrap();
    assert_eq!(&got[..], data, "get after put must return the same bytes");
}

async fn put_overwrites_existing(store: &impl ObjectStorage) {
    let key = Path::new("contract/overwrite");
    store.put(key, b"first").await.unwrap();
    store.put(key, b"second").await.unwrap();
    let got = store.get(key).await.unwrap();
    assert_eq!(&got[..], b"second", "second put must overwrite the first");
}

/// A put that replaces an object is all-or-nothing to everyone reading: a get
/// racing it answers the old bytes or the new ones, never a part of either, and
/// a listing racing it names the object once and nothing else.
///
/// Every layer stacked on a backend assumes this — the sealed layer opens what
/// `get` answers, and the blinded layer reads every object a listing names — so
/// a backend that truncates and then writes fails a whole listing for one torn
/// object. That is how a contact who rotated would be left with no door at
/// all.
async fn a_replaced_object_is_read_whole(store: &impl ObjectStorage) {
    const BASE: usize = 64 * 1024;
    let key = Path::new("contract/replaced/object");
    let version = |i: usize| vec![(i % 251) as u8; BASE + i];
    let whole = |bytes: &[u8]| {
        bytes.len() >= BASE && bytes.iter().all(|b| *b as usize == (bytes.len() - BASE) % 251)
    };
    store.put(key, &version(0)).await.unwrap();
    let done = std::sync::atomic::AtomicBool::new(false);
    let writer = async {
        for i in 1..=64 {
            store.put(key, &version(i)).await.unwrap();
        }
        done.store(true, std::sync::atomic::Ordering::SeqCst);
    };
    let reader = async {
        let mut reads = 0u32;
        while !done.load(std::sync::atomic::Ordering::SeqCst) {
            let got = store.get(key).await.unwrap_or_else(|e| panic!("get {reads} racing a put failed: {e:?}"));
            assert!(whole(&got), "get {reads} racing a put read {} bytes of neither object", got.len());
            let keys: Vec<String> = store
                .list(Path::new("contract/replaced/"))
                .await
                .unwrap_or_else(|e| panic!("listing {reads} racing a put failed: {e:?}"))
                .into_iter()
                .filter(|m| !m.is_dir)
                .map(|m| m.key.trim_start_matches('/').to_string())
                .collect();
            assert_eq!(keys, vec!["contract/replaced/object".to_string()], "listing {reads} racing a put");
            reads += 1;
        }
    };
    tokio::join!(writer, reader);
}

async fn metadata_reflects_size(store: &impl ObjectStorage) {
    let key = Path::new("contract/meta");
    let data = b"size check";
    store.put(key, data).await.unwrap();
    let meta = store.metadata(key).await.unwrap();
    assert_eq!(
        meta.size,
        data.len() as u64,
        "metadata.size must equal the byte length of the stored object"
    );
    assert!(
        !meta.is_dir,
        "metadata.is_dir must be false for a regular object"
    );
}

async fn exists_true_after_put(store: &impl ObjectStorage) {
    let key = Path::new("contract/exists_true");
    store.put(key, b"x").await.unwrap();
    assert!(
        store.exists(key).await.unwrap(),
        "exists must return true immediately after put"
    );
}

async fn exists_false_after_delete(store: &impl ObjectStorage) {
    let key = Path::new("contract/exists_false");
    store.put(key, b"x").await.unwrap();
    store.delete(key).await.unwrap();
    assert!(
        !store.exists(key).await.unwrap(),
        "exists must return false after delete"
    );
}

async fn delete_missing_returns_not_found(store: &impl ObjectStorage) {
    let result = store.delete(Path::new("contract/no_such_key")).await;
    assert!(
        matches!(result, Err(ObjectStorageError::NotFound(_))),
        "delete of missing key must return NotFound; got {result:?}"
    );
}

async fn list_returns_objects_under_prefix(store: &impl ObjectStorage) {
    store.put(Path::new("listprefix/a"), b"1").await.unwrap();
    store.put(Path::new("listprefix/b"), b"2").await.unwrap();
    store.put(Path::new("other/c"), b"3").await.unwrap();
    let entries = store.list(Path::new("listprefix")).await.unwrap();
    assert_eq!(
        entries.len(),
        2,
        "list('listprefix') must return exactly the two objects under that prefix"
    );
}

async fn list_empty_prefix_returns_all(store: &impl ObjectStorage) {
    // We can't know the full count (prior sub-tests have added objects), so just
    // assert the list call itself succeeds and returns something.
    let entries = store.list(Path::new("")).await.unwrap();
    assert!(
        !entries.is_empty(),
        "list('') must return at least the objects inserted by prior contract steps"
    );
}

async fn list_no_match_returns_empty(store: &impl ObjectStorage) {
    let entries = store
        .list(Path::new("zzz_no_such_prefix_xyz"))
        .await
        .unwrap();
    assert!(
        entries.is_empty(),
        "list with a prefix that matches nothing must return an empty vec"
    );
}

async fn large_object_roundtrip(store: &impl ObjectStorage) {
    let key = Path::new("contract/large");
    let data: Vec<u8> = (0u32..65_536).map(|i| (i % 251) as u8).collect();
    store.put(key, &data).await.unwrap();
    let got = store.get(key).await.unwrap();
    assert_eq!(got.len(), data.len(), "large object length must match");
    assert_eq!(&got[..], &data[..], "large object content must match");
}

async fn empty_value_roundtrip(store: &impl ObjectStorage) {
    let key = Path::new("contract/empty_value");
    store.put(key, b"").await.unwrap();
    let got = store.get(key).await.unwrap();
    assert_eq!(
        &got[..],
        b"",
        "storing an empty value must round-trip to empty bytes"
    );
}
