// SPDX-License-Identifier: AGPL-3.0-or-later
//! Per-object DEK envelope encryption for any `ObjectStorage` backend.
//!
//! `EncryptedObjectStorage<S>` wraps an inner storage backend. Every object is
//! encrypted with a fresh random per-object DEK; the DEK is wrapped with the
//! user's CEK (AES-256-KW, RFC 3394) and stored in the blob header.
//!
//! ## Wire format
//!
//! ```text
//! [ wrapped_dek: 40 bytes  ]   AES-256-KW(CEK, DEK) — 32-byte DEK + 8-byte integrity
//! [ nonce:       12 bytes  ]   random, generated fresh on every put
//! [ ciphertext + tag       ]   ChaCha20-Poly1305(DEK, nonce, plaintext)
//! ```
//!
//! The per-object DEK means that a guest with access to specific paths can be
//! given only the DEKs for those paths, re-wrapped to a guest session key
//! (`GuestAccessToken.wrapped_deks`), without receiving the master CEK.
//!
//! `list`, `metadata`, `delete`, and `exists` are pass-through — object keys
//! and metadata are not encrypted.

use aes_kw::KekAes256;
use async_trait::async_trait;
use bytes::Bytes;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use kotton_sys::store::{
    ObjectMetadata, ObjectStorage, ObjectStorageError, ObjectStorageResult, SealedObjectAccess,
};
use rand::RngCore as _;
use std::path::Path;
use std::sync::Arc;

/// AES-256-KW output size: 32-byte DEK + 8-byte integrity check word.
const WRAPPED_DEK_LEN: usize = 40;
/// ChaCha20-Poly1305 nonce length.
const NONCE_LEN: usize = 12;
/// Minimum blob size: wrapped DEK header + nonce.
const HEADER_LEN: usize = WRAPPED_DEK_LEN + NONCE_LEN;

/// Canonical AEAD additional-authenticated-data binding a ciphertext to its
/// object path. Bound on both seal and open so an untrusted provider cannot
/// relocate a blob to a different path and have it decrypt (the swap half of
/// H5).
///
/// The form is **canonical** — `\` → `/`, leading/duplicate slashes stripped,
/// and `.`/`..` collapsed (matching `to_object_key`) — so the sealer (which
/// holds an object-storage key like `notes/x`) and a DEK-holding guest (which
/// may hold the VFS path `/notes/x`) derive identical AAD for the same object.
/// `pub` so guest-side decryption can reconstruct it.
///
/// Authenticates the *path*, not freshness: rollback to a stale version at the
/// *same* path is not covered — that needs a version/epoch in the AAD plus a
/// client freshness expectation, which the stateless `ObjectStorage` interface
/// does not yet carry (tracked as an H5 follow-up).
pub fn path_aad(key: &Path) -> Vec<u8> {
    let unix = key.to_string_lossy().replace('\\', "/");
    let mut parts: Vec<&str> = Vec::new();
    for seg in unix.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    parts.join("/").into_bytes()
}

/// Seal one plaintext into the envelope this module defines, under `cek`.
///
/// The format is the one documented at the top of this file and nothing beside
/// it: a fresh per-object DEK wrapped with the CEK, a fresh nonce, and
/// ChaCha20-Poly1305 over the plaintext with `aad` bound. [`EncryptedObjectStorage::put`]
/// is this function plus a write, and says so by calling it.
///
/// **Free, so that a byte sequence that is not an object can be sealed the same
/// way.** The roots index's meaning half is the case that asks for it: a
/// small file in the
/// core root's tree, read before any store stack is assembled and written by a
/// synchronous call, which cannot go through an `async` `ObjectStorage` and must
/// not therefore get a second envelope format of its own. A second format is a
/// second thing to get wrong, and the first one anybody would forget to bind an
/// AAD in.
///
/// `aad` is the caller's to choose and is authenticated, not encrypted. For an
/// object it is [`path_aad`] of the object key; for a file it is [`path_aad`] of
/// the path the file is written at, which is what stops a blob being moved to
/// another name and opening there (H5).
pub fn seal_envelope(cek: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> ObjectStorageResult<Vec<u8>> {
    let mut dek = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut dek);

    let mut wrapped_dek = [0u8; WRAPPED_DEK_LEN];
    KekAes256::from(*cek)
        .wrap(&dek, &mut wrapped_dek)
        .map_err(|_| ObjectStorageError::BackendError("DEK wrap failed".into()))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let cipher = ChaCha20Poly1305::new(&dek.into());
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| ObjectStorageError::BackendError("encryption failed".into()))?;

    let mut blob = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    blob.extend_from_slice(&wrapped_dek);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Open an envelope [`seal_envelope`] wrote, under `cek` and the same `aad`.
///
/// A wrong key, a wrong AAD, a tampered byte and a truncated blob are all one
/// answer — an error — because telling them apart is telling an attacker which
/// of their guesses was closer.
pub fn open_envelope(cek: &[u8; 32], aad: &[u8], blob: &[u8]) -> ObjectStorageResult<Vec<u8>> {
    if blob.len() < HEADER_LEN {
        return Err(ObjectStorageError::BackendError(
            "sealed blob too short to contain its header".into(),
        ));
    }
    let wrapped_dek: [u8; WRAPPED_DEK_LEN] = blob[..WRAPPED_DEK_LEN].try_into().unwrap();
    let nonce_bytes = &blob[WRAPPED_DEK_LEN..HEADER_LEN];
    let ciphertext = &blob[HEADER_LEN..];

    let mut dek = [0u8; 32];
    KekAes256::from(*cek)
        .unwrap(&wrapped_dek, &mut dek)
        .map_err(|_| ObjectStorageError::BackendError("DEK unwrap failed".into()))?;

    let cipher = ChaCha20Poly1305::new(&dek.into());
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| ObjectStorageError::BackendError("decryption failed".into()))
}

/// `ObjectStorage` wrapper with per-object DEK envelope encryption.
///
/// # Example
///
/// ```rust,ignore
/// let inner = MemoryObjectStorage::new();
/// let cek: [u8; 32] = derive_cek_from_identity(...);
/// let enc = EncryptedObjectStorage::new(inner, cek);
/// enc.put(Path::new("notes/hello.txt"), b"secret").await?;
/// let plaintext = enc.get(Path::new("notes/hello.txt")).await?;
/// let dek = enc.get_dek_for_path(Path::new("notes/hello.txt")).await?;
/// ```
pub struct EncryptedObjectStorage<S: ObjectStorage> {
    inner: Arc<S>,
    kek: KekAes256,
    cek: [u8; 32],
}

impl<S: ObjectStorage + 'static> EncryptedObjectStorage<S> {
    /// Wrap `inner` with per-object DEK encryption using the given 32-byte CEK.
    pub fn new(inner: S, cek: [u8; 32]) -> Self {
        Self {
            inner: Arc::new(inner),
            kek: KekAes256::from(cek),
            cek,
        }
    }

    /// Return the plaintext DEK for an existing object.
    ///
    /// Reads only the 40-byte wrapped DEK header from the stored blob,
    /// unwraps it with the CEK, and returns the 32-byte DEK.  The caller
    /// can re-wrap this DEK with a guest session key to populate
    /// `GuestAccessToken.wrapped_deks`.
    ///
    /// **Contract:** the object's ciphertext is sealed with its key bound as
    /// AEAD AAD (see [`path_aad`] — H5). A consumer decrypting with this DEK
    /// **must** supply the same AAD (the canonical, forward-slash object key),
    /// or the open will fail. The guest holds the path (it keys `wrapped_deks`),
    /// so it can reconstruct the AAD.
    pub async fn get_dek_for_path(&self, key: &Path) -> ObjectStorageResult<[u8; 32]> {
        let raw = self.inner.get(key).await?;
        if raw.len() < HEADER_LEN {
            return Err(ObjectStorageError::BackendError(format!(
                "blob too short to contain DEK header for key {}",
                key.display()
            )));
        }
        let wrapped_dek: [u8; WRAPPED_DEK_LEN] = raw[..WRAPPED_DEK_LEN].try_into().unwrap();
        let mut dek = [0u8; 32];
        self.kek
            .unwrap(&wrapped_dek, &mut dek)
            .map_err(|_| ObjectStorageError::BackendError("DEK unwrap failed".into()))?;
        Ok(dek)
    }

    /// Expose the raw CEK so callers can derive guest session keys via ECDH.
    ///
    /// Only used by `pair_node_ephemeral` to wrap per-path DEKs for guests.
    pub fn cek(&self) -> [u8; 32] {
        self.cek
    }
}

#[async_trait]
impl<S: ObjectStorage + 'static> ObjectStorage for EncryptedObjectStorage<S> {
    async fn get(&self, key: &Path) -> ObjectStorageResult<Bytes> {
        let raw = self.inner.get(key).await?;
        // Bind the object key as AAD: a ciphertext sealed for one path will fail
        // to open at another, so an untrusted provider cannot relocate blobs (H5).
        let plaintext = open_envelope(&self.cek, &path_aad(key), &raw).map_err(|e| match e {
            // The short-blob case is the one worth naming the key in: it is a
            // corrupt or truncated object rather than a wrong key, and the
            // message is what a person reads when one turns up.
            ObjectStorageError::BackendError(m) if m.contains("too short") => {
                ObjectStorageError::BackendError(format!(
                    "encrypted blob too short for key {}",
                    key.display()
                ))
            }
            other => other,
        })?;
        Ok(Bytes::from(plaintext))
    }

    async fn put(&self, key: &Path, data: &[u8]) -> ObjectStorageResult<()> {
        // Bind the object key as AAD so the ciphertext authenticates its path (H5).
        let blob = seal_envelope(&self.cek, &path_aad(key), data)?;
        self.inner.put(key, &blob).await
    }

    async fn delete(&self, key: &Path) -> ObjectStorageResult<()> {
        self.inner.delete(key).await
    }

    async fn list(&self, prefix: &Path) -> ObjectStorageResult<Vec<ObjectMetadata>> {
        self.inner.list(prefix).await
    }

    async fn metadata(&self, key: &Path) -> ObjectStorageResult<ObjectMetadata> {
        let mut meta = self.inner.metadata(key).await?;
        // Report the plaintext size by subtracting the per-blob overhead:
        // 40-byte wrapped DEK + 12-byte nonce + 16-byte AEAD tag.
        const OVERHEAD: u64 = (HEADER_LEN + 16) as u64;
        meta.size = meta.size.saturating_sub(OVERHEAD);
        Ok(meta)
    }

    fn backend_name(&self) -> &str {
        "encrypted"
    }
}

/// The sealed view of an encrypting store is the **envelope it writes to its
/// inner backend** — `[wrapped_dek][nonce][ciphertext+tag]` — read and written
/// without touching the CEK.
///
/// This is the load-bearing implementation for sealed replication: replication reads
/// here instead of through [`ObjectStorage::get`], so a sync pass never
/// materialises plaintext and a peer without the CEK receives bytes it cannot
/// open.
///
/// Note it delegates to `inner.get`/`inner.put`, *not* to the inner store's own
/// sealed view: this layer's sealed representation is precisely what it hands
/// down to the layer below, which is that layer's ordinary content.
///
/// The [`path_aad`] binding survives replication intact. A blob is sealed
/// against its canonical key, so copying it verbatim to the same key on another
/// node still opens, while a node that relocates a blob to a different key
/// produces one that no longer decrypts — the H5 anti-relocation property now
/// also defends against a malicious replica.
#[async_trait]
impl<S: ObjectStorage + 'static> SealedObjectAccess for EncryptedObjectStorage<S> {
    async fn get_sealed(&self, key: &Path) -> ObjectStorageResult<Bytes> {
        self.inner.get(key).await
    }

    async fn put_sealed(&self, key: &Path, blob: &[u8]) -> ObjectStorageResult<()> {
        self.inner.put(key, blob).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts;
    use crate::memory::MemoryObjectStorage;

    const TEST_CEK: [u8; 32] = [0x42; 32];

    fn enc() -> EncryptedObjectStorage<MemoryObjectStorage> {
        EncryptedObjectStorage::new(MemoryObjectStorage::new(), TEST_CEK)
    }

    /// The sealed view never yields plaintext — the property replication depends
    /// on. `get` decrypts; `get_sealed` must not.
    #[tokio::test]
    async fn sealed_view_is_ciphertext_not_plaintext() {
        let store = enc();
        let key = Path::new("notes/secret.txt");
        let plaintext = b"attack at dawn";

        store.put(key, plaintext).await.unwrap();

        assert_eq!(store.get(key).await.unwrap().as_ref(), plaintext);

        let sealed = store.get_sealed(key).await.unwrap();
        assert_ne!(sealed.as_ref(), plaintext);
        assert!(
            !sealed.windows(plaintext.len()).any(|w| w == plaintext),
            "plaintext must not appear anywhere in the sealed blob"
        );
        assert!(
            sealed.len() > HEADER_LEN,
            "sealed blob carries the envelope header"
        );
    }

    /// A blob copied verbatim between two stores in the same key domain stays
    /// readable — replication moves sealed bytes without either side decrypting.
    #[tokio::test]
    async fn sealed_blob_transfers_verbatim_between_stores() {
        let source = enc();
        let dest = enc();
        let key = Path::new("notes/secret.txt");
        let plaintext = b"attack at dawn";

        source.put(key, plaintext).await.unwrap();

        // The transfer: no decrypt on read, no encrypt on write.
        let sealed = source.get_sealed(key).await.unwrap();
        dest.put_sealed(key, &sealed).await.unwrap();

        assert_eq!(dest.get(key).await.unwrap().as_ref(), plaintext);
    }

    /// A store in a different key domain receives the blob but cannot open it —
    /// the guarantee a `BlindStorage` relies on.
    #[tokio::test]
    async fn transferred_blob_is_opaque_without_the_cek() {
        let source = enc();
        let stranger = EncryptedObjectStorage::new(MemoryObjectStorage::new(), [0x99; 32]);
        let key = Path::new("notes/secret.txt");

        source.put(key, b"attack at dawn").await.unwrap();
        let sealed = source.get_sealed(key).await.unwrap();
        stranger.put_sealed(key, &sealed).await.unwrap();

        assert!(stranger.get(key).await.is_err());
    }

    #[tokio::test]
    async fn roundtrip_basic() {
        let store = enc();
        let key = Path::new("hello.txt");
        store.put(key, b"plaintext").await.unwrap();
        let got = store.get(key).await.unwrap();
        assert_eq!(&got[..], b"plaintext");
    }

    #[tokio::test]
    async fn raw_bytes_differ_from_plaintext() {
        let store = enc();
        let key = Path::new("secret");
        store.put(key, b"sensitive data").await.unwrap();
        let raw = store.inner.get(key).await.unwrap();
        // The ciphertext portion (after the header) must not equal the plaintext.
        assert_ne!(&raw[HEADER_LEN..raw.len() - 16], b"sensitive data");
    }

    #[tokio::test]
    async fn two_writes_produce_different_ciphertexts() {
        let store = enc();
        let key1 = Path::new("a");
        let key2 = Path::new("b");
        store.put(key1, b"same plaintext").await.unwrap();
        store.put(key2, b"same plaintext").await.unwrap();
        let raw1 = store.inner.get(key1).await.unwrap();
        let raw2 = store.inner.get(key2).await.unwrap();
        // Different DEKs + nonces → different blobs even for identical plaintext.
        assert_ne!(raw1, raw2);
    }

    #[tokio::test]
    async fn wrong_key_fails_decryption() {
        let store = enc();
        let key = Path::new("data");
        store.put(key, b"secret").await.unwrap();
        let raw = store.inner.get(key).await.unwrap();
        // Same blob, different CEK → DEK unwrap fails.
        let wrong_store = EncryptedObjectStorage::new(MemoryObjectStorage::new(), [0x00; 32]);
        wrong_store.inner.put(key, &raw).await.unwrap();
        assert!(wrong_store.get(key).await.is_err());
    }

    #[tokio::test]
    async fn relocated_blob_fails_to_decrypt() {
        // H5: an untrusted provider must not be able to move a ciphertext to a
        // different path and have the client accept it. The object key is bound
        // as AEAD AAD, so a blob only opens at the path it was sealed for — even
        // though the DEK (wrapped in the blob) is otherwise valid.
        let store = enc();
        let src = Path::new("notes/private.txt");
        let dst = Path::new("shared/leak.txt");
        store.put(src, b"secret").await.unwrap();

        // Provider relocates the raw blob from src to dst.
        let raw = store.inner.get(src).await.unwrap();
        store.inner.put(dst, &raw).await.unwrap();

        // Reading dst must fail (AAD = dst ≠ src).
        assert!(
            store.get(dst).await.is_err(),
            "a blob sealed for {src:?} must not decrypt at {dst:?}"
        );
        // The original path still reads fine.
        assert_eq!(&store.get(src).await.unwrap()[..], b"secret");
    }

    #[tokio::test]
    async fn get_dek_for_path_returns_correct_dek() {
        let store = enc();
        let key = Path::new("notes/doc.md");
        store.put(key, b"hello").await.unwrap();

        let dek = store.get_dek_for_path(key).await.unwrap();

        // The returned DEK must decrypt the stored ciphertext correctly — with
        // the object key bound as AAD (the seal binds it too — H5).
        let raw = store.inner.get(key).await.unwrap();
        let nonce_bytes = &raw[WRAPPED_DEK_LEN..HEADER_LEN];
        let ciphertext = &raw[HEADER_LEN..];
        let cipher = ChaCha20Poly1305::new(&dek.into());
        let aad = path_aad(key);
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(nonce_bytes),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(plaintext, b"hello");
    }

    #[tokio::test]
    async fn delete_removes_object() {
        let store = enc();
        let key = Path::new("to_delete");
        store.put(key, b"bye").await.unwrap();
        store.delete(key).await.unwrap();
        assert!(matches!(
            store.get(key).await,
            Err(ObjectStorageError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn list_returns_keys() {
        let store = enc();
        store.put(Path::new("dir/a"), b"1").await.unwrap();
        store.put(Path::new("dir/b"), b"2").await.unwrap();
        let entries = store.list(Path::new("dir")).await.unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[tokio::test]
    async fn empty_plaintext_roundtrips() {
        let store = enc();
        let key = Path::new("empty");
        store.put(key, b"").await.unwrap();
        let got = store.get(key).await.unwrap();
        assert_eq!(&got[..], b"");
    }

    #[tokio::test]
    async fn truncated_blob_returns_error() {
        let store = enc();
        let key = Path::new("truncated");
        store.inner.put(key, &[0u8; 5]).await.unwrap();
        assert!(matches!(
            store.get(key).await,
            Err(ObjectStorageError::BackendError(_))
        ));
    }

    #[tokio::test]
    async fn satisfies_object_storage_contract() {
        contracts::run_all(enc()).await;
    }
}
