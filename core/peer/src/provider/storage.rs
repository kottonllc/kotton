// SPDX-License-Identifier: AGPL-3.0-or-later
//! `KottonPeerObjectStorage` — ObjectStorage backed by a paired peer.
//!
//! Each method translates the `ObjectStorage` call into a `DeviceRequest`,
//! sends it to the peer via the `PeerChannel`, and translates the
//! `DeviceResponse` back into the `ObjectStorage` result type.
//!
//! The wire format is identical to the local IPC channel: JSON-encoded
//! `DeviceRequest` / `DeviceResponse` wrapped in the 4-byte-BE-length framing.
//! The peer daemon routes these through the same `UserRuntime` code path used
//! for local requests, so no new server-side logic is needed.

use crate::channel::PeerChannel;
use async_trait::async_trait;
use bytes::Bytes;
use kotton_sys::store::{
    ObjectMetadata, ObjectStorage, ObjectStorageError, ObjectStorageResult, SealedObjectAccess,
};
use kotton_wire::{
    ipc::{UserRequest, UserResponse, VaultPeerRequest},
    peer::PairedNode,
};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// KottonPeerObjectStorage
// ---------------------------------------------------------------------------

/// `ObjectStorage` implementation backed by a paired peer daemon.
///
/// Operations are forwarded over the [`PeerChannel`] as `DeviceRequest`
/// messages; responses are deserialized from `DeviceResponse`.
///
/// The peer authenticates via mutual TLS (Ed25519 identity keys) before any
/// request is processed. The `PeerChannel` is established post-mTLS.
///
/// # Mount identification
///
/// **VFS paths are resolved by the peer**, against its own `storage-mounts.toml`.
/// This side names a path and never a store, so a peer that has
/// routed `/photos` elsewhere is honoured without this end knowing.
///
/// The **sealed** view is different and keeps `remote_mount`: replication
/// addresses a specific store by design, which is why it is exempt.
/// scenarios).
pub struct KottonPeerObjectStorage {
    channel: Arc<dyn PeerChannel>,
    /// Peer node record — kept for logging; nothing reads it yet.
    #[allow(dead_code)]
    node: PairedNode,
    user_id: String,
    /// The peer's directly-dialable address as observed on *this* connection,
    /// set only when the connection was established over a direct or
    /// hole-punched path (where `remote_address()` is the peer itself, not a
    /// TURN/relay intermediary). `None` for TURN/relayed connections and by
    /// default. The daemon persists this back into `paired_nodes` so the next
    /// dial tries the live address first (see `PairedNode::addresses`).
    observed_direct_addr: Option<SocketAddr>,
    /// The relay the peer said it reserves at, asked on this connect;
    /// `None` when it did not answer. The daemon persists it.
    learned_relay: Option<String>,
    /// Hex key-domain id — a one-way fingerprint of the CEK — identifying which
    /// domain this node's sealed objects belong to.
    ///
    /// Carried on every sealed transfer so the receiver can refuse a blob it
    /// cannot open rather than storing one nobody can attribute to a key. It is
    /// a property of the *key domain* the transfer happens in, known by the
    /// runtime, not of any storage backend — which is why it lives here on the
    /// wire client and not in [`SealedObjectAccess`], whose implementors (a local
    /// directory, an in-memory map) have no notion of a CEK at all.
    ///
    /// `None` until declared: sealed replication then fails closed rather than
    /// guessing a domain.
    domain_id: Option<String>,
    /// Store on the peer that the **sealed** verbs address.
    remote_mount: String,
}

impl KottonPeerObjectStorage {
    /// Create a new instance backed by `channel`.
    ///
    /// `node` is the metadata record for the peer (for logging); `user_id` is
    /// the user account on the remote peer; `remote_mount` names the store the
    /// **sealed** verbs address there (usually [`kotton_common::LOCAL_MOUNT`]).
    /// VFS paths carry no store — the peer routes those itself.
    pub fn new(
        channel: Arc<dyn PeerChannel>,
        node: PairedNode,
        user_id: String,
        remote_mount: impl Into<String>,
    ) -> Self {
        Self {
            channel,
            node,
            user_id,
            remote_mount: remote_mount.into(),
            observed_direct_addr: None,
            learned_relay: None,
            domain_id: None,
        }
    }

    /// Declare the key domain this node's sealed objects belong to.
    ///
    /// Required before any sealed transfer; without it `get_sealed`/`put_sealed`
    /// refuse rather than move blobs whose key domain is unstated.
    #[must_use]
    pub fn with_domain_id(mut self, domain_id: String) -> Self {
        self.domain_id = Some(domain_id);
        self
    }

    /// Address another store on the peer with the **sealed** verbs — a drive a
    /// vault keeps beside the tenancy's own tree, by the tree it is kept under
    /// (`kotton_wire::ipc::MadeDrive::tree`). The VFS verbs are unchanged:
    /// they name no store.
    #[must_use]
    pub fn with_remote_mount(mut self, remote_mount: impl Into<String>) -> Self {
        self.remote_mount = remote_mount.into();
        self
    }

    /// Record the peer's directly-dialable address observed on this connection.
    ///
    /// The dialer passes `Some(addr)` only for direct / hole-punched paths, where
    /// the connection's remote address is the peer itself; `None` for TURN or
    /// relayed paths (whose remote address is infrastructure, not the peer).
    #[must_use]
    pub fn with_observed_direct_addr(mut self, addr: Option<SocketAddr>) -> Self {
        self.observed_direct_addr = addr;
        self
    }

    /// The peer's directly-dialable address observed when this connection was
    /// established, if it came up over a direct or hole-punched path. `None`
    /// otherwise. The daemon uses this to refresh `paired_nodes.addresses`.
    pub fn observed_direct_addr(&self) -> Option<SocketAddr> {
        self.observed_direct_addr
    }

    /// Record what the peer answered to `NodeRelay` on this connect.
    pub fn with_learned_relay(mut self, relay_url: Option<String>) -> Self {
        self.learned_relay = relay_url;
        self
    }

    /// The relay the peer said it reserves at on this connect, if it answered.
    pub fn learned_relay(&self) -> Option<&str> {
        self.learned_relay.as_deref()
    }

    /// Send a `DeviceRequest` to the peer and deserialize the `DeviceResponse`.
    pub async fn send(&self, req: &UserRequest) -> anyhow::Result<UserResponse> {
        self.exchange(req).await
    }

    /// Send one of a vault's own verbs — a tenant's or the landlord's — to a
    /// peer that is a vault, and deserialize its answer.
    ///
    /// The vault's peer acceptor decodes `VaultPeerRequest` and nothing else,
    /// so a verb only a vault answers is built as that type here rather than as
    /// the device's `UserRequest`. The sealed verbs the [`SealedObjectAccess`]
    /// impl sends, and the `NodeRelay` asked on connect, go through
    /// [`Self::send`]: they are said alike to a device and a vault, and both
    /// peer wires mirror the door's spelling of them.
    pub async fn send_to_vault(&self, req: &VaultPeerRequest) -> anyhow::Result<UserResponse> {
        self.exchange(req).await
    }

    /// One request and its answer. Private, so what may be sent is what the
    /// two typed doors above name.
    async fn exchange(&self, req: &impl serde::Serialize) -> anyhow::Result<UserResponse> {
        let bytes = serde_json::to_vec(req)?;
        let resp_bytes = self.channel.request(&bytes).await?;
        let resp = serde_json::from_slice::<UserResponse>(&resp_bytes)?;
        Ok(resp)
    }

    /// Convert a runtime error into an `ObjectStorageError`.
    fn io_err(msg: impl std::fmt::Display) -> ObjectStorageError {
        ObjectStorageError::BackendError(msg.to_string())
    }

    fn path_str(p: &Path) -> String {
        p.to_string_lossy().into_owned()
    }

    /// The declared key domain, or an error. Sealed replication fails closed when
    /// the domain is unstated — moving blobs nobody recorded a domain for is how a
    /// mount ends up holding objects no key can open.
    fn require_domain_id(&self) -> ObjectStorageResult<&str> {
        self.domain_id.as_deref().ok_or_else(|| {
            ObjectStorageError::BackendError(
                "sealed replication requires a declared key domain (see with_domain_id)"
                    .to_string(),
            )
        })
    }
}

// ---------------------------------------------------------------------------
// ObjectStorage impl
// ---------------------------------------------------------------------------

#[async_trait]
impl ObjectStorage for KottonPeerObjectStorage {
    async fn get(&self, key: &Path) -> ObjectStorageResult<Bytes> {
        // Fetch in sub-cap ranges and reassemble, so an object larger than the
        // frame cap can be read.
        const RANGE_LEN: u32 = 4 * 1024 * 1024;
        let path = Self::path_str(key);
        let mut out: Vec<u8> = Vec::new();
        loop {
            let req = UserRequest::ReadFile {
                user_id: self.user_id.clone(),
                path: path.clone(),
                offset: out.len() as u64,
                length: RANGE_LEN,
            };
            match self.send(&req).await.map_err(Self::io_err)? {
                UserResponse::FileData { data, total_size } => {
                    let advanced = !data.is_empty();
                    out.extend_from_slice(&data);
                    if out.len() as u64 >= total_size {
                        return Ok(Bytes::from(out));
                    }
                    if !advanced {
                        return Err(ObjectStorageError::BackendError(format!(
                            "peer stalled at {} of {total_size} bytes for {path}",
                            out.len()
                        )));
                    }
                }
                UserResponse::Error { message } => {
                    return if message.to_lowercase().contains("not found") {
                        Err(ObjectStorageError::NotFound(path))
                    } else {
                        Err(ObjectStorageError::BackendError(message))
                    };
                }
                other => {
                    return Err(ObjectStorageError::BackendError(format!(
                        "unexpected peer response: {other:?}"
                    )))
                }
            }
        }
    }

    async fn put(&self, key: &Path, data: &[u8]) -> ObjectStorageResult<()> {
        // Send in sub-cap chunks the peer reassembles.
        const CHUNK: usize = 4 * 1024 * 1024;
        let path = Self::path_str(key);
        let total_size = data.len() as u64;
        let content_hash = blake3::hash(data).to_hex().to_string();
        let mut offset = 0usize;
        loop {
            let end = (offset + CHUNK).min(data.len());
            let req = UserRequest::WriteFile {
                user_id: self.user_id.clone(),
                path: path.clone(),
                data: data[offset..end].to_vec(),
                offset: offset as u64,
                total_size,
                content_hash: content_hash.clone(),
            };
            match self.send(&req).await.map_err(Self::io_err)? {
                UserResponse::Ok => {}
                UserResponse::Error { message } => {
                    return Err(ObjectStorageError::BackendError(message))
                }
                other => {
                    return Err(ObjectStorageError::BackendError(format!(
                        "unexpected peer response: {other:?}"
                    )))
                }
            }
            offset = end;
            if offset >= data.len() {
                return Ok(());
            }
        }
    }

    async fn delete(&self, key: &Path) -> ObjectStorageResult<()> {
        let req = UserRequest::DeleteFile {
            user_id: self.user_id.clone(),
            path: Self::path_str(key),
        };
        match self.send(&req).await.map_err(Self::io_err)? {
            UserResponse::Ok => Ok(()),
            UserResponse::Error { message } => {
                if message.to_lowercase().contains("not found") {
                    Err(ObjectStorageError::NotFound(Self::path_str(key)))
                } else {
                    Err(ObjectStorageError::BackendError(message))
                }
            }
            other => Err(ObjectStorageError::BackendError(format!(
                "unexpected peer response: {other:?}"
            ))),
        }
    }

    async fn list(&self, prefix: &Path) -> ObjectStorageResult<Vec<ObjectMetadata>> {
        let req = UserRequest::ListFiles {
            user_id: self.user_id.clone(),
            prefix: Self::path_str(prefix),
        };
        match self.send(&req).await.map_err(Self::io_err)? {
            UserResponse::FileList { files } => Ok(files
                .into_iter()
                .map(|f| ObjectMetadata {
                    key: f,
                    is_dir: false,
                    size: 0, // size unknown from list; use metadata() for exact size
                    modified: None,
                })
                .collect()),
            UserResponse::Error { message } => Err(ObjectStorageError::BackendError(message)),
            other => Err(ObjectStorageError::BackendError(format!(
                "unexpected peer response: {other:?}"
            ))),
        }
    }

    async fn metadata(&self, key: &Path) -> ObjectStorageResult<ObjectMetadata> {
        // The current IPC protocol does not have a dedicated metadata call.
        // Approximate: attempt a read and return metadata if successful.
        // TODO: add HeadFile IPC variant for efficient metadata.
        match self.get(key).await {
            Ok(data) => Ok(ObjectMetadata {
                key: Self::path_str(key),
                is_dir: false,
                size: data.len() as u64,
                modified: None,
            }),
            Err(ObjectStorageError::NotFound(_)) => {
                Err(ObjectStorageError::NotFound(Self::path_str(key)))
            }
            Err(e) => Err(e),
        }
    }

    fn backend_name(&self) -> &str {
        "peer"
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Sealed access over the peer link uses the dedicated replication verbs, not the
/// VFS ones.
///
/// This is why sealed replication needs wire operations of its own: `ObjectStorage::get`
/// here sends `ReadFile`, which the peer answers by running its *own* storage
/// stack — decrypting on read and re-sealing on write. Routing sealed transfers
/// through those verbs would hand the envelope to a peer that seals it a second
/// time, and would have moved plaintext across the link in the other direction.
/// `ReadSealed`/`WriteSealed` bind to the peer's sealed view instead, so neither
/// end materialises plaintext and a keyless peer receives bytes it cannot open.
#[async_trait]
impl SealedObjectAccess for KottonPeerObjectStorage {
    async fn get_sealed(&self, key: &Path) -> ObjectStorageResult<Bytes> {
        let domain = self.require_domain_id()?;
        let path = Self::path_str(key);

        // Fetch the sealed object as a sequence of sub-cap ranges. A pack is a
        // fixed 16 MiB, larger than the peer channel's 10 MiB
        // response cap, so a single oversized response is impossible; base64 on
        // the wire keeps a 4 MiB range comfortably under the cap. The response
        // carries `total_size`, so the reader knows when it has the whole object.
        const RANGE_LEN: u32 = 4 * 1024 * 1024;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let req = UserRequest::ReadSealed {
                user_id: self.user_id.clone(),
                mount: self.remote_mount.clone(),
                path: path.clone(),
                offset: out.len() as u64,
                length: RANGE_LEN,
            };
            match self.send(&req).await.map_err(Self::io_err)? {
                UserResponse::SealedObject {
                    blob,
                    domain_id,
                    total_size,
                } => {
                    // Pulling a blob from a key domain we cannot open would store
                    // something unreadable; refuse at the boundary instead.
                    if domain_id != domain {
                        return Err(ObjectStorageError::BackendError(format!(
                            "peer object at {path} belongs to key domain {domain_id}, this node \
                             holds {domain}"
                        )));
                    }
                    let advanced = !blob.is_empty();
                    out.extend_from_slice(&blob);
                    if out.len() as u64 >= total_size {
                        return Ok(Bytes::from(out));
                    }
                    // A peer that returns an empty range before the end is
                    // under-reporting; refuse rather than spin forever.
                    if !advanced {
                        return Err(ObjectStorageError::BackendError(format!(
                            "peer stalled at {} of {total_size} bytes for {path}",
                            out.len()
                        )));
                    }
                }
                UserResponse::Error { message } => {
                    return if message.to_lowercase().contains("not found") {
                        Err(ObjectStorageError::NotFound(path))
                    } else {
                        Err(ObjectStorageError::BackendError(message))
                    };
                }
                other => {
                    return Err(ObjectStorageError::BackendError(format!(
                        "unexpected peer response: {other:?}"
                    )))
                }
            }
        }
    }

    /// One round trip returns every leaf under `prefix`: the serving side walks
    /// its directory tree before answering (`UserRuntime::list_sealed`), because
    /// `SealedListEntry` carries no `is_dir` for this side to recurse on. That
    /// contract is what makes `is_dir: false` below correct rather than a guess.
    async fn list_sealed(&self, prefix: &Path) -> ObjectStorageResult<Vec<ObjectMetadata>> {
        let req = UserRequest::ListSealed {
            user_id: self.user_id.clone(),
            mount: self.remote_mount.clone(),
            prefix: Self::path_str(prefix),
        };
        match self.send(&req).await.map_err(Self::io_err)? {
            UserResponse::SealedList { entries } => Ok(entries
                .into_iter()
                .map(|e| ObjectMetadata {
                    key: e.key,
                    is_dir: false,
                    size: e.size,
                    modified: e.modified,
                })
                .collect()),
            UserResponse::Error { message } => Err(ObjectStorageError::BackendError(message)),
            other => Err(ObjectStorageError::BackendError(format!(
                "unexpected peer response: {other:?}"
            ))),
        }
    }

    async fn put_sealed(&self, key: &Path, blob: &[u8]) -> ObjectStorageResult<()> {
        let domain = self.require_domain_id()?.to_string();
        let path = Self::path_str(key);

        // Send the sealed object as a run of sub-cap chunks: a pack is
        // 16 MiB, over the peer frame cap, so one `WriteSealed` per object is
        // impossible. `content_hash` is the whole object's BLAKE3 — it keys the
        // receiver's reassembly buffer and gates the commit against corruption.
        const CHUNK: usize = 4 * 1024 * 1024;
        let total_size = blob.len() as u64;
        let content_hash = blake3::hash(blob).to_hex().to_string();

        let mut offset: usize = 0;
        loop {
            let end = (offset + CHUNK).min(blob.len());
            let req = UserRequest::WriteSealed {
                user_id: self.user_id.clone(),
                mount: self.remote_mount.clone(),
                path: path.clone(),
                blob: blob[offset..end].to_vec(),
                domain_id: domain.clone(),
                offset: offset as u64,
                total_size,
                content_hash: content_hash.clone(),
            };
            match self.send(&req).await.map_err(Self::io_err)? {
                UserResponse::Ok => {}
                UserResponse::SealedDomainMismatch { expected, got } => {
                    return Err(ObjectStorageError::BackendError(format!(
                        "peer refused sealed write at {path}: it holds key domain {expected}, we \
                         sent {got}"
                    )));
                }
                UserResponse::Error { message } => {
                    return Err(ObjectStorageError::BackendError(message))
                }
                other => {
                    return Err(ObjectStorageError::BackendError(format!(
                        "unexpected peer response: {other:?}"
                    )))
                }
            }
            offset = end;
            // A zero-length object still sends one chunk (offset 0); otherwise
            // stop once the last byte has gone.
            if offset >= blob.len() {
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::mock::MockPeerChannel;
    use kotton_wire::did::Did;
    use kotton_wire::peer::PairedNode;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn make_node() -> PairedNode {
        PairedNode {
            id: "test-peer".to_string(),
            device_did: Did::new("key", "z6MkTest"),
            public_key: [0u8; 32],
            paired_at: 0,
            addresses: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000)],
            relay_url: None,
            posture: None,
        }
    }

    fn mock_response(resp: &UserResponse) -> Vec<u8> {
        serde_json::to_vec(resp).unwrap()
    }

    fn make_storage(channel: Arc<dyn PeerChannel>) -> KottonPeerObjectStorage {
        KottonPeerObjectStorage::new(channel, make_node(), "alice".to_string(), "local")
    }

    // -- get ------------------------------------------------------------------

    #[tokio::test]
    async fn get_returns_file_data() {
        let resp = mock_response(&UserResponse::FileData {
            data: b"hello world".to_vec(),
            total_size: b"hello world".len() as u64,
        });
        let ch = Arc::new(MockPeerChannel::new(vec![resp]));
        let storage = make_storage(ch);

        let data = storage.get(Path::new("/notes/a.md")).await.unwrap();
        assert_eq!(data.as_ref(), b"hello world");
    }

    #[tokio::test]
    async fn get_not_found_maps_to_not_found_error() {
        let resp = mock_response(&UserResponse::Error {
            message: "file not found".to_string(),
        });
        let ch = Arc::new(MockPeerChannel::new(vec![resp]));
        let storage = make_storage(ch);

        let err = storage.get(Path::new("/missing.txt")).await.unwrap_err();
        assert!(
            matches!(err, ObjectStorageError::NotFound(_)),
            "expected NotFound, got {err:?}"
        );
    }

    // -- put ------------------------------------------------------------------

    #[tokio::test]
    async fn put_sends_write_file_request() {
        let resp = mock_response(&UserResponse::Ok);
        let ch = Arc::new(MockPeerChannel::new(vec![resp]));
        let storage = make_storage(ch.clone());

        storage
            .put(Path::new("/notes/a.md"), b"content")
            .await
            .unwrap();

        let sent = ch.take_received();
        let req: UserRequest = serde_json::from_slice(&sent[0]).unwrap();
        assert!(matches!(req, UserRequest::WriteFile { path, .. } if path == "/notes/a.md"));
    }

    // -- delete ---------------------------------------------------------------

    #[tokio::test]
    async fn delete_sends_delete_file_request() {
        let resp = mock_response(&UserResponse::Ok);
        let ch = Arc::new(MockPeerChannel::new(vec![resp]));
        let storage = make_storage(ch.clone());

        storage.delete(Path::new("/notes/a.md")).await.unwrap();

        let sent = ch.take_received();
        let req: UserRequest = serde_json::from_slice(&sent[0]).unwrap();
        assert!(matches!(req, UserRequest::DeleteFile { path, .. } if path == "/notes/a.md"));
    }

    // -- list -----------------------------------------------------------------

    #[tokio::test]
    async fn list_returns_metadata_entries() {
        let resp = mock_response(&UserResponse::FileList {
            files: vec!["/notes/a.md".to_string(), "/notes/b.md".to_string()],
        });
        let ch = Arc::new(MockPeerChannel::new(vec![resp]));
        let storage = make_storage(ch);

        let entries = storage.list(Path::new("/notes")).await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "/notes/a.md");
    }

    // -- a peer mounted in the person's tree ----------------------------------

    /// **A peer mount is handed the person's path, not the rooted key**, so it
    /// never roots a path twice.
    ///
    /// A peer is a door onto the person's tree of its own: its `WriteFile`
    /// handler roots the path it is given under `PERSON_TREE_ROOT`, exactly as
    /// this node's does. So the store routing `/shared` to it must send
    /// `/shared/x` — sending the key `files/shared/x` put the file at
    /// `/files/shared/x` in the peer's tree, a path nobody named. The read, the
    /// listing and the delete go the same way, and the listing answers in the
    /// person's paths.
    #[tokio::test]
    async fn a_peer_mount_is_sent_the_persons_path_not_the_rooted_key() {
        use kotton_crypto::derive_cek;
        use kotton_store::runtime::{user::UserStore, StorageMountEntry, StorageMountsFile, UserKeys};

        let temp = tempfile::TempDir::new().unwrap();
        let store = UserStore::create(
            "alice",
            "did:key:zAlice",
            temp.path().to_path_buf(),
            UserKeys::new(Some(derive_cek(&[7u8; 32]))),
            &kotton_store::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();

        let ch = Arc::new(MockPeerChannel::new(vec![
            mock_response(&UserResponse::Ok),
            mock_response(&UserResponse::FileData {
                data: b"through the peer".to_vec(),
                total_size: 16,
            }),
            // What the far side's `list_files` answers: the person's paths,
            // its own root already taken off.
            mock_response(&UserResponse::FileList {
                files: vec!["shared/x".to_string()],
            }),
            mock_response(&UserResponse::Ok),
        ]));
        store
            .add_remote(
                "phone".to_string(),
                Arc::new(make_storage(ch.clone())),
                kotton_wire::remote::RemoteConfig {
                    backend: kotton_wire::remote::RemoteBackend::Kotton {
                        peer_did: "did:key:z6MkTest".to_string(),
                        label: "phone".to_string(),
                    },
                    cache_dir: None,
                    key_format: kotton_wire::remote::KeyFormat::default(),
                },
            )
            .unwrap();
        StorageMountsFile {
            mounts: vec![StorageMountEntry {
                path: "/shared".to_string(),
                remote: "phone".to_string(),
            }],
        }
        .save(temp.path())
        .unwrap();
        store.invalidate_mount_router();

        let sent = |ch: &MockPeerChannel| -> UserRequest {
            let got = ch.take_received();
            assert_eq!(got.len(), 1, "one request per call");
            serde_json::from_slice(&got[0]).unwrap()
        };

        store.write_file("/shared/x", b"through the peer").await.unwrap();
        let req = sent(&ch);
        assert!(
            matches!(&req, UserRequest::WriteFile { path, .. } if path == "/shared/x"),
            "the WriteFile a peer mount sends names the person's path: {req:?}"
        );

        assert_eq!(store.read_file("/shared/x").await.unwrap(), b"through the peer");
        let req = sent(&ch);
        assert!(matches!(&req, UserRequest::ReadFile { path, .. } if path == "/shared/x"), "{req:?}");

        assert_eq!(store.list_files("/shared").await.unwrap(), vec!["shared/x".to_string()]);
        let req = sent(&ch);
        assert!(matches!(&req, UserRequest::ListFiles { prefix, .. } if prefix == "/shared"), "{req:?}");

        store.delete_file("/shared/x").await.unwrap();
        let req = sent(&ch);
        assert!(matches!(&req, UserRequest::DeleteFile { path, .. } if path == "/shared/x"), "{req:?}");
    }

    // -- backend_name ---------------------------------------------------------

    #[test]
    fn backend_name_is_peer() {
        let ch = Arc::new(MockPeerChannel::new(vec![]));
        let storage = make_storage(ch);
        assert_eq!(storage.backend_name(), "peer");
    }
}
