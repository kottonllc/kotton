// SPDX-License-Identifier: AGPL-3.0-or-later
//! File operations, remote storage management, and sync IPC handlers.

use kotton_peer::daemon::db as network_db;
use kotton_wire::ipc::SyncDirection;
use kotton_wire::remote::{RemoteBackend, RemoteConfig};
use kotton_diag::service::{Event, EventCategory, EventLevel, EventScope};
use serde_json::{json, Value as JsonValue};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use kotton_wire::ipc::UserResponse;

// ---------------------------------------------------------------------------
// What these handlers need from the node
// ---------------------------------------------------------------------------

/// The whole of what the file and mount handlers ask of the machine.
///
/// Enumerated rather than assumed: every `runtime.*` call in this file was
/// counted, and it is four things — an event bus, two uses of the keychain, the
/// node's key domain for a user, and dialing a peer for its store.
///
/// **The keychain is not handed over, and that is the point.** `&dyn
/// SecretsStore` would have been two fewer methods and would let these handlers
/// read *any* secret, identity signing keys included. The four named operations
/// below are what they actually do: pin and read a mount's key domain,
/// and hold a remote's credentials. A capability named for its
/// purpose can be audited; a provider handed over cannot.
///
/// This is the [`kotton_peer::membership::MemberStore`] inversion — domain logic naming what it needs, not who supplies it — applied
/// where it narrows a reach rather than merely relocating one.
#[async_trait::async_trait]
pub trait FileHost: Send + Sync {
    /// Where file and mount events are published.
    fn events(&self) -> &Arc<kotton_diag::service::EventBus>;

    /// The key domain a blind mount was pinned to by its first sealed write:
    /// `Ok(None)` when it has none, and an error when the store could not say.
    ///
    /// Three answers, not two. An `Option` had no way to say *could not read*,
    /// so both hosts flattened a store's error into *not pinned*, and the next
    /// sealed write pinned the mount to its own domain over the one it had.
    fn mount_domain(&self, user_id: &str, mount: &str) -> io::Result<Option<String>>;

    /// Record the domain a mount's objects are sealed in, on that first write.
    fn pin_mount_domain(&self, user_id: &str, mount: &str, domain: &str) -> io::Result<()>;

    /// Which key domain this node treats as authoritative for a user.
    ///
    /// Takes the store rather than the runtime because that is all it reads —
    /// the key the user's objects actually seal under. The live store is
    /// authoritative over the keychain, which is the invariant `user_cek_domain_id`
    /// exists to hold.
    fn cek_domain_id(
        &self,
        user_id: &str,
        store: Option<&kotton_store::runtime::user::UserStore>,
    ) -> Option<String>;

    /// Store a remote's credentials.
    fn set_remote_credentials(&self, user_id: &str, name: &str, value: &str) -> io::Result<()>;

    /// Forget a remote's credentials. Absence is not an error — a remote may
    /// never have had any.
    fn forget_remote_credentials(&self, user_id: &str, name: &str);

    /// This user's store, if they are resident on this node.
    ///
    /// The one thing these handlers ever wanted from a `UserRuntime`: production
    /// called `.store()` on it seventeen times and nothing else. Asking for the
    /// store directly is what takes the daemon's residency map out of twenty-three
    /// signatures — a domain crate cannot name that map, because bookkeeping of
    /// which users are live in this process is the daemon's.
    fn user_store(
        &self,
        user_id: &str,
    ) -> Option<Arc<kotton_store::runtime::user::UserStore>>;

    /// Replicate a mount, records included.
    ///
    /// Listed because these handlers serve the `SyncMount` verb, not because
    /// they own replication — the pass itself is `sync_engine`'s, and it still
    /// holds the machine for mount locks and peer dialing. Routing it through
    /// the host is what keeps *this* file free of the runtime while that stays
    /// true.
    async fn sync_mount(
        &self,
        user_id: &str,
        mount: &str,
        remote: &str,
        direction: Option<kotton_wire::ipc::SyncDirection>,
    ) -> anyhow::Result<kotton_wire::remote::SyncResult>;

    /// Dial a paired node and return its object store.
    async fn open_peer_storage(
        &self,
        node: kotton_wire::peer::PairedNode,
        user_id: &str,
        store: Option<&kotton_store::runtime::user::UserStore>,
    ) -> anyhow::Result<Arc<dyn kotton_sys::store::SyncableStore>>;
}

// ---------------------------------------------------------------------------
// File operations
// ---------------------------------------------------------------------------

pub async fn read_file(
    host: &dyn FileHost,
    user_id: String,
    path: String,
    offset: u64,
    length: u32,
) -> io::Result<UserResponse> {
    let user_store = match host.user_store(&user_id) {
        Some(store) => store,
        None => {
            return Ok(UserResponse::Error {
                message: format!("user '{}' not found", user_id),
            })
        }
    };
    // A large file exceeds the IPC frame cap, so it is read in ranges: return
    // `[offset, offset+length)` plus the whole file's size.
    //
    // The range is asked of the *store*. It used to be taken here, out of a
    // whole-file read, and the comment that stood in this place called a
    // storage-level ranged read "the later optimization" — which was true right
    // up to the size at which it stopped being an optimization and became the
    // difference between a file that can be read and one that cannot. A client
    // walks a file in 4 MiB ranges, so a whole-file read per range is work
    // quadratic in the file's size: measured, a 200 MiB object did not finish
    // in twenty-five minutes of CPU.
    match user_store.read_file_range(&path, offset, length as u64).await {
        Ok((data, total_size)) => Ok(UserResponse::FileData { data, total_size }),
        Err(e) => Ok(UserResponse::Error {
            message: e.to_string(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Sealed replication
// ---------------------------------------------------------------------------

/// The key domain a blind mount was pinned to by its first sealed write, or
/// the store's error naming the mount — never `None` for *could not read*.
fn blind_mount_domain(host: &dyn FileHost, user_id: &str, mount: &str) -> io::Result<Option<String>> {
    host.mount_domain(user_id, mount).map_err(|e| {
        io::Error::new(e.kind(), format!("the key domain mount '{mount}' is pinned to could not be read: {e}"))
    })
}

/// Which key domain this node treats as authoritative for `mount`: its own if it
/// holds data keys, otherwise whatever the mount was pinned to.
///
/// Delegates to the runtime so the daemon and the peer client cannot disagree
/// about which domain this node's objects belong to.
fn effective_domain(
    host: &dyn FileHost,
    // Takes the store rather than the runtime: everything this needs is the
    // store's, and the VFS is `core/store`'s. With this,
    // `files.rs` names nothing from the runtime crate but the machine itself.
    user_store: &kotton_store::runtime::user::UserStore,
    mount: &str,
) -> io::Result<Option<String>> {
    let user_id = user_store.user_id();
    match host.cek_domain_id(user_id, Some(user_store)) {
        Some(own) => Ok(Some(own)),
        None => blind_mount_domain(host, user_id, mount),
    }
}

/// Serve an object as a sealed blob, with the epoch it is sealed under.
///
/// **Caller narrowing lives in the peer dispatcher, not here.** This handler is
/// reached from two places and deliberately makes no authorisation decision of
/// its own. `handle_peer_request` holds the peer's DID from the mTLS handshake
/// and refuses sealed replication to anything but a permanently paired device;
/// local IPC callers have already cleared the session and trust
/// floor. Putting the check here as well would duplicate a decision that belongs
/// where the caller's identity is actually known.
pub async fn read_sealed(
    host: &dyn FileHost,
    user_id: String,
    mount: String,
    path: String,
    offset: u64,
    length: u32,
) -> io::Result<UserResponse> {
    let Some(user_store) = host.user_store(&user_id) else {
        return Ok(UserResponse::Error {
            message: format!("user '{user_id}' not found"),
        });
    };

    let domain_id = match effective_domain(host, &user_store, &mount) {
        Ok(domain) => domain,
        Err(e) => return Ok(UserResponse::Error { message: e.to_string() }),
    };
    let Some(domain_id) = domain_id else {
        return Ok(UserResponse::Error {
            message: format!(
                "mount '{mount}' has no recorded key domain; nothing sealed has been \
                 replicated to it yet"
            ),
        });
    };

    // A sealed object can be a whole 16 MiB pack, larger than the peer channel's
    // response cap, so the caller fetches it in ranges. Return `[offset, offset+
    // length)` of the object plus its total size. (The whole object is read to
    // serve each range — fine at pack sizes; a storage-level ranged read is a
    // later optimization if objects grow.)
    match user_store.read_sealed(&mount, &path).await {
        Ok(blob) => {
            let total_size = blob.len() as u64;
            let start = (offset as usize).min(blob.len());
            let end = start.saturating_add(length as usize).min(blob.len());
            Ok(UserResponse::SealedObject {
                blob: blob[start..end].to_vec(),
                domain_id,
                total_size,
            })
        }
        Err(e) => Ok(UserResponse::Error {
            message: e.to_string(),
        }),
    }
}

/// Server-side reassembly of chunked sealed writes, keyed by
/// `(user_id, mount, path, content_hash)`.
///
/// A large sealed object (a 16 MiB pack) exceeds the peer frame cap, so it
/// arrives as a run of `WriteSealed` chunks. The content hash in the key means
/// two writers pushing *different* content to one path never share a buffer, so
/// they cannot interleave; identical content shares one buffer (idempotent).
/// Shared for the peer listener's lifetime, like the FROST participant.
pub type SealedReassembly =
    Arc<tokio::sync::Mutex<HashMap<(String, String, String, String), ReassemblyBuf>>>;

/// One in-progress reassembly.
pub struct ReassemblyBuf {
    body: ReassemblyBody,
    total_size: u64,
    last_touch: Instant,
}

/// Where a transfer's bytes are going while it is in flight.
///
/// `Buffered` is the original behaviour and still the answer for everything
/// small: hold the object, hash it, write it once. `Streamed` exists because a
/// model is gigabytes and holding one costs a multiple of it in memory — the
/// bytes go to the store as they arrive and the hash is computed on the way
/// past.
pub enum ReassemblyBody {
    Buffered(Vec<u8>),
    Streamed {
        sink: Box<dyn kotton_sys::store::ObjectSink>,
        /// Boxed: a hasher is about 1.9 KB, and every `Buffered` transfer in the
        /// map would otherwise be that size too.
        hasher: Box<blake3::Hasher>,
        received: u64,
    },
}

impl ReassemblyBody {
    /// Bytes accepted so far — the offset the next chunk must start at.
    fn received(&self) -> u64 {
        match self {
            ReassemblyBody::Buffered(d) => d.len() as u64,
            ReassemblyBody::Streamed { received, .. } => *received,
        }
    }
}

/// Reject a declared `total_size` above this — a bound on what one hostile or
/// buggy chunk stream can make the receiver buffer.
///
/// This is the **sealed peer path**, which is still whole-buffer, so this is
/// still a memory bound and it does not move.
const MAX_SEALED_OBJECT_BYTES: u64 = 256 * 1024 * 1024;

/// What one file may buffer when the store offers no streaming ingest.
///
/// Unchanged in value from the single cap that used to govern both paths, and
/// unchanged in meaning: memory. A store that cannot stream refuses above this
/// rather than trying, because a clean refusal and an out-of-memory are not the
/// same failure.
pub(super) const MAX_BUFFERED_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// What one **streamed** file may write before its hash is checked.
///
/// Defined on the wire, not here: it is a property of the channel rather than of
/// this end, and it used to be written down twice. See
/// [`kotton_wire::ipc::MAX_STREAMED_FILE_BYTES`] for what it bounds and why it
/// moved.
use kotton_wire::ipc::MAX_STREAMED_FILE_BYTES;

/// Stream above this; buffer at or below it.
///
/// One pack. Below a single pack an object cannot fill a pack of its own, so
/// streaming would buy nothing and cost a commit — and a change that is right
/// for a 3 GiB model must not make a 4 KiB note more expensive.
const STREAM_ABOVE_BYTES: u64 = 16 * 1024 * 1024;
/// Reap a reassembly buffer a writer abandoned this long ago.
const REASSEMBLY_TTL: Duration = Duration::from_secs(120);

/// Store a sealed blob, reassembled from chunks and verified against its content
/// hash before it is written.
///
/// `reassembly` is `Some` on the peer path (chunks accumulate in the shared map)
/// and `None` on the local path, which admits only a single complete chunk —
/// there is no local chunked-write caller. See [`read_sealed`] for the
/// caller-narrowing gap that applies here too.
#[allow(clippy::too_many_arguments)]
pub async fn write_sealed(
    host: &dyn FileHost,
    user_id: String,
    mount: String,
    path: String,
    blob: Vec<u8>,
    domain_id: String,
    offset: u64,
    total_size: u64,
    content_hash: String,
    reassembly: Option<&SealedReassembly>,
) -> io::Result<UserResponse> {
    let Some(user_store) = host.user_store(&user_id) else {
        return Ok(UserResponse::Error {
            message: format!("user '{user_id}' not found"),
        });
    };

    if total_size > MAX_SEALED_OBJECT_BYTES {
        return Ok(UserResponse::Error {
            message: format!("sealed object too large: {total_size} bytes"),
        });
    }

    // The domain decision is content-independent, so make it once, at the start
    // of the transfer, before buffering — a wrong-domain write is refused
    // without occupying a reassembly buffer. A node holding data keys can only
    // open blobs from its own domain; a blind node pins the mount to the first
    // domain it sees. A pin that could not be read refuses the write and pins
    // nothing: an error is not *no pin*, and pinning over it is what would
    // admit a second domain to a single-domain mount.
    if offset == 0 {
        match effective_domain(host, &user_store, &mount) {
            Err(e) => return Ok(UserResponse::Error { message: format!("{e}; the write was refused") }),
            Ok(Some(expected)) if expected != domain_id => {
                return Ok(UserResponse::SealedDomainMismatch {
                    expected,
                    got: domain_id,
                });
            }
            Ok(Some(_)) => {}
            Ok(None) => {
                if let Err(e) = host.pin_mount_domain(&user_id, &mount, &domain_id) {
                    return Ok(UserResponse::Error {
                        message: format!("failed to pin mount '{mount}' to a key domain: {e}"),
                    });
                }
            }
        }
    }

    // Assemble the whole object.
    let full: Vec<u8> = match reassembly {
        // Local path: a single complete chunk, or nothing (no local chunked
        // caller exists, so refuse rather than half-store).
        None => {
            if offset != 0 || blob.len() as u64 != total_size {
                return Ok(UserResponse::Error {
                    message: "chunked sealed writes are only accepted over a peer connection"
                        .into(),
                });
            }
            blob
        }
        // Peer path: accumulate into the shared buffer for this transfer.
        Some(map) => {
            // Slot 2 namespaces the reassembly so a VFS write and a sealed
            // write to the same path and hash cannot share a buffer. Sealed
            // writes still address a store, so theirs carries the mount; VFS
            // writes name none and use a marker no
            // `sealed:` key can equal.
            let key = (
                user_id.clone(),
                format!("sealed:{mount}"),
                path.clone(),
                content_hash.clone(),
            );
            // `None`: the sealed peer path stays whole-buffer, bounded by
            // MAX_SEALED_OBJECT_BYTES above. Streaming here would need the
            // sealed view rather than the file view, and nothing asks for it
            // yet — a sealed object is a peer's replication unit, not a model.
            match accept_chunk(map, &key, &blob, offset, total_size, None).await {
                ChunkOutcome::NeedMore => return Ok(UserResponse::Ok),
                ChunkOutcome::Reject(m) => {
                    return Ok(UserResponse::Error { message: m.into() })
                }
                ChunkOutcome::Complete(full) => full,
                ChunkOutcome::CompleteStreamed { .. } => {
                    return Ok(UserResponse::Error {
                        message: "sealed writes do not stream".into(),
                    })
                }
            }
        }
    };

    // Integrity gate: the reassembled bytes must hash to what the sender
    // declared. A corrupt or interleaved reassembly fails here — at write time,
    // a clean rejection — rather than being stored to fail later at read.
    let got = blake3::hash(&full).to_hex().to_string();
    if got != content_hash {
        return Ok(UserResponse::Error {
            message: format!(
                "sealed content hash mismatch (declared {content_hash}, got {got}); refusing to store"
            ),
        });
    }

    match user_store.write_sealed(&mount, &path, &full).await {
        Ok(()) => Ok(UserResponse::Ok),
        Err(e) => Ok(UserResponse::Error {
            message: e.to_string(),
        }),
    }
}

/// Drop reassembly buffers whose writer has gone quiet past the TTL.
fn reap_stale(map: &mut HashMap<(String, String, String, String), ReassemblyBuf>) {
    let now = Instant::now();
    map.retain(|_, b| now.duration_since(b.last_touch) < REASSEMBLY_TTL);
}

/// What feeding one chunk to the reassembly map produced.
pub(super) enum ChunkOutcome {
    /// The buffer is not yet full; the caller acknowledges and awaits more.
    NeedMore,
    /// The buffer is complete; here are the assembled bytes (still unverified).
    Complete(Vec<u8>),
    /// A streamed transfer received its last byte. The sink is **not yet
    /// committed** and `hash` is what actually arrived: the caller compares it
    /// to what was declared and commits only on a match, so bytes whose hash is
    /// wrong never become visible under any name.
    CompleteStreamed {
        sink: Box<dyn kotton_sys::store::ObjectSink>,
        hash: String,
    },
    /// The chunk was inconsistent (out of order, wrong size, overran); the
    /// buffer was dropped.
    Reject(&'static str),
}

/// Append one chunk at `offset` into the reassembly buffer for `key`, in order,
/// and report whether the object is now complete. The caller verifies the
/// content hash on `Complete` — this only assembles. Shared by chunked sealed
/// and plaintext writes, so the two cannot drift.
pub(super) async fn accept_chunk(
    map: &SealedReassembly,
    key: &(String, String, String, String),
    chunk: &[u8],
    offset: u64,
    total_size: u64,
    new_sink: Option<Box<dyn kotton_sys::store::ObjectSink>>,
) -> ChunkOutcome {
    let mut guard = map.lock().await;
    reap_stale(&mut guard);

    // A sink is only ever adopted at the start of a transfer. Handing one to a
    // transfer already in flight would mean two destinations for one object.
    if offset == 0 {
        guard.remove(key);
        let body = match new_sink {
            Some(sink) => ReassemblyBody::Streamed {
                sink,
                hasher: Box::new(blake3::Hasher::new()),
                received: 0,
            },
            None => ReassemblyBody::Buffered(Vec::new()),
        };
        guard.insert(
            key.clone(),
            ReassemblyBuf {
                body,
                total_size,
                last_touch: Instant::now(),
            },
        );
    }

    let Some(buf) = guard.get_mut(key) else {
        // A later chunk with no transfer open: the first chunk was refused, or
        // the buffer was reaped. Either way there is nothing to append to.
        return ChunkOutcome::Reject("no transfer in progress for this object");
    };

    // Chunks must arrive in order and agree on the size; a mismatch is a
    // confused or hostile stream — drop the whole transfer. Unchanged for both
    // bodies, which is why `received()` exists rather than two copies of this.
    if buf.total_size != total_size || offset != buf.body.received() {
        guard.remove(key);
        return ChunkOutcome::Reject("out-of-order or inconsistent chunk");
    }

    // Overrun is checked *before* the chunk is taken, so an overrunning stream
    // never writes its last chunk. Buffered order is unchanged in effect.
    if buf.body.received().saturating_add(chunk.len() as u64) > total_size {
        guard.remove(key);
        return ChunkOutcome::Reject("transfer overran its declared size");
    }

    match &mut buf.body {
        ReassemblyBody::Buffered(data) => data.extend_from_slice(chunk),
        ReassemblyBody::Streamed {
            sink,
            hasher,
            received,
        } => {
            if let Err(e) = sink.push(chunk).await {
                guard.remove(key);
                tracing::warn!("streamed write failed mid-transfer: {e}");
                return ChunkOutcome::Reject("the store refused a chunk mid-transfer");
            }
            hasher.update(chunk);
            *received += chunk.len() as u64;
        }
    }
    buf.last_touch = Instant::now();

    if buf.body.received() < total_size {
        return ChunkOutcome::NeedMore;
    }
    match guard.remove(key).map(|b| b.body) {
        Some(ReassemblyBody::Buffered(data)) => ChunkOutcome::Complete(data),
        Some(ReassemblyBody::Streamed { sink, hasher, .. }) => ChunkOutcome::CompleteStreamed {
            sink,
            hash: hasher.finalize().to_hex().to_string(),
        },
        None => ChunkOutcome::Reject("transfer vanished while completing"),
    }
}

/// List a mount in storage-key space — the opaque keys replication
/// addresses. See [`read_sealed`] on why authorisation lives in the dispatcher.
pub async fn list_sealed(
    host: &dyn FileHost,
    user_id: String,
    mount: String,
    prefix: String,
) -> io::Result<UserResponse> {
    let Some(user_store) = host.user_store(&user_id) else {
        return Ok(UserResponse::Error {
            message: format!("user '{user_id}' not found"),
        });
    };
    match user_store.list_sealed(&mount, &prefix).await {
        Ok(entries) => Ok(UserResponse::SealedList {
            entries: entries
                .into_iter()
                .map(|(key, size, modified)| kotton_wire::ipc::SealedListEntry {
                    key,
                    size,
                    modified,
                })
                .collect(),
        }),
        Err(e) => Ok(UserResponse::Error {
            message: e.to_string(),
        }),
    }
}

/// Write a file, reassembled from chunks and verified against its content hash.
///
/// A file over the IPC frame cap arrives as a run of chunks accumulated in
/// `reassembly` (the local path always supplies it). A single complete chunk is
/// the common small-file case and commits immediately.
#[allow(clippy::too_many_arguments)]
pub async fn write_file(
    host: &dyn FileHost,
    user_id: String,
    path: String,
    data: Vec<u8>,
    offset: u64,
    total_size: u64,
    content_hash: String,
    reassembly: Option<&SealedReassembly>,
) -> io::Result<UserResponse> {
    let user_store = match host.user_store(&user_id) {
        Some(store) => store,
        None => {
            return Ok(UserResponse::Error {
                message: format!("user '{}' not found", user_id),
            })
        }
    };

    // The absolute ceiling, checked on every chunk: no file write may exceed
    // what a stream is allowed to put on disk, whichever path it takes.
    if total_size > MAX_STREAMED_FILE_BYTES {
        return Ok(UserResponse::Error {
            message: format!(
                "file too large: {total_size} bytes exceeds the {MAX_STREAMED_FILE_BYTES}-byte ceiling"
            ),
        });
    }

    // Stream or buffer — decided once, at the start of the transfer, from the
    // declared size alone. Content-independent, like the domain pin above it,
    // and for the same reason: a write that cannot be accepted is refused
    // before it occupies anything.
    //
    // A store that offers no streaming ingest answers `None`, and the transfer
    // falls back to buffering under the smaller cap. That is a refusal for a
    // model-sized file rather than an attempt, because a clean refusal and an
    // out-of-memory are not the same failure.
    let mut new_sink: Option<Box<dyn kotton_sys::store::ObjectSink>> = None;
    if offset == 0 && reassembly.is_some() && total_size > STREAM_ABOVE_BYTES {
        match user_store.begin_file_write(&path).await {
            Ok(sink) => new_sink = sink,
            Err(e) => {
                return Ok(UserResponse::Error {
                    message: format!("could not begin a streamed write: {e}"),
                })
            }
        }
    }
    if offset == 0 && new_sink.is_none() && total_size > MAX_BUFFERED_FILE_BYTES {
        return Ok(UserResponse::Error {
            message: format!(
                "file too large to buffer: {total_size} bytes exceeds \
                 {MAX_BUFFERED_FILE_BYTES} and this store offers no streaming ingest"
            ),
        });
    }

    // Assemble the whole file from its chunks.
    let full: Vec<u8> = match reassembly {
        None => {
            if offset != 0 || data.len() as u64 != total_size {
                return Ok(UserResponse::Error {
                    message: "chunked file writes require the local IPC path".into(),
                });
            }
            data
        }
        Some(map) => {
            let key = (
                user_id.clone(),
                "vfs".to_string(),
                path.clone(),
                content_hash.clone(),
            );
            match accept_chunk(map, &key, &data, offset, total_size, new_sink).await {
                ChunkOutcome::NeedMore => return Ok(UserResponse::Ok),
                ChunkOutcome::Reject(m) => {
                    return Ok(UserResponse::Error { message: m.into() })
                }
                ChunkOutcome::Complete(full) => full,
                // The streamed path ends here rather than falling through: the
                // bytes are already down, so there is nothing to hand to
                // `write_file` and the only remaining question is whether they
                // may be seen.
                ChunkOutcome::CompleteStreamed { mut sink, hash } => {
                    // The same gate the buffered path applies, at the same
                    // point in the object's life: before anything can name it.
                    // On a mismatch the sink is dropped uncommitted, so no key
                    // resolves to the bytes and compaction reclaims them.
                    if hash != content_hash {
                        return Ok(UserResponse::Error {
                            message: format!(
                                "file content hash mismatch (declared {content_hash}, got {hash}); \
                                 refusing to write"
                            ),
                        });
                    }
                    if let Err(e) = sink.commit().await {
                        return Ok(UserResponse::Error {
                            message: format!("streamed write failed to commit: {e}"),
                        });
                    }
                    let _ = host.events().publish(
                        Event::with_payload(
                            EventCategory::VFS,
                            EventLevel::Debug,
                            format!("WriteFile: {user_id}{path}"),
                            json!({ "path": format!("{path}"), "bytes": total_size, "streamed": true }),
                        )
                        .in_scope(EventScope::User(user_id.clone())),
                    );
                    return Ok(UserResponse::Ok);
                }
            }
        }
    };

    // Integrity gate before the write: the assembled bytes must hash to what the
    // client declared, so a corrupt or interleaved reassembly is refused here.
    let got = blake3::hash(&full).to_hex().to_string();
    if got != content_hash {
        return Ok(UserResponse::Error {
            message: format!(
                "file content hash mismatch (declared {content_hash}, got {got}); refusing to write"
            ),
        });
    }
    let data = full;

    match user_store.write_file(&path, &data).await {
        Ok(_) => {
            let bytes = data.len();
            let _ = host.events().publish(Event::with_payload(
                EventCategory::VFS,
                EventLevel::Debug,
                format!("WriteFile: {user_id}{path}"),
                json!({ "path": format!("{path}"), "bytes": bytes }),
            )
            .in_scope(EventScope::User(user_id.clone())));
            Ok(UserResponse::Ok)
        }
        Err(e) => {
            let _ = host.events().publish(Event::with_payload(
                EventCategory::System,
                EventLevel::Error,
                format!("WriteFile failed {user_id}/{path}: {e}"),
                json!({ "path": format!("{path}"), "error": e.to_string() }),
            )
            .in_scope(EventScope::User(user_id.clone())));
            Ok(UserResponse::Error {
                message: e.to_string(),
            })
        }
    }
}

pub async fn list_files(
    host: &dyn FileHost,
    user_id: String,
    prefix: String,
) -> io::Result<UserResponse> {
    let user_store = match host.user_store(&user_id) {
        Some(store) => store,
        None => {
            return Ok(UserResponse::Error {
                message: format!("user '{}' not found", user_id),
            })
        }
    };
    match user_store.list_files(&prefix).await {
        Ok(files) => Ok(UserResponse::FileList { files }),
        Err(e) => Ok(UserResponse::Error {
            message: e.to_string(),
        }),
    }
}

pub async fn delete_file(
    host: &dyn FileHost,
    user_id: String,
    path: String,
) -> io::Result<UserResponse> {
    let user_store = match host.user_store(&user_id) {
        Some(store) => store,
        None => {
            return Ok(UserResponse::Error {
                message: format!("user '{}' not found", user_id),
            })
        }
    };
    match user_store.delete_file(&path).await {
        Ok(_) => Ok(UserResponse::Ok),
        Err(e) => Ok(UserResponse::Error {
            message: e.to_string(),
        }),
    }
}

/// Paths with a retained losing version, and the content ids kept for each.
///
/// Replication keeps the loser of a concurrent write rather than destroying it.
/// This is how anyone finds out: without it the retention is real and invisible.
pub async fn list_conflicts(
    host: &dyn FileHost,
    user_id: String,
) -> io::Result<UserResponse> {
    let Some(user_store) = host.user_store(&user_id) else {
        return Ok(UserResponse::Error {
            message: format!("user '{user_id}' not found"),
        });
    };
    // In the person's tree, by their paths: the same tree `kotton fs write`
    // and every app's `files` handle address (`UserStore::file_conflicts`).
    match user_store.file_conflicts().await {
        Ok(conflicts) => Ok(UserResponse::ConflictList { conflicts }),
        Err(e) => Ok(UserResponse::Error {
            message: e.to_string(),
        }),
    }
}

/// Settle the conflict on `path`, releasing what was retained for it.
///
/// `keep` promotes a retained version by writing its bytes as an ordinary new
/// version, so the resolution replays elsewhere as a decision naming what it
/// superseded rather than as an unexplained reversal.
pub async fn resolve_conflict(
    host: &dyn FileHost,
    user_id: String,
    path: String,
    keep: Option<String>,
) -> io::Result<UserResponse> {
    let Some(user_store) = host.user_store(&user_id) else {
        return Ok(UserResponse::Error {
            message: format!("user '{user_id}' not found"),
        });
    };
    match user_store.resolve_file_conflict(&path, keep.as_deref()).await {
        Ok(()) => Ok(UserResponse::Ok),
        Err(e) => Ok(UserResponse::Error {
            message: e.to_string(),
        }),
    }
}

/// Erase a path and its entire history (`purge`).
///
/// Local-origin only — see the verb. A delete stays recoverable because the log
/// records it; this removes the record, and nothing brings it back.
pub async fn purge_file(
    host: &dyn FileHost,
    user_id: String,
    path: String,
) -> io::Result<UserResponse> {
    let Some(user_store) = host.user_store(&user_id) else {
        return Ok(UserResponse::Error {
            message: format!("user '{user_id}' not found"),
        });
    };
    match user_store.purge_file(&path).await {
        Ok(()) => Ok(UserResponse::Ok),
        Err(e) => Ok(UserResponse::Error {
            message: e.to_string(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Remote storage management
// ---------------------------------------------------------------------------

pub async fn remote_add(
    db: &Arc<SqlitePool>,
    host: &dyn FileHost,
    user_id: String,
    name: String,
    backend: RemoteBackend,
    credentials: Option<JsonValue>,
) -> io::Result<UserResponse> {
    // Handle Kotton peer remotes separately — they require DB access for node
    // lookup and NAT traversal, bypassing the standard add_user_remote path.
    if let RemoteBackend::Kotton {
        ref peer_did,
        ref label,
    } = backend
    {
        return remote_add_kotton(db, host, user_id, name, peer_did.clone(), label.clone())
            .await;
    }

    if let Some(ref creds) = credentials {
        if let Err(e) = host.set_remote_credentials(&user_id, &name, &creds.to_string()) {
            return Ok(UserResponse::Error {
                message: format!("failed to store credentials: {e}"),
            });
        }
    }
    // Validate and prepare the backend before resolving the runtime. Moved here
    // from the runtime's `remote_cmds` wrapper: deciding whether a *request* is
    // well-formed is the daemon's job, and this is the only caller.
    let local_path = match &backend {
        RemoteBackend::Local { path } => {
            if let Err(e) = std::fs::create_dir_all(path) {
                return Ok(UserResponse::Error {
                    message: format!("failed to create local remote dir {path:?}: {e}"),
                });
            }
            path.clone()
        }
        RemoteBackend::S3 { .. } => {
            return Ok(UserResponse::Error {
                message: "S3 remote not supported in this build".to_string(),
            });
        }
        RemoteBackend::Ipfs { .. } => {
            return Ok(UserResponse::Error {
                message: "IPFS remote not supported in this build".to_string(),
            });
        }
        // Handled above, before credentials are stored.
        RemoteBackend::Kotton { .. } => unreachable!("Kotton peer remotes return earlier"),
    };

    let config = kotton_wire::remote::RemoteConfig {
        backend,
        cache_dir: None,
        // Born blinded: a new mount has no legacy objects to migrate.
        key_format: kotton_wire::remote::KeyFormat::Blinded,
    };

    // Built through the user's runtime so the mount lands in their key domain.
    // Constructing a bare LocalObjectStorage here is what once left
    // runtime-added mounts storing plaintext while startup mounts were sealed.
    // The store is the host's answer now: this handler asks for the user it is
    // serving, rather than resolving one out of the daemon's residency map.
    let added = host
        .user_store(&user_id)
        .ok_or_else(|| anyhow::anyhow!("user '{user_id}' is not active"))
        .and_then(|user_store| {
        // `OsFilesystem` is supplied here because `store` must not name a host
        // OS — see `UserStore::local_store_with`. The daemon is a layer that
        // legitimately knows one exists.
        let storage = user_store.local_store_with(
            local_path,
            kotton_fs::OsFilesystem,
            kotton_wire::remote::KeyFormat::Blinded,
        );
        user_store.add_remote(name.clone(), storage, config)
    });
    match added {
        Ok(_) => {
            let _ = host.events().publish(Event::with_payload(
                EventCategory::Storage,
                EventLevel::Info,
                format!("Remote added: {user_id}/{name}"),
                json!({ "user_id": user_id, "name": name }),
            )
            .in_scope(EventScope::User(user_id.clone())));
            Ok(UserResponse::RemoteAdded { name })
        }
        Err(e) => Ok(UserResponse::Error {
            message: e.to_string(),
        }),
    }
}

/// Handle `RemoteBackend::Kotton`: look up the drive's node, connect via NAT
/// traversal, then register the live `KottonPeerObjectStorage`. Only a drive.
async fn remote_add_kotton(
    db: &Arc<SqlitePool>,
    host: &dyn FileHost,
    user_id: String,
    name: String,
    peer_did: String,
    label: String,
) -> io::Result<UserResponse> {
    // 1. Resolve peer_did → the node one of the person's drives is reached
    //    through. A peer remote is a drive and nothing else: a device
    //    replicates to its person's drives, and no device is another's
    //    target, so a paired node the drive record does not name — another of
    //    the person's own devices — is refused here, the one place a peer
    //    remote is opened from a request.
    let drives = match kotton_peer::daemon::drives::nodes(db, &user_id).await {
        Ok(n) => n,
        Err(e) => {
            return Ok(UserResponse::Error {
                message: format!("failed to list your drives: {e}"),
            });
        }
    };
    let node = match drives
        .into_iter()
        .find(|n| n.device_did.to_string() == peer_did)
    {
        Some(n) => n,
        None => {
            let paired = network_db::list_paired_nodes(db, &user_id)
                .await
                .map(|nodes| nodes.iter().any(|n| n.device_did.to_string() == peer_did))
                .unwrap_or(false);
            return Ok(UserResponse::Error {
                message: if paired {
                    format!(
                        "'{peer_did}' is not one of your drives: a device is not a sync target — \
                         devices sync to their drives, never to each other"
                    )
                } else {
                    format!(
                        "no paired node with DID '{peer_did}' — pair this device first with \
                         `kotton pair`"
                    )
                },
            });
        }
    };

    // 2. NAT traversal → KottonPeerObjectStorage.
    let user_store = host.user_store(&user_id);
    let storage = match host
        .open_peer_storage(node, &user_id, user_store.as_deref())
        .await
    {
        Ok(s) => s,
        Err(e) => {
            return Ok(UserResponse::Error {
                message: format!("peer connection failed: {e}"),
            });
        }
    };

    // 3. Register with the user runtime (no DB write — exists only for this session).
    let config = RemoteConfig {
        backend: RemoteBackend::Kotton {
            peer_did: peer_did.clone(),
            label,
        },
        cache_dir: None,
        key_format: kotton_wire::remote::KeyFormat::default(),
    };
    match user_store
        .ok_or_else(|| anyhow::anyhow!("user '{user_id}' is not active"))
        .and_then(|store| store.add_remote(name.clone(), storage, config))
    {
        Ok(_) => {
            let _ = host.events().publish(Event::with_payload(
                EventCategory::Storage,
                EventLevel::Info,
                format!("Kotton peer remote added: {user_id}/{name} (peer: {peer_did})"),
                json!({ "user_id": user_id, "name": name, "peer_did": peer_did }),
            )
            .in_scope(EventScope::User(user_id.clone())));
            Ok(UserResponse::RemoteAdded { name })
        }
        Err(e) => Ok(UserResponse::Error {
            message: e.to_string(),
        }),
    }
}

pub async fn remote_remove(
    host: &dyn FileHost,
    user_id: String,
    name: String,
) -> io::Result<UserResponse> {
    host.forget_remote_credentials(&user_id, &name);
    match host
        .user_store(&user_id)
        .ok_or_else(|| anyhow::anyhow!("user '{user_id}' is not active"))
        .and_then(|store| store.remove_remote(&name))
    {
        Ok(_) => {
            let _ = host.events().publish(Event::with_payload(
                EventCategory::Storage,
                EventLevel::Info,
                format!("Remote removed: {user_id}/{name}"),
                json!({ "user_id": user_id, "name": name }),
            )
            .in_scope(EventScope::User(user_id.clone())));
            Ok(UserResponse::Ok)
        }
        Err(e) => Ok(UserResponse::Error {
            message: e.to_string(),
        }),
    }
}

pub async fn remote_list(
    host: &dyn FileHost,
    user_id: String,
) -> io::Result<UserResponse> {
    match host
        .user_store(&user_id)
        .ok_or_else(|| anyhow::anyhow!("user '{user_id}' is not active"))
        .map(|store| store.list_remotes())
    {
        Ok(remotes) => Ok(UserResponse::RemoteList { remotes }),
        Err(e) => Ok(UserResponse::Error {
            message: e.to_string(),
        }),
    }
}

pub async fn remote_cache_clear(
    _host: &dyn FileHost,
    user_id: String,
    name: String,
) -> io::Result<UserResponse> {
    // Not wired to `CachedObjectStorage`: this only acknowledges.
    eprintln!("RemoteCacheClear: {user_id}/{name} (no-op until Phase 5)");
    Ok(UserResponse::Ok)
}

pub async fn remote_credentials_set(
    host: &dyn FileHost,
    user_id: String,
    name: String,
    credentials: JsonValue,
) -> io::Result<UserResponse> {
    match host.set_remote_credentials(&user_id, &name, &credentials.to_string()) {
        Ok(_) => Ok(UserResponse::Ok),
        Err(e) => Ok(UserResponse::Error {
            message: format!("failed to update credentials: {e}"),
        }),
    }
}

// ---------------------------------------------------------------------------
// Sync
// ---------------------------------------------------------------------------

pub async fn sync_mount(
    db: &Arc<SqlitePool>,
    host: &dyn FileHost,
    user_id: String,
    mount: String,
    remote: String,
    direction: Option<SyncDirection>,
) -> io::Result<UserResponse> {
    let Some(store) = host.user_store(&user_id) else {
        return Ok(UserResponse::Error {
            message: format!("user '{}' not found", user_id),
        });
    };
    // A drive is a remote by the id of the node it is reached through. The
    // enrolment records the drive; the remote — the peer storage opened to the
    // vault — is derivable from that record and nothing else, so naming a
    // drive's node here opens it, and no client has to know that a `remote add`
    // stands between `device admit` and `sync`: the line the product prints
    // after admitting a vault — "run `sync <id>`" — works as typed.
    //
    // Only a drive. A paired node that is not one — another of the person's
    // devices — is not a sync target, so it opens no remote here, and
    // `remote_add_kotton` refuses it by name.
    if !store.list_remotes().contains(&remote) {
        if let Some(node) = network_db::get_paired_node_by_id(db, &user_id, &remote).await? {
            let did = node.device_did.to_string();
            if let UserResponse::Error { message } =
                remote_add_kotton(db, host, user_id.clone(), remote.clone(), did, remote.clone()).await?
            {
                return Ok(UserResponse::Error {
                    message: format!("'{remote}' is paired but is not synced with: {message}"),
                });
            }
        }
    }
    // Records ride the same pass as objects, so a manual `kotton sync`
    // converges the record store too, not just files.
    match host.sync_mount(&user_id, &mount, &remote, direction)
        .await
    {
        Ok(result) => {
            let _ = host.events().publish(Event::with_payload(
                EventCategory::Storage,
                EventLevel::Info,
                format!(
                    "Sync complete: {user_id}\u{2194}{remote}: \
                     pushed={}, pulled={}, skipped={}",
                    result.pushed, result.pulled, result.skipped
                ),
                json!({
                    "user_id": user_id,
                    "mount": mount,
                    "remote": remote,
                    "pushed": result.pushed,
                    "pulled": result.pulled,
                    "skipped": result.skipped,
                }),
            ));
            Ok(UserResponse::SyncComplete {
                pushed: result.pushed,
                pulled: result.pulled,
                skipped: result.skipped,
                transfers: result.transfers,
            })
        }
        Err(e) => Ok(UserResponse::Error {
            message: e.to_string(),
        }),
    }
}
