// SPDX-License-Identifier: AGPL-3.0-or-later
//! Sync operations for UserRuntime
//!
//! A sync pass has two halves. First it **transfers sealed bytes**: every leaf
//! key on each side is compared and the sealed envelope moved to wherever it is
//! missing or newer, by `modified` timestamp (ties and timestamp-less objects
//! go to local — push semantics). For a packed mount those keys are packs and
//! generation-keyed superblocks — unique-named, immutable blobs — so the
//! comparison is a set union that never destroys either side.
//!
//! Then it **reconciles**: packs carry the sealed history log, and
//! replaying the union of this device's segments with a peer's rebuilds current
//! state. That, not the timestamp comparison, is the authority for packed
//! mounts — a delete is a segment rather than an absence, so it propagates
//! instead of resurrecting, and a concurrent overwrite keeps its loser in
//! history rather than being clobbered. The timestamp path still governs loose
//! (not-yet-packed) objects and stores with no log (a blind storage node).
//!
//! # Sync moves sealed bytes
//!
//! Transfers go through [`SealedObjectAccess`], **never** through
//! [`ObjectStorage::get`]/[`put`]. On an encrypting store `get` decrypts, so a
//! sync pass built on it reads plaintext and writes plaintext to the peer — and
//! a node whose posture withholds the data keys (`BlindStorage`) would
//! then persist the user's data in the clear, having been handed it rather than
//! having decrypted it. Moving the sealed envelope verbatim means neither side
//! materialises plaintext and a keyless peer receives bytes it cannot open.
//!
//! It is also cheaper: no decrypt-then-re-encrypt round trip per object.
//!
//! [`SealedObjectAccess`]: kotton_sys::store::SealedObjectAccess
//! [`ObjectStorage::get`]: kotton_sys::store::ObjectStorage::get
//! [`put`]: kotton_sys::store::ObjectStorage::put

use super::UserStore;
use crate::StorageKey;
use anyhow::{anyhow, Result};
use kotton_sys::store::SyncableStore;
use kotton_wire::ipc::SyncDirection;
pub use kotton_wire::remote::SyncResult;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// What a pass may send to the remote.
///
/// Decided by whoever knows who is on the other end — the sync domain reads the
/// peer's posture (`kotton_sync::engine::sync_mount_with_records`) — and held
/// here, at the one loop that moves bytes, so the property does not depend on
/// anything having happened to the mount first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outbound {
    /// Every object the comparison says to push. For a remote that holds the
    /// data keys, or one in the person's own key domain (a directory).
    Everything,
    /// Packs and superblocks only. A loose object's sealed
    /// length is its file's length plus a constant, so toward a peer that holds
    /// no data keys it is never sent: it stays in the local mount, counted as
    /// skipped, until a packing pass puts it in a pack. A write that lands after
    /// the pre-push pack — ordinary file writes take no mount lock — is withheld
    /// here rather than crossing loose.
    PacksOnly,
}

impl Outbound {
    /// Whether an object at `key` may cross under this scope.
    fn admits(self, key: &StorageKey) -> bool {
        match self {
            Outbound::Everything => true,
            Outbound::PacksOnly => {
                use crate::packed::ObjectKind;
                matches!(
                    crate::packed::kind(key.as_str()),
                    ObjectKind::Superblock | ObjectKind::ContentPack | ObjectKind::IndexPack
                )
            }
        }
    }
}

/// What a device keeps of the drive a pass is with (kotton #55, pins): which
/// of the drive's files it keeps whole, and the room it has for them.
///
/// Decided by the sync domain, which reads the person's pin settings
/// (`kotton_device::users::pins`); held here, at the one loop that moves
/// bytes, because a pass that fetched first and asked afterwards would have
/// kept what it was told not to.
/// What names the setting that keeps a path whole ([`Keep::whole`]).
pub type KeptBy = Box<dyn Fn(&str) -> Option<String> + Send + Sync>;

pub struct Keep {
    /// The setting that keeps the file at `path` — a logical store key,
    /// `files/<person path>` for the person's tree — whole, as the person
    /// would say it to keep less (`personal:/photos`), or `None` for a file
    /// this device keeps the index of and fetches when it is opened.
    pub whole: KeptBy,
    /// The bytes of packs this device may hold of the drive, or `None` for no
    /// bound but the disk's.
    pub budget: Option<u64>,
}

/// What a pass kept, against the room it had.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeepReport {
    /// Bytes of packs this device holds of the drive after the pass: each
    /// pack is one of two fixed sizes (`crate::pack::PACK_SIZE`,
    /// `crate::pack::INDEX_PACK_SIZE`), read from one listing of the pack
    /// directory; no pack is opened or walked to know it.
    pub held: u64,
    /// The room it was given, as [`Keep::budget`].
    pub budget: Option<u64>,
    /// Bytes of the content packs its whole pins want.
    pub wanted: u64,
    /// The settings that keep more than the room allows, each as the person
    /// would say it to keep less — empty when every whole pin was kept.
    pub short: Vec<String>,
    /// Content packs fetched for a whole pin in this pass.
    pub fetched: u32,
    /// Content packs no whole pin keeps, let go to make room: the drive holds
    /// each, and a read fetches it again (`crate::fetch`).
    pub evicted: u32,
}

impl UserStore {
    /// Synchronise a local mount against a named remote.
    ///
    /// # Arguments
    /// * `local_mount`  – local storage mount name (typically `"local"`).
    /// * `remote_name`  – named remote to sync against.
    /// * `direction`    – `None` = bidirectional last-write-wins;
    ///   `Some(Push)` = local → remote only; `Some(Pull)` = remote → local only.
    /// * `outbound`     – what may be pushed at all ([`Outbound`]); an object
    ///   it does not admit is skipped, never sent.
    pub async fn sync_mount(
        &self,
        local_mount: &str,
        remote_name: &str,
        direction: Option<SyncDirection>,
        outbound: Outbound,
    ) -> Result<SyncResult> {
        Ok(self.sync_mount_keeping(local_mount, remote_name, direction, outbound, None).await?.0)
    }

    /// [`Self::sync_mount`], keeping what `keep` says of the remote's content
    /// and no more (kotton #55).
    ///
    /// With `keep`, a pass pulls in two steps. First everything but content
    /// packs (`crate::packed::CONTENT_PACK_PREFIX`) — the superblocks and the
    /// index packs, which carry the history log and the manifests — and
    /// reconciles, so this device knows every file the drive holds and where
    /// its content is. Then, from the reconciled manifest, the content packs
    /// of the files `keep` keeps whole, as far as the room allows; a setting
    /// whose packs do not fit is named in the report, never dropped silently.
    /// A pinned file brings the whole pack it was written in, with whatever
    /// else that pass wrote: such a neighbour is held as long as the pin is,
    /// counts against the room as the pin's, and is named under the pin's
    /// setting when short (kotton #168 cuts packs by folder).
    /// Then, over the room, content packs no whole pin keeps and the drive
    /// holds are let go, since a read fetches them again. A content pack is
    /// the unit: a file kept whole brings whatever else its pack holds — what
    /// one packing pass on one device wrote beside it.
    ///
    /// `None` keeps everything, as every pass did before pins.
    pub async fn sync_mount_keeping(
        &self,
        local_mount: &str,
        remote_name: &str,
        direction: Option<SyncDirection>,
        outbound: Outbound,
        keep: Option<&Keep>,
    ) -> Result<(SyncResult, Option<KeepReport>)> {
        let local = self
            .get_remote(local_mount)
            .ok_or_else(|| anyhow!("Local mount '{}' not found", local_mount))?;
        let remote = self
            .get_remote(remote_name)
            .ok_or_else(|| anyhow!("Remote '{}' not found", remote_name))?;

        // Every leaf key on each side, recursing subdirectories — a filesystem
        // backend's `list` is one level deep, so a flat listing would silently
        // skip anything nested (e.g. `notes/2026/trip.md`). Each key is
        // admitted as it is listed ([`list_sealed_recursive`]); one that is
        // not canonical is refused there, and counted among the skipped.
        let (local_map, local_refused) = list_sealed_recursive(local.as_ref(), local_mount).await?;
        let (remote_map, remote_refused) = list_sealed_recursive(remote.as_ref(), remote_name).await?;

        // Union of all object keys across both sides.
        let all_keys: BTreeSet<StorageKey> =
            local_map.keys().chain(remote_map.keys()).cloned().collect();

        let mut pushed: u32 = 0;
        let mut pulled: u32 = 0;
        let mut skipped: u32 = local_refused + remote_refused;
        let mut withheld: u32 = 0;
        let mut transfers: Vec<(SyncDirection, String, u64)> = Vec::new();
        let mut on_remote: BTreeSet<StorageKey> = remote_map.keys().cloned().collect();

        for key in &all_keys {
            let local_ts = local_map.get(key).copied();
            let remote_ts = remote_map.get(key).copied();

            // Which way this key moves, if at all.
            let wants_push = match &direction {
                Some(SyncDirection::Push) => local_ts.is_some(),
                Some(SyncDirection::Pull) => false,
                None => match (local_ts, remote_ts) {
                    // Ties go to local: `>=` keeps push semantics for objects
                    // whose timestamps match.
                    (Some(lts), Some(rts)) => lts >= rts,
                    (Some(_), None) => true,
                    _ => false,
                },
            };
            let push = wants_push && outbound.admits(key);
            if wants_push && !push {
                withheld += 1;
            }
            let pull = match &direction {
                Some(SyncDirection::Pull) => remote_ts.is_some(),
                Some(SyncDirection::Push) => false,
                None => match (local_ts, remote_ts) {
                    (Some(lts), Some(rts)) => lts < rts,
                    (None, Some(_)) => true,
                    _ => false,
                },
            };
            // A content pack is kept by what the reconciled index says this
            // device keeps whole, which is the second step's to decide. A pack
            // is immutable and uniquely named, so one this device holds is
            // never pulled again either way.
            let pull = pull && !(keep.is_some() && crate::packed::is_content_pack(key.as_str()));

            if push {
                let bytes = transfer_sealed(local.as_ref(), remote.as_ref(), key).await?;
                pushed += 1;
                transfers.push((SyncDirection::Push, key.to_string(), bytes));
                on_remote.insert(key.clone());
            } else if pull {
                let bytes = transfer_sealed(remote.as_ref(), local.as_ref(), key).await?;
                pulled += 1;
                transfers.push((SyncDirection::Pull, key.to_string(), bytes));
            } else {
                skipped += 1;
            }
        }

        if withheld > 0 {
            tracing::info!(
                mount = local_mount,
                remote = remote_name,
                withheld,
                "sync: loose objects withheld from a peer that holds no data keys; \
                 they cross once a packing pass has packed them",
            );
        }

        // Replay is the authority. The transfer above moved packs,
        // generation-keyed superblocks, and the sealed segments they carry
        // across as opaque unique-keyed blobs; reconciling now unions this
        // device's history with whatever a peer's replication just delivered
        // and rebuilds current state from it. This is what converges where the
        // per-file `modified` comparison above never could — a delete is a
        // segment, not an absence, so it propagates instead of resurrecting.
        //
        // Only the local mount is reconciled: each device replays its own
        // history after an exchange, and in production `remote` is a peer
        // handle we do not drive. A store with no data keys (a blind storage node)
        // carries the segments and reconciles nothing — `reconcile` returns
        // `None` and this is a no-op.
        match local.reconcile().await {
            Ok(Some(summary)) if summary.segments_adopted > 0 => {
                tracing::info!(
                    mount = local_mount,
                    remote = remote_name,
                    segments_adopted = summary.segments_adopted,
                    paths_changed = summary.paths_changed,
                    paths_pending_content = summary.paths_pending_content,
                    conflicts = summary.conflicts,
                    generation = summary.generation,
                    "reconcile adopted peer segments after sync",
                );
            }
            Ok(_) => {}
            // A reconcile failure must not fail the transfer that already
            // succeeded: the bytes are durably on both sides, and the next
            // pass reconciles again from the same segments. Surface it loudly
            // rather than swallow it — a store that keeps failing to reconcile
            // is diverging.
            Err(e) => tracing::warn!(
                mount = local_mount,
                error = %e,
                "reconcile after sync failed; transfer preserved, retried next pass",
            ),
        }

        let report = match keep {
            Some(keep) if !matches!(direction, Some(SyncDirection::Push)) => {
                let kept_paths = |path: &str| (keep.whole)(path).is_some();
                let holding = local.packs_holding(&kept_paths).await?;
                let r = keep_whole(local.as_ref(), remote.as_ref(), keep, holding, &on_remote, &mut transfers).await?;
                pulled += r.fetched;
                Some(r)
            }
            _ => None,
        };

        Ok((
            SyncResult {
                pushed,
                pulled,
                skipped,
                transfers,
            },
            report,
        ))
    }
}

impl UserStore {
    /// Whether this device holds, here, every pack the content of the file at
    /// `path` in the person's tree is in — kept whole, or fetched since — so
    /// reading it asks no drive. `false` for a path the index does not name.
    pub async fn kept_here(&self, path: &str) -> Result<bool> {
        let local = self.get_remote("local").ok_or_else(|| anyhow!("Local mount 'local' not found"))?;
        let key = crate::fs_view::rooted_key(super::files::PERSON_TREE_ROOT, path);
        let named = |p: &str| p == key;
        let Some(holding) = local.packs_holding(&named).await? else {
            return Ok(true);
        };
        if holding.is_empty() {
            return Ok(false);
        }
        let here: BTreeSet<String> = local
            .list_sealed(Path::new(crate::packed::PACK_PREFIX))
            .await?
            .into_iter()
            .map(|m| m.key)
            .collect();
        Ok(holding.keys().all(|id| here.contains(id)))
    }
}

/// The second step of a pass that keeps less than everything
/// ([`UserStore::sync_mount_keeping`]): fetch the content packs `holding` names
/// that this device lacks, within the room, and let go of content packs no
/// whole pin keeps when it is over the room.
///
/// The packs it fetches are named by the reconciled index, which other
/// devices wrote, so each id is admitted ([`StorageKey`]) before it is read or
/// written; one that is not canonical is refused and fetched by no one.
async fn keep_whole(
    local: &dyn SyncableStore,
    remote: &dyn SyncableStore,
    keep: &Keep,
    holding: Option<BTreeMap<String, Vec<String>>>,
    on_remote: &BTreeSet<StorageKey>,
    transfers: &mut Vec<(SyncDirection, String, u64)>,
) -> Result<KeepReport> {
    let pack = crate::pack::PACK_SIZE as u64;
    // What this device holds of the drive: its packs, each its fixed size —
    // one listing of the pack directory, never a walk of what is in them.
    let mut held: BTreeMap<StorageKey, u64> = local
        .list_sealed(Path::new(crate::packed::PACK_PREFIX))
        .await?
        .into_iter()
        .filter(|m| !m.is_dir)
        .filter_map(|m| Some((admit(&m.key, "local")?, m.size)))
        .collect();
    let bytes = |held: &BTreeMap<StorageKey, u64>| held.values().sum::<u64>();
    let holding = holding.unwrap_or_default();
    let wanted: BTreeMap<StorageKey, &Vec<String>> = holding
        .iter()
        .filter(|(id, _)| crate::packed::is_content_pack(id))
        .filter_map(|(id, paths)| Some((admit(id, "the index")?, paths)))
        .collect();
    let mut report = KeepReport { budget: keep.budget, wanted: wanted.len() as u64 * pack, ..Default::default() };
    let fits = |held: &BTreeMap<StorageKey, u64>| keep.budget.is_none_or(|b| bytes(held) + pack <= b);
    let mut short: BTreeSet<String> = BTreeSet::new();
    for (id, paths) in &wanted {
        if held.contains_key(id) {
            continue;
        }
        if !on_remote.contains(id) {
            // Named by the index and held by neither side: the pass that wrote
            // it has not reached this drive yet, and a later one brings it.
            continue;
        }
        if !fits(&held) {
            short.extend(paths.iter().filter_map(|p| (keep.whole)(p)));
            continue;
        }
        let got = transfer_sealed(remote, local, id).await?;
        transfers.push((SyncDirection::Pull, id.to_string(), got));
        held.insert(id.clone(), got);
        report.fetched += 1;
    }
    if let Some(budget) = keep.budget {
        let spare: Vec<StorageKey> = held
            .keys()
            .filter(|k| crate::packed::is_content_pack(k.as_str()) && !wanted.contains_key(*k) && on_remote.contains(*k))
            .cloned()
            .collect();
        for key in spare {
            if bytes(&held) <= budget {
                break;
            }
            local.delete_sealed(key.as_path()).await?;
            held.remove(&key);
            report.evicted += 1;
        }
    }
    report.held = bytes(&held);
    // Over the room with nothing left to let go: what it holds is the index
    // and what its whole pins keep, so each of those settings keeps more than
    // fits.
    if keep.budget.is_some_and(|b| report.held > b) {
        for (id, paths) in &wanted {
            if held.contains_key(id) {
                short.extend(paths.iter().filter_map(|p| (keep.whole)(p)));
            }
        }
        if short.is_empty() {
            // The index alone: no setting keeps less, and the notice says so.
            short.insert(String::new());
        }
    }
    report.short = short.into_iter().collect();
    Ok(report)
}

/// Every leaf `(key, modified)` on a store, recursing into the directory entries
/// its `list_sealed` reports, and how many keys it listed were refused.
///
/// A filesystem backend lists one level and returns `is_dir` entries, so a flat
/// `list_sealed("")` misses everything nested. This walks the tree in
/// storage-key space, one `list_sealed` per directory. A peer store never
/// reports `is_dir` — the serving side walks its own tree and answers with
/// every leaf in one round trip (see `UserStore::list_sealed`), so for a peer
/// the loop below runs exactly once.
///
/// **The admission of a pass** (kotton #265). A listing is what the other
/// side chose to answer, and every key in it becomes a read on one side and
/// a write on the other, so each key, a directory's as well as a leaf's, is
/// parsed into a [`StorageKey`] here, before anything is built from it. A key
/// that is not canonical (`../x`, `./_pack/i-1`, `/_pack/i-1`, a directory
/// marker such as `_pack/`) is refused: named in the log, counted, and never
/// read, written or descended into. Nothing after this point reads a key
/// past a leading `/` or a `.`: there is none to read past.
async fn list_sealed_recursive(
    store: &dyn SyncableStore,
    side: &str,
) -> Result<(BTreeMap<StorageKey, Option<u64>>, u32)> {
    let mut out = BTreeMap::new();
    let mut refused: u32 = 0;
    let mut queue: Vec<String> = vec![String::new()];
    while let Some(prefix) = queue.pop() {
        for entry in store.list_sealed(Path::new(&prefix)).await? {
            let Some(key) = admit(&entry.key, side) else {
                refused += 1;
                continue;
            };
            if entry.is_dir {
                queue.push(key.to_string());
            } else {
                out.insert(key, entry.modified);
            }
        }
    }
    Ok((out, refused))
}

/// `key`, admitted, or `None` with the refusal in the log, naming where the
/// key came from.
fn admit(key: &str, side: &str) -> Option<StorageKey> {
    match StorageKey::parse(key) {
        Ok(key) => Some(key),
        Err(refused) => {
            tracing::warn!(from = side, "sync: {refused}; nothing is read or written under it");
            None
        }
    }
}

/// Move one object between stores as a **sealed blob**, returning its size.
///
/// The read and the write both go through the sealed view, so the envelope
/// crosses verbatim: nothing is decrypted on the way out and nothing is sealed
/// on the way in. This is the single place a sync transfer touches object bytes,
/// which is what makes *sync moves sealed bytes* checkable by inspection.
///
/// The reported size is the sealed length (plaintext plus the per-object DEK
/// header and AEAD tag) — what actually crossed the link.
///
/// It takes a [`StorageKey`], so the key it reads and writes was admitted
/// where it entered the pass.
async fn transfer_sealed(
    from: &dyn SyncableStore,
    to: &dyn SyncableStore,
    key: &StorageKey,
) -> Result<u64> {
    let blob = from.get_sealed(key.as_path()).await?;
    let bytes = blob.len() as u64;
    to.put_sealed(key.as_path(), &blob).await?;
    Ok(bytes)
}

#[cfg(test)]
mod keep_tests {
    use super::*;
    use crate::runtime::{pack_mount, UserKeys};
    use kotton_crypto::derive_cek;
    use kotton_wire::remote::{KeyFormat, RemoteBackend, RemoteConfig};
    use std::sync::Arc;

    fn noise(len: usize, seed: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        let mut state = seed;
        while out.len() < len {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            out.extend_from_slice(&state.to_le_bytes());
        }
        out.truncate(len);
        out
    }

    /// A device of alice's, writing as `writer`.
    fn device(dir: &tempfile::TempDir, writer: &str) -> UserStore {
        UserStore::create(
            "alice",
            "did:key:zAlice",
            dir.path().to_path_buf(),
            UserKeys::new(Some(derive_cek(&[42u8; 32]))).with_log(writer, &[7u8; 32]),
            &crate::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap()
    }

    /// A drive: a keyless tree that takes sealed bytes, as a vault keeps one.
    fn drive(dir: &tempfile::TempDir) -> Arc<dyn SyncableStore> {
        crate::stack::build_local_store(dir.path().to_path_buf(), kotton_fs::OsFilesystem, None, None, None, KeyFormat::Blinded)
    }

    fn reach(rt: &UserStore, drive: &Arc<dyn SyncableStore>, at: &tempfile::TempDir) {
        rt.add_remote(
            "drive".into(),
            Arc::clone(drive),
            RemoteConfig { backend: RemoteBackend::Local { path: at.path().to_path_buf() }, cache_dir: None, key_format: KeyFormat::Blinded },
        )
        .unwrap();
    }

    /// Keeps `/photos` whole, the rest of the person's tree on demand, and
    /// the daemon's own objects whole by no setting.
    fn photos_whole(budget: Option<u64>) -> Keep {
        Keep {
            whole: Box::new(|key: &str| match key.strip_prefix("files/") {
                Some(p) if p.starts_with("photos/") => Some("personal:/photos".to_string()),
                Some(_) => None,
                None => Some(String::new()),
            }),
            budget,
        }
    }

    struct FromDrive(Arc<dyn SyncableStore>);

    #[async_trait::async_trait]
    impl crate::fetch::PackSource for FromDrive {
        async fn fetch(&self, _user_id: &str, key: &str) -> anyhow::Result<Option<bytes::Bytes>> {
            Ok(self.0.get_sealed(Path::new(key)).await.ok())
        }
    }

    /// **A key a remote lists that is not canonical is refused before any
    /// path is built from it** (kotton #265). The remote here is a memory
    /// store, which lists keys exactly as they were put, so it serves
    /// `../x`, `./_pack/i-1`, `/_pack/i-1` and `_pack/` as a hostile drive
    /// would. Before the admission the pull wrote `../x` beside the device's
    /// mount. Now the pass completes, pulls nothing, writes nothing outside
    /// the mount or into its pack directory, and counts each refused key
    /// among those it skipped; and the serving verbs refuse the same keys.
    #[tokio::test]
    async fn a_listed_key_that_is_not_canonical_is_refused_and_lands_nowhere() {
        let outer = tempfile::tempdir().unwrap();
        let home = outer.path().join("alice");
        std::fs::create_dir_all(&home).unwrap();
        let a = UserStore::create(
            "alice",
            "did:key:zAlice",
            home.clone(),
            UserKeys::new(Some(derive_cek(&[42u8; 32]))).with_log("did:key:zA", &[7u8; 32]),
            &crate::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();
        let hostile = ["../x", "./_pack/i-1", "/_pack/i-1", "_pack/"];
        use kotton_sys::store::SealedObjectAccess as _;
        let served = crate::MemoryObjectStorage::new();
        for key in hostile {
            served.put_sealed(Path::new(key), b"served").await.unwrap();
        }
        a.add_remote(
            "drive".into(),
            Arc::new(served),
            RemoteConfig { backend: RemoteBackend::Local { path: outer.path().join("unused") }, cache_dir: None, key_format: KeyFormat::Blinded },
        )
        .unwrap();
        let before: BTreeSet<_> = std::fs::read_dir(&home).unwrap().map(|e| e.unwrap().file_name()).collect();

        let result = a.sync_mount("local", "drive", Some(SyncDirection::Pull), Outbound::Everything).await;

        assert!(!home.join("x").exists(), "`../x` was written beside the mount: {result:?}");
        let after: BTreeSet<_> = std::fs::read_dir(&home).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(after, before, "the pass changed the tree outside the mount");
        assert!(!home.join("data").join("_pack").join("i-1").exists(), "a served key aliased onto the pack directory");
        let result = result.expect("a pass that refuses keys still completes");
        assert_eq!((result.pulled, result.transfers.len()), (0, 0), "{result:?}");
        let held = a.list_sealed("local", "").await.unwrap().len();
        assert_eq!(result.skipped as usize, held + hostile.len(), "each refused key is counted: {result:?}");

        for key in hostile {
            assert!(a.write_sealed("local", key, b"sealed").await.is_err(), "write_sealed admitted {key:?}");
            assert!(a.read_sealed("local", key).await.is_err(), "read_sealed admitted {key:?}");
        }
        assert!(!home.join("x").exists(), "write_sealed wrote `../x` beside the mount");
    }

    /// **Nothing a setting says withholds the index** (kotton #171's rule: a
    /// device fetches a drive's index before it consults any setting or
    /// claim). A device whose settings keep nothing whole — not even the
    /// daemon's own objects — with no room at all still pulls every index
    /// pack the drive holds, the ones that carry the record segments and so
    /// every whole-keeper claim, and knows every file; it fetches no content
    /// pack. The first step of a pass reads only whether there is a `Keep`,
    /// never what it says.
    #[tokio::test]
    async fn nothing_a_setting_says_withholds_the_index() {
        let (dir_a, dir_b, dir_drive) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (a, b) = (device(&dir_a, "did:key:zA"), device(&dir_b, "did:key:zB"));
        let the_drive = drive(&dir_drive);
        reach(&a, &the_drive, &dir_drive);
        reach(&b, &the_drive, &dir_drive);
        a.write_file("/photos/a.jpg", &noise(64 * 1024, 2)).await.unwrap();
        pack_mount(&*a.get_remote("local").unwrap(), "local").await.unwrap().unwrap();
        a.write_file("/notes/b.md", b"a note").await.unwrap();
        pack_mount(&*a.get_remote("local").unwrap(), "local").await.unwrap().unwrap();
        a.sync_mount("local", "drive", Some(SyncDirection::Push), Outbound::PacksOnly).await.unwrap();

        let nothing = Keep { whole: Box::new(|_: &str| None), budget: Some(0) };
        let (_, report) = b
            .sync_mount_keeping("local", "drive", Some(SyncDirection::Pull), Outbound::PacksOnly, Some(&nothing))
            .await
            .unwrap();
        assert_eq!(report.expect("a keeping pass reports").fetched, 0);
        let packs = |rt: Arc<dyn SyncableStore>| async move {
            rt.list_sealed(Path::new(crate::packed::PACK_PREFIX)).await.unwrap().into_iter().map(|m| m.key).collect::<BTreeSet<String>>()
        };
        let (on_drive, on_b) = (packs(Arc::clone(&the_drive)).await, packs(b.get_remote("local").unwrap()).await);
        let index: BTreeSet<&String> = on_drive.iter().filter(|k| !crate::packed::is_content_pack(k)).collect();
        assert!(!index.is_empty(), "the drive holds no index pack: {on_drive:?}");
        for key in &index {
            assert!(on_b.contains(*key), "an index pack was withheld by what the settings say: {key}");
        }
        assert!(on_b.iter().all(|k| !crate::packed::is_content_pack(k)), "a content pack was kept that nothing keeps: {on_b:?}");
        for (dir, name) in [("/photos", "a.jpg"), ("/notes", "b.md")] {
            let listed = b.list_files(dir).await.unwrap();
            assert!(format!("{listed:?}").contains(name), "the index does not name {dir}/{name}: {listed:?}");
        }
    }

    /// **A pass keeps what the pins keep whole and the index of the rest;
    /// the rest is fetched when it is opened; and the room is held.** A
    /// writes a photo and a note in two passes, and pushes both to the drive.
    /// B, keeping `/photos` whole, pulls the index and the photo's content
    /// pack and not the note's; it lists the note, cannot read it offline,
    /// and reads it once a source is lent — fetched on open, and kept. Then a
    /// budget with room for the index alone: the note's pack, which no pin
    /// keeps, is let go, and the photo's pack, which a pin keeps, is not
    /// fetched again by a fresh device, which names the setting that keeps
    /// less.
    #[tokio::test]
    async fn a_pass_keeps_what_the_pins_keep_whole_and_fetches_the_rest_on_open() {
        let (dir_a, dir_b, dir_c, dir_drive) =
            (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (a, b) = (device(&dir_a, "did:key:zA"), device(&dir_b, "did:key:zB"));
        let the_drive = drive(&dir_drive);
        reach(&a, &the_drive, &dir_drive);
        reach(&b, &the_drive, &dir_drive);

        let photo = noise(64 * 1024, 1);
        a.write_file("/photos/a.jpg", &photo).await.unwrap();
        pack_mount(&*a.get_remote("local").unwrap(), "local").await.unwrap().unwrap();
        a.write_file("/notes/b.md", b"a note").await.unwrap();
        pack_mount(&*a.get_remote("local").unwrap(), "local").await.unwrap().unwrap();
        a.sync_mount("local", "drive", Some(SyncDirection::Push), Outbound::PacksOnly).await.unwrap();

        let (_, report) = b
            .sync_mount_keeping("local", "drive", Some(SyncDirection::Pull), Outbound::PacksOnly, Some(&photos_whole(None)))
            .await
            .unwrap();
        let report = report.expect("a keeping pass reports");
        assert_eq!(report.fetched, 1, "{report:?}");
        assert!(report.short.is_empty(), "{report:?}");
        assert!(b.kept_here("/photos/a.jpg").await.unwrap(), "the photo was not kept");
        assert!(!b.kept_here("/notes/b.md").await.unwrap(), "the note was kept, which nothing pins");
        assert_eq!(b.read_file("/photos/a.jpg").await.unwrap(), photo);
        let listed = b.list_files("/notes").await.unwrap();
        assert!(format!("{listed:?}").contains("b.md"), "the index does not name the note: {listed:?}");
        assert!(b.read_file("/notes/b.md").await.is_err(), "the note read with no drive to fetch it from");

        b.lend_pack_source(Arc::new(FromDrive(Arc::clone(&the_drive))));
        assert_eq!(b.read_file("/notes/b.md").await.unwrap(), b"a note", "fetched on open");
        assert!(b.kept_here("/notes/b.md").await.unwrap(), "what was opened is kept");

        // Room for all B holds but the note's pack, which no pin keeps: it goes.
        let held = |rt: &UserStore| {
            let local = rt.get_remote("local").unwrap();
            async move { local.list_sealed(Path::new(crate::packed::PACK_PREFIX)).await.unwrap().iter().map(|m| m.size).sum::<u64>() }
        };
        let room = held(&b).await - crate::pack::PACK_SIZE as u64;
        let (_, kept) = b
            .sync_mount_keeping("local", "drive", Some(SyncDirection::Pull), Outbound::PacksOnly, Some(&photos_whole(Some(room))))
            .await
            .unwrap();
        let kept = kept.unwrap();
        assert_eq!((kept.evicted, kept.held), (1, room), "{kept:?}");
        assert!(!b.kept_here("/notes/b.md").await.unwrap());
        assert!(b.kept_here("/photos/a.jpg").await.unwrap(), "a pinned pack was let go");
        assert_eq!(b.read_file("/notes/b.md").await.unwrap(), b"a note", "fetched again");

        // A fresh device with room for the index alone: short, and it says
        // which setting keeps less.
        let c = device(&dir_c, "did:key:zC");
        reach(&c, &the_drive, &dir_drive);
        let index_only: u64 = the_drive
            .list_sealed(Path::new(crate::packed::PACK_PREFIX))
            .await
            .unwrap()
            .iter()
            .filter(|m| !crate::packed::is_content_pack(&m.key))
            .map(|m| m.size)
            .sum();
        assert!(index_only < crate::pack::PACK_SIZE as u64, "an index pack was sealed at the full size: {index_only}");
        let (_, short) = c
            .sync_mount_keeping("local", "drive", Some(SyncDirection::Pull), Outbound::PacksOnly, Some(&photos_whole(Some(index_only))))
            .await
            .unwrap();
        let short = short.unwrap();
        assert_eq!(short.fetched, 0, "{short:?}");
        assert_eq!(short.short, ["personal:/photos"], "{short:?}");
        assert_eq!(short.wanted, crate::pack::PACK_SIZE as u64);
        assert!(!c.kept_here("/photos/a.jpg").await.unwrap());
    }
}
