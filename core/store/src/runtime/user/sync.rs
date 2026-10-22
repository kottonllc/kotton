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
    fn admits(self, key: &str) -> bool {
        match self {
            Outbound::Everything => true,
            Outbound::PacksOnly => {
                let key = key.trim_start_matches('/');
                [crate::packed::PACK_PREFIX, crate::superblock::SUPERBLOCK_PREFIX]
                    .iter()
                    .any(|prefix| {
                        key.strip_prefix(prefix).is_some_and(|rest| rest.starts_with('/'))
                    })
            }
        }
    }
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
        let local = self
            .get_remote(local_mount)
            .ok_or_else(|| anyhow!("Local mount '{}' not found", local_mount))?;
        let remote = self
            .get_remote(remote_name)
            .ok_or_else(|| anyhow!("Remote '{}' not found", remote_name))?;

        // Every leaf key on each side, recursing subdirectories — a filesystem
        // backend's `list` is one level deep, so a flat listing would silently
        // skip anything nested (e.g. `notes/2026/trip.md`).
        let local_map: BTreeMap<String, Option<u64>> =
            list_sealed_recursive(local.as_ref()).await?;
        let remote_map: BTreeMap<String, Option<u64>> =
            list_sealed_recursive(remote.as_ref()).await?;

        // Union of all object keys across both sides.
        let all_keys: BTreeSet<String> =
            local_map.keys().chain(remote_map.keys()).cloned().collect();

        let mut pushed: u32 = 0;
        let mut pulled: u32 = 0;
        let mut skipped: u32 = 0;
        let mut withheld: u32 = 0;
        let mut transfers: Vec<(SyncDirection, String, u64)> = Vec::new();

        for key in &all_keys {
            let key_path = Path::new(key.as_str());
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

            if push {
                let bytes = transfer_sealed(local.as_ref(), remote.as_ref(), key_path).await?;
                pushed += 1;
                transfers.push((SyncDirection::Push, key.clone(), bytes));
            } else if pull {
                let bytes = transfer_sealed(remote.as_ref(), local.as_ref(), key_path).await?;
                pulled += 1;
                transfers.push((SyncDirection::Pull, key.clone(), bytes));
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

        Ok(SyncResult {
            pushed,
            pulled,
            skipped,
            transfers,
        })
    }
}

/// Every leaf `(key, modified)` on a store, recursing into the directory entries
/// its `list_sealed` reports.
///
/// A filesystem backend lists one level and returns `is_dir` entries, so a flat
/// `list_sealed("")` misses everything nested. This walks the tree in
/// storage-key space, one `list_sealed` per directory. A peer store never
/// reports `is_dir` — the serving side walks its own tree and answers with
/// every leaf in one round trip (see `UserRuntime::list_sealed`), so for a peer
/// the loop below runs exactly once. Directory-marker keys (trailing `/`) are
/// skipped: they are never readable objects.
async fn list_sealed_recursive(
    store: &dyn SyncableStore,
) -> Result<BTreeMap<String, Option<u64>>> {
    let mut out = BTreeMap::new();
    let mut queue: Vec<String> = vec![String::new()];
    while let Some(prefix) = queue.pop() {
        for entry in store.list_sealed(Path::new(&prefix)).await? {
            if entry.key.ends_with('/') {
                continue;
            }
            if entry.is_dir {
                queue.push(entry.key);
            } else {
                out.insert(entry.key, entry.modified);
            }
        }
    }
    Ok(out)
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
async fn transfer_sealed(
    from: &dyn SyncableStore,
    to: &dyn SyncableStore,
    key: &Path,
) -> Result<u64> {
    let blob = from.get_sealed(key).await?;
    let bytes = blob.len() as u64;
    to.put_sealed(key, &blob).await?;
    Ok(bytes)
}
