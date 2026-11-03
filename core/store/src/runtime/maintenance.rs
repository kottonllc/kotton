// SPDX-License-Identifier: AGPL-3.0-or-later
//! Mount maintenance — packing, compaction, and scan recovery.
//!
//! Each takes the store it acts on rather than a runtime holding every mount,
//! which is least reach in its smallest form: a function that packs
//! one mount should not be able to reach a second user's.

use anyhow::{Context, Result};
use kotton_sys::store::{CompactSummary, PackSummary, ScanRecovery, SyncableStore};

/// Run one packing pass on a mount: fold loose objects into packs.
///
/// Returns `None` for a store with no pack layer.
///
/// Explicitly triggered only, and deliberately **not** part of any automatic
/// path yet: until pack-level sync lands, two devices packing the same synced
/// mount independently produce manifests that object-level sync cannot merge.
/// Nothing is destroyed, but packed names can stop resolving on the other
/// device.
pub async fn pack_mount(store: &dyn SyncableStore, name: &str) -> Result<Option<PackSummary>> {
    let summary = store
        .pack_loose()
        .await
        .with_context(|| format!("packing pass on mount '{name}'"))?;
    if let Some(s) = &summary {
        tracing::info!(
            mount = %name,
            files = s.files_packed,
            packs = s.packs_written,
            generation = ?s.generation,
            "RFC-0045: packing pass complete"
        );
    }
    Ok(summary)
}

/// Run one compaction pass on a mount: sweep packs no committed manifest
/// references, and merge sparse packs into fewer dense ones — reading the
/// replacements back and committing before anything is unlinked.
///
/// Returns `None` for a store with no pack layer. Compaction must read chunks to
/// know which are live, so a blind storage node can never run it.
///
/// Explicitly triggered only, and for a second reason beyond [`pack_mount`]'s: a
/// pack that no committed manifest references is treated as reclaimable, so a
/// packing pass running concurrently — whose packs are written but not yet
/// committed — is indistinguishable from crash debris. The two passes must not
/// overlap on one mount. Both being explicit triggers is what guarantees that
/// today; automating either requires a mount lock first.
pub async fn compact_mount(
    store: &dyn SyncableStore,
    name: &str,
) -> Result<Option<CompactSummary>> {
    let summary = store
        .compact()
        .await
        .with_context(|| format!("compaction pass on mount '{name}'"))?;
    if let Some(s) = &summary {
        tracing::info!(
            mount = %name,
            rewritten = s.packs_rewritten,
            written = s.packs_written,
            retired = s.packs_retired,
            chunks_kept = s.chunks_kept,
            unadmitted = s.packs_unadmitted,
            generation = ?s.generation,
            "RFC-0045: compaction pass complete"
        );
    }
    Ok(summary)
}

/// Rebuild a mount's root pointer by scanning its packs, for a
/// store whose superblock is missing or unreadable.
///
/// This is the operation behind "a device with the mnemonic and the pack set can
/// reconstruct every file with no external index" — the storage half of
/// continuity. Returns `None` for a store with no pack layer, or when a
/// superblock still loads: recovery never competes with a working root pointer.
pub async fn recover_mount(
    store: &dyn SyncableStore,
    name: &str,
) -> Result<Option<ScanRecovery>> {
    let recovery = store
        .recover_by_scan()
        .await
        .with_context(|| format!("scan recovery on mount '{name}'"))?;
    if let Some(r) = &recovery {
        tracing::info!(
            mount = %name,
            packs = r.packs_scanned,
            manifests = r.manifests_found,
            files = r.files_recovered,
            generation = r.generation,
            "RFC-0045: scan recovery complete"
        );
    }
    Ok(recovery)
}
