// SPDX-License-Identifier: AGPL-3.0-or-later
//! Local KEL storage — RFC-0038 Phase 4 (minimal own-identity version).
//!
//! The user's own key event log: an append-only chain at
//! `users/{user_id}/identity/kel.json`. Enough to resolve *own* identity's current
//! key **locally, with no network** (honoring the machine-count invariant). The
//! always-synced identity-core packet (RFC-0034) — which also carries *other*
//! issuers' KELs so their grants can be verified — is the later upgrade.

use anyhow::{Context, Result};
use kotton_wire::kel::KelEvent;
use kotton_crypto::kel_verify::{resolve_current_key, LocalArbiter};
use std::path::{Path, PathBuf};

fn kel_path(base_dir: &Path, user_id: &str) -> PathBuf {
    base_dir
        .join("users")
        .join(user_id)
        .join("identity")
        .join("kel.json")
}

/// Load the user's KEL chain (empty if there is none yet).
pub fn load_chain(base_dir: &Path, user_id: &str) -> Result<Vec<KelEvent>> {
    let path = kel_path(base_dir, user_id);
    match std::fs::read_to_string(&path) {
        Ok(json) => serde_json::from_str(&json).with_context(|| format!("parse {path:?}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(anyhow::Error::new(e).context(format!("read {path:?}"))),
    }
}

/// Append an event to the user's KEL chain (creating the file if needed). The
/// caller is responsible for the event being a valid continuation; `resolve_*`
/// validates the whole chain on read.
///
/// # Why this writes a temporary file and renames it
///
/// The chain is one JSON array, so appending rewrites the whole file. A plain
/// `write` to the live path truncates it first, and a crash — or a full disk —
/// between the truncate and the last byte leaves a partial array that will not
/// parse. `load_chain` then returns an error, `resolve_current_key_for` cannot
/// resolve, and the identity is gone.
///
/// That is not a scale concern to be deferred. It is reachable at three events,
/// the window is every `RotationAddRecovery` and every recovery, and the file is
/// the *only* local record of the identity's key history — on a device that has
/// lost the rest of its fleet, this file **is** the identity
/// (`TASK-recovery-on-a-device-with-no-chain-has-nothing-to-verify-against` is
/// the whole story of what it costs to be without it).
///
/// Write-then-rename makes the replacement atomic on POSIX: a reader sees either
/// the old chain or the new one. The `sync_all` before the rename is what makes
/// that true across a power loss rather than only across a process crash — a
/// rename can otherwise reach the disk before the bytes it points at.
///
/// This does **not** fix the O(n) rewrite. That is
/// [`IDEA-the-key-log-has-no-answer-for-a-large-fleet`], and it is deliberately
/// separate: the rewrite is a cost that grows, and this is a correctness bug that
/// is already here. Fixing the format would fix both, and would need the ruling
/// that record asks for first.
pub fn append_event(base_dir: &Path, user_id: &str, event: &KelEvent) -> Result<()> {
    let mut chain = load_chain(base_dir, user_id)?;
    chain.push(event.clone());
    save_chain(base_dir, user_id, &chain)
}

/// Adopt a whole chain, replacing whatever was stored.
///
/// For the two moments a device holds a chain it did not build event by event:
/// enrolment, and recovery onto a device that fetched it (`RFC-0081`). The
/// caller owns validity, as with [`append_event`] — replay it first.
pub fn save_chain(base_dir: &Path, user_id: &str, chain: &[KelEvent]) -> Result<()> {
    let path = kel_path(base_dir, user_id);
    if let Some(parent) = path.parent() {
        kotton_common::fs::create_dir_all_owner_only(parent)?;
    }
    let json = serde_json::to_string_pretty(chain).context("serialise KEL")?;

    // Same directory as the target: `rename` is only atomic within a filesystem,
    // and a temp dir can be on another one.
    let tmp = path.with_extension("json.tmp");
    {
        use std::io::Write as _;
        let mut f = std::fs::File::create(&tmp).with_context(|| format!("create {tmp:?}"))?;
        f.write_all(json.as_bytes())
            .with_context(|| format!("write {tmp:?}"))?;
        f.sync_all().with_context(|| format!("sync {tmp:?}"))?;
    }
    std::fs::rename(&tmp, &path).with_context(|| format!("rename {tmp:?} -> {path:?}"))?;
    Ok(())
}

// `recover_to_device_key` lived here from 2026-08-23 to 2026-08-24 and was removed as a
// duplicate: `kuserd`'s `rotate_identity_via_mnemonic` already did the same work, predates it,
// and is the one wired to a caller. Two implementations of a rotation is exactly the shape
// that produced the reserve-index bug — the copy counted only mnemonic recoveries where the
// original counted both, so an identity that had used a guardian recovery would have built its
// next rotation against the wrong rung.
//
// What survives is the part that was genuinely missing: `kel_verify::next_recovery_index`,
// which both would have needed and which now has the guardian case under test. Where the verb
// body *should* live — a domain crate rather than the daemon — is `RFC-0080`'s question, and
// moving it belongs to that restructure rather than to this record.

/// Where `user_id` keeps a contact's key log. One file per contact, named by
/// the AID with the characters a path cannot carry replaced, under the user's
/// own identity directory — a contact's chain is the user's knowledge of that
/// contact, not the contact's data.
fn contact_kel_path(base_dir: &Path, user_id: &str, contact_aid: &str) -> PathBuf {
    let safe: String = contact_aid
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    base_dir
        .join("users")
        .join(user_id)
        .join("identity")
        .join("contacts")
        .join(format!("{safe}.kel.json"))
}

/// Keep a contact's key log as it arrived — at pairing (RFC-0022), signed over
/// the ceremony transcript — so their current key can be resolved later the
/// way the user's own is, and a rotation they announce can be replayed against
/// it (RFC-0038's contact KEL sync). The second half is built: a log that comes
/// with the contact's reach note and continues this one replaces it, with the
/// key it proves (`TASK-a-rotated-persons-contacts-keep-the-key-it-retired`).
pub fn save_contact_chain(
    base_dir: &Path,
    user_id: &str,
    contact_aid: &str,
    chain: &[KelEvent],
) -> Result<()> {
    let path = contact_kel_path(base_dir, user_id, contact_aid);
    if let Some(parent) = path.parent() {
        kotton_common::fs::create_dir_all_owner_only(parent).with_context(|| format!("create {parent:?}"))?;
    }
    let json = serde_json::to_string_pretty(chain).context("serialize contact KEL")?;
    std::fs::write(&path, json).with_context(|| format!("write {path:?}"))
}

/// A contact's stored key log (empty if none was kept).
pub fn load_contact_chain(base_dir: &Path, user_id: &str, contact_aid: &str) -> Result<Vec<KelEvent>> {
    let path = contact_kel_path(base_dir, user_id, contact_aid);
    match std::fs::read_to_string(&path) {
        Ok(json) => serde_json::from_str(&json).with_context(|| format!("parse {path:?}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(anyhow::Error::new(e).context(format!("read {path:?}"))),
    }
}

/// A contact's current key by replaying the chain kept for them. `Ok(None)` when
/// no chain was kept (a `did:key` contact carries its key in its name).
pub fn resolve_contact_key(base_dir: &Path, user_id: &str, contact_aid: &str) -> Result<Option<[u8; 32]>> {
    let chain = load_contact_chain(base_dir, user_id, contact_aid)?;
    if chain.is_empty() {
        return Ok(None);
    }
    resolve_current_key(&chain, &LocalArbiter, false)
        .map(Some)
        .map_err(|e| anyhow::anyhow!("contact KEL replay failed: {e}"))
}

/// Resolve the user's current authoritative key by replaying their stored KEL.
/// `Ok(None)` if no KEL exists yet; `Err` if the chain fails validation.
pub fn resolve_current_key_for(
    base_dir: &Path,
    user_id: &str,
    has_other_factors: bool,
) -> Result<Option<[u8; 32]>> {
    let chain = load_chain(base_dir, user_id)?;
    if chain.is_empty() {
        return Ok(None);
    }
    resolve_current_key(&chain, &LocalArbiter, has_other_factors)
        .map(Some)
        .map_err(|e| anyhow::anyhow!("KEL replay failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use kotton_crypto::kdf::derive_kel_recovery_key;
    use kotton_crypto::kel_verify::{build_inception, kel_recovery_pubkey};

    #[test]
    fn append_load_resolve_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let user = "alice";

        // No KEL yet → empty chain, no current key.
        assert!(load_chain(dir.path(), user).unwrap().is_empty());
        assert!(resolve_current_key_for(dir.path(), user, false)
            .unwrap()
            .is_none());

        // Emit + store an inception.
        let seed = [42u8; 32];
        let group = SigningKey::from_bytes(&[1u8; 32]);
        let krec0 = kel_recovery_pubkey(&derive_kel_recovery_key(&seed, 0));
        let inc = build_inception(&group, &[krec0]);
        append_event(dir.path(), user, &inc).unwrap();

        // Load round-trips; resolve returns the inception's group key.
        let chain = load_chain(dir.path(), user).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0], inc);
        assert_eq!(
            resolve_current_key_for(dir.path(), user, false)
                .unwrap()
                .unwrap(),
            group.verifying_key().to_bytes()
        );
    }

    /// A half-written chain is never what a reader finds.
    ///
    /// The property, stated as the failure it prevents: `write` truncates before it
    /// fills, so a crash mid-append used to be able to leave a partial JSON array —
    /// unparseable, and therefore an identity with no key history. This asserts the
    /// mechanism that makes that unreachable, by checking no leftover temporary
    /// file remains and the chain still parses after repeated appends.
    ///
    /// It cannot crash the process mid-write, so it pins what it can: that the
    /// append is a rename rather than an in-place rewrite (no `.tmp` survives), and
    /// that the visible file is always a complete chain.
    #[test]
    fn an_append_leaves_a_whole_chain_and_no_debris() {
        let dir = tempfile::tempdir().unwrap();
        let user = "alice";
        let inc = kotton_crypto::kel_verify::build_user_inception(&[1u8; 32]);
        for _ in 0..3 {
            append_event(dir.path(), user, &inc).unwrap();
            // Always parses — never a partial array.
            let chain = load_chain(dir.path(), user).unwrap();
            assert!(!chain.is_empty());
            // And nothing is left behind for the next reader to trip over.
            let tmp = kel_path(dir.path(), user).with_extension("json.tmp");
            assert!(!tmp.exists(), "a temporary chain file survived the append");
        }
        assert_eq!(load_chain(dir.path(), user).unwrap().len(), 3);
    }
}
