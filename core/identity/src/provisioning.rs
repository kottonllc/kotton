// SPDX-License-Identifier: AGPL-3.0-or-later
//! Provisioning a user on a device: their keys, roots, vault and recovery.
//!
//! Arrived from `05_runtime` on 2026-08-22 (RFC-0080). This crate's `lib.rs`
//! had claimed `create_user` and `logout_user` for a while before the code got
//! here — a doc describing an architecture the tree did not have yet.
//!
//! ## What is here, and what is deliberately not
//!
//! Everything here is about a user's **identity**: the BIP-39 credentials they
//! are generated with, the operational roots derived from them, the keychain
//! labels those live under, the PIN vault that seals them at rest, and the
//! recovery bundle that survives losing the device.
//!
//! What is **not** here is standing up a user's *store*. Creating a user
//! ultimately produces both an identity and somewhere to put their data, and
//! those two were one file until they were measured: **the 21 functions here
//! call the store-creating ones exactly zero times.** A file can look like one
//! concern for a long time when nothing forces the question.
//!
//! The machine appears only as [`crate::ProvisioningHost`] — nine named
//! capabilities rather than a runtime handle, which is what let this move at
//! all.

use crate::ProvisioningHost;
use kotton_sys::secret::{attempt_limiting_for, AttemptLimiting};
use kotton_crypto::provider::recovery::RecoveryCopy;
use kotton_crypto::OperationalRoots;

/// The file a user's PIN vault is written to, under `users/<id>/`.
///
/// One constant because this filename is both written and probed, and it
/// drifted once already: `set_user_pin` moved from `wrapped_seed.json` to
/// `vault.json` at the RFC-0039 cutover, while the two callers reporting
/// whether a PIN was set kept probing the old name — so `pin_set` read
/// `false` for every user who had one. Anything asking "does this user have a
/// PIN?" goes through [`pin_is_set`].
/// Result from creating a new user.
///
/// Stays because it is the one type here that is not a file's schema: nothing
/// persists it. It is what `create_user` hands back, and it travels to
/// `identity` with that function.
///
/// **The recovery key is in here in plaintext and is meant to be.** It is a
/// BIP-39 mnemonic that exists in memory exactly once, on the way to being
/// shown to the user, and is never written down by us — which is the whole
/// point of it. Whoever moves this must not add `Serialize`.
#[derive(Debug, Clone)]
pub struct UserCreationResult {
    pub user_id: String,
    pub did: String,
    pub device_fingerprint: String,
}

pub const VAULT_FILE: &str = "vault.json";

/// A vault sealed around a rotated key **before** the rotation is appended, and
/// renamed over [`VAULT_FILE`] once it is.
///
/// The key log is append-only, so the one order in which a rotation and its vault
/// cannot disagree is: seal the new vault first, append, then rename. A failure
/// before the append leaves nothing changed; a crash between the append and the
/// rename leaves this file, and the next unlock finishes the rename
/// ([`unlock_with_pin`]). It is sealed exactly as the vault is — the same
/// credential, the same binding, the same file tree — and it lives only for that
/// window (`TASK-a-rotation-whose-vault-reseal-fails-has-landed-with-the-vault-sealing-the-retired-key`).
pub const STAGED_VAULT_FILE: &str = "vault.next.json";

/// The sealed device-binding secret for a user, if they have opted in.
///
/// Per-user rather than per-device, so two identities on one machine get
/// separate binding secrets (RFC-0056 R4) even though both come from the same
/// chip.
pub const BINDING_FILE: &str = "device_binding.bin";

/// The sealed binding secret the roots index's **routing half** is sealed
/// under, for a user on a device whose hardware can hold one.
///
/// Deliberately **not** [`BINDING_FILE`]. That one is the vault's, it is opt-in
/// because clearing the TPM leaves the person behind their recovery phrase, and
/// it may carry an auth policy that wants the daily credential — which would
/// make it useless for a file that has to be read before anybody has typed
/// anything. This one has no auth policy, is created on first use wherever the
/// platform allows, and protects a cache: losing it costs one rebuild of the
/// routing half at the next unlock
/// (`TASK-the-routing-half-of-the-roots-index-seals-under-the-devices-binding`).
pub const ROUTING_BINDING_FILE: &str = "routing_binding.bin";
use serde::{Deserialize, Serialize};
use anyhow::{anyhow, Context, Result};
use kotton_common::crypto::kdf_labels;
use kotton_crypto::{
    derive_cek, open_vault, seal_vault, unwrap_cek_recovery,
    unwrap_master_secret_recovery, wrap_cek_recovery,
    wrap_master_secret_recovery, AtRestVault, CekRecovery,
};
use kotton_sys::secret::{DeviceBinding, SecretsStore};
use std::path::{Path, PathBuf};

// `generate_user_credentials` and `derive_aid_from_mnemonic` were deleted on
// 2026-08-28. They minted an identity whose AID was the digest of an inception
// built from the mnemonic, and reconstructed that AID from the phrase — which is
// what made the phrase *be* the identity, and therefore unrotatable.
//
// An identity is now a random key with an AID that derives from nothing anybody
// holds. A phrase does not compute it; it *verifies* it, against the recovery
// authorities an establishment event pre-commits. See
// `IDEA-a-public-identifier-should-not-derive-from-a-secret`.

/// The mnemonic-sealed recovery copies of the three random operational roots,
/// stored at `users/{user_id}/recovery.json`.
///
/// All three, which is RFC-0066's "each wrapped under `U` at rest and under
/// `KEK_r` as a recovery copy" — `wrap_identity_recovery` existed, tested, with
/// nothing calling it, because the identity key used to re-derive from the phrase
/// and needed no copy. Making it random is what gave that function its caller.
///
/// A wrapped copy is not a derivation, and the distinction is the whole design: the
/// AID is the digest of an inception event and still comes from nothing anybody
/// holds, while the key it installs has a backup. The phrase does not *make* the
/// identity; it opens a box that happens to contain a key to it.
///
/// The copy is a convenience, not the recovery model. Recovery proper is the
/// pre-rotation ladder — a reserve key signs a rotation to a *fresh* random key —
/// and that is the path that works when this file is gone, which is the case the
/// ladder exists for. See `IDEA-should-recovery-restore-the-key-or-rotate-it`.
#[derive(Serialize, Deserialize)]
struct RecoveryBundle {
    master_secret: RecoveryCopy,
    /// **Never read.** Bundles written before 2026-09-04 carry a sealed copy of
    /// the identity key; `DEC-0051` rules that a phrase rotates the operational
    /// root and never re-installs it, so nothing opens this field and nothing
    /// writes it. It is kept so an old bundle still parses for its data roots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity_key: Option<RecoveryCopy>,
    cek: CekRecovery,
}

/// Every phrase's sealed copy of the data roots, keyed by the reserve pubkey
/// that opens it — the file at `users/{user_id}/recovery.json`.
///
/// This is the fix for `TASK-a-second-recovery-phrase-silently-disinherits-the-first`.
/// The file used to hold a single [`RecoveryBundle`], so a second
/// `add_recovery_phrase` overwrote the first phrase's copy: the KEL committed
/// two recovery authorities while only the latest could still open the data, and
/// nothing said so. The sealed half is now per-authority, keyed by
/// `hex(K_rec[0])` — the same reserve pubkey the KEL commits in `recovery_set` —
/// so the set of phrases that can unseal the roots grows with the set the KEL
/// commits, by construction rather than by remembering to.
#[derive(Serialize, Deserialize)]
struct RecoveryBundleSet {
    /// `hex(reserve pubkey)` → the copy that key opens. The map key is the join
    /// to the KEL: a phrase derives its `K_rec[0]`, and the copy it can open is
    /// the one filed under that pubkey.
    copies: std::collections::BTreeMap<String, RecoveryBundle>,
    /// A pre-fix single bundle whose authority is not recorded — it was written
    /// before this file was a keyed set, so which phrase sealed it is unknown
    /// without that phrase. Kept as a fallback so a phrase written before this
    /// change still opens its data; never written by new code, and retired the
    /// next time that phrase's copy is written under its key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    legacy: Option<RecoveryBundle>,
}

/// The `hex(K_rec[0])` a phrase seed maps to — the reserve pubkey the KEL commits
/// for it, and the key its sealed copy is filed under. Deriving it here from the
/// same primitives `add_recovery_phrase` uses keeps the two halves' keys equal by
/// construction.
fn authority_key_hex(seed32: &[u8; 32]) -> String {
    let krec0 = kotton_crypto::kel_verify::kel_recovery_pubkey(
        &kotton_crypto::kdf::derive_kel_recovery_key(seed32, 0),
    );
    hex::encode(krec0)
}

/// Load the recovery file as a keyed set, migrating a legacy single bundle into
/// the `legacy` slot. `Ok(None)` means no file yet.
fn load_recovery_set(
    base_dir: &std::path::Path,
    user_id: &str,
) -> Result<Option<RecoveryBundleSet>> {
    let path = recovery_bundle_path(base_dir, user_id);
    let json = match std::fs::read_to_string(&path) {
        Ok(j) => j,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(anyhow::Error::new(e).context(format!("read {path:?}"))),
    };
    // The keyed set first; a legacy bare bundle (no `copies`) falls through to
    // the `legacy` slot so its one phrase keeps working.
    if let Ok(set) = serde_json::from_str::<RecoveryBundleSet>(&json) {
        return Ok(Some(set));
    }
    let legacy: RecoveryBundle =
        serde_json::from_str(&json).context("recovery file is neither a keyed set nor a bundle")?;
    Ok(Some(RecoveryBundleSet {
        copies: std::collections::BTreeMap::new(),
        legacy: Some(legacy),
    }))
}

/// The two roots a phrase may put back: the data roots. The identity key is not
/// among them — a phrase drives a *visible, signed rotation* onto a fresh key
/// (`DEC-0051`, `RFC-0075`), never a silent re-install of the old one.
#[derive(Clone)]
pub struct DataRoots {
    pub master_secret: [u8; 32],
    pub cek: [u8; 32],
}

pub fn recovery_bundle_path(base_dir: &std::path::Path, user_id: &str) -> std::path::PathBuf {
    base_dir.join("users").join(user_id).join("recovery.json")
}

/// Seal recovery copies of the two data roots, `master_secret` and `cek`, under
/// the mnemonic seed and write them to the user directory. The mnemonic is used only here (and at unseal
/// during recovery) — never in normal operation.
pub fn write_recovery_bundle(
    base_dir: &std::path::Path,
    user_id: &str,
    seed32: &[u8; 32],
    master_secret: &[u8; 32],
    cek: &[u8; 32],
) -> Result<()> {
    let bundle = RecoveryBundle {
        master_secret: wrap_master_secret_recovery(seed32, master_secret)?,
        identity_key: None,
        cek: wrap_cek_recovery(seed32, cek, 0)?,
    };
    // Grow, never replace. Add this phrase's copy under its reserve pubkey,
    // keeping every other phrase's copy — the mirror of the KEL's `recovery_set`,
    // which only ever gains members (TASK-a-second-recovery-phrase-silently-
    // disinherits-the-first). A second phrase used to overwrite the first here.
    let mut set = load_recovery_set(base_dir, user_id)?.unwrap_or(RecoveryBundleSet {
        copies: std::collections::BTreeMap::new(),
        legacy: None,
    });
    let key = authority_key_hex(seed32);
    // Writing this phrase's own copy retires the un-keyed legacy slot when it was
    // that phrase's: the copy now has a home under its key.
    if set.legacy.is_some() && !set.copies.contains_key(&key) {
        // Only clear it if this seed opens the legacy copy — otherwise the legacy
        // belongs to a different phrase and must be kept.
        if let Some(legacy) = &set.legacy {
            if unwrap_cek_recovery(&legacy.cek, seed32).is_ok() {
                set.legacy = None;
            }
        }
    }
    set.copies.insert(key, bundle);
    let json = serde_json::to_string_pretty(&set).context("serialise recovery bundle set")?;
    let path = recovery_bundle_path(base_dir, user_id);
    if let Some(parent) = path.parent() {
        kotton_common::fs::create_dir_all_owner_only(parent).with_context(|| format!("create {parent:?}"))?;
    }
    std::fs::write(&path, json).with_context(|| format!("write {path:?}"))?;
    Ok(())
}

/// A binding whose key carries the credential as its auth value is tied to
/// *that* credential: changing it means a new key, or the chip would refuse the
/// new one and count the refusal. So on a credential change a policied binding
/// is replaced — a fresh binding under the new credential, the old key
/// discarded — before the vault is re-sealed against it. A policy-less binding
/// is left alone. Rolls back the stored bytes if the new binding cannot be
/// written, so a failed change leaves the old one openable.
fn rebind_if_policied(rt: &dyn ProvisioningHost, user_id: &str, credential: &str) -> Result<()> {
    let Some(old) = stored_binding(rt, user_id)? else {
        return Ok(());
    };
    if !old.requires_credential() {
        return Ok(());
    }
    let path = binding_path(rt, user_id);
    let previous = std::fs::read(&path)?;
    let (_new, stored) = rt.create_binding(credential)?;
    if let Err(e) = std::fs::write(&path, &stored) {
        let _ = std::fs::write(&path, &previous);
        return Err(anyhow::Error::new(e).context("replacing the device binding"));
    }
    old.discard();
    Ok(())
}

/// The recovery bundle exactly as written — sealed, unparsed — for a node that
/// keeps it on the user's behalf without being able to open it (`RFC-0081`).
pub fn read_recovery_bundle_raw(
    base_dir: &std::path::Path,
    user_id: &str,
) -> Result<Option<String>> {
    let path = recovery_bundle_path(base_dir, user_id);
    match std::fs::read_to_string(&path) {
        Ok(json) => Ok(Some(json)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow::Error::new(e).context(format!("read {path:?}"))),
    }
}

/// Keep a recovery bundle another device wrote, verbatim.
///
/// Parsed before it is written so that a node never stores something it would
/// later fail to serve as a bundle — but the parse checks *shape*, not contents:
/// the copies inside stay sealed, and this node holds nothing that opens them.
pub fn write_recovery_bundle_raw(
    base_dir: &std::path::Path,
    user_id: &str,
    json: &str,
) -> Result<()> {
    // Accept either the keyed set (current) or a legacy single bundle: a node
    // stores the blob opaquely, and both are valid shapes it may be handed.
    if serde_json::from_str::<RecoveryBundleSet>(json).is_err()
        && serde_json::from_str::<RecoveryBundle>(json).is_err()
    {
        anyhow::bail!("recovery bundle is neither a keyed set nor a single bundle");
    }
    let path = recovery_bundle_path(base_dir, user_id);
    if let Some(parent) = path.parent() {
        kotton_common::fs::create_dir_all_owner_only(parent).with_context(|| format!("create {parent:?}"))?;
    }
    std::fs::write(&path, json).with_context(|| format!("write {path:?}"))?;
    Ok(())
}

/// Read and unseal the recovery bundle with the mnemonic seed, if present.
///
/// Returns [`DataRoots`] rather than a pair of `[u8; 32]`s: two same-typed arrays
/// in a tuple is a shape where transposing them is a valid program. The identity
/// key is not returned even from a bundle that carries one (see
/// [`RecoveryBundle::identity_key`]).
pub fn read_recovery_bundle(
    base_dir: &std::path::Path,
    user_id: &str,
    seed32: &[u8; 32],
) -> Result<Option<DataRoots>> {
    let path = recovery_bundle_path(base_dir, user_id);
    let json = match std::fs::read_to_string(&path) {
        Ok(j) => j,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(anyhow::Error::new(e).context(format!("read {path:?}"))),
    };
    // The keyed set first: find the copy filed under this phrase's reserve pubkey.
    if let Ok(set) = serde_json::from_str::<RecoveryBundleSet>(&json) {
        let key = authority_key_hex(seed32);
        if let Some(bundle) = set.copies.get(&key) {
            return Ok(Some(open_bundle(bundle, seed32)?));
        }
        // Fall back to the un-keyed legacy copy: it opens only under the one
        // phrase that sealed it, so a successful unseal is proof it is this one.
        if let Some(legacy) = &set.legacy {
            if let Ok(roots) = open_bundle(legacy, seed32) {
                return Ok(Some(roots));
            }
        }
        // A committed phrase with no copy of its own: the KEL proves it an
        // authority, but the sealed half cannot open the data for it. Reported by
        // the caller as exactly that, rather than silently returning someone
        // else's roots.
        return Ok(None);
    }
    // A fully legacy file: a single bundle, no envelope.
    let bundle: RecoveryBundle = serde_json::from_str(&json).context("parse recovery bundle")?;
    Ok(Some(open_bundle(&bundle, seed32)?))
}

/// Unseal one sealed copy into its two data roots.
fn open_bundle(bundle: &RecoveryBundle, seed32: &[u8; 32]) -> Result<DataRoots> {
    Ok(DataRoots {
        master_secret: unwrap_master_secret_recovery(&bundle.master_secret, seed32)?,
        cek: unwrap_cek_recovery(&bundle.cek, seed32)?,
    })
}

/// Store the three operational roots into the OS keychain for the session.
pub fn store_operational_roots(
    secrets: &(dyn SecretsStore + Send + Sync),
    user_id: &str,
    roots: &OperationalRoots,
) {
    let _ = secrets.set_secret(
        &kdf_labels::identity_signing_key(user_id),
        &hex::encode(roots.identity_key),
    );
    let _ = secrets.set_secret(
        &kdf_labels::master_secret_keychain_key(user_id),
        &hex::encode(roots.master_secret),
    );
    let _ = secrets.set_secret(
        &kdf_labels::operational_cek(user_id),
        &hex::encode(roots.cek),
    );
}

/// Read the three operational roots back from the keychain (e.g. to seal the vault).
pub fn load_operational_roots(
    secrets: &(dyn SecretsStore + Send + Sync),
    user_id: &str,
) -> Result<OperationalRoots> {
    let get = |label: String| -> Result<[u8; 32]> {
        let hex = secrets
            .get_secret(&label)
            .context("secrets store read failed")?
            .ok_or_else(|| anyhow!("missing key '{label}'; log in first"))?;
        hex::decode(&hex)
            .ok()
            .and_then(|b| b.get(..32).and_then(|s| s.try_into().ok()))
            .ok_or_else(|| anyhow!("keychain entry '{label}' is not 32 bytes"))
    };
    Ok(OperationalRoots {
        master_secret: get(kdf_labels::master_secret_keychain_key(user_id))?,
        identity_key: get(kdf_labels::identity_signing_key(user_id))?,
        cek: get(kdf_labels::operational_cek(user_id))?,
    })
}



/// Delete all per-user keychain labels for `user_id` (best-effort). Kept in one
/// place so a new secret can't be added without also being purged on removal —
/// the "remove leaves no trace" invariant. Does NOT touch device-level or
/// per-app secrets (not user-scoped).
pub fn delete_all_user_secrets(secrets: &dyn kotton_sys::secret::SecretsStore, user_id: &str) {
    for label in [
        kdf_labels::seed32_keychain_key(user_id),
        kdf_labels::identity_signing_key(user_id),
        kdf_labels::master_secret_keychain_key(user_id),
        kdf_labels::operational_cek(user_id),
        kdf_labels::operational_cek_epoch(user_id),
        kdf_labels::frost_share(user_id),
        kdf_labels::frost_pubkey_package(user_id),
        kdf_labels::warm_signing_key(user_id),
        kdf_labels::warm_key_delegation(user_id),
        kdf_labels::user_records_db(user_id),
    ] {
        let _ = secrets.delete_secret(&label);
    }
}



/// Delete the **device-level** keychain labels — the ones no user owns.
///
/// The companion to [`delete_all_user_secrets`], kept beside it for the same
/// reason: a new device-scoped secret must not be addable without a purge to add
/// it to. `logout_user` deliberately leaves these alone, because other
/// identities on the machine share them; a whole-device reset is the one caller
/// for which that is no longer true.
///
/// **What it cannot reach, stated rather than implied.** Two label families are
/// named by an id this function has no way to enumerate — `org_signing_key` per
/// org DID and `app_db` per app id — and `SecretsStore` offers get/set/delete
/// with no listing, so there is nothing to sweep them with. They outlive a reset
/// (`TASK-a-device-reset-cannot-name-every-keychain-label`).
pub fn delete_all_device_secrets(secrets: &dyn kotton_sys::secret::SecretsStore) {
    for label in [
        kdf_labels::device_operational_key(),
        kdf_labels::device_operator_key(),
    ] {
        let _ = secrets.delete_secret(&label);
    }
}

/// How many recovery authorities this device holds a sealed copy for.
///
/// `0` is the answer that matters: it means no phrase was ever set up here, so
/// this identity does not survive the base directory going. That sentence is the
/// whole reason `kotton device reset` lists before it asks
/// (`TASK-a-device-has-no-verb-to-start-fresh`).
///
/// Reads the file and nothing else — no key, no daemon, no session — because the
/// count is a property of the *set*, not of what any phrase can open. A person
/// whose install is too broken to start is exactly the person asking, and a
/// listing that needed the daemon would be absent when it is needed.
///
/// A legacy un-keyed bundle counts as one: its authority is unrecorded, not
/// missing. An unreadable or malformed file counts as `0` — it cannot be
/// *relied* on, which is the question being asked.
pub fn recovery_authority_count(base_dir: &std::path::Path, user_id: &str) -> usize {
    let Ok(Some(set)) = load_recovery_set(base_dir, user_id) else {
        return 0;
    };
    set.copies.len() + usize::from(set.legacy.is_some())
}

/// Whether `user_dir` holds a PIN vault — the one place that decides.
/// Whether this user has a PIN vault on disk.
///
/// `pub(crate)` since 2026-08-21: `device/users.rs` now calls `identity` and
/// `crypto` directly and needs this to compute their `pin_set` argument.
/// Shared rather than re-derived because two readers naming `vault.json`
/// independently is a bug this file has already had once.
pub fn pin_is_set(user_dir: &Path) -> bool {
    user_dir.join(VAULT_FILE).exists()
}

pub fn binding_path(rt: &dyn ProvisioningHost, user_id: &str) -> PathBuf {
    rt.base_dir()
        .join("users")
        .join(user_id)
        .join(BINDING_FILE)
}

/// This user's vault-binding secret, if they have bound this device.
///
/// **The presence of the file is the opt-in.** Binding is not inferred from the
/// hardware being available, because it changes the recovery story — clearing
/// the TPM or moving the disk then leaves only the recovery phrase — and that is
/// a choice a person makes, not a consequence of buying a machine with a chip in
/// it (RFC-0053: hardware sealing is "never required").
///
/// Seal and open both route through here, so the two can never disagree about
/// whether a binding applies.
/// The stored binding for `user_id`, if the vault is bound to hardware.
fn stored_binding(rt: &dyn ProvisioningHost, user_id: &str) -> Result<Option<Box<dyn DeviceBinding>>> {
    let path = binding_path(rt, user_id);
    if !path.exists() {
        return Ok(None);
    }
    let stored = std::fs::read(&path)
        .with_context(|| format!("failed to read the device binding at {path:?}"))?;
    Ok(Some(rt.binding_from_stored(stored)))
}

/// What limits guessing on `user_id`'s vault: what their hardware binding
/// answers, or nothing where there is none. Readable without the credential —
/// the stored form says whether the key carries a policy — so the daemon can
/// choose the credential bar before anyone types (DEC-0046,
/// TASK-the-enclave-does-not-count-attempts).
pub fn attempt_limiting_for_user(rt: &dyn ProvisioningHost, user_id: &str) -> AttemptLimiting {
    match stored_binding(rt, user_id) {
        Ok(Some(b)) => attempt_limiting_for(Some(b.as_ref())),
        _ => AttemptLimiting::None,
    }
}

/// This device's binding for `user_dir`'s routing half, minting one on first
/// use where the platform has hardware for it.
///
/// **On by default, and that is the difference from the vault's binding.**
/// Binding the vault is a choice because it changes what recovery means; this
/// binds a cache, so the worst a cleared TPM does is cost a rebuild at the next
/// unlock. So there is no opt-in to read and no flag to set: a device that can
/// hold a key holds one.
///
/// **No auth policy**, through [`kotton_secret::PlatformBinding::create`]
/// rather than `create_with_credential`. The file this protects is read by a
/// daemon that has booted and has not been unlocked; a key the chip will not
/// use without a credential could not be read then, which is the only time it
/// matters.
///
/// `None` on a machine with no hardware backing — every Linux machine today — and
/// on any failure, because a cache whose key could not be made is a cache
/// written in the clear and saying so, not a person locked out of their roots.
/// A stored binding the hardware will no longer honour is **replaced**: that is
/// the cleared-TPM case, and a fresh key here plus a rebuilt routing half is
/// the whole of the repair.
pub fn routing_binding(user_dir: &Path) -> Option<Box<dyn DeviceBinding>> {
    let path = user_dir.join(ROUTING_BINDING_FILE);
    if let Ok(stored) = std::fs::read(&path) {
        let binding = kotton_secret::PlatformBinding::from_sealed(stored);
        match binding.binding_secret(None) {
            Ok(_) => return Some(Box::new(binding)),
            Err(e) => tracing::warn!(
                error = %e,
                path = %path.display(),
                "identity: this device's hardware no longer reproduces the binding the \
                 roots index's routing half was sealed under — minting a new one, which \
                 costs one rebuild of that half"
            ),
        }
    }
    if !kotton_secret::PlatformBinding::is_available() {
        return None;
    }
    match kotton_secret::PlatformBinding::create() {
        Ok((binding, stored)) => match std::fs::write(&path, &stored) {
            Ok(()) => Some(Box::new(binding)),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = %path.display(),
                    "identity: a device binding for the roots index's routing half was \
                     made and could not be stored; the half stays in the clear"
                );
                None
            }
        },
        Err(e) => {
            tracing::warn!(
                error = %e,
                "identity: this device reports hardware key storage and would not make a \
                 binding for the roots index's routing half; the half stays in the clear"
            );
            None
        }
    }
}

/// The binding secret for `user_id`, opened with `credential` where the
/// binding's key carries a policy that needs it.
pub fn device_binding_secret(
    rt: &dyn ProvisioningHost,
    user_id: &str,
    credential: Option<&str>,
) -> Result<Option<[u8; 32]>> {
    let Some(binding) = stored_binding(rt, user_id)? else {
        return Ok(None);
    };
    let secret = binding
        .binding_secret(credential)
        .map_err(|e| {
            anyhow!(
                "this identity is bound to this device's hardware, and that hardware could \
                 not supply the binding secret ({e}). If the TPM was cleared or the disk \
                 moved, recover with your recovery phrase."
            )
        })?;
    Ok(Some(secret))
}

/// Bind this user's vault to this device's hardware (RFC-0053 step 8).
///
/// Requires the user's daily credential, because the vault must be re-sealed
/// under a key that now mixes in the binding — there is no way to add a binding
/// to a sealed vault without opening it.
///
/// **Ordering and rollback.** The binding file is written first, then the vault
/// is re-sealed against it. If the re-seal fails, the file is removed again: a
/// binding file beside an unbound vault is a state where every later unlock is
/// refused ("this vault predates device binding"), which would look like data
/// loss to the user. The reverse order is worse — a vault sealed against a
/// binding whose ciphertext was never persisted is genuinely unopenable.
pub async fn bind_device(rt: &dyn ProvisioningHost, user_id: &str, credential: &str) -> Result<()> {
    if !rt.binding_available() {
        anyhow::bail!(
            "this machine has no usable hardware-backed key store, so there is nothing to \
             bind to — your vault is still protected by your passphrase"
        );
    }
    let path = binding_path(rt, user_id);
    if path.exists() {
        anyhow::bail!("'{user_id}' is already bound to this device");
    }
    if !pin_is_set(&rt.base_dir().join("users").join(user_id)) {
        anyhow::bail!(
            "set a passphrase for '{user_id}' first — binding protects the vault, and there \
             is no vault until a credential seals one"
        );
    }

    // With an auth policy where the platform can put one: the credential is
    // then the key's auth value too, so the chip checks and counts it
    // (TASK-the-enclave-does-not-count-attempts).
    let (_binding, stored) = rt.create_binding(credential)?;
    std::fs::write(&path, &stored)
        .with_context(|| format!("failed to write the device binding to {path:?}"))?;

    // Re-seal under the credential: the seal now finds the binding file and
    // produces a v2 vault. Not `set_user_pin`, which would take the binding
    // just created for a stale one and replace it — the counting double
    // caught exactly that, and on a chip it is a key made and deleted per bind.
    if let Err(e) = seal_and_adopt(rt, user_id, credential) {
        let _ = std::fs::remove_file(&path);
        return Err(e.context(
            "binding was rolled back because the vault could not be re-sealed against it",
        ));
    }
    Ok(())
}

/// Seal the user's operational roots under a PIN and write [`VAULT_FILE`].
///
/// The secrets-store entry must already exist — i.e. the user must be logged in
/// via `create_user` or `login_with_recovery_key`.
///
/// This creates a PIN-based fallback so the user can call `unlock_with_pin`
/// on a cold start when that entry is absent.
pub async fn set_user_pin(rt: &dyn ProvisioningHost, user_id: &str, pin: &str) -> Result<()> {
    rebind_if_policied(rt, user_id, pin)?;
    seal_and_adopt(rt, user_id, pin)
}

/// Seal the vault under `pin` against whatever binding is stored, then take
/// the plaintext roots out of the platform's hands.
fn seal_and_adopt(rt: &dyn ProvisioningHost, user_id: &str, pin: &str) -> Result<()> {
    seal_vault_under(rt, user_id, pin)?;

    // The vault is now on disk, so a durable sealed copy of these roots exists —
    // which is the precondition for taking the plaintext out of the platform's
    // hands (RFC-0053 step 4). Ordering is the whole safety argument: adopting
    // before the write would leave the roots in memory only, and a restart would
    // be data loss rather than a re-lock.
    adopt_roots_into_memory(rt, user_id);

    Ok(())
}

/// Write the sealed vault, and **leave the platform's plaintext copies alone**.
///
/// The half of [`set_user_pin`] that makes recovery possible, without the half
/// that makes the account locked.
///
/// Split out on 2026-08-29 for `create_user`, which needs the first and must not
/// yet do the second. Purging at creation is *correct* — it is RFC-0053 step 4,
/// and it is what the guest-shell path has always done — but it makes every
/// daemon restart require an unlock, and **nothing in the product can unlock
/// yet**: `lock.rs` is 59 lines and calls no auth verb
/// (`TASK-surface-identity-and-unlock`). Adopting at creation today would seal
/// people out of their own accounts on the next restart.
///
/// So this is a deliberate, temporary concession with the seam left open: the
/// credential is recorded and the vault is sealed, which is the security
/// property that was missing; the purge waits for a surface that can undo it.
/// See `TASK-creation-seals-the-vault-but-does-not-lock-it`.
pub fn seal_vault_under(rt: &dyn ProvisioningHost, user_id: &str, pin: &str) -> Result<()> {
    // Seal the three operational roots under U = Argon2id(PIN) into the at-rest
    // vault. `seed32` is never involved (RFC-0039).
    let roots = load_operational_roots(rt.secrets(), user_id)?;
    write_sealed(rt, user_id, pin, &roots, VAULT_FILE)
}

/// Seal `roots` under `pin` against the stored binding and write them to `file`
/// under the user's directory, through [`write_replacing`].
fn write_sealed(
    rt: &dyn ProvisioningHost,
    user_id: &str,
    pin: &str,
    roots: &OperationalRoots,
    file: &str,
) -> Result<()> {
    let binding = device_binding_secret(rt, user_id, Some(pin))?;
    let vault = seal_vault(pin, roots, binding.as_ref()).context("vault sealing failed")?;
    let path = rt.base_dir().join("users").join(user_id).join(file);
    let json = serde_json::to_string_pretty(&vault).context("failed to serialise vault")?;
    write_replacing(&path, json.as_bytes())
}

/// Replace `path` with `bytes` through a temporary file in the same directory
/// and a rename, the way `kel_store::save_chain` and `retired_keys::save` do.
///
/// The vault is the one durable copy of the person's roots. A plain `write`
/// truncates it first, so a crash or a full disk before the last byte leaves a
/// vault that opens under nothing, and the roots are gone. After this a reader
/// sees the old vault or the new one. The temporary file is removed on any
/// failure, so a refused write leaves no second sealed copy behind.
fn write_replacing(path: &Path, bytes: &[u8]) -> Result<()> {
    // Same directory as the target: `rename` is only atomic within a filesystem.
    let tmp = path.with_extension("json.tmp");
    let written = (|| {
        use std::io::Write as _;
        let mut f = std::fs::File::create(&tmp).with_context(|| format!("create {tmp:?}"))?;
        f.write_all(bytes).with_context(|| format!("write {tmp:?}"))?;
        f.sync_all().with_context(|| format!("sync {tmp:?}"))?;
        std::fs::rename(&tmp, path).with_context(|| format!("rename {tmp:?} -> {path:?}"))
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

/// Seal the user's roots, with `identity_key` in place of the one custody holds,
/// under `pin` into [`STAGED_VAULT_FILE`] — the first half of a rotation's
/// re-seal, done **before** the rotation is appended so that a failure here
/// changes nothing. The live vault is untouched.
pub fn stage_rotated_vault(
    rt: &dyn ProvisioningHost,
    user_id: &str,
    pin: &str,
    identity_key: &[u8; 32],
) -> Result<()> {
    let mut roots = load_operational_roots(rt.secrets(), user_id)?;
    roots.identity_key = *identity_key;
    write_sealed(rt, user_id, pin, &roots, STAGED_VAULT_FILE)
}

/// Whether the key log has committed to `identity_key`: its last event installs
/// that key's verifying half. The one test that decides whether a staged vault
/// is the vault or is nothing — asked by the rotation after its append, and by
/// the unlock after a crash.
pub fn key_log_installs(base_dir: &Path, user_id: &str, identity_key: &[u8; 32]) -> Result<bool> {
    let public = ed25519_dalek::SigningKey::from_bytes(identity_key)
        .verifying_key()
        .to_bytes();
    Ok(crate::kel_store::load_chain(base_dir, user_id)?
        .last()
        .is_some_and(|head| head.key_state.group_key == public))
}

/// The second half: the rotation is appended, so the staged vault becomes the
/// vault. One rename within the user's directory.
pub fn commit_staged_vault(rt: &dyn ProvisioningHost, user_id: &str) -> Result<()> {
    let dir = rt.base_dir().join("users").join(user_id);
    let (staged, live) = (dir.join(STAGED_VAULT_FILE), dir.join(VAULT_FILE));
    std::fs::rename(&staged, &live).with_context(|| format!("rename {staged:?} -> {live:?}"))
}

/// The rotation did not land: the staged vault seals a key nothing installed,
/// and is removed. A delete that fails is logged — the next unlock removes it.
pub fn discard_staged_vault(rt: &dyn ProvisioningHost, user_id: &str) {
    let path = rt.base_dir().join("users").join(user_id).join(STAGED_VAULT_FILE);
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!(user_id = %user_id, "could not remove {path:?}: {e}"),
    }
}

/// Remove the copy of the identity key this device keeps sealed under the
/// person's passphrase ([`VAULT_FILE`]), and any staged one, after a recovery
/// rotated the identity onto another key. Returns whether a sealed copy was there.
///
/// Both seal the key the recovery replaced, so the passphrase they are sealed
/// under would restore it, and the person may not remember that passphrase: they
/// are often recovering because of it. The recovery then seals the roots under
/// the passphrase chosen for this device ([`set_user_pin`]). The staged copy's
/// removal is [`discard_staged_vault`]'s, logged on failure; a sealed copy that
/// cannot be removed is an error, since it is the one an unlock reads.
pub fn remove_sealed_copy(rt: &dyn ProvisioningHost, user_id: &str) -> Result<bool> {
    discard_staged_vault(rt, user_id);
    let path = rt.base_dir().join("users").join(user_id).join(VAULT_FILE);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(anyhow::Error::new(e).context(format!("remove {path:?}"))),
    }
}

/// Finish or drop a staged vault left by a rotation that did not reach its
/// rename, given the roots the live vault just opened to under `pin`. Returns
/// the staged roots when it was promoted.
///
/// **Only what is proved not to be the installed key is removed.** The key log
/// decides, and the staged vault is dropped in exactly two cases:
///
/// - it opens, and the log does not install its key — the rotation never landed;
/// - it does not open, and the log installs the live vault's key — the live vault
///   is current, so nothing the staged file holds can be needed.
///
/// It is promoted — renamed over the vault — when it opens under the credential
/// that just opened the live vault and the log installs its key. Every other
/// case is kept for a later unlock: a staged vault that will not open while the
/// live one is stale, or a key log that cannot be read, may be holding the only
/// sealed copy of the key the log installs, and deleting it on a transient error
/// would be the defect this exists to close.
pub fn settle_staged_vault(
    rt: &dyn ProvisioningHost,
    user_id: &str,
    pin: &str,
    live: &OperationalRoots,
) -> Option<OperationalRoots> {
    let path = rt.base_dir().join("users").join(user_id).join(STAGED_VAULT_FILE);
    if !path.exists() {
        return None;
    }
    let installs =
        |roots: &OperationalRoots| key_log_installs(rt.base_dir(), user_id, &roots.identity_key);
    let staged = std::fs::read_to_string(&path)
        .map_err(anyhow::Error::from)
        .and_then(|json| serde_json::from_str::<AtRestVault>(&json).map_err(Into::into))
        .and_then(|vault| {
            let binding = device_binding_secret(rt, user_id, Some(pin))?;
            open_vault(&vault, pin, binding.as_ref())
        });
    let keep = |why: &str| {
        tracing::warn!(user_id = %user_id, "a rotation's staged vault is kept for a later unlock: {why}");
        None
    };
    match staged {
        Ok(staged) => match installs(&staged) {
            Ok(true) => {
                if let Err(e) = commit_staged_vault(rt, user_id) {
                    tracing::warn!(
                        user_id = %user_id,
                        "the key log installs the rotated key and the vault could not take it \
                         yet; this unlock restores it and the next one retries: {e:#}"
                    );
                }
                Some(staged)
            }
            Ok(false) => {
                discard_staged_vault(rt, user_id);
                None
            }
            Err(e) => keep(&format!("the key log could not be read: {e:#}")),
        },
        Err(open_failed) => match installs(live) {
            Ok(true) => {
                discard_staged_vault(rt, user_id);
                None
            }
            Ok(false) => keep(&format!(
                "the live vault is not the key the log installs and the staged one did not \
                 open: {open_failed:#}"
            )),
            Err(e) => keep(&format!("the key log could not be read: {e:#}")),
        },
    }
}

/// Move this user's operational roots into memory-only custody, purging the
/// platform's plaintext copies.
///
/// Only ever called where a sealed vault demonstrably exists — just written
/// ([`set_user_pin`]) or just opened ([`unlock_with_pin`]).
///
/// Failures are logged, not propagated: the caller's operation (setting a
/// credential, unlocking) has already succeeded, and a keychain that refuses a
/// delete should not turn that into an error the user cannot act on. It does
/// mean a plaintext copy may survive on a platform store that misbehaves, so it
/// is logged at `warn` rather than swallowed.
pub fn adopt_roots_into_memory(rt: &dyn ProvisioningHost, user_id: &str) {
    for label in [
        kdf_labels::master_secret_keychain_key(user_id),
        kdf_labels::identity_signing_key(user_id),
        kdf_labels::operational_cek(user_id),
        // Pre-RFC-0039 accounts still keep a seed here, and it derives all three
        // of the above — leaving it behind would make purging the others
        // pointless.
        kdf_labels::seed32_keychain_key(user_id),
    ] {
        match rt.adopt_root(&label) {
            Ok(true) => tracing::info!(user_id = %user_id, "purged plaintext {label} from platform storage"),
            Ok(false) => {}
            Err(e) => tracing::warn!(
                user_id = %user_id,
                "could not take {label} into memory-only custody: {e}"
            ),
        }
    }
}

/// Open the PIN vault and restore the operational roots to the secrets store.
///
/// Use this on cold start when the secrets store doesn't have the entry yet —
/// after a successful call, `get_or_create_record_store` can derive the DB key
/// as usual.
pub async fn unlock_with_pin(rt: &dyn ProvisioningHost, user_id: &str, pin: &str) -> Result<()> {
    // The live vault first: it is what proves the credential, so a wrong one is
    // refused — and, on a counting binding, counted — once, not once per file.
    let mut roots = open_vault_under(rt, user_id, pin)?;
    // Then a rotation that crashed between its append and its rename is finished
    // here, where the credential that sealed its staged vault is in hand.
    if let Some(staged) = settle_staged_vault(rt, user_id, pin, &roots) {
        roots = staged;
    }

    // Restore the operational roots for this session. `store_operational_roots`
    // writes through the custody layer, so on a device that already adopted them
    // they land straight in memory; on one that has not, they land in the
    // platform store and the adopt below takes them out of it.
    store_operational_roots(rt.secrets(), user_id, &roots);

    // We just opened the vault, so a durable sealed copy provably exists — the
    // same precondition `set_user_pin` establishes by writing one. Without this,
    // every unlock would re-deposit plaintext roots in the keychain and quietly
    // undo the purge.
    adopt_roots_into_memory(rt, user_id);

    Ok(())
}

/// What [`repair_roots_from_vault`] wrote: the labels it restored from the vault.
/// Empty when every root read and matched — a repair with nothing to repair.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RootsRepair {
    pub written: Vec<String>,
}

/// **Repair the operational roots from the vault the owner's credential opens**
/// — the one verb that writes a root the store could not read
/// (`TASK-a-keychain-entry-that-fails-permanently-has-no-repair-verb-and-lockedby-says-it-is-recoverable`).
///
/// Every reader refuses a root it cannot read, and the unlock restores roots
/// only when the store answers that it holds none, so an entry that fails every
/// read — a keyring `BadEncoding`, a tampered entry — was refused at every door
/// and never written: the key it might hold was kept, and the owner was locked
/// out by it. This is the way out, and it is not an overwrite:
///
/// 1. **The vault is read first**, under `pin`, and a rotation staged by a crash
///    is settled exactly as [`unlock_with_pin`] settles it. Settling does not
///    by itself make the vault current — it leaves a stale live vault in place
///    when the staged one will not open, or when the key log cannot be read —
///    so **the repair then requires the key log to install the vault's identity
///    key** ([`key_log_installs`] answering `Ok(true)`), and refuses, writing
///    nothing, when it does not or cannot be read. Only a vault the log agrees
///    with may be written into an entry that could not be read: after a crashed
///    rotation that entry may hold the key the chain admits. What this proves is
///    the identity key's currency; the master secret and the CEK are trusted
///    because the vault seals all three together.
/// 2. **Every root label it could write is read**, and sorted: a store that
///    answers *none*, or cannot answer, is to be written; a store that answers
///    is compared with the vault, and **one that differs refuses the whole
///    repair, naming the label, before anything is written.** An entry that
///    reads and disagrees is not a failure this verb may resolve — it may be
///    the newer key — so it is the owner's to look at, not ours to replace.
/// 3. **Only the labels sorted to be written are written**, each write's error
///    returned rather than dropped, and each read back: a store that still
///    cannot read what it was just given is reported, not called repaired.
/// 4. Then the roots are adopted into memory custody, as every unlock adopts
///    them. That deletes the platform's plaintext copies — of labels that read
///    only after they matched the vault, so nothing is lost: the value is held
///    in memory and sealed in the vault that was just opened.
///
/// Returns the labels written; empty when every root read and matched.
pub fn repair_roots_from_vault(rt: &dyn ProvisioningHost, user_id: &str, pin: &str) -> Result<RootsRepair> {
    let mut roots = open_vault_under(rt, user_id, pin)?;
    if let Some(staged) = settle_staged_vault(rt, user_id, pin, &roots) {
        roots = staged;
    }
    match key_log_installs(rt.base_dir(), user_id, &roots.identity_key) {
        Ok(true) => {}
        Ok(false) => {
            return Err(anyhow!(
                "the vault's identity key for '{user_id}' is not the one its key log installs — \
                 a rotation may not have reached the vault — so nothing was written; an entry that \
                 could not be read may hold the key the log admits"
            ))
        }
        Err(e) => {
            return Err(anyhow!(
                "the key log for '{user_id}' could not be read, so the vault could not be shown \
                 current and nothing was written: {e:#}"
            ))
        }
    }
    let labelled = [
        (kdf_labels::master_secret_keychain_key(user_id), roots.master_secret),
        (kdf_labels::identity_signing_key(user_id), roots.identity_key),
        (kdf_labels::operational_cek(user_id), roots.cek),
    ];

    let mut to_write: Vec<&(String, [u8; 32])> = Vec::new();
    for root in &labelled {
        let (label, sealed) = root;
        match rt.secrets().get_secret(label) {
            Ok(None) => to_write.push(root),
            Err(e) => {
                tracing::warn!(user_id = %user_id, "repair: {label} could not be read and will be written from the vault: {e}");
                to_write.push(root);
            }
            Ok(Some(held)) => {
                let matches = hex::decode(held.trim()).is_ok_and(|bytes| bytes.as_slice() == sealed.as_slice());
                if !matches {
                    return Err(anyhow!(
                        "{label} reads, and does not hold what the vault seals for '{user_id}'; \
                         nothing was written. An entry that reads is never written over by a repair \
                         — it may hold a newer key than the vault"
                    ));
                }
            }
        }
    }

    // The writes are not one transaction: a store offers none. So a failure part
    // way names what was already written, and the owner knows the state left.
    let mut written: Vec<String> = Vec::new();
    let so_far = |written: &[String]| {
        if written.is_empty() {
            "nothing else was written".to_string()
        } else {
            format!("already written from the vault: {}", written.join(", "))
        }
    };
    for (label, sealed) in to_write {
        let hex_value = hex::encode(sealed);
        if let Err(e) = rt.secrets().set_secret(label, &hex_value) {
            return Err(anyhow!("{label} could not be written from the vault: {e}; {}", so_far(&written)));
        }
        written.push(label.clone());
        let failed = match rt.secrets().get_secret(label) {
            Ok(Some(back)) if back == hex_value => None,
            Ok(_) => Some(format!("{label} was written from the vault and does not read back as it")),
            Err(e) => Some(format!("{label} was written from the vault and still cannot be read: {e}")),
        };
        if let Some(why) = failed {
            return Err(anyhow!("{why}; {}", so_far(&written)));
        }
    }

    adopt_roots_into_memory(rt, user_id);
    Ok(RootsRepair { written })
}

/// Open this user's vault under `pin` and return the roots it seals, **without**
/// restoring them anywhere.
///
/// [`unlock_with_pin`] is this and then the restore. A caller that must prove the
/// credential before re-sealing — a rotation, which changes one of the roots —
/// uses this alone, so proving the credential never moves custody.
pub fn open_vault_under(rt: &dyn ProvisioningHost, user_id: &str, pin: &str) -> Result<OperationalRoots> {
    let path = rt
        .base_dir()
        .join("users")
        .join(user_id)
        .join(VAULT_FILE);
    let json = std::fs::read_to_string(&path)
        .with_context(|| format!("vault.json not found for '{user_id}'"))?;
    let vault: AtRestVault =
        serde_json::from_str(&json).context("failed to parse vault.json")?;

    // A vault sealed with a binding needs the same device to open it; one sealed
    // without must not be given one. `open_vault` refuses either mismatch by
    // name rather than reporting a wrong credential.
    let binding = device_binding_secret(rt, user_id, Some(pin))?;
    open_vault(&vault, pin, binding.as_ref())
        .context("PIN unlock failed — wrong PIN or corrupted vault.json")
}

/// Resolve a user's operational VFS Content Encryption Key from the keychain.
///
/// The CEK is one of the two random data roots: `create_user` fills it from
/// `generate_cek`, a `Full` enrollment delivers it, and an unlock or a recovery
/// restores it. It derives from nothing. It is read in priority order:
/// - the stored **random operational CEK** (`operational_cek`);
/// - failing that, a CEK derived from a **`seed32`** the keychain still holds.
///   Nothing writes a seed; this is only a read fallback for a keychain that has
///   one. Its siblings read the same fallback: `core/record`'s
///   `user_record_store` and `core/kuserd`'s `resolve_master` for
///   `master_secret`, and `core/peer`'s `resolve_root` for both roots. A fourth
///   reader, `core/peer`'s `user_has_cek` (through `load_seed32_opt`), asks only
///   whether a seed is present.
///
/// The stored root is read first, so a keychain holding both answers with the
/// random CEK. Returns `None` when neither is present (a blind relay, or a locked
/// session): the VFS then falls back to plaintext storage / `NoCek` on decrypt,
/// unchanged.
///
/// Note: this resolves only the VFS object-storage CEK. The per-user records.db
/// key, the event-log HMAC key and the history-log key derive from the other
/// random root, `master_secret` ([`resolve_master_secret`]), which is **not**
/// delivered by enrollment — an enrolled node cannot open those until a later
/// slice distributes it.
///
/// A store that could not be read is an error, never "absent": taken for
/// absent, the read fell through to the `seed32` fallback and answered with a
/// key derived from another root, and a caller that wrote it back replaced the
/// one it could not read
/// (`TASK-a-key-the-store-cannot-read-is-taken-for-no-key-and-a-new-one-is-minted`).
pub fn resolve_operational_cek(
    secrets: &(dyn SecretsStore + Send + Sync),
    user_id: &str,
) -> Result<Option<[u8; 32]>> {
    let decode32 = |hex: String| -> Option<[u8; 32]> {
        hex::decode(hex).ok().and_then(|b| b.try_into().ok())
    };

    if let Some(cek) = read_root(secrets, &kdf_labels::operational_cek(user_id))?.and_then(decode32) {
        return Ok(Some(cek));
    }

    // The read fallback: a keychain that holds a `seed32` and no stored CEK reads
    // the CEK as derived from it. Nothing writes a seed.
    Ok(read_root(secrets, &kdf_labels::seed32_keychain_key(user_id))?
        .and_then(decode32)
        .map(|seed| derive_cek(&seed)))
}

/// One root's stored text: `Ok(None)` only when the store answered that it holds
/// none, and the store's own error, naming the label, when it could not answer.
fn read_root(secrets: &(dyn SecretsStore + Send + Sync), label: &str) -> Result<Option<String>> {
    secrets
        .get_secret(label)
        .map_err(|e| anyhow!("could not read {label} from the secrets store: {e}"))
}

/// Read `master_secret` from the secrets store, if this node holds it — and the
/// store's error when it could not be read, which is not "does not hold it".
pub fn resolve_master_secret(
    secrets: &(dyn SecretsStore + Send + Sync),
    user_id: &str,
) -> Result<Option<[u8; 32]>> {
    Ok(read_root(secrets, &kdf_labels::master_secret_keychain_key(user_id))?
        .and_then(|hex| hex::decode(hex).ok())
        .and_then(|b| b.try_into().ok()))
}

#[cfg(test)]
mod recovery_set_tests {
    use super::*;

    fn seed(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    /// A legacy single bundle on disk (pre-fix shape) still opens under its
    /// phrase, and adding a second phrase preserves it: `read` falls back to the
    /// `legacy` slot for the old phrase and finds the keyed copy for the new one.
    #[test]
    fn a_legacy_bundle_survives_a_second_phrase() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        std::fs::create_dir_all(base.join("users").join("u")).unwrap();

        // Write a pre-fix bare bundle directly, sealed under seed A.
        let (ms, cek) = ([1u8; 32], [2u8; 32]);
        let a = seed(0xAA);
        let legacy = RecoveryBundle {
            master_secret: wrap_master_secret_recovery(&a, &ms).unwrap(),
            identity_key: None,
            cek: wrap_cek_recovery(&a, &cek, 0).unwrap(),
        };
        std::fs::write(
            recovery_bundle_path(base, "u"),
            serde_json::to_string_pretty(&legacy).unwrap(),
        )
        .unwrap();

        // A second phrase (seed B) is added the normal way.
        let b = seed(0xBB);
        write_recovery_bundle(base, "u", &b, &ms, &cek).unwrap();

        // Both open. The legacy phrase falls back to the un-keyed slot; the new
        // one is found under its key.
        let da = read_recovery_bundle(base, "u", &a).unwrap().expect("legacy phrase opens");
        let db = read_recovery_bundle(base, "u", &b).unwrap().expect("new phrase opens");
        assert_eq!(da.master_secret, ms);
        assert_eq!(db.master_secret, ms);
        assert_eq!(da.cek, cek);
        assert_eq!(db.cek, cek);
    }

    /// **Every device-level label the purge names is actually gone afterwards.**
    ///
    /// This is the half `cli_identity`'s process test cannot see: it runs against
    /// a throwaway root, where `secrets_for_base_dir` hands back an in-process
    /// store by design, so the purge there runs against something that persists
    /// nothing. Here the store is loaded first and read after, which is the only
    /// arrangement in which "the entries are gone" is an observation rather than
    /// an assumption.
    ///
    /// It holds the list rather than the mechanism: the failure it exists to
    /// catch is a new device-scoped secret added without a line in
    /// `delete_all_device_secrets`, which is the "remove leaves no trace"
    /// invariant `delete_all_user_secrets` was written in one place to keep.
    #[test]
    fn every_device_label_is_purged() {
        use kotton_sys::secret::SecretsStore;
        let secrets = kotton_secret::MemorySecrets::new();
        let labels = [
            kdf_labels::device_operational_key(),
            kdf_labels::device_operator_key(),
        ];
        for label in &labels {
            secrets.set_secret(label, "deadbeef").unwrap();
        }
        // Loaded is loaded — otherwise the assertion below passes on an empty
        // store and proves nothing.
        for label in &labels {
            assert!(secrets.get_secret(label).unwrap().is_some(), "{label} was not set");
        }

        delete_all_device_secrets(&secrets);

        for label in &labels {
            assert_eq!(
                secrets.get_secret(label).unwrap(),
                None,
                "{label} survived delete_all_device_secrets"
            );
        }
    }

    /// `recovery_authority_count` reads what `write_recovery_bundle` wrote, with
    /// no key, no daemon and no session — the property `kotton device reset`
    /// stands on, since the person asking to start fresh is often the one whose
    /// install will not start.
    ///
    /// Written against the real writer rather than a handmade fixture: a file
    /// that fails to parse counts as `0`, which is the same answer as "no
    /// phrase", so a test that built its own JSON could pass while the function
    /// read nothing at all.
    #[test]
    fn the_authority_count_is_readable_from_the_file_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        std::fs::create_dir_all(base.join("users").join("u")).unwrap();

        assert_eq!(
            recovery_authority_count(base, "u"),
            0,
            "a user who has set up no phrase has no authority"
        );

        let (ms, cek) = ([1u8; 32], [2u8; 32]);
        write_recovery_bundle(base, "u", &seed(0xA1), &ms, &cek).unwrap();
        assert_eq!(recovery_authority_count(base, "u"), 1);

        // A second phrase grows the set rather than replacing it
        // (`TASK-a-second-recovery-phrase-silently-disinherits-the-first`), so
        // the count follows it.
        write_recovery_bundle(base, "u", &seed(0xB2), &ms, &cek).unwrap();
        assert_eq!(recovery_authority_count(base, "u"), 2);
    }

    /// A legacy un-keyed bundle counts as one authority.
    ///
    /// Its phrase is unrecorded, not missing — the copy opens for whoever holds
    /// the phrase that sealed it. Counting it as `0` would tell a person their
    /// identity does not come back when it does.
    #[test]
    fn a_legacy_bundle_counts_as_one_authority() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        std::fs::create_dir_all(base.join("users").join("u")).unwrap();
        let (ms, cek) = ([5u8; 32], [6u8; 32]);
        let a = seed(0xD4);
        let legacy = RecoveryBundle {
            master_secret: wrap_master_secret_recovery(&a, &ms).unwrap(),
            identity_key: None,
            cek: wrap_cek_recovery(&a, &cek, 0).unwrap(),
        };
        std::fs::write(
            recovery_bundle_path(base, "u"),
            serde_json::to_string_pretty(&legacy).unwrap(),
        )
        .unwrap();

        assert_eq!(recovery_authority_count(base, "u"), 1);
    }

    /// A file that cannot be parsed counts as **no** authority.
    ///
    /// The safe direction, deliberately. The listing's job is to warn that an
    /// identity may not come back: over-warning costs a person some caution,
    /// under-warning costs them the identity. Claiming a phrase is set up when
    /// the file is unreadable is the failure that matters.
    #[test]
    fn an_unreadable_bundle_counts_as_none() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        std::fs::create_dir_all(base.join("users").join("u")).unwrap();
        std::fs::write(recovery_bundle_path(base, "u"), b"{ not json").unwrap();
        assert_eq!(recovery_authority_count(base, "u"), 0);
    }

    /// Re-writing a phrase's own copy retires the legacy slot once that phrase
    /// has a keyed home — the fallback does not linger forever.
    #[test]
    fn writing_the_legacy_phrases_own_copy_retires_the_slot() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        std::fs::create_dir_all(base.join("users").join("u")).unwrap();
        let (ms, cek) = ([3u8; 32], [4u8; 32]);
        let a = seed(0xCC);
        let legacy = RecoveryBundle {
            master_secret: wrap_master_secret_recovery(&a, &ms).unwrap(),
            identity_key: None,
            cek: wrap_cek_recovery(&a, &cek, 0).unwrap(),
        };
        std::fs::write(
            recovery_bundle_path(base, "u"),
            serde_json::to_string_pretty(&legacy).unwrap(),
        )
        .unwrap();

        // Writing seed A's own copy files it under A's key and clears the slot.
        write_recovery_bundle(base, "u", &a, &ms, &cek).unwrap();
        let set = load_recovery_set(base, "u").unwrap().unwrap();
        assert!(set.legacy.is_none(), "the legacy slot is retired once its phrase has a key");
        assert_eq!(set.copies.len(), 1);
        assert_eq!(read_recovery_bundle(base, "u", &a).unwrap().unwrap().master_secret, ms);
    }
}

/// The credential ladder, end to end, on a machine with no TPM
/// (TASK-the-enclave-does-not-count-attempts).
///
/// The `ProvisioningHost` binding seam is where a test stands a counting
/// double, and this is that test: with the double bound, the bar the daemon
/// would set drops to the hardware-limited figure, a six-digit PIN seals the
/// vault, wrong guesses are counted where the caller cannot reset them, and
/// past the limit even the right PIN is refused.
#[cfg(test)]
mod credential_ladder_tests {
    use super::*;
    use kotton_secret::{CountingBinding, MemorySecrets};
    use kotton_sys::secret::{CustodyBackend, SecretsResult};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// How many wrong credentials the double tolerates before it locks.
    const MAX_WRONG: u32 = 3;

    /// One counter shared by every reopen: the host hands out views onto it,
    /// so a caller reopening the stored bytes gets the same count — as a chip
    /// keeps its own count no matter how many times the key is loaded.
    struct CounterView(Arc<CountingBinding>);

    impl DeviceBinding for CounterView {
        fn backend(&self) -> CustodyBackend {
            self.0.backend()
        }
        fn binding_secret(&self, credential: Option<&str>) -> SecretsResult<[u8; 32]> {
            self.0.binding_secret(credential)
        }
        fn counts_attempts(&self) -> bool {
            self.0.counts_attempts()
        }
        fn requires_credential(&self) -> bool {
            self.0.requires_credential()
        }
    }

    /// A host whose hardware is the counting double. Stored bytes name the
    /// counter, so a rebind under a new credential is a new counter, and the
    /// old one is what `discard` would have deleted from a chip.
    struct CountingHost {
        base: std::path::PathBuf,
        secrets: MemorySecrets,
        counters: Mutex<Vec<Arc<CountingBinding>>>,
    }

    impl CountingHost {
        fn new(base: &Path) -> Self {
            Self {
                base: base.to_owned(),
                secrets: MemorySecrets::new(),
                counters: Mutex::new(Vec::new()),
            }
        }
        fn counter(&self, stored: &[u8]) -> Arc<CountingBinding> {
            let idx = usize::from(stored[0]);
            self.counters.lock().unwrap()[idx].clone()
        }
    }

    impl ProvisioningHost for CountingHost {
        fn base_dir(&self) -> &Path {
            &self.base
        }
        fn secrets(&self) -> &(dyn SecretsStore + Send + Sync) {
            &self.secrets
        }
        fn device_fingerprint(&self) -> &str {
            "fp-test"
        }
        fn device_did(&self) -> &str {
            "did:key:test"
        }
        fn shelves(&self) -> &dyn kotton_sys::store::Shelves {
            unreachable!("the credential ladder opens no store")
        }
        fn principal(&self) -> Option<&str> {
            None
        }
        fn register_device(&self, _: String, _: String) {}
        fn unregister_user_devices(&self, _: &str) {}
        fn restore_device_routes(&self, _: HashMap<String, String>) {}
        fn adopt_root(&self, _: &str) -> Result<bool> {
            Ok(false)
        }
        fn binding_from_stored(&self, stored: Vec<u8>) -> Box<dyn DeviceBinding> {
            Box::new(CounterView(self.counter(&stored)))
        }
        fn create_binding(&self, credential: &str) -> Result<(Box<dyn DeviceBinding>, Vec<u8>)> {
            let mut counters = self.counters.lock().unwrap();
            let secret = [0x5A ^ counters.len() as u8; 32];
            let counter = Arc::new(CountingBinding::new(secret, credential, MAX_WRONG));
            let stored = vec![counters.len() as u8];
            counters.push(counter.clone());
            Ok((Box::new(CounterView(counter)), stored))
        }
        fn binding_available(&self) -> bool {
            true
        }
    }

    const USER: &str = "u";
    const PASSPHRASE: &str = "correct horse battery staple kotton";
    const PIN: &str = "135790";

    fn host() -> (tempfile::TempDir, CountingHost) {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("users").join(USER)).unwrap();
        let host = CountingHost::new(tmp.path());
        let roots = OperationalRoots {
            master_secret: [1u8; 32],
            identity_key: [2u8; 32],
            cek: [3u8; 32],
        };
        store_operational_roots(host.secrets(), USER, &roots);
        (tmp, host)
    }

    /// `vault.json` is replaced through a temporary file and a rename, so a write
    /// that fails part-way leaves the old sealed copy whole and openable, and
    /// leaves no temporary copy behind. The failure is injected by occupying the
    /// temporary file's path; a plain `write` to the live path would not have
    /// failed there, and would have truncated the vault on any failure that did
    /// (`TASK-a-rotation-whose-vault-reseal-fails-has-landed-with-the-vault-sealing-the-retired-key`).
    #[tokio::test]
    async fn a_vault_write_that_fails_leaves_the_old_vault_whole() {
        let (_tmp, host) = host();
        set_user_pin(&host, USER, PASSPHRASE).await.unwrap();
        let user_dir = host.base_dir().join("users").join(USER);
        let vault = user_dir.join(VAULT_FILE);
        let tmp = vault.with_extension("json.tmp");
        assert!(!tmp.exists(), "a write that succeeds leaves no temporary file");
        let before = std::fs::read(&vault).unwrap();

        // The roots change, and the re-seal cannot finish.
        store_operational_roots(
            host.secrets(),
            USER,
            &OperationalRoots { master_secret: [1u8; 32], identity_key: [8u8; 32], cek: [3u8; 32] },
        );
        std::fs::create_dir_all(tmp.join("occupied")).unwrap();
        assert!(seal_vault_under(&host, USER, PASSPHRASE).is_err(), "the write fails");

        assert_eq!(std::fs::read(&vault).unwrap(), before, "the old vault's bytes survive");
        let roots = open_vault_under(&host, USER, PASSPHRASE).expect("and still open");
        assert_eq!(roots.identity_key, [2u8; 32], "to the roots it sealed");

        std::fs::remove_dir_all(&tmp).unwrap();
        seal_vault_under(&host, USER, PASSPHRASE).unwrap();
        assert_eq!(open_vault_under(&host, USER, PASSPHRASE).unwrap().identity_key, [8u8; 32]);
        assert!(!tmp.exists(), "no temporary copy after a write that succeeds");
    }

    fn bits(host: &CountingHost) -> f64 {
        kotton_crypto::provider::daily_credential::required_entropy_bits_for(
            attempt_limiting_for_user(host, USER),
        )
    }

    #[tokio::test]
    async fn the_bar_follows_the_binding_and_the_hardware_locks() {
        let (_tmp, host) = host();

        // Unbound: nothing counts, the full bar stands.
        assert_eq!(attempt_limiting_for_user(&host, USER), AttemptLimiting::None);
        assert_eq!(bits(&host), kotton_common::crypto::daily_credential::MIN_ENTROPY_BITS);

        // A passphrase seals the vault, then the device is bound under it.
        set_user_pin(&host, USER, PASSPHRASE).await.unwrap();
        bind_device(&host, USER, PASSPHRASE).await.unwrap();
        assert_eq!(host.counters.lock().unwrap().len(), 1);

        // Bound to something that counts: the bar drops to the counted figure.
        assert_eq!(attempt_limiting_for_user(&host, USER), AttemptLimiting::Hardware);
        assert_eq!(bits(&host), kotton_common::crypto::daily_credential::MIN_ENTROPY_BITS_HARDWARE_LIMITED);
        assert!(
            bits(&host) < 20.0,
            "a six-digit PIN (19.9 bits) must clear the counted bar"
        );

        // Changing the credential re-keys the hardware under the new one: a
        // second counter, the first retired, and the vault opens with the PIN.
        set_user_pin(&host, USER, PIN).await.unwrap();
        assert_eq!(host.counters.lock().unwrap().len(), 2);
        unlock_with_pin(&host, USER, PIN).await.unwrap();
        assert_eq!(host.counter(&[1]).wrong_attempts(), 0);

        // Wrong PINs are counted by the binding, not by us.
        for n in 1..=MAX_WRONG {
            let err = unlock_with_pin(&host, USER, "000000").await.unwrap_err();
            assert!(
                err.to_string().contains("hardware could not supply"),
                "a wrong PIN is refused by the hardware, not by the vault: {err}"
            );
            assert_eq!(host.counter(&[1]).wrong_attempts(), n);
        }

        // Past the limit the right PIN is refused too — the property that
        // makes 19.9 bits enough (DEC-0046).
        let err = unlock_with_pin(&host, USER, PIN).await.unwrap_err();
        assert!(format!("{err:#}").contains("locked"), "{err:#}");
    }

    /// Binding is a choice, not a consequence of the hardware being there: with
    /// no binding file the bar stays where it was even though `create_binding`
    /// would count.
    #[tokio::test]
    async fn an_unbound_user_keeps_the_full_bar() {
        let (_tmp, host) = host();
        set_user_pin(&host, USER, PASSPHRASE).await.unwrap();
        assert_eq!(attempt_limiting_for_user(&host, USER), AttemptLimiting::None);
        unlock_with_pin(&host, USER, PASSPHRASE).await.unwrap();
    }
}

/// The two resolvers above, over a store that cannot read one root
/// (`TASK-a-key-the-store-cannot-read-is-taken-for-no-key-and-a-new-one-is-minted`).
#[cfg(test)]
mod unreadable_root_tests {
    use super::*;
    use kotton_sys::secret::{SecretsError, SecretsResult};

    /// Reads of `broken` fail; every other label is the inner store's.
    struct OneUnreadable {
        inner: kotton_secret::MemorySecrets,
        broken: String,
    }
    impl SecretsStore for OneUnreadable {
        fn get_secret(&self, key: &str) -> SecretsResult<Option<String>> {
            if key == self.broken {
                return Err(SecretsError::Storage("the keychain did not answer".into()));
            }
            self.inner.get_secret(key)
        }
        fn set_secret(&self, key: &str, value: &str) -> SecretsResult<()> {
            self.inner.set_secret(key, value)
        }
        fn delete_secret(&self, key: &str) -> SecretsResult<()> {
            self.inner.delete_secret(key)
        }
    }

    /// A store holding a legacy `seed32` beside a root whose read fails.
    fn with_seed_and_unreadable(broken: String) -> OneUnreadable {
        let inner = kotton_secret::MemorySecrets::new();
        inner.set_secret(&kdf_labels::seed32_keychain_key("u"), &hex::encode([7u8; 32])).unwrap();
        OneUnreadable { inner, broken }
    }

    /// **An operational CEK the store cannot read is an error, never the
    /// `seed32` derivation.** Taken for absent, the read fell through to the
    /// legacy fallback and answered with a key derived from another root — a
    /// CEK the account does not seal under.
    #[test]
    fn an_unreadable_operational_cek_is_an_error_not_the_seed_derivation() {
        let s = with_seed_and_unreadable(kdf_labels::operational_cek("u"));
        let got = format!("{:?}", resolve_operational_cek(&s, "u"));
        assert!(got.contains("the keychain did not answer"), "the read's error is returned: {got}");
    }

    /// **A master secret the store cannot read is an error, never "absent".**
    #[test]
    fn an_unreadable_master_secret_is_an_error_not_absent() {
        let s = with_seed_and_unreadable(kdf_labels::master_secret_keychain_key("u"));
        let got = format!("{:?}", resolve_master_secret(&s, "u"));
        assert!(got.contains("the keychain did not answer"), "the read's error is returned: {got}");
    }
}
