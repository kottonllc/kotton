// SPDX-License-Identifier: AGPL-3.0-or-later
//! The identity keys a person has rotated away from, kept so that what was
//! sealed to them still opens for the person.
//!
//! A direct message is sealed to one identity key and opens on that key alone.
//! A rotation used to replace the stored key outright, and with it every message
//! the person had received — and their own copy of every one they sent — stopped
//! opening
//! (`TASK-a-rotated-identity-key-leaves-every-older-message-sealed-to-a-key-the-node-no-longer-holds`).
//! The store is the person's (Article V); a routine rotation should not cost them
//! its contents.
//!
//! ## Where the retired keys live, and under what
//!
//! `users/{user_id}/identity/retired-keys.json`, **sealed to the current identity
//! key** ([`kotton_crypto::x25519::retired_keys_seal`]). Nothing new is held in
//! the clear and nothing new joins the vault or the custody layer: opening them
//! takes the current key, so they are under whatever lock the current key is
//! under. For a person with a PIN vault that is the vault, which a rotation
//! re-seals around the new key, so the set opens again after a restart and an
//! unlock (`TASK-a-rotation-leaves-the-pin-vault-holding-the-key-it-retired`).
//! They are read in this process, used to open, and never leave it.
//!
//! Each rotation re-seals the **whole** set to the new key. The alternative, a
//! chain where each retired key is sealed to its successor, would let anyone who
//! compromised one retired key walk back to every key before it; re-sealing means
//! that once a rotation has [`settle`]d, nothing on disk opens on any key but the
//! current one. `settle` is best-effort; until it succeeds, the previous set —
//! sealed to the key just retired — is still on disk.
//!
//! ## Why the file holds generations
//!
//! A rotation writes the new set *before* the keychain takes the new key, so a
//! failure between the two never leaves the retired keys sealed only to a key the
//! node does not hold. The file is a list of sealed sets, newest first; a read
//! takes the first one the current key opens. [`retire`] prepends; [`settle`],
//! called once the new key is stored, drops every generation the current key does
//! not open.
//!
//! ## What this does not do
//!
//! It keeps retired keys for **opening** — messages and anything else sealed to
//! them. Nothing here signs, and nothing here reaches a relay or a vault: a
//! retired key's only use is on the person's own node, to read what is already
//! theirs. It also cannot keep a key the node never held: a device recovering an
//! identity whose old key was on a lost device has nothing to retire.

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// One sealed set of retired keys. Hex, like the rest of this directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SealedSet {
    ephemeral_pub: String,
    nonce: String,
    body: String,
}

fn path(base_dir: &Path, user_id: &str) -> PathBuf {
    base_dir
        .join("users")
        .join(user_id)
        .join("identity")
        .join("retired-keys.json")
}

fn load(base_dir: &Path, user_id: &str) -> Result<Vec<SealedSet>> {
    let path = path(base_dir, user_id);
    match std::fs::read_to_string(&path) {
        Ok(json) => serde_json::from_str(&json).with_context(|| format!("parse {path:?}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(anyhow::Error::new(e).context(format!("read {path:?}"))),
    }
}

/// Write-then-rename, for the reason `kel_store::save_chain` gives: a torn
/// write of this file is the loss of every message sealed to a retired key.
fn save(base_dir: &Path, user_id: &str, sets: &[SealedSet]) -> Result<()> {
    let path = path(base_dir, user_id);
    if let Some(parent) = path.parent() {
        kotton_common::fs::create_dir_all_owner_only(parent).with_context(|| format!("create {parent:?}"))?;
    }
    let json = serde_json::to_string_pretty(sets).context("serialise retired keys")?;
    let tmp = path.with_extension("json.tmp");
    {
        use std::io::Write as _;
        let mut f = std::fs::File::create(&tmp).with_context(|| format!("create {tmp:?}"))?;
        f.write_all(json.as_bytes())
            .with_context(|| format!("write {tmp:?}"))?;
        f.sync_all().with_context(|| format!("sync {tmp:?}"))?;
    }
    std::fs::rename(&tmp, &path).with_context(|| format!("rename {tmp:?} -> {path:?}"))
}

fn open_set(set: &SealedSet, holder: &SigningKey) -> Result<Vec<SigningKey>> {
    let decode32 = |s: &str, what: &str| -> Result<[u8; 32]> {
        hex::decode(s)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| anyhow!("retired keys: {what} is not 32 hex bytes"))
    };
    let eph = decode32(&set.ephemeral_pub, "ephemeral_pub")?;
    let nonce: [u8; 12] = hex::decode(&set.nonce)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("retired keys: nonce is not 12 hex bytes"))?;
    let body = hex::decode(&set.body).context("retired keys: body is not hex")?;
    kotton_crypto::x25519::retired_keys_open(&body, &nonce, &eph, holder)
}

/// The keys `current` retired, newest first — every identity key this person
/// held on this node before `current`. Empty when there are none.
pub fn open(base_dir: &Path, user_id: &str, current: &SigningKey) -> Result<Vec<SigningKey>> {
    Ok(load(base_dir, user_id)?
        .iter()
        .find_map(|set| open_set(set, current).ok())
        .unwrap_or_default())
}

/// Retire `retiring` in favour of the key whose public half is `successor_pub`:
/// seal it, and every key it had itself retired, to the successor, and put that
/// set first in the file. Call **before** the successor is stored; then
/// [`settle`] once it is.
pub fn retire(
    base_dir: &Path,
    user_id: &str,
    retiring: &SigningKey,
    successor_pub: &[u8; 32],
) -> Result<()> {
    let mut sets = load(base_dir, user_id)?;
    let mut keys = vec![retiring.clone()];
    if let Some(older) = sets.iter().find_map(|set| open_set(set, retiring).ok()) {
        keys.extend(older);
    }
    let (body, nonce, eph) = kotton_crypto::x25519::retired_keys_seal(&keys, successor_pub)?;
    sets.insert(
        0,
        SealedSet {
            ephemeral_pub: hex::encode(eph),
            nonce: hex::encode(nonce),
            body: hex::encode(body),
        },
    );
    save(base_dir, user_id, &sets)
}

/// Drop every generation `current` does not open. After a rotation completes,
/// that leaves one set, sealed to the current key, and nothing on disk that any
/// retired key opens.
pub fn settle(base_dir: &Path, user_id: &str, current: &SigningKey) -> Result<()> {
    let sets = load(base_dir, user_id)?;
    let kept: Vec<SealedSet> = sets
        .iter()
        .filter(|set| open_set(set, current).is_ok())
        .take(1)
        .cloned()
        .collect();
    if kept.len() == sets.len() {
        return Ok(());
    }
    save(base_dir, user_id, &kept)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> SigningKey {
        SigningKey::from_bytes(&[b; 32])
    }

    fn bytes(keys: &[SigningKey]) -> Vec<[u8; 32]> {
        keys.iter().map(SigningKey::to_bytes).collect()
    }

    #[test]
    fn two_rotations_keep_both_retired_keys_under_the_current_one_only() {
        let dir = tempfile::tempdir().unwrap();
        let (k0, k1, k2) = (key(1), key(2), key(3));

        retire(dir.path(), "u", &k0, &k1.verifying_key().to_bytes()).unwrap();
        settle(dir.path(), "u", &k1).unwrap();
        assert_eq!(
            bytes(&open(dir.path(), "u", &k1).unwrap()),
            bytes(std::slice::from_ref(&k0))
        );

        retire(dir.path(), "u", &k1, &k2.verifying_key().to_bytes()).unwrap();
        settle(dir.path(), "u", &k2).unwrap();
        assert_eq!(
            bytes(&open(dir.path(), "u", &k2).unwrap()),
            bytes(&[k1.clone(), k0.clone()])
        );
        // Nothing left on disk opens on a retired key.
        assert!(open(dir.path(), "u", &k1).unwrap().is_empty());
        assert!(open(dir.path(), "u", &k0).unwrap().is_empty());
    }

    #[test]
    fn a_rotation_that_never_stored_its_key_loses_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (k0, k1, never) = (key(1), key(2), key(9));
        retire(dir.path(), "u", &k0, &k1.verifying_key().to_bytes()).unwrap();
        settle(dir.path(), "u", &k1).unwrap();

        // Retired toward a key the keychain then refused to take: k1 is still
        // current, and still opens what it had.
        retire(dir.path(), "u", &k1, &never.verifying_key().to_bytes()).unwrap();
        assert_eq!(bytes(&open(dir.path(), "u", &k1).unwrap()), bytes(&[k0]));
    }
}
