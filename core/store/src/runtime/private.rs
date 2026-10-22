// SPDX-License-Identifier: AGPL-3.0-or-later
//! A person's private objects: small things only their own daemon needs,
//! sealed under their own keys at rest and kept beside their store — in no
//! root, so no sync carries them, no target holds them and no guest's view of
//! the store names them.
//!
//! The first is the operator credential a landlord's desktop holds for an
//! instance: a key that
//! governs a machine, which must not travel to the machine it governs, nor to
//! a browser or an app through the file verbs. A file in the person's tree
//! would be sealed too, and reachable by every one of those.
//!
//! Sealed with the CEK and the path relative to the person's directory as
//! AAD, as the roots index's meaning half is; one blob at a known path, so
//! there is no path key to blind. Written durably, so a crash leaves the old
//! object or the new one.

use crate::runtime::roots::{plain_name, write_durably};
use crate::runtime::user::UserStore;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// The directory under a person's own that holds these, outside every root.
const DIR: &str = "private";

fn relative(name: &str) -> Result<PathBuf> {
    Ok(Path::new(DIR).join(format!("{}.sealed", plain_name(name)?)))
}

fn cek(store: &UserStore) -> Result<[u8; 32]> {
    let keys = store.sealing_keys().ok_or_else(|| {
        anyhow::anyhow!(
            "this node holds no keys for {}, so it keeps nothing private for them",
            store.user_id()
        )
    })?;
    Ok(*keys.cek)
}

/// Seal `bytes` under the person's keys and keep them as `name`, replacing
/// what was there.
pub fn write(store: &UserStore, name: &str, bytes: &[u8]) -> Result<()> {
    let rel = relative(name)?;
    let sealed = crate::provider::seal_envelope(&cek(store)?, &crate::provider::path_aad(&rel), bytes)
        .map_err(|e| anyhow::anyhow!("sealing {name}: {e}"))?;
    let path = store.base_dir().join(&rel);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    write_durably(&path, &sealed)
}

/// Open what is kept as `name`, or `None` when nothing is.
pub fn read(store: &UserStore, name: &str) -> Result<Option<Vec<u8>>> {
    let rel = relative(name)?;
    let sealed = match std::fs::read(store.base_dir().join(&rel)) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {name}")),
    };
    crate::provider::open_envelope(&cek(store)?, &crate::provider::path_aad(&rel), &sealed)
        .map(Some)
        .map_err(|e| anyhow::anyhow!("{name} did not open under this person's keys: {e}"))
}
