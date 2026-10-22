// SPDX-License-Identifier: AGPL-3.0-or-later
//! A person's name, kept as a record of theirs, so it travels with their
//! identity.
//!
//! The name a person types on the welcome, or sets later in Settings, is one of
//! the daemon's own records in **their** store: written through
//! [`UserStore::write_daemon_object`], sealed under their keys like every
//! object on the `local` mount, and carried to their other devices by the same
//! sync that carries their membership set and their reach note. A device
//! admitted to the identity later is therefore greeted by the same name without
//! being asked for it.
//!
//! **The record is the source; the registry is a cache.** Each device keeps a
//! copy in `device/users.json`'s `display_name` ([`crate::device_users`]),
//! because the lock screen greets the person before anything of theirs is
//! unlocked and cannot read a sealed store. That copy is written from the
//! record — when a write here succeeds, and when a sync pass lands one another
//! device wrote ([`refresh_cache`]) — and is never read back into it.
//!
//! **No app reaches it.** The key is outside the person's tree
//! (`kotton_store::runtime::user::PERSON_TREE_ROOT`), so no path a `files`
//! grant can name resolves to it — not even a grant on `/`, which is the
//! shell's — and the file browser does not show it. Only this module names
//! the key.
//!
//! **It goes nowhere a person's other sealed objects do not.** A relay or a
//! vault carries it the way it carries every other blob, without a key; no
//! peer that is not one of the person's own devices is sent it; and nothing
//! here puts it in a ceremony, a card, or a message. Whether a name is shown to
//! *other people* is Contacts' and Messages' question, not this record's.

use std::io;
use std::path::Path;

use anyhow::Context as _;
use kotton_store::runtime::user::UserStore;
use serde::{Deserialize, Serialize};

use crate::device_users;

/// Where the name is kept in the person's store. A daemon key: outside the
/// person's tree, so no files grant names it.
pub const NAME_PATH: &str = "/identity/name";

/// The directory [`NAME_PATH`] is listed in, so absence is decided by a listing
/// rather than by a read that failed.
const IDENTITY_DIR: &str = "/identity/";

/// The record at [`NAME_PATH`].
///
/// `name: None` is a person who cleared their name, which every device follows
/// by clearing its copy; a store with **no record at all** is a person whose
/// name was never written here (an identity the CLI made, or one made before
/// this record), and a device leaves its copy alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameRecord {
    /// What the desktop calls the person, as
    /// [`device_users::normalize_display_name`] reads it.
    pub name: Option<String>,
}

/// The name record in `store`, or `None` when there is none.
///
/// *None* is decided by the listing, as `read_own_reach_note` decides it: a
/// record that is listed and cannot be read or parsed is an error, never
/// absence, so a device never mistakes a record it failed to open for a person
/// who never said their name.
pub async fn read(store: &UserStore) -> anyhow::Result<Option<NameRecord>> {
    let listed = store
        .list_daemon_objects(IDENTITY_DIR)
        .await
        .context("look for this person's name — this node may be locked")?;
    // The store lists keys without the leading slash.
    let wanted = NAME_PATH.trim_start_matches('/');
    if !listed.iter().any(|k| k.trim_start_matches('/') == wanted) {
        return Ok(None);
    }
    let bytes = store
        .read_daemon_object(NAME_PATH)
        .await
        .context("read this person's name")?;
    Ok(Some(
        serde_json::from_slice(&bytes).context("parse this person's name")?,
    ))
}

/// Keep `raw`, as [`device_users::normalize_display_name`] reads it, as the
/// person's name in their own store. An empty name clears it. Returns what was
/// kept.
///
/// Normalised here and not only by callers, for the reason
/// `device_users::set_display_name` gives: every device's copy is written from
/// this record, and the `names` launch argument relies on no copy holding
/// U+001F.
pub async fn write(store: &UserStore, raw: &str) -> io::Result<Option<String>> {
    let name = device_users::normalize_display_name(raw)?;
    let json = serde_json::to_vec(&NameRecord { name: name.clone() })
        .map_err(|e| io::Error::other(format!("serialize the name record: {e}")))?;
    store
        .write_daemon_object(NAME_PATH, &json)
        .await
        .map_err(|e| io::Error::other(format!("keep the name with the identity: {e:#}")))?;
    Ok(name)
}

/// Bring this device's copy of `user_id`'s name up to the record in `store`.
///
/// Returns whether the copy changed. No record leaves the copy as it is. A
/// record whose name does not normalise is refused rather than copied: it came
/// from one of the person's own devices, but the copy is read by a launch that
/// splits on a control character, so the rule is held where the copy is made.
///
/// A device the person joined has no entry in the registry until something
/// makes one; the name arriving is that something, and the entry it makes
/// carries the store's DID, which is the identity the device joined
/// ([`device_users::cache_display_name`]).
pub async fn refresh_cache(base: &Path, user_id: &str, store: &UserStore) -> io::Result<bool> {
    let Some(record) = read(store).await.map_err(|e| io::Error::other(format!("{e:#}")))? else {
        return Ok(false);
    };
    let name = match record.name.as_deref() {
        Some(raw) => device_users::normalize_display_name(raw)?,
        None => None,
    };
    device_users::cache_display_name(base, user_id, store.did(), name.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotton_crypto::derive_cek;
    use kotton_store::runtime::UserKeys;
    use tempfile::TempDir;

    /// A store with an encrypted local mount, as an unlocked device has.
    fn store(temp: &TempDir) -> UserStore {
        UserStore::create(
            "alice",
            "did:kel:EAlice",
            temp.path().join("users").join("alice"),
            UserKeys::new(Some(derive_cek(&[7u8; 32]))),
            &kotton_store::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap()
    }

    /// The name round-trips through the store, normalised, and is absent before
    /// the first write.
    #[tokio::test]
    async fn the_name_round_trips_through_the_persons_store() {
        let temp = TempDir::new().unwrap();
        let store = store(&temp);
        assert_eq!(read(&store).await.unwrap(), None);
        assert_eq!(write(&store, "  Austin ").await.unwrap().as_deref(), Some("Austin"));
        assert_eq!(
            read(&store).await.unwrap(),
            Some(NameRecord { name: Some("Austin".into()) })
        );
        assert_eq!(write(&store, "   ").await.unwrap(), None, "an empty name clears it");
        assert_eq!(read(&store).await.unwrap(), Some(NameRecord { name: None }));
        assert!(write(&store, "Aus\u{1f}tin").await.is_err(), "the launch's separator");
    }

    /// A record that is there and cannot be parsed is an error, never *no
    /// name*: read as none, a device would keep a copy the person had changed.
    #[tokio::test]
    async fn an_unreadable_name_record_is_an_error_not_none() {
        let temp = TempDir::new().unwrap();
        let store = store(&temp);
        store.write_daemon_object(NAME_PATH, b"not a record").await.unwrap();
        assert!(read(&store).await.is_err());
    }

    /// The name is not in the person's tree: a listing of `/` and a read of the
    /// path the key would have as a file find nothing.
    #[tokio::test]
    async fn the_name_is_not_a_file_of_the_persons() {
        let temp = TempDir::new().unwrap();
        let store = store(&temp);
        write(&store, "Austin").await.unwrap();
        let listed = store.list_files("/").await.expect("the person's tree lists");
        assert!(
            listed.iter().all(|k| !k.contains("identity")),
            "the person's tree lists the name's key: {listed:?}"
        );
        assert!(store.read_file("/identity/name").await.is_err());
    }

    /// The copy follows the record: set, changed and cleared, and left alone
    /// when there is no record. A device with no entry for the person gets one,
    /// under the store's DID.
    #[tokio::test]
    async fn the_registry_copy_follows_the_record_and_never_leads_it() {
        let temp = TempDir::new().unwrap();
        let base = temp.path();
        let store = store(&temp);

        // No record: nothing to copy, and no entry is made from nothing.
        assert!(!refresh_cache(base, "alice", &store).await.unwrap());
        assert!(device_users::load(base).unwrap().is_empty());

        // A record arrives on a device that has no entry: the entry is made.
        write(&store, "Austin").await.unwrap();
        assert!(refresh_cache(base, "alice", &store).await.unwrap());
        let copy = &device_users::load(base).unwrap()["alice"];
        assert_eq!(copy.display_name.as_deref(), Some("Austin"));
        assert_eq!(copy.did, "did:kel:EAlice");

        // Unchanged: nothing written.
        assert!(!refresh_cache(base, "alice", &store).await.unwrap());

        // A copy edited on this device alone is put back to the record's.
        device_users::set_display_name(base, "alice", "Someone Else").unwrap();
        assert!(refresh_cache(base, "alice", &store).await.unwrap());
        assert_eq!(
            device_users::load(base).unwrap()["alice"].display_name.as_deref(),
            Some("Austin")
        );

        // Cleared in the record: cleared in the copy.
        write(&store, "").await.unwrap();
        assert!(refresh_cache(base, "alice", &store).await.unwrap());
        assert_eq!(device_users::load(base).unwrap()["alice"].display_name, None);
    }
}
