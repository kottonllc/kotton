// SPDX-License-Identifier: AGPL-3.0-or-later
//! Device-network membership — who is admitted to the user's fleet.
//!
//! The membership set is the single source of truth for **every principal
//! admitted to the user's network** — own devices (by enrollment), contacts (by
//! contact pairing), and relays. The paired-key allowlist,
//! the relay allowlist, and the device list are all **computed views** over it,
//! distinguished by `Role` — they are never edited independently. Revoke once
//! (remove a member) and every derived gate closes on the next handshake.
//!
//! Members are stored as individual VFS objects on the `"local"` mount at
//! `Member::vfs_path` (`/network/members/<did>`), CEK-encrypted like any file,
//! so they sync across the user's own nodes and are readable by an
//! enrolled node that holds only the operational CEK (not `seed32` /
//! `master_secret`). One object per DID keeps concurrent admissions on different
//! nodes conflict-free and makes revocation a per-member tombstone.
//!
//! **What a member's DID is.** For an own device, a name for its key: the key's
//! derivation, its `did:key`, and nothing else ([`Membership::write_member`]
//! writes no other, kottonllc/kotton#597, 27A). For a contact, the person's
//! identifier, beside the key their key log resolves to today, which changes
//! under the same DID when they rotate. A member is admitted by its key's
//! bytes, whatever an earlier build spelled beside them (5B).
//!
//! ## Why this lives in `peer`
//!
//! As an inherent impl on the user runtime, every peer handler needing
//! membership would name the runtime crate, and `peer -> runtime -> device ->
//! peer` is a cycle. (The crate is not spelled here on purpose — the criterion
//! is checked with `grep -c`, and a mention would be a false positive.)
//!
//! Membership is not the machine's, or even the user runtime's. It is the
//! source of truth for principals admitted to *the user's network* — the
//! fleet's vocabulary. All it needs from a store is somewhere to put bytes.
//!
//! So that is all it asks for. [`MemberStore`] is **four methods**, and anything
//! that can store bytes under a path satisfies it. `UserRuntime` implements it
//! by delegating to its VFS; `peer` never learns that `UserRuntime` exists.
//!
//! This is the inverse of a `UserHandle` trait, which would narrow a *reach
//! into the registry* — making an unwanted capability safe
//! rather than absent. This one **inverts a dependency**: domain logic naming
//! what it needs instead of who provides it.

use anyhow::{Context, Result};
use kotton_schemas::membership::{member_path, Member, ReachNote};

/// VFS prefix (on the `"local"` mount) under which member records live.
const MEMBERS_PREFIX: &str = "/network/members/";

/// Where this person's own last-signed reach note is kept: a daemon object
/// beside their members, out of every app's reach, and carried to their other
/// devices by the same sync — so the next note any of them signs starts from
/// the version this one reached. Outside [`MEMBERS_PREFIX`], so it is never
/// listed as a member.
const OWN_REACH_NOTE_PATH: &str = "/network/reach-note";

/// The directory [`OWN_REACH_NOTE_PATH`] is listed in.
const NETWORK_DIR: &str = "/network/";

/// Somewhere to keep membership records — the whole of what this domain needs
/// from its host.
#[async_trait::async_trait]
pub trait MemberStore: Send + Sync {
    async fn member_write(&self, path: &str, data: &[u8]) -> Result<()>;
    async fn member_read(&self, path: &str) -> Result<Vec<u8>>;
    async fn member_delete(&self, path: &str) -> Result<()>;
    async fn member_list(&self, prefix: &str) -> Result<Vec<String>>;
}

/// The membership verbs and the views projected from them.
///
/// Blanket-implemented for every [`MemberStore`], so call sites keep the method
/// syntax they had when these were inherent on `UserRuntime`.
#[async_trait::async_trait]
pub trait Membership: MemberStore {

    /// Write (insert or replace) a membership record — the source of truth the
    /// computed views are projected from.
    ///
    /// The member's key is put to the Ed25519 rule first, and a member whose
    /// bytes it refuses is not written: every member this writes names a key,
    /// so a member under such bytes is one an earlier build wrote. Such a member
    /// is left in the set and read as no key (the projection writes nothing for
    /// it), and is removed by [`Self::remove_found`], found in the set's own
    /// listing by its DID as stored.
    ///
    /// **An own device's DID is its key's derivation, or it is not written**
    /// (kottonllc/kotton#597, 27A): for an own device the DID is a name for its
    /// key, [`kotton_crypto::DidKeyMethod::from_public_key`], and no writer can
    /// hand the set a second one. A contact's DID names the person, and the key
    /// beside it is what their key log resolves to today, so it changes under
    /// the same DID when they rotate: a contact's member, and a relay's, are
    /// written as given.
    async fn write_member(&self, member: &Member) -> Result<()> {
        let key = kotton_crypto::ed25519::VerifyingKey::from_bytes(&member.public_key)
            .map_err(|e| anyhow::anyhow!("member {}: its key is not an Ed25519 key: {e}", member.did))?;
        if member.is_own_device() {
            let derived = kotton_crypto::DidKeyMethod::from_public_key(&key);
            if member.did != derived.to_string() {
                anyhow::bail!(
                    "own-device member {}: its DID is not the did:key of its key, which is {derived}; \
                     nothing was written",
                    member.did
                );
            }
        }
        let json = serde_json::to_vec(member).context("serialize member record")?;
        self.member_write(&member.vfs_path(), &json)
            .await
            .with_context(|| format!("write member {}", member.did))
    }

    /// Read one membership record by DID. Returns `Ok(None)` when no record is
    /// present (the caller treats absence as "not a member").
    async fn read_member(&self, did: &str) -> Result<Option<Member>> {
        match self.member_read(&member_path(did)).await {
            Ok(bytes) => Ok(Some(
                serde_json::from_slice(&bytes)
                    .with_context(|| format!("parse member record {did}"))?,
            )),
            Err(_) => Ok(None),
        }
    }

    /// List every membership record. Skips directory entries and any object that
    /// fails to parse as a [`Member`] (a corrupt or foreign file must not abort
    /// the whole projection).
    ///
    /// **A failure of the listing itself is an error, not an empty set**, and the
    /// difference is the whole reason this doc paragraph exists. Ended with
    /// `unwrap_or_default()`, a store that could not open its own objects — a
    /// node whose account is locked, which is every node between a restart and
    /// its unlock — would answer *"this person is a member of nothing"*. Every
    /// computed view is projected from this set, so the contact list, the People
    /// screens, the paired-key allowlist and the doors handed to a vault would all
    /// go empty with success reported at every step, and a node could complete a
    /// pairing ceremony, print *"Paired with"*, restart, and report that it knew
    /// nobody — while the storage layers answered correctly all along.
    ///
    /// The per-object skips below stay: one unreadable object among many is a
    /// projection with a hole in it, and aborting on it would let a single corrupt
    /// or foreign file empty the whole set. A listing that cannot be taken at all
    /// is the other thing, and every caller already has an arm for it.
    async fn list_members(&self) -> Result<Vec<Member>> {
        Ok(self.list_found().await?.into_iter().map(|f| f.member).collect())
    }

    /// [`Self::list_members`], each member beside the key the set's own listing
    /// gave for its object: the one thing [`Self::remove_found`] removes by.
    ///
    /// A member is found by what the listing returns and never by a path made
    /// from a name. A member's object is kept under its DID, but nothing holds the
    /// DID an object carries to the key it is listed under, and a name a person
    /// typed is compared with what is stored, never joined into a store path
    /// (kottonllc/kotton#610).
    async fn list_found(&self) -> Result<Vec<Found>> {
        let keys = self
            .member_list(MEMBERS_PREFIX)
            .await
            .context("read the membership set — this node may be locked")?;
        let mut members = Vec::new();
        for key in keys {
            if key.ends_with('/') {
                continue; // directory entry, not a member object
            }
            match self.member_read(&key).await {
                Ok(bytes) => match serde_json::from_slice::<Member>(&bytes) {
                    Ok(member) => members.push(Found { key, member }),
                    // The key and the kind of failure, never serde's text:
                    // for a field of the wrong type it quotes the value, and
                    // the value is a decrypted card's.
                    Err(e) => tracing::warn!(key, kind = ?e.classify(), "a member object does not parse; left out of the set"),
                },
                Err(e) => tracing::warn!(key, error = format!("{e:#}"), "a member object is unreadable; left out of the set"),
            }
        }
        Ok(members)
    }

    /// A known member's stored Ed25519 public key.
    ///
    /// [`Member::public_key`] is captured at admission precisely so this needs
    /// no re-derivation from a DID — which matters for `did:kel`, where the
    /// identifier carries no key at all.
    ///
    /// This is the key as of admission, or as of the last key log the contact
    /// sent that proved a newer one. A contact who rotates re-signs their reach
    /// note with the new key and sends their log with it; the card takes the
    /// key that log resolves to from the AID it holds, and from nothing else
    /// (`kotton_msg::daemon::delivery`), so a rotated person's contacts learn
    /// the new key.
    /// Until that note arrives the key here is the retired one: a wrong-key
    /// failure, never a silent disclosure.
    ///
    /// Not on `DeviceRuntime`: there it would take a `user_id`, and the machine
    /// would resolve an id to a user's runtime before it could answer — and with
    /// the resolution at the caller, the body uses nothing of the machine at all. See the module note
    /// on [`Self::list_contacts`].
    async fn member_public_key(&self, did: &str) -> Option<[u8; 32]> {
        self.read_member(did).await.ok().flatten().map(|m| m.public_key)
    }

    /// Every contact admitted by this user, as `(did, label)`.
    ///
    /// The contact view, in the same sense as the paired-key allowlist and the
    /// device list above: a projection of the membership set filtered by
    /// [`Role`], never a separately edited collection.
    ///
    /// Here and not on `DeviceRuntime`, and that is the point rather than a
    /// tidy-up. On the machine, holding the registry that turns a `user_id`
    /// into a runtime, anything needing a user's data would be reachable from
    /// the machine. With the resolution hop at the caller that already knows
    /// *which* user is asking, this and [`Self::member_public_key`] name no
    /// machine state whatsoever. They are not device operations.
    async fn list_contacts(&self) -> Result<Vec<(String, Option<String>)>> {
        use kotton_schemas::membership::Role;
        Ok(self
            .list_members()
            .await?
            .into_iter()
            .filter(|m| m.role == Role::Contact)
            .map(|m| (m.did, m.label))
            .collect())
    }

    /// Every vault this person has enrolled, as `(did, label)`, in DID order.
    ///
    /// The vault view: an [`Role::OwnDevice`] admitted under
    /// [`Posture::BlindStorage`](kotton_schemas::membership::Posture::BlindStorage),
    /// which is what `finalize_enrolled_node` writes when a vault is admitted —
    /// by `kotton drive enrol … --blind` and by an invite pasted at Settings'
    /// door alike, since both run `handle_device_admit`. A projection, like the
    /// contact view beside it, and never a separately edited collection.
    ///
    /// **Why this and not the remote set.** Admission never writes
    /// `config.toml`'s `RemoteBackend::Kotton` entries — a remote is the peer
    /// storage *opened* to a node, registered the first time something syncs to
    /// it — so read from there, a vault admitted a second ago would be in no list
    /// the person could see, and one revoked would stay in it, because revocation
    /// removes the member and not the remote.
    /// Admission and revocation both edit this set, so a view over it has
    /// nothing to fall out of step with.
    ///
    /// A listing that cannot be taken is an error, for the reason
    /// [`Self::list_members`] gives: *could not look* is not *no vaults*.
    async fn list_vaults(&self) -> Result<Vec<(String, Option<String>)>> {
        use kotton_schemas::membership::{Posture, Role};
        let mut vaults: Vec<(String, Option<String>)> = self
            .list_members()
            .await?
            .into_iter()
            .filter(|m| m.role == Role::OwnDevice && m.posture == Some(Posture::BlindStorage))
            .map(|m| (m.did, m.label))
            .collect();
        // The store lists objects in whatever order its mount keeps them; a
        // person and a test should see one order.
        vaults.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(vaults)
    }

    /// The reach note this person last signed, or `None` before the first.
    ///
    /// *None held* is decided by the listing, not by a failed read. A read
    /// error taken as absence would have the next note signed at the current
    /// time, which can be a lower version than the note contacts already hold
    /// — and every one of them would refuse it. So a note that is listed and
    /// cannot be read is an error, and nothing is signed over it.
    async fn read_own_reach_note(&self) -> Result<Option<ReachNote>> {
        let listed = self
            .member_list(NETWORK_DIR)
            .await
            .context("look for this person's reach note — this node may be locked")?;
        // The store lists keys without the leading slash.
        let wanted = OWN_REACH_NOTE_PATH.trim_start_matches('/');
        if !listed.iter().any(|k| k.trim_start_matches('/') == wanted) {
            return Ok(None);
        }
        let bytes = self
            .member_read(OWN_REACH_NOTE_PATH)
            .await
            .context("read this person's reach note")?;
        Ok(Some(serde_json::from_slice(&bytes).context("parse this person's reach note")?))
    }

    /// Keep `note` as the one this person last signed.
    async fn write_own_reach_note(&self, note: &ReachNote) -> Result<()> {
        let json = serde_json::to_vec(note).context("serialize reach note")?;
        self.member_write(OWN_REACH_NOTE_PATH, &json)
            .await
            .context("write this person's reach note")
    }

    /// Remove a member the set's own listing returned (revocation), by the key
    /// the listing gave for its object ([`Self::list_found`]). Deleting the
    /// object closes every computed view that referenced this member on the next
    /// projection.
    async fn remove_found(&self, found: &Found) -> Result<()> {
        self.member_delete(&found.key)
            .await
            .with_context(|| format!("remove member {}", found.member.did))
    }
}

/// A member as the set's own listing returned it: the member, and the key its
/// object was listed under ([`Membership::list_found`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// The key the listing gave for the member's object.
    pub key: String,
    /// The member the object holds.
    pub member: Member,
}

#[async_trait::async_trait]
impl<T: MemberStore + ?Sized> Membership for T {}

/// A user's store is the place their member records go.
///
/// It sits in `peer` rather than `store` because the
/// dependency should run in the direction of the need: `membership` is what
/// wants records persisted, and `store` should never learn what a member is.
///
/// The four verbs are the store's own operations on **the daemon's records**,
/// not on the person's files. Nothing here chooses a mount or names a host OS —
/// the store was handed its filesystem when it was built, which is the property
/// that lets this impl exist at all without dragging `kotton-fs` into a domain
/// crate.
///
/// **Not `write_file`.** Those verbs address the person's own tree, which an
/// app with a `files` grant reaches; through them, an app granted `files.write`
/// on `/` could write an own-device member that this set then fed to the
/// paired-key allowlist.
/// The daemon's verbs address keys no person path resolves to.
#[async_trait::async_trait]
impl MemberStore for kotton_store::runtime::user::UserStore {
    async fn member_write(&self, path: &str, data: &[u8]) -> Result<()> {
        self.write_daemon_object(path, data).await
    }

    async fn member_read(&self, path: &str) -> Result<Vec<u8>> {
        self.read_daemon_object(path).await
    }

    async fn member_delete(&self, path: &str) -> Result<()> {
        self.delete_daemon_object(path).await
    }

    async fn member_list(&self, prefix: &str) -> Result<Vec<String>> {
        self.list_daemon_objects(prefix).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotton_crypto::derive_cek;
    use kotton_schemas::membership::{Ceremony, Member, Posture, Role};
    use kotton_store::runtime::{user::UserStore, UserKeys};
    use tempfile::TempDir;

    /// Remove the members under `did` as stored, found in the set's own listing,
    /// as a revoke does.
    async fn remove(store: &UserStore, did: &str) {
        for found in store.list_found().await.unwrap().into_iter().filter(|f| f.member.did == did) {
            store.remove_found(&found).await.unwrap();
        }
    }

    fn member(did: &str, role: Role, posture: Option<Posture>) -> Member {
        Member {
            did: did.to_string(),
            public_key: *kotton_crypto::ed25519::verifying_key(&ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])).as_bytes(),
            role,
            admitted_by: Ceremony::DeviceEnroll,
            added_at: "2026-06-26T00:00:00Z".to_string(),
            posture,
            label: Some("home-vps".to_string()),
            reach: None,
        }
    }

    /// An own device under `seed`'s key, named by its key's derivation, as every
    /// writer of an own-device member names it (kottonllc/kotton#597, 27A).
    fn own(seed: u8, posture: Posture) -> Member {
        let key = kotton_crypto::ed25519::verifying_key(&ed25519_dalek::SigningKey::from_bytes(&[seed; 32]));
        Member {
            did: kotton_crypto::DidKeyMethod::from_public_key(&key).to_string(),
            public_key: *key.as_bytes(),
            ..member("", Role::OwnDevice, Some(posture))
        }
    }

    /// A store with an encrypted local mount, as an enrolled node has.
    ///
    /// These came from `05_runtime`, where they ran against a `UserRuntime`.
    /// They exercise the domain through a real store rather than a stub, which
    /// is the half worth testing — the trait's default methods are covered by
    /// whoever implements it.
    fn store(temp: &TempDir) -> UserStore {
        UserStore::create(
            "alice",
            "did:key:zAlice",
            temp.path().to_path_buf(),
            UserKeys::new(Some(derive_cek(&[7u8; 32]))),
            &kotton_store::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap()
    }

    /// A person's own note round-trips, is absent before the first, and is
    /// never listed as a member.
    #[tokio::test]
    async fn the_own_reach_note_round_trips_and_is_not_a_member() {
        let temp = TempDir::new().unwrap();
        let store = store(&temp);
        assert_eq!(store.read_own_reach_note().await.unwrap(), None);
        let note = ReachNote {
            did: "did:key:zAlice".into(),
            relays: vec![],
            devices: vec![],
            version: 7,
            expires_at: 9,
            sig: "00".into(),
        };
        store.write_own_reach_note(&note).await.unwrap();
        assert_eq!(store.read_own_reach_note().await.unwrap(), Some(note));
        assert!(store.list_members().await.unwrap().is_empty());
    }

    /// A note that is there and cannot be read is an error, never *none held*:
    /// read as none, the next note would be signed at the current time, which
    /// can be below the version every contact holds, and all of them would
    /// refuse it.
    #[tokio::test]
    async fn an_unreadable_own_reach_note_is_an_error_not_none() {
        let temp = TempDir::new().unwrap();
        let store = store(&temp);
        store.member_write(OWN_REACH_NOTE_PATH, b"not a note").await.unwrap();
        assert!(store.read_own_reach_note().await.is_err());
    }

    /// **A member under bytes the Ed25519 rule refuses is not written**, for every
    /// key vector: the set holds what it held. One an earlier build wrote is read
    /// back as it was, and removed by its DID as stored.
    #[tokio::test]
    async fn a_member_under_bytes_the_rule_refuses_is_not_written_and_one_stored_is_removed() {
        let temp = TempDir::new().unwrap();
        let store = store(&temp);
        let own = own(2, Posture::Full);
        store.write_member(&own).await.unwrap();
        for (name, bytes) in kotton_crypto::ed25519::refused_keys() {
            let mut m = member("did:key:zEarlier", Role::OwnDevice, Some(Posture::Full));
            m.public_key = bytes;
            let why = store.write_member(&m).await.unwrap_err().to_string();
            assert!(why.contains("not an Ed25519 key"), "{name}: {why}");
            assert_eq!(store.list_members().await.unwrap(), vec![own.clone()], "{name}");

            store.member_write(&m.vfs_path(), &serde_json::to_vec(&m).unwrap()).await.unwrap();
            assert_eq!(store.read_member("did:key:zEarlier").await.unwrap(), Some(m.clone()), "{name}");
            remove(&store, "did:key:zEarlier").await;
            assert_eq!(store.list_members().await.unwrap(), vec![own.clone()], "{name}");
        }
    }

    #[tokio::test]
    async fn member_round_trips_through_the_vfs() {
        let temp = TempDir::new().unwrap();
        let store = store(&temp);

        let own = own(2, Posture::Full);
        store.write_member(&own).await.unwrap();

        assert_eq!(
            store.read_member(&own.did).await.unwrap(),
            Some(own.clone())
        );
        // A missing DID is None, not an error.
        assert_eq!(store.read_member("did:key:zMissing").await.unwrap(), None);
        assert_eq!(store.list_members().await.unwrap(), vec![own]);
    }

    #[tokio::test]
    async fn remove_member_closes_the_view() {
        let temp = TempDir::new().unwrap();
        let store = store(&temp);

        let a = own(3, Posture::Full);
        store.write_member(&a).await.unwrap();
        store
            .write_member(&member("did:key:zB", Role::Contact, None))
            .await
            .unwrap();
        assert_eq!(store.list_members().await.unwrap().len(), 2);

        remove(&store, &a.did).await;
        let remaining = store.list_members().await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].did, "did:key:zB");
        assert_eq!(store.read_member(&a.did).await.unwrap(), None);
    }

    #[tokio::test]
    async fn computed_views_filter_by_role() {
        let temp = TempDir::new().unwrap();
        let store = store(&temp);
        let dev = own(4, Posture::Full);
        for m in [
            dev.clone(),
            member("did:key:zContact", Role::Contact, None),
            member("did:key:zRelay", Role::Relay, None),
        ] {
            store.write_member(&m).await.unwrap();
        }

        let all = store.list_members().await.unwrap();
        // The paired-key allowlist is the device fleet, and nobody else. A
        // contact has their own door — a per-pair mailbox admitting one key,
        // serving one verb — and admitting them
        // here as well would put them back on the peer listener and on every
        // device reservation, with a standing check as the only guard.
        let admitted: Vec<_> = all
            .iter()
            .filter(|m| m.in_paired_key_allowlist())
            .collect();
        assert_eq!(admitted.len(), 1, "own devices only: {admitted:?}");
        assert_eq!(admitted[0].did, dev.did);
        // device-list view = own-device only.
        let devices: Vec<_> = all.iter().filter(|m| m.is_own_device()).collect();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].did, dev.did);
    }

    /// The vault view is the blind own devices, and revoking one takes it out.
    ///
    /// A full device, a co-signer, a contact and a relay are each a member and
    /// none of them is a vault; the two blind own devices are, in DID order.
    /// Removing one is the revocation `device revoke` performs
    /// (`daemon::nodes::revoke_named`), and the view follows it with nothing
    /// else edited.
    #[tokio::test]
    async fn the_vault_view_is_the_blind_own_devices_and_follows_revocation() {
        let temp = TempDir::new().unwrap();
        let store = store(&temp);
        let (one, two) = (own(5, Posture::BlindStorage), own(8, Posture::BlindStorage));
        // In DID order, as the view lists them.
        let (first, second) = if one.did < two.did { (one.clone(), two.clone()) } else { (two.clone(), one.clone()) };
        for m in [
            one,
            own(6, Posture::Full),
            own(7, Posture::Cosigner),
            two,
            member("did:key:zContact", Role::Contact, None),
            member("did:key:zRelay", Role::Relay, None),
        ] {
            store.write_member(&m).await.unwrap();
        }

        assert_eq!(
            store.list_vaults().await.unwrap(),
            vec![
                (first.did.clone(), Some("home-vps".to_string())),
                (second.did.clone(), Some("home-vps".to_string())),
            ]
        );

        remove(&store, &first.did).await;
        assert_eq!(
            store.list_vaults().await.unwrap(),
            vec![(second.did.clone(), Some("home-vps".to_string()))],
            "a revoked vault is out of the view with nothing else edited"
        );
    }

    /// A card rewritten while the set is listed is in the listing, old or new,
    /// and the listing is never an error, so a contact who learned a rotated
    /// key is reachable at the new door.
    ///
    /// The second write of a rotation — the reach note, straight after the
    /// key — raced the mailbox rebuild the first one woke, and an object read
    /// half-written failed the whole listing; the rebuild then left the person
    /// with no door for anyone, and nothing woke it again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_card_rewritten_while_the_set_is_listed_is_listed_whole() {
        let temp = TempDir::new().unwrap();
        let store = std::sync::Arc::new(store(&temp));
        let mut card = member("did:key:zBob", Role::Contact, None);
        store.write_member(&card).await.unwrap();
        let writer = {
            let store = std::sync::Arc::clone(&store);
            tokio::spawn(async move {
                for i in 0..400u32 {
                    card.label = Some(format!("bob, version {i} {}", "x".repeat(i as usize * 16)));
                    store.write_member(&card).await.unwrap();
                }
            })
        };
        let mut listings = 0u32;
        while !writer.is_finished() {
            let set = store.list_members().await;
            let set = set.unwrap_or_else(|e| panic!("listing {listings} failed mid-write: {e:#}"));
            assert_eq!(set.len(), 1, "listing {listings} lost the card mid-write");
            listings += 1;
        }
        writer.await.unwrap();
        assert!(listings > 0, "the listing ran beside the writes");
    }

    /// **An own device's DID is its key's derivation, or it is not written**
    /// (kottonllc/kotton#597, 27A): an own-device member under another spelling
    /// of its key's `did:key`, under another key's `did:key`, and under a DID of
    /// another method, each beside a key from a seed, is refused and the set
    /// holds what it held; the same member under its key's derivation is
    /// written.
    #[tokio::test]
    async fn an_own_device_member_whose_did_is_not_its_keys_derivation_is_not_written() {
        let temp = TempDir::new().unwrap();
        let store = store(&temp);
        let honest = own(21, Posture::Full);
        let other = own(22, Posture::Full);
        for (name, did) in [
            ("another spelling", kotton_crypto::DidKeyMethod::spelled_otherwise(&honest.public_key).to_string()),
            ("another key's did:key", other.did.clone()),
            ("another method", "did:web:laptop.example".to_string()),
        ] {
            let m = Member { did, ..honest.clone() };
            let why = store.write_member(&m).await.expect_err(name).to_string();
            assert!(why.contains("not the did:key of its key") && why.contains(&honest.did), "{name}: {why}");
            assert!(store.list_members().await.unwrap().is_empty(), "{name}: a member was written");
        }
        store.write_member(&honest).await.unwrap();
        assert_eq!(store.list_members().await.unwrap(), vec![honest]);
    }

    /// **A contact's key changes under its DID, and a relay's member is written
    /// as given** (kottonllc/kotton#597, 27A): a contact's DID names the person,
    /// and the key beside it is what their key log resolves to today, so a
    /// rotation writes the new key under the same DID and the set holds one
    /// member for them, with the new key. Neither DID is the key's derivation.
    #[tokio::test]
    async fn a_contacts_key_changes_under_its_did_and_a_relays_member_is_written_as_given() {
        let temp = TempDir::new().unwrap();
        let store = store(&temp);
        let (before, after) = (own(23, Posture::Full).public_key, own(24, Posture::Full).public_key);
        let mut bob = Member { public_key: before, ..member("did:kel:Ebob", Role::Contact, None) };
        store.write_member(&bob).await.unwrap();
        bob.public_key = after;
        store.write_member(&bob).await.unwrap();
        assert_eq!(store.read_member("did:kel:Ebob").await.unwrap(), Some(bob.clone()));
        let relay = Member { public_key: before, ..member("did:key:zRelay", Role::Relay, None) };
        store.write_member(&relay).await.unwrap();
        let mut set = store.list_members().await.unwrap();
        set.sort_by(|a, b| a.did.cmp(&b.did));
        assert_eq!(set, vec![bob, relay]);
    }
}
