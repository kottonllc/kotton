// SPDX-License-Identifier: AGPL-3.0-or-later
//! The drive's verbs on a person's device: `drive
//! create <name> [--on <vault>]`, `list`, `show <name>` and `move <name> --to
//! <vault> [--from <vault>]`, over the several drives a person may keep on one vault or many.
//!
//! **A drive is a sealed tree a vault keeps for its tenant** (`kvaultd::drives`):
//! the tenancy's own tree, `local` — the pool every vault kept before, the
//! person's first drive there, which every device calls `personal` — and each
//! drive made beside it. What this device records of them is the drive record
//! ([`kotton_peer::daemon::drives`]), one row per vault, tenancy and tree.
//!
//! **Names are sealed, and the vault is where every device reads them.** A
//! made drive's name is sealed under the person's key, bound to the tree, and
//! kept by the vault beside the tree; any device of the person's opens it, the
//! vault never can. So the vault's listing (`TenantDrives`) is how a device
//! learns of a drive another device made, and of one moved away: [`follow`]
//! takes a vault's whole listing as what this device records of the drives
//! made there ([`kotton_peer::daemon::drives::reconcile`]). It runs at every
//! `drive list`, after every verb here that changes a vault, and after every
//! sync pass with a vault (`kotton_sync::engine`), so **every device follows a
//! drive** wherever it was made or moved, at its next pass, without being told.
//!
//! **A move carries the sealed tree under the same key.** This device reads
//! every sealed object of the drive from the vault it lives on and writes it,
//! byte for byte, to a tree made for it at the other — the objects stay sealed
//! under the person's key and neither vault can open them; the device declares
//! the person's own key domain, so a tree in any other domain is refused at the
//! read (`KottonPeerObjectStorage::get_sealed`). The tree at the other vault
//! has an id minted for it there, and its name is sealed afresh for that tree,
//! so the two landlords hold nothing in common for it.
//!
//! **A move is finished in one order, and undone in the reverse.** The tree at
//! the other vault is made under a name sealed *unfinished*
//! (`UserStore::seal_drive_name`), which every device reads as a move in
//! progress and never as a second drive of that name; the objects are
//! copied; the other vault's listing must name every key at its size; only
//! then is the tree named finished (`TenantDriveName`), and only after that is
//! the drive retired where it was ([`carry_and_settle`]). A copy, a check or a
//! naming that fails retires the unfinished tree and the drive stays where it
//! was; the person is told it was not moved. If the other vault will not
//! retire the unfinished tree either, the person is told that too, by the
//! tree's name: `drive list` on every device shows it as unfinished, and the
//! next move of that drive to that vault retires it before it starts.
//!
//! **A retire is idempotent, so its one retry is exact.** A vault answers a
//! retire of a made drive it no longer keeps with `Ok` (`kvaultd::drives`), so
//! an ask whose answer was lost and the ask after it agree. The clean-up
//! retire is asked a second time only when the first answer was not `Ok` — a
//! dropped connection, a timeout — and the second answer is then the truth;
//! the tree is said to be left only when the vault, asked twice, says it keeps
//! it.
//!
//! **Every copy of a drive carries the drive's id** (kotton #171;
//! kotton-protocol #26). A made drive's sealed name holds the
//! person's name for it and the drive's *id*, sixteen random bytes minted once
//! at `drive create` ([`mint_id`]) and sealed with every copy a move makes
//! ([`SealedName`]); the vault reads neither, and keeps only its own tree id,
//! minted fresh at each vault. The id names no vault, so it says nothing of
//! where the drive was first kept, and it is in no path or name a vault or a
//! relay sees: it lives inside the sealed name and in this device's record
//! ([`kotton_peer::daemon::drives::Drive::id`]). Two finished copies that share
//! an id are one drive kept twice: a move whose source retire failed, or a
//! device that died between naming the copy and retiring the source, or two
//! devices moving the same drive at once. **`drive move <name> --to <vault>`
//! resolves that state by the id** ([`plan_move`]): if `<vault>` holds a copy,
//! it keeps that one and retires the others, and answers that the drive moved
//! — the interrupted move, finished; if it holds none, it moves one copy there
//! and then retires the rest. Two copies of one name with *different* ids are
//! two drives that no move made — two `create`s that raced — and are left
//! alone: `move` refuses and names both, and `--from <vault>` names the one
//! meant.
//!
//! **A name sealed before ids, migrated in place.** kotton #155 sealed a
//! drive's *origin* (the vault and tree it was first made as) where the id now
//! is. Such a name reads with an id derived from that origin ([`legacy_id`]),
//! the same on every device and for every copy of one origin, so copies a move
//! made before ids still resolve as one drive; and the device that reads one
//! finished re-seals it with that id and names the tree again
//! (`TenantDriveName`), so the next reader finds an id and no origin. This is
//! a concession for records that exist (pre-alpha, no tag): a migrated drive's
//! id is a digest of where it was first made rather than random, so whoever
//! knows that vault's key and that tree could compute it — though, like every
//! id, it is only ever inside the sealed name and this device's record, and no
//! vault or relay is sent it. A drive made from here on carries a random one. `drive create` asks every vault the person keeps drives on before
//! it takes a name, and refuses while one does not answer, so a device whose
//! record is stale cannot make a second drive of a name another device took.
//!
//! **A listing taken mid-move never makes a device forget the drive.** Until
//! the source is retired, the vault it lives on lists it, so a device that
//! follows there keeps it; the other vault lists it only once it is named
//! finished, which is after it holds every object. Between the naming and the
//! retire both vaults list it, and a device may record it at both for one
//! pass; `drive show` names both, and the next `drive move` to the vault that
//! holds the finished copy retires the other, as above. A device whose one pass
//! followed the other vault before the naming and the source after the retire
//! has no record of the drive until its next pass; nothing at either vault is
//! lost by it, because the retire comes only after the other vault holds and
//! names every object, and the record is rebuilt from the vaults' listings.
//!
//! **What a move holds: the drive, on this device.** A move takes the drive's
//! lock on this device ([`drive_lock`], a [`DeviceRuntime::lock_mount`] keyed by
//! the drive's name) for the whole of it, so two moves of one drive on one
//! device are one after the other, and the second reads where the first left
//! it. A vault refuses a write into a tree it is retiring
//! (`kvaultd::drives::retire`). What no device-local lock can hold is another
//! device: two devices moving one drive at once, two making one name at once,
//! or a pass another device runs into a made drive while this one moves it.
//! Today no device writes into a made drive — a device keeps no tree of one
//! until drive paths (kotton #58) and the first drive among others (#124) —
//! so the last cannot happen yet, and the first two are resolved afterwards by
//! the next move as above. Making them exclusive needs a lease or a sequence
//! the vault keeps, which is a design of its own and is filed as one.
//!
//! **What does not move yet: the first drive.** The tenancy's own tree is what
//! this device's own tree syncs with, at every vault the person keeps drives
//! on (`kotton_sync::engine`); it is kept at each and lives at none alone, so
//! `move` refuses it and says so. Its id is
//! [`kotton_wire::ipc::FIRST_DRIVE_ID`] until #124 makes it a made drive. A
//! device keeping a made drive's files — and so the first drive becoming one
//! drive among others — is the drive paths' (kotton #58) and #124's.
//!
//! **Which devices keep a drive whole: its claims, and nothing else.** What a
//! device keeps of a drive is its pin settings, which are its own and stay in
//! its own database (`crate::users::pins`); what it publishes is one sealed
//! whole-keeper claim per drive it keeps whole, a record in that drive keyed by
//! the device and the drive's id. `drive list`, `show`, `create` and `move`
//! name the devices that keep each drive whole from those claims, matched by
//! the drive's id and counted only for devices still in the person's device
//! set ([`describe`]). A drive's claims ride inside it, so a move carries them
//! and a retire takes them with the tree. **Seam, not built:** the creating
//! device's claim at `drive create` waits until a device keeps a tree of a made
//! drive (kotton #58, #124), so today no claim names a made drive and every
//! made drive is told of as kept whole by nobody, which is true.
//!
//! **What a drive is, told to its person** (the drive decision's types).
//! `drive create`, `list`, `show` and `move` answer with descriptors
//! ([`describe`]), one per vault a drive is kept at: the drive's id, its
//! name, the vault that keeps it, its size as that vault last said, the
//! devices that claim it whole, and whether it is a move's unfinished tree.
//! The id is the record's ([`kotton_peer::daemon::drives::Drive::id`]) —
//! [`kotton_wire::ipc::FIRST_DRIVE_ID`] for the first drive until #124 mints
//! it one — and an unfinished tree's is the id sealed with it, so copies of
//! one drive show one id and two drives of one name show two. A descriptor is
//! this device's answer to its own person over its own IPC; no descriptor,
//! and so no id, is sent to a vault or a relay.

use crate::users::DeviceUsers as _;
use crate::users::pins;
use crate::DeviceRuntime;
use kotton_record::SqliteRecordStore;
use kotton_peer::daemon::drives::{self as record, Drive};
use kotton_peer::KottonPeerObjectStorage;
use kotton_store::runtime::user::UserStore;
use kotton_sys::store::SealedObjectAccess as _;
use kotton_wire::ipc::{DriveDescriptor, MadeDrive, TenantDrive, UserRequest, UserResponse, FIRST_DRIVE_ID, FIRST_DRIVE_TREE};
use kotton_wire::peer::PairedNode;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// How long one vault is given to answer one request.
const EACH_VAULT: Duration = Duration::from_secs(20);

/// The longest name a drive may have, in bytes.
pub const MAX_NAME: usize = 128;

fn refused(message: impl Into<String>) -> io::Result<UserResponse> {
    Ok(UserResponse::Error { message: message.into() })
}

/// Where kotton #155 sealed that a drive was first made — a vault's key, hex,
/// and the tree — before a drive had an id. Read from a name sealed then, and
/// never written ([`legacy_id`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Origin {
    pub vault_key: String,
    pub tree: String,
}

/// What a made drive's sealed name holds (module doc): the person's name for
/// it, and the drive's id, shared by every copy a move makes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedName {
    pub name: String,
    pub id: String,
}

/// A sealed name as it may have been sealed: with an id, or, by kotton #155,
/// with an origin in its place.
#[derive(Deserialize)]
struct AsSealed {
    name: String,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    origin: Option<Origin>,
}

impl SealedName {
    fn seal(&self, store: &UserStore, tree: &str, finished: bool) -> io::Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self).map_err(io::Error::other)?;
        store.seal_drive_name(tree, &bytes, finished).map_err(|e| io::Error::other(format!("{e:#}")))
    }

    /// The name sealed in `bytes`, and whether it was sealed before ids (and
    /// so carries [`legacy_id`]'s id for `here`, the place it is listed at).
    fn read(bytes: &[u8], here: &Origin) -> Result<(Self, bool), String> {
        let sealed: AsSealed = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        Ok(match sealed.id {
            Some(id) => (Self { name: sealed.name, id }, false),
            None => (Self { name: sealed.name, id: legacy_id(sealed.origin.as_ref().unwrap_or(here)) }, true),
        })
    }
}

/// A new drive's id: sixteen random bytes, hex (module doc).
pub fn mint_id() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

/// The id a drive whose name kotton #155 sealed with an `origin` reads with
/// (module doc): a digest of that origin, so every copy of one origin, read on
/// any device, has the same id, and copies never share one with a drive made
/// elsewhere. Sixteen bytes, hex, as [`mint_id`]'s.
pub fn legacy_id(origin: &Origin) -> String {
    let said = serde_json::to_vec(&(&origin.vault_key, &origin.tree)).unwrap_or_default();
    let digest = blake3::derive_key("kotton 2026-10-28 a drive's id from the origin #155 sealed", &said);
    hex::encode(&digest[..16])
}

/// One copy of a drive at one vault, as that vault's listing says it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Copy {
    pub vault_key: [u8; 32],
    pub tree: String,
    pub name: String,
    /// The drive's id, from its sealed name (module doc).
    pub id: String,
    /// Sealed bytes the vault holds in the tree.
    pub held: u64,
    /// A name sealed finished: a drive. Unfinished: a move's tree.
    pub finished: bool,
    /// Its name was sealed before ids ([`legacy_id`]), and is to be sealed
    /// again with its id.
    pub sealed_before_ids: bool,
}

impl Copy {
    fn made(&self) -> Option<MadeDrive> {
        MadeDrive::from_tree(&self.tree)
    }
}

/// Every copy every vault listed, and the vaults that did not answer.
#[derive(Debug, Default)]
struct Seen {
    copies: Vec<Copy>,
    unanswered: Vec<String>,
}

impl Seen {
    fn sizes(&self) -> HashMap<([u8; 32], String), u64> {
        self.copies.iter().map(|c| ((c.vault_key, c.tree.clone()), c.held)).collect()
    }
}

/// Ask `client`, a vault `user_id` keeps drives on, for every drive it keeps
/// for them, and take its listing as what this device records of the drives
/// made there. Returns every copy it listed, the first drive among them.
///
/// A name that does not open under the person's key — a vault that altered
/// it, or one sealed for another tree — names no drive: a drive this device
/// already records keeps the name it has, and one it does not is not recorded,
/// and both are logged. A name sealed unfinished is a move's tree, not a
/// drive, and is never recorded.
pub async fn follow(
    store: &UserStore,
    db: &Arc<SqlitePool>,
    user_id: &str,
    vault_key: &[u8; 32],
    client: &KottonPeerObjectStorage,
) -> io::Result<Vec<Copy>> {
    let listed = match ask(client, UserRequest::TenantDrives { user_id: user_id.to_string() }).await? {
        UserResponse::TenantDrivesResult { drives } => drives,
        UserResponse::Error { message } => return Err(io::Error::other(message)),
        other => return Err(io::Error::other(format!("the vault answered {other:?} to TenantDrives"))),
    };
    let recorded: Vec<(String, String, Option<String>)> = record::all(db, user_id)
        .await?
        .into_iter()
        .filter(|d| d.vault_key == *vault_key)
        .map(|d| (d.tree, d.name, d.id))
        .collect();
    let copies = read_listing(store, user_id, vault_key, &listed, &recorded);
    let made: Vec<record::Listed> = copies
        .iter()
        .filter(|c| c.finished && c.tree != FIRST_DRIVE_TREE)
        .map(|c| record::Listed { tree: c.tree.clone(), name: c.name.clone(), id: c.id.clone() })
        .collect();
    record::reconcile(db, user_id, vault_key, &made).await?;
    for copy in copies.iter().filter(|c| c.sealed_before_ids && c.finished) {
        if let Err(e) = seal_with_id(store, user_id, client, copy).await {
            tracing::warn!(user_id, tree = %copy.tree, error = %e, "a drive's name sealed before ids was not sealed again with its id");
        }
    }
    Ok(copies)
}

/// Seal `copy`'s name again, finished, with the id it was read with, and name
/// its tree with it (module doc: migrated in place). The id is the one every
/// device reads for it, so two devices doing this at once seal the same name.
/// Only a finished name: an unfinished one is a move's tree, which the next
/// move of that drive retires, and naming it again could undo the naming of a
/// move that finishes meanwhile.
async fn seal_with_id(store: &UserStore, user_id: &str, client: &KottonPeerObjectStorage, copy: &Copy) -> io::Result<()> {
    let Some(drive) = copy.made() else { return Ok(()) };
    let sealed_name = SealedName { name: copy.name.clone(), id: copy.id.clone() }.seal(store, &copy.tree, true)?;
    match ask(client, UserRequest::TenantDriveName { user_id: user_id.to_string(), drive, sealed_name }).await? {
        UserResponse::Ok => Ok(()),
        UserResponse::Error { message } => Err(io::Error::other(message)),
        other => Err(io::Error::other(format!("the vault answered {other:?} to TenantDriveName"))),
    }
}

/// A vault's listing, read as copies: the first drive, named as every device
/// names it; each made drive whose name opens, finished or not; and a made
/// drive whose name does not open, under the name `recorded` has for its tree
/// if any, or not at all.
fn read_listing(
    store: &UserStore,
    user_id: &str,
    vault_key: &[u8; 32],
    listed: &[TenantDrive],
    recorded: &[(String, String, Option<String>)],
) -> Vec<Copy> {
    let mut copies = Vec::new();
    for drive in listed {
        let here = Origin { vault_key: hex::encode(vault_key), tree: drive.tree.clone() };
        let copy = |name: String, id: String, finished: bool, sealed_before_ids: bool| Copy {
            vault_key: *vault_key,
            tree: drive.tree.clone(),
            name,
            id,
            held: drive.held,
            finished,
            sealed_before_ids,
        };
        if drive.tree == FIRST_DRIVE_TREE {
            copies.push(copy(kotton_wire::ipc::FIRST_DRIVE_NAME.to_string(), FIRST_DRIVE_ID.to_string(), true, false));
            continue;
        }
        let opened = store
            .open_drive_name(&drive.tree, &drive.sealed_name)
            .map_err(|e| format!("{e:#}"))
            .and_then(|(bytes, finished)| SealedName::read(&bytes, &here).map(|(n, before)| (n, finished, before)));
        match opened {
            Ok((sealed, finished, before)) => copies.push(copy(sealed.name, sealed.id, finished, before)),
            Err(e) => {
                tracing::warn!(user_id, tree = %drive.tree, error = %e, "a drive's name did not open");
                if let Some((_, name, id)) = recorded.iter().find(|(tree, _, _)| *tree == drive.tree) {
                    let id = id.clone().unwrap_or_else(|| legacy_id(&here));
                    copies.push(copy(name.clone(), id, true, false));
                }
            }
        }
    }
    copies
}

async fn ask(client: &KottonPeerObjectStorage, request: UserRequest) -> io::Result<UserResponse> {
    tokio::time::timeout(EACH_VAULT, client.send(&request))
        .await
        .map_err(|_| io::Error::other("the vault did not answer in time"))?
        .map_err(|e| io::Error::other(e.to_string()))
}

async fn dial(runtime: &DeviceRuntime, node: &PairedNode, user_id: &str) -> io::Result<KottonPeerObjectStorage> {
    tokio::time::timeout(EACH_VAULT, runtime.dialer().connect(node.clone(), user_id))
        .await
        .map_err(|_| io::Error::other(format!("the vault '{}' did not answer in time", node.id)))?
        .map_err(|e| io::Error::other(format!("the vault '{}' did not answer: {e}", node.id)))
}

/// Ask every vault `user_id` keeps drives on, following each that answers.
async fn follow_every_vault(runtime: &DeviceRuntime, store: &UserStore, db: &Arc<SqlitePool>, user_id: &str) -> io::Result<Seen> {
    let mut seen = Seen::default();
    for vault in record::list(db, user_id).await? {
        let followed = match dial(runtime, &vault.node, user_id).await {
            Ok(client) => follow(store, db, user_id, &vault.vault_key, &client).await,
            Err(e) => Err(e),
        };
        match followed {
            Ok(copies) => seen.copies.extend(copies),
            Err(e) => {
                tracing::warn!(user_id, vault = %vault.node.id, error = %e, "a vault's drives were not listed");
                seen.unanswered.push(vault.node.id.clone());
            }
        }
    }
    Ok(seen)
}

fn describe(drive: &Drive, sizes: &HashMap<([u8; 32], String), u64>, pins: &pins::Read) -> DriveDescriptor {
    DriveDescriptor {
        // The record's id, as this device opened it from the sealed name
        // ([`kotton_peer::daemon::drives::Drive::id`]).
        id: drive.id.clone(),
        name: drive.name.clone(),
        vault: drive.node.id.clone(),
        vault_key: hex::encode(drive.vault_key),
        size: sizes.get(&(drive.vault_key, drive.tree.clone())).copied(),
        // The devices whose whole-keeper claim for this drive's id is in the
        // drive, and which are still the person's (`crate::users::pins`).
        pinned_whole: pins.whole_on(drive.id.as_deref()),
        unfinished: false,
    }
}

/// What a drive's descriptors need of the whole-keeper claims, read once per
/// verb.
async fn pins_now(runtime: &DeviceRuntime, records: &SqliteRecordStore, store: &UserStore, db: &SqlitePool, user_id: &str) -> io::Result<pins::Read> {
    pins::Read::now(&runtime.schema_registry, records, store, db, user_id, &runtime.operational_did()).await
}

/// The name of the lock a drive is held under on this device while a verb
/// changes where it is (`drive move`): [`DeviceRuntime::lock_mount`]'s, keyed
/// by the person's name for the drive, which a move does not change — its tree
/// does, at every vault it is carried to. Anything on this device that writes
/// into a made drive takes it too (kotton #55's last comment; a device keeps
/// no tree of a made drive yet, kotton #58 and #124).
pub fn drive_lock(name: &str) -> String {
    format!("drive:{name}")
}

/// The unfinished trees `seen` holds, as descriptors, each under the label of
/// the vault it is at.
async fn unfinished_described(db: &Arc<SqlitePool>, user_id: &str, seen: &Seen) -> io::Result<Vec<DriveDescriptor>> {
    let vaults = record::list(db, user_id).await?;
    Ok(seen
        .copies
        .iter()
        .filter(|c| !c.finished)
        .map(|c| DriveDescriptor {
            // The id sealed with the unfinished tree's name: the drive the
            // move was of.
            id: Some(c.id.clone()),
            name: c.name.clone(),
            vault: vaults.iter().find(|v| v.vault_key == c.vault_key).map(|v| v.node.id.clone()).unwrap_or_default(),
            vault_key: hex::encode(c.vault_key),
            size: Some(c.held),
            pinned_whole: Vec::new(),
            unfinished: true,
        })
        .collect())
}

/// The vault `named` names among those `user_id` keeps drives on: its label
/// while one carries it, its DID, or its key in hex; or, named by nothing, the
/// one vault there is. `Err` is the sentence the person reads.
async fn vault_named(db: &Arc<SqlitePool>, user_id: &str, named: Option<&str>, flag: &str) -> io::Result<Result<Drive, String>> {
    let vaults = record::list(db, user_id).await?;
    let Some(named) = named else {
        return Ok(match vaults.as_slice() {
            [one] => Ok(one.clone()),
            [] => Err("you keep drives on no vault yet; `vault invite --me` makes one".to_string()),
            many => Err(format!(
                "you keep drives on {} vaults ({}); name one with {flag}",
                many.len(),
                many.iter().map(|v| v.node.id.as_str()).collect::<Vec<_>>().join(", ")
            )),
        });
    };
    let found: Vec<&Drive> = vaults
        .iter()
        .filter(|v| v.node.id == named || v.node.device_did.to_string() == named || hex::encode(v.vault_key) == named)
        .collect();
    Ok(match found.as_slice() {
        [one] => Ok((*one).clone()),
        [] => Err(format!("'{named}' names none of the vaults you keep drives on")),
        many => Err(format!(
            "'{named}' is the label of {} of your vaults ({}); name the one you mean by its DID",
            many.len(),
            many.iter().map(|v| v.node.device_did.to_string()).collect::<Vec<_>>().join(", ")
        )),
    })
}

/// A name a drive may have: some text, short, and not a flag.
fn name_said(name: &str) -> Result<String, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("a drive needs a name".into());
    }
    if name.len() > MAX_NAME {
        return Err(format!("a drive's name is at most {MAX_NAME} bytes"));
    }
    if name.starts_with('-') || name.chars().any(char::is_control) {
        return Err(format!("'{name}' is not a drive's name: it starts with '-' or holds a control character"));
    }
    Ok(name.to_string())
}

/// Whether `name` is free for a new drive, given what every vault listed:
/// `Err` names where it is taken, or the vaults that did not answer, so a
/// name is never taken on a record this device has not refreshed.
fn name_is_free(seen: &Seen, name: &str) -> Result<(), String> {
    if !seen.unanswered.is_empty() {
        return Err(format!(
            "{} did not answer, so whether '{name}' is free cannot be told; try again when it does",
            seen.unanswered.join(", ")
        ));
    }
    if seen.copies.iter().any(|c| c.name == name) {
        return Err(format!("you have a drive called '{name}' already"));
    }
    Ok(())
}

/// `drive create <name> [--on <vault>]`.
pub async fn create(
    runtime: &DeviceRuntime,
    store: &UserStore,
    records: &SqliteRecordStore,
    db: &Arc<SqlitePool>,
    user_id: &str,
    name: &str,
    on: Option<&str>,
) -> io::Result<UserResponse> {
    let name = match name_said(name) {
        Ok(n) => n,
        Err(e) => return refused(format!("drive create: {e}")),
    };
    let vault = match vault_named(db, user_id, on, "--on").await? {
        Ok(v) => v,
        Err(e) => return refused(format!("drive create: {e}")),
    };
    // Every vault, not this one alone: a drive of this name made on another
    // by another device is taken whatever this device's record says.
    let seen = follow_every_vault(runtime, store, db, user_id).await?;
    if let Err(e) = name_is_free(&seen, &name) {
        return refused(format!("drive create: {e}"));
    }
    let client = dial(runtime, &vault.node, user_id).await?;
    let drive = MadeDrive(rand::random());
    let tree = drive.tree();
    // The drive's id, minted once, here, and sealed with every copy a move
    // makes; the tree's id is the vault's and is minted fresh at each.
    let sealed_name = SealedName { name: name.clone(), id: mint_id() }.seal(store, &tree, true)?;
    match ask(&client, UserRequest::TenantDriveMake { user_id: user_id.to_string(), drive, sealed_name }).await? {
        UserResponse::Ok => {}
        UserResponse::Error { message } => return refused(format!("drive create: the vault '{}' refused: {message}", vault.node.id)),
        other => return refused(format!("drive create: the vault answered {other:?}")),
    }
    let copies = follow(store, db, user_id, &vault.vault_key, &client).await?;
    let sizes = Seen { copies, unanswered: vec![] }.sizes();
    let made = record::all(db, user_id)
        .await?
        .into_iter()
        .find(|d| d.vault_key == vault.vault_key && d.tree == tree)
        .ok_or_else(|| io::Error::other("the vault made the drive but did not list it"))?;
    // The device that creates a drive keeps it whole until told otherwise
    // (the protocol's storage model), and says so by a whole-keeper claim in
    // the drive — once a device keeps a tree of a made drive at all, which
    // drive paths (kotton #58) and the first drive among others (#124) give
    // it. That is the seam (module doc): until then no device keeps a made
    // drive, so none claims it, and a claim saying so would silence the
    // telling that only the vault holds it (`crate::users::pins`), which is
    // the truth.
    tracing::info!(user_id, vault = %vault.node.id, "made a drive");
    Ok(UserResponse::Drives { drives: vec![describe(&made, &sizes, &pins_now(runtime, records, store, db, user_id).await?)] })
}

/// `drive list`: every drive, after asking each vault what it keeps, and
/// every unfinished move's tree, marked so.
pub async fn list(
    runtime: &DeviceRuntime,
    store: &UserStore,
    records: &SqliteRecordStore,
    db: &Arc<SqlitePool>,
    user_id: &str,
) -> io::Result<UserResponse> {
    let seen = follow_every_vault(runtime, store, db, user_id).await?;
    let sizes = seen.sizes();
    let pins = pins_now(runtime, records, store, db, user_id).await?;
    let mut drives: Vec<DriveDescriptor> = record::all(db, user_id).await?.iter().map(|d| describe(d, &sizes, &pins)).collect();
    drives.extend(unfinished_described(db, user_id, &seen).await?);
    Ok(UserResponse::Drives { drives })
}

/// `drive show <name>`: the drives called `name`, one per vault it is kept on.
pub async fn show(
    runtime: &DeviceRuntime,
    store: &UserStore,
    records: &SqliteRecordStore,
    db: &Arc<SqlitePool>,
    user_id: &str,
    name: &str,
) -> io::Result<UserResponse> {
    let seen = follow_every_vault(runtime, store, db, user_id).await?;
    let sizes = seen.sizes();
    let pins = pins_now(runtime, records, store, db, user_id).await?;
    let mut drives: Vec<DriveDescriptor> = record::all(db, user_id)
        .await?
        .iter()
        .filter(|d| d.name == name)
        .map(|d| describe(d, &sizes, &pins))
        .collect();
    drives.extend(unfinished_described(db, user_id, &seen).await?.into_iter().filter(|d| d.name == name));
    if drives.is_empty() {
        return refused(format!("drive show: you have no drive called '{name}'"));
    }
    Ok(UserResponse::Drives { drives })
}

/// One vault a move reads from or writes to: a made drive's tree there, and
/// the vault's tenant verbs. A trait so the order [`carry_and_settle`] keeps
/// can be held against vaults that misbehave.
#[async_trait::async_trait]
pub trait VaultEnd: Send + Sync {
    /// Every sealed object of the tree, by key, with its size.
    async fn objects(&self) -> Result<Vec<(String, u64)>, String>;
    /// One sealed object, as it rests.
    async fn read(&self, key: &str) -> Result<Vec<u8>, String>;
    /// Write one sealed object, as it rests.
    async fn write(&self, key: &str, blob: &[u8]) -> Result<(), String>;
    /// A tenant verb the vault answers `Ok` to, or why not.
    async fn tell(&self, request: UserRequest) -> Result<(), String>;
}

/// A vault reached over the peer link, its sealed verbs pointed at one tree.
struct PeerEnd(KottonPeerObjectStorage);

#[async_trait::async_trait]
impl VaultEnd for PeerEnd {
    async fn objects(&self) -> Result<Vec<(String, u64)>, String> {
        let listed = self.0.list_sealed(Path::new("")).await.map_err(|e| e.to_string())?;
        Ok(listed.into_iter().map(|o| (o.key, o.size)).collect())
    }
    async fn read(&self, key: &str) -> Result<Vec<u8>, String> {
        self.0.get_sealed(Path::new(key)).await.map(|b| b.to_vec()).map_err(|e| e.to_string())
    }
    async fn write(&self, key: &str, blob: &[u8]) -> Result<(), String> {
        self.0.put_sealed(Path::new(key), blob).await.map_err(|e| e.to_string())
    }
    async fn tell(&self, request: UserRequest) -> Result<(), String> {
        match ask(&self.0, request).await.map_err(|e| e.to_string())? {
            UserResponse::Ok => Ok(()),
            UserResponse::Error { message } => Err(message),
            other => Err(format!("the vault answered {other:?}")),
        }
    }
}

/// Retire the made drive `drive` at `end`, asking a second time only when the
/// first answer was not `Ok`. A retire is idempotent at the vault, so a first
/// ask that acted and whose answer was lost is answered `Ok` the second time;
/// an `Err` from the second is the vault saying it still keeps the tree.
pub async fn retire(end: &dyn VaultEnd, user_id: &str, drive: MadeDrive) -> Result<(), String> {
    let ask = || end.tell(UserRequest::TenantDriveRetire { user_id: user_id.to_string(), drive });
    match ask().await {
        Ok(()) => Ok(()),
        Err(_) => ask().await,
    }
}

/// How a move came out ([`carry_and_settle`]).
#[derive(Debug, PartialEq, Eq)]
pub enum Carried {
    /// The other vault holds the drive, named; the vault it left retired it.
    Moved,
    /// The other vault holds the drive, named, and the vault it left did not
    /// retire it: both keep it, until the move is asked again (module doc).
    SourceKept(String),
    /// The drive is where it was; the unfinished tree at the other vault was
    /// retired. Why it was not moved.
    NotMoved(String),
    /// The drive is where it was, and the other vault would not retire the
    /// unfinished tree either: why it was not moved, and why that tree stays.
    NotMovedTreeLeft { why: String, left: String },
}

/// Copy the drive, check it, name it finished at `to`, then retire it at
/// `from` — and, if any step before the naming fails, retire the unfinished
/// tree at `to` (module doc). `to` was made under a name sealed unfinished;
/// `finished_name` is the drive's name sealed finished for `to_id`.
pub async fn carry_and_settle(
    user_id: &str,
    from: &dyn VaultEnd,
    from_id: MadeDrive,
    to: &dyn VaultEnd,
    to_id: MadeDrive,
    finished_name: Vec<u8>,
) -> Carried {
    let carried = async {
        let mut wanted = from.objects().await.map_err(|e| format!("the drive could not be listed: {e}"))?;
        for (key, _) in &wanted {
            let blob = from.read(key).await.map_err(|e| format!("reading {key}: {e}"))?;
            to.write(key, &blob).await.map_err(|e| format!("writing {key}: {e}"))?;
        }
        let mut landed = to.objects().await.map_err(|e| format!("the other vault could not list what it took: {e}"))?;
        wanted.sort();
        landed.sort();
        if wanted != landed {
            let missing = wanted.iter().filter(|w| !landed.contains(w)).count();
            return Err(format!(
                "the other vault does not list {missing} of the {} objects at the size they were sent",
                wanted.len()
            ));
        }
        to.tell(UserRequest::TenantDriveName { user_id: user_id.to_string(), drive: to_id, sealed_name: finished_name })
            .await
            .map_err(|e| format!("the other vault did not name the drive: {e}"))
    }
    .await;
    if let Err(why) = carried {
        return match retire(to, user_id, to_id).await {
            Ok(()) => Carried::NotMoved(why),
            Err(left) => Carried::NotMovedTreeLeft { why, left },
        };
    }
    match retire(from, user_id, from_id).await {
        Ok(()) => Carried::Moved,
        Err(e) => Carried::SourceKept(e),
    }
}

/// What `drive move <name> --to <vault> [--from <vault>]` does, given every
/// copy of every drive the vaults listed (module doc).
#[derive(Debug, PartialEq, Eq)]
pub enum Plan {
    /// No drive is called that (at `--from`, when named).
    NoSuch,
    /// It is the tenancy's own tree, which does not move.
    First,
    /// Copies of that name with more than one id: drives no move made.
    Ambiguous(Vec<Copy>),
    /// The drive is at the vault already; the other copies of it are retired.
    /// No others: it lives there already.
    AtDestination { keep: Copy, retire: Vec<Copy> },
    /// Carry `source` to the vault, then retire the other copies of it.
    Carry { source: Copy, retire_after: Vec<Copy> },
}

/// Decide a move (module doc). `copies` is every finished copy every vault
/// listed; `dest` the vault named by `--to`, `from` the one named by
/// `--from`.
pub fn plan_move(copies: &[Copy], name: &str, dest: &[u8; 32], from: Option<&[u8; 32]>) -> Plan {
    let named: Vec<&Copy> = copies.iter().filter(|c| c.finished && c.name == name).collect();
    if named.is_empty() {
        return Plan::NoSuch;
    }
    if named.iter().all(|c| c.tree == FIRST_DRIVE_TREE) {
        return Plan::First;
    }
    let named: Vec<&Copy> = named.into_iter().filter(|c| c.tree != FIRST_DRIVE_TREE).collect();
    // `--from` names the drive by the vault one of its copies is at: the
    // copies of its id, wherever they are.
    let ids: Vec<&str> = match from {
        Some(at) => named.iter().filter(|c| &c.vault_key == at).map(|c| c.id.as_str()).collect(),
        None => named.iter().map(|c| c.id.as_str()).collect(),
    };
    let Some(id) = ids.first().copied() else {
        return Plan::NoSuch;
    };
    if ids.iter().any(|i| *i != id) || (from.is_none() && named.iter().any(|c| c.id != id)) {
        return Plan::Ambiguous(named.into_iter().cloned().collect());
    }
    let drive: Vec<Copy> = named.into_iter().filter(|c| c.id == id).cloned().collect();
    if let Some(keep) = drive.iter().find(|c| &c.vault_key == dest).cloned() {
        let retire = drive.into_iter().filter(|c| *c != keep).collect();
        return Plan::AtDestination { keep, retire };
    }
    // Any copy: each holds the whole drive, as it was named finished only
    // once it did.
    let source = drive[0].clone();
    let retire_after = drive.into_iter().filter(|c| *c != source).collect();
    Plan::Carry { source, retire_after }
}

/// `drive move <name> --to <vault> [--from <vault>]` (module doc).
#[allow(clippy::too_many_arguments)]
pub async fn move_to(
    runtime: &DeviceRuntime,
    store: &UserStore,
    records: &SqliteRecordStore,
    db: &Arc<SqlitePool>,
    user_id: &str,
    name: &str,
    to: &str,
    from: Option<&str>,
) -> io::Result<UserResponse> {
    // The drive is held on this device for the whole move ([`drive_lock`]):
    // a second move of it here waits, and then reads where the first left it.
    // Another device's move, or a pass another device runs into the drive,
    // this lock does not see; that needs a lease the vault keeps (module doc).
    let _held = runtime.lock_mount(user_id, &drive_lock(name)).await;
    let pins = pins_now(runtime, records, store, db, user_id).await?;
    let dest = match vault_named(db, user_id, Some(to), "--to").await? {
        Ok(v) => v,
        Err(e) => return refused(format!("drive move: {e}")),
    };
    let from_vault = match from {
        Some(f) => match vault_named(db, user_id, Some(f), "--from").await? {
            Ok(v) => Some(v),
            Err(e) => return refused(format!("drive move: {e}")),
        },
        None => None,
    };
    let vaults = record::list(db, user_id).await?;
    let label = |key: &[u8; 32]| vaults.iter().find(|v| v.vault_key == *key).map(|v| v.node.id.clone()).unwrap_or_else(|| hex::encode(key));
    let seen = follow_every_vault(runtime, store, db, user_id).await?;
    if !seen.unanswered.is_empty() {
        return refused(format!(
            "drive move: {} did not answer, so where every copy of '{name}' is cannot be told; try again when it does",
            seen.unanswered.join(", ")
        ));
    }
    let plan = plan_move(&seen.copies, name, &dest.vault_key, from_vault.as_ref().map(|v| &v.vault_key));
    let (source, retire_after) = match plan {
        Plan::NoSuch => return refused(format!("drive move: you have no drive called '{name}'{}", from.map(|f| format!(" on '{f}'")).unwrap_or_default())),
        Plan::First => {
            return refused(format!(
                "drive move: '{name}' is the tenancy's own tree, kept at each vault you keep drives on; this device's \
                 own tree syncs with it at every one, so it lives at none alone and does not move"
            ))
        }
        Plan::Ambiguous(copies) => {
            return refused(format!(
                "drive move: you have {} drives called '{name}' that no move made ({}); name the one you mean with \
                 --from <vault>",
                copies.len(),
                copies.iter().map(|c| format!("{} on '{}'", c.tree, label(&c.vault_key))).collect::<Vec<_>>().join(", ")
            ))
        }
        Plan::AtDestination { keep, retire: rest } if rest.is_empty() => {
            let _ = keep;
            return refused(format!("drive move: '{name}' lives on '{}' already", dest.node.id));
        }
        Plan::AtDestination { keep, retire: rest } => {
            // A move cut off after it named the copy here: finish it.
            let left = retire_copies(runtime, &vaults, user_id, &rest).await;
            refollow(runtime, store, db, user_id, &vaults, &rest, &dest).await;
            if let Some(left) = left {
                return refused(format!("drive move: '{name}' is on '{}', and {left}; run the move again to retire it", dest.node.id));
            }
            let sizes = Seen { copies: vec![keep.clone()], unanswered: vec![] }.sizes();
            let moved = record::all(db, user_id).await?.into_iter().find(|d| d.vault_key == keep.vault_key && d.tree == keep.tree);
            let moved = moved.ok_or_else(|| io::Error::other("the drive's copy at the vault was not recorded"))?;
            tracing::info!(user_id, to = %dest.node.id, "finished an interrupted drive move");
            return Ok(UserResponse::Drives { drives: vec![describe(&moved, &sizes, &pins)] });
        }
        Plan::Carry { source, retire_after } => (source, retire_after),
    };
    let Some(from_id) = source.made() else {
        return refused(format!("drive move: '{name}' is the tenancy's own tree, which does not move"));
    };
    let Some(source_vault) = vaults.iter().find(|v| v.vault_key == source.vault_key).cloned() else {
        return refused(format!("drive move: the vault '{name}' is on is not one this device reaches"));
    };
    let Some(domain) = runtime.user_cek_domain_id(user_id, Some(store)) else {
        return refused("drive move: this device holds no key for you, so it cannot carry a drive");
    };

    let from_client = dial(runtime, &source_vault.node, user_id).await?;
    let dest_client = dial(runtime, &dest.node, user_id).await?;
    // An earlier move of this drive to this vault that left its tree there.
    for stale in seen.copies.iter().filter(|c| !c.finished && c.vault_key == dest.vault_key && c.name == name) {
        let Some(id) = stale.made() else { continue };
        let end = PeerEnd(dial(runtime, &dest.node, user_id).await?);
        if let Err(e) = retire(&end, user_id, id).await {
            return refused(format!(
                "drive move: '{}' still keeps an unfinished copy of '{name}' under {}, from an earlier move, and did \
                 not retire it now ({e}); '{name}' is still on '{}'",
                dest.node.id, stale.tree, source_vault.node.id
            ));
        }
    }
    let to_id = MadeDrive(rand::random());
    let to_tree = to_id.tree();
    // The copy carries the drive's id; its tree gets an id of its own there.
    let carried_name = SealedName { name: name.to_string(), id: source.id.clone() };
    let unfinished_name = carried_name.seal(store, &to_tree, false)?;
    let finished_name = carried_name.seal(store, &to_tree, true)?;
    match ask(&dest_client, UserRequest::TenantDriveMake { user_id: user_id.to_string(), drive: to_id, sealed_name: unfinished_name }).await? {
        UserResponse::Ok => {}
        UserResponse::Error { message } => return refused(format!("drive move: '{}' refused the drive: {message}", dest.node.id)),
        other => return refused(format!("drive move: '{}' answered {other:?}", dest.node.id)),
    }
    let from_end = PeerEnd(from_client.with_remote_mount(source.tree.clone()).with_domain_id(domain.clone()));
    let to_end = PeerEnd(dest_client.with_remote_mount(to_tree.clone()).with_domain_id(domain));
    let carried = carry_and_settle(user_id, &from_end, from_id, &to_end, to_id, finished_name).await;
    let left = if carried == Carried::Moved { retire_copies(runtime, &vaults, user_id, &retire_after).await } else { None };

    let mut sizes = HashMap::new();
    for (vault, end) in [(&source_vault, &from_end), (&dest, &to_end)] {
        match follow(store, db, user_id, &vault.vault_key, &end.0).await {
            Ok(copies) => sizes.extend(Seen { copies, unanswered: vec![] }.sizes()),
            Err(e) => tracing::warn!(user_id, vault = %vault.node.id, error = %e, "a vault was not followed after a move"),
        }
    }
    refollow(runtime, store, db, user_id, &vaults, &retire_after, &dest).await;
    let (src, dst) = (source_vault.node.id.as_str(), dest.node.id.as_str());
    match carried {
        Carried::Moved => {}
        Carried::NotMoved(why) => return refused(format!("drive move: '{name}' was not moved, and is still on '{src}': {why}")),
        Carried::NotMovedTreeLeft { why, left } => {
            return refused(format!(
                "drive move: '{name}' was not moved, and is still on '{src}': {why}. '{dst}' also keeps an unfinished \
                 copy of it under {to_tree}, which it did not retire ({left}): `drive list` shows it as unfinished, \
                 and moving '{name}' to '{dst}' again retires it first"
            ))
        }
        Carried::SourceKept(e) => {
            return refused(format!(
                "drive move: '{name}' is on '{dst}' now, and '{src}' still keeps it too: it did not retire it ({e}). \
                 Run `drive move {name} --to {dst}` again to retire it there"
            ))
        }
    }
    if let Some(left) = left {
        return refused(format!("drive move: '{name}' is on '{dst}' now, and {left}; run the move again to retire it"));
    }
    let moved = record::all(db, user_id)
        .await?
        .into_iter()
        .find(|d| d.vault_key == dest.vault_key && d.tree == to_tree)
        .ok_or_else(|| io::Error::other("the drive was moved but the vault it moved to did not list it"))?;
    tracing::info!(user_id, from = %src, to = %dst, "moved a drive");
    Ok(UserResponse::Drives { drives: vec![describe(&moved, &sizes, &pins)] })
}

/// Retire each of `copies` at its vault. `None` when every one went; else the
/// sentence naming those that stay.
async fn retire_copies(runtime: &DeviceRuntime, vaults: &[Drive], user_id: &str, copies: &[Copy]) -> Option<String> {
    let mut left = Vec::new();
    for copy in copies {
        let (Some(id), Some(vault)) = (copy.made(), vaults.iter().find(|v| v.vault_key == copy.vault_key)) else {
            continue;
        };
        let outcome = match dial(runtime, &vault.node, user_id).await {
            Ok(client) => retire(&PeerEnd(client), user_id, id).await,
            Err(e) => Err(e.to_string()),
        };
        if let Err(e) = outcome {
            left.push(format!("'{}' still keeps a copy under {} ({e})", vault.node.id, copy.tree));
        }
    }
    (!left.is_empty()).then(|| left.join(", "))
}

/// Follow the vaults `copies` were at, and `dest`, so this device's record
/// says where the drive is now. Best-effort.
async fn refollow(
    runtime: &DeviceRuntime,
    store: &UserStore,
    db: &Arc<SqlitePool>,
    user_id: &str,
    vaults: &[Drive],
    copies: &[Copy],
    dest: &Drive,
) {
    let mut keys: Vec<[u8; 32]> = copies.iter().map(|c| c.vault_key).collect();
    keys.push(dest.vault_key);
    keys.dedup();
    for key in keys {
        let Some(vault) = vaults.iter().find(|v| v.vault_key == key) else { continue };
        if let Ok(client) = dial(runtime, &vault.node, user_id).await {
            if let Err(e) = follow(store, db, user_id, &key, &client).await {
                tracing::warn!(user_id, vault = %vault.node.id, error = %e, "a vault was not followed after a move");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! The order a move keeps and how it resolves a drive kept twice, held
    //! against vaults that misbehave. These are fakes at the [`VaultEnd`]
    //! seam and pure calls of [`plan_move`] and [`name_is_free`], not vaults:
    //! the suite's fixture
    //! (`drive_sync::a_vault_keeps_several_drives_and_a_moved_drive_is_followed_by_every_device`)
    //! has real vaults that answer, and cannot make one list a wrong size,
    //! drop a write, lose an answer or refuse a retire.
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    /// A vault's tree, in memory, with what can go wrong at it. Its retire is
    /// idempotent, as `kvaultd::drives::retire` is.
    #[derive(Default)]
    struct Fake {
        objects: Mutex<Vec<(String, Vec<u8>)>>,
        /// Every tenant verb it was told, by name.
        told: Mutex<Vec<&'static str>>,
        /// The write of this key fails.
        fail_write: Option<&'static str>,
        /// Its listing says this key is one byte larger than it is.
        misreport: Option<&'static str>,
        /// Its listing leaves this key out, as a vault that lost the write.
        hides: Option<&'static str>,
        /// It answers every retire with an error, and keeps the tree.
        refuse_retire: AtomicBool,
        /// Its next retire acts, and its answer is lost.
        lose_retire_answer: AtomicBool,
    }

    impl Fake {
        fn holding(objects: &[(&str, &[u8])]) -> Self {
            Self { objects: Mutex::new(objects.iter().map(|(k, v)| (k.to_string(), v.to_vec())).collect()), ..Self::default() }
        }
        fn keys(&self) -> Vec<String> {
            self.objects.lock().unwrap().iter().map(|(k, _)| k.clone()).collect()
        }
        fn told(&self) -> Vec<&'static str> {
            self.told.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl VaultEnd for Fake {
        async fn objects(&self) -> Result<Vec<(String, u64)>, String> {
            Ok(self
                .objects
                .lock()
                .unwrap()
                .iter()
                .filter(|(k, _)| self.hides != Some(k.as_str()))
                .map(|(k, v)| (k.clone(), v.len() as u64 + u64::from(self.misreport == Some(k.as_str()))))
                .collect())
        }
        async fn read(&self, key: &str) -> Result<Vec<u8>, String> {
            self.objects.lock().unwrap().iter().find(|(k, _)| k == key).map(|(_, v)| v.clone()).ok_or("not found".into())
        }
        async fn write(&self, key: &str, blob: &[u8]) -> Result<(), String> {
            if self.fail_write == Some(key) {
                return Err("the connection dropped".into());
            }
            self.objects.lock().unwrap().push((key.to_string(), blob.to_vec()));
            Ok(())
        }
        async fn tell(&self, request: UserRequest) -> Result<(), String> {
            self.told.lock().unwrap().push(request.variant_name());
            match request {
                UserRequest::TenantDriveRetire { .. } if self.refuse_retire.load(Ordering::SeqCst) => Err("the vault would not".into()),
                UserRequest::TenantDriveRetire { .. } => {
                    self.objects.lock().unwrap().clear();
                    if self.lose_retire_answer.swap(false, Ordering::SeqCst) {
                        return Err("the answer did not arrive".into());
                    }
                    Ok(())
                }
                _ => Ok(()),
            }
        }
    }

    const FROM: MadeDrive = MadeDrive([1; 16]);
    const TO: MadeDrive = MadeDrive([2; 16]);

    fn source() -> Fake {
        Fake::holding(&[("p/one", b"one"), ("p/two", b"two two")])
    }

    async fn settle(from: &Fake, to: &Fake) -> Carried {
        carry_and_settle("alice", from, FROM, to, TO, b"finished".to_vec()).await
    }

    /// The order when every vault answers: copy, name the other vault's tree
    /// finished, and only then retire the drive where it was.
    #[tokio::test]
    async fn a_move_names_the_copy_finished_before_it_retires_the_source() {
        let (from, to) = (source(), Fake::default());
        assert_eq!(settle(&from, &to).await, Carried::Moved);
        assert_eq!(to.keys(), ["p/one", "p/two"]);
        assert_eq!(to.told(), ["TenantDriveName"]);
        assert_eq!(from.told(), ["TenantDriveRetire"]);
    }

    /// **A destination that lists a key at the wrong size, or not at all,
    /// leaves the drive where it was**: the source is told nothing and keeps
    /// every object, the unfinished tree is retired and never named, and the
    /// person reads that it was not moved and why.
    #[tokio::test]
    async fn a_destination_that_lists_a_wrong_size_or_misses_a_key_leaves_the_drive_where_it_was() {
        for (to, said) in [
            (Fake { misreport: Some("p/two"), ..Fake::default() }, "does not list 1 of the 2 objects at the size they were sent"),
            (Fake { hides: Some("p/two"), ..Fake::default() }, "does not list 1 of the 2 objects"),
        ] {
            let from = source();
            match settle(&from, &to).await {
                Carried::NotMoved(why) => assert!(why.contains(said), "{why}"),
                other => panic!("a destination that does not list what it took was taken: {other:?}"),
            }
            assert_eq!(to.told(), ["TenantDriveRetire"], "the unfinished tree was not retired, or was named");
            assert!(to.keys().is_empty(), "the unfinished tree kept what it took");
            assert!(from.told().is_empty(), "the source was told something: {:?}", from.told());
            assert_eq!(from.keys(), ["p/one", "p/two"], "the source lost an object");
        }
    }

    /// **A copy that fails mid-way leaves the drive where it was**, and the
    /// unfinished tree retired.
    #[tokio::test]
    async fn a_copy_that_fails_mid_way_leaves_the_drive_where_it_was() {
        let (from, to) = (source(), Fake { fail_write: Some("p/two"), ..Fake::default() });
        match settle(&from, &to).await {
            Carried::NotMoved(why) => assert!(why.contains("writing p/two") && why.contains("dropped"), "{why}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(to.told(), ["TenantDriveRetire"]);
        assert!(to.keys().is_empty(), "the unfinished tree kept what it took");
        assert!(from.told().is_empty());
        assert_eq!(from.keys(), ["p/one", "p/two"]);
    }

    /// **A clean-up retire that acted and whose answer was lost is read as
    /// done**: the second ask finds the tree gone, which an idempotent retire
    /// answers `Ok`, so the person is told the drive was not moved — not that
    /// the other vault keeps a copy it does not keep.
    #[tokio::test]
    async fn a_cleanup_retire_whose_answer_was_lost_is_read_as_done() {
        let (from, to) = (source(), Fake { fail_write: Some("p/two"), ..Fake::default() });
        to.lose_retire_answer.store(true, Ordering::SeqCst);
        match settle(&from, &to).await {
            Carried::NotMoved(why) => assert!(why.contains("writing p/two"), "{why}"),
            other => panic!("a retire that acted was said to leave the tree: {other:?}"),
        }
        assert!(to.keys().is_empty());
        assert_eq!(to.told(), ["TenantDriveRetire", "TenantDriveRetire"]);
    }

    /// **A destination that will not retire the unfinished tree is named to
    /// the person**: asked again and still refusing, the answer carries both
    /// why it was not moved and why the tree stays — which `move_to` says by
    /// the tree's name. The tree was never named finished.
    #[tokio::test]
    async fn an_unfinished_tree_the_destination_will_not_retire_is_said_and_never_named_finished() {
        let (from, to) = (source(), Fake { fail_write: Some("p/two"), ..Fake::default() });
        to.refuse_retire.store(true, Ordering::SeqCst);
        match settle(&from, &to).await {
            Carried::NotMovedTreeLeft { why, left } => {
                assert!(why.contains("writing p/two"), "{why}");
                assert!(left.contains("would not"), "{left}");
            }
            other => panic!("{other:?}"),
        }
        assert!(!to.told().contains(&"TenantDriveName"), "the unfinished tree was named");
        assert_eq!(from.keys(), ["p/one", "p/two"]);
        assert!(from.told().is_empty());
    }

    /// A source that will not retire the drive after the copy is named
    /// finished: the move happened, both vaults keep it, and the person is
    /// told so rather than that it moved.
    #[tokio::test]
    async fn a_source_that_will_not_retire_leaves_the_drive_at_both() {
        let (from, to) = (source(), Fake::default());
        from.refuse_retire.store(true, Ordering::SeqCst);
        match settle(&from, &to).await {
            Carried::SourceKept(e) => assert!(e.contains("would not"), "{e}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(to.told(), ["TenantDriveName"]);
        assert_eq!(from.keys(), ["p/one", "p/two"]);
    }

    const V1: [u8; 32] = [1; 32];
    const V2: [u8; 32] = [2; 32];
    const V3: [u8; 32] = [3; 32];

    /// A finished copy of the drive `drive` (its id), called `name`, at
    /// `vault` under the tree `tree`.
    fn a_copy(vault: [u8; 32], tree: u8, name: &str, drive: u8) -> Copy {
        Copy {
            vault_key: vault,
            tree: MadeDrive([tree; 16]).tree(),
            name: name.into(),
            id: hex::encode([drive; 16]),
            held: 1,
            finished: true,
            sealed_before_ids: false,
        }
    }

    /// **A move cut off between naming the copy and retiring the source —
    /// a source that refused, or a device that died there — is finished by
    /// the next move to the same vault.** Both vaults then list a finished
    /// `photos` of one id; the plan keeps the copy at the destination and
    /// retires the source, and the retire, asked again, takes.
    #[tokio::test]
    async fn a_move_cut_off_after_the_naming_is_finished_by_the_next_move() {
        let (from, to) = (source(), Fake::default());
        from.refuse_retire.store(true, Ordering::SeqCst);
        assert!(matches!(settle(&from, &to).await, Carried::SourceKept(_)));

        // What the two vaults list now: the drive where it was, and the copy
        // the move made and named, which carries the drive's id under a tree
        // id of its own.
        let at_source = a_copy(V1, 1, "photos", 7);
        let at_dest = a_copy(V2, 2, "photos", 7);
        let copies = [at_source.clone(), at_dest.clone()];
        match plan_move(&copies, "photos", &V2, None) {
            Plan::AtDestination { keep, retire: rest } => {
                assert_eq!(keep, at_dest);
                assert_eq!(rest, [at_source]);
            }
            other => panic!("an interrupted move was not finished: {other:?}"),
        }
        from.refuse_retire.store(false, Ordering::SeqCst);
        assert_eq!(retire(&from, "alice", FROM).await, Ok(()));
        assert!(from.keys().is_empty(), "the source still keeps the drive");
        assert_eq!(to.keys(), ["p/one", "p/two"], "the copy lost an object");
    }

    /// **Two devices moving one drive at once leave two finished copies of one
    /// id**, and the source retired by both (the second retire `Ok`, as a
    /// retire is idempotent). A move to either vault keeps that copy and
    /// retires the other; a move to a third carries one and retires the other.
    #[test]
    fn two_copies_of_one_drive_two_movers_made_resolve_on_the_next_move() {
        let first = a_copy(V2, 2, "photos", 7);
        let second = a_copy(V3, 3, "photos", 7);
        let copies = [first.clone(), second.clone()];
        assert_eq!(
            plan_move(&copies, "photos", &V3, None),
            Plan::AtDestination { keep: second.clone(), retire: vec![first.clone()] }
        );
        match plan_move(&copies, "photos", &V1, None) {
            Plan::Carry { source, retire_after } => {
                assert_eq!(retire_after.len(), 1);
                assert_ne!(source, retire_after[0]);
            }
            other => panic!("{other:?}"),
        }
    }

    /// **Two drives of one name that no move made — two creates that raced —
    /// are not resolved for the person**: the plan names both, and `--from`
    /// names the one meant, which then moves as any drive does.
    #[test]
    fn two_drives_no_move_made_are_refused_and_from_names_the_one_meant() {
        let on_v1 = a_copy(V1, 1, "photos", 7);
        let on_v2 = a_copy(V2, 2, "photos", 8);
        let copies = [on_v1.clone(), on_v2.clone()];
        match plan_move(&copies, "photos", &V3, None) {
            Plan::Ambiguous(both) => assert_eq!(both, copies),
            other => panic!("two drives no move made were resolved: {other:?}"),
        }
        assert_eq!(plan_move(&copies, "photos", &V3, Some(&V1)), Plan::Carry { source: on_v1.clone(), retire_after: vec![] });
        assert_eq!(plan_move(&copies, "photos", &V2, Some(&V2)), Plan::AtDestination { keep: on_v2, retire: vec![] });
        assert_eq!(plan_move(&copies, "photos", &V2, Some(&V3)), Plan::NoSuch);
    }

    /// The first drive does not move; a name no copy has is no drive; and an
    /// unfinished tree is no copy of the drive.
    #[test]
    fn the_first_drive_and_a_name_nothing_has_are_planned_as_such() {
        let first = Copy {
            vault_key: V1,
            tree: FIRST_DRIVE_TREE.into(),
            name: "personal".into(),
            id: FIRST_DRIVE_ID.into(),
            held: 1,
            finished: true,
            sealed_before_ids: false,
        };
        assert_eq!(plan_move(&[first], "personal", &V2, None), Plan::First);
        let unfinished = Copy { finished: false, ..a_copy(V2, 2, "photos", 7) };
        assert_eq!(plan_move(&[unfinished], "photos", &V2, None), Plan::NoSuch);
    }

    /// **`create` takes a name only on what every vault says**: a drive made on
    /// another vault by another device — one this device's record lacks — is
    /// a name taken, and a vault that did not answer is a name that cannot be
    /// told free.
    #[test]
    fn a_name_is_free_only_when_every_vault_says_so() {
        let made_elsewhere = Seen { copies: vec![a_copy(V2, 2, "photos", 7)], unanswered: vec![] };
        let refused = name_is_free(&made_elsewhere, "photos").unwrap_err();
        assert!(refused.contains("already"), "{refused}");
        assert_eq!(name_is_free(&made_elsewhere, "work"), Ok(()));
        let silent = Seen { copies: vec![], unanswered: vec!["vault-2".into()] };
        let refused = name_is_free(&silent, "work").unwrap_err();
        assert!(refused.contains("vault-2 did not answer"), "{refused}");
    }

    /// **A listing, read**: a name sealed finished is a drive with the id it
    /// carries; one sealed unfinished is a move's tree; one that does not open
    /// keeps the name and id this device has for its tree, or names nothing.
    #[test]
    fn a_listing_reads_drives_their_ids_and_unfinished_moves() {
        let dir = tempfile::tempdir().unwrap();
        let store = a_store(dir.path());
        let tree = |id: u8| MadeDrive([id; 16]).tree();
        let (photos, work) = (mint_id(), mint_id());
        let seal = |t: u8, id: &str, finished: bool| {
            SealedName { name: "photos".into(), id: id.into() }.seal(&store, &tree(t), finished).unwrap()
        };
        let listed = vec![
            TenantDrive { tree: FIRST_DRIVE_TREE.into(), sealed_name: vec![], held: 1 },
            TenantDrive { tree: tree(1), sealed_name: seal(1, &photos, true), held: 1 },
            TenantDrive { tree: tree(2), sealed_name: seal(2, &photos, false), held: 1 },
            TenantDrive { tree: tree(3), sealed_name: b"altered".to_vec(), held: 1 },
            TenantDrive { tree: tree(4), sealed_name: b"altered".to_vec(), held: 1 },
        ];
        let recorded = vec![(tree(3), "work".to_string(), Some(work.clone()))];
        let copies = read_listing(&store, "alice", &V2, &listed, &recorded);
        let said: Vec<(String, String, bool, String, bool)> =
            copies.into_iter().map(|c| (c.tree, c.name, c.finished, c.id, c.sealed_before_ids)).collect();
        assert_eq!(
            said,
            [
                (FIRST_DRIVE_TREE.to_string(), "personal".to_string(), true, FIRST_DRIVE_ID.to_string(), false),
                (tree(1), "photos".into(), true, photos.clone(), false),
                (tree(2), "photos".into(), false, photos, false),
                (tree(3), "work".into(), true, work, false),
            ]
        );
    }

    /// **A name kotton #155 sealed, with an origin and no id, is read with
    /// the id derived from that origin** (module doc: migrated in place): the
    /// drive where it was made, which sealed no origin, and the copy a move
    /// made of it at another vault, which sealed the origin, read with one id
    /// — so they are one drive to [`plan_move`] — and a drive made elsewhere
    /// reads with another. Each is marked to be sealed again with its id; a
    /// name sealed with one is not.
    #[test]
    fn a_name_sealed_with_an_origin_reads_with_the_id_every_copy_shares() {
        let dir = tempfile::tempdir().unwrap();
        let store = a_store(dir.path());
        let tree = |id: u8| MadeDrive([id; 16]).tree();
        let as_155 = |t: u8, body: serde_json::Value| store.seal_drive_name(&tree(t), &serde_json::to_vec(&body).unwrap(), true).unwrap();
        let made_here = TenantDrive { tree: tree(1), sealed_name: as_155(1, serde_json::json!({"name": "photos"})), held: 1 };
        let moved_from_v1 = serde_json::json!({"name": "photos", "origin": {"vault_key": hex::encode(V1), "tree": tree(1)}});
        let carried = TenantDrive { tree: tree(2), sealed_name: as_155(2, moved_from_v1), held: 1 };
        let elsewhere = TenantDrive { tree: tree(3), sealed_name: as_155(3, serde_json::json!({"name": "photos"})), held: 1 };

        let at_v1 = read_listing(&store, "alice", &V1, &[made_here], &[]);
        let at_v2 = read_listing(&store, "alice", &V2, &[carried, elsewhere], &[]);
        let id = legacy_id(&Origin { vault_key: hex::encode(V1), tree: tree(1) });
        assert_eq!((at_v1[0].id.as_str(), at_v2[0].id.as_str()), (id.as_str(), id.as_str()), "the copies of one origin read as two drives");
        assert_ne!(at_v2[1].id, id, "a drive made elsewhere reads as the same drive");
        assert_eq!(id.len(), 32, "a migrated id is not shaped like a minted one: {id}");
        assert!(at_v1.iter().chain(&at_v2).all(|c| c.sealed_before_ids), "a name sealed with an origin is not marked to be sealed again");
        let copies: Vec<Copy> = at_v1.into_iter().chain(at_v2).collect();
        assert_eq!(plan_move(&copies, "photos", &V2, Some(&V1)), Plan::AtDestination { keep: copies[1].clone(), retire: vec![copies[0].clone()] });

        let resealed = SealedName { name: "photos".into(), id: id.clone() }.seal(&store, &tree(2), true).unwrap();
        let read = read_listing(&store, "alice", &V2, &[TenantDrive { tree: tree(2), sealed_name: resealed, held: 1 }], &[]);
        assert_eq!((read[0].id.as_str(), read[0].sealed_before_ids), (id.as_str(), false), "a name sealed again with its id reads as one before ids");
    }

    /// **A drive's id is in no path or name a vault sees** (CLAUDE.md's
    /// first test: no new join key). What a vault is sent for a drive is its
    /// tree id and the sealed name: the tree id is minted apart from the
    /// drive's id, and the sealed name does not carry the id in the clear.
    #[test]
    fn a_drives_id_is_in_nothing_a_vault_is_sent() {
        let dir = tempfile::tempdir().unwrap();
        let store = a_store(dir.path());
        let id = mint_id();
        let tree = MadeDrive(rand::random()).tree();
        let sealed = SealedName { name: "photos".into(), id: id.clone() }.seal(&store, &tree, true).unwrap();
        assert!(!tree.contains(&id), "the tree id carries the drive's id");
        let hex_sealed = hex::encode(&sealed);
        assert!(!hex_sealed.contains(&id) && !String::from_utf8_lossy(&sealed).contains(&id), "the sealed name carries the id in the clear");
        assert_ne!(mint_id(), id, "two drives were minted one id");
    }

    fn a_store(dir: &Path) -> UserStore {
        UserStore::create(
            "alice",
            "did:key:zAlice",
            dir.to_path_buf(),
            kotton_store::runtime::UserKeys::new(Some([7; 32])),
            &kotton_store::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap()
    }

    /// **A move holds the drive on this device for the whole of it**
    /// ([`drive_lock`]): while anything else on this device holds `photos` —
    /// another move of it — a move of `photos` waits, and runs once it is let
    /// go. (Here it then refuses: the person keeps drives on no vault; what
    /// is held is the wait.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_move_holds_the_drive_on_this_device_for_the_whole_of_it() {
        use crate::users::DeviceUsers as _;
        let temp = tempfile::TempDir::new().unwrap();
        let secrets = Arc::new(kotton_secret::MemorySecrets::new());
        let rt = Arc::new(
            DeviceRuntime::new_with_secrets(temp.path().to_path_buf(), crate::config::RuntimeConfig::default(), secrets)
                .await
                .unwrap(),
        );
        let (_, store) = rt.create_user("alice", "canyon-orbit-velvet-fish-hospital").await.unwrap();
        let records = Arc::new(kotton_record::open::user_record_store(rt.base_dir(), "alice", rt.secrets()).unwrap());
        let db = Arc::new(kotton_record::open_sqlite(&temp.path().join("machine.db")).await.unwrap());
        crate::db::MIGRATOR.run(db.as_ref()).await.unwrap();

        let held = rt.lock_mount("alice", &drive_lock("photos")).await;
        let moving = tokio::spawn({
            let (rt, store, records, db) = (Arc::clone(&rt), Arc::clone(&store), Arc::clone(&records), Arc::clone(&db));
            async move { move_to(&rt, &store, &records, &db, "alice", "photos", "elsewhere", None).await.unwrap() }
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!moving.is_finished(), "a move ran while the drive was held on this device");
        let other = rt.try_lock_mount("alice", &drive_lock("work"));
        assert!(other.is_some(), "holding one drive held another");
        drop(held);
        match moving.await.unwrap() {
            UserResponse::Error { message } => assert!(message.contains("drive move"), "{message}"),
            other => panic!("{other:?}"),
        }
    }
}
