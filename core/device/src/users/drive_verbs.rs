// SPDX-License-Identifier: AGPL-3.0-or-later
//! The drive's verbs on a person's device: `drive
//! create <name> [--on <vault>]`, `list`, `show <name>` and `move <name> --to
//! <vault> [--from <vault>]`, over the several drives a person may keep on one vault or many.
//!
//! **A drive is a sealed tree a vault keeps for its tenant** (`kvaultd::drives`):
//! each a tree made in the tenant's pool, `personal` among them; the
//! tenancy's own tree, `local`, is the pool's own mount and no drive. What
//! this device records of them is the drive record
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
//! **A move admits each key where the listing enters it** (kotton #274; the
//! rule is kotton #265's). What the device reads and writes is what the vault
//! the drive leaves listed, so each listed key is parsed into a
//! [`kotton_store::StorageKey`] before anything is read or written under it
//! ([`admit_listing`]), and carried typed from there. A key that is not
//! canonical, such as `../x`, is no object any device wrote: it is refused,
//! read at neither vault and written at neither, the rest of the drive moves,
//! and the move's answer counts it (`UserResponse::DriveMoved::keys_refused`), as a sync
//! pass counts the keys it refuses.
//!
//! **Each refused key is named in the person's own event log, where the move
//! refuses it** (kotton #315). The answer carries a count; the names go to the
//! log of the person whose drive it is ([`refused_events`], scoped to them, so
//! their log takes them and the device's and no one else's do), which `logs`
//! reads: the note a count is said with points there (`logs --level warn`, which
//! reads the same in the REPL and as `kotton logs`, kotton #355).
//! The listing is the vault's to answer, so a vault that lists a great many
//! such keys gets [`NAMED_AT_MOST`] of them named and one event counting the
//! rest, not a log the vault can fill. They are published as the listing is
//! admitted, before anything is copied, so a move cut off afterwards has
//! already handed them to the log. **Finishing an interrupted move**
//! ([`Plan::AtDestination`]) reads the listing of each copy it retires, to top
//! the drive up from it (below), and admits that listing the same way: what
//! it refuses there it names in the log and counts in its answer; the keys
//! the cut-off move refused were counted in that move's own refusal when it
//! answered one ([`Carried::SourceKept`]'s), and named in the log either way,
//! including when the device died between naming the copy and retiring the
//! source and nothing answered. What this does not hold: a log not open for the person
//! (no subscriber) takes nothing, and a daemon that dies in the moment between
//! publishing and the log's write loses the names; the count in the answer is
//! unaffected. The alternative, the names carried in the answer itself, is a
//! wire change (`DriveMoved` would carry them), and the finish would still
//! have none to carry.
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
//! devices' moves of it whose leases crossed (below). **`drive move <name> --to <vault>`
//! resolves that state by the id** ([`plan_move`]): if `<vault>` holds a copy,
//! it keeps that one, tops it up from the others, and retires them, and
//! answers that the drive moved — the interrupted move, finished; if it holds
//! none, it moves one copy there and then does the same with the rest. Two
//! copies of one name with *different* ids are two drives that no move made —
//! two `create`s that raced apart, which the making lease (below) rules out
//! among devices that record the same vaults — and are left alone: `move`
//! refuses and names both, and `--from <vault>` names the one meant.
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
//! **What a move holds: the drive, on this device and at every vault it
//! touches** (kotton #143). A move takes the drive's lock on this device
//! ([`drive_lock`], a [`DeviceRuntime::lock_mount`] keyed by the drive's name)
//! for the whole of it, so two moves of one drive on one device are one after
//! the other, and the second reads where the first left it. What no
//! device-local lock can hold is another device, so a move also takes a
//! lease the vault keeps (`kvaultd::drives`) on every tree it touches: the
//! drive where it is, before it lists it, read again once held, since
//! another device may have moved it meanwhile; the copy, whose lease the
//! vault gives with the tree (`TenantDriveMake`), or, finishing a move cut
//! off, the copy it tops up; each other finished copy it retires; and an
//! unfinished tree an earlier move left. A lease id is one
//! vault's and is never sent to another. While a tree is held, no other
//! device's pass writes into it, names it, retires it or moves it: each is
//! refused with `DriveHeld`, which names the holding device, and a pass so
//! refused fails as any failed pass does, keeps what it wrote, and sends it
//! where the drive is at its next pass. Every retire names the lease it is
//! under, and the vault refuses one that has lapsed or been taken since: a
//! fencing token. A lease is renewed every [`RENEW_EVERY`] on a connection of
//! its own, so a large object copied on the move's connection never holds a
//! renewal back, and again right before the copy is named finished and before
//! each retire; a renewal that fails stops the copy at its next object, and
//! the drive stays where it is ([`Leased`]). Every lease is let go when the
//! move ends, the copy's above all, which the person's other devices write
//! into once it is named.
//!
//! **One state a lease does not rule out.** A lease that lapses between its
//! last renewal and the naming — a device stalled there for a minute — can
//! be taken by another device's move of the same drive, and both may name a
//! copy finished. The first device's retire of the source is then refused,
//! its lease being gone, and the second's retires it; what is left is two
//! finished copies with one id and no source, which the next move resolves by
//! that id as it resolves any drive kept twice ([`plan_move`];
//! `two_copies_of_one_drive_two_movers_made_resolve_on_the_next_move`).
//! Nothing is lost: each copy was named finished only once it held every
//! object, and the next move tops up the one it retires.
//!
//! **Finishing a move tops up first, for every drive.** Retiring a finished
//! copy other than the one the drive now lives at — the source of a move cut
//! off after it named the copy, or a copy left by an earlier move — first
//! carries into the copy everything it lists that the copy does not, under a
//! lease on it, so what another device's pass wrote there meanwhile is not
//! lost ([`settle_copies`], [`top_up_and_settle`]).
//!
//! **One device at a time makes a drive.** `drive create` and the enrolment's
//! [`make_first`] take the person's *making* lease at one vault, the lowest
//! keyed among those the device records ([`making_vault`]), across the
//! listing and the make, and also hold the drive's name on this device
//! ([`drive_lock`]). So two devices creating one name at once, on one vault
//! or two, make one drive and refuse the other, which names the device
//! making one. The lease names no drive: the vault learns that some device of
//! the person's is making one, as the make tells it a moment later. It
//! coordinates the person's own devices, and is not a defence against them.
//!
//! **The first drive is made at the first vault, and moves like any other**
//! (kotton-protocol's *A drive is where things live and a device keeps what its person
//! chose*; kotton #124). `personal` is a made drive whose sealed name carries
//! [`kotton_wire::ipc::FIRST_DRIVE_ID`]. The device that enrols the person's
//! first vault makes it there, with no verb from the person ([`make_first`]):
//! only when every vault it records answers and no listing carries that id,
//! so a later vault holds nothing until a drive is made or moved there, and a
//! device that cannot tell makes none rather than a second. It holds
//! `personal`'s [`drive_lock`] across the listing, the make and the mark, as
//! `drive create personal` does, so two enrolments at once on this device make
//! one. It keeps it whole
//! until told otherwise, as the device that makes a drive does
//! (`crate::users::pins`). Every device's own tree syncs with it where it
//! lives ([`record::first`], `kotton_sync::engine`). `drive move personal
//! --to <vault>` carries it as it carries any drive, and every device follows
//! it at its next listing. A move of it holds this device's tree for the
//! whole of it, as a pass does, so this device writes nothing into the vault
//! it leaves meanwhile, and once the copy is named finished this device syncs
//! with the copy. A write another device's pass makes there while the move
//! runs is refused by the move's lease, and sent to the copy at that device's
//! next pass (above). **Two trees sealed `first`** are either the
//! two a move of it left, cut off between naming the copy and retiring the
//! source, or two that devices apart from each other each made, which no move
//! may resolve: a move retires every copy but one, and the other may hold
//! what this one does not. This device tells them apart by its own record of
//! the move it began ([`record::MoveBegun`], kept on this device and sent
//! nowhere): when that record names exactly the two listed, running the move
//! again to the same vault is let through ([`twice`]) and finishes it. While
//! it was cut off, the person's other devices kept syncing with the tree it
//! left, so before that tree is retired the rerun carries into the copy every
//! object the copy does not list, and checks the copy lists each, as a move
//! checks ([`top_up_and_settle`]); an object both list is left as the copy
//! holds it, since this device has synced with the copy since. Otherwise `move` refuses and
//! names both, and `status` says which this device keeps syncing with
//! (`crate::users::pins`). Choosing between two made apart is the person's,
//! by a verb not built yet.
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
//! drive (kotton #58), so today no claim names a made drive and every
//! made drive is told of as kept whole by nobody, which is true.
//!
//! **What a drive is, told to its person** (the drive decision's types).
//! `drive create`, `list`, `show` and `move` answer with descriptors
//! ([`describe`]), one per vault a drive is kept at: the drive's id, its
//! name, the vault that keeps it, its size as that vault last said, the
//! devices that claim it whole, and whether it is a move's unfinished tree.
//! The id is the record's ([`kotton_peer::daemon::drives::Drive::id`]) —
//! [`kotton_wire::ipc::FIRST_DRIVE_ID`] for `personal` — and an unfinished
//! tree's is the id sealed with it, so copies of
//! one drive show one id and two drives of one name show two. A descriptor is
//! this device's answer to its own person over its own IPC; no descriptor,
//! and so no id, is sent to a vault or a relay.

use crate::users::DeviceUsers as _;
use crate::users::pins;
use crate::DeviceRuntime;
use kotton_diag::{Event, EventCategory, EventLevel, EventScope};
use kotton_record::SqliteRecordStore;
use kotton_peer::daemon::drives::{self as record, Drive};
use kotton_peer::KottonPeerObjectStorage;
use kotton_store::runtime::user::UserStore;
use kotton_store::{NotCanonical, StorageKey};
use kotton_sys::store::SealedObjectAccess as _;
use kotton_wire::ipc::{
    DriveDescriptor, DriveLease, Holding, MadeDrive, TenantDrive, UserResponse, VaultPeerRequest, FIRST_DRIVE_ID, FIRST_DRIVE_NAME,
    TENANCY_TREE,
};
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
/// made there. Returns every copy it listed, `personal` among them.
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
    let listed = match ask(client, VaultPeerRequest::TenantDrives { user_id: user_id.to_string() }).await? {
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
        .filter(|c| c.finished)
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
    match ask(client, VaultPeerRequest::TenantDriveName { user_id: user_id.to_string(), drive, sealed_name }).await? {
        UserResponse::Ok => Ok(()),
        // Another device holds the tree, to move it (kotton #143): the name is
        // sealed again by whichever device next reads it unmoved, or the move
        // carries the tree away. Skipped, not failed.
        UserResponse::DriveHeld { .. } => {
            tracing::debug!(user_id, tree = %copy.tree, "a drive's name was not sealed again: another device holds it");
            Ok(())
        }
        UserResponse::Error { message } => Err(io::Error::other(message)),
        other => Err(io::Error::other(format!("the vault answered {other:?} to TenantDriveName"))),
    }
}

/// A vault's listing, read as copies: each made drive whose name opens,
/// finished or not, and a made drive whose name does not open, under the name
/// `recorded` has for its tree if any, or not at all. The tenancy's own tree
/// is no drive and no copy of one (module doc), whatever the vault lists of it.
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
        if drive.tree == TENANCY_TREE {
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

async fn ask(client: &KottonPeerObjectStorage, request: VaultPeerRequest) -> io::Result<UserResponse> {
    tokio::time::timeout(EACH_VAULT, client.send_to_vault(&request))
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

/// How often a lease this device holds is renewed while it holds it
/// ([`Leased`]): a third of the time a vault keeps one (`kvaultd::drives`).
/// One renewal that fails or goes unanswered within [`EACH_VAULT`] marks the
/// lease lost and stops what holds it: this device never acts on a lease it
/// cannot show the vault still holds, so the slack is in its favour only
/// when a renewal is slow, not when one is lost.
const RENEW_EVERY: Duration = Duration::from_secs(20);

/// Another device of the person's holds a lease at a vault (`DriveHeld`): its
/// key, as the vault admitted it, and how long the lease has left.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldBy {
    pub device_did: String,
    pub for_secs: u32,
}

/// The person's devices, by key and this device's name for each
/// (`pins::devices`): what a sentence naming a holding device reads.
type Names = Arc<Vec<(String, String)>>;

/// The person's devices as `store` lists them, this one among them.
async fn device_names(runtime: &DeviceRuntime, store: &UserStore) -> Names {
    Arc::new(pins::devices(store, &runtime.operational_did()).await)
}

/// `did`, under this device's name for it: `this device`, the person's own
/// label for another of theirs, or its key when this device knows none.
fn named_in(names: &[(String, String)], did: &str) -> String {
    match names.iter().find(|(d, _)| d == did) {
        Some((_, name)) => format!("'{name}'"),
        None => format!("another of your devices ({did})"),
    }
}

impl HeldBy {
    /// The holding device, under this device's name for it ([`named_in`]).
    async fn named(&self, runtime: &DeviceRuntime, store: &UserStore) -> String {
        named_in(&device_names(runtime, store).await, &self.device_did)
    }

    /// The sentence a verb refused by it says, after `what` (`"'photos' is
    /// being moved"`, `"a drive is being made"`).
    async fn said(&self, runtime: &DeviceRuntime, store: &UserStore, what: &str, vault: &str) -> String {
        format!(
            "{what} by {} now; try again when it is done (its hold on '{vault}' lasts {}s more unless that device renews it)",
            self.named(runtime, store).await,
            self.for_secs
        )
    }
}

/// Renew `lease` on `holding` at the vault `client` reaches; a refusal names
/// the holding device among `names`.
async fn renew_lease(client: &KottonPeerObjectStorage, user_id: &str, holding: Holding, lease: DriveLease, names: &[(String, String)]) -> Result<(), String> {
    let asked = VaultPeerRequest::TenantDriveHold { user_id: user_id.to_string(), holding, lease: Some(lease) };
    match ask(client, asked).await.map_err(|e| e.to_string())? {
        UserResponse::DriveHold { lease: renewed, .. } if renewed == lease => Ok(()),
        UserResponse::DriveHeld { device_did, for_secs } => {
            Err(format!("{} holds it now, for {for_secs}s more", named_in(names, &device_did)))
        }
        UserResponse::Error { message } => Err(message),
        other => Err(format!("the vault answered {other:?}")),
    }
}

/// **A lease this device holds at one vault** (kotton #143;
/// `kvaultd::drives`): on a made drive's tree while a move touches it, or on
/// the person's making of a drive. It is renewed every [`RENEW_EVERY`] on a
/// connection of its own, so a large object copied on another connection —
/// or a relayed one, whose requests go one at a time — never holds a renewal
/// back; and right before a move names a copy finished and before each
/// retire ([`VaultEnd::renew`]). A renewal that fails marks it lost, and a
/// move whose lease is lost stops at its next read or write
/// ([`PeerEnd`]): the renewal cancels the copy. Dropped, it stops renewing,
/// and the vault lets it go when it lapses; [`Self::let_go`] lets it go at
/// once.
pub struct Leased {
    user_id: String,
    holding: Holding,
    lease: DriveLease,
    client: KottonPeerObjectStorage,
    names: Names,
    lost: Arc<std::sync::Mutex<Option<String>>>,
    renewing: tokio::task::JoinHandle<()>,
}

impl Drop for Leased {
    fn drop(&mut self) {
        self.renewing.abort();
    }
}

impl Leased {
    /// Take `holding` at `node`, on a connection of its own. `Ok(Err)` is
    /// another device holding it.
    async fn take(runtime: &DeviceRuntime, names: &Names, node: &PairedNode, user_id: &str, holding: Holding) -> io::Result<Result<Arc<Self>, HeldBy>> {
        let client = dial(runtime, node, user_id).await?;
        let asked = VaultPeerRequest::TenantDriveHold { user_id: user_id.to_string(), holding, lease: None };
        match ask(&client, asked).await? {
            UserResponse::DriveHold { lease, .. } => Ok(Ok(Self::holding(client, names, user_id, holding, lease))),
            UserResponse::DriveHeld { device_did, for_secs } => Ok(Err(HeldBy { device_did, for_secs })),
            UserResponse::Error { message } => Err(io::Error::other(format!("the vault '{}' gave no lease: {message}", node.id))),
            other => Err(io::Error::other(format!("the vault '{}' answered {other:?} to TenantDriveHold", node.id))),
        }
    }

    /// The lease a vault gave (`DriveHold`), kept and renewed from here on,
    /// on `client`. A move's leases are each given a connection nothing else
    /// uses ([`Self::take`], and the copy's dialled for it), so a renewal
    /// never waits behind the copy. The new tree's lease `drive create` and
    /// [`make_first`] are given rides the connection they made the tree on,
    /// which they read one listing on before they let it go: nothing long is
    /// sent there for a renewal to wait behind.
    fn holding(client: KottonPeerObjectStorage, names: &Names, user_id: &str, holding: Holding, lease: DriveLease) -> Arc<Self> {
        let lost = Arc::new(std::sync::Mutex::new(None));
        let renewing = tokio::spawn({
            let (client, user_id, lost, names) = (client.clone(), user_id.to_string(), Arc::clone(&lost), Arc::clone(names));
            async move {
                loop {
                    tokio::time::sleep(RENEW_EVERY).await;
                    if let Err(e) = renew_lease(&client, &user_id, holding, lease, &names).await {
                        tracing::warn!(user_id, error = %e, "a lease on a drive was lost; what holds it stops");
                        *lost.lock().unwrap() = Some(e);
                        return;
                    }
                }
            }
        });
        Arc::new(Self { user_id: user_id.to_string(), holding, lease, client, names: Arc::clone(names), lost, renewing })
    }

    /// Why the lease was lost, once it was.
    fn lost(&self) -> Option<String> {
        self.lost.lock().unwrap().clone()
    }

    /// Renew it now, or say why it is lost.
    async fn renew(&self) -> Result<(), String> {
        if let Some(why) = self.lost() {
            return Err(why);
        }
        renew_lease(&self.client, &self.user_id, self.holding, self.lease, &self.names).await.inspect_err(|e| {
            *self.lost.lock().unwrap() = Some(e.clone());
        })
    }

    /// Let it go at the vault, so another device may take it at once.
    /// Best-effort: a lease not let go lapses.
    async fn let_go(&self) {
        self.renewing.abort();
        let asked = VaultPeerRequest::TenantDriveLetGo { user_id: self.user_id.clone(), holding: self.holding, lease: self.lease };
        if let Err(e) = ask(&self.client, asked).await {
            tracing::debug!(user_id = %self.user_id, error = %e, "a lease was not let go; it lapses");
        }
    }
}

/// Every lease a verb took, let go together when it ends, however it ends.
#[derive(Default)]
struct Holds(std::sync::Mutex<Vec<Arc<Leased>>>);

impl Holds {
    fn keep(&self, leased: &Arc<Leased>) {
        self.0.lock().unwrap().push(Arc::clone(leased));
    }

    async fn let_go(&self) {
        let held: Vec<Arc<Leased>> = std::mem::take(&mut *self.0.lock().unwrap());
        for leased in held {
            leased.let_go().await;
        }
    }
}

/// The vault a device takes the person's making lease at: the one with the
/// lowest key among those it records (module doc), so every device of theirs
/// that records the same vaults asks the same one.
async fn making_vault(db: &Arc<SqlitePool>, user_id: &str) -> io::Result<Option<Drive>> {
    Ok(record::list(db, user_id).await?.into_iter().min_by_key(|v| v.vault_key))
}

/// Take the person's making lease at [`making_vault`], kept in `holds`.
/// `Ok(Err)` is the sentence for another device holding it; `Ok(Ok(None))` a
/// device that records no vault, which makes nothing anyway.
async fn take_making(
    runtime: &DeviceRuntime,
    store: &UserStore,
    db: &Arc<SqlitePool>,
    user_id: &str,
    holds: &Holds,
) -> io::Result<Result<Option<Arc<Leased>>, String>> {
    let Some(vault) = making_vault(db, user_id).await? else { return Ok(Ok(None)) };
    match Leased::take(runtime, &device_names(runtime, store).await, &vault.node, user_id, Holding::Making).await? {
        Ok(making) => {
            holds.keep(&making);
            Ok(Ok(Some(making)))
        }
        Err(held) => Ok(Err(held.said(runtime, store, "a drive is being made", &vault.node.id).await)),
    }
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
/// no tree of a made drive yet, kotton #58). `personal` is the one made drive
/// a pass writes into, and a move of it also holds the tree the pass holds
/// ([`move_to`]).
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
    // Held across the listing and the make, so two creates of one name on
    // this device, or a create of `personal` beside an enrolment's
    // [`make_first`], make one drive: the second reads the first's.
    let _held = runtime.lock_mount(user_id, &drive_lock(&name)).await;
    // And the person's making lease, across their devices (module doc).
    let holds = Holds::default();
    let made = create_holding(runtime, store, records, db, user_id, &name, &vault, &holds).await;
    holds.let_go().await;
    made
}

/// [`create`], once the name is held on this device: the making lease taken,
/// the name found free at every vault, and the drive made.
#[allow(clippy::too_many_arguments)]
async fn create_holding(
    runtime: &DeviceRuntime,
    store: &UserStore,
    records: &SqliteRecordStore,
    db: &Arc<SqlitePool>,
    user_id: &str,
    name: &str,
    vault: &Drive,
    holds: &Holds,
) -> io::Result<UserResponse> {
    let name = name.to_string();
    let making = match take_making(runtime, store, db, user_id, holds).await? {
        Ok(making) => making,
        Err(why) => return refused(format!("drive create: {why}")),
    };
    // Every vault, not this one alone: a drive of this name made on another
    // by another device is taken whatever this device's record says.
    let seen = follow_every_vault(runtime, store, db, user_id).await?;
    if let Err(e) = name_is_free(&seen, &name) {
        return refused(format!("drive create: {e}"));
    }
    // Still held when the drive is made: a listing slow enough to outlast it
    // may have let another device make the name meanwhile.
    if let Some(making) = &making {
        if let Err(e) = making.renew().await {
            return refused(format!("drive create: this device's hold on making a drive was lost while it listed your drives ({e}); try again"));
        }
    }
    let client = dial(runtime, &vault.node, user_id).await?;
    let drive = MadeDrive(rand::random());
    let tree = drive.tree();
    // The drive's id, minted once, here, and sealed with every copy a move
    // makes; the tree's id is the vault's and is minted fresh at each. A
    // `personal` made here — no vault listed one, as every vault answered —
    // is the first drive, which [`make_first`] makes at enrolment, and takes
    // its id.
    let id = if name == FIRST_DRIVE_NAME { FIRST_DRIVE_ID.to_string() } else { mint_id() };
    let sealed_name = SealedName { name: name.clone(), id }.seal(store, &tree, true)?;
    match ask(&client, VaultPeerRequest::TenantDriveMake { user_id: user_id.to_string(), drive, sealed_name }).await? {
        // The new tree's lease, which nothing here holds it under: let go.
        UserResponse::DriveHold { lease, .. } => holds.keep(&Leased::holding(client.clone(), &device_names(runtime, store).await, user_id, Holding::Drive(drive), lease)),
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
    // drive paths (kotton #58) give it. That is the seam (module doc): until
    // then no device keeps a made drive, so none claims it, and a claim saying
    // so would silence the
    // telling that only the vault holds it (`crate::users::pins`), which is
    // the truth.
    if name == FIRST_DRIVE_NAME {
        made_here(db, user_id, &made).await?;
    }
    tracing::info!(user_id, vault = %vault.node.id, "made a drive");
    Ok(UserResponse::Drives { drives: vec![describe(&made, &sizes, &pins_now(runtime, records, store, db, user_id).await?)] })
}

/// What [`make_first`] did at an enrolment.
#[derive(Debug, PartialEq, Eq)]
pub enum MadeFirst {
    /// `personal` was made at the vault just enrolled.
    Made,
    /// A listing carries it already: the vault just enrolled is a place for
    /// drives and holds nothing.
    Kept,
    /// These vaults did not answer, so whether `personal` is kept at one of
    /// them cannot be told; none was made.
    Unanswered(Vec<String>),
    /// Another device of the person's is making a drive now (its making
    /// lease, kotton #143), so this one made none: the sentence says which.
    Making(String),
}

/// **Make `personal` at the vault `vault_key` just enrolled, if it is the
/// first** (module doc; kotton-protocol's storage model): with no verb from the person, only when
/// every vault this device records answers and no listing carries
/// [`FIRST_DRIVE_ID`]. Its name is sealed there as any drive's, with that id,
/// and this device keeps it whole until told otherwise ([`made_here`]). A
/// vault enrolled after it holds nothing until a drive is made or moved there.
pub async fn make_first(runtime: &DeviceRuntime, store: &UserStore, db: &Arc<SqlitePool>, user_id: &str, vault_key: &[u8; 32]) -> io::Result<MadeFirst> {
    // Held across the listing, the make and the mark: two enrolments at once
    // on this device make one `personal`, the second reading the first's.
    let _held = runtime.lock_mount(user_id, &drive_lock(FIRST_DRIVE_NAME)).await;
    // And across the person's devices, as `drive create` holds it.
    let holds = Holds::default();
    let made = make_first_holding(runtime, store, db, user_id, vault_key, &holds).await;
    holds.let_go().await;
    made
}

/// [`make_first`], once `personal` is held on this device.
async fn make_first_holding(
    runtime: &DeviceRuntime,
    store: &UserStore,
    db: &Arc<SqlitePool>,
    user_id: &str,
    vault_key: &[u8; 32],
    holds: &Holds,
) -> io::Result<MadeFirst> {
    let making = match take_making(runtime, store, db, user_id, holds).await? {
        Ok(making) => making,
        Err(why) => return Ok(MadeFirst::Making(why)),
    };
    let seen = follow_every_vault(runtime, store, db, user_id).await?;
    if !seen.unanswered.is_empty() {
        return Ok(MadeFirst::Unanswered(seen.unanswered));
    }
    if let Some(making) = &making {
        if let Err(e) = making.renew().await {
            return Ok(MadeFirst::Making(format!("this device's hold on making a drive was lost while it listed ({e})")));
        }
    }
    if seen.copies.iter().any(|c| c.id == FIRST_DRIVE_ID) {
        return Ok(MadeFirst::Kept);
    }
    let vault = record::list(db, user_id)
        .await?
        .into_iter()
        .find(|v| v.vault_key == *vault_key)
        .ok_or_else(|| io::Error::other("the vault just enrolled is not recorded"))?;
    let client = dial(runtime, &vault.node, user_id).await?;
    let drive = MadeDrive(rand::random());
    let tree = drive.tree();
    let sealed_name = SealedName { name: FIRST_DRIVE_NAME.to_string(), id: FIRST_DRIVE_ID.to_string() }.seal(store, &tree, true)?;
    match ask(&client, VaultPeerRequest::TenantDriveMake { user_id: user_id.to_string(), drive, sealed_name }).await? {
        UserResponse::DriveHold { lease, .. } => holds.keep(&Leased::holding(client.clone(), &device_names(runtime, store).await, user_id, Holding::Drive(drive), lease)),
        UserResponse::Error { message } => return Err(io::Error::other(format!("the vault '{}' refused it: {message}", vault.node.id))),
        other => return Err(io::Error::other(format!("the vault '{}' answered {other:?}", vault.node.id))),
    }
    follow(store, db, user_id, vault_key, &client).await?;
    let made = record::all(db, user_id)
        .await?
        .into_iter()
        .find(|d| d.vault_key == *vault_key && d.tree == tree)
        .ok_or_else(|| io::Error::other("the vault made the drive but did not list it"))?;
    made_here(db, user_id, &made).await?;
    tracing::info!(user_id, vault = %vault.node.id, "made the first drive at the first vault");
    Ok(MadeFirst::Made)
}

/// `personal`, made by this device at `made`: the copy its tree syncs with
/// ([`record::mark_synced`]), kept whole here until told otherwise — a drive
/// setting written only when this device's settings would not keep it whole
/// already, as a device that joined defaults to on demand. The claim that says
/// so is written by the pass that carries this device's tree to it, which is
/// the first time the drive can hold it (`crate::users::pins::claim`).
async fn made_here(db: &Arc<SqlitePool>, user_id: &str, made: &Drive) -> io::Result<()> {
    record::mark_synced(db, user_id, &made.vault_key, &made.tree).await?;
    if !pins::keeps_whole(&pins::settings(db, user_id).await?, FIRST_DRIVE_NAME) {
        pins::write(db, user_id, &kotton_wire::ipc::PinScope::Drive { drive: FIRST_DRIVE_NAME.into() }, Some(kotton_wire::ipc::PinValue::Whole)).await?;
    }
    Ok(())
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
    let mut drives: Vec<DriveDescriptor> = record::kept(db, user_id).await?.iter().map(|d| describe(d, &sizes, &pins)).collect();
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
    let mut drives: Vec<DriveDescriptor> = record::kept(db, user_id)
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
    /// Every sealed object of the tree, by key, with its size, as the vault
    /// listed them. A key here is what the vault chose to answer:
    /// [`carry_and_settle`] admits each before it reads or writes under it.
    async fn objects(&self) -> Result<Vec<(String, u64)>, String>;
    /// One sealed object, as it rests, by an admitted key.
    async fn read(&self, key: &StorageKey) -> Result<Vec<u8>, String>;
    /// Write one sealed object, as it rests, under an admitted key.
    async fn write(&self, key: &StorageKey, blob: &[u8]) -> Result<(), String>;
    /// A tenant verb the vault answers `Ok` to, or why not.
    async fn tell(&self, request: VaultPeerRequest) -> Result<(), String>;
    /// Renew the lease this device holds on the tree (kotton #143), or say
    /// why it is lost. A tree held under no lease has none to renew.
    async fn renew(&self) -> Result<(), String> {
        Ok(())
    }
    /// The lease this device holds on the tree, which a retire of it names.
    fn lease(&self) -> Option<DriveLease> {
        None
    }
}

/// A vault reached over the peer link, its sealed verbs pointed at one tree,
/// and the lease this device holds on that tree there, if it holds one: a
/// read or write once the lease is lost is refused here, so a move stops
/// ([`Leased`]).
struct PeerEnd(KottonPeerObjectStorage, Option<Arc<Leased>>);

impl PeerEnd {
    fn still_held(&self) -> Result<(), String> {
        match self.1.as_ref().and_then(|l| l.lost()) {
            Some(why) => Err(format!("this device's hold on the drive there was lost ({why}), so the move stopped")),
            None => Ok(()),
        }
    }
}

#[async_trait::async_trait]
impl VaultEnd for PeerEnd {
    async fn objects(&self) -> Result<Vec<(String, u64)>, String> {
        self.still_held()?;
        let listed = self.0.list_sealed(Path::new("")).await.map_err(|e| e.to_string())?;
        Ok(listed.into_iter().map(|o| (o.key, o.size)).collect())
    }
    async fn read(&self, key: &StorageKey) -> Result<Vec<u8>, String> {
        self.still_held()?;
        self.0.get_sealed(key.as_path()).await.map(|b| b.to_vec()).map_err(|e| e.to_string())
    }
    async fn write(&self, key: &StorageKey, blob: &[u8]) -> Result<(), String> {
        self.still_held()?;
        self.0.put_sealed(key.as_path(), blob).await.map_err(|e| e.to_string())
    }
    async fn tell(&self, request: VaultPeerRequest) -> Result<(), String> {
        match ask(&self.0, request).await.map_err(|e| e.to_string())? {
            UserResponse::Ok => Ok(()),
            UserResponse::DriveHeld { device_did, for_secs } => {
                let holder = match &self.1 {
                    Some(leased) => named_in(&leased.names, &device_did),
                    None => format!("another of your devices ({device_did})"),
                };
                Err(format!("{holder} holds the drive there, for {for_secs}s more"))
            }
            UserResponse::Error { message } => Err(message),
            other => Err(format!("the vault answered {other:?}")),
        }
    }
    async fn renew(&self) -> Result<(), String> {
        match &self.1 {
            Some(leased) => leased.renew().await,
            None => Ok(()),
        }
    }
    fn lease(&self) -> Option<DriveLease> {
        self.1.as_ref().map(|l| l.lease)
    }
}

/// Retire the made drive `drive` at `end`, under the lease this device holds
/// on it there, renewed first (kotton #143), asking a second time only when
/// the first answer was not `Ok`. A retire is idempotent at the vault, so a
/// first ask that acted and whose answer was lost is answered `Ok` the second
/// time, lease or none; an `Err` from the second is the vault saying it still
/// keeps the tree — among the reasons, that the lease lapsed or another device
/// took it, which the vault refuses as a fencing token. The renewal is
/// best-effort: the vault's answer to the retire is the one that counts.
pub async fn retire(end: &dyn VaultEnd, user_id: &str, drive: MadeDrive) -> Result<(), String> {
    if let Err(e) = end.renew().await {
        tracing::debug!(user_id, error = %e, "a lease was not renewed before a retire; the vault decides");
    }
    let lease = end.lease();
    let ask = || end.tell(VaultPeerRequest::TenantDriveRetire { user_id: user_id.to_string(), drive, lease });
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

/// A move's outcome ([`Carried`]) and the keys the vault it left listed that
/// were refused at the listing ([`admit_listing`]): read from neither vault,
/// written to neither, and counted in the move's answer.
#[derive(Debug)]
pub struct Settled {
    /// How the move came out.
    pub carried: Carried,
    /// Each key the source listed that is not canonical, and why.
    pub refused: Vec<NotCanonical>,
}

/// **The admission of a move** (kotton #274; the rule is kotton #265's,
/// `kotton_store::StorageKey`). The source's listing is what that vault chose
/// to answer, and every key in it becomes a read there and a write at the
/// other vault, so each is parsed into a [`StorageKey`] here, where the
/// listing enters the move, and carried typed from here on. A key that is not
/// canonical (`../x`, `./p`, `/p`, `p/`) is refused: named in the log,
/// returned, and never read or written. It is no object any device wrote,
/// since a store writes only canonical keys, so the rest of the drive moves
/// without it, as a sync pass skips and counts it.
fn admit_listing(listed: Vec<(String, u64)>) -> (Vec<(StorageKey, u64)>, Vec<NotCanonical>) {
    let mut admitted = Vec::with_capacity(listed.len());
    let mut refused = Vec::new();
    for (key, size) in listed {
        match StorageKey::parse(&key) {
            Ok(key) => admitted.push((key, size)),
            Err(not) => {
                tracing::warn!("drive move: the vault the drive leaves listed a key: {not}; nothing is read or written under it");
                refused.push(not);
            }
        }
    }
    (admitted, refused)
}

/// How many refused keys one move names in the log, one event each; past it,
/// one event counts the rest ([`refused_events`]).
pub const NAMED_AT_MOST: usize = 32;

/// The events that name the keys a move of the drive `name` refused
/// (`refused`), for the log of the person whose drive it is (`user_id`):
/// scoped to them, so their own log takes them ([`EventScope::User`]), which
/// `logs` reads; at `warn`, which the note that counts the keys names (`logs
/// --level warn`). Each names the drive and the vault (`from`) as the person
/// calls them, and the key as the vault listed it, quoted, so a key with a
/// control character in it is printed escaped. The first [`NAMED_AT_MOST`] are
/// named, one event each, and one more event counts any past them: the listing
/// is the vault's, and how much it writes into the person's log is not.
pub fn refused_events(user_id: &str, name: &str, from: &str, refused: &[NotCanonical]) -> Vec<Event> {
    let scope = EventScope::User(user_id.to_string());
    let mut events: Vec<Event> = refused
        .iter()
        .take(NAMED_AT_MOST)
        .map(|not| {
            Event::with_payload(
                EventCategory::Storage,
                EventLevel::Warn,
                format!("drive move of '{name}' from '{from}': {not}; the move read and wrote nothing under it, and did not carry it"),
                serde_json::json!({ "drive": name, "from": from, "key": not.key, "why": not.why }),
            )
            .in_scope(scope.clone())
        })
        .collect();
    if let Some(rest) = refused.len().checked_sub(NAMED_AT_MOST).filter(|rest| *rest > 0) {
        events.push(
            Event::with_payload(
                EventCategory::Storage,
                EventLevel::Warn,
                format!(
                    "drive move of '{name}' from '{from}': it also listed {}, past the {NAMED_AT_MOST} named before \
                     this; the move read and wrote nothing under them, and did not carry them",
                    NotCanonical::counted(rest)
                ),
                serde_json::json!({ "drive": name, "from": from, "not_named": rest }),
            )
            .in_scope(scope),
        );
    }
    events
}

/// Copy the drive, check it, name it finished at `to`, then retire it at
/// `from` — and, if any step before the naming fails, retire the unfinished
/// tree at `to` (module doc). `to` was made under a name sealed unfinished;
/// `finished_name` is the drive's name sealed finished for `to_id`. Each key
/// `from` lists is admitted before anything is read or written under it
/// ([`admit_listing`]); those refused are handed to `record` then, before
/// anything is copied, and are in the answer.
pub async fn carry_and_settle(
    user_id: &str,
    from: &dyn VaultEnd,
    from_id: MadeDrive,
    to: &dyn VaultEnd,
    to_id: MadeDrive,
    finished_name: Vec<u8>,
    record: &(dyn Fn(&[NotCanonical]) + Sync),
) -> Settled {
    let mut refused = Vec::new();
    let carried = async {
        let listed = from.objects().await.map_err(|e| format!("the drive could not be listed: {e}"))?;
        let (wanted, not_canonical) = admit_listing(listed);
        if !not_canonical.is_empty() {
            record(&not_canonical);
        }
        refused = not_canonical;
        for (key, _) in &wanted {
            let blob = from.read(key).await.map_err(|e| format!("reading {key}: {e}"))?;
            to.write(key, &blob).await.map_err(|e| format!("writing {key}: {e}"))?;
        }
        // What the other vault lists is compared with what was sent, as it
        // spelled it: a key that was not sent, canonical or not, fails it.
        let mut wanted: Vec<(String, u64)> = wanted.into_iter().map(|(k, size)| (k.as_str().to_string(), size)).collect();
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
        // Both holds renewed right before the naming (kotton #143): a source
        // this device no longer holds may have taken a write since it was
        // listed, and a copy it no longer holds may be another move's.
        from.renew().await.map_err(|e| format!("this device's hold on the drive where it is was lost: {e}"))?;
        to.renew().await.map_err(|e| format!("this device's hold on the copy was lost: {e}"))?;
        to.tell(VaultPeerRequest::TenantDriveName { user_id: user_id.to_string(), drive: to_id, sealed_name: finished_name })
            .await
            .map_err(|e| format!("the other vault did not name the drive: {e}"))
    }
    .await;
    let carried = if let Err(why) = carried {
        match retire(to, user_id, to_id).await {
            Ok(()) => Carried::NotMoved(why),
            Err(left) => Carried::NotMovedTreeLeft { why, left },
        }
    } else {
        match retire(from, user_id, from_id).await {
            Ok(()) => Carried::Moved,
            Err(e) => Carried::SourceKept(e),
        }
    };
    Settled { carried, refused }
}

/// **Finish a move cut off after it named its copy at `to`**: carry from
/// `from`, the tree the move left, every object the copy does not list —
/// what another device's pass wrote there after the copy was made — check that
/// the copy lists each at the size sent and every key `from` lists, and then
/// retire `from`. An object both list is left as the copy holds it, since a
/// pass that synced with the copy may have written it since (module doc).
/// Keys are admitted as [`carry_and_settle`] admits them. Nothing here
/// retires the copy, which is named finished already: a failure leaves both
/// trees as they are, [`Carried::SourceKept`], and the move is run again.
pub async fn top_up_and_settle(
    user_id: &str,
    from: &dyn VaultEnd,
    from_id: MadeDrive,
    to: &dyn VaultEnd,
    record: &(dyn Fn(&[NotCanonical]) + Sync),
) -> Settled {
    let mut refused = Vec::new();
    let topped = async {
        let listed = from.objects().await.map_err(|e| format!("the tree it left could not be listed: {e}"))?;
        let (wanted, not_canonical) = admit_listing(listed);
        if !not_canonical.is_empty() {
            record(&not_canonical);
        }
        refused = not_canonical;
        let held: Vec<(String, u64)> = to.objects().await.map_err(|e| format!("the copy could not be listed: {e}"))?;
        let lacking: Vec<&(StorageKey, u64)> = wanted.iter().filter(|(k, _)| !held.iter().any(|(h, _)| h == k.as_str())).collect();
        for (key, _) in &lacking {
            let blob = from.read(key).await.map_err(|e| format!("reading {key}: {e}"))?;
            to.write(key, &blob).await.map_err(|e| format!("writing {key}: {e}"))?;
        }
        let landed = to.objects().await.map_err(|e| format!("the copy could not list what it took: {e}"))?;
        // Each key the tree it left lists is at the copy; each one sent is
        // there at the size it was sent.
        let sent = |k: &StorageKey| lacking.iter().any(|(l, _)| l == k);
        let missing = wanted
            .iter()
            .filter(|(k, size)| !landed.iter().any(|(l, s)| l == k.as_str() && (!sent(k) || s == size)))
            .count();
        if missing > 0 {
            return Err(format!("the copy does not list {missing} of the objects the tree it left holds, at the size they were sent"));
        }
        Ok(())
    }
    .await;
    let carried = match topped {
        Err(why) => Carried::SourceKept(why),
        Ok(()) => match retire(from, user_id, from_id).await {
            Ok(()) => Carried::Moved,
            Err(e) => Carried::SourceKept(e),
        },
    };
    Settled { carried, refused }
}

/// The clause a refused move's answer adds when the vault it left listed keys
/// it refused ([`admit_listing`]); empty when it listed none. A count, said as
/// the shell's note says it ([`NotCanonical::counted`]), as the answer to a
/// move that went counts them, and where the names are: the person's event
/// log, which [`refused_events`] wrote them to.
fn refused_said(refused: &[NotCanonical], src: &str) -> String {
    match refused.len() {
        0 => String::new(),
        n => format!(
            " ('{src}' also listed {}, which the move refused and did not carry; your event log names {}: `logs --level warn`)",
            NotCanonical::counted(n),
            if n == 1 { "it" } else { "them" }
        ),
    }
}

/// What `drive move <name> --to <vault> [--from <vault>]` does, given every
/// copy of every drive the vaults listed (module doc).
#[derive(Debug, PartialEq, Eq)]
pub enum Plan {
    /// No drive is called that (at `--from`, when named).
    NoSuch,
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

/// Every finished tree the vaults listed sealed with [`FIRST_DRIVE_ID`], by
/// vault and tree.
pub fn finished_firsts(copies: &[Copy]) -> Vec<record::TreeAt> {
    copies.iter().filter(|c| c.finished && c.id == FIRST_DRIVE_ID).map(|c| (c.vault_key, c.tree.clone())).collect()
}

/// What two finished trees sealed `first` are to a move of `personal`
/// (module doc).
#[derive(Debug, PartialEq, Eq)]
pub enum Twice {
    /// One, or none: nothing to tell apart.
    No,
    /// The two this device's own move left, to the vault it is asked to move
    /// to: the move runs again, and finishes ([`Plan::AtDestination`]).
    OwnMove,
    /// The two this device's own move left, to another vault than the one
    /// asked: that move is finished first.
    OwnMoveElsewhere([u8; 32]),
    /// Two this device began no move between: another device's move, or two
    /// made apart. No move retires either.
    Apart,
}

/// Tell what `firsts` (every finished tree sealed `first`) are, given the move
/// this device began, if any, and the vault a move is asked to go to.
pub fn twice(firsts: &[record::TreeAt], begun: Option<&record::MoveBegun>, dest: &[u8; 32]) -> Twice {
    if firsts.len() <= 1 {
        return Twice::No;
    }
    match begun {
        Some(b) if b.names_exactly(firsts) && b.to.0 == *dest => Twice::OwnMove,
        Some(b) if b.names_exactly(firsts) => Twice::OwnMoveElsewhere(b.to.0),
        _ => Twice::Apart,
    }
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
    // this lock does not see; the leases the vaults keep do (module doc).
    let _held = runtime.lock_mount(user_id, &drive_lock(name)).await;
    // `personal` is what this device's own tree syncs with, wherever it
    // lives, so its move also holds the tree as a pass does
    // (`kotton_sync::engine::sync_mount_with_records`): no pass of this
    // device's writes into the vault it leaves while it is being copied.
    let _tree_held = if name == FIRST_DRIVE_NAME { Some(runtime.lock_mount(user_id, kotton_common::LOCAL_MOUNT).await) } else { None };
    // Every lease the move takes, let go when it ends, however it ends: the
    // copy's above all, which other devices' passes write into once it is
    // named finished.
    let holds = Holds::default();
    let moved = move_holding(runtime, store, records, db, user_id, name, to, from, &holds).await;
    holds.let_go().await;
    moved
}

/// [`move_to`], once the drive is held on this device; every lease it takes
/// is kept in `holds`.
#[allow(clippy::too_many_arguments)]
async fn move_holding(
    runtime: &DeviceRuntime,
    store: &UserStore,
    records: &SqliteRecordStore,
    db: &Arc<SqlitePool>,
    user_id: &str,
    name: &str,
    to: &str,
    from: Option<&str>,
    holds: &Holds,
) -> io::Result<UserResponse> {
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
    // Where a test pauses a move, to put another device's between its
    // listing and its first lease (debug builds only; kotton #143).
    #[cfg(debug_assertions)]
    runtime.test_hooks.move_listed().await;
    let names = device_names(runtime, store).await;
    if !seen.unanswered.is_empty() {
        return refused(format!(
            "drive move: {} did not answer, so where every copy of '{name}' is cannot be told; try again when it does",
            seen.unanswered.join(", ")
        ));
    }
    // Two trees sealed as `personal`: a move would retire all but one, and the
    // other may hold what this one does not, unless they are the two this
    // device's own move left (module doc).
    if name == FIRST_DRIVE_NAME {
        let firsts = finished_firsts(&seen.copies);
        let begun = record::move_begun(db, user_id).await?;
        match twice(&firsts, begun.as_ref(), &dest.vault_key) {
            Twice::No => {
                if begun.is_some() && firsts.len() <= 1 {
                    // A move this device began that is over: finished at
                    // another device, or by a listing that no longer has two.
                    record::end_move(db, user_id).await?;
                }
            }
            Twice::OwnMove => {}
            Twice::OwnMoveElsewhere(to) => {
                return refused(format!(
                    "drive move: this device's move of '{name}' to '{}' has not finished, and '{name}' is on both \
                     vaults until it does: run `drive move {name} --to {}` first",
                    label(&to),
                    label(&to)
                ))
            }
            Twice::Apart => {
                return refused(format!(
                    "drive move: you have {} drives called '{name}' ({}), and this device began no move between them. \
                     If another of your devices began moving it, run that move again there to finish it; otherwise \
                     they were made apart, and a move, which keeps one and retires the rest, would lose what only the \
                     other holds, so none is moved. `status` says which this device syncs with",
                    firsts.len(),
                    firsts.iter().map(|(k, _)| format!("on '{}'", label(k))).collect::<Vec<_>>().join(", ")
                ))
            }
        }
    }
    let Some(domain) = runtime.user_cek_domain_id(user_id, Some(store)) else {
        return refused("drive move: this device holds no key for you, so it cannot carry a drive");
    };
    let plan = plan_move(&seen.copies, name, &dest.vault_key, from_vault.as_ref().map(|v| &v.vault_key));
    let (source, retire_after) = match plan {
        Plan::NoSuch => return refused(format!("drive move: you have no drive called '{name}'{}", from.map(|f| format!(" on '{f}'")).unwrap_or_default())),
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
            // A move cut off after it named the copy here, this device's own
            // or another's: finish it. Whatever the copies it left took since
            // — another device's pass kept writing there — is carried into
            // the copy before each is retired, under a lease on each
            // ([`settle_copies`]). For `personal` this is only ever this
            // device's own move ([`twice`] refused any other above). The copy
            // it writes into is held too, as every tree a move touches is.
            let Some(keep_id) = keep.made() else {
                return refused(format!("drive move: '{name}' is kept under {}, which is no drive's tree", keep.tree));
            };
            let keep_held = match Leased::take(runtime, &names, &dest.node, user_id, Holding::Drive(keep_id)).await {
                Ok(Ok(held)) => {
                    holds.keep(&held);
                    held
                }
                Ok(Err(held)) => {
                    return refused(format!(
                        "drive move: {}",
                        held.said(runtime, store, &format!("'{name}' is being moved"), &dest.node.id).await
                    ))
                }
                Err(e) => return refused(format!("drive move: '{name}' could not be held on '{}' to finish its move ({e}); try again", dest.node.id)),
            };
            let into = PeerEnd(dial(runtime, &dest.node, user_id).await?.with_remote_mount(keep.tree.clone()).with_domain_id(domain.clone()), Some(keep_held));
            let settled = settle_copies(runtime, store, &vaults, user_id, name, &rest, &into, &domain, holds).await?;
            refollow(runtime, store, db, user_id, &vaults, &rest, &dest).await;
            let also = refused_said(&settled.refused, &settled.from);
            if let Some(left) = settled.left {
                return refused(if name == FIRST_DRIVE_NAME {
                    format!(
                        "drive move: '{name}' is on '{}', and this device syncs with it there, but {left}. Run \
                         `drive move {name} --to {}` again on this device to finish it{also}",
                        dest.node.id, dest.node.id
                    )
                } else {
                    format!("drive move: '{name}' is on '{}', and {left}; run the move again to retire it{also}", dest.node.id)
                });
            }
            if name == FIRST_DRIVE_NAME {
                record::end_move(db, user_id).await?;
                record::mark_synced(db, user_id, &keep.vault_key, &keep.tree).await?;
            }
            let sizes = Seen { copies: vec![keep.clone()], unanswered: vec![] }.sizes();
            let moved = record::all(db, user_id).await?.into_iter().find(|d| d.vault_key == keep.vault_key && d.tree == keep.tree);
            let moved = moved.ok_or_else(|| io::Error::other("the drive's copy at the vault was not recorded"))?;
            let keys_refused = settled.refused.len();
            tracing::info!(user_id, to = %dest.node.id, keys_refused, "finished an interrupted drive move");
            let keys_refused = u32::try_from(keys_refused).unwrap_or(u32::MAX);
            return Ok(UserResponse::DriveMoved { drives: vec![describe(&moved, &sizes, &pins)], keys_refused });
        }
        Plan::Carry { source, retire_after } => (source, retire_after),
    };
    let Some(from_id) = source.made() else {
        return refused(format!("drive move: '{name}' is kept under {}, which is no drive's tree", source.tree));
    };
    let Some(source_vault) = vaults.iter().find(|v| v.vault_key == source.vault_key).cloned() else {
        return refused(format!("drive move: the vault '{name}' is on is not one this device reaches"));
    };

    // The drive is held where it is before it is listed, and to its retire
    // (module doc): no other device writes into it, names it, retires it or
    // moves it meanwhile.
    let source_held = match Leased::take(runtime, &names, &source_vault.node, user_id, Holding::Drive(from_id)).await {
        Ok(Ok(held)) => {
            holds.keep(&held);
            held
        }
        Ok(Err(held)) => {
            return refused(format!(
                "drive move: {}",
                held.said(runtime, store, &format!("'{name}' is being moved"), &source_vault.node.id).await
            ))
        }
        Err(e) => {
            return refused(format!(
                "drive move: '{name}' could not be held on '{}' to move it ({e}); try again",
                source_vault.node.id
            ))
        }
    };
    let from_client = dial(runtime, &source_vault.node, user_id).await?;
    // Read again now that it is held: another device's move may have taken it
    // between this device's listing and its lease.
    let relisted = follow(store, db, user_id, &source.vault_key, &from_client).await?;
    if !relisted.iter().any(|c| c.finished && c.tree == source.tree && c.id == source.id) {
        return refused(format!(
            "drive move: '{name}' changed on '{}' as this move began (another of your devices moved or retired it); \
             run the move again",
            source_vault.node.id
        ));
    }
    let dest_client = dial(runtime, &dest.node, user_id).await?;
    // An earlier move of this drive to this vault that left its tree there,
    // retired under a lease of its own.
    for stale in seen.copies.iter().filter(|c| !c.finished && c.vault_key == dest.vault_key && c.name == name) {
        let Some(id) = stale.made() else { continue };
        let held = match Leased::take(runtime, &names, &dest.node, user_id, Holding::Drive(id)).await {
            Ok(Ok(held)) => {
                holds.keep(&held);
                Some(held)
            }
            Ok(Err(held)) => {
                return refused(format!(
                    "drive move: {}",
                    held.said(runtime, store, &format!("'{name}' is being moved to '{}'", dest.node.id), &dest.node.id).await
                ))
            }
            // Gone since it was listed, or the vault did not answer: the
            // retire, idempotent, says which.
            Err(_) => None,
        };
        let end = PeerEnd(dial(runtime, &dest.node, user_id).await?, held);
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
    // The copy's lease is renewed on a connection of its own (module doc),
    // dialled before the tree is made so a failed dial leaves nothing there.
    let renews_copy = dial(runtime, &dest.node, user_id).await?;
    let dest_held = match ask(&dest_client, VaultPeerRequest::TenantDriveMake { user_id: user_id.to_string(), drive: to_id, sealed_name: unfinished_name }).await? {
        UserResponse::DriveHold { lease, .. } => Leased::holding(renews_copy, &names, user_id, Holding::Drive(to_id), lease),
        UserResponse::Error { message } => return refused(format!("drive move: '{}' refused the drive: {message}", dest.node.id)),
        other => return refused(format!("drive move: '{}' answered {other:?}", dest.node.id)),
    };
    holds.keep(&dest_held);
    // What lets a rerun of this move through, should it be cut off between
    // naming the copy finished and retiring the source (module doc).
    if name == FIRST_DRIVE_NAME {
        let begun = record::MoveBegun { from: (source.vault_key, source.tree.clone()), to: (dest.vault_key, to_tree.clone()) };
        record::begin_move(db, user_id, &begun).await?;
    }
    let from_end = PeerEnd(from_client.with_remote_mount(source.tree.clone()).with_domain_id(domain.clone()), Some(source_held));
    let to_end = PeerEnd(dest_client.with_remote_mount(to_tree.clone()).with_domain_id(domain.clone()), Some(dest_held));
    // The keys the move refuses are named in the person's own log as the
    // listing is admitted ([`refused_events`]). No subscriber (no log open)
    // drops them; the count is still in the answer.
    let bus = runtime.event_bus();
    let src_label = source_vault.node.id.as_str();
    let record = |refused: &[NotCanonical]| {
        for event in refused_events(user_id, name, src_label, refused) {
            let _ = bus.publish(event);
        }
    };
    let Settled { carried, refused: mut not_carried } =
        carry_and_settle(user_id, &from_end, from_id, &to_end, to_id, finished_name, &record).await;
    // The other copies of the drive, as the source was: each held, what it
    // took since topped up into the copy, and retired ([`settle_copies`]).
    let left = if carried == Carried::Moved && !retire_after.is_empty() {
        let settled = settle_copies(runtime, store, &vaults, user_id, name, &retire_after, &to_end, &domain, holds).await?;
        not_carried.extend(settled.refused);
        settled.left
    } else {
        None
    };

    let mut sizes = HashMap::new();
    for (vault, end) in [(&source_vault, &from_end), (&dest, &to_end)] {
        match follow(store, db, user_id, &vault.vault_key, &end.0).await {
            Ok(copies) => sizes.extend(Seen { copies, unanswered: vec![] }.sizes()),
            Err(e) => tracing::warn!(user_id, vault = %vault.node.id, error = %e, "a vault was not followed after a move"),
        }
    }
    refollow(runtime, store, db, user_id, &vaults, &retire_after, &dest).await;
    if name == FIRST_DRIVE_NAME {
        match &carried {
            // The copy is named finished: this device's tree syncs with it
            // from now on, and writes nothing more into the tree it left.
            Carried::Moved | Carried::SourceKept(_) => record::mark_synced(db, user_id, &dest.vault_key, &to_tree).await?,
            Carried::NotMoved(_) | Carried::NotMovedTreeLeft { .. } => {}
        }
        // The record stays only while the source is kept beside the copy.
        if !matches!(carried, Carried::SourceKept(_)) && left.is_none() {
            record::end_move(db, user_id).await?;
        }
    }
    let (src, dst) = (source_vault.node.id.as_str(), dest.node.id.as_str());
    let also = refused_said(&not_carried, src);
    match carried {
        Carried::Moved => {}
        Carried::NotMoved(why) => return refused(format!("drive move: '{name}' was not moved, and is still on '{src}': {why}{also}")),
        Carried::NotMovedTreeLeft { why, left } => {
            return refused(format!(
                "drive move: '{name}' was not moved, and is still on '{src}': {why}. '{dst}' also keeps an unfinished \
                 copy of it under {to_tree}, which it did not retire ({left}): `drive list` shows it as unfinished, \
                 and moving '{name}' to '{dst}' again retires it first{also}"
            ))
        }
        Carried::SourceKept(e) if name == FIRST_DRIVE_NAME => {
            return refused(format!(
                "drive move: '{name}' is on '{dst}' now, and this device syncs with it there, but '{src}' still keeps \
                 the copy it left: it did not retire it ({e}). Run `drive move {name} --to {dst}` again on this \
                 device to retire it; until then your other devices may say two drives are called '{name}'{also}"
            ))
        }
        Carried::SourceKept(e) => {
            return refused(format!(
                "drive move: '{name}' is on '{dst}' now, and '{src}' still keeps it too: it did not retire it ({e}). \
                 Run `drive move {name} --to {dst}` again to retire it there{also}"
            ))
        }
    }
    if let Some(left) = left {
        return refused(format!("drive move: '{name}' is on '{dst}' now, and {left}; run the move again to retire it{also}"));
    }
    let moved = record::all(db, user_id)
        .await?
        .into_iter()
        .find(|d| d.vault_key == dest.vault_key && d.tree == to_tree)
        .ok_or_else(|| io::Error::other("the drive was moved but the vault it moved to did not list it"))?;
    tracing::info!(user_id, from = %src, to = %dst, keys_refused = not_carried.len(), "moved a drive");
    let keys_refused = u32::try_from(not_carried.len()).unwrap_or(u32::MAX);
    Ok(UserResponse::DriveMoved { drives: vec![describe(&moved, &sizes, &pins)], keys_refused })
}

/// What [`settle_copies`] did with the copies a move retires besides its
/// source.
struct SettledCopies {
    /// The keys their listings held that were refused, each named in the
    /// person's log as it was admitted.
    refused: Vec<NotCanonical>,
    /// The vault the last refused key was listed at, for the sentence.
    from: String,
    /// The sentence naming those that stay, when any does.
    left: Option<String>,
}

/// **Retire each of `copies`, the other finished copies of the drive, at its
/// vault, after carrying into `into` — the copy the drive now lives at —
/// everything it holds that `into` does not** (kotton #143): another device's
/// pass may have written there since the copy was made, as it may into the
/// tree an interrupted move left. Each is held under a lease of its own
/// first, so nothing more lands in it between the top-up's listing and its
/// retire, and retired under that lease ([`top_up_and_settle`]). One another
/// device holds is left, and said, as is one whose top-up or retire fails.
#[allow(clippy::too_many_arguments)]
async fn settle_copies(
    runtime: &DeviceRuntime,
    store: &UserStore,
    vaults: &[Drive],
    user_id: &str,
    name: &str,
    copies: &[Copy],
    into: &dyn VaultEnd,
    domain: &str,
    holds: &Holds,
) -> io::Result<SettledCopies> {
    let bus = runtime.event_bus();
    let names = device_names(runtime, store).await;
    let mut settled = SettledCopies { refused: Vec::new(), from: String::new(), left: None };
    let mut left = Vec::new();
    for copy in copies {
        let Some(id) = copy.made() else {
            left.push(format!("'{name}' is also kept under {}, which is no drive's tree", copy.tree));
            continue;
        };
        let Some(vault) = vaults.iter().find(|v| v.vault_key == copy.vault_key) else {
            left.push(format!("a vault '{name}' is also on is not one this device reaches"));
            continue;
        };
        let held = match Leased::take(runtime, &names, &vault.node, user_id, Holding::Drive(id)).await {
            Ok(Ok(held)) => {
                holds.keep(&held);
                held
            }
            Ok(Err(held)) => {
                left.push(format!("{} holds the copy on '{}' now, for {}s more", held.named(runtime, store).await, vault.node.id, held.for_secs));
                continue;
            }
            Err(e) => {
                // Gone since it was listed, or the vault did not answer: a
                // retire, idempotent, says which, and needs no lease for a
                // tree the vault no longer keeps.
                let gone = match dial(runtime, &vault.node, user_id).await {
                    Ok(client) => retire(&PeerEnd(client, None), user_id, id).await,
                    Err(e) => Err(e.to_string()),
                };
                if gone.is_err() {
                    left.push(format!("'{}' still keeps a copy under {} ({e})", vault.node.id, copy.tree));
                }
                continue;
            }
        };
        let from = PeerEnd(dial(runtime, &vault.node, user_id).await?.with_remote_mount(copy.tree.clone()).with_domain_id(domain.to_string()), Some(held));
        let label = vault.node.id.clone();
        let record = |refused: &[NotCanonical]| {
            for event in refused_events(user_id, name, &label, refused) {
                let _ = bus.publish(event);
            }
        };
        let Settled { carried, refused } = top_up_and_settle(user_id, &from, id, into, &record).await;
        if !refused.is_empty() {
            settled.from = vault.node.id.clone();
        }
        settled.refused.extend(refused);
        if let Carried::SourceKept(e) = carried {
            left.push(format!("'{}' still keeps the copy it left ({e})", vault.node.id));
        }
    }
    settled.left = (!left.is_empty()).then(|| left.join(", "));
    Ok(settled)
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
        /// Every key it was asked to read.
        reads: Mutex<Vec<String>>,
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
        /// The lease this device holds on the tree, which its retire names.
        lease: Option<DriveLease>,
        /// Renewing that lease fails: another device took it, or it lapsed.
        renew_fails: AtomicBool,
        /// The lease each retire it was told named.
        retired_under: Mutex<Vec<Option<DriveLease>>>,
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
        async fn read(&self, key: &StorageKey) -> Result<Vec<u8>, String> {
            self.reads.lock().unwrap().push(key.to_string());
            self.objects.lock().unwrap().iter().find(|(k, _)| k == key.as_str()).map(|(_, v)| v.clone()).ok_or("not found".into())
        }
        async fn write(&self, key: &StorageKey, blob: &[u8]) -> Result<(), String> {
            if self.fail_write == Some(key.as_str()) {
                return Err("the connection dropped".into());
            }
            self.objects.lock().unwrap().push((key.to_string(), blob.to_vec()));
            Ok(())
        }
        async fn tell(&self, request: VaultPeerRequest) -> Result<(), String> {
            self.told.lock().unwrap().push(request.variant_name());
            if let VaultPeerRequest::TenantDriveRetire { lease, .. } = &request {
                self.retired_under.lock().unwrap().push(*lease);
            }
            match request {
                VaultPeerRequest::TenantDriveRetire { .. } if self.refuse_retire.load(Ordering::SeqCst) => Err("the vault would not".into()),
                VaultPeerRequest::TenantDriveRetire { .. } => {
                    self.objects.lock().unwrap().clear();
                    if self.lose_retire_answer.swap(false, Ordering::SeqCst) {
                        return Err("the answer did not arrive".into());
                    }
                    Ok(())
                }
                _ => Ok(()),
            }
        }
        async fn renew(&self) -> Result<(), String> {
            match self.renew_fails.load(Ordering::SeqCst) {
                true => Err("another of your devices holds it now".into()),
                false => Ok(()),
            }
        }
        fn lease(&self) -> Option<DriveLease> {
            self.lease
        }
    }

    const FROM: MadeDrive = MadeDrive([1; 16]);

    /// **A move whose hold on the drive is lost names no copy** (kotton
    /// #143). Its hold on the source is renewed right before the copy is
    /// named finished; when it is lost — it lapsed, and another device took
    /// it, and a pass may have written there since the listing — the copy is
    /// retired unnamed and the drive stays where it is, whole. So is a hold on
    /// the copy that is lost.
    #[tokio::test]
    async fn a_move_whose_hold_is_lost_names_no_copy_and_leaves_the_drive() {
        for lost_at_source in [true, false] {
            let (from, to) = (source(), Fake::default());
            if lost_at_source { &from } else { &to }.renew_fails.store(true, Ordering::SeqCst);
            match settle(&from, &to).await {
                Carried::NotMoved(why) => assert!(why.contains("hold"), "{why}"),
                other => panic!("a move whose hold was lost said {other:?}"),
            }
            assert_eq!(to.told(), ["TenantDriveRetire"], "the copy was named, or not retired");
            assert!(from.told().is_empty(), "the drive was retired where it is");
            assert_eq!(from.keys(), ["p/one", "p/two"]);
        }
    }

    /// **Every retire names the lease its device holds on the tree** (kotton
    /// #143): the source's under the source's, a copy cleaned up under the
    /// copy's, and the vault fences each.
    #[tokio::test]
    async fn every_retire_names_the_lease_this_device_holds_on_the_tree() {
        let (held_from, held_to) = (DriveLease([5; 16]), DriveLease([6; 16]));
        let from = Fake { lease: Some(held_from), ..source() };
        let to = Fake { lease: Some(held_to), ..Fake::default() };
        assert_eq!(settle(&from, &to).await, Carried::Moved);
        assert_eq!(*from.retired_under.lock().unwrap(), [Some(held_from)]);
        let from = Fake { lease: Some(held_from), ..source() };
        let to = Fake { lease: Some(held_to), hides: Some("p/two"), ..Fake::default() };
        assert!(matches!(settle(&from, &to).await, Carried::NotMoved(_)));
        assert_eq!(*to.retired_under.lock().unwrap(), [Some(held_to)]);
    }
    const TO: MadeDrive = MadeDrive([2; 16]);

    fn source() -> Fake {
        Fake::holding(&[("p/one", b"one"), ("p/two", b"two two")])
    }

    async fn settle(from: &Fake, to: &Fake) -> Carried {
        let settled = carry_and_settle("alice", from, FROM, to, TO, b"finished".to_vec(), &|_| {}).await;
        assert!(settled.refused.is_empty(), "a source of canonical keys had one refused: {settled:?}");
        settled.carried
    }

    /// **A key the source lists that is not canonical is refused where the
    /// listing enters the move** (kotton #274): it is neither read at the
    /// source nor written at the destination, every other object moves, the
    /// check holds against what was sent, and the refusal is in the answer,
    /// each key with why.
    #[tokio::test]
    async fn a_listed_key_that_is_not_canonical_is_refused_and_the_rest_moves() {
        let hostile = ["../x", "./p/one", "/p/one", "p/", "p\\one", "p//one"];
        let mut held: Vec<(&str, &[u8])> = vec![("p/one", b"one"), ("p/two", b"two two")];
        held.extend(hostile.iter().map(|k| (*k, &b"served"[..])));
        let (from, to) = (Fake::holding(&held), Fake::default());
        // What was recorded, each with how many reads the source had served when it was.
        let recorded = std::sync::Mutex::new(Vec::new());
        let record = |refused: &[NotCanonical]| {
            let reads = from.reads.lock().unwrap().len();
            recorded.lock().unwrap().extend(refused.iter().map(|not| (not.key.clone(), reads)));
        };
        let settled = carry_and_settle("alice", &from, FROM, &to, TO, b"finished".to_vec(), &record).await;
        assert_eq!(settled.carried, Carried::Moved, "{settled:?}");
        let refused: Vec<&str> = settled.refused.iter().map(|r| r.key.as_str()).collect();
        assert_eq!(refused, hostile, "each key that is not canonical is refused, and only those");
        assert_eq!(*from.reads.lock().unwrap(), ["p/one", "p/two"], "a refused key was read at the source");
        assert_eq!(to.keys(), ["p/one", "p/two"], "a refused key was written at the destination");
        assert_eq!(to.told(), ["TenantDriveName"]);
        assert_eq!(from.told(), ["TenantDriveRetire"]);
        // Each refused key was recorded, and before anything was read: a move cut
        // off after its listing has named them already (kotton #315).
        let recorded = recorded.into_inner().unwrap();
        assert_eq!(recorded.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(), hostile, "each refused key is recorded, and only those");
        assert!(recorded.iter().all(|(_, reads)| *reads == 0), "a refused key was recorded after the copy began: {recorded:?}");
        let said = refused_said(&settled.refused, "vault");
        assert!(said.contains(&format!("listed {},", NotCanonical::counted(6))), "{said}");
        assert!(said.contains("listed 6 keys that are not storage keys") && said.contains("names them: `logs --level warn`)") && !said.contains("in the REPL"), "{said}");
        let one = refused_said(&settled.refused[..1], "vault");
        assert!(one.contains("listed 1 key that is not a storage key,") && one.contains("names it: `logs --level warn`)") && !one.contains("in the REPL"), "{one}");
        assert!(refused_said(&[], "vault").is_empty());
    }

    /// **A refused key is named in the log of the person whose drive it is**
    /// (kotton #315): the event is theirs, so their own log takes it and the
    /// device's and every other person's do not; it is at `warn`, the level the
    /// note names; and it names the drive, the vault and the key, escaped.
    #[test]
    fn a_refused_key_is_an_event_in_the_persons_own_log() {
        let not = StorageKey::parse("../x\u{7}").unwrap_err();
        let events = refused_events("alice", "photos", "vault-1", std::slice::from_ref(&not));
        let [event] = events.as_slice() else { panic!("one refused key is not one event: {events:?}") };
        assert!(event.belongs_to(&EventScope::User("alice".into())));
        assert!(!event.belongs_to(&EventScope::Device));
        assert!(!event.belongs_to(&EventScope::User("bob".into())));
        assert_eq!(event.level, EventLevel::Warn);
        assert!(
            event.message.contains("'photos'") && event.message.contains("'vault-1'") && event.message.contains(&format!("{:?}", not.key)),
            "{}",
            event.message
        );
        let payload = event.payload.as_ref().unwrap();
        assert_eq!(payload["key"], not.key);
        assert_eq!(payload["drive"], "photos");
    }

    /// **A vault cannot fill the person's log**: past [`NAMED_AT_MOST`] refused
    /// keys, one event counts the rest, in the person's log too.
    #[test]
    fn past_the_named_keys_one_event_counts_the_rest() {
        let refused: Vec<NotCanonical> =
            (0..NAMED_AT_MOST + 5).map(|i| StorageKey::parse(&format!("../{i}")).unwrap_err()).collect();
        let events = refused_events("alice", "photos", "vault-1", &refused);
        assert_eq!(events.len(), NAMED_AT_MOST + 1, "{events:?}");
        assert!(events.iter().all(|e| e.belongs_to(&EventScope::User("alice".into())) && e.level == EventLevel::Warn));
        let last = events.last().unwrap();
        assert!(last.message.contains(&format!("also listed {}, past the {NAMED_AT_MOST}", NotCanonical::counted(5))), "{}", last.message);
        assert!(refused_events("alice", "photos", "vault-1", &refused[..NAMED_AT_MOST]).len() == NAMED_AT_MOST);
        assert!(refused_events("alice", "photos", "vault-1", &[]).is_empty());
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

    /// **A move of `personal` cut off after the naming is finished by running
    /// it again on the device that began it** (kotton #124). The source
    /// refuses its retire, so two finished trees carry the first drive's id.
    /// The move this device recorded names exactly those two, so a rerun to
    /// the same vault is let through and planned as any drive's interrupted
    /// move: the copy kept, the source retired, and the record forgotten.
    /// Without that record the two are trees no move of this device's left,
    /// and no move retires either; with it, a move to a third vault is sent
    /// to finish this one first. What another device wrote at the tree the
    /// move left while it was cut off is carried into the copy before that
    /// tree is retired ([`top_up_and_settle`]); what this device wrote at the
    /// copy meanwhile is kept as it is; and a top-up that fails retires
    /// nothing.
    #[tokio::test]
    async fn a_cut_off_move_of_personal_is_finished_by_running_it_again() {
        let temp = tempfile::TempDir::new().unwrap();
        let db = Arc::new(kotton_record::open_sqlite(&temp.path().join("machine.db")).await.unwrap());
        crate::db::MIGRATOR.run(db.as_ref()).await.unwrap();
        let personal = |vault: [u8; 32], tree: u8| Copy { name: FIRST_DRIVE_NAME.into(), id: FIRST_DRIVE_ID.into(), ..a_copy(vault, tree, "personal", 7) };
        let (at_source, at_dest) = (personal(V1, 1), personal(V2, 2));

        // The move begins: its record is written once the copy's tree is
        // made, and the source refuses its retire.
        let begun = record::MoveBegun { from: (V1, at_source.tree.clone()), to: (V2, at_dest.tree.clone()) };
        record::begin_move(&db, "alice", &begun).await.unwrap();
        let (from, to) = (source(), Fake::default());
        from.refuse_retire.store(true, Ordering::SeqCst);
        assert!(matches!(settle(&from, &to).await, Carried::SourceKept(_)));

        // Both vaults list a finished `personal` now.
        let copies = [at_source.clone(), at_dest.clone()];
        let firsts = finished_firsts(&copies);
        let recorded = record::move_begun(&db, "alice").await.unwrap();
        assert_eq!(recorded.as_ref(), Some(&begun), "the move this device began was not kept");
        assert_eq!(twice(&firsts, None, &V2), Twice::Apart, "two trees no move of this device left were let through");
        assert_eq!(twice(&firsts, recorded.as_ref(), &V3), Twice::OwnMoveElsewhere(V2));
        let stranger = record::MoveBegun { from: (V1, at_source.tree.clone()), to: (V3, at_dest.tree.clone()) };
        assert_eq!(twice(&firsts, Some(&stranger), &V2), Twice::Apart, "a record of another move let these two through");

        // The rerun.
        assert_eq!(twice(&firsts, recorded.as_ref(), &V2), Twice::OwnMove);
        match plan_move(&copies, FIRST_DRIVE_NAME, &V2, None) {
            Plan::AtDestination { keep, retire: rest } => {
                assert_eq!(keep, at_dest);
                assert_eq!(rest, [at_source]);
            }
            other => panic!("the rerun of personal's move did not finish it: {other:?}"),
        }
        // While it was cut off, another device kept syncing with the tree
        // the move left and wrote there, and this device synced with the copy
        // and wrote there, a new object and a newer form of one both hold.
        let written = |end: &Fake, key: &str, blob: &[u8]| end.objects.lock().unwrap().push((key.to_string(), blob.to_vec()));
        written(&from, "p/three", b"written on B at the tree the move left");
        written(&to, "p/four", b"written on A at the copy");
        to.objects.lock().unwrap().iter_mut().find(|(k, _)| k == "p/one").unwrap().1 = b"one, newer".to_vec();

        // A top-up that cannot write leaves both trees as they are.
        let failing = Fake { objects: Mutex::new(to.objects.lock().unwrap().clone()), fail_write: Some("p/three"), ..Fake::default() };
        let settled = top_up_and_settle("alice", &from, FROM, &failing, &|_| {}).await;
        assert!(matches!(&settled.carried, Carried::SourceKept(why) if why.contains("writing p/three")), "{settled:?}");
        assert!(from.keys().contains(&"p/three".to_string()), "a failed top-up lost B's write");
        assert!(failing.told().is_empty(), "a failed top-up told the copy {:?}", failing.told());

        // The rerun carries B's write into the copy, keeps A's, and only then
        // retires the tree it left.
        from.refuse_retire.store(false, Ordering::SeqCst);
        let settled = top_up_and_settle("alice", &from, FROM, &to, &|_| {}).await;
        assert_eq!(settled.carried, Carried::Moved, "{settled:?}");
        assert!(from.keys().is_empty(), "the source still keeps personal");
        let mut held = to.objects.lock().unwrap().clone();
        held.sort();
        assert_eq!(
            held,
            [
                ("p/four".to_string(), b"written on A at the copy".to_vec()),
                ("p/one".to_string(), b"one, newer".to_vec()),
                ("p/three".to_string(), b"written on B at the tree the move left".to_vec()),
                ("p/two".to_string(), b"two two".to_vec()),
            ],
            "the rerun lost a write, or put an older form over a newer one"
        );
        assert_eq!(to.told(), ["TenantDriveName"], "the rerun told the copy more: it is named finished already");
        record::end_move(&db, "alice").await.unwrap();
        assert_eq!(record::move_begun(&db, "alice").await.unwrap(), None);
        assert_eq!(twice(&finished_firsts(&[at_dest]), None, &V2), Twice::No);
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

    /// `personal` is planned as any made drive is (kotton #124): carried from
    /// the tree its name is sealed for, and retired there. A name no copy has
    /// is no drive; and an unfinished tree is no copy of the drive.
    #[test]
    fn personal_and_a_name_nothing_has_are_planned_as_such() {
        let first = Copy { name: "personal".into(), id: FIRST_DRIVE_ID.into(), ..a_copy(V1, 1, "personal", 7) };
        assert_eq!(plan_move(std::slice::from_ref(&first), "personal", &V2, None), Plan::Carry { source: first, retire_after: vec![] });
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
    /// keeps the name and id this device has for its tree, or names nothing;
    /// and the tenancy's own tree is no drive, whatever the vault says of it.
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
            TenantDrive { tree: TENANCY_TREE.into(), sealed_name: vec![], held: 1 },
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

    /// **Copies of one drive describe with one id; two drives of one name
    /// with two** (kotton #188; the drive decision's types). Alice keeps drives
    /// at `home` and `office`. `photos` is recorded at `home`; a move of it to
    /// `office` left an unfinished tree there, sealed with the same id; and a
    /// second `photos`, made at `office` by a `create` that raced, carries an
    /// id of its own; `personal` lives at `home`. The descriptors say
    /// `personal` is [`FIRST_DRIVE_ID`] and is described once, the raced
    /// drive's id differs from the recorded one, and the unfinished copy
    /// carries the recorded one.
    #[tokio::test]
    async fn copies_of_one_drive_describe_with_one_id_and_two_drives_of_one_name_with_two() {
        use kotton_peer::daemon::db as network_db;
        let temp = tempfile::TempDir::new().unwrap();
        let db = Arc::new(kotton_record::open_sqlite(&temp.path().join("machine.db")).await.unwrap());
        crate::db::MIGRATOR.run(db.as_ref()).await.unwrap();
        let key = |seed: u8| ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes();
        for (label, k) in [("home", key(9)), ("office", key(4))] {
            let did = kotton_crypto::DidKeyMethod::from_public_key_bytes(&k).unwrap().to_string();
            network_db::insert_paired_node(&db, label, "alice", &did, &k, "[]", 0, None).await.unwrap();
            record::record(&db, "alice", &k).await.unwrap();
        }
        let (recorded, raced) = ("ab".repeat(16), "cd".repeat(16));
        let listed = |tree: String, id: &str| record::Listed { tree, name: "photos".into(), id: id.into() };
        let personal = record::Listed { tree: MadeDrive([5; 16]).tree(), name: FIRST_DRIVE_NAME.into(), id: FIRST_DRIVE_ID.into() };
        record::reconcile(&db, "alice", &key(9), &[listed(MadeDrive([1; 16]).tree(), &recorded), personal]).await.unwrap();
        record::reconcile(&db, "alice", &key(4), &[listed(MadeDrive([2; 16]).tree(), &raced)]).await.unwrap();
        let seen = Seen {
            copies: vec![Copy {
                vault_key: key(4),
                tree: MadeDrive([3; 16]).tree(),
                name: "photos".into(),
                id: recorded.clone(),
                held: 7,
                finished: false,
                sealed_before_ids: false,
            }],
            unanswered: Vec::new(),
        };
        let pins = pins::Read { settings: Vec::new(), claims: Vec::new(), devices: Vec::new() };
        let described: Vec<DriveDescriptor> = record::kept(&db, "alice").await.unwrap().iter().map(|d| describe(d, &HashMap::new(), &pins)).collect();
        let id_at = |vault: &str, name: &str| -> Option<String> {
            let found: Vec<_> = described.iter().filter(|d| d.vault == vault && d.name == name).collect();
            assert_eq!(found.len(), 1, "{vault}/{name}: {described:?}");
            found[0].id.clone()
        };
        assert_eq!(id_at("home", FIRST_DRIVE_NAME).as_deref(), Some(FIRST_DRIVE_ID), "personal at home");
        assert_eq!(described.iter().filter(|d| d.name == FIRST_DRIVE_NAME).count(), 1, "personal is described where it is not: {described:?}");
        assert_eq!(id_at("home", "photos"), Some(recorded.clone()));
        assert_eq!(id_at("office", "photos"), Some(raced.clone()));
        assert_ne!(id_at("home", "photos"), id_at("office", "photos"), "two drives of one name describe with one id");

        let unfinished = unfinished_described(&db, "alice", &seen).await.unwrap();
        assert_eq!(unfinished.len(), 1, "{unfinished:?}");
        assert!(unfinished[0].unfinished && unfinished[0].vault == "office", "{unfinished:?}");
        assert_eq!(unfinished[0].id, Some(recorded), "the copy a move left does not carry its drive's id: {unfinished:?}");
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
